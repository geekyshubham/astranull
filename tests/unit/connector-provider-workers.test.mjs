import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { afterEach, describe, it } from 'node:test';
import { pollAwsWaf } from '../../src/lib/connectorProviders/awsWaf.mjs';
import { pollCloudflare } from '../../src/lib/connectorProviders/cloudflare.mjs';
import {
  CONNECTOR_POLL_FETCH_DEFAULT_TIMEOUT_MS,
  CONNECTOR_POLL_INVENTORY_PAGE_SIZE,
  CONNECTOR_POLL_MAX_INVENTORY_ITEMS,
  hashRef,
  parseProviderSecret,
  resolveConnectorPollFetchTimeoutMs,
} from '../../src/lib/connectorProviders/common.mjs';
import {
  listConnectorProviders,
  OUTBOUND_POLL_PROVIDERS,
  supportsOutboundProviderPoll,
} from '../../src/lib/connectorProviders/index.mjs';
import {
  executeConnectorProviderPoll,
  shouldAttemptOutboundConnectorPoll,
} from '../../src/lib/connectorProviders/pollWorker.mjs';
import { withConnectorPollRetry } from '../../src/lib/connectorProviders/retry.mjs';
import { buildSecretAad, encryptSecret, loadSecretEncryptionKey } from '../../src/lib/secrets.mjs';
import * as wafPosture from '../../src/services/wafPosture.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';

const TEST_ENC_KEY_B64 = randomBytes(32).toString('base64');
const envSnapshot = { ...process.env };

function restoreEnv() {
  for (const key of Object.keys(process.env)) {
    if (!(key in envSnapshot)) delete process.env[key];
  }
  Object.assign(process.env, envSnapshot);
}

function demoCtx(role = 'admin', tenantId = 'ten_demo', userId = 'usr_admin') {
  return { tenantId, userId, role };
}

function seedConnector(overrides = {}) {
  const store = getStore();
  if (!Array.isArray(store.wafConnectors)) store.wafConnectors = [];
  if (!Array.isArray(store.wafConnectorSnapshots)) store.wafConnectorSnapshots = [];
  const connector = {
    id: 'conn_cf_1',
    tenant_id: 'ten_demo',
    provider: 'cloudflare',
    name: 'edge-readonly',
    secret_id: 'sec_cf_1',
    config_json: { read_only: true, zone_ref_hash: hashRef('cloudflare:zone:zone_1') },
    status: 'active',
    created_at: '2026-07-01T00:00:00.000Z',
    updated_at: '2026-07-01T00:00:00.000Z',
    last_success_at: null,
    ...overrides,
  };
  store.wafConnectors.push(connector);
  return connector;
}

function slowFetchMock() {
  return async (_url, init = {}) => new Promise((_resolve, reject) => {
    const onAbort = () => {
      const err = new Error('The operation was aborted');
      err.name = 'AbortError';
      reject(err);
    };
    if (init.signal?.aborted) {
      onAbort();
      return;
    }
    init.signal?.addEventListener('abort', onAbort, { once: true });
  });
}

function seedEncryptedSecret({ id, purpose, name, plaintext, tenantId = 'ten_demo' }) {
  const key = loadSecretEncryptionKey({ ASTRANULL_SECRET_ENCRYPTION_KEY: TEST_ENC_KEY_B64 });
  const record = {
    id,
    tenant_id: tenantId,
    purpose,
    name,
    metadata: {},
    rotation: 0,
    created_at: '2026-07-01T00:00:00.000Z',
    updated_at: '2026-07-01T00:00:00.000Z',
    created_by: 'usr_admin',
  };
  record.envelope = encryptSecret(plaintext, key, buildSecretAad(record));
  getStore().encryptedSecrets.push(record);
  return record;
}

afterEach(() => {
  restoreEnv();
  process.env.ASTRANULL_NO_PERSIST = '1';
});

describe('connector provider helpers', () => {
  it('lists every outbound poll provider with read-only metadata', () => {
    const providers = listConnectorProviders().map((entry) => entry.provider).sort();
    assert.deepEqual(providers, [...OUTBOUND_POLL_PROVIDERS].sort());
    for (const entry of listConnectorProviders()) {
      assert.equal(entry.read_only, true);
      assert.ok(Array.isArray(entry.required_scopes));
      assert.ok(Array.isArray(entry.snapshot_kinds));
      assert.equal(supportsOutboundProviderPoll(entry.provider), true);
    }
    assert.equal(supportsOutboundProviderPoll('generic_waf'), false);
  });

  it('parses cloudflare and aws_waf vault secret shapes', () => {
    assert.deepEqual(parseProviderSecret('cf-token-plain', 'cloudflare'), { api_token: 'cf-token-plain' });
    assert.deepEqual(
      parseProviderSecret('{"api_token":"cf-json-token"}', 'cloudflare'),
      { api_token: 'cf-json-token' },
    );
    assert.deepEqual(
      parseProviderSecret(
        '{"access_key_id":"AKIA","secret_access_key":"secret","region":"us-west-2"}',
        'aws_waf',
      ),
      {
        access_key_id: 'AKIA',
        secret_access_key: 'secret',
        region: 'us-west-2',
      },
    );
  });

  it('normalizes prefetched cloudflare metadata without raw config bodies', async () => {
    const result = await pollCloudflare({
      credentials: null,
      config: { zone_ref_hash: hashRef('cloudflare:zone:zone_1') },
      prefetchedMetadata: {
        zones: [
          {
            id: 'zone_1',
            name: 'app.example.com',
            security_level: 'high',
            rulesets: [{ phase: 'http_request_firewall', rules: [{ id: 'r1' }, { id: 'r2' }] }],
          },
        ],
      },
      observedAt: '2026-07-02T12:00:00.000Z',
    });
    assert.equal(result.snapshots.length, 1);
    const snap = result.snapshots[0];
    assert.equal(snap.snapshot_kind, 'waf_policy');
    assert.equal(snap.display_ref, 'app.example.com');
    assert.equal(snap.summary.policy_mode, 'block');
    assert.equal(snap.summary.rule_count, 2);
    assert.ok(snap.summary.config_hash);
    assert.equal(snap.config_hash, snap.summary.config_hash);
    assert.ok(!JSON.stringify(snap).includes('raw_payload'));
  });

  it('uses explicit scope for aws_waf live poll even when account_ref_hash is set', async () => {
    const capturedScopes = [];
    const fetchFn = async (_url, init) => {
      const body = JSON.parse(init.body);
      capturedScopes.push(body.Scope);
      if (body.Scope && !body.Id) {
        return {
          ok: true,
          status: 200,
          json: async () => ({ WebACLs: [] }),
        };
      }
      return {
        ok: true,
        status: 200,
        json: async () => ({ WebACL: {} }),
      };
    };

    await pollAwsWaf({
      credentials: {
        access_key_id: 'AKIATEST',
        secret_access_key: 'secret',
        region: 'us-east-1',
      },
      config: {
        account_ref_hash: hashRef('aws:account:123456789012'),
        scope: 'regional',
      },
      fetchFn,
      observedAt: '2026-07-02T12:00:00.000Z',
    });
    assert.deepEqual(capturedScopes, ['REGIONAL']);

    capturedScopes.length = 0;
    await pollAwsWaf({
      credentials: {
        access_key_id: 'AKIATEST',
        secret_access_key: 'secret',
        region: 'us-east-1',
      },
      config: {
        account_ref_hash: hashRef('aws:account:123456789012'),
        scope: 'cloudfront',
      },
      fetchFn,
      observedAt: '2026-07-02T12:00:00.000Z',
    });
    assert.deepEqual(capturedScopes, ['CLOUDFRONT']);
  });

  it('normalizes prefetched aws_waf metadata summaries', async () => {
    const result = await pollAwsWaf({
      credentials: null,
      prefetchedMetadata: {
        web_acls: [
          {
            ARN: 'arn:aws:wafv2:us-east-1:123:regional/webacl/demo/abc',
            Name: 'demo-webacl',
            DefaultAction: { Block: {} },
            Rules: [{ Name: 'AWSManagedRulesCommonRuleSet' }],
          },
        ],
      },
      observedAt: '2026-07-02T12:00:00.000Z',
    });
    assert.equal(result.snapshots.length, 1);
    assert.equal(result.snapshots[0].summary.policy_mode, 'block');
    assert.equal(result.snapshots[0].summary.rule_count, 1);
    assert.equal(result.snapshots[0].summary.config_hash, result.snapshots[0].config_hash);
    assert.ok(result.snapshots[0].config_hash);
  });

  it('resolves connector poll fetch timeout from env with safe fallback', () => {
    assert.equal(resolveConnectorPollFetchTimeoutMs({}), CONNECTOR_POLL_FETCH_DEFAULT_TIMEOUT_MS);
    assert.equal(
      resolveConnectorPollFetchTimeoutMs({ ASTRANULL_CONNECTOR_POLL_FETCH_TIMEOUT_MS: '5000' }),
      5000,
    );
    assert.equal(
      resolveConnectorPollFetchTimeoutMs({ ASTRANULL_CONNECTOR_POLL_FETCH_TIMEOUT_MS: 'not-a-number' }),
      CONNECTOR_POLL_FETCH_DEFAULT_TIMEOUT_MS,
    );
  });

  it('scopes cloudflare live poll permission_gaps to each zone snapshot', async () => {
    const fetchFn = async (url) => {
      if (url.includes('/zones?') && url.includes('per_page=')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            success: true,
            result: [
              { id: 'zone_1', name: 'app.example.com' },
              { id: 'zone_2', name: 'api.example.com' },
            ],
            result_info: { page: 1, per_page: 50, total_pages: 1 },
          }),
        };
      }
      if (url.endsWith('/zones/zone_1/rulesets')) {
        return {
          ok: false,
          status: 403,
          json: async () => ({
            success: false,
            errors: [{ message: 'Insufficient permissions' }],
          }),
        };
      }
      if (url.endsWith('/zones/zone_2/rulesets')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            success: true,
            result: [{ phase: 'http_request_firewall', rules: [{ id: 'r1' }] }],
          }),
        };
      }
      throw new Error(`unexpected fetch url: ${url}`);
    };

    const result = await pollCloudflare({
      credentials: { api_token: 'cf-live-token' },
      fetchFn,
      observedAt: '2026-07-02T12:00:00.000Z',
    });

    assert.equal(result.snapshots.length, 2);
    assert.equal(result.health, 'degraded');
    assert.deepEqual(result.permission_gaps, ['rulesets:zone_1']);

    const zone1 = result.snapshots.find((snap) => snap.display_ref === 'app.example.com');
    const zone2 = result.snapshots.find((snap) => snap.display_ref === 'api.example.com');
    assert.deepEqual(zone1.summary.permission_gaps, ['rulesets:zone_1']);
    assert.equal(zone2.summary.permission_gaps, undefined);
    assert.equal(zone2.summary.rule_count, 1);
  });

  it('fails cloudflare live poll when fetch exceeds bounded timeout', async () => {
    await assert.rejects(
      () => pollCloudflare({
        credentials: { api_token: 'cf-live-token' },
        fetchFn: slowFetchMock(),
        fetchTimeoutMs: 50,
        observedAt: '2026-07-02T12:00:00.000Z',
      }),
      (err) => {
        assert.equal(err.code, 'provider_poll_failed');
        assert.match(err.message, /bounded timeout/i);
        return true;
      },
    );
  });

  it('fails aws_waf live poll when fetch exceeds bounded timeout', async () => {
    await assert.rejects(
      () => pollAwsWaf({
        credentials: {
          access_key_id: 'AKIATESTKEY',
          secret_access_key: 'secret-test-key',
          region: 'us-east-1',
        },
        fetchFn: slowFetchMock(),
        fetchTimeoutMs: 50,
        observedAt: '2026-07-02T12:00:00.000Z',
      }),
      (err) => {
        assert.equal(err.code, 'provider_poll_failed');
        assert.match(err.message, /bounded timeout/i);
        return true;
      },
    );
  });

  it('paginates cloudflare zones until inventory is exhausted', async () => {
    const zonePages = [
      Array.from({ length: CONNECTOR_POLL_INVENTORY_PAGE_SIZE }, (_entry, index) => ({
        id: `zone_page1_${index}`,
        name: `page1-${index}.example.com`,
      })),
      Array.from({ length: 25 }, (_entry, index) => ({
        id: `zone_page2_${index}`,
        name: `page2-${index}.example.com`,
      })),
    ];
    const requestedPages = [];

    const fetchFn = async (url) => {
      if (url.includes('/zones?') && url.includes('per_page=')) {
        const page = Number(new URL(url).searchParams.get('page') ?? '1');
        requestedPages.push(page);
        const result = zonePages[page - 1] ?? [];
        return {
          ok: true,
          status: 200,
          json: async () => ({
            success: true,
            result,
            result_info: {
              page,
              per_page: CONNECTOR_POLL_INVENTORY_PAGE_SIZE,
              total_pages: zonePages.length,
            },
          }),
        };
      }
      if (url.includes('/rulesets')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({ success: true, result: [] }),
        };
      }
      throw new Error(`unexpected fetch url: ${url}`);
    };

    const result = await pollCloudflare({
      credentials: { api_token: 'cf-live-token' },
      fetchFn,
      observedAt: '2026-07-02T12:00:00.000Z',
    });

    assert.deepEqual(requestedPages, [1, 2]);
    assert.equal(result.snapshots.length, 75);
    assert.equal(result.health, 'active');
    assert.deepEqual(result.permission_gaps, []);
  });

  it('caps cloudflare zone inventory at 200 items with truncated_inventory gap', async () => {
    const requestedPages = [];

    const fetchFn = async (url) => {
      if (url.includes('/zones?') && url.includes('per_page=')) {
        const page = Number(new URL(url).searchParams.get('page') ?? '1');
        requestedPages.push(page);
        const start = (page - 1) * CONNECTOR_POLL_INVENTORY_PAGE_SIZE;
        const result = Array.from({ length: CONNECTOR_POLL_INVENTORY_PAGE_SIZE }, (_entry, index) => ({
          id: `zone_${start + index}`,
          name: `zone-${start + index}.example.com`,
        }));
        return {
          ok: true,
          status: 200,
          json: async () => ({
            success: true,
            result,
            result_info: {
              page,
              per_page: CONNECTOR_POLL_INVENTORY_PAGE_SIZE,
              total_pages: 10,
            },
          }),
        };
      }
      if (url.includes('/rulesets')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({ success: true, result: [] }),
        };
      }
      throw new Error(`unexpected fetch url: ${url}`);
    };

    const result = await pollCloudflare({
      credentials: { api_token: 'cf-live-token' },
      fetchFn,
      observedAt: '2026-07-02T12:00:00.000Z',
    });

    assert.deepEqual(requestedPages, [1, 2, 3, 4]);
    assert.equal(result.snapshots.length, CONNECTOR_POLL_MAX_INVENTORY_ITEMS);
    assert.equal(result.health, 'degraded');
    assert.deepEqual(result.permission_gaps, ['truncated_inventory']);
  });

  it('paginates aws_waf web ACL inventory with NextMarker until exhausted', async () => {
    const listCalls = [];

    const fetchFn = async (_url, init) => {
      const body = JSON.parse(init.body);
      if (body.Scope && !body.Id) {
        listCalls.push(body);
        if (!body.NextMarker) {
          return {
            ok: true,
            status: 200,
            json: async () => ({
              WebACLs: Array.from({ length: CONNECTOR_POLL_INVENTORY_PAGE_SIZE }, (_entry, index) => ({
                Id: `acl_page1_${index}`,
                Name: `page1-acl-${index}`,
                ARN: `arn:aws:wafv2:us-east-1:123:regional/webacl/page1-acl-${index}/id`,
              })),
              NextMarker: 'page-2',
            }),
          };
        }
        return {
          ok: true,
          status: 200,
          json: async () => ({
            WebACLs: [
              {
                Id: 'acl_page2_0',
                Name: 'page2-acl-0',
                ARN: 'arn:aws:wafv2:us-east-1:123:regional/webacl/page2-acl-0/id',
              },
            ],
          }),
        };
      }
      return {
        ok: true,
        status: 200,
        json: async () => ({ WebACL: { DefaultAction: { Allow: {} }, Rules: [] } }),
      };
    };

    const result = await pollAwsWaf({
      credentials: {
        access_key_id: 'AKIATEST',
        secret_access_key: 'secret',
        region: 'us-east-1',
      },
      fetchFn,
      observedAt: '2026-07-02T12:00:00.000Z',
    });

    assert.equal(listCalls.length, 2);
    assert.equal(listCalls[0].Limit, CONNECTOR_POLL_INVENTORY_PAGE_SIZE);
    assert.equal(listCalls[1].NextMarker, 'page-2');
    assert.equal(result.snapshots.length, CONNECTOR_POLL_INVENTORY_PAGE_SIZE + 1);
    assert.equal(result.health, 'active');
    assert.deepEqual(result.permission_gaps, []);
  });

  it('caps aws_waf web ACL inventory at 200 items with truncated_inventory gap', async () => {
    const listCalls = [];

    const fetchFn = async (_url, init) => {
      const body = JSON.parse(init.body);
      if (body.Scope && !body.Id) {
        listCalls.push(body);
        return {
          ok: true,
          status: 200,
          json: async () => ({
            WebACLs: Array.from({ length: CONNECTOR_POLL_INVENTORY_PAGE_SIZE }, (_entry, index) => ({
              Id: `acl_${listCalls.length}_${index}`,
              Name: `acl-${listCalls.length}-${index}`,
              ARN: `arn:aws:wafv2:us-east-1:123:regional/webacl/acl-${listCalls.length}-${index}/id`,
            })),
            NextMarker: `page-${listCalls.length + 1}`,
          }),
        };
      }
      return {
        ok: true,
        status: 200,
        json: async () => ({ WebACL: { DefaultAction: { Allow: {} }, Rules: [] } }),
      };
    };

    const result = await pollAwsWaf({
      credentials: {
        access_key_id: 'AKIATEST',
        secret_access_key: 'secret',
        region: 'us-east-1',
      },
      fetchFn,
      observedAt: '2026-07-02T12:00:00.000Z',
    });

    assert.equal(listCalls.length, 4);
    assert.equal(result.snapshots.length, CONNECTOR_POLL_MAX_INVENTORY_ITEMS);
    assert.equal(result.health, 'degraded');
    assert.deepEqual(result.permission_gaps, ['truncated_inventory']);
  });

  it('retries retryable provider failures with bounded attempts', async () => {
    let calls = 0;
    await assert.rejects(
      () => withConnectorPollRetry(async () => {
        calls += 1;
        const err = new Error('temporary provider outage');
        err.status = 503;
        throw err;
      }, { maxAttempts: 3, baseBackoffMs: 1 }),
      /temporary provider outage/,
    );
    assert.equal(calls, 3);
  });
});

describe('connector provider poll worker', () => {
  it('only attempts outbound poll for supported providers with secret_id', () => {
    const connector = {
      provider: 'cloudflare',
      secret_id: 'sec_1',
      status: 'active',
      config_json: { read_only: true },
    };
    assert.equal(shouldAttemptOutboundConnectorPoll(connector, {}), true);
    assert.equal(shouldAttemptOutboundConnectorPoll(connector, { snapshots: [{ snapshot_kind: 'waf_policy' }] }), false);
    assert.equal(shouldAttemptOutboundConnectorPoll({ ...connector, secret_id: null }, {}), false);
    assert.equal(
      shouldAttemptOutboundConnectorPoll({ ...connector, provider: 'generic_waf' }, {}),
      false,
    );
  });

  it('executes provider poll using vault-resolved credentials and prefetched metadata', async () => {
    const connector = seedConnector();
    const resolved = await executeConnectorProviderPoll({
      connector,
      ctx: demoCtx(),
      secretResolver: async () => ({ plaintext: 'cf-token' }),
      prefetchedMetadata: {
        zones: [{ id: 'zone_1', name: 'app.example.com', security_level: 'medium', rulesets: [] }],
      },
      now: '2026-07-02T12:00:00.000Z',
      maxAttempts: 1,
    });
    assert.equal(resolved.snapshots.length, 1);
    assert.equal(resolved.health.status, 'active');
    assert.equal(resolved.health.attempts, 1);
  });

  it('executes aws_waf provider poll worker with prefetched metadata', async () => {
    const connector = seedConnector({
      id: 'conn_aws_1',
      provider: 'aws_waf',
      secret_id: 'sec_aws_1',
      config_json: { read_only: true, scope: 'regional' },
    });
    const resolved = await executeConnectorProviderPoll({
      connector,
      ctx: demoCtx(),
      secretResolver: async () => ({
        plaintext: '{"access_key_id":"AKIATEST","secret_access_key":"secret","region":"us-east-1"}',
      }),
      prefetchedMetadata: {
        web_acls: [
          {
            ARN: 'arn:aws:wafv2:us-east-1:123:regional/webacl/demo/abc',
            Name: 'demo-webacl',
            DefaultAction: { Block: {} },
            Rules: [{ Name: 'AWSManagedRulesCommonRuleSet' }],
          },
        ],
      },
      now: '2026-07-02T12:00:00.000Z',
      maxAttempts: 1,
    });
    assert.equal(resolved.snapshots.length, 1);
    assert.equal(resolved.health.status, 'active');
    assert.equal(resolved.snapshots[0].snapshot_kind, 'waf_policy');
    assert.ok(!JSON.stringify(resolved).includes('AKIATEST'));
  });
});

describe('wafPosture pollConnector outbound slice', () => {
  it('fails closed when outbound poll is requested without usable vault credentials', async () => {
    freshStore();
    process.env.ASTRANULL_WAF_POSTURE_ENABLED = '1';
    const connector = seedConnector();
    const result = await wafPosture.pollConnector(demoCtx(), connector.id, {});
    assert.equal(result.error, 'connector_poll_failed');
    assert.equal(result.status, 503);
    assert.equal(result.health.health_code, 'encryption_not_configured');
    assert.equal(getStore().wafConnectors[0].status, 'error');
    assert.ok(getStore().wafConnectors[0].last_error_at);
  });

  it('polls cloudflare via provider worker and stores metadata-only snapshots', async () => {
    freshStore();
    process.env.ASTRANULL_WAF_POSTURE_ENABLED = '1';
    process.env.ASTRANULL_SECRET_ENCRYPTION_KEY = TEST_ENC_KEY_B64;
    const connector = seedConnector();
    seedEncryptedSecret({
      id: connector.secret_id,
      purpose: 'connector',
      name: 'cloudflare-readonly',
      plaintext: 'cf-live-token',
    });

    const result = await wafPosture.pollConnector(demoCtx(), connector.id, {}, {
      prefetchedMetadata: {
        zones: [
          {
            id: 'zone_1',
            name: 'app.example.com',
            security_level: 'high',
            rulesets: [{ phase: 'http_request_firewall', rules: [{ id: 'r1' }] }],
          },
        ],
      },
      maxAttempts: 1,
    });

    assert.equal(result.snapshots.length, 1);
    assert.equal(result.poll_job.status, 'completed');
    assert.equal(result.poll_job.health.status, 'active');
    assert.equal(getStore().wafConnectorSnapshots.length, 1);
    assert.equal(getStore().wafConnectors[0].status, 'active');
    assert.ok(getStore().wafConnectors[0].last_success_at);
    assert.equal(JSON.stringify(result.snapshots).includes('cf-live-token'), false);
  });

  it('keeps manual metadata poll working when snapshots are supplied', async () => {
    freshStore();
    process.env.ASTRANULL_WAF_POSTURE_ENABLED = '1';
    const connector = seedConnector({ secret_id: 'sec_cf_1' });
    const result = await wafPosture.pollConnector(demoCtx(), connector.id, {
      snapshots: [
        {
          snapshot_kind: 'waf_policy',
          resource_ref_hash: 'res_manual_1',
          display_ref: 'manual-zone',
          config_hash: 'cfg_manual_1',
          summary: { hostnames: ['manual.example.com'], policy_mode: 'block', rule_count: 4 },
        },
      ],
    });
    assert.equal(result.error, undefined);
    assert.equal(result.snapshots.length, 1);
    assert.equal(result.snapshots[0].summary.rule_count, 4);
    assert.equal(getStore().wafConnectorSnapshots.length, 1);
  });

  it('validate exposes outbound_polling when secret_id is configured', () => {
    freshStore();
    const connector = seedConnector();
    const validated = wafPosture.validateConnector(demoCtx(), connector.id);
    assert.equal(validated.status, 'active');
    assert.equal(validated.capabilities.outbound_polling, true);
  });
});