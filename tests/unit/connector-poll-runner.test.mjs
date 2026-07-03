import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import {
  buildConnectorPollRunnerSummary,
  isOutboundPollEligibleConnector,
  listEligibleConnectorsFromStore,

  parseConnectorPollRunnerArgs,
  parseTenantIdsFromJson,
  redactConnectorPollRunnerMessage,
  resolveConnectorPollConcurrency,
  resolveConnectorPollRunnerConfig,
  resolveConnectorPollTenantIds,
  resolveTenantIdsFromConnectors,
  runConnectorPollRunner,
  runDevJsonConnectorPolls,
  runPostgresConnectorPolls,
  runWithBoundedConcurrency,
  summarizeTenantConnectorPollScope,
  toMetadataOnlyConnectorPollResult,
  toMetadataOnlyPollOutcome,
} from '../../scripts/connector-poll-runner.mjs';
import { hashRef } from '../../src/lib/connectorProviders/common.mjs';
import { buildSecretAad, encryptSecret, loadSecretEncryptionKey } from '../../src/lib/secrets.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';

const TEST_ENC_KEY_B64 = randomBytes(32).toString('base64');
const tempDirs = [];
const envSnapshot = { ...process.env };

function restoreEnv() {
  for (const key of Object.keys(process.env)) {
    if (!(key in envSnapshot)) delete process.env[key];
  }
  Object.assign(process.env, envSnapshot);
}

function tempDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-connector-poll-runner-'));
  tempDirs.push(dir);
  return dir;
}

function wafEnabledEnv() {
  return {
    ...process.env,
    ASTRANULL_NO_PERSIST: '1',
    ASTRANULL_WAF_POSTURE_ENABLED: '1',
  };
}

function ensureConnectorStore() {
  const store = getStore();
  if (!Array.isArray(store.wafConnectors)) store.wafConnectors = [];
  if (!Array.isArray(store.wafConnectorSnapshots)) store.wafConnectorSnapshots = [];
  return store;
}

function seedConnector(overrides = {}) {
  const store = ensureConnectorStore();
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
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop(), { recursive: true, force: true });
  }
});

describe('connector poll runner args', () => {
  it('parses defaults when only argv0/argv1 are present', () => {
    assert.deepEqual(parseConnectorPollRunnerArgs(['node', 'connector-poll-runner.mjs']), {
      tenantId: null,
      tenantIdsFile: null,
      allTenants: false,
      concurrency: null,
      dryRun: false,
      out: null,
      help: false,
    });
  });

  it('parses tenant, dry-run, all-tenants, concurrency, out, and help', () => {
    assert.deepEqual(
      parseConnectorPollRunnerArgs([
        'node',
        'connector-poll-runner.mjs',
        '--tenant-id',
        'ten_alpha',
        '--dry-run',
        '--all-tenants',
        '--concurrency',
        '2',
        '--out',
        '/tmp/summary.json',
        '--help',
      ]),
      {
        tenantId: 'ten_alpha',
        tenantIdsFile: null,
        allTenants: true,
        concurrency: 2,
        dryRun: true,
        out: '/tmp/summary.json',
        help: true,
      },
    );
  });

  it('rejects unknown arguments and missing values', () => {
    assert.throws(
      () => parseConnectorPollRunnerArgs(['node', 'script.mjs', '--tenant-id']),
      /--tenant-id requires a value/,
    );
    assert.throws(
      () => parseConnectorPollRunnerArgs(['node', 'script.mjs', '--bogus']),
      /unknown argument/,
    );
  });
});

describe('connector poll runner config', () => {
  it('requires WAF posture feature enabled', () => {
    const config = resolveConnectorPollRunnerConfig(
      { ASTRANULL_WAF_POSTURE_ENABLED: '0' },
      parseConnectorPollRunnerArgs(['node', 'script.mjs', '--tenant-id', 'ten_a']),
    );
    assert.equal(config.ok, false);
    assert.match(config.message, /WAF posture feature must be enabled/);
  });

  it('resolves dev-json mode without database URL', () => {
    const config = resolveConnectorPollRunnerConfig(
      wafEnabledEnv(),
      parseConnectorPollRunnerArgs(['node', 'script.mjs', '--tenant-id', 'ten_a']),
    );
    assert.equal(config.ok, true);
    assert.equal(config.persistenceMode, 'dev-json');
    assert.deepEqual(config.tenantIds, ['ten_a']);
    assert.equal(config.allTenants, false);
    assert.equal(config.concurrency, 4);
    assert.equal(config.maxAttempts, 3);
  });

  it('defaults to all tenants in dev-json when tenant scope is omitted', () => {
    const config = resolveConnectorPollRunnerConfig(
      wafEnabledEnv(),
      parseConnectorPollRunnerArgs(['node', 'script.mjs']),
    );
    assert.equal(config.ok, true);
    assert.equal(config.tenantIds, null);
    assert.equal(config.allTenants, true);
  });

  it('requires explicit tenant scope in postgres mode', () => {
    const config = resolveConnectorPollRunnerConfig(
      {
        ...wafEnabledEnv(),
        ASTRANULL_DATABASE_URL: 'postgresql://user:secret@db.example.invalid/astranull',
      },
      parseConnectorPollRunnerArgs(['node', 'script.mjs']),
    );
    assert.equal(config.ok, false);
    assert.match(config.message, /explicit tenant scope/i);
  });

  it('selects postgres mode when database URL is set', () => {
    const config = resolveConnectorPollRunnerConfig(
      {
        ...wafEnabledEnv(),
        ASTRANULL_DATABASE_URL: 'postgresql://user:secret@db.example.invalid/astranull',
      },
      parseConnectorPollRunnerArgs(['node', 'script.mjs', '--tenant-id', 'ten_a']),
    );
    assert.equal(config.ok, true);
    assert.equal(config.persistenceMode, 'postgres');
  });

  it('honors env and CLI concurrency overrides', () => {
    assert.equal(resolveConnectorPollConcurrency({}), 4);
    assert.equal(resolveConnectorPollConcurrency({ ASTRANULL_CONNECTOR_POLL_CONCURRENCY: '8' }), 8);
    assert.equal(resolveConnectorPollConcurrency({}, 2), 2);
  });
});

describe('connector poll runner eligibility', () => {
  it('lists only outbound-eligible enabled connectors', () => {
    const store = {
      wafConnectors: [
        {
          id: 'conn_ok',
          tenant_id: 'ten_demo',
          provider: 'cloudflare',
          secret_id: 'sec_1',
          status: 'active',
          config_json: { read_only: true },
        },
        {
          id: 'conn_disabled',
          tenant_id: 'ten_demo',
          provider: 'cloudflare',
          secret_id: 'sec_2',
          status: 'disabled',
          config_json: { read_only: true },
        },
        {
          id: 'conn_manual',
          tenant_id: 'ten_demo',
          provider: 'generic_waf',
          secret_id: 'sec_3',
          status: 'active',
          config_json: { read_only: true },
        },
      ],
    };

    const eligible = listEligibleConnectorsFromStore(store, ['ten_demo']);
    assert.equal(eligible.length, 1);
    assert.equal(eligible[0].id, 'conn_ok');
    assert.equal(isOutboundPollEligibleConnector(eligible[0]), true);
  });

  it('summarizes tenant connector poll scope', () => {
    const store = {
      wafConnectors: [
        {
          id: 'conn_cf',
          tenant_id: 'ten_demo',
          provider: 'cloudflare',
          secret_id: 'sec_1',
          status: 'active',
          config_json: { read_only: true },
        },
        {
          id: 'conn_aws',
          tenant_id: 'ten_demo',
          provider: 'aws_waf',
          secret_id: 'sec_2',
          status: 'active',
          config_json: { read_only: true },
        },
      ],
    };

    const scope = summarizeTenantConnectorPollScope(store, 'ten_demo');
    assert.equal(scope.eligible_connectors_count, 2);
    assert.deepEqual(scope.providers, ['aws_waf', 'cloudflare']);
  });
});

describe('connector poll runner bounded concurrency', () => {
  it('limits concurrent workers', async () => {
    let active = 0;
    let maxActive = 0;
    const items = [1, 2, 3, 4, 5, 6];

    await runWithBoundedConcurrency(items, 2, async () => {
      active += 1;
      maxActive = Math.max(maxActive, active);
      await new Promise((resolve) => setTimeout(resolve, 20));
      active -= 1;
      return true;
    });

    assert.ok(maxActive <= 2);
  });
});

describe('connector poll runner dev-json execution', () => {
  it('dry-run reports scope without outbound provider calls', async () => {
    Object.assign(process.env, wafEnabledEnv());
    freshStore();
    seedConnector();
    seedConnector({
      id: 'conn_aws_1',
      provider: 'aws_waf',
      secret_id: 'sec_aws_1',
      tenant_id: 'ten_beta',
    });

    const connectorResults = await runDevJsonConnectorPolls({
      tenantIds: [],
      dryRun: true,
      concurrency: 2,
      maxAttempts: 1,
    });

    assert.equal(connectorResults.length, 2);
    assert.equal(connectorResults[0].dry_run, true);
    assert.equal(connectorResults[0].scope.eligible_connectors_count, 1);
    assert.equal(getStore().wafConnectorSnapshots.length, 0);
  });

  it('polls eligible connectors and records metadata-only outcomes', async () => {
    Object.assign(process.env, wafEnabledEnv());
    process.env.ASTRANULL_SECRET_ENCRYPTION_KEY = TEST_ENC_KEY_B64;
    freshStore();
    const connector = seedConnector();
    seedEncryptedSecret({
      id: connector.secret_id,
      purpose: 'connector',
      name: 'cloudflare-readonly',
      plaintext: 'cf-live-token',
    });

    const connectorResults = await runDevJsonConnectorPolls({
      tenantIds: ['ten_demo'],
      dryRun: false,
      concurrency: 2,
      maxAttempts: 1,
      pollConnectorFn: async (ctx, id, body, options) => {
        const { pollConnector } = await import('../../src/services/wafPosture.mjs');
        return pollConnector(ctx, id, body, {
          ...options,
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
        });
      },
    });

    assert.equal(connectorResults.length, 1);
    assert.equal(connectorResults[0].poll_result.snapshot_count, 1);
    assert.equal(connectorResults[0].poll_result.health_status, 'active');
    assert.equal(getStore().wafConnectorSnapshots.length, 1);
    assert.ok(!JSON.stringify(connectorResults[0]).includes('cf-live-token'));
  });

  it('records metadata-only health updates when outbound poll fails', async () => {
    Object.assign(process.env, wafEnabledEnv());
    freshStore();
    seedConnector();

    const connectorResults = await runDevJsonConnectorPolls({
      tenantIds: ['ten_demo'],
      dryRun: false,
      concurrency: 1,
      maxAttempts: 1,
    });

    assert.equal(connectorResults.length, 1);
    assert.equal(connectorResults[0].error, 'connector_poll_failed');
    assert.equal(connectorResults[0].poll_result.health_code, 'encryption_not_configured');
    assert.equal(getStore().wafConnectors[0].status, 'error');
  });
});

describe('connector poll runner summary artifact', () => {
  it('builds metadata-only summary and writes output file', async () => {
    Object.assign(process.env, wafEnabledEnv());
    freshStore();
    seedConnector();

    const outPath = path.join(tempDir(), 'connector-poll-run.json');
    const { summary, exitCode } = await runConnectorPollRunner(
      wafEnabledEnv(),
      {
        dryRun: false,
        tenantIds: ['ten_demo'],
        allTenants: false,
        out: outPath,
        persistenceMode: 'dev-json',
        concurrency: 2,
        maxAttempts: 1,
      },
    );

    assert.equal(exitCode, 1);
    assert.equal(summary.artifact_type, 'connector_poll_runtime_run');
    assert.equal(summary.persistence_mode, 'dev-json');
    assert.equal(summary.connector_count, 1);
    assert.equal(summary.connectors_failed, 1);
    const written = JSON.parse(readFileSync(outPath, 'utf8'));
    assert.equal(written.connectors_failed, 1);
    assert.ok(!JSON.stringify(written).includes('postgresql://'));
    assert.ok(!JSON.stringify(written).includes('api_token'));
  });

  it('redacts database URLs from error messages', () => {
    const redacted = redactConnectorPollRunnerMessage(
      new Error('connect failed postgresql://user:secret@db.example.invalid/astranull'),
      { ASTRANULL_DATABASE_URL: 'postgresql://user:secret@db.example.invalid/astranull' },
    );
    assert.ok(!String(redacted).includes('postgresql://user:secret'));
  });
});

describe('connector poll runner postgres tenant scope', () => {
  it('returns explicit tenant ids for postgres mode', () => {
    const tenantIds = resolveConnectorPollTenantIds(['ten_explicit'], 'postgres');
    assert.deepEqual(tenantIds, ['ten_explicit']);
  });

  it('fails closed for postgres mode without tenant scope', () => {
    assert.throws(
      () => resolveConnectorPollTenantIds([], 'postgres'),
      /explicit tenant scope/i,
    );
  });

  it('polls every outbound provider in postgres apply mode', async () => {
    const pollCalls = [];
    const connectorResults = await runPostgresConnectorPolls({
      env: { ASTRANULL_DATABASE_URL: 'postgresql://user:secret@db.example.invalid/astranull' },
      tenantIds: ['ten_providers'],
      dryRun: false,
      concurrency: 2,
      maxAttempts: 1,
      createPostgresRuntimeFn: async () => ({
        pool: { query: async () => ({ rows: [] }) },
        services: {
          wafPosture: {
            listConnectors: async () => [
              {
                id: 'conn_cf',
                tenant_id: 'ten_providers',
                provider: 'cloudflare',
                secret_id: 'sec_cf',
                status: 'active',
                config_json: { read_only: true },
              },
              {
                id: 'conn_aws',
                tenant_id: 'ten_providers',
                provider: 'aws_waf',
                secret_id: 'sec_aws',
                status: 'active',
                config_json: { read_only: true, scope: 'regional' },
              },
            ],
            pollConnector: async (_ctx, connectorId) => {
              pollCalls.push(connectorId);
              return {
                poll_job: {
                  status: 'completed',
                  snapshot_count: 1,
                  health: { status: 'active', health_code: 'active', attempts: 1 },
                },
                snapshots: [{ id: `snap_${connectorId}` }],
              };
            },
          },
        },
        close: async () => {},
      }),
    });

    assert.equal(connectorResults.length, 2);
    assert.deepEqual(
      connectorResults.map((row) => row.provider).sort(),
      ['aws_waf', 'cloudflare'],
    );
    assert.equal(pollCalls.length, 2);
    assert.deepEqual(pollCalls.sort(), ['conn_aws', 'conn_cf']);
    assert.equal(
      connectorResults.every((row) => row.poll_result?.snapshot_count === 1),
      true,
    );
  });

  it('fails closed for postgres dry-run without explicit tenant scope', async () => {
    await assert.rejects(
      () => runPostgresConnectorPolls({
        env: { ASTRANULL_DATABASE_URL: 'postgresql://user:secret@db.example.invalid/astranull' },
        tenantIds: [],
        dryRun: true,
        concurrency: 2,
        maxAttempts: 1,
        createPostgresRuntimeFn: async () => ({
          pool: {
            query: async () => {
              throw new Error('pool query should not run without explicit tenant scope');
            },
          },
          services: { wafPosture: { listConnectors: async () => [], pollConnector: async () => ({}) } },
          close: async () => {},
        }),
      }),
      /explicit tenant scope/i,
    );
  });
});

describe('connector poll runner helpers', () => {
  it('parses tenant id file forms', () => {
    assert.deepEqual(parseTenantIdsFromJson(['ten_a', ' ten_b ']), ['ten_a', 'ten_b']);
    assert.deepEqual(parseTenantIdsFromJson({ tenant_ids: ['ten_x'] }), ['ten_x']);
  });

  it('resolves tenant ids from eligible connectors', () => {
    const tenantIds = resolveTenantIdsFromConnectors([], {
      wafConnectors: [
        {
          tenant_id: 'ten_a',
          provider: 'cloudflare',
          secret_id: 'sec_1',
          status: 'active',
          config_json: { read_only: true },
        },
        {
          tenant_id: 'ten_b',
          provider: 'aws_waf',
          secret_id: 'sec_2',
          status: 'active',
          config_json: { read_only: true },
        },
      ],
    });
    assert.deepEqual(tenantIds.sort(), ['ten_a', 'ten_b']);
  });

  it('strips forbidden fields from poll outcome summaries', () => {
    const summary = toMetadataOnlyPollOutcome({
      poll_job: {
        status: 'completed',
        snapshot_count: 2,
        health: { status: 'active', health_code: 'active', attempts: 1 },
      },
      snapshots: [{ display_ref: 'zone.example.com' }],
      secret: 'must-not-appear',
    });
    assert.equal(summary.snapshot_count, 2);
    assert.equal(summary.secret, undefined);
  });

  it('builds dry-run summary without polled connectors', () => {
    const summary = buildConnectorPollRunnerSummary({
      dryRun: true,
      connectorResults: [{
        tenant_id: 'ten_demo',
        connector_id: null,
        provider: null,
        dry_run: true,
        scope: { tenant_id: 'ten_demo', eligible_connectors_count: 1, providers: ['cloudflare'] },
        poll_result: null,
      }],
      startedAt: '2026-06-01T00:00:00.000Z',
      finishedAt: '2026-06-01T00:00:01.000Z',
      persistenceMode: 'dev-json',
      concurrency: 4,
    });
    assert.equal(summary.dry_run, true);
    assert.equal(summary.connectors_polled, 0);
    assert.equal(summary.total_snapshots, 0);
    assert.equal(toMetadataOnlyConnectorPollResult(summary.connectors[0]).scope.eligible_connectors_count, 1);
  });
});