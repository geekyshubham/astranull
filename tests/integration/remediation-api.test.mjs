import assert from 'node:assert/strict';
import { after, afterEach, before, describe, it } from 'node:test';
import { loadRuntimeConfig } from '../../src/config.mjs';
import { createServer } from '../../src/server.mjs';
import { getStore } from '../../src/store.mjs';
import { demoHeaders, request } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';

const envSnapshot = { ...process.env };

function restoreEnv() {
  for (const key of Object.keys(process.env)) {
    if (!(key in envSnapshot)) delete process.env[key];
  }
  Object.assign(process.env, envSnapshot);
}

function wafEnabledEnv() {
  return {
    ...process.env,
    ASTRANULL_NO_PERSIST: '1',
    ASTRANULL_WAF_POSTURE_ENABLED: '1',
  };
}

function applyWafEnv() {
  Object.assign(process.env, wafEnabledEnv());
}

function startServer(env = wafEnabledEnv()) {
  const runtimeConfig = loadRuntimeConfig(env);
  const server = createServer({ runtimeConfig, env });
  server.listen(0);
  const { port } = server.address();
  return { server, baseUrl: `http://127.0.0.1:${port}` };
}

async function createWafAsset(baseUrl, headers) {
  const res = await request(baseUrl, 'POST', '/v1/waf/assets', {
    headers,
    body: {
      target_group_id: 'tg_1',
      canonical_url: 'https://remediation-app.example.com',
      owner_hint: 'edge-team',
    },
  });
  assert.equal(res.status, 201);
  return res.json.asset;
}

function seedWafFinding(assetId, tenantId = 'ten_demo') {
  const findingId = 'fnd_remediation_1';
  getStore().findings.push({
    id: findingId,
    tenant_id: tenantId,
    check_id: `waf.posture.${assetId}`,
    target_group_id: 'tg_1',
    status: 'open',
    severity: 'medium',
    title: 'WAF posture underprotected on remediation-app.example.com',
    notes: 'Reason codes: marker_rule_not_blocking.',
    remediation_template: 'waf_posture_remediation',
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  });
  return findingId;
}

function seedOtherTenant() {
  const store = getStore();
  store.tenants.push({ id: 'ten_other', name: 'Other' });
  store.targetGroups.push({
    id: 'tg_other',
    tenant_id: 'ten_other',
    environment_id: 'env_demo',
    name: 'Other TG',
  });
}

describe('WAF action items API feature flag', () => {
  let server;
  let baseUrl;

  before(() => {
    freshStore();
    const env = { ...process.env, ASTRANULL_NO_PERSIST: '1' };
    delete env.ASTRANULL_WAF_POSTURE_ENABLED;
    ({ server, baseUrl } = startServer(env));
  });

  after(() => {
    server?.close();
    restoreEnv();
  });

  it('returns waf_feature_disabled when flag is off', async () => {
    const res = await request(baseUrl, 'GET', '/v1/waf/action-items', {
      headers: demoHeaders('admin'),
    });
    assert.equal(res.status, 404);
    assert.equal(res.json.error, 'waf_feature_disabled');
  });
});

describe('WAF action items API', () => {
  let server;
  let baseUrl;

  before(() => {
    freshStore();
    applyWafEnv();
    ({ server, baseUrl } = startServer());
  });

  after(() => {
    server?.close();
    restoreEnv();
  });

  afterEach(() => {
    freshStore();
    applyWafEnv();
  });

  it('creates an action item from a finding and lists items scoped to tenant', async () => {
    const engineer = demoHeaders('engineer');
    const asset = await createWafAsset(baseUrl, engineer);
    const findingId = seedWafFinding(asset.id);

    const created = await request(baseUrl, 'POST', '/v1/waf/action-items', {
      headers: engineer,
      body: { finding_id: findingId },
    });
    assert.equal(created.status, 201);
    assert.equal(created.json.created, true);
    assert.ok(created.json.action_item.action_item_id);
    assert.equal(created.json.action_item.status, 'open');
    assert.equal(created.json.action_item.asset.display, 'https://remediation-app.example.com');
    assert.equal(created.json.action_item.owner, 'edge-team');

    const list = await request(baseUrl, 'GET', '/v1/waf/action-items', { headers: engineer });
    assert.equal(list.status, 200);
    assert.equal(list.json.items.length, 1);
    assert.equal(list.json.items[0].action_item_id, created.json.action_item.action_item_id);

    seedOtherTenant();
    const otherHeaders = demoHeaders('engineer', 'ten_other', 'usr_other');
    const otherAssetRes = await request(baseUrl, 'POST', '/v1/waf/assets', {
      headers: otherHeaders,
      body: {
        target_group_id: 'tg_other',
        canonical_url: 'https://other-app.example.com',
        owner_hint: 'other-team',
      },
    });
    assert.equal(otherAssetRes.status, 201);
    const otherFindingId = seedWafFinding(otherAssetRes.json.asset.id, 'ten_other');
    await request(baseUrl, 'POST', '/v1/waf/action-items', {
      headers: demoHeaders('engineer', 'ten_other', 'usr_other'),
      body: { finding_id: otherFindingId },
    });

    const scoped = await request(baseUrl, 'GET', '/v1/waf/action-items', { headers: engineer });
    assert.equal(scoped.status, 200);
    assert.equal(scoped.json.items.length, 1);
    assert.equal(scoped.json.items[0].action_item_id, created.json.action_item.action_item_id);
  });

  it('updates action item status via PATCH', async () => {
    const engineer = demoHeaders('engineer');
    const asset = await createWafAsset(baseUrl, engineer);
    const findingId = seedWafFinding(asset.id);

    const created = await request(baseUrl, 'POST', '/v1/waf/action-items', {
      headers: engineer,
      body: { finding_id: findingId },
    });
    const actionItemId = created.json.action_item.action_item_id;

    const patched = await request(baseUrl, 'PATCH', `/v1/waf/action-items/${actionItemId}`, {
      headers: engineer,
      body: { status: 'ticketed', notes: 'Jira WAF-101' },
    });
    assert.equal(patched.status, 200);
    assert.equal(patched.json.action_item.status, 'ticketed');

    const audits = getStore().auditLog.filter(
      (e) => e.action === 'waf.action_item.updated' && e.resource_id === actionItemId,
    );
    assert.ok(audits.length >= 1);
    assert.equal(audits.at(-1).metadata.status, 'ticketed');
  });

  it('delivers action items via dry_run by default without outbound I/O', async () => {
    const engineer = demoHeaders('engineer');
    const asset = await createWafAsset(baseUrl, engineer);
    const findingId = seedWafFinding(asset.id);

    const created = await request(baseUrl, 'POST', '/v1/waf/action-items', {
      headers: engineer,
      body: { finding_id: findingId },
    });
    const actionItemId = created.json.action_item.action_item_id;

    const delivered = await request(
      baseUrl,
      'POST',
      `/v1/waf/action-items/${actionItemId}/deliver`,
      {
        headers: engineer,
        body: { channel: 'webhook' },
      },
    );
    assert.equal(delivered.status, 200);
    assert.equal(delivered.json.delivery.action_item_id, actionItemId);
    assert.equal(delivered.json.delivery.channel, 'webhook');
    assert.equal(delivered.json.delivery.status, 'metadata_only');
    assert.equal(delivered.json.delivery.dry_run, true);
    assert.ok(delivered.json.delivery.payload);

    const audits = getStore().auditLog.filter(
      (e) => e.action === 'waf.action_item.delivered' && e.resource_id === actionItemId,
    );
    assert.equal(audits.length, 1);
    assert.equal(audits[0].metadata.dry_run, true);
    assert.equal(JSON.stringify(delivered.json).includes('ASTRANULL_'), false);
  });

  it('enforces RBAC on write operations', async () => {
    const engineer = demoHeaders('engineer');
    const asset = await createWafAsset(baseUrl, engineer);
    const findingId = seedWafFinding(asset.id);

    const created = await request(baseUrl, 'POST', '/v1/waf/action-items', {
      headers: engineer,
      body: { finding_id: findingId },
    });
    const actionItemId = created.json.action_item.action_item_id;
    const viewer = demoHeaders('viewer', 'ten_demo', 'usr_viewer');

    const list = await request(baseUrl, 'GET', '/v1/waf/action-items', { headers: viewer });
    assert.equal(list.status, 200);
    assert.equal(list.json.items.length, 1);

    const create = await request(baseUrl, 'POST', '/v1/waf/action-items', {
      headers: viewer,
      body: { finding_id: findingId },
    });
    assert.equal(create.status, 403);
    assert.equal(create.json.permission, 'waf:write');

    const patch = await request(baseUrl, 'PATCH', `/v1/waf/action-items/${actionItemId}`, {
      headers: viewer,
      body: { status: 'ticketed' },
    });
    assert.equal(patch.status, 403);
    assert.equal(patch.json.permission, 'waf:write');
  });
});