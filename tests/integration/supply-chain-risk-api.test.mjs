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

function sampleRiskBody(overrides = {}) {
  return {
    exposure_type: 'dangling_cname',
    hostname: 'orphan.example.com',
    evidence_summary: {
      cname_chain_hash: 'chain_hash_abc',
      data_source: 'dns_cname_chain',
    },
    confidence: 0.8,
    severity: 'high',
    state: 'suspected',
    owner_hint: 'dns-team',
    remediation_steps: ['Review DNS CNAME records.'],
    ...overrides,
  };
}

async function createRisk(baseUrl, headers, overrides = {}) {
  const res = await request(baseUrl, 'POST', '/v1/waf/supply-chain/risks', {
    headers,
    body: sampleRiskBody(overrides),
  });
  assert.equal(res.status, 201);
  return res.json.risk;
}

function seedOtherTenant() {
  const store = getStore();
  store.tenants.push({ id: 'ten_other', name: 'Other' });
}

describe('supply chain risk API feature flag', () => {
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
    const res = await request(baseUrl, 'GET', '/v1/waf/supply-chain/risks', {
      headers: demoHeaders('admin'),
    });
    assert.equal(res.status, 404);
    assert.equal(res.json.error, 'waf_feature_disabled');
  });
});

describe('supply chain risk API', () => {
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

  it('creates and lists supply chain risks scoped to tenant', async () => {
    const engineer = demoHeaders('engineer');
    const risk = await createRisk(baseUrl, engineer);
    assert.equal(risk.hostname, 'orphan.example.com');
    assert.equal(risk.exposure_type, 'dangling_cname');
    assert.equal(risk.state, 'suspected');

    const list = await request(baseUrl, 'GET', '/v1/waf/supply-chain/risks', { headers: engineer });
    assert.equal(list.status, 200);
    assert.equal(list.json.items.length, 1);
    assert.equal(list.json.items[0].id, risk.id);

    seedOtherTenant();
    await createRisk(baseUrl, demoHeaders('engineer', 'ten_other', 'usr_other'), {
      hostname: 'other.example.com',
    });

    const scoped = await request(baseUrl, 'GET', '/v1/waf/supply-chain/risks', { headers: engineer });
    assert.equal(scoped.status, 200);
    assert.equal(scoped.json.items.length, 1);
    assert.equal(scoped.json.items[0].hostname, 'orphan.example.com');
  });

  it('updates risk state via PATCH', async () => {
    const engineer = demoHeaders('engineer');
    const risk = await createRisk(baseUrl, engineer, {
      evidence_summary: {
        cname_chain_hash: 'chain_hash_confirm',
        provider_error_signature_id: 'sig_provider_1',
        data_source: 'dns_cname_chain',
        connector_confirmation: true,
      },
      confidence: 0.85,
    });

    const patched = await request(
      baseUrl,
      'PATCH',
      `/v1/waf/supply-chain/risks/${risk.id}/state`,
      {
        headers: engineer,
        body: { state: 'confirmed', owner_hint: 'platform-team' },
      },
    );
    assert.equal(patched.status, 200);
    assert.equal(patched.json.risk.state, 'confirmed');
    assert.equal(patched.json.risk.owner_hint, 'platform-team');
  });

  it('creates a remediation ticket for a risk', async () => {
    const engineer = demoHeaders('engineer');
    const risk = await createRisk(baseUrl, engineer);

    const ticket = await request(
      baseUrl,
      'POST',
      `/v1/waf/supply-chain/risks/${risk.id}/ticket`,
      { headers: engineer, body: { owner_hint: 'secops' } },
    );
    assert.equal(ticket.status, 201);
    assert.ok(ticket.json.ticket.id);
    assert.equal(ticket.json.ticket.hostname, risk.hostname);
    assert.equal(ticket.json.ticket.owner_hint, 'secops');
    assert.match(ticket.json.ticket.retest_link, new RegExp(`/v1/supply-chain/risks/${risk.id}/retest`));
  });

  it('assesses dangling CNAME risk', async () => {
    const engineer = demoHeaders('engineer');
    const res = await request(baseUrl, 'POST', '/v1/waf/supply-chain/assess/dangling-cname', {
      headers: engineer,
      body: {
        hostname: 'dangling.example.com',
        cname_chain_hash: 'cname_hash_1',
        provider_error_signature_id: 'provider_sig_1',
        connector_confirmation: true,
      },
    });
    assert.equal(res.status, 200);
    assert.equal(res.json.assessed, true);
    assert.equal(res.json.created, true);
    assert.ok(res.json.risk);
    assert.equal(res.json.risk.exposure_type, 'dangling_cname');
    assert.equal(res.json.risk.hostname, 'dangling.example.com');
  });

  it('assesses dangling dependency risk', async () => {
    const engineer = demoHeaders('engineer');
    const res = await request(baseUrl, 'POST', '/v1/waf/supply-chain/assess/dangling-dependency', {
      headers: engineer,
      body: {
        hostname: 'app.example.com',
        script_host: 'cdn.thirdparty.com',
        status_code: 404,
        dependency_url_hash: 'dep_hash_1',
      },
    });
    assert.equal(res.status, 200);
    assert.equal(res.json.assessed, true);
    assert.equal(res.json.created, true);
    assert.ok(res.json.risk);
    assert.equal(res.json.risk.exposure_type, 'dangling_script_inclusion');
    assert.equal(res.json.risk.hostname, 'app.example.com');
  });

  it('enforces RBAC on write operations', async () => {
    const engineer = demoHeaders('engineer');
    const risk = await createRisk(baseUrl, engineer);
    const viewer = demoHeaders('viewer', 'ten_demo', 'usr_viewer');

    const list = await request(baseUrl, 'GET', '/v1/waf/supply-chain/risks', { headers: viewer });
    assert.equal(list.status, 200);

    const create = await request(baseUrl, 'POST', '/v1/waf/supply-chain/risks', {
      headers: viewer,
      body: sampleRiskBody({ hostname: 'denied.example.com' }),
    });
    assert.equal(create.status, 403);
    assert.equal(create.json.permission, 'waf:write');

    const assess = await request(baseUrl, 'POST', '/v1/waf/supply-chain/assess/dangling-cname', {
      headers: viewer,
      body: { hostname: 'denied.example.com', connector_confirmation: true },
    });
    assert.equal(assess.status, 403);
    assert.equal(assess.json.permission, 'waf:write');

    const patch = await request(
      baseUrl,
      'PATCH',
      `/v1/waf/supply-chain/risks/${risk.id}/state`,
      { headers: viewer, body: { state: 'confirmed' } },
    );
    assert.equal(patch.status, 403);
    assert.equal(patch.json.permission, 'waf:write');
  });
});