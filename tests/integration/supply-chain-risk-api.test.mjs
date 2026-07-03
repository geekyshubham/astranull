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
    assert.equal(ticket.json.ticket.phase, 'AP1_ticket_workflow');
    assert.equal(
      ticket.json.ticket.retest_link,
      `/v1/waf/supply-chain/risks?risk_id=${encodeURIComponent(risk.id)}`,
    );

    const fetched = await request(baseUrl, 'GET', `/v1/waf/supply-chain/risks/${risk.id}`, {
      headers: engineer,
    });
    assert.equal(fetched.status, 200);
    assert.equal(fetched.json.risk.phase, 'AP1_ticket_workflow');
  });

  it('reads a single supply chain risk by id and retest query link', async () => {
    const engineer = demoHeaders('engineer');
    const risk = await createRisk(baseUrl, engineer, { hostname: 'single.example.com' });

    const byPath = await request(baseUrl, 'GET', `/v1/waf/supply-chain/risks/${risk.id}`, {
      headers: engineer,
    });
    assert.equal(byPath.status, 200);
    assert.equal(byPath.json.risk.id, risk.id);
    assert.equal(byPath.json.risk.hostname, 'single.example.com');

    const byQuery = await request(
      baseUrl,
      'GET',
      `/v1/waf/supply-chain/risks?risk_id=${encodeURIComponent(risk.id)}`,
      { headers: engineer },
    );
    assert.equal(byQuery.status, 200);
    assert.equal(byQuery.json.risk.id, risk.id);

    const missing = await request(baseUrl, 'GET', '/v1/waf/supply-chain/risks/risk_missing', {
      headers: engineer,
    });
    assert.equal(missing.status, 404);
    assert.equal(missing.json.error, 'supply_chain_risk_not_found');
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

  it('ingests supply chain source batches', async () => {
    const engineer = demoHeaders('engineer');
    const res = await request(baseUrl, 'POST', '/v1/waf/supply-chain/sources/ingest', {
      headers: engineer,
      body: {
        source: 'dangling_cname',
        records: [
          {
            hostname: 'dangling.example.com',
            source_type: 'dangling_cname',
            cname_chain_hash: 'cname_hash_1',
            provider_error_signature_id: 'provider_sig_1',
            connector_confirmation: true,
            observed_at: '2026-07-03T10:00:00.000Z',
          },
        ],
      },
    });
    assert.equal(res.status, 200);
    assert.equal(res.json.ingested, 1);
    assert.equal(res.json.created, 1);
    assert.equal(res.json.results[0].exposure_type, 'dangling_cname');
    assert.ok(res.json.results[0].risk);

    const vendorRes = await request(baseUrl, 'POST', '/v1/waf/supply-chain/sources/ingest', {
      headers: engineer,
      body: {
        source: 'vendor_dependency',
        records: [
          {
            hostname: 'app.example.com',
            source_type: 'vendor_dependency',
            script_host: 'widgets.vendor.example',
            dependency_url_hash: 'dep_hash_2',
            status_code: 404,
            observed_at: '2026-07-03T11:00:00.000Z',
          },
        ],
      },
    });
    assert.equal(vendorRes.status, 200);
    assert.equal(vendorRes.json.created, 1);
    assert.equal(vendorRes.json.results[0].exposure_type, 'vendor_dependency_risk');
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

  it('records AP2 phase authorization after ticket workflow', async () => {
    const engineer = demoHeaders('engineer');
    const admin = demoHeaders('admin');
    const risk = await createRisk(baseUrl, engineer, {
      evidence_summary: {
        cname_chain_hash: 'chain_hash_confirm',
        provider_error_signature_id: 'sig_provider_1',
        data_source: 'dns_cname_chain',
        connector_confirmation: true,
      },
      confidence: 0.85,
      state: 'confirmed',
    });

    const ticket = await request(
      baseUrl,
      'POST',
      `/v1/waf/supply-chain/risks/${risk.id}/ticket`,
      { headers: engineer, body: { owner_hint: 'secops' } },
    );
    assert.equal(ticket.status, 201);

    const denied = await request(
      baseUrl,
      'POST',
      `/v1/waf/supply-chain/risks/${risk.id}/phase-authorization`,
      {
        headers: engineer,
        body: {
          target_phase: 'AP2_manual_custody',
          customer_approval_reference: 'cust-approval-1',
          customer_signed_at: '2026-07-03T12:00:00.000Z',
          custody_ids: ['custody://doc-1'],
          manual_workflow_owner: 'dns-team',
        },
      },
    );
    assert.equal(denied.status, 403);
    assert.equal(denied.json.permission, 'supply_chain:authorize');

    const authorized = await request(
      baseUrl,
      'POST',
      `/v1/waf/supply-chain/risks/${risk.id}/phase-authorization`,
      {
        headers: admin,
        body: {
          target_phase: 'AP2_manual_custody',
          customer_approval_reference: 'cust-approval-1',
          customer_signed_at: '2026-07-03T12:00:00.000Z',
          custody_ids: ['custody://doc-1'],
          manual_workflow_owner: 'dns-team',
        },
      },
    );
    assert.equal(authorized.status, 201);
    assert.equal(authorized.json.risk.phase, 'AP2_manual_custody');
    assert.equal(authorized.json.risk.state, 'customer_custody');
    assert.equal(authorized.json.authorization.target_phase, 'AP2_manual_custody');

    const listed = await request(
      baseUrl,
      'GET',
      `/v1/waf/supply-chain/risks/${risk.id}/phase-authorization`,
      { headers: engineer },
    );
    assert.equal(listed.status, 200);
    assert.equal(listed.json.phase_authorizations.length, 1);
  });

  it('completes AP3 governed active authorization after AP2 manual custody', async () => {
    const engineer = demoHeaders('engineer');
    const admin = demoHeaders('admin');
    const risk = await createRisk(baseUrl, engineer, {
      evidence_summary: {
        cname_chain_hash: 'chain_hash_confirm',
        provider_error_signature_id: 'sig_provider_1',
        data_source: 'dns_cname_chain',
        connector_confirmation: true,
      },
      confidence: 0.85,
      state: 'confirmed',
      hostname: 'governed.example.com',
    });

    const ticket = await request(
      baseUrl,
      'POST',
      `/v1/waf/supply-chain/risks/${risk.id}/ticket`,
      { headers: engineer, body: { owner_hint: 'secops' } },
    );
    assert.equal(ticket.status, 201);

    const ap2 = await request(
      baseUrl,
      'POST',
      `/v1/waf/supply-chain/risks/${risk.id}/phase-authorization`,
      {
        headers: admin,
        body: {
          target_phase: 'AP2_manual_custody',
          customer_approval_reference: 'cust-approval-1',
          customer_signed_at: '2026-07-03T12:00:00.000Z',
          custody_ids: ['custody://doc-1'],
          manual_workflow_owner: 'dns-team',
        },
      },
    );
    assert.equal(ap2.status, 201);
    assert.equal(ap2.json.risk.phase, 'AP2_manual_custody');
    assert.equal(ap2.json.risk.state, 'customer_custody');

    const ap3Denied = await request(
      baseUrl,
      'POST',
      `/v1/waf/supply-chain/risks/${risk.id}/phase-authorization`,
      {
        headers: engineer,
        body: {
          target_phase: 'AP3_governed_active',
          customer_approval_reference: 'cust-approval-2',
          legal_approval_reference: 'legal-approval-1',
          legal_signed_at: '2026-07-03T13:00:00.000Z',
          provider_terms_reference: 'provider-terms-v3',
          custody_ids: ['custody://doc-2'],
          insurance_review_reference: 'insurance-review-1',
          release_back_workflow_reference: 'release-back-runbook-1',
        },
      },
    );
    assert.equal(ap3Denied.status, 403);
    assert.equal(ap3Denied.json.permission, 'supply_chain:authorize');

    const ap3 = await request(
      baseUrl,
      'POST',
      `/v1/waf/supply-chain/risks/${risk.id}/phase-authorization`,
      {
        headers: admin,
        body: {
          target_phase: 'AP3_governed_active',
          customer_approval_reference: 'cust-approval-2',
          legal_approval_reference: 'legal-approval-1',
          legal_signed_at: '2026-07-03T13:00:00.000Z',
          provider_terms_reference: 'provider-terms-v3',
          custody_ids: ['custody://doc-2'],
          insurance_review_reference: 'insurance-review-1',
          release_back_workflow_reference: 'release-back-runbook-1',
          provider_path: 'provider-safe-hold',
        },
      },
    );
    assert.equal(ap3.status, 201);
    assert.equal(ap3.json.risk.phase, 'AP3_governed_active');
    assert.equal(ap3.json.authorization.target_phase, 'AP3_governed_active');
    assert.equal(ap3.json.authorization.authorization.legal_approval_reference, 'legal-approval-1');

    const fetched = await request(baseUrl, 'GET', `/v1/waf/supply-chain/risks/${risk.id}`, {
      headers: engineer,
    });
    assert.equal(fetched.status, 200);
    assert.equal(fetched.json.risk.phase, 'AP3_governed_active');
    assert.equal(fetched.json.risk.phase_authorizations.length, 2);

    const listed = await request(
      baseUrl,
      'GET',
      `/v1/waf/supply-chain/risks/${risk.id}/phase-authorization`,
      { headers: engineer },
    );
    assert.equal(listed.status, 200);
    assert.equal(listed.json.phase, 'AP3_governed_active');
    assert.equal(listed.json.phase_authorizations.length, 2);
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

    const ingest = await request(baseUrl, 'POST', '/v1/waf/supply-chain/sources/ingest', {
      headers: viewer,
      body: {
        source: 'dangling_cname',
        records: [{
          hostname: 'denied.example.com',
          source_type: 'dangling_cname',
          connector_confirmation: true,
          observed_at: '2026-07-03T10:00:00.000Z',
        }],
      },
    });
    assert.equal(ingest.status, 403);
    assert.equal(ingest.json.permission, 'waf:write');

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