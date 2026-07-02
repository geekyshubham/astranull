import assert from 'node:assert/strict';
import { after, afterEach, before, describe, it } from 'node:test';
import { loadRuntimeConfig } from '../../src/config.mjs';
import {
  buildSiemEventPayload,
  createActionItem,
  groupFindings,
  REMEDIATION_CONNECTOR_TYPES,
  validateActionItem,
} from '../../src/contracts/wafPosture.mjs';
import { createServer } from '../../src/server.mjs';
import * as wafPosture from '../../src/services/wafPosture.mjs';
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

function startServer(env = wafEnabledEnv()) {
  const runtimeConfig = loadRuntimeConfig(env);
  const server = createServer({ runtimeConfig, env });
  server.listen(0);
  const { port } = server.address();
  return { server, baseUrl: `http://127.0.0.1:${port}` };
}

async function createDemoAsset(baseUrl, headers) {
  const created = await request(baseUrl, 'POST', '/v1/waf/assets', {
    headers,
    body: {
      target_group_id: 'tg_1',
      canonical_url: 'https://waf-app.example.com',
      owner_hint: 'edge-team',
    },
  });
  assert.equal(created.status, 201);
  return created.json.asset;
}

async function createBoundSafeTestRun(baseUrl, headers) {
  const runRes = await request(baseUrl, 'POST', '/v1/test-runs', {
    headers,
    body: {
      check_id: 'waf.marker_rule.safe',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
    },
  });
  assert.equal(runRes.status, 201);
  return runRes.json.run;
}

function clearProbeEventsForRun(testRunId) {
  const store = getStore();
  store.events = store.events.filter(
    (e) => !(e.test_run_id === testRunId && e.signal_type === 'probe_result'),
  );
}

function injectMetadataProbeEvent({ testRunId, nonceHash, externalResult, metadata = {} }) {
  const store = getStore();
  const probeId = `evt_probe_${nonceHash}`;
  store.events.push({
    id: probeId,
    tenant_id: 'ten_demo',
    test_run_id: testRunId,
    target_id: 'tgt_1',
    check_id: 'waf.marker_rule.safe',
    source: 'probe_worker',
    signal_type: 'probe_result',
    timestamp: new Date().toISOString(),
    nonce_hash: nonceHash,
    metadata: { external_result: externalResult, ...metadata },
  });
  return probeId;
}

const FORBIDDEN_FINDING_TERMS = [
  'raw_payload',
  'headers',
  'exploit',
  'cookie',
  'secret',
  'token',
];

function assertSerializedSafe(value, label = 'payload') {
  const serialized = JSON.stringify(value).toLowerCase();
  for (const term of FORBIDDEN_FINDING_TERMS) {
    assert.ok(
      !serialized.includes(term),
      `${label} must not serialize forbidden term: ${term}`,
    );
  }
}

function assertFindingSerializedSafe(finding) {
  assertSerializedSafe(finding, 'finding');
}

function demoCtx(role = 'engineer', tenantId = 'ten_demo', userId = 'usr_eng') {
  return { tenantId, userId, role };
}

function openWafPostureFindingsForAsset(assetId) {
  const checkId = `waf.posture.${assetId}`;
  return getStore().findings.filter(
    (f) => f.tenant_id === 'ten_demo' && f.check_id === checkId && f.status === 'open',
  );
}

function openWafDriftEventsForAsset(assetId, driftType = null) {
  return getStore().wafDriftEvents.filter(
    (e) =>
      e.tenant_id === 'ten_demo'
      && e.waf_asset_id === assetId
      && e.status === 'open'
      && (driftType === null || e.drift_type === driftType),
  );
}

async function finalizeProtectedPosture(baseUrl, headers, asset) {
  const validation = await request(baseUrl, 'POST', '/v1/waf/validations', {
    headers,
    body: { waf_asset_id: asset.id, modes: ['marker'] },
  });
  assert.equal(validation.status, 201);
  const runId = validation.json.validation_run.id;
  const finalize = await request(baseUrl, 'POST', `/v1/waf/validations/${runId}/finalize`, {
    headers,
    body: {
      waf_detected: true,
      validation_passed: true,
      scenario_results: [
        {
          scenario_family: 'marker',
          passed: true,
          observed_action: 'block',
          evidence_summary: { request_id: 'req_protected', blocked: true },
        },
      ],
    },
  });
  assert.equal(finalize.status, 200);
  assert.equal(finalize.json.posture.status, 'protected');
  return { validationRunId: runId, posture: finalize.json.posture };
}

async function finalizeUnderprotectedMarkerLeak(baseUrl, headers, asset, { safeRun: existingSafeRun } = {}) {
  const safeRun = existingSafeRun ?? (await createBoundSafeTestRun(baseUrl, headers));
  clearProbeEventsForRun(safeRun.id);
  const nonceHash = safeRun.correlation?.nonce_hash ?? 'nonce_marker_leak';
  injectMetadataProbeEvent({
    testRunId: safeRun.id,
    nonceHash,
    externalResult: 'blocked',
  });
  injectMetadataAgentObservation({
    testRunId: safeRun.id,
    nonceHash,
    metadata: { waf_marker: true, marker_type: 'header' },
  });

  const validation = await request(baseUrl, 'POST', '/v1/waf/validations', {
    headers,
    body: { waf_asset_id: asset.id, modes: ['marker'], test_run_id: safeRun.id },
  });
  assert.equal(validation.status, 201);
  const runId = validation.json.validation_run.id;

  const finalize = await request(baseUrl, 'POST', `/v1/waf/validations/${runId}/finalize`, {
    headers,
    body: {},
  });
  assert.equal(finalize.status, 200);
  assert.ok(['underprotected', 'unprotected'].includes(finalize.json.posture.status));
  return {
    validationRunId: runId,
    safeRunId: safeRun.id,
    safeRun,
    posture: finalize.json.posture,
  };
}

function injectMetadataAgentObservation({ testRunId, nonceHash, metadata = {} }) {
  const store = getStore();
  const agentId = `evt_agent_${nonceHash}`;
  store.events.push({
    id: agentId,
    tenant_id: 'ten_demo',
    test_run_id: testRunId,
    target_id: 'tgt_1',
    check_id: 'waf.marker_rule.safe',
    agent_id: 'ag_waf_test',
    source: 'agent',
    signal_type: 'agent_observation',
    timestamp: new Date().toISOString(),
    nonce_hash: nonceHash,
    metadata,
  });
  return agentId;
}

describe('WAF posture API feature flag', () => {
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
    const res = await request(baseUrl, 'GET', '/v1/waf/assets', {
      headers: demoHeaders('admin'),
    });
    assert.equal(res.status, 404);
    assert.equal(res.json.error, 'waf_feature_disabled');
  });

  it('returns waf_feature_disabled for connectors when flag is off', async () => {
    const res = await request(baseUrl, 'GET', '/v1/connectors', {
      headers: demoHeaders('admin'),
    });
    assert.equal(res.status, 404);
    assert.equal(res.json.error, 'waf_feature_disabled');
  });
});

describe('WAF posture API', () => {
  let server;
  let baseUrl;

  before(() => {
    freshStore();
    ({ server, baseUrl } = startServer());
  });

  after(() => {
    server?.close();
    restoreEnv();
  });

  afterEach(() => {
    freshStore();
  });

  it('lets viewers read but not create or run validations', async () => {
    const engineer = demoHeaders('engineer', 'ten_demo', 'usr_eng');
    const asset = await createDemoAsset(baseUrl, engineer);

    const viewer = demoHeaders('viewer', 'ten_demo', 'usr_viewer');
    const list = await request(baseUrl, 'GET', '/v1/waf/assets', { headers: viewer });
    assert.equal(list.status, 200);
    assert.equal(list.json.items.length, 1);

    const create = await request(baseUrl, 'POST', '/v1/waf/assets', {
      headers: viewer,
      body: {
        target_group_id: 'tg_1',
        canonical_url: 'https://blocked.example.com',
      },
    });
    assert.equal(create.status, 403);
    assert.equal(create.json.permission, 'waf:write');

    const run = await request(baseUrl, 'POST', '/v1/waf/validations', {
      headers: viewer,
      body: { waf_asset_id: asset.id, modes: ['marker'] },
    });
    assert.equal(run.status, 403);
    assert.equal(run.json.permission, 'waf:run');
  });

  it('lets engineers create assets and safe validation runs', async () => {
    const engineer = demoHeaders('engineer');
    const asset = await createDemoAsset(baseUrl, engineer);

    const validation = await request(baseUrl, 'POST', '/v1/waf/validations', {
      headers: engineer,
      body: {
        waf_asset_id: asset.id,
        modes: ['marker'],
        probe_profile: { max_requests: 2, timeout_ms: 2000 },
        marker_profile: { marker_type: 'header', expected_action: 'block' },
      },
    });
    assert.equal(validation.status, 201);
    assert.equal(validation.json.validation_run.status, 'planned');
    assert.deepEqual(validation.json.validation_run.safety_profile_json.modes, ['marker']);
    assert.equal(validation.json.validation_run.safety_profile_json.probe_profile.max_requests, 2);
  });

  it('rejects unsafe finalize payloads and does not persist evidence', async () => {
    const engineer = demoHeaders('engineer');
    const asset = await createDemoAsset(baseUrl, engineer);
    const validation = await request(baseUrl, 'POST', '/v1/waf/validations', {
      headers: engineer,
      body: { waf_asset_id: asset.id, modes: ['marker'] },
    });
    const runId = validation.json.validation_run.id;

    const beforeSnaps = getStore().wafPostureSnapshots?.length ?? 0;
    const beforeScenarios = getStore().wafScenarioResults?.length ?? 0;

    const finalize = await request(baseUrl, 'POST', `/v1/waf/validations/${runId}/finalize`, {
      headers: engineer,
      body: {
        waf_detected: true,
        validation_passed: true,
        scenario_results: [
          {
            scenario_family: 'marker',
            evidence_summary: { request_id: 'req_1', raw_payload: 'blocked' },
          },
        ],
      },
    });
    assert.equal(finalize.status, 400);
    assert.equal(finalize.json.error, 'unsafe_waf_evidence');
    assert.equal(getStore().wafPostureSnapshots?.length ?? 0, beforeSnaps);
    assert.equal(getStore().wafScenarioResults?.length ?? 0, beforeScenarios);
  });

  it('rejects naked protected finalize without corroborating scenario evidence', async () => {
    const engineer = demoHeaders('engineer');
    const asset = await createDemoAsset(baseUrl, engineer);
    const validation = await request(baseUrl, 'POST', '/v1/waf/validations', {
      headers: engineer,
      body: { waf_asset_id: asset.id, modes: ['marker'] },
    });
    const runId = validation.json.validation_run.id;

    const beforeSnaps = getStore().wafPostureSnapshots?.length ?? 0;
    const beforeScenarios = getStore().wafScenarioResults?.length ?? 0;

    const finalize = await request(baseUrl, 'POST', `/v1/waf/validations/${runId}/finalize`, {
      headers: engineer,
      body: {
        waf_detected: true,
        validation_passed: true,
      },
    });
    assert.equal(finalize.status, 400);
    assert.equal(finalize.json.error, 'waf_validation_evidence_required');
    assert.equal(getStore().wafPostureSnapshots?.length ?? 0, beforeSnaps);
    assert.equal(getStore().wafScenarioResults?.length ?? 0, beforeScenarios);
  });

  it('finalizes protected posture when WAF is detected and validation passes', async () => {
    const engineer = demoHeaders('engineer');
    const asset = await createDemoAsset(baseUrl, engineer);
    const validation = await request(baseUrl, 'POST', '/v1/waf/validations', {
      headers: engineer,
      body: { waf_asset_id: asset.id, modes: ['marker'] },
    });
    const runId = validation.json.validation_run.id;

    const finalize = await request(baseUrl, 'POST', `/v1/waf/validations/${runId}/finalize`, {
      headers: engineer,
      body: {
        waf_detected: true,
        validation_passed: true,
        scenario_results: [
          {
            scenario_family: 'marker',
            passed: true,
            observed_action: 'block',
            evidence_summary: { request_id: 'req_ok', blocked: true },
          },
        ],
      },
    });
    assert.equal(finalize.status, 200);
    assert.equal(finalize.json.posture.status, 'protected');

    const fetched = await request(baseUrl, 'GET', `/v1/waf/assets/${asset.id}`, {
      headers: engineer,
    });
    assert.equal(fetched.status, 200);
    assert.equal(fetched.json.current_posture.status, 'protected');
    assert.equal(fetched.json.current_posture.is_current, true);

    const coverage = await request(baseUrl, 'GET', '/v1/waf/coverage', { headers: engineer });
    assert.equal(coverage.status, 200);
    assert.equal(coverage.json.total_assets, 1);
    assert.equal(coverage.json.protected, 1);
    assert.equal(coverage.json.percentages.protected, 100);
  });

  it('classifies detected-but-unvalidated assets as unknown', async () => {
    const engineer = demoHeaders('engineer');
    const asset = await createDemoAsset(baseUrl, engineer);
    const validation = await request(baseUrl, 'POST', '/v1/waf/validations', {
      headers: engineer,
      body: { waf_asset_id: asset.id, modes: ['marker'] },
    });
    const runId = validation.json.validation_run.id;

    const finalize = await request(baseUrl, 'POST', `/v1/waf/validations/${runId}/finalize`, {
      headers: engineer,
      body: {
        waf_detected: true,
        validation_passed: false,
      },
    });
    assert.equal(finalize.status, 200);
    assert.equal(finalize.json.posture.status, 'unknown');
    assert.ok(finalize.json.posture.reason_codes.includes('insufficient_validation_evidence'));
  });

  it('rejects cross-tenant or mismatched target_group test_run_id binding', async () => {
    const engineer = demoHeaders('engineer');
    const asset = await createDemoAsset(baseUrl, engineer);
    const safeRun = await createBoundSafeTestRun(baseUrl, engineer);

    const otherTenantRun = {
      id: 'run_other_tenant',
      tenant_id: 'ten_other',
      target_group_id: 'tg_other',
      target_id: 'tgt_other',
      check_id: 'waf.marker_rule.safe',
      status: 'collecting',
    };
    getStore().tenants.push({ id: 'ten_other', name: 'Other' });
    getStore().targetGroups.push({
      id: 'tg_other',
      tenant_id: 'ten_other',
      environment_id: 'env_demo',
      name: 'Other TG',
    });
    getStore().testRuns.push(otherTenantRun);

    const crossTenant = await request(baseUrl, 'POST', '/v1/waf/validations', {
      headers: engineer,
      body: { waf_asset_id: asset.id, modes: ['marker'], test_run_id: otherTenantRun.id },
    });
    assert.equal(crossTenant.status, 404);
    assert.equal(crossTenant.json.error, 'test_run_not_found');

    getStore().testRuns.push({
      id: 'run_wrong_tg',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_other_demo',
      target_id: 'tgt_1',
      check_id: 'waf.marker_rule.safe',
      status: 'collecting',
    });
    getStore().targetGroups.push({
      id: 'tg_other_demo',
      tenant_id: 'ten_demo',
      environment_id: 'env_demo',
      name: 'Other demo TG',
    });

    const wrongGroup = await request(baseUrl, 'POST', '/v1/waf/validations', {
      headers: engineer,
      body: { waf_asset_id: asset.id, modes: ['marker'], test_run_id: 'run_wrong_tg' },
    });
    assert.equal(wrongGroup.status, 400);
    assert.equal(wrongGroup.json.error, 'invalid_request');

    const bound = await request(baseUrl, 'POST', '/v1/waf/validations', {
      headers: engineer,
      body: { waf_asset_id: asset.id, modes: ['marker'], test_run_id: safeRun.id },
    });
    assert.equal(bound.status, 201);
    assert.equal(bound.json.validation_run.test_run_id, safeRun.id);
  });

  it('derives protected posture from blocked probe without matching agent observation', async () => {
    const engineer = demoHeaders('engineer');
    const asset = await createDemoAsset(baseUrl, engineer);
    const safeRun = await createBoundSafeTestRun(baseUrl, engineer);
    clearProbeEventsForRun(safeRun.id);
    const nonceHash = safeRun.correlation?.nonce_hash ?? 'nonce_blocked_only';
    injectMetadataProbeEvent({
      testRunId: safeRun.id,
      nonceHash,
      externalResult: 'blocked',
    });

    const validation = await request(baseUrl, 'POST', '/v1/waf/validations', {
      headers: engineer,
      body: { waf_asset_id: asset.id, modes: ['marker'], test_run_id: safeRun.id },
    });
    const runId = validation.json.validation_run.id;

    const finalize = await request(baseUrl, 'POST', `/v1/waf/validations/${runId}/finalize`, {
      headers: engineer,
      body: {},
    });
    assert.equal(finalize.status, 200);
    assert.equal(finalize.json.posture.status, 'protected');

    const detail = await request(baseUrl, 'GET', `/v1/waf/validations/${runId}`, { headers: engineer });
    assert.equal(detail.status, 200);
    assert.equal(detail.json.scenario_results.length, 1);
    assert.equal(detail.json.scenario_results[0].passed, true);
    assert.equal(detail.json.scenario_results[0].evidence_summary_json.blocked, true);
    assert.equal(detail.json.scenario_results[0].evidence_summary_json.observed_at_agent, false);
  });

  it('classifies matching agent marker observation as underprotected, not protected', async () => {
    const engineer = demoHeaders('engineer');
    const asset = await createDemoAsset(baseUrl, engineer);
    const { posture } = await finalizeUnderprotectedMarkerLeak(baseUrl, engineer, asset);
    assert.notEqual(posture.status, 'protected');
    assert.ok(['underprotected', 'unprotected'].includes(posture.status));
  });

  it('creates one open WAF posture finding when marker validation is underprotected', async () => {
    const engineer = demoHeaders('engineer');
    const asset = await createDemoAsset(baseUrl, engineer);
    const { validationRunId, safeRunId } = await finalizeUnderprotectedMarkerLeak(
      baseUrl,
      engineer,
      asset,
    );

    const findings = openWafPostureFindingsForAsset(asset.id);
    assert.equal(findings.length, 1);
    const finding = findings[0];
    assert.equal(finding.check_id, `waf.posture.${asset.id}`);
    assert.equal(finding.target_group_id, 'tg_1');
    assert.equal(finding.test_run_id, safeRunId);
    assert.equal(finding.last_waf_validation_run_id, validationRunId);
    assert.equal(finding.remediation_template, 'waf_posture_remediation');
    assert.equal(finding.severity, 'medium');
    assert.match(finding.title, /WAF posture underprotected/i);
    assert.match(finding.title, /waf-app\.example\.com/);
    assert.match(finding.notes, /marker_rule_not_blocking/);
    assert.match(finding.notes, /Retest:/);
    assert.ok(Array.isArray(finding.evidence_ids));
    assert.ok(finding.evidence_ids.length >= 1);

    const apiList = await request(baseUrl, 'GET', '/v1/findings', { headers: engineer });
    assert.equal(apiList.status, 200);
    const fromApi = apiList.json.items.find((f) => f.id === finding.id);
    assert.ok(fromApi);
    assertFindingSerializedSafe(fromApi);
  });

  it('updates the same open WAF finding on repeat failed finalize for the asset', async () => {
    const engineer = demoHeaders('engineer');
    const asset = await createDemoAsset(baseUrl, engineer);
    const firstRun = await finalizeUnderprotectedMarkerLeak(baseUrl, engineer, asset);
    const first = openWafPostureFindingsForAsset(asset.id)[0];
    const firstUpdatedAt = first.updated_at;

    const second = await finalizeUnderprotectedMarkerLeak(baseUrl, engineer, asset, {
      safeRun: firstRun.safeRun,
    });
    const findings = openWafPostureFindingsForAsset(asset.id);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].id, first.id);
    assert.equal(findings[0].last_waf_validation_run_id, second.validationRunId);
    assert.notEqual(findings[0].updated_at, firstUpdatedAt);

    const createdAudits = getStore().auditLog.filter(
      (e) => e.action === 'finding.created' && e.resource_id === first.id,
    );
    const updatedAudits = getStore().auditLog.filter(
      (e) => e.action === 'finding.updated' && e.resource_id === first.id,
    );
    assert.equal(createdAudits.length, 1);
    assert.ok(updatedAudits.length >= 1);
    assert.deepEqual(updatedAudits[0].metadata.reason_codes, ['marker_rule_not_blocking']);
  });

  it('does not create findings for protected or fingerprint-only unknown finalize', async () => {
    const engineer = demoHeaders('engineer');
    const asset = await createDemoAsset(baseUrl, engineer);

    const protectedValidation = await request(baseUrl, 'POST', '/v1/waf/validations', {
      headers: engineer,
      body: { waf_asset_id: asset.id, modes: ['marker'] },
    });
    const protectedRunId = protectedValidation.json.validation_run.id;
    const protectedFinalize = await request(
      baseUrl,
      'POST',
      `/v1/waf/validations/${protectedRunId}/finalize`,
      {
        headers: engineer,
        body: {
          waf_detected: true,
          validation_passed: true,
          scenario_results: [
            {
              scenario_family: 'marker',
              passed: true,
              observed_action: 'block',
              evidence_summary: { request_id: 'req_ok', blocked: true },
            },
          ],
        },
      },
    );
    assert.equal(protectedFinalize.status, 200);
    assert.equal(protectedFinalize.json.posture.status, 'protected');
    assert.equal(openWafPostureFindingsForAsset(asset.id).length, 0);

    const safeRun = await createBoundSafeTestRun(baseUrl, engineer);
    clearProbeEventsForRun(safeRun.id);
    const nonceHash = safeRun.correlation?.nonce_hash ?? 'nonce_fingerprint_only_findings';
    injectMetadataProbeEvent({
      testRunId: safeRun.id,
      nonceHash,
      externalResult: '',
      metadata: { waf_product_hint: 'vendor-x', block_page_fingerprint_hash: 'fp_hash_1' },
    });
    const unknownValidation = await request(baseUrl, 'POST', '/v1/waf/validations', {
      headers: engineer,
      body: { waf_asset_id: asset.id, modes: ['marker'], test_run_id: safeRun.id },
    });
    const unknownRunId = unknownValidation.json.validation_run.id;
    const unknownFinalize = await request(
      baseUrl,
      'POST',
      `/v1/waf/validations/${unknownRunId}/finalize`,
      { headers: engineer, body: { waf_detected: true } },
    );
    assert.equal(unknownFinalize.status, 200);
    assert.equal(unknownFinalize.json.posture.status, 'unknown');
    assert.equal(openWafPostureFindingsForAsset(asset.id).length, 0);
  });

  it('keeps fingerprint-only evidence unknown without validation pass', async () => {
    const engineer = demoHeaders('engineer');
    const asset = await createDemoAsset(baseUrl, engineer);
    const safeRun = await createBoundSafeTestRun(baseUrl, engineer);
    clearProbeEventsForRun(safeRun.id);
    const nonceHash = safeRun.correlation?.nonce_hash ?? 'nonce_fingerprint_only';
    injectMetadataProbeEvent({
      testRunId: safeRun.id,
      nonceHash,
      externalResult: '',
      metadata: { waf_product_hint: 'vendor-x', block_page_fingerprint_hash: 'fp_hash_1' },
    });

    const validation = await request(baseUrl, 'POST', '/v1/waf/validations', {
      headers: engineer,
      body: { waf_asset_id: asset.id, modes: ['marker'], test_run_id: safeRun.id },
    });
    const runId = validation.json.validation_run.id;

    const finalize = await request(baseUrl, 'POST', `/v1/waf/validations/${runId}/finalize`, {
      headers: engineer,
      body: { waf_detected: true },
    });
    assert.equal(finalize.status, 200);
    assert.equal(finalize.json.posture.status, 'unknown');
    assert.ok(finalize.json.posture.reason_codes.includes('insufficient_validation_evidence'));
  });

  it('does not leak assets across tenants', async () => {
    const store = getStore();
    store.tenants.push({ id: 'ten_other', name: 'Other' });
    store.targetGroups.push({
      id: 'tg_other',
      tenant_id: 'ten_other',
      environment_id: 'env_demo',
      name: 'Other TG',
    });

    const engineer = demoHeaders('engineer', 'ten_demo');
    const asset = await createDemoAsset(baseUrl, engineer);

    const other = demoHeaders('engineer', 'ten_other', 'usr_other');
    const cross = await request(baseUrl, 'GET', `/v1/waf/assets/${asset.id}`, { headers: other });
    assert.equal(cross.status, 404);
    assert.equal(cross.json.error, 'waf_asset_not_found');
  });
});

describe('WAF drift events API', () => {
  let server;
  let baseUrl;

  before(() => {
    freshStore();
    ({ server, baseUrl } = startServer());
  });

  after(() => {
    server?.close();
    restoreEnv();
  });

  afterEach(() => {
    freshStore();
  });

  it('does not create drift on first finalize with no previous snapshot', async () => {
    const engineer = demoHeaders('engineer');
    const asset = await createDemoAsset(baseUrl, engineer);
    await finalizeProtectedPosture(baseUrl, engineer, asset);
    assert.equal(openWafDriftEventsForAsset(asset.id).length, 0);

    const list = await request(baseUrl, 'GET', '/v1/waf/drift-events', { headers: engineer });
    assert.equal(list.status, 200);
    assert.equal(list.json.items.length, 0);
  });

  it('creates one open marker_failed drift after protected then underprotected marker leak', async () => {
    const engineer = demoHeaders('engineer');
    const asset = await createDemoAsset(baseUrl, engineer);
    await finalizeProtectedPosture(baseUrl, engineer, asset);

    const leak = await finalizeUnderprotectedMarkerLeak(baseUrl, engineer, asset);
    const finding = openWafPostureFindingsForAsset(asset.id)[0];
    const drifts = openWafDriftEventsForAsset(asset.id, 'marker_failed');
    assert.equal(drifts.length, 1);
    const drift = drifts[0];
    assert.equal(drift.severity, 'high');
    assert.equal(drift.finding_id, finding.id);
    assert.equal(drift.before_summary_json.status, 'protected');
    assert.equal(drift.after_summary_json.status, leak.posture.status);

    const apiList = await request(baseUrl, 'GET', '/v1/waf/drift-events', { headers: engineer });
    assert.equal(apiList.status, 200);
    const fromApi = apiList.json.items.find((e) => e.id === drift.id);
    assert.ok(fromApi);
    assert.equal(fromApi.drift_type, 'marker_failed');
    assertFindingSerializedSafe(fromApi);

    const detectedAudits = getStore().auditLog.filter(
      (e) => e.action === 'waf.drift.detected' && e.resource_id === drift.id,
    );
    assert.equal(detectedAudits.length, 1);
    assert.deepEqual(detectedAudits[0].metadata.reason_codes, ['marker_rule_not_blocking']);
    assert.equal(detectedAudits[0].metadata.posture_from, 'protected');
    assert.ok(['underprotected', 'unprotected'].includes(detectedAudits[0].metadata.posture_to));
  });

  it('updates the same open drift event on repeat failed finalize', async () => {
    const engineer = demoHeaders('engineer');
    const asset = await createDemoAsset(baseUrl, engineer);
    await finalizeProtectedPosture(baseUrl, engineer, asset);
    const first = await finalizeUnderprotectedMarkerLeak(baseUrl, engineer, asset);
    const drift = openWafDriftEventsForAsset(asset.id, 'marker_failed')[0];
    const detectedBefore = getStore().auditLog.filter(
      (e) => e.action === 'waf.drift.detected' && e.resource_id === drift.id,
    ).length;

    const second = await finalizeUnderprotectedMarkerLeak(baseUrl, engineer, asset, {
      safeRun: first.safeRun,
    });
    const drifts = openWafDriftEventsForAsset(asset.id, 'marker_failed');
    assert.equal(drifts.length, 1);
    assert.equal(drifts[0].id, drift.id);
    assert.ok(drifts[0].updated_at);
    assert.equal(drifts[0].finding_id, openWafPostureFindingsForAsset(asset.id)[0].id);
    assert.equal(drifts[0].after_summary_json.status, second.posture.status);

    const detectedAfter = getStore().auditLog.filter(
      (e) => e.action === 'waf.drift.detected' && e.resource_id === drift.id,
    ).length;
    assert.ok(detectedAfter > detectedBefore);
  });

  it('PATCH drift status is tenant and RBAC protected', async () => {
    const engineer = demoHeaders('engineer');
    const asset = await createDemoAsset(baseUrl, engineer);
    await finalizeProtectedPosture(baseUrl, engineer, asset);
    await finalizeUnderprotectedMarkerLeak(baseUrl, engineer, asset);
    const drift = openWafDriftEventsForAsset(asset.id, 'marker_failed')[0];

    const viewer = demoHeaders('viewer');
    const denied = await request(baseUrl, 'PATCH', `/v1/waf/drift-events/${drift.id}`, {
      headers: viewer,
      body: { status: 'acknowledged' },
    });
    assert.equal(denied.status, 403);
    assert.equal(denied.json.permission, 'waf:write');

    const patched = await request(baseUrl, 'PATCH', `/v1/waf/drift-events/${drift.id}`, {
      headers: engineer,
      body: { status: 'acknowledged', notes: 'Owner notified' },
    });
    assert.equal(patched.status, 200);
    assert.equal(patched.json.drift_event.status, 'acknowledged');
    assert.equal(patched.json.drift_event.notes, 'Owner notified');

    const updatedAudits = getStore().auditLog.filter(
      (e) => e.action === 'waf.drift.updated' && e.resource_id === drift.id,
    );
    assert.equal(updatedAudits.length, 1);
    assert.equal(updatedAudits[0].metadata.status, 'acknowledged');

    getStore().tenants.push({ id: 'ten_other', name: 'Other' });
    const other = demoHeaders('engineer', 'ten_other', 'usr_other');
    const cross = await request(baseUrl, 'PATCH', `/v1/waf/drift-events/${drift.id}`, {
      headers: other,
      body: { status: 'resolved' },
    });
    assert.equal(cross.status, 404);
    assert.equal(cross.json.error, 'waf_drift_event_not_found');
  });

  it('does not create drift for unknown finalize without prior protected snapshot', async () => {
    const engineer = demoHeaders('engineer');
    const asset = await createDemoAsset(baseUrl, engineer);
    const safeRun = await createBoundSafeTestRun(baseUrl, engineer);
    clearProbeEventsForRun(safeRun.id);
    const nonceHash = safeRun.correlation?.nonce_hash ?? 'nonce_unknown_no_drift';
    injectMetadataProbeEvent({
      testRunId: safeRun.id,
      nonceHash,
      externalResult: '',
      metadata: { waf_product_hint: 'vendor-x', block_page_fingerprint_hash: 'fp_hash_1' },
    });
    const validation = await request(baseUrl, 'POST', '/v1/waf/validations', {
      headers: engineer,
      body: { waf_asset_id: asset.id, modes: ['marker'], test_run_id: safeRun.id },
    });
    const runId = validation.json.validation_run.id;
    const finalize = await request(baseUrl, 'POST', `/v1/waf/validations/${runId}/finalize`, {
      headers: engineer,
      body: { waf_detected: true },
    });
    assert.equal(finalize.status, 200);
    assert.equal(finalize.json.posture.status, 'unknown');
    assert.equal(openWafDriftEventsForAsset(asset.id).length, 0);
  });
});

describe('WAF connector API', () => {
  let server;
  let baseUrl;

  before(() => {
    freshStore();
    ({ server, baseUrl } = startServer());
  });

  after(() => {
    server?.close();
    restoreEnv();
  });

  afterEach(() => {
    freshStore();
  });

  async function createReadOnlyConnector(headers, overrides = {}) {
    const res = await request(baseUrl, 'POST', '/v1/connectors', {
      headers,
      body: {
        provider: 'cloudflare',
        name: 'edge-readonly',
        secret_id: 'sec_pointer_1',
        config: {
          read_only: true,
          zone_ref_hash: 'zone_hash_abc',
          default_snapshot_kind: 'waf_policy',
        },
        status: 'active',
        ...overrides,
      },
    });
    assert.equal(res.status, 201);
    return res.json.connector;
  }

  it('lets engineers list connectors but not create or poll', async () => {
    const admin = demoHeaders('admin');
    const connector = await createReadOnlyConnector(admin);

    const engineer = demoHeaders('engineer', 'ten_demo', 'usr_eng');
    const list = await request(baseUrl, 'GET', '/v1/connectors', { headers: engineer });
    assert.equal(list.status, 200);
    assert.equal(list.json.items.length, 1);
    assert.equal(list.json.items[0].id, connector.id);

    const create = await request(baseUrl, 'POST', '/v1/connectors', {
      headers: engineer,
      body: {
        provider: 'aws_waf',
        name: 'denied',
        config: { read_only: true },
      },
    });
    assert.equal(create.status, 403);
    assert.equal(create.json.permission, 'waf:connector_write');

    const poll = await request(baseUrl, 'POST', `/v1/connectors/${connector.id}/poll`, {
      headers: engineer,
      body: { snapshots: [] },
    });
    assert.equal(poll.status, 403);
    assert.equal(poll.json.permission, 'waf:connector_write');
  });

  it('lets admin create, validate, poll, and disable metadata-only connectors', async () => {
    const admin = demoHeaders('admin');
    const connector = await createReadOnlyConnector(admin);
    assert.equal(connector.status, 'active');
    assert.equal(connector.config.read_only, true);
    assert.equal(connector.secret_id, 'sec_pointer_1');
    assert.ok(!('api_token' in connector.config));

    const validate = await request(baseUrl, 'POST', `/v1/connectors/${connector.id}/validate`, {
      headers: admin,
    });
    assert.equal(validate.status, 200);
    assert.equal(validate.json.status, 'active');
    assert.equal(validate.json.capabilities.outbound_polling, false);

    const poll = await request(baseUrl, 'POST', `/v1/connectors/${connector.id}/poll`, {
      headers: admin,
      body: {
        snapshots: [
          {
            snapshot_kind: 'waf_policy',
            resource_ref_hash: 'res_hash_1',
            display_ref: 'zone-a',
            config_hash: 'cfg_hash_1',
            observed_at: '2026-07-02T12:00:00Z',
            summary: {
              hostnames: ['app.example.com'],
              policy_mode: 'block',
              rule_count: 12,
            },
          },
        ],
      },
    });
    assert.equal(poll.status, 202);
    assert.equal(poll.json.snapshots.length, 1);
    assert.equal(poll.json.snapshots[0].summary.rule_count, 12);
    assert.equal(poll.json.poll_job.snapshot_count, 1);

    const snapshots = await request(baseUrl, 'GET', `/v1/connectors/${connector.id}/snapshots`, {
      headers: admin,
    });
    assert.equal(snapshots.status, 200);
    assert.equal(snapshots.json.items.length, 1);

    const disable = await request(baseUrl, 'POST', `/v1/connectors/${connector.id}/disable`, {
      headers: admin,
      body: { reason: 'maintenance' },
    });
    assert.equal(disable.status, 200);
    assert.equal(disable.json.connector.status, 'disabled');

    const createdAudit = getStore().auditLog.find((e) => e.action === 'connector.created');
    assert.ok(createdAudit);
    assert.equal(createdAudit.metadata.provider, 'cloudflare');
    assert.ok(!JSON.stringify(createdAudit.metadata).includes('zone_hash'));
  });

  it('rejects raw or secret connector config and does not persist plaintext secrets', async () => {
    const admin = demoHeaders('admin');
    const before = getStore().wafConnectors?.length ?? 0;

    const rawConfig = await request(baseUrl, 'POST', '/v1/connectors', {
      headers: admin,
      body: {
        provider: 'cloudflare',
        name: 'bad-config',
        config: { read_only: true, raw_payload: 'leak' },
      },
    });
    assert.equal(rawConfig.status, 400);
    assert.equal(rawConfig.json.error, 'unsafe_waf_evidence');

    const topSecret = await request(baseUrl, 'POST', '/v1/connectors', {
      headers: admin,
      body: {
        provider: 'cloudflare',
        name: 'bad-secret',
        api_token: 'plaintext-token',
        config: { read_only: true },
      },
    });
    assert.equal(topSecret.status, 400);
    assert.equal(topSecret.json.error, 'unsafe_waf_evidence');

    const nestedSecret = await request(baseUrl, 'POST', '/v1/connectors', {
      headers: admin,
      body: {
        provider: 'cloudflare',
        name: 'nested-secret',
        config: {
          read_only: true,
          tag_summary: { api_token: 'nested-plaintext-token' },
        },
      },
    });
    assert.equal(nestedSecret.status, 400);
    assert.equal(nestedSecret.json.error, 'unsafe_waf_evidence');

    assert.equal(getStore().wafConnectors?.length ?? 0, before);
  });

  it('validate is local-only and requires read_only', async () => {
    const admin = demoHeaders('admin');
    const created = await request(baseUrl, 'POST', '/v1/connectors', {
      headers: admin,
      body: {
        provider: 'aws_waf',
        name: 'not-read-only',
        config: { account_ref_hash: 'acct_hash_1' },
      },
    });
    assert.equal(created.status, 201);
    assert.equal(created.json.connector.status, 'disabled');
    const connectorId = created.json.connector.id;

    const validate = await request(baseUrl, 'POST', `/v1/connectors/${connectorId}/validate`, {
      headers: admin,
    });
    assert.equal(validate.status, 200);
    assert.equal(validate.json.status, 'error');
    assert.ok(validate.json.redacted_errors[0].includes('read_only'));

    const stored = getStore().wafConnectors.find((c) => c.id === connectorId);
    assert.equal(stored.status, 'error');
  });

  it('poll rejects raw snapshot fields and stores metadata-only summaries', async () => {
    const admin = demoHeaders('admin');
    const connector = await createReadOnlyConnector(admin);

    const rejected = await request(baseUrl, 'POST', `/v1/connectors/${connector.id}/poll`, {
      headers: admin,
      body: {
        snapshots: [
          {
            snapshot_kind: 'waf_policy',
            resource_ref_hash: 'res_hash_2',
            display_ref: 'zone-b',
            config_hash: 'cfg_hash_2',
            summary: { headers: { 'x-test': '1' } },
          },
        ],
      },
    });
    assert.equal(rejected.status, 400);
    assert.equal(rejected.json.error, 'unsafe_waf_evidence');
    assert.equal(getStore().wafConnectorSnapshots.length, 0);

    const poll = await request(baseUrl, 'POST', `/v1/connectors/${connector.id}/poll`, {
      headers: admin,
      body: {
        snapshots: [
          {
            snapshot_kind: 'cdn_property',
            resource_ref_hash: 'res_hash_3',
            display_ref: 'property-c',
            config_hash: 'cfg_hash_3',
            summary: {
              hostnames: ['cdn.example.com'],
              policy_mode: 'block',
              raw_payload: 'must-not-store',
            },
          },
        ],
      },
    });
    assert.equal(poll.status, 400);
    assert.equal(poll.json.error, 'unsafe_waf_evidence');
    assert.equal(getStore().wafConnectorSnapshots.length, 0);
  });

  it('does not leak connector snapshots across tenants', async () => {
    const admin = demoHeaders('admin');
    const connector = await createReadOnlyConnector(admin);
    await request(baseUrl, 'POST', `/v1/connectors/${connector.id}/poll`, {
      headers: admin,
      body: {
        snapshots: [
          {
            snapshot_kind: 'waf_policy',
            resource_ref_hash: 'res_hash_tenant',
            display_ref: 'zone-tenant',
            config_hash: 'cfg_hash_tenant',
            summary: { hostnames: ['tenant.example.com'], policy_mode: 'block' },
          },
        ],
      },
    });

    getStore().tenants.push({ id: 'ten_other', name: 'Other' });
    const other = demoHeaders('engineer', 'ten_other', 'usr_other');
    const crossList = await request(baseUrl, 'GET', `/v1/connectors/${connector.id}/snapshots`, {
      headers: other,
    });
    assert.equal(crossList.status, 404);
    assert.equal(crossList.json.error, 'connector_not_found');

    const crossConnectors = await request(baseUrl, 'GET', '/v1/connectors', { headers: other });
    assert.equal(crossConnectors.status, 200);
    assert.equal(crossConnectors.json.items.length, 0);
  });
});

describe('WAF remediation action items and connector payloads', () => {
  let server;
  let baseUrl;

  before(() => {
    freshStore();
    ({ server, baseUrl } = startServer());
  });

  after(() => {
    server?.close();
    restoreEnv();
  });

  afterEach(() => {
    freshStore();
  });

  it('creates a valid action item from a WAF finding with redacted fields', async () => {
    const engineer = demoHeaders('engineer');
    const asset = await createDemoAsset(baseUrl, engineer);
    await finalizeUnderprotectedMarkerLeak(baseUrl, engineer, asset);
    const finding = openWafPostureFindingsForAsset(asset.id)[0];

    const result = wafPosture.createActionItemFromFinding(demoCtx(), finding);
    assert.equal(result.created, true);
    const item = result.action_item;
    assert.equal(item.category, 'waf_coverage');
    assert.equal(item.asset.display, 'https://waf-app.example.com');
    assert.equal(item.owner, 'edge-team');
    assert.match(item.evidence.summary, /marker_rule_not_blocking/);
    assert.ok(item.evidence.links.some((l) => l.type === 'finding'));
    assert.match(item.retest_url, /waf_asset_id=/);
    assert.match(item.recommended_solution, /blocking mode/i);
    assert.equal(item.status, 'open');
    validateActionItem(item);
    assertSerializedSafe(item, 'action item');

    const listed = wafPosture.listActionItems(demoCtx());
    assert.equal(listed.length, 1);
    assert.equal(listed[0].action_item_id, item.action_item_id);
  });

  it('deduplicates action items by tenant, asset, and primary reason', async () => {
    const engineer = demoHeaders('engineer');
    const asset = await createDemoAsset(baseUrl, engineer);
    await finalizeUnderprotectedMarkerLeak(baseUrl, engineer, asset);
    const finding = openWafPostureFindingsForAsset(asset.id)[0];

    const first = wafPosture.createActionItemFromFinding(demoCtx(), finding);
    const second = wafPosture.createActionItemFromFinding(demoCtx(), finding);
    assert.equal(first.created, true);
    assert.equal(second.created, false);
    assert.equal(second.action_item.action_item_id, first.action_item.action_item_id);
    assert.equal(wafPosture.listActionItems(demoCtx()).length, 1);
  });

  it('patches action item status with audit trail', async () => {
    const engineer = demoHeaders('engineer');
    const asset = await createDemoAsset(baseUrl, engineer);
    await finalizeUnderprotectedMarkerLeak(baseUrl, engineer, asset);
    const finding = openWafPostureFindingsForAsset(asset.id)[0];
    const created = wafPosture.createActionItemFromFinding(demoCtx(), finding);

    const patched = wafPosture.patchActionItemStatus(
      demoCtx(),
      created.action_item.action_item_id,
      { status: 'ticketed', notes: 'Jira ABC-1' },
    );
    assert.equal(patched.action_item.status, 'ticketed');
    const audits = getStore().auditLog.filter(
      (e) =>
        e.action === 'waf.action_item.updated'
        && e.resource_id === created.action_item.action_item_id,
    );
    assert.ok(audits.length >= 1);
    assert.equal(audits.at(-1).metadata.status, 'ticketed');
  });

  it('groupFindings merges related findings by asset+reason, policy, CVE, and origin bypass', () => {
    const findings = [
      {
        id: 'fnd_a1',
        check_id: 'waf.posture.asset_a',
        notes: 'Reason codes: marker_rule_not_blocking.',
        waf_policy_ref: 'policy_zone_1',
      },
      {
        id: 'fnd_a2',
        check_id: 'waf.posture.asset_b',
        notes: 'Reason codes: marker_rule_not_blocking.',
        waf_policy_ref: 'policy_zone_1',
      },
      {
        id: 'fnd_cve_1',
        check_id: 'waf.posture.asset_c',
        cve_id: 'CVE-2026-1234',
        owner: 'payments-platform',
        notes: 'Reason codes: mitigation_recommended.',
      },
      {
        id: 'fnd_cve_2',
        check_id: 'waf.posture.asset_d',
        cve_id: 'CVE-2026-1234',
        owner: 'payments-platform',
        notes: 'Reason codes: mitigation_recommended.',
      },
      {
        id: 'fnd_origin_1',
        check_id: 'waf.posture.asset_e',
        origin_bypass_path: '/internal-origin',
        notes: 'Reason codes: origin_bypass_confirmed.',
      },
      {
        id: 'fnd_origin_2',
        check_id: 'waf.posture.asset_f',
        origin_bypass_path: '/internal-origin',
        notes: 'Reason codes: origin_bypass_confirmed.',
      },
    ];

    const groups = groupFindings(findings);
    const byType = Object.fromEntries(groups.map((g) => [g.group_type, g]));

    assert.equal(byType.policy_assets.findings.length, 2);
    assert.equal(byType.cve_owner.findings.length, 2);
    assert.equal(byType.origin_bypass.findings.length, 2);
    assert.equal(groups.length, 3);
  });

  it('buildSiemEventPayload matches astranull.waf_event.v1 schema', () => {
    const payload = buildSiemEventPayload({
      event_type: 'waf.drift.detected',
      tenant_id: 'ten_demo',
      event_id: 'evt_test_1',
      occurred_at: '2026-07-02T00:00:00Z',
      severity: 'high',
      asset: {
        id: 'asset_1',
        display: 'app.example.com',
        owner_hint: 'payments-platform',
        business_criticality: 'critical',
      },
      finding: {
        id: 'fnd_1',
        reason_codes: ['marker_rule_not_blocking'],
        summary: 'WAF marker rule no longer blocks before origin.',
        evidence_url: 'https://portal.example/evidence/fnd_1',
        retest_url: 'https://portal.example/retest/asset_1',
      },
      recommendation: {
        vendor: 'cloudflare',
        type: 'mode_change',
        summary: 'Review WAF rule mode and ensure marker/managed rules are in blocking mode.',
      },
    });

    assert.equal(payload.schema_version, 'astranull.waf_event.v1');
    assert.equal(payload.event_type, 'waf.drift.detected');
    assert.match(payload.tenant_id, /^redacted:/);
    assert.equal(payload.asset.display, 'app.example.com');
    assert.deepEqual(payload.finding.reason_codes, ['marker_rule_not_blocking']);
    assert.equal(payload.recommendation.vendor, 'cloudflare');
    assertSerializedSafe(payload, 'siem event');
  });

  it('validateActionItem rejects forbidden fields', () => {
    const base = {
      action_item_id: 'ai_test_1',
      category: 'waf_coverage',
      title: 'Fix WAF coverage',
      asset: { display: 'app.example.com' },
      owner: 'edge-team',
      severity: 'high',
      evidence: { summary: 'Metadata-only evidence summary.', links: [] },
      recommended_solution: 'Enable blocking mode.',
      retest_url: '/v1/waf/validations?waf_asset_id=asset_1',
      status: 'open',
    };
    validateActionItem(base);
    assert.throws(
      () => validateActionItem({ ...base, evidence: { summary: 'x', links: [], raw_payload: 'no' } }),
      /Forbidden action item field/,
    );
    assert.throws(
      () => validateActionItem({ ...base, secret: 'hidden' }),
      /Forbidden action item field/,
    );
  });

  it('buildRemediationPayload returns required connector fields without secrets', () => {
    const item = createActionItem({
      action_item_id: 'ai_connector_1',
      category: 'waf_drift',
      title: 'WAF drift on app.example.com',
      asset: { id: 'asset_1', display: 'app.example.com', owner_hint: 'edge-team' },
      owner: 'edge-team',
      severity: 'high',
      evidence: {
        summary: 'Marker validation failed after protected baseline.',
        links: [{ type: 'finding', url: '/v1/findings/fnd_1', label: 'Finding' }],
      },
      recommended_solution: 'Restore blocking mode for managed rules.',
      retest_url: '/v1/waf/validations?waf_asset_id=asset_1',
      status: 'open',
      finding_ids: ['fnd_1'],
      tenant_id: 'ten_demo',
    });

    for (const connectorType of REMEDIATION_CONNECTOR_TYPES) {
      const payload = wafPosture.buildRemediationPayload(item, connectorType);
      assert.equal(payload.connector, connectorType);
      assert.ok(
        payload.issue
        || payload.incident
        || payload.event
        || payload.records
        || payload.action_item
        || payload.text
        || payload.subject
        || payload.title,
      );
      assertSerializedSafe(payload, `remediation payload (${connectorType})`);
    }
  });
});
