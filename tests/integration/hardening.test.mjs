import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { agentHeaders, demoHeaders, request } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';
import { getStore } from '../../src/store.mjs';
import { createBootstrapToken } from '../../src/services/tokens.mjs';
import { REQUIRED_ARTIFACT_TYPES } from '../../src/services/highScale.mjs';
import {
  acceptHighScaleAuthorizationPack,
  acceptLegacyAuthorizationArtifactsOnly,
  acceptRequiredAuthorizationArtifactsOnly,
  validHighScaleRequestPayload,
} from '../helpers/highScalePayload.mjs';

const socPrimary = () => demoHeaders('soc', 'ten_demo', 'usr_soc');
const socSecondary = () => demoHeaders('soc', 'ten_demo', 'usr_soc2');

async function dualSocApprove(hsId) {
  const first = await request(baseUrl, 'POST', `/internal/soc/high-scale/${hsId}/approve`, {
    headers: socPrimary(),
  });
  assert.equal(first.status, 200);
  assert.equal(first.json.state, 'under_review');
  const dup = await request(baseUrl, 'POST', `/internal/soc/high-scale/${hsId}/approve`, {
    headers: socPrimary(),
  });
  assert.equal(dup.status, 409);
  assert.equal(dup.json.error, 'duplicate_soc_approval');
  const second = await request(baseUrl, 'POST', `/internal/soc/high-scale/${hsId}/approve`, {
    headers: socSecondary(),
  });
  assert.equal(second.status, 200);
  assert.equal(second.json.state, 'approved');
  assert.ok(second.json.scope_hash);
  return second.json;
}

async function uploadAndAcceptArtifacts(hsId, socHeaders) {
  await acceptHighScaleAuthorizationPack(baseUrl, hsId, socHeaders);
}

let baseUrl;
let server;

async function registerAgent(targetGroupId = 'tg_1') {
  const ctx = { tenantId: 'ten_demo', userId: 'u1', role: 'admin' };
  const { secret } = createBootstrapToken(ctx, { target_group_id: targetGroupId, max_registrations: 5 });
  const reg = await request(baseUrl, 'POST', '/v1/agents/register', {
    headers: demoHeaders('engineer'),
    body: { bootstrap_token: secret, hostname: 'hardening-host', capabilities: ['canary', 'heartbeat'] },
  });
  assert.equal(reg.status, 201);
  return { agentId: reg.json.agent.id, credential: reg.json.agent_credential };
}

before(() => {
  freshStore();
  server = createServer();
  server.listen(0);
  const { port } = server.address();
  baseUrl = `http://127.0.0.1:${port}`;
});

after(() => server.close());

describe('hardening acceptance gaps', () => {
  it('rejects missing/invalid agent credential and audits denial', async () => {
    const { agentId } = await registerAgent();
    const engineerOnly = demoHeaders('engineer');

    const hb = await request(baseUrl, 'POST', `/v1/agents/${agentId}/heartbeat`, {
      headers: engineerOnly,
      body: { version: '0.1.0' },
    });
    assert.equal(hb.status, 401);

    const jobs = await request(baseUrl, 'GET', `/v1/agents/${agentId}/jobs`, { headers: engineerOnly });
    assert.equal(jobs.status, 401);

    const badCred = await request(baseUrl, 'GET', `/v1/agents/${agentId}/jobs`, {
      headers: agentHeaders('agc_invalid'),
    });
    assert.equal(badCred.status, 401);

    assert.ok(getStore().auditLog.some((a) => a.action === 'agent.auth_denied'));
  });

  it('allows heartbeat, job poll, ack, and observation with registered credential', async () => {
    const h = demoHeaders('engineer');
    const { agentId, credential } = await registerAgent();

    const hb = await request(baseUrl, 'POST', `/v1/agents/${agentId}/heartbeat`, {
      headers: agentHeaders(credential),
      body: { version: '0.1.0' },
    });
    assert.equal(hb.status, 200);

    const run = await request(baseUrl, 'POST', '/v1/test-runs', {
      headers: h,
      body: {
        check_id: 'origin.direct_bypass.safe',
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
      },
    });
    assert.equal(run.status, 201);
    const runId = run.json.run.id;
    const nonce_hash = run.json.run.correlation.nonce_hash;

    const jobs = await request(baseUrl, 'GET', `/v1/agents/${agentId}/jobs`, {
      headers: agentHeaders(credential),
    });
    assert.equal(jobs.status, 200);
    assert.ok(jobs.json.jobs.length >= 1);

    const ack = await request(baseUrl, 'POST', `/v1/agents/${agentId}/jobs/${jobs.json.jobs[0].id}/ack`, {
      headers: agentHeaders(credential),
    });
    assert.equal(ack.status, 200);

    const obs = await request(baseUrl, 'POST', `/v1/agents/${agentId}/observations`, {
      headers: agentHeaders(credential),
      body: {
        agent_job_id: jobs.json.jobs[0].id,
        test_run_id: runId,
        target_id: 'tgt_1',
        nonce_hash,
      },
    });
    assert.equal(obs.status, 201);
  });

  it('rejects observation without agent_job_id and audits rejection', async () => {
    const { agentId, credential } = await registerAgent();
    const h = demoHeaders('engineer');
    const run = await request(baseUrl, 'POST', '/v1/test-runs', {
      headers: h,
      body: {
        check_id: 'origin.direct_bypass.safe',
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
      },
    });
    const runId = run.json.run.id;
    const res = await request(baseUrl, 'POST', `/v1/agents/${agentId}/observations`, {
      headers: agentHeaders(credential),
      body: { test_run_id: runId, target_id: 'tgt_1', nonce_hash: run.json.run.correlation.nonce_hash },
    });
    assert.equal(res.status, 400);
    assert.equal(res.json.error, 'missing_agent_job_id');
    assert.ok(getStore().auditLog.some((a) => a.action === 'observation.rejected'));
    const cancelled = await request(baseUrl, 'POST', `/v1/test-runs/${runId}/cancel`, { headers: h });
    assert.equal(cancelled.status, 200);
  });

  it('finalizes blocked safe check to protected with no observation', async () => {
    const h = demoHeaders('engineer');
    const { agentId, credential } = await registerAgent();
    await request(baseUrl, 'POST', `/v1/agents/${agentId}/heartbeat`, {
      headers: agentHeaders(credential),
      body: { version: '0.1.0' },
    });

    const run = await request(baseUrl, 'POST', '/v1/test-runs', {
      headers: h,
      body: {
        check_id: 'l3.forbidden_tcp_port.safe',
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
      },
    });
    assert.equal(run.status, 201);
    const runId = run.json.run.id;

    const storeRun = getStore().testRuns.find((r) => r.id === runId);
    storeRun.collection_deadline_at = new Date(Date.now() - 1000).toISOString();

    const finalized = await request(baseUrl, 'POST', `/v1/test-runs/${runId}/finalize`, { headers: h });
    assert.equal(finalized.status, 200);
    assert.equal(finalized.json.verdict.verdict, 'protected');

    const events = await request(baseUrl, 'GET', `/v1/test-runs/${runId}/events`, { headers: h });
    assert.ok(events.json.items.some((e) => e.signal_type === 'agent_no_observation'));
    assert.ok(getStore().auditLog.some((a) => a.action === 'verdict.finalized_no_observation'));
  });

  it('rejects high-scale start outside window and allows start inside window via governed dry-run adapter', async () => {
    const soc = demoHeaders('soc', 'ten_demo', 'usr_soc');
    const created = await request(baseUrl, 'POST', '/v1/high-scale-requests', {
      headers: demoHeaders('engineer'),
      body: validHighScaleRequestPayload({ objective: 'validation' }),
    });
    const hsId = created.json.id;

    await uploadAndAcceptArtifacts(hsId, soc);
    await dualSocApprove(hsId);

    const pastStart = new Date(Date.now() - 7200000).toISOString();
    const pastEnd = new Date(Date.now() - 3600000).toISOString();
    const schedulePast = await request(baseUrl, 'POST', `/internal/soc/high-scale/${hsId}/schedule`, {
      headers: soc,
      body: { window_start: pastStart, window_end: pastEnd },
    });
    assert.equal(schedulePast.status, 200);

    const outside = await request(baseUrl, 'POST', `/internal/soc/high-scale/${hsId}/start`, { headers: soc });
    assert.equal(outside.status, 409);
    assert.equal(outside.json.error, 'outside_schedule_window');
    assert.ok(getStore().auditLog.some((a) => a.action === 'high_scale.start_gate_denied'));

    const activeStart = new Date(Date.now() - 60000).toISOString();
    const activeEnd = new Date(Date.now() + 3600000).toISOString();
    const req = getStore().highScaleRequests.find((r) => r.id === hsId);
    req.state = 'scheduled';
    req.scheduled_window = { window_start: activeStart, window_end: activeEnd };

    const inside = await request(baseUrl, 'POST', `/internal/soc/high-scale/${hsId}/start`, { headers: soc });
    assert.equal(inside.status, 200);
    assert.equal(inside.json.state, 'running');
    assert.ok(
      getStore().auditLog.some(
        (a) => a.action === 'high_scale.adapter_stub_started' && a.metadata?.note?.includes('dry-run'),
      ),
    );
  });

  it('stores salted bootstrap tokens and redacts secrets on list', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'u1', role: 'admin' };
    const { secret, token } = createBootstrapToken(ctx, { target_group_id: 'tg_1' });
    assert.ok(token.token_salt);
    assert.ok(token.token_hash);

    const listed = await request(baseUrl, 'GET', '/v1/bootstrap-tokens', { headers: demoHeaders('admin') });
    const item = listed.json.items.find((t) => t.id === token.id);
    assert.equal(item.token_hash, undefined);
    assert.equal(item.token_salt, undefined);
    assert.equal(item.secret, undefined);

    const replay = await request(baseUrl, 'POST', '/v1/agents/register', {
      headers: demoHeaders('engineer'),
      body: { bootstrap_token: secret, hostname: 'salt-replay' },
    });
    assert.equal(replay.status, 201);
    const replay2 = await request(baseUrl, 'POST', '/v1/agents/register', {
      headers: demoHeaders('engineer'),
      body: { bootstrap_token: secret, hostname: 'salt-replay-2' },
    });
    assert.equal(replay2.status, 401);
  });

  it('stores production-shaped high-scale intake and rejects missing or invalid fields', async () => {
    const h = demoHeaders('engineer');
    const valid = await request(baseUrl, 'POST', '/v1/high-scale-requests', {
      headers: h,
      body: validHighScaleRequestPayload({
        objective: 'L7 readiness validation',
        environment: 'staging',
        business_criticality: 'high',
      }),
    });
    assert.equal(valid.status, 201);
    const stored = getStore().highScaleRequests.find((r) => r.id === valid.json.id);
    assert.equal(stored.objective, 'L7 readiness validation');
    assert.equal(stored.reason, 'L7 readiness validation');
    assert.equal(stored.scope_confirmation, true);
    assert.ok(stored.requested_window.window_start);
    assert.ok(stored.requested_window.window_end);
    assert.equal(stored.requested_window.timezone, 'UTC');
    assert.equal(stored.emergency_contacts.length, 1);
    assert.equal(stored.environment, 'staging');
    assert.equal(stored.business_criticality, 'high');
    assert.deepEqual(stored.requested_scenario_families, ['volumetric_metadata']);
    assert.equal(stored.requested_limits.max_duration_minutes, 45);
    assert.ok(stored.stop_criteria.abort_on_customer_signal);
    assert.ok(stored.abort_criteria.auto_stop);
    assert.equal(stored.abort_criteria.threshold, 'error_rate_above_5pct');
    assert.ok(stored.authorization_pack_status?.overall);
    assert.ok(stored.provider_context.provider_name);

    const incomplete = await request(baseUrl, 'POST', '/v1/high-scale-requests', {
      headers: h,
      body: { target_group_id: 'tg_1' },
    });
    assert.equal(incomplete.status, 400);
    assert.equal(incomplete.json.error, 'missing_high_scale_request_fields');
    assert.ok(incomplete.json.missing.includes('reason_or_objective'));
    assert.ok(incomplete.json.missing.includes('requested_window'));
    assert.ok(incomplete.json.missing.includes('emergency_contacts'));
    assert.ok(incomplete.json.missing.includes('provider_context'));
    assert.ok(incomplete.json.missing.includes('scope_confirmation'));
    assert.ok(incomplete.json.missing.includes('environment'));
    assert.ok(incomplete.json.missing.includes('business_criticality'));
    assert.ok(incomplete.json.missing.includes('requested_scenario_families'));
    assert.ok(incomplete.json.missing.includes('requested_limits'));
    assert.ok(incomplete.json.missing.includes('stop_criteria'));
    assert.ok(incomplete.json.missing.includes('abort_criteria'));

    const badWindow = await request(baseUrl, 'POST', '/v1/high-scale-requests', {
      headers: h,
      body: validHighScaleRequestPayload({
        requested_window: {
          window_start: new Date(Date.now() + 86400000).toISOString(),
          window_end: new Date(Date.now() - 86400000).toISOString(),
        },
      }),
    });
    assert.equal(badWindow.status, 400);
    assert.equal(badWindow.json.error, 'invalid_requested_window');
  });

  it('rejects invalid high-scale target scope on create', async () => {
    const h = demoHeaders('engineer');
    const missing = await request(baseUrl, 'POST', '/v1/high-scale-requests', {
      headers: h,
      body: { reason: 'no group' },
    });
    assert.equal(missing.status, 400);
    assert.equal(missing.json.error, 'missing_target_group_id');

    const foreign = await request(baseUrl, 'POST', '/v1/high-scale-requests', {
      headers: h,
      body: { target_group_id: 'tg_foreign', reason: 'foreign' },
    });
    assert.equal(foreign.status, 404);
    assert.equal(foreign.json.error, 'target_group_not_found');

    getStore().targetGroups.push({
      id: 'tg_empty',
      tenant_id: 'ten_demo',
      environment_id: 'env_demo',
      name: 'Empty',
      expected_behavior_default: 'must_block_before_origin',
    });
    const empty = await request(baseUrl, 'POST', '/v1/high-scale-requests', {
      headers: h,
      body: { target_group_id: 'tg_empty', reason: 'empty' },
    });
    assert.equal(empty.status, 400);
    assert.equal(empty.json.error, 'target_group_empty');
  });

  it('requires stopped state before close and kill switch auto-stops running requests', async () => {
    const soc = socPrimary();
    const created = await request(baseUrl, 'POST', '/v1/high-scale-requests', {
      headers: demoHeaders('engineer'),
      body: validHighScaleRequestPayload({ objective: 'governance' }),
    });
    const hsId = created.json.id;
    await uploadAndAcceptArtifacts(hsId, soc);
    await dualSocApprove(hsId);

    const activeStart = new Date(Date.now() - 60000).toISOString();
    const activeEnd = new Date(Date.now() + 3600000).toISOString();
    await request(baseUrl, 'POST', `/internal/soc/high-scale/${hsId}/schedule`, {
      headers: soc,
      body: { window_start: activeStart, window_end: activeEnd },
    });
    const started = await request(baseUrl, 'POST', `/internal/soc/high-scale/${hsId}/start`, { headers: soc });
    assert.equal(started.status, 200);

    const closeRunning = await request(baseUrl, 'POST', `/internal/soc/high-scale/${hsId}/close`, { headers: soc });
    assert.equal(closeRunning.status, 409);
    assert.equal(closeRunning.json.error, 'invalid_transition');

    const ks = await request(baseUrl, 'POST', '/internal/soc/kill-switch', {
      headers: soc,
      body: { active: true, reason: 'governance test' },
    });
    assert.equal(ks.status, 200);
    assert.ok(ks.json.stopped_request_ids.includes(hsId));
    assert.equal(getStore().highScaleRequests.find((r) => r.id === hsId).state, 'stopped');
    assert.ok(getStore().auditLog.some((a) => a.action === 'high_scale.kill_switch_auto_stop'));
    assert.ok(getStore().auditLog.some((a) => a.action === 'high_scale.adapter_stub_stopped'));

    const stopAgain = await request(baseUrl, 'POST', `/internal/soc/high-scale/${hsId}/stop`, { headers: soc });
    assert.equal(stopAgain.status, 409);
    assert.equal(stopAgain.json.error, 'not_running');

    const closeWithoutReport = await request(baseUrl, 'POST', `/internal/soc/high-scale/${hsId}/close`, { headers: soc });
    assert.equal(closeWithoutReport.status, 409);
    assert.equal(closeWithoutReport.json.error, 'post_test_report_required');

    const engineerDenied = await request(baseUrl, 'POST', `/internal/soc/high-scale/${hsId}/post-test-report`, {
      headers: demoHeaders('engineer'),
      body: { impact_summary: 'blocked' },
    });
    assert.equal(engineerDenied.status, 403);

    await request(baseUrl, 'POST', `/internal/soc/high-scale/${hsId}/notes`, {
      headers: soc,
      body: { body: 'token ast_secret12345678 in note Bearer abc.def secret leak' },
    });

    const reportRes = await request(baseUrl, 'POST', `/internal/soc/high-scale/${hsId}/post-test-report`, {
      headers: soc,
      body: {
        impact_summary: 'ast_secret12345678 observed',
        recommendations: 'rotate agc_secret12345678',
        secret: 'must-not-persist',
        customer_summary: 'Bearer abc.def',
      },
    });
    assert.equal(reportRes.status, 201);
    assert.equal(reportRes.json.high_scale_request_id, hsId);
    assert.equal(reportRes.json.adapter.traffic_generated, false);
    assert.ok(reportRes.json.timeline.length > 0);

    const serialized = JSON.stringify(reportRes.json);
    assert.doesNotMatch(serialized, /ast_secret12345678/);
    assert.doesNotMatch(serialized, /agc_secret12345678/);
    assert.doesNotMatch(serialized, /Bearer abc\.def/);
    assert.doesNotMatch(serialized, /must-not-persist/);

    const stored = getStore().socReports.find((r) => r.high_scale_request_id === hsId);
    const storedJson = JSON.stringify(stored);
    assert.doesNotMatch(storedJson, /ast_secret12345678/);
    assert.doesNotMatch(storedJson, /agc_secret12345678/);
    assert.doesNotMatch(storedJson, /must-not-persist/);

    assert.ok(
      getStore().auditLog.some(
        (a) => a.action === 'high_scale.post_test_report_created' && a.resource_id === reportRes.json.id,
      ),
    );

    const updateRes = await request(baseUrl, 'POST', `/internal/soc/high-scale/${hsId}/post-test-report`, {
      headers: soc,
      body: { residual_risk: 'low after remediation' },
    });
    assert.equal(updateRes.status, 200);
    assert.equal(updateRes.json.id, reportRes.json.id);
    assert.equal(updateRes.json.residual_risk, 'low after remediation');
    assert.ok(updateRes.json.recommendations.includes('[REDACTED]'));
    assert.doesNotMatch(updateRes.json.recommendations, /agc_secret12345678/);
    assert.ok(
      getStore().auditLog.some(
        (a) => a.action === 'high_scale.post_test_report_updated' && a.resource_id === reportRes.json.id,
      ),
    );

    const closed = await request(baseUrl, 'POST', `/internal/soc/high-scale/${hsId}/close`, { headers: soc });
    assert.equal(closed.status, 200);
    assert.equal(closed.json.state, 'closed');
  });

  it('denies engineer on high-scale telemetry routes', async () => {
    const soc = socPrimary();
    const created = await request(baseUrl, 'POST', '/v1/high-scale-requests', {
      headers: demoHeaders('engineer'),
      body: validHighScaleRequestPayload({ objective: 'telemetry rbac' }),
    });
    const hsId = created.json.id;

    const postDenied = await request(baseUrl, 'POST', `/internal/soc/high-scale/${hsId}/telemetry`, {
      headers: demoHeaders('engineer'),
      body: { category: 'external_availability', live_status: 'stable' },
    });
    assert.equal(postDenied.status, 403);

    const getDenied = await request(baseUrl, 'GET', `/internal/soc/high-scale/${hsId}/telemetry`, {
      headers: demoHeaders('engineer'),
    });
    assert.equal(getDenied.status, 403);
  });

  it('rejects telemetry before scheduled/running/stopped/closed and records safe metadata when active', async () => {
    const soc = socPrimary();
    const created = await request(baseUrl, 'POST', '/v1/high-scale-requests', {
      headers: demoHeaders('engineer'),
      body: validHighScaleRequestPayload({ objective: 'telemetry lifecycle' }),
    });
    const hsId = created.json.id;

    const tooEarly = await request(baseUrl, 'POST', `/internal/soc/high-scale/${hsId}/telemetry`, {
      headers: soc,
      body: { category: 'external_availability', live_status: 'stable' },
    });
    assert.equal(tooEarly.status, 409);
    assert.equal(tooEarly.json.error, 'telemetry_not_active');

    await uploadAndAcceptArtifacts(hsId, soc);
    await dualSocApprove(hsId);

    const approvedOnly = await request(baseUrl, 'POST', `/internal/soc/high-scale/${hsId}/telemetry`, {
      headers: soc,
      body: { category: 'agent_health' },
    });
    assert.equal(approvedOnly.status, 409);
    assert.equal(approvedOnly.json.error, 'telemetry_not_active');

    const activeStart = new Date(Date.now() - 60000).toISOString();
    const activeEnd = new Date(Date.now() + 3600000).toISOString();
    await request(baseUrl, 'POST', `/internal/soc/high-scale/${hsId}/schedule`, {
      headers: soc,
      body: { window_start: activeStart, window_end: activeEnd },
    });

    const scheduledOk = await request(baseUrl, 'POST', `/internal/soc/high-scale/${hsId}/telemetry`, {
      headers: soc,
      body: {
        category: 'external_availability',
        live_status: 'stable',
        metrics: { http_error_rate: 0.01, latency_p99_ms: 120 },
      },
    });
    assert.equal(scheduledOk.status, 201);
    assert.equal(scheduledOk.json.category, 'external_availability');

    await request(baseUrl, 'POST', '/internal/soc/kill-switch', {
      headers: soc,
      body: { active: false },
    });

    const started = await request(baseUrl, 'POST', `/internal/soc/high-scale/${hsId}/start`, { headers: soc });
    assert.equal(started.status, 200);

    const forbidden = await request(baseUrl, 'POST', `/internal/soc/high-scale/${hsId}/telemetry`, {
      headers: soc,
      body: {
        category: 'service_health',
        metrics: { nested: { raw_log: 'must not store' } },
      },
    });
    assert.equal(forbidden.status, 400);
    assert.equal(forbidden.json.error, 'forbidden_telemetry_fields');
    assert.equal(
      getStore().highScaleTelemetry.filter((t) => t.high_scale_request_id === hsId).length,
      1,
    );

    const recorded = await request(baseUrl, 'POST', `/internal/soc/high-scale/${hsId}/telemetry`, {
      headers: soc,
      body: {
        category: 'mitigation',
        live_status: 'mitigating',
        source: 'provider-dashboard-metadata',
      },
    });
    assert.equal(recorded.status, 201);

    const listed = await request(baseUrl, 'GET', `/internal/soc/high-scale/${hsId}/telemetry`, { headers: soc });
    assert.equal(listed.status, 200);
    assert.equal(listed.json.items.length, 2);
    assert.ok(listed.json.items.every((t) => t.tenant_id === 'ten_demo'));
    assert.ok(
      getStore().auditLog.some(
        (a) =>
          a.action === 'high_scale.telemetry_recorded' &&
          a.metadata?.category === 'mitigation' &&
          a.metadata?.high_scale_request_id === hsId &&
          a.metadata?.metrics === undefined,
      ),
    );

    await request(baseUrl, 'POST', `/internal/soc/high-scale/${hsId}/stop`, { headers: soc });

    const reportRes = await request(baseUrl, 'POST', `/internal/soc/high-scale/${hsId}/post-test-report`, {
      headers: soc,
      body: { impact_summary: 'telemetry summary check' },
    });
    assert.equal(reportRes.status, 201);
    assert.equal(reportRes.json.telemetry_summary.record_count, 2);
    assert.equal(reportRes.json.telemetry_summary.category_counts.external_availability, 1);
    assert.equal(reportRes.json.telemetry_summary.category_counts.mitigation, 1);
    assert.equal(reportRes.json.telemetry_summary.latest_live_status, 'mitigating');
    assert.ok(reportRes.json.telemetry_summary.latest_live_status_at);
    const reportJson = JSON.stringify(reportRes.json);
    assert.doesNotMatch(reportJson, /raw_log/);
  });

  it('legacy artifact set without SOC-009 proof types blocks SOC approve with structured requirements', async () => {
    const soc = demoHeaders('soc', 'ten_demo', 'usr_soc');
    const created = await request(baseUrl, 'POST', '/v1/high-scale-requests', {
      headers: demoHeaders('engineer'),
      body: validHighScaleRequestPayload({ objective: 'legacy pack only' }),
    });
    assert.equal(created.status, 201);
    const hsId = created.json.id;
    await acceptLegacyAuthorizationArtifactsOnly(baseUrl, hsId, soc);

    const blocked = await request(baseUrl, 'POST', `/internal/soc/high-scale/${hsId}/approve`, {
      headers: soc,
    });
    assert.equal(blocked.status, 409);
    assert.equal(blocked.json.error, 'authorization_pack_incomplete');
    assert.ok(Array.isArray(blocked.json.requirements));
    const missingTypes = blocked.json.requirements
      .filter((r) => r.status !== 'accepted')
      .map((r) => r.type);
    assert.ok(missingTypes.includes('business_approval'));
    assert.ok(missingTypes.includes('legal_approval'));
    assert.ok(missingTypes.includes('scope_and_rate_plan'));
    assert.ok(missingTypes.includes('abort_criteria'));
  });

  it('provider approval checklist gates SOC approve until provider evidence is accepted', async () => {
    const soc = demoHeaders('soc', 'ten_demo', 'usr_soc');
    const created = await request(baseUrl, 'POST', '/v1/high-scale-requests', {
      headers: demoHeaders('engineer'),
      body: validHighScaleRequestPayload({
        objective: 'provider checklist',
        provider_context: { requires_provider_approval: true, provider_name: 'Cloudflare' },
      }),
    });
    assert.equal(created.status, 201);
    const hsId = created.json.id;

    const reqAfterCreate = getStore().highScaleRequests.find((r) => r.id === hsId);
    assert.equal(reqAfterCreate.provider_approval_checklist.length, 1);
    assert.equal(reqAfterCreate.provider_approval_checklist[0].provider_name, 'Cloudflare');
    assert.equal(reqAfterCreate.provider_approval_checklist[0].status, 'missing');

    await acceptRequiredAuthorizationArtifactsOnly(baseUrl, hsId, soc);

    const blocked = await request(baseUrl, 'POST', `/internal/soc/high-scale/${hsId}/approve`, {
      headers: soc,
    });
    assert.equal(blocked.status, 409);
    assert.equal(blocked.json.error, 'authorization_pack_incomplete');

    const providerUp = await request(baseUrl, 'POST', `/v1/high-scale-requests/${hsId}/artifacts`, {
      headers: demoHeaders('engineer'),
      body: {
        type: 'provider_approval',
        provider_name: 'Cloudflare',
        provider_ref: 'CF-CASE-1001',
        reference_uri: 'metadata://provider/cloudflare',
      },
    });
    assert.equal(providerUp.status, 201);

    const pendingReq = getStore().highScaleRequests.find((r) => r.id === hsId);
    assert.equal(pendingReq.provider_approval_checklist[0].status, 'pending_review');
    assert.equal(pendingReq.provider_approval_checklist[0].artifact_id, providerUp.json.id);

    const providerReview = await request(
      baseUrl,
      'POST',
      `/internal/soc/high-scale/${hsId}/artifacts/${providerUp.json.id}/review`,
      { headers: soc, body: { status: 'accepted' } },
    );
    assert.equal(providerReview.status, 200);

    const acceptedReq = getStore().highScaleRequests.find((r) => r.id === hsId);
    assert.equal(acceptedReq.provider_approval_checklist[0].status, 'partial');
    assert.ok(acceptedReq.provider_approval_checklist[0].missing_fields.includes('valid_window'));

    const blockedPartial = await request(baseUrl, 'POST', `/internal/soc/high-scale/${hsId}/approve`, {
      headers: soc,
    });
    assert.equal(blockedPartial.status, 409);
    assert.equal(blockedPartial.json.error, 'authorization_pack_incomplete');

    const providerComplete = await request(baseUrl, 'POST', `/v1/high-scale-requests/${hsId}/artifacts`, {
      headers: demoHeaders('engineer'),
      body: {
        type: 'provider_approval',
        provider_name: 'Cloudflare',
        provider_ref: 'CF-CASE-1002',
        reference_uri: 'metadata://provider/cloudflare-complete',
        approval_reference: 'CF-CASE-1002',
        valid_window: {
          valid_to: new Date(Date.now() + 86400000).toISOString(),
        },
        approved_targets: ['tg_1'],
        approved_scenario_families: ['volumetric_metadata'],
        contact_path: 'provider-war-room@example.invalid',
        approved_limits: { max_rate: '500_rps_metadata', max_duration_minutes: 45 },
        provider_specific_evidence: { ticket: 'CF-CASE-1002' },
        emergency_stop_path: 'provider-stop-bridge',
      },
    });
    assert.equal(providerComplete.status, 201);
    const completeReview = await request(
      baseUrl,
      'POST',
      `/internal/soc/high-scale/${hsId}/artifacts/${providerComplete.json.id}/review`,
      { headers: soc, body: { status: 'accepted' } },
    );
    assert.equal(completeReview.status, 200);
    const completeReq = getStore().highScaleRequests.find((r) => r.id === hsId);
    assert.equal(completeReq.provider_approval_checklist[0].status, 'accepted');
    assert.deepEqual(completeReq.provider_approval_checklist[0].missing_fields, []);

    await dualSocApprove(hsId);
  });

  describe('high-scale adapter runtime mode', () => {
    async function startReadyRequest(adapterEnv) {
      freshStore();
      const localServer = createServer({
        env: {
          ...process.env,
          ASTRANULL_NO_PERSIST: '1',
          ASTRANULL_HIGH_SCALE_ADAPTER_MODE: adapterEnv,
        },
      });
      localServer.listen(0);
      const { port } = localServer.address();
      const url = `http://127.0.0.1:${port}`;
      const soc = socPrimary();
      const created = await request(url, 'POST', '/v1/high-scale-requests', {
        headers: demoHeaders('engineer'),
        body: validHighScaleRequestPayload({ objective: `adapter mode ${adapterEnv}` }),
      });
      const hsId = created.json.id;
      await acceptHighScaleAuthorizationPack(url, hsId, soc);
      const first = await request(url, 'POST', `/internal/soc/high-scale/${hsId}/approve`, {
        headers: socPrimary(),
      });
      assert.equal(first.status, 200);
      const second = await request(url, 'POST', `/internal/soc/high-scale/${hsId}/approve`, {
        headers: socSecondary(),
      });
      assert.equal(second.status, 200);
      const activeStart = new Date(Date.now() - 60000).toISOString();
      const activeEnd = new Date(Date.now() + 3600000).toISOString();
      await request(url, 'POST', `/internal/soc/high-scale/${hsId}/schedule`, {
        headers: soc,
        body: { window_start: activeStart, window_end: activeEnd },
      });
      const startRes = await request(url, 'POST', `/internal/soc/high-scale/${hsId}/start`, { headers: soc });
      localServer.close();
      return { startRes, hsId };
    }

    it('denies start when runtime highScaleAdapterMode is disabled', async () => {
      const { startRes, hsId } = await startReadyRequest('disabled');
      assert.equal(startRes.status, 409);
      assert.equal(startRes.json.error, 'adapter_disabled');
      assert.equal(getStore().highScaleRequests.find((r) => r.id === hsId).state, 'scheduled');
      assert.ok(
        getStore().auditLog.some(
          (a) => a.action === 'high_scale.start_gate_denied' && a.metadata?.reason === 'adapter_disabled',
        ),
      );
      assert.equal(
        getStore().auditLog.some((a) => a.action === 'high_scale.adapter_stub_started'),
        false,
      );
    });

    it('denies start when runtime highScaleAdapterMode is governed-adapter', async () => {
      const { startRes, hsId } = await startReadyRequest('governed-adapter');
      assert.equal(startRes.status, 503);
      assert.equal(startRes.json.error, 'governed_adapter_not_configured');
      assert.equal(getStore().highScaleRequests.find((r) => r.id === hsId).state, 'scheduled');
      assert.ok(
        getStore().auditLog.some(
          (a) =>
            a.action === 'high_scale.start_gate_denied' &&
            a.metadata?.reason === 'governed_adapter_not_configured',
        ),
      );
      assert.equal(
        getStore().auditLog.some((a) => a.action === 'high_scale.adapter_stub_started'),
        false,
      );
    });
  });

  it('expired provider approval window blocks SOC approve via checklist', async () => {
    const soc = demoHeaders('soc', 'ten_demo', 'usr_soc');
    const created = await request(baseUrl, 'POST', '/v1/high-scale-requests', {
      headers: demoHeaders('engineer'),
      body: validHighScaleRequestPayload({
        objective: 'expired provider window',
        provider_context: { requires_provider_approval: true, provider_name: 'Akamai' },
      }),
    });
    const hsId = created.json.id;
    await uploadAndAcceptArtifacts(hsId, soc);

    const pastEnd = new Date(Date.now() - 3600000).toISOString();
    const providerUp = await request(baseUrl, 'POST', `/v1/high-scale-requests/${hsId}/artifacts`, {
      headers: demoHeaders('engineer'),
      body: {
        type: 'provider_approval',
        provider_name: 'Akamai',
        valid_window: { valid_to: pastEnd },
        reference_uri: 'metadata://provider/akamai',
      },
    });
    assert.equal(providerUp.status, 201);

    const stored = getStore().highScaleRequests.find((r) => r.id === hsId);
    assert.equal(stored.provider_approval_checklist[0].status, 'expired');

    await request(
      baseUrl,
      'POST',
      `/internal/soc/high-scale/${hsId}/artifacts/${providerUp.json.id}/review`,
      { headers: soc, body: { status: 'accepted' } },
    );
    assert.equal(
      getStore().highScaleRequests.find((r) => r.id === hsId).provider_approval_checklist[0].status,
      'expired',
    );

    const blocked = await request(baseUrl, 'POST', `/internal/soc/high-scale/${hsId}/approve`, {
      headers: soc,
    });
    assert.equal(blocked.status, 409);
    assert.equal(blocked.json.error, 'authorization_pack_incomplete');
  });
});
