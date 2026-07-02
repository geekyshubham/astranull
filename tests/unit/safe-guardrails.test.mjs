import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { getCheckById } from '../../src/contracts/checks.mjs';
import { createTargetGroup } from '../../src/services/targetGroups.mjs';
import { cancelTestRun, ingestObservation, startTestRun } from '../../src/services/testRuns.mjs';
import { getStore } from '../../src/store.mjs';
import { demoHeaders, request } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';

const ctx = { tenantId: 'ten_demo', userId: 'u1', role: 'engineer' };

function seedAgent() {
  getStore().agents.push({
    id: 'ag_guard',
    tenant_id: 'ten_demo',
    status: 'online',
    capabilities: ['canary', 'packet', 'heartbeat'],
    target_group_id: 'tg_1',
  });
}

function ackedJobForAgent(agentId, runId) {
  const job = getStore().agentJobs.find((j) => j.agent_id === agentId && j.test_run_id === runId);
  assert.ok(job, 'expected agent job for run');
  job.status = 'acked';
  job.acked_at = new Date().toISOString();
  return job;
}

function observationBody(run, job, extra = {}) {
  return {
    agent_job_id: job.id,
    test_run_id: run.id,
    target_id: run.target_id,
    nonce_hash: run.correlation.nonce_hash,
    ...extra,
  };
}

function completeRunsForGroup() {
  for (const run of getStore().testRuns.filter((r) => r.target_group_id === 'tg_1')) {
    run.status = 'verdicted';
    run.completed_at = new Date().toISOString();
  }
}

describe('safe-test guardrails', () => {
  it('rejects runs outside configured safe_test_windows', () => {
    freshStore();
    seedAgent();
    const group = getStore().targetGroups.find((g) => g.id === 'tg_1');
    group.safe_test_windows = [
      {
        start_at: new Date(Date.now() + 3_600_000).toISOString(),
        end_at: new Date(Date.now() + 7_200_000).toISOString(),
        reason: 'maintenance',
      },
    ];
    const result = startTestRun(ctx, {
      check_id: 'origin.direct_bypass.safe',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
    });
    assert.equal(result.error, 'safe_window_closed');
    assert.equal(result.status, 429);
    assert.ok(getStore().auditLog.some((a) => a.action === 'test_run.safe_window_denied'));
  });

  it('permits runs inside a current safe_test_window', () => {
    freshStore();
    seedAgent();
    const group = getStore().targetGroups.find((g) => g.id === 'tg_1');
    group.safe_test_windows = [
      {
        start_at: new Date(Date.now() - 60_000).toISOString(),
        end_at: new Date(Date.now() + 60_000).toISOString(),
      },
    ];
    const result = startTestRun(ctx, {
      check_id: 'origin.direct_bypass.safe',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
    });
    assert.ok(result.run);
    assert.ok(result.run.safety_constraints);
    assert.equal(result.run.safety_constraints.max_runs_per_hour, 60);
  });

  it('enforces max_runs_per_hour for the tenant', () => {
    freshStore();
    seedAgent();
    const group = getStore().targetGroups.find((g) => g.id === 'tg_1');
    group.safety_policy = { max_runs_per_hour: 1, min_seconds_between_runs: 0 };
    const first = startTestRun(ctx, {
      check_id: 'origin.direct_bypass.safe',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
    });
    assert.ok(first.run);
    completeRunsForGroup();
    const second = startTestRun(ctx, {
      check_id: 'dns.authoritative_response.safe',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
    });
    assert.equal(second.error, 'safe_rate_cap_exceeded');
    assert.equal(second.status, 429);
    assert.ok(getStore().auditLog.some((a) => a.action === 'test_run.safe_rate_denied'));
  });

  it('enforces min_seconds_between_runs on the target group', () => {
    freshStore();
    seedAgent();
    const group = getStore().targetGroups.find((g) => g.id === 'tg_1');
    group.safety_policy = { max_runs_per_hour: 60, min_seconds_between_runs: 300 };
    const first = startTestRun(ctx, {
      check_id: 'origin.direct_bypass.safe',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
    });
    assert.ok(first.run);
    const cancelled = cancelTestRun(ctx, first.run.id);
    assert.ok(cancelled.run);
    const retry = startTestRun(ctx, {
      check_id: 'dns.authoritative_response.safe',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
    });
    assert.equal(retry.error, 'safe_min_interval_active');
    assert.equal(retry.status, 429);
    assert.ok(getStore().auditLog.some((a) => a.action === 'test_run.safe_interval_denied'));
  });

  it('rejects observations beyond per-run max_events', () => {
    freshStore();
    seedAgent();
    const check = getCheckById('l3.forbidden_tcp_port.safe');
    assert.equal(check.safety_constraints.max_events, 3);
    const started = startTestRun(ctx, {
      check_id: check.check_id,
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
    });
    assert.ok(started.run);
    const runId = started.run.id;
    getStore().events.push(
      {
        id: 'event_guard_fill_1',
        tenant_id: 'ten_demo',
        test_run_id: runId,
        signal_type: 'guard_fill',
        timestamp: new Date().toISOString(),
      },
      {
        id: 'event_guard_fill_2',
        tenant_id: 'ten_demo',
        test_run_id: runId,
        signal_type: 'guard_fill',
        timestamp: new Date().toISOString(),
      },
    );
    const agentCtx = { tenantId: 'ten_demo', userId: 'agent', role: 'agent' };
    const job = ackedJobForAgent('ag_guard', runId);
    const denied = ingestObservation(
      agentCtx,
      'ag_guard',
      observationBody(started.run, job),
    );
    assert.equal(denied.error, 'event_cap_exceeded');
    assert.equal(denied.status, 429);
    assert.ok(getStore().auditLog.some((a) => a.action === 'test_run.event_cap_denied'));
  });

  it('rejects observations for terminal runs', () => {
    freshStore();
    seedAgent();
    const started = startTestRun(ctx, {
      check_id: 'origin.direct_bypass.safe',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
    });
    const run = getStore().testRuns.find((r) => r.id === started.run.id);
    run.status = 'verdicted';
    const job = ackedJobForAgent('ag_guard', run.id);
    const denied = ingestObservation(
      { tenantId: 'ten_demo', userId: 'agent', role: 'agent' },
      'ag_guard',
      observationBody(run, job),
    );
    assert.equal(denied.error, 'run_not_collecting');
    assert.equal(denied.status, 409);
    assert.ok(getStore().auditLog.some((a) => a.action === 'observation.rejected_inactive_run'));
  });

  it('rejects missing agent_job_id and audits observation.rejected', () => {
    freshStore();
    seedAgent();
    const started = startTestRun(ctx, {
      check_id: 'origin.direct_bypass.safe',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
    });
    const agentCtx = { tenantId: 'ten_demo', userId: 'agent', role: 'agent' };
    const denied = ingestObservation(agentCtx, 'ag_guard', {
      test_run_id: started.run.id,
      nonce_hash: started.run.correlation.nonce_hash,
    });
    assert.equal(denied.error, 'missing_agent_job_id');
    assert.equal(denied.status, 400);
    assert.ok(
      getStore().auditLog.some(
        (a) => a.action === 'observation.rejected' && a.metadata?.reason === 'missing_agent_job_id',
      ),
    );
    assert.equal(
      getStore().events.filter((e) => e.signal_type === 'agent_observation').length,
      0,
    );
  });

  it('rejects observation for another agent job', () => {
    freshStore();
    seedAgent();
    getStore().agents.push({
      id: 'ag_other',
      tenant_id: 'ten_demo',
      status: 'online',
      capabilities: ['canary'],
      target_group_id: 'tg_1',
    });
    const started = startTestRun(ctx, {
      check_id: 'origin.direct_bypass.safe',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
    });
    const job = ackedJobForAgent('ag_guard', started.run.id);
    const agentCtx = { tenantId: 'ten_demo', userId: 'agent', role: 'agent' };
    const denied = ingestObservation(agentCtx, 'ag_other', observationBody(started.run, job));
    assert.equal(denied.error, 'agent_job_mismatch');
    assert.equal(denied.status, 403);
    assert.ok(getStore().auditLog.some((a) => a.action === 'observation.rejected'));
    assert.equal(job.status, 'acked');
  });

  it('rejects nonce mismatch between body and assigned job', () => {
    freshStore();
    seedAgent();
    const started = startTestRun(ctx, {
      check_id: 'origin.direct_bypass.safe',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
    });
    const job = ackedJobForAgent('ag_guard', started.run.id);
    const agentCtx = { tenantId: 'ten_demo', userId: 'agent', role: 'agent' };
    const denied = ingestObservation(agentCtx, 'ag_guard', {
      ...observationBody(started.run, job),
      nonce_hash: 'sha256:wrongnonce',
    });
    assert.equal(denied.error, 'agent_job_mismatch');
    assert.equal(job.status, 'acked');
  });

  it('rejects observation when job is pending (not acked)', () => {
    freshStore();
    seedAgent();
    const started = startTestRun(ctx, {
      check_id: 'origin.direct_bypass.safe',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
    });
    const job = getStore().agentJobs.find((j) => j.agent_id === 'ag_guard');
    assert.equal(job.status, 'pending');
    const agentCtx = { tenantId: 'ten_demo', userId: 'agent', role: 'agent' };
    const denied = ingestObservation(agentCtx, 'ag_guard', observationBody(started.run, job));
    assert.equal(denied.error, 'agent_job_not_acked');
    assert.equal(job.status, 'pending');
  });

  it('rejects raw packet fields in observation metadata without creating events', () => {
    freshStore();
    seedAgent();
    const started = startTestRun(ctx, {
      check_id: 'origin.direct_bypass.safe',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
    });
    const job = ackedJobForAgent('ag_guard', started.run.id);
    const agentCtx = { tenantId: 'ten_demo', userId: 'agent', role: 'agent' };
    const denied = ingestObservation(agentCtx, 'ag_guard', {
      ...observationBody(started.run, job),
      metadata: { raw_packet: { bytes: '00' } },
    });
    assert.equal(denied.error, 'raw_packet_rejected');
    assert.equal(
      getStore().events.filter((e) => e.signal_type === 'agent_observation').length,
      0,
    );
  });

  it('rejects nested headers in observation metadata without creating events', () => {
    freshStore();
    seedAgent();
    const started = startTestRun(ctx, {
      check_id: 'origin.direct_bypass.safe',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
    });
    const job = ackedJobForAgent('ag_guard', started.run.id);
    const agentCtx = { tenantId: 'ten_demo', userId: 'agent', role: 'agent' };
    const denied = ingestObservation(agentCtx, 'ag_guard', {
      ...observationBody(started.run, job),
      metadata: { request: { headers: { authorization: 'Bearer secret' } } },
    });
    assert.equal(denied.error, 'raw_packet_rejected');
    assert.equal(job.status, 'acked');
    assert.equal(
      getStore().events.filter((e) => e.signal_type === 'agent_observation').length,
      0,
    );
  });

  it('rejects nested sample raw_packet in observation metadata', () => {
    freshStore();
    seedAgent();
    const started = startTestRun(ctx, {
      check_id: 'origin.direct_bypass.safe',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
    });
    const job = ackedJobForAgent('ag_guard', started.run.id);
    const agentCtx = { tenantId: 'ten_demo', userId: 'agent', role: 'agent' };
    const denied = ingestObservation(agentCtx, 'ag_guard', {
      ...observationBody(started.run, job),
      metadata: { sample: { raw_packet: 'deadbeef' } },
    });
    assert.equal(denied.error, 'raw_packet_rejected');
    assert.equal(job.status, 'acked');
    assert.equal(
      getStore().events.filter((e) => e.signal_type === 'agent_observation').length,
      0,
    );
  });

  it('rejects nested log_line inside metadata arrays', () => {
    freshStore();
    seedAgent();
    const started = startTestRun(ctx, {
      check_id: 'origin.direct_bypass.safe',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
    });
    const job = ackedJobForAgent('ag_guard', started.run.id);
    const agentCtx = { tenantId: 'ten_demo', userId: 'agent', role: 'agent' };
    const denied = ingestObservation(agentCtx, 'ag_guard', {
      ...observationBody(started.run, job),
      metadata: { lines: [{ log_line: 'nonce seen in access.log' }] },
    });
    assert.equal(denied.error, 'raw_packet_rejected');
    assert.equal(
      getStore().events.filter((e) => e.signal_type === 'agent_observation').length,
      0,
    );
  });

  it('redacts secret-looking metadata before storing observation event', () => {
    freshStore();
    seedAgent();
    const started = startTestRun(ctx, {
      check_id: 'origin.direct_bypass.safe',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
    });
    const job = ackedJobForAgent('ag_guard', started.run.id);
    const agentCtx = { tenantId: 'ten_demo', userId: 'agent', role: 'agent' };
    const ok = ingestObservation(agentCtx, 'ag_guard', {
      ...observationBody(started.run, job),
      metadata: { api_key: 'ast_supersecrettoken123456', note: 'ok' },
    });
    assert.equal(ok.error, undefined);
    const evt = getStore().events.find((e) => e.signal_type === 'agent_observation');
    assert.equal(evt.metadata.api_key, '[REDACTED]');
    assert.equal(evt.metadata.note, 'ok');
    assert.equal(job.status, 'observed');
    assert.ok(job.observed_at);
  });

  it('stores safety policy fields on createTargetGroup', () => {
    freshStore();
    const adminCtx = { tenantId: 'ten_demo', userId: 'u1', role: 'admin' };
    const group = createTargetGroup(adminCtx, {
      name: 'Guarded',
      timezone: 'America/New_York',
      safe_test_windows: [{ start_at: '2026-01-01T00:00:00.000Z', end_at: '2026-12-31T00:00:00.000Z' }],
      safety_policy: { max_runs_per_hour: 12, min_seconds_between_runs: 30 },
    });
    assert.equal(group.timezone, 'America/New_York');
    assert.equal(group.safe_test_windows.length, 1);
    assert.equal(group.safety_policy.max_runs_per_hour, 12);
    assert.equal(group.safety_policy.min_seconds_between_runs, 30);
  });

  it('returns not_cancellable for verdicted runs via service and HTTP', async () => {
    freshStore();
    seedAgent();
    const started = startTestRun(ctx, {
      check_id: 'origin.direct_bypass.safe',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
    });
    getStore().testRuns.find((r) => r.id === started.run.id).status = 'verdicted';
    const denied = cancelTestRun(ctx, started.run.id);
    assert.equal(denied.error, 'not_cancellable');
    assert.equal(denied.status, 409);

    const server = createServer();
    await new Promise((resolve) => server.listen(0, resolve));
    const baseUrl = `http://127.0.0.1:${server.address().port}`;
    try {
      const res = await request(baseUrl, 'POST', `/v1/test-runs/${started.run.id}/cancel`, {
        headers: demoHeaders('engineer'),
      });
      assert.equal(res.status, 409);
      assert.equal(res.json.error, 'not_cancellable');
    } finally {
      server.close();
    }
  });
});
