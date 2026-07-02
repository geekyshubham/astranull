import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createPostgresHighScaleServices } from '../../src/persistence/postgres/highScaleServiceAdapters.mjs';
import { validHighScaleRequestPayload, artifactProofBody } from '../helpers/highScalePayload.mjs';
import { REQUIRED_ARTIFACT_TYPES } from '../../src/lib/highScalePolicy.mjs';

const CTX_A = { tenantId: 'ten_demo', userId: 'soc_a', role: 'soc' };
const CTX_B = { tenantId: 'ten_demo', userId: 'soc_b', role: 'soc' };
const CTX_ENG = { tenantId: 'ten_demo', userId: 'eng_1', role: 'engineer' };

function memoryRepositories(overrides = {}) {
  const state = {
    requests: [],
    artifacts: [],
    notes: [],
    telemetry: [],
    reports: {},
    killSwitch: { active: false },
    testRuns: [],
    audit: [],
  };

  let targetGroupSnapshot = {
    id: 'tg_1',
    targets: [{ id: 'tgt_1', kind: 'fqdn', value: 'app.example' }],
  };
  const coreCatalog = {
    async getTargetGroup(ctx, id) {
      if (id !== 'tg_1') return null;
      if (!targetGroupSnapshot) return null;
      return {
        id: targetGroupSnapshot.id,
        targets: [...(targetGroupSnapshot.targets ?? [])],
      };
    },
    setTargetGroupSnapshot(next) {
      targetGroupSnapshot = next;
    },
  };

  const highScale = {
    async createHighScaleRequest(ctx, record) {
      const row = { ...record, tenant_id: ctx.tenantId };
      state.requests.push(row);
      return row;
    },
    async listHighScaleRequests(ctx) {
      return state.requests.filter((r) => r.tenant_id === ctx.tenantId);
    },
    async getHighScaleRequest(ctx, id) {
      const req = state.requests.find((r) => r.tenant_id === ctx.tenantId && r.id === id);
      return req ? { ...req } : null;
    },
    async updateHighScaleRequest(ctx, id, patch) {
      const idx = state.requests.findIndex((r) => r.tenant_id === ctx.tenantId && r.id === id);
      if (idx < 0) return null;
      state.requests[idx] = { ...state.requests[idx], ...patch };
      return { ...state.requests[idx] };
    },
    async listRunningHighScaleRequests(ctx) {
      return state.requests.filter((r) => r.tenant_id === ctx.tenantId && r.state === 'running');
    },
    async insertAuthorizationArtifact(ctx, requestId, artifact) {
      state.artifacts.push({ requestId, artifact });
      return artifact;
    },
    async updateAuthorizationArtifact() {
      return null;
    },
    async listAuthorizationArtifacts() {
      return [];
    },
    async appendSocNote(ctx, requestId, note) {
      const row = { ...note, tenant_id: ctx.tenantId, high_scale_request_id: requestId };
      state.notes.push(row);
      return row;
    },
    async listSocNotes(ctx, requestId) {
      return state.notes.filter((n) => n.tenant_id === ctx.tenantId && n.high_scale_request_id === requestId);
    },
    async appendTelemetry(ctx, record) {
      const row = { ...record, tenant_id: ctx.tenantId };
      state.telemetry.push(row);
      return row;
    },
    async listTelemetry(ctx, requestId) {
      return state.telemetry.filter(
        (t) => t.tenant_id === ctx.tenantId && t.high_scale_request_id === requestId,
      );
    },
    async getSocReport(ctx, requestId) {
      return state.reports[`${ctx.tenantId}:${requestId}`] ?? null;
    },
    async upsertSocReport(ctx, requestId, report) {
      state.reports[`${ctx.tenantId}:${requestId}`] = report;
      return report;
    },
  };

  const killSwitch = {
    async isKillSwitchActiveForTenant() {
      return state.killSwitch.active;
    },
    async getKillSwitchRecord(ctx) {
      return { ...state.killSwitch, tenant_id: ctx.tenantId };
    },
    async upsertKillSwitch(ctx, patch) {
      state.killSwitch = { ...state.killSwitch, ...patch, tenant_id: ctx.tenantId };
      return state.killSwitch;
    },
  };

  const validationEvidence = {
    async listTestRuns(ctx, options = {}) {
      let runs = state.testRuns.filter((r) => r.tenant_id === ctx.tenantId);
      if (options.statuses) runs = runs.filter((r) => options.statuses.includes(r.status));
      return runs;
    },
    async updateTestRun(ctx, id, patch) {
      const idx = state.testRuns.findIndex((r) => r.id === id);
      if (idx >= 0) state.testRuns[idx] = { ...state.testRuns[idx], ...patch };
      return state.testRuns[idx];
    },
  };

  const audit = {
    async appendAuditEvent(entry) {
      state.audit.push(entry);
    },
  };

  const probeJobs = {
    async cancelOpenProbeJobsForTestRuns(ctx, testRunIds, cancelledAt) {
      const open = (overrides.probeJobsOpen ?? []).filter(
        (j) =>
          j.tenant_id === ctx.tenantId &&
          testRunIds.includes(j.test_run_id) &&
          (j.status === 'pending' || j.status === 'leased'),
      );
      for (const job of open) {
        job.status = 'cancelled';
        job.completed_at = cancelledAt;
      }
      return open.map((j) => ({ ...j }));
    },
  };

  return {
    state,
    coreCatalog,
    repositories: {
      coreCatalog,
      highScale,
      killSwitch,
      validationEvidence,
      audit,
      probeJobs,
      notifications: overrides.notifications ?? null,
    },
    probeJobs,
  };
}

async function scheduleReadyForStart(svc, hsId) {
  await acceptPack(svc, hsId);
  await svc.transitionHighScale(CTX_A, hsId, 'approve');
  await svc.transitionHighScale(CTX_B, hsId, 'approve');
  const now = Date.now();
  await svc.transitionHighScale(CTX_A, hsId, 'schedule', {
    window_start: new Date(now - 60_000).toISOString(),
    window_end: new Date(now + 3600_000).toISOString(),
  });
}

async function acceptPack(svc, hsId) {
  for (const type of REQUIRED_ARTIFACT_TYPES) {
    const art = await svc.addArtifact(CTX_ENG, hsId, artifactProofBody(type));
    await svc.reviewArtifact(CTX_A, hsId, art.id, { status: 'accepted' });
  }
  const req = await svc.listHighScaleRequests(CTX_A);
  const hs = req.find((r) => r.id === hsId);
  for (const item of hs?.provider_approval_checklist ?? []) {
    const art = await svc.addArtifact(CTX_ENG, hsId, {
      type: 'provider_approval',
      provider_name: item.provider_name,
      reference_uri: 'metadata://pack/provider',
      approval_reference: 'PROV-REF-001',
      valid_window: artifactProofBody('test_plan').valid_window,
      approved_targets: ['tg_1'],
      approved_scenario_families: ['volumetric_metadata'],
      contact_path: 'provider-war-room@example.invalid',
      approved_limits: { max_rate: '500_rps_metadata', max_duration_minutes: 45 },
      provider_specific_evidence: {
        approval_path: item.approval_path ?? 'manual_coordination',
        provider_key: item.provider_key ?? 'generic',
      },
      emergency_stop_path: 'provider-stop-bridge',
    });
    await svc.reviewArtifact(CTX_A, hsId, art.id, { status: 'accepted' });
  }
}

describe('postgres high-scale service adapters', () => {
  it('createHighScaleRequest validates declared target group and stores authorization pack status', async () => {
    const { repositories } = memoryRepositories();
    const svc = createPostgresHighScaleServices(repositories, {
      now: () => new Date('2026-06-01T12:00:00.000Z'),
      newId: (p) => `${p}_test`,
    });
    const created = await svc.createHighScaleRequest(CTX_ENG, validHighScaleRequestPayload());
    assert.equal(created.state, 'submitted');
    assert.equal(created.authorization_pack_status.overall, 'missing');
    const empty = await svc.createHighScaleRequest(CTX_ENG, validHighScaleRequestPayload({ target_group_id: 'tg_missing' }));
    assert.equal(empty.error, 'target_group_not_found');
  });

  it('dual SOC approval sets scope hash from declared targets', async () => {
    const { repositories } = memoryRepositories();
    const svc = createPostgresHighScaleServices(repositories);
    const created = await svc.createHighScaleRequest(CTX_ENG, validHighScaleRequestPayload());
    await acceptPack(svc, created.id);
    const first = await svc.transitionHighScale(CTX_A, created.id, 'approve');
    assert.equal(first.state, 'under_review');
    const dup = await svc.transitionHighScale(CTX_A, created.id, 'approve');
    assert.equal(dup.error, 'duplicate_soc_approval');
    const second = await svc.transitionHighScale(CTX_B, created.id, 'approve');
    assert.equal(second.state, 'approved');
    assert.ok(second.scope_hash);
  });

  it('telemetry rejects forbidden raw fields', async () => {
    const { repositories } = memoryRepositories();
    const svc = createPostgresHighScaleServices(repositories);
    const created = await svc.createHighScaleRequest(CTX_ENG, validHighScaleRequestPayload());
    await acceptPack(svc, created.id);
    await svc.transitionHighScale(CTX_A, created.id, 'approve');
    await svc.transitionHighScale(CTX_B, created.id, 'approve');
    const now = Date.now();
    await svc.transitionHighScale(CTX_A, created.id, 'schedule', {
      window_start: new Date(now - 60_000).toISOString(),
      window_end: new Date(now + 3600_000).toISOString(),
    });
    await svc.transitionHighScale(CTX_A, created.id, 'start');
    const bad = await svc.recordHighScaleTelemetry(CTX_A, created.id, {
      category: 'adapter_metric',
      metrics: { packet_payload: 'secret' },
    });
    assert.equal(bad.error, 'forbidden_telemetry_fields');
  });

  it('emits state-change notifications from options.notifications and survives delivery errors', async () => {
    const notificationCalls = [];
    const notifications = {
      async emitNotification(ctx, payload) {
        notificationCalls.push({ ctx, payload });
      },
    };
    const { repositories } = memoryRepositories();
    const svc = createPostgresHighScaleServices(repositories, { notifications });
    const created = await svc.createHighScaleRequest(CTX_ENG, validHighScaleRequestPayload());
    assert.equal(notificationCalls.length, 1);
    assert.equal(notificationCalls[0].payload.trigger, 'high_scale.state_change');
    assert.equal(notificationCalls[0].payload.metadata.request_id, created.id);

    const throwing = {
      async emitNotification() {
        throw new Error('notify down');
      },
    };
    const { repositories: repos2 } = memoryRepositories();
    const svc2 = createPostgresHighScaleServices(repos2, { notifications: throwing });
    const hs = await svc2.createHighScaleRequest(CTX_ENG, validHighScaleRequestPayload());
    await acceptPack(svc2, hs.id);
    const approved = await svc2.transitionHighScale(CTX_A, hs.id, 'approve');
    assert.equal(approved.state, 'under_review');
  });

  it('second SOC approval fails closed when target group is missing or empty', async () => {
    const { repositories, coreCatalog, state } = memoryRepositories();
    const svc = createPostgresHighScaleServices(repositories);
    const created = await svc.createHighScaleRequest(CTX_ENG, validHighScaleRequestPayload());
    await acceptPack(svc, created.id);
    await svc.transitionHighScale(CTX_A, created.id, 'approve');

    coreCatalog.setTargetGroupSnapshot(null);
    const missing = await svc.transitionHighScale(CTX_B, created.id, 'approve');
    assert.equal(missing.error, 'target_group_not_found');
    assert.equal(missing.status, 404);
    let stored = state.requests.find((r) => r.id === created.id);
    assert.equal(stored.state, 'under_review');
    assert.equal(stored.soc_approvals.length, 1);
    assert.ok(
      state.audit.some(
        (e) => e.action === 'high_scale.approval_gate_denied' && e.metadata?.reason === 'target_group_not_found',
      ),
    );

    coreCatalog.setTargetGroupSnapshot({ id: 'tg_1', targets: [] });
    const empty = await svc.transitionHighScale(CTX_B, created.id, 'approve');
    assert.equal(empty.error, 'target_group_empty');
    assert.equal(empty.status, 400);
    stored = state.requests.find((r) => r.id === created.id);
    assert.equal(stored.state, 'under_review');
    assert.equal(stored.soc_approvals.length, 1);
    assert.ok(
      state.audit.some(
        (e) => e.action === 'high_scale.approval_gate_denied' && e.metadata?.reason === 'target_group_empty',
      ),
    );
  });

  it('start fails closed when scope validation fails before adapter start', async () => {
    const { repositories, coreCatalog, state } = memoryRepositories();
    const svc = createPostgresHighScaleServices(repositories);
    const created = await svc.createHighScaleRequest(CTX_ENG, validHighScaleRequestPayload());
    await acceptPack(svc, created.id);
    await svc.transitionHighScale(CTX_A, created.id, 'approve');
    await svc.transitionHighScale(CTX_B, created.id, 'approve');
    const now = Date.now();
    await svc.transitionHighScale(CTX_A, created.id, 'schedule', {
      window_start: new Date(now - 60_000).toISOString(),
      window_end: new Date(now + 3600_000).toISOString(),
    });

    coreCatalog.setTargetGroupSnapshot({ id: 'tg_1', targets: [] });
    const denied = await svc.transitionHighScale(CTX_A, created.id, 'start');
    assert.equal(denied.error, 'target_group_empty');
    assert.equal(denied.status, 400);
    const stored = state.requests.find((r) => r.id === created.id);
    assert.equal(stored.state, 'scheduled');
    assert.ok(
      state.audit.some(
        (e) => e.action === 'high_scale.start_gate_denied' && e.metadata?.reason === 'target_group_empty',
      ),
    );
    assert.equal(
      state.audit.some((e) => e.action === 'high_scale.adapter_stub_started'),
      false,
    );
  });

  it('dry-run adapter mode allows start without explicit metadata', async () => {
    const { repositories, state } = memoryRepositories();
    const svc = createPostgresHighScaleServices(repositories);
    const created = await svc.createHighScaleRequest(CTX_ENG, validHighScaleRequestPayload());
    await scheduleReadyForStart(svc, created.id);
    const running = await svc.transitionHighScale(CTX_A, created.id, 'start');
    assert.equal(running.state, 'running');
    assert.equal(running.adapter.traffic_generated, false);
    assert.ok(state.audit.some((e) => e.action === 'high_scale.adapter_stub_started'));
  });

  it('disabled adapter mode denies start without adapter stub audit', async () => {
    const { repositories, state } = memoryRepositories();
    const svc = createPostgresHighScaleServices(repositories);
    const created = await svc.createHighScaleRequest(CTX_ENG, validHighScaleRequestPayload());
    await scheduleReadyForStart(svc, created.id);
    const denied = await svc.transitionHighScale(CTX_A, created.id, 'start', { adapter_mode: 'disabled' });
    assert.equal(denied.error, 'adapter_disabled');
    assert.equal(denied.status, 409);
    assert.equal(state.requests.find((r) => r.id === created.id).state, 'scheduled');
    assert.ok(
      state.audit.some(
        (e) => e.action === 'high_scale.start_gate_denied' && e.metadata?.reason === 'adapter_disabled',
      ),
    );
    assert.equal(
      state.audit.some((e) => e.action === 'high_scale.adapter_stub_started'),
      false,
    );
  });

  it('governed-adapter mode denies start without adapter stub audit', async () => {
    const { repositories, state } = memoryRepositories();
    const svc = createPostgresHighScaleServices(repositories);
    const created = await svc.createHighScaleRequest(CTX_ENG, validHighScaleRequestPayload());
    await scheduleReadyForStart(svc, created.id);
    const denied = await svc.transitionHighScale(CTX_A, created.id, 'start', {
      adapter_mode: 'governed-adapter',
    });
    assert.equal(denied.error, 'governed_adapter_not_configured');
    assert.equal(denied.status, 503);
    assert.equal(state.requests.find((r) => r.id === created.id).state, 'scheduled');
    assert.ok(
      state.audit.some(
        (e) =>
          e.action === 'high_scale.start_gate_denied' &&
          e.metadata?.reason === 'governed_adapter_not_configured',
      ),
    );
    assert.equal(
      state.audit.some((e) => e.action === 'high_scale.adapter_stub_started'),
      false,
    );
  });

  it('kill switch auto-stops running requests and cancels active safe runs', async () => {
    const { repositories, state } = memoryRepositories({
      probeJobsOpen: [
        {
          id: 'pjob_open',
          tenant_id: 'ten_demo',
          test_run_id: 'run_1',
          status: 'pending',
        },
        {
          id: 'pjob_done',
          tenant_id: 'ten_demo',
          test_run_id: 'run_1',
          status: 'completed',
        },
      ],
    });
    state.testRuns.push({
      id: 'run_1',
      tenant_id: 'ten_demo',
      status: 'running',
      check_id: 'origin.direct_bypass.safe',
      target_group_id: 'tg_1',
      summary: {},
    });
    const svc = createPostgresHighScaleServices(repositories);
    const created = await svc.createHighScaleRequest(CTX_ENG, validHighScaleRequestPayload());
    await acceptPack(svc, created.id);
    await svc.transitionHighScale(CTX_A, created.id, 'approve');
    await svc.transitionHighScale(CTX_B, created.id, 'approve');
    const now = Date.now();
    await svc.transitionHighScale(CTX_A, created.id, 'schedule', {
      window_start: new Date(now - 60_000).toISOString(),
      window_end: new Date(now + 3600_000).toISOString(),
    });
    const running = await svc.transitionHighScale(CTX_A, created.id, 'start');
    assert.equal(running.state, 'running');
    assert.equal(running.adapter.traffic_generated, false);
    const ks = await svc.setKillSwitch(CTX_A, true, 'incident');
    assert.ok(ks.stopped_request_ids.includes(created.id));
    assert.ok(ks.cancelled_run_ids.includes('run_1'));
    assert.deepEqual(ks.cancelled_probe_job_ids, ['pjob_open']);
    assert.equal(state.testRuns[0].status, 'cancelled');
    const stubStopped = state.audit.filter((e) => e.action === 'high_scale.adapter_stub_stopped');
    const autoStop = state.audit.filter((e) => e.action === 'high_scale.kill_switch_auto_stop');
    assert.equal(stubStopped.length, 1);
    assert.equal(autoStop.length, 1);
    assert.equal(stubStopped[0].metadata.reason, 'incident');
    const probeCancel = state.audit.filter((e) => e.action === 'probe_job.kill_switch_auto_cancel');
    assert.equal(probeCancel.length, 1);
    assert.equal(probeCancel[0].resource_id, 'pjob_open');
    assert.equal(probeCancel[0].metadata.test_run_id, 'run_1');
    assert.equal(probeCancel[0].metadata.reason, 'incident');
    const activated = state.audit.find((e) => e.action === 'soc.kill_switch.activated');
    assert.deepEqual(activated.metadata.cancelled_probe_job_ids, ['pjob_open']);
  });
});
