import assert from 'node:assert/strict';
import { after, afterEach, before, describe, it } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { loadRuntimeConfig } from '../../src/config.mjs';
import { getCheckById } from '../../src/contracts/checks.mjs';
import {
  authenticateProbeWorker,
  ingestProbeResult,
  probeWorkerAuthHeaders,
  signProbeWorkerRequest,
  verifyProbeJobSignature,
} from '../../src/services/probeCoordinator.mjs';
import { createOwnershipChallenge } from '../../src/services/ownershipVerification.mjs';
import {
  finalizeTestRun,
  ingestObservation,
  maybeFinalizeRunAfterProbeIngest,
  startTestRun,
} from '../../src/services/testRuns.mjs';
import { getStore } from '../../src/store.mjs';
import { demoHeaders, request } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';

const WORKER_SECRET = 'probe-worker-secret-at-least-32-chars!!';
const ctx = { tenantId: 'ten_demo', userId: 'u1', role: 'engineer' };
const envSnapshot = { ...process.env };

function restoreEnv() {
  for (const key of Object.keys(process.env)) {
    if (!(key in envSnapshot)) delete process.env[key];
  }
  Object.assign(process.env, envSnapshot);
}

function completeActiveRuns() {
  for (const run of getStore().testRuns) {
    if (['running', 'collecting', 'planned'].includes(run.status)) {
      run.status = 'verdicted';
      run.completed_at = new Date().toISOString();
    }
  }
}

function seedAgent() {
  getStore().agents.push({
    id: 'ag_probe',
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

function runtimeSignedWorker() {
  return loadRuntimeConfig({
    NODE_ENV: 'test',
    ASTRANULL_NO_PERSIST: '1',
    ASTRANULL_PROBE_MODE: 'signed-worker',
    ASTRANULL_PROBE_WORKER_SECRET: WORKER_SECRET,
  });
}

function compliantSafetyAttestation(job) {
  const maxRequests = job?.constraints?.max_requests ?? 1;
  const timeoutMs = job?.constraints?.timeout_ms ?? 5000;
  return {
    requests_sent: Math.min(1, maxRequests),
    duration_ms: Math.min(100, timeoutMs),
  };
}

function probeResultBody(job, externalResult, extra = {}) {
  return {
    external_result: externalResult,
    safety_attestation: compliantSafetyAttestation(job),
    ...extra,
  };
}

describe('probe runtime config', () => {
  afterEach(restoreEnv);

  it('requires ASTRANULL_PROBE_WORKER_SECRET in signed-worker mode', () => {
    process.env.NODE_ENV = 'test';
    process.env.ASTRANULL_PROBE_MODE = 'signed-worker';
    delete process.env.ASTRANULL_PROBE_WORKER_SECRET;
    assert.throws(() => loadRuntimeConfig(), /ASTRANULL_PROBE_WORKER_SECRET/);
  });

  it('defaults to simulation outside production', () => {
    process.env.NODE_ENV = 'test';
    delete process.env.ASTRANULL_PROBE_MODE;
    delete process.env.ASTRANULL_NO_PERSIST;
    const cfg = loadRuntimeConfig();
    assert.equal(cfg.probeMode, 'simulation');
    assert.equal(cfg.probeWorkerSecretConfigured, false);
  });
});

describe('signed probe coordinator', () => {
  let baseUrl;
  let server;

  before(() => {
    freshStore();
    seedAgent();
    server = createServer({
      env: {
        NODE_ENV: 'test',
        ASTRANULL_NO_PERSIST: '1',
        ASTRANULL_PROBE_MODE: 'signed-worker',
        ASTRANULL_PROBE_WORKER_SECRET: WORKER_SECRET,
      },
    });
    server.listen(0);
    const { port } = server.address();
    baseUrl = `http://127.0.0.1:${port}`;
  });

  after(() => server.close());

  it('rejects unauthenticated worker job fetch', async () => {
    const res = await request(baseUrl, 'GET', '/internal/probe/jobs');
    assert.equal(res.status, 401);
  });

  it('rejects customer dev-headers on worker routes', async () => {
    const res = await request(baseUrl, 'GET', '/internal/probe/jobs', {
      headers: demoHeaders('admin'),
    });
    assert.equal(res.status, 401);
  });

  it('rejects tampered worker signature', async () => {
    const headers = probeWorkerAuthHeaders(
      'worker-a',
      { method: 'GET', path: '/internal/probe/jobs', tenantId: 'ten_demo' },
      WORKER_SECRET,
    );
    headers['x-probe-signature'] = 'tampered';
    const res = await request(baseUrl, 'GET', '/internal/probe/jobs', { headers });
    assert.equal(res.status, 401);
  });

  it('rejects stale probe worker timestamp beyond skew window', async () => {
    const runtime = runtimeSignedWorker();
    const staleTs = String(Math.floor(Date.now() / 1000) - 301);
    const signature = signProbeWorkerRequest(
      {
        method: 'GET',
        path: '/internal/probe/jobs',
        timestamp: staleTs,
        bodyText: '',
        tenantId: 'ten_demo',
      },
      WORKER_SECRET,
    );
    const auth = authenticateProbeWorker(
      {
        'x-probe-worker-id': 'worker-a',
        'x-probe-timestamp': staleTs,
        'x-probe-signature': signature,
        'x-probe-tenant-id': 'ten_demo',
      },
      'GET',
      '/internal/probe/jobs',
      '',
      runtime,
    );
    assert.equal(auth.ok, false);
    assert.equal(auth.status, 401);
    assert.match(auth.body.message, /too old or too far in the future/);

    const res = await request(baseUrl, 'GET', '/internal/probe/jobs', {
      headers: {
        'x-probe-worker-id': 'worker-a',
        'x-probe-timestamp': staleTs,
        'x-probe-signature': signature,
        'x-probe-tenant-id': 'ten_demo',
      },
    });
    assert.equal(res.status, 401);
  });

  it('rejects signed-worker probe requests without x-probe-tenant-id', async () => {
    const runtime = runtimeSignedWorker();
    const signature = signProbeWorkerRequest(
      { method: 'GET', path: '/internal/probe/jobs', timestamp: String(Math.floor(Date.now() / 1000)), bodyText: '' },
      WORKER_SECRET,
    );
    const auth = authenticateProbeWorker(
      {
        'x-probe-worker-id': 'worker-a',
        'x-probe-timestamp': String(Math.floor(Date.now() / 1000)),
        'x-probe-signature': signature,
      },
      'GET',
      '/internal/probe/jobs',
      '',
      runtime,
    );
    assert.equal(auth.ok, false);
    assert.equal(auth.status, 401);
    assert.match(auth.body.message, /x-probe-tenant-id/);
  });

  it('rejects future probe worker timestamp beyond skew window', async () => {
    const runtime = runtimeSignedWorker();
    const futureTs = String(Math.floor(Date.now() / 1000) + 3600);
    const signature = signProbeWorkerRequest(
      {
        method: 'GET',
        path: '/internal/probe/jobs',
        timestamp: futureTs,
        bodyText: '',
        tenantId: 'ten_demo',
      },
      WORKER_SECRET,
    );
    const auth = authenticateProbeWorker(
      {
        'x-probe-worker-id': 'worker-a',
        'x-probe-timestamp': futureTs,
        'x-probe-signature': signature,
        'x-probe-tenant-id': 'ten_demo',
      },
      'GET',
      '/internal/probe/jobs',
      '',
      runtime,
    );
    assert.equal(auth.ok, false);
    assert.equal(auth.status, 401);
    assert.match(auth.body.message, /too old or too far in the future/);

    const res = await request(baseUrl, 'GET', '/internal/probe/jobs', {
      headers: {
        'x-probe-worker-id': 'worker-a',
        'x-probe-timestamp': futureTs,
        'x-probe-signature': signature,
        'x-probe-tenant-id': 'ten_demo',
      },
    });
    assert.equal(res.status, 401);
  });

  it('worker can fetch signed pending job and ingest metadata result', async () => {
    completeActiveRuns();
    const started = startTestRun(
      ctx,
      {
        check_id: 'origin.direct_bypass.safe',
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
      },
      runtimeSignedWorker(),
    );
    assert.ok(started.probe_job?.job_signature);
    assert.equal(started.run.status, 'running');
    assert.equal(started.probe_event, undefined);

    const listHeaders = probeWorkerAuthHeaders(
      'worker-a',
      { method: 'GET', path: '/internal/probe/jobs', tenantId: 'ten_demo' },
      WORKER_SECRET,
    );
    const listed = await request(baseUrl, 'GET', '/internal/probe/jobs', { headers: listHeaders });
    assert.equal(listed.status, 200);
    assert.equal(listed.json.jobs.length, 1);
    assert.equal(listed.json.jobs[0].id, started.probe_job.id);
    assert.equal(listed.json.jobs[0].job_signature, started.probe_job.job_signature);

    const job = getStore().probeJobs.find((j) => j.test_run_id === started.run.id);
    const check = getCheckById('origin.direct_bypass.safe');
    assert.deepEqual(job.probe_profile, check.probe_profile);
    assert.equal(job.constraints.max_requests, check.probe_profile.max_requests);
    assert.equal(job.constraints.timeout_ms, 5000);
    const body = probeResultBody(job, 'blocked', { metadata: { region: 'us-east' } });
    const resultPath = `/internal/probe/jobs/${started.probe_job.id}/result`;
    const resultHeaders = probeWorkerAuthHeaders(
      'worker-a',
      { method: 'POST', path: resultPath, bodyText: JSON.stringify(body), tenantId: 'ten_demo' },
      WORKER_SECRET,
    );
    const ingested = await request(baseUrl, 'POST', resultPath, { headers: resultHeaders, body });
    assert.equal(ingested.status, 201);

    const run = getStore().testRuns.find((r) => r.id === started.run.id);
    assert.equal(run.probe_external_result, 'blocked');
    assert.equal(run.awaiting_external_probe, false);
    assert.equal(run.status, 'collecting');
    assert.equal(getStore().verdicts.some((v) => v.test_run_id === run.id), false);
    const probeEvent = getStore().events.find(
      (e) => e.test_run_id === run.id && e.signal_type === 'probe_result',
    );
    assert.ok(probeEvent);
    assert.equal(probeEvent.metadata.external_result, 'blocked');
    assert.deepEqual(probeEvent.metadata.safety_attestation, body.safety_attestation);
    assert.ok(getStore().evidenceVault.some((e) => e.label === 'probe_worker_evidence'));
    assert.ok(getStore().auditLog.some((a) => a.action === 'probe_job.result_ingested'));
  });

  it('rejects raw packet fields in worker result', async () => {
    completeActiveRuns();
    const started = startTestRun(
      ctx,
      {
        check_id: 'origin.direct_bypass.safe',
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
      },
      runtimeSignedWorker(),
    );
    const job = getStore().probeJobs.find((j) => j.test_run_id === started.run.id);
    const body = {
      ...probeResultBody(job, 'blocked'),
      packet_payload: 'deadbeef',
    };
    const resultPath = `/internal/probe/jobs/${job.id}/result`;
    const resultHeaders = probeWorkerAuthHeaders(
      'worker-b',
      { method: 'POST', path: resultPath, bodyText: JSON.stringify(body), tenantId: 'ten_demo' },
      WORKER_SECRET,
    );
    const res = await request(baseUrl, 'POST', resultPath, { headers: resultHeaders, body });
    assert.equal(res.status, 400);
    assert.equal(res.json.error, 'raw_packet_rejected');
    const jobAfter = getStore().probeJobs.find((j) => j.id === job.id);
    assert.equal(jobAfter.status, 'pending');
    assert.equal(jobAfter.leased_by, null);
    assert.equal(jobAfter.leased_at, null);
  });

  it('rejects nested raw_packet in metadata and leaves job open', () => {
    freshStore();
    seedAgent();
    const started = startTestRun(
      ctx,
      {
        check_id: 'origin.direct_bypass.safe',
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
      },
      runtimeSignedWorker(),
    );
    const job = getStore().probeJobs[0];
    const out = ingestProbeResult(
      { workerId: 'worker-a' },
      job.id,
      probeResultBody(job, 'blocked', {
        metadata: { sample: { raw_packet: 'deadbeef' } },
      }),
      runtimeSignedWorker(),
    );
    assert.equal(out.status, 400);
    assert.equal(out.error, 'raw_packet_rejected');
    assert.equal(job.status, 'pending');
    assert.equal(job.leased_by, null);
    assert.equal(started.run.probe_external_result, undefined);
    assert.equal(
      getStore().events.some((e) => e.test_run_id === started.run.id && e.signal_type === 'probe_result'),
      false,
    );
  });

  it('rejects compact raw payload aliases in probe metadata', () => {
    freshStore();
    seedAgent();
    const started = startTestRun(
      ctx,
      {
        check_id: 'origin.direct_bypass.safe',
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
      },
      runtimeSignedWorker(),
    );
    const job = getStore().probeJobs[0];
    const out = ingestProbeResult(
      { workerId: 'worker-a' },
      job.id,
      probeResultBody(job, 'blocked', {
        metadata: { sample: { rawpayload: 'deadbeef', requestHeaders: { authorization: 'secret' } } },
      }),
      runtimeSignedWorker(),
    );
    assert.equal(out.status, 400);
    assert.equal(out.error, 'raw_packet_rejected');
    assert.equal(job.status, 'pending');
  });

  it('rejects invalid external_result on pending job without claiming lease', () => {
    freshStore();
    seedAgent();
    const started = startTestRun(
      ctx,
      {
        check_id: 'origin.direct_bypass.safe',
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
      },
      runtimeSignedWorker(),
    );
    const job = getStore().probeJobs[0];
    const out = ingestProbeResult(
      { workerId: 'worker-a' },
      job.id,
      { external_result: 'not-a-valid-result' },
      runtimeSignedWorker(),
    );
    assert.equal(out.status, 400);
    assert.equal(out.error, 'invalid_external_result');
    assert.equal(job.status, 'pending');
    assert.equal(job.leased_by, null);
    assert.equal(job.leased_at, null);
    assert.equal(started.run.probe_external_result, undefined);
  });

  it('rejects result ingestion from a worker that did not lease the job', async () => {
    completeActiveRuns();
    const started = startTestRun(
      ctx,
      {
        check_id: 'origin.direct_bypass.safe',
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
      },
      runtimeSignedWorker(),
    );
    const job = getStore().probeJobs.find((j) => j.test_run_id === started.run.id);
    job.status = 'leased';
    job.leased_by = 'worker-a';
    job.leased_at = new Date().toISOString();

    const body = probeResultBody(job, 'blocked');
    const resultPath = `/internal/probe/jobs/${job.id}/result`;
    const resultHeaders = probeWorkerAuthHeaders(
      'worker-b',
      { method: 'POST', path: resultPath, bodyText: JSON.stringify(body), tenantId: 'ten_demo' },
      WORKER_SECRET,
    );
    const res = await request(baseUrl, 'POST', resultPath, { headers: resultHeaders, body });
    assert.equal(res.status, 403);
    assert.equal(res.json.error, 'job_leased_to_another_worker');
  });

  it('rejects duplicate probe result after job completion', () => {
    freshStore();
    seedAgent();
    const started = startTestRun(
      ctx,
      {
        check_id: 'origin.direct_bypass.safe',
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
      },
      runtimeSignedWorker(),
    );
    const job = getStore().probeJobs[0];
    const workerCtx = { workerId: 'worker-a' };
    const cfg = runtimeSignedWorker();
    const firstBody = probeResultBody(job, 'blocked');
    const first = ingestProbeResult(workerCtx, job.id, firstBody, cfg);
    assert.equal(first.error, undefined);
    const dup = ingestProbeResult(workerCtx, job.id, firstBody, cfg);
    assert.equal(dup.status, 409);
    assert.equal(dup.error, 'probe_already_ingested');
  });

  it('observation before signed-worker probe result does not publish a verdict', () => {
    freshStore();
    seedAgent();
    const started = startTestRun(
      ctx,
      {
        check_id: 'origin.direct_bypass.safe',
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
      },
      runtimeSignedWorker(),
    );
    assert.equal(started.run.awaiting_external_probe, true);
    const agentCtx = { tenantId: 'ten_demo', userId: 'agent', role: 'agent' };
    const job = ackedJobForAgent('ag_probe', started.run.id);
    const obs = ingestObservation(agentCtx, 'ag_probe', {
      agent_job_id: job.id,
      test_run_id: started.run.id,
      target_id: 'tgt_1',
      nonce_hash: started.run.correlation.nonce_hash,
    });
    assert.equal(obs.error, undefined);
    const run = getStore().testRuns.find((r) => r.id === started.run.id);
    assert.equal(run.status, 'running');
    assert.equal(run.awaiting_external_probe, true);
    assert.equal(getStore().verdicts.some((v) => v.test_run_id === run.id), false);
    assert.ok(getStore().events.some((e) => e.signal_type === 'agent_observation'));
  });

  it('finalizes with verdict when probe result follows a matching observation', () => {
    freshStore();
    seedAgent();
    const started = startTestRun(
      ctx,
      {
        check_id: 'origin.direct_bypass.safe',
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
      },
      runtimeSignedWorker(),
    );
    const agentCtx = { tenantId: 'ten_demo', userId: 'agent', role: 'agent' };
    const agentJob = ackedJobForAgent('ag_probe', started.run.id);
    ingestObservation(agentCtx, 'ag_probe', {
      agent_job_id: agentJob.id,
      test_run_id: started.run.id,
      target_id: 'tgt_1',
      nonce_hash: started.run.correlation.nonce_hash,
      metadata: { observed: true },
    });
    const job = getStore().probeJobs[0];
    const out = ingestProbeResult(
      { workerId: 'worker-a' },
      job.id,
      probeResultBody(job, 'connected'),
      runtimeSignedWorker(),
    );
    assert.equal(out.error, undefined);
    const verdict = maybeFinalizeRunAfterProbeIngest(out.run_id);
    assert.ok(verdict);
    const run = getStore().testRuns.find((r) => r.id === started.run.id);
    assert.equal(run.status, 'verdicted');
    assert.ok(getStore().events.some((e) => e.signal_type === 'probe_result'));
    assert.ok(getStore().events.some((e) => e.signal_type === 'agent_observation'));
    const storedVerdict = getStore().verdicts.find((v) => v.test_run_id === started.run.id);
    assert.ok(storedVerdict?.placement_confidence);
    assert.equal(storedVerdict.placement_confidence.status, 'observed_this_run');
    assert.equal(storedVerdict.placement_confidence.agent_id, 'ag_probe');
    assert.equal(storedVerdict.placement_confidence.level, 'Medium');
    assert.equal(storedVerdict.placement_confidence.observation_mode, 'unknown');
  });

  it('keeps run collecting when probe result arrives without observation and window is active', () => {
    freshStore();
    seedAgent();
    const started = startTestRun(
      ctx,
      {
        check_id: 'origin.direct_bypass.safe',
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
      },
      runtimeSignedWorker(),
    );
    const run = getStore().testRuns.find((r) => r.id === started.run.id);
    run.collection_deadline_at = new Date(Date.now() + 60_000).toISOString();

    const job = getStore().probeJobs[0];
    const out = ingestProbeResult(
      { workerId: 'worker-a' },
      job.id,
      probeResultBody(job, 'blocked'),
      runtimeSignedWorker(),
    );
    maybeFinalizeRunAfterProbeIngest(out.run_id);

    assert.equal(run.status, 'collecting');
    assert.equal(run.awaiting_external_probe, false);
    assert.equal(getStore().verdicts.some((v) => v.test_run_id === run.id), false);
  });

  it('force finalization after probe evidence still publishes no-observation verdict', () => {
    freshStore();
    seedAgent();
    const started = startTestRun(
      ctx,
      {
        check_id: 'origin.direct_bypass.safe',
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
      },
      runtimeSignedWorker(),
    );
    const job = getStore().probeJobs[0];
    const out = ingestProbeResult(
      { workerId: 'worker-a' },
      job.id,
      probeResultBody(job, 'blocked'),
      runtimeSignedWorker(),
    );
    maybeFinalizeRunAfterProbeIngest(out.run_id);
    const run = getStore().testRuns.find((r) => r.id === started.run.id);
    assert.equal(run.status, 'collecting');

    const finalized = finalizeTestRun(ctx, run.id, { force: true });
    assert.equal(finalized.error, undefined);
    assert.equal(finalized.run.status, 'verdicted');
    assert.ok(finalized.verdict);
    assert.ok(getStore().events.some((e) => e.signal_type === 'agent_no_observation'));
    assert.equal(finalized.verdict.placement_confidence.level, 'Low');
    assert.equal(finalized.verdict.placement_confidence.status, 'not_observed_this_run');
  });

  it('ingestProbeResult updates run correlation for unit path', () => {
    freshStore();
    seedAgent();
    const started = startTestRun(
      ctx,
      {
        check_id: 'origin.direct_bypass.safe',
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
      },
      runtimeSignedWorker(),
    );
    const job = getStore().probeJobs[0];
    const workerCtx = { workerId: 'worker-unit' };
    const out = ingestProbeResult(
      workerCtx,
      job.id,
      probeResultBody(job, 'connected'),
      runtimeSignedWorker(),
    );
    assert.equal(out.error, undefined);
    maybeFinalizeRunAfterProbeIngest(out.run_id);
    const run = getStore().testRuns.find((r) => r.id === started.run.id);
    assert.equal(run.probe_external_result, 'connected');
    assert.equal(run.status, 'collecting');
    assert.ok(getStore().events.some((e) => e.signal_type === 'probe_result'));
    assert.equal(getStore().verdicts.some((v) => v.test_run_id === run.id), false);
  });

  it('rejects probe result without safety attestation and leaves job and run open', () => {
    freshStore();
    seedAgent();
    const started = startTestRun(
      ctx,
      {
        check_id: 'origin.direct_bypass.safe',
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
      },
      runtimeSignedWorker(),
    );
    const job = getStore().probeJobs[0];
    const out = ingestProbeResult(
      { workerId: 'worker-a' },
      job.id,
      { external_result: 'blocked' },
      runtimeSignedWorker(),
    );
    assert.equal(out.status, 400);
    assert.equal(out.error, 'missing_safety_attestation');
    assert.equal(job.status, 'pending');
    assert.equal(job.leased_by, null);
    assert.equal(started.run.probe_external_result, undefined);
    assert.equal(
      getStore().events.some((e) => e.test_run_id === started.run.id && e.signal_type === 'probe_result'),
      false,
    );
  });

  it('rejects safety attestation when requests_sent exceeds max_requests', () => {
    freshStore();
    seedAgent();
    const started = startTestRun(
      ctx,
      {
        check_id: 'origin.direct_bypass.safe',
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
      },
      runtimeSignedWorker(),
    );
    const job = getStore().probeJobs[0];
    assert.equal(job.constraints.max_requests, 1);
    const out = ingestProbeResult(
      { workerId: 'worker-a' },
      job.id,
      {
        external_result: 'blocked',
        safety_attestation: { requests_sent: 2, duration_ms: 50 },
      },
      runtimeSignedWorker(),
    );
    assert.equal(out.status, 422);
    assert.equal(out.error, 'safety_attestation_exceeded');
    assert.equal(job.status, 'pending');
    assert.equal(started.run.probe_external_result, undefined);
  });

  it('rejects safety attestation when duration_ms exceeds timeout_ms', () => {
    freshStore();
    seedAgent();
    const started = startTestRun(
      ctx,
      {
        check_id: 'origin.direct_bypass.safe',
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
      },
      runtimeSignedWorker(),
    );
    const job = getStore().probeJobs[0];
    assert.equal(job.constraints.timeout_ms, 5000);
    const out = ingestProbeResult(
      { workerId: 'worker-a' },
      job.id,
      {
        external_result: 'blocked',
        safety_attestation: { requests_sent: 1, duration_ms: 5001 },
      },
      runtimeSignedWorker(),
    );
    assert.equal(out.status, 422);
    assert.equal(out.error, 'safety_attestation_exceeded');
    assert.equal(job.status, 'pending');
    assert.equal(started.run.probe_external_result, undefined);
  });

  it('stores safety_attestation on accepted probe event metadata', () => {
    freshStore();
    seedAgent();
    const started = startTestRun(
      ctx,
      {
        check_id: 'origin.direct_bypass.safe',
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
      },
      runtimeSignedWorker(),
    );
    const job = getStore().probeJobs[0];
    const attestation = { requests_sent: 1, duration_ms: 250, worker_version: 'pw-1.0' };
    const out = ingestProbeResult(
      { workerId: 'worker-a' },
      job.id,
      { external_result: 'timeout', safety_attestation: attestation },
      runtimeSignedWorker(),
    );
    assert.equal(out.error, undefined);
    const probeEvent = getStore().events.find(
      (e) => e.test_run_id === started.run.id && e.signal_type === 'probe_result',
    );
    assert.deepEqual(probeEvent.metadata.safety_attestation, {
      requests_sent: 1,
      duration_ms: 250,
      worker_version: 'pw-1.0',
    });
    const evidence = getStore().evidenceVault.find((e) => e.label === 'probe_worker_evidence');
    assert.deepEqual(evidence.metadata.safety_attestation, probeEvent.metadata.safety_attestation);
  });

  it('does not let worker metadata override reserved probe event fields', () => {
    freshStore();
    seedAgent();
    const started = startTestRun(
      ctx,
      {
        check_id: 'origin.direct_bypass.safe',
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
      },
      runtimeSignedWorker(),
    );
    const job = getStore().probeJobs[0];
    const out = ingestProbeResult(
      { workerId: 'worker-trusted' },
      job.id,
      probeResultBody(job, 'blocked', {
        metadata: {
          external_result: 'connected',
          probe_worker_id: 'worker-evil',
          safety_attestation: { requests_sent: 999, duration_ms: 999 },
          region: 'us-east',
        },
      }),
      runtimeSignedWorker(),
    );
    assert.equal(out.error, undefined);
    const probeEvent = getStore().events.find(
      (e) => e.test_run_id === started.run.id && e.signal_type === 'probe_result',
    );
    assert.equal(probeEvent.metadata.external_result, 'blocked');
    assert.equal(probeEvent.metadata.probe_worker_id, 'worker-trusted');
    assert.deepEqual(probeEvent.metadata.safety_attestation, compliantSafetyAttestation(job));
    assert.equal(probeEvent.metadata.region, 'us-east');
    const evidence = getStore().evidenceVault.find((e) => e.label === 'probe_worker_evidence');
    assert.deepEqual(evidence.metadata.safety_attestation, probeEvent.metadata.safety_attestation);
  });

  it('redacts secret-looking probe metadata before storage', () => {
    freshStore();
    seedAgent();
    const started = startTestRun(
      ctx,
      {
        check_id: 'origin.direct_bypass.safe',
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
      },
      runtimeSignedWorker(),
    );
    const job = getStore().probeJobs[0];
    const out = ingestProbeResult(
      { workerId: 'worker-a' },
      job.id,
      probeResultBody(job, 'blocked', {
        metadata: { api_key: 'ast_supersecrettoken123456', note: 'ok' },
      }),
      runtimeSignedWorker(),
    );
    assert.equal(out.error, undefined);
    const probeEvent = getStore().events.find(
      (e) => e.test_run_id === started.run.id && e.signal_type === 'probe_result',
    );
    assert.equal(probeEvent.metadata.api_key, '[REDACTED]');
    assert.equal(probeEvent.metadata.note, 'ok');
  });

  it('signed probe job target descriptor includes separate port for l3.forbidden_tcp_port.safe', () => {
    freshStore();
    seedAgent();
    const tgt = getStore().targets.find((t) => t.id === 'tgt_1');
    tgt.kind = 'ip';
    tgt.value = '127.0.0.1';
    tgt.port = 65534;
    const started = startTestRun(
      ctx,
      {
        check_id: 'l3.forbidden_tcp_port.safe',
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
      },
      runtimeSignedWorker(),
    );
    const job = getStore().probeJobs.find((j) => j.test_run_id === started.run.id);
    assert.equal(job.target.value, '127.0.0.1');
    assert.equal(job.target.port, 65534);
    assert.equal(verifyProbeJobSignature(job, WORKER_SECRET), true);
    job.target = { ...job.target, port: 1 };
    assert.equal(verifyProbeJobSignature(job, WORKER_SECRET), false);
  });

  it('rejects tampered probe_profile on signed probe job', () => {
    freshStore();
    seedAgent();
    const started = startTestRun(
      ctx,
      {
        check_id: 'origin.direct_bypass.safe',
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
      },
      runtimeSignedWorker(),
    );
    const job = getStore().probeJobs[0];
    assert.equal(verifyProbeJobSignature(job, WORKER_SECRET), true);
    job.probe_profile = { ...job.probe_profile, kind: 'tcp_connect', max_requests: 99 };
    assert.equal(verifyProbeJobSignature(job, WORKER_SECRET), false);
  });

  it('signs WAF marker probe jobs with scenario metadata and rejects tampering', () => {
    freshStore();
    seedAgent();
    const started = startTestRun(
      ctx,
      {
        check_id: 'waf.marker_rule.safe',
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
        probe_profile: {
          scenario_family: 'marker',
          expected_action: 'block',
          collect: ['status_code', 'waf_product_hint'],
        },
      },
      runtimeSignedWorker(),
    );
    const job = getStore().probeJobs.find((j) => j.test_run_id === started.run.id);
    const check = getCheckById('waf.marker_rule.safe');
    assert.equal(job.probe_profile.scenario_family, 'marker');
    assert.equal(job.probe_profile.expected_action, 'block');
    assert.deepEqual(job.probe_profile.collect, ['status_code', 'waf_product_hint']);
    assert.equal(job.probe_profile.kind, check.probe_profile.kind);
    const signedProfile = { ...job.probe_profile };
    assert.equal(verifyProbeJobSignature(job, WORKER_SECRET), true);
    job.probe_profile = { ...job.probe_profile, max_requests: 99 };
    assert.equal(verifyProbeJobSignature(job, WORKER_SECRET), false);
    job.probe_profile = signedProfile;
    job.probe_profile = { ...job.probe_profile, expected_action: 'allow_expected' };
    assert.equal(verifyProbeJobSignature(job, WORKER_SECRET), false);
  });

  it('signProbeWorkerRequest is sensitive to path tampering', () => {
    const sig = signProbeWorkerRequest(
      { method: 'GET', path: '/internal/probe/jobs', timestamp: '1000', bodyText: '' },
      WORKER_SECRET,
    );
    const other = signProbeWorkerRequest(
      { method: 'GET', path: '/internal/probe/jobs/evil', timestamp: '1000', bodyText: '' },
      WORKER_SECRET,
    );
    assert.notEqual(sig, other);
  });

  it('binds tenant id in signing payload only when header is present', () => {
    const withoutTenant = signProbeWorkerRequest(
      { method: 'GET', path: '/internal/probe/jobs', timestamp: '1000', bodyText: '' },
      WORKER_SECRET,
    );
    const withTenant = signProbeWorkerRequest(
      {
        method: 'GET',
        path: '/internal/probe/jobs',
        timestamp: '1000',
        bodyText: '',
        tenantId: 'ten_demo',
      },
      WORKER_SECRET,
    );
    assert.notEqual(withoutTenant, withTenant);
    const headers = probeWorkerAuthHeaders(
      'pw_1',
      { method: 'GET', path: '/internal/probe/jobs', tenantId: 'ten_demo' },
      WORKER_SECRET,
    );
    const runtime = runtimeSignedWorker();
    const ok = authenticateProbeWorker(
      headers,
      'GET',
      '/internal/probe/jobs',
      '',
      runtime,
    );
    assert.equal(ok.ok, true);
    assert.equal(ok.workerCtx.tenantId, 'ten_demo');
  });
});

describe('ready endpoint probe metadata', () => {
  let baseUrl;
  let server;

  before(() => {
    freshStore();
    server = createServer({
      env: {
        NODE_ENV: 'test',
        ASTRANULL_NO_PERSIST: '1',
        ASTRANULL_PROBE_MODE: 'signed-worker',
        ASTRANULL_PROBE_WORKER_SECRET: WORKER_SECRET,
      },
    });
    server.listen(0);
    baseUrl = `http://127.0.0.1:${server.address().port}`;
  });

  after(() => server.close());

  it('does not expose probe worker secret on /ready', async () => {
    const res = await request(baseUrl, 'GET', '/ready');
    assert.equal(res.status, 200);
    assert.equal(res.json.probe_mode, 'signed-worker');
    assert.equal(res.json.probe_worker_secret_configured, true);
    assert.equal(res.json.probe_worker_secret, undefined);
    assert.equal(res.json.ASTRANULL_PROBE_WORKER_SECRET, undefined);
  });
});

describe('ownership challenge probe jobs', () => {
  const ownershipCtx = { tenantId: 'ten_demo', userId: 'u1', role: 'owner' };
  const workerCtx = { workerId: 'worker-own', role: 'probe_worker', tenantId: 'ten_demo' };

  afterEach(() => {
    freshStore();
  });

  it('dispatches signed ownership job and records probe signal on ingest', () => {
    freshStore();
    const store = getStore();
    if (!Array.isArray(store.ownershipVerifications)) {
      store.ownershipVerifications = [];
    }
    store.agents.push({
      id: 'agent_1',
      tenant_id: 'ten_demo',
      name: 'canary',
      status: 'online',
      target_group_id: 'tg_1',
      probe_endpoint: { declared_fqdn: 'origin.test' },
      last_token_validation_status: 'valid',
    });

    const runtimeConfig = runtimeSignedWorker();
    const created = createOwnershipChallenge(
      ownershipCtx,
      { target_group_id: 'tg_1', agent_id: 'agent_1' },
      runtimeConfig,
    );
    assert.equal(created.error, undefined);

    const verification = created.verification;
    const job = getStore().probeJobs.find(
      (j) => j.ownership_verification_id === verification.id,
    );
    assert.ok(job);
    assert.equal(job.check_id, 'ownership.challenge');
    assert.equal(job.probe_profile.kind, 'ownership_challenge');
    assert.equal(job.nonce_hash, verification.challenge_nonce_hash);

    const body = {
      external_result: 'connected',
      safety_attestation: compliantSafetyAttestation(job),
    };
    const ingested = ingestProbeResult(workerCtx, job.id, body, runtimeConfig);
    assert.equal(ingested.error, undefined);
    assert.equal(ingested.ownership_verification_id, verification.id);

    const updated = getStore().ownershipVerifications.find((v) => v.id === verification.id);
    assert.equal(updated.probe_observed, true);
    assert.equal(updated.status, 'challenge_sent');
  });
});
