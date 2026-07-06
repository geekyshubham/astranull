import { createHmac, timingSafeEqual } from 'node:crypto';
import { audit } from '../audit.mjs';
import { newId } from '../lib/ids.mjs';
import {
  buildSignedProbeJobRecord,
  signProbeJob,
  verifyProbeJobSignature,
} from '../lib/probeJobs.mjs';
import {
  sanitizeWorkerProbeMetadata,
  validateProbeResultBody,
} from '../lib/probeResultValidation.mjs';
import { enrichOutsideInWafProbeMetadata } from '../lib/outsideInWafAgentEvidence.mjs';
import { enrichProbeMetadataWithWafCatalog } from '../lib/wafProductCatalog.mjs';
import { getStore, persistStore } from '../store.mjs';
import { recordEvidence } from './evidence.mjs';
import * as ownershipVerification from './ownershipVerification.mjs';

const PROBE_WORKER_SIG_VERSION = 'pw1';

const MAX_TIMESTAMP_SKEW_SEC = 300;

function safeEqualUtf8(a, b) {
  if (!a || !b) return false;
  const ba = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (ba.length !== bb.length) return false;
  return timingSafeEqual(ba, bb);
}

export { signProbeJob, verifyProbeJobSignature };

export function workerRequestSigningPayload(method, path, timestamp, bodyText, tenantId) {
  const base = `${PROBE_WORKER_SIG_VERSION}\n${method}\n${path}\n${timestamp}\n${bodyText ?? ''}`;
  if (tenantId != null && tenantId !== '') {
    return `${base}\n${String(tenantId)}`;
  }
  return base;
}

export function signProbeWorkerRequest(
  { method, path, timestamp, bodyText = '', tenantId },
  secret,
) {
  return createHmac('sha256', secret)
    .update(
      workerRequestSigningPayload(method, path, timestamp, bodyText, tenantId),
      'utf8',
    )
    .digest('base64url');
}

export function probeWorkerAuthHeaders(
  workerId,
  { method, path, bodyText = '', tenantId },
  secret,
) {
  const timestamp = String(Math.floor(Date.now() / 1000));
  const signature = signProbeWorkerRequest(
    { method, path, timestamp, bodyText, tenantId },
    secret,
  );
  const headers = {
    'x-probe-worker-id': workerId,
    'x-probe-timestamp': timestamp,
    'x-probe-signature': signature,
  };
  if (tenantId != null && tenantId !== '') {
    headers['x-probe-tenant-id'] = String(tenantId);
  }
  return headers;
}

export function createProbeJob(ctx, run, check, target, probeProfile, runtimeConfig) {
  const job = buildSignedProbeJobRecord({
    run,
    check,
    target,
    probeProfile,
    probeWorkerSecret: runtimeConfig.probeWorkerSecret,
    now: new Date(),
    newId: () => newId('pjob'),
  });
  getStore().probeJobs.push(job);

  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'probe_job.created',
    resource_type: 'probe_job',
    resource_id: job.id,
    metadata: { test_run_id: run.id, check_id: check.check_id },
  });
  persistStore();
  return job;
}

export function createOwnershipChallengeJob(ctx, { verification }, runtimeConfig) {
  if (runtimeConfig?.probeMode !== 'signed-worker' || !runtimeConfig?.probeWorkerSecret) {
    return null;
  }

  const run = {
    id: verification.id,
    tenant_id: ctx.tenantId,
    safety_constraints: { max_events: 1, max_duration_seconds: 30 },
  };
  const check = {
    check_id: 'ownership.challenge',
    vector_family: 'ownership',
    title: 'Ownership challenge',
    probe_profile: {
      kind: 'ownership_challenge',
      max_requests: 1,
      timeout_ms: 5000,
      marker: 'astranull-ownership-challenge',
    },
  };
  const target = {
    id: verification.agent_id,
    kind: 'fqdn',
    value: verification.declared_fqdn,
  };

  const job = buildSignedProbeJobRecord({
    run,
    check,
    target,
    probeProfile: undefined,
    probeWorkerSecret: runtimeConfig.probeWorkerSecret,
    now: new Date(),
    newId: () => newId('pjob'),
  });
  job.ownership_verification_id = verification.id;
  job.nonce_hash = verification.challenge_nonce_hash;
  job.job_signature = signProbeJob(job, runtimeConfig.probeWorkerSecret);

  getStore().probeJobs.push(job);

  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'probe_job.created',
    resource_type: 'probe_job',
    resource_id: job.id,
    metadata: {
      ownership_verification_id: verification.id,
      check_id: 'ownership.challenge',
    },
  });
  persistStore();
  return job;
}

export function authenticateProbeWorker(headers, method, path, bodyText, runtimeConfig) {
  if (runtimeConfig.probeMode !== 'signed-worker') {
    return {
      ok: false,
      status: 503,
      body: { error: 'probe_worker_unavailable', message: 'Probe worker mode is not enabled.' },
    };
  }
  const secret = runtimeConfig.probeWorkerSecret;
  if (!secret) {
    return {
      ok: false,
      status: 503,
      body: { error: 'probe_worker_unconfigured', message: 'Probe worker secret is not configured.' },
    };
  }

  const workerId = headers['x-probe-worker-id'];
  const timestamp = headers['x-probe-timestamp'];
  const signature = headers['x-probe-signature'];
  const tenantId = headers['x-probe-tenant-id'];
  if (!workerId || !timestamp || !signature) {
    return {
      ok: false,
      status: 401,
      body: { error: 'unauthorized', message: 'Missing probe worker authentication headers.' },
    };
  }
  if (!tenantId || String(tenantId).trim() === '') {
    return {
      ok: false,
      status: 401,
      body: {
        error: 'unauthorized',
        message: 'Missing x-probe-tenant-id for signed probe worker requests.',
      },
    };
  }

  const ts = Number(timestamp);
  if (!Number.isFinite(ts)) {
    return {
      ok: false,
      status: 401,
      body: { error: 'unauthorized', message: 'Invalid probe worker timestamp.' },
    };
  }
  const nowSec = Math.floor(Date.now() / 1000);
  if (Math.abs(nowSec - ts) > MAX_TIMESTAMP_SKEW_SEC) {
    return {
      ok: false,
      status: 401,
      body: { error: 'unauthorized', message: 'Probe worker timestamp is too old or too far in the future.' },
    };
  }

  const expected = signProbeWorkerRequest(
    {
      method,
      path,
      timestamp: String(timestamp),
      bodyText: bodyText ?? '',
      tenantId: tenantId != null && tenantId !== '' ? String(tenantId) : undefined,
    },
    secret,
  );
  if (!safeEqualUtf8(signature, expected)) {
    return {
      ok: false,
      status: 401,
      body: { error: 'unauthorized', message: 'Invalid probe worker signature.' },
    };
  }

  return {
    ok: true,
    workerCtx: {
      workerId: String(workerId),
      role: 'probe_worker',
      tenantId: String(tenantId),
    },
  };
}

function jobForWorkerResponse(job) {
  const { nonce, ...rest } = job;
  return {
    ...rest,
    nonce,
    job_signature: job.job_signature,
  };
}

export function listPendingProbeJobsForWorker(workerCtx, runtimeConfig) {
  const store = getStore();
  const now = new Date().toISOString();
  const tenantId = workerCtx?.tenantId;
  if (!tenantId) {
    return [];
  }
  const jobs = store.probeJobs.filter(
    (j) => j.status === 'pending' && j.tenant_id === tenantId,
  );
  for (const job of jobs) {
    job.status = 'leased';
    job.leased_at = now;
    job.leased_by = workerCtx.workerId;
  }
  if (jobs.length) persistStore();
  return jobs.map((j) => jobForWorkerResponse(j));
}

export function ingestProbeResult(workerCtx, jobId, body, runtimeConfig) {
  const store = getStore();
  const job = store.probeJobs.find((j) => j.id === jobId);
  if (!job) return { error: 'job_not_found', status: 404 };
  if (workerCtx?.tenantId && job.tenant_id !== workerCtx.tenantId) {
    return { error: 'job_not_found', status: 404 };
  }

  if (job.ownership_verification_id) {
    if (job.status === 'completed') {
      return { error: 'job_not_open', status: 409 };
    }
    if (job.status === 'leased' && job.leased_by !== workerCtx.workerId) {
      return {
        error: 'job_leased_to_another_worker',
        status: 403,
        message: 'This probe job is leased to a different worker.',
      };
    }
    if (job.status !== 'pending' && job.status !== 'leased') {
      return { error: 'job_not_open', status: 409 };
    }
    if (body == null || typeof body !== 'object' || Array.isArray(body)) {
      return {
        error: 'invalid_body',
        status: 400,
        message: 'Probe result body must be a JSON object.',
      };
    }
    const validated = validateProbeResultBody(body, job.constraints ?? {}, {
      probeKind: job.probe_profile?.kind,
    });
    if (!validated.ok) {
      return {
        error: validated.error,
        status: validated.status,
        message: validated.message,
      };
    }
    const now = new Date().toISOString();
    job.status = 'completed';
    job.completed_at = now;

    ownershipVerification.recordOwnershipSignalByNonce(
      { tenantId: job.tenant_id },
      { source: 'probe', nonce_hash: job.nonce_hash },
    );

    audit({
      tenant_id: job.tenant_id,
      actor_user_id: workerCtx.workerId,
      actor_role: 'probe_worker',
      action: 'probe_job.result_ingested',
      resource_type: 'probe_job',
      resource_id: job.id,
      metadata: { ownership_verification_id: job.ownership_verification_id },
    });

    persistStore();
    return {
      ownership_verification_id: job.ownership_verification_id,
      job_id: job.id,
      tenant_id: job.tenant_id,
    };
  }

  const runForJob = store.testRuns.find(
    (r) => r.id === job.test_run_id && r.tenant_id === job.tenant_id,
  );
  if (job.status === 'completed') {
    const dupProbe = runForJob
      ? store.events.find(
          (e) =>
            e.test_run_id === runForJob.id &&
            e.signal_type === 'probe_result' &&
            e.nonce_hash === job.nonce_hash,
        )
      : null;
    if (dupProbe) {
      return { error: 'probe_already_ingested', status: 409 };
    }
    return { error: 'job_not_open', status: 409 };
  }

  if (job.status === 'leased' && job.leased_by !== workerCtx.workerId) {
    return {
      error: 'job_leased_to_another_worker',
      status: 403,
      message: 'This probe job is leased to a different worker.',
    };
  }

  if (job.status !== 'pending' && job.status !== 'leased') {
    return { error: 'job_not_open', status: 409 };
  }

  const validated = validateProbeResultBody(body, job.constraints ?? {}, {
    probeKind: job.probe_profile?.kind,
  });
  if (!validated.ok) {
    return {
      error: validated.error,
      status: validated.status,
      message: validated.message,
    };
  }
  const { externalResult, safetyAttestation, workerMetadata } = validated;

  const run = runForJob;
  if (!run) return { error: 'run_not_found', status: 404 };

  const existingProbe = store.events.find(
    (e) => e.test_run_id === run.id && e.signal_type === 'probe_result' && e.nonce_hash === job.nonce_hash,
  );
  if (existingProbe) {
    return { error: 'probe_already_ingested', status: 409 };
  }

  if (job.status === 'pending') {
    job.status = 'leased';
    job.leased_at = new Date().toISOString();
    job.leased_by = workerCtx.workerId;
  }

  let probeMetadata = enrichProbeMetadataWithWafCatalog(
    {
      ...workerMetadata,
      external_result: externalResult,
      probe_worker_id: workerCtx.workerId,
      safety_attestation: safetyAttestation,
    },
    job.check_id,
  );

  if (job.probe_profile?.kind === 'outside_in_waf_scan') {
    const agentObservations = store.events.filter(
      (event) => event.test_run_id === run.id && event.signal_type === 'agent_observation',
    );
    probeMetadata = enrichOutsideInWafProbeMetadata(probeMetadata, {
      agents: agentObservations,
      nonceHash: job.nonce_hash,
    });
  }

  const probeEvent = {
    id: newId('event'),
    tenant_id: run.tenant_id,
    test_run_id: run.id,
    target_id: job.target_id,
    check_id: job.check_id,
    source: 'probe_worker',
    signal_type: 'probe_result',
    timestamp: new Date().toISOString(),
    nonce_hash: job.nonce_hash,
    metadata: probeMetadata,
  };
  store.events.push(probeEvent);

  recordEvidence(
    { tenantId: run.tenant_id, userId: 'probe_worker', role: 'probe_worker' },
    {
      test_run_id: run.id,
      label: 'probe_worker_evidence',
      metadata: enrichProbeMetadataWithWafCatalog(
        {
          probe_job_id: job.id,
          probe_event_id: probeEvent.id,
          external_result: externalResult,
          vector_family: job.vector_family,
          safety_attestation: safetyAttestation,
        },
        job.check_id,
      ),
      related_event_id: probeEvent.id,
    },
  );

  run.correlation.nonce_hash = job.nonce_hash;
  run.probe_external_result = externalResult;
  if (run.status === 'running') run.status = 'collecting';

  job.status = 'completed';
  job.completed_at = new Date().toISOString();

  audit({
    tenant_id: run.tenant_id,
    actor_user_id: workerCtx.workerId,
    actor_role: 'probe_worker',
    action: 'probe_job.result_ingested',
    resource_type: 'probe_job',
    resource_id: job.id,
    metadata: { test_run_id: run.id, external_result: externalResult },
  });

  persistStore();

  return { probe_event: probeEvent, run_id: run.id, job_id: job.id, tenant_id: run.tenant_id };
}
