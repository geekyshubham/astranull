import { createHmac, timingSafeEqual } from 'node:crypto';
import { buildProbeProfile, WAF_SAFE_PROBE_METADATA_KEYS } from '../contracts/checks.mjs';
import { generateNonce, hashNonce } from '../lib/crypto.mjs';

const DEFAULT_MAX_REQUESTS = 1;
const DEFAULT_TIMEOUT_CAP_MS = 5000;

const BENIGN_PROBE_PROFILE_OVERRIDE_KEYS = new Set(['marker', ...WAF_SAFE_PROBE_METADATA_KEYS]);

function safeEqualUtf8(a, b) {
  if (!a || !b) return false;
  const ba = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (ba.length !== bb.length) return false;
  return timingSafeEqual(ba, bb);
}

export function resolveJobProbeProfile(check, override) {
  const base = check?.probe_profile
    ? { ...check.probe_profile }
    : buildProbeProfile({ kind: 'metadata_marker' });
  if (override == null || typeof override === 'string') return base;
  if (typeof override !== 'object' || Array.isArray(override)) return base;
  const merged = { ...base };
  for (const key of BENIGN_PROBE_PROFILE_OVERRIDE_KEYS) {
    if (key === 'nonce_hash_only') {
      if (override.nonce_hash_only === true) merged.nonce_hash_only = true;
      continue;
    }
    if (key === 'collect') {
      if (Array.isArray(override.collect)) merged.collect = override.collect;
      continue;
    }
    if (override[key] != null) {
      merged[key] = String(override[key]).slice(0, 128);
    }
  }
  return buildProbeProfile(merged);
}

export function normalizeJobConstraints(safetyConstraints, probeProfile) {
  const src = safetyConstraints ?? {};
  const out = {};
  if (src.max_events != null) out.max_events = src.max_events;
  if (src.max_duration_seconds != null) out.max_duration_seconds = src.max_duration_seconds;
  if (src.max_concurrent_runs_per_target_group != null) {
    out.max_concurrent_runs_per_target_group = src.max_concurrent_runs_per_target_group;
  }
  let maxRequests =
    probeProfile?.max_requests != null ? probeProfile.max_requests : DEFAULT_MAX_REQUESTS;
  if (src.max_requests != null) {
    maxRequests = Math.min(maxRequests, src.max_requests);
  }
  out.max_requests = maxRequests;
  let timeoutMs;
  if (src.timeout_ms != null) {
    timeoutMs = src.timeout_ms;
  } else {
    const fromDuration =
      src.max_duration_seconds != null
        ? Math.floor(Number(src.max_duration_seconds) * 1000)
        : DEFAULT_TIMEOUT_CAP_MS;
    const derived = Number.isFinite(fromDuration) ? fromDuration : DEFAULT_TIMEOUT_CAP_MS;
    timeoutMs = Math.min(derived, DEFAULT_TIMEOUT_CAP_MS);
  }
  if (probeProfile?.timeout_ms != null) {
    timeoutMs = Math.min(timeoutMs, probeProfile.timeout_ms);
  }
  out.timeout_ms = Math.min(timeoutMs, DEFAULT_TIMEOUT_CAP_MS);
  return out;
}

export function targetDescriptor(target) {
  const out = {
    id: target.id,
    kind: target.kind,
    value: target.value,
    expected_behavior: target.expected_behavior ?? null,
  };
  if (target.port != null) out.port = target.port;
  if (target.protocol != null) out.protocol = target.protocol;
  return out;
}

function canonicalJobSigningPayload(job) {
  return JSON.stringify({
    check_id: job.check_id,
    constraints: job.constraints,
    id: job.id,
    nonce_hash: job.nonce_hash,
    probe_profile: job.probe_profile,
    target: job.target,
    tenant_id: job.tenant_id,
    test_run_id: job.test_run_id,
  });
}

export function signProbeJob(job, secret) {
  return createHmac('sha256', secret)
    .update(canonicalJobSigningPayload(job), 'utf8')
    .digest('hex');
}

export function verifyProbeJobSignature(job, secret) {
  if (!job?.job_signature || !secret) return false;
  const signingJob = {
    check_id: job.check_id,
    constraints: job.constraints,
    id: job.id,
    nonce_hash: job.nonce_hash,
    probe_profile: job.probe_profile,
    target: job.target,
    tenant_id: job.tenant_id,
    test_run_id: job.test_run_id,
  };
  const expected = signProbeJob(signingJob, secret);
  return safeEqualUtf8(job.job_signature, expected);
}

/**
 * @param {{
 *   run: { id: string, tenant_id: string, safety_constraints?: Record<string, unknown> },
 *   check: Record<string, unknown>,
 *   target: Record<string, unknown>,
 *   probeProfile?: unknown,
 *   probeWorkerSecret: string,
 *   now: Date,
 *   newId: () => string,
 * }} params
 */
export function buildSignedProbeJobRecord({
  run,
  check,
  target,
  probeProfile,
  probeWorkerSecret,
  now,
  newId,
}) {
  const nonce = generateNonce();
  const nonce_hash = hashNonce(nonce);
  const resolvedProbeProfile = resolveJobProbeProfile(check, probeProfile);
  const constraints = normalizeJobConstraints(run.safety_constraints, resolvedProbeProfile);
  const job = {
    id: newId(),
    tenant_id: run.tenant_id,
    test_run_id: run.id,
    target_id: target.id,
    check_id: check.check_id,
    vector_family: check.vector_family,
    status: 'pending',
    created_at: now.toISOString(),
    nonce_hash,
    nonce,
    probe_profile: resolvedProbeProfile,
    constraints,
    target: targetDescriptor(target),
    worker_metadata: {
      check_title: check.title ?? check.check_id,
      safety_class: check.safety_class ?? check.risk_class ?? null,
    },
    leased_at: null,
    leased_by: null,
    completed_at: null,
  };
  job.job_signature = signProbeJob(job, probeWorkerSecret);
  return job;
}