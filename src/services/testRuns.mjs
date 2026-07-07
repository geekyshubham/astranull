import { isIP } from 'node:net';
import { audit } from '../audit.mjs';
import {
  evaluateCheckPrerequisites,
  getCheckById,
  isCustomerRunnable,
  resolveExpectedBehaviorForCheck,
} from '../contracts/checks.mjs';
import { incMetric } from '../lib/metrics.mjs';
import { redactObject } from '../lib/redact.mjs';
import { recordEvidence } from './evidence.mjs';
import { newId } from '../lib/ids.mjs';
import { enrichProbeMetadataWithWafCatalog } from '../lib/wafProductCatalog.mjs';
import { getStore, persistStore } from '../store.mjs';
import { enqueueAgentJob } from './agents.mjs';
import { correlateExternalOnlyVerdict, correlateVerdict, withinCorrelationWindow } from './correlation.mjs';
import { upsertFindingFromVerdict } from './findings.mjs';
import { executeOpsReadinessProbe, isOpsReadinessProbeKind } from '../lib/opsReadinessValidation.mjs';
import { simulateProbeResult } from './probeStub.mjs';
import { createProbeJob } from './probeCoordinator.mjs';
import { computeReadiness } from './readiness.mjs';
import { isArchivedTargetGroup } from './targetGroups.mjs';
import {
  countCustomerRunnableRunsLastHour,
  effectiveSafetyConstraints,
  isWithinSafeTestWindow,
  lastRunForTargetGroup,
  normalizeSafetyPolicy,
  wouldExceedEventCap,
} from './safeTestPolicy.mjs';
import { isKillSwitchActiveForTenant } from './killSwitchState.mjs';
import { computePlacementConfidence } from './placement.mjs';
import { assertSubscriptionLimit, getTenantAccount } from './subscriptions.mjs';

const OBSERVATION_RAW_FIELD_DENYLIST = new Set([
  'packet_payload',
  'raw_packet',
  'raw_packets',
  'packet_data',
  'raw_payload',
  'payload',
  'body',
  'headers',
  'request_body',
  'request_headers',
  'authorization',
  'cookie',
  'raw_log',
  'log_line',
]);
const OBSERVATION_RAW_FIELD_COMPACT_DENYLIST = new Set(
  [...OBSERVATION_RAW_FIELD_DENYLIST].map((key) => key.replace(/_/g, '')),
);

function normalizeObservationRawFieldKey(key) {
  return String(key)
    .trim()
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2')
    .replace(/([a-z])([A-Z])/g, '$1_$2')
    .replace(/[^a-zA-Z0-9]+/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase();
}

function observationBodyContainsRawFields(body) {
  if (!body || typeof body !== 'object') return false;
  const scan = (value) => {
    if (value == null) return false;
    if (Array.isArray(value)) {
      for (const item of value) {
        if (scan(item)) return true;
      }
      return false;
    }
    if (typeof value !== 'object') return false;
    for (const key of Object.keys(value)) {
      const normalized = normalizeObservationRawFieldKey(key);
      const compact = normalized.replace(/_/g, '');
      if (
        OBSERVATION_RAW_FIELD_DENYLIST.has(normalized)
        || OBSERVATION_RAW_FIELD_COMPACT_DENYLIST.has(compact)
        || normalized.startsWith('raw_')
        || compact.startsWith('raw')
      ) {
        return true;
      }
      if (scan(value[key])) return true;
    }
    return false;
  };
  return scan(body);
}

function rejectObservation(ctx, tenantId, agentId, reason, error, status, resourceId, extra = {}) {
  audit({
    tenant_id: tenantId,
    actor_user_id: ctx?.userId ?? 'agent',
    actor_role: ctx?.role ?? 'agent',
    action: 'observation.rejected',
    resource_type: 'test_run',
    resource_id: resourceId ?? null,
    metadata: { agent_id: agentId, reason, ...extra },
  });
  persistStore();
  return { error, status };
}

export function listChecks() {
  return getStore().checkCatalog ?? [];
}

export function listTestRuns(ctx, options = {}) {
  let rows = getStore().testRuns.filter((r) => r.tenant_id === ctx.tenantId);
  if (options.target_group_id) {
    rows = rows.filter((r) => r.target_group_id === options.target_group_id);
  }
  if (options.target_id) {
    rows = rows.filter((r) => r.target_id === options.target_id);
  }
  rows = rows.sort((a, b) => String(b.started_at ?? b.created_at).localeCompare(String(a.started_at ?? a.created_at)));
  const limit = Number(options.limit);
  if (Number.isFinite(limit) && limit > 0) rows = rows.slice(0, limit);
  return rows;
}

export function listTestRunsEnvelope(ctx, options = {}) {
  const items = listTestRuns(ctx, options);
  return {
    items,
    count: items.length,
    meta: {
      empty_reason: items.length
        ? null
        : options.target_group_id
          ? 'No test runs match this target group filter.'
          : options.target_id
            ? 'No test runs match this target filter.'
            : 'No test runs have been started for this tenant yet.',
    },
  };
}

function collectionDeadlineMs(check) {
  const seconds = check?.safety_constraints?.max_duration_seconds ?? 120;
  return seconds * 1000;
}

function hasMatchingObservation(run) {
  const store = getStore();
  const probeEvent = store.events.find(
    (e) =>
      e.test_run_id === run.id &&
      e.signal_type === 'probe_result' &&
      e.nonce_hash === run.correlation.nonce_hash,
  );
  const obsEvents = store.events.filter(
    (e) => e.test_run_id === run.id && e.signal_type === 'agent_observation',
  );
  return obsEvents.some(
    (e) =>
      e.nonce_hash === run.correlation.nonce_hash &&
      withinCorrelationWindow(probeEvent?.timestamp, e.timestamp, run.correlation.window_ms),
  );
}

function boundOnlineAgentForRun(run) {
  return getStore().agents.find(
    (a) =>
      a.tenant_id === run.tenant_id &&
      a.status === 'online' &&
      (a.target_group_id === run.target_group_id || !a.target_group_id),
  );
}

function isCollectionWindowExpired(run) {
  if (!run.collection_deadline_at) return false;
  return Date.now() >= new Date(run.collection_deadline_at).getTime();
}

function hasExternalProbeEvidence(run) {
  if (run.probe_external_result != null && run.probe_external_result !== '') return true;
  const store = getStore();
  return store.events.some(
    (e) =>
      e.test_run_id === run.id &&
      e.signal_type === 'probe_result' &&
      e.nonce_hash === run.correlation.nonce_hash,
  );
}

export function maybeFinalizeCollectingRun(run, { force = false } = {}) {
  if (!run || run.status !== 'collecting') return null;
  if (getStore().verdicts.some((v) => v.test_run_id === run.id)) return null;
  if (!hasExternalProbeEvidence(run)) return null;
  if (hasMatchingObservation(run)) return null;
  if (!force && !isCollectionWindowExpired(run)) return null;
  return finalizeNoObservation(run);
}

export function finalizeTestRun(ctx, id, { force = false } = {}) {
  const run = getStore().testRuns.find((r) => r.id === id && r.tenant_id === ctx.tenantId);
  if (!run) return null;
  if (run.status !== 'collecting') {
    return { error: 'not_collecting', status: 409 };
  }
  if (!hasExternalProbeEvidence(run)) {
    return { error: 'external_probe_pending', status: 409 };
  }
  if (!force && !isCollectionWindowExpired(run)) {
    return { error: 'observation_window_active', status: 409 };
  }
  const verdict = maybeFinalizeCollectingRun(run, { force: true });
  if (!verdict) {
    return { error: 'cannot_finalize', status: 409 };
  }
  persistStore();
  return { run: getTestRun(ctx, id), verdict };
}

export function getTestRun(ctx, id) {
  const run = getStore().testRuns.find((r) => r.id === id && r.tenant_id === ctx.tenantId);
  if (!run) return null;
  maybeFinalizeCollectingRun(run);
  const verdict = getStore().verdicts.find((v) => v.test_run_id === id);
  return { ...run, verdict: verdict ?? null };
}

export function getRunEvents(ctx, id) {
  const run = getStore().testRuns.find((r) => r.id === id && r.tenant_id === ctx.tenantId);
  if (!run) return null;
  return getStore().events.filter((e) => e.test_run_id === id && e.tenant_id === ctx.tenantId);
}

function activeRunForGroup(tenantId, targetGroupId) {
  return getStore().testRuns.find(
    (r) =>
      r.tenant_id === tenantId &&
      r.target_group_id === targetGroupId &&
      ['running', 'collecting', 'planned'].includes(r.status),
  );
}

const CANCELLABLE_STATUSES = new Set(['planned', 'running', 'collecting']);

function denySafeStart(ctx, action, resourceId, metadata, error, status = 429) {
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action,
    resource_type: 'test_run',
    resource_id: resourceId,
    metadata,
  });
  persistStore();
  return { error, status };
}

function denyEventCap(ctx, run, metadata = {}) {
  return denySafeStart(
    ctx,
    'test_run.event_cap_denied',
    run.id,
    { check_id: run.check_id, ...metadata },
    'event_cap_exceeded',
    429,
  );
}

function normalizedUrlHostname(value) {
  try {
    return new URL(String(value)).hostname.replace(/^\[|\]$/g, '');
  } catch {
    return null;
  }
}

function effectiveTargetKind(target) {
  if (/^https?:\/\//i.test(String(target?.value ?? ''))) return 'url';
  return target?.kind;
}

function hasDirectOriginForHostSni(target, body = {}) {
  const overrideDirectIp =
    body?.probe_profile != null && typeof body.probe_profile === 'object' && !Array.isArray(body.probe_profile)
      ? body.probe_profile.direct_ip
      : null;
  const metadata = target?.metadata_json ?? target?.metadata ?? {};
  const directIp = overrideDirectIp ?? metadata.direct_origin_ip;
  if (typeof directIp === 'string' && directIp.trim()) return true;
  if (target?.kind === 'ip' && isIP(String(target.value ?? '').replace(/^\[|\]$/g, '')) !== 0) {
    return true;
  }
  if (/^https?:\/\//i.test(String(target?.value ?? ''))) {
    const host = normalizedUrlHostname(target.value);
    if (host && isIP(host) !== 0) return true;
  }
  return false;
}

export function maybeFinalizeRunAfterProbeIngest(ctxOrRunId, maybeRunId) {
  let ctx = null;
  let runId;
  if (typeof ctxOrRunId === 'string') {
    runId = ctxOrRunId;
  } else if (ctxOrRunId != null && typeof ctxOrRunId === 'object' && maybeRunId != null) {
    ctx = ctxOrRunId;
    runId = maybeRunId;
  } else {
    return null;
  }
  if (!runId) return null;

  const store = getStore();
  const run = store.testRuns.find((r) => {
    if (r.id !== runId) return false;
    if (ctx?.tenantId) return r.tenant_id === ctx.tenantId;
    return true;
  });
  if (!run) return null;
  run.awaiting_external_probe = false;
  if (!hasExternalProbeEvidence(run)) return null;

  const agent = boundOnlineAgentForRun(run);
  if (hasMatchingObservation(run)) {
    return finalizeVerdictIfReady(run, agent);
  }
  if (isCollectionWindowExpired(run)) {
    return maybeFinalizeCollectingRun(run);
  }
  if (run.status === 'running') run.status = 'collecting';
  persistStore();
  return null;
}

export function startTestRun(ctx, body, runtimeConfig = { probeMode: 'simulation' }) {
  const check = getCheckById(body.check_id);
  if (!check) return { error: 'unknown_check', status: 400 };
  if (!isCustomerRunnable(check)) {
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'test_run.blocked_soc_gated',
      resource_type: 'check',
      resource_id: check.check_id,
    });
    persistStore();
    return { error: 'soc_gated_check', status: 403, message: 'This check requires SOC governance.' };
  }

  const targetGroupId = body.target_group_id;
  const group = getStore().targetGroups.find(
    (g) => g.id === targetGroupId && g.tenant_id === ctx.tenantId && !isArchivedTargetGroup(g),
  );
  if (!group) return { error: 'target_group_not_found', status: 404 };

  if (isKillSwitchActiveForTenant(ctx.tenantId)) {
    return denySafeStart(
      ctx,
      'test_run.kill_switch_denied',
      targetGroupId,
      { check_id: check.check_id, target_group_id: targetGroupId },
      'kill_switch_active',
      423,
    );
  }

  const tenantAccount = getTenantAccount(ctx.tenantId);
  if (tenantAccount?.lifecycle_state === 'suspended') {
    return {
      error: 'tenant_suspended',
      status: 403,
      message: 'Tenant access is suspended.',
    };
  }

  const hourlyRuns = countCustomerRunnableRunsLastHour(ctx.tenantId);
  const subscriptionLimit = assertSubscriptionLimit(
    ctx.tenantId,
    'safe_runs_per_hour',
    hourlyRuns,
  );
  if (!subscriptionLimit.ok) {
    return {
      error: subscriptionLimit.error,
      status: 403,
      metric: subscriptionLimit.metric,
      limit: subscriptionLimit.limit,
      current: subscriptionLimit.current,
      message: 'Subscription safe-run limit reached.',
    };
  }

  if (activeRunForGroup(ctx.tenantId, targetGroupId)) {
    return { error: 'concurrent_run_blocked', status: 409 };
  }

  const targetId = body.target_id ?? getStore().targets.find((t) => t.target_group_id === targetGroupId)?.id;
  const target = getStore().targets.find(
    (t) => t.id === targetId && t.tenant_id === ctx.tenantId && t.target_group_id === targetGroupId,
  );
  if (!target) return { error: 'target_not_found', status: 404 };

  const kind = effectiveTargetKind(target);
  if (Array.isArray(check.supported_targets) && check.supported_targets.length > 0) {
    if (!check.supported_targets.includes(kind)) {
      return {
        error: 'target_kind_not_supported',
        status: 400,
        check_id: check.check_id,
        target_kind: kind ?? null,
        supported_targets: check.supported_targets,
      };
    }
  }

  if (
    runtimeConfig.probeMode === 'signed-worker'
    && check.probe_profile?.kind === 'host_sni_bypass'
    && !hasDirectOriginForHostSni(target, body)
  ) {
    return {
      error: 'missing_direct_origin_ip',
      status: 400,
      check_id: check.check_id,
      message:
        'Signed-worker Host/SNI bypass checks require an IP target, literal-IP URL, probe_profile.direct_ip, or target.metadata.direct_origin_ip.',
    };
  }

  const onlineAgents = getStore().agents.filter(
    (a) =>
      a.tenant_id === ctx.tenantId &&
      a.status === 'online' &&
      a.last_token_validation_status !== 'invalid',
  );
  const missingPrereqs = evaluateCheckPrerequisites(check, { onlineAgents });
  if (missingPrereqs.length) {
    return {
      error: 'prerequisites_not_met',
      status: 409,
      missing: missingPrereqs,
      message: `Missing prerequisites: ${missingPrereqs.join(', ')}`,
    };
  }

  const groupPolicy = normalizeSafetyPolicy(group.safety_policy);
  if ((group.safe_test_windows ?? []).length > 0 && !isWithinSafeTestWindow(group)) {
    return denySafeStart(
      ctx,
      'test_run.safe_window_denied',
      targetGroupId,
      { check_id: check.check_id, target_group_id: targetGroupId },
      'safe_window_closed',
      429,
    );
  }

  if (countCustomerRunnableRunsLastHour(ctx.tenantId) >= groupPolicy.max_runs_per_hour) {
    return denySafeStart(
      ctx,
      'test_run.safe_rate_denied',
      targetGroupId,
      {
        check_id: check.check_id,
        max_runs_per_hour: groupPolicy.max_runs_per_hour,
      },
      'safe_rate_cap_exceeded',
      429,
    );
  }

  const priorRun = lastRunForTargetGroup(ctx.tenantId, targetGroupId);
  if (priorRun && groupPolicy.min_seconds_between_runs > 0) {
    const elapsedMs = Date.now() - new Date(priorRun.created_at).getTime();
    if (elapsedMs < groupPolicy.min_seconds_between_runs * 1000) {
      return denySafeStart(
        ctx,
        'test_run.safe_interval_denied',
        priorRun.id,
        {
          check_id: check.check_id,
          target_group_id: targetGroupId,
          min_seconds_between_runs: groupPolicy.min_seconds_between_runs,
        },
        'safe_min_interval_active',
        429,
      );
    }
  }

  const safetyConstraints = effectiveSafetyConstraints(check, group);
  const runId = newId('run');
  const run = {
    id: runId,
    tenant_id: ctx.tenantId,
    target_group_id: targetGroupId,
    target_id: target.id,
    check_id: check.check_id,
    vector_family: check.vector_family,
    safety_class: check.safety_class ?? check.risk_class,
    remediation_template: check.remediation_template,
    safety_constraints: safetyConstraints,
    status: 'running',
    created_at: new Date().toISOString(),
    created_by: ctx.userId,
    correlation: { nonce_hash: null, window_ms: 120000 },
    collection_deadline_at: new Date(
      Date.now() + collectionDeadlineMs(check),
    ).toISOString(),
  };
  getStore().testRuns.push(run);

  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'test_run.started',
    resource_type: 'test_run',
    resource_id: runId,
    metadata: { check_id: check.check_id },
  });

  const probeMode = runtimeConfig.probeMode ?? 'simulation';
  let probe;
  let probeEvent = null;
  let probeJob = null;

  const inlineProbe = isOpsReadinessProbeKind(check) || probeMode !== 'signed-worker';

  if (!inlineProbe) {
    if (wouldExceedEventCap(run, 1)) {
      getStore().testRuns.pop();
      return denyEventCap(ctx, run, { phase: 'probe_job' });
    }
    probeJob = createProbeJob(ctx, run, check, target, body.probe_profile, runtimeConfig);
    run.correlation.nonce_hash = probeJob.nonce_hash;
    run.awaiting_external_probe = true;
    probe = { nonce: probeJob.nonce, nonce_hash: probeJob.nonce_hash, external_result: null };
  } else {
    probe = isOpsReadinessProbeKind(check)
      ? executeOpsReadinessProbe(ctx, check, target)
      : simulateProbeResult(check, target, body.probe_profile);
    run.correlation.nonce_hash = probe.nonce_hash;

    if (wouldExceedEventCap(run, 1)) {
      getStore().testRuns.pop();
      return denyEventCap(ctx, run, { phase: 'probe' });
    }

    const evidenceLabel = isOpsReadinessProbeKind(check)
      ? 'ops_readiness_probe_evidence'
      : 'probe_simulation_evidence';

    probeEvent = {
      id: probe.event_id,
      tenant_id: ctx.tenantId,
      test_run_id: runId,
      target_id: target.id,
      check_id: check.check_id,
      source: probe.source,
      signal_type: probe.signal_type,
      timestamp: new Date().toISOString(),
      nonce_hash: probe.nonce_hash,
      metadata: { ...probe.metadata, external_result: probe.external_result },
    };
    getStore().events.push(probeEvent);

    recordEvidence(ctx, {
      test_run_id: runId,
      label: evidenceLabel,
      metadata: enrichProbeMetadataWithWafCatalog(
        {
          vector_family: check.vector_family,
          safety_class: check.safety_class,
          probe_event_id: probeEvent.id,
          ...(isOpsReadinessProbeKind(check)
            ? { ops_readiness: true }
            : { simulation: 'SAFE_PROBE_SIMULATION' }),
        },
        check.check_id,
      ),
      related_event_id: probeEvent.id,
    });
    run.status = 'collecting';
    run.probe_external_result = probe.external_result;
  }

  const boundAgents = getStore().agents.filter(
    (a) =>
      a.tenant_id === ctx.tenantId &&
      a.status === 'online' &&
      a.last_token_validation_status !== 'invalid' &&
      (a.target_group_id === targetGroupId || !a.target_group_id),
  );

  for (const agent of boundAgents) {
    enqueueAgentJob({
      tenantId: ctx.tenantId,
      agentId: agent.id,
      testRunId: runId,
      checkId: check.check_id,
      targetId: target.id,
      nonce_hash: probe.nonce_hash,
      nonce: probe.nonce,
    });
  }

  incMetric('test_runs_started_total');
  persistStore();

  const result = { run, jobs_dispatched: boundAgents.length };
  if (probeEvent) result.probe_event = probeEvent;
  if (probeJob) {
    result.probe_job = {
      id: probeJob.id,
      status: probeJob.status,
      job_signature: probeJob.job_signature,
      nonce_hash: probeJob.nonce_hash,
    };
  }
  return result;
}

export function ingestObservation(ctx, agentId, body) {
  const store = getStore();
  const agent = store.agents.find((a) => a.id === agentId);
  if (!agent) return { error: 'agent_not_found', status: 404 };
  const run = store.testRuns.find(
    (r) => r.id === body.test_run_id && r.tenant_id === agent.tenant_id,
  );
  if (!run) return { error: 'run_not_found', status: 404 };

  if (body.tenant_id && body.tenant_id !== agent.tenant_id) {
    audit({
      tenant_id: agent.tenant_id,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'observation.tenant_rejected',
      resource_type: 'agent',
      resource_id: agentId,
      metadata: { attempted_tenant: body.tenant_id },
    });
    persistStore();
    return { error: 'cross_tenant_injection', status: 403 };
  }

  if (!['running', 'collecting'].includes(run.status)) {
    audit({
      tenant_id: run.tenant_id,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'observation.rejected_inactive_run',
      resource_type: 'test_run',
      resource_id: run.id,
      metadata: { status: run.status, agent_id: agentId },
    });
    persistStore();
    return { error: 'run_not_collecting', status: 409 };
  }

  if (observationBodyContainsRawFields(body)) {
    return rejectObservation(
      ctx,
      run.tenant_id,
      agentId,
      'raw_packet_fields',
      'raw_packet_rejected',
      400,
      run.id,
    );
  }

  const agentJobId = body.agent_job_id ?? body.job_id;
  if (!agentJobId) {
    return rejectObservation(
      ctx,
      run.tenant_id,
      agentId,
      'missing_agent_job_id',
      'missing_agent_job_id',
      400,
      run.id,
    );
  }

  const job = store.agentJobs.find((j) => j.id === agentJobId);
  if (!job) {
    return rejectObservation(
      ctx,
      run.tenant_id,
      agentId,
      'agent_job_not_found',
      'agent_job_not_found',
      404,
      run.id,
      { agent_job_id: agentJobId },
    );
  }

  const targetId = body.target_id ?? run.target_id;
  const jobMismatch =
    job.agent_id !== agentId ||
    job.tenant_id !== run.tenant_id ||
    job.test_run_id !== run.id ||
    job.nonce_hash !== body.nonce_hash ||
    job.target_id !== targetId ||
    job.check_id !== run.check_id;

  if (jobMismatch) {
    return rejectObservation(
      ctx,
      run.tenant_id,
      agentId,
      'agent_job_mismatch',
      'agent_job_mismatch',
      403,
      run.id,
      { agent_job_id: agentJobId },
    );
  }

  if (job.status === 'pending') {
    return rejectObservation(
      ctx,
      run.tenant_id,
      agentId,
      'agent_job_not_acked',
      'agent_job_not_acked',
      409,
      run.id,
      { agent_job_id: agentJobId },
    );
  }

  if (job.status === 'observed') {
    return rejectObservation(
      ctx,
      run.tenant_id,
      agentId,
      'agent_job_already_observed',
      'agent_job_already_observed',
      409,
      run.id,
      { agent_job_id: agentJobId },
    );
  }

  if (job.status !== 'acked') {
    return rejectObservation(
      ctx,
      run.tenant_id,
      agentId,
      'agent_job_not_open',
      'agent_job_not_open',
      409,
      run.id,
      { agent_job_id: agentJobId, status: job.status },
    );
  }

  if (wouldExceedEventCap(run, 1)) {
    return denyEventCap(
      { tenantId: run.tenant_id, userId: ctx?.userId ?? 'agent', role: ctx?.role ?? 'agent' },
      run,
      { agent_id: agentId, phase: 'agent_observation' },
    );
  }

  const obsEvent = {
    id: newId('event'),
    tenant_id: run.tenant_id,
    test_run_id: run.id,
    target_id: body.target_id ?? run.target_id,
    check_id: run.check_id,
    agent_id: agentId,
    source: 'agent',
    signal_type: 'agent_observation',
    timestamp: new Date().toISOString(),
    nonce_hash: body.nonce_hash,
    metadata: redactObject(body.metadata ?? {}),
  };
  store.events.push(obsEvent);

  job.status = 'observed';
  job.observed_at = new Date().toISOString();

  audit({
    tenant_id: run.tenant_id,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'observation.ingested',
    resource_type: 'test_run',
    resource_id: run.id,
    metadata: { agent_id: agentId },
  });

  if (run.awaiting_external_probe && !hasExternalProbeEvidence(run)) {
    persistStore();
    return { observation: obsEvent, run: { ...run, verdict: null } };
  }

  const verdict = finalizeVerdictIfReady(run, agent);
  persistStore();
  const storedVerdict = verdict ?? getStore().verdicts.find((v) => v.test_run_id === run.id) ?? null;
  return { observation: obsEvent, run: { ...run, verdict: storedVerdict } };
}

function finalizeNoObservation(run) {
  const store = getStore();
  if (wouldExceedEventCap(run, 1)) {
    audit({
      tenant_id: run.tenant_id,
      actor_user_id: 'system',
      actor_role: 'system',
      action: 'test_run.event_cap_denied',
      resource_type: 'test_run',
      resource_id: run.id,
      metadata: { phase: 'agent_no_observation' },
    });
    persistStore();
    return null;
  }
  store.events.push({
    id: newId('event'),
    tenant_id: run.tenant_id,
    test_run_id: run.id,
    target_id: run.target_id,
    check_id: run.check_id,
    source: 'system',
    signal_type: 'agent_no_observation',
    timestamp: new Date().toISOString(),
    metadata: {
      reason: 'bounded_observation_window_elapsed',
      collection_deadline_at: run.collection_deadline_at,
    },
  });
  const agent = boundOnlineAgentForRun(run);
  return finalizeVerdictIfReady(run, agent, { agentObserved: false, finalizedWithoutObservation: true });
}

function finalizeVerdictIfReady(run, agent, options = {}) {
  const store = getStore();
  if (store.verdicts.some((v) => v.test_run_id === run.id)) return store.verdicts.find((v) => v.test_run_id === run.id);
  if (!hasExternalProbeEvidence(run)) return null;
  const target = store.targets.find((t) => t.id === run.target_id);
  const group = store.targetGroups.find(
    (g) => g.id === run.target_group_id && g.tenant_id === run.tenant_id,
  );
  const externalOnly = group?.validation_mode === 'external_only';
  const probeEvent = store.events.find(
    (e) =>
      e.test_run_id === run.id &&
      e.signal_type === 'probe_result' &&
      e.nonce_hash === run.correlation.nonce_hash,
  );
  const obsEvents = store.events.filter(
    (e) => e.test_run_id === run.id && e.signal_type === 'agent_observation',
  );
  const matchingObs = obsEvents.find(
    (e) =>
      e.nonce_hash === run.correlation.nonce_hash &&
      withinCorrelationWindow(probeEvent?.timestamp, e.timestamp, run.correlation.window_ms),
  );

  const agentObserved =
    options.agentObserved !== undefined ? options.agentObserved : Boolean(matchingObs);

  if (
    !externalOnly
    && !options.finalizedWithoutObservation
    && !matchingObs
    && !isCollectionWindowExpired(run)
  ) {
    return null;
  }

  const externalResult = run.probe_external_result ?? probeEvent?.metadata?.external_result;
  const expectedBehavior = resolveExpectedBehaviorForCheck(run.check_id);

  const result = externalOnly
    ? correlateExternalOnlyVerdict({ externalResult, expectedBehavior })
    : correlateVerdict({
      externalResult,
      agentObserved,
      expectedBehavior,
      agentOnline: agent?.status === 'online',
      agentBound: Boolean(
        agent && (agent.target_group_id === run.target_group_id || !agent.target_group_id),
      ),
    });

  const evidenceIds = store.events
    .filter((e) => e.test_run_id === run.id)
    .map((e) => e.id);

  const placement_confidence = computePlacementConfidence(store, run, {
    matchingObservation: matchingObs ?? null,
    agentObserved,
    finalizedWithoutObservation: Boolean(options.finalizedWithoutObservation),
    agent: agent ?? null,
  });

  const verdict = {
    id: newId('evidence'),
    tenant_id: run.tenant_id,
    test_run_id: run.id,
    target_id: run.target_id,
    check_id: run.check_id,
    verdict: result.verdict,
    confidence: result.confidence,
    placement_confidence,
    explanation: result.explanation,
    evidence_ids: evidenceIds,
    severity: result.severity,
    created_at: new Date().toISOString(),
  };
  if (externalOnly) {
    verdict.placement = result.placement ?? 'unverified';
    verdict.strengthen_hint = result.strengthen_hint;
  }
  store.verdicts.push(verdict);
  run.status = 'verdicted';
  run.completed_at = new Date().toISOString();

  audit({
    tenant_id: run.tenant_id,
    actor_user_id: 'system',
    actor_role: 'system',
    action: options.finalizedWithoutObservation ? 'verdict.finalized_no_observation' : 'verdict.published',
    resource_type: 'test_run',
    resource_id: run.id,
    metadata: {
      verdict: verdict.verdict,
      confidence: verdict.confidence,
      placement_confidence_level: placement_confidence.level,
      placement_confidence_status: placement_confidence.status,
    },
  });

  if (result.createsFinding) {
    upsertFindingFromVerdict(
      { tenantId: run.tenant_id, userId: 'system', role: 'system' },
      verdict,
      run,
      target,
    );
  }

  computeReadiness(run.tenant_id);
  return verdict;
}

export function autoCancelActiveSafeRunsForKillSwitch(ctx, reason) {
  const cancelledRunIds = [];
  for (const run of getStore().testRuns) {
    if (run.tenant_id !== ctx.tenantId) continue;
    if (!CANCELLABLE_STATUSES.has(run.status)) continue;
    run.status = 'cancelled';
    run.completed_at = new Date().toISOString();
    run.cancelled_by_kill_switch = true;
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'test_run.kill_switch_auto_cancel',
      resource_type: 'test_run',
      resource_id: run.id,
      metadata: { reason: reason ?? null, check_id: run.check_id, target_group_id: run.target_group_id },
    });
    cancelledRunIds.push(run.id);
  }
  if (cancelledRunIds.length) persistStore();
  return cancelledRunIds;
}

export function cancelTestRun(ctx, id) {
  const run = getStore().testRuns.find((r) => r.id === id && r.tenant_id === ctx.tenantId);
  if (!run) return null;
  if (!CANCELLABLE_STATUSES.has(run.status)) {
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'test_run.cancel_denied',
      resource_type: 'test_run',
      resource_id: id,
      metadata: { status: run.status },
    });
    persistStore();
    return { error: 'not_cancellable', status: 409 };
  }
  run.status = 'cancelled';
  run.completed_at = new Date().toISOString();
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'test_run.cancelled',
    resource_type: 'test_run',
    resource_id: id,
  });
  persistStore();
  return { run };
}
