import {
  CHECK_CATALOG,
  evaluateCheckPrerequisites,
  getCheckById,
  isCustomerRunnable,
  resolveExpectedBehaviorForCheck,
} from '../../contracts/checks.mjs';
import { newId } from '../../lib/ids.mjs';
import { incMetric } from '../../lib/metrics.mjs';
import { buildSignedProbeJobRecord } from '../../lib/probeJobs.mjs';
import { redactObject } from '../../lib/redact.mjs';
import {
  countCustomerRunnableRunsLastHour,
  effectiveSafetyConstraints,
  isWithinSafeTestWindow,
  lastRunForTargetGroup,
  wouldExceedEventCap,
} from '../../lib/safeTestGuards.mjs';
import { computePlacementConfidence } from '../../lib/placementConfidence.mjs';
import { enrichProbeMetadataWithWafCatalog } from '../../lib/wafProductCatalog.mjs';
import {
  correlateExternalOnlyVerdict,
  correlateVerdict,
  withinCorrelationWindow,
} from '../../services/correlation.mjs';
import {
  buildOpsReadinessData,
  executeOpsReadinessProbe,
  isOpsReadinessProbeKind,
  resolveOpsReadinessScenario,
} from '../../lib/opsReadinessValidation.mjs';
import { simulateProbeResult } from '../../services/probeStub.mjs';

/** @type {readonly string[]} */
export const VALIDATION_EVIDENCE_REPOSITORY_METHODS = Object.freeze([
  'listTestRuns',
  'getTestRun',
  'getVerdictForRun',
  'listRunEvents',
  'listEvidence',
  'getEvidence',
  'listFindings',
  'getFinding',
  'patchFinding',
  'findEventByTenantEventId',
  'appendEventIdempotent',
  'appendEvidence',
  'createTestRun',
  'updateTestRun',
  'appendEvent',
  'createVerdictIfAbsent',
  'findOpenFinding',
  'upsertOpenFindingFromVerdict',
]);

/** @type {readonly string[]} */
export const VALIDATION_CORE_CATALOG_REPOSITORY_METHODS = Object.freeze(['getTargetGroup']);

/** @type {readonly string[]} */
export const VALIDATION_AGENT_CONTROL_REPOSITORY_METHODS = Object.freeze([
  'listAgents',
  'createAgentJob',
  'getAgentById',
  'getAgentJobById',
  'markAgentJobObserved',
]);

/** @type {readonly string[]} */
export const VALIDATION_PROBE_JOB_REPOSITORY_METHODS = Object.freeze(['createProbeJob']);

/** @type {readonly string[]} */
export const VALIDATION_KILL_SWITCH_REPOSITORY_METHODS = Object.freeze([
  'isKillSwitchActiveForTenant',
]);

/** @type {readonly string[]} */
export const VALIDATION_AUDIT_REPOSITORY_METHODS = Object.freeze(['appendAuditEvent']);

const ACTIVE_RUN_STATUSES = Object.freeze(['planned', 'running', 'collecting']);
const CANCELLABLE_STATUSES = new Set(['planned', 'running', 'collecting']);

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

const EVENT_RAW_FIELD_DENYLIST = new Set([
  'packet_payload',
  'raw_packet',
  'raw_packets',
  'packet_data',
  'raw_payload',
  'exploit_payload',
  'body',
  'headers',
  'request_body',
  'request_headers',
  'authorization',
  'cookie',
  'raw_log',
  'log_line',
]);
const EVENT_RAW_FIELD_COMPACT_DENYLIST = new Set(
  [...EVENT_RAW_FIELD_DENYLIST].map((key) => key.replace(/_/g, '')),
);

function normalizeEventRawFieldKey(key) {
  return String(key)
    .trim()
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2')
    .replace(/([a-z])([A-Z])/g, '$1_$2')
    .replace(/[^a-zA-Z0-9]+/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase();
}

function eventIngestContainsRawFields(value) {
  if (value == null || typeof value !== 'object') return false;
  if (Array.isArray(value)) return value.some((item) => eventIngestContainsRawFields(item));
  for (const [key, child] of Object.entries(value)) {
    const normalized = normalizeEventRawFieldKey(key);
    const compact = normalized.replace(/_/g, '');
    if (
      EVENT_RAW_FIELD_DENYLIST.has(normalized)
      || EVENT_RAW_FIELD_COMPACT_DENYLIST.has(compact)
      || normalized.startsWith('raw_')
      || compact.startsWith('raw')
    ) {
      return true;
    }
    if (eventIngestContainsRawFields(child)) return true;
  }
  return false;
}

function isCollectionWindowExpired(run, nowMs) {
  if (!run.collection_deadline_at) return false;
  return nowMs >= new Date(run.collection_deadline_at).getTime();
}

function hasExternalProbeEvidence(run, events) {
  if (run.probe_external_result != null && run.probe_external_result !== '') return true;
  const nonce = run.correlation?.nonce_hash;
  return events.some(
    (e) => e.test_run_id === run.id && e.signal_type === 'probe_result' && e.nonce_hash === nonce,
  );
}

function findProbeEvent(run, events) {
  const nonce = run.correlation?.nonce_hash;
  return events.find(
    (e) =>
      e.test_run_id === run.id && e.signal_type === 'probe_result' && e.nonce_hash === nonce,
  );
}

function findMatchingObservation(run, events) {
  const probeEvent = findProbeEvent(run, events);
  const windowMs = run.correlation?.window_ms ?? 120_000;
  const nonce = run.correlation?.nonce_hash;
  const obsEvents = events.filter(
    (e) => e.test_run_id === run.id && e.signal_type === 'agent_observation',
  );
  return obsEvents.find(
    (e) =>
      e.nonce_hash === nonce &&
      withinCorrelationWindow(probeEvent?.timestamp, e.timestamp, windowMs),
  );
}

function hasMatchingObservation(run, events) {
  return Boolean(findMatchingObservation(run, events));
}

function boundOnlineAgentForRun(agents, run) {
  return (
    agents.find(
      (a) =>
        a.status === 'online' &&
        (a.target_group_id === run.target_group_id || !a.target_group_id),
    ) ?? null
  );
}

function collectionDeadlineMs(check) {
  const seconds = check?.safety_constraints?.max_duration_seconds ?? 120;
  return seconds * 1000;
}

/** @type {readonly string[]} */
export const POSTGRES_VALIDATION_TEST_RUNS_SERVICE_METHODS = Object.freeze([
  'listChecks',
  'listTestRuns',
  'getTestRun',
  'getRunEvents',
  'startTestRun',
  'finalizeTestRun',
  'cancelTestRun',
  'ingestObservation',
  'maybeFinalizeRunAfterProbeIngest',
]);

/** @type {readonly string[]} */
export const POSTGRES_VALIDATION_EVIDENCE_SERVICE_METHODS = Object.freeze([
  'listEvidence',
  'getEvidence',
]);

/** @type {readonly string[]} */
export const POSTGRES_VALIDATION_FINDINGS_SERVICE_METHODS = Object.freeze([
  'listFindings',
  'getFinding',
  'patchFinding',
]);

/** @type {readonly string[]} */
export const POSTGRES_EVENTS_SERVICE_METHODS = Object.freeze(['ingestEvent']);

export const POSTGRES_VALIDATION_ORCHESTRATION_ERROR = 'postgres_validation_orchestration_not_wired';

function orchestrationNotWired() {
  return { error: POSTGRES_VALIDATION_ORCHESTRATION_ERROR, status: 503 };
}

function assertRepositoryMethods(repo, label, methods) {
  if (!repo || typeof repo !== 'object') {
    throw new Error(`Postgres validation service adapter requires repositories.${label}.`);
  }
  for (const method of methods) {
    if (typeof repo[method] !== 'function') {
      throw new Error(`Postgres validation service adapter requires ${label}.${method}().`);
    }
  }
}

function assertValidationServiceDependencies(repositories) {
  assertRepositoryMethods(
    repositories?.validationEvidence,
    'validationEvidence',
    VALIDATION_EVIDENCE_REPOSITORY_METHODS,
  );
  assertRepositoryMethods(repositories?.audit, 'audit', VALIDATION_AUDIT_REPOSITORY_METHODS);
  assertRepositoryMethods(
    repositories?.coreCatalog,
    'coreCatalog',
    VALIDATION_CORE_CATALOG_REPOSITORY_METHODS,
  );
  assertRepositoryMethods(
    repositories?.agentControl,
    'agentControl',
    VALIDATION_AGENT_CONTROL_REPOSITORY_METHODS,
  );
  assertRepositoryMethods(repositories?.probeJobs, 'probeJobs', VALIDATION_PROBE_JOB_REPOSITORY_METHODS);
  assertRepositoryMethods(
    repositories?.killSwitch,
    'killSwitch',
    VALIDATION_KILL_SWITCH_REPOSITORY_METHODS,
  );
}

/**
 * @param {{
 *   validationEvidence?: Record<string, unknown>,
 *   audit?: { appendAuditEvent?: (...args: unknown[]) => unknown },
 * }} repositories
 * @param {{ now?: () => Date }} [options]
 */
export function createPostgresValidationServices(repositories, options = {}) {
  assertValidationServiceDependencies(repositories);
  const validationEvidence = repositories.validationEvidence;
  const audit = repositories.audit;
  const coreCatalog = repositories.coreCatalog;
  const agentControl = repositories.agentControl;
  const probeJobs = repositories.probeJobs;
  const killSwitch = repositories.killSwitch;
  const productionReleaseEvidence = repositories.productionReleaseEvidence;
  const nowFn = options.now ?? (() => new Date());

  /**
   * Gather ops-readiness governance records from Postgres repositories so the
   * inline ops-readiness probe computes a real result from persisted data. Any
   * repository that is genuinely unavailable degrades to empty inputs, which
   * yields an accurate error/no-evidence verdict rather than a hardcoded pass.
   */
  async function gatherOpsReadinessData(ctx, check) {
    const scenario = resolveOpsReadinessScenario(check);
    let releaseEvidenceLedger = [];
    if (
      productionReleaseEvidence
      && typeof productionReleaseEvidence.listProductionReleaseEvidence === 'function'
    ) {
      releaseEvidenceLedger = await productionReleaseEvidence.listProductionReleaseEvidence(ctx);
    }
    let killSwitchRecord = null;
    let auditEntries = [];
    if (scenario === 'kill_switch_readiness') {
      if (typeof killSwitch.getKillSwitchRecord === 'function') {
        killSwitchRecord = await killSwitch.getKillSwitchRecord(ctx);
      }
      if (typeof audit.listAuditEntries === 'function') {
        auditEntries = await audit.listAuditEntries(ctx, { limit: 500 });
      }
    }
    return buildOpsReadinessData({
      scenario,
      tenantId: ctx.tenantId,
      releaseEvidenceLedger,
      killSwitchRecord,
      auditEntries,
    });
  }

  async function appendAudit(ctx, action, resourceType, resourceId, metadata) {
    await audit.appendAuditEvent(
      {
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId,
        actor_role: ctx.role,
        action,
        resource_type: resourceType,
        resource_id: resourceId,
        metadata: metadata == null ? undefined : redactObject(metadata),
      },
      { now: nowFn() },
    );
  }

  async function denySafeStart(ctx, action, resourceId, metadata, error, status = 429) {
    await appendAudit(ctx, action, 'test_run', resourceId, metadata);
    return { error, status };
  }

  async function rejectObservation(ctx, tenantId, agentId, reason, error, status, resourceId, extra = {}) {
    await appendAudit(
      { tenantId, userId: ctx?.userId ?? 'agent', role: ctx?.role ?? 'agent' },
      'observation.rejected',
      'test_run',
      resourceId ?? null,
      { agent_id: agentId, reason, ...extra },
    );
    return { error, status };
  }

  async function denyEventCapForRun(ctx, run, metadata = {}) {
    return denySafeStart(
      { tenantId: run.tenant_id, userId: ctx?.userId ?? 'agent', role: ctx?.role ?? 'agent' },
      'test_run.event_cap_denied',
      run.id,
      { check_id: run.check_id, ...metadata },
      'event_cap_exceeded',
      429,
    );
  }

  async function upsertFindingForVerdict(ctx, verdict, run, target, agents) {
    if (!target) return null;
    const findingCtx = { tenantId: run.tenant_id, userId: 'system', role: 'system' };
    const existing = await validationEvidence.findOpenFinding(findingCtx, {
      target_group_id: run.target_group_id,
      target_id: target.id,
      check_id: run.check_id,
    });
    const nowIso = nowFn().toISOString();
    const findingId = existing?.id ?? newId('finding');
    const findingRow = await validationEvidence.upsertOpenFindingFromVerdict(findingCtx, {
      id: findingId,
      target_group_id: run.target_group_id,
      target_id: target.id,
      test_run_id: run.id,
      check_id: run.check_id,
      title: `Finding: ${verdict.verdict} on ${target.value}`,
      severity: verdict.severity ?? 'medium',
      status: 'open',
      notes: verdict.explanation,
      evidence_ids: verdict.evidence_ids,
      remediation_template: run.remediation_template,
      verdict_id: existing ? existing.verdict_id : verdict.id,
      last_verdict_id: verdict.id,
      assignee: null,
      created_at: existing?.created_at ?? nowIso,
      updated_at: nowIso,
    });
    await appendAudit(
      findingCtx,
      existing ? 'finding.updated' : 'finding.created',
      'finding',
      findingRow?.id ?? findingId,
    );
    return findingRow;
  }

  async function finalizeVerdictIfReady(ctx, run, agents, options = {}) {
    const existingVerdict = await validationEvidence.getVerdictForRun(ctx, run.id);
    if (existingVerdict) return existingVerdict;

    const events = await validationEvidence.listRunEvents(ctx, run.id, { limit: 1000 });
    if (!hasExternalProbeEvidence(run, events)) return null;

    const group = await coreCatalog.getTargetGroup(ctx, run.target_group_id);
    const target = group?.targets?.find((t) => t.id === run.target_id) ?? null;
    const externalOnly = group?.validation_mode === 'external_only';

    const probeEvent = findProbeEvent(run, events);
    const matchingObs = findMatchingObservation(run, events);
    const agentObserved =
      options.agentObserved !== undefined ? options.agentObserved : Boolean(matchingObs);

    if (
      !externalOnly &&
      !options.finalizedWithoutObservation &&
      !matchingObs &&
      !isCollectionWindowExpired(run, nowFn().getTime())
    ) {
      return null;
    }

    const agent =
      options.agent ??
      boundOnlineAgentForRun(agents, run) ??
      (matchingObs?.agent_id
        ? agents.find((a) => a.id === matchingObs.agent_id) ?? null
        : null);

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

    const evidenceIds = events.map((e) => e.id);
    const placementStore = { agents, testRuns: [run] };
    const placement_confidence = computePlacementConfidence(placementStore, run, {
      matchingObservation: matchingObs ?? null,
      agentObserved,
      finalizedWithoutObservation: Boolean(options.finalizedWithoutObservation),
      agent: agent ?? null,
    });

    const nowIso = nowFn().toISOString();
    const verdictRecord = {
      id: newId('evidence'),
      test_run_id: run.id,
      target_id: run.target_id,
      check_id: run.check_id,
      verdict: result.verdict,
      confidence: result.confidence,
      placement_confidence,
      explanation: result.explanation,
      evidence_ids: evidenceIds,
      severity: result.severity,
      created_at: nowIso,
    };
    const verdict = await validationEvidence.createVerdictIfAbsent(ctx, verdictRecord);

    await validationEvidence.updateTestRun(ctx, run.id, {
      status: 'verdicted',
      completed_at: nowIso,
    });
    run.status = 'verdicted';
    run.completed_at = nowIso;

    await appendAudit(
      { tenantId: run.tenant_id, userId: 'system', role: 'system' },
      options.finalizedWithoutObservation && !externalOnly
        ? 'verdict.finalized_no_observation'
        : 'verdict.published',
      'test_run',
      run.id,
      {
        verdict: verdict.verdict,
        confidence: verdict.confidence,
        placement_confidence_level: placement_confidence.level,
        placement_confidence_status: placement_confidence.status,
      },
    );

    if (result.createsFinding) {
      const fullVerdict = { ...verdict, severity: result.severity ?? verdict.severity };
      await upsertFindingForVerdict(ctx, fullVerdict, run, target, agents);
    }

    return verdict;
  }

  async function finalizeNoObservation(ctx, run, agents) {
    const events = await validationEvidence.listRunEvents(ctx, run.id, { limit: 1000 });
    if (wouldExceedEventCap(run, events.length, 1)) {
      await appendAudit(
        { tenantId: run.tenant_id, userId: 'system', role: 'system' },
        'test_run.event_cap_denied',
        'test_run',
        run.id,
        { phase: 'agent_no_observation' },
      );
      return null;
    }
    const nowIso = nowFn().toISOString();
    await validationEvidence.appendEvent(ctx, {
      id: newId('event'),
      tenant_id: run.tenant_id,
      test_run_id: run.id,
      target_id: run.target_id,
      check_id: run.check_id,
      source: 'system',
      signal_type: 'agent_no_observation',
      timestamp: nowIso,
      metadata: {
        reason: 'bounded_observation_window_elapsed',
        collection_deadline_at: run.collection_deadline_at,
      },
    });
    const boundAgent = boundOnlineAgentForRun(agents, run);
    return finalizeVerdictIfReady(ctx, run, agents, {
      agentObserved: false,
      finalizedWithoutObservation: true,
      agent: boundAgent,
    });
  }

  async function maybeFinalizeCollectingRun(ctx, run, agents, { force = false } = {}) {
    if (!run || run.status !== 'collecting') return null;
    const existingVerdict = await validationEvidence.getVerdictForRun(ctx, run.id);
    if (existingVerdict) return null;
    const events = await validationEvidence.listRunEvents(ctx, run.id, { limit: 1000 });
    if (!hasExternalProbeEvidence(run, events)) return null;
    if (hasMatchingObservation(run, events)) return null;
    const collectingGroup = await coreCatalog.getTargetGroup(ctx, run.target_group_id);
    if (collectingGroup?.validation_mode === 'external_only') {
      return finalizeVerdictIfReady(ctx, run, agents, { agentObserved: false });
    }
    if (!force && !isCollectionWindowExpired(run, nowFn().getTime())) return null;
    return finalizeNoObservation(ctx, run, agents);
  }

  const testRuns = {
    listChecks() {
      return CHECK_CATALOG;
    },
    async listTestRuns(ctx) {
      return validationEvidence.listTestRuns(ctx);
    },
    async getTestRun(ctx, id) {
      const run = await validationEvidence.getTestRun(ctx, id);
      if (!run) return null;
      const verdict = await validationEvidence.getVerdictForRun(ctx, id);
      return { ...run, verdict: verdict ?? null };
    },
    async getRunEvents(ctx, id) {
      const run = await validationEvidence.getTestRun(ctx, id);
      if (!run) return null;
      return validationEvidence.listRunEvents(ctx, id);
    },
    async startTestRun(ctx, body, runtimeConfig = { probeMode: 'simulation' }) {
      const check = getCheckById(body.check_id);
      if (!check) return { error: 'unknown_check', status: 400 };
      if (!isCustomerRunnable(check)) {
        await appendAudit(ctx, 'test_run.blocked_soc_gated', 'check', check.check_id);
        return {
          error: 'soc_gated_check',
          status: 403,
          message: 'This check requires SOC governance.',
        };
      }

      const targetGroupId = body.target_group_id;
      const group = await coreCatalog.getTargetGroup(ctx, targetGroupId);
      if (!group) return { error: 'target_group_not_found', status: 404 };

      if (await killSwitch.isKillSwitchActiveForTenant(ctx)) {
        return denySafeStart(
          ctx,
          'test_run.kill_switch_denied',
          targetGroupId,
          { check_id: check.check_id, target_group_id: targetGroupId },
          'kill_switch_active',
          423,
        );
      }

      const activeRuns = await validationEvidence.listTestRuns(ctx, {
        targetGroupId,
        statuses: [...ACTIVE_RUN_STATUSES],
        limit: 1,
      });
      if (activeRuns.length > 0) {
        return { error: 'concurrent_run_blocked', status: 409 };
      }

      const targets = group.targets ?? [];
      const targetId = body.target_id ?? targets[0]?.id;
      const target = targets.find((t) => t.id === targetId);
      if (!target) return { error: 'target_not_found', status: 404 };

      const agents = await agentControl.listAgents(ctx);
      const onlineAgents = agents.filter((a) => a.status === 'online');
      const missingPrereqs = evaluateCheckPrerequisites(check, { onlineAgents });
      if (missingPrereqs.length) {
        return {
          error: 'prerequisites_not_met',
          status: 409,
          missing: missingPrereqs,
          message: `Missing prerequisites: ${missingPrereqs.join(', ')}`,
        };
      }

      const now = nowFn();
      const nowMs = now.getTime();
      if ((group.safe_test_windows ?? []).length > 0 && !isWithinSafeTestWindow(group, nowMs)) {
        return denySafeStart(
          ctx,
          'test_run.safe_window_denied',
          targetGroupId,
          { check_id: check.check_id, target_group_id: targetGroupId },
          'safe_window_closed',
          429,
        );
      }

      const recentRuns = await validationEvidence.listTestRuns(ctx, { limit: 500 });
      const groupPolicy = effectiveSafetyConstraints(check, group);
      if (countCustomerRunnableRunsLastHour(recentRuns, ctx.tenantId, nowMs) >= groupPolicy.max_runs_per_hour) {
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

      const priorRun = lastRunForTargetGroup(recentRuns, ctx.tenantId, targetGroupId);
      if (priorRun && groupPolicy.min_seconds_between_runs > 0) {
        const elapsedMs = nowMs - new Date(priorRun.created_at).getTime();
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
      const runRecord = {
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
        created_at: now.toISOString(),
        created_by: ctx.userId,
        correlation: { nonce_hash: null, window_ms: 120000 },
        collection_deadline_at: new Date(nowMs + collectionDeadlineMs(check)).toISOString(),
      };
      let run = await validationEvidence.createTestRun(ctx, runRecord);

      await appendAudit(ctx, 'test_run.started', 'test_run', runId, { check_id: check.check_id });

      const probeMode = runtimeConfig.probeMode ?? 'simulation';
      let probe;
      let probeEvent = null;
      let probeJob = null;

      const inlineProbe = isOpsReadinessProbeKind(check) || probeMode !== 'signed-worker';

      if (!inlineProbe) {
        if (wouldExceedEventCap(run, 0, 1)) {
          await validationEvidence.updateTestRun(ctx, runId, {
            status: 'cancelled',
            completed_at: now.toISOString(),
          });
          return denySafeStart(
            ctx,
            'test_run.event_cap_denied',
            runId,
            { check_id: check.check_id, phase: 'probe_job' },
            'event_cap_exceeded',
            429,
          );
        }
        const builtJob = buildSignedProbeJobRecord({
          run,
          check,
          target,
          probeProfile: body.probe_profile,
          probeWorkerSecret: runtimeConfig.probeWorkerSecret,
          now,
          newId: () => newId('pjob'),
        });
        probeJob = await probeJobs.createProbeJob(ctx, builtJob);
        run = await validationEvidence.updateTestRun(ctx, runId, {
          correlation: { nonce_hash: probeJob.nonce_hash, window_ms: 120000 },
          awaiting_external_probe: true,
        });
        probe = { nonce: probeJob.nonce, nonce_hash: probeJob.nonce_hash, external_result: null };
        await appendAudit(ctx, 'probe_job.created', 'probe_job', probeJob.id, {
          test_run_id: runId,
          check_id: check.check_id,
        });
      } else {
        probe = isOpsReadinessProbeKind(check)
          ? executeOpsReadinessProbe(ctx, check, target, await gatherOpsReadinessData(ctx, check))
          : simulateProbeResult(check, target, body.probe_profile);
        if (wouldExceedEventCap(run, 0, 1)) {
          await validationEvidence.updateTestRun(ctx, runId, {
            status: 'cancelled',
            completed_at: now.toISOString(),
          });
          return denySafeStart(
            ctx,
            'test_run.event_cap_denied',
            runId,
            { check_id: check.check_id, phase: 'probe' },
            'event_cap_exceeded',
            429,
          );
        }
        probeEvent = await validationEvidence.appendEvent(ctx, {
          id: probe.event_id,
          tenant_id: ctx.tenantId,
          test_run_id: runId,
          target_id: target.id,
          check_id: check.check_id,
          source: probe.source,
          signal_type: probe.signal_type,
          timestamp: now.toISOString(),
          nonce_hash: probe.nonce_hash,
          metadata: { ...probe.metadata, external_result: probe.external_result },
        });
        await validationEvidence.appendEvidence(ctx, {
          id: newId('evidence'),
          test_run_id: runId,
          label: isOpsReadinessProbeKind(check)
            ? 'ops_readiness_probe_evidence'
            : 'probe_simulation_evidence',
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
          created_at: now.toISOString(),
        });
        run = await validationEvidence.updateTestRun(ctx, runId, {
          status: 'collecting',
          probe_external_result: probe.external_result,
          correlation: { nonce_hash: probe.nonce_hash, window_ms: 120000 },
        });
      }

      const boundAgents = onlineAgents.filter(
        (a) => a.target_group_id === targetGroupId || !a.target_group_id,
      );
      for (const agent of boundAgents) {
        await agentControl.createAgentJob({
          id: newId('job'),
          tenant_id: ctx.tenantId,
          agent_id: agent.id,
          test_run_id: runId,
          check_id: check.check_id,
          target_id: target.id,
          nonce_hash: probe.nonce_hash,
          nonce_for_agent: probe.nonce,
          type: 'observe_window',
          status: 'pending',
          created_at: now.toISOString(),
        });
      }

      incMetric('test_runs_started_total');

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
    },
    async finalizeTestRun(ctx, id, { force = false } = {}) {
      const run = await validationEvidence.getTestRun(ctx, id);
      if (!run) return null;
      if (run.status !== 'collecting') {
        return { error: 'not_collecting', status: 409 };
      }
      const events = await validationEvidence.listRunEvents(ctx, id, { limit: 1000 });
      if (!hasExternalProbeEvidence(run, events)) {
        return { error: 'external_probe_pending', status: 409 };
      }
      if (!force && !isCollectionWindowExpired(run, nowFn().getTime())) {
        return { error: 'observation_window_active', status: 409 };
      }
      const agents = await agentControl.listAgents(ctx);
      const verdict = await maybeFinalizeCollectingRun(ctx, run, agents, { force: true });
      if (!verdict) {
        return { error: 'cannot_finalize', status: 409 };
      }
      const updatedRun = await validationEvidence.getTestRun(ctx, id);
      const storedVerdict = await validationEvidence.getVerdictForRun(ctx, id);
      return { run: { ...updatedRun, verdict: storedVerdict ?? null }, verdict };
    },
    async cancelTestRun(ctx, id) {
      const run = await validationEvidence.getTestRun(ctx, id);
      if (!run) return null;
      if (!CANCELLABLE_STATUSES.has(run.status)) {
        await appendAudit(ctx, 'test_run.cancel_denied', 'test_run', id, { status: run.status });
        return { error: 'not_cancellable', status: 409 };
      }
      const completed_at = nowFn().toISOString();
      const updated = await validationEvidence.updateTestRun(ctx, id, {
        status: 'cancelled',
        completed_at,
      });
      await appendAudit(ctx, 'test_run.cancelled', 'test_run', id);
      return { run: updated };
    },
    async ingestObservation(ctx, agentId, body) {
      const agent = await agentControl.getAgentById(
        { tenantId: ctx.tenantId, userId: ctx.userId, role: ctx.role },
        agentId,
      );
      if (!agent) return { error: 'agent_not_found', status: 404 };

      const runCtx = { tenantId: agent.tenant_id, userId: ctx.userId, role: ctx.role };
      const run = await validationEvidence.getTestRun(runCtx, body.test_run_id);
      if (!run) return { error: 'run_not_found', status: 404 };

      if (body.tenant_id && body.tenant_id !== agent.tenant_id) {
        await appendAudit(runCtx, 'observation.tenant_rejected', 'agent', agentId, {
          attempted_tenant: body.tenant_id,
        });
        return { error: 'cross_tenant_injection', status: 403 };
      }

      if (!['running', 'collecting'].includes(run.status)) {
        await appendAudit(runCtx, 'observation.rejected_inactive_run', 'test_run', run.id, {
          status: run.status,
          agent_id: agentId,
        });
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

      const job = await agentControl.getAgentJobById({
        tenantId: run.tenant_id,
        agentId,
        jobId: agentJobId,
      });
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

      const priorEvents = await validationEvidence.listRunEvents(runCtx, run.id, { limit: 1000 });
      if (wouldExceedEventCap(run, priorEvents.length, 1)) {
        return denyEventCapForRun(ctx, run, { agent_id: agentId, phase: 'agent_observation' });
      }

      const nowIso = nowFn().toISOString();
      const observedJob = await agentControl.markAgentJobObserved(
        { tenantId: run.tenant_id, agentId, jobId: agentJobId },
        nowIso,
      );
      if (!observedJob) {
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

      const obsEvent = await validationEvidence.appendEvent(runCtx, {
        id: newId('event'),
        tenant_id: run.tenant_id,
        test_run_id: run.id,
        target_id: targetId,
        check_id: run.check_id,
        agent_id: agentId,
        source: 'agent',
        signal_type: 'agent_observation',
        timestamp: nowIso,
        nonce_hash: body.nonce_hash,
        metadata: redactObject(body.metadata ?? {}),
      });

      await appendAudit(runCtx, 'observation.ingested', 'test_run', run.id, { agent_id: agentId });

      const eventsAfter = [...priorEvents, obsEvent];
      if (run.awaiting_external_probe && !hasExternalProbeEvidence(run, eventsAfter)) {
        return { observation: obsEvent, run: { ...run, verdict: null } };
      }

      const agents = await agentControl.listAgents(runCtx);
      const verdict =
        (await finalizeVerdictIfReady(runCtx, run, agents, { agent })) ??
        (await validationEvidence.getVerdictForRun(runCtx, run.id));
      const updatedRun = await validationEvidence.getTestRun(runCtx, run.id);
      return {
        observation: obsEvent,
        run: { ...updatedRun, verdict: verdict ?? null },
      };
    },
    async maybeFinalizeRunAfterProbeIngest(ctxOrRunId, maybeRunId) {
      let ctx;
      let runId;
      if (typeof ctxOrRunId === 'string' || ctxOrRunId == null) {
        runId = ctxOrRunId;
        return null;
      }
      ctx = ctxOrRunId;
      runId = maybeRunId;
      if (!runId) return null;

      const run = await validationEvidence.getTestRun(ctx, runId);
      if (!run) return null;

      const events = await validationEvidence.listRunEvents(ctx, runId, { limit: 1000 });
      run.awaiting_external_probe = false;
      await validationEvidence.updateTestRun(ctx, runId, { awaiting_external_probe: false });

      if (!hasExternalProbeEvidence(run, events)) return null;

      const agents = await agentControl.listAgents(ctx);
      if (hasMatchingObservation(run, events)) {
        return finalizeVerdictIfReady(ctx, run, agents);
      }
      const ingestGroup = await coreCatalog.getTargetGroup(ctx, run.target_group_id);
      if (ingestGroup?.validation_mode === 'external_only') {
        if (run.status === 'running') {
          await validationEvidence.updateTestRun(ctx, runId, { status: 'collecting' });
          run.status = 'collecting';
        }
        return finalizeVerdictIfReady(ctx, run, agents, { agentObserved: false });
      }
      if (isCollectionWindowExpired(run, nowFn().getTime())) {
        return maybeFinalizeCollectingRun(ctx, run, agents);
      }
      if (run.status === 'running') {
        await validationEvidence.updateTestRun(ctx, runId, { status: 'collecting' });
        run.status = 'collecting';
      }
      return null;
    },
  };

  const evidence = {
    async listEvidence(ctx) {
      return validationEvidence.listEvidence(ctx);
    },
    async getEvidence(ctx, id) {
      return validationEvidence.getEvidence(ctx, id);
    },
  };

  const findings = {
    async listFindings(ctx, options = {}) {
      return validationEvidence.listFindings(ctx, options);
    },
    async getFinding(ctx, id) {
      return validationEvidence.getFinding(ctx, id);
    },
    async patchFinding(ctx, id, body) {
      const updated_at = nowFn().toISOString();
      const row = await validationEvidence.patchFinding(ctx, id, { ...body, updated_at });
      if (!row) return null;
      await audit.appendAuditEvent(
        {
          tenant_id: ctx.tenantId,
          actor_user_id: ctx.userId,
          actor_role: ctx.role,
          action: 'finding.updated',
          resource_type: 'finding',
          resource_id: id,
          metadata: redactObject(body),
        },
        { now: nowFn() },
      );
      return row;
    },
  };

  const events = {
    async ingestEvent(ctx, body) {
      const tenantId = ctx.tenantId;
      if (body.tenant_id && body.tenant_id !== tenantId) {
        await audit.appendAuditEvent(
          {
            tenant_id: tenantId,
            actor_user_id: ctx.userId,
            actor_role: ctx.role,
            action: 'event.ingest_rejected_cross_tenant',
            resource_type: 'event',
            resource_id: body.event_id ?? null,
            metadata: { attempted_tenant: body.tenant_id },
          },
          { now: nowFn() },
        );
        return { error: 'cross_tenant_mismatch', status: 403 };
      }

      const eventId = body.event_id;
      if (!eventId) return { error: 'missing_event_id', status: 400 };

      const existing = await validationEvidence.findEventByTenantEventId(ctx, eventId);
      if (existing) return { duplicate: true, event: existing };

      if (eventIngestContainsRawFields(body)) {
        return { error: 'packet_payload_forbidden', status: 400 };
      }

      const metadata = redactObject(body.metadata ?? {});
      const record = {
        id: newId('event'),
        event_id: eventId,
        tenant_id: tenantId,
        test_run_id: body.test_run_id ?? null,
        source: body.source ?? 'internal',
        signal_type: body.signal_type ?? 'generic',
        timestamp: body.timestamp ?? nowFn().toISOString(),
        nonce_hash: body.nonce_hash ?? null,
        metadata,
      };
      const appended = await validationEvidence.appendEventIdempotent(ctx, record);

      if (body.evidence) {
        await validationEvidence.appendEvidence(ctx, {
          id: body.evidence.evidence_id ?? newId('evidence'),
          test_run_id: body.test_run_id ?? null,
          label: body.evidence.label ?? 'ingested_metadata',
          metadata: redactObject(body.evidence.metadata ?? metadata),
          related_event_id: appended.id,
          created_at: nowFn().toISOString(),
        });
      }

      incMetric('events_ingested_total');
      await audit.appendAuditEvent(
        {
          tenant_id: tenantId,
          actor_user_id: ctx.userId,
          actor_role: ctx.role,
          action: 'event.ingested',
          resource_type: 'event',
          resource_id: eventId,
        },
        { now: nowFn() },
      );
      return { event: appended };
    },
  };

  return { testRuns, evidence, findings, events };
}
