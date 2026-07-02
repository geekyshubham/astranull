import {
  REQUIRED_ARTIFACT_TYPES,
  authorizationPackComplete,
  distinctSocApprovalCount,
} from '../../lib/highScalePolicy.mjs';

/** Evidence older than this window earns no freshness credit. */
const RECENT_EVIDENCE_WINDOW_DAYS = 30;
const RECENT_EVIDENCE_WINDOW_MS = RECENT_EVIDENCE_WINDOW_DAYS * 24 * 60 * 60 * 1000;

const WEIGHT_COVERAGE = 40;
const WEIGHT_AGENT_PLACEMENT = 25;
const WEIGHT_VERDICTS = 25;
const WEIGHT_EVIDENCE_FRESHNESS = 15;
const WEIGHT_SOC_GOVERNANCE = 10;

const RUN_EVIDENCE_TIMESTAMP_FIELDS = [
  'verdict_at',
  'completed_at',
  'updated_at',
  'created_at',
];

const AGENT_OBSERVATION_SIGNALS = new Set(['agent_observation', 'agent_no_observation']);
const PROVEN_OBSERVATION_SIGNAL = 'agent_observation';
const GOVERNED_HS_STATES = new Set(['scheduled', 'running', 'stopped', 'closed']);

const TEST_RUN_LIST_LIMIT = 500;
const EVIDENCE_LIST_LIMIT = 500;
const RUN_EVENTS_LIMIT = 1000;
const RUN_EVENT_FETCH_RUN_LIMIT = 30;
const RECENT_RUNS_LIMIT = 5;

/** @type {readonly string[]} */
export const STATE_CORE_CATALOG_REPOSITORY_METHODS = Object.freeze(['listTargetGroups']);

/** @type {readonly string[]} */
export const STATE_AGENT_CONTROL_REPOSITORY_METHODS = Object.freeze(['listAgents']);

/** @type {readonly string[]} */
export const STATE_VALIDATION_EVIDENCE_REPOSITORY_METHODS = Object.freeze([
  'listTestRuns',
  'getVerdictForRun',
  'listRunEvents',
  'listEvidence',
  'listFindings',
]);

/** @type {readonly string[]} */
export const STATE_HIGH_SCALE_REPOSITORY_METHODS = Object.freeze(['listHighScaleRequests']);

/** @type {readonly string[]} */
export const STATE_KILL_SWITCH_REPOSITORY_METHODS = Object.freeze(['getKillSwitchRecord']);

/** @type {readonly string[]} */
export const POSTGRES_STATE_SERVICE_METHODS = Object.freeze(['getState']);

function parseTs(value) {
  if (!value) return null;
  const ms = new Date(value).getTime();
  return Number.isFinite(ms) ? ms : null;
}

function isRecentMs(ms, nowMs) {
  if (ms == null || !Number.isFinite(ms)) return false;
  if (ms > nowMs) return false;
  return nowMs - ms <= RECENT_EVIDENCE_WINDOW_MS;
}

function runStatusEligible(run) {
  return run.status === 'completed' || run.status === 'verdicted';
}

function assertStateRepositories(repositories) {
  const coreCatalog = repositories?.coreCatalog;
  if (!coreCatalog || typeof coreCatalog !== 'object') {
    throw new Error('Postgres state service adapter requires repositories.coreCatalog.');
  }
  for (const method of STATE_CORE_CATALOG_REPOSITORY_METHODS) {
    if (typeof coreCatalog[method] !== 'function') {
      throw new Error(`Postgres state service adapter requires coreCatalog.${method}().`);
    }
  }

  const agentControl = repositories?.agentControl;
  if (!agentControl || typeof agentControl !== 'object') {
    throw new Error('Postgres state service adapter requires repositories.agentControl.');
  }
  for (const method of STATE_AGENT_CONTROL_REPOSITORY_METHODS) {
    if (typeof agentControl[method] !== 'function') {
      throw new Error(`Postgres state service adapter requires agentControl.${method}().`);
    }
  }

  const validationEvidence = repositories?.validationEvidence;
  if (!validationEvidence || typeof validationEvidence !== 'object') {
    throw new Error('Postgres state service adapter requires repositories.validationEvidence.');
  }
  for (const method of STATE_VALIDATION_EVIDENCE_REPOSITORY_METHODS) {
    if (typeof validationEvidence[method] !== 'function') {
      throw new Error(`Postgres state service adapter requires validationEvidence.${method}().`);
    }
  }

  const highScale = repositories?.highScale;
  if (!highScale || typeof highScale !== 'object') {
    throw new Error('Postgres state service adapter requires repositories.highScale.');
  }
  for (const method of STATE_HIGH_SCALE_REPOSITORY_METHODS) {
    if (typeof highScale[method] !== 'function') {
      throw new Error(`Postgres state service adapter requires highScale.${method}().`);
    }
  }

  const killSwitch = repositories?.killSwitch;
  if (!killSwitch || typeof killSwitch !== 'object') {
    throw new Error('Postgres state service adapter requires repositories.killSwitch.');
  }
  for (const method of STATE_KILL_SWITCH_REPOSITORY_METHODS) {
    if (typeof killSwitch[method] !== 'function') {
      throw new Error(`Postgres state service adapter requires killSwitch.${method}().`);
    }
  }
}

function runHasEvidenceBacking(run, verdict, events, vaultItems) {
  if (verdict) return true;
  if (events.length > 0) return true;
  if (vaultItems.length > 0) return true;
  return false;
}

function collectEvidenceTimestamps(run, verdict, events, vaultItems) {
  const stamps = [];
  for (const field of RUN_EVIDENCE_TIMESTAMP_FIELDS) {
    const ms = parseTs(run[field]);
    if (ms != null) stamps.push(ms);
  }
  if (verdict) {
    const vMs = parseTs(verdict.created_at);
    if (vMs != null) stamps.push(vMs);
  }
  for (const ev of events) {
    const eMs = parseTs(ev.timestamp ?? ev.created_at);
    if (eMs != null) stamps.push(eMs);
  }
  for (const rec of vaultItems) {
    const rMs = parseTs(rec.created_at);
    if (rMs != null) stamps.push(rMs);
  }
  return stamps;
}

function evidenceFreshnessForRun(run, verdict, events, vaultItems, nowMs) {
  if (!runStatusEligible(run) || !runHasEvidenceBacking(run, verdict, events, vaultItems)) {
    return { recent: false, stale: false, backed: false };
  }
  const stamps = collectEvidenceTimestamps(run, verdict, events, vaultItems);
  if (stamps.length === 0) {
    return { recent: false, stale: false, backed: true };
  }
  const hasRecent = stamps.some((ms) => isRecentMs(ms, nowMs));
  return { recent: hasRecent, stale: !hasRecent, backed: true };
}

function agentsForTenant(agents, tenantId) {
  return agents.filter((a) => a.tenant_id === tenantId && a.status !== 'revoked');
}

function boundAgentsForGroup(agents, targetGroupId) {
  return agents.filter((a) => a.target_group_id === targetGroupId);
}

function onlineAgentIds(agentList) {
  return agentList.filter((a) => a.status === 'online').map((a) => a.id);
}

function runIdsForGroup(runs, tenantId, targetGroupId) {
  return new Set(
    runs
      .filter((r) => r.tenant_id === tenantId && r.target_group_id === targetGroupId)
      .map((r) => r.id),
  );
}

function countRecentObservationsForGroup(
  eventsByRun,
  runs,
  tenantId,
  targetGroupId,
  nowMs,
  signalType = null,
) {
  const runIds = runIdsForGroup(runs, tenantId, targetGroupId);
  if (runIds.size === 0) return 0;
  let count = 0;
  for (const runId of runIds) {
    for (const e of eventsByRun.get(runId) ?? []) {
      if (e.tenant_id !== tenantId) continue;
      const sig = e.signal_type;
      if (signalType) {
        if (sig === signalType && isRecentMs(parseTs(e.timestamp ?? e.created_at), nowMs)) count += 1;
      } else if (
        AGENT_OBSERVATION_SIGNALS.has(sig)
        && isRecentMs(parseTs(e.timestamp ?? e.created_at), nowMs)
      ) {
        count += 1;
      }
    }
  }
  return count;
}

function hasRecentProvenObservation(eventsByRun, runs, tenantId, targetGroupId, nowMs) {
  return (
    countRecentObservationsForGroup(
      eventsByRun,
      runs,
      tenantId,
      targetGroupId,
      nowMs,
      PROVEN_OBSERVATION_SIGNAL,
    ) > 0
  );
}

function diagnoseGroup(group, agents, unboundOnlineIds, eventsByRun, runs, tenantId, nowMs) {
  const bound = boundAgentsForGroup(agents, group.id);
  const boundIds = bound.map((a) => a.id);
  const onlineBoundIds = onlineAgentIds(bound);
  const recentObservationCount = countRecentObservationsForGroup(
    eventsByRun,
    runs,
    tenantId,
    group.id,
    nowMs,
  );
  const warnings = [];
  let status;

  if (bound.length === 0) {
    status = 'missing_agent';
    warnings.push('no_bound_agent');
    if (unboundOnlineIds.length > 0) warnings.push('unbound_agent_only');
  } else if (onlineBoundIds.length === 0) {
    status = 'misplaced_risk';
    warnings.push('no_online_bound_agent');
  } else if (!hasRecentProvenObservation(eventsByRun, runs, tenantId, group.id, nowMs)) {
    status = 'needs_baseline';
    warnings.push('no_recent_observation');
  } else {
    status = 'proven';
  }

  return {
    target_group_id: group.id,
    target_group_name: group.name ?? group.id,
    bound_agent_ids: boundIds,
    online_bound_agent_ids: onlineBoundIds,
    recent_observation_count: recentObservationCount,
    status,
    warnings,
  };
}

function summarizePlacementDiagnostics(diagnostics) {
  const groups = diagnostics?.groups ?? [];
  const counts = {
    proven: 0,
    needs_baseline: 0,
    missing_agent: 0,
    misplaced_risk: 0,
  };
  for (const g of groups) {
    if (counts[g.status] !== undefined) counts[g.status] += 1;
  }
  const total = groups.length;
  const summary =
    total === 0
      ? 'No declared target groups for placement diagnostics.'
      : `Placement diagnostics: ${counts.proven} proven, ${counts.needs_baseline} need baseline, ${counts.missing_agent} missing agent, ${counts.misplaced_risk} misplaced risk (of ${total} group(s)).`;

  return {
    total_groups: total,
    proven: counts.proven,
    needs_baseline: counts.needs_baseline,
    missing_agent: counts.missing_agent,
    misplaced_risk: counts.misplaced_risk,
    unbound_online_agent_count: (diagnostics?.unbound_online_agent_ids ?? []).length,
    summary,
  };
}

function placementScoreFromDiagnostics(diagnostics, maxScore) {
  const summary = summarizePlacementDiagnostics(diagnostics);
  if (summary.total_groups === 0) return null;
  const ratio = summary.proven / summary.total_groups;
  return Math.round(Math.min(maxScore, ratio * maxScore));
}

function hasAgentObservationEvidence(eventsByRun, tenantId) {
  for (const events of eventsByRun.values()) {
    for (const e of events) {
      if (e.tenant_id === tenantId && AGENT_OBSERVATION_SIGNALS.has(e.signal_type)) {
        return true;
      }
    }
  }
  return false;
}

function computeReadinessSummary({
  tenantId,
  groups,
  agents,
  runs,
  findings,
  verdictByRun,
  eventsByRun,
  evidenceByRun,
  highScaleRequests,
  killSwitch,
  nowMs,
}) {
  const onlineAgents = agents.filter((a) => a.status === 'online');
  const openFindings = findings.filter((f) => f.status === 'open');
  const factors = [];

  const declaredGroupIds = new Set(groups.map((g) => g.id));
  const coveredGroupIds = new Set();
  let staleBackedRuns = 0;
  let recentBackedRuns = 0;

  for (const run of runs) {
    const verdict = verdictByRun.get(run.id) ?? null;
    const events = eventsByRun.get(run.id) ?? [];
    const vaultItems = evidenceByRun.get(run.id) ?? [];
    const freshness = evidenceFreshnessForRun(run, verdict, events, vaultItems, nowMs);
    if (!freshness.backed) continue;
    if (
      freshness.recent
      && run.target_group_id
      && declaredGroupIds.has(run.target_group_id)
    ) {
      coveredGroupIds.add(run.target_group_id);
      recentBackedRuns += 1;
    } else if (freshness.stale) {
      staleBackedRuns += 1;
    }
  }

  const totalGroups = groups.length;
  const coveredCount = coveredGroupIds.size;
  const coverageRatio = totalGroups ? coveredCount / totalGroups : 0;
  const coverageScore = Math.round(Math.min(WEIGHT_COVERAGE, coverageRatio * WEIGHT_COVERAGE));

  let coverageDetail;
  if (!totalGroups) {
    coverageDetail = 'No declared target groups.';
  } else if (coveredCount === 0) {
    if (staleBackedRuns > 0) {
      coverageDetail = `0 of ${totalGroups} target group(s) covered by recent evidence-backed validations; stale evidence exists on ${staleBackedRuns} run(s).`;
    } else {
      coverageDetail = `0 of ${totalGroups} target group(s) have evidence-backed validations in the last ${RECENT_EVIDENCE_WINDOW_DAYS} days.`;
    }
  } else {
    const missing = totalGroups - coveredCount;
    coverageDetail = `${coveredCount} of ${totalGroups} target group(s) have recent evidence-backed validations.`;
    if (missing > 0) {
      coverageDetail += ` ${missing} group(s) lack recent validation evidence.`;
    }
  }

  factors.push({
    key: 'coverage',
    label: 'Validation coverage',
    score: coverageScore,
    detail: coverageDetail,
  });

  const unboundOnline = agents.filter((a) => a.status === 'online' && a.target_group_id == null);
  const unboundOnlineIds = unboundOnline.map((a) => a.id);
  const groupDiagnostics = groups.map((g) =>
    diagnoseGroup(g, agents, unboundOnlineIds, eventsByRun, runs, tenantId, nowMs),
  );
  const placementDiagnostics = {
    tenant_id: tenantId,
    computed_at: new Date(nowMs).toISOString(),
    unbound_online_agent_ids: unboundOnlineIds,
    groups: groupDiagnostics,
  };
  const placementSummary = summarizePlacementDiagnostics(placementDiagnostics);
  const pathObservation = hasAgentObservationEvidence(eventsByRun, tenantId);

  let placementScore = 0;
  let placementDetail;
  if (!agents.length) {
    placementDetail = 'No agents registered; internal path observation cannot be evidenced.';
    if (totalGroups > 0) placementDetail += ` ${placementSummary.summary}`;
  } else if (!onlineAgents.length) {
    placementDetail = `0 online of ${agents.length} registered agent(s); agents are not reporting healthy.`;
    if (!pathObservation) placementDetail += ' No agent observation evidence recorded yet.';
    if (totalGroups > 0) placementDetail += ` ${placementSummary.summary}`;
  } else if (totalGroups > 0) {
    placementScore = placementScoreFromDiagnostics(placementDiagnostics, WEIGHT_AGENT_PLACEMENT) ?? 0;
    placementDetail = `${onlineAgents.length} online of ${agents.length} registered agent(s). ${placementSummary.summary}`;
    if (placementSummary.unbound_online_agent_count > 0 && placementSummary.proven === 0) {
      placementDetail +=
        ' Unbound online agents do not prove placement for declared target groups.';
    } else if (!pathObservation && placementSummary.proven === 0) {
      placementDetail +=
        ' Online agents registered; path coverage is not yet proven by agent observation evidence.';
    }
  } else {
    placementScore = Math.round(
      Math.min(WEIGHT_AGENT_PLACEMENT, (onlineAgents.length / agents.length) * WEIGHT_AGENT_PLACEMENT),
    );
    placementDetail = `${onlineAgents.length} online of ${agents.length} registered agent(s).`;
    if (pathObservation) {
      placementDetail += ' Agent observation evidence exists for validation runs.';
    } else {
      placementDetail +=
        ' Online agents registered; path coverage is not yet proven by agent observation evidence.';
    }
  }

  factors.push({
    key: 'agent_placement',
    label: 'Agent placement & health',
    score: placementScore,
    detail: placementDetail,
    placement_diagnostics: placementSummary,
  });

  const verdicts = [...verdictByRun.values()];
  const recentVerdicts = verdicts.filter((v) => isRecentMs(parseTs(v.created_at), nowMs));
  const staleVerdicts = verdicts.filter((v) => {
    const ms = parseTs(v.created_at);
    return ms != null && ms <= nowMs && nowMs - ms > RECENT_EVIDENCE_WINDOW_MS;
  });

  let verdictScore = 0;
  let verdictDetail;
  if (verdicts.length === 0) {
    verdictDetail =
      'No verdict evidence recorded; absence of findings is not proof of readiness until verdict evidence exists.';
  } else if (recentVerdicts.length === 0) {
    verdictDetail = `${openFindings.length} open finding(s); ${verdicts.length} verdict(s) recorded (0 recent`;
    if (staleVerdicts.length) verdictDetail += `, ${staleVerdicts.length} stale`;
    verdictDetail +=
      '). Stale or missing recent verdict evidence does not support full posture credit.';
  } else {
    const penalty = Math.min(WEIGHT_VERDICTS, openFindings.length * 10);
    verdictScore = Math.max(0, WEIGHT_VERDICTS - penalty);
    verdictDetail = `${openFindings.length} open finding(s); ${verdicts.length} verdict(s) recorded (${recentVerdicts.length} recent`;
    if (staleVerdicts.length) verdictDetail += `, ${staleVerdicts.length} stale`;
    verdictDetail += ').';
  }

  factors.push({
    key: 'verdicts',
    label: 'Open findings impact',
    score: Math.round(verdictScore),
    detail: verdictDetail,
  });

  let freshnessScore = 0;
  let freshnessDetail;
  if (recentBackedRuns > 0 || coveredCount > 0) {
    freshnessScore = WEIGHT_EVIDENCE_FRESHNESS;
    freshnessDetail = `Recent evidence-backed validation within ${RECENT_EVIDENCE_WINDOW_DAYS} days (${recentBackedRuns} run(s), ${coveredCount} target group(s)).`;
  } else if (staleBackedRuns > 0) {
    freshnessDetail = `Evidence exists but is stale (older than ${RECENT_EVIDENCE_WINDOW_DAYS} days); no freshness credit awarded.`;
  } else {
    freshnessDetail = 'No evidence-backed validations yet.';
  }

  factors.push({
    key: 'evidence_freshness',
    label: 'Evidence freshness',
    score: freshnessScore,
    detail: freshnessDetail,
  });

  const socGovernance = scoreSocGovernance({ highScaleRequests, killSwitch });
  factors.push({
    key: 'soc_readiness',
    label: 'SOC governance posture',
    score: socGovernance.score,
    detail: socGovernance.detail,
  });

  const score = Math.min(100, Math.round(factors.reduce((s, f) => s + f.score, 0)));
  return {
    score,
    factors,
    updated_at: new Date(nowMs).toISOString(),
    persistence: 'postgres',
  };
}

function indexEvidenceByRun(evidenceItems) {
  /** @type {Map<string, object[]>} */
  const map = new Map();
  for (const item of evidenceItems) {
    const runId = item.test_run_id;
    if (!runId) continue;
    if (!map.has(runId)) map.set(runId, []);
    map.get(runId).push(item);
  }
  return map;
}

function sortRunsNewestFirst(runs) {
  return [...runs].sort((a, b) => (parseTs(b.created_at) ?? 0) - (parseTs(a.created_at) ?? 0));
}

function acceptedArtifactTypes(req) {
  return new Set(
    (req.artifacts ?? [])
      .filter((artifact) => artifact?.status === 'accepted')
      .map((artifact) => artifact.type),
  );
}

function pendingHighScaleGates(requests) {
  const gates = [];
  for (const req of requests) {
    if (['closed', 'rejected'].includes(req.state)) continue;
    const missing = [];
    if (!authorizationPackComplete(req)) {
      const accepted = acceptedArtifactTypes(req);
      const missingTypes = REQUIRED_ARTIFACT_TYPES.filter((type) => !accepted.has(type));
      if (missingTypes.length > 0) {
        missing.push(`missing accepted artifacts: ${missingTypes.join(', ')}`);
      }
    }
    const approvals = distinctSocApprovalCount(req);
    if (approvals < 2) {
      missing.push(`SOC approvals ${approvals}/2`);
    }
    if (missing.length > 0) {
      gates.push({ requestId: req.id, state: req.state, missing });
    }
  }
  return gates;
}

function killSwitchHasEvidence(killSwitch) {
  return Boolean(killSwitch?.updated_at);
}

function highScaleGovernanceEvidence(requests) {
  const hits = [];
  for (const req of requests) {
    const approvals = distinctSocApprovalCount(req);
    if (authorizationPackComplete(req) && approvals >= 2) {
      hits.push({
        requestId: req.id,
        detail: `Request ${req.id}: authorization pack accepted with ${approvals} SOC approver(s).`,
      });
    }
    if (GOVERNED_HS_STATES.has(req.state) && (req.audit_trail?.length ?? 0) > 0) {
      hits.push({
        requestId: req.id,
        detail: `Request ${req.id}: governed lifecycle state "${req.state}" with audit trail.`,
      });
    }
  }
  return hits;
}

function scoreSocGovernance({ highScaleRequests, killSwitch }) {
  const pendingGates = pendingHighScaleGates(highScaleRequests);
  const hsHits = highScaleGovernanceEvidence(highScaleRequests);
  const hasKillSwitchEvidence = killSwitchHasEvidence(killSwitch);

  if (!hasKillSwitchEvidence && hsHits.length === 0) {
    let detail = 'No high-scale governance evidence recorded yet.';
    if (pendingGates.length > 0) {
      const parts = pendingGates.map(
        (gate) => `${gate.requestId} (${gate.state}): ${gate.missing.join('; ')}`,
      );
      detail = `Pending high-scale workflow gates remain: ${parts.join(' | ')}.`;
    }
    return { score: 0, detail };
  }

  const details = [];
  if (hasKillSwitchEvidence) details.push('Kill switch state recorded for tenant.');
  for (const hit of hsHits) details.push(hit.detail);
  if (pendingGates.length > 0) {
    const parts = pendingGates.map(
      (gate) => `${gate.requestId}: ${gate.missing.join('; ')}`,
    );
    details.push(`Other request(s) still pending gates: ${parts.join(' | ')}.`);
  }

  return { score: WEIGHT_SOC_GOVERNANCE, detail: details.join(' ') };
}

function sanitizeKillSwitchRecord(record, tenantId) {
  return {
    tenant_id: record?.tenant_id ?? tenantId,
    active: Boolean(record?.active),
    reason: record?.reason ?? null,
    updated_at: record?.updated_at ?? null,
    updated_by: record?.updated_by ?? null,
  };
}

/**
 * @param {{
 *   coreCatalog?: Record<string, unknown>,
 *   agentControl?: Record<string, unknown>,
 *   validationEvidence?: Record<string, unknown>,
 *   highScale?: Record<string, unknown>,
 *   killSwitch?: Record<string, unknown>,
 * }} repositories
 * @param {{ now?: () => Date }} [options]
 */
export function createPostgresStateServices(repositories, options = {}) {
  assertStateRepositories(repositories);
  const coreCatalog = repositories.coreCatalog;
  const agentControl = repositories.agentControl;
  const validationEvidence = repositories.validationEvidence;
  const highScale = repositories.highScale;
  const killSwitch = repositories.killSwitch;
  const nowFn = options.now ?? (() => new Date());

  return {
    async getState(ctx) {
      const tenantId = ctx.tenantId;
      const nowMs = nowFn().getTime();

      const [
        groups,
        agents,
        runs,
        evidenceItems,
        findings,
        highScaleRequests,
        killSwitchRecord,
      ] = await Promise.all([
        coreCatalog.listTargetGroups(ctx),
        agentControl.listAgents(ctx),
        validationEvidence.listTestRuns(ctx, { limit: TEST_RUN_LIST_LIMIT }),
        validationEvidence.listEvidence(ctx, { limit: EVIDENCE_LIST_LIMIT }),
        validationEvidence.listFindings(ctx),
        highScale.listHighScaleRequests(ctx),
        killSwitch.getKillSwitchRecord(ctx),
      ]);

      const tenantAgents = agentsForTenant(agents, tenantId);
      const evidenceByRun = indexEvidenceByRun(evidenceItems);
      const sortedRuns = sortRunsNewestFirst(runs);

      const eventFetchRuns = sortedRuns.slice(0, RUN_EVENT_FETCH_RUN_LIMIT);
      /** @type {Map<string, object[]>} */
      const eventsByRun = new Map();
      await Promise.all(
        eventFetchRuns.map(async (run) => {
          const events = await validationEvidence.listRunEvents(ctx, run.id, {
            limit: RUN_EVENTS_LIMIT,
          });
          eventsByRun.set(run.id, events);
        }),
      );

      /** @type {Map<string, object>} */
      const verdictByRun = new Map();
      await Promise.all(
        runs.map(async (run) => {
          if (!runStatusEligible(run)) return;
          const verdict = await validationEvidence.getVerdictForRun(ctx, run.id);
          if (verdict) verdictByRun.set(run.id, verdict);
        }),
      );

      const readiness = computeReadinessSummary({
        tenantId,
        groups,
        agents: tenantAgents,
        runs,
        findings,
        verdictByRun,
        eventsByRun,
        evidenceByRun,
        highScaleRequests,
        killSwitch: killSwitchRecord,
        nowMs,
      });

      return {
        tenant_id: tenantId,
        readiness,
        target_groups: groups.length,
        agents_online: tenantAgents.filter((a) => a.status === 'online').length,
        recent_runs: sortedRuns.slice(0, RECENT_RUNS_LIMIT),
        open_findings: findings.filter((f) => f.status === 'open').length,
        high_scale_requests: highScaleRequests.length,
        high_scale_status: 'available',
        kill_switch: sanitizeKillSwitchRecord(killSwitchRecord, tenantId),
      };
    },
  };
}
