import { getStore } from '../store.mjs';
import {
  computePlacementConfidence,
  resolveObservationMode,
} from '../lib/placementConfidence.mjs';

export { computePlacementConfidence, resolveObservationMode };

/** Aligns with readiness evidence freshness window (metadata-only placement checks). */
const RECENT_EVIDENCE_WINDOW_MS = 30 * 24 * 60 * 60 * 1000;

const AGENT_OBSERVATION_SIGNALS = new Set(['agent_observation', 'agent_no_observation']);
const PROVEN_OBSERVATION_SIGNAL = 'agent_observation';

function parseTs(value) {
  if (!value) return null;
  const ms = new Date(value).getTime();
  return Number.isFinite(ms) ? ms : null;
}

function isRecentMs(ms, nowMs = Date.now()) {
  if (ms == null || !Number.isFinite(ms)) return false;
  if (ms > nowMs) return false;
  return nowMs - ms <= RECENT_EVIDENCE_WINDOW_MS;
}

function agentsForTenant(store, tenantId) {
  return store.agents.filter((a) => a.tenant_id === tenantId && a.status !== 'revoked');
}

function boundAgentsForGroup(agents, targetGroupId) {
  return agents.filter((a) => a.target_group_id === targetGroupId);
}

function onlineAgentIds(agents) {
  return agents.filter((a) => a.status === 'online').map((a) => a.id);
}

function runIdsForGroup(store, tenantId, targetGroupId) {
  return new Set(
    store.testRuns
      .filter((r) => r.tenant_id === tenantId && r.target_group_id === targetGroupId)
      .map((r) => r.id),
  );
}

function countRecentObservationsForGroup(store, tenantId, targetGroupId, nowMs, signalType = null) {
  const runIds = runIdsForGroup(store, tenantId, targetGroupId);
  if (runIds.size === 0) return 0;
  return store.events.filter((e) => {
    if (e.tenant_id !== tenantId || !runIds.has(e.test_run_id)) return false;
    const sig = e.signal_type;
    if (signalType) return sig === signalType && isRecentMs(parseTs(e.timestamp ?? e.created_at), nowMs);
    if (!AGENT_OBSERVATION_SIGNALS.has(sig)) return false;
    return isRecentMs(parseTs(e.timestamp ?? e.created_at), nowMs);
  }).length;
}

function hasRecentProvenObservation(store, tenantId, targetGroupId, nowMs) {
  return countRecentObservationsForGroup(store, tenantId, targetGroupId, nowMs, PROVEN_OBSERVATION_SIGNAL) > 0;
}

function diagnoseGroup(store, tenantId, group, agents, unboundOnlineIds, nowMs) {
  const bound = boundAgentsForGroup(agents, group.id);
  const boundIds = bound.map((a) => a.id);
  const onlineBoundIds = onlineAgentIds(bound);
  const recentObservationCount = countRecentObservationsForGroup(store, tenantId, group.id, nowMs);
  const warnings = [];

  let status;

  if (bound.length === 0) {
    status = 'missing_agent';
    warnings.push('no_bound_agent');
    if (unboundOnlineIds.length > 0) {
      warnings.push('unbound_agent_only');
    }
  } else if (onlineBoundIds.length === 0) {
    status = 'misplaced_risk';
    warnings.push('no_online_bound_agent');
  } else if (!hasRecentProvenObservation(store, tenantId, group.id, nowMs)) {
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

export function computePlacementDiagnostics(tenantId, nowMs = Date.now()) {
  const store = getStore();
  const groups = store.targetGroups.filter((g) => g.tenant_id === tenantId);
  const agents = agentsForTenant(store, tenantId);
  const unboundOnline = agents.filter((a) => a.status === 'online' && a.target_group_id == null);
  const unboundOnlineIds = unboundOnline.map((a) => a.id);

  const groupDiagnostics = groups.map((g) =>
    diagnoseGroup(store, tenantId, g, agents, unboundOnlineIds, nowMs),
  );

  return {
    tenant_id: tenantId,
    computed_at: new Date(nowMs).toISOString(),
    unbound_online_agent_ids: unboundOnlineIds,
    groups: groupDiagnostics,
  };
}

export function summarizePlacementDiagnostics(diagnostics) {
  const groups = diagnostics?.groups ?? [];
  const counts = {
    proven: 0,
    needs_baseline: 0,
    missing_agent: 0,
    misplaced_risk: 0,
  };
  for (const g of groups) {
    if (counts[g.status] !== undefined) {
      counts[g.status] += 1;
    }
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

export function placementScoreFromDiagnostics(diagnostics, maxScore) {
  const summary = summarizePlacementDiagnostics(diagnostics);
  if (summary.total_groups === 0) {
    return null;
  }
  const ratio = summary.proven / summary.total_groups;
  return Math.round(Math.min(maxScore, ratio * maxScore));
}

