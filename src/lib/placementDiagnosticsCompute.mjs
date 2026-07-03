/** Pure metadata-only placement diagnostics computation (no store/DB imports). */

/** Aligns with readiness evidence freshness window (metadata-only placement checks). */
export const RECENT_EVIDENCE_WINDOW_MS = 30 * 24 * 60 * 60 * 1000;

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

function agentsForTenant(agents, tenantId) {
  return agents.filter((a) => a.tenant_id === tenantId && a.status !== 'revoked');
}

function boundAgentsForGroup(agents, targetGroupId) {
  return agents.filter((a) => a.target_group_id === targetGroupId);
}

function onlineAgentIds(agents) {
  return agents.filter((a) => a.status === 'online').map((a) => a.id);
}

function runIdsForGroup(runs, tenantId, targetGroupId) {
  return new Set(
    runs
      .filter((r) => r.tenant_id === tenantId && r.target_group_id === targetGroupId)
      .map((r) => r.id),
  );
}

function countRecentObservationsForGroup(
  events,
  runs,
  tenantId,
  targetGroupId,
  nowMs,
  signalType = null,
) {
  const runIds = runIdsForGroup(runs, tenantId, targetGroupId);
  if (runIds.size === 0) return 0;
  return events.filter((e) => {
    if (e.tenant_id !== tenantId || !runIds.has(e.test_run_id)) return false;
    const sig = e.signal_type;
    if (signalType) return sig === signalType && isRecentMs(parseTs(e.timestamp ?? e.created_at), nowMs);
    if (!AGENT_OBSERVATION_SIGNALS.has(sig)) return false;
    return isRecentMs(parseTs(e.timestamp ?? e.created_at), nowMs);
  }).length;
}

function hasRecentProvenObservation(events, runs, tenantId, targetGroupId, nowMs) {
  return (
    countRecentObservationsForGroup(
      events,
      runs,
      tenantId,
      targetGroupId,
      nowMs,
      PROVEN_OBSERVATION_SIGNAL,
    ) > 0
  );
}

function diagnoseGroup(group, agents, unboundOnlineIds, events, runs, tenantId, nowMs) {
  const bound = boundAgentsForGroup(agents, group.id);
  const boundIds = bound.map((a) => a.id);
  const onlineBoundIds = onlineAgentIds(bound);
  const recentObservationCount = countRecentObservationsForGroup(
    events,
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
    if (unboundOnlineIds.length > 0) {
      warnings.push('unbound_agent_only');
    }
  } else if (onlineBoundIds.length === 0) {
    status = 'misplaced_risk';
    warnings.push('no_online_bound_agent');
  } else if (!hasRecentProvenObservation(events, runs, tenantId, group.id, nowMs)) {
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

/**
 * @param {{
 *   tenantId: string,
 *   groups: Array<{ id: string, tenant_id?: string, name?: string }>,
 *   agents: Array<{ id: string, tenant_id: string, status: string, target_group_id?: string | null }>,
 *   runs: Array<{ id: string, tenant_id: string, target_group_id?: string | null }>,
 *   events: Array<{ tenant_id: string, test_run_id: string, signal_type: string, timestamp?: string, created_at?: string }>,
 *   nowMs?: number,
 * }} input
 */
export function computePlacementDiagnosticsFromData(input) {
  const tenantId = input.tenantId;
  const nowMs = input.nowMs ?? Date.now();
  const groups = (input.groups ?? []).filter((g) => g.tenant_id == null || g.tenant_id === tenantId);
  const agents = agentsForTenant(input.agents ?? [], tenantId);
  const runs = (input.runs ?? []).filter((r) => r.tenant_id === tenantId);
  const events = input.events ?? [];
  const unboundOnline = agents.filter((a) => a.status === 'online' && a.target_group_id == null);
  const unboundOnlineIds = unboundOnline.map((a) => a.id);

  const groupDiagnostics = groups.map((g) =>
    diagnoseGroup(g, agents, unboundOnlineIds, events, runs, tenantId, nowMs),
  );

  return {
    tenant_id: tenantId,
    computed_at: new Date(nowMs).toISOString(),
    unbound_online_agent_ids: unboundOnlineIds,
    groups: groupDiagnostics,
  };
}