const DIRECT_OBSERVATION_MODES = new Set(['host', 'sidecar', 'canary']);
const BROAD_OBSERVATION_MODES = new Set(['packet_mirror', 'log_tail']);

function normalizeModeToken(raw) {
  if (raw == null || raw === '') return null;
  const s = String(raw).toLowerCase().trim();
  if (s.includes('canary')) return 'canary';
  if (s.includes('sidecar')) return 'sidecar';
  if (s.includes('host') || s === 'origin') return 'host';
  if (s.includes('mirror') || s.includes('tap') || s === 'packet') return 'packet_mirror';
  if (s.includes('log')) return 'log_tail';
  if (s === 'unbound') return 'unbound';
  if (DIRECT_OBSERVATION_MODES.has(s) || BROAD_OBSERVATION_MODES.has(s)) return s;
  return 'unknown';
}

function observationModesFromCapabilities(capabilities) {
  const caps = new Set(capabilities ?? []);
  const modes = new Set();
  if (caps.has('host')) modes.add('host');
  if (caps.has('sidecar')) modes.add('sidecar');
  if (caps.has('canary')) modes.add('canary');
  if (caps.has('packet') || caps.has('mirror')) modes.add('packet_mirror');
  if (caps.has('log_tail') || caps.has('log')) modes.add('log_tail');
  return [...modes];
}

function inferObservationModeFromCapabilities(capabilities) {
  const modes = observationModesFromCapabilities(capabilities);
  if (modes.length === 1) return modes[0];
  return null;
}

export function resolveObservationMode(agent, observationEvent) {
  const meta = observationEvent?.metadata ?? {};
  for (const key of ['observation_mode', 'mode', 'placement_type', 'placement', 'source']) {
    const fromMeta = normalizeModeToken(meta[key]);
    if (fromMeta && fromMeta !== 'unknown') return fromMeta;
  }
  const fromAgentPlacement = normalizeModeToken(agent?.placement_type ?? agent?.placement);
  if (fromAgentPlacement && fromAgentPlacement !== 'unknown') return fromAgentPlacement;
  const fromCaps = inferObservationModeFromCapabilities(agent?.capabilities);
  if (fromCaps) return fromCaps;
  return 'unknown';
}

function placementLevelForMode(mode) {
  if (DIRECT_OBSERVATION_MODES.has(mode)) return 'High';
  if (BROAD_OBSERVATION_MODES.has(mode)) return 'Medium';
  if (mode === 'unknown') return 'Medium';
  return 'Invalid';
}

function boundAgentsForRun(store, run) {
  return store.agents.filter(
    (a) =>
      a.tenant_id === run.tenant_id &&
      a.status !== 'revoked' &&
      a.target_group_id === run.target_group_id,
  );
}

function agentById(store, tenantId, agentId) {
  if (!agentId) return null;
  return store.agents.find((a) => a.tenant_id === tenantId && a.id === agentId) ?? null;
}

function isBoundOnline(agent, targetGroupId) {
  return Boolean(agent && agent.status === 'online' && agent.target_group_id === targetGroupId);
}

/**
 * Per-run placement confidence for a finalized verdict (distinct from correlation verdict confidence).
 */
export function computePlacementConfidence(store, run, options = {}) {
  const {
    matchingObservation = null,
    agentObserved = false,
    finalizedWithoutObservation = false,
    agent = null,
  } = options;

  const warnings = [];
  const bound = boundAgentsForRun(store, run);
  const onlineBound = bound.filter((a) => a.status === 'online');
  const unboundOnline = store.agents.filter(
    (a) =>
      a.tenant_id === run.tenant_id &&
      a.status === 'online' &&
      (a.target_group_id == null || a.target_group_id === ''),
  );

  const obsAgent =
    agentById(store, run.tenant_id, matchingObservation?.agent_id) ?? agent ?? null;
  const obsAgentBoundOnline = isBoundOnline(obsAgent, run.target_group_id);

  if (matchingObservation && agentObserved) {
    if (!obsAgentBoundOnline) {
      if (obsAgent && obsAgent.target_group_id == null) {
        warnings.push('unbound_agent_only');
      } else if (obsAgent && obsAgent.status !== 'online') {
        warnings.push('observation_from_offline_agent');
      } else {
        warnings.push('observation_agent_not_bound_to_group');
      }
      return {
        level: 'Invalid',
        status: 'missing_agent',
        observation_mode: resolveObservationMode(obsAgent, matchingObservation),
        reason:
          'Agent observation exists but no bound online agent proves placement for this target group.',
        agent_id: obsAgent?.id ?? null,
        evidence_event_id: matchingObservation.id ?? null,
        warnings,
      };
    }

    const observation_mode = resolveObservationMode(obsAgent, matchingObservation);
    const level = placementLevelForMode(observation_mode);
    const reason =
      level === 'High'
        ? `Bound online agent reported ${observation_mode} observation correlated to this run.`
        : level === 'Medium'
          ? `Bound online agent reported ${observation_mode} observation; path evidence is broader than host-level.`
          : 'Observation mode does not support strong placement proof for this verdict.';

    return {
      level,
      status: 'observed_this_run',
      observation_mode,
      reason,
      agent_id: obsAgent.id,
      evidence_event_id: matchingObservation.id ?? null,
      warnings,
    };
  }

  if (bound.length === 0) {
    if (unboundOnline.length > 0) warnings.push('unbound_agent_only');
    return {
      level: 'Invalid',
      status: 'missing_agent',
      observation_mode: 'unbound',
      reason: 'No agent is bound to this target group; internal path proof is unavailable.',
      agent_id: null,
      evidence_event_id: null,
      warnings,
    };
  }

  if (onlineBound.length === 0) {
    return {
      level: 'Invalid',
      status: 'misplaced_risk',
      observation_mode: resolveObservationMode(bound[0], null),
      reason: 'Agents are bound to this group but none are online; placement cannot be trusted.',
      agent_id: bound[0]?.id ?? null,
      evidence_event_id: null,
      warnings: ['no_online_bound_agent'],
    };
  }

  const primaryAgent = onlineBound[0];
  const observation_mode = resolveObservationMode(primaryAgent, null);

  if (finalizedWithoutObservation) {
    return {
      level: 'Low',
      status: 'not_observed_this_run',
      observation_mode,
      reason:
        'Bound online agent did not produce a correlated observation this run; verdict relies on external probe evidence only.',
      agent_id: primaryAgent.id,
      evidence_event_id: null,
      warnings: ['no_matching_observation_this_run'],
    };
  }

  return {
    level: 'Low',
    status: 'needs_baseline',
    observation_mode,
    reason:
      'Bound online agent is present but this run lacks correlated internal observation evidence.',
    agent_id: primaryAgent.id,
    evidence_event_id: null,
    warnings: ['no_matching_observation_this_run'],
  };
}