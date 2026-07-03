/** Metadata-only placement diagnostics payloads for readiness/API/UI surfaces. */

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

export function publicPlacementDiagnosticsPayload(diagnostics) {
  const summary = summarizePlacementDiagnostics(diagnostics);
  const groups = (diagnostics?.groups ?? []).map((g) => ({
    target_group_id: g.target_group_id,
    target_group_name: g.target_group_name,
    status: g.status,
    warnings: g.warnings ?? [],
    bound_agent_ids: g.bound_agent_ids ?? [],
    online_bound_agent_ids: g.online_bound_agent_ids ?? [],
    recent_observation_count: g.recent_observation_count ?? 0,
  }));
  return {
    ...summary,
    computed_at: diagnostics?.computed_at ?? null,
    unbound_online_agent_ids: diagnostics?.unbound_online_agent_ids ?? [],
    groups,
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