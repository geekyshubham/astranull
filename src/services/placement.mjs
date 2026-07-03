import { getStore } from '../store.mjs';
import {
  computePlacementConfidence,
  resolveObservationMode,
} from '../lib/placementConfidence.mjs';
import { computePlacementDiagnosticsFromData } from '../lib/placementDiagnosticsCompute.mjs';
import {
  placementScoreFromDiagnostics,
  publicPlacementDiagnosticsPayload,
  summarizePlacementDiagnostics,
} from '../lib/placementDiagnostics.mjs';

export {
  placementScoreFromDiagnostics,
  publicPlacementDiagnosticsPayload,
  summarizePlacementDiagnostics,
};

export { computePlacementConfidence, resolveObservationMode };

export function buildPlacementReviewsPayload(diagnostics) {
  const publicPayload = publicPlacementDiagnosticsPayload(diagnostics);
  return {
    computed_at: publicPayload.computed_at,
    summary: {
      total_groups: publicPayload.total_groups,
      proven: publicPayload.proven,
      needs_baseline: publicPayload.needs_baseline,
      missing_agent: publicPayload.missing_agent,
      misplaced_risk: publicPayload.misplaced_risk,
      unbound_online_agent_count: publicPayload.unbound_online_agent_count,
      summary: publicPayload.summary,
    },
    reviews: publicPayload.groups,
    unbound_online_agent_ids: publicPayload.unbound_online_agent_ids,
  };
}

export function computePlacementDiagnostics(tenantId, nowMs = Date.now()) {
  const store = getStore();
  return computePlacementDiagnosticsFromData({
    tenantId,
    groups: store.targetGroups,
    agents: store.agents,
    runs: store.testRuns,
    events: store.events,
    nowMs,
  });
}

/**
 * Metadata-only per-target placement review diagnostics for API consumers.
 *
 * @param {{ tenantId: string }} ctx
 * @param {{ target_group_id?: string | null }} [query]
 */
export function listPlacementReviews(ctx, query = {}) {
  const diagnostics = computePlacementDiagnostics(ctx.tenantId);
  const targetGroupId =
    query.target_group_id != null && String(query.target_group_id).trim() !== ''
      ? String(query.target_group_id).trim()
      : null;

  if (targetGroupId) {
    const match = diagnostics.groups.find((g) => g.target_group_id === targetGroupId);
    if (!match) {
      return { error: 'not_found', status: 404 };
    }
    const filtered = {
      ...diagnostics,
      groups: [match],
    };
    return {
      target_group_id: targetGroupId,
      ...buildPlacementReviewsPayload(filtered),
    };
  }

  return buildPlacementReviewsPayload(diagnostics);
}