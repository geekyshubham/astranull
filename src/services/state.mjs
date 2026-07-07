import { getStore } from '../store.mjs';
import { computeReadiness } from './readiness.mjs';
import { activeTargetGroupsForTenant } from './targetGroups.mjs';
import { buildGetStatePayload } from '../lib/statePayload.mjs';

function tenantStateRollup(store, tenantId) {
  const rollups = store.stateRollups;
  if (!rollups || typeof rollups !== 'object') return null;
  const rollup = rollups[tenantId];
  return rollup && typeof rollup === 'object' ? rollup : null;
}

/**
 * Dev-json / memory dashboard aggregate for GET /v1/state.
 * @param {{ tenantId: string }} ctx
 */
export async function getState(ctx) {
  const store = getStore();
  const tenantId = ctx.tenantId;
  const rollup = tenantStateRollup(store, tenantId);
  const tenantHighScaleRequests = Array.isArray(store.highScaleRequests)
    ? store.highScaleRequests.filter((h) => h.tenant_id === tenantId)
    : [];

  return buildGetStatePayload({
    tenantId,
    rollup,
    computed: {
      readiness: computeReadiness(tenantId),
      target_groups: activeTargetGroupsForTenant(tenantId).length,
      agents_online: store.agents.filter((a) => a.tenant_id === tenantId && a.status === 'online').length,
      recent_runs: store.testRuns.filter((r) => r.tenant_id === tenantId).slice(-5),
      open_findings: store.findings.filter(
        (f) => f.tenant_id === tenantId && (f.status === 'open' || f.state === 'open'),
      ).length,
      high_scale_requests: tenantHighScaleRequests.length,
    },
    killSwitch: store.socKillSwitch,
    highScaleWired: Array.isArray(store.highScaleRequests),
    highScaleRequests: tenantHighScaleRequests,
  });
}