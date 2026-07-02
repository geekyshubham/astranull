import { getStore } from '../store.mjs';
import { computeReadiness } from './readiness.mjs';

/**
 * Dev-json / memory dashboard aggregate for GET /v1/state.
 * @param {{ tenantId: string }} ctx
 */
export async function getState(ctx) {
  const readiness = computeReadiness(ctx.tenantId);
  const store = getStore();
  const tenantId = ctx.tenantId;
  return {
    tenant_id: tenantId,
    readiness,
    target_groups: store.targetGroups.filter((g) => g.tenant_id === tenantId).length,
    agents_online: store.agents.filter((a) => a.tenant_id === tenantId && a.status === 'online').length,
    recent_runs: store.testRuns.filter((r) => r.tenant_id === tenantId).slice(-5),
    open_findings: store.findings.filter((f) => f.tenant_id === tenantId && f.status === 'open').length,
    high_scale_requests: store.highScaleRequests.filter((h) => h.tenant_id === tenantId).length,
    kill_switch: store.socKillSwitch,
  };
}