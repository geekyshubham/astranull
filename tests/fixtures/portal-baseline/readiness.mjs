/**
 * Store mutations that produce distinct evidence-backed readiness scores for FT-PROV-dyn-01.
 */
import { PORTAL_BASELINE_IDS } from './seed.mjs';

const FROZEN = PORTAL_BASELINE_IDS.frozenAt;
const NOW = new Date().toISOString();

/** Baseline + recent verdict evidence → a stable non-zero readiness score (typically 25). */
export function applyPortalBaselineReadinessBoost(store) {
  const ids = PORTAL_BASELINE_IDS;
  const agent = store.agents.find((entry) => entry.id === ids.agentId);
  if (agent) agent.status = 'online';

  if (store.testRuns[0]) {
    store.testRuns[0].status = 'completed';
    store.testRuns[0].completed_at = NOW;
    store.testRuns[0].verdict_at = NOW;
  }

  store.verdicts.push({
    id: 'vrd_portal_baseline_boost',
    tenant_id: ids.tenantId,
    target_group_id: ids.targetGroupId,
    target_id: ids.targetId,
    verdict: 'pass',
    created_at: NOW,
  });
}

/** Open-finding pressure drops the boosted score (typically 25 → 5). */
export function applyPortalBaselineReadinessPenalty(store) {
  applyPortalBaselineReadinessBoost(store);
  const ids = PORTAL_BASELINE_IDS;

  for (const finding of store.findings) {
    if (finding.tenant_id !== ids.tenantId) continue;
    finding.status = 'open';
    finding.state = 'open';
  }

  store.findings.push({
    id: 'fnd_portal_baseline_penalty',
    tenant_id: ids.tenantId,
    target_group_id: ids.targetGroupId,
    target_id: ids.targetId,
    severity: 's2',
    title: 'Penalty finding',
    status: 'open',
    state: 'open',
    opened_at: FROZEN,
    owner_group: 'edge-sre',
  });
}