/**
 * Store mutations for FT-PROV-dyn-02..07 (docs/ux/17 §5.2).
 * Each pair mutates buildPortalBaselineStore() so Playwright can assert UI updates after restart.
 */
import { PORTAL_BASELINE_IDS } from './seed.mjs';

const FROZEN = PORTAL_BASELINE_IDS.frozenAt;
const ids = PORTAL_BASELINE_IDS;

export const PROVENANCE_FINDINGS = Object.freeze({
  baselineOpenCount: 5,
  mutatedOpenCount: 8,
  baselineOnlyTitles: [
    'Provenance open finding 05',
    'Provenance open finding 04',
    'Provenance open finding 03',
    'Provenance open finding 02',
  ],
  mutatedOnlyTitles: [
    'Provenance open finding 08',
    'Provenance open finding 07',
    'Provenance open finding 06',
  ],
});

export const PROVENANCE_DNS_LADDER = Object.freeze({
  baselineDnsVerified: 3,
  mutatedDnsVerified: 4,
  total: 5,
  promotedTargetId: 'tgt_checkout_2',
  promotedTargetValue: 'pay.acme.com',
});

export const PROVENANCE_WAF_POSTURE = Object.freeze({
  targetId: ids.targetId,
  baselinePosture: 'protected',
  mutatedPosture: 'drift',
  baselineDriftReason: 'none',
  mutatedDriftReason: 'policy_exception',
});

export const PROVENANCE_WAF_CONNECTORS = Object.freeze({
  baselineActive: 1,
  baselineDegraded: 0,
  mutatedActive: 0,
  mutatedDegraded: 1,
});

export const PROVENANCE_REMEDIATION = Object.freeze({
  findingId: ids.findingId,
  baselineState: 'open',
  mutatedState: 'delivered',
  baselineDescription: 'Remediation pending delivery.',
  mutatedDescription: 'Delivered via jira (WAF-9001)',
  deliveredVia: 'jira',
});

export const PROVENANCE_SOC_QUEUE = Object.freeze({
  baselineRequestId: 'hsr_checkout_scheduled',
  addedRequestId: 'hsr_prov_dyn07',
  addedObjective: 'Dyn-07 provenance SOC queue drill',
});

function clearWafCoverageCache(store) {
  if (store.wafCoverageSummaries?.[ids.tenantId]) {
    delete store.wafCoverageSummaries[ids.tenantId];
  }
}

function openFindingRows(count) {
  const rows = [];
  for (let index = 1; index <= count; index += 1) {
    const suffix = String(index).padStart(2, '0');
    rows.push({
      id: index === 1 ? ids.findingId : `fnd_prov_open_${suffix}`,
      tenant_id: ids.tenantId,
      target_group_id: ids.targetGroupId,
      target_id: ids.targetId,
      severity: index % 2 === 0 ? 's3' : 's2',
      title: `Provenance open finding ${suffix}`,
      state: 'open',
      status: 'open',
      opened_at: FROZEN,
      owner_group: 'edge-sre',
    });
  }
  return rows;
}

function seedOpenFindings(store, openCount) {
  const closed = store.findings.filter((row) => row.state === 'closed' || row.status === 'closed');
  store.findings = [...openFindingRows(openCount), ...closed];
}

function setTargetVerificationState(store, targetId, state) {
  const target = store.targets.find((row) => row.id === targetId);
  if (!target) return;

  target.verify_state = state;
  target.verification_state = state;
  if (state === 'dns_verified') {
    target.agent_binding = null;
  }

  store.targetVerifications = store.targetVerifications.filter(
    (row) => row.target_id !== targetId || row.state === 'pending',
  );

  const hasDns = store.targetVerifications.some(
    (row) => row.target_id === targetId && row.state === 'dns_verified',
  );
  if (state === 'dns_verified' && !hasDns) {
    store.targetVerifications.push({
      id: `tv_${targetId}_dns_prov`,
      tenant_id: ids.tenantId,
      target_id: targetId,
      state: 'dns_verified',
      source_kind: 'dns_txt',
      source_ref: { dns_challenge_id: `dns_${targetId}_prov` },
      transitioned_at: FROZEN,
      transitioned_by: 'system',
      audit_entry_id: `aud_${targetId}_dns_prov`,
    });
  }

  if (state === 'agent_verified') {
    store.targetVerifications.push({
      id: `tv_${targetId}_agent_prov`,
      tenant_id: ids.tenantId,
      target_id: targetId,
      state: 'agent_verified',
      source_kind: 'agent_observation',
      source_ref: {
        agent_id: ids.agentId,
        observation_id: `obs_${targetId}_prov`,
        correlated_at: FROZEN,
      },
      transitioned_at: FROZEN,
      transitioned_by: 'system',
      audit_entry_id: `aud_${targetId}_agent_prov`,
    });
    target.agent_binding = { agent_id: ids.agentId, bound_at: FROZEN };
  }
}

function setWafPosture(store, posture, driftReason) {
  const snapshot = store.wafPostureSnapshots.find((row) => row.waf_asset_id === 'wa_checkout_1');
  if (snapshot) {
    snapshot.state = posture;
    snapshot.posture = posture;
    snapshot.drift_reason = driftReason === 'none' ? null : driftReason;
    snapshot.observed_at = FROZEN;
  }

  const asset = store.wafAssets.find((row) => row.id === 'wa_checkout_1');
  if (asset) {
    asset.raw_context_yaml = [
      'asset_id: wa_checkout_1',
      'vendor: cloudflare',
      `target_id: ${ids.targetId}`,
      `posture: ${posture}`,
      `drift_reason: ${driftReason}`,
      '',
    ].join('\n');
  }

  clearWafCoverageCache(store);
}

function setConnectorStatus(store, status) {
  const connector = store.wafConnectors.find((row) => row.id === ids.connectorId);
  if (connector) connector.status = status;
  clearWafCoverageCache(store);
}

function attachFindingRemediation(store, state, description, deliveredVia = null) {
  const finding = store.findings.find((row) => row.id === PROVENANCE_REMEDIATION.findingId);
  if (!finding) return;

  finding.remediation = {
    action_slug: 'origin_restrict',
    owner_group: 'edge-sre',
    state,
    description,
    steps: ['Review finding evidence', 'Apply recommended control change', 'Re-run validation'],
    delivered_via: deliveredVia,
  };
  finding.rem_state = state;
  finding.rem_description = description;
}

/** FT-PROV-dyn-02 baseline: 5 open findings. */
export function applyPortalProvenanceFindingsBaseline(store) {
  seedOpenFindings(store, PROVENANCE_FINDINGS.baselineOpenCount);
}

/** FT-PROV-dyn-02 mutated: 8 open findings. */
export function applyPortalProvenanceFindingsExpanded(store) {
  seedOpenFindings(store, PROVENANCE_FINDINGS.mutatedOpenCount);
}

/** FT-PROV-dyn-03 baseline: DNS-verified ladder step 3/5. */
export function applyPortalProvenanceDnsLadderBaseline(store) {
  // Baseline seed already has 3 DNS-verified targets; mirror verify_state for chip rendering.
  for (const target of store.targets) {
    if (target.target_group_id !== ids.targetGroupId) continue;
    target.verification_state = target.verify_state;
  }
}

/** FT-PROV-dyn-03 mutated: DNS-verified ladder step 4/5. */
export function applyPortalProvenanceDnsLadderExpanded(store) {
  applyPortalProvenanceDnsLadderBaseline(store);
  setTargetVerificationState(store, PROVENANCE_DNS_LADDER.promotedTargetId, 'dns_verified');
}

/** FT-PROV-dyn-04 baseline: protected WAF posture on checkout target. */
export function applyPortalProvenanceWafPostureProtected(store) {
  setWafPosture(store, PROVENANCE_WAF_POSTURE.baselinePosture, PROVENANCE_WAF_POSTURE.baselineDriftReason);
}

/** FT-PROV-dyn-04 mutated: drift WAF posture on checkout target. */
export function applyPortalProvenanceWafPostureDrift(store) {
  setWafPosture(store, PROVENANCE_WAF_POSTURE.mutatedPosture, PROVENANCE_WAF_POSTURE.mutatedDriftReason);
}

/** FT-PROV-dyn-05 baseline: one active WAF connector. */
export function applyPortalProvenanceConnectorActive(store) {
  setConnectorStatus(store, 'active');
}

/** FT-PROV-dyn-05 mutated: connector degraded (active 1→0, degraded 0→1). */
export function applyPortalProvenanceConnectorDegraded(store) {
  setConnectorStatus(store, 'degraded');
}

/** FT-PROV-dyn-06 baseline: remediation state open. */
export function applyPortalProvenanceRemediationOpen(store) {
  applyPortalProvenanceFindingsBaseline(store);
  attachFindingRemediation(
    store,
    PROVENANCE_REMEDIATION.baselineState,
    PROVENANCE_REMEDIATION.baselineDescription,
  );
}

/** FT-PROV-dyn-06 mutated: remediation delivered with delivered_via line. */
export function applyPortalProvenanceRemediationDelivered(store) {
  applyPortalProvenanceRemediationOpen(store);
  attachFindingRemediation(
    store,
    PROVENANCE_REMEDIATION.mutatedState,
    PROVENANCE_REMEDIATION.mutatedDescription,
    PROVENANCE_REMEDIATION.deliveredVia,
  );
}

/** FT-PROV-dyn-07 baseline: single inline SOC queue row (scheduled). */
export function applyPortalProvenanceSocQueueBaseline(store) {
  store.highScaleRequests = store.highScaleRequests.filter(
    (row) => row.id === PROVENANCE_SOC_QUEUE.baselineRequestId,
  );
}

/** FT-PROV-dyn-07 mutated: add a second inline-queue high-scale request. */
export function applyPortalProvenanceSocQueueExpanded(store) {
  applyPortalProvenanceSocQueueBaseline(store);
  store.highScaleRequests.push({
    id: PROVENANCE_SOC_QUEUE.addedRequestId,
    tenant_id: ids.tenantId,
    target_group_id: ids.targetGroupId,
    state: 'submitted',
    reason: PROVENANCE_SOC_QUEUE.addedObjective,
    objective: PROVENANCE_SOC_QUEUE.addedObjective,
    emergency_contacts: [{ name: 'Ops', contact: 'ops@baseline.local' }],
    scope_confirmation: true,
    created_at: FROZEN,
    created_by: 'usr_owner',
    audit_trail: [],
    requested_window: {
      window_start: '2026-07-02T11:00:00.000Z',
      window_end: '2026-07-02T14:00:00.000Z',
      timezone: 'UTC',
    },
    requested_limits: { max_rate: '500_rps_metadata', max_duration_minutes: 45 },
    authorization_pack_status: { overall: 'missing' },
    artifacts: [],
  });
}