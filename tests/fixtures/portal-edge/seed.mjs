/**
 * Edge-case fixture for portal revamp state-coverage tests (docs/ux/17 §2).
 */
import { CHECK_CATALOG } from '../../../src/contracts/checks.mjs';
import { resetStoreForTests } from '../../../src/store.mjs';
import { buildPortalBaselineStore, PORTAL_BASELINE_IDS } from '../portal-baseline/seed.mjs';

export const PORTAL_EDGE_IDS = Object.freeze({
  ...PORTAL_BASELINE_IDS,
  longNameGroupId: 'tg_edge_long_name',
  nullFieldFindingId: 'fnd_edge_null_optional',
  noRunsTargetId: 'tgt_edge_no_runs',
  rtlOwner: 'فريق-الحافة',
});

const LONG_GROUP_NAME = 'g'.repeat(256);

export function buildPortalEdgeStore() {
  const baseline = buildPortalBaselineStore();
  const ids = PORTAL_EDGE_IDS;

  baseline.targetGroups.push({
    id: ids.longNameGroupId,
    tenant_id: ids.tenantId,
    environment_id: ids.environmentId,
    name: LONG_GROUP_NAME,
    expected_behavior_default: 'must_block_before_origin',
    owner: ids.rtlOwner,
  });

  baseline.targets.push({
    id: ids.noRunsTargetId,
    tenant_id: ids.tenantId,
    target_group_id: ids.longNameGroupId,
    kind: 'fqdn',
    value: 'no-runs.edge.example',
    expected_behavior: 'must_block_before_origin',
  });

  baseline.findings.push({
    id: ids.nullFieldFindingId,
    tenant_id: ids.tenantId,
    target_group_id: ids.targetGroupId,
    target_id: null,
    severity: 's4',
    title: 'Optional fields null',
    state: 'open',
    opened_at: ids.frozenAt,
    owner_group: null,
    remediation: null,
    description: null,
  });

  return baseline;
}

export function seedPortalEdge() {
  process.env.ASTRANULL_NO_PERSIST = '1';
  return resetStoreForTests(buildPortalEdgeStore());
}