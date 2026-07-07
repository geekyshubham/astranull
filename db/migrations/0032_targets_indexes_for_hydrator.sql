-- 0032_targets_indexes_for_hydrator.sql
-- Portal revamp: target-detail hydrator indexes (§2.8), adapted to findings.status column.

CREATE INDEX IF NOT EXISTS targets_by_tenant ON targets(tenant_id);
CREATE INDEX IF NOT EXISTS targets_by_group_kind ON targets(target_group_id, kind);
CREATE INDEX IF NOT EXISTS findings_by_target ON findings(target_id) WHERE target_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS findings_by_target_state ON findings(target_id, status)
  WHERE target_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS test_runs_by_target ON test_runs(target_id) WHERE target_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS waf_assets_by_target ON waf_assets(target_id) WHERE target_id IS NOT NULL;