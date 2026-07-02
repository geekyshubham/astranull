-- 0004_validation_ledger_indexes.sql
-- Additive hot-path indexes for validation/evidence/report repository queries. Schema coverage only.

CREATE INDEX idx_test_runs_tenant_created ON test_runs(tenant_id, created_at DESC);
CREATE INDEX idx_test_runs_tenant_group_created ON test_runs(tenant_id, target_group_id, created_at DESC);
CREATE INDEX idx_events_tenant_run_time ON events(tenant_id, test_run_id, timestamp);
CREATE INDEX idx_evidence_vault_tenant_run_created ON evidence_vault(tenant_id, test_run_id, created_at DESC);
CREATE INDEX idx_evidence_vault_tenant_related_event ON evidence_vault(tenant_id, related_event_id);
CREATE UNIQUE INDEX uniq_findings_open_target_check ON findings(tenant_id, target_group_id, target_id, check_id) WHERE status = 'open';
CREATE UNIQUE INDEX uniq_probe_result_per_run_nonce ON events(tenant_id, test_run_id, signal_type, nonce_hash) WHERE signal_type = 'probe_result' AND nonce_hash IS NOT NULL;