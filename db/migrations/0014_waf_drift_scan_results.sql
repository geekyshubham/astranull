-- 0014_waf_drift_scan_results.sql
-- Persist metadata-only WAF drift scan summaries (parity with dev-json wafDriftScanResults).

CREATE TABLE IF NOT EXISTS waf_drift_scan_results (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  scan_type TEXT NOT NULL,
  assets_scanned INT NOT NULL DEFAULT 0,
  drifts_detected INT NOT NULL DEFAULT 0,
  scan_duration_ms INT NOT NULL DEFAULT 0,
  completed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  state TEXT NOT NULL DEFAULT 'completed',
  assets_with_connector_snapshots INT,
  drift_check_types TEXT[] NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'waf_drift_scan_results_tenant_id_id_key'
  ) THEN
    ALTER TABLE waf_drift_scan_results
      ADD CONSTRAINT waf_drift_scan_results_tenant_id_id_key UNIQUE (tenant_id, id);
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_waf_drift_scan_results_latest
  ON waf_drift_scan_results(tenant_id, completed_at DESC);

ALTER TABLE waf_drift_scan_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_drift_scan_results FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE schemaname = current_schema()
      AND tablename = 'waf_drift_scan_results'
      AND policyname = 'tenant_isolation_waf_drift_scan_results'
  ) THEN
    CREATE POLICY tenant_isolation_waf_drift_scan_results ON waf_drift_scan_results
      USING (tenant_id = current_setting('app.tenant_id', true))
      WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
  END IF;
END $$;