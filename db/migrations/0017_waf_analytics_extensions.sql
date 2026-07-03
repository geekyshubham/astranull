-- WAF-019: analytics schema extensions (geography, posture effectiveness, coverage rollups).

ALTER TABLE waf_assets
  ADD COLUMN IF NOT EXISTS region_code TEXT,
  ADD COLUMN IF NOT EXISTS geography_label TEXT,
  ADD COLUMN IF NOT EXISTS entity_id TEXT,
  ADD COLUMN IF NOT EXISTS owasp_exposure_tags TEXT[] NOT NULL DEFAULT '{}';

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'fk_waf_assets_entity_tenant'
  ) THEN
    ALTER TABLE waf_assets
      ADD CONSTRAINT fk_waf_assets_entity_tenant
      FOREIGN KEY (tenant_id, entity_id) REFERENCES discovery_entities (tenant_id, id);
  END IF;
END $$;

ALTER TABLE waf_posture_snapshots
  ADD COLUMN IF NOT EXISTS scenario_pass_rate NUMERIC,
  ADD COLUMN IF NOT EXISTS control_bypass_status TEXT;

CREATE TABLE IF NOT EXISTS waf_coverage_daily_rollups (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  rollup_date DATE NOT NULL,
  total_assets INT NOT NULL DEFAULT 0,
  protected INT NOT NULL DEFAULT 0,
  underprotected INT NOT NULL DEFAULT 0,
  unprotected INT NOT NULL DEFAULT 0,
  unknown INT NOT NULL DEFAULT 0,
  excluded INT NOT NULL DEFAULT 0,
  coverage_ratio NUMERIC NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'waf_coverage_daily_rollups_tenant_id_id_key'
  ) THEN
    ALTER TABLE waf_coverage_daily_rollups
      ADD CONSTRAINT waf_coverage_daily_rollups_tenant_id_id_key UNIQUE (tenant_id, id);
  END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS uniq_waf_coverage_daily_rollups_tenant_date
  ON waf_coverage_daily_rollups(tenant_id, rollup_date);

CREATE INDEX IF NOT EXISTS idx_waf_coverage_daily_rollups_tenant_date
  ON waf_coverage_daily_rollups(tenant_id, rollup_date DESC);

ALTER TABLE waf_coverage_daily_rollups ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_coverage_daily_rollups FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE schemaname = current_schema()
      AND tablename = 'waf_coverage_daily_rollups'
      AND policyname = 'tenant_isolation_waf_coverage_daily_rollups'
  ) THEN
    CREATE POLICY tenant_isolation_waf_coverage_daily_rollups ON waf_coverage_daily_rollups
      USING (tenant_id = current_setting('app.tenant_id', true))
      WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
  END IF;
END $$;