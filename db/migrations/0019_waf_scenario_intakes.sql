-- WAF-021: durable scenario intake records (metadata-only threat pattern references).

CREATE TABLE IF NOT EXISTS waf_scenario_intakes (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  pattern_title TEXT NOT NULL,
  advisory_refs TEXT[] NOT NULL DEFAULT '{}',
  proposed_scenario_family TEXT,
  risk_class TEXT NOT NULL DEFAULT 'metadata_only',
  intake_stage TEXT NOT NULL DEFAULT 'intake',
  notes TEXT,
  threat_summary TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_waf_scenario_intakes_tenant_created
  ON waf_scenario_intakes(tenant_id, created_at DESC);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'waf_scenario_intakes_tenant_id_id_key'
  ) THEN
    ALTER TABLE waf_scenario_intakes
      ADD CONSTRAINT waf_scenario_intakes_tenant_id_id_key UNIQUE (tenant_id, id);
  END IF;
END $$;

ALTER TABLE waf_scenario_intakes ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_scenario_intakes FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE schemaname = 'public'
      AND tablename = 'waf_scenario_intakes'
      AND policyname = 'tenant_isolation_waf_scenario_intakes'
  ) THEN
    CREATE POLICY tenant_isolation_waf_scenario_intakes ON waf_scenario_intakes
      USING (tenant_id = current_setting('app.tenant_id', true))
      WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
  END IF;
END $$;