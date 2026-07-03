-- WAF-021: composite tenant-scoped unique key for scenario intakes (FK target parity).

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'waf_scenario_intakes_tenant_id_id_key'
  ) THEN
    ALTER TABLE waf_scenario_intakes
      ADD CONSTRAINT waf_scenario_intakes_tenant_id_id_key UNIQUE (tenant_id, id);
  END IF;
END $$;