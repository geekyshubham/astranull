-- 0009_wave1_extensions.sql
-- Wave 1 extensions: discovery entities, supply chain risks, WAF action items,
-- and tenant-consistent links from external asset candidates and CVE pipeline items.

CREATE TABLE IF NOT EXISTS discovery_entities (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  entity_type TEXT NOT NULL,
  name TEXT NOT NULL,
  display_name TEXT NOT NULL,
  parent_entity_id TEXT,
  root_domains TEXT[] NOT NULL DEFAULT '{}',
  country TEXT,
  confidence NUMERIC NOT NULL DEFAULT 0,
  source TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS supply_chain_risks (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  exposure_type TEXT NOT NULL,
  hostname TEXT NOT NULL,
  evidence_summary_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  confidence NUMERIC NOT NULL DEFAULT 0,
  severity TEXT NOT NULL DEFAULT 'medium',
  state TEXT NOT NULL DEFAULT 'suspected',
  owner_hint TEXT,
  remediation_steps TEXT[] NOT NULL DEFAULT '{}',
  assessment_metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS waf_action_items (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  category TEXT NOT NULL,
  title TEXT NOT NULL,
  asset_display TEXT,
  owner TEXT,
  severity TEXT NOT NULL DEFAULT 'medium',
  evidence_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  recommended_solution TEXT,
  retest_url TEXT,
  status TEXT NOT NULL DEFAULT 'open',
  primary_reason TEXT,
  cve_pipeline_item_id TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE discovery_entities
  ADD CONSTRAINT discovery_entities_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE supply_chain_risks
  ADD CONSTRAINT supply_chain_risks_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE waf_action_items
  ADD CONSTRAINT waf_action_items_tenant_id_id_key UNIQUE (tenant_id, id);

ALTER TABLE external_asset_candidates ADD CONSTRAINT fk_external_asset_candidates_entity
  FOREIGN KEY (tenant_id, entity_id) REFERENCES discovery_entities (tenant_id, id);
ALTER TABLE waf_action_items ADD CONSTRAINT fk_waf_action_items_cve_pipeline_item_tenant
  FOREIGN KEY (tenant_id, cve_pipeline_item_id) REFERENCES cve_pipeline_items (tenant_id, id);

CREATE INDEX IF NOT EXISTS idx_supply_chain_risks_lookup
  ON supply_chain_risks(tenant_id, state, severity);
CREATE INDEX IF NOT EXISTS idx_waf_action_items_status
  ON waf_action_items(tenant_id, status, severity);
CREATE INDEX IF NOT EXISTS idx_discovery_entities_lookup
  ON discovery_entities(tenant_id, entity_type);
CREATE UNIQUE INDEX IF NOT EXISTS uniq_supply_chain_risks_dedupe
  ON supply_chain_risks(tenant_id, hostname, exposure_type);
CREATE UNIQUE INDEX IF NOT EXISTS uniq_waf_action_items_dedupe
  ON waf_action_items(tenant_id, asset_display, primary_reason);

ALTER TABLE discovery_entities ENABLE ROW LEVEL SECURITY;
ALTER TABLE discovery_entities FORCE ROW LEVEL SECURITY;
ALTER TABLE supply_chain_risks ENABLE ROW LEVEL SECURITY;
ALTER TABLE supply_chain_risks FORCE ROW LEVEL SECURITY;
ALTER TABLE waf_action_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_action_items FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_discovery_entities ON discovery_entities
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_supply_chain_risks ON supply_chain_risks
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_waf_action_items ON waf_action_items
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));