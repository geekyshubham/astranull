-- 0008_waf_posture.sql
-- WAF posture foundation: approved assets, safe validation envelopes, posture snapshots,
-- optional read-only connectors, CVE pipeline, and metadata-only evidence (no raw payloads).

-- Findings composite parent key for tenant-consistent WAF drift/CVE FKs.
ALTER TABLE findings
  ADD CONSTRAINT findings_tenant_id_id_key UNIQUE (tenant_id, id);

CREATE TABLE IF NOT EXISTS external_asset_candidates (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  entity_id TEXT,
  asset_type TEXT NOT NULL,
  asset_value_hash TEXT NOT NULL,
  display_value TEXT NOT NULL,
  source_type TEXT NOT NULL,
  source_ref TEXT,
  confidence NUMERIC NOT NULL DEFAULT 0,
  approval_status TEXT NOT NULL DEFAULT 'not_requested',
  approved_target_id TEXT,
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  evidence_summary_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS waf_products (
  id TEXT PRIMARY KEY,
  vendor TEXT NOT NULL,
  product TEXT NOT NULL,
  deployment_type TEXT NOT NULL DEFAULT 'unknown',
  fingerprint_version TEXT NOT NULL DEFAULT '1',
  confidence_rules_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  enabled BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS waf_assets (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  target_group_id TEXT NOT NULL,
  target_id TEXT,
  environment_id TEXT,
  canonical_url TEXT NOT NULL,
  asset_kind TEXT NOT NULL DEFAULT 'unknown',
  expected_waf_required BOOLEAN NOT NULL DEFAULT TRUE,
  expected_vendor_hint TEXT,
  business_criticality TEXT NOT NULL DEFAULT 'medium',
  traffic_tier TEXT NOT NULL DEFAULT 'unknown',
  compliance_tags TEXT[] NOT NULL DEFAULT '{}',
  owner_hint TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS waf_fingerprints (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  waf_asset_id TEXT NOT NULL,
  test_run_id TEXT,
  detected_vendor TEXT,
  detected_product TEXT,
  confidence NUMERIC NOT NULL DEFAULT 0,
  signals_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS waf_validation_runs (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  test_run_id TEXT,
  waf_asset_id TEXT NOT NULL,
  mode TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'planned',
  started_at TIMESTAMPTZ,
  finalized_at TIMESTAMPTZ,
  safety_profile_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  summary_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS waf_scenario_results (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  waf_validation_run_id TEXT NOT NULL,
  scenario_family TEXT NOT NULL,
  test_material_type TEXT NOT NULL DEFAULT 'metadata_only',
  expected_action TEXT NOT NULL,
  observed_action TEXT NOT NULL DEFAULT 'inconclusive',
  passed BOOLEAN,
  confidence NUMERIC NOT NULL DEFAULT 0,
  evidence_summary_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS waf_posture_snapshots (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  waf_asset_id TEXT NOT NULL,
  status TEXT NOT NULL,
  reason_codes TEXT[] NOT NULL DEFAULT '{}',
  detected_vendor TEXT,
  detected_product TEXT,
  coverage_required BOOLEAN NOT NULL DEFAULT TRUE,
  risk_score INT NOT NULL DEFAULT 0,
  confidence NUMERIC NOT NULL DEFAULT 0,
  source_mix_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  is_current BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS waf_baselines (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  waf_asset_id TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'proposed',
  baseline_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  approved_by TEXT,
  approved_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS waf_drift_events (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  waf_asset_id TEXT NOT NULL,
  baseline_id TEXT,
  drift_type TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'medium',
  before_summary_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  after_summary_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  status TEXT NOT NULL DEFAULT 'open',
  finding_id TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  resolved_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS waf_connectors (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  provider TEXT NOT NULL,
  name TEXT NOT NULL,
  secret_id TEXT,
  config_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  status TEXT NOT NULL DEFAULT 'disabled',
  last_success_at TIMESTAMPTZ,
  last_error_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS waf_connector_snapshots (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  connector_id TEXT NOT NULL,
  provider TEXT NOT NULL,
  snapshot_kind TEXT NOT NULL,
  resource_ref_hash TEXT NOT NULL,
  display_ref TEXT,
  summary_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  config_hash TEXT,
  observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cve_pipeline_items (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  cve_id TEXT NOT NULL,
  published_at TIMESTAMPTZ,
  severity TEXT,
  known_exploited BOOLEAN NOT NULL DEFAULT FALSE,
  public_poc_signal BOOLEAN NOT NULL DEFAULT FALSE,
  state TEXT NOT NULL DEFAULT 'ingested',
  triage_summary_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cve_asset_matches (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  cve_pipeline_item_id TEXT NOT NULL,
  waf_asset_id TEXT NOT NULL,
  match_confidence NUMERIC NOT NULL DEFAULT 0,
  match_sources TEXT[] NOT NULL DEFAULT '{}',
  validation_status TEXT NOT NULL DEFAULT 'pending',
  risk_score INT NOT NULL DEFAULT 0,
  finding_id TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS waf_rule_recommendations (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  waf_asset_id TEXT NOT NULL,
  cve_asset_match_id TEXT,
  vendor TEXT NOT NULL,
  recommendation_type TEXT NOT NULL,
  recommendation_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  approval_status TEXT NOT NULL DEFAULT 'draft',
  ticket_id TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE waf_assets
  ADD CONSTRAINT waf_assets_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE waf_validation_runs
  ADD CONSTRAINT waf_validation_runs_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE waf_baselines
  ADD CONSTRAINT waf_baselines_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE waf_connectors
  ADD CONSTRAINT waf_connectors_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE cve_pipeline_items
  ADD CONSTRAINT cve_pipeline_items_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE cve_asset_matches
  ADD CONSTRAINT cve_asset_matches_tenant_id_id_key UNIQUE (tenant_id, id);

ALTER TABLE external_asset_candidates ADD CONSTRAINT fk_external_asset_candidates_approved_target_tenant
  FOREIGN KEY (tenant_id, approved_target_id) REFERENCES targets (tenant_id, id);
ALTER TABLE waf_assets ADD CONSTRAINT fk_waf_assets_target_group_tenant
  FOREIGN KEY (tenant_id, target_group_id) REFERENCES target_groups (tenant_id, id);
ALTER TABLE waf_assets ADD CONSTRAINT fk_waf_assets_target_tenant
  FOREIGN KEY (tenant_id, target_id) REFERENCES targets (tenant_id, id);
ALTER TABLE waf_assets ADD CONSTRAINT fk_waf_assets_environment_tenant
  FOREIGN KEY (tenant_id, environment_id) REFERENCES environments (tenant_id, id);
ALTER TABLE waf_fingerprints ADD CONSTRAINT fk_waf_fingerprints_waf_asset_tenant
  FOREIGN KEY (tenant_id, waf_asset_id) REFERENCES waf_assets (tenant_id, id);
ALTER TABLE waf_fingerprints ADD CONSTRAINT fk_waf_fingerprints_test_run_tenant
  FOREIGN KEY (tenant_id, test_run_id) REFERENCES test_runs (tenant_id, id);
ALTER TABLE waf_validation_runs ADD CONSTRAINT fk_waf_validation_runs_test_run_tenant
  FOREIGN KEY (tenant_id, test_run_id) REFERENCES test_runs (tenant_id, id);
ALTER TABLE waf_validation_runs ADD CONSTRAINT fk_waf_validation_runs_waf_asset_tenant
  FOREIGN KEY (tenant_id, waf_asset_id) REFERENCES waf_assets (tenant_id, id);
ALTER TABLE waf_scenario_results ADD CONSTRAINT fk_waf_scenario_results_waf_validation_run_tenant
  FOREIGN KEY (tenant_id, waf_validation_run_id) REFERENCES waf_validation_runs (tenant_id, id);
ALTER TABLE waf_posture_snapshots ADD CONSTRAINT fk_waf_posture_snapshots_waf_asset_tenant
  FOREIGN KEY (tenant_id, waf_asset_id) REFERENCES waf_assets (tenant_id, id);
ALTER TABLE waf_baselines ADD CONSTRAINT fk_waf_baselines_waf_asset_tenant
  FOREIGN KEY (tenant_id, waf_asset_id) REFERENCES waf_assets (tenant_id, id);
ALTER TABLE waf_drift_events ADD CONSTRAINT fk_waf_drift_events_waf_asset_tenant
  FOREIGN KEY (tenant_id, waf_asset_id) REFERENCES waf_assets (tenant_id, id);
ALTER TABLE waf_drift_events ADD CONSTRAINT fk_waf_drift_events_baseline_tenant
  FOREIGN KEY (tenant_id, baseline_id) REFERENCES waf_baselines (tenant_id, id);
ALTER TABLE waf_drift_events ADD CONSTRAINT fk_waf_drift_events_finding_tenant
  FOREIGN KEY (tenant_id, finding_id) REFERENCES findings (tenant_id, id);
ALTER TABLE waf_connectors ADD CONSTRAINT fk_waf_connectors_secret_tenant
  FOREIGN KEY (tenant_id, secret_id) REFERENCES encrypted_secrets (tenant_id, id);
ALTER TABLE waf_connector_snapshots ADD CONSTRAINT fk_waf_connector_snapshots_connector_tenant
  FOREIGN KEY (tenant_id, connector_id) REFERENCES waf_connectors (tenant_id, id);
ALTER TABLE cve_asset_matches ADD CONSTRAINT fk_cve_asset_matches_cve_pipeline_item_tenant
  FOREIGN KEY (tenant_id, cve_pipeline_item_id) REFERENCES cve_pipeline_items (tenant_id, id);
ALTER TABLE cve_asset_matches ADD CONSTRAINT fk_cve_asset_matches_waf_asset_tenant
  FOREIGN KEY (tenant_id, waf_asset_id) REFERENCES waf_assets (tenant_id, id);
ALTER TABLE cve_asset_matches ADD CONSTRAINT fk_cve_asset_matches_finding_tenant
  FOREIGN KEY (tenant_id, finding_id) REFERENCES findings (tenant_id, id);
ALTER TABLE waf_rule_recommendations ADD CONSTRAINT fk_waf_rule_recommendations_waf_asset_tenant
  FOREIGN KEY (tenant_id, waf_asset_id) REFERENCES waf_assets (tenant_id, id);
ALTER TABLE waf_rule_recommendations ADD CONSTRAINT fk_waf_rule_recommendations_cve_asset_match_tenant
  FOREIGN KEY (tenant_id, cve_asset_match_id) REFERENCES cve_asset_matches (tenant_id, id);

CREATE INDEX IF NOT EXISTS idx_waf_assets_tenant_group_url
  ON waf_assets(tenant_id, target_group_id, canonical_url);
CREATE INDEX IF NOT EXISTS idx_external_asset_candidates_approval_queue
  ON external_asset_candidates(tenant_id, approval_status, confidence DESC);
CREATE UNIQUE INDEX IF NOT EXISTS uniq_waf_posture_snapshot_current
  ON waf_posture_snapshots(tenant_id, waf_asset_id) WHERE is_current = TRUE;
CREATE INDEX IF NOT EXISTS idx_waf_posture_snapshots_dashboard
  ON waf_posture_snapshots(tenant_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_waf_drift_events_queue
  ON waf_drift_events(tenant_id, drift_type, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_waf_connector_snapshots_history
  ON waf_connector_snapshots(tenant_id, connector_id, provider, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_cve_pipeline_items_lookup
  ON cve_pipeline_items(tenant_id, cve_id);
CREATE UNIQUE INDEX IF NOT EXISTS uniq_cve_asset_matches_dedupe
  ON cve_asset_matches(tenant_id, cve_pipeline_item_id, waf_asset_id);

ALTER TABLE external_asset_candidates ENABLE ROW LEVEL SECURITY;
ALTER TABLE external_asset_candidates FORCE ROW LEVEL SECURITY;
ALTER TABLE waf_assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_assets FORCE ROW LEVEL SECURITY;
ALTER TABLE waf_fingerprints ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_fingerprints FORCE ROW LEVEL SECURITY;
ALTER TABLE waf_validation_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_validation_runs FORCE ROW LEVEL SECURITY;
ALTER TABLE waf_scenario_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_scenario_results FORCE ROW LEVEL SECURITY;
ALTER TABLE waf_posture_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_posture_snapshots FORCE ROW LEVEL SECURITY;
ALTER TABLE waf_baselines ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_baselines FORCE ROW LEVEL SECURITY;
ALTER TABLE waf_drift_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_drift_events FORCE ROW LEVEL SECURITY;
ALTER TABLE waf_connectors ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_connectors FORCE ROW LEVEL SECURITY;
ALTER TABLE waf_connector_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_connector_snapshots FORCE ROW LEVEL SECURITY;
ALTER TABLE cve_pipeline_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE cve_pipeline_items FORCE ROW LEVEL SECURITY;
ALTER TABLE cve_asset_matches ENABLE ROW LEVEL SECURITY;
ALTER TABLE cve_asset_matches FORCE ROW LEVEL SECURITY;
ALTER TABLE waf_rule_recommendations ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_rule_recommendations FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_external_asset_candidates ON external_asset_candidates
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_waf_assets ON waf_assets
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_waf_fingerprints ON waf_fingerprints
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_waf_validation_runs ON waf_validation_runs
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_waf_scenario_results ON waf_scenario_results
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_waf_posture_snapshots ON waf_posture_snapshots
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_waf_baselines ON waf_baselines
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_waf_drift_events ON waf_drift_events
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_waf_connectors ON waf_connectors
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_waf_connector_snapshots ON waf_connector_snapshots
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_cve_pipeline_items ON cve_pipeline_items
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_cve_asset_matches ON cve_asset_matches
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_waf_rule_recommendations ON waf_rule_recommendations
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));