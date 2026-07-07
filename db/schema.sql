-- AstraNull PostgreSQL production schema contract (migrations 0001–0009 including WAF posture and wave 1 extensions).
-- Developer validation uses src/store.mjs (JSON). Schema coverage only — runtime Postgres adapter remains fail-closed until wired.
-- App code must set_config('app.tenant_id', ..., true) inside transactions when using RLS-backed queries.

CREATE TABLE schema_migrations (
  version TEXT PRIMARY KEY,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


CREATE TABLE tenants (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  plan TEXT,
  data_region TEXT,
  status TEXT DEFAULT 'active',
  privacy_settings JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE environments (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  name TEXT NOT NULL,
  status TEXT DEFAULT 'active',
  timezone TEXT,
  privacy_settings JSONB DEFAULT '{}',
  settings_json JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE users (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  email TEXT NOT NULL,
  name TEXT,
  role TEXT NOT NULL,
  mfa_enabled BOOLEAN DEFAULT FALSE,
  status TEXT DEFAULT 'active',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (tenant_id, email)
);

CREATE TABLE signup_requests (
  id TEXT PRIMARY KEY,
  organization_name TEXT NOT NULL,
  contact_email TEXT NOT NULL,
  contact_name TEXT NOT NULL,
  email_domain TEXT NOT NULL,
  requested_plan TEXT NOT NULL,
  intended_use TEXT NOT NULL,
  region TEXT NOT NULL,
  high_scale_interest BOOLEAN NOT NULL DEFAULT FALSE,
  state TEXT NOT NULL,
  reviewer_staff_id TEXT,
  decision_reason TEXT,
  customer_notice TEXT,
  provisioned_tenant_id TEXT REFERENCES tenants(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  decided_at TIMESTAMPTZ
);

CREATE TABLE staff_users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  display_name TEXT,
  staff_roles TEXT[] NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'active',
  last_login_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE tenant_accounts (
  tenant_id TEXT PRIMARY KEY REFERENCES tenants(id),
  legal_name TEXT,
  support_owner TEXT,
  region TEXT NOT NULL DEFAULT 'us',
  lifecycle_state TEXT NOT NULL DEFAULT 'active',
  contract_reference TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ
);

CREATE TABLE tenant_subscriptions (
  tenant_id TEXT PRIMARY KEY REFERENCES tenants(id),
  plan_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  billing_provider_ref TEXT,
  effective_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  renewal_at TIMESTAMPTZ,
  limits_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  feature_entitlements_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ
);

CREATE TABLE entitlement_grants (
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  feature TEXT NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  limit_value JSONB,
  source TEXT NOT NULL DEFAULT 'staff_override',
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ,
  PRIMARY KEY (tenant_id, feature)
);

CREATE TABLE internal_approval_requests (
  id TEXT PRIMARY KEY,
  tenant_id TEXT REFERENCES tenants(id),
  kind TEXT NOT NULL,
  subject_ref TEXT,
  state TEXT NOT NULL DEFAULT 'submitted',
  assigned_to TEXT,
  decision TEXT,
  reason TEXT,
  evidence_refs TEXT[] NOT NULL DEFAULT '{}',
  reviewer_staff_id TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  decided_at TIMESTAMPTZ
);

CREATE TABLE internal_audit_log (
  id TEXT PRIMARY KEY,
  tenant_id TEXT REFERENCES tenants(id),
  staff_id TEXT,
  staff_role TEXT,
  action TEXT NOT NULL,
  resource_type TEXT,
  resource_id TEXT,
  reason TEXT,
  metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE target_groups (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  environment_id TEXT,
  name TEXT NOT NULL,
  description TEXT,
  criticality TEXT,
  owner_user_id TEXT,
  expected_behavior_default TEXT,
  high_scale_allowed BOOLEAN DEFAULT FALSE,
  timezone TEXT,
  safe_test_windows JSONB DEFAULT '[]',
  safety_policy JSONB DEFAULT '{}',
  settings_json JSONB DEFAULT '{}',
  archived_at TIMESTAMPTZ,
  validation_mode TEXT DEFAULT 'agent_assisted',
  ownership_status TEXT DEFAULT 'unverified',
  dns_ownership JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE targets (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  target_group_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  value TEXT NOT NULL,
  expected_behavior TEXT,
  protocol TEXT,
  port INT,
  metadata_json JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE bootstrap_tokens (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  name TEXT,
  token_hash TEXT NOT NULL,
  token_salt TEXT NOT NULL,
  environment_id TEXT,
  target_group_id TEXT,
  prebind_fqdn TEXT,
  deployment_packaging TEXT,
  allowed_modes TEXT[],
  max_registrations INT NOT NULL DEFAULT 1,
  registrations_used INT NOT NULL DEFAULT 0,
  allowed_cidrs TEXT[],
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  created_by TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE agents (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  environment_id TEXT,
  target_group_id TEXT,
  bootstrap_token_id TEXT,
  name TEXT,
  hostname TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  version TEXT,
  placement_type TEXT,
  capabilities TEXT[],
  fingerprint TEXT,
  credential_hash TEXT,
  credential_salt TEXT,
  last_heartbeat_at TIMESTAMPTZ,
  metadata_json JSONB DEFAULT '{}',
  probe_endpoint JSONB,
  probe_endpoint_status TEXT,
  probe_endpoint_error TEXT,
  last_token_validation_at TIMESTAMPTZ,
  last_token_validation_status TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE test_runs (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  target_group_id TEXT NOT NULL,
  target_id TEXT,
  check_id TEXT NOT NULL,
  created_by TEXT,
  initiated_by TEXT,
  risk_class TEXT,
  safety_class TEXT,
  vector_family TEXT,
  status TEXT NOT NULL,
  probe_external_result TEXT,
  awaiting_external_probe BOOLEAN NOT NULL DEFAULT FALSE,
  remediation_template TEXT,
  safety_constraints JSONB DEFAULT '{}',
  correlation_json JSONB DEFAULT '{}',
  collection_deadline_at TIMESTAMPTZ,
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  summary_json JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE probe_jobs (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  test_run_id TEXT NOT NULL,
  target_id TEXT,
  check_id TEXT NOT NULL,
  vector_family TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  nonce_hash TEXT NOT NULL,
  nonce_for_worker TEXT,
  probe_profile JSONB,
  constraints_json JSONB NOT NULL DEFAULT '{}',
  target_descriptor_json JSONB DEFAULT '{}',
  worker_metadata_json JSONB DEFAULT '{}',
  job_signature TEXT,
  leased_at TIMESTAMPTZ,
  leased_by TEXT,
  completed_at TIMESTAMPTZ,
  ownership_verification_id TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE ownership_verifications (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  target_group_id TEXT NOT NULL,
  agent_id TEXT,
  declared_fqdn TEXT,
  status TEXT NOT NULL,
  challenge_nonce_hash TEXT,
  probe_observed BOOLEAN NOT NULL DEFAULT false,
  agent_observed BOOLEAN NOT NULL DEFAULT false,
  verified_at TIMESTAMPTZ,
  confirmed_by_user_id TEXT,
  confirmed_at TIMESTAMPTZ,
  probe_job_id TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_by TEXT
);

CREATE TABLE test_policies (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  target_group_id TEXT NOT NULL,
  check_id TEXT NOT NULL,
  cadence TEXT NOT NULL DEFAULT 'manual'
    CHECK (cadence IN ('manual', 'daily', 'weekly', 'monthly', 'event_driven')),
  expected_verdict TEXT NOT NULL DEFAULT 'pass'
    CHECK (expected_verdict IN ('pass', 'warn', 'fail', 'manual_review')),
  safe_windows JSONB NOT NULL DEFAULT '[]',
  state TEXT NOT NULL DEFAULT 'active',
  safety_policy_snapshot JSONB NOT NULL DEFAULT '{}',
  archived_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE agent_jobs (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  agent_id TEXT NOT NULL,
  test_run_id TEXT,
  check_id TEXT,
  target_id TEXT,
  type TEXT NOT NULL DEFAULT 'observe_window',
  status TEXT NOT NULL DEFAULT 'pending',
  nonce_hash TEXT,
  nonce_for_agent TEXT,
  payload_json JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  acked_at TIMESTAMPTZ,
  observed_at TIMESTAMPTZ
);

CREATE TABLE events (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  event_id TEXT,
  test_run_id TEXT,
  target_id TEXT,
  check_id TEXT,
  agent_id TEXT,
  source TEXT,
  signal_type TEXT,
  nonce_hash TEXT,
  timestamp TIMESTAMPTZ NOT NULL,
  metadata_json JSONB DEFAULT '{}'
);

CREATE TABLE verdicts (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  test_run_id TEXT NOT NULL,
  target_id TEXT,
  check_id TEXT,
  verdict TEXT NOT NULL,
  confidence TEXT,
  explanation TEXT,
  evidence_ids TEXT[],
  placement_confidence_json JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE findings (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  target_group_id TEXT,
  target_id TEXT,
  test_run_id TEXT,
  check_id TEXT,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  evidence_ids TEXT[],
  notes TEXT,
  remediation_template TEXT,
  verdict_id TEXT,
  last_verdict_id TEXT,
  assignee TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ
);

CREATE TABLE evidence_vault (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  test_run_id TEXT,
  label TEXT,
  metadata_json JSONB DEFAULT '{}',
  related_event_id TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE reports (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  kind TEXT NOT NULL,
  title TEXT NOT NULL,
  status TEXT NOT NULL,
  summary_json JSONB DEFAULT '{}',
  run_ids TEXT[],
  created_by TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE high_scale_requests (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  target_group_id TEXT,
  requested_by TEXT,
  state TEXT NOT NULL,
  reason TEXT,
  objective TEXT,
  requested_window JSONB DEFAULT '{}',
  emergency_contacts JSONB DEFAULT '[]',
  scope_confirmation BOOLEAN DEFAULT FALSE,
  created_by TEXT,
  audit_trail JSONB DEFAULT '[]',
  artifacts JSONB DEFAULT '[]',
  scope_hash TEXT,
  soc_approvals JSONB DEFAULT '[]',
  provider_approval_checklist JSONB DEFAULT '[]',
  adapter_json JSONB DEFAULT '{}',
  scheduled_window JSONB,
  provider_context_json JSONB DEFAULT '{}',
  risk_review_json JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ
);

CREATE TABLE authorization_artifacts (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  high_scale_request_id TEXT NOT NULL,
  type TEXT NOT NULL,
  reference_uri TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  reviewed_by TEXT,
  reviewed_at TIMESTAMPTZ,
  metadata_json JSONB DEFAULT '{}',
  content_sha256 TEXT,
  custody_id TEXT,
  custody_uri TEXT,
  content_type TEXT,
  filename_redacted TEXT,
  upload_envelope TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_authorization_artifacts_tenant_request_created
  ON authorization_artifacts(tenant_id, high_scale_request_id, created_at);

CREATE INDEX idx_authorization_artifacts_tenant_custody
  ON authorization_artifacts(tenant_id, custody_id)
  WHERE custody_id IS NOT NULL;

CREATE TABLE soc_notes (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  high_scale_request_id TEXT NOT NULL,
  body TEXT NOT NULL,
  created_by TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE soc_kill_switch (
  tenant_id TEXT PRIMARY KEY REFERENCES tenants(id),
  active BOOLEAN NOT NULL DEFAULT FALSE,
  reason TEXT,
  updated_at TIMESTAMPTZ,
  updated_by TEXT
);

CREATE TABLE notification_rules (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  channel TEXT NOT NULL,
  destination TEXT NOT NULL,
  trigger TEXT,
  triggers_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  enabled BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE notification_events (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  rule_id TEXT,
  trigger TEXT,
  subject TEXT,
  metadata_json JSONB DEFAULT '{}'::jsonb,
  delivery_status TEXT DEFAULT 'metadata_only',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE service_accounts (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  name TEXT NOT NULL,
  role TEXT NOT NULL,
  scopes TEXT[] NOT NULL DEFAULT '{}',
  secret_hash TEXT NOT NULL,
  secret_salt TEXT NOT NULL,
  expires_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by TEXT,
  rotated_at TIMESTAMPTZ,
  last_used_at TIMESTAMPTZ
);

CREATE TABLE encrypted_secrets (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  purpose TEXT NOT NULL,
  name TEXT NOT NULL,
  metadata_json JSONB DEFAULT '{}',
  rotation INT NOT NULL DEFAULT 0,
  envelope_json JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by TEXT
);

CREATE TABLE agent_update_trust_keys (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  name TEXT NOT NULL,
  public_key_der_base64 TEXT NOT NULL,
  fingerprint_sha256 TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by TEXT,
  revoked_at TIMESTAMPTZ
);

CREATE TABLE agent_update_releases (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  version TEXT NOT NULL,
  channel TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'active',
  manifest_json JSONB NOT NULL DEFAULT '{}',
  signature TEXT,
  distribution_json JSONB DEFAULT '{}',
  rollout_json JSONB DEFAULT '{}',
  rollback_json JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by TEXT,
  rollback_requested_at TIMESTAMPTZ
);

CREATE TABLE agent_update_statuses (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  agent_id TEXT NOT NULL,
  release_id TEXT NOT NULL,
  status TEXT NOT NULL,
  action TEXT,
  installed_version TEXT,
  error_code TEXT,
  recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE high_scale_telemetry (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  high_scale_request_id TEXT NOT NULL,
  category TEXT NOT NULL,
  live_status TEXT,
  observed_at TIMESTAMPTZ NOT NULL,
  source TEXT,
  metrics_json JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  recorded_by TEXT
);

CREATE TABLE soc_reports (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  high_scale_request_id TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_by TEXT,
  impact_summary TEXT DEFAULT '',
  recommendations TEXT DEFAULT '',
  customer_summary TEXT DEFAULT '',
  residual_risk TEXT DEFAULT '',
  next_steps TEXT DEFAULT '',
  attachments_json JSONB DEFAULT '[]',
  evidence_ids TEXT[] DEFAULT '{}',
  derived_json JSONB DEFAULT '{}',
  final_state TEXT
);

CREATE TABLE notification_delivery_attempts (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  notification_event_id TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  channel TEXT NOT NULL,
  destination_preview TEXT,
  status TEXT NOT NULL,
  reason TEXT,
  attempt_number INT,
  max_attempts INT,
  next_retry_at TIMESTAMPTZ,
  provider_error TEXT,
  exhausted BOOLEAN,
  provider_status INT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  attempted_at TIMESTAMPTZ
);

CREATE TABLE production_release_evidence (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  kind TEXT NOT NULL,
  release_id TEXT,
  status TEXT NOT NULL DEFAULT 'accepted',
  evidence_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  notes TEXT,
  validation_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by TEXT
);

CREATE TABLE external_asset_candidates (
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

CREATE TABLE waf_products (
  id TEXT PRIMARY KEY,
  vendor TEXT NOT NULL,
  product TEXT NOT NULL,
  deployment_type TEXT NOT NULL DEFAULT 'unknown',
  fingerprint_version TEXT NOT NULL DEFAULT '1',
  confidence_rules_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  enabled BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE waf_assets (
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
  region_code TEXT,
  geography_label TEXT,
  entity_id TEXT,
  owasp_exposure_tags TEXT[] NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE waf_fingerprints (
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

CREATE TABLE waf_validation_runs (
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

CREATE TABLE waf_scenario_results (
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

CREATE TABLE waf_posture_snapshots (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  waf_asset_id TEXT NOT NULL,
  status TEXT NOT NULL,
  reason_codes TEXT[] NOT NULL DEFAULT '{}',
  detected_vendor TEXT,
  detected_product TEXT,
  coverage_required BOOLEAN NOT NULL DEFAULT TRUE,
  risk_score INT NOT NULL DEFAULT 0,
  risk_factors_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  priority_band TEXT,
  recommended_action TEXT,
  scenario_pass_rate NUMERIC,
  control_bypass_status TEXT,
  confidence NUMERIC NOT NULL DEFAULT 0,
  source_mix_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  is_current BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE waf_coverage_daily_rollups (
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

CREATE TABLE waf_scenario_intakes (
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

CREATE TABLE waf_baselines (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  waf_asset_id TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'proposed',
  baseline_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  approved_by TEXT,
  approved_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE waf_exceptions (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  waf_asset_id TEXT NOT NULL,
  owner TEXT NOT NULL,
  reason TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  scope_hash TEXT,
  approved_at TIMESTAMPTZ NOT NULL,
  approved_by TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE waf_validation_plans (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  target_group_id TEXT NOT NULL,
  mode TEXT NOT NULL DEFAULT 'manual',
  schedule_interval TEXT,
  custom_cron_expression TEXT,
  scenarios_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  max_concurrent INT NOT NULL DEFAULT 1,
  timeout_ms INT NOT NULL DEFAULT 60000,
  state TEXT NOT NULL DEFAULT 'draft',
  delegated_jobs_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  executed_at TIMESTAMPTZ,
  cancelled_at TIMESTAMPTZ,
  execution_lock_token TEXT,
  execution_lock_expires_at TIMESTAMPTZ
);

CREATE TABLE waf_baseline_approvals (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  baseline_id TEXT NOT NULL,
  waf_asset_id TEXT NOT NULL,
  approver TEXT NOT NULL,
  approval_notes TEXT NOT NULL,
  approved_at TIMESTAMPTZ NOT NULL,
  fingerprint_summary_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE waf_retest_requests (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  drift_event_id TEXT NOT NULL,
  waf_asset_id TEXT NOT NULL,
  retest_plan_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  requested_by TEXT NOT NULL,
  priority TEXT NOT NULL DEFAULT 'normal',
  status TEXT NOT NULL DEFAULT 'requested',
  verdict TEXT,
  verdict_reason TEXT,
  delegated_jobs_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ,
  execution_lock_token TEXT,
  execution_lock_expires_at TIMESTAMPTZ
);

COMMENT ON COLUMN waf_validation_plans.delegated_jobs_json IS
  'Delegated safe test runs. Each entry may include status pending_start (reserved before startTestRun), starting (startTestRun succeeded, finalize pending), delegated (persisted with test_run_id), or failed (reconciled or start failure). Legacy entries without status are treated as delegated when test_run_id is present.';

COMMENT ON COLUMN waf_retest_requests.delegated_jobs_json IS
  'Delegated retest safe test runs. Each entry may include status pending_start (reserved before startTestRun), starting (startTestRun succeeded, finalize pending), delegated (persisted with test_run_id), or failed (reconciled or start failure). Legacy entries without status are treated as delegated when test_run_id is present.';

CREATE TABLE waf_drift_events (
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

CREATE TABLE waf_drift_scan_results (
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

CREATE TABLE waf_connectors (
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

CREATE TABLE waf_connector_snapshots (
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

CREATE TABLE cve_pipeline_items (
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

CREATE TABLE cve_asset_matches (
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

CREATE TABLE waf_rule_recommendations (
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

CREATE TABLE discovery_entities (
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

CREATE TABLE supply_chain_risks (
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

CREATE TABLE waf_action_items (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  category TEXT NOT NULL,
  title TEXT NOT NULL,
  asset_display TEXT,
  waf_asset_id TEXT,
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

CREATE TABLE audit_logs (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  sequence BIGINT NOT NULL,
  prev_hash TEXT,
  entry_hash TEXT NOT NULL,
  actor_user_id TEXT,
  actor_role TEXT,
  action TEXT NOT NULL,
  resource_type TEXT,
  resource_id TEXT,
  metadata_json JSONB DEFAULT '{}'
);

CREATE TABLE platform_metrics (
  id TEXT PRIMARY KEY DEFAULT 'global',
  counters_json JSONB NOT NULL DEFAULT '{}',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Tenant-consistent foreign keys: composite UNIQUE (tenant_id, id) on parents; child FKs use (tenant_id, parent_id).
ALTER TABLE environments ADD CONSTRAINT environments_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE users ADD CONSTRAINT users_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE target_groups ADD CONSTRAINT target_groups_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE targets ADD CONSTRAINT targets_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE bootstrap_tokens ADD CONSTRAINT bootstrap_tokens_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE agents ADD CONSTRAINT agents_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE test_runs ADD CONSTRAINT test_runs_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE verdicts ADD CONSTRAINT verdicts_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE events ADD CONSTRAINT events_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE high_scale_requests ADD CONSTRAINT high_scale_requests_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE notification_rules ADD CONSTRAINT notification_rules_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE notification_events ADD CONSTRAINT notification_events_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE service_accounts ADD CONSTRAINT service_accounts_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE encrypted_secrets ADD CONSTRAINT encrypted_secrets_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE agent_update_trust_keys ADD CONSTRAINT agent_update_trust_keys_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE agent_update_releases ADD CONSTRAINT agent_update_releases_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE agent_update_statuses ADD CONSTRAINT agent_update_statuses_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE high_scale_telemetry ADD CONSTRAINT high_scale_telemetry_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE soc_reports ADD CONSTRAINT soc_reports_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE notification_delivery_attempts ADD CONSTRAINT notification_delivery_attempts_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE production_release_evidence ADD CONSTRAINT production_release_evidence_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE findings ADD CONSTRAINT findings_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE waf_assets ADD CONSTRAINT waf_assets_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE waf_validation_runs ADD CONSTRAINT waf_validation_runs_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE waf_baselines ADD CONSTRAINT waf_baselines_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE waf_validation_plans ADD CONSTRAINT waf_validation_plans_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE waf_baseline_approvals ADD CONSTRAINT waf_baseline_approvals_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE waf_retest_requests ADD CONSTRAINT waf_retest_requests_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE waf_drift_events ADD CONSTRAINT waf_drift_events_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE waf_drift_scan_results ADD CONSTRAINT waf_drift_scan_results_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE waf_connectors ADD CONSTRAINT waf_connectors_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE cve_pipeline_items ADD CONSTRAINT cve_pipeline_items_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE cve_asset_matches ADD CONSTRAINT cve_asset_matches_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE discovery_entities ADD CONSTRAINT discovery_entities_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE supply_chain_risks ADD CONSTRAINT supply_chain_risks_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE waf_action_items ADD CONSTRAINT waf_action_items_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE waf_coverage_daily_rollups ADD CONSTRAINT waf_coverage_daily_rollups_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE waf_scenario_intakes ADD CONSTRAINT waf_scenario_intakes_tenant_id_id_key UNIQUE (tenant_id, id);

ALTER TABLE target_groups ADD CONSTRAINT fk_target_groups_environment_tenant
  FOREIGN KEY (tenant_id, environment_id) REFERENCES environments (tenant_id, id);
ALTER TABLE target_groups ADD CONSTRAINT fk_target_groups_owner_user_tenant
  FOREIGN KEY (tenant_id, owner_user_id) REFERENCES users (tenant_id, id);
ALTER TABLE targets ADD CONSTRAINT fk_targets_target_group_tenant
  FOREIGN KEY (tenant_id, target_group_id) REFERENCES target_groups (tenant_id, id);
ALTER TABLE bootstrap_tokens ADD CONSTRAINT fk_bootstrap_tokens_environment_tenant
  FOREIGN KEY (tenant_id, environment_id) REFERENCES environments (tenant_id, id);
ALTER TABLE bootstrap_tokens ADD CONSTRAINT fk_bootstrap_tokens_target_group_tenant
  FOREIGN KEY (tenant_id, target_group_id) REFERENCES target_groups (tenant_id, id);
ALTER TABLE agents ADD CONSTRAINT fk_agents_environment_tenant
  FOREIGN KEY (tenant_id, environment_id) REFERENCES environments (tenant_id, id);
ALTER TABLE agents ADD CONSTRAINT fk_agents_target_group_tenant
  FOREIGN KEY (tenant_id, target_group_id) REFERENCES target_groups (tenant_id, id);
ALTER TABLE agents ADD CONSTRAINT fk_agents_bootstrap_token_tenant
  FOREIGN KEY (tenant_id, bootstrap_token_id) REFERENCES bootstrap_tokens (tenant_id, id);
ALTER TABLE test_runs ADD CONSTRAINT fk_test_runs_target_group_tenant
  FOREIGN KEY (tenant_id, target_group_id) REFERENCES target_groups (tenant_id, id);
ALTER TABLE test_runs ADD CONSTRAINT fk_test_runs_target_tenant
  FOREIGN KEY (tenant_id, target_id) REFERENCES targets (tenant_id, id);
ALTER TABLE probe_jobs ADD CONSTRAINT fk_probe_jobs_test_run_tenant
  FOREIGN KEY (tenant_id, test_run_id) REFERENCES test_runs (tenant_id, id);
ALTER TABLE probe_jobs ADD CONSTRAINT fk_probe_jobs_target_tenant
  FOREIGN KEY (tenant_id, target_id) REFERENCES targets (tenant_id, id);
ALTER TABLE agent_jobs ADD CONSTRAINT fk_agent_jobs_agent_tenant
  FOREIGN KEY (tenant_id, agent_id) REFERENCES agents (tenant_id, id);
ALTER TABLE agent_jobs ADD CONSTRAINT fk_agent_jobs_test_run_tenant
  FOREIGN KEY (tenant_id, test_run_id) REFERENCES test_runs (tenant_id, id);
ALTER TABLE agent_jobs ADD CONSTRAINT fk_agent_jobs_target_tenant
  FOREIGN KEY (tenant_id, target_id) REFERENCES targets (tenant_id, id);
ALTER TABLE events ADD CONSTRAINT fk_events_test_run_tenant
  FOREIGN KEY (tenant_id, test_run_id) REFERENCES test_runs (tenant_id, id);
ALTER TABLE events ADD CONSTRAINT fk_events_target_tenant
  FOREIGN KEY (tenant_id, target_id) REFERENCES targets (tenant_id, id);
ALTER TABLE events ADD CONSTRAINT fk_events_agent_tenant
  FOREIGN KEY (tenant_id, agent_id) REFERENCES agents (tenant_id, id);
ALTER TABLE verdicts ADD CONSTRAINT fk_verdicts_test_run_tenant
  FOREIGN KEY (tenant_id, test_run_id) REFERENCES test_runs (tenant_id, id);
ALTER TABLE verdicts ADD CONSTRAINT fk_verdicts_target_tenant
  FOREIGN KEY (tenant_id, target_id) REFERENCES targets (tenant_id, id);
ALTER TABLE findings ADD CONSTRAINT fk_findings_target_group_tenant
  FOREIGN KEY (tenant_id, target_group_id) REFERENCES target_groups (tenant_id, id);
ALTER TABLE findings ADD CONSTRAINT fk_findings_target_tenant
  FOREIGN KEY (tenant_id, target_id) REFERENCES targets (tenant_id, id);
ALTER TABLE findings ADD CONSTRAINT fk_findings_test_run_tenant
  FOREIGN KEY (tenant_id, test_run_id) REFERENCES test_runs (tenant_id, id);
ALTER TABLE findings ADD CONSTRAINT fk_findings_verdict_tenant
  FOREIGN KEY (tenant_id, verdict_id) REFERENCES verdicts (tenant_id, id);
ALTER TABLE findings ADD CONSTRAINT fk_findings_last_verdict_tenant
  FOREIGN KEY (tenant_id, last_verdict_id) REFERENCES verdicts (tenant_id, id);
ALTER TABLE evidence_vault ADD CONSTRAINT fk_evidence_vault_test_run_tenant
  FOREIGN KEY (tenant_id, test_run_id) REFERENCES test_runs (tenant_id, id);
ALTER TABLE evidence_vault ADD CONSTRAINT fk_evidence_vault_related_event_tenant
  FOREIGN KEY (tenant_id, related_event_id) REFERENCES events (tenant_id, id);
ALTER TABLE high_scale_requests ADD CONSTRAINT fk_high_scale_requests_target_group_tenant
  FOREIGN KEY (tenant_id, target_group_id) REFERENCES target_groups (tenant_id, id);
ALTER TABLE authorization_artifacts ADD CONSTRAINT fk_authorization_artifacts_high_scale_request_tenant
  FOREIGN KEY (tenant_id, high_scale_request_id) REFERENCES high_scale_requests (tenant_id, id);
ALTER TABLE soc_notes ADD CONSTRAINT fk_soc_notes_high_scale_request_tenant
  FOREIGN KEY (tenant_id, high_scale_request_id) REFERENCES high_scale_requests (tenant_id, id);
ALTER TABLE notification_events ADD CONSTRAINT fk_notification_events_rule_tenant
  FOREIGN KEY (tenant_id, rule_id) REFERENCES notification_rules (tenant_id, id);
ALTER TABLE agent_update_statuses ADD CONSTRAINT fk_agent_update_statuses_agent_tenant
  FOREIGN KEY (tenant_id, agent_id) REFERENCES agents (tenant_id, id);
ALTER TABLE agent_update_statuses ADD CONSTRAINT fk_agent_update_statuses_release_tenant
  FOREIGN KEY (tenant_id, release_id) REFERENCES agent_update_releases (tenant_id, id);
ALTER TABLE high_scale_telemetry ADD CONSTRAINT fk_high_scale_telemetry_high_scale_request_tenant
  FOREIGN KEY (tenant_id, high_scale_request_id) REFERENCES high_scale_requests (tenant_id, id);
ALTER TABLE soc_reports ADD CONSTRAINT fk_soc_reports_high_scale_request_tenant
  FOREIGN KEY (tenant_id, high_scale_request_id) REFERENCES high_scale_requests (tenant_id, id);
ALTER TABLE notification_delivery_attempts ADD CONSTRAINT fk_notification_delivery_attempts_event_tenant
  FOREIGN KEY (tenant_id, notification_event_id) REFERENCES notification_events (tenant_id, id);
ALTER TABLE notification_delivery_attempts ADD CONSTRAINT fk_notification_delivery_attempts_rule_tenant
  FOREIGN KEY (tenant_id, rule_id) REFERENCES notification_rules (tenant_id, id);
ALTER TABLE external_asset_candidates ADD CONSTRAINT fk_external_asset_candidates_approved_target_tenant
  FOREIGN KEY (tenant_id, approved_target_id) REFERENCES targets (tenant_id, id);
ALTER TABLE external_asset_candidates ADD CONSTRAINT fk_external_asset_candidates_entity
  FOREIGN KEY (tenant_id, entity_id) REFERENCES discovery_entities (tenant_id, id);
ALTER TABLE waf_assets ADD CONSTRAINT fk_waf_assets_target_group_tenant
  FOREIGN KEY (tenant_id, target_group_id) REFERENCES target_groups (tenant_id, id);
ALTER TABLE waf_assets ADD CONSTRAINT fk_waf_assets_target_tenant
  FOREIGN KEY (tenant_id, target_id) REFERENCES targets (tenant_id, id);
ALTER TABLE waf_assets ADD CONSTRAINT fk_waf_assets_environment_tenant
  FOREIGN KEY (tenant_id, environment_id) REFERENCES environments (tenant_id, id);
ALTER TABLE waf_assets ADD CONSTRAINT fk_waf_assets_entity_tenant
  FOREIGN KEY (tenant_id, entity_id) REFERENCES discovery_entities (tenant_id, id);
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
ALTER TABLE waf_exceptions ADD CONSTRAINT waf_exceptions_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE waf_exceptions ADD CONSTRAINT fk_waf_exceptions_waf_asset_tenant
  FOREIGN KEY (tenant_id, waf_asset_id) REFERENCES waf_assets (tenant_id, id);
ALTER TABLE waf_validation_plans ADD CONSTRAINT fk_waf_validation_plans_target_group_tenant
  FOREIGN KEY (tenant_id, target_group_id) REFERENCES target_groups (tenant_id, id);
ALTER TABLE waf_baseline_approvals ADD CONSTRAINT fk_waf_baseline_approvals_baseline_tenant
  FOREIGN KEY (tenant_id, baseline_id) REFERENCES waf_baselines (tenant_id, id);
ALTER TABLE waf_baseline_approvals ADD CONSTRAINT fk_waf_baseline_approvals_waf_asset_tenant
  FOREIGN KEY (tenant_id, waf_asset_id) REFERENCES waf_assets (tenant_id, id);
ALTER TABLE waf_retest_requests ADD CONSTRAINT fk_waf_retest_requests_drift_event_tenant
  FOREIGN KEY (tenant_id, drift_event_id) REFERENCES waf_drift_events (tenant_id, id);
ALTER TABLE waf_retest_requests ADD CONSTRAINT fk_waf_retest_requests_waf_asset_tenant
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
ALTER TABLE waf_action_items ADD CONSTRAINT fk_waf_action_items_cve_pipeline_item_tenant
  FOREIGN KEY (tenant_id, cve_pipeline_item_id) REFERENCES cve_pipeline_items (tenant_id, id);
ALTER TABLE waf_action_items ADD CONSTRAINT fk_waf_action_items_waf_asset_tenant
  FOREIGN KEY (tenant_id, waf_asset_id) REFERENCES waf_assets (tenant_id, id);

CREATE INDEX idx_environments_tenant ON environments(tenant_id);
CREATE UNIQUE INDEX uniq_signup_requests_active_domain ON signup_requests(email_domain) WHERE state <> 'rejected';
CREATE UNIQUE INDEX uniq_signup_requests_active_org ON signup_requests(lower(organization_name)) WHERE state <> 'rejected';
CREATE INDEX idx_signup_requests_state_created ON signup_requests(state, created_at DESC);
CREATE INDEX idx_internal_approval_requests_queue ON internal_approval_requests(state, kind, created_at DESC);
CREATE INDEX idx_internal_audit_log_tenant_created ON internal_audit_log(tenant_id, created_at DESC);
CREATE INDEX idx_internal_audit_log_staff_created ON internal_audit_log(staff_id, created_at DESC);
CREATE INDEX idx_target_groups_tenant ON target_groups(tenant_id);
CREATE INDEX idx_ownership_verifications_tenant_target ON ownership_verifications(tenant_id, target_group_id);
CREATE INDEX idx_test_policies_tenant_active ON test_policies(tenant_id, target_group_id) WHERE archived_at IS NULL;
CREATE INDEX idx_targets_tenant_group ON targets(tenant_id, target_group_id);
CREATE INDEX idx_agents_tenant_heartbeat ON agents(tenant_id, last_heartbeat_at);
CREATE INDEX idx_agents_tenant_group ON agents(tenant_id, target_group_id);
CREATE INDEX idx_test_runs_tenant ON test_runs(tenant_id, target_group_id);
CREATE INDEX idx_agent_jobs ON agent_jobs(tenant_id, agent_id, status, created_at);
CREATE INDEX idx_probe_jobs_status_leased ON probe_jobs(status, leased_at, created_at);
CREATE INDEX idx_probe_jobs_tenant_run ON probe_jobs(tenant_id, test_run_id);
CREATE UNIQUE INDEX uniq_verdict_per_test_run ON verdicts(test_run_id);
CREATE UNIQUE INDEX uniq_active_test_run ON test_runs(tenant_id, target_group_id)
  WHERE status IN ('planned', 'running', 'collecting');
CREATE INDEX idx_events_correlation ON events(tenant_id, test_run_id, signal_type, nonce_hash, timestamp);
CREATE UNIQUE INDEX uniq_events_tenant_event_id ON events(tenant_id, event_id) WHERE event_id IS NOT NULL;
CREATE INDEX idx_findings_tenant_status ON findings(tenant_id, status, severity);
CREATE UNIQUE INDEX uniq_audit_tenant_sequence ON audit_logs(tenant_id, sequence);
CREATE INDEX idx_audit_tenant_time ON audit_logs(tenant_id, timestamp);
CREATE INDEX idx_hs_requests_tenant_state ON high_scale_requests(tenant_id, state);
CREATE INDEX idx_service_accounts_tenant_role ON service_accounts(tenant_id, role);
CREATE INDEX idx_agent_update_releases_tenant_state ON agent_update_releases(tenant_id, state);
CREATE INDEX idx_agent_update_statuses_tenant_agent ON agent_update_statuses(tenant_id, agent_id, recorded_at);
CREATE UNIQUE INDEX uniq_active_agent_update_trust_key_fingerprint
  ON agent_update_trust_keys(tenant_id, fingerprint_sha256) WHERE status = 'active';
CREATE INDEX idx_high_scale_telemetry_request_observed
  ON high_scale_telemetry(tenant_id, high_scale_request_id, observed_at);
CREATE UNIQUE INDEX uniq_soc_report_per_high_scale_request ON soc_reports(tenant_id, high_scale_request_id);
CREATE INDEX idx_notification_delivery_attempts_event ON notification_delivery_attempts(tenant_id, notification_event_id);
CREATE INDEX idx_production_release_evidence_tenant_kind_created
  ON production_release_evidence(tenant_id, kind, created_at DESC);
CREATE INDEX idx_test_runs_tenant_created ON test_runs(tenant_id, created_at DESC);
CREATE INDEX idx_test_runs_tenant_group_created ON test_runs(tenant_id, target_group_id, created_at DESC);
CREATE INDEX idx_events_tenant_run_time ON events(tenant_id, test_run_id, timestamp);
CREATE INDEX idx_evidence_vault_tenant_run_created ON evidence_vault(tenant_id, test_run_id, created_at DESC);
CREATE INDEX idx_evidence_vault_tenant_related_event ON evidence_vault(tenant_id, related_event_id);
CREATE UNIQUE INDEX uniq_findings_open_target_check ON findings(tenant_id, target_group_id, target_id, check_id) WHERE status = 'open';
CREATE UNIQUE INDEX uniq_probe_result_per_run_nonce ON events(tenant_id, test_run_id, signal_type, nonce_hash) WHERE signal_type = 'probe_result' AND nonce_hash IS NOT NULL;
CREATE INDEX idx_waf_assets_tenant_group_url ON waf_assets(tenant_id, target_group_id, canonical_url);
CREATE INDEX idx_external_asset_candidates_approval_queue ON external_asset_candidates(tenant_id, approval_status, confidence DESC);
CREATE UNIQUE INDEX uniq_waf_posture_snapshot_current ON waf_posture_snapshots(tenant_id, waf_asset_id) WHERE is_current = TRUE;
CREATE INDEX idx_waf_posture_snapshots_dashboard ON waf_posture_snapshots(tenant_id, status, created_at DESC);
CREATE INDEX idx_waf_drift_events_queue ON waf_drift_events(tenant_id, drift_type, status, created_at DESC);
CREATE INDEX idx_waf_drift_scan_results_latest ON waf_drift_scan_results(tenant_id, completed_at DESC);
CREATE UNIQUE INDEX uniq_waf_coverage_daily_rollups_tenant_date ON waf_coverage_daily_rollups(tenant_id, rollup_date);
CREATE INDEX idx_waf_coverage_daily_rollups_tenant_date ON waf_coverage_daily_rollups(tenant_id, rollup_date DESC);
CREATE INDEX idx_waf_validation_plans_tenant_state ON waf_validation_plans(tenant_id, state, created_at DESC);
CREATE INDEX idx_waf_validation_plans_scheduled ON waf_validation_plans(tenant_id, created_at DESC) WHERE state = 'scheduled';
CREATE INDEX idx_waf_retest_requests_drift ON waf_retest_requests(tenant_id, drift_event_id, created_at DESC);
CREATE INDEX idx_waf_validation_plans_execution_lock ON waf_validation_plans(tenant_id, execution_lock_expires_at) WHERE execution_lock_token IS NOT NULL;
CREATE INDEX idx_waf_retest_requests_execution_lock ON waf_retest_requests(tenant_id, execution_lock_expires_at) WHERE execution_lock_token IS NOT NULL;
CREATE INDEX idx_waf_baseline_approvals_baseline ON waf_baseline_approvals(tenant_id, baseline_id, created_at DESC);
CREATE INDEX idx_waf_exceptions_tenant_expires ON waf_exceptions(tenant_id, expires_at);
CREATE INDEX idx_waf_exceptions_tenant_asset ON waf_exceptions(tenant_id, waf_asset_id);
CREATE INDEX idx_waf_connector_snapshots_history ON waf_connector_snapshots(tenant_id, connector_id, provider, observed_at DESC);
CREATE INDEX idx_cve_pipeline_items_lookup ON cve_pipeline_items(tenant_id, cve_id);
CREATE UNIQUE INDEX uniq_cve_asset_matches_dedupe ON cve_asset_matches(tenant_id, cve_pipeline_item_id, waf_asset_id);
CREATE INDEX idx_supply_chain_risks_lookup ON supply_chain_risks(tenant_id, state, severity);
CREATE INDEX idx_waf_action_items_status ON waf_action_items(tenant_id, status, severity);
CREATE INDEX idx_discovery_entities_lookup ON discovery_entities(tenant_id, entity_type);
CREATE UNIQUE INDEX uniq_supply_chain_risks_dedupe ON supply_chain_risks(tenant_id, hostname, exposure_type);
CREATE UNIQUE INDEX uniq_waf_action_items_dedupe ON waf_action_items(tenant_id, waf_asset_id, primary_reason);

-- Row level security: app code must set app.tenant_id via set_config inside each transaction
-- once the Postgres adapter exists. Empty/unset setting denies tenant-scoped rows (fail closed).
-- FORCE RLS applies policies even to table owners; runtime role must be non-owner and not BYPASSRLS.

ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
ALTER TABLE environments ENABLE ROW LEVEL SECURITY;
ALTER TABLE environments FORCE ROW LEVEL SECURITY;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;
ALTER TABLE tenant_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_accounts FORCE ROW LEVEL SECURITY;
ALTER TABLE tenant_subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_subscriptions FORCE ROW LEVEL SECURITY;
ALTER TABLE entitlement_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE entitlement_grants FORCE ROW LEVEL SECURITY;
ALTER TABLE internal_approval_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE internal_approval_requests FORCE ROW LEVEL SECURITY;
ALTER TABLE internal_audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE internal_audit_log FORCE ROW LEVEL SECURITY;
ALTER TABLE target_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE target_groups FORCE ROW LEVEL SECURITY;
ALTER TABLE targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE targets FORCE ROW LEVEL SECURITY;
ALTER TABLE bootstrap_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE bootstrap_tokens FORCE ROW LEVEL SECURITY;
ALTER TABLE agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE agents FORCE ROW LEVEL SECURITY;
ALTER TABLE test_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE test_runs FORCE ROW LEVEL SECURITY;
ALTER TABLE probe_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE probe_jobs FORCE ROW LEVEL SECURITY;
ALTER TABLE ownership_verifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE ownership_verifications FORCE ROW LEVEL SECURITY;
ALTER TABLE test_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE test_policies FORCE ROW LEVEL SECURITY;
ALTER TABLE agent_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_jobs FORCE ROW LEVEL SECURITY;
ALTER TABLE events ENABLE ROW LEVEL SECURITY;
ALTER TABLE events FORCE ROW LEVEL SECURITY;
ALTER TABLE verdicts ENABLE ROW LEVEL SECURITY;
ALTER TABLE verdicts FORCE ROW LEVEL SECURITY;
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings FORCE ROW LEVEL SECURITY;
ALTER TABLE evidence_vault ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence_vault FORCE ROW LEVEL SECURITY;
ALTER TABLE reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE reports FORCE ROW LEVEL SECURITY;
ALTER TABLE high_scale_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE high_scale_requests FORCE ROW LEVEL SECURITY;
ALTER TABLE authorization_artifacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE authorization_artifacts FORCE ROW LEVEL SECURITY;
ALTER TABLE soc_notes ENABLE ROW LEVEL SECURITY;
ALTER TABLE soc_notes FORCE ROW LEVEL SECURITY;
ALTER TABLE soc_kill_switch ENABLE ROW LEVEL SECURITY;
ALTER TABLE soc_kill_switch FORCE ROW LEVEL SECURITY;
ALTER TABLE notification_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_rules FORCE ROW LEVEL SECURITY;
ALTER TABLE notification_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_events FORCE ROW LEVEL SECURITY;
ALTER TABLE service_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE service_accounts FORCE ROW LEVEL SECURITY;
ALTER TABLE encrypted_secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE encrypted_secrets FORCE ROW LEVEL SECURITY;
ALTER TABLE agent_update_trust_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_update_trust_keys FORCE ROW LEVEL SECURITY;
ALTER TABLE agent_update_releases ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_update_releases FORCE ROW LEVEL SECURITY;
ALTER TABLE agent_update_statuses ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_update_statuses FORCE ROW LEVEL SECURITY;
ALTER TABLE high_scale_telemetry ENABLE ROW LEVEL SECURITY;
ALTER TABLE high_scale_telemetry FORCE ROW LEVEL SECURITY;
ALTER TABLE soc_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE soc_reports FORCE ROW LEVEL SECURITY;
ALTER TABLE notification_delivery_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_delivery_attempts FORCE ROW LEVEL SECURITY;
ALTER TABLE production_release_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE production_release_evidence FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs FORCE ROW LEVEL SECURITY;
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
ALTER TABLE waf_exceptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_exceptions FORCE ROW LEVEL SECURITY;
ALTER TABLE waf_validation_plans ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_validation_plans FORCE ROW LEVEL SECURITY;
ALTER TABLE waf_baseline_approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_baseline_approvals FORCE ROW LEVEL SECURITY;
ALTER TABLE waf_retest_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_retest_requests FORCE ROW LEVEL SECURITY;
ALTER TABLE waf_drift_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_drift_events FORCE ROW LEVEL SECURITY;
ALTER TABLE waf_drift_scan_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_drift_scan_results FORCE ROW LEVEL SECURITY;
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
ALTER TABLE discovery_entities ENABLE ROW LEVEL SECURITY;
ALTER TABLE discovery_entities FORCE ROW LEVEL SECURITY;
ALTER TABLE supply_chain_risks ENABLE ROW LEVEL SECURITY;
ALTER TABLE supply_chain_risks FORCE ROW LEVEL SECURITY;
ALTER TABLE waf_action_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_action_items FORCE ROW LEVEL SECURITY;
ALTER TABLE waf_coverage_daily_rollups ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_coverage_daily_rollups FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_tenants ON tenants
  USING (id = current_setting('app.tenant_id', true))
  WITH CHECK (id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_environments ON environments
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_users ON users
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_target_groups ON target_groups
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_targets ON targets
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_bootstrap_tokens ON bootstrap_tokens
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_agents ON agents
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_test_runs ON test_runs
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_probe_jobs ON probe_jobs
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_ownership_verifications ON ownership_verifications
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_test_policies ON test_policies
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_agent_jobs ON agent_jobs
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_events ON events
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_verdicts ON verdicts
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_findings ON findings
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_evidence_vault ON evidence_vault
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_reports ON reports
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_high_scale_requests ON high_scale_requests
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_authorization_artifacts ON authorization_artifacts
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_soc_notes ON soc_notes
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_soc_kill_switch ON soc_kill_switch
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_notification_rules ON notification_rules
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_notification_events ON notification_events
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_service_accounts ON service_accounts
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_encrypted_secrets ON encrypted_secrets
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_agent_update_trust_keys ON agent_update_trust_keys
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_agent_update_releases ON agent_update_releases
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_agent_update_statuses ON agent_update_statuses
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_high_scale_telemetry ON high_scale_telemetry
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_soc_reports ON soc_reports
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_notification_delivery_attempts ON notification_delivery_attempts
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_production_release_evidence ON production_release_evidence
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_audit_logs ON audit_logs
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
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
CREATE POLICY tenant_isolation_waf_exceptions ON waf_exceptions
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_waf_validation_plans ON waf_validation_plans
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_waf_baseline_approvals ON waf_baseline_approvals
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_waf_retest_requests ON waf_retest_requests
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_waf_drift_events ON waf_drift_events
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_waf_drift_scan_results ON waf_drift_scan_results
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
CREATE POLICY tenant_isolation_discovery_entities ON discovery_entities
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_supply_chain_risks ON supply_chain_risks
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_waf_action_items ON waf_action_items
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_isolation_waf_coverage_daily_rollups ON waf_coverage_daily_rollups
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
ALTER TABLE waf_scenario_intakes ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_scenario_intakes FORCE ROW LEVEL SECURITY;
CREATE INDEX idx_waf_scenario_intakes_tenant_created ON waf_scenario_intakes(tenant_id, created_at DESC);
CREATE POLICY tenant_isolation_waf_scenario_intakes ON waf_scenario_intakes
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
