-- 0001_core_validation_loop.sql
-- Production schema contract for the hardened core validation loop (dev store: src/store.mjs).
-- Runtime Postgres adapter is not wired; apply via migration runner when available.
-- App code must set_config('app.tenant_id', ..., true) inside transactions when using RLS-backed queries.

CREATE TABLE schema_migrations (
  version TEXT PRIMARY KEY,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO schema_migrations (version) VALUES ('0001_core_validation_loop');

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
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE agent_jobs (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  agent_id TEXT NOT NULL,
  test_run_id TEXT,
  check_id TEXT,
  target_id TEXT,
  job_type TEXT NOT NULL DEFAULT 'observe_window',
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
  scope_hash TEXT,
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
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

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
  enabled BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE notification_events (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  rule_id TEXT,
  trigger TEXT,
  subject TEXT,
  delivery_status TEXT DEFAULT 'metadata_only',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
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
ALTER TABLE events ADD CONSTRAINT events_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE high_scale_requests ADD CONSTRAINT high_scale_requests_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE notification_rules ADD CONSTRAINT notification_rules_tenant_id_id_key UNIQUE (tenant_id, id);

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

CREATE INDEX idx_environments_tenant ON environments(tenant_id);
CREATE INDEX idx_target_groups_tenant ON target_groups(tenant_id);
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

-- Row level security: app code must set app.tenant_id via set_config inside each transaction
-- once the Postgres adapter exists. Empty/unset setting denies tenant-scoped rows (fail closed).
-- FORCE RLS applies policies even to table owners; runtime role must be non-owner and not BYPASSRLS.

ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
ALTER TABLE environments ENABLE ROW LEVEL SECURITY;
ALTER TABLE environments FORCE ROW LEVEL SECURITY;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;
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
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs FORCE ROW LEVEL SECURITY;

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
CREATE POLICY tenant_isolation_audit_logs ON audit_logs
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));