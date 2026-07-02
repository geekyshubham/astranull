-- 0002_production_ledgers.sql
-- Additive production ledgers aligned with dev store (src/store.mjs). Schema coverage only — runtime Postgres adapter not wired.

ALTER TABLE high_scale_requests ADD COLUMN IF NOT EXISTS requested_window JSONB DEFAULT '{}';
ALTER TABLE high_scale_requests ADD COLUMN IF NOT EXISTS emergency_contacts JSONB DEFAULT '[]';
ALTER TABLE high_scale_requests ADD COLUMN IF NOT EXISTS scope_confirmation BOOLEAN DEFAULT FALSE;
ALTER TABLE high_scale_requests ADD COLUMN IF NOT EXISTS created_by TEXT;
ALTER TABLE high_scale_requests ADD COLUMN IF NOT EXISTS audit_trail JSONB DEFAULT '[]';
ALTER TABLE high_scale_requests ADD COLUMN IF NOT EXISTS artifacts JSONB DEFAULT '[]';
ALTER TABLE high_scale_requests ADD COLUMN IF NOT EXISTS soc_approvals JSONB DEFAULT '[]';
ALTER TABLE high_scale_requests ADD COLUMN IF NOT EXISTS provider_approval_checklist JSONB DEFAULT '[]';
ALTER TABLE high_scale_requests ADD COLUMN IF NOT EXISTS adapter_json JSONB DEFAULT '{}';

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
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  attempted_at TIMESTAMPTZ
);

ALTER TABLE notification_events ADD CONSTRAINT notification_events_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE service_accounts ADD CONSTRAINT service_accounts_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE encrypted_secrets ADD CONSTRAINT encrypted_secrets_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE agent_update_trust_keys ADD CONSTRAINT agent_update_trust_keys_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE agent_update_releases ADD CONSTRAINT agent_update_releases_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE agent_update_statuses ADD CONSTRAINT agent_update_statuses_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE high_scale_telemetry ADD CONSTRAINT high_scale_telemetry_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE soc_reports ADD CONSTRAINT soc_reports_tenant_id_id_key UNIQUE (tenant_id, id);
ALTER TABLE notification_delivery_attempts ADD CONSTRAINT notification_delivery_attempts_tenant_id_id_key UNIQUE (tenant_id, id);

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

CREATE INDEX idx_service_accounts_tenant_role ON service_accounts(tenant_id, role);
CREATE INDEX idx_agent_update_releases_tenant_state ON agent_update_releases(tenant_id, state);
CREATE INDEX idx_agent_update_statuses_tenant_agent ON agent_update_statuses(tenant_id, agent_id, recorded_at);
CREATE UNIQUE INDEX uniq_active_agent_update_trust_key_fingerprint
  ON agent_update_trust_keys(tenant_id, fingerprint_sha256) WHERE status = 'active';
CREATE INDEX idx_high_scale_telemetry_request_observed
  ON high_scale_telemetry(tenant_id, high_scale_request_id, observed_at);
CREATE UNIQUE INDEX uniq_soc_report_per_high_scale_request ON soc_reports(tenant_id, high_scale_request_id);
CREATE INDEX idx_notification_delivery_attempts_event ON notification_delivery_attempts(tenant_id, notification_event_id);

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