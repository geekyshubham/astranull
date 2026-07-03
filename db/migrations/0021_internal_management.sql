-- Public sign-up intake and staff-only internal management.
-- Public records are reviewed by AstraNull staff before tenant provisioning.

CREATE TABLE IF NOT EXISTS signup_requests (
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

CREATE UNIQUE INDEX IF NOT EXISTS uniq_signup_requests_active_domain
  ON signup_requests(email_domain)
  WHERE state <> 'rejected';

CREATE UNIQUE INDEX IF NOT EXISTS uniq_signup_requests_active_org
  ON signup_requests(lower(organization_name))
  WHERE state <> 'rejected';

CREATE INDEX IF NOT EXISTS idx_signup_requests_state_created
  ON signup_requests(state, created_at DESC);

CREATE TABLE IF NOT EXISTS staff_users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  display_name TEXT,
  staff_roles TEXT[] NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'active',
  last_login_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS tenant_accounts (
  tenant_id TEXT PRIMARY KEY REFERENCES tenants(id),
  legal_name TEXT,
  support_owner TEXT,
  region TEXT NOT NULL DEFAULT 'us',
  lifecycle_state TEXT NOT NULL DEFAULT 'active',
  contract_reference TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS tenant_subscriptions (
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

CREATE TABLE IF NOT EXISTS entitlement_grants (
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

CREATE TABLE IF NOT EXISTS internal_approval_requests (
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

CREATE INDEX IF NOT EXISTS idx_internal_approval_requests_queue
  ON internal_approval_requests(state, kind, created_at DESC);

CREATE TABLE IF NOT EXISTS internal_audit_log (
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

CREATE INDEX IF NOT EXISTS idx_internal_audit_log_tenant_created
  ON internal_audit_log(tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_internal_audit_log_staff_created
  ON internal_audit_log(staff_id, created_at DESC);

ALTER TABLE tenant_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_accounts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_accounts_isolation ON tenant_accounts;
CREATE POLICY tenant_accounts_isolation ON tenant_accounts
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE tenant_subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_subscriptions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_subscriptions_isolation ON tenant_subscriptions;
CREATE POLICY tenant_subscriptions_isolation ON tenant_subscriptions
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE entitlement_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE entitlement_grants FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS entitlement_grants_isolation ON entitlement_grants;
CREATE POLICY entitlement_grants_isolation ON entitlement_grants
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE internal_approval_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE internal_approval_requests FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS internal_approval_requests_isolation ON internal_approval_requests;
CREATE POLICY internal_approval_requests_isolation ON internal_approval_requests
  USING (tenant_id IS NULL OR tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id IS NULL OR tenant_id = current_setting('app.tenant_id', true));

ALTER TABLE internal_audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE internal_audit_log FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS internal_audit_log_isolation ON internal_audit_log;
CREATE POLICY internal_audit_log_isolation ON internal_audit_log
  USING (tenant_id IS NULL OR tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id IS NULL OR tenant_id = current_setting('app.tenant_id', true));
