-- 0024_ownership_verifications.sql
-- AG-017/AG-018: ownership verification ledger + target group ownership columns.

CREATE TABLE IF NOT EXISTS ownership_verifications (
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

CREATE INDEX IF NOT EXISTS idx_ownership_verifications_tenant_target
  ON ownership_verifications(tenant_id, target_group_id);

ALTER TABLE target_groups ADD COLUMN IF NOT EXISTS validation_mode TEXT;
ALTER TABLE target_groups ADD COLUMN IF NOT EXISTS ownership_status TEXT;
ALTER TABLE target_groups ADD COLUMN IF NOT EXISTS dns_ownership JSONB;

ALTER TABLE probe_jobs ADD COLUMN IF NOT EXISTS ownership_verification_id TEXT;

ALTER TABLE ownership_verifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE ownership_verifications FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_ownership_verifications ON ownership_verifications
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));