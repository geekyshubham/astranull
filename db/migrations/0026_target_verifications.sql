-- 0026_target_verifications.sql
-- Portal revamp: target verification state machine ledger (§2.2).

CREATE TABLE IF NOT EXISTS target_verifications (
  id               TEXT PRIMARY KEY,
  tenant_id        TEXT NOT NULL,
  target_id        TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  state            TEXT NOT NULL
                   CHECK (state IN ('unverified', 'pending', 'dns_verified', 'agent_verified', 'user_confirmed')),
  source_kind      TEXT NOT NULL
                   CHECK (source_kind IN ('dns_txt', 'agent_observation', 'user_attestation', 'manual_override')),
  source_ref       JSONB NOT NULL,
  transitioned_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  transitioned_by  TEXT NOT NULL,
  audit_entry_id   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS target_verifications_latest
  ON target_verifications(target_id, transitioned_at DESC);
CREATE INDEX IF NOT EXISTS target_verifications_tenant
  ON target_verifications(tenant_id, state);

CREATE OR REPLACE VIEW target_verification_current AS
  SELECT DISTINCT ON (target_id)
    target_id, tenant_id, state, source_kind, source_ref, transitioned_at
  FROM target_verifications
  ORDER BY target_id, transitioned_at DESC;

ALTER TABLE target_verifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE target_verifications FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS target_verifications_tenant_isolation ON target_verifications;
CREATE POLICY target_verifications_tenant_isolation ON target_verifications
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));