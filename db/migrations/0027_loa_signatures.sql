-- 0027_loa_signatures.sql
-- Portal revamp: LOA signature metadata (§2.3).

CREATE TABLE IF NOT EXISTS loa_signatures (
  id                    TEXT PRIMARY KEY,
  tenant_id             TEXT NOT NULL,
  target_group_id       TEXT NOT NULL REFERENCES target_groups(id) ON DELETE CASCADE,
  state                 TEXT NOT NULL DEFAULT 'signed'
                        CHECK (state IN ('signed', 'revoked', 'expired', 'superseded')),
  signer_name           TEXT NOT NULL,
  signer_title          TEXT NOT NULL,
  signer_email          TEXT NOT NULL,
  signed_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at            TIMESTAMPTZ,
  emergency_contact     JSONB NOT NULL,
  attested              BOOLEAN NOT NULL,
  scope_snapshot        JSONB NOT NULL,
  custody_artifact_id   TEXT NOT NULL,
  custody_digest_sha256 TEXT NOT NULL,
  soc_countersign_id    TEXT,
  soc_countersigned_at  TIMESTAMPTZ,
  audit_entry_id        TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS loa_signatures_active
  ON loa_signatures(target_group_id)
  WHERE state = 'signed';

CREATE INDEX IF NOT EXISTS loa_signatures_expiring
  ON loa_signatures(expires_at)
  WHERE state = 'signed' AND expires_at IS NOT NULL;

ALTER TABLE loa_signatures ENABLE ROW LEVEL SECURITY;
ALTER TABLE loa_signatures FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS loa_signatures_tenant_isolation ON loa_signatures;
CREATE POLICY loa_signatures_tenant_isolation ON loa_signatures
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));