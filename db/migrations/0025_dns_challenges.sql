-- 0025_dns_challenges.sql
-- Portal revamp: DNS TXT ownership challenges (docs/ux/16-portal-revamp-backend-spec.md §2.1).

CREATE TABLE IF NOT EXISTS dns_challenges (
  id                TEXT PRIMARY KEY,
  tenant_id         TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  target_group_id   TEXT NOT NULL REFERENCES target_groups(id) ON DELETE CASCADE,
  target_id         TEXT REFERENCES targets(id) ON DELETE CASCADE,
  record_name       TEXT NOT NULL,
  record_value      TEXT NOT NULL,
  ttl_seconds       INTEGER NOT NULL DEFAULT 60,
  state             TEXT NOT NULL DEFAULT 'pending'
                    CHECK (state IN ('pending', 'resolved', 'expired', 'revoked')),
  issued_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  resolved_at       TIMESTAMPTZ,
  last_checked_at   TIMESTAMPTZ,
  last_check_result JSONB,
  expires_at        TIMESTAMPTZ NOT NULL,
  audit_entry_id    TEXT
);

CREATE INDEX IF NOT EXISTS dns_challenges_by_group
  ON dns_challenges(tenant_id, target_group_id, state);
CREATE INDEX IF NOT EXISTS dns_challenges_by_target
  ON dns_challenges(tenant_id, target_id) WHERE target_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS dns_challenges_expiring
  ON dns_challenges(state, expires_at) WHERE state = 'pending';

ALTER TABLE dns_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE dns_challenges FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS dns_challenges_tenant_isolation ON dns_challenges;
CREATE POLICY dns_challenges_tenant_isolation ON dns_challenges
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));