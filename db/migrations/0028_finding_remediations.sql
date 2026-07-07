-- 0028_finding_remediations.sql
-- Portal revamp: per-finding remediation panel (§2.4) with RLS (FT-RLS-01).

CREATE TABLE IF NOT EXISTS finding_remediations (
  id              TEXT PRIMARY KEY,
  tenant_id       TEXT NOT NULL,
  finding_id      TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  action_slug     TEXT NOT NULL,
  owner_group     TEXT NOT NULL,
  state           TEXT NOT NULL DEFAULT 'open'
                  CHECK (state IN ('open', 'in_progress', 'delivered', 'accepted_risk', 'resolved')),
  sla_hours       INTEGER,
  sla_deadline    TIMESTAMPTZ,
  description     TEXT NOT NULL,
  steps           TEXT[] NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  delivered_at    TIMESTAMPTZ,
  delivered_via   TEXT,
  delivered_ref   TEXT,
  audit_entry_id  TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS finding_remediations_by_finding
  ON finding_remediations(finding_id);
CREATE INDEX IF NOT EXISTS finding_remediations_sla
  ON finding_remediations(tenant_id, state, sla_deadline)
  WHERE state IN ('open', 'in_progress');

ALTER TABLE finding_remediations ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding_remediations FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS finding_remediations_tenant_isolation ON finding_remediations;
CREATE POLICY finding_remediations_tenant_isolation ON finding_remediations
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));