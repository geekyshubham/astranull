-- 0007_production_release_evidence.sql
-- Tenant-scoped release-gate evidence ledger for production readiness signoff references.

CREATE TABLE IF NOT EXISTS production_release_evidence (
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

ALTER TABLE production_release_evidence
  ADD CONSTRAINT production_release_evidence_tenant_id_id_key UNIQUE (tenant_id, id);

CREATE INDEX IF NOT EXISTS idx_production_release_evidence_tenant_kind_created
  ON production_release_evidence(tenant_id, kind, created_at DESC);

ALTER TABLE production_release_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE production_release_evidence FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_production_release_evidence ON production_release_evidence
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
