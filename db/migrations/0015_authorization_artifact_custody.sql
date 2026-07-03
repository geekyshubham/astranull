-- 0015_authorization_artifact_custody.sql
-- Durable metadata-only custody ledger columns for authorization proof artifacts.

ALTER TABLE authorization_artifacts
  ADD COLUMN IF NOT EXISTS content_sha256 TEXT,
  ADD COLUMN IF NOT EXISTS custody_id TEXT,
  ADD COLUMN IF NOT EXISTS custody_uri TEXT,
  ADD COLUMN IF NOT EXISTS content_type TEXT,
  ADD COLUMN IF NOT EXISTS filename_redacted TEXT,
  ADD COLUMN IF NOT EXISTS upload_envelope TEXT;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_authorization_artifacts_tenant_request_created
  ON authorization_artifacts(tenant_id, high_scale_request_id, created_at);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_authorization_artifacts_tenant_custody
  ON authorization_artifacts(tenant_id, custody_id)
  WHERE custody_id IS NOT NULL;