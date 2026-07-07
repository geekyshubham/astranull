-- 0033_high_scale_customer_view_index.sql
-- Portal revamp: high-scale customer queue indexes (§2.9), adapted to authorization_artifacts schema.

CREATE INDEX IF NOT EXISTS high_scale_requests_by_tenant_state
  ON high_scale_requests(tenant_id, state, created_at DESC);

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'authorization_artifacts'
      AND column_name = 'artifact_type'
  ) THEN
    CREATE INDEX IF NOT EXISTS authorization_artifacts_by_request
      ON authorization_artifacts(tenant_id, high_scale_request_id, artifact_type);
  ELSE
    CREATE INDEX IF NOT EXISTS authorization_artifacts_by_request
      ON authorization_artifacts(tenant_id, high_scale_request_id, created_at);
  END IF;
END $$;