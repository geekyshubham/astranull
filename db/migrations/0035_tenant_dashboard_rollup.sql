-- Portal revamp: optional materialized dashboard rollup for GET /v1/state at scale (doc 16 §6).
ALTER TABLE tenants
  ADD COLUMN IF NOT EXISTS dashboard_rollup JSONB;