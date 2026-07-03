-- 0012_waf_orchestrator_execution_leases.sql
-- DB-backed execution leases for WAF validation-plan and retest worker idempotency.

ALTER TABLE waf_validation_plans ADD COLUMN IF NOT EXISTS execution_lock_token TEXT;
ALTER TABLE waf_validation_plans ADD COLUMN IF NOT EXISTS execution_lock_expires_at TIMESTAMPTZ;

ALTER TABLE waf_retest_requests ADD COLUMN IF NOT EXISTS execution_lock_token TEXT;
ALTER TABLE waf_retest_requests ADD COLUMN IF NOT EXISTS execution_lock_expires_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_waf_validation_plans_execution_lock
  ON waf_validation_plans(tenant_id, execution_lock_expires_at) WHERE execution_lock_token IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_waf_retest_requests_execution_lock
  ON waf_retest_requests(tenant_id, execution_lock_expires_at) WHERE execution_lock_token IS NOT NULL;