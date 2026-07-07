-- 0037_test_policies.sql
-- Safe validation policies (PP-09): customer-declared cadence + expected verdict
-- bound to a target group and a customer-runnable check, with a safety snapshot.

CREATE TABLE IF NOT EXISTS test_policies (
  id                      TEXT PRIMARY KEY,
  tenant_id               TEXT NOT NULL,
  target_group_id         TEXT NOT NULL,
  check_id                TEXT NOT NULL,
  cadence                 TEXT NOT NULL DEFAULT 'manual'
                          CHECK (cadence IN ('manual', 'daily', 'weekly', 'monthly', 'event_driven')),
  expected_verdict        TEXT NOT NULL DEFAULT 'pass'
                          CHECK (expected_verdict IN ('pass', 'warn', 'fail', 'manual_review')),
  safe_windows            JSONB NOT NULL DEFAULT '[]',
  state                   TEXT NOT NULL DEFAULT 'active',
  safety_policy_snapshot  JSONB NOT NULL DEFAULT '{}',
  archived_at             TIMESTAMPTZ,
  created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_test_policies_tenant_active
  ON test_policies(tenant_id, target_group_id)
  WHERE archived_at IS NULL;

ALTER TABLE test_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE test_policies FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS test_policies_tenant_isolation ON test_policies;
CREATE POLICY test_policies_tenant_isolation ON test_policies
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
