-- 0011_waf_orchestrator.sql
-- WAF orchestration persistence: validation plans, baseline approvals, retest requests.

ALTER TABLE waf_baselines ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'waf_drift_events_tenant_id_id_key'
  ) THEN
    ALTER TABLE waf_drift_events
      ADD CONSTRAINT waf_drift_events_tenant_id_id_key UNIQUE (tenant_id, id);
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS waf_validation_plans (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  target_group_id TEXT NOT NULL,
  mode TEXT NOT NULL DEFAULT 'manual',
  schedule_interval TEXT,
  custom_cron_expression TEXT,
  scenarios_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  max_concurrent INT NOT NULL DEFAULT 1,
  timeout_ms INT NOT NULL DEFAULT 60000,
  state TEXT NOT NULL DEFAULT 'draft',
  delegated_jobs_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  executed_at TIMESTAMPTZ,
  cancelled_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS waf_baseline_approvals (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  baseline_id TEXT NOT NULL,
  waf_asset_id TEXT NOT NULL,
  approver TEXT NOT NULL,
  approval_notes TEXT NOT NULL,
  approved_at TIMESTAMPTZ NOT NULL,
  fingerprint_summary_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS waf_retest_requests (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  drift_event_id TEXT NOT NULL,
  waf_asset_id TEXT NOT NULL,
  retest_plan_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  requested_by TEXT NOT NULL,
  priority TEXT NOT NULL DEFAULT 'normal',
  status TEXT NOT NULL DEFAULT 'requested',
  verdict TEXT,
  verdict_reason TEXT,
  delegated_jobs_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'waf_validation_plans_tenant_id_id_key'
  ) THEN
    ALTER TABLE waf_validation_plans
      ADD CONSTRAINT waf_validation_plans_tenant_id_id_key UNIQUE (tenant_id, id);
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'waf_baseline_approvals_tenant_id_id_key'
  ) THEN
    ALTER TABLE waf_baseline_approvals
      ADD CONSTRAINT waf_baseline_approvals_tenant_id_id_key UNIQUE (tenant_id, id);
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'waf_retest_requests_tenant_id_id_key'
  ) THEN
    ALTER TABLE waf_retest_requests
      ADD CONSTRAINT waf_retest_requests_tenant_id_id_key UNIQUE (tenant_id, id);
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'fk_waf_validation_plans_target_group_tenant'
  ) THEN
    ALTER TABLE waf_validation_plans ADD CONSTRAINT fk_waf_validation_plans_target_group_tenant
      FOREIGN KEY (tenant_id, target_group_id) REFERENCES target_groups (tenant_id, id);
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'fk_waf_baseline_approvals_baseline_tenant'
  ) THEN
    ALTER TABLE waf_baseline_approvals ADD CONSTRAINT fk_waf_baseline_approvals_baseline_tenant
      FOREIGN KEY (tenant_id, baseline_id) REFERENCES waf_baselines (tenant_id, id);
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'fk_waf_baseline_approvals_waf_asset_tenant'
  ) THEN
    ALTER TABLE waf_baseline_approvals ADD CONSTRAINT fk_waf_baseline_approvals_waf_asset_tenant
      FOREIGN KEY (tenant_id, waf_asset_id) REFERENCES waf_assets (tenant_id, id);
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'fk_waf_retest_requests_drift_event_tenant'
  ) THEN
    ALTER TABLE waf_retest_requests ADD CONSTRAINT fk_waf_retest_requests_drift_event_tenant
      FOREIGN KEY (tenant_id, drift_event_id) REFERENCES waf_drift_events (tenant_id, id);
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'fk_waf_retest_requests_waf_asset_tenant'
  ) THEN
    ALTER TABLE waf_retest_requests ADD CONSTRAINT fk_waf_retest_requests_waf_asset_tenant
      FOREIGN KEY (tenant_id, waf_asset_id) REFERENCES waf_assets (tenant_id, id);
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_waf_validation_plans_tenant_state
  ON waf_validation_plans(tenant_id, state, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_waf_validation_plans_scheduled
  ON waf_validation_plans(tenant_id, created_at DESC) WHERE state = 'scheduled';
CREATE INDEX IF NOT EXISTS idx_waf_retest_requests_drift
  ON waf_retest_requests(tenant_id, drift_event_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_waf_baseline_approvals_baseline
  ON waf_baseline_approvals(tenant_id, baseline_id, created_at DESC);

ALTER TABLE waf_validation_plans ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_validation_plans FORCE ROW LEVEL SECURITY;
ALTER TABLE waf_baseline_approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_baseline_approvals FORCE ROW LEVEL SECURITY;
ALTER TABLE waf_retest_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE waf_retest_requests FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_waf_validation_plans'
  ) THEN
    CREATE POLICY tenant_isolation_waf_validation_plans ON waf_validation_plans
      USING (tenant_id = current_setting('app.tenant_id', true))
      WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_waf_baseline_approvals'
  ) THEN
    CREATE POLICY tenant_isolation_waf_baseline_approvals ON waf_baseline_approvals
      USING (tenant_id = current_setting('app.tenant_id', true))
      WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_waf_retest_requests'
  ) THEN
    CREATE POLICY tenant_isolation_waf_retest_requests ON waf_retest_requests
      USING (tenant_id = current_setting('app.tenant_id', true))
      WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
  END IF;
END $$;