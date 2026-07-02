-- 0003_runtime_shape_parity.sql
-- Align Postgres contract with runtime service writes (findings verdict links, agent_jobs.type). Schema coverage only.

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'agent_jobs'
      AND column_name = 'job_type'
  ) AND NOT EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'agent_jobs'
      AND column_name = 'type'
  ) THEN
    ALTER TABLE agent_jobs RENAME COLUMN job_type TO type;
  END IF;
END $$;

ALTER TABLE findings ADD COLUMN IF NOT EXISTS verdict_id TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS last_verdict_id TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS assignee TEXT;

ALTER TABLE verdicts ADD CONSTRAINT verdicts_tenant_id_id_key UNIQUE (tenant_id, id);

ALTER TABLE findings ADD CONSTRAINT fk_findings_verdict_tenant
  FOREIGN KEY (tenant_id, verdict_id) REFERENCES verdicts (tenant_id, id);
ALTER TABLE findings ADD CONSTRAINT fk_findings_last_verdict_tenant
  FOREIGN KEY (tenant_id, last_verdict_id) REFERENCES verdicts (tenant_id, id);