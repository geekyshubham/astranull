-- WAF-013: risk factor evidence and deployment tier metadata on posture snapshots.

ALTER TABLE waf_posture_snapshots
  ADD COLUMN IF NOT EXISTS risk_factors_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS priority_band TEXT,
  ADD COLUMN IF NOT EXISTS recommended_action TEXT;