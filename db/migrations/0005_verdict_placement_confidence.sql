-- 0005_verdict_placement_confidence.sql
-- DET-014: persist placement_confidence on verdicts for Postgres repository parity.

ALTER TABLE verdicts ADD COLUMN IF NOT EXISTS placement_confidence_json JSONB DEFAULT '{}';