-- 0006_notification_rule_triggers.sql
-- API notification rules support triggers[]; persist as JSONB instead of singular trigger TEXT.

ALTER TABLE notification_rules ADD COLUMN IF NOT EXISTS triggers_json JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE notification_events ADD COLUMN IF NOT EXISTS metadata_json JSONB DEFAULT '{}'::jsonb;

UPDATE notification_rules
SET triggers_json = jsonb_build_array(trigger)
WHERE trigger IS NOT NULL
  AND btrim(trigger) <> ''
  AND (triggers_json IS NULL OR triggers_json = '[]'::jsonb);
