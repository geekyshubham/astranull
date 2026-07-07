-- 0034_privacy_settings_defaults.sql
-- Portal revamp: non-null privacy_settings defaults for retention inputs (§2.10).

UPDATE tenants
SET privacy_settings = jsonb_strip_nulls(coalesce(privacy_settings, '{}'::jsonb) || jsonb_build_object(
  'metadata_retention_days', coalesce((privacy_settings->>'metadata_retention_days')::int, 365),
  'evidence_retention_days', coalesce((privacy_settings->>'evidence_retention_days')::int, 1825),
  'audit_retention_days', coalesce((privacy_settings->>'audit_retention_days')::int, 2555)
))
WHERE privacy_settings IS NULL OR privacy_settings = '{}'::jsonb;

ALTER TABLE tenants
  ALTER COLUMN privacy_settings SET DEFAULT jsonb_build_object(
    'metadata_retention_days', 365,
    'evidence_retention_days', 1825,
    'audit_retention_days', 2555
  );