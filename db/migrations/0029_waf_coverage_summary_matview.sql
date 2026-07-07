-- 0029_waf_coverage_summary_matview.sql
-- Portal revamp: dashboard WAF coverage summary (§2.5), adapted to waf_posture_snapshots + waf_connectors.

DROP MATERIALIZED VIEW IF EXISTS waf_coverage_summary;

CREATE MATERIALIZED VIEW waf_coverage_summary AS
WITH asset_posture AS (
  SELECT
    a.tenant_id,
    a.id AS asset_id,
    CASE
      WHEN ps.status = 'protected' THEN 'protected'
      WHEN ps.status IN ('underprotected', 'unprotected', 'drift') THEN 'underprotected'
      ELSE 'unknown'
    END AS posture_class,
    ps.detected_vendor AS vendor
  FROM waf_assets a
  LEFT JOIN waf_posture_snapshots ps
    ON ps.tenant_id = a.tenant_id
   AND ps.waf_asset_id = a.id
   AND ps.is_current = TRUE
),
tenant_rollups AS (
  SELECT
    tenant_id,
    COUNT(*)::int AS assets_total,
    COUNT(*) FILTER (WHERE posture_class = 'protected')::int AS protected,
    COUNT(*) FILTER (WHERE posture_class = 'underprotected')::int AS underprotected,
    COUNT(*) FILTER (WHERE posture_class = 'unknown')::int AS unknown,
    (COUNT(*) FILTER (WHERE posture_class = 'protected')::float / NULLIF(COUNT(*), 0)) * 100 AS coverage_pct
  FROM asset_posture
  GROUP BY tenant_id
),
vendor_rollups AS (
  SELECT
    tenant_id,
    COALESCE(NULLIF(TRIM(vendor), ''), 'generic') AS vendor,
    COUNT(*)::int AS assets,
    COUNT(*) FILTER (WHERE posture_class = 'protected')::int AS protected
  FROM asset_posture
  GROUP BY tenant_id, COALESCE(NULLIF(TRIM(vendor), ''), 'generic')
),
vendor_json AS (
  SELECT
    tenant_id,
    jsonb_object_agg(
      vendor,
      jsonb_build_object('assets', assets, 'protected', protected)
    ) AS by_vendor
  FROM vendor_rollups
  GROUP BY tenant_id
),
connector_counts AS (
  SELECT
    tenant_id,
    COUNT(*) FILTER (WHERE status = 'active')::int AS connectors_active,
    COUNT(*) FILTER (WHERE status = 'error')::int AS connectors_degraded,
    COUNT(*) FILTER (WHERE status = 'disabled')::int AS connectors_disabled
  FROM waf_connectors
  GROUP BY tenant_id
)
SELECT
  tr.tenant_id,
  tr.assets_total,
  tr.protected,
  tr.underprotected,
  tr.unknown,
  tr.coverage_pct,
  COALESCE(vj.by_vendor, '{}'::jsonb) AS by_vendor,
  COALESCE(cc.connectors_active, 0) AS connectors_active,
  COALESCE(cc.connectors_degraded, 0) AS connectors_degraded,
  COALESCE(cc.connectors_disabled, 0) AS connectors_disabled,
  now() AS refreshed_at
FROM tenant_rollups tr
LEFT JOIN vendor_json vj ON vj.tenant_id = tr.tenant_id
LEFT JOIN connector_counts cc ON cc.tenant_id = tr.tenant_id;

CREATE UNIQUE INDEX IF NOT EXISTS waf_coverage_summary_tenant
  ON waf_coverage_summary(tenant_id);