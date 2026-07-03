# WAF Analytics Schema Extensions (Planned Migration)

## Purpose

Document database additions required by [WAF Risk and Coverage Analytics](14-waf-risk-coverage-analytics.md) that are not yet in `0008_waf_posture.sql`. Implement via a forward migration (for example `0016_waf_analytics_extensions.sql`) when WAF-019 starts.

## `waf_assets` additions

| Column | Type | Notes |
|---|---|---|
| `region_code` | text nullable | ISO country or cloud region code from customer declaration. |
| `geography_label` | text nullable | Human label (EMEA, APAC, us-east-1). |
| `entity_id` | text nullable | FK to `entity_nodes.id` when discovery enabled. |
| `owasp_exposure_tags` | text[] | login, upload, api, graphql, admin, search, payment. |

Geography is **declared metadata only**. Do not infer from geo-IP.

## `entity_nodes` alignment

Add `region` to allowed `entity_type` values to match [Enhanced External Discovery](../product/10-enhanced-external-discovery.md):

`parent`, `subsidiary`, `acquisition`, `brand`, `business_unit`, `region`, `vendor_managed`.

## `waf_posture_snapshots` additions

| Column | Type | Notes |
|---|---|---|
| `priority_band` | text nullable | tier_1, tier_2, tier_3, tier_4. |
| `risk_factors_json` | jsonb | Factor contributions from `wafRiskService`. |
| `scenario_pass_rate` | numeric nullable | Lookback pass rate snapshot at finalize time. |
| `control_bypass_status` | text nullable | none, suspected, confirmed. |

## `waf_coverage_daily_rollups` (new table)

Tenant-level trend buckets for dashboard `trend[]`.

| Column | Type | Notes |
|---|---|---|
| `id` | text | PK. |
| `tenant_id` | text | RLS. |
| `rollup_date` | date | UTC date bucket. |
| `total_assets` | int | Count in scope. |
| `protected` | int | Status count. |
| `underprotected` | int | Status count. |
| `unprotected` | int | Status count. |
| `unknown` | int | Status count. |
| `excluded` | int | Status count. |
| `coverage_ratio` | numeric | protected / (total - excluded). |
| `created_at` | timestamptz | Insert time. |

Unique index: `(tenant_id, rollup_date)`.

## `waf_scenario_results` addition

Add scenario family `block_page_expectation` with `test_material_type: metadata_only` for expected block/challenge page signature match (no full body storage).

## Nightly rollup worker

| Job | Runner | Purpose |
|---|---|---|
| `waf_coverage_rollup` | Backend worker | Insert `waf_coverage_daily_rollups` from current snapshots. |
| `waf_risk_recompute` | Backend worker | Refresh risk scores and tiers for all assets. |

Schedule externally (cron/Kubernetes CronJob), same pattern as `waf:drift:runner`.

## Done criteria

- Migration spec matches API analytics responses.
- RLS on new rollup table.
- Backfill strategy documented for existing tenants (single-day seed from current snapshots).
- WAF-019 tracks implementation and tests.