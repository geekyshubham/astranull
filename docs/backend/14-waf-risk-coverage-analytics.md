# WAF Risk Scoring and Coverage Analytics

## Purpose

Define how AstraNull computes WAF posture risk, rolls up executive coverage analytics, and produces a tiered deployment roadmap for unprotected and underprotected assets.

This doc closes the gap between the product capability map and the runtime services named in the WAF architecture (`wafRiskService`, `wafCoverageService`).

## Services

| Service | Responsibility |
|---|---|
| `wafRiskService` | Compute 0–100 risk score per asset with factor-level evidence; assign deployment tier; optional vendor-consolidation hints. |
| `wafCoverageService` | Aggregate tenant coverage by status, vendor, entity, geography, and time; expose trend series and roadmap outputs. |

Both services must be deterministic, tenant-scoped, metadata-only, and unit testable from posture snapshots, validation runs, connector snapshots, CVE matches, and declared asset metadata.

## Risk scoring model

The prioritization framework uses **six primary factor families** aligned with enterprise deployment-roadmap offerings: traffic volume, business criticality, known vulnerability exposure, OWASP attack surface, hosting environment, and regulatory scope. Protection state, validation result, origin bypass, and confidence layer on top for explainable 0–100 scores.

### Inputs

| Factor | Source | Weight direction |
|---|---|---|
| Protection state | Latest posture snapshot | Unprotected highest; underprotected next; protected lowest when validated. |
| Validation result | Latest validation run scenario results | Failed/inconclusive raises score. |
| Origin bypass | Posture snapshot + origin-bypass check | Confirmed bypass raises score strongly. |
| Business criticality | `waf_assets.business_criticality` | Auth, checkout, PII, admin, API raise score. |
| Traffic tier | `waf_assets.traffic_tier` | High raises score. |
| Known vulnerabilities | CVE pipeline matches, CNAPP/CSPM imports | Known-exploited or high-severity open matches raise score. |
| OWASP exposure | Declared `asset_kind`, path tags, connector app metadata | Login, upload, search, API, GraphQL, admin surfaces raise score. |
| Hosting environment | Target group environment, connector cloud context | Unknown, vendor-managed, subsidiary hosting can raise priority. |
| Regulatory scope | `compliance_tags` | PCI, HIPAA, GDPR, SOC 2, ISO 27001, NIST in-scope tags raise priority. |
| Confidence | `source_mix_json`, agent placement | Low confidence does not lower risk; it lowers certainty and adds review flags. |

### Output shape

```json
{
  "waf_asset_id": "uuid",
  "risk_score": 72,
  "priority_band": "tier_1",
  "factors": [
    { "factor": "protection_state", "value": "unprotected", "contribution": 28 },
    { "factor": "business_criticality", "value": "payment", "contribution": 18 }
  ],
  "confidence": 0.81,
  "recommended_action": "deploy_waf_blocking",
  "computed_at": "2026-07-03T00:00:00Z"
}
```

Store factor contributions in posture snapshots (`risk_score`, `risk_factors_json`) on finalize and on scheduled recompute.

### OWASP exposure inference

| `asset_kind` or tag | OWASP exposure class |
|---|---|
| `auth_portal`, `login` | Authentication surface |
| `payment`, `checkout` | Payment/PII surface |
| `admin`, `internal_admin` | Administrative surface |
| `api`, `graphql` | Machine/API surface |
| `upload`, `file_exchange` | File upload surface |
| `search`, `public_form` | Input-heavy public surface |

OWASP exposure is metadata-only. Do not crawl or guess endpoints beyond customer-declared scope.

## Deployment roadmap tiers

| Tier | Name | Typical rollout window | Entry criteria |
|---|---|---|---|
| `tier_1` | Immediate | 0–14 days | Risk score ≥ 75, or unprotected critical/PII/payment asset, or confirmed origin bypass on in-scope asset. Typical examples: `auth_portal`, `payment`, `login`, PII APIs. |
| `tier_2` | Near-term | 15–60 days | Risk score 50–74, or underprotected high-traffic asset, or compliance-tagged asset with failed validation. |
| `tier_3` | Planned | 61–180 days | Risk score 25–49, or low-traffic/marketing/legacy asset needing eventual coverage. |
| `tier_4` | Monitor | Review quarterly | Excluded assets, unknown with low business impact, or customer-approved exception not yet expired. |

Roadmap items must include: asset id, hostname, owner hint, detected vendor (if any), primary reason codes, suggested remediation class (`deploy_waf`, `fix_blocking_mode`, `close_origin_bypass`, `refresh_rules`, `approve_exception`), and linked finding/action-item ids when present.

## Vendor consolidation advisory (optional)

When a tenant runs multiple WAF/CDN vendors, produce a read-only advisory overlay:

| Output | Meaning |
|---|---|
| `vendor_footprint` | Count of assets per detected vendor/product. |
| `overlap_candidates` | Hostnames or business units with multiple edge vendors. |
| `consolidation_opportunities` | Metadata-only suggestions where one vendor already covers a majority of assets in the same entity or region. |
| `operating_cost_signals` | Number of active connectors, stale rule updates, and duplicate policy drift events per vendor. |

This is advisory only. AstraNull does not migrate WAF vendors or push rules across consoles.

## Coverage analytics rollups

### Tenant summary (`GET /v1/waf/coverage`)

| Field | Meaning |
|---|---|
| `total` | Count of WAF assets in scope. |
| `protected`, `underprotected`, `unprotected`, `unknown`, `excluded` | Status counts. |
| `coverage_ratio` | `protected / (total - excluded)` when denominator > 0. |
| `trend` | Time series of `coverage_ratio` and status counts (default 90 days, daily buckets). |

### Vendor breakdown (`GET /v1/waf/coverage/vendors`)

| Field | Meaning |
|---|---|
| `items[]` | `{ vendor, product, asset_count, protected_count, underprotected_count, unprotected_count, unknown_count }`. |
| `vendor_mix` | Percentage of protected assets per vendor for executive charts. |

### Criticality rollup (`GET /v1/waf/coverage/criticality`)

| Field | Meaning |
|---|---|
| `items[]` | `{ business_criticality, asset_count, coverage_ratio, protected, underprotected, unprotected, critical_gap_count }`. |
| `critical_gap_count` | Unprotected or underprotected assets at `high` or `critical` criticality. |

### Entity rollup (`GET /v1/waf/coverage/entities`)

| Field | Meaning |
|---|---|
| `items[]` | `{ entity_id, entity_type, name, coverage_ratio, protected, underprotected, unprotected, critical_gap_count }`. |
| `entity_type` | `parent`, `subsidiary`, `brand`, `business_unit`, `region`, `vendor_managed`. |

Requires optional discovery entity linkage or `owner_hint` / target-group business-unit tags when entity graph is disabled.

### Geography rollup (`GET /v1/waf/coverage/geography`)

| Field | Meaning |
|---|---|
| `items[]` | `{ region_code, region_label, asset_count, coverage_ratio, unprotected_critical_count }`. |
| `region_code` | ISO country, cloud region, or tenant-defined geography tag from asset/target-group metadata. |

Geography is derived from declared metadata only. No geo-IP inventory discovery.

### Deployment roadmap (`GET /v1/waf/coverage/risk-roadmap`)

| Field | Meaning |
|---|---|
| `tiers` | `{ tier_1, tier_2, tier_3, tier_4 }` each with ordered `items[]`. |
| `generated_at` | Timestamp of risk recompute. |
| `method` | `waf_risk_v1`. |

Query params: `entity_id`, `region_code`, `vendor`, `min_score`, `limit_per_tier`.

## Recompute triggers

| Event | Action |
|---|---|
| Posture snapshot finalize | Recompute asset risk score and tier. |
| Drift event open/resolve | Recompute affected asset; refresh roadmap slice. |
| CVE asset match created/resolved | Adjust vulnerability factor. |
| Connector snapshot ingest | Refresh rule-count/staleness factors when connector mode enabled. |
| Nightly worker | Recompute tenant rollups and trend buckets. |

## Executive report payloads (R7/R8 — developer validation)

Implemented analytics report kinds extend the existing export contract:

| Report kind | Additional sections after R7 |
|---|---|
| `executive_coverage` | Vendor mix chart data, entity/geography/criticality rollups, `coverage_ratio` trend, Tier 1–2 gap counts. |
| `board_roadmap_brief` | Procurement justification narrative, recommended investment phases, Tier 1 asset examples (auth, payment, PII). |
| `compliance_audit` | Criticality rollup, exception register, control-mapping appendix (see product doc 12). |

## Done criteria

- `wafRiskService` produces stable scores with explainable factor JSON.
- `wafCoverageService` serves summary, vendors, entities, geography, trend, and roadmap responses.
- Roadmap tiers are documented in UX and API contract with acceptance tests.
- Vendor consolidation advisory is optional, metadata-only, and clearly labeled non-prescriptive.
- No raw payloads, secrets, or full policy bodies in analytics outputs.
