# WAF Posture Data Model

## Design principles

- Tenant scoped everywhere.
- Metadata-only evidence.
- Raw payloads and secrets prohibited.
- Approved targets are separate from discovered candidates.
- Connector data is normalized into summaries and config hashes, not full sensitive configs.
- Baselines are immutable snapshots; new baseline supersedes old baseline.

## New tables

### `entity_nodes`

Optional entity discovery graph.

| Column | Type | Notes |
|---|---|---|
| `id` | uuid | PK. |
| `tenant_id` | uuid | RLS. |
| `entity_type` | text | parent, subsidiary, acquisition, brand, business_unit, vendor_managed. |
| `name` | text | Redacted-safe display name. |
| `parent_entity_id` | uuid nullable | Self FK. |
| `confidence` | numeric | 0-1. |
| `source_summary_json` | jsonb | Metadata-only sources. |
| `ownership_status` | text | unknown, likely_owned, confirmed_owned, third_party, rejected. |
| `created_at` / `updated_at` | timestamptz | Standard. |

### `external_asset_candidates`

Opt-in discovery candidates. Not directly testable.

| Column | Type | Notes |
|---|---|---|
| `id` | uuid | PK. |
| `tenant_id` | uuid | RLS. |
| `entity_id` | uuid nullable | Entity link. |
| `asset_type` | text | fqdn, url, api, cname, cert_name, dependency. |
| `asset_value_hash` | text | Hash for dedupe. |
| `display_value` | text | Redacted or safe hostname/URL. |
| `source_type` | text | dns, ct_log, connector, import, registry, page_link, passive_dns. |
| `source_ref` | text nullable | Safe pointer. |
| `confidence` | numeric | 0-1. |
| `approval_status` | text | not_requested, pending, approved, rejected, exception. |
| `approved_target_id` | uuid nullable | Link to `targets` after approval. |
| `first_seen_at` / `last_seen_at` | timestamptz | Timestamps. |
| `evidence_summary_json` | jsonb | Metadata-only. |

### `waf_assets`

Approved web posture assets. Usually backed by existing `targets`.

| Column | Type | Notes |
|---|---|---|
| `id` | uuid | PK. |
| `tenant_id` | uuid | RLS. |
| `target_group_id` | uuid | Existing target group. |
| `target_id` | uuid nullable | Existing target. |
| `environment_id` | uuid nullable | Existing environment. |
| `canonical_url` | text | Safe URL/FQDN. |
| `asset_kind` | text | web_app, api, login, admin, marketing, payment, docs, unknown. |
| `expected_waf_required` | boolean | Policy. |
| `expected_vendor_hint` | text nullable | Optional customer hint. |
| `business_criticality` | text | low, medium, high, critical. |
| `traffic_tier` | text | low, medium, high, unknown. |
| `compliance_tags` | text[] | pci, hipaa, gdpr, etc. |
| `owner_hint` | text nullable | Routing. |
| `created_at` / `updated_at` | timestamptz | Standard. |

### `waf_products`

Normalized product catalog and fingerprint rules.

| Column | Type | Notes |
|---|---|---|
| `id` | uuid | PK. |
| `vendor` | text | cloudflare, akamai, aws, azure, gcp, imperva, etc. |
| `product` | text | Cloudflare WAF, Akamai Kona, AWS WAF, Azure Front Door WAF, etc. |
| `deployment_type` | text | cdn, cloud_native, appliance, reverse_proxy, unknown. |
| `fingerprint_version` | text | Signature set version. |
| `confidence_rules_json` | jsonb | Metadata rule ids, not raw secrets. |
| `enabled` | boolean | Runtime toggle. |

### `waf_fingerprints`

Per-run product detection results.

| Column | Type | Notes |
|---|---|---|
| `id` | uuid | PK. |
| `tenant_id` | uuid | RLS. |
| `waf_asset_id` | uuid | FK. |
| `test_run_id` | uuid nullable | FK to test run. |
| `detected_vendor` | text nullable | Best match. |
| `detected_product` | text nullable | Best match. |
| `confidence` | numeric | 0-1. |
| `signals_json` | jsonb | Safe metadata: header names, DNS chain class, block fingerprint hash, ASN/CDN hints. |
| `observed_at` | timestamptz | Timestamp. |

### `waf_validation_runs`

Posture-specific validation envelope. Can link to existing `test_runs`.

| Column | Type | Notes |
|---|---|---|
| `id` | uuid | PK. |
| `tenant_id` | uuid | RLS. |
| `test_run_id` | uuid nullable | Existing test run. |
| `waf_asset_id` | uuid | FK. |
| `mode` | text | marker, fingerprint, origin_bypass, rate_limit, connector_only, combined. |
| `status` | text | planned, running, collecting, finalized, failed, canceled. |
| `started_at` / `finalized_at` | timestamptz | Standard. |
| `safety_profile_json` | jsonb | Max requests/duration, no payloads. |
| `summary_json` | jsonb | Final metadata summary. |

### `waf_scenario_results`

Safe scenario family results. No raw payloads.

| Column | Type | Notes |
|---|---|---|
| `id` | uuid | PK. |
| `tenant_id` | uuid | RLS. |
| `waf_validation_run_id` | uuid | FK. |
| `scenario_family` | text | marker, sqli_marker, xss_marker, rce_marker, path_traversal_marker, rate_limit_marker, origin_bypass. |
| `test_material_type` | text | customer_marker, vendor_safe_test, metadata_only, manual_review. |
| `expected_action` | text | block, challenge, rate_limit, allow, no_observe. |
| `observed_action` | text | blocked, challenged, allowed, timed_out, observed_at_agent, inconclusive. |
| `passed` | boolean nullable | Null when inconclusive. |
| `confidence` | numeric | 0-1. |
| `evidence_summary_json` | jsonb | Metadata-only. |

### `waf_posture_snapshots`

Current and historical status.

| Column | Type | Notes |
|---|---|---|
| `id` | uuid | PK. |
| `tenant_id` | uuid | RLS. |
| `waf_asset_id` | uuid | FK. |
| `status` | text | protected, underprotected, unprotected, unknown, excluded. |
| `reason_codes` | text[] | Underprotected reasons. |
| `detected_vendor` / `detected_product` | text nullable | From latest fingerprint. |
| `coverage_required` | boolean | Policy. |
| `risk_score` | integer | 0-100. |
| `confidence` | numeric | 0-1. |
| `source_mix_json` | jsonb | external, agent, connector, cve, import. |
| `created_at` | timestamptz | Snapshot time. |
| `is_current` | boolean | Partial unique per asset. |

### `waf_baselines`

Approved posture baseline.

| Column | Type | Notes |
|---|---|---|
| `id` | uuid | PK. |
| `tenant_id` | uuid | RLS. |
| `waf_asset_id` | uuid | FK. |
| `state` | text | proposed, active, superseded, rejected. |
| `baseline_json` | jsonb | Expected vendor/product, marker behavior, connector config hash, mode, rule counts. |
| `approved_by` | uuid nullable | Actor. |
| `approved_at` | timestamptz nullable | Approval time. |
| `created_at` | timestamptz | Created. |

### `waf_drift_events`

Changes from baseline or last known good.

| Column | Type | Notes |
|---|---|---|
| `id` | uuid | PK. |
| `tenant_id` | uuid | RLS. |
| `waf_asset_id` | uuid | FK. |
| `baseline_id` | uuid nullable | FK. |
| `drift_type` | text | mode_change, rule_count_change, fingerprint_lost, vendor_change, marker_failed, origin_bypass_new, stale_rules, threshold_change. |
| `severity` | text | low, medium, high, critical. |
| `before_summary_json` | jsonb | Metadata. |
| `after_summary_json` | jsonb | Metadata. |
| `status` | text | open, acknowledged, remediation_started, retest_pending, resolved, accepted_risk, false_positive. |
| `finding_id` | uuid nullable | Existing finding. |
| `created_at` / `resolved_at` | timestamptz | Standard. |

### `connectors`

Connector configuration metadata. Secrets live in secret vault.

| Column | Type | Notes |
|---|---|---|
| `id` | uuid | PK. |
| `tenant_id` | uuid | RLS. |
| `provider` | text | cloudflare, akamai, aws, azure, gcp, imperva, wiz, prisma, servicenow, jira, splunk, sentinel, xsoar, slack, webhook. |
| `name` | text | Display. |
| `secret_id` | uuid nullable | Secret vault pointer. |
| `config_json` | jsonb | Redacted config. |
| `status` | text | disabled, validating, active, error, revoked. |
| `last_success_at` / `last_error_at` | timestamptz | Health. |
| `created_at` / `updated_at` | timestamptz | Standard. |

### `connector_snapshots`

Read-only snapshots.

| Column | Type | Notes |
|---|---|---|
| `id` | uuid | PK. |
| `tenant_id` | uuid | RLS. |
| `connector_id` | uuid | FK. |
| `provider` | text | Provider. |
| `snapshot_kind` | text | waf_policy, dns_zone, cdn_property, cloud_asset, vulnerability, ticket_status. |
| `resource_ref_hash` | text | Resource identifier hash. |
| `display_ref` | text nullable | Safe display name/id. |
| `summary_json` | jsonb | Metadata-only normalized fields. |
| `config_hash` | text nullable | Hash of normalized config summary. |
| `observed_at` | timestamptz | Timestamp. |

### `cve_pipeline_items`

New CVE tracking.

| Column | Type | Notes |
|---|---|---|
| `id` | uuid | PK. |
| `tenant_id` | uuid | RLS or global + tenant state depending design. |
| `cve_id` | text | CVE identifier. |
| `published_at` | timestamptz | Source published date. |
| `severity` | text nullable | Critical/high/etc. |
| `known_exploited` | boolean | From KEV/threat intel. |
| `public_poc_signal` | boolean | Indicator only. |
| `state` | text | ingested, triaged, matched, validation_pending, exposed, not_relevant, not_exploitable, mitigation_recommended, resolved. |
| `triage_summary_json` | jsonb | Affected products/versions, risk notes. |
| `created_at` / `updated_at` | timestamptz | Standard. |

### `cve_asset_matches`

Matches between CVEs and WAF assets.

| Column | Type | Notes |
|---|---|---|
| `id` | uuid | PK. |
| `tenant_id` | uuid | RLS. |
| `cve_pipeline_item_id` | uuid | FK. |
| `waf_asset_id` | uuid | FK. |
| `match_confidence` | numeric | 0-1. |
| `match_sources` | text[] | tech_fingerprint, connector_vuln, cnapp, manual, sbom, banner. |
| `validation_status` | text | pending, exposed, not_exploitable, inconclusive, skipped. |
| `risk_score` | integer | 0-100. |
| `finding_id` | uuid nullable | Existing finding. |
| `created_at` / `updated_at` | timestamptz | Standard. |

### `waf_rule_recommendations`

Human-approved mitigation guidance.

| Column | Type | Notes |
|---|---|---|
| `id` | uuid | PK. |
| `tenant_id` | uuid | RLS. |
| `waf_asset_id` | uuid | FK. |
| `cve_asset_match_id` | uuid nullable | FK. |
| `vendor` | text | cloudflare, aws, azure, akamai, imperva, fortinet, generic. |
| `recommendation_type` | text | managed_rule_enable, custom_rule_add, mode_change, origin_restrict, rate_limit_adjust, patch_required. |
| `recommendation_json` | jsonb | Template, not auto-deploy secret. |
| `approval_status` | text | draft, needs_review, approved_for_ticket, deployed_external, rejected, expired. |
| `ticket_id` | uuid nullable | Sync link. |
| `created_at` / `updated_at` | timestamptz | Standard. |

## Indexes

| Index | Purpose |
|---|---|
| `(tenant_id, waf_asset_id, is_current)` partial unique current snapshot | Fast current posture. |
| `(tenant_id, status, created_at)` on snapshots | Dashboard filters. |
| `(tenant_id, drift_type, status, created_at)` on drift events | Drift queue. |
| `(tenant_id, connector_id, provider, observed_at)` on snapshots | Connector history. |
| `(tenant_id, cve_id)` on CVE items | CVE lookup. |
| `(tenant_id, cve_pipeline_item_id, waf_asset_id)` unique on matches | Deduping. |
| `(tenant_id, approval_status, confidence)` on candidates | Discovery inbox. |
| `(tenant_id, target_group_id, canonical_url)` on WAF assets | Asset lookup. |

## Migration order

1. Create entity/candidate tables.
2. Create WAF product/catalog tables.
3. Create WAF asset and validation tables.
4. Create posture snapshot and baseline tables.
5. Create connector tables if not already generalized.
6. Create CVE pipeline tables.
7. Create recommendation tables.
8. Add indexes and RLS policies.
9. Add read-only views for dashboard aggregates.
10. Backfill WAF assets from existing approved URL/FQDN targets.

## Retention

| Data | Default retention |
|---|---:|
| Current posture snapshot | Until superseded; current retained. |
| Historical posture snapshots | 365 days, configurable. |
| Probe evidence summaries | Existing evidence retention. |
| Connector snapshots | 90-180 days unless baseline requires hash reference. |
| Discovery rejected candidates | 30-90 days. |
| Drift events and findings | Until resolved + retention policy. |
| CVE pipeline items | 365 days or compliance policy. |
| Raw secrets | Never returned; rotate/delete via secret vault. |

## Done criteria

- Migrations pass tenant query audit.
- All WAF tables enforce RLS.
- Unit tests reject forbidden evidence keys.
- Backfill does not create findings until checks run.
- Current posture view returns stable aggregate in under expected dashboard SLA.
