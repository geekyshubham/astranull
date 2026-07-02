# WAF Posture API Contract

## Authentication and RBAC

Reuse AstraNull bearer auth, service accounts, tenant isolation, and audit.

| Permission | Purpose |
|---|---|
| `waf:read` | Read WAF assets, posture, coverage, drift, recommendations. |
| `waf:write` | Update WAF asset metadata, approve baselines, manage exceptions. |
| `waf:run` | Start customer-runnable safe WAF validations. |
| `waf:connector_read` | View connector metadata/health. |
| `waf:connector_write` | Create/rotate/delete connector configs. |
| `waf:recommendation_review` | Approve/reject WAF recommendations for ticketing. |
| `discovery:read` | View candidate discovery inbox. |
| `discovery:write` | Approve/reject/import discovered candidates. |
| `cve_pipeline:read` | View CVE pipeline. |
| `cve_pipeline:write` | Override triage/match status. |

## Asset APIs

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| GET | `/v1/waf/assets` | `waf:read` | filters: status, vendor, group, owner, criticality | `{ items, page }`. |
| POST | `/v1/waf/assets` | `waf:write` | `{ target_group_id, target_id?, canonical_url, asset_kind?, expected_waf_required?, expected_vendor_hint?, business_criticality?, traffic_tier?, compliance_tags?, owner_hint? }` | `201 { asset }`. |
| GET | `/v1/waf/assets/:id` | `waf:read` | - | `{ asset, current_posture, latest_validation, baseline, drift, recommendations }`. |
| PATCH | `/v1/waf/assets/:id` | `waf:write` | partial metadata | `{ asset }`. |
| POST | `/v1/waf/assets/:id/exception` | `waf:write` | `{ reason, expires_at, owner, scope_hash? }` | `{ exception, posture }`. |

## Coverage APIs

| Method | Path | Permission | Response |
|---|---|---|---|
| GET | `/v1/waf/coverage` | `waf:read` | `{ total, protected, underprotected, unprotected, unknown, excluded, coverage_ratio, trend }`. |
| GET | `/v1/waf/coverage/vendors` | `waf:read` | Vendor/product breakdown. |
| GET | `/v1/waf/coverage/entities` | `waf:read` | Business unit/subsidiary/entity rollup. |
| GET | `/v1/waf/coverage/risk-roadmap` | `waf:read` | Tiered WAF deployment priorities. |

## Validation APIs

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| POST | `/v1/waf/validations` | `waf:run` | `{ waf_asset_id, modes[], marker_profile?, probe_profile? }` | `201 { validation_run, test_run?, probe_job? }`. |
| GET | `/v1/waf/validations` | `waf:read` | filters | `{ items }`. |
| GET | `/v1/waf/validations/:id` | `waf:read` | - | `{ validation_run, scenario_results, evidence }`. |
| POST | `/v1/waf/validations/:id/finalize` | `waf:run` | `{ force?: boolean }` | `{ validation_run, posture }`. |

### Validation request constraints

- `modes` allowed values: `fingerprint`, `marker`, `origin_bypass`, `rate_limit_safe`, `connector_only`, `combined`.
- `marker_profile` may reference header/path/query marker; server generates nonce.
- Client cannot raise request count, timeout, or concurrency above catalog maximums.
- Server rejects raw payload fields.

## Baseline and drift APIs

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| GET | `/v1/waf/assets/:id/baselines` | `waf:read` | - | `{ items }`. |
| POST | `/v1/waf/assets/:id/baselines` | `waf:write` | `{ source_snapshot_id?, baseline_json?, note? }` | `201 { baseline }` in proposed state. |
| POST | `/v1/waf/baselines/:id/approve` | `waf:write` | `{ note? }` | `{ baseline }` active. |
| POST | `/v1/waf/baselines/:id/reject` | `waf:write` | `{ reason }` | `{ baseline }` rejected. |
| GET | `/v1/waf/drift-events` | `waf:read` | filters | `{ items }`. |
| PATCH | `/v1/waf/drift-events/:id` | `waf:write` | `{ status, notes? }` | `{ drift_event }`. |
| POST | `/v1/waf/drift-events/:id/retest` | `waf:run` | - | `201 { validation_run }`. |

## Discovery APIs

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| GET | `/v1/discovery/entities` | `discovery:read` | filters | `{ items }`. |
| POST | `/v1/discovery/entities` | `discovery:write` | `{ entity_type, name, parent_entity_id?, source_summary? }` | `201 { entity }`. |
| GET | `/v1/discovery/candidates` | `discovery:read` | filters | `{ items }`. |
| POST | `/v1/discovery/candidates/:id/approve` | `discovery:write` | `{ target_group_id, asset_kind?, expected_waf_required? }` | `{ candidate, target, waf_asset }`. |
| POST | `/v1/discovery/candidates/:id/reject` | `discovery:write` | `{ reason }` | `{ candidate }`. |
| POST | `/v1/discovery/import` | `discovery:write` | CSV/API import metadata | `{ import_job }`. |

## Connector APIs

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| GET | `/v1/connectors` | `waf:connector_read` | filters | `{ items }`. |
| POST | `/v1/connectors` | `waf:connector_write` | `{ provider, name, secret_id?, config }` | `201 { connector }`. |
| POST | `/v1/connectors/:id/validate` | `waf:connector_write` | - | `{ status, capabilities, redacted_errors? }`. |
| POST | `/v1/connectors/:id/poll` | `waf:connector_write` | `{ snapshot_kinds? }` | `202 { poll_job }`. |
| GET | `/v1/connectors/:id/snapshots` | `waf:connector_read` | filters | `{ items }`. |
| POST | `/v1/connectors/:id/disable` | `waf:connector_write` | `{ reason? }` | `{ connector }`. |

## CVE pipeline APIs

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| GET | `/v1/cve-pipeline` | `cve_pipeline:read` | filters | `{ items }`. |
| GET | `/v1/cve-pipeline/:id` | `cve_pipeline:read` | - | `{ item, matches, recommendations }`. |
| POST | `/v1/cve-pipeline/ingest` | `cve_pipeline:write` | `{ cve_id?, source?, metadata? }` | `202 { job }`. |
| POST | `/v1/cve-pipeline/:id/triage` | `cve_pipeline:write` | `{ state?, note?, affected_products? }` | `{ item }`. |
| POST | `/v1/cve-pipeline/:id/match-assets` | `cve_pipeline:write` | - | `202 { job }`. |
| POST | `/v1/cve-matches/:id/validate` | `waf:run` | safe validation request | `201 { validation_run }`. |

## Recommendation APIs

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| GET | `/v1/waf/recommendations` | `waf:read` | filters | `{ items }`. |
| GET | `/v1/waf/recommendations/:id` | `waf:read` | - | `{ recommendation, asset, evidence, ticket_sync }`. |
| POST | `/v1/waf/recommendations/:id/approve-for-ticket` | `waf:recommendation_review` | `{ note? }` | `{ recommendation }`. |
| POST | `/v1/waf/recommendations/:id/reject` | `waf:recommendation_review` | `{ reason }` | `{ recommendation }`. |
| POST | `/v1/waf/recommendations/:id/create-ticket` | `waf:recommendation_review` | `{ connector_id?, project?, assignment? }` | `{ ticket_sync }`. |
| POST | `/v1/waf/recommendations/:id/mark-deployed` | `waf:recommendation_review` | `{ change_ref, deployed_at }` | `{ recommendation }`. |
| POST | `/v1/waf/recommendations/:id/retest` | `waf:run` | - | `201 { validation_run }`. |

## Response shapes

### `WafPostureSnapshot`

```json
{
  "id": "uuid",
  "waf_asset_id": "uuid",
  "status": "protected|underprotected|unprotected|unknown|excluded",
  "reason_codes": ["marker_rule_not_blocking"],
  "detected_vendor": "cloudflare",
  "detected_product": "Cloudflare WAF",
  "risk_score": 78,
  "confidence": 0.86,
  "source_mix": { "external": true, "agent": true, "connector": false },
  "created_at": "2026-07-02T00:00:00Z"
}
```

### `WafDriftEvent`

```json
{
  "id": "uuid",
  "waf_asset_id": "uuid",
  "drift_type": "marker_failed",
  "severity": "high",
  "status": "open",
  "before_summary": { "marker_result": "blocked" },
  "after_summary": { "marker_result": "allowed" },
  "finding_id": "uuid",
  "created_at": "2026-07-02T00:00:00Z"
}
```

## Audit events

| Event | Metadata |
|---|---|
| `waf.asset.created` | asset id, target id, source. |
| `waf.validation.started` | asset id, modes, safety profile hash. |
| `waf.posture.updated` | asset id, old/new status, reason codes. |
| `waf.baseline.approved` | baseline id, asset id, actor. |
| `waf.drift.detected` | drift id, type, severity. |
| `waf.recommendation.approved` | recommendation id, type, vendor. |
| `connector.created` | provider, connector id, no secrets. |
| `connector.snapshot.created` | provider, snapshot kind, counts. |
| `discovery.candidate.approved` | candidate id, target id, confidence. |
| `cve_pipeline.item_triaged` | cve id, state. |

## Error codes

| Code | Meaning |
|---|---|
| `waf_feature_disabled` | Feature flag off. |
| `waf_asset_not_found` | Missing or cross-tenant asset. |
| `waf_asset_not_approved` | Candidate not approved for testing. |
| `unsafe_waf_profile` | Probe profile exceeds safe limits or contains prohibited fields. |
| `marker_profile_required` | Marker validation requested without marker config. |
| `agent_observation_required` | Strong proof requires agent/canary but none exists. |
| `connector_secret_missing` | Connector needs secret pointer. |
| `connector_validation_failed` | Read-only validation failed. |
| `baseline_not_active` | Drift comparison requested without active baseline. |
| `recommendation_not_reviewable` | Recommendation state cannot transition. |

## Done criteria

- API contract implemented with integration tests.
- Feature flag off returns safe disabled errors.
- RBAC enforced per endpoint.
- All raw payload/header/body fields rejected.
- OpenAPI spec generated from this contract.
