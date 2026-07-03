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

Implementation status: `GET /v1/waf/coverage` returns status counts in developer validation. Routes below are **contracted** and must stay in sync with `docs/api/waf-posture-openapi.json` when implemented. See [WAF Risk and Coverage Analytics](14-waf-risk-coverage-analytics.md).

| Method | Path | Permission | Query params | Response |
|---|---|---|---|---|
| GET | `/v1/waf/coverage` | `waf:read` | `window_days?` (default 90) | `{ total, protected, underprotected, unprotected, unknown, excluded, coverage_ratio, percentages, trend[] }`. `trend[]`: `{ date, coverage_ratio, protected, underprotected, unprotected }`. |
| GET | `/v1/waf/coverage/vendors` | `waf:read` | - | `{ items: [{ vendor, product, asset_count, protected_count, underprotected_count, unprotected_count, unknown_count }], vendor_mix[] }`. |
| GET | `/v1/waf/coverage/entities` | `waf:read` | `entity_type?` | `{ items: [{ entity_id, entity_type, name, coverage_ratio, protected, underprotected, unprotected, critical_gap_count }] }`. |
| GET | `/v1/waf/coverage/criticality` | `waf:read` | - | `{ items: [{ business_criticality, asset_count, coverage_ratio, protected, underprotected, unprotected, critical_gap_count }] }`. |
| GET | `/v1/waf/coverage/geography` | `waf:read` | `region_code?` | `{ items: [{ region_code, region_label, asset_count, coverage_ratio, unprotected_critical_count }] }`. |
| GET | `/v1/waf/coverage/risk-roadmap` | `waf:read` | `entity_id?`, `region_code?`, `vendor?`, `min_score?`, `limit_per_tier?` | `{ tiers: { tier_1[], tier_2[], tier_3[], tier_4[] }, generated_at, method }`. Each item: asset summary, `risk_score`, `priority_band`, `primary_reason_codes`, `recommended_action`. |
| GET | `/v1/waf/coverage/vendor-consolidation` | `waf:read` | - | `{ vendor_footprint[], overlap_candidates[], consolidation_opportunities[], operating_cost_signals[] }` advisory metadata only. |

### Asset effectiveness fields

`GET /v1/waf/assets/:id` must include when available:

| Field | Meaning |
|---|---|
| `effectiveness.scenario_pass_rate` | Lookback pass rate for scenario families |
| `effectiveness.rule_count` | From latest connector snapshot |
| `effectiveness.last_rule_update_at` | From latest connector snapshot |
| `effectiveness.control_bypass_status` | `none`, `suspected`, `confirmed` |
| `effectiveness.block_page_signature_id` | Latest fingerprint evidence |

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
| POST | `/v1/waf/drift-events/:id/retest` | `waf:run` | `{ note? }` | `201 { retest_request }`. |
| POST | `/v1/waf/drift-scans/run` | `waf:run` | - | `200 { scan_result }`. Dev-json: `wafDriftWorker.runDriftScan`. Postgres: requires injected `services.wafDrift` or `503 postgres_route_not_wired`. |
| GET | `/v1/waf/drift-scans/latest` | `waf:read` | - | `200 { scan_result }` (`scan_result` may be `null`). |

## WAF report export APIs

Developer-validation metadata-only exports with custody manifests. **Not** immutable storage, external signing, or production signoff.

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| GET | `/v1/waf/reports/:kind/export` | `waf:read` | `format=json\|markdown` (default `json`) | JSON: `200 { payload, custody }`. Markdown: `200` redacted `text/markdown` body with custody section. Unknown `kind` → `400 waf_report_kind_invalid`. |

Allowed `kind`: `executive_coverage`, `technical_evidence`, `drift_audit`, `connector_health`, `compliance_audit`, `board_roadmap_brief`.

`board_roadmap_brief`: CISO/board audience; includes coverage trend, Tier 1–2 summary counts, vendor mix, geography highlights, procurement justification narrative (metadata only), and links to roadmap API — no raw policy bodies. Payloads use declared assets, coverage, validation runs, drift events, and connector metadata only—no raw bodies, headers, tokens, secrets, or provider URLs. `compliance_audit` adds control-mapping appendix and exception register per [WAF Compliance Audit Evidence](../product/12-waf-compliance-audit-evidence.md). Audits `waf.report.exported` with digest metadata in dev-json; Postgres uses `runtime.services.wafPosture.exportWafReport` with `auditRepository.appendAuditEvent`. Immutable retention/signing remains **open**.

### API artifact sync rule

Any new or changed WAF route in this contract must be reflected in `docs/api/waf-posture-openapi.json` and covered by `npm run api:waf:openapi:check` before the related `PROGRESS.md` WAF row is marked complete.

## WAF orchestration APIs

Dev-json routes are implemented in `src/server.mjs`. Postgres mode wires persistence/runtime through `createPostgresRuntime()` (`runtime.repositories.wafOrchestrator`, `runtime.services.wafOrchestrator`) backed by `db/migrations/0011_waf_orchestrator.sql`, `db/migrations/0012_waf_orchestrator_execution_leases.sql`, `db/migrations/0013_waf_delegation_outbox.sql` / `db/schema.sql` (`waf_validation_plans`, `waf_baseline_approvals`, `waf_retest_requests`, `waf_baselines.updated_at`, tenant-consistent RLS/indexes). Routes return `503 { error: postgres_waf_orchestrator_unavailable }` only when `serviceDeps.wafOrchestrator` is not injected. Postgres **validation-plan execute** and **retest execute** use **safe continuation**: the work queue may include multiple assets × scenarios, with total queue length capped by the plan’s `max_concurrent` (preflight `422 waf_orchestration_batch_too_large` before mutation when exceeded). Because the signed-worker validation runtime enforces an active-run safety gate per target group, each execute call (or operator-runner tick) starts **at most one** new safe job through `runtime.services.testRuns.startTestRun` when `runtimeConfig.probeMode === 'signed-worker'` (safe check catalog + signed probe-worker path; no direct probe-job creation, no dev-json store imports; WAF scenario metadata is allowlisted and tamper-sensitive). Progress resumes from persisted `delegated_jobs`; while pending items remain, the plan or retest stays `running` and the response may include `continuation_required: true` until later ticks finish delegation. Plan state `completed` means all planned jobs are delegated—not final WAF posture or coverage closure. Retest `status: delegated` means all retest scenarios are delegated; `POST /v1/waf/retests/:id/complete` closes only from finalized test-run verdict evidence via injected `getTestRun` (completion evidence is bound to persisted `delegated_jobs` metadata where runtime fields are present). Postgres persistence applies retest status/verdict, linked drift `resolved`/`open`, and `waf.retest.completed` audit atomically in one tenant transaction via `completeRetestWithDriftAndAudit` (not posture closure by itself). Postgres **retest execute** ignores request-body verdict-ish fields and audits `waf.retest.delegated` when new jobs start—delegation-only; it does not set `verdict`, `completed_at`, or close drift. Fail closed when the orchestrator service, `startTestRun`, or `getTestRun` is missing, `probeMode` is not `signed-worker`, preflight/delegation preconditions fail, asset/target is missing, safe check is invalid, or persistence fails; blocks duplicate retest execute when already `delegated` or `completed` (`waf_retest_already_delegated`, `waf_retest_already_completed`). Postgres plan/retest execute claim a DB **execution lease** before any `startTestRun` side effect: nullable `execution_lock_token` and `execution_lock_expires_at` on `waf_validation_plans` and `waf_retest_requests`. **Claim** and **finish**/**release** lifecycle-gate eligible plan states (`draft`, `scheduled`, `running`) and retest statuses (`requested`, `running`); claim-before-side-effect; finish/release requires a matching token and clears the lease. Default lease TTL is at least the plan safe-run `timeout_ms` plus a 30s safety buffer (90s base when `timeout_ms` is absent; 90s default for retests without timeout), or the larger configured `executionLeaseMs` when set—reducing TTL-overlap duplicate ticks. **Crash-safe delegation outbox:** before each `startTestRun`, the service persists a `delegated_jobs` entry with `status: pending_start` (plus `reservation_id`, scenario, asset, check metadata) via `stageValidationPlanDelegation` / `stageRetestDelegation` while holding the execution lease; only after that reservation succeeds does it call `startTestRun`. On success it immediately stages `status: starting` with `test_run_id`/`probe_job_id`, then finishes with `status: delegated`. On `startTestRun` failure it marks the reservation `status: failed` and releases the execution lease. The next execute tick reconciles stale `pending_start` or `starting` entries to `failed` (best-effort `cancelTestRun` when `test_run_id` is present) so work items can resume without duplicate side effects. Legacy `delegated_jobs` entries without `status` but with `test_run_id` remain treated as delegated. **Cancel** (`cancelValidationPlanExecution`) atomically sets `cancelled`, clears any active execution lease, and blocks resurrecting a cancelled plan; then best-effort cancels delegated safe runs recorded on the returned cancelled plan row snapshot (`delegated_jobs` on `200 { validation_plan }`) via control-plane `cancelTestRun` (metadata/run cancellation only—not raw traffic generation). If a stale executor loses its finish token (for example after cancel or token mismatch), `finishValidationPlanExecution`/`finishRetestExecution` returns null, the service compensating-cancels any just-started safe run, best-effort releases with the claim token, and does not advance plan/retest state. If **finish throws** after a successful claim and `startTestRun`, the service still compensating-cancels `started_run_ids`, then **best-effort** `releaseValidationPlanExecution` / `releaseRetestExecution` with the claim token (release failures are swallowed) before returning `422 validation_plan_execution_failed`—reducing lease TTL lockout on handled finish failures. When a **claim miss** occurs (`claimValidationPlanExecution` / `claimRetestExecution` returns null), the service **re-reads** the row and maps to lifecycle errors instead of treating every miss as in-progress: plan execute → `409 validation_plan_cancelled` or `409 validation_plan_already_completed`; retest execute → `409 waf_retest_already_delegated` or `409 waf_retest_already_completed` (or `404` if the row vanished). Reserve `409 waf_orchestrator_execution_in_progress` for true active-lease conflicts—another holder still owns an unexpired lease on an eligible plan/retest. **Open production gates:** staging crash-recovery evidence for the outbox (kill process between `starting` staging and `delegated` finish, verify reconciliation + no duplicate `startTestRun`); externally scheduled operator runner (`scripts/waf-orchestrator-runner.mjs`, `npm run waf:orchestrator:runner`) staging scheduling/execution evidence; live/staging DB acceptance; provider connector workers; WAF add-on security/observability/release signoff—not production-ready until those gates close.

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| GET | `/v1/waf/validation-plans` | `waf:read` | filters | `{ items }`. |
| POST | `/v1/waf/validation-plans` | `waf:run` | safe orchestrator plan body | `201 { validation_plan }`. Rejects unsafe scenarios (`unsafe_orchestrator_plan`). |
| GET | `/v1/waf/validation-plans/scheduled` | `waf:read` | - | `{ items }`. |
| POST | `/v1/waf/validation-plans/:id/execute` | `waf:run` | - | Dev-json: `200 { validation_plan, delegated_jobs? }`. Postgres (injected service, signed-worker mode): `200 { validation_plan, delegated_jobs [, continuation_required] }` after at most one new safe job delegated this tick via `startTestRun`, resuming from `delegated_jobs` until plan `completed` (all jobs delegated—not final WAF verdict/coverage closure). Lifecycle fail closed: `404 validation_plan_not_found`; `409 validation_plan_already_completed`; `409 validation_plan_cancelled`; `409 waf_orchestrator_execution_in_progress` (unexpired execution lease held by another caller). Runtime fail closed: `503 postgres_waf_orchestrator_unavailable` (service absent); `422 waf_orchestrator_execution_not_ready` (`startTestRun` not injected); `422 waf_orchestrator_signed_worker_required` (probe mode not `signed-worker`); `422 waf_orchestration_batch_too_large` (assets × scenarios work queue exceeds plan `max_concurrent`, no mutation); `422 validation_plan_execution_failed` (invalid target group/assets/scenario or no job delegated). Safe test-run `startTestRun` denials (safe-window, rate/concurrency caps, SOC-gated high-scale) may pass through unchanged. |
| POST | `/v1/waf/validation-plans/:id/cancel` | `waf:run` | - | `200 { validation_plan }` (cancelled row snapshot). Postgres: atomically cancels eligible plans and clears active execution leases (`execution_lock_token` / `execution_lock_expires_at`); best-effort cancels delegated safe runs recorded on that returned cancelled row snapshot (`delegated_jobs`) via control-plane `cancelTestRun` (metadata/run cancellation only—not raw traffic generation); audit may include `cancelled_run_ids` when jobs existed. `404 validation_plan_not_found`; `409 validation_plan_not_cancellable` (including state/lease race). In-flight executors that lose the finish token compensating-cancel started runs and cannot resurrect `cancelled`. |
| GET | `/v1/waf/retests` | `waf:read` | optional `drift_event_id` filter | `{ items }` tenant-scoped retest requests (newest first). Dev-json and Postgres (`wafOrchestratorRepository.listRetestRequests`). |
| POST | `/v1/waf/retests/:id/execute` | `waf:run` | `{ note? }` (verdict-ish fields ignored in Postgres) | Dev-json: `200 { retest_request, validation_run? }`. Postgres (injected service, signed-worker mode): `200 { retest_request, delegated_jobs [, continuation_required] }` after at most one new safe scenario delegated this tick via `startTestRun`, resuming from `delegated_jobs` until `status: delegated` (all scenarios delegated—not verdict/drift closure; `running` while partial). Lifecycle fail closed: `404 waf_retest_not_found`; `409 waf_retest_already_completed`; `409 waf_retest_already_delegated` (fully delegated only; `running` may continue); `409 waf_orchestrator_execution_in_progress` (unexpired execution lease held by another caller). Runtime fail closed: `503 postgres_waf_orchestrator_unavailable`; `422 waf_orchestrator_execution_not_ready`; `422 waf_orchestrator_signed_worker_required`; `422 validation_plan_execution_failed` (missing asset/target, invalid safe check, empty retest plan, or delegation persistence failure). `404 waf_drift_event_not_found`; `404 waf_asset_not_found`. Safe test-run `startTestRun` denials may pass through unchanged. |
| POST | `/v1/waf/retests/:id/complete` | `waf:run` | - | Postgres (injected service): `200 { retest_request, verdict, delegated_jobs }` when all delegated test runs are terminal with verdict evidence via `getTestRun` (evidence bound to `delegated_jobs` metadata). Persists retest completion, drift transition, and `waf.retest.completed` audit atomically via `completeRetestWithDriftAndAudit` (one tenant transaction). Fail closed: `404 waf_retest_not_found`; `409 waf_retest_already_completed`; `422 waf_retest_closure_not_ready` (not delegated, missing runs, job/evidence mismatch, or verdict evidence not finalized); `404 waf_drift_event_not_found`; `503 postgres_waf_orchestrator_unavailable`. |

**Operator runner (externally scheduled):** `scripts/waf-orchestrator-runner.mjs` (`npm run waf:orchestrator:runner`) is not part of API startup and is not an in-repo daemon—schedule it via cron, Kubernetes CronJob, CI, or this runbook. It requires `ASTRANULL_DATABASE_URL`, explicit tenant scope (`--tenant-id` or `--tenant-ids-file`), and signed-worker probe mode (`ASTRANULL_PROBE_MODE=signed-worker` plus `ASTRANULL_PROBE_WORKER_SECRET`). `--dry-run` lists runnable/scheduled plans without executing; apply mode calls `executeValidationPlan` once per scheduled plan per run (safe continuation: at most one new `startTestRun` per plan per tick, `max_concurrent` preflight on full queue). Success means delegation recorded in metadata-only summaries—not final WAF verdict or coverage closure. Staging/live DB execution evidence remains an open production proof item.

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

Routes are under `/v1/waf/cve-pipeline` (WAF add-on namespace). See [Live Exposure Defense CVE Pipeline](../detection/15-live-exposure-defense-cve-pipeline.md) for feed ingest, validation executor, and retest closure behavior.

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| GET | `/v1/waf/cve-pipeline` | `waf:read` | filters | `{ items }`. |
| POST | `/v1/waf/cve-pipeline` | `waf:write` | pipeline item body | `201 { item }`. |
| POST | `/v1/waf/cve-pipeline/ingest` | `waf:write` | `{ items: [...] }` feed batch | `202 { ingested, skipped }`. |
| POST | `/v1/waf/cve-pipeline/:id/triage` | `waf:write` | - | `200 { item }`. |
| POST | `/v1/waf/cve-pipeline/:id/match` | `waf:write` | - | `200 { item, matches }`. |
| POST | `/v1/waf/cve-pipeline/:id/validate` | `waf:run` | safe validation request | `201 { validation_runs }`. |
| POST | `/v1/waf/cve-pipeline/:id/retest` | `waf:run` | `{ note? }` | `200` or `201` post-mitigation retest + closure metadata. |
| POST | `/v1/waf/cve-pipeline/:id/recommend` | `waf:write` | `{ vendor }` | `201 { recommendation }`. |
| PATCH | `/v1/waf/cve-pipeline/:id/stage` | `waf:write` | `{ stage }` | `200 { item }`. |

### Multi-vendor CVE playbook APIs (planned — WAF-020)

When asset matches span multiple vendors, grouped playbooks coordinate mitigation and retest. See [Multi-Vendor CVE Mitigation Playbook](../detection/17-multi-vendor-cve-mitigation-playbook.md).

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| GET | `/v1/waf/cve-pipeline/:id/playbook` | `waf:read` | - | `{ playbook }` with `vendor_slices[]`. |
| POST | `/v1/waf/cve-pipeline/:id/playbook/approve` | `waf:write` | `{ note? }` | `{ playbook }` ready for ticketing. |
| POST | `/v1/waf/cve-pipeline/playbooks/:id/retest` | `waf:run` | - | `201` coordinated safe retest across vendor slices. |

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
| `waf.validation_plan.executed` | plan id, target group, delegated job counts, test_run/probe_job ids, plan state. |
| `waf.retest.delegated` | retest id, drift event id, delegated job counts, test_run/probe_job ids, retest status. |
| `waf.retest.completed` | retest id, drift event id, verdict, delegated job counts, test_run/probe_job ids. |

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
| `unsafe_orchestrator_plan` | Validation plan create: scenario/profile exceeds safe orchestrator allowlist. |
| `postgres_waf_orchestrator_unavailable` | Postgres WAF orchestrator service not injected. |
| `validation_plan_not_found` | Plan id missing or cross-tenant. |
| `validation_plan_already_completed` | Plan execute/cancel: plan already in completed state. |
| `validation_plan_cancelled` | Plan execute: plan was cancelled. |

| `waf_orchestrator_execution_not_ready` | Plan execute: `startTestRun` not available on runtime. |
| `waf_orchestrator_signed_worker_required` | Plan execute: `probeMode` must be `signed-worker`. |
| `waf_orchestration_batch_too_large` | Plan execute: assets × scenarios work queue exceeds plan `max_concurrent` (preflight, no mutation). |
| `validation_plan_execution_failed` | Plan/retest execute: invalid plan inputs or delegation produced no job / persistence failed after start. |
| `waf_retest_closure_not_ready` | Retest complete: retest not delegated, delegated runs missing, or verdict evidence not finalized. |
| `waf_retest_not_found` | Retest id missing or cross-tenant. |
| `waf_retest_already_completed` | Retest execute: retest already completed (duplicate closure guard). |
| `waf_retest_already_delegated` | Retest execute: retest already fully delegated (`status: delegated`); duplicate execute blocked (`running` retests may continue). |
| `waf_orchestrator_execution_in_progress` | Plan/retest execute: after a claim miss re-read, another caller still holds an unexpired DB execution lease on the same eligible plan or retest (`execution_lock_token` / `execution_lock_expires_at`). Not returned when the re-read shows `cancelled`/`completed` plan or `delegated`/`completed` retest—those map to `validation_plan_cancelled`, `validation_plan_already_completed`, `waf_retest_already_delegated`, or `waf_retest_already_completed`. Lease TTL defaults to safe-run timeout plus buffer (or larger configured lease). |
| `waf_drift_event_not_found` | Drift-linked retest/create: drift event missing or cross-tenant. |
| `waf_report_kind_invalid` | Report export: unknown `kind` query path segment. |

## Done criteria

Completion checklist for this contract (not all items are satisfied yet):

- [x] Endpoints behave per tables above, including Postgres validation-plan execute HTTP integration tests (`tests/unit/server-postgres-mode.test.mjs`: RBAC `waf:run`, injected success with `delegated_jobs` and `runtimeConfig.persistenceMode=postgres`, lifecycle/lease error propagation without dev-store fallback).
- [x] Feature flag off returns safe disabled errors.
- [x] RBAC enforced per endpoint.
- [x] All raw payload/header/body fields rejected.
- [x] Machine-readable OpenAPI artifact published from this contract (**local** — [`docs/api/waf-posture-openapi.json`](../api/waf-posture-openapi.json), validated by `npm run api:waf:openapi:check`; live endpoint parity and external signoff **open**).
- [x] Postgres plan/retest execute concurrent tick coordination via developer-validation-hardened DB execution leases (`execution_lock_token`, `execution_lock_expires_at`; claim-before-`startTestRun`; claim/finish lifecycle-gate plan states and retest statuses; claim miss re-read maps lifecycle errors; TTL at least safe-run `timeout_ms` + 30s buffer or larger configured lease; validation-plan cancel atomically clears active leases and best-effort cancels delegated safe runs on the returned cancelled row snapshot (`delegated_jobs` on `200 { validation_plan }`); `409 waf_orchestrator_execution_in_progress` only for true lease conflicts; matching-token finish/release; compensating cancel of just-started safe runs when finish returns null or throws, plus best-effort release on finish null/throw—cannot resurrect `cancelled`).
- [x] Crash-safe delegation outbox in `delegated_jobs_json` (`0013_waf_delegation_outbox.sql`): `pending_start` reservation before `startTestRun`, `starting` staging with run ids after success, `delegated` on finish, `failed` on start failure or stale reconciliation; `stageValidationPlanDelegation` / `stageRetestDelegation` persist while holding execution lease. **Open:** staging kill/crash evidence between `starting` and `delegated` finish (reconciliation path implemented; production proof still required).
- [ ] Externally scheduled orchestrator runner staging/live execution evidence; live/staging DB acceptance; provider connector workers; WAF security/observability/release signoff (**open**—WAF orchestrator not production-ready until closed).
