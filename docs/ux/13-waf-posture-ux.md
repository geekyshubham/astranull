# WAF Posture UX

## Navigation

Add top-level or product-tab entry: `WAF Posture`.

Sub-tabs:

| Tab | Purpose |
|---|---|
| Overview | Executive coverage, risk, drift, SLA, vendor mix, and geography summary. |
| Roadmap | Tiered WAF deployment priorities (Tier 1–4). |
| Assets | Asset-level posture table. |
| Drift | Configuration/behavior drift queue. |
| Validation Runs | WAF validation history and evidence. |
| CVE Pipeline | CVE-to-exposure status and WAF recommendations. |
| Discovery Inbox | Optional discovered candidate assets. |
| Integrations | WAF/CDN/cloud/CNAPP connector setup and health. |
| Reports | WAF posture exports and audit packs. |

## Overview cards

| Card | Shows |
|---|---|
| WAF coverage | Protected / Underprotected / Unprotected / Unknown % with `coverage_ratio` trend sparkline. |
| Critical unprotected assets | Count and top 5. |
| Vendor mix | Protected asset share by detected WAF/CDN vendor (`GET /v1/waf/coverage/vendors`). |
| Entity coverage | Rollup by business unit/subsidiary (`GET /v1/waf/coverage/entities`). |
| Criticality coverage | Rollup by `business_criticality` (`GET /v1/waf/coverage/criticality`). |
| Geography coverage | Rollup by declared region/country (`GET /v1/waf/coverage/geography`). |
| Drift events | Open critical/high drift. |
| Origin bypass / control bypass | Confirmed bypass count; label as control bypass in UI copy. |
| Validation pass rate | Last 30 days pass/fail/inconclusive (tenant-wide). |
| CVE exposure SLA | Items by pipeline state. |
| Connector health | Active/degraded/error connectors. |

## Deployment roadmap tab

| Column | Details |
|---|---|
| Tier | Tier 1 (0–14d), Tier 2 (15–60d), Tier 3 (61–180d), Tier 4 (quarterly review). |
| Asset | Hostname, environment, owner. |
| Risk | 0–100 with expandable factor breakdown. |
| Status | Protected / Underprotected / Unprotected / Unknown. |
| Primary gap | Top reason code (for example origin bypass, monitor-only). |
| Recommended action | Deploy WAF, fix blocking mode, close bypass, refresh rules, exception. |
| Vendor | Detected product or `none`. |

Data source: `GET /v1/waf/coverage/risk-roadmap`. Empty state explains when risk scoring has not run yet.

Optional **Vendor consolidation** panel (read-only): footprint by vendor, overlap candidates, advisory opportunities from `GET /v1/waf/coverage/vendor-consolidation`.

## Assets table

| Column | Details |
|---|---|
| Asset | Hostname/URL, target group, environment. |
| Status | Protected, Underprotected, Unprotected, Unknown, Excluded. |
| Vendor/Product | Detected WAF/CDN product and confidence. |
| Validation | Last validation result and time. |
| Pass rate | Scenario pass rate for lookback window (per asset). |
| Rule health | Rule count and last update (connector mode; `—` when unavailable). |
| Drift | Open drift count/reason. |
| Control bypass | None/suspected/confirmed. |
| Risk | 0-100 with factors and tier badge. |
| Owner | Owner/business unit. |
| Actions | Run validation, view evidence, create ticket, set exception. |

## Asset detail page

Sections:

1. Posture summary.
2. Evidence timeline.
3. WAF fingerprint signals.
4. Marker/scenario result matrix.
5. Origin-bypass result.
6. Connector config summary if enabled.
7. Drift history.
8. CVE matches.
9. Recommendations and tickets.
10. Baseline and exceptions.

## Scenario matrix

| Scenario | Expected | Observed | Result | Confidence |
|---|---|---|---|---|
| Marker rule | Block before origin | Blocked; agent not observed | Pass | High |
| Origin direct path | No reach | Agent observed | Fail | High |
| Rate limit marker | 429/challenge | Normal app response | Fail | Medium |
| Connector mode | Blocking | Monitor | Fail | High |

## Drift queue (`#waf-posture`)

The WAF Posture console includes a **Drift events** section on `#waf-posture` (developer-validation UI; not production signoff). Operators can see open drift without leaving the core posture view.

| Column | Details |
|---|---|
| Drift type | Mode change, rule count, marker failed, origin bypass, stale rules. |
| Asset/policy | Affected asset or WAF policy. |
| Before → After | Metadata-only safe summary (no raw policy bodies, payloads, or secrets). |
| Severity | Critical/high/medium/low. |
| First seen | Timestamp. |
| Owner | Routed owner. |
| Status | Open/ack/remediation/retest/resolved. |
| Retest | Retest follow-up controls and id/status hydrated from `GET /v1/waf/retests` (newest per drift event) with session override after request/execute/complete in the same UI session. |
| Action | Patch status (`PATCH /v1/waf/drift-events/:id`), request retest, execute retest, complete retest (RBAC `waf:write` / `waf:run`). |

**Developer-validation controls (local / dev-json and Postgres when orchestrator is injected):**

- List and render drift events from `GET /v1/waf/drift-events` (no client-side filter controls in this slice).
- Patch drift workflow status only via UI (`PATCH /v1/waf/drift-events/:id`; ack/remediation/retest/resolved paths per API contract — the API may accept notes, but this UI slice does not expose a note input).
- **Request retest** — `POST /v1/waf/drift-events/:id/retest` creates a retest request; UI shows the returned id and state (also listed via `GET /v1/waf/retests`).
- **Execute retest** — `POST /v1/waf/retests/:id/execute` delegates safe signed-worker jobs (continuation may be required); UI surfaces `delegated_jobs` / `continuation_required` metadata only.
- **Complete retest** — `POST /v1/waf/retests/:id/complete` closes from finalized test-run verdict evidence and updates linked drift status; UI reflects terminal retest and drift status after success.

Empty and error states must explain feature disable (`waf_feature_disabled`), missing orchestrator (`postgres_waf_orchestrator_unavailable`), and safe-run gates (`waf_orchestrator_signed_worker_required`, execution-in-progress lease conflicts) without echoing sensitive payloads.

**Not production-ready:** drift queue UI satisfies developer-validation coverage only. Immutable report storage/signing, full WAF add-on accessibility/browser matrix evidence, staging/live DB acceptance, WAF orchestrator runner scheduling/execution evidence, provider connector workers, connector config drift workers, and security/observability/release signoff remain open per [`docs/release-checklist.md`](../release-checklist.md).

## WAF reports panel (`#waf-posture`)

Developer-validation export controls on `#waf-posture`:

| Control | Behavior |
|---|---|
| Report kind | `executive_coverage`, `technical_evidence`, `drift_audit`, `connector_health`, `compliance_audit`, `board_roadmap_brief`. |
| Format | `json` (download + custody preview) or `markdown` (download only). |
| Export | `GET /v1/waf/reports/:kind/export?format=…` (`waf:read`). |
| Custody preview | Summary-only manifest preview (digest, artifact id, subjects)—no full payload dump on page. |

**Not production-ready:** local/developer export with custody manifest exists; immutable storage, staging evidence, browser/accessibility matrix, and production signoff remain **open**.

## WAF connectors panel (`#waf-posture`)

Developer-validation connector health on `#waf-posture` (Integrations slice; not production signoff).

| Column | Details |
|---|---|
| Provider | Normalized connector provider (for example `cloudflare`, `aws_waf`). |
| Name | Operator-defined connector label (bounded metadata). |
| Status | `active`, `degraded`, `error`, `disabled`, or provider-mapped health states. |
| Last poll | `last_poll_at` when present, otherwise `last_success_at` from successful ingest/outbound poll. |
| Health summary | Metadata-only summary: `read_only`, allowlisted config presence (`zone_ref_hash: configured`), outbound credential configured/none, poll interval, and bounded `last_error_at` when status is unhealthy — no secrets, policy bodies, or raw snapshot payloads. |
| Action | **Poll now** — `POST /v1/connectors/:id/poll` (`waf:connector_write`). Triggers outbound provider pull when `secret_id` and supported provider are configured; otherwise supports manual metadata snapshot ingest via API. Disabled connectors cannot be polled from the UI. |

**Developer-validation controls (local / dev-json and Postgres when `runtime.services.wafPosture` is injected):**

- **List connectors** — `GET /v1/connectors` (`waf:connector_read`).
- **Poll now** — `POST /v1/connectors/:id/poll` with empty body for outbound-or-noop; poll results surface in `#wafOut` as a redacted summary (`poll_job` status, `snapshot_count`, safe `health` codes) — never full snapshot bodies or credentials.
- **Graceful degradation** — list failures show `connectors_unavailable` warning; poll failures map `connector_poll_failed`, `connector_not_found`, and permission errors to safe guidance without echoing provider responses.

**Not production-ready:** connector panel is developer-validation visibility only. Provider connector workers, vault-backed credential rotation UI, staging provider evidence, connector-to-asset reconciliation, config drift workers, and security/observability/release signoff remain **open** per [`docs/release-checklist.md`](../release-checklist.md).

## Validation-plan operator panel (`#waf-posture`)

The WAF Posture console includes a **Validation plans (operator)** section on `#waf-posture` for developer validation. Operators can inspect and drive safe WAF validation plans without leaving the core posture view.

| Column | Details |
|---|---|
| Plan id | Stable plan identifier. |
| Target group | Declared scope for the plan. |
| State | `draft`, `scheduled`, `running`, `completed`, `cancelled`. |
| Scenarios | Safe catalog scenarios (for example marker, fingerprint). |
| Schedule | Next run / cadence metadata when scheduled. |
| Delegation | Metadata-only `delegated_jobs` / `continuation_required` summary after execute (no raw payloads). |
| Action | Create plan, execute, cancel (RBAC `waf:write` / `waf:run` per API contract). |

**Developer-validation controls (local / dev-json and Postgres when `runtime.services.wafOrchestrator` is injected):**

- **List all plans** — `GET /v1/waf/validation-plans`.
- **List scheduled plans** — `GET /v1/waf/validation-plans/scheduled` (operator visibility for externally scheduled work).
- **Create plan** — `POST /v1/waf/validation-plans` with safe scenarios and bounded concurrency (`max_concurrent`).
- **Execute plan** — `POST /v1/waf/validation-plans/:id/execute` delegates **safe signed-worker jobs only**; UI surfaces delegation metadata (`delegated_jobs`, `continuation_required`) and plan state transitions. Plan `completed` means all jobs in the plan queue were delegated — **not** final WAF posture closure or coverage signoff.
- **Cancel plan** — `POST /v1/waf/validation-plans/:id/cancel` when lifecycle allows; UI reflects terminal cancelled state.

When the optional WAF orchestrator service is not injected (Postgres without orchestrator wiring), the panel **degrades gracefully**: explain `postgres_waf_orchestrator_unavailable`, disable execute/cancel/create that require orchestrator, and avoid echoing sensitive payloads. Same fail-closed surfaces as drift retest flows for `waf_orchestrator_signed_worker_required`, execution lease conflicts (`waf_orchestrator_execution_in_progress`), and safe-run gates.

**Not production-ready:** validation-plan operator UI is developer-validation coverage only. Production scheduling still runs **externally** via `npm run waf:orchestrator:runner` (cron/Kubernetes CronJob/on-call) — see [`docs/operator-local-runbook.md`](../operator-local-runbook.md). Staging scheduling/execution evidence for the runner, immutable report storage/signing, accessibility/browser matrix evidence, live/staging DB acceptance, provider connector workers, connector config drift workers, and security/observability/release signoff remain **open** per [`docs/release-checklist.md`](../release-checklist.md).

## CVE pipeline UX

| Column | Details |
|---|---|
| CVE | CVE id, severity, known exploited marker. |
| State | Ingested, triaged, matched, validation pending, exposed, mitigation recommended, resolved. |
| Affected assets | Count and critical assets. |
| WAF coverage | Protected/underprotected/unprotected among matches. |
| Recommendation | Vendor-specific mitigation available? |
| SLA | Time since publish and target SLA. |

## Discovery inbox UX

| Column | Details |
|---|---|
| Candidate | Hostname/URL/domain. |
| Entity | Subsidiary/brand/business unit. |
| Source | DNS, CT, connector, import, registry, page link. |
| Confidence | High/medium/low. |
| Ownership | Likely owned, unknown, third-party. |
| Action | Approve as target, reject, exception, assign review. |

## Integrations UX

| Connector card | Shows |
|---|---|
| Provider | Cloudflare/AWS/Azure/etc. |
| Status | Active/degraded/error/disabled. |
| Last poll | Timestamp. |
| Data pulled | Zones/policies/assets/vulnerabilities/tickets. |
| Permission gaps | Missing scopes. |
| Actions | Validate, poll now, rotate secret, disable. |

## Microcopy

| Situation | UI text |
|---|---|
| WAF detected but not validated | `WAF detected, but AstraNull has not proven it blocks before origin yet.` |
| Underprotected due to marker | `The WAF exists, but the safe marker reached the app. Review blocking mode or marker rule.` |
| Outside-in limit | `AstraNull inferred behavior from external evidence. Connect the WAF API for exact rule/config details.` |
| Candidate asset | `This asset was discovered but is not tested until you approve it.` |
| Recommendation | `Review and deploy this rule in your WAF console. AstraNull will retest after deployment.` |

## Reports

| Report | Audience |
|---|---|
| WAF Executive Coverage | CISO/board. |
| WAF Technical Evidence | Security engineers. |
| WAF Drift Audit | Audit/compliance. |
| WAF Compliance Audit | GRC/auditors with control-mapping appendix. |
| Board Roadmap Brief | CISO/board; Tier 1–2 summary, vendor/geography highlights, procurement justification narrative. |
| CVE Exposure Response | Incident/vulnerability management. |
| Connector Health Report | Platform/security operations. |

## Done criteria

- WAF overview provides actionable posture in one screen including vendor mix and geography rollups when analytics APIs are available.
- Deployment roadmap tab renders Tier 1–4 items from risk-roadmap API with factor breakdown.
- Asset table shows per-asset pass rate and connector rule health when data exists.
- Asset detail implements all ten sections with effectiveness metrics and control-bypass status.
- `#waf-posture` drift queue lists and renders drift events with metadata-only before/after summaries, status-patch controls, and retest follow-up hydrated from `GET /v1/waf/retests` (developer validation).
- `#waf-posture` reports panel exports metadata-only WAF reports with custody manifest preview (developer validation; immutable storage/signing open).
- `#waf-posture` connectors panel lists connector health metadata and exposes poll-now with safe poll-result summaries in `#wafOut` (developer validation; provider workers and staging evidence open).
- `#waf-posture` validation-plan operator panel lists all/scheduled plans and exposes create/execute/cancel for safe validation plans with orchestrator-unavailable graceful degradation (developer validation; production runner evidence open).
- Asset detail can explain every verdict with evidence.
- Discovery inbox cannot accidentally launch tests.
- UI clearly distinguishes detected, validated, underprotected, and unknown.
- Reports export with custody manifest and redacted evidence (**local/developer slice shipped**; immutable storage/signing and production signoff **open**).
