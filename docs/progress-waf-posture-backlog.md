# WAF Posture Build Backlog

## Doc audit status

Enterprise WAF posture **product scaffolding is doc-complete** as of 2026-07-03. See [Exposure Management Research Map — Doc audit status](sources/exposure-management-research-map.md#doc-audit-status-waf-posture-gap-closure) for the recommended-additions history and re-audit checklist. Implementation status for WAF-001–WAF-022 is tracked in `PROGRESS.md`; rows marked `[x]` are developer-validation complete unless their completion goal calls out remaining external promotion gates.

## Epic summary

| Epic | Status | Owner agent |
|---|---|---|
| WAF product spec and feature flags | Complete for first runtime slice | Product agent. |
| Safe validation policy | In progress | Security agent. |
| Data model and migrations | In progress; first runtime route family wired | Backend/DB agent. |
| WAF fingerprinting catalog | In progress | Detection agent. |
| Marker validation + correlation | In progress | Detection/probe/agent agents. |
| Drift baselines/events | In progress; first behavior-drift event slice wired | Backend/detection agent. |
| Connector framework | In progress; metadata-only config/snapshot APIs wired | Integration agent. |
| Cloudflare/AWS connector MVP | Not started | Integration agent. |
| WAF dashboard UX | In progress | Frontend agent. |
| Remediation ticket/SIEM connectors | In progress; action-item APIs and dev-json/Postgres repository parity wired in developer validation | Integration/workflow agent. **Open:** outbound Jira/ServiceNow/SIEM/SOAR delivery and staging evidence. |
| CVE pipeline | In progress; CVE pipeline APIs, metadata-only feed ingest, and dev-json/Postgres repository parity wired in developer validation | Backend/detection/product agents. **Open (external):** safe validation executor and staging evidence. |
| Discovery inbox | In progress; discovery inbox/API and dev-json/Postgres repository parity wired in developer validation | Product/backend/frontend agents. **Open:** DNS/CT/connector data-source integrations and staging evidence. |
| Active protection / supply chain | In progress; `/v1/waf/supply-chain/*` APIs and dev-json/Postgres repository parity wired in developer validation | Product/backend agents. **Open:** live data-source integrations, legal gate formalization, staging evidence. |
| Reports and custody | In progress: `GET /v1/waf/reports/:kind/export` (dev-json + Postgres `exportWafReport`), `compliance_audit`, `board_roadmap_brief`, custody via `buildCustodyManifest`, `#waf-posture` export/custody preview, integration/e2e tests, OpenAPI artifact. **Open (external):** immutable storage/signing, staging evidence, browser/accessibility matrix, production signoff. |
| Risk scoring and roadmap | Developer-validation complete | Backend/product agent. `wafRiskService`, tier assignment, factor JSON on snapshots, and roadmap API are implemented. **Open (external):** staging/live evidence and release signoff. |
| Coverage analytics APIs | Developer-validation complete | Backend/frontend agent. Vendors, entities, geography, criticality, trend, risk-roadmap, vendor-consolidation routes, and OpenAPI parity are implemented. **Open (external):** staging/live evidence and rollup-backed trend proof where required. |
| Executive analytics UX | Developer-validation complete | Frontend agent. Vendor mix, geography, roadmap tab, per-asset effectiveness columns, and asset detail effectiveness are implemented. **Open (external):** browser/accessibility matrix and staging signoff. |
| Scenario cadence and catalog scale | Developer-validation complete | Detection/security agent. 50+ vendor catalog, scenario intake, and control-bypass taxonomy UX are implemented. **Open (external):** staging/customer validation. |
| Analytics schema extensions | Developer-validation complete | Backend/DB agent. Geography fields, risk/scenario rollup fields, and coverage daily rollups landed via `0016_waf_risk_analytics.sql` and `0017_waf_analytics_extensions.sql`. **Open (external):** live/staging DB acceptance and scheduled rollup evidence. |
| Product catalog seed pipeline | Developer-validation complete | Detection/backend agent. `waf_products` seed artifact, validate/seed scripts, and regression fixtures are implemented. **Open (external):** operator seed custody and staging signoff. |
| Multi-vendor CVE playbooks | Developer-validation complete | Backend/product agent. Grouped playbook API, coordinated retest workflow, and parent/child tickets are implemented. **Open (external):** staging security review, immutable ticket custody, live multi-vendor operator workflow. |
| QA/security gates | In progress | QA/security agent. |

## Milestone 1 - No-access WAF posture MVP

| Task | Done when |
|---|---|
| Add feature flag | Done: `ASTRANULL_WAF_POSTURE_ENABLED` and `ASTRANULL_EXTERNAL_DISCOVERY_ENABLED` default off; disabled WAF API/UI fails closed. |
| Add WAF asset metadata | Done for dev-json/API/schema/Postgres runtime: declared WAF assets link to tenant target groups and can be marked WAF-required. |
| Add WAF check catalog entries | Done for safe slice: `waf.fingerprint.safe`, `waf.marker_rule.safe`, `waf.origin_bypass.safe`, `waf.low_rate_limit.safe` plus enriched `l7.waf_marker_rule.safe` with signed WAF probe metadata. |
| Add probe worker WAF profiles | Done for safe slice: signed jobs preserve only allowlisted WAF scenario metadata and enforce max requests/timeouts. |
| Add agent WAF observation | Done for safe slice: agent advertises WAF observer capabilities and uploads sanitized canary/log-pointer fields with nonce hash only. |
| Add correlation logic | Partial: metadata-only finalization classifies protected/underprotected/unprotected/unknown and rejects naked protected claims without bound safe test-run evidence or explicit scenario evidence; dev-json validation can derive posture from bound probe/agent events. Failed posture now feeds metadata-only findings and first behavior-drift events. Dev-json WAF orchestrator routes (validation plans, baseline approve, drift retest, retest execute) are exposed; Postgres injects `runtime.services.wafOrchestrator` (`0011_waf_orchestrator`) for plan/approval/retest persistence and list/create/cancel paths, with `postgres_waf_orchestrator_unavailable` when the service is missing. Postgres plan/retest execute use safe continuation (`max_concurrent` caps full assets×scenarios queue; at most one new `startTestRun` per tick; `continuation_required` + `running` until `delegated_jobs` complete; plan `completed` = all jobs delegated, not posture closure) when `probeMode === 'signed-worker'`; preflight `waf_orchestration_batch_too_large` when queue exceeds `max_concurrent`. Postgres retest execute ignores request-body verdict fields, sets `delegated` when all scenarios delegated, audits `waf.retest.delegated`; `POST /v1/waf/retests/:id/complete` closes from finalized test-run verdict evidence via `getTestRun` (bound to `delegated_jobs` metadata); `completeRetestWithDriftAndAudit` atomically persists retest status/verdict, drift `resolved`/`open`, and `waf.retest.completed` in one tenant transaction. Adapter/repository tests cover signed-worker continuation, `max_concurrent` preflight, `completeRetest` evidence gates, `completeRetestWithDriftAndAudit` rollback, `startTestRun` error propagation, `waf_retest_already_delegated`, invalid asset `target_id` fail-closed, and compensating cancellation after post-delegation persistence failure. Postgres plan/retest execute use developer-validation-hardened DB execution leases coordinate concurrent API/runner execute ticks (`execution_lock_token`, `execution_lock_expires_at`; claim-before-`startTestRun`; claim/finish lifecycle-gate plan states and retest statuses; claim miss re-read maps lifecycle errors; TTL at least safe-run `timeout_ms` + 30s buffer or larger configured lease; validation-plan cancel clears active leases and best-effort cancels delegated safe runs in `delegated_jobs`; `409 waf_orchestrator_execution_in_progress` only for true lease conflicts; stale-finish/null-finish compensating cancel with best-effort lease release; finish throw after `startTestRun` also best-effort releases the lease—cannot resurrect `cancelled`; hard process crash after `startTestRun` before `delegated_jobs` persistence remains crash-recovery/staging evidence open—no production at-most-once delegation claim). **Open:** staging scheduling/execution evidence for `npm run waf:orchestrator:runner`; Postgres live-event correlation parity. |
| Add findings | Done for first slice: underprotected/unprotected WAF posture creates or refreshes deduplicated, metadata-only open findings in dev-json and Postgres, linked to safe scenario/snapshot evidence. **Open:** outbound ticket/SIEM/SOAR delivery and retest-based closure (action-item APIs and Postgres parity exist in developer validation only). |
| Add basic dashboard | Done for first console: feature-disabled state, coverage cards, asset table, validation history, and safe marker actions. |
| Add tests | Done for first slice: unit/integration/e2e/schema tests for flags, contracts, RLS/migrations, dev-json and Postgres WAF APIs/adapters, UI, signed WAF probe profiles, sanitized agent WAF observations, and protected-finalize evidence gates. |

## Milestone 2 - Drift

| Task | Done when |
|---|---|
| Baseline API | User can propose/approve active baseline. |
| Scheduled validation | WAF checks run on schedule under safe windows. |
| Drift compare | In progress: protected-to-weakened behavior changes create or refresh open metadata-only drift events for marker failures, origin-bypass, mode/fingerprint loss in dev-json and Postgres. Dev-json and Postgres baseline approve and drift/retest orchestration persistence are wired (`waf_baseline_approvals`, `waf_retest_requests`); Postgres plan/retest execute use safe continuation (one new signed-worker job per tick; `delegated_jobs` persistence; delegation-only); `POST /v1/waf/retests/:id/complete` closes from evidence-backed verdicts via `getTestRun` and atomically updates retest + linked drift + `waf.retest.completed` via `completeRetestWithDriftAndAudit` in developer validation. **Open:** connector config drift workers, scheduled compare worker, and staging/live retest-to-drift transition evidence. |
| Notifications | First slice: critical/high dev-json drift emits safe notification metadata; Postgres `notification_delivery_attempts` persist retry/DLQ metadata in developer validation with combined-mode retry parity. **Open:** provider routing/signoff, production redrive beyond metadata-only retry UI/API, and always-on retry scheduling. |
| Retest closure | Postgres `completeRetest` closes from delegated test-run verdict evidence only; `completeRetestWithDriftAndAudit` atomically persists retest status/verdict, linked drift status, and `waf.retest.completed` in developer validation. **Open:** production-live closure flow, approved-exception/baseline paths, and staging evidence. |

## Milestone 3 - Connectors

| Task | Done when |
|---|---|
| Generic connector framework | In progress: create/validate/poll/disable works for metadata-only config and snapshot ingestion in dev-json and Postgres; no outbound provider calls. **Open:** provider workers, secret-vault runtime validation, backoff/retry, status sync, UI. |
| Cloudflare connector | Open: zones/DNS/policy summaries normalized by an actual read-only provider worker. Current API accepts metadata-only Cloudflare connector records and snapshots only. |
| AWS connector | Open: WAFv2/CloudFront/ALB/API Gateway associations normalized by an actual read-only provider worker. Current API accepts metadata-only AWS connector records and snapshots only. |
| Connector snapshots | Metadata-only config hashes stored. |
| Config drift | Mode/rule count/hash changes create drift events. |
| Permission UX | Missing scopes shown clearly. |

## Milestone 4 - Remediation workflows

| Task | Done when |
|---|---|
| Action item grouping | In progress: `/v1/waf/action-items` APIs, dev-json/Postgres repository/service/runtime parity, and tenant+`waf_asset_id`+`primary_reason` dedupe (`0010`) in developer validation. **Open:** production-live persistence signoff. Related findings deduped at API layer. |
| Jira ticket creation | In progress: redacted connector payload builders in developer validation. **Open:** actual outbound Jira delivery; ticket contains evidence/recommendation/retest link. |
| ServiceNow ticket creation | In progress: redacted connector payload builders in developer validation. **Open:** actual outbound ServiceNow delivery; same fields mapped to incident/task/change. |
| Splunk/Sentinel events | In progress: `astranull.waf_event.v1` payload builder in developer validation. **Open:** actual outbound redacted event stream. |
| XSOAR feed | In progress: action-item feed shape in developer validation. **Open:** pull/push delivery to XSOAR. |
| Slack/webhook alerts | **Open:** critical drift/unprotected assets notify via live connectors. |
| Bidirectional ticket sync | **Open:** pull Jira/ServiceNow status/comments into action items when read scope granted. |

## Milestone 5 - CVE pipeline

| Task | Done when |
|---|---|
| CVE ingest | In progress: `/v1/waf/cve-pipeline` APIs and dev-json/Postgres parity in developer validation. **Open:** live CVE feed ingestion; items tracked with published date and severity. |
| Triage | In progress: triage scoring and state transitions in developer validation. **Open:** production-live feed-driven triage. Relevance score and state available. |
| Asset matching | In progress: match APIs and Postgres repository parity in developer validation. Matches to WAF assets by tech/CNAPP/import. |
| Recommendation templates | In progress: vendor-aware WAF guidance templates in developer validation. |
| Ticket workflow | **Open:** approved recommendations become live outbound tickets (API workflow exists in developer validation). |
| Retest loop | **Open:** post-mitigation retest updates finding in production-live flow. |
| Multi-vendor playbook | Grouped playbook per CVE across vendors; parent ticket + vendor slices; coordinated retest. |

## Milestone 6 - Optional discovery

| Task | Done when |
|---|---|
| Entity model | In progress: entity APIs and Postgres repository parity (`id === entity_id` on create) in developer validation. Parent/subsidiary/brand graph supported at API layer. |
| Candidate discovery | In progress: discovery inbox/API in developer validation. **Open:** passive DNS/CT/connector data sources; passive/import/connector candidates visible from live sources. |
| Approval gate | In progress: approval/rejection workflows and unapproved-candidate testing guard in developer validation. No tests run until approval. |
| Import to target group | **Open:** approved candidate creates target and WAF asset in production-live flow (API hooks exist in developer validation). |
| Discovery report | **Open:** shows candidate sources/confidence from live integrations. |

## Milestone 7 - Active protection / supply chain (optional)

| Task | Done when |
|---|---|
| Risk APIs | In progress: `/v1/waf/supply-chain/*` and dev-json/Postgres repository/service/runtime parity in developer validation. AP0 metadata-only assessment paths; no automated acquisition. |
| Remediation tickets | In progress: redacted ticket payloads with retest/reference link `/v1/waf/supply-chain/risks?risk_id=<id>` in developer validation. **Open:** live ticketing connectors. |
| Data sources | **Open:** DNS/CT/page-dependency/connector integrations beyond declared metadata. |
| Legal gate | **Open:** formal AP2/AP3 legal and customer authorization workflow. |

## Milestone 8 - Risk, coverage analytics, and compliance evidence

| Task | Done when |
|---|---|
| Risk scoring service | `wafRiskService` computes 0–100 scores with factor JSON; snapshots persist `risk_score` and tiers; unit tests cover tier boundaries. |
| Coverage trend and ratio | `GET /v1/waf/coverage` returns `coverage_ratio` and `trend[]` time series. |
| Vendor rollup API | `GET /v1/waf/coverage/vendors` returns vendor mix used by overview UI. |
| Entity rollup API | `GET /v1/waf/coverage/entities` returns business-unit/subsidiary coverage. |
| Geography rollup API | `GET /v1/waf/coverage/geography` returns region/country coverage from declared metadata. |
| Deployment roadmap API | `GET /v1/waf/coverage/risk-roadmap` returns Tier 1–4 ordered items with recommended actions. |
| Vendor consolidation advisory | `GET /v1/waf/coverage/vendor-consolidation` returns read-only advisory metadata. |
| Per-asset effectiveness | `GET /v1/waf/assets/:id` includes pass rate, rule health, control-bypass status. |
| Roadmap UX tab | `#waf-posture` roadmap tab renders tiers with factor drill-down. |
| Executive rollup cards | Overview shows vendor mix and geography cards when APIs are available. |
| Compliance audit report | `compliance_audit` export kind with control-mapping appendix and exception register. |
| OpenAPI sync | All coverage analytics routes documented in `docs/api/waf-posture-openapi.json`; `npm run api:waf:openapi:check` passes. |
| Scenario cadence process | Security-reviewed intake path for new scenario families documented and backlog-linked. |
| Catalog breadth R3 | Fingerprint catalog reaches 50+ entries with regression tests. |
| Criticality rollup API | `GET /v1/waf/coverage/criticality` returns executive breakdown by business criticality. |
| Coverage trend storage | `waf_coverage_daily_rollups` populated by nightly worker; `trend[]` served from rollups. |
| Analytics schema migration | `0016_waf_analytics_extensions.sql` (or equivalent) applied with RLS and tests. |
| Board roadmap brief report | `board_roadmap_brief` export kind with procurement justification section. |
| Block page scenario | `block_page_expectation` scenario family in catalog and validation matrix. |
| OpenAPI parity | All coverage analytics and playbook routes in `waf-posture-openapi.json`; check passes. |
| Product catalog seed | `npm run waf:catalog:validate` and `waf:catalog:seed` operational in dev-json/Postgres. |
| Multi-vendor CVE playbook API | `GET/POST` playbook routes on CVE pipeline with coordinated retest. |

## Release blockers

- Security review confirms no raw payloads/secrets stored.
- RLS and tenant isolation tests pass for every WAF table/API, including live/staging DB acceptance beyond static schema/repository checks (orchestrator tables in `0011_waf_orchestrator` included).
- `npm run waf:orchestrator:runner` implemented (runnable/scheduled plans, safe-continuation `executeValidationPlan` per plan per tick); Postgres plan/retest execute concurrent coordination implemented via developer-validation-hardened DB execution leases coordinate concurrent API/runner execute ticks (`execution_lock_token`, `execution_lock_expires_at`; claim-before-`startTestRun`; claim/finish lifecycle-gate plan states and retest statuses; claim miss re-read maps lifecycle errors; TTL at least safe-run `timeout_ms` + 30s buffer or larger configured lease; validation-plan cancel clears active leases and best-effort cancels delegated safe runs in `delegated_jobs`; `409 waf_orchestrator_execution_in_progress` only for true lease conflicts; stale-finish/null-finish compensating cancel with best-effort lease release; finish throw after `startTestRun` also best-effort releases the lease—cannot resurrect `cancelled`; hard process crash after `startTestRun` before `delegated_jobs` persistence remains crash-recovery/staging evidence open—no production at-most-once delegation claim). Staging scheduling/execution evidence for the runner, live/staging DB acceptance, provider connector workers, and WAF security/observability/release signoff remain open (`waf_orchestrator_execution_not_ready` and related errors fail closed when `startTestRun`/signed-worker preconditions are missing)—WAF add-on not production-ready.
- Connector config drift workers, live provider/customer evidence, and WAF add-on security signoff.
- Probe worker cannot exceed signed safe limits.
- Customer-declared target path still works with all WAF features disabled.
- Connector secrets rotate/revoke cleanly.
- UI and API never allow testing unapproved discovered candidates.
- Reports are redacted and have custody manifests (local/developer export exists; immutable retention/signing and staging evidence remain open).
