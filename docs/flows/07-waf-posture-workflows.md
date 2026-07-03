# WAF Posture Workflows

## 1. No-access WAF posture onboarding

| Step | Actor | Action |
|---|---|---|
| 1 | Customer admin | Enables WAF posture feature for tenant/environment. |
| 2 | Customer engineer | Selects existing target group or creates web target group. |
| 3 | Customer engineer | Adds URL/FQDN/API target and expected WAF requirement. |
| 4 | Customer engineer | Optionally installs/positions agent or canary. |
| 5 | Customer WAF owner | Creates harmless marker rule in WAF console. |
| 6 | AstraNull | Runs fingerprint + marker + origin-bypass safe checks. |
| 7 | AstraNull | Produces posture snapshot and findings if needed. |
| 8 | Customer | Reviews evidence, remediates, retests. |

Acceptance criteria:

- Works with zero cloud/WAF credentials.
- Max requests enforced by safe catalog.
- Strong verdict requires agent/canary when proving before-origin block.

## 2. Connector-enriched onboarding

| Step | Actor | Action |
|---|---|---|
| 1 | Customer admin | Creates read-only connector secret. |
| 2 | AstraNull | Validates connector permissions. |
| 3 | AstraNull | Pulls normalized snapshots. |
| 4 | AstraNull | Reconciles connector resources to approved WAF assets. |
| 5 | Customer | Approves proposed baseline. |
| 6 | AstraNull | Schedules drift comparison. |

Acceptance criteria:

- No plaintext secret returned.
- Permission gaps shown clearly.
- Connector data enhances posture but does not override failed external validation without explanation.

## 3. WAF drift detection

| Step | Actor | Action |
|---|---|---|
| 1 | AstraNull | Loads active baseline. |
| 2 | AstraNull | Runs scheduled safe validation and/or connector poll. |
| 3 | AstraNull | Compares latest result against baseline. |
| 4 | AstraNull | Creates drift event if behavior/config weakened. |
| 5 | AstraNull | Opens/updates finding and sends notification/ticket. |
| 6 | Customer engineer | Lists/renders drift on `#waf-posture` drift queue (metadata-only before/after summary, severity, status; no filter controls in this slice). |
| 7 | Customer engineer | Patches drift status only (ack/remediation/etc.; no note input in this UI slice) via UI → `PATCH /v1/waf/drift-events/:id` when authorized (`waf:write`). |
| 8 | Customer engineer | Requests retest from drift row → `POST /v1/waf/drift-events/:id/retest` (`waf:run`); developer-validation UI shows retest id/status for retests created in the current session only — **governed**, not a bypass of safe catalog or SOC high-scale paths. |
| 9 | Operator / automation | Executes retest → `POST /v1/waf/retests/:id/execute` (safe signed-worker delegation; may require continuation ticks or `npm run waf:orchestrator:runner` in Postgres). |
| 10 | Operator / automation | Completes retest when verdict evidence is finalized → `POST /v1/waf/retests/:id/complete` (atomically updates drift + audit). |
| 11 | Customer | Fixes WAF policy or approves new baseline/exception. |
| 12 | AstraNull | Closes drift only on proof (retest complete or approved baseline), not on UI action alone. |

Acceptance criteria:

- Drift queue list/render and retest follow-up controls are UI-visible on `#waf-posture` for developer validation; retest id/status is session-scoped until a list-retests API (or equivalent) enables persistent hydration from the drift list.
- Retest request/execute/complete remain API-gated (`waf:run`, orchestrator availability, signed-worker mode, execution leases, safe-run caps); UI must surface fail-closed errors without sensitive payloads.
- Staging scheduling/execution evidence for the WAF orchestrator runner, live/staging DB acceptance, provider connector workers, and connector config drift workers are **out of scope** for this UI slice and stay release blockers.
- No production readiness or production signoff is implied by drift UI alone; see [`docs/release-checklist.md`](../release-checklist.md).

## 4. Origin-bypass escalation

| Step | Actor | Action |
|---|---|---|
| 1 | AstraNull | Detects direct-origin path reaches agent/canary. |
| 2 | AstraNull | Creates critical finding for protected asset. |
| 3 | AstraNull | Recommends origin restriction: CDN/WAF egress ACL, authenticated origin pull, mTLS, private origin, Host/SNI validation. |
| 4 | Customer | Applies fix in cloud/load balancer/origin/WAF. |
| 5 | AstraNull | Retests direct path and protected path. |
| 6 | AstraNull | Closes when direct path no longer reaches origin and protected path still works. |

## 5. CVE-to-WAF mitigation

| Step | Actor | Action |
|---|---|---|
| 1 | AstraNull | Ingests CVE/advisory. |
| 2 | AstraNull | Triage filters by tenant tech footprint. |
| 3 | AstraNull | Matches affected approved WAF assets. |
| 4 | AstraNull | Runs safe validation where available. |
| 5 | AstraNull | Drafts vendor-specific WAF recommendation. |
| 6 | Human reviewer | Approves recommendation for ticketing/deployment. |
| 7 | AstraNull | Creates ticket/action item with evidence. |
| 8 | Customer | Deploys mitigation in WAF console. |
| 9 | AstraNull | Retests and updates ticket/finding. |

## 6. Optional discovery candidate workflow

| Step | Actor | Action |
|---|---|---|
| 1 | Tenant admin | Enables external discovery and defines allowed entity scope. |
| 2 | AstraNull | Builds entity/candidate map from approved sources. |
| 3 | AstraNull | Shows candidates in discovery inbox; no findings yet. |
| 4 | Customer | Approves/rejects candidates. |
| 5 | AstraNull | Approved candidates become targets/WAF assets. |
| 6 | AstraNull | Runs safe posture validation. |

## 7. Remediation workflow

| Step | Actor | Action |
|---|---|---|
| 1 | AstraNull | Groups related WAF findings into action item. |
| 2 | AstraNull | Routes to owner based on target group/entity/connector tags. |
| 3 | AstraNull | Creates Jira/ServiceNow ticket or SIEM/SOAR event. |
| 4 | Customer | Fixes, marks deployed, or accepts risk. |
| 5 | AstraNull | Retests. |
| 6 | AstraNull | Closes finding or reopens with updated evidence. |

## 8. Safe validation-plan orchestration (operator-visible)

| Step | Actor | Action |
|---|---|---|
| 1 | Customer engineer / operator | Creates a safe validation plan for a declared target group (`POST /v1/waf/validation-plans`) with allowlisted scenarios and bounded `max_concurrent`. |
| 2 | Operator | Reviews all and scheduled plans on `#waf-posture` validation-plan operator panel (`GET /v1/waf/validation-plans`, `GET /v1/waf/validation-plans/scheduled`). |
| 3 | Operator / automation | Executes plan tick → `POST /v1/waf/validation-plans/:id/execute` (safe signed-worker delegation only; may require continuation ticks). |
| 4 | Operator / automation (production path) | Externally scheduled runner applies scheduled plans → `npm run waf:orchestrator:runner` (not an in-app daemon). |
| 5 | Operator | Cancels in-flight or scheduled plan when needed → `POST /v1/waf/validation-plans/:id/cancel` (clears execution leases; best-effort cancels delegated safe runs in metadata). |
| 6 | AstraNull | Marks plan `completed` when all safe jobs in the plan queue are delegated — **not** when final posture verdicts or drift closure are proven. |
| 7 | Customer | Reviews validation runs, evidence, and findings; remediates and retests per other workflows. |

Acceptance criteria:

- Scheduled safe orchestration is **operator-visible** in developer validation (UI panel + API list/scheduled routes) but **externally scheduled in production** via `npm run waf:orchestrator:runner` per [`docs/operator-local-runbook.md`](../operator-local-runbook.md).
- Execute paths delegate safe catalog jobs only; UI and API surface metadata-only delegation (`delegated_jobs`, `continuation_required`) without sensitive payloads.
- UI degrades gracefully when `postgres_waf_orchestrator_unavailable`; orchestrator fail-closed gates (`waf_orchestrator_signed_worker_required`, execution leases) must not be bypassed from the panel.
- Staging scheduling/execution evidence for the WAF orchestrator runner, list-retests persistent hydration, reports/custody exports, accessibility/browser matrix evidence, live/staging DB acceptance, provider connector workers, connector config drift workers, and security/observability/release signoff remain **open** — not production-ready.

## 9. Multi-vendor CVE mitigation playbook

| Step | Actor | Action |
|---|---|---|
| 1 | AstraNull | Clusters CVE asset matches and recommendations by vendor. |
| 2 | AstraNull | Creates grouped playbook with ordered vendor slices. |
| 3 | Human reviewer | Approves playbook for ticketing. |
| 4 | AstraNull | Creates parent action item; optional per-vendor child items. |
| 5 | Customer | Deploys mitigations in each WAF console. |
| 6 | AstraNull | Runs coordinated retest across all playbook assets. |
| 7 | AstraNull | Closes playbook when all slices pass or risk is accepted. |

Acceptance criteria: see [Multi-Vendor CVE Mitigation Playbook](../detection/17-multi-vendor-cve-mitigation-playbook.md).

## 10. Deployment roadmap and executive rollups

| Step | Actor | Action |
|---|---|---|
| 1 | AstraNull | Recomputes asset risk scores and Tier 1–4 assignments (`wafRiskService`). |
| 2 | Customer exec / CISO | Reviews overview cards for coverage ratio, vendor mix, entity and geography rollups. |
| 3 | Customer engineer | Opens roadmap tab sorted by tier; filters by entity or region. |
| 4 | Customer | Remediates Tier 1 gaps first; creates tickets from roadmap rows. |
| 5 | AstraNull | Refreshes roadmap after retest closure or connector snapshot ingest. |
| 6 | Customer audit/GRC | Exports `compliance_audit` report for assessment window. |
| 7 | Customer exec / board | Optionally exports `board_roadmap_brief` for procurement and investment narrative. |

Acceptance criteria:

- Roadmap ordering is explainable from factor JSON.
- Geography and entity rollups use declared metadata only.
- Vendor consolidation view is advisory and never triggers automated changes.

## Done criteria for workflow suite

- Every workflow has audit events.
- Every unsafe or unapproved path is blocked by API/service layer.
- Every finding can be retested.
- Every external ticket has a link back to evidence and retest.
- User can disable WAF posture or discovery per tenant/environment.
