Deep-checked the astranull codebase against the current OD prototype (nav, screens, panels, JS handlers). Below is the honest gap list, grouped by cause. This is analysis only — I did not modify any files.

Sources I audited: `docs/feature-functionality-coverage-matrix.md` (200+ backend feature inventory), `docs/api.md`, `src/services/*` (54 services), `src/contracts/*` (25 contracts), `src/lib/*` (61 modules), `db/schema.sql`, and the current `index.html` + `app.js`.

## Group A — Backend features you explicitly deleted from the UI, but the capability is still live in the backend

Deleting the top-level pages was the right call for clarity. But some of the *actions* those pages exposed have not been re-homed anywhere and are now unreachable from any screen.

| Capability | Backend surface | Where it went | Gap |
|---|---|---|---|
| **CVE pipeline triage** (`POST /v1/waf/cve-pipeline/:id/triage \| /validate \| /match \| /playbook \| /coordinated-retest`) | `src/services/cvePipeline.mjs` (39 KB), `src/contracts/cvePipeline.mjs` (40 KB) | Nowhere | No way to view or triage a CVE. `docs/detection/15-live-exposure-defense-cve-pipeline.md` is the design. |
| **WAF drift queue + drift scan** (`GET /v1/waf/drift-events`, `POST /v1/waf/drift-scans/run`, `POST /v1/waf/drift-events/:id/retest`) | `src/services/wafDriftWorker.mjs`, `src/routes/wafDriftRoutes.mjs`, migration `0014_waf_drift_scan_results.sql` | Nowhere — only the WAF panel on Dashboard aggregates counts | Users can't see or triage which asset drifted or run a scan. |
| **WAF exceptions** (`GET /v1/waf/exceptions`, `POST /v1/waf/assets/:id/exception`) | `src/services/wafPosture.mjs` (94 KB), migration `0022_waf_exceptions.sql` | Nowhere | Exception approvals are a compliance requirement; no UI to create, view, or expire them. |
| **WAF validation plans (orchestrator)** (`GET/POST /v1/waf/validation-plans`, `POST …/execute \| /cancel`) | `src/services/wafOrchestrator.mjs` (29 KB), migration `0011_waf_orchestrator.sql` | Nowhere | Scheduled WAF validation cycles have no visibility. |
| **Risk roadmap (Tier 1–4)** (`GET /v1/waf/coverage/risk-roadmap`) | `src/services/wafRiskService.mjs`, `src/services/wafCoverageService.mjs` | Nowhere | Only summary KPIs made it into the Dashboard WAF summary panel; the tier-by-tier remediation roadmap is unreachable. |
| **Discovery entities + candidate inbox** (`POST /v1/discovery/entities`, `POST /v1/discovery/candidates/:id/approve \| reject \| import`) | `src/services/externalDiscovery.mjs` (20 KB), `src/contracts/externalDiscovery.mjs` | Nowhere | External asset discovery / shadow IT reconciliation has no UI. |
| **Supply-chain risks + AP2/AP3 phase authorization** (`POST /v1/waf/supply-chain/risks/:id/state \| /phase-authorization \| /remediation-ticket`) | `src/services/supplyChainRisk.mjs` (23 KB), `src/contracts/supplyChainPhaseAuthorization.mjs` | Nowhere | Third-party/vendor risk workflow (dangling CNAMEs, SaaS dependencies) is unreachable. |
| **Remediation delivery** (`POST /v1/waf/action-items/:id/deliver`) | `src/lib/remediationDelivery.mjs` (11 KB), connector delivery | The `Mark delivered` button on finding-detail toasts but doesn't call the API | The connector delivery pipeline (Jira/ServiceNow/webhook) is never triggered from the UI. |
| **Release evidence inventory + attestation** (`GET /v1/production-release-evidence`, `GET …/attestation`) | `src/services/productionReleaseEvidence.mjs`, `src/contracts/productionReleaseEvidence.mjs` (29 KB), migration `0007_production_release_evidence.sql`, ~30 evidence-collector scripts | Nowhere | You called this correctly for customers, but **auditor role** (`auditor` in `roles.mjs`) has `release_evidence:read` explicitly granted and now has no page for it. |

## Group B — Capabilities that never had a UI in this prototype and are still absent

These are documented in the backend + product docs but no screen was ever built.

### Agent lifecycle (FM-AGENT gaps)

| Missing | Backend | Why it matters |
|---|---|---|
| **Agent updates — release list + rollback** | `src/services/agentUpdates.mjs` (10 KB), `src/lib/agentUpdates.mjs` (13 KB), `GET /v1/agent-updates`, `POST /v1/agent-updates/:id/rollback` | Fleet-wide agent version rollout is invisible. Rollback is one click behind an API but not exposed. |
| **Agent trust keys** — list/add/revoke | `GET/POST /v1/agent-update-trust-keys`, `POST …/:id/revoke` | Update signing keys — critical for supply-chain trust — have no rotation UI. |
| **mTLS gateway identity** — fingerprint + rotation | `src/lib/agentAuth.mjs`, `ASTRANULL_AGENT_IDENTITY_MODE=gateway-mtls` | The agent-detail page doesn't show gateway mTLS fingerprint or last cert-rotation event. |
| **Host operational log tail / telemetry** | UX spec calls for a Logs tab per `docs/ux/04-agents-page.md` | Agents page only shows an audit-trail slice, not CPU/mem/disk/queue depth. Boundary — no host log API. |

### Validation depth (FM-VALIDATION gaps)

| Missing | Backend | Why it matters |
|---|---|---|
| **Run raw events tab** | `GET /v1/test-runs/:id/events` | run-detail has a summary + evidence but no "Raw events" sub-tab. React portal has it. |
| **Probe results detail panel** | `probe_result` event type in run events | Users can't inspect the actual probe payloads (headers, DNS RRs, TLS handshake). |
| **Agent observations detail panel** | `agent_observation` / `agent_no_observation` events | Same for agent-side observations. |
| **Traffic path diagram per verdict** | Derived from verdict state, planned in `run-proof-panels.tsx` | Verdict explanation panels exist on finding-detail but no visual path diagram. |
| **Correlation matrix on runs** | Correlation is computed by `src/services/correlation.mjs` and rendered as a Dashboard widget | It should also appear per-run to justify the specific verdict, not just cycle-wide. |

### Governance depth (FM-GOV gaps)

| Missing | Backend | Why it matters |
|---|---|---|
| **Notification rule create form** | `POST /v1/notifications` — supports rule type, filters, delivery mode | Notifications page only shows the ledger; no way to CREATE a rule from the UI. |
| **Delivery retry / DLQ redrive** | `POST /v1/notifications/retries/process`, `POST …/dlq/redrive`, `src/services/notificationRetry.mjs`, `src/services/notificationDlqRedrive.mjs` | Ops action needed when a webhook provider fails — currently only invocable by CLI. |
| **Notification provider credentials** | `src/services/notificationProviderCredentials.mjs`, `src/lib/notificationProviderCredentials.mjs` | Adding a Slack webhook, PagerDuty routing key, or generic HTTPS webhook has no UI. |
| **Retention & privacy settings** | `src/services/privacyRetention.mjs`, `src/lib/privacySettings.mjs`, `PATCH /v1/tenants/current` | Settings > Retention has hardcoded input values, not wired to `/v1/tenants/current` privacy_settings. |
| **Secret vault** — list/create/rotate | `src/services/secretVault.mjs`, `src/lib/addressedSecrets.mjs`, `GET /v1/secrets` | Settings has no Secret Vault tab; connector integrations reference secret refs but the source-of-truth vault isn't visible. |
| **Compliance report kinds detail** | `src/contracts/complianceReports.mjs` (15 KB), supports `soc2 / iso27001 / dora / nis2 / internal_audit` | The Reports page has these as `<option>`s in the generator, but no per-kind template preview or requirement checklist. |

### Auth, RBAC, tenant (FM-CORE gaps)

| Missing | Backend | Why it matters |
|---|---|---|
| **Users & roles directory** (invite / disable / role assign) | `POST /internal/admin/tenants/:id/users/:id/resend-invite \| disable` on staff surface; **no customer-side API** | Settings > Users is read-only "session + IdP posture." That's a documented boundary but should be labelled as "staff-managed" explicitly. |
| **Enterprise SSO configuration** (OIDC/SAML mapping per tenant) | `src/lib/oidc.mjs`, `src/lib/bundledStagingOidc.mjs`, `docs/security/01-security-model.md` | Settings > SSO tab shows posture readout only. Per-tenant IdP mapping is external ops. |
| **Service accounts rotation** | `POST /v1/service-accounts/:id/rotate` | Settings > API keys has the create-flow but rotation UX is missing. |
| **Bootstrap tokens list + revoke** | `POST /v1/bootstrap-tokens/:id/revoke` | Only visible in a subset of screens; no centralized "all tokens" view. |

### Staff surfaces (FM-STAFF partial)

| Missing | Backend | Why it matters |
|---|---|---|
| **Signup queue** on Admin console | `GET /internal/admin/signup-requests`, `POST …/:id/approve \| reject` | The signup ledger exists in the backend (`src/services/signupIntake.mjs`), but the staff Admin console has no queue view — only the tenant directory. |
| **Approval requests decisions** | `POST /internal/admin/approval-requests/:id/decision` | Approval requests panel exists on Admin, but the wired action is `approval-grant` — no reject/hold/decline decisions. |
| **Support owner assignment** | `PATCH /internal/admin/tenants/:id` `support_owner` | Not currently on the tenant-detail page. |
| **Tenant user invite/disable** on tenant-detail | `POST …/users/:id/resend-invite \| disable` | Tenant detail doesn't have a Users tab. |
| **Internal audit log filter** | `GET /internal/admin/audit-log` | Admin has an audit tab but the filter form is missing. |

### High-scale (FM-HIGHSCALE — inline queue is present, but…)

| Missing | Backend | Why it matters |
|---|---|---|
| **Authorization pack upload flow** | `POST /v1/high-scale-requests/:id/artifacts` (metadata-only, no plaintext) | The SOC-gated queue on Test runs shows an "Attach pack" button, but there's no wizard for uploading LOA / DPA / provider approval / runbook artifacts. |
| **Provider approval paths** | `src/contracts/providerApprovalPaths.mjs` (12 KB) — encodes AWS/GCP/Cloudflare/Azure approval flow contracts | Users don't see whether their provider needs advance notice for a load test. |
| **Authorization template library** | `src/contracts/authorizationTemplates.mjs`, `docs/templates/*` | The 4 templates (LOA, high-scale auth pack, provider approval, SOC runbook) aren't downloadable from any screen. Only the customer LOA is embedded on target-group-detail. |
| **Break-glass workflow** | `src/services/breakGlass.mjs`, `src/contracts/breakGlass.mjs` | Emergency override path for SOC-gated ops has zero UI surface anywhere. |

### Ownership, DNS, integrations (missing depth)

| Missing | Backend | Why it matters |
|---|---|---|
| **Ownership verification ledger** | `src/services/ownershipVerification.mjs`, `src/services/dnsOwnership.mjs`, migration `0024_ownership_verifications.sql` | The target-group-detail page has per-target verification chips (great), but there's no ledger showing when each proof was recorded, who verified, and the raw signal. |
| **Probe endpoint binding** | `src/lib/probeEndpoint.mjs`, migration `0023_agent_probe_endpoint.sql` | The agent's discovered public IP + probe endpoint binding is what makes IP ownership work; agent-detail should surface this but doesn't. |
| **Connector poll runner status** | `scripts/connector-poll-runner.mjs`, `src/lib/connectorProviders/*` (7 providers) | Integrations page has connector toggles but no per-connector last-poll time, error count, or manual "poll now" action. |
| **Passive discovery sources** | `POST /v1/discovery/sources/ingest`, `src/lib/discoverySources.mjs` | External asset discovery via passive sources has no configuration UI. |
| **CVE feed ingest state** | `POST /v1/waf/cve-pipeline/ingest`, `src/lib/cveFeedIngest.mjs`, `src/services/cvePipeline.mjs` | Which feeds are active, when they last ingested, how many CVEs came in — invisible. |

### Reports (FM-REPORTS)

| Missing | Backend | Why it matters |
|---|---|---|
| **Custody-verify action on Reports** | `POST /v1/custody/verify` | Report exports carry a custody digest but the "Verify chain" action isn't exposed. |
| **Report schedule (recurring generation)** | Report kinds support cadence in backend; no UI | Compliance reports need to be regenerated quarterly / monthly — there's no scheduling UI. |

### Kill switch & operational safety

| Missing | Backend | Why it matters |
|---|---|---|
| **Customer view of kill switch state** | `POST /internal/soc/kill-switch` sets it; `GET` returns state | Currently only visible in the staff SOC console. Customers should see "your tenant's kill switch is currently ARMED" as a Dashboard banner if the SOC has armed it — right now it's silent. |
| **Governed adapter telemetry** | `src/lib/governedAdapterTelemetry.mjs`, `src/services/governedAdapterTelemetryIngestWorker` | Adapter execution telemetry (dry-run vs prod, RPS achieved, kill-switch trip time) has no surface. |

### Health & readiness signal

| Missing | Backend | Why it matters |
|---|---|---|
| **Readiness factors breakdown** | `src/services/readiness.mjs` (14 KB), `GET /v1/state` includes weighted factors | Dashboard shows readiness score `82/100`. It doesn't show WHICH factors are pulling it down (agent placement, evidence freshness, kill-switch drill, WAF coverage etc.). This is the single most useful "what should I do next" signal. |
| **Kill-switch drill freshness** | `src/services/breakGlass.mjs`, drill scripts | The SOC console shows "Kill switch drill current · no" — but a customer should also know their own tenant needs a drill, on the Dashboard. |
| **Placement diagnostics** | `src/lib/placementDiagnosticsCompute.mjs`, `src/services/placement.mjs`, `GET /v1/placement/reviews` | Agent placement confidence per target group is computed but not surfaced anywhere as a widget. |

## Group C — Frontend features you asked for or that memory says you want, but haven't been fully built

| Item | Status |
|---|---|
| **Deployable agent image generation** (bring your own container / signed OCI image, per-tenant download) | The Agents page shows a deploy matrix with **pinned container digest + cosign verify snippets**, but the actual "generate deployable image" API — `agent-container-evidence.mjs`, `render-agent-helm.mjs`, `package-agent.mjs` — is one-click behind the CLI, not the portal. Your original directive was "along with the agents, we also had a functionality to generate an image that the customers can deploy." That has evolved into showing the metadata but not offering a **generate + download tenant-specific image** action. |
| **Domain verification via provider integration** (Cloudflare / Route 53 / GoDaddy / Namecheap inventory pull) | Provider cards + inventory picker modal are wired; live provider API integration is not (all seven providers currently render **demo payloads**). Backend `src/lib/connectorProviders/cloudflare.mjs` implements the real Cloudflare path. |
| **Overview KPIs still hardcoded** | The Dashboard's "4 open findings", "3/3 agents online" KPIs are static in HTML; they should read from `ENTITIES.findings` and `ENTITIES.agents`. I flagged this in a prior turn and it's still open. |
| **Customer-facing target sub-catalogs beyond `tg_checkout`** | Only `tg_checkout` has a fully-populated `ENTITIES.targets` sub-catalog. The 6 other groups (`tg_media`, `tg_api`, `tg_dns`, `tg_stage`, `tg_fail`, `tg_marketing`) fall back to the empty state on the target-detail hydrator, and 11 of 17 findings on finding-detail's "Affected targets" panel show the empty state. |
| **Target-group-detail hydrator** | Currently hardcoded to `tg_checkout` — clicking any other group in the sidebar list opens this same screen with the same data. Needs `populateTargetGroupDetail(entityId)` parallel to `populateTargetDetail`. Flagged in a prior turn. |

## Group D — Documented product features not implemented anywhere (per `docs/product/*`)

| Feature | Doc | State |
|---|---|---|
| **Signup public site config** — `signup_enabled`, region availability, plan surface | `src/services/publicSite.mjs`, `GET /v1/public/site-config` | Landing page copy is hardcoded; site config is not read. |
| **Tenant deployment features** | `src/services/tenantDeploymentFeatures.mjs` | Which optional features a tenant has (WAF add-on, discovery add-on, high-scale entitlement) — invisible. |
| **Support playbook** | `docs/support-playbook.md` | Support page has kill-switch state but not the runbook / SLA / escalation matrix. |
| **DR restore drill status** | `scripts/dr-restore-evidence.mjs`, `scripts/postgres-restore-drill.mjs` | Not exposed anywhere — should probably surface on Support or SOC console as a freshness KPI. |
| **Vector safety policy evidence** | `scripts/vector-safety-policy-evidence.mjs`, `src/services/safeTestPolicy.mjs` | Which vector families are currently safe/gated/blocked isn't shown to customers on the Checks page or Test policies. |

## Bottom line

- **~40 backend endpoints across 8 services** have no reachable UI right now.
- The largest single gap is **CVE pipeline + WAF drift + validation plans + supply-chain** — you deleted the top-level pages for taste reasons, but the *actions* (triage a CVE, review a drift event, run a scheduled validation cycle, authorize a supply-chain phase) now have no home. Options: (a) restore a slim `Posture` section with those specific action queues, or (b) fold them into Findings as vector-scoped triage tabs (CVE tab, WAF-drift tab, Supply-chain tab).
- **Auditor role has no landing page** — `auditor` has `release_evidence:read` and `audit:read` but no dedicated surface after Release evidence was deleted. Either the sidebar needs a role-aware "Auditor" group or the audit log needs to gain custody-verify / evidence-export inline.
- **The single most impactful missing widget is the readiness-factors breakdown on the Dashboard.** Right now the score is `82/100` with no explanation. `src/services/readiness.mjs` returns the exact factor list (agent_placement, evidence_freshness, kill_switch_drill_fresh, waf_coverage, high_scale_readiness, cve_pipeline_current). Wiring that into the Dashboard would make "What to do next" actually derived from data instead of hand-picked.

Say the word on which of these you want built next and I'll pick them off one at a time in hard-scoped turns.