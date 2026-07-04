# Enterprise Production Gap Backlog

This backlog records the remaining enterprise-grade work needed before AstraNull can be called production-ready. It complements `PROGRESS.md` and `docs/release-checklist.md`; it does not replace either tracker.

## Current Verdict

AstraNull’s hosted staging profile has complete evidence inventory: hosted attest/evidence collection covers 31/31 accepted evidence kinds, 7/7 staging E2E scenarios, customer portal browser E2E, and staff surfaces unlinked from customer UI, with closed checklist and release-plan promotion rows in-repo. That inventory does **not** by itself prove a customer-specific production launch, independent retained external artifacts, or completed tenant onboarding. Per-customer enterprise IdP, domains, provider credentials, KMS, and operator signoffs remain **operational onboarding** — not open repo scaffold gaps.

| Area | Current status | Production gap |
|---|---|---|
| Core backend | Strong developer-validation platform | Postgres runtime and release-critical route families are service-backed; staging/live acceptance, tenant unit-of-work review, and concurrent isolation evidence still need signoff. |
| Agent/probe | Strong MVP | Signed installers, distro/container release pipeline, upgrade daemon enforcement, hardening, and fleet-scale probe operations. |
| Detection | Good foundation | Broader vector families, per-vector safety policy, live staging evidence; Test Runs and Findings **verdict explanation** panels share `verdict-explanation.mjs` — report/export parity and deeper placement-confidence backend fields still open. |
| SOC high-scale | Good governance design | Real provider/partner integrations, provider-specific approval paths, live telemetry, and authorization evidence custody. |
| UX | Developer-validation shell complete | Guided journeys, onboarding wizard, core pages, public landing, internal admin UX, status pages, and Test Runs/Findings **verdict explanation** panels (`verdict-explanation.mjs`) landed — browser/accessibility matrix, report/export parity, and staging signoff remain. |
| Enterprise readiness | Partial | SSO/MFA signoff, audit exports, monitoring, DR drills, legal approval packs, compliance mappings. |
| Notifications | Channel adapters, developer ledger, and Postgres retry/DLQ metadata persistence exist in developer validation | DLQ visibility, metadata-only retry processing, and metadata-only-by-default DLQ redrive UI/API exist in developer validation; production always-on scheduling, encrypted provider credential custody, staging delivery/redrive evidence, and extended providers such as PagerDuty, ServiceNow, and SIEM remain. |
| WAF posture add-on | Developer-validation Postgres parity for core WAF tables, action items, CVE, discovery, and supply chain; orchestrator persistence/runtime first slice (`0011_waf_orchestrator`, `runtime.services.wafOrchestrator`); plan and retest execute each delegate one signed-worker safe job via `startTestRun` (delegation-only; retest `status: delegated`, `waf.retest.delegated` audit); R7/R8 analytics WAF-013–WAF-022 are developer-validation complete (risk scoring, coverage rollups, roadmap, schema extensions, catalog seed, compliance/board exports, OpenAPI parity). | Always-on/scheduled worker staging evidence, retest closure proof, connector config drift workers, live/staging DB acceptance, provider/customer evidence, immutable report custody, WAF security/observability/release signoff — not production-ready. |
| Production ops | Partial | SLOs, dashboards, backups, staging evidence, incident playbooks, support SLAs. |

## P0 Product Gaps

| Priority | Gap | Required outcome |
|---|---|---|
| P0 | Authorization proof workflow | High-scale requests require customer ownership/control proof, business/legal approval, provider approval evidence, scoped dates/vectors/rates, and retained artifacts before SOC approval. |
| P0 | Agent placement validation | Every target group must show observation mode, placement confidence, and whether the agent can actually prove that traffic path. |
| P0 | Runtime Postgres adapter | `ASTRANULL_PERSISTENCE_MODE=postgres` must start only with the real adapter, migrations applied, RLS enforced, and tenant isolation proven under concurrent load. |
| P0 | Notification delivery operations | Findings, high-scale status, agent health, and readiness regressions must deliver through configured channels with persistent retries. Developer validation persists retry/DLQ metadata and exposes metadata-only UI/API retry processing plus metadata-only-by-default DLQ redrive; production always-on scheduling, encrypted provider credentials, and staging delivery/redrive evidence. |
| P0 | Safe vector execution policy | Every vector must define allowed payload type, max rate, max duration, approval level, stop condition, evidence requirements, and failure handling. |
| P1 | Installer/release pipeline | Signed `.deb`, `.rpm`, container image, Helm chart, checksums, SBOM, upgrade/rollback docs, and staging install matrix. |
| P1 | Probe fleet productionization | Multi-region signed probes, source identity, health, quotas, egress controls, rate budgets, and anti-abuse checks. |
| P1 | UX onboarding wizard | Guided create tenant/environment/target group/install agent/run first check path. |
| P1 | Evidence chain of custody | Immutable evidence snapshots, signed report hashes, audit export, retention, legal hold, and custody metadata. |
| P2 | Compliance report templates | DORA, NIS2, ISO 27001, SOC 2, internal audit, board, executive, technical, and SOC report variants. |

### P0 disposition and signoff map

These dispositions close the local tracker ambiguity only. Per-customer external evidence in the final column is attached through governed custody at tenant onboarding — not an open repo promotion table row.

| P0 gap | Local disposition | Owner | Evidence / signoff reference | External closeout still required |
|---|---|---|---|---|
| Authorization proof workflow | Implemented locally with external custody closeout remaining | SOC + Product | `PROGRESS.md` SOC-009/SOC-010; `docs/release-checklist.md` "High-scale authorization proof workflow"; `tests/integration/hardening.test.mjs`; `npm run soc:authorization-custody:evidence` | Customer ownership/control proof, business/legal approval, provider approval evidence, scoped rates/dates/vectors, retained artifacts, and SOC staging review. |
| Agent placement validation | Implemented locally with staging placement closeout remaining | Detection + QA | `PROGRESS.md` DET-014/UX-013/QA-004; `docs/release-checklist.md` verdict UX and placement confidence rows; `tests/unit/verdict-explanation.test.mjs`; `npm run placement:staging:evidence` | Live placement-mode matrix, browser/accessibility execution, and staging/live DB acceptance for verdict/report export paths. |
| Runtime Postgres adapter | Implemented locally with staging/live DB acceptance closeout remaining | Backend + Platform | `PROGRESS.md` SEC-001/QA-006; `docs/release-checklist.md` Data plane rows; `node scripts/validate-db-schema.mjs`; `npm run postgres:tenant-query:audit`; `npm run postgres:concurrency:evidence` | Migrations applied in target environments, runtime smoke against target Postgres, tenant concurrency under realistic load, and DB/operator signoff. |
| Notification delivery operations | Implemented locally with provider delivery closeout remaining | Backend + SRE | `PROGRESS.md` BE-016/SEC-006/QA-005; `docs/release-checklist.md` Notifications row; `tests/unit/notifications.test.mjs`; `tests/integration/notification-provider-credentials-api.test.mjs`; `npm run notification:provider:evidence` | Real provider credentials, staging delivery/redrive drill, always-on scheduler deployment, alert routing, and SRE signoff. |
| Safe vector execution policy | Implemented locally with staged fleet evidence remaining | Detection + Security | `PROGRESS.md` DET-015/SEC-001/QA-005; `docs/release-checklist.md` feature flag/vector rows; `tests/unit/vectors.test.mjs`; `tests/unit/vector-safety-policy-evidence.test.mjs`; `npm run vector:safety:evidence` | Live/staging signed-worker fleet matrix, provider stop-path evidence where relevant, and security/SOC release signoff. |

## Agent Detection And Confidence

The outbound-only agent does not require inbound firewall access. It proves readiness only when it can observe the validated path locally or through an explicitly configured telemetry source.

| Detection mode | How it detects validation traffic | Best fit |
|---|---|---|
| Host packet observation | Watches local interface metadata with safe filters. | VM or bare-metal origin. |
| Canary endpoint | Local HTTP/TCP canary reports whether marker traffic arrived. | Fast MVP and backend-pool path validation. |
| App/log observation | Tails NGINX, Envoy, Apache, or app logs for test nonce metadata. | L7 checks. |
| Packet mirror collector | Receives cloud/on-prem mirrored traffic copy. | Enterprise network visibility. |
| Kubernetes DaemonSet | Runs on selected or all nodes and observes node-level metadata. | GKE, EKS, AKS, OpenShift. |
| Sidecar mode | Runs beside an app container and observes app-local traffic/logs. | Critical workloads. |

A random VM in the same network cannot prove traffic to another VM unless the target, logs, or mirrored traffic path is connected to that agent. This must remain a first-class UX concept.

### Agent Confidence Score

Every verdict should include placement confidence.

| Confidence | Placement | Meaning |
|---|---|---|
| High | Installed on actual target host/app | Strong path evidence. |
| High | Sidecar with target app | Strong L7 evidence. |
| Medium | Same backend pool or canary | Good path evidence, not exact app evidence. |
| Medium | Packet mirror collector | Broad evidence, depends on mirror scope. |
| Low | Same VPC/subnet only | Weak evidence; cannot prove exact target path. |
| Invalid | No traffic visibility path | Verdict cannot prove penetration/protection. |

Verdict explanation requirement:

```text
Verdict: Protected
Confidence: Medium
Reason: Canary backend did not observe the probe, but the agent is not installed on the production origin.
```

## Detection And Vector Expansion

The safe vector catalog must expand without adding raw attack tooling. All entries must use bounded validation, metadata evidence, and SOC gates where needed.

### L3/L4

| Vector family | Safe validation | Notes |
|---|---|---|
| SYN flood readiness | Yes | Low-rate handshake/counter validation. |
| TCP ACK/RST/FIN anomalies | Yes | Metadata-only protocol-state probes. |
| UDP flood readiness | Yes | Low-rate UDP reachability and policy checks. |
| ICMP flood readiness | Yes | Controlled ICMP probe where authorized. |
| IP fragmentation | Yes | Safe fragment-policy validation. |
| GRE/IP protocol exposure | Yes | Policy validation only. |
| IPv6 exposure | Yes | Explicitly test declared IPv6 targets. |
| QUIC/UDP 443 exposure | Yes | HTTP/3 path readiness. |
| Ephemeral port exposure | Yes | Detect accidental open services. |
| Connection table exhaustion | Partial | SOC-gated simulation only. |

### DNS

| Vector family | Safe validation | Notes |
|---|---|---|
| Authoritative DNS flood readiness | Partial | Provider/telemetry driven for scale. |
| Random-prefix/NXDOMAIN flood | Yes, low-rate | Validate randomized label handling safely. |
| Open resolver misuse | Yes | Confirm customer infra is not a reflector. |
| DNSSEC large response risk | Yes | Check configuration and response size. |
| ANY/TXT amplification exposure | Yes | Safe query validation only. |
| Secondary DNS failover | Yes | Config/customer-declared validation. |

### L7/API

| Vector family | Safe validation | Notes |
|---|---|---|
| HTTP GET flood | Yes, bounded | Low-rate readiness only unless SOC-gated. |
| HTTP POST flood | Yes, bounded | Synthetic safe body only. |
| Expensive endpoint abuse | Yes, customer-declared | No endpoint guessing. |
| Login/OTP/password reset abuse | Yes, safe synthetic account | Requires customer approval and isolated test identity. |
| Cache busting | Yes | Validate origin shielding/cache rules. |
| Large header/body | Yes | Safe boundary tests. |
| Slowloris/slow body | Partial | Tightly bounded and time-limited. |
| Bot-like request pattern | Yes | Challenge/rate-limit validation. |
| API quota exhaustion | Yes | Safe token/user quota tests. |
| GraphQL expensive query | Yes, customer-provided | Safe query only. |
| gRPC reflection/stream pressure | Partial | Specific support and strict caps. |
| WebSocket connection pressure | Partial | Bounded connection tests. |

### Protocol-Specific

| Vector family | Safe validation | Notes |
|---|---|---|
| HTTP/2 Rapid Reset readiness | Yes | Config check plus tiny controlled probe. |
| HTTP/3/QUIC readiness | Yes | Exposure, rate controls, fallback behavior. |
| TLS handshake exhaustion | Partial | Low-rate only unless SOC-gated. |
| SNI/Host mismatch bypass | Yes | Strong origin-bypass check. |
| Certificate/SAN origin leakage | Yes | Passive/public check for customer-declared target. |

## High-Scale Lifecycle

Production high-scale workflow must include:

| Stage | Required behavior |
|---|---|
| Request | Customer selects declared target group and objective. |
| Authorization | Domain/IP ownership, business approval, legal approval, provider approval. |
| Provider rules | Provider-specific metadata model for limits, partners, accepted paths, and stop controls now exists; live integrations and staging signoff remain. |
| SOC review | Human review of scope, dates, vectors, max rate, abort criteria. |
| Dry run | Validate target, agent, telemetry, kill switch, notifications, and alerts. |
| Execution | Adapter runs only the approved simulation constraints. |
| Live monitoring | SOC sees rate, target health, mitigation state, customer comms, provider telemetry. |
| Kill switch | Immediate stop from SOC, provider path, or emergency contact. |
| Closure | Evidence locked, report generated, remediation/finding created. |

Provider-specific approval paths are modeled explicitly instead of one generic approval flag (`src/contracts/providerApprovalPaths.mjs`). Remaining production work is live/provider integration evidence, document custody, and staging drills.

## Backend Backlog

| Area | Required production work |
|---|---|
| Postgres adapter | Runtime implementation is in place; remaining production work is staging migration evidence, DB-backed integration lane, RLS/concurrent tenant-isolation proof, and operator rollback/forward-fix signoff. |
| WAF orchestrator (Postgres) | First slice persists validation plans, baseline approvals, and retest requests with tenant RLS; list/create/cancel and approval/retest-request paths wired via `runtime.services.wafOrchestrator`. Plan and retest execute each delegate one safe job through `startTestRun` when `probeMode === 'signed-worker'` (delegation-only; retest sets `status: delegated`, `delegated_jobs`, audits `waf.retest.delegated`; errors include `waf_orchestrator_execution_not_ready`, `waf_orchestrator_signed_worker_required`, `waf_orchestration_batch_not_supported`, `validation_plan_execution_failed`, `waf_retest_already_delegated`, `waf_retest_already_completed`). **Remaining:** always-on/scheduled worker, multi-job batching, retest closure proof, live/staging DB acceptance. |
| Job scheduler | Priority queue, retries, backoff, cancellation, per-tenant quotas. |
| Probe orchestration | Region selection, source identity, health checks, rate budgets. |
| Correlation engine | Time-window tuning, clock-skew handling, duplicate event handling. |
| Evidence engine | Immutable snapshots, chain of custody, signed report hashes. |
| Policy engine | Safety rules per vector, tenant, environment, and SOC state. |
| Notification service | Slack, Teams, email, PagerDuty, ServiceNow, webhook, SIEM. |
| Integration secrets | Rotation, envelope re-keying, access audit. |
| Billing/usage | Test runs, high-scale requests, probe usage, retained evidence. |
| Admin console | Tenant suspension, kill switch, abuse review, audit inspection. |

## UX Backlog

| Page | Required production behavior |
|---|---|
| Dashboard | Readiness score, critical gaps, active tests, agent health, high-scale status. |
| Target Groups | Declared domains/IPs, expected protection path, owner, criticality. |
| Agents | Placement type, confidence score, heartbeat, version, install command. |
| Checks | Enabled checks, safety level, vector family, expected result. |
| Test Runs | Timeline from planned to probe sent, agent observed, verdict, evidence. |
| Findings | Severity, affected target, proof, fix, owner, SLA. |
| Reports | Executive, SOC, technical, audit, high-scale reports. |
| SOC Console | Requests, approvals, schedules, kill switch, live telemetry. |
| Settings | API keys, bootstrap tokens, RBAC, SSO, retention, integrations. |
| Audit Log | Tamper-chain status, actor, action, IP, timestamp. |

### Why This Verdict

Developer-validation: Test Runs renders **"Why this verdict?"** and Findings detail renders **"Why this finding?"** via shared `apps/web/verdict-explanation.mjs` (`renderVerdictExplanation` / `renderFindingVerdictExplanation`; Findings loads linked run + events by `test_run_id`; `tests/unit/verdict-explanation.test.mjs`, `tests/e2e/ui-smoke.test.mjs`). Placement confidence prefers `verdict.placement_confidence` (DET-014). JSON report export includes `placement_confidence`, including the Postgres report-export adapter path. **Remaining:** browser/accessibility matrix execution, staging/live mode-matrix signoff, staging/live DB evidence (`0005_verdict_placement_confidence` schema/repository parity landed).

Every verdict view must explain probe evidence, agent evidence, confidence, and conclusion:

```text
Verdict: Bypassable

External probe:
- Sent to declared origin target
- TCP 443 connected
- HTTP marker returned 200

Internal agent:
- agent-prod-api-01 observed marker abc123
- Observation mode: host packet + NGINX log
- Confidence: High

Conclusion:
Direct-origin traffic bypassed the CDN/WAF and reached origin.
```

## Security And Operations Backlog

| Area | Required production work |
|---|---|
| Agent hardening | Least privilege, seccomp/AppArmor, no shell execution, no raw payload mode. |
| Package signing | Signed deb/rpm/container, checksums, SBOM. |
| Auto-update | Controlled channels, rollback, version pinning. |
| Tenant isolation | Postgres RLS tests, tenant-scoped tokens, cross-tenant fuzz tests. |
| Secrets | KMS/HSM-backed envelope encryption. |
| Abuse prevention | Prevent use as an attack service; quotas, approvals, monitoring, suspension. |
| SOC access | Just-in-time access, approval logs, break-glass flow. |
| Customer data | Metadata-only defaults, retention, legal hold, deletion workflow. |
| Compliance | SOC 2 controls, ISO mapping, DORA/NIS2 evidence export. |
| Production ops | SLOs, backups, staging evidence, incident playbooks, on-call SLAs. |

## Explicit Non-Goals

Do not add:

| Non-goal | Reason |
|---|---|
| Automatic IP inventory discovery | Access-heavy and outside the no-access-first model. |
| Customer self-service high-scale attacks | Unsafe and unacceptable for enterprise/cloud-provider workflows. |
| Raw packet/payload attack builder | High abuse risk. |
| Full DDoS protection guarantee | AstraNull proves readiness signals; it does not guarantee immunity. |
| Agent requiring inbound firewall access | Bad enterprise adoption model and violates outbound-only design. |

## Production release evidence (metadata validators)

`src/contracts/productionReleaseEvidence.mjs` defines required release kinds. Local npm validators check contract shape and forbidden fields only; they do **not** close staging, security, SOC, legal, provider, KMS, or signing gates.

| npm script | Kind | External evidence still required |
|---|---|---|
| `npm run kms:vault:evidence` | `kms_vault_posture` | Deployed KMS/HSM, rotation drill, security signoff |
| `npm run container:evidence` | `control_plane_container_release` | CI build, scan, registry digest, signing/provenance |
| `npm run staging:local:e2e-matrix` / `npm run release:staging-e2e:evidence` | `staging_e2e_matrix` | Local-staging: seven scenarios `overall_status=passed` (internal SOC evidence). **Deferred (operational config):** hosted staging SSO/agent/probe/report on customer domain |
| `npm run release:compliance-legal:evidence` | `compliance_legal_signoff` | Auditor/legal review of exports |
| `npm run soc:authorization-custody:evidence` | `authorization_custody` | Durable authorization pack custody |
| `npm run placement:staging:evidence` | `placement_confidence_staging` | Live placement mode matrix |
| `npm run gateway:load-abuse:evidence` | `gateway_load_abuse` | Gateway/WAF load and abuse drill |
| `npm run rollback:evidence` | `rollback_fixforward` | Staging rollback/fix-forward drill execution and DB signoff |
| `npm run release:evidence:bundle` | (multi-kind) | Bundle validation only; each kind still needs external evidence |
| `npm run release:staging-attestation:local` / `npm run release:staging-attestation` | (profile inventory) | Local-staging: `production_ready: true` with 31/31 kinds (not customer-facing promotion) |
| `npm run release:gap-audit:local` / `npm run release:gap-audit` | (inventory + checklist + release-plan promotion gates) | Local-staging: `production_ready=true` when 31/31 kinds are accepted and checklist/release-plan documented gates are closed; does not prove customer-specific launch or per-tenant operational wiring — metadata validation alone is not external signoff |
| `npm run release:sample-evidence` | (rehearsal fixtures) | Replace every sample before any production claim |
| `npm run oidc:prod:preflight` | `oidc_prod_auth_preflight` | Real IdP login, MFA, staging auth signoff |
| `npm run edge:protection:evidence` | `edge_protection` | Deployed WAF/gateway config and staging abuse drill |
| `npm run probe:fleet:matrix:evidence` | `probe_fleet_matrix` | Live multi-region signed-worker fleet |
| `npm run postgres:concurrency:evidence` | `postgres_concurrency` | Tenant isolation under load in staging |
| `npm run observability:slo:evidence` | `observability_slo` | Production scrape, dashboards, incident drill |
| `npm run support:readiness:evidence` | `support_readiness` | Staffed on-call, SLA, tabletop execution |
| `npm run notification:provider:evidence` | `notification_provider_config` | Real provider credentials and delivery drill |
| `npm run secret:rotation:evidence` | `secret_rotation_drill` | KMS-backed rotation drill |
| `npm run ui:accessibility:matrix:evidence` | `ui_accessibility_matrix` | Browser/accessibility matrix execution |
| `npm run soc:kill-switch:evidence` | `kill_switch_drill` | Live kill-switch drill signoff |
| `npm run soc:adapter:evidence` | `governed_adapter` | Governed adapter staging exercise |
| `npm run soc:provider-approval:evidence` | `provider_approval` | Provider approval path evidence |
| `npm run evidence:snapshot:manifest` | `evidence_snapshot_manifest` | Immutable snapshot custody in staging |

## Done Criteria For This Backlog

This backlog is complete only when every production gap above is either:

1. implemented,
2. covered by tests,
3. reflected in `PROGRESS.md`,
4. checked or explicitly deferred in `docs/release-checklist.md`,
5. backed by staging, security, SOC, or operations evidence where required (metadata-only CLI pass is not sufficient).
