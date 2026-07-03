# Platform Roadmap

Phases describe **production capability targets**. Developer validation mode may implement slices early; a phase is not complete until [`docs/release-checklist.md`](../release-checklist.md) evidence exists for that phase.

## Phase 0: Public entry and internal management foundation

Goal: separate public acquisition, customer product use, and AstraNull staff operations before broad rollout.

| Feature | Outcome | Production gate |
|---|---|---|
| Public landing | Visitors can understand AstraNull and choose sign up or login. | Privacy-safe public analytics, no internal links |
| Sign-up intake | Prospects submit account requests for review/provisioning. | Abuse controls, audit, notification path |
| Internal management | AstraNull staff manage sign-up requests, tenants, subscriptions, entitlements, and support actions. | Staff IdP, MFA, staff RBAC, internal audit |
| Subscription enforcement | Plans and entitlements gate features and limits in services. | Backend enforcement tests |
| Staff/customer separation | Customer portal cannot expose or authorize internal management actions. | Direct-route denial tests |

## Phase 1: Core validation loop (production)

Goal: prove the outside-to-inside validation loop in a hardened deployment.

| Feature | Outcome | Production gate |
|---|---|---|
| Tenant/org setup | Customer authenticates via SSO and creates environments. | OIDC, MFA policy |
| Target groups | Customer declares what to validate. | No auto-discovery |
| Bootstrap tokens | Customer generates install command. | Signed agent packages |
| Agent install | Agent registers and sends heartbeat outbound-only. | mTLS or strong identity |
| External probes | Safe canary probes from probe workers. | Signed jobs, rate caps |
| Agent observations | Agent reports whether nonce arrived. | Placement guide compliance |
| Correlation | Verdict from external + internal signals. | Evidence in durable store |
| Dashboard/report | Readiness and evidence for stakeholders. | Redaction + retention |

## Phase 2: Safe check library

Goal: cover the main low-risk DDoS readiness checks.

| Feature | Outcome |
|---|---|
| Direct-origin bypass | Detect origin exposure. |
| Protected-path canary | Prove CDN/WAF/LB path behavior. |
| Forbidden port checks | Validate network exposure. |
| DNS checks | Validate declared DNS exposure and resolver posture. |
| HTTP/L7 checks | Validate method, header, WAF marker, rate-limit basics. |
| API checks | Validate declared expensive endpoints. |
| Misplaced-agent detection | Prevent false confidence. |

## Phase 3: Enterprise evidence

Goal: continuous operation for large enterprises.

| Feature | Outcome |
|---|---|
| RBAC and audit | Enterprise controls on all sensitive actions. |
| Reports | Executive, technical, audit, SOC. |
| Integrations | Slack, Teams, email, webhook, ticketing (customer-configured). |
| Scheduled retesting | Drift detection. |
| Evidence archive | Compliance-ready proof. |

## Phase 4: SOC-gated high-scale

Goal: legally authorized high-scale readiness assessments only.

| Feature | Outcome |
|---|---|
| High-scale request | Customer can request but not self-run. |
| Authorization pack | Provider/customer/legal approvals tracked. |
| SOC console | SOC validates, schedules, runs, monitors, stops. |
| Execution adapters | Governed provider/internal adapters controlled by SOC — no unmanaged generators. |
| Post-test report | Outcome, timeline, impact, mitigations, evidence. |

## Phase 5: Optional enhanced mode

Goal: deeper evidence for customers who approve integrations.

| Feature | Outcome |
|---|---|
| Optional cloud/CDN/WAF connectors | Config evidence and richer context. |
| Optional SIEM/SOAR integration | Alert validation and incident evidence. |
| Optional IaC integration | Remediation-as-code suggestions. |

## Phase 6: Optional WAF posture add-on

Goal: add WAF posture management without changing the core no-access-first product path.

| Feature | Outcome |
|---|---|
| WAF coverage inventory | Customer-declared targets can be classified as protected, underprotected, unprotected, or unknown using evidence. |
| Safe WAF marker validation | Harmless marker rules/canaries validate block/challenge/monitor behavior without attack payloads. |
| WAF effectiveness drift | Approved baselines compare behavior over time and raise evidence-backed drift findings. |
| CVE-to-mitigation pipeline | Relevant CVEs can produce vendor-aware WAF mitigation recommendations and tickets, with no auto-deploy by default. |
| Optional WAF/CDN/cloud connectors | Read-only connector snapshots enrich posture when the customer explicitly configures them. |
| Optional discovery inbox | Passive/import/connector candidates require approval before becoming targets or test scope. |
| Remediation/SIEM/SOAR workflows | Findings can route to ticketing, SIEM, SOAR, Slack, and webhooks with redacted metadata. |
