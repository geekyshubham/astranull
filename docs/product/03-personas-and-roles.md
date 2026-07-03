# Personas and Roles

## External customer personas

| Persona | Needs | Product experience |
|---|---|---|
| CISO / VP Security | Enterprise risk, board evidence, trend, audit readiness | Dashboard, score trend, executive reports, risk acceptance. |
| Security Architect | Validation coverage, protection design gaps | Target groups, check library, findings, remediation guidance. |
| Network Engineer | Ports, protocols, origin exposure, packet path | L3/L4 checks, agent placement, packet observation evidence. |
| App/API Owner | L7 readiness, rate limits, endpoint risk | API/L7 checks, endpoint limits, safe recommendations. |
| SRE / Platform Engineer | Availability, health, runbooks, alerts | Test runs, timelines, health data, retest scheduling. |
| Compliance/Auditor | Evidence and approvals | Reports, immutable audit log, authorization artifacts. |
| Read-only Executive | Minimal high-level status | Business-service score cards and reports. |

## Internal AstraNull personas

| Persona | Responsibilities | Product area |
|---|---|---|
| SOC Analyst | Review high-scale requests, validate permissions, monitor runs | SOC Console |
| SOC Lead | Approve risky tests, enforce rules, stop tests | SOC Console, Authorization Pack |
| Customer Success Engineer | Help customers onboard and place agents correctly | Onboarding, Agents, Target Groups |
| Detection Engineer | Add/maintain vector checks and verdict logic | Check Library, Detection Engine |
| Platform Admin | Tenant support, operational health, incident response | Internal Management and Observability |
| Billing Operations | Manage subscription status, plan metadata, billing references, and entitlement requests | Internal Management |
| Security Admin | Review internal audit, legal hold, data export approval, and staff access policy | Internal Management, Audit |

## RBAC matrix

| Permission | Owner | Admin | Engineer | SOC Analyst | Auditor | Viewer |
|---|---:|---:|---:|---:|---:|---:|
| View dashboard | Yes | Yes | Yes | Yes | Yes | Yes |
| Manage target groups | Yes | Yes | Yes | No | No | No |
| Generate bootstrap token | Yes | Yes | Yes | No | No | No |
| Install agent | External action | External action | External action | No | No | No |
| Start safe test | Yes | Yes | Yes | No | No | No |
| Request high-scale test | Yes | Yes | Yes | No | No | No |
| Approve high-scale test | No | No | No | Yes | No | No |
| Execute high-scale test | No | No | No | Yes | No | No |
| Stop high-scale test | No | No | No | Yes | No | No |
| View reports | Yes | Yes | Yes | Yes | Yes | Yes |
| Accept risk | Yes | Yes | No | No | No | No |
| Manage users | Yes | Yes | No | No | No | No |
| View audit logs | Yes | Yes | No | Yes | Yes | No |

## Internal staff roles

Customer tenant roles do not grant access to AstraNull internal management. Internal staff roles are assigned through the staff identity provider and apply only to `/internal/*` management surfaces.

| Staff role | Scope |
|---|---|
| `internal_admin` | Tenant lifecycle, sign-up review, subscription metadata, entitlements, support owner assignment. |
| `billing_ops` | Subscription status, billing references, entitlement requests; no SOC execution. |
| `support_engineer` | Support context, approved owner/admin invites, role correction requests; no subscription or high-scale approval. |
| `soc_analyst` | High-scale request review, authorization pack validation, monitoring, notes. |
| `soc_lead` | Final high-scale approval, schedule/start/stop/close, kill-switch decisions. |
| `security_admin` | Internal audit review, legal hold, data export approval, staff access policy. |

See [Public Landing and Internal Management](13-public-landing-and-internal-management.md) for the staff-only management surface and approval model.
