# Product Pages and Tabs

> **Superseded in part by the 2026-07 portal revamp.**  
> The authoritative page map, sidebar structure, per-page composition, and interaction contracts for the next React port live in [`14-portal-revamp-2026-07.md`](14-portal-revamp-2026-07.md). CRUD gaps in [`15-crud-operations-backlog.md`](15-crud-operations-backlog.md). Visual reference in [`reference-2026-07/`](reference-2026-07/).  
> Where this file and the revamp spec disagree on IA (sidebar groups, deleted routes, renamed labels), the revamp spec wins. Sections below that describe checks, target groups, agents, and findings **tab depth** remain useful — the revamp keeps those tabs.

This is the master page map for AstraNull.

## Global navigation

| Main page | Who uses it | Purpose |
|---|---|---|
| Public Landing | Visitors, prospects, returning users | Explain AstraNull and route to sign-up or login. |
| Sign-Up Intake | Prospects/customers | Submit account request metadata for review or provisioning. |
| Dashboard | Everyone | Enterprise readiness overview. |
| Onboarding | New users | Guided setup: environment, targets, agent install, heartbeat verification, optional placement test, first safe run. |
| Target Groups | Engineers, security architects | Define what to validate. |
| Agents | Engineers, platform teams | Install, monitor, troubleshoot agents. |
| Checks Library | Security architects, engineers | Understand and enable readiness checks. |
| Test Runs | Engineers, SOC, auditors | Inspect execution, timeline, evidence, verdicts. |
| Findings | Security/SRE teams | Triage and remediate gaps. |
| High-Scale Requests | Customers | Submit and track high-scale requests; no approval or execution controls. |
| Reports | Executives, auditors, engineers | Generate reports and evidence packs. |
| Integrations | Admins | Webhooks, Slack, Teams, SIEM, ticketing, optional future connectors. |
| Settings | Admins | Users, roles, API keys, SSO, retention, audit logs, compact release evidence summary. |
| Release Evidence | Owner, admin, SOC, auditor | Metadata-only production release evidence ledger visibility (not production-ready signoff). |
| Internal Management | AstraNull staff only | Manage sign-up requests, tenants, subscriptions, entitlements, support actions, and internal approvals. |
| SOC Console | AstraNull internal SOC | Operate high-scale workflow and test monitoring. |

Customer-facing navigation must not include `Internal Management` or `SOC Console`. Those pages are separate staff-only surfaces and must fail closed for customer principals even when accessed by direct URL.

## Public and internal pages

| Page | Audience | Required behavior |
|---|---|---|
| Public Landing | Unauthenticated visitors | Show AstraNull product promise and route `Sign up` to intake and `Log in` to the configured IdP. |
| Sign-Up Intake | Prospects/customers | Capture organization, work email/domain, contact, requested plan, intended use, region, and high-scale interest. |
| Internal Overview | AstraNull staff | Show pending sign-ups, subscription requests, high-scale reviews, blocked tenants, and support alerts. |
| Sign-Up Queue | Internal admin/customer operations | Approve, reject, request more information, and provision tenants. |
| Tenant Detail | Internal admin/support/security | View lifecycle state, subscription, entitlements, owner/admin users, support notes, and audit activity. |
| Subscription Console | Internal admin/billing operations | Manage plan, limits, billing status, contract references, and effective-date changes. |
| User Support Console | Internal admin/support | Resend approved invites, disable users, request role corrections, and record support notes. |
| Approval Queue | Staff roles by request type | Decide sign-up, subscription, connector, export, and high-scale requests with evidence and reason. |
| Internal Audit | Internal admin/security | Filter internal audit by tenant, actor, action, resource, and time. |

## Onboarding wizard steps

| Step | User action | Platform behavior | Success condition |
|---|---|---|---|
| Environment | Create validation scope | Stores environment metadata | At least one environment exists. |
| Target group | Declare business service | Stores target group | Target group created. |
| Declared target | Add FQDN/URL/IP | Format validation only | At least one target exists. |
| Bootstrap token | Generate one-time token | Issues install credential | Token created; install commands shown. |
| Install agent | Copy Linux/Docker/Helm command | Shows outbound-only install tabs | Optional — agent registration recommended. |
| Verify heartbeat | Wait on wizard | Polls `GET /v1/agents` until heartbeat or timeout | Online agent with `last_heartbeat_at`; timeout shows friendly troubleshooting empty state with retry and Agents page links. |
| Placement test | Start optional safe canary run | Starts `path.protected_canary.safe` against declared target | Optional — bounded metadata-only canary to strengthen placement confidence. |
| First safe run | Start validation | Starts customer-runnable safe check (e.g. `origin.direct_bypass.safe`) | Safe test run created. |
| Review result | Open runs/evidence/findings | Links to verdict and evidence chain | Verdicted run exists. |

Wizard panels surface **placement confidence** hints (from readiness diagnostics and agent capabilities) on heartbeat verification and placement-test steps. Heartbeat verification does not render raw agent credentials or payloads.

## Dashboard tabs

| Tab | Details shown |
|---|---|
| Overview | Readiness score, critical findings, coverage, latest runs, high-scale requests. |
| Business Services | Scores grouped by target group/business service. |
| Risk Trends | Score trend, finding count, recurring failures. |
| Evidence Feed | Latest validated events, reports, approvals. |

## Target Groups tabs

| Tab | Details shown |
|---|---|
| Overview | Score, risk, coverage, active findings, last run. |
| Targets | FQDNs, URLs, IPs, ports, DNS services, canaries. |
| Expected Behavior | Block/allow/challenge/rate-limit expectations. |
| Agents | Bound agents, placement status, observation modes. |
| Checks | Enabled checks, risk class, schedule, last result. |
| Runs | Historical test runs. |
| Findings | Issues linked to this group. |
| Settings | Owners, contacts, maintenance windows, notifications. |

## Agents tabs

| Tab | Details shown |
|---|---|
| Install | Linux, Docker, Kubernetes, cloud-startup commands. |
| Fleet | Agent list, status, environment, target group, version. |
| Health | Heartbeats, latency, queue lag, CPU/memory, clock skew. |
| Placement | What this agent can observe and whether baseline traffic was seen. |
| Capabilities | Packet metadata, canary listener, log tail, mirror collector, Kubernetes mode. |
| Logs | Agent-side operational logs and error codes. |
| Upgrades | Version rollout, pinned versions, update history. |

## Checks Library tabs

| Tab | Details shown |
|---|---|
| Recommended | Best checks for current target group. |
| Origin Bypass | Direct IP/Host/SNI/canary bypass checks. |
| L3/L4 | TCP/UDP/ICMP/protocol/port checks. |
| DNS | Resolver/authoritative/NXDOMAIN/exposure checks. |
| L7/API | HTTP/WAF/rate-limit/API/resource checks. |
| Protocols | TLS, HTTP/2, HTTP/3/QUIC, WebSocket. |
| High-Scale | SOC-gated validation scenarios. |
| Custom | Customer-defined marker or safe canary rules. |

## Test Runs tabs

| Tab | Details shown |
|---|---|
| Summary | Verdict, score impact, top findings, start/end time. |
| Timeline | Sequence of planner, probe, agent, detection, finding, notification events. |
| Probe Results | External response, status code, latency, network outcome, source region. |
| Agent Observations | Nonce observed/not observed, interface, port, timestamp, signal type. |
| Correlation | Matching logic, time window, confidence, truth table result. |
| Evidence | Immutable event IDs, logs, screenshots, approvals, artifacts. |
| Raw Events | Filtered debug view for advanced users. |

## Findings tabs

| Tab | Details shown |
|---|---|
| Open | Active findings by severity. |
| By Target Group | Findings grouped by service. |
| By Vector | Origin, L3/L4, DNS, L7/API, high-scale. |
| Accepted Risk | Findings risk-accepted by owner. |
| Closed | Fixed or no longer detected. |
| SLA | Due dates, owner, escalation. |

## High-Scale Requests tabs

| Tab | Details shown |
|---|---|
| Request Form | Target group, scope, objective, window, contacts. |
| Authorization | Customer approval, provider approval, legal documents, emergency contacts. |
| SOC Review | SOC checklist, risk rating, decision, comments. |
| Schedule | Time window, freeze periods, stakeholder reminders. |
| Live Run | SOC-only run state, metrics, external health, agent health, kill switch. |
| Post-Test | Findings, report, evidence, lessons learned. |

## Settings tabs

| Tab | Details shown |
|---|---|
| Organization | Company details, environments, data residency. |
| Users & Roles | Invite users, assign roles, remove users. |
| API Keys | Generate bootstrap tokens, service tokens, rotate/revoke. |
| SSO/SAML | Enterprise identity integration. |
| Notifications | Email/Slack/Teams/webhook rules. |
| Integrations | Ticketing, SIEM/SOAR, optional provider connectors. |
| Data Retention | Evidence retention, packet metadata policy, report archive. |
| Audit Log | Immutable admin, agent, test, approval actions. |
