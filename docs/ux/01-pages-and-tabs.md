# Product Pages and Tabs

This is the master page map for AstraNull.

## Global navigation

| Main page | Who uses it | Purpose |
|---|---|---|
| Dashboard | Everyone | Enterprise readiness overview. |
| Onboarding | New users | Guided setup: environment, targets, agent, first run. |
| Target Groups | Engineers, security architects | Define what to validate. |
| Agents | Engineers, platform teams | Install, monitor, troubleshoot agents. |
| Checks Library | Security architects, engineers | Understand and enable readiness checks. |
| Test Runs | Engineers, SOC, auditors | Inspect execution, timeline, evidence, verdicts. |
| Findings | Security/SRE teams | Triage and remediate gaps. |
| High-Scale Requests | Customers and SOC | Request, review, approve, execute, close high-scale tests. |
| Reports | Executives, auditors, engineers | Generate reports and evidence packs. |
| Integrations | Admins | Webhooks, Slack, Teams, SIEM, ticketing, optional future connectors. |
| Settings | Admins | Users, roles, API keys, SSO, retention, audit logs, compact release evidence summary. |
| Release Evidence | Owner, admin, SOC, auditor | Metadata-only production release evidence ledger visibility (not production-ready signoff). |
| SOC Console | AstraNull internal SOC | Operate high-scale workflow and test monitoring. |

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
