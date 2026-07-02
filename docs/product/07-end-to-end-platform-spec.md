# AstraNull End-to-End Platform Spec

## Product definition

AstraNull is a no-access-first DDoS readiness validation platform. Customers declare target groups and install an internal AstraNull Agent/canary. AstraNull then runs safe external validation probes and correlates external probe outcomes with internal observations. High-scale DDoS simulations are not customer self-serve; they are requested by customers, reviewed by SOC, gated by authorization/provider approval, executed or coordinated by SOC, monitored live, and closed with evidence.

## Platform modules

| Module | User-facing purpose | Backend responsibility | Completion signal |
|---|---|---|---|
| Organization & Environment | Separate customers, business units, prod/stage/lab | Tenant isolation, retention, RBAC, audit | Org/env can be created, updated, archived, audited |
| Target Groups | Customer-declared scope such as `Retail Checkout`, `Public APIs`, `DNS Edge` | Store targets, expected behavior, linked agents, enabled checks | Safe run can be planned without IP discovery |
| Agent Fleet | Internal observation and heartbeat | Registration, control channel, observation ingestion, upgrades | Agent is online, placed, healthy, versioned |
| Checks Library | Explain what each check validates | Versioned check definitions, safety class, prerequisites | Every enabled check has docs, limits, evidence schema |
| Test Runs | Execute validation and show proof | Planning, scheduling, probe dispatch, correlation, verdicts | Run has timeline, result, evidence, findings |
| Findings | Turn failures into work | Deduplication, severity, remediation, assignment, retest | Finding can be assigned, fixed, retested, closed |
| Reports | Executive/technical/audit evidence | Report rendering, evidence bundling, export | Downloadable report with signed evidence references |
| SOC Console | Govern high-scale tests | Approval state machine, ROE, kill switch, live control room | SOC can approve/reject/run/stop/close with audit |
| Settings & Identity | Tokens, users, SSO, integrations | Auth, RBAC, token lifecycle, integration secrets | Tokens are scoped/rotatable/revocable/audited |

## Core objects

| Object | Required fields | Why it exists |
|---|---|---|
| Organization | name, plan, region, retention, owners | Tenant boundary |
| Environment | org_id, name, type, data_region, safety_profile | Prod/stage/lab separation |
| Target Group | env_id, name, owner, criticality, declared targets, expected behavior | Primary validation scope |
| Target | type, value, protocol, port, hostname/SNI, path, notes | What to probe |
| Agent | identity, env, version, modes, health, placement, capabilities | What can observe inside |
| Agent Binding | target_group_id, agent_id, observation role | Which agent proves which target |
| Check Definition | id, vector, safety class, prerequisites, evidence schema | Reusable validation logic |
| Test Policy | target_group, enabled checks, schedule, caps, notification rules | What runs and when |
| Test Run | policy/check, state, timestamps, run owner, risk class | Execution instance |
| Probe Event | source region, target, nonce, response metadata | External observation |
| Agent Observation | agent, nonce, signal type, interface/log/path, timestamp | Internal observation |
| Verdict | check, target, result, confidence, reason | Product answer |
| Finding | severity, owner, status, remediation, SLA, retest link | Work item |
| SOC Request | scope, ROE, approvals, provider evidence, schedule | High-scale governance |

## User roles

| Role | Can do | Cannot do |
|---|---|---|
| Customer Owner | Manage org, users, SSO, tokens, target groups, safe runs, high-scale requests | Start high-scale traffic directly |
| Security Admin | Manage target groups, checks, reports, findings | Bypass SOC approval |
| Platform Engineer | Install agents, bind agents, troubleshoot placement, run safe checks | Change org billing/security settings unless granted |
| App Owner | View assigned target group, findings, reports, retests | Manage other target groups |
| Auditor | Read-only reports, evidence, audit logs | Run checks or change config |
| SOC Analyst | Review request, preflight, monitor, stop, annotate | Approve final high-risk decision alone if policy requires two-person approval |
| SOC Approver | Approve/reject high-scale request | Execute outside approved scope |
| Platform Admin | Operate AstraNull system | Access customer payload data by default |

## End-to-end flows

### Flow A: Customer onboarding

```text
Invite accepted -> Organization selected -> Environment created -> Target group created -> Target declared -> Agent install method selected -> Bootstrap token generated -> Agent installed -> Agent registers outbound -> Placement test -> First safe run -> Findings/report
```

| Step | UX detail | Backend detail | Error state |
|---|---|---|---|
| Create environment | Simple form: name, prod/stage, region | `environment.created` audit event | Duplicate name, missing owner |
| Add target group | Wizard asks business service, criticality, owner | Creates target_group row | No targets yet -> empty state guidance |
| Add declared target | Domain/IP/URL/port, expected behavior | Format validation only | Do not infer assets or scan inventory |
| Generate token | Show one-time install command | Hash token, TTL, scope, max uses | Expired/revoked token explained clearly |
| Install agent | Linux/Docker/Helm tabs | Agent registers via outbound TLS | Offline/troubleshooting page |
| Placement test | Friendly diagram shows what agent can prove | Baseline nonce job | Misplaced agent verdict if no signal expected |
| First run | Button: Run safe validation | Planner creates bounded jobs | Blocked if no agent binding/check prerequisites |

### Flow B: Safe validation run

```text
User clicks Run -> Planner validates scope -> Agent opens observation window -> Probe sends nonce -> Agent uploads observations -> Correlation engine evaluates -> Verdict/finding/report created
```

| State | Actor | Details |
|---|---|---|
| Planned | Backend | Select enabled checks, target list, safety caps, probe regions |
| Agent Armed | Agent | Observation window opened before probe starts |
| Probing | Probe Fleet | Sends bounded low-rate labeled probes only |
| Collecting | Backend | Waits for probe and agent events |
| Correlating | Correlation Engine | Matches by test_id, nonce, target, time window |
| Verdicted | Verdict Engine | Protected, Bypassable, Inconclusive, Misplaced Agent, Partial |
| Reported | UI/Notification | Findings, evidence timeline, report artifacts |

### Flow C: Agent installation

```text
Settings/Agent page -> Generate bootstrap token -> Copy install command -> Run in customer environment -> Agent registers -> Identity issued -> Heartbeat visible -> Agent bound to target group
```

Important UX rule: show install choices as tabs, not a long command list.

| Tab | Best for | Main command/artifact |
|---|---|---|
| Linux one-line | VM/bare metal quick start | `curl ... install.sh | sudo bash -s -- --token ...` |
| Debian/Ubuntu | Controlled package management | apt repo or `.deb` |
| RHEL/Amazon Linux | Enterprise Linux | yum/dnf repo or `.rpm` |
| Generic Linux | Locked-down distros | signed tarball |
| Docker | Canary container | `docker run ...` |
| Kubernetes | GKE/EKS/AKS/OpenShift | Helm chart |
| Packet Mirror Collector | Broad traffic observation | virtual appliance/container with mirror target settings |

### Flow D: High-scale request

```text
Customer requests -> Authorization pack collected -> Provider approval tracked -> SOC reviews -> Risk/preflight -> Schedule -> Live SOC control room -> Stop/complete -> Evidence report -> Remediation/retest
```

High-scale state machine:

| State | Meaning | Allowed next states |
|---|---|---|
| Draft | Customer preparing request | Submitted, Cancelled |
| Submitted | Awaiting SOC review | Needs Info, Rejected, Authorization Pending |
| Authorization Pending | Customer/provider docs missing | Ready for Preflight, Rejected |
| Ready for Preflight | Docs present | Preflight Failed, Scheduled |
| Scheduled | Approved window exists | Armed, Cancelled |
| Armed | SOC go/no-go about to happen | Running, Aborted |
| Running | SOC-controlled execution active | Stopping, Completed |
| Stopping | Kill switch/stop requested | Stopped |
| Completed | Scenario ended normally | Evidence Review |
| Stopped | Scenario terminated | Evidence Review |
| Evidence Review | SOC preparing final report | Closed |
| Closed | Immutable final state | none |

## Product pages and tabs

| Page | Primary user | Must show | Primary action |
|---|---|---|---|
| Dashboard | All | Readiness score, risk trend, critical findings, agent health, last run | Run safe validation / open finding |
| Onboarding Wizard | New users | Stepper, explanation, install commands, first run | Finish setup |
| Environments | Owner/Admin | Env cards, health, data region, target groups, agents | Create environment |
| Target Groups | Security/App owners | Service map, targets, agents, checks, runs, findings | Add target / run checks |
| Target Group Detail | Engineers | Overview, target list, expected behavior, coverage matrix | Edit policy / run now |
| Agents | Platform engineers | Install tabs, fleet table, health, version, mode, placement | Generate token |
| Agent Detail | Platform engineers | Heartbeat, capabilities, observations, logs, upgrade status | Revoke/upgrade/troubleshoot |
| API Keys & Tokens | Owners/Admins | Token scope, TTL, last use, revoke, audit | Generate bootstrap token |
| Checks Library | Security admins | Check explanation, vector, risk class, prerequisites, evidence | Enable/check details |
| Test Policies | Security admins | Enabled checks, schedules, caps, notifications | Save policy |
| Test Runs | Engineers/SOC | Timeline, probe, agent, correlation, evidence | Download evidence |
| Findings | Security/app owners | Severity, owner, SLA, remediation, retest | Assign/close/retest |
| Evidence Vault | Auditors | Immutable event chain, reports, authorization docs | Export evidence |
| High-Scale Requests | Customers/SOC | Request form, docs, status, schedule, live state | Submit/review |
| SOC Console | SOC | Queue, preflight, live run, kill switch, post-test | Approve/stop/close |
| Reports | Executives/Auditors | Executive, technical, SOC, compliance reports | Generate/export |
| Integrations | Admins | Slack/Teams/webhook/SIEM/ticketing | Connect integration |
| Audit Log | Admins/Auditors | User, token, agent, test, SOC actions | Filter/export |
| Settings | Owners | Org, SSO, RBAC, retention, billing | Configure org |

## Best UX representations

| Representation | Use it for | Why it works |
|---|---|---|
| Readiness score ring | Executive overview | Instantly communicates posture |
| Vector coverage matrix | L3/L4/DNS/L7/API/high-scale coverage | Shows gaps without long text |
| Traffic path diagram | Outside probe -> CDN/WAF -> origin -> agent | Makes inside/outside proof intuitive |
| Truth-table card | Probe result + agent observation -> verdict | Explains why a result passed/failed |
| Timeline | Test run, SOC approval, evidence chain | Audit-friendly sequence |
| Placement confidence badge | Agent can/cannot prove target | Prevents false confidence |
| Findings heatmap | Severity by target group/vector | Prioritization |
| SOC control room panel | Live high-scale operation | Safe execution and stop visibility |
| Evidence chain | Signed events and artifacts | Builds trust for audit/compliance |

## Friendly UX rules

- Every empty state must answer: “What should I do next?”
- Every dangerous action must show scope, risk, approval state, and stop path.
- Every inconclusive result must explain whether the agent was misplaced, logs were missing, or traffic path was not observable.
- Never show “DDoS attack started” to customers for high-scale; show “SOC-controlled approved simulation running.”
- Default language should be “validation,” “readiness,” “evidence,” and “simulation,” not casual attack wording.
- Always show expected behavior next to actual result.
- Always provide a retest button after remediation.

## Completion criteria

This spec is complete when product, UX, backend, detection, agent, and SOC agents can trace every build task to a page, flow, object, state machine, and acceptance criterion.
