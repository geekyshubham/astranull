# Full Wireframes and Interaction Details

This document gives implementation agents a concrete UX shape. These are not visual-design final mocks; they are product-level wireframes and interaction requirements.

## Global layout

```text
+--------------------------------------------------------------------------------+
| AstraNull | Org switcher | Env: Production | Search | Help | User             |
+----------------------+---------------------------------------------------------+
| Dashboard            | Page title                         Actions              |
| Target Groups        | ------------------------------------------------------- |
| Agents               | Main content                                           |
| Checks Library       |                                                       |
| Test Runs            |                                                       |
| Findings             |                                                       |
| High-Scale Requests  |                                                       |
| Evidence Vault       |                                                       |
| Reports              |                                                       |
| Integrations         |                                                       |
| Audit Log            |                                                       |
| Settings             |                                                       |
+----------------------+---------------------------------------------------------+
```

Global UX requirements:

- Environment selector must be persistent.
- High-scale controls appear only to authorized SOC/internal users or as customer request forms.
- Dangerous actions require confirmation with scope summary.
- Every page has breadcrumbs and contextual docs link.
- Every table supports filter, search, column chooser, export where appropriate.

## Dashboard wireframe

```text
[Readiness Score 82] [Critical Findings 3] [Agents Online 14/15] [Last Run 22m ago]

[Traffic Path Map: Probe -> Edge/WAF -> Load Balancer -> Agent/Origin]

[Vector Coverage Matrix]
Target Group        Origin  L3/L4  DNS  L7/API  TLS  High-Scale  Alerts
Retail Checkout     FAIL    PASS   N/A  PARTIAL PASS REQUESTED   UNKNOWN
Public API          PASS    PASS   PASS FAIL    PASS NOT RUN     PASS
DNS Edge            N/A     PASS   FAIL N/A     N/A  SCHEDULED   PARTIAL

[Top Findings]                          [Recent Test Runs]
- Direct origin reachable                - Checkout safe run PASS/PARTIAL
- Missing WAF marker block               - API L7 run FAIL
- DNS random-prefix inconclusive         - DNS run INCONCLUSIVE
```

Dashboard tabs:

| Tab | Details |
|---|---|
| Overview | Score, top risks, agent health, recent runs, SOC requests |
| By Target Group | Cards for each service with score, trend, findings |
| By Vector | Matrix grouped by origin/L3/L4/DNS/L7/TLS/high-scale/alerts |
| Executive | Plain-language risk, business impact, recommended next steps |
| Engineering | Raw run health, probe/agent correlation, failed prerequisites |

## Onboarding wizard

```text
Step 1 Org -> Step 2 Environment -> Step 3 Target Group -> Step 4 Agent -> Step 5 First Run
```

Required interactions:

| Step | UI components | Validation |
|---|---|---|
| Organization | name, region, owner | required |
| Environment | prod/stage/lab, data residency, safety level | required |
| Target Group | service name, criticality, owner, description | required |
| Target | domain/IP/URL, protocol, port, expected behavior | format only; no inventory discovery |
| Agent | install method tabs, token scope, copy command | token TTL visible |
| First Run | placement check, safe checks, report preview | disabled until agent online or canary declared |

Empty/error states:

- “No agent yet” -> show install command and troubleshooting.
- “Agent online but cannot prove this target” -> show placement guide.
- “No target declared” -> ask user to add one target manually.

## Target Group Detail

```text
Target Group: Retail Checkout                      [Run Safe Validation]
Owner: payments-team   Criticality: Tier 1   Score: 68

Tabs: Overview | Targets | Agents | Checks | Runs | Findings | Evidence | Settings
```

Overview must show:

- business owner,
- declared targets,
- expected behavior,
- linked agents,
- placement confidence,
- last verdict by vector,
- active findings,
- next recommended action.

Targets tab table:

| Column | Meaning |
|---|---|
| Target | domain/IP/URL declared by customer |
| Type | HTTP, TCP, UDP, DNS, TLS, API |
| Expected behavior | block, allow only protected path, challenge, rate-limit, observe only |
| Agent binding | which agent should observe |
| Last run | last validation |
| Last verdict | protected/bypassable/inconclusive |

## Agents page

```text
[Install New Agent]
Tabs: Linux | Docker | Kubernetes | Packet Mirror | Windows Future

Fleet table:
Agent Name | Env | Target Groups | Mode | Health | Version | Placement | Last Seen | Actions
```

Agent detail wireframe:

```text
Agent: prod-origin-01                         [Upgrade] [Revoke]
Health: Online   Last seen: 8s   Version: 0.4.2   Mode: packet_metadata,canary

Tabs: Overview | Placement | Capabilities | Observations | Logs | Upgrades | Security
```

Placement tab must include:

- what this agent can observe,
- what it cannot observe,
- bound target groups,
- last placement test,
- “random VM cannot observe traffic to other VM unless mirrored” warning,
- recommended alternate placement.

## Test Runs page

```text
Run #TR-2026-000129  Retail Checkout  Direct Origin Bypass
Verdict: BYPASSABLE  Confidence: High  Duration: 42s

[Timeline]
10:00:01 Planner created job
10:00:03 Agent armed observation window
10:00:05 Probe sent nonce from region A
10:00:06 Agent observed nonce on eth0:443
10:00:08 Verdict: bypassable

Tabs: Summary | Timeline | Probe Results | Agent Observations | Correlation | Evidence | Raw Events
```

**"Why this verdict?"** panel (developer-validation on Test Runs — `renderVerdictExplanation`; wireframe content below). Placed after traffic path, before truth table. Findings detail and report export parity still open.

```text
Why this verdict?

Expected: direct origin traffic should be blocked.
External probe: connection succeeded.
Internal agent: nonce was observed on eth0:443.
Observation mode: host packet + NGINX log
Placement confidence: High
Result: Bypassable. Traffic reached protected environment.
Recommended fix: restrict origin ingress to CDN/scrubber/LB source ranges or enforce authenticated origin access.
```

## Findings page

Finding detail must show:

| Section | Content |
|---|---|
| Summary | What failed in one sentence |
| Business context | Target group, owner, criticality |
| Evidence | Probe event, agent event, timestamp, run ID |
| Impact | What an attacker could bypass or exhaust |
| Remediation | Concrete safe fix, not generic advice |
| Retest | Button to rerun exact check |
| Timeline | Created, assigned, accepted, fixed, retested, closed |

## High-Scale Request page

Customer-facing form:

```text
Target Group | Objective | Requested Window | Provider/Cloud | Scope Confirmation
Authorization Upload | Emergency Contacts | Business Impact | Runbook Link
[Submit Request to SOC]
```

Customer cannot choose raw attack implementation. They choose objective and vector family at a controlled abstraction level.

SOC detail page:

```text
Request Summary | Authorization | Provider Approval | Preflight | Schedule | Live Run | Evidence Review

[Approve] [Reject] [Need Info] [Schedule] [Abort] [Close]
```

Live SOC control room:

```text
Status: RUNNING APPROVED SIMULATION        [GLOBAL STOP]
Scope: Retail Checkout only
Window: 10:00-10:30 UTC
Stop Criteria: health < threshold, provider alert, customer stop call, SOC judgement

Panels:
- External availability
- Agent health
- Provider/partner status
- Customer contacts
- Timeline and notes
- Kill switch status
```

## Reports page

Report types:

| Report | Audience | Must contain |
|---|---|---|
| Executive | CISO/board | score, top risks, trend, business services, next decisions |
| Technical | engineering | failed checks, evidence, remediation, retest links |
| SOC | SOC/IR | high-scale details, timeline, stop criteria, live notes |
| Audit | compliance | immutable evidence references, approvals, RBAC/audit events |
| Customer handoff | app owners | only assigned target groups and remediation tasks |

## Visualization checklist

| Visualization | Required interaction |
|---|---|
| Score ring | Click opens score breakdown |
| Vector matrix | Click cell opens latest run/finding |
| Traffic path diagram | Click node shows evidence at that layer |
| Timeline | Filter by planner/probe/agent/SOC/verdict |
| Heatmap | Filter by criticality/severity/environment |
| Agent placement badge | Click opens placement guide |
| Evidence chain | Copy evidence ID and export bundle |

## Completion criteria

UX is complete when a first-time enterprise user can onboard, install an agent, create target groups, run safe checks, interpret results, request high-scale validation, and export evidence without needing a manual product walkthrough.
