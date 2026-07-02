# Target Groups Page

## Purpose

Target Groups are how customers tell AstraNull what to validate. There is no automatic inventory discovery in core scope.

## Page layout

```text
Target Groups
[+ New Target Group] [Import CSV] [Filter]

| Name | Env | Criticality | Score | Agents | Last Run | Findings | Actions |
| Retail Checkout | Prod | Critical | 62 | 2 online | 2h ago | 3 critical | Open |
| API Gateway | Prod | Critical | 81 | 1 warning | 1d ago | 1 high | Open |
```

## Create target group wizard

| Step | Fields | Validation |
|---|---|---|
| 1. Basics | Name, environment, criticality, owner, emergency contact | Name unique inside tenant. |
| 2. Targets | FQDN/IP/URL/DNS/canary definitions | At least one target required. |
| 3. Expected behavior | Block/allow/challenge/rate-limit expectations | Every target needs default expectation. |
| 4. Agent binding | Select existing agent or generate install token | Warn if no agent exists. |
| 5. Checks | Recommended safe checks enabled | High-scale checks shown as request-only. |
| 6. Review | Summary and first-run option | User confirms scope. |

## Target detail page

### Overview tab

Show:

- readiness score,
- latest verdict,
- active findings,
- attached agents,
- enabled checks,
- last successful evidence timestamp,
- next scheduled run.

### Targets tab

Columns:

| Column | Description |
|---|---|
| Type | FQDN, URL, IP, DNS, canary. |
| Value | Target string. |
| Protocol/Port | Example: HTTPS/443, TCP/443, UDP/53. |
| Expected behavior | Must block, must allow, must challenge, etc. |
| Agent binding | Agent expected to observe this target. |
| Last result | Pass/fail/inconclusive. |

### Expected Behavior tab

Use friendly policy cards:

```text
Direct Origin Access
Expected: Must be blocked before origin
Evidence needed: External probe blocked + agent does not observe nonce
Status: Failing
```

### Checks tab

Show checks as cards with risk class:

| Field | Description |
|---|---|
| Check name | Direct-origin bypass, forbidden port, WAF marker. |
| Risk class | Safe, controlled, SOC-gated. |
| Frequency | Manual, hourly, daily, weekly. |
| Last result | Pass/fail/inconclusive. |
| Requirements | Agent mode, canary port, customer marker rule. |

## Completion criteria

Target Groups page is complete when users can fully configure declared scope without cloud access, bind agents, enable checks, run safe tests, and understand missing requirements.
