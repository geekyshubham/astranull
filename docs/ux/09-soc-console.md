# SOC Console UX

## Purpose

The SOC Console is for AstraNull internal SOC users. It handles high-scale DDoS validation governance.

Customers can request high-scale tests, but they cannot execute them. SOC owns review, approval, scheduling, monitoring, stopping, and closure.

## Implemented (developer validation UI)

The web app **SOC Console** route (`#soc`, role `soc` or local developer fallback `owner`) provides a work-focused console wired to existing `/internal/soc/*` APIs:

| Band | Controls | Backend |
|---|---|---|
| Kill switch | Activate / clear tenant kill switch | `POST /internal/soc/kill-switch` |
| Queue | Request id, state chip, target group, reason, artifact counts | `GET /v1/high-scale-requests`, artifacts list |
| Authorization | **Review pack** — accept all `pending_review` artifacts | `POST .../artifacts/:id/review` |
| Governance | **Approve** (dual-SOC workflow unchanged) | `POST .../approve` |
| Schedule | Near-term window (`now−60s` → `now+60m`) for local validation | `POST .../schedule` with `window_start` / `window_end` |
| Execution | Start (dry-run adapter), stop, adapter status | `POST .../start`, `.../stop`, `GET .../adapter-status` |
| Transcript | Optional SOC note | `POST .../notes` |
| Closure | Metadata post-test report; close (backend-gated) | `POST .../post-test-report`, `POST .../close` |

**Action output** panel shows JSON or error text from the latest SOC action without replacing the whole page on failure.

Copy and labels explicitly state: governed **dry-run adapter only**, no customer-triggered traffic, no production completion implied.

Production must remove the customer-owner fallback and treat SOC as a staff-only surface. Customers may submit high-scale requests, but only AstraNull SOC staff can review, approve, reject, schedule, execute, stop, and close them. The broader tenant/subscription/user management plane is documented separately in [Public Landing and Internal Management](../product/13-public-landing-and-internal-management.md).

## SOC console main tabs (product target)

Full production console remains tabbed; developer validation collapses these into bands on one page:

| Tab | Purpose |
|---|---|
| Queue | Incoming high-scale requests and their state. |
| Authorization | Documents, approvals, provider evidence, contacts. |
| Risk Review | Scope, blast radius, test class, safety constraints. |
| Schedule | Windows, notifications, go/no-go checklist. |
| Execution | Live run console, health, metrics, kill switch. |
| Closure | Post-test notes, findings, report, lessons learned. |

## High-scale request card

Customers file requests from the **High-Scale Requests** page (`#high-scale` form: target group, objective, window, timezone, emergency contacts, provider context, scope confirmation). SOC sees the same fields on the queue card (target group, reason/objective, artifact counts). Execution controls stay on this SOC console only.

| Field | Description |
|---|---|
| Customer | Tenant/org. |
| Target group | Declared scope. |
| Objective | What the customer wants to validate. |
| Requested window | Start/end time and timezone. |
| Environment | Prod/staging/lab. |
| Business criticality | Critical/high/medium/low. |
| Provider | AWS/Azure/GCP/CDN/on-prem/other. |
| Emergency contacts | Metadata-only contacts from intake (redacted). |
| Scope confirmation | Customer attestation that declared scope is accurate. |
| Authorization status | Missing/partial/complete. |
| Risk status | Low/medium/high/blocked. |
| SOC owner | Assigned analyst. |

## Execution console

Must show:

- run state,
- active scenario name,
- approved scope,
- current phase,
- external availability,
- agent health,
- target health,
- customer contact status,
- provider contact status,
- kill switch,
- stop reason dialog,
- live notes.

## SOC state machine

```text
Requested
  -> Scope Review
  -> Authorization Review
  -> Provider Approval Pending
  -> Risk Review
  -> Scheduled
  -> Go/No-Go
  -> Running
  -> Stopping
  -> Completed
  -> Report Published

Blocked states:
  Authorization Missing
  Provider Denied
  Scope Invalid
  Customer Unreachable
  Safety Constraint Failed
```

## Production gaps (not in developer-validation UI)

- Dedicated tabs (risk review, go/no-go checklist, live metrics, provider contacts).
- Per-artifact reject workflow and authorization pack completeness UI.
- Read-only post-test report viewer and export signoff.
- Kill switch status indicator and run timeline visualization.
- Staging/ops evidence and durable legal retention workflows.

## Completion criteria

SOC Console is complete when no high-scale test can run without documented scope, authorization, schedule, monitoring, and kill switch readiness.
