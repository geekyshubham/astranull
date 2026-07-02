# High-Scale Request and Approval Flow

## Principle

Customers can request high-scale DDoS validation. They cannot self-execute it. AstraNull SOC decides whether it can proceed after validating authorization, scope, provider rules, timing, and safety.

## Flow

```text
Customer submits request (UI form or API with production-shaped payload)
  -> Platform validates target scope and SOC-009 intake (environment, criticality, scenarios, safe limits, stop/abort criteria, window, contacts, provider context, scope_confirmation)
  -> Platform computes authorization_pack_status (missing requirements until proof uploaded)
  -> SOC reviews scope
  -> Customer uploads authorization pack artifacts (metadata references per type)
  -> SOC validates customer/business/legal/provider approvals and scope/rate plan
  -> SOC performs risk review
  -> SOC schedules window
  -> Go/no-go meeting/checklist
  -> SOC executes through approved adapter/provider
  -> SOC monitors health and can stop immediately
  -> SOC closes with report and findings
```

## Required request fields

| Field | Required | Description |
|---|---:|---|
| Target group | Yes | Declared scope only. |
| Objective | Yes | What readiness question is being answered. |
| Environment | Yes | Production/staging/lab. |
| Business criticality | Yes | Used for risk review. |
| Requested scenario / vector families | Yes | Metadata declaration of families to validate. |
| Safe requested limits | Yes | `requested_limits.max_rate` and `requested_limits.max_duration_minutes` (metadata only). |
| Stop criteria | Yes | Written pause/stop thresholds. |
| Abort criteria | Yes | Immediate abort conditions. |
| Requested window | Yes | Start/end/timezone. |
| Cloud/provider/CDN context | Yes | AWS/Azure/GCP/CDN/on-prem/other. |
| Emergency contacts | Yes | Customer contacts available during test. |
| Provider contacts | If applicable | Cloud/CDN/DDoS provider contacts. |
| Existing mitigation provider | If known | Helps SOC determine permission path. |
| Maintenance approval | Required for prod | Customer-side change/test approval. |
| Scope confirmation | Yes | Customer confirms declared target group scope. |
| Authorization pack artifacts | Required before SOC approve | Per-type metadata uploads; see authorization pack doc. |

## Approval gates

| Gate | Owner | Must be true |
|---|---|---|
| Scope gate | SOC | Target belongs to customer-declared scope. |
| Intake gate | Platform | SOC-009 intake fields present. |
| Authorization pack gate | SOC | `authorization_pack_status` acceptable; required artifacts accepted. |
| Legal gate | SOC/legal | Written customer and legal authorization when required. |
| Provider gate | SOC/customer | Required cloud/CDN/provider approval exists. |
| Technical gate | SOC | Agent/health monitoring is ready. |
| Safety gate | SOC | Limits, kill switch, stop/abort criteria, contacts, window are set. |
| Go/no-go gate | SOC lead | Final sign-off before execution. |

## Authorization pack status (customer-visible)

When the API returns `authorization_pack_status` on a request:

| Surface | Behavior |
|---|---|
| High-Scale UI | Shows overall status and missing requirement names/fields. |
| SOC approve | Blocked with `authorization_pack_incomplete` until pack gate passes. |

## Authorization templates

The governed template catalog in `src/contracts/authorizationTemplates.mjs` and the markdown pack at [`../templates/high-scale-authorization-pack.md`](../templates/high-scale-authorization-pack.md) cover every required authorization artifact type, including business approval, legal approval, scope/rate plan, abort criteria, and provider approval. These templates are operational starting points only; production use still requires customer/legal review, durable document custody, export retention signoff, and staging workflow evidence.

## High-scale states

| State | Meaning |
|---|---|
| Draft | Customer is preparing request. |
| Submitted | Request is waiting for SOC. |
| Scope Review | SOC validates target scope. |
| Authorization Pending | Required documents missing. |
| Provider Approval Pending | Cloud/CDN/provider approval missing. |
| Risk Review | SOC evaluates blast radius. |
| Scheduled | Approved window exists. |
| Go/No-Go | Final pre-run checklist. |
| Running | SOC-controlled execution active. |
| Stopping | Kill switch/normal stop in progress. |
| Completed | Execution ended. |
| Report Published | Post-test report available. |
| Rejected | SOC rejected request with reason. |
| Cancelled | Customer/SOC cancelled before execution. |

## Implementation status (developer validation)

| Area | Status |
|---|---|
| Customer intake API | **Developer validation (SOC-009)** — required intake enforced on `POST /v1/high-scale-requests` (`environment`, `business_criticality`, `requested_scenario_families`, `requested_limits`, `stop_criteria`, `abort_criteria`, plus window/contacts/provider/scope fields); stored on request record. Errors: `missing_high_scale_request_fields`, `invalid_requested_window`. Covered by `tests/integration/hardening.test.mjs`. |
| Customer intake UI | **Partial** — High-Scale form collects SOC-009 fields and submits metadata-only payload; per-type authorization pack upload helpers; displays `authorization_pack_status` when present. **Production blockers:** full staged customer workflow, durable document store, legal/offline signoff, browser accessibility matrix. |
| Authorization proof | **Developer validation (SOC-009)** — expanded required artifact types (business/legal approval, scope/rate plan, abort criteria, etc.); server computes `authorization_pack_status`; SOC `approve` gated on complete pack. **Production blockers:** real provider integration, durable document custody, staging/legal signoff. |
| Authorization templates | **Developer validation** — tested catalog plus markdown pack cover required artifact types and proof fields. **Production blockers:** legal review, retained signed templates, durable custody, staging walkthrough. |
| SOC execution | **SOC-only** — approve/schedule/start/stop/close remain `/internal/soc/*`; unchanged by intake slice. |

## Completion criteria

High-scale workflow is complete when no execution path exists unless all gates are passed, `authorization_pack_status` is enforced, and the SOC console is the only place that can start the run.
