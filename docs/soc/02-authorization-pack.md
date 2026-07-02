# Authorization Pack

## Purpose

The authorization pack proves that a high-scale test is allowed. **SOC-009** ties every required proof artifact and intake field to `authorization_pack_status` before SOC can approve, schedule, or start governed execution.

## Required intake metadata (customer request)

Submitted with `POST /v1/high-scale-requests` (metadata only — not traffic controls):

| Field | Required | Notes |
|---|---:|---|
| `environment` | Yes | Production, staging, or lab. |
| `business_criticality` | Yes | Risk review input. |
| `requested_scenario_families` | Yes | Declared vector/scenario families (metadata). |
| `requested_limits.max_rate` | Yes | Safe declared rate cap (metadata only). |
| `requested_limits.max_duration_minutes` | Yes | Safe declared duration cap (metadata only). |
| `stop_criteria` | Yes | Written pause/stop thresholds. |
| `abort_criteria` | Yes | Immediate abort conditions. |
| Objective, window, contacts, provider context, scope confirmation | Yes | Unchanged from intake contract. |

## Required artifacts

| Artifact type | Required when | Notes |
|---|---|---|
| `customer_authorization_letter` | Always | Target scope, window, approver. |
| `target_ownership_confirmation` | Always | Customer owns/controls targets. |
| `business_approval` | Always | Business owner sign-off metadata. |
| `legal_approval` | Enterprise / prod | Legal/security approval when policy requires. |
| `emergency_contacts` | Always | Customer and escalation paths. |
| `stop_criteria` | Always | Written stop thresholds (artifact + request field). |
| `test_plan` | Always | Scenario families, constraints, monitoring (metadata). |
| `scope_and_rate_plan` | Always | Approved scope, rates, duration caps (metadata). |
| `abort_criteria` | Always | Abort conditions and escalation. |
| `provider_approval` | When provider/CDN/cloud requires it | Checklist-bound; see below. |
| Maintenance/change approval | Production tests | Customer change ticket metadata when applicable. |

The source-of-truth template catalog is `src/contracts/authorizationTemplates.mjs`. It maps each required artifact type to metadata fields, required sections, retention classification, legal-review posture, and the markdown pack at [`../templates/high-scale-authorization-pack.md`](../templates/high-scale-authorization-pack.md). Unit tests fail if a required artifact type or enforced proof field lacks template coverage.

## Artifact metadata (upload body)

Customer upload API accepts metadata references — not binary attack tooling. Safe fields include:

| Field | Use |
|---|---|
| `approval_reference` | Ticket, case, or reference ID. |
| `approver` | Named approver role or ID (redacted on persist). |
| `valid_window` | Approved from/to ISO timestamps. |
| `approved_targets` | Scope covered. |
| `approved_scenario_families` | Vector families covered. |
| `max_rate` / `max_duration_minutes` | Declared caps in scope/rate plan artifacts. |
| `abort_criteria` | Abort text or reference. |
| `emergency_contacts` | Contact path metadata. |
| `reference_uri` | e.g. `metadata://ui/<type>/<request_id>` until durable document store lands. |

SOC reviews each artifact via `POST /internal/soc/high-scale/:id/artifacts/:artifactId/review`. **Production blockers:** durable document store/custody, staging/legal signoff, live provider integrations.

## Authorization pack status

Each high-scale request may expose `authorization_pack_status` (computed server-side):

| Field | Meaning |
|---|---|
| `status` (or `overall_status`) | `missing`, `partial`, `under_review`, `accepted`, `rejected`, `expired`. |
| `missing` / `missing_requirements` | Names of artifact types or intake fields still required. |

| Status | Meaning |
|---|---|
| Missing | Required artifacts or intake proof not satisfied. |
| Partial | Some artifacts uploaded but incomplete or pending review. |
| Under Review | SOC is validating uploaded proof. |
| Accepted | SOC accepted authorization; provider checklist satisfied when required. |
| Rejected | SOC rejected with reason. |
| Expired | Window or approval date expired. |

The High-Scale UI surfaces `authorization_pack_status` when present. SOC `approve` returns `409` `authorization_pack_incomplete` until status is acceptable and required artifact types are accepted.

## SOC approval gate

| Gate | Owner | Must be true |
|---|---|---|
| Intake gate | Platform | Required intake fields present and normalized. |
| Pack gate | SOC | `authorization_pack_status` acceptable; required artifact types `accepted`. |
| Provider gate | SOC/customer | Every required `provider_approval_checklist` item `accepted` and not expired. |
| Legal gate | SOC/legal | Customer and legal approvals validated when policy requires. |
| Safety gate | SOC | Stop/abort criteria, limits, contacts, and window recorded. |
| Go/no-go gate | SOC lead | Final sign-off before execution. |

## Provider approval checklist (metadata)

High-scale requests can carry a per-provider `provider_approval_checklist` derived at submit time from `provider_approvals`, `provider_context.providers`, and/or a single provider name on `provider_context`. When `requires_provider_approval` is true but no provider is named, SOC tracks a required `unspecified_provider` item. SOC-010 adds a metadata-only provider path catalog for AWS, Azure, GCP, Cloudflare, Akamai, other CDN/WAF providers, ISP/carrier paths, on-prem labs, approved partner labs, and generic providers.

| Checklist field | Meaning |
|---|---|
| `provider_name` | Provider label (redacted on persist). |
| `provider_key` / `approval_path` | Normalized provider and high-level path such as provider fire drill, partner adapter, manual coordination, or internal lab. |
| `status` | `missing`, `partial`, `pending_review`, `accepted`, `rejected`, or `expired` (window end in the past). |
| `approval_reference` | Ticket/case/reference metadata. |
| `valid_window` | Approved from/to; expired windows block SOC approve even if an artifact was accepted. |
| `approved_targets` / `approved_scenario_families` | Declared scope metadata. |
| `contact_path` | Escalation path (redacted). |
| `approved_limits` | Provider-approved intensity/duration labels. |
| `provider_specific_evidence` | Metadata-only evidence fields for the provider path. |
| `emergency_stop_path` | Provider or partner stop bridge. |
| `missing_fields` | Required provider fields still missing; any non-empty list keeps the item partial and blocks SOC approval. |
| `artifact_id` | Linked `provider_approval` artifact after upload. |

Uploading a `provider_approval` artifact binds metadata to the matching checklist row. SOC artifact review is the acceptance gate for each required provider, but an accepted artifact is still `partial` if provider-specific required fields are missing. **Production blockers:** live provider integrations (AWS/Azure/GCP/CDN APIs), staging approval evidence, and export/signoff for legal retention.

## Provider-specific tracking

AstraNull should not assume a universal provider process. Store provider approval as an artifact with metadata:

| Field | Description |
|---|---|
| Provider name | AWS, Azure, GCP, Cloudflare, Akamai, ISP, on-prem, etc. |
| Approval reference | Ticket/case/email/reference ID. |
| Valid from/to | Approved window. |
| Approved targets | Scope covered. |
| Approved scenarios | Vector families/intensity classes. |
| Contact path | Provider contact or escalation. |
| Attachment | Approval PDF/email/screenshot/export (production document store). |

The implementation stores provider-path metadata only. It does not call provider APIs, store provider credentials, or execute provider traffic.

## Provider approval evidence (SOC validation)

Before SOC schedules or starts a provider-gated high-scale test, operator tooling validates metadata-only provider approval evidence with:

`node scripts/provider-approval-evidence.mjs --input <evidence.json> [--out output/provider-approval-evidence.json] [--as-of <ISO>] [--validate-only]`

Input is a single JSON object (not binary attachments). Required SOC review fields:

| Field | Required | Notes |
|---|---:|---|
| `requested_scenario_families` | Yes | Declared vector families for the request; each must appear in provider-approved families. |
| `authorized_scope_hash` | Yes | Must match the computed target-group scope hash bound at SOC approve/schedule. |
| `soc_reviewer` | Yes | SOC reviewer user/role metadata (redacted on persist). |
| `legal_signoff.reference` | Yes | Legal/security signoff reference when policy requires provider-gated execution. |
| `legal_signoff.signed_at` | Yes | ISO timestamp for legal signoff metadata. |
| `custody_ids` | Yes | One or more document custody IDs for stored approval artifacts (metadata references only). |
| `provider_approval.*` | When provider gate applies | Provider-path fields from `src/contracts/providerApprovalPaths.mjs` (`approval_reference`, `valid_window`, `approved_targets`, `approved_scenario_families`, `contact_path`, `approved_limits`, `provider_specific_evidence`, `emergency_stop_path`). |

The validator rejects:

- missing provider-path or SOC review requirements (manifest lists `missing_requirements`),
- expired `valid_window` (`approval_expired`),
- credential/secret/token/password fields,
- target IP inventory dumps (`target_ip_inventory`, `target_ips`, `ip_inventory`, `ip_list`),
- packet/log/body/header/payload blobs and any `raw_*` keys.

On failure it still writes a **redacted metadata-only manifest** (no secrets, no IP lists, no raw blobs) including `validation.missing_requirements` and `validation.forbidden_fields`. Production scheduling still requires durable document custody, legal retention, and live provider coordination — this CLI is developer-validation evidence only.

## Implementation status (developer validation)

| Area | Status |
|---|---|
| Intake + pack types | **Developer validation (SOC-009)** — backend enforces required intake (including request-level `abort_criteria`) and expanded artifact types; UI collects fields and exposes per-type metadata upload helpers; integration tests in `hardening.test.mjs`. |
| `authorization_pack_status` | **Developer validation** — computed server-side on create/artifact review; surfaced in UI when API returns it; gates SOC `approve` (`authorization_pack_incomplete` until pack accepted). |
| Authorization templates | **Developer validation** — tested catalog plus markdown pack cover every required artifact type and provider approval; not legal advice and not a substitute for customer/legal signoff. |
| Document custody | **Not production** — metadata `reference_uri` only; durable store and legal retention open. |
| Provider integrations | **Not production** — checklist metadata only. |

## Completion criteria

Authorization pack is complete when SOC can validate permission before execution, `authorization_pack_status` is authoritative, and auditors can later prove why the test was allowed.
