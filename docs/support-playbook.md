# Support playbook

Customer and operator guidance for **production** incidents and **developer validation** troubleshooting. Fill on-call contacts, SLAs, and escalation paths before GA ([`docs/release-checklist.md`](release-checklist.md)).

## Support readiness evidence (metadata-only)

Before GA, attach **metadata-only** support/on-call readiness evidence for release review. Do not paste raw tickets, log excerpts, customer payloads, attachments, tokens, or credentials into evidence JSON.

**Operator validator:** `node scripts/support-readiness-evidence.mjs --input evidence.json [--out manifest.json] [--validate-only]`

| Section | Required metadata | Notes |
|---|---|---|
| `on_call_rotation` | `rotation_name`, `owner`, `schedule_reference` | Named rotation and primary owner; use pager/schedule URIs, not personal secrets |
| `escalation_contacts` | Array of `role`, `contact_reference` | Support, engineering, and SOC paths as references only |
| `sla_policy` | `policy_reference`, `severity_tiers[]` with `severity` and `response_minutes` | Customer SLA policy linked by reference; tiers must cover production severities |
| `incident_tabletop` | `tabletop_id`, `conducted_at`, `scenario_reference`, `owner`, `evidence_uri` | Rehearsal of escalation/SOC handoff; owner is the incident commander or delegate |
| `soc_escalation_path` | `path_reference`, `severity_routes[]` | Maps severities (e.g. S1/S2) to SOC escalation references |
| `customer_comms_templates` | `template_id`, `purpose`, `reference_uri` per template | Approved notice/resolution templates by URI, not email bodies |
| `support_signoff` | `signoff_owner`, `signed_at`, `signoff_reference` | Support operations lead signoff that rotation, SLA, tabletop, and comms are staffed |

The CLI rejects forbidden fields (`ticket`, `logs`, `attachments`, `customer_payload`, `token`, `credential`, raw `*_log` / `raw_*` keys, and contact strings that embed passwords or API keys). It writes a **redacted manifest** and fails when rotation owner, SLA policy, tabletop owner, or support signoff is missing.

Store immutable custody copies of schedules, tabletop recordings, and signed SLA policy outside the repo; the manifest is an index, not the source of truth.

## Customer and operator UI (Settings)

The **Settings** page includes a separate **Support & on-call readiness** panel (`renderSupportReadinessPanel` in `apps/web/ui-helpers.js`) that is distinct from the production **release evidence** ledger view and export custody previews.

| UI surface | What it shows | What it does **not** imply |
|---|---|---|
| Support readiness panel | SLA policy **reference**, escalation path **references**, SOC escalation route references, kill-switch state from `/v1/state`, and optional `support_readiness` release-evidence summary fields | Staffed 24/7 production on-call, personal phone numbers, email addresses, or raw tickets/logs |
| Release evidence panel | Accepted metadata-only evidence kinds and custody URI previews | Production readiness complete (see release-checklist gates) |

Default developer-validation copy states that production support is **not staffed** until named rotation, SLA policy, tabletop rehearsal, and support signoff evidence are recorded and accepted via `POST /v1/production-release-evidence`.

## Severity and escalation (production)

| Severity | Examples | Action |
|---|---|---|
| S1 | Active unauthorized high-scale traffic, credential compromise, cross-tenant data exposure | SOC kill switch; revoke tokens; page on-call; preserve audit log |
| S2 | Probe fleet misconfiguration, agent mass offline, failed backups | On-call engineer; customer comms per SLA |
| S3 | Single-tenant check failures, report export errors | Support queue; runbook section below |
| S4 | UX/docs issues | Normal ticket |

**Do not mark SOC/high-scale incidents resolved** without evidence: adapter stopped, audit timeline, and customer notification per contract.

---

## Developer validation troubleshooting

Use when running locally or on a trusted sales-engineering host — not production.

### Agent authentication failure (401)

**Symptoms:** Heartbeat, jobs, or observations return `401` / `agent.auth_denied` in audit log.

**Checks:**

1. Use the **agent credential** (`agc_v1.…` from registration; format `agc_v1.<tenantB64>.<agentIdB64>.<random>`) from `POST /v1/agents/register`, not the bootstrap `ast_…` token. Legacy opaque `agc_…` credentials still work in the dev JSON store.
2. Header must be `Authorization: Bearer <credential>`.
3. `x-tenant-id` on agent calls should match the token’s tenant (default `ten_demo` in validation seed).
4. Re-register if credential was lost; bootstrap token may be exhausted — create a new one in Settings.

### Bootstrap token replay (401 on second register)

**Symptoms:** Second agent install with same bootstrap secret fails.

**Cause:** `max_registrations` enforced (often `1` in validation environments).

**Fix:** Create a new bootstrap token; revoke old token if compromised.

### Misplaced or missing agent observation

**Symptoms:** Verdict `protected` with `agent_no_observation` event, or `inconclusive` correlation.

**Checks:**

1. Agent online (`POST …/heartbeat`) before or during run.
2. Agent acked the observation job from `GET …/jobs`.
3. Observation body includes correct `test_run_id`, `target_id`, and `nonce_hash` from the run response.
4. Placement: agent must observe the declared target path per [`docs/agent/06-placement-guide.md`](agent/06-placement-guide.md) — automatic placement discovery is out of scope.

### SOC authorization incomplete (409 on approve/start)

**Symptoms:** `authorization_pack_incomplete`, `outside_schedule_window`, or `scope_hash_mismatch`.

**Fixes:**

1. Upload and SOC-**accept** all required artifact types (see `REQUIRED_ARTIFACT_TYPES` in `highScale.mjs`).
2. Schedule a window that includes **now** before `start` (developer validation).
3. Do not add targets to the group after approval without re-approval (scope hash changes).

### Customer cannot use SOC console

**Symptoms:** 403 on `/internal/soc/*`.

**Expected:** Only `soc` and `owner` roles. Engineers submit requests and artifacts only.

**Validation fix:** Switch UI role to `soc` (developer validation headers only).

### Safety-check failure in CI

**Symptoms:** `make verify` fails at `safety-check`.

**Cause:** Forbidden patterns (attack tooling strings, cloud SDK imports) in `src`, `agents`, `apps/web`, or `scripts`.

**Fix:** Remove or refactor the matching code; do not disable the scanner on release branches.

### Report export shows `[REDACTED]`

**Expected** when content contained token-like strings. If legitimate data is over-redacted, open a product ticket — do not disable redaction in production.

### Unauthorized high-scale start (production)

**Expected:** Customer API cannot start adapters. Investigate SOC role misuse, compromised SOC accounts, or adapter misconfiguration — not customer self-service APIs.

Related: [`docs/operator-local-runbook.md`](operator-local-runbook.md), [`docs/security/local-security-review.md`](security/local-security-review.md).