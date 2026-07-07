# CRUD operations backlog — portal revamp 2026-07

**Companion to** [`14-portal-revamp-2026-07.md`](14-portal-revamp-2026-07.md). Every gap here must be built in the React port even though the OD prototype does not demonstrate it.

The prototype is a **read + verify + gate** demo. It intentionally omits most create / edit / delete flows because the point was to nail the IA and the interaction contracts. The real portal must fill every gap below.

## 0. Baseline rule

Every mutation follows the same three rules regardless of surface:

1. **Confirmation for destructive actions.** Delete, archive, revoke, reject, force-stop, kill-switch, and rotate operations show a confirm modal that (a) names the object being changed, (b) lists the blast radius (linked runs, findings, dependent target groups), and (c) requires typing the object's id or name for hard-destructive ops (delete tenant, delete target group with active runs).
2. **Optimistic UI is not allowed for destructive or audit-writing actions.** Show a `pending` state, block re-submission, and only reflect success after the API responds with the audit-chain entry id.
3. **Every mutation writes an audit entry.** Backend audit chain is authoritative (`src/audit.mjs`); the UI must display the returned entry id in the toast confirmation for the auditor's benefit.

## 1. Target scope surfaces

### 1.1 Target groups

Backend covers everything already. Gaps are UI-only.

| Op | Route | Payload | Notes |
|---|---|---|---|
| Create | `POST /v1/target-groups` | `{ name, environment, criticality, description, safe_test_policy }` | Wizard-style modal from `#target-groups` page-head. |
| Rename | `PATCH /v1/target-groups/:id` | `{ name, description }` | Inline edit on `target-group-detail` header. |
| Change criticality | `PATCH /v1/target-groups/:id` | `{ criticality: 'critical' \| 'high' \| 'medium' }` | Confirmation required (affects readiness weighting). |
| Change validation mode | `PATCH /v1/target-groups/:id` | `{ validation_mode: 'agent_assisted' \| 'external_only' }` | Toggle on target-group-detail settings tab. |
| **Archive** | `DELETE /v1/target-groups/:id` | `{ confirm: '<group-name>' }` in body | **Blocked** with `409 target_group_active_run` when an active run exists — surface the block reason with a link to the offending run. |
| Restore archived | `POST /v1/target-groups/:id/restore` | — | New action on an "Archived" filter in the list. Backend endpoint is a small addition to `src/services/targetGroups.mjs`. |

### 1.2 Targets

Same pattern; already partially exposed on the current React target-group-detail.

| Op | Route | Payload | Notes |
|---|---|---|---|
| Create manually | `POST /v1/target-groups/:id/targets` | `{ kind: 'fqdn' \| 'tcp' \| 'url' \| 'dns_zone', value, expected_behavior, agent_binding? }` | Format validation only. No inventory discovery. |
| Import from provider | `POST /v1/target-groups/:id/targets` (bulk) | `{ targets: [...], source: 'cloudflare' \| 'route53' \| ... }` | See prototype §7.3 (provider inventory picker). New rows start `verify-chip = dns_pending` / `awaiting_heartbeat`. |
| Import via CSV | `POST /v1/target-groups/:id/targets:csv` | multipart CSV | Present on the current build but not the prototype — keep it. |
| Edit | `PATCH /v1/target-groups/:id/targets/:targetId` | `{ expected_behavior, agent_binding, kind, value }` | Confirmation required when changing kind or value (invalidates prior verification). |
| **Delete** | `DELETE /v1/target-groups/:id/targets/:targetId` | — | **Blocked** when the target has active runs or open findings unless `force=true` + confirm modal. |
| Verify (issue proof) | `POST /v1/target-groups/:id/dns-ownership/issue` (fqdn) OR agent-binding correlation (tcp) | — | Row-level Verify button. State machine: `unverified` → `pending` → `dns_verified` / `agent_verified`. |
| User-confirm | `POST /v1/target-groups/:id/targets/:targetId:confirm` | `{ signer, date }` | Elevates chip to `user_confirmed`. Requires LOA. |

### 1.3 Environments

Present in the current React build (`EnvironmentsPage`). Add:

| Op | Route | Notes |
|---|---|---|
| Rename | `PATCH /v1/environments/:id` | Inline edit. |
| Delete | `DELETE /v1/environments/:id` | Blocked when any target group references it. |

## 2. Agents

The prototype demos install and heartbeat verification but not the fleet mutations. Backend has all of these; UI just needs to wire them.

| Op | Route | Notes |
|---|---|---|
| Create bootstrap token | `POST /v1/bootstrap-tokens` | Already on `#agents` install tab. Add TTL selector and a one-time-show pattern (never redisplay a token). |
| **Revoke bootstrap token** | `POST /v1/bootstrap-tokens/:id/revoke` | Confirmation required. |
| Revoke agent | `POST /v1/agents/:id/revoke` | Already partially wired. Confirm modal that lists in-flight jobs. |
| Delete agent record (post-revoke) | `DELETE /v1/agents/:id` | Optional cleanup — only after revoke. |
| Update trust key (add / revoke) | `POST /v1/agent-update-trust-keys`, `POST …/:id/revoke` | On the Upgrades tab. |
| Rollback agent release | `POST /v1/agent-updates/:id/rollback` | On the Upgrades tab. |
| Release create ceremony | `POST /v1/agent-updates` | **Operator boundary** — keep out of customer UI. Documented in [Feature coverage matrix FM-AGENT](../feature-ui-coverage-matrix.md). |

## 3. Test policies + settings

### 3.1 Test policies

| Op | Route | Notes |
|---|---|---|
| Create | `POST /v1/test-policies` | Multi-select target-group dropdown per prototype §7.5. |
| Edit | `PATCH /v1/test-policies/:id` | Cadence, expected verdict, safe windows. |
| Pause / resume | `PATCH /v1/test-policies/:id` `{ paused: true \| false }` | Row action. |
| **Delete** | `DELETE /v1/test-policies/:id` | Blocked when scheduled runs are queued. |

### 3.2 Settings — retention

**Currently broken:** the Data retention inputs on `#settings` are read-only visual with hardcoded values. Wire them:

| Op | Route | Notes |
|---|---|---|
| Save retention | `PATCH /v1/tenants/current` `{ privacy_settings: { evidence_retention_days, audit_retention_days, ... } }` | Backend is `src/services/privacyRetention.mjs`. Add form validation (min / max per plan tier). |

### 3.3 Settings — secrets vault

| Op | Route | Notes |
|---|---|---|
| Create secret | `POST /v1/secrets` | One-time-show pattern. Referenced from Integrations connector forms. |
| Rotate | `POST /v1/secrets/:id/rotate` | One-time-show for the new value. |
| Revoke | `POST /v1/secrets/:id/revoke` | Confirmation required. |
| List | `GET /v1/secrets` | Metadata only — never plaintext. |

### 3.4 Settings — API keys / service accounts

| Op | Route | Notes |
|---|---|---|
| Create service account | `POST /v1/service-accounts` `{ scopes, name }` | One-time-show pattern for the addressed `svc_v1.…` token. |
| Rotate | `POST /v1/service-accounts/:id/rotate` | One-time-show. |
| Revoke | `POST /v1/service-accounts/:id/revoke` | Confirmation required. |

## 4. Findings

The prototype demos triage but not archival.

| Op | Route | Notes |
|---|---|---|
| Assign owner | `PATCH /v1/findings/:id` `{ owner }` | Already wired. |
| Change state | `PATCH /v1/findings/:id` `{ state: 'accepted' \| 'closed' }` | Already wired; needs an `Undo` toast for 10s. |
| Add note | `PATCH /v1/findings/:id` `{ notes }` | Append-only ledger — never overwrite prior notes. |
| Retest | `POST /v1/test-runs` `{ target_id, check_id }` | Row action + finding-detail action. |
| Export | `POST /v1/findings/:id/export` | Custody-sealed JSON. |
| Mark remediation delivered | `POST /v1/waf/action-items/:id/deliver` | See prototype §7.6 + `src/lib/remediationDelivery.mjs`. |
| **Delete** | Not offered | Findings are audit records — never deletable. Accept-risk + close are the terminal states. |

## 5. Runs + SOC-gated queue

| Op | Route | Notes |
|---|---|---|
| Start safe run | `POST /v1/test-runs` | Existing. Prototype adds a locked-Run button on unverified targets. |
| **Cancel run** | `POST /v1/test-runs/:id/cancel` | Confirmation required. Immediate kill of associated probe jobs. |
| Finalize run | `POST /v1/test-runs/:id/finalize` | Manual finalize for edge cases (already wired). |
| Request SOC-gated run | `POST /v1/high-scale-requests` `{ target_group_id, policy_id, peak_rps, window, business_impact }` | New page-head action on `#runs`. |
| Upload authorization pack artifact | `POST /v1/high-scale-requests/:id/artifacts` (metadata-only) | Wizard-style flow for LOA / DPA / provider approval / runbook. Currently there is no wizard — see `docs/templates/high-scale-authorization-pack.md` for the 4 templates. |
| Withdraw request (before SOC review) | `POST /v1/high-scale-requests/:id/withdraw` | Customer can cancel their own submission before SOC picks it up. Backend endpoint to add. |

## 6. Governance

### 6.1 Notifications — create rule form

Missing entirely from current React `#notifications` page. Backend is `src/services/notifications.mjs`; contract is validated.

| Op | Route | Notes |
|---|---|---|
| Create rule | `POST /v1/notifications` `{ kind, filters, delivery_mode, destination }` | Wizard: pick rule kind (finding.opened / run.finalized / high_scale.state_changed) → filters (severity, target group, owner) → delivery mode (webhook / email / slack / teams) → destination + secret ref. |
| Edit rule | `PATCH /v1/notifications/:id` | — |
| Pause / resume rule | `PATCH /v1/notifications/:id` `{ paused }` | — |
| **Delete rule** | `DELETE /v1/notifications/:id` | Confirmation. |
| Retry DLQ | `POST /v1/notifications/dlq/redrive` | Already exists as an action; needs a per-delivery-attempt view. |
| Process due retries | `POST /v1/notifications/retries/process` | Ops action; keep behind admin RBAC. |
| Manage provider credentials | `POST /v1/notification-provider-credentials` | Adds Slack webhook / PagerDuty routing key / SMTP. |

### 6.2 Integrations — connector lifecycle

Present on the current build; add:

| Op | Route | Notes |
|---|---|---|
| Enable connector | `POST /v1/connectors` `{ provider, credentials_ref, scope }` | Points at a secret from the vault. Never accept plaintext keys. |
| Validate | `POST /v1/connectors/:id/validate` | Test the credentials + scope. |
| **Poll now** | `POST /v1/connectors/:id/poll` | Manual snapshot. Show last-poll timestamp and error count per connector row. |
| Manual snapshot ingest | `POST /v1/connectors/:id/snapshots` | Import a JSON snapshot when the connector-poll runner is disabled. |
| Disable | `PATCH /v1/connectors/:id` `{ enabled: false }` | Stops the connector-poll runner from picking it up. |
| Delete | `DELETE /v1/connectors/:id` | Confirmation. Blocked when snapshots exist unless `force=true`. |

### 6.3 Reports

| Op | Route | Notes |
|---|---|---|
| Generate | `POST /v1/reports` `{ kind, scope, format }` | Existing. |
| Export | `GET /v1/reports/:id/export?format=json\|markdown\|html` | PDF is an intentional boundary. |
| Verify custody | `POST /v1/custody/verify` `{ report_id }` | Existing. |
| Delete | `DELETE /v1/reports/:id` | Optional — reports are audit records; consider archive-only instead. |

### 6.4 Audit log

Read-only. No mutations. Add:

- Filter form (currently missing on the current build's audit tab): actor / action / resource / from / to.
- Custody-chain-only toggle.
- Per-entry drill-down showing prev_hash / entry_hash for tamper-evidence display.

## 7. Staff surfaces

### 7.1 Admin console — Signup queue tab

Backend exists (`GET /internal/admin/signup-requests`, approve/reject); the current React admin page shows only the tenant directory.

| Op | Route | Notes |
|---|---|---|
| List queue | `GET /internal/admin/signup-requests?state=pending` | Signup queue tab. |
| Approve | `POST /internal/admin/signup-requests/:id/approve` `{ owner_email, plan, region }` | Provisions tenant + env + owner + default subscription + entitlements. |
| Reject | `POST /internal/admin/signup-requests/:id/reject` `{ reason }` | Audit-only. |
| Request more info | `POST /internal/admin/signup-requests/:id/hold` `{ note }` | Optional — backend endpoint to add. |

### 7.2 Admin console — Approval requests decisions

Currently only `approval-grant` is wired.

| Op | Route | Notes |
|---|---|---|
| Approve / Reject / Hold | `POST /internal/admin/approval-requests/:id/decision` `{ decision, reason }` | Add all three decisions with a decision-reason field. |

### 7.3 Tenant detail — Users tab

Missing from current React `TenantDetailView`. Backend exists.

| Op | Route | Notes |
|---|---|---|
| List users | `GET /internal/admin/tenants/:id/users` | Add tab. |
| Resend invite | `POST /internal/admin/tenants/:id/users/:userId/resend-invite` | — |
| Disable user | `POST /internal/admin/tenants/:id/users/:userId/disable` | Confirmation. |
| Assign support owner | `PATCH /internal/admin/tenants/:id` `{ support_owner }` | Header field. |

### 7.4 Tenant detail — Lifecycle

| Op | Route | Notes |
|---|---|---|
| Activate / Suspend | `POST /internal/admin/tenants/:id/activate` / `/suspend` | Existing but partially wired — surface the confirmation modal on suspend. |
| Grant entitlement | `POST /internal/admin/tenants/:id/entitlements` `{ feature, until }` | Existing. |
| Revoke entitlement | `DELETE /internal/admin/tenants/:id/entitlements/:featureId` | Add. |

### 7.5 SOC console (staff-only)

| Op | Route | Notes |
|---|---|---|
| Accept authorization pack | `POST /internal/soc/high-scale/:id/accept-pack` | Existing. |
| Reject pack | `POST /internal/soc/high-scale/:id/reject-pack` | Existing. |
| Schedule run | `POST /internal/soc/high-scale/:id/schedule` `{ window_start, window_end }` | Existing. |
| Execute | `POST /internal/soc/high-scale/:id/execute` | Governed dry-run → live. |
| **Global stop / kill switch** | `POST /internal/soc/high-scale/:id/stop` | Big red button. Confirmation required. |
| Close request | `POST /internal/soc/high-scale/:id/close` | With post-test report attached. |
| Break-glass override | `POST /internal/soc/break-glass` | `src/services/breakGlass.mjs`. Emergency override for SOC-gated ops. Zero-latency; audit-heavy. |

## 8. Universal patterns

### 8.1 One-time-show for secrets

For every endpoint that mints a new secret (`svc_v1.…`, `ast_v1.…`, provider credentials, encrypted webhook signing keys), the UI must:

1. Show the raw value in a copyable `<code>` block **exactly once**, immediately after the mint call resolves.
2. Persist a `"Copied · did you save it?"` acknowledgement that the user must click to close the modal.
3. Never re-render the raw value on subsequent list views — only the last 4 chars + a redacted mask.

### 8.2 Confirm modals

Every destructive action shows a `.modal-confirm` with:

- Verb + object in the title (`Delete target group edge-checkout`).
- A blast-radius list (linked runs, findings, agents).
- A cancel button + a destructive button that turns from `--danger` background to a filled `--danger` pill only after typing the id for hard-destructive ops.
- An `Are you sure?` phrase in the description — this is not filler; the prototype's anti-slop rules make an exception for confirm modals because clarity here saves data.

### 8.3 Bulk operations

At minimum, findings + notifications + targets need bulk actions:

- Multi-select via row checkbox column.
- Sticky action bar at the panel-foot when ≥1 row is selected.
- Bulk actions: assign owner, change state (findings); pause / resume / delete (notifications); import (provider inventory picker — already handled); delete + verify (targets).
- Every bulk action confirms with a count summary and streams progress row-by-row.

### 8.4 Undo toasts

Non-destructive state changes (finding state, notification pause, target-group rename) show an `Undo · 10s` toast that calls the inverse endpoint if clicked in time. Destructive actions never offer Undo — they require the confirm modal instead.

### 8.5 Empty states for CRUD surfaces

Every list view must ship a friendly empty state with a Create CTA. See `renderFriendlyEmptyState` in the current React `page-components.tsx`. Do not regress this.

## 9. Testing

Every CRUD op above must have:

1. A unit test in `tests/unit/` covering the service layer.
2. An integration test in `tests/integration/` covering the API contract.
3. A React portal browser test in `scripts/pp-XX-*.mjs` covering the UI flow.

Follow the existing PP-XX numbering (see `scripts/pp-10-runs-qa.mjs`, `scripts/pp-11-findings-qa.mjs`, etc.).

## 10. Explicit "not doing" list

To keep the revamp scope honest, these are explicitly **out of scope** for the 2026-07 revamp and remain external ops or intentional boundaries:

- Enterprise IdP per-customer claim mapping (external).
- PDF report export (backend supports json / md / html only — documented boundary).
- Release evidence customer-facing page (deleted — auditor read-access reachable via API only).
- SOC execution APIs in the customer bundle (staff-only, forever).
- Automatic IP-inventory discovery (product rule; never).
- Agent update release creation ceremony in customer UI (operator-only via CLI).
- Real-time host operational log tail per agent (no host log API; documented boundary).
- Multi-tenant SOC queue in a single customer's `#soc` view (staff-only surface).
