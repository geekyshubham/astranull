# Settings Page

## Organization tab

Fields:

- organization name,
- environments,
- primary timezone,
- data residency preference,
- support contacts (reference URIs or role labels only in UI — no personal phone/email in product surfaces),
- emergency contacts (same metadata-only rule).

## Support & on-call readiness (Settings section)

Separate from the **Production release evidence** compact panel and the full **Release Evidence** nav route. Surfaces metadata references only:

| Block | Content |
|---|---|
| SLA policy reference | `policy://…` URI and severity tier response targets (preview table) |
| Escalation path reference | `runbook://…` URI and role → `escalation://…` contact references |
| SOC escalation | SOC path reference, kill-switch state from dashboard state, S1/S2 route references |
| Readiness status | Whether `support_readiness` release evidence is attached; playbook and validator CLI references |

Banner copy must state that **production on-call is not staffed** in developer validation and that indexed evidence does not replace release-checklist signoff.

Implementation: `buildSupportReadinessPreview` + `renderSupportReadinessPanel` in `apps/web/ui-helpers.js`; wired from `viewSettings()` in `apps/web/app.js`.

## Users & Roles tab

Capabilities:

- invite user,
- assign role,
- remove user,
- require MFA,
- map SSO groups to roles,
- view last login.

## API Keys tab

AstraNull has multiple credential types.

| Credential | Purpose | Created by | Expiry |
|---|---|---|---|
| Bootstrap token | Install/register agent | Owner/admin/engineer | Short-lived |
| Agent identity | Agent runtime auth | Platform after registration | Rotated |
| Service API token | Automation/API access | Owner/admin | Configurable |
| Webhook secret | Sign outbound webhooks | Platform/admin | Rotatable |

### Bootstrap token form

| Field | Description |
|---|---|
| Environment | Prod/staging/lab. |
| Target group | Optional default binding. |
| Expiry | 15 min, 1 hour, 24 hours, custom. |
| Max registrations | Number of agents that can register. |
| Allowed source CIDRs | Optional. |
| Observation modes | Packet/log/canary/mirror. |
| Tags | Region, app, team, cloud, deployment. |
| Notes | Why token was created. |

## Notifications tab

Rules:

- critical finding created,
- agent offline,
- high-scale request status changed,
- report ready,
- safe run failed,
- token created/revoked.

## Production release evidence (developer-validation)

Compact panel on Settings and full **Release Evidence** nav page (`#release-evidence`):

- Lists accepted production release evidence kinds from `GET /v1/production-release-evidence` (RBAC: `release_evidence:read`).
- Shows kind, status, validation summary, release id, created time, and a **custody URI preview** only (no raw evidence bodies).
- Coverage summary compares recorded kinds to the contract in `src/contracts/productionReleaseEvidence.mjs`.
- Prominent gate copy: attached metadata does **not** mean production readiness is complete while staging, legal, SOC, and security signoffs in `docs/release-checklist.md` remain open.

## Audit Log tab

Show immutable records for:

- login,
- user/role change,
- token creation/revocation,
- agent registration/revocation,
- target group changes,
- test execution,
- SOC approval,
- high-scale execution,
- report export.

## Completion criteria

Settings are complete when security-sensitive operations are controlled, audited, reversible where possible, and understandable.
