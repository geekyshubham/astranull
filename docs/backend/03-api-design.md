# API Design

## API principles

- Tenant ID is derived from auth context, not trusted from request body.
- All mutating actions create audit events.
- Bootstrap token secrets are returned once.
- High-scale execution APIs are internal/SOC-only.
- External customer APIs cannot start SOC-gated scenarios.
- Every list endpoint supports pagination and filtering.
- Public sign-up APIs accept only minimal account-request metadata and never provision privileged access directly.
- Internal management APIs are staff-only and must not accept customer tenant roles as authorization.

## Core endpoints

### Public entry and sign-up

| Method | Path | Purpose |
|---|---|---|
| GET | `/` | Public landing page. |
| GET | `/login` | Redirect to configured identity provider. |
| GET | `/signup` | Public sign-up intake page. |
| POST | `/v1/signup-requests` | Submit account request metadata for staff review or provisioning. |

### Target groups

| Method | Path | Purpose |
|---|---|---|
| GET | `/v1/target-groups` | List target groups. |
| POST | `/v1/target-groups` | Create target group. |
| GET | `/v1/target-groups/{id}` | Get detail. |
| PATCH | `/v1/target-groups/{id}` | Update metadata/settings. |
| DELETE | `/v1/target-groups/{id}` | Archive/delete target group. |
| POST | `/v1/target-groups/{id}/targets` | Add target. |
| POST | `/v1/target-groups/{id}/import` | CSV/API import declared targets. |

### Bootstrap tokens and agents

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/bootstrap-tokens` | Create one-time install token. |
| GET | `/v1/bootstrap-tokens` | List token metadata, never secrets. |
| POST | `/v1/bootstrap-tokens/{id}/revoke` | Revoke token. |
| POST | `/v1/agents/register` | Agent exchanges bootstrap token for identity. |
| POST | `/v1/agents/{id}/heartbeat` | Agent heartbeat. |
| POST | `/v1/agents/{id}/observations` | Agent observation upload. |
| GET | `/v1/agents` | List agents. |
| PATCH | `/v1/agents/{id}` | Update name/tags/binding. |
| POST | `/v1/agents/{id}/revoke` | Revoke agent identity. |

### Checks and runs

| Method | Path | Purpose |
|---|---|---|
| GET | `/v1/checks` | List check catalog. |
| POST | `/v1/test-runs` | Start safe/controlled run. |
| GET | `/v1/test-runs` | List runs. |
| GET | `/v1/test-runs/{id}` | Run detail. |
| POST | `/v1/test-runs/{id}/cancel` | Cancel safe run. |
| GET | `/v1/test-runs/{id}/events` | Timeline/evidence events. |

### Findings and reports

| Method | Path | Purpose |
|---|---|---|
| GET | `/v1/findings` | List findings. |
| GET | `/v1/findings/{id}` | Finding detail. |
| PATCH | `/v1/findings/{id}` | Assign/status/notes. |
| POST | `/v1/findings/{id}/accept-risk` | Risk acceptance. |
| POST | `/v1/reports` | Generate report. |
| GET | `/v1/reports/{id}` | Report status/download. |

### High-scale/SOC

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/high-scale-requests` | Customer requests high-scale validation. |
| GET | `/v1/high-scale-requests` | Customer-visible request list. |
| PATCH | `/v1/high-scale-requests/{id}` | Customer updates draft/submitted request. |
| POST | `/internal/soc/high-scale/{id}/approve` | SOC-only approval. |
| POST | `/internal/soc/high-scale/{id}/schedule` | SOC-only schedule. |
| POST | `/internal/soc/high-scale/{id}/start` | SOC-only start after gates. |
| POST | `/internal/soc/high-scale/{id}/stop` | SOC-only kill switch. |
| POST | `/internal/soc/high-scale/{id}/close` | SOC-only closure. |

### Internal management

All routes in this group require a staff principal from the staff identity provider. Customer principals, including customer `owner` and `admin`, must receive `403` even when they know the route.

| Method | Path | Purpose |
|---|---|---|
| GET | `/internal/admin/signup-requests` | Staff queue for account requests. |
| POST | `/internal/admin/signup-requests/{id}/approve` | Approve request and optionally provision tenant. |
| POST | `/internal/admin/signup-requests/{id}/reject` | Reject request with staff reason and customer-safe reason. |
| GET | `/internal/admin/tenants` | Search customer tenants. |
| GET | `/internal/admin/tenants/{tenantId}` | Tenant operations detail. |
| PATCH | `/internal/admin/tenants/{tenantId}` | Update lifecycle, metadata, support owner, or status. |
| GET | `/internal/admin/tenants/{tenantId}/subscription` | Read subscription and entitlement state. |
| PATCH | `/internal/admin/tenants/{tenantId}/subscription` | Update plan, billing status metadata, and effective dates. |
| POST | `/internal/admin/tenants/{tenantId}/entitlements` | Grant, update, or revoke feature entitlements. |
| GET | `/internal/admin/approval-requests` | Unified staff approval queue. |
| POST | `/internal/admin/approval-requests/{id}/decision` | Approve/reject with reason and evidence refs. |
| GET | `/internal/admin/audit-log` | Search staff/internal audit events. |

## API key generation flow

1. User opens Settings → API Keys → Create Bootstrap Token.
2. User selects environment, target group, expiry, max registrations, allowed modes.
3. Backend stores token hash and returns raw token once.
4. UI shows install commands using the token.
5. Agent registers with token.
6. Backend invalidates or decrements token usage.
7. Audit log records creation and registration.

## Completion criteria

API design is complete when frontend, agent, probe workers, and SOC console can perform all flows without bypassing permissions or safety gates.
