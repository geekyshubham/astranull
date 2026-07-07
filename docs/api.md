# AstraNull API reference (production contract)

This document defines the **production API contract** for AstraNull and records **current implementation status** in developer validation mode. Route shapes and permissions below are the target unless marked as a production release blocker.

## Authentication

| Mode | Use | Production |
|---|---|---|
| **OIDC JWT (`oidc-jwt`)** | `Authorization: Bearer <RS256 compact JWT>` from enterprise IdP | **Default human auth** when `NODE_ENV=production` (or set `ASTRANULL_AUTH_MODE=oidc-jwt`). Verifier requires RS256, `kid`, and RSA signing JWKS keys (`kty`, optional `use`, optional `alg`); JWKS fetch uses a bounded timeout (`ASTRANULL_OIDC_JWKS_FETCH_TIMEOUT_MS`) and **does not follow HTTP redirects**; production startup requires **HTTPS** `ASTRANULL_OIDC_JWKS_URL`. Validates issuer, audience, strict numeric `exp`, optional numeric `nbf`, and maps tenant/user/role claims to AstraNull RBAC. **Not** valid on agent or probe-worker routes. |
| **Signed session (`signed-session`)** | HMAC bearer token (`asn1.<payload>.<sig>`) minted with `ASTRANULL_SESSION_SECRET` | **Non-production only** — local tests and operator flows; refused at startup when `NODE_ENV=production`. Not a production IdP. |
| **Bearer agent credential + production gateway mTLS fingerprint** | `POST /v1/agents/register` → `agc_v1.…` (`agc_v1.<tenantB64>.<agentIdB64>.<random>`) on heartbeat, jobs, observations; legacy opaque `agc_…` still accepted in dev JSON store | **Required** — full credential verified against stored `credential_salt` / `credential_hash`; in production `ASTRANULL_AGENT_IDENTITY_MODE=gateway-mtls` requires a forwarded client certificate SHA-256 fingerprint matching the registered agent fingerprint |
| **Service account token** | `Authorization: Bearer svc_…` on `/v1/*` and `/internal/*` (not agent or probe-worker routes) | **Built-in automation boundary** — tenant-bound, revocable, scoped; secret shown once at create/rotate as `svc_v1.…` with embedded tenant/account id hints (salted hash of full secret stored; legacy opaque `svc_…` still accepted in dev store). Works independently of human auth mode (`oidc-jwt`, `signed-session`, `dev-headers`). Not a substitute for agent credentials or probe-worker HMAC. |
| **Developer validation headers (`dev-headers`)** | `x-tenant-id`, `x-user-id`, `x-role` for local UI and CI | **Forbidden in production** — refused at startup if `NODE_ENV=production`; see [`docs/release-checklist.md`](release-checklist.md) |

### Human auth environment (`oidc-jwt`)

| Variable | Required | Notes |
|---|---|---|
| `ASTRANULL_OIDC_ISSUER` | Yes | Expected JWT `iss`. |
| `ASTRANULL_OIDC_AUDIENCE` | Yes | Expected JWT `aud`. |
| `ASTRANULL_OIDC_JWKS_URL` | Yes | JWKS document URL for RS256 verification. Must use **HTTPS** when `NODE_ENV=production`. |
| `ASTRANULL_OIDC_TENANT_CLAIM` | No | Default `tenant_id`. |
| `ASTRANULL_OIDC_ROLE_CLAIM` | No | Default `role` (mapped to AstraNull RBAC). |
| `ASTRANULL_OIDC_USER_CLAIM` | No | Default `sub`. |
| `ASTRANULL_OIDC_JWKS_CACHE_TTL_MS` | No | Bounded JWKS cache TTL (default 300000 ms). |
| `ASTRANULL_OIDC_JWKS_FETCH_TIMEOUT_MS` | No | Bounded JWKS HTTP fetch timeout (default 5000 ms; min 1000, max 30000). Redirect responses are not followed. |

`resolveAuthMode()` defaults to `oidc-jwt` when `NODE_ENV=production`. `loadRuntimeConfig()` refuses both `dev-headers` and `signed-session` in production.

Agent calls use `Authorization: Bearer <agc_v1.…>` (or legacy `agc_…` in dev store) on agent-scoped routes. Newly issued credentials embed tenant and agent id lookup hints; verification still uses the full secret against stored salt/hash. Invalid addressed `agc_v1` bearer auth audits `agent.auth_denied` only when a matching `(tenant_id, agent_id)` agent row exists; nonexistent or mismatched hints return `401` without tenant-local audit. Unknown legacy opaque route agents return `401` without audit; invalid legacy opaque for an existing route agent still audits under the confirmed tenant. Production defaults `ASTRANULL_AGENT_IDENTITY_MODE` to `gateway-mtls` and refuses bearer-only mode; the gateway must forward the verified client certificate fingerprint in `x-client-cert-fingerprint`, `x-astranull-client-cert-fingerprint`, or `x-forwarded-client-cert-sha256`, and it must match the agent fingerprint captured at registration. Packaged agents default to HTTPS control-plane URLs (`ASTRANULL_API_URL`); localhost HTTP requires `--allow-insecure-localhost-api` or `ASTRANULL_ALLOW_INSECURE_LOCALHOST_API=1` (developer validation only). Packaged installs persist registration identity at `/var/lib/astranull/identity.json` (`0700` directory / `0600` file; override with `--identity` or `ASTRANULL_AGENT_IDENTITY`). Shipped generic Linux tarballs are validated to block server-side `src/*` imports (packaged source-isolation test). Automation uses `Authorization: Bearer <svc_…>` where human OIDC JWTs are not appropriate; effective access requires both the service account **role** and an explicit **scope** (or `*` for admin-only accounts).

Unless noted, responses are JSON. Errors use `{ "error": "<code>", "message"?: "…" }` with HTTP 4xx/5xx.

## Safety notes (all endpoints)

- No endpoint starts unmanaged DDoS traffic. Safe checks use bounded probes. `ASTRANULL_PROBE_MODE=simulation` (default outside production) runs metadata-only `SAFE_PROBE_SIMULATION` in-process for developer validation and CI only; startup **refuses** explicit `simulation` when `NODE_ENV=production`. Production defaults to `signed-worker` so external workers consume HMAC-signed jobs via `/internal/probe/*`. Deploying and operating the probe fleet remains a release blocker.
- High-scale **start** must invoke **governed** execution adapters only (SOC role, approved pack, schedule window). `ASTRANULL_HIGH_SCALE_ADAPTER_MODE` defaults to `governed-adapter` in production and `dry-run` outside production; `dry-run` is refused when `NODE_ENV=production`. Developer validation uses adapter dry-run metadata — **production release blocker**: partner/internal governed adapter.
- Event ingestion rejects `packet_payload` and `raw_packet`.
- Agent observation ingestion requires a matching **acked** `agent_job_id` (job poll/ack proof); rejects raw packet/log/header/body payload fields; stores **metadata only** after `redactObject`.
- Exports pass through `redactObject` (no `ast_` / `svc_` / `agc_` / full dotted `agc_v1…` tokens in output).
- Notifications record delivery intent; external send requires configured providers — **production release blocker** for customer-facing alerting.

## API rate limiting (service layer)

A fixed-window limiter applies to all `/v1/*` and `/internal/*` requests before auth and handlers run. These paths are **not** limited: `GET /health`, `GET /ready`, `GET /metrics`, and static UI (`/`, `/react-app.js`, `/react-app.css`).

| Variable | Default | Bounds | Notes |
|---|---|---|---|
| `ASTRANULL_RATE_LIMIT_WINDOW_MS` | `60000` | `1000`–`3600000` | Window length in milliseconds. |
| `ASTRANULL_RATE_LIMIT_MAX_REQUESTS` | `600` | `1`–`100000` | Max requests per client key per window. |
| `ASTRANULL_RATE_LIMIT_DISABLED` | off | — | `=1` allowed only outside `NODE_ENV=production`; production startup **fails closed** if set. |
| `ASTRANULL_TRUST_PROXY_HEADERS` | `false` | — | When `=1`, client key uses `x-forwarded-for` / `x-real-ip`. Enable **only** behind a trusted reverse proxy that strips spoofed inbound headers. |

When limited, the API returns HTTP `429` with JSON `{ "error": "rate_limited" }` and a `Retry-After` header (seconds). Counter `api_rate_limited_total` increments. Gateway/WAF limits and staging load/abuse evidence remain **production release blockers** (see checklist).

## Public / unauthenticated

| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/health` | — | Liveness: `{ status, service }` (`service` is `astranull`). |
| GET | `/ready` | — | Readiness for deploy gates: `{ status, service, auth_mode, persistence, probe_mode, probe_worker_secret_configured, timestamp }` (no secrets or database URLs); `503` with `status: not_ready` when the store is unavailable. |
| GET | `/metrics` | — | Metrics endpoint. The in-process route is unauthenticated; production deployments must restrict scrape access at the gateway/network layer per observability policy. |
| GET | `/`, `/react-app.js`, `/react-app.css` | — | React SPA shell and bundle assets. |
| GET | `/v1/public/site-config` | — | Public landing/login/signup configuration with no secrets. |
| POST | `/v1/auth/bundled-staging-login` | — | Bundled staging login exchange for hosted/local staging. Not a production enterprise IdP substitute. |
| POST | `/v1/signup-requests` | — | Public account request intake. Returns `201 { request }`, `400 validation_failed`, `403 signup_disabled`, `409 duplicate_request`, or `429 rate_limited`. |
| GET | `/v1/signup-requests/:id` | — | Public-safe signup request status (`{ request }`) or `404`. |
| GET | `/v1/signup-requests/:id/events` | — | Ordered signup queue events `{ events, count }`; messages truncated to **500** chars; rate-limited to **12/min** per request id (`429 rate_limited`). |
| GET | `/v1/checks` | — | Global check catalog. **Production gate:** tenant-aware RBAC if catalog is customized per tenant. |
| GET | `/v1/state` | `tenant:read` | Dashboard aggregate. In `postgres` mode uses `runtime.services.state.getState` (evidence-backed readiness from Postgres repositories); high-scale counts and kill-switch state return explicit not-wired metadata until those route families migrate. |
| GET | `/v1/placement/reviews` | `target_group:read` | Optional query `target_group_id`. Metadata-only per-target-group placement diagnostics (`proven`, `needs_baseline`, `missing_agent`, `misplaced_risk`) with summary counts, bound/online agent ids, recent observation counts, and warnings. `404` `not_found` when `target_group_id` is not declared for the tenant. Postgres mode uses `runtime.services.placement.listPlacementReviews`. |

## Tenant and environments

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| GET | `/v1/tenants/current` | `tenant:read` | — | Tenant object incl. `privacy_settings`. |
| PATCH | `/v1/tenants/current` | `tenant:write` | `{ privacy_settings?, name? }` | Updated tenant. `privacy_settings.metadata_retention_days`, `evidence_retention_days`, and `audit_retention_days` are normalized/clamped on read and write (defaults **365** / **1825** / **2555** per migration `0034`); changing privacy settings runs an immediate metadata retention purge for the current tenant (see [Privacy retention](#privacy-retention-metadata)). |
| GET | `/v1/environments` | `environment:read` | — | `{ items: Environment[] }`. |
| POST | `/v1/environments` | `environment:write` | `{ name, timezone? }` | `201` environment. |
| PATCH | `/v1/environments/:id` | `environment:write` | partial fields | Environment or `404`. |

## Target groups

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| GET | `/v1/target-groups` | `target_group:read` | `?archived=true` lists soft-deleted groups only | `{ items, count }` active groups by default (`deleted_at` / `archived_at` null). |
| POST | `/v1/target-groups` | `target_group:write` | `{ name, environment_id?, description?, timezone?, safe_test_windows?, safety_policy? }` | `201` group. `safe_test_windows`: `[{ start_at, end_at, reason? }]`. `safety_policy`: `{ max_runs_per_hour?, min_seconds_between_runs? }` (defaults `60` / `0`). |
| GET | `/v1/target-groups/:id` | `target_group:read` | — | Group with `targets[]`. |
| PATCH | `/v1/target-groups/:id` | `target_group:write` | partial group fields | Updated group or `404`. |
| DELETE | `/v1/target-groups/:id` | `target_group:write` | — | Soft-archives the group (`deleted_at`, `deleted_by`) or returns `409 target_group_active_run` while an active run still references it. |
| POST | `/v1/target-groups/:id/restore` | `target_group:write` | — | Clears `deleted_at` / `deleted_by` and returns `{ target_group }`, or `404 not_archived` when the group is active. |
| POST | `/v1/target-groups/:id/targets` | `target_group:write` | target declaration | `201` target. |
| PATCH | `/v1/target-groups/:id/targets/:targetId` | `target_group:write` | partial target fields | Updated target or `404`. |
| DELETE | `/v1/target-groups/:id/targets/:targetId` | `target_group:write` | — | Deletes/archives the declared target or returns the service-layer conflict. |

## Tenant subscription and support summary

`GET /v1/subscription/current` is customer-accessible with `tenant:read` and returns only tenant-scoped subscription/account metadata plus derived usage counts. It does not create a default plan when no subscription exists; `subscription`, `plan`, and `account` can be `null`, and the React UI must show an empty/not-configured state instead of invented plan data.

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| GET | `/v1/subscription/current` | `tenant:read` | — | `{ tenant_id, account, subscription, plan, usage, support }` with usage derived from users, declared target groups, agents, safe runs started in the last hour, findings, high-scale requests, and recent tenant audit metadata. |

## Public signup and staff internal management

Public signup routes are intentionally narrow and expose only sanitized request state. Staff routes require service-account or staff principal access with `staff:*` permissions; customer principals are denied with `403 staff_forbidden`. In Postgres mode these routes fail closed with `503 postgres_internal_admin_not_wired` unless the internal management service is injected.

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| GET | `/internal/admin/overview` | `staff:signup:read` | — | Internal queue and tenant summary. |
| GET | `/internal/admin/signup-requests` | `staff:signup:read` | `state?` | `{ items }` signup queue. |
| POST | `/internal/admin/signup-requests/:id/approve` | `staff:signup:decide` | approval payload | Creates/updates tenant onboarding state; `404` or `409` on invalid lifecycle. |
| POST | `/internal/admin/signup-requests/:id/reject` | `staff:signup:decide` | rejection payload | Rejected request or `404`/`409`. |
| GET | `/internal/admin/tenants` | `staff:tenant:read` | `q?` | `{ items }` tenant directory. |
| GET | `/internal/admin/tenants/:id` | `staff:tenant:read` | — | Tenant detail or `404`. |
| PATCH | `/internal/admin/tenants/:id` | `staff:tenant:write` | allowed tenant fields | Updated tenant detail or validation error. |
| GET | `/internal/admin/tenants/:id/subscription` | `staff:subscription:read` | — | Subscription and entitlement summary. |
| PATCH | `/internal/admin/tenants/:id/subscription` | `staff:subscription:write` | subscription fields | Updated subscription or validation error. |
| POST | `/internal/admin/tenants/:id/entitlements` | `staff:entitlement:write` | entitlement grant | Upserted entitlement grant. |
| POST | `/internal/admin/tenants/:id/users/:userId/resend-invite` | `staff:support:write` | invite metadata | Invite resend intent. |
| POST | `/internal/admin/tenants/:id/users/:userId/disable` | `staff:support:write` | reason metadata | Disabled tenant user. |
| GET | `/internal/admin/approval-requests` | `staff:approval:read` | `state?, kind?` | `{ items }` internal approval requests. |
| POST | `/internal/admin/approval-requests/:id/decision` | `staff:approval:decide` | decision payload | Approval decision or lifecycle conflict. |
| GET | `/internal/admin/audit-log` | `staff:audit:read` | `tenant_id?, staff_id?, action?, limit?` | `{ items }` internal audit rows. |

## WAF posture add-on

**OpenAPI:** [`docs/api/waf-posture-openapi.json`](api/waf-posture-openapi.json) — OpenAPI 3.1 artifact for WAF assets, coverage analytics, safe validations, orchestrator execute/retest/cancel paths, CVE playbooks, action items, RBAC, and metadata-only safety notes. Check locally with `npm run api:waf:openapi:check`. This artifact does **not** close staging/live orchestrator, provider, or security/release signoff gates.

Disabled by default. `ASTRANULL_WAF_POSTURE_ENABLED=1` enables the current route family; when disabled, `/v1/waf/*` returns `404 { "error": "waf_feature_disabled" }`. The add-on does **not** require cloud/WAF credentials for core no-access mode. PostgreSQL schema, migration support (`0008_waf_posture`), repository primitives, and `runtime.services.wafPosture` adapters exist for the WAF asset/coverage/validation/drift routes; in custom Postgres servers without an injected WAF service the API still fails closed with `503 { "error": "postgres_route_not_wired" }`.

WAF evidence is metadata-only. WAF validation contracts reject raw payload/body/header/packet fields, secrets, exploit material, SOC-gated profiles, prohibited profiles, automatic discovery approval, and protected-posture finalization without bound safe test-run evidence or explicit metadata-only scenario evidence.

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| GET | `/v1/waf/assets` | `waf:read` | — | `{ items }` tenant-scoped declared WAF assets. |
| POST | `/v1/waf/assets` | `waf:write` | `{ target_group_id, canonical_url? \| hostname?, target_id?, owner_hint?, expected_waf_required? }` | `201 { asset }`. Discovery candidates cannot be auto-approved through this route. |
| GET | `/v1/waf/assets/:id` | `waf:read` | — | `{ asset, current_posture? }` or `404`. |
| PATCH | `/v1/waf/assets/:id` | `waf:write` | metadata fields only | `{ asset }`; unsafe/raw fields are rejected. |
| POST | `/v1/waf/assets/:id/exception` | `waf:write` | `{ owner, reason, expires_at, scope_hash? }` | `201 { exception, posture }`; approved metadata-only exception is tenant-scoped, future-expiring, audited, and available to compliance exports. |
| GET | `/v1/waf/exceptions` | `waf:read` | — | `{ items }` active, non-expired tenant-scoped WAF exceptions. |
| GET | `/v1/waf/coverage` | `waf:read` | `window_days?` | Status counts, `percentages`, aggregate `coverage_ratio`, and `trend[]` rollups when available. |
| GET | `/v1/waf/coverage/summary` | `waf:read` | — | Dashboard summary from `waf_coverage_summary` matview (dev-json parity via rollup refresh): `{ assets_total, protected, underprotected, unknown, coverage_pct, by_vendor, connectors_active, connectors_degraded, connectors_disabled, refreshed_at }`. |
| GET | `/v1/waf/offensive-suites` | `waf:read` | — | `{ suites[] }` SOC-gated offensive suite catalog (SQLi, XSS, RCE, etc.). |
| POST | `/v1/waf/offensive-requests` | `waf_offensive:request` | `{ waf_asset_id, objective, requested_suites[], emergency_contacts[], scope_confirmation: true, ... }` | `201 { offensive_request }`. Customer request only — SOC must approve and execute. |
| GET | `/v1/waf/offensive-requests` | `waf_offensive:read` | — | `{ items }` offensive validation requests. |
| GET | `/v1/waf/offensive-requests/:id` | `waf_offensive:read` | — | `{ offensive_request }` or `404`. |
| POST | `/v1/waf/offensive-requests/:id/artifacts` | `waf_offensive:write` | metadata-only authorization artifact | `201 { artifact }`. |
| POST | `/v1/waf/validations` | `waf:run` | `{ waf_asset_id, modes?, probe_profile?, marker_profile? }` | `201 { validation_run }`. Safe marker profiles enforce `max_requests` 1-5 and `timeout_ms` 100-5000. SOC offensive runs are created via `/internal/soc/waf-offensive/:id/start`, not this route. |
| GET | `/v1/waf/validations` | `waf:read` | — | `{ items }` validation runs. |
| GET | `/v1/waf/validations/:id` | `waf:read` | — | `{ validation_run, scenario_results }` or `404`. |
| POST | `/v1/waf/validations/:id/finalize` | `waf:run` | metadata-only summary and `scenario_results[]` | `{ validation_run, posture }`; writes a current posture snapshot, refreshes WAF posture findings for underprotected/unprotected outcomes, and creates/refreshes behavior-drift events when previously protected posture weakens. `protected` is returned only when WAF is detected and validation passes with corroborating metadata evidence. |
| GET | `/v1/waf/drift-events` | `waf:read` | — | `{ items }` open and historical behavior-drift events. |
| PATCH | `/v1/waf/drift-events/:id` | `waf:write` | `{ status, notes? }` | `{ drift_event }`; allowed statuses are `open`, `acknowledged`, `remediation_started`, `retest_pending`, `resolved`, `accepted_risk`, and `false_positive`. |

### WAF coverage analytics

Implemented as read-only WAF analytics routes in developer validation and documented in [WAF API Contract](backend/13-waf-posture-api-contract.md). They remain subject to staging export signoff, scheduled rollup evidence, and WAF add-on release approval before customer-facing promotion.

| Method | Path | Permission | Response summary |
|---|---|---|---|
| GET | `/v1/waf/coverage/vendors` | `waf:read` | Vendor/product mix and counts. |
| GET | `/v1/waf/coverage/entities` | `waf:read` | Business-unit/subsidiary rollups. |
| GET | `/v1/waf/coverage/criticality` | `waf:read` | Coverage by `business_criticality`. |
| GET | `/v1/waf/coverage/geography` | `waf:read` | Coverage by declared region. |
| GET | `/v1/waf/coverage/risk-roadmap` | `waf:read` | Tier 1–4 deployment priorities. |
| GET | `/v1/waf/coverage/vendor-consolidation` | `waf:read` | Read-only multi-vendor advisory. |
| GET | `/v1/waf/products` | `waf:read` | Seeded WAF product catalog entries and metadata. |
| GET | `/v1/waf/scenario-intake` | `waf:read` | Submitted product/scenario intake requests. |
| POST | `/v1/waf/scenario-intake` | `waf:write` | `202` accepted metadata-only intake request; raw exploit/probe material is rejected by service contracts. |

CVE playbook routes (`/v1/waf/cve-pipeline/:id/playbook`, `/playbook/approve`, and `/coordinated-retest`) are implemented with `waf:read`, `waf:write`, and `waf:run` respectively; see [Multi-Vendor CVE Playbook](detection/17-multi-vendor-cve-mitigation-playbook.md).

### WAF connector framework

The connector routes are also disabled when `ASTRANULL_WAF_POSTURE_ENABLED` is off. The current slice is metadata-only: it stores connector configuration summaries and operator-provided normalized snapshots, but does not call provider APIs, discover assets, or require credentials for core validation. Credential material must live in the secret vault and be referenced by `secret_id`; raw configs, headers, bodies, logs, plaintext tokens, and full policy bodies are rejected.

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| GET | `/v1/connectors` | `waf:connector_read` | — | `{ items }` tenant-scoped connector metadata. |
| POST | `/v1/connectors` | `waf:connector_write` | `{ provider, name, secret_id?, config, status? }` | `201 { connector }`; `config` is reduced to allowlisted metadata such as `read_only`, resource hashes, owner hints, tags, and polling interval. |
| POST | `/v1/connectors/:id/validate` | `waf:connector_write` | — | `{ status, capabilities, redacted_errors?, connector? }`; validation is local-only and requires `config.read_only=true`. |
| POST | `/v1/connectors/:id/poll` | `waf:connector_write` | `{ snapshots?: [...] }` | `202 { poll_job, snapshots }`; this ingests normalized metadata snapshots only. |
| GET | `/v1/connectors/:id/snapshots` | `waf:connector_read` | — | `{ items }` normalized metadata snapshots. |
| POST | `/v1/connectors/:id/disable` | `waf:connector_write` | `{ reason? }` | `{ connector }`. |

## Bootstrap tokens

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| POST | `/v1/bootstrap-tokens` | `bootstrap_token:create` | `{ name, target_group_id?, max_registrations?, expires_at?, prebind_fqdn?, deployment_packaging? }` — optional `prebind_fqdn` (string) pins the FQDN an agent may report on heartbeat `probe_endpoint.declared_fqdn`; optional `deployment_packaging` is `image`, `standalone`, or `helm` (stored on token metadata). | `201` metadata + **`secret` once** (`ast_v1.…` tenant/token id hints; salted hash stored only; legacy opaque tokens still verify in dev store). |
| GET | `/v1/bootstrap-tokens` | `bootstrap_token:read` | — | List without hash/salt/secret. |
| POST | `/v1/bootstrap-tokens/:id/revoke` | `bootstrap_token:revoke` | — | Revoked token metadata. |

## Service accounts (automation)

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| POST | `/v1/service-accounts` | `service_account:create` | `{ name, role, scopes, expires_at? }` | `201` metadata + **`secret` once** (`svc_…`, not stored plaintext). `role` must be `admin`, `engineer`, `auditor`, or `viewer` (not owner/SOC). `scopes` are permission strings; each must be allowed by `role` unless `scopes` is `["*"]` (admin only). |
| GET | `/v1/service-accounts` | `service_account:read` | — | List without hash/salt/secret. |
| POST | `/v1/service-accounts/:id/revoke` | `service_account:revoke` | — | Revoked account metadata. |
| POST | `/v1/service-accounts/:id/rotate` | `service_account:rotate` | — | `200` metadata + **`secret` once** (`svc_…`). Prior bearer stops working immediately. Revoked accounts return `409` (`service_account_revoked`). Response omits `secret_hash` / `secret_salt`. |

API calls authenticate with `Authorization: Bearer <svc_…>`. RBAC checks require matching scope (or `*`) in addition to role permission. Revoked or invalid tokens return `401`. Service account tokens do not satisfy agent or probe-worker authentication.

## Secrets (integration credentials)

Tenant-scoped integration secrets are stored as **AES-256-GCM** envelopes. The public API never returns plaintext, ciphertext, or auth tags, and there is **no** decrypt endpoint—plaintext is accepted only on create and rotate.

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| POST | `/v1/secrets` | `secret:write` | `{ purpose, name, plaintext, metadata? }` | `201` `{ secret }` metadata + redacted envelope (no plaintext). `503` `{ error: "encryption_not_configured" }` when `ASTRANULL_SECRET_ENCRYPTION_KEY` is unset. |
| GET | `/v1/secrets` | `secret:read` | — | `{ items }` metadata-only records per tenant. |
| POST | `/v1/secrets/:id/rotate` | `secret:rotate` | `{ plaintext, metadata? }` | `200` updated metadata + redacted envelope; `404` `{ error: "not_found" }`; `503` when encryption key is unset. |

Sensitive metadata keys are redacted on store and in responses. Internal workflows may decrypt for authorized use only (not exposed on `/v1`).

## Agents (outbound)

| Method | Path | Auth | Request | Response |
|---|---|---|---|---|
| POST | `/v1/agents/register` | bootstrap `secret` in body | `{ bootstrap_token, hostname, capabilities? }` | `201` `{ agent, agent_credential }`. |
| GET | `/v1/agents` | `agent:read` | — | Fleet list. |
| POST | `/v1/agents/:id/revoke` | `agent:revoke` | — | Marks the tenant agent `revoked`, records `agent.revoked`, and immediately rejects the old agent credential on heartbeat, jobs, observations, and update poll/status routes. `404` when the agent is not in the caller tenant. |
| POST | `/v1/agents/:id/heartbeat` | Bearer agent credential | `{ version, placement?, capabilities?, probe_endpoint? }` — optional `probe_endpoint` object (`declared_fqdn?`, `declared_ip?`, `discovered_public_ip?`, `agent_local_ip?`, `listen_port?`, `path_prefix?`, `discovered_via?` ∈ `operator_env` \| `cloud_metadata` \| `dns_resolve` \| `stun`). Server validates schema (FQDN format; routable IPv4/IPv6 literals rejecting loopback, link-local, metadata, RFC1918, and ULA unless dev-private override; port 1–65535; `path_prefix`; `discovered_via` enum), then applies binding: `declared_fqdn` must equal the bootstrap token `prebind_fqdn` when set and must appear among the agent target group FQDN targets when any exist. Failures set `probe_endpoint_status: rejected` and `probe_endpoint_error` to `invalid_probe_endpoint`, `fqdn_prebind_mismatch`, or `target_group_mismatch`; success stores normalized `probe_endpoint` with `probe_endpoint_status: reported` and updates `last_token_validation_at` / `last_token_validation_status` (`valid` on accepted binding path). Heartbeat always returns `200`; response includes `probe_endpoint_accepted` (boolean). Invalid endpoints are rejected without failing the heartbeat HTTP status. Fleet `GET /v1/agents` exposes `probe_endpoint`, `probe_endpoint_status`, `last_token_validation_at`, and `last_token_validation_status`. | `200` health update with `probe_endpoint_accepted`. |
| GET | `/v1/agents/:id/jobs` | Bearer | — | `{ jobs }` (long-poll up to ~3s). |
| POST | `/v1/agents/:id/jobs/:jobId/ack` | Bearer | — | Acknowledged job. |
| POST | `/v1/agents/:id/observations` | Bearer | `{ agent_job_id, test_run_id, target_id, nonce_hash, metadata? }` | Correlation input tied to acked agent job (`403` `agent_job_mismatch`, `409` `agent_job_not_acked`, `400` `missing_agent_job_id`, `400` `raw_packet_rejected`); metadata redacted; `429` `event_cap_exceeded` when run event budget is exhausted. |
| GET | `/v1/agents/:id/update` | Bearer | — | `{ update: null }` or `{ update: { release_id, action: upgrade\|rollback, version, channel, manifest, signature, rollback_version?, download: { manifest_url, signature_url, artifact_url } } }`. `download` carries absolute HTTPS URLs from the release (or embedded rollback) distribution metadata. Eligible upgrade from active releases matching staged rollout; rollback when release `state` is `rollback_requested` and agent previously reported `applied`. Host agents can consume `download` via `--download-and-apply-update`; **production gate:** unattended daemon orchestration, service restart, and fleet rollout/rollback drills. |
| POST | `/v1/agents/:id/update-status` | Bearer | `{ release_id, status, installed_version?, action?, error_code? }` | `201` status record. `status` must be `downloaded`, `verified`, `applied`, `failed`, or `rolled_back`. `installed_version` required semantics for version bump when `status` is `applied` or `rolled_back`. `error_code` optional lowercase identifier. Errors: `400` `invalid_release_id`, `invalid_status`, `invalid_installed_version`, `invalid_error_code`, `invalid_action`; `404` `not_found`. Audits `agent_update.status_recorded`. |

## Agent update releases (tenant admin)

Tenant-scoped ledgers: `agentUpdateReleases`, `agentUpdateStatuses` in developer validation; `agent_update_releases`, `agent_update_statuses`, and `runtime.services.agentUpdates` in `ASTRANULL_PERSISTENCE_MODE=postgres`. Manifests must use package `astranull-agent`, matching `version`, signed artifact metadata (safe `*.tar.gz` basename, SHA-256, positive size), `signing.signed: true`, detached Ed25519 signature over canonical manifest fields (same algorithm as `scripts/package-agent.mjs`).

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| POST | `/v1/agent-updates` | `agent_update:write` | `{ version, channel?, manifest, signature, distribution, rollout?, rollback? }` | `201` `{ release }` including stored `distribution`. `channel` defaults to `stable` (`stable`/`beta`/`canary`). Required `distribution`: `{ manifest_url, signature_url, artifact_url }` — each an absolute **HTTPS** URL (query strings allowed, e.g. CDN signed URLs); URL credentials rejected; malformed URLs and malformed `artifact_url` path encoding rejected; decoded `artifact_url` pathname basename must equal `manifest.artifact.name`. `rollout`: `{ percentage?, environment_ids?, target_group_ids?, agent_ids? }`. Optional `rollback`: `{ version, manifest, signature, distribution }` with the same distribution rules. Manifest `signing.public_key_der_base64` must match an **active** tenant trust key or `400` `untrusted_signing_key`. Errors include `invalid_version`, `invalid_channel`, `invalid_manifest`, `invalid_package`, `version_mismatch`, `invalid_artifact_name`, `invalid_artifact_sha256`, `invalid_artifact_size`, `unsigned_manifest`, `missing_signature`, `invalid_signature`, `missing_signing_public_key`, `invalid_signing_public_key`, `signature_verification_failed`, `invalid_rollout`, `untrusted_signing_key`, `missing_distribution`, `invalid_distribution_url`, `artifact_url_mismatch`, rollback-specific `missing_rollback_signature` / `invalid_rollback_signature` / `invalid_rollback_manifest` / `invalid_rollback_distribution`. Audits `agent_update.release_created` with metadata that **excludes** distribution URLs and query strings. |
| GET | `/v1/agent-updates` | `agent_update:read` | — | `{ items: Release[] }` for caller tenant. |
| POST | `/v1/agent-updates/:id/rollback` | `agent_update:rollback` | — | `200` `{ release }` with `state: rollback_requested` when embedded rollback exists; `404` `not_found`; `400` `rollback_not_available`. Audits `agent_update.rollback_requested`. **Production gate:** fleet rollback drill with staging evidence (distribution metadata required at release creation). |

Tenant-scoped ledger: `agentUpdateTrustKeys` in developer validation; `agent_update_trust_keys` through `runtime.services.agentUpdates` in Postgres mode. Public keys are stored server-side; list/create responses are metadata-oriented (no raw DER in list payloads).

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| POST | `/v1/agent-update-trust-keys` | `agent_update:write` | `{ name, public_key_der_base64 }` | `201` `{ trust_key }` with `id`, `name`, `fingerprint_sha256`, `status: active`, timestamps. Validates DER SPKI Ed25519; rejects invalid key material and duplicate active fingerprint. Audits `agent_update.trust_key_added`. |
| GET | `/v1/agent-update-trust-keys` | `agent_update:read` | — | `{ items: TrustKey[] }` metadata for caller tenant (`id`, `name`, `fingerprint_sha256`, `status`, `created_at`, `revoked_at?`). |
| POST | `/v1/agent-update-trust-keys/:id/revoke` | `agent_update:write` | — | `200` `{ trust_key }` with `status: revoked`; `404` `not_found`; `400` `already_revoked`. Audits `agent_update.trust_key_revoked`. |

## Test policies

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| GET | `/v1/test-policies` | `test_policy:read` | — | `{ items }` active, non-archived safe validation policies enriched with active target group and check catalog metadata. Policies for archived target groups are omitted. |
| POST | `/v1/test-policies` | `test_policy:write` | `{ target_group_id, check_id, cadence?, expected_verdict?, safe_windows? }` | `201` policy. Only customer-runnable safe checks can be bound. SOC-gated/high-scale checks return `403 { error: "soc_gated_check" }` and must use the SOC request workflow. |
| PATCH | `/v1/test-policies/:id` | `test_policy:write` | `{ cadence?, expected_verdict?, safe_windows?, state? }` | Updated policy or `404`; `state` accepts `active` or `paused`. |
| DELETE | `/v1/test-policies/:id` | `test_policy:write` | — | Archives the policy and returns the archived record or `404`. |

In memory/developer mode the routes use the tenant store and audit `test_policy.created`, `test_policy.updated`, and `test_policy.archived`. In Postgres mode the routes fail closed with `503 postgres_route_not_wired` unless a production-grade `testPolicies` service is injected.

## Test runs

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| POST | `/v1/test-runs` | `test_run:start` | `{ check_id, target_group_id, target_id?, probe_profile? }` | `201` run + correlation nonce; `simulation` mode includes immediate `probe_event`; `signed-worker` mode includes `probe_job` and awaits external worker. Safety denials: `429` `safe_window_closed`, `safe_rate_cap_exceeded`, `safe_min_interval_active`; `403` `soc_gated_check`; `409` `concurrent_run_blocked`. |
| GET | `/v1/test-runs` | `test_run:read` | — | `{ items }`. |
| GET | `/v1/test-runs/:id` | `test_run:read` | — | Run detail + verdict when present. |
| GET | `/v1/test-runs/:id/events` | `test_run:read` | — | Timeline events. |
| POST | `/v1/test-runs/:id/finalize` | `test_run:read` | — | Verdict after collection window. |
| POST | `/v1/test-runs/:id/cancel` | `test_run:start` | — | `200` cancelled run when status is `planned`, `running`, or `collecting`; `409` `{ error: "not_cancellable" }` for terminal runs. |

In `postgres` mode, `runtime.services.testRuns` backs the safe validation loop: `POST /v1/test-runs` and `POST /v1/test-runs/:id/cancel` enforce target declaration, customer-runnable check gating, prerequisites, safe windows, tenant rate/cooldown limits, concurrent-run blocking, tenant kill switch, audit logging, agent job dispatch, and signed probe-job creation in `signed-worker` mode; probe results ingest through `runtime.services.probeJobs`; agent `POST /v1/agents/:id/observations` uses exact-once job transition before observation evidence is written; probe/agent events correlate; automatic verdict publication runs when both sides correlate; `POST /v1/test-runs/:id/finalize` forces bounded no-observation finalization after the observation window; findings upsert from verdicts; audits cover starts, cancellations, probe jobs, observations, verdict publication, no-observation finalization, findings, denials, and rejected observations; raw packet/payload/header fields are rejected for metadata-only evidence. Guarded high-scale/SOC routes are backed by `runtime.services.highScale` in Postgres mode. **Release blockers** remain live/staging Postgres acceptance and tenant unit-of-work/concurrency hardening under load, not rewiring these route families.

## Findings

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| GET | `/v1/findings` | `finding:read` | — | `{ items }`. |
| GET | `/v1/findings/:id` | `finding:read` | — | Finding. |
| PATCH | `/v1/findings/:id` | `finding:write` | `{ status?, notes? }` | Updated finding. |
| POST | `/v1/findings/:id/export` | `finding:read` | — | Redacted export JSON: existing finding fields plus top-level `custody` (digest manifest; see **Export custody** below). |

## Reports

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| GET | `/v1/reports` | `report:create` | `limit?` | `{ items }` generated report metadata for the tenant, newest first. |
| POST | `/v1/reports` | `report:create` | `{ kind?, title? }` | `201` report with summary. |
| GET | `/v1/reports/:id` | `report:create` | — | Report metadata. |
| GET | `/v1/reports/:id/export?format=json\|markdown\|html` | `report:create` | — | `format=json`: `{ payload, custody }`. `format=markdown` or `html`: redacted report text with an embedded **Custody** section (artifact id, `content_sha256`, canonicalization, `created_at`, optional `previous_audit_hash`). Self-contained HTML has no external scripts. |

### Export custody (developer validation)

Report and finding exports attach a metadata-only **custody** manifest (`schema_version`: `astranull.custody.v1`) built by `src/lib/custody.mjs`:

- **Digest:** `content_sha256` is SHA-256 over the export payload using deterministic `json-key-sorted-v1` canonical JSON (plain objects/arrays only; unsupported types fail verification).
- **Linkage:** `previous_audit_hash` matches the global tamper-evident audit chain predecessor for the `report.exported` / `finding.exported` event; `previous_tenant_audit_hash` may be present when a prior tenant-scoped audit entry exists.
- **Verification:** clients can call `POST /v1/custody/verify` with `{ payload, custody }` (`audit:read`) or the local `verifyCustodyManifest({ payload, custody })` helper. Both recompute the digest; neither performs KMS/signature validation yet.
- **Verification response:** `/v1/custody/verify` returns `{ ok, verification }` with safe manifest metadata and `error` such as `custody_missing` or `content_sha256_mismatch`; it does not echo the submitted payload.
- **Audit metadata:** export audit rows record only `format`, `content_sha256`, and `custody_schema_version` (no full manifest duplication).
- **Verification audit:** custody verification records `custody.verified` with metadata-only status, artifact type, digest, and schema version.

**Production gates still open:** external signing/KMS ceremony, durable immutable evidence snapshots, retained export custody storage, retention/legal-hold enforcement evidence, and staging signoff. Digest manifests are **not** a substitute for signed immutable evidence archives.

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| POST | `/v1/custody/verify` | `audit:read` | `{ payload, custody }` | `200` `{ ok, verification }`; safe metadata only, no payload echo. Audits `custody.verified`. |

## Events and evidence

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| POST | `/v1/events` | `event:ingest` | `{ event_id, signal_type?, metadata?, test_run_id?, evidence? }` | `201` or `200` duplicate; rejects cross-tenant `tenant_id` and packet fields. |
| GET | `/v1/evidence` | `evidence:read` | — | `{ items }`. |
| GET | `/v1/evidence/:id` | `evidence:read` | — | Evidence record (metadata). |

## Production release evidence

Release readiness evidence is tenant-scoped, metadata-only, and validated by `src/contracts/productionReleaseEvidence.mjs`. Accepted kinds (canonical list in `PRODUCTION_RELEASE_EVIDENCE_KINDS`) are:

`third_party_security_review`, `migration_apply`, `operator_runbook_exercise`, `oidc_prod_auth_preflight`, `edge_protection`, `agent_sbom_provenance`, `agent_install_matrix`, `agent_mtls_gateway`, `agent_trust_key_ceremony`, `governed_adapter`, `provider_approval`, `kill_switch_drill`, `postgres_concurrency`, `dr_restore`, `ui_accessibility_matrix`, `notification_provider_config`, `probe_fleet_matrix`, `vector_safety_policy`, `secret_rotation_drill`, `observability_slo`, `support_readiness`, `evidence_snapshot_manifest`, `postgres_tenant_query_audit`, `rollback_fixforward`, `kms_vault_posture`, `control_plane_container_release`, `staging_e2e_matrix`, `compliance_legal_signoff`, `authorization_custody`, `placement_confidence_staging`, and `gateway_load_abuse`.

Each kind requires top-level metadata fields aligned with the corresponding operator evidence manifests (URIs, digests, signoff references, validation summaries, and a retained `evidence_uri` custody pointer — not raw logs, packet captures, SQL dumps, IP inventories, attachments, ciphertext, or secrets). Forbidden nested keys include packet/pcap/raw SQL/raw dump/target IP inventory/api key fields and other secret- or payload-bearing names; `authorized_scope_hash` and similar scope digests remain allowed.

**Developer validation vs production gates:** `POST` accepts metadata that passed contract validation and records custody pointers in the tenant ledger. That inventory step is **not** staging execution, operator drill completion, independent security review, SOC/legal signoff, or promotion approval. Rehearsal fixtures from `npm run release:sample-evidence` must not be treated as operator-attested production evidence.

In `postgres` mode, the route family is backed by `runtime.services.productionReleaseEvidence` and the `production_release_evidence` table.

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| GET | `/v1/production-release-evidence` | `release_evidence:read` | — | `{ items }` for the caller tenant. |
| POST | `/v1/production-release-evidence` | `release_evidence:write` | `{ kind, evidence, release_id?, notes? }` | `201` `{ evidence }` with redacted evidence metadata, validation result, creator, and `status: "accepted"`. Errors: `400` `invalid_evidence_kind`, `missing_evidence_fields`, or `forbidden_evidence_fields`. Audits `production_release_evidence.recorded` with kind/release id only. |
| GET | `/v1/production-release-evidence/attestation` | `release_evidence:read` | — | `200` `{ attestation, records }` — metadata-only staging readiness summary derived from **accepted** tenant ledger rows (see below). Viewers and other roles without `release_evidence:read` receive `403`. |
| GET | `/v1/production-release-evidence/:id` | `release_evidence:read` | — | Evidence record or `404` when missing or cross-tenant. |

### Attestation (`GET /v1/production-release-evidence/attestation`)

Aggregates accepted records for the caller tenant through the same logic as `scripts/staging-readiness-attestation.mjs` (`aggregateStagingReadinessAttestation`). The API always evaluates profile **`full`** (every kind in `PRODUCTION_RELEASE_EVIDENCE_KINDS`). Offline CLIs can scope required kinds with `--profile` (see [Offline attestation and gap audit](#offline-attestation-and-gap-audit)).

**Response shape**

- **`attestation`** — `artifact_type: staging_readiness_attestation`, `profile`, `release_id`, `production_ready`, `signoff_status` (`missing_evidence`, `invalid_evidence`, `evidence_complete`, or `blocked`), `required_evidence_kinds` (`required`, `present`, `missing`, `invalid`, `rejected`), `optional_evidence_kinds`, `blocker_summary`, `record_counts`, and `caveats`.
- **`records`** — per-kind summaries only: `id`, `kind`, `status`, `release_id`, `created_at`, `validation` (no `evidence` bodies, notes, or secret-bearing fields).

**Production gate caveat:** `attestation.production_ready: true` means the tenant ledger contains contract-valid **accepted** metadata for every kind required by the evaluated profile. It does **not** close [`docs/release-checklist.md`](release-checklist.md), external staging/security/SOC/legal gates, or customer promotion. Checklist rows and operator signoff outside AstraNull still govern release.

### Offline attestation and gap audit

| Command | Purpose | Profiles |
|---|---|---|
| `node scripts/staging-readiness-attestation.mjs --input <evidence.json> [--profile …] [--release-id rel] [--out file] [--validate-only]` / `npm run release:staging-attestation` | Metadata-only attestation over a local evidence bundle or record list | `full` (default), `safe-validation-ga`, `high-scale-ga` — see `STAGING_READINESS_RELEASE_PROFILES` in `scripts/staging-readiness-attestation.mjs` |
| `node scripts/production-readiness-gap-audit.mjs [--evidence bundle.json] [--release-id rel] [--out file] [--validate-only]` / `npm run release:gap-audit` | Cross-checks evidence inventory against **all** contract kinds plus open gates parsed from `docs/release-checklist.md` and this release plan; reports `external_gates` categories that local validation cannot satisfy | Inventory step uses the full kind set; pair with a profile-scoped staging attestation when evaluating `safe-validation-ga` or `high-scale-ga` milestones |

Both CLIs reject secrets, raw payloads, logs, packet captures, SQL dumps, IP inventories, tokens, database URLs, and ciphertext in input. `production_ready` in CLI output has the same meaning as the API field: evidence inventory only, not production sign-off.

## Notifications

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| GET | `/v1/notifications` | `notification:read` | — | `{ rules, events }` for the caller’s tenant. Rules expose `destination_preview` only; events include `delivery_attempts` (channel, `destination_preview`, status, timestamps). No cross-tenant data and no full provider destinations. |
| POST | `/v1/notifications` | `notification:write` | `{ channel?, destination?, triggers?, enabled? }` | Created rule on success with `destination_preview` only in the HTTP response. Validates `channel` (`in_app`, `webhook`, `email`, `slack`, `teams`), `triggers` (allowed set), and webhook `destination` (`https://` or dev-only `http` hosts). Non-`in_app` rules require a non-empty `destination`. Invalid input returns HTTP `400` with `{ error, status: 400 }`. **Default:** external channels record `queued_provider_not_configured` (no outbound send). **Opt-in:** set `ASTRANULL_NOTIFICATION_DELIVERY_MODE=webhook` to POST redacted event JSON to webhook rules only (`delivered_provider` / `provider_retry_scheduled` / `provider_failed_dlq`); email/Slack/Teams remain metadata-only. |
| POST | `/v1/notifications/retries/process` | `notification:write` | `{ dry_run?, as_of? }` | Processes due `provider_retry_scheduled` attempts in forced metadata-only mode. Returns safe retry summary without internal `delivery_record`, full destinations, provider URLs, request/response bodies, logs, tokens, or secrets. Production still uses an externally scheduled runner plus provider/staging evidence. |
| POST | `/v1/notifications/dlq/redrive` | `notification:write` | `{ dry_run?, attempt_ids?, rule_id? }` | Requeues selected `provider_failed_dlq` attempts through the HTTP/UI metadata-only path. Client-supplied provider-delivery overrides are ignored; response strips internal `delivery_record`, full destinations, provider URLs, request/response bodies, logs, tokens, and secrets. |

## High-scale (customer)

| Method | Path | Permission | Request | Response |
|---|---|---|---|---|
| POST | `/v1/high-scale-requests` | `high_scale:request` | **Required:** `target_group_id`; `reason` or `objective` (both stored from supplied text); `environment`; `business_criticality`; non-empty `requested_scenario_families[]` (metadata-only, redacted); `requested_limits` with at least one of `max_rate` (metadata string) or `max_duration_minutes` (positive number); non-empty metadata objects `stop_criteria` and `abort_criteria` (redacted on persist); `requested_window` with `window_start`/`window_end` (aliases `start`/`end` accepted — normalized ISO, optional `timezone`); non-empty `emergency_contacts[]` (metadata-only, redacted); `provider_context` with at least one provider label (`provider_name` / `provider` / `name`, `providers[]`) or `requires_provider_approval: true` (stored redacted); `scope_confirmation: true`. **Optional (redacted metadata):** `maintenance_approval`, `provider_contacts`, `provider_approvals[]`. | `201` request in `submitted` state with normalized intake fields stored on the request record (including `abort_criteria`). Target scope errors unchanged: `400` `missing_target_group_id`, `404` `target_group_not_found`, `400` `target_group_empty`. After valid scope, incomplete intake returns `400` `{ error: 'missing_high_scale_request_fields', missing: [...] }` (may include `abort_criteria`, `stop_criteria`, `environment`, etc.). Invalid dates or `start >= end` returns `400` `invalid_requested_window`. Provider checklist initialization unchanged: when provider metadata is supplied, the server initializes `provider_approval_checklist` (metadata-only items; string fields redacted). If `requires_provider_approval` is true and no provider name is given, a required `unspecified_provider` checklist item is created. SOC approve requires complete `authorization_pack_status` (expanded required artifact types accepted) and every required checklist item `accepted` and not expired. Customer roles cannot approve, schedule, start, stop, or close. |
| GET | `/v1/high-scale-requests` | `high_scale:read` | `?scope=my-tenant` filters to inline SOC queue states (`submitted`, `soc_review`, `scheduled`, `under_review`) ordered by `state`, `created_at` | `{ items, count }`. |
| POST | `/v1/high-scale-requests/:id/artifacts` | `high_scale:request` | **Required:** `type` (expanded SOC-009 pack types, e.g. `customer_authorization_letter`, `target_ownership_confirmation`, `emergency_contacts`, `stop_criteria`, `test_plan`, `business_approval`, `legal_approval`, `scope_and_rate_plan`, `abort_criteria`, `provider_approval`). **Optional metadata-only proof fields (redacted on persist):** `reference_uri` (URI/ticket pointer — not binary upload in developer validation); `approval_reference`; `approver`; `valid_window` (`window_start`/`window_end` or aliases); `approved_targets[]`; `approved_scenario_families[]`; `max_rate`; `max_duration_minutes` (positive number); `emergency_contacts[]`; `abort_criteria` (object); `retention_policy` (object); `retained_artifact_metadata` (object); `contact_path`. **Provider approval (`type: provider_approval`):** `provider_name`, `provider_ref`, plus the proof fields above as applicable. Required proof fields per type are enforced when computing `authorization_pack_status` (see authorization pack doc). | `201` artifact metadata record (proof fields stored on the artifact; bodies are metadata references only). `type: provider_approval` updates or creates the matching `provider_approval_checklist` item (`pending_review`, or `expired` when the valid window end is in the past). SOC artifact review sets linked checklist items to `accepted` or `rejected` (expired windows remain `expired`). **Production gate:** secure durable document store/custody for real authorization letters, legal approvals, and provider attestations — API accepts metadata references only until that store is integrated. |
| GET | `/v1/high-scale-requests/:id/artifacts` | `high_scale:read` | — | `{ items }`. |

## SOC internal (`/internal/soc/*`)

Requires `soc:high_scale` or `soc:kill_switch`. **Customer roles (engineer, viewer, auditor) receive 403** and `rbac.denied` audit entries.

| Method | Path | Permission | Body | Notes |
|---|---|---|---|---|
| POST | `/internal/soc/high-scale/:id/approve` | `soc:high_scale` | — | Requires complete authorization pack. |
| POST | `/internal/soc/high-scale/:id/schedule` | `soc:high_scale` | `{ window_start, window_end }` | Sets approved window. |
| POST | `/internal/soc/high-scale/:id/start` | `soc:high_scale` | — | **Production:** governed adapter only. Developer validation: dry-run adapter; gated by window + scope hash. |
| POST | `/internal/soc/high-scale/:id/stop` | `soc:high_scale` | — | Stop transition. |
| POST | `/internal/soc/high-scale/:id/post-test-report` | `soc:high_scale` | `{ impact_summary?, recommendations?, customer_summary?, residual_risk?, next_steps?, attachments?, evidence_ids? }` | Upsert metadata-only SOC post-test report. Requires request `state === stopped`; otherwise `409` `report_requires_stopped_request`. Customer/engineer roles receive `403`. Body and derived SOC note text are redacted before persistence. Response includes derived `timeline` (from audit trail), artifact summary (id/type/status/reviewed_at), redacted SOC notes, adapter status metadata (`traffic_generated` retained when present), safe `telemetry_summary` (record counts, per-category counts, latest live status — not full metric payloads), and `final_state`. |
| GET | `/internal/soc/high-scale/:id/post-test-report` | `soc:high_scale` | — | Read stored post-test report for the request. `404` if none. |
| POST | `/internal/soc/high-scale/:id/close` | `soc:high_scale` | — | Close request from `stopped` only. `409` `post_test_report_required` if no post-test report exists. |
| POST | `/internal/soc/high-scale/:id/artifacts/:artifactId/review` | `soc:high_scale` | `{ status: accepted\|rejected }` | SOC review. |
| GET/POST | `/internal/soc/high-scale/:id/notes` | `soc:high_scale` | `{ body }` on POST | SOC transcript notes (redacted on export). |
| GET | `/internal/soc/high-scale/:id/adapter-status` | `soc:high_scale` | — | Adapter status; production must reflect real fleet state. |
| POST | `/internal/soc/high-scale/:id/telemetry` | `soc:high_scale` | `{ category, live_status?, observed_at?, source?, metrics? }` | Metadata-only SOC telemetry during governed runs. Allowed when request `state` is `scheduled`, `running`, `stopped`, or `closed`; otherwise `409` `telemetry_not_active`. Categories: `external_availability`, `agent_health`, `service_health`, `mitigation`, `stop_evidence`, `adapter_metric`. Optional `live_status`: `stable`, `mitigating`, `degraded`, `breached_threshold`, `stopping`, `stopped`, `inconclusive`. Rejects nested raw/payload/header/log/body fields in `metrics` with `400` `forbidden_telemetry_fields`. Customer/engineer roles receive `403`. Audit: `high_scale.telemetry_recorded` (category, live status, request id only). **Production gate:** live provider/staging telemetry feeds. |
| POST | `/internal/soc/high-scale/:id/telemetry/ingest` | `soc:high_scale` | `{ adapter_id, adapter_type?, provider_key?, provider_run_id?, snapshots: [{ category, live_status?, observed_at?, metrics? }] }` | Batch governed-adapter telemetry ingest. Same active-state gate as manual telemetry. Rejects forbidden attack/payload/header/log fields in envelope and snapshots. Audit: `high_scale.adapter_telemetry_ingested` (adapter id, snapshot count, ingestion id only). Scheduled operator helper: `scripts/governed-adapter-telemetry-ingest-runner.mjs` / `npm run soc:adapter-telemetry:ingest`. **Production gate:** live partner/provider adapter feeds wired to the scheduled ingest manifest. |
| GET | `/internal/soc/high-scale/:id/telemetry` | `soc:high_scale` | — | Tenant-scoped telemetry items for the request (newest `observed_at` first). |
| POST | `/internal/soc/kill-switch` | `soc:kill_switch` | `{ active, reason? }` | Tenant-scoped kill switch for the SOC caller’s tenant. On `active: true`, auto-stops running high-scale requests, auto-cancels in-flight safe test runs (`test_run.kill_switch_auto_cancel` per run), and in Postgres mode cancels open signed-worker probe jobs tied to those runs (`probe_job.kill_switch_auto_cancel` per job, metadata-only). Response and `soc.kill_switch.activated` audit metadata include `tenant_id`, `stopped_request_ids`, `cancelled_run_ids`, and `cancelled_probe_job_ids`. Legacy dev-json shape without `tenant_id` while active blocks all tenants. Clearing does not cancel runs or probe jobs. **Release blocker:** staging/live signed-worker fleet stop-path evidence — control-plane cancellation does not by itself prove external workers halt in flight. |

## Probe workers (internal, HMAC)

Authenticated with `x-probe-worker-id`, `x-probe-timestamp`, and `x-probe-signature` (HMAC over method, path, timestamp, raw body, and optional tenant id). Requires `ASTRANULL_PROBE_MODE=signed-worker` and `ASTRANULL_PROBE_WORKER_SECRET` (≥32 characters). In `ASTRANULL_PERSISTENCE_MODE=postgres`, workers must also include signed `x-probe-tenant-id` (the reference worker accepts `--tenant-id` / `ASTRANULL_PROBE_TENANT_ID`) so `/internal/probe/*` routes can use tenant-scoped Postgres repositories. Human OIDC JWTs, signed-session tokens, and dev headers are **not** accepted on these routes.

| Method | Path | Auth | Response |
|---|---|---|---|
| GET | `/internal/probe/jobs` | Probe worker HMAC | `{ jobs: SignedProbeJob[] }` — pending jobs are leased to the worker on fetch. |
| POST | `/internal/probe/jobs/:id/result` | Probe worker HMAC | `{ external_result, safety_attestation, metadata? }` metadata only. **`safety_attestation`** (alias **`execution_summary`**) is required: `{ requests_sent, duration_ms, worker_version?, region?, completed_at? }` must be within the signed job `constraints.max_requests` and `constraints.timeout_ms`. Errors: `400` `missing_safety_attestation` / `invalid_safety_attestation`; `422` `safety_attestation_exceeded`. Rejects `packet_payload` / `raw_packet`. Accepted results create probe timeline event and evidence including sanitized attestation. |

`POST /v1/test-runs` in `signed-worker` mode returns `probe_job` metadata (including `job_signature`) and leaves the run in `running` until the worker posts a result, then `collecting` for agent correlation.

In Postgres mode, probe worker leasing and result ingestion are wired through `runtime.services.probeJobs`, and customer `POST /v1/test-runs` / finalize orchestration is backed by `runtime.services.testRuns` in the same persistence boundary. **Release blockers** remain staging/live multi-region signed-worker fleet matrix evidence (`probe_fleet_matrix`), gateway load/abuse and concurrency isolation under realistic probe load (`gateway_load_abuse`, `postgres_concurrency`), and operator-attested acceptance of customer-declared targets by vector — not missing internal poll/result or test-run route wiring.

## Audit and observability

| Method | Path | Permission | Response |
|---|---|---|---|
| GET | `/v1/audit-log` | `audit:read` | Tenant audit entries (production: paginated, durable store). |
| GET | `/v1/observability` | `tenant:read` | JSON counters + inventory counts. |

## Role → permission map

See `src/contracts/roles.mjs` for the canonical list. SOC-only permissions: `soc:high_scale`, `soc:kill_switch`.

## Persistence modes

| Mode | When | Notes |
|---|---|---|
| `dev-json` | Default outside `NODE_ENV=production` | Local `.data/astranull-dev.json` for developer validation only. |
| `memory` | `ASTRANULL_NO_PERSIST=1` (non-production only) | Ephemeral store for tests and CI. |
| `postgres` | Default when `NODE_ENV=production` | Requires `ASTRANULL_DATABASE_URL` in production; startup **fails closed** if unset, migration preflight fails, or a required injected service is missing (no fake adapter; JSON store is never used while reporting `postgres`). `memory` and `dev-json` are refused in production. See [`db/README.md`](../db/README.md). |

Set explicitly with `ASTRANULL_PERSISTENCE_MODE`. `/ready` exposes `persistence` mode name only, never connection strings.

**Operator preflight:** `npm run postgres:startup-check` (`scripts/postgres-startup-check.mjs`) requires `ASTRANULL_DATABASE_URL`, pings Postgres, asserts latest migration applied (optional `--migrate` to apply pending migrations first). Connection strings are redacted in output. Runtime `postgres` mode initializes the same Postgres facade at startup and injects migrated control-plane services (catalog, auth, agents, agent updates, validation safe loop including events, notifications, evidence, findings, production release evidence, secrets, reports, state, probe jobs, high-scale/SOC, audit, retention). A route returns `postgres_route_not_wired` only when its required injected service is missing or that handler is not yet Postgres-backed. See [`docs/operator-local-runbook.md`](operator-local-runbook.md).

## Privacy retention (metadata)

Per-tenant `privacy_settings.metadata_retention_days` controls how long **metadata** is kept in `events`, `evidenceVault`, `reports`, and `notificationEvents`. Values are clamped to 1–3650 days on read/update.

Retention enforcement:

- Runs immediately when `PATCH /v1/tenants/current` changes privacy settings.
- Exported as `enforceMetadataRetentionForTenant(tenantId)` for scheduled jobs.

Purge rules:

- Deletes current-tenant rows in the four collections when `timestamp` / `created_at` is older than the retention window.
- Preserves other tenants, rows with invalid/missing timestamps, audit logs, findings, test runs, high-scale requests, authorization artifacts, SOC notes, targets, and agents.
- Emits audit entries with action `privacy.retention_purged` when rows are removed.

**Production gates still open:** audit and high-scale legal retention, regional residency, durable Postgres-backed purge at scale, and redaction coverage on every export path.

## Production release blockers (current implementation status)

| Capability | Verification evidence |
|---|---|
| OIDC/SSO and disabled header auth | Built-in `oidc-jwt` + JWKS verification (HTTPS JWKS URL in production, bounded fetch timeout, no redirect follow) plus production-default MFA claim enforcement (`ASTRANULL_OIDC_REQUIRE_MFA`, `ASTRANULL_OIDC_MFA_CLAIM`, `ASTRANULL_OIDC_MFA_VALUES`); **remaining:** real IdP tenant/role mapping, conditional access/session policy evidence, staging login flow, header-only negative test in prod-like deployment, audit/ops signoff |
| PostgreSQL persistence and RLS | Migration CI job + tenant isolation integration tests |
| Rate limiting and WAF | Service limiter in code; gateway/WAF + staging load/abuse test report |
| Encrypted secrets store | Security review + rotation drill |
| Signed probe jobs and external workers | Probe worker E2E in staging |
| Signed agent packages | Install matrix on supported distros |
| Governed high-scale adapter | SOC runbook exercise with partner sandbox |
| External notification providers | Configured channel test per tenant |

See [`docs/release-checklist.md`](release-checklist.md) for the full gate list.
