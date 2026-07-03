# Security Model

## Security goals

| Goal | Requirement |
|---|---|
| Tenant isolation | No tenant can access another tenant's agents, runs, evidence, reports, or tokens. |
| Credential safety | Human **production** auth is built-in **`oidc-jwt`** (RS256 JWT + JWKS; production requires **HTTPS** `ASTRANULL_OIDC_JWKS_URL`; bounded `ASTRANULL_OIDC_JWKS_FETCH_TIMEOUT_MS`; JWKS fetch does not follow redirects; `dev-headers` and `signed-session` refused when `NODE_ENV=production`; MFA claim enforcement defaults on in production via `ASTRANULL_OIDC_REQUIRE_MFA`, `ASTRANULL_OIDC_MFA_CLAIM`, and `ASTRANULL_OIDC_MFA_VALUES`). Bootstrap tokens and service account secrets are stored as salted hashes only; plaintext shown once on create and on `POST /v1/service-accounts/:id/rotate` (old bearer invalidates immediately). Newly issued `ast_` / `svc_` secrets embed tenant and record id hints (`ast_v1.…` / `svc_v1.…`) for Postgres lookup under forced RLS; verification still uses the full secret against stored salt/hash (legacy opaque dev tokens remain supported). Service-account `svc_` tokens are a separate automation boundary and work independently of human auth mode. Integration/webhook/certificate material uses tenant-scoped **AES-256-GCM** secret envelopes (`src/lib/secrets.mjs`, `src/services/secretVault.mjs`, `src/persistence/postgres/secretVaultRepository.mjs`); list and audit responses are metadata-only. **Admin API** (`GET/POST /v1/secrets`, `POST /v1/secrets/:id/rotate`) exposes metadata and redacted envelopes only—no public decrypt route; plaintext is accepted on create/rotate and never returned. Agent identities combine `agc_v1.…` bearer credentials with production gateway mTLS fingerprint binding: `ASTRANULL_AGENT_IDENTITY_MODE` defaults to `gateway-mtls` in production and refuses bearer-only mode; agent routes require the forwarded client certificate fingerprint to match the registered agent fingerprint. Agent update releases require Ed25519-signed manifests verified server-side before persistence; release/rollback signing keys must match an active tenant trust key (`POST/GET /v1/agent-update-trust-keys`, revoke route; `untrusted_signing_key` otherwise). Agents can preflight manifests, apply signed packages on the host (`--verify-update-manifest`, `--apply-update-manifest` → `current.json`), and download-then-apply via `--download-and-apply-update` (HTTPS-only by default; hardened localhost/test flag; size/timeout caps; no redirect follow). Release creation requires control-plane `distribution: { manifest_url, signature_url, artifact_url }` (absolute HTTPS; audit excludes URLs); poll returns `download`. **Production blockers:** IdP tenant/role mapping and conditional-access/session-policy signoff, gateway/proxy mTLS deployment and spoofing controls, trust-key ceremony/custody/rotation/revocation drill, installer/update-daemon enforcement, hosted artifact custody/CDN ops runbooks and staging evidence, unattended daemon restart / fleet rollout drills. |
| Least privilege | Users/agents/services receive only required permissions. |
| Auditability | Sensitive actions create immutable audit records. |
| Safe testing | Checks are rate-limited, scoped, and classified. |
| Privacy | Packet payloads are not uploaded by default. |
| API abuse resistance | Service-layer fixed-window rate limits on `/v1` and `/internal` routes; production cannot disable limits. |
| Internal management isolation | AstraNull staff-only management routes use staff identity, MFA, staff roles, audit, and optional network/edge restrictions; customer tenant roles never authorize `/internal/admin` or SOC execution. |

## Rate limiting and defense in depth

The control plane enforces an in-process fixed-window limiter keyed by the connection’s remote address (`req.socket.remoteAddress`). By default, inbound `X-Forwarded-For` and `X-Real-IP` are **not** trusted, so a direct client cannot spoof those headers to evade per-client limits. Set `ASTRANULL_TRUST_PROXY_HEADERS=1` only when the API sits behind a **trusted reverse proxy or load balancer** that strips or overwrites spoofed forwarding headers and appends the real client IP. Exceeded requests receive HTTP `429` with `error: rate_limited` and a `Retry-After` header. Stale per-client buckets are pruned as windows advance so long-lived processes do not accumulate unbounded keys. Liveness (`/health`), readiness (`/ready`), static assets, and `/metrics` are not subject to this API limiter.

Operators should still place **gateway or WAF rate limits** in front of the API in production. Edge limits complement the service-layer limiter and remain required defense-in-depth against volumetric abuse.

## OIDC production-auth preflight evidence (offline)

Before promoting a production-like control-plane image or attaching auth evidence to `/v1/production-release-evidence`, operators can capture **offline** negative-test proof that unsafe human-auth posture is refused. `scripts/oidc-prod-auth-preflight.mjs` reads `process.env` only: it does **not** fetch JWKS or contact a live IdP.

Export the same production OIDC variables used at runtime (`NODE_ENV=production`, `ASTRANULL_AUTH_MODE=oidc-jwt` or default, `ASTRANULL_OIDC_ISSUER`, `ASTRANULL_OIDC_AUDIENCE`, **HTTPS** `ASTRANULL_OIDC_JWKS_URL`, encryption key, database URL, probe worker secret), then run:

```bash
NODE_ENV=production \
ASTRANULL_OIDC_ISSUER='https://idp.example/oauth2/default' \
ASTRANULL_OIDC_AUDIENCE='astranull-api' \
ASTRANULL_OIDC_JWKS_URL='https://idp.example/oauth2/default/v1/keys' \
ASTRANULL_SECRET_ENCRYPTION_KEY='…' \
ASTRANULL_DATABASE_URL='postgresql://…' \
ASTRANULL_PROBE_WORKER_SECRET='…' \
node scripts/oidc-prod-auth-preflight.mjs --out output/oidc-prod-auth-preflight.json
```

The JSON manifest is metadata-only: pass/fail checks, redacted issuer/JWKS URLs (query strings and credentials stripped), MFA claim posture, and synthetic offline probes that prove `dev-headers`, `signed-session`, and HTTP JWKS URLs are rejected under `NODE_ENV=production`. The script exits nonzero when required checks fail. Passing preflight does not replace staging login flow, header-only API negative tests, IdP tenant/role mapping signoff, or security/ops approval.

## Secret provider rotation drill evidence (offline)

Before promoting production envelope key rotation or attaching rotation drill proof to `/v1/production-release-evidence`, operators capture **metadata-only** drill evidence with `scripts/secret-rotation-drill-evidence.mjs`. The validator does **not** call KMS/HSM APIs, decrypt envelopes, or expose decrypt routes—it checks structural proof only.

Prepare a JSON drill record with key reference before/after (plus provider reference), tenant count, envelope re-key totals, any failed rotations (each must be explicitly accepted with an acceptance reference), rollback plan and rollback test reference, operator and security signoff references, audit event ids, and a `zero_plaintext_exposure` attestation (`attested: true`). Then run:

```bash
node scripts/secret-rotation-drill-evidence.mjs \
  --input output/secret-rotation-drill-input.json \
  --out output/secret-rotation-drill-evidence.json
```

The manifest is redacted metadata: drill summary counts and references, validation status, and caveats. The script rejects plaintext secrets, ciphertext, auth tags, database URLs, raw logs, tokens, credential fields, and other forbidden keys; it exits nonzero when signoff is missing or failed rotations are not accepted. Passing local validation does not replace live KMS/vault operator evidence, envelope re-key verification in staging, or security approval.

## Agent gateway mTLS evidence (offline)

Production agent routes combine `agc_v1.…` bearer credentials with gateway-terminated mTLS: the proxy must forward a verified client certificate SHA-256 fingerprint using only the platform-allowed header names (`x-client-cert-fingerprint`, `x-astranull-client-cert-fingerprint`, `x-forwarded-client-cert-sha256`), strip untrusted client-supplied fingerprint headers, and match the registered agent fingerprint.

Operators capture **metadata-only** deployment and drill proof with `scripts/agent-mtls-gateway-evidence.mjs` / `npm run agent:mtls:evidence` before recording `agent_mtls_gateway` release evidence. The JSON input references gateway/proxy configuration, PKI issuance runbooks, spoofing controls, staging registration/heartbeat custody URIs, rotation/revocation drill references, and security signoff — not PEM bodies, private keys, tokens, passwords, database URLs, ciphertext, raw logs, or HTTP headers/bodies. The script exits nonzero when required metadata is missing or forbidden content is present. Passing validation does not replace live gateway configuration review, PKI ceremony execution, or fleet staging proof.

## Edge protection baseline

Production API and UI traffic must sit behind a provider-neutral edge control: WAF, API gateway, CDN edge, managed reverse proxy, or equivalent enterprise gateway. The canonical baseline is `src/contracts/edgeProtectionBaseline.mjs`; it requires metadata evidence for TLS termination, host allowlists, request/header/body size limits, bot and credential-stuffing defenses, managed WAF or equivalent rule families, origin shielding, edge logging/audit routing, health endpoint handling, security headers, and proxy-header spoofing controls.

`validateEdgeProtectionEvidence()` accepts release-review metadata only. It rejects raw headers, bodies, packet payloads, logs, credentials, tokens, and secrets. Passing local validation does not prove deployment; production signoff still requires the actual gateway/WAF configuration, staging abuse/load validation, alert/log routing evidence, and security approval.

## Threats to address

| Threat | Control |
|---|---|
| Leaked bootstrap token | Short expiry, max registrations, optional CIDR, revocation, audit. |
| Fake agent registration | Token validation, identity issuance, tenant binding. |
| Cross-tenant event injection | Authenticated agent identity, production gateway-mTLS fingerprint binding, and tenant validation. |
| Customer starts high-scale test directly | API separation and SOC-only internal execution. |
| Unsafe target testing | Declared targets only, ownership/authorization for high-scale. |
| Evidence tampering | Immutable event log, signed reports, audit trail. |
| Tampered agent update packages | Control-plane rejects unsigned or signature-invalid manifests; safe artifact basenames and SHA-256/size checks; manifest signing key must match active tenant trust key; required HTTPS `distribution` URLs with `artifact_url` basename match; agent-side verifier, `--apply-update-manifest`, and `--download-and-apply-update` reject key/signature/artifact mismatch, unsafe paths, symlinks, oversized downloads, and redirect-based fetch tricks. **Remaining:** production trust-key lifecycle operations, installer enforcement on hosts, hosted artifact custody/CDN ops evidence, unattended daemon restart and staging fleet rollout drills. |
| Sensitive packet leakage | Metadata-only default, redaction, configurable retention. |
| API abuse / credential stuffing | Service-layer rate limits, gateway/WAF throttling, audit on auth failures. |
| Customer accesses internal management | Staff-only auth boundary, separate staff roles, direct-route denial, optional admin host/network allowlist, and audit on denied access. |

## RBAC enforcement

Every API should check:

- authenticated principal,
- tenant membership,
- role permission,
- service account scope (when principal is `service_account:<id>`),
- staff principal and staff role for `/internal/*` routes,
- resource ownership,
- feature entitlement,
- safety/risk class permission.

## Audit events

Audit these actions:

- user login/logout,
- invite/role changes,
- public sign-up request submit/review/approve/reject/provision,
- internal tenant lifecycle changes and subscription/entitlement changes,
- staff support actions including invite resend, user disable, role correction, and any approved support access,
- bootstrap token create/revoke,
- service account create/revoke/rotate and failed service-account authentication (metadata must not include any substring of bearer secrets; rotation audit may include role/scopes only; use non-secret reasons such as `invalid_token`, `revoked`, or `expired` only),
- agent register/revoke,
- agent update release create and rollback request (`agent_update.release_created`, `agent_update.rollback_requested`),
- agent update trust key add and revoke (`agent_update.trust_key_added`, `agent_update.trust_key_revoked` — metadata: key id, name, fingerprint; no public key material),
- agent update status from agent credential (`agent_update.status_recorded` — metadata: agent id, release id, status, action; no manifest secrets),
- target group changes,
- check enable/disable,
- test run start/cancel,
- finding risk acceptance,
- report export,
- high-scale request/approval/start/stop/close,
- integration credential changes (`secret.stored`, `secret.rotated`, `secret.decrypted_for_use` — metadata only, no plaintext or ciphertext),

## Completion criteria

Security model is complete when unauthorized access, unmanaged high-scale execution, token misuse, and evidence tampering are blocked and tested.
