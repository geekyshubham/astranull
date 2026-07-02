# AstraNull

**AstraNull** is a no-access-first DDoS readiness validation platform.

It validates whether enterprise environments are ready for DDoS scenarios by combining:

- externally originated validation probes,
- customer-installed internal agents or canaries,
- target groups declared by the customer,
- SOC-approved high-scale simulation workflows,
- evidence-backed readiness scoring,
- operational UX for engineering, security, SOC, and executives.

AstraNull does **not** depend on customer cloud credentials in the default mode. It does **not** perform IP inventory discovery in the core product. Customers define the target groups they care about, install the AstraNull Agent in the right observation location, and AstraNull validates whether unwanted traffic reaches protected zones.

## Product promise

**AstraNull proves DDoS readiness for customer-declared targets without requiring cloud credentials or automatic IP inventory discovery.**

Evidence-backed verdicts, readiness scoring, and SOC-gated high-scale workflows show what was tested, what happened, and what to fix next.

## Current product decision

| Area | Decision |
|---|---|
| Product name | AstraNull |
| Discovery model | No automatic IP inventory discovery in core scope |
| Access model | No customer cloud/API access required by default |
| Agent model | Outbound-only control channel; no inbound management firewall rule required |
| High-scale tests | SOC-gated only; customer requests, SOC validates authorization and executes/coordinates |
| Detection model | Correlate external probe events with internal agent observations and health signals |
| First killer use case | Direct-origin bypass and protected-path validation |
| Optional WAF posture add-on | Feature-flagged WAF coverage, drift, CVE mitigation, remediation workflow, connector enrichment, and approval-gated candidate discovery; off by default and not required for core validation |

## Production readiness contract

AstraNull is built toward **production deployment**, not a disposable demo. Implementation agents and release owners must treat the following as hard gates before claiming production readiness:

| Gate | Owner area | Evidence required |
|---|---|---|
| Identity and access | Backend + Security | OIDC/SSO (or enterprise IdP), MFA policy, service accounts; **header-based tenant/role auth is developer validation only** and is a release blocker for production |
| Data plane | Backend + DB | PostgreSQL with versioned migrations from `db/schema.sql`, tenant RLS or equivalent, encryption at rest for secrets, backup/restore tested |
| Safe probes | Detection + Backend | Signed probe jobs, bounded rates, external probe workers — not in-process simulation stubs alone |
| Agent supply chain | Agent engineering | Signed deb/rpm/tarball/container artifacts, verified install paths, staged update/rollback |
| High-scale execution | SOC | Governed execution adapters only; legal authorization pack, provider approvals, kill switch validated end-to-end — **no raw attack tooling or unmanaged traffic generators** |
| Observability and ops | Backend + Security | Metrics, alerting, audit retention, DR runbook, on-call playbook |
| Quality | QA | `make verify` plus staging matrix; no `[x]` in `PROGRESS.md` for production-only work without checklist evidence |

**Do not mark complete unless:** linked implementation doc acceptance criteria are met, tests exist, audit logging exists for security-relevant actions, and the applicable rows in [`docs/release-checklist.md`](docs/release-checklist.md) are satisfied with recorded verification (CI run, runbook exercise, or security review artifact).

**Metadata-only evidence validators** (see [`src/contracts/productionReleaseEvidence.mjs`](src/contracts/productionReleaseEvidence.mjs)) check JSON shape and redaction rules; they do not prove staging execution or external signoff. Strict kinds (including `governed_adapter` and kill-switch drill evidence) surface contract failures as `invalid_fields` on validation and API `invalid_evidence_fields` responses. Use `npm run release:evidence:bundle` and `npm run release:staging-attestation` on operator-attested records; use `npm run release:gap-audit` to summarize open gates — it exits nonzero when `production_ready=false` (incomplete inventory and/or open checklist gates). `npm run release:sample-evidence` generates **rehearsal-only** fixtures for local walkthroughs — passing sample generation does not mean the product is production-ready.

Current **implementation status** (honest): a Node.js vertical slice runs locally for developer validation, and Postgres mode now initializes a fail-closed runtime with migrated catalog/auth/agent/validation services: safe test-run start/cancel, signed probe-job dispatch, probe-worker lease/result ingestion, agent observation ingestion (exact-once job transition before evidence write), probe/agent correlation, automatic and forced finalization, verdict and finding publication, metadata-only event ingestion with raw packet/payload/header rejection, notification management, evidence/finding reads, report/finding exports, encrypted secret vault, dashboard state summaries, guarded high-scale/SOC workflows, tenant kill switch, and audit-log reads. The **safe validation loop** (start -> probe -> observation -> finalization -> verdict -> finding) and SOC-gated high-scale route family are wired through Postgres service adapters; the whole product is **not** production-complete. **Production release blockers** remain live/staging Postgres acceptance and a DB-backed integration lane, tenant unit-of-work/concurrency isolation under load, production probe-worker fleet evidence and multi-region operations, certified governed high-scale execution/provider telemetry adapters, outbound notification providers, signed agent packages/fleet rollout evidence, and enterprise auth rollout plus compliance/report custody hardening where already tracked. See [`PROGRESS.md`](PROGRESS.md), [`docs/security/local-security-review.md`](docs/security/local-security-review.md), and the enterprise gap backlog in [`docs/product/08-enterprise-production-gap-backlog.md`](docs/product/08-enterprise-production-gap-backlog.md).

## Repository map

| File / folder | Purpose |
|---|---|
| `AGENTS.md` | Instructions for AI/software agents building AstraNull |
| `PROGRESS.md` | Granular implementation tracker with links to docs |
| `docs/product/` | Platform, scope, personas, data model, roadmap |
| `docs/ux/` | Pages, tabs, UX, visualizations, dashboard design |
| `docs/flows/` | User, SOC, agent, and execution flows |
| `docs/backend/` | Backend architecture, APIs, schemas, queues, orchestration |
| `docs/agent/` | Agent architecture, install, placement, packaging, detection modes |
| `docs/detection/` | Vector catalog, check library, correlation engine, scoring |
| `docs/soc/` | High-scale approval, SOC console, runbooks, evidence requirements |
| `docs/security/` | Security, privacy, compliance, safe testing guardrails |
| `docs/integrations/` | Optional WAF/CDN/cloud, remediation, SIEM, SOAR, and notification connector specs |
| `docs/agent-prompts/` | Agent task prompts, including the WAF add-on feed order |
| `docs/sources/` | Source/research maps used for optional capability inspiration |
| `docs/templates/` | Customer/provider approval and report templates |
| `docs/adr/` | Architecture decision records |
| `docs/api.md` | Production API contract + current developer validation behavior |
| `docs/operator-local-runbook.md` | Production operations overview + developer validation mode |
| `docs/release-checklist.md` | Production readiness gates (release blockers) |
| `docs/support-playbook.md` | Production support + developer validation troubleshooting |
| `docs/security/local-security-review.md` | Developer validation controls vs production gates |
| `db/` | PostgreSQL schema contract; migrations/RLS required for production |

## Developer validation mode (local)

Use this mode **only** for local development, CI, and pre-staging verification — not as the production target architecture.

- Declared target groups, environments, tenant privacy settings, bootstrap tokens (secret shown once), outbound agent process for validation, safe vector catalog (developer validation and CI may use bounded in-process probe simulation; production defaults to signed-worker mode, refuses explicit `ASTRANULL_PROBE_MODE=simulation`, and the reference worker CLI exists — **production release blocker:** staged probe-worker fleet evidence), correlation/verdicts/findings, evidence vault, event ingestion with idempotency, report JSON/Markdown/HTML export (redacted) with SHA-256 digest **custody** manifests (`json-key-sorted-v1` canonicalization; developer validation only — not KMS-signed immutable storage), finding export custody on JSON payloads, notification delivery records (metadata until external providers are configured), `/metrics` + `/v1/observability`, and SOC-gated high-scale workflow with authorization pack artifacts, scope hash, governed adapter boundary (dry-run until partner adapters are integrated), and live notes.
- **No** live unmanaged DDoS traffic, amplification, cloud credential access, or IP inventory discovery.

### API surface (selected)

| Area | Endpoints |
|---|---|
| Tenant / env | `GET/PATCH /v1/tenants/current`, `GET/POST /v1/environments`, `PATCH /v1/environments/:id` |
| Events / evidence | `POST /v1/events`, `GET /v1/evidence`, `GET /v1/evidence/:id` |
| Reports | `GET /v1/reports/:id/export?format=json\|markdown\|html`, `POST /v1/findings/:id/export` |
| High-scale | `POST/GET /v1/high-scale-requests/:id/artifacts`, SOC `.../artifacts/:id/review`, `.../notes`, `.../adapter-status` |
| Notifications | `GET/POST /v1/notifications` |
| Agent updates | `POST/GET /v1/agent-updates` (requires `distribution` URLs), `GET /v1/agents/:id/update` (`download` payload), `POST /v1/agents/:id/update-status`; trust keys `POST/GET /v1/agent-update-trust-keys` |
| Observability | `GET /metrics`, `GET /v1/observability` |

### Run (developer validation)

```bash
cd /Users/checkred_admin/Projects/astranull
npm start
```

Open [http://localhost:3000](http://localhost:3000). **Local developer validation** uses header auth (`x-tenant-id`, `x-user-id`, `x-role` in the sidebar) when `ASTRANULL_AUTH_MODE=dev-headers` (default outside production), or `signed-session` with `ASTRANULL_SESSION_SECRET` for tests and operator flows. **Production** defaults to built-in **`oidc-jwt`** (RS256 JWT verified against your IdP JWKS); startup refuses `dev-headers` and `signed-session` when `NODE_ENV=production`. Configure `ASTRANULL_OIDC_ISSUER`, `ASTRANULL_OIDC_AUDIENCE`, and `ASTRANULL_OIDC_JWKS_URL` (HTTPS in production; JWKS fetch uses a bounded timeout and does not follow redirects). Optional claim and JWKS tuning: `ASTRANULL_OIDC_TENANT_CLAIM`, `ASTRANULL_OIDC_ROLE_CLAIM`, `ASTRANULL_OIDC_USER_CLAIM`, `ASTRANULL_OIDC_JWKS_CACHE_TTL_MS`, `ASTRANULL_OIDC_JWKS_FETCH_TIMEOUT_MS` — see [`docs/api.md`](docs/api.md) and [`docs/release-checklist.md`](docs/release-checklist.md).

Optional validation agent (after creating a bootstrap token in Settings):

```bash
ASTRANULL_BOOTSTRAP_TOKEN='<secret>' node agents/linux/astranull-agent.mjs --api http://localhost:3000 --once
```

Packaged Linux agents default agent identity to `/var/lib/astranull/identity.json` (`0700` dir / `0600` file). Override with `--identity` or `ASTRANULL_AGENT_IDENTITY`. A dev checkout may use `.data/agent-identity.json` only when explicitly overridden (delete that file to re-register locally).

### Test

```bash
make verify
```

Individual targets: `make lint`, `make test-unit`, `make test-integration`, `make test-e2e-first-slice`, `make safety-check`.

Production-readiness evidence CLIs (metadata validation unless noted): `npm run container:evidence` (release kind `control_plane_container_release`), `npm run kms:vault:evidence`, `npm run release:staging-e2e:evidence`, `npm run release:compliance-legal:evidence`, `npm run soc:authorization-custody:evidence`, `npm run placement:staging:evidence`, `npm run gateway:load-abuse:evidence`, `npm run release:gap-audit`, and rehearsal-only `npm run release:sample-evidence`. See [`docs/operator-local-runbook.md`](docs/operator-local-runbook.md).

Latest local evidence (`make NODE=/opt/homebrew/bin/node verify`): lint, **1143 unit**, **82 integration**, **2 e2e**, `scripts/safety-check.mjs`, and `scripts/postgres-tenant-query-audit.mjs` with 0 findings.

Developer validation persists to `.data/astranull-dev.json` when `ASTRANULL_PERSISTENCE_MODE=dev-json` (default outside production) or uses in-memory store when `ASTRANULL_NO_PERSIST=1`. **Production** defaults to `postgres`, refuses to start without `ASTRANULL_DATABASE_URL`, blocks `memory`/`dev-json` when `NODE_ENV=production`, and now initializes `createPostgresRuntime()` at startup through `src/startup.mjs`. The server injects migrated Postgres services for tenant/catalog, bootstrap/service-account auth, agent control/auth, agent update lifecycle, validation reads, safe test-run start/cancel and signed probe dispatch, event ingestion, notification management, evidence reads, finding updates, encrypted secret vault, report/finding custody exports, dashboard state/readiness summaries (`runtime.services.state`, including repository-backed high-scale and kill-switch fields), probe worker lease/result ingestion (`runtime.services.probeJobs` with signed `x-probe-tenant-id` in Postgres mode), guarded high-scale/SOC workflows (`runtime.services.highScale`), metadata retention enforcement (`runtime.services.retention`), audit-log reads, and Postgres-backed RBAC denial auditing. In Postgres mode, routes return `postgres_route_not_wired` only when a required injected service for that route is missing or the handler is not yet Postgres-backed; they do not silently use the dev JSON store. Remaining production work is live/staging Postgres acceptance, tenant unit-of-work/concurrency hardening under load, certified governed high-scale execution/provider telemetry adapters, and fleet/provider production evidence.

## Start here

1. Read [`docs/product/01-platform-overview.md`](docs/product/01-platform-overview.md).
2. Read [`docs/product/02-scope-and-principles.md`](docs/product/02-scope-and-principles.md).
3. Read [`docs/agent/01-agent-architecture.md`](docs/agent/01-agent-architecture.md).
4. Read [`docs/detection/01-vector-catalog.md`](docs/detection/01-vector-catalog.md).
5. Use [`PROGRESS.md`](PROGRESS.md) as the build tracker.
6. Before any release claim, walk [`docs/release-checklist.md`](docs/release-checklist.md).

## Naming note

A basic web search should still be followed by proper trademark, domain, package-registry, and legal clearance before public launch. Product naming target: **AstraNull**.

## Deep docs added for build agents

| File | Purpose |
|---|---|
| `docs/product/07-end-to-end-platform-spec.md` | Full platform model, flows, pages, state machines, UX methods. |
| `docs/product/08-enterprise-production-gap-backlog.md` | Enterprise production gap backlog: P0/P1/P2 missing layers, agent confidence, vector expansion, high-scale lifecycle, provider notifications, ops, and compliance. |
| `docs/ux/12-full-wireframes-and-interactions.md` | Wireframes and page interaction details. |
| `docs/backend/10-agent-probe-detection-blueprint.md` | Backend services, detection, agent/probe lifecycle, token flows. |
| `docs/detection/12-vector-test-matrix.md` | Safe/SOC vector coverage matrix and completion rules. |
| `docs/progress-detailed.md` | Granular progress tracker with implementation links. |
| `docs/waf-posture-addon-master.md` | Optional WAF posture add-on summary. |
| `docs/progress-waf-posture-backlog.md` | Optional WAF posture backlog and release blockers. |
