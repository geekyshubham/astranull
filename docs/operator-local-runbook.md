# Operator runbook

Production operations for AstraNull plus **developer validation mode** for local engineering. Production sections are release blockers until [`docs/release-checklist.md`](release-checklist.md) items are evidenced.

## Production operations (target)

### Control-plane container artifact

Root [`Dockerfile`](../Dockerfile) packages the API and static UI (`src/`, `apps/web/`). Build context is trimmed via [`.dockerignore`](../.dockerignore).

```bash
docker build -t astranull-control-plane:local .
```

Record local build/inspect/scan evidence without embedding secrets:

```bash
npm run container:evidence -- \
  --image astranull-control-plane:local \
  --scanner trivy \
  --require-scan \
  --promotion-target staging \
  --commit "$(git rev-parse HEAD)" \
  --out output/container-release-evidence.json
```

The script builds from the root `Dockerfile`, inspects the resulting image ID/repo digests, optionally runs `trivy` or `grype`, and writes safe metadata only for release kind **`control_plane_container_release`**. This evidence file is not a production promotion by itself; release CI must still attach scanner output, registry digest, signing/provenance, runtime secret configuration, Postgres acceptance, and staging signoff.

Run (requires production secrets and a migrated Postgres runtime boundary):

```bash
docker run --rm -p 3000:3000 \
  -e ASTRANULL_DATABASE_URL='postgresql://user:pass@host:5432/astranull' \
  -e ASTRANULL_OIDC_ISSUER='https://idp.example/oauth2/default' \
  -e ASTRANULL_OIDC_AUDIENCE='astranull-api' \
  -e ASTRANULL_OIDC_JWKS_URL='https://idp.example/oauth2/default/v1/keys' \
  astranull-control-plane:local
```

With `NODE_ENV=production` (the image default), startup requires `ASTRANULL_DATABASE_URL`, **`oidc-jwt`** human auth (`ASTRANULL_OIDC_ISSUER`, `ASTRANULL_OIDC_AUDIENCE`, `ASTRANULL_OIDC_JWKS_URL` — **HTTPS**; optional `ASTRANULL_OIDC_JWKS_FETCH_TIMEOUT_MS` for bounded JWKS fetch; JWKS HTTP **redirects are not followed**), `ASTRANULL_SECRET_ENCRYPTION_KEY`, and signed-worker probe credentials. `dev-headers` and `signed-session` are refused in production, and the process must not silently fall back to dev JSON or header auth.

Production startup now initializes `createPostgresRuntime()` and injects migrated services into `createServer` (catalog, auth, agents, agent updates, validation safe loop, events, notifications, evidence, findings, production release evidence, secrets, reports, state, probe jobs, high-scale/SOC, audit, retention). Postgres mode returns `503 postgres_route_not_wired` only when a route's required injected service is missing or that route handler is not yet Postgres-backed; handlers must not silently fall back to the dev JSON store. Required production env also includes `ASTRANULL_SECRET_ENCRYPTION_KEY` and, unless `ASTRANULL_PROBE_MODE` is explicitly changed outside production, a 32+ character `ASTRANULL_PROBE_WORKER_SECRET`.

Production feature toggles are fail-closed:

| Variable | Production default | Production rule |
|---|---|---|
| `ASTRANULL_PROBE_MODE` | `signed-worker` | Requires `ASTRANULL_PROBE_WORKER_SECRET`; `simulation` is developer/CI only and startup refuses it when `NODE_ENV=production`. |
| `ASTRANULL_HIGH_SCALE_ADAPTER_MODE` | `governed-adapter` | `dry-run` is refused in production; use `disabled` to block high-scale start while preserving request intake/review. |
| `ASTRANULL_AGENT_IDENTITY_MODE` | `gateway-mtls` | `bearer` is refused in production; gateway/proxy must forward the verified client certificate SHA-256 fingerprint. |
| `ASTRANULL_RATE_LIMIT_DISABLED` | unset | `1` is refused in production. |

For local engineering with HMAC sessions (non-production), set `NODE_ENV=development` (or unset production) and `ASTRANULL_AUTH_MODE=signed-session` with `ASTRANULL_SESSION_SECRET` (≥32 characters).

For local engineering, use **developer validation mode** (`npm start` or `node src/index.mjs` without production env) and `make verify` (Node-only; no npm required on PATH).

CI runs the same verification steps as `make verify` in [`.github/workflows/ci.yml`](../.github/workflows/ci.yml).

### Production evidence contracts

Release evidence for third-party security review, staging/prod migration application, and production-runbook staging exercises must satisfy `src/contracts/productionReleaseEvidence.mjs`. Evidence is metadata-only: use URIs/references to controlled artifacts, not raw logs, connection strings, credentials, tokens, request bodies, headers, or payloads.

Operators can validate and bundle release-evidence records before submitting them through `/v1/production-release-evidence`:

```bash
npm run release:evidence:bundle -- \
  --input output/staging-release-evidence-input.json \
  --release-id rel_2026_07_02 \
  --out output/staging-release-evidence-bundle.json
```

Use `--validate-only` in staging CI or preflight jobs to fail fast without writing an artifact. The bundle utility validates every record with the production evidence contract, drops unknown top-level input fields, and writes metadata-only records plus release caveats. It does not replace security, DB/operator, legal, or release-manager signoff.

Aggregate attestation (still metadata-only; `production_ready: true` means profile inventory is complete — accepted, contract-valid required kinds — not production promotion signoff):

```bash
npm run release:staging-attestation -- \
  --input output/staging-release-evidence-bundle.json \
  --out output/staging-readiness-attestation.json
```

**Local production-like stack** (Docker Compose Postgres + control-plane on `127.0.0.1:3000`):

```bash
npm run staging:local:up
npm run staging:local:attest
```

`staging:local:attest` runs seed, Postgres verify, smoke, E2E matrix, evidence collection (31 kinds), `release:gap-audit:local`, `release:staging-attestation:local`, and API evidence submit. Expect `production_ready=true` when checklist gates are closed.

Cross-check attestation, required kinds from `src/contracts/productionReleaseEvidence.mjs`, and open rows in `docs/release-checklist.md`. The audit exits **nonzero** when `production_ready=false` (missing/invalid inventory and/or open checklist gates). Strict evidence kinds (including `governed_adapter` and kill-switch drill contracts) surface failures as `invalid_fields` during bundle validation and on `/v1/production-release-evidence` as `invalid_evidence_fields`.

```bash
npm run release:gap-audit -- \
  --evidence output/staging-release-evidence-bundle.json \
  --release-id rel_2026_07_02 \
  --out output/production-readiness-gap-audit.json
```

**Rehearsal-only samples** (local operator walkthrough; not staging signoff):

```bash
npm run release:sample-evidence -- --out-dir output --release-id rel-sample-rehearsal
```

Generated artifacts are marked `rehearsal_only: true`. Replace every record with real staging/security/SOC/legal/provider/KMS evidence before API submission.

Additional metadata-only validators (npm aliases → release kinds in parentheses):

| npm script | Release kind |
|---|---|
| `npm run container:evidence` | `control_plane_container_release` |
| `npm run kms:vault:evidence` | `kms_vault_posture` |
| `npm run release:staging-e2e:evidence` | `staging_e2e_matrix` |
| `npm run release:compliance-legal:evidence` | `compliance_legal_signoff` |
| `npm run soc:authorization-custody:evidence` | `authorization_custody` |
| `npm run placement:staging:evidence` | `placement_confidence_staging` |
| `npm run gateway:load-abuse:evidence` | `gateway_load_abuse` |
| `npm run rollback:evidence` | `rollback_fixforward` |
| `npm run release:evidence:bundle` | (multi-kind bundle validation) |
| `npm run release:staging-attestation` | (profile inventory attestation) |
| `npm run release:gap-audit` | (inventory + checklist gap summary) |

See `package.json` scripts and `src/contracts/productionReleaseEvidence.mjs` for additional kind validators (OIDC preflight, edge protection, SOC drills, probe fleet matrix, Postgres concurrency, and others).

### Database migrations (operators)

Apply versioned migrations before production Postgres startup:

```bash
ASTRANULL_DATABASE_URL='postgresql://user:pass@host:5432/astranull' node scripts/migrate-postgres.mjs
```

This applies versioned DDL from [`db/migrations/`](../db/migrations/). Control-plane startup also verifies the latest migration through `createPostgresRuntime`; use `scripts/postgres-startup-check.mjs` before deploys and run the gated acceptance harness for staging evidence.

### Postgres acceptance harness (staging evidence)

Repeatable live-database checks for migrations, forced RLS, transaction-local tenant context, and tenant-consistent composite FKs. **Not** part of default `make verify`; **does not** start the control plane — use `ASTRANULL_PERSISTENCE_MODE=postgres` startup (or gated `postgres-runtime-smoke`) for runtime wiring evidence. Staging/live acceptance execution remains a release blocker.

| Variable | Required | Meaning |
|---|---|---|
| `ASTRANULL_POSTGRES_ACCEPTANCE` | To run checks | Must be exactly `1` or the script skips (exit 0). |
| `ASTRANULL_DATABASE_URL` | When acceptance is `1` | PostgreSQL connection string (never logged by the script). |
| `ASTRANULL_REQUIRE_POSTGRES_ACCEPTANCE` | Optional | If `1` and acceptance is not enabled, exit nonzero (for gated CI/staging jobs). |

```bash
ASTRANULL_POSTGRES_ACCEPTANCE=1 \
ASTRANULL_DATABASE_URL='postgresql://user:pass@host:5432/astranull' \
node scripts/postgres-acceptance.mjs
```

Equivalent: `npm run postgres:acceptance` with the same environment. Success prints `postgres-acceptance: ok` and `latest_version`.

### Postgres startup preflight (verify-only)

Operator check before promoting a release or after DB maintenance. It verifies connectivity and latest migration state; it does not replace the app startup path or the gated staging acceptance harness.

| Flag / env | Meaning |
|---|---|
| `ASTRANULL_DATABASE_URL` | Required — PostgreSQL connection string (redacted in script output). |
| (default) | Verify-only: parse bounded pool config, ping Postgres, assert latest migration version applied. |
| `--migrate` | Apply pending migrations via the same runner as `migrate-postgres.mjs`, then run verify-only checks. |

```bash
ASTRANULL_DATABASE_URL='postgresql://user:pass@host:5432/astranull' \
node scripts/postgres-startup-check.mjs
```

With migrations first:

```bash
ASTRANULL_DATABASE_URL='postgresql://user:pass@host:5432/astranull' \
node scripts/postgres-startup-check.mjs --migrate
```

Equivalent: `npm run postgres:startup-check` (pass `--` before `--migrate` when using npm). Unit coverage: `tests/unit/postgres-startup-check.test.mjs`.

### WAF orchestrator runner (externally scheduled)

**Operator surfaces:** In developer validation, use the `#waf-posture` **validation-plan operator panel** (list all/scheduled plans; create/execute/cancel safe plans) together with this CLI. The UI is for local engineering visibility and manual ticks; it does **not** replace external scheduling in staging/production.

Postgres operator CLI for runnable/scheduled WAF validation plans. **Not** a daemon—wire it to cron, a Kubernetes CronJob, CI, or an on-call runbook. Requires `ASTRANULL_DATABASE_URL`, explicit tenant scope, and signed-worker probe mode (`ASTRANULL_PROBE_MODE=signed-worker` and a 32+ character `ASTRANULL_PROBE_WORKER_SECRET`). Apply mode calls `executeValidationPlan` once per scheduled plan per run: safe continuation (full assets×scenarios queue capped by plan `max_concurrent`; at most one new `startTestRun` per plan per tick because of the signed-worker active-run gate; plans may stay `running` until later runs finish `delegated_jobs`). Concurrent API and runner ticks coordinate through Postgres execution leases on `waf_validation_plans` and `waf_retest_requests` (`execution_lock_token`, `execution_lock_expires_at`): claim/finish lifecycle-gate eligible plan states and retest statuses; claim-before-side-effect; default TTL at least plan safe-run `timeout_ms` + 30s buffer (or larger configured `executionLeaseMs`). On a **claim miss**, execute paths **re-read** the plan/retest and return lifecycle errors (`validation_plan_cancelled`, `validation_plan_already_completed`, `waf_retest_already_delegated`, `waf_retest_already_completed`) rather than treating every miss as in-progress; reserve `409 waf_orchestrator_execution_in_progress` for true active-lease conflicts. Validation-plan cancel atomically clears active leases and best-effort cancels delegated safe runs recorded on the returned cancelled plan row snapshot (`delegated_jobs` on `POST /v1/waf/validation-plans/:id/cancel` → `200 { validation_plan }`; control-plane `cancelTestRun`—metadata only, not traffic generation); a stale executor that loses its finish token compensating-cancels any just-started safe run and cannot resurrect a cancelled plan; if **finish throws** after `startTestRun`, the service compensating-cancels `started_run_ids` and **best-effort** releases the execution lease before returning `422 validation_plan_execution_failed`. Developer-validation hardened only: a **hard process crash** after `startTestRun` but before `delegated_jobs` persistence remains crash-recovery/staging evidence open—no production at-most-once delegation claim. Success means delegation recorded in metadata-only output, not final WAF verdict or coverage closure. Staging scheduling/execution evidence for this runner, hard-crash resilience evidence, live/staging DB acceptance, provider connector workers, and WAF security/observability/release signoff remain open—not production-ready until closed.

Dry run (list scheduled plans, no execute):

```bash
ASTRANULL_DATABASE_URL='postgresql://user:pass@host:5432/astranull' \
ASTRANULL_PROBE_MODE=signed-worker \
ASTRANULL_PROBE_WORKER_SECRET='…' \
npm run waf:orchestrator:runner -- --tenant-id tenant-a --dry-run
```

Apply run with optional metadata-only summary:

```bash
ASTRANULL_DATABASE_URL='postgresql://user:pass@host:5432/astranull' \
ASTRANULL_PROBE_MODE=signed-worker \
ASTRANULL_PROBE_WORKER_SECRET='…' \
npm run waf:orchestrator:runner -- \
  --tenant-ids-file ./staging-tenant-ids.json \
  --out ./waf-orchestrator-run.json
```

`--tenant-id` and `--tenant-ids-file` are mutually exclusive. Without signed-worker mode the runner fails closed before opening a Postgres runtime.

### WAF drift runner (externally scheduled)

Operator CLI for scheduled connector/posture drift scans. **Not** a daemon—wire it to cron, a Kubernetes CronJob, CI, or an on-call runbook. Compares stored connector and posture snapshots only; **no outbound WAF/provider calls**.

Developer validation (dev-json store, default when `ASTRANULL_DATABASE_URL` is unset):

```bash
ASTRANULL_WAF_POSTURE_ENABLED=1 \
npm run waf:drift:runner -- --tenant-id ten_demo
```

Scan every tenant with WAF assets (default when tenant scope is omitted):

```bash
ASTRANULL_WAF_POSTURE_ENABLED=1 \
npm run waf:drift:runner -- --all-tenants --out ./waf-drift-run.json
```

Dry run (scope summary only; no drift events or scan results persisted):

```bash
ASTRANULL_WAF_POSTURE_ENABLED=1 \
npm run waf:drift:runner -- --tenant-ids-file ./staging-tenant-ids.json --dry-run
```

API equivalents (dev-json mode; `waf:run` / `waf:read`):

- `POST /v1/waf/drift-scans/run` → `{ scan_result }` for the authenticated tenant
- `GET /v1/waf/drift-scans/latest` → `{ scan_result }` (or `null` when none yet)

Postgres mode is selected automatically when `ASTRANULL_DATABASE_URL` is set and requires `runtime.services.wafDrift` (returns `503 postgres_route_not_wired` until that adapter is injected). `--tenant-id` and `--tenant-ids-file` are mutually exclusive.

### Notification retry scheduler (always-on or cron-friendly)

Operator scheduler for due notification delivery retries. Processes the latest `provider_retry_scheduled` attempts whose `next_retry_at` is on or before the tick timestamp. **Default delivery mode is metadata-only** (no outbound webhook/email/Slack/Teams I/O). Opt-in provider delivery requires explicit `ASTRANULL_NOTIFICATION_DELIVERY_MODE` configuration and staging evidence before production enablement.

Developer validation (dev-json store, default when `ASTRANULL_DATABASE_URL` is unset):

```bash
npm run notification:retry:scheduler -- --once --tenant-id ten_demo
```

Long-running loop (sleep between ticks; exits on `SIGINT`/`SIGTERM`):

```bash
ASTRANULL_NOTIFICATION_RETRY_INTERVAL_MS=60000 \
npm run notification:retry:scheduler -- --all-tenants
```

Cron-friendly single tick with metadata-only summary:

```bash
ASTRANULL_DATABASE_URL='postgresql://user:pass@host:5432/astranull' \
npm run notification:retry:scheduler -- \
  --once \
  --tenant-ids-file ./staging-tenant-ids.json \
  --out ./notification-retry-scheduler-tick.json
```

Dry run (summarize due retries without persisting attempts or sending providers):

```bash
npm run notification:retry:scheduler -- --once --tenant-id ten_demo --dry-run
```

`--tenant-id` and `--tenant-ids-file` are mutually exclusive. When tenant scope is omitted, the scheduler defaults to `--all-tenants` (every tenant with notification ledger data). Interval defaults to `60000` ms and is bounded `5000`–`300000` ms via `ASTRANULL_NOTIFICATION_RETRY_INTERVAL_MS` or `--interval-ms`. Postgres mode is selected automatically when `ASTRANULL_DATABASE_URL` is set and requires `runtime.services.notifications.processDueNotificationRetries`. Unit coverage: `tests/unit/notification-retry-scheduler.test.mjs`.

### Connector poll runner (externally scheduled)

Operator CLI for scheduled outbound read-only WAF/CDN connector polls. **Not** a daemon—wire it to cron, a Kubernetes CronJob, CI, or an on-call runbook. Polls enabled connectors with vault-backed `secret_id`, bounded concurrency, provider retry/backoff, and metadata-only health updates. Manual `POST /v1/connectors/:id/poll` remains available for on-demand operator or UI ticks.

Developer validation (dev-json store, default when `ASTRANULL_DATABASE_URL` is unset):

```bash
ASTRANULL_WAF_POSTURE_ENABLED=1 \
ASTRANULL_SECRET_ENCRYPTION_KEY='<base64-32-byte-key>' \
npm run connector:poll:runner -- --tenant-id ten_demo
```

Poll every tenant with outbound-eligible connectors (default when tenant scope is omitted):

```bash
ASTRANULL_WAF_POSTURE_ENABLED=1 \
ASTRANULL_SECRET_ENCRYPTION_KEY='<base64-32-byte-key>' \
npm run connector:poll:runner -- --all-tenants --out ./connector-poll-run.json
```

Dry run (eligible connector scope only; no outbound provider calls):

```bash
ASTRANULL_WAF_POSTURE_ENABLED=1 \
npm run connector:poll:runner -- --tenant-ids-file ./staging-tenant-ids.json --dry-run
```

Optional bounded parallelism: `--concurrency <n>` or `ASTRANULL_CONNECTOR_POLL_CONCURRENCY` (default `4`). Provider retry attempts: `ASTRANULL_CONNECTOR_POLL_MAX_ATTEMPTS` (default `3`). Postgres mode is selected automatically when `ASTRANULL_DATABASE_URL` is set and requires `runtime.services.wafPosture.pollConnector()`. `--tenant-id` and `--tenant-ids-file` are mutually exclusive.

### Deployment expectations

- API and UI behind enterprise SSO/OIDC — no header-based impersonation in production
- API and UI behind WAF, API gateway, CDN edge, managed reverse proxy, or equivalent edge control; release evidence must satisfy `src/contracts/edgeProtectionBaseline.mjs` without raw headers, bodies, packet payloads, logs, tokens, or secrets
- PostgreSQL with migrations from [`db/migrations/`](../db/migrations/) (contract in [`db/schema.sql`](../db/schema.sql)); use `node scripts/migrate-postgres.mjs` or `npm run postgres:startup-check` (optional `--migrate`) for operator preflight in staging/prod — production app startup is fail-closed for any route family that is not yet backed by a migrated Postgres service
- Secrets in approved vault/KMS; bootstrap and agent credentials rotated per policy
- Agent control channel behind gateway mTLS; forwarded cert fingerprint must match the registered agent fingerprint
- Probe workers and SOC execution adapters on governed networks only; in Postgres mode, probe workers must send signed `x-probe-tenant-id` via `--tenant-id` or `ASTRANULL_PROBE_TENANT_ID`
- Metrics scraped per [`docs/backend/08-observability.md`](backend/08-observability.md); alerts routed to on-call

### Production happy path (customer)

1. Customer authenticates via IdP; tenant and roles mapped from SSO claims.
2. Customer declares target groups and targets (no automatic IP discovery).
3. Admin creates bootstrap token; customer installs **signed** agent package outbound-only to AstraNull API.
4. Safe checks run via signed probe jobs; agent observations correlate to verdicts and findings.
5. Reports exported with redaction; audit log retained per retention policy.
6. High-scale tests: customer submits request and authorization artifacts; **SOC only** approves, schedules, starts governed adapter, monitors, stops, closes.

### Production SOC high-scale

1. Verify authorization pack complete and provider approvals on file.
2. Schedule window inside approved maintenance; confirm scope hash matches declared targets.
3. Start **governed** execution adapter; monitor health, external availability, agent observations.
4. Kill switch and stop paths tested each release; exercise evidence must satisfy `src/contracts/killSwitchValidation.mjs` and post-test report archived. In Postgres mode, activating the tenant kill switch auto-stops governed high-scale runs, auto-cancels in-flight safe test runs, and cancels open signed-worker probe jobs for those runs. Each cancelled probe job audits `probe_job.kill_switch_auto_cancel` (metadata-only); the API response and `soc.kill_switch.activated` audit include `cancelled_probe_job_ids` alongside `stopped_request_ids` and `cancelled_run_ids`. That control-plane behavior is implemented and unit-tested; **staging/live signed-worker fleet stop validation is still a release blocker** — workers must be shown halting in flight per `npm run soc:kill-switch:evidence` / `probe:fleet:matrix:evidence`, not inferred from DB job state alone.

### Incident and rollback

- Follow [`docs/support-playbook.md`](support-playbook.md) severity table and on-call contacts (must be filled before GA).
- Rollback: migration forward-fix first, `ASTRANULL_HIGH_SCALE_ADAPTER_MODE=disabled` for high-scale stop-the-line, probe-worker mode/secret rotation for worker issues, and SOC kill switch first for active high-scale windows and in-flight safe runs (Postgres: also marks open probe jobs cancelled and returns `cancelled_probe_job_ids`; confirm fleet workers actually stop via staging drill evidence).
- Before production promotion, validate metadata-only rollback/fix-forward plan evidence (release id, migration plan, Postgres backup reference, tested **command references** — not raw shell bodies — adapter disablement plan, probe-worker flag plan, notification/support comms, success criteria, and release/DB signoffs):

```bash
npm run rollback:evidence -- \
  --input output/rollback-fixforward-plan-input.json \
  --out output/rollback-fixforward-plan-evidence.json
```

Use `--validate-only` in staging CI. Attach the manifest (or bundle it via `npm run release:evidence:bundle`) to `/v1/production-release-evidence` as kind `rollback_fixforward`. The validator rejects credentials, SQL dumps, packet captures, database URLs, tokens, and raw command scripts; it does **not** execute rollback steps.
- **Disaster recovery (production):** Postgres backups, restore drills, RPO/RTO, and regional failover are **not complete** until the runtime adapter and operator evidence land — see [`docs/disaster-recovery.md`](disaster-recovery.md).

---

## Developer validation mode (local only)

Not a production deployment. Use for engineering, CI, and sales engineering **only on trusted networks**.

### Prerequisites

- Node.js 20+
- Repository root: `/Users/checkred_admin/Projects/astranull` (or your clone path)
- No PostgreSQL required for default `make verify` (production gate: Postgres in staging/prod)

### Startup

```bash
cd /Users/checkred_admin/Projects/astranull
npm start
```

Default URL: [http://localhost:3000](http://localhost:3000). Server binds per `src/index.mjs` (typically port 3000).

Optional: disable file persistence during tests:

```bash
ASTRANULL_NO_PERSIST=1 npm start
```

### Developer validation auth (UI)

The sidebar sets compatibility headers ( **not valid for production** ):

- `x-tenant-id` (default `ten_demo` after seed)
- `x-user-id` (`usr_admin` in UI)
- `x-role` (`admin`, `engineer`, `soc`, etc.)

Switch to **soc** or **owner** to exercise `/internal/soc/*` from the SOC Console.

### Validation flow (local)

1. **Dashboard** — confirm readiness score and counts via `/v1/state`.
2. **Target Groups** — create a group and target (or use seeded validation tenant when not using test reset).
3. **Settings** — create a bootstrap token; copy the **one-time** secret.
4. **Validation agent** (separate terminal):

   ```bash
   ASTRANULL_BOOTSTRAP_TOKEN='<secret>' node agents/linux/astranull-agent.mjs --api http://localhost:3000 --once
   ```

   Repo-root dev agent may use HTTP localhost; **packaged** agents default to HTTPS and require `--allow-insecure-localhost-api` or `ASTRANULL_ALLOW_INSECURE_LOCALHOST_API=1` for HTTP localhost. Packaged identity defaults to `/var/lib/astranull/identity.json` (dev checkout often uses `.data/agent-identity.json`).

5. **Test Runs** — start `origin.direct_bypass.safe` (or use UI button).
6. Agent polls jobs, acks, posts observation with `nonce_hash` from the run.
7. **Findings / Evidence** — review correlated verdict and evidence vault entries.
8. **Reports** — generate report; export JSON, Markdown, or HTML.

### WAF posture and validation plans (developer validation)

1. **WAF Posture** (`#waf-posture`) — coverage, declared assets, validation runs, drift queue, and the **validation-plan operator panel** (list all/scheduled plans; create/execute/cancel safe plans). When Postgres orchestrator is not injected, the panel explains `postgres_waf_orchestrator_unavailable` and disables orchestrator-dependent actions without leaking payloads.
2. **Manual execute tick** — `POST /v1/waf/validation-plans/:id/execute` from the panel or API (signed-worker mode in Postgres); plan `completed` means all safe jobs delegated, not final posture closure.
3. **Scheduled production path (open evidence)** — wire `npm run waf:orchestrator:runner` to external schedule (see [WAF orchestrator runner](#waf-orchestrator-runner-externally-scheduled) above). Staging scheduling/execution evidence for the runner remains a release blocker — **not production-ready** until evidenced per [`docs/release-checklist.md`](release-checklist.md).

### SOC high-scale (developer validation adapter boundary)

1. As **engineer**: submit high-scale request; add authorization pack artifacts (metadata URIs).
2. As **soc**: review artifacts → approve → schedule window (include current time) → **Start (dry-run adapter)**.
3. Confirm adapter status shows no unmanaged traffic generation.
4. Stop / close as needed; optional kill switch from API.

### Metrics and observability

- `GET /metrics` — plaintext counters (production: protect endpoint)
- `GET /v1/observability` — JSON summary (requires `tenant:read`)

### Data persistence and reset (developer validation)

| Mode | Location |
|---|---|
| Default dev | `.data/astranull-dev.json` |
| No persist | `ASTRANULL_NO_PERSIST=1` |

**Reset local data:** stop the server, delete `.data/astranull-dev.json`, restart (seed recreates validation tenant when store is empty).

**Backup and restore (developer validation):** `npm run dr:backup:dev` and `npm run dr:restore:dev` (manifest checksum + `--dry-run` / `--yes`). Details and production DR gate: [`docs/disaster-recovery.md`](disaster-recovery.md).

Agent identity file (validation agent): packaged default `/var/lib/astranull/identity.json`; dev checkout may use `.data/agent-identity.json` only when overridden via `--identity` or `ASTRANULL_AGENT_IDENTITY` — delete that file to re-register locally.

### Verification

```bash
make verify
```

Runs lint, unit tests, integration tests (including security polish), e2e flows, UI smoke, `scripts/safety-check.mjs`, and `scripts/postgres-tenant-query-audit.mjs` using Node directly (no npm on PATH required). Override Node with `make NODE=/path/to/node verify`. Latest local verification: `npm test` 2120 passing; `npm run staging:local:attest` reports `production_ready=true` for local-staging inventory. A green local verify is local production-quality evidence — not customer-facing hosted production promotion. See `npm run staging:local:attest` for the full Docker Compose gate.

Agent update releases require `distribution: { manifest_url, signature_url, artifact_url }` on `POST /v1/agent-updates`; agents polling `GET /v1/agents/:id/update` receive `download` with the same three URLs. In Postgres mode the route family persists through `runtime.services.agentUpdates`; developer validation uses the JSON store. Host apply: `agents/linux/astranull-agent.mjs --download-and-apply-update` (see [`docs/agent/07-agent-lifecycle.md`](agent/07-agent-lifecycle.md)). Production still requires CDN/mirror custody runbooks, unattended daemon restart, and fleet rollout drills.

### Troubleshooting (developer validation)

| Symptom | Check |
|---|---|
| 403 on SOC actions | Role must be `soc` or `owner`; engineer cannot call `/internal/soc/*`. |
| 401 on agent heartbeat | Use `Authorization: Bearer <agent_credential>` from registration, not bootstrap token. |
| Bootstrap token replay | Tokens are one-time per `max_registrations`; create a new token. |
| High-scale start 409 | Authorization pack incomplete, outside schedule window, or scope hash mismatch after target changes. |
| Empty readiness | Run at least one finalized test; agent observation affects bypass findings. |
| Port in use | Change listen port via env or stop conflicting process. |

See also [`docs/support-playbook.md`](support-playbook.md).
