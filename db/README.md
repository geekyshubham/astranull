# Database artifacts

This directory defines the **production PostgreSQL contract** for AstraNull. Developer validation mode persists to `.data/astranull-dev.json` via `src/store.mjs` for local CI; that path is **not** a production data plane.

## Files

| File | Purpose |
|---|---|
| `schema.sql` | Current PostgreSQL DDL snapshot (migrations 0001–0008): core validation loop, production ledgers (service accounts, encrypted secrets, agent update trust keys/releases/statuses, high-scale telemetry, SOC post-test reports, notification delivery attempts, expanded `high_scale_requests` fields), runtime shape parity (`findings` `verdict_id` / `last_verdict_id` / `assignee`, `verdicts_tenant_id_id_key`, tenant-consistent findings→verdict FKs, `agent_jobs.type` aligned with runtime), validation-ledger hot-path indexes (`0004_validation_ledger_indexes`), verdict `placement_confidence_json` (`0005_verdict_placement_confidence`), notification `triggers_json` / event `metadata_json` (`0006_notification_rule_triggers`), tenant-scoped `production_release_evidence` ledger (`0007_production_release_evidence`), and WAF posture foundation (`0008_waf_posture`) |
| `migrations/0001_core_validation_loop.sql` | First versioned migration: validation loop, SOC/audit entities, forced RLS, tenant-consistent composite FKs |
| `migrations/0002_production_ledgers.sql` | Second versioned migration: additive production ledgers aligned with dev-store shapes; RLS on new tenant tables |
| `migrations/0003_runtime_shape_parity.sql` | Third versioned migration: runtime shape parity — `findings` gains `verdict_id`, `last_verdict_id`, and `assignee`; `verdicts` composite unique `verdicts_tenant_id_id_key` and tenant-consistent findings→verdict FKs; fresh `agent_jobs` uses `type TEXT NOT NULL DEFAULT 'observe_window'` (legacy `job_type` renamed safely when present) |
| `migrations/0004_validation_ledger_indexes.sql` | Fourth versioned migration: additive indexes for validation/evidence/report repository hot paths (`test_runs`, `events`, `evidence_vault`, partial unique on open findings and probe results). **Operators:** on non-empty databases, preflight for duplicate open findings on `(tenant_id, target_group_id, target_id, check_id)` before applying `uniq_findings_open_target_check`. Migrations run in a single transaction (no `CONCURRENTLY`). |
| `migrations/0005_verdict_placement_confidence.sql` | Fifth versioned migration: additive `verdicts.placement_confidence_json` JSONB for DET-014 placement confidence repository parity |
| `migrations/0006_notification_rule_triggers.sql` | Sixth versioned migration: `notification_rules.triggers_json` JSONB (API `triggers[]` parity) and `notification_events.metadata_json` JSONB; backfills legacy singular `trigger` into `triggers_json` when empty |
| `migrations/0007_production_release_evidence.sql` | Seventh versioned migration: tenant-scoped `production_release_evidence` table (kind, release id, status, `evidence_json`, `validation_json`) with forced RLS for `/v1/production-release-evidence` persistence |
| `migrations/0008_waf_posture.sql` | Eighth versioned migration: WAF posture foundation (`waf_assets`, validation runs, posture snapshots, drift, optional `waf_connectors`, CVE pipeline, rule recommendations) with metadata-only JSONB evidence, composite tenant FKs, and forced RLS on tenant tables |

Static verification: `node scripts/validate-db-schema.mjs`, `tests/unit/db-schema.test.mjs`, and `tests/unit/postgres-migrations.test.mjs`.

Apply migrations to a live database (operators/staging; not part of default `make verify`):

```bash
ASTRANULL_DATABASE_URL='postgresql://user:pass@host:5432/astranull' node scripts/migrate-postgres.mjs
```

**Staging acceptance evidence** (operators; gated — not part of default `make verify`; does **not** start the control plane — complements `postgres:startup-check` and optional `postgres-runtime-smoke`):

```bash
ASTRANULL_POSTGRES_ACCEPTANCE=1 \
ASTRANULL_DATABASE_URL='postgresql://user:pass@host:5432/astranull' \
node scripts/postgres-acceptance.mjs
```

Or `npm run postgres:acceptance` with the same env vars. Without `ASTRANULL_POSTGRES_ACCEPTANCE=1`, the script prints a skip message and exits 0. Set `ASTRANULL_REQUIRE_POSTGRES_ACCEPTANCE=1` in CI jobs that must run live DB evidence. The harness applies migrations, verifies forced RLS and composite FK catalog posture, seeds temporary `ten_accept_*` rows under `withTenantContext`, asserts tenant isolation and cross-tenant rejection, then best-effort cleanup.

Primitives: `src/persistence/postgres/pool.mjs` (pool + `pingPostgres`), `migrations.mjs` (versioned DDL + advisory transaction lock), `tenantContext.mjs` (`set_config('app.tenant_id', …, true)` per transaction), `coreCatalogRepository.mjs`, `auditRepository.mjs` (`appendAuditEvent` + `src/audit.mjs` `buildAuditRecord`), `authTokenRepository.mjs` (bootstrap tokens and service accounts under `withTenantContext`, including addressed-hint lookup by `(tenant_id, id)` without unbounded scans), `agentControlRepository.mjs` (tenant-scoped agents and agent jobs under `withTenantContext`, including addressed-hint lookup by `(tenant_id, id)`), `validationEvidenceRepository.mjs` (bounded `listTestRuns` / `listRunEvents` / `listEvidence` / `listEvidenceForRun`; idempotent `appendEventIdempotent`, `appendProbeResultEventIdempotent`, `createVerdictIfAbsent` (maps API `placement_confidence` to `placement_confidence_json` per `0005_verdict_placement_confidence`), and `upsertOpenFindingFromVerdict` aligned with `0004_validation_ledger_indexes` open-finding and probe-result partial unique indexes; test runs, events, verdicts, findings, evidence vault), `notificationRepository.mjs` (`triggers_json` / `metadata_json` per `0006_notification_rule_triggers`), production release evidence persistence (`0007_production_release_evidence`), WAF posture persistence (`0008_waf_posture` via `wafPostureRepository.mjs` / `wafPostureServiceAdapters.mjs`), and `reportRepository.mjs`, plus service adapters assembled by `createPostgresRuntime()` in `src/persistence/postgres/runtime.mjs`. Production startup (`src/startup.mjs`) initializes `createPostgresRuntime()`, injects `runtime.services` into `createServer()`, and closes the pool on shutdown. Addressed-secret auth uses Postgres adapters only (no legacy secret scans). Routes return `postgres_route_not_wired` only when a required injected service is missing or that handler is not yet Postgres-backed — not because Postgres mode is globally disabled. Covered by `tests/unit/postgres-service-adapters.test.mjs`, `tests/unit/postgres-runtime-adapter.test.mjs`, `tests/unit/server-service-injection.test.mjs`, and `tests/unit/startup.test.mjs`.

## Tenant isolation (RLS)

Tenant-facing tables **enable and force** row level security (`FORCE ROW LEVEL SECURITY` so table owners cannot bypass policies). Most policies compare `tenant_id` to `current_setting('app.tenant_id', true)`; `tenants` uses `id = current_setting('app.tenant_id', true)` so a normal tenant session cannot read other tenant rows. Roles with PostgreSQL `BYPASSRLS` still bypass RLS — the **application runtime database role must not be the table owner and must not have `BYPASSRLS`**.

API code in Postgres mode should use `withTenantContext` (or equivalent):

```sql
BEGIN;
SELECT set_config('app.tenant_id', '<tenant-id>', true);
-- queries ...
COMMIT;
```

Unset or empty `app.tenant_id` fails closed (no visible rows). Global tables without RLS: `schema_migrations` and `platform_metrics` only.

## Tenant-consistent foreign keys

Child rows that reference another tenant-scoped entity use composite foreign keys `(tenant_id, parent_id) → parent(tenant_id, id)`, backed by `UNIQUE (tenant_id, id)` on each referenced parent table. This blocks cross-tenant object graphs even if application code mis-assigns ids. `scripts/validate-db-schema.mjs` enforces the named constraint set; do not reintroduce single-column `REFERENCES …(id)` for those relationships.

`runMigrations()` holds a single client, opens a transaction, takes `pg_advisory_xact_lock` before reading `schema_migrations`, then applies or skips sorted migrations and commits once — so concurrent migrators do not race.

## Production release blockers

| Requirement | Acceptance criteria | Owner |
|---|---|---|
| Migration runner | Versioned migrations applied in staging and prod (`scripts/migrate-postgres.mjs`; unit-tested runner landed) | Backend |
| Runtime Postgres adapter | Control plane starts with `ASTRANULL_PERSISTENCE_MODE=postgres`, initializes `createPostgresRuntime()`, and injects migrated services; per-route `postgres_route_not_wired` when a required service is missing | Backend |
| Connection pooling | HA pool with health checks and timeouts | Backend |
| Tenant isolation | RLS + gated `postgres-acceptance`; **remaining:** staging/live acceptance execution and concurrent load evidence | Backend + Security |
| Encryption at rest | Token hashes, agent credentials, sensitive JSONB | Security |
| Backup and restore | Scheduled backups; restore drill documented (`SEC-007`); **remaining:** production backup/restore drill execution | Backend |
| KMS / HSM | External vault for integration secrets and key ceremony; **remaining:** deployment and staging evidence | Security |
| Provider / fleet evidence | Signed probe fleet, governed adapter, and notification provider staging evidence | SOC + Backend |

Developer validation JSON (`.data/astranull-dev.json`) is **not** a production data plane. With `NODE_ENV=production`, the control plane **refuses to start** unless `ASTRANULL_PERSISTENCE_MODE=postgres` and `ASTRANULL_DATABASE_URL` is set; `memory` and `dev-json` are refused. Startup runs migration preflight, initializes `createPostgresRuntime()`, and injects migrated services. A green local `make verify` or migration-only prep does **not** satisfy staging/live DB acceptance, tenant concurrency under load, backup/restore drills, or external KMS/provider signoff.

## Implementation direction

1. Apply `migrations/*.sql` via tooling; never mutate production schema by hand.
2. Enforce tenant isolation with RLS plus transaction-local tenant context via `withTenantContext` (`set_config('app.tenant_id', …, true)`) in the adapter transaction scope.
3. Replace JSON file persistence with transactional writes in the API layer.
4. Add a CI job that runs the full test suite against a live PostgreSQL instance (gated acceptance + optional runtime smoke) in addition to default `make verify`.

Backend agents implementing durable storage must match this artifact and add new migrations when the contract changes.
