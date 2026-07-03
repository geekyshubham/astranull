# Database Schema

Authoritative DDL lives in [`db/schema.sql`](../../db/schema.sql), [`db/migrations/0001_core_validation_loop.sql`](../../db/migrations/0001_core_validation_loop.sql), [`db/migrations/0002_production_ledgers.sql`](../../db/migrations/0002_production_ledgers.sql), [`db/migrations/0003_runtime_shape_parity.sql`](../../db/migrations/0003_runtime_shape_parity.sql), [`db/migrations/0004_validation_ledger_indexes.sql`](../../db/migrations/0004_validation_ledger_indexes.sql), [`db/migrations/0005_verdict_placement_confidence.sql`](../../db/migrations/0005_verdict_placement_confidence.sql), [`db/migrations/0006_notification_rule_triggers.sql`](../../db/migrations/0006_notification_rule_triggers.sql), [`db/migrations/0007_production_release_evidence.sql`](../../db/migrations/0007_production_release_evidence.sql), and [`db/migrations/0008_waf_posture.sql`](../../db/migrations/0008_waf_posture.sql). Developer validation uses the JSON shape in `src/store.mjs`. A tested Postgres **runtime facade** (`createPostgresRuntime` in `src/persistence/postgres/runtime.mjs`) owns one pool, optional auto-migrate, latest-migration verification, repository bundles, `runtime.services` via catalog/auth/agent/agent-updates/validation/events/notifications/report/secret-vault/state/probe-job/high-scale/production-release-evidence/retention/WAF adapters plus audit, health, and idempotent shutdown. `src/startup.mjs` initializes that facade for `ASTRANULL_PERSISTENCE_MODE=postgres`, injects migrated services into `createServer`, uses runtime health for `/ready`, skips dev seeding, and closes the pool on shutdown/failure. Unmigrated JSON-backed route families return `503 postgres_route_not_wired` until their Postgres services land.

## Migration bookkeeping

| Column | Type | Notes |
|---|---|---|
| version | text | Primary key (e.g. `0001_core_validation_loop`, …, `0007_production_release_evidence`). |
| applied_at | timestamptz | When migration was applied. |

## Core validation loop tables

### tenants / environments / users

Org and RBAC primitives. Environments carry `privacy_settings` and `settings_json`.

### target_groups / targets

Customer-declared scope (no inventory discovery). Target groups store `safety_policy` and `safe_test_windows` JSON for safe-test guardrails. Targets use `kind` + `value` (fqdn/url/ip_port, etc.).

### bootstrap_tokens

Hashed install secrets with optional environment/target group binding and registration limits.

### agents

Outbound-only fleet identity: `target_group_id`, `bootstrap_token_id`, `fingerprint`, `credential_hash`/`credential_salt`, heartbeat and capability fields.

### test_runs

Planner/orchestration state aligned with `src/services/testRuns.mjs`: `check_id`, `safety_constraints`, `remediation_template`, `awaiting_external_probe`, `probe_external_result`, `correlation_json`, `created_by`, statuses including `planned` / `running` / `collecting`.

Partial unique index `uniq_active_test_run` on `(tenant_id, target_group_id)` for active statuses prevents overlapping safe runs per group.

### probe_jobs

Signed external probe dispatch (`job_signature`, `constraints_json`, `target_descriptor_json`, lease/completion fields). Used when `probeMode=signed-worker`.

### agent_jobs

Hardened observation jobs: `type TEXT NOT NULL DEFAULT 'observe_window'` (not legacy `job_type`; `0003_runtime_shape_parity` renames `job_type` when upgrading older databases), `check_id`, `target_id`, `nonce_hash`, `nonce_for_agent`, statuses `pending` → `acked` → `observed`, `observed_at`.

### events

Correlation stream with `target_id`, `check_id`, `agent_id`, `signal_type`, `nonce_hash`. `event_id` is optional for internal runtime events; external idempotency via partial unique index `uniq_events_tenant_event_id` on `(tenant_id, event_id) WHERE event_id IS NOT NULL`.

### verdicts / findings / evidence_vault

Verdict engine outputs; one verdict per run (`uniq_verdict_per_test_run`). `verdicts` exposes composite unique `verdicts_tenant_id_id_key` for tenant-consistent FK targets and `placement_confidence_json` (DET-014; `0005_verdict_placement_confidence`) mapped to API `placement_confidence` in Postgres repositories. Findings carry `verdict_id`, `last_verdict_id`, `assignee`, and remediation templates; findings→verdict links use tenant-consistent composite FKs (`0003_runtime_shape_parity`). Vault stores metadata-only evidence pointers.

### soc_kill_switch

Per-tenant kill switch row.

### audit_logs

Tamper-evident chain: monotonic per-tenant `sequence` enforced by `uniq_audit_tenant_sequence`, plus `prev_hash`, `entry_hash` (matches `src/audit.mjs`).

### platform_metrics

Global counters snapshot (no RLS).

## Production ledger tables (`0002_production_ledgers`)

Additive schema coverage for durable production ledgers (repository/runtime adapter integration still open).

### service_accounts

Automation principals: `role`, `scopes`, salted `secret_hash`/`secret_salt`, revoke/rotate timestamps, `last_used_at`.

### encrypted_secrets

Tenant secret vault envelopes: `purpose`, `name`, redacted `metadata_json`, `rotation`, `envelope_json` (AES-256-GCM at the application layer).

### agent_update_trust_keys / agent_update_releases / agent_update_statuses

Tenant trust-key ledger (Ed25519 fingerprint, active/revoked), signed release/rollback manifests with `distribution_json` and rollout JSON, per-agent update status timeline (`release_id`, `status`, `installed_version`).

### high_scale_telemetry

Metadata-only SOC telemetry rows per high-scale request (`category`, `live_status`, `metrics_json`, `observed_at`).

### soc_reports

One post-test report per high-scale request (`uniq_soc_report_per_high_scale_request`): impact/recommendations/summaries, `derived_json`, `evidence_ids`, `final_state`.

### notification_delivery_attempts

Per-event delivery ledger (`notification_event_id`, `rule_id`, `channel`, `status`, `attempted_at`) for notification auditability.

### production_release_evidence (`0007_production_release_evidence`)

Tenant-scoped release gate evidence records for security review, migration apply, and operator runbook exercises. Rows store metadata-only `evidence_json`, `validation_json`, creator, status, optional `release_id`, notes, and audit timestamps under forced RLS.

### high_scale_requests (expanded fields)

`0002` adds `requested_window`, `emergency_contacts`, `scope_confirmation`, `created_by`, `audit_trail`, `artifacts`, `soc_approvals`, `provider_approval_checklist`, and `adapter_json` alongside the core request state machine.

## WAF posture tables (`0008_waf_posture`)

Additive schema for WAF readiness validation (see `docs/backend/12-waf-posture-data-model.md`). Approved assets (`waf_assets`) link to declared `target_groups` / `targets`; discovery candidates (`external_asset_candidates`) are not directly testable until approved into targets. Safe validation envelopes (`waf_validation_runs`, `waf_scenario_results`, `waf_fingerprints`) store metadata-only JSONB summaries—no raw payloads, bodies, headers, or packet captures. Posture state (`waf_posture_snapshots`, `waf_baselines`, `waf_drift_events`) and optional read-only connectors (`waf_connectors`, `waf_connector_snapshots`, default `disabled`) normalize vendor config into hashes and summaries. CVE tracking (`cve_pipeline_items`, `cve_asset_matches`) and human-reviewed `waf_rule_recommendations` tie into existing `findings` via composite tenant FKs. Global catalog: `waf_products` (no RLS). `findings` gains `findings_tenant_id_id_key` for drift/CVE links.

| Index | Purpose |
|---|---|
| `uniq_waf_posture_snapshot_current` | One current snapshot per asset (partial unique) |
| `idx_waf_posture_snapshots_dashboard` | Posture status filters |
| `idx_waf_drift_events_queue` | Drift remediation queue |
| `idx_waf_connector_snapshots_history` | Connector snapshot timeline |
| `idx_cve_pipeline_items_lookup` | CVE id lookup per tenant |
| `uniq_cve_asset_matches_dedupe` | Deduped CVE↔asset matches |
| `idx_external_asset_candidates_approval_queue` | Discovery approval inbox |
| `idx_waf_assets_tenant_group_url` | Asset lookup by group and URL |

## Row level security

Tenant-facing tables enable and **force** RLS (`ALTER TABLE … FORCE ROW LEVEL SECURITY`) so owners cannot bypass policies. Policies use `tenant_id = current_setting('app.tenant_id', true)` for both `USING` and `WITH CHECK`, except `tenants`, which uses `id = current_setting('app.tenant_id', true)` via `tenant_isolation_tenants`. Global tables (no RLS): `schema_migrations` and `platform_metrics`. The runtime DB role must be a non-owner application role **without** the `BYPASSRLS` attribute.

## Tenant-consistent foreign keys

RLS limits what rows a session can read, but single-column foreign keys (`child.parent_id → parent.id`) do not prove the parent row belongs to the same tenant as the child. The schema therefore defines composite **unique** keys on tenant-scoped parents (`UNIQUE (tenant_id, id)`) and composite **foreign keys** on children (`FOREIGN KEY (tenant_id, parent_id) REFERENCES parent (tenant_id, id)`). Nullable parent id columns stay nullable; PostgreSQL skips the composite FK check when any referencing column is null.

Static verification (`scripts/validate-db-schema.mjs`) requires the named composite FK contract across `schema.sql` and all versioned migrations under `db/migrations/` (including `0001_core_validation_loop.sql` through `0008_waf_posture.sql`), rejects revived single-column `REFERENCES parent(id)` patterns on tenant-scoped relationships, rejects forbidden raw-payload columns on WAF tables, and rejects stale fresh-schema `agent_jobs.job_type` (contract requires `type`).

## Hot-path indexes

| Index | Purpose |
|---|---|
| `idx_agent_jobs` | Agent poll: `(tenant_id, agent_id, status, created_at)` |
| `idx_probe_jobs_status_leased` | Worker lease sweep |
| `idx_probe_jobs_tenant_run` | Run-scoped probe lookup |
| `idx_events_correlation` | `(tenant_id, test_run_id, signal_type, nonce_hash, timestamp)` |
| `uniq_audit_tenant_sequence` | Unique per-tenant audit sequence (tamper-evident chain) |
| `uniq_events_tenant_event_id` | External event idempotency when `event_id` is set |
| `uniq_verdict_per_test_run` | Single verdict per run |
| `uniq_active_test_run` | Active run guard per target group |
| `idx_service_accounts_tenant_role` | Service-account list/filter by role |
| `idx_agent_update_releases_tenant_state` | Active rollout release lookup |
| `idx_agent_update_statuses_tenant_agent` | Agent update status history |
| `uniq_active_agent_update_trust_key_fingerprint` | One active trust key per tenant fingerprint |
| `idx_high_scale_telemetry_request_observed` | SOC telemetry timeline per request |
| `uniq_soc_report_per_high_scale_request` | Single post-test report per high-scale request |
| `idx_notification_delivery_attempts_event` | Delivery attempts per notification event |
| `idx_test_runs_tenant_created` | Tenant run history ordered by `created_at` |
| `idx_test_runs_tenant_group_created` | Target-group run history ordered by `created_at` |
| `idx_events_tenant_run_time` | Run timeline event fetch by `timestamp` |
| `idx_evidence_vault_tenant_run_created` | Evidence vault rows per run, newest first |
| `idx_evidence_vault_tenant_related_event` | Evidence lookup by correlated event |
| `uniq_findings_open_target_check` | One open finding per tenant/target/check (partial unique) |
| `uniq_probe_result_per_run_nonce` | Probe result idempotency per run and nonce (partial unique) |

**Operator preflight before `0004` on non-empty databases:** query for duplicate open findings on `(tenant_id, target_group_id, target_id, check_id)` and remediate before applying `uniq_findings_open_target_check`; migration `0004` does not use `CREATE INDEX CONCURRENTLY` (transactional runner).

## Static verification

`scripts/validate-db-schema.mjs`, `tests/unit/db-schema.test.mjs`, and `tests/unit/postgres-migrations.test.mjs` assert the contract without a live database.

## Migration runner and DB primitives

| Module | Role |
|---|---|
| `src/persistence/postgres/pool.mjs` | `pg` pool from `ASTRANULL_DATABASE_URL` with bounded pool env overrides; `pingPostgres` health probe |
| `src/persistence/postgres/migrations.mjs` | Single transaction per run with `pg_advisory_xact_lock` before reading `schema_migrations`; applies sorted `db/migrations/*.sql` |
| `src/persistence/postgres/tenantContext.mjs` | `withTenantContext(pool, tenantId, fn)` → `BEGIN` / `set_config('app.tenant_id', …, true)` / `COMMIT` |
| `src/persistence/postgres/coreCatalogRepository.mjs` | Parameterized tenant/environment/target-group/target repository (`createCoreCatalogRepository`, incl. `getCurrentTenant` and `patchCurrentTenant` for tenant basic settings); uses `withTenantContext` + explicit `tenant_id` predicates; wired into Postgres startup through `runtime.services.tenants` / `runtime.services.targetGroups` |
| `src/persistence/postgres/auditRepository.mjs` | `createAuditRepository(pool)` — tenant-scoped `audit_logs` reads (`listAuditEntries`) plus production appender `appendAuditEvent(entry, options?)` (rejects missing tenant before DB connect; `withTenantContext`; `pg_advisory_xact_lock(hashtext($1))`; reads last row; builds redacted sequence/prev_hash/entry_hash via `buildAuditRecord` from `src/audit.mjs`; parameterized insert; rollback on failure). Exposed as `runtime.services.audit` for Postgres-mode RBAC-denial auditing and `GET /v1/audit-log`. Unit tests: `tests/unit/postgres-audit-repository.test.mjs`, `tests/unit/audit-chain.test.mjs`, `tests/unit/server-postgres-mode.test.mjs` |
| `src/persistence/postgres/authTokenRepository.mjs` | `createAuthTokenRepository(pool)` — bootstrap tokens and service accounts under `withTenantContext`; addressed-hint lookup by `(tenant_id, id)`; revocation; legacy `incrementBootstrapTokenRegistrations`; atomic gated `consumeBootstrapTokenRegistration`; service-account rotation and last-used updates; wired through `createPostgresAuthServices` for migrated token/service-account routes |
| `src/persistence/postgres/agentControlRepository.mjs` | `createAgentControlRepository(pool)` — tenant-scoped `agents` and `agent_jobs` under `withTenantContext`; addressed-hint lookup by `(tenant_id, id)` for agents; wired through `createPostgresAgentServices` for migrated agent routes |
| `src/persistence/postgres/agentUpdateRepository.mjs` | `createAgentUpdateRepository(pool)` — tenant-scoped `agent_update_trust_keys`, `agent_update_releases`, and `agent_update_statuses` under `withTenantContext`; enforces active trust-key lookup, release/status history, rollback state, and agent version update writes for update-status acknowledgments |
| `src/persistence/postgres/validationEvidenceRepository.mjs` | `createValidationEvidenceRepository(pool)` — tenant-scoped `test_runs`, `events`, `verdicts`, `findings`, and `evidence_vault` under `withTenantContext`; bounded list reads; idempotent append/create/upsert methods aligned with validation indexes; wired through validation services for read/update surfaces |
| `src/persistence/postgres/probeJobRepository.mjs` | `createProbeJobRepository(pool)` — tenant-scoped `probe_jobs` create/lease/read/claim/complete operations under `withTenantContext`; creates signed worker jobs from Postgres `startTestRun`, leases pending jobs with `FOR UPDATE SKIP LOCKED`, bounded worker limits, and worker-facing nonce mapping |
| `src/persistence/postgres/killSwitchRepository.mjs` | `createKillSwitchRepository(pool)` — tenant-scoped `soc_kill_switch` read/upsert under `withTenantContext`; `runtime.services.testRuns.startTestRun` denies new safe runs while active and `runtime.services.highScale.setKillSwitch` persists activation/clear plus auto-stop context |
| `src/persistence/postgres/notificationRepository.mjs` | `createNotificationRepository(pool)` — tenant-scoped `notification_rules`, `notification_events`, and `notification_delivery_attempts`; maps `triggers_json` to the API `triggers` array, stores redacted `metadata_json`, and reads delivery attempts for tenant-scoped notification events |
| `src/persistence/postgres/reportRepository.mjs` | `createReportRepository(pool)` — tenant-scoped report persistence plus report-run/verdict/finding export read models under `withTenantContext`; wired through `createPostgresReportServices` as `runtime.services.reports` |
| `src/persistence/postgres/reportServiceAdapters.mjs` | `createPostgresReportServices(repositories, options?)` — report create/get plus report/finding exports from Postgres rows; preserves custody manifests and export audits via `audit.getLastAuditEntry` / `audit.appendAuditEvent`; uses evidence-based partial readiness summaries instead of dev-store `computeReadiness`; `/v1/reports*` and `/v1/findings/:id/export` routes use `serviceDeps.reports` and fail closed with `postgres_route_not_wired` only when the service is not injected |
| `src/persistence/postgres/secretVaultRepository.mjs` | `createSecretVaultRepository(pool)` — tenant-scoped `encrypted_secrets` create/list/get/update under `withTenantContext`; persists `metadata_json` and `envelope_json` only (no plaintext); wired through `createPostgresSecretVaultServices` as `runtime.services.secretVault` |
| `src/persistence/postgres/secretVaultServiceAdapters.mjs` | `createPostgresSecretVaultServices(repositories, options?)` — store/list/rotate/decrypt-for-use with AES-256-GCM envelopes, redacted list metadata, and `audit.appendAuditEvent` on lifecycle actions; `/v1/secrets` routes use `serviceDeps.secretVault` and fail closed with `postgres_route_not_wired` only when the service is not injected |
| `src/persistence/postgres/serviceAdapters.mjs` | `createPostgresCatalogServices(repositories)` — forwards tenant/environment and target-group methods into the `createServer({ services })` shape; wired by `src/startup.mjs` in Postgres mode |
| `src/persistence/postgres/authServiceAdapters.mjs` | `createPostgresAuthServices(repositories, options?)` — bootstrap tokens and service accounts via `repositories.authTokens` + `repositories.audit.appendAuditEvent`; addressed-secret mint/verify only; atomic `consumeBootstrapTokenRegistration` on bootstrap consume; wired by `src/startup.mjs` in Postgres mode |
| `src/persistence/postgres/agentServiceAdapters.mjs` | `createPostgresAgentServices(repositories, options?)` — agent register/list/heartbeat/poll/ack via `repositories.agentControl` + shared `tokens.consumeBootstrapToken` + `audit.appendAuditEvent`; addressed `agc_` agent credentials only; wired by `src/startup.mjs` in Postgres mode |
| `src/persistence/postgres/agentUpdateServiceAdapters.mjs` | `createPostgresAgentUpdateServices(repositories, options?)` — agent update trust-key/release/rollback/poll/status routes via `repositories.agentUpdates` + `agents` + `audit`; shares manifest/distribution/signature validation with the dev service, audits lifecycle actions, returns download payloads, records status, and updates installed agent version on applied/rolled-back acknowledgments |
| `src/persistence/postgres/validationServiceAdapters.mjs` | `createPostgresValidationServices(repositories, options?)` — safe reads/updates via `repositories.validationEvidence` + `audit.appendAuditEvent`; `startTestRun`/`cancelTestRun` with safe-window/rate/cooldown/concurrency/kill-switch/prerequisite gates, signed probe-job creation in `signed-worker` mode, and agent job dispatch; `ingestObservation` with exact-once agent job transition before evidence write; `maybeFinalizeRunAfterProbeIngest` and `finalizeTestRun` for correlation, automatic verdict publication, forced no-observation finalization, and finding upsert; metadata-only `events.ingestEvent` for `POST /v1/events` (tenant check, `event_id` idempotency, packet/raw-field rejection, `event.ingested` audit); audits for starts, cancellations, observations, verdict publication, no-observation finalization, findings, denials, and rejected observations; wired by `src/startup.mjs` in Postgres mode |
| `src/persistence/postgres/notificationServiceAdapters.mjs` | `createPostgresNotificationServices(repositories, options?)` — notification rule list/create plus metadata-only `emitNotification`; validates channels/triggers/destinations, stores multi-trigger rules, records redacted metadata and delivery attempts, audits safe lifecycle actions, and powers `GET/POST /v1/notifications` through `runtime.services.notifications` |
| `src/persistence/postgres/highScaleRepository.mjs` | `createHighScaleRepository(pool)` — tenant-scoped `high_scale_requests`, `authorization_artifacts`, `soc_notes`, `high_scale_telemetry`, and `soc_reports` reads/writes under `withTenantContext`; maps JSON ledgers for risk review, authorization pack status, provider checklist, adapter state, telemetry metadata, notes, and reports |
| `src/persistence/postgres/highScaleServiceAdapters.mjs` | `createPostgresHighScaleServices(repositories, options?)` — backs `POST/GET /v1/high-scale-requests` and SOC-only high-scale routes with target-scope validation, required intake, metadata artifact upload/review, authorization pack gates, two-person SOC approval, scope-hash locking/revalidation, scheduling/start/stop/close state machine, dry-run adapter state, metadata-only telemetry, post-test report gate, tenant kill switch auto-stop/cancel, state-change notifications, and safe audit logging |
| `src/persistence/postgres/stateServiceAdapters.mjs` | `createPostgresStateServices(repositories, options?)` — bounded Postgres reads from `coreCatalog`, `agentControl`, `validationEvidence`, `highScale`, and `killSwitch` to build `GET /v1/state` dashboard aggregates with evidence-backed readiness factors, high-scale request counts, sanitized kill-switch state, and SOC governance posture; no dev-store `getStore` / `computeReadiness`; wired as `runtime.services.state` |
| `src/persistence/postgres/probeJobServiceAdapters.mjs` | `createPostgresProbeJobServices(repositories, options?)` — worker `GET /internal/probe/jobs` and `POST /internal/probe/jobs/:id/result` behavior via `probeJobs`, `validationEvidence`, and `audit`; validates metadata-only results, rejects duplicate nonce ingestion before append, writes probe events/evidence, updates run probe state, completes jobs, and audits safe worker lifecycle metadata |
| `src/persistence/postgres/wafPostureRepository.mjs` | `createWafPostureRepository(pool)` — tenant-scoped WAF asset, validation-run, scenario-result, and posture-snapshot primitives under `withTenantContext`; stores metadata-only JSON summaries and current snapshot updates |
| `src/persistence/postgres/wafPostureServiceAdapters.mjs` | `createPostgresWafPostureServices(repositories, options?)` — WAF asset/coverage/validation API service through Postgres repositories plus catalog target-group validation and audit logging; rejects raw WAF evidence and protected-finalize self-attestation without corroborating scenario evidence |
| `src/persistence/postgres/runtime.mjs` | `createPostgresRuntime(env, options?)` — single pool (`createPgPool`), default `db/migrations`, ping, optional `autoMigrate` / `ASTRANULL_POSTGRES_AUTO_MIGRATE=1`, assert latest migration, construct all repository primitives on the same pool, expose `services` via catalog + auth + agent + agent-updates + validation/events + notifications + report + secret-vault + state + probe-job + high-scale + WAF service adapters plus kill-switch and audit repositories (`tenants`, `targetGroups`, `tokens`, `serviceAccounts`, `agents`, `agentAuth`, `agentUpdates`, `testRuns`, `events`, `notifications`, `evidence`, `findings`, `reports`, `secretVault`, `state`, `probeJobs`, `highScale`, `wafPosture`, `audit`), `health()` metadata, idempotent `close()`; DI hooks for tests; no `getStore` / dev-json paths (`tests/unit/postgres-runtime-adapter.test.mjs`) |
| `src/startup.mjs` / `src/server.mjs` | Production startup loads config once, creates `createPostgresRuntime()` when `persistenceMode=postgres`, injects `runtime.services`, uses `runtime.health()` for `/ready`, skips dev seeding in Postgres mode, closes the pool on shutdown/failure, and redacts database URLs in startup errors. `createServer` returns `503 postgres_route_not_wired` for unmigrated JSON-backed route families (`tests/unit/startup.test.mjs`, `tests/unit/server-postgres-mode.test.mjs`, `tests/unit/server-service-injection.test.mjs`) |
| `scripts/migrate-postgres.mjs` | Operator CLI to apply migrations (does not unblock app startup) |
| `scripts/postgres-startup-check.mjs` | Operator preflight (`npm run postgres:startup-check`) — verify-only ping + latest migration assert; `--migrate` applies pending migrations first; redacts URLs |
| `scripts/postgres-acceptance.mjs` | Gated staging harness (`ASTRANULL_POSTGRES_ACCEPTANCE=1`) — migrations, forced RLS catalog, composite FK names, `withTenantContext` isolation and cross-tenant reject; evidence only, not runtime adapter completion |
| `scripts/postgres-runtime-smoke.mjs` | Gated DB-backed runtime wiring harness (`ASTRANULL_POSTGRES_RUNTIME_SMOKE=1`) — initializes `createPostgresRuntime`, asserts migrated route service families (catalog/auth/agents/testRuns/events/notifications/reports/secretVault/state/probeJobs/highScale/wafPosture/productionReleaseEvidence/retention/audit), calls `runtime.health()`, closes the pool; no customer data seeding and no DDoS/safe-check execution; skipped unless explicitly enabled (`tests/unit/postgres-runtime-smoke.test.mjs`) |

Run startup preflight (verify-only):

```bash
ASTRANULL_DATABASE_URL='…' node scripts/postgres-startup-check.mjs
```

Apply migrations then verify:

```bash
ASTRANULL_DATABASE_URL='…' node scripts/postgres-startup-check.mjs --migrate
```

Run live acceptance in staging (skipped by default; not in `make verify`):

```bash
ASTRANULL_POSTGRES_ACCEPTANCE=1 ASTRANULL_DATABASE_URL='…' node scripts/postgres-acceptance.mjs
```

Run DB-backed runtime wiring smoke in staging (skipped by default; not in `make verify`):

```bash
ASTRANULL_POSTGRES_RUNTIME_SMOKE=1 ASTRANULL_DATABASE_URL='…' node scripts/postgres-runtime-smoke.mjs
```

Require the harness in CI/release automation (fails when not enabled):

```bash
ASTRANULL_REQUIRE_POSTGRES_RUNTIME_SMOKE=1 node scripts/postgres-runtime-smoke.mjs
```

## Static Postgres tenant-query audit (pre-concurrency signoff)

Before recording staging tenant concurrency evidence, run the **metadata-only** static audit over Postgres repository and service-adapter sources. `scripts/postgres-tenant-query-audit.mjs` scans selected files under `src/persistence/postgres` (repositories and `*ServiceAdapters.mjs` by default), skips migration/pool/runtime/tenant-context helpers, and flags template-literal or single-quoted `.query('…')` SQL that references tenant-scoped tables without `withTenantContext`, `tenant_id`, dynamic `conditions` builders that inject `tenant_id = $1`, `app.tenant_id` / RLS `set_config`, a `tenants` `WHERE id = $…` predicate, or an inline `tenant-query-audit:allow` / `tenant-query-audit:global` comment. Global lookup tables (`schema_migrations`, `platform_metrics`) are allowlisted. Output is JSON with repo-relative `scanned_files`, `finding_count`, and per-finding `file`, `line`, `check`, `table`, and a short `query_label` only (no full SQL text or customer data). The audit runs in default `make verify` / GitHub CI and can emit `postgres_tenant_query_audit` production release evidence via `buildProductionTenantQueryAuditEvidence()` or `--evidence-uri`. Unit tests: `tests/unit/postgres-tenant-query-audit.test.mjs`.

Audit default repository bundle (exit nonzero when findings remain):

```bash
node scripts/postgres-tenant-query-audit.mjs
# or: npm run postgres:tenant-query:audit
# or: make postgres-tenant-query-audit
```

Audit explicit paths and write a report artifact:

```bash
node scripts/postgres-tenant-query-audit.mjs \
  --paths src/persistence/postgres/validationEvidenceRepository.mjs,src/persistence/postgres/highScaleRepository.mjs \
  --out output/postgres-tenant-query-audit.json
```

Allow findings for exploratory runs without failing CI locally:

```bash
node scripts/postgres-tenant-query-audit.mjs --allow-findings
```

## Staging tenant concurrency / isolation evidence (metadata-only)

Operators record **metadata-only** JSON from a gated staging concurrency run (no live DB connection in the validator). `scripts/postgres-concurrency-evidence.mjs` reads captured evidence, rejects database URLs, raw SQL dumps, tokens, row payloads, and customer data, and writes a redacted manifest with route-family coverage gaps. Unit tests: `tests/unit/postgres-concurrency-evidence.test.mjs`.

Validate captured evidence (no Postgres connection):

```bash
node scripts/postgres-concurrency-evidence.mjs --input staging/postgres-concurrency-evidence.json --validate-only
```

Write redacted manifest:

```bash
node scripts/postgres-concurrency-evidence.mjs --input staging/postgres-concurrency-evidence.json --out output/postgres-concurrency-evidence-manifest.json
```

Expected input shape (`artifact_type: postgres_tenant_concurrency_evidence`, `schema_version: 1`):

| Field | Type | Notes |
|---|---|---|
| `environment` | string | e.g. `staging`. |
| `tenant_count` | integer | ≥ 2 isolated tenants exercised under load. |
| `concurrent_actors` | integer | ≥ 1 concurrent workers/sessions. |
| `duration_seconds` | number | Wall-clock duration of the concurrency window (> 0). |
| `route_families_exercised` | string[] | Must include every family in `REQUIRED_CONCURRENCY_ROUTE_FAMILIES` from `scripts/postgres-concurrency-evidence.mjs` (`catalog`, `auth`, `agents`, `agentUpdates`, `testRuns`, `events`, `notifications`, `reports`, `secretVault`, `state`, `probeJobs`, `highScale`, `wafPosture`, `wafDrift`, `wafOrchestrator`, `supplyChain`, `productionReleaseEvidence`, `retention`, `audit`). |
| `isolation.cross_tenant_read_rejections` | integer | Count of rejected cross-tenant reads (metadata count only). |
| `isolation.cross_tenant_write_rejections` | integer | Count of rejected cross-tenant writes. |
| `isolation.cross_tenant_leaks` | integer | Must be `0`; any positive value fails validation. |
| `rls_evidence.error_ids` | string[] | Non-empty metadata ids referencing RLS/constraint denial artifacts (not SQL text). |
| `rls_evidence.audit_evidence_ids` | string[] | Non-empty metadata ids for correlated audit-log evidence. |
| `operator_signoff.operator` | string | Operator identity (no secrets). |
| `operator_signoff.signed_at` | string | ISO-8601 signoff timestamp. |
| `operator_signoff.reference` | string | Ticket/runbook URI or external reference (no credentials). |

Forbidden in evidence payloads: `database_url`, `connection_string`, `raw_sql`, `sql_dump`, `query_text`, `rows`, `row_payload(s)`, `customer_data`, `token`, `secret`, `password`, `payload`, `body`, `headers`, raw `SELECT`/`INSERT`/`COPY` text, and `postgres://` / `postgresql://` strings anywhere in the document.

## Completion criteria

Schema contract is **in progress** for production completion: DDL + forced RLS + tenant-consistent composite FKs + runtime shape parity + validation-ledger indexes + verdict placement confidence + advisory-locked migrations are implemented and statically verified. Production startup injects the Postgres runtime facade and wires the safe validation loop (start/probe/observation/finalization/verdict/finding publication) plus guarded high-scale/SOC workflows through Postgres service adapters. Gated `postgres-runtime-smoke` supplies operator evidence that `createPostgresRuntime` initializes and exposes migrated service families without creating customer data or running safe checks. **Complete** when tenant unit-of-work covers all queries, migrations are applied in staging/prod as part of release, live/staging acceptance and runtime-smoke evidence are recorded, and integration tests prove no cross-tenant reads/writes under load.
