# Disaster recovery (DR)

AstraNull separates **developer-validation DR** (local JSON store) from **production DR** (PostgreSQL and governed evidence). Production DR is **not complete** until Postgres runtime persistence covers all release-required route families, operator backup tooling exists, and documented restore drills are in place.

## Developer validation (local JSON store)

Engineering and CI use `.data/astranull-dev.json` when running outside production (`ASTRANULL_PERSISTENCE_MODE=dev-json` or default non-production behavior). This path is **not** a production data plane.

### Backup

```bash
npm run dr:backup:dev
```

Equivalent:

```bash
node scripts/backup-dev-store.mjs
```

| Flag | Default | Purpose |
|---|---|---|
| `--source` | `.data/astranull-dev.json` | Developer-validation store to copy |
| `--out` | `.data/backups` | Directory for timestamped backup + manifest |
| `--label` | (none) | Optional safe label (`[a-zA-Z0-9._-]`, max 64) recorded in manifest |

The script validates JSON, copies the file, and writes an adjacent `.manifest.json` with `version`, `created_at`, `source`, `backup_file`, `sha256`, `bytes`, and `label`. Output is paths and checksum summary only — never store contents.

### Restore

```bash
npm run dr:restore:dev -- --manifest .data/backups/<backup>.json.manifest.json --dry-run
```

To apply after verification:

```bash
npm run dr:restore:dev -- --manifest .data/backups/<backup>.json.manifest.json --yes
```

| Flag | Default | Purpose |
|---|---|---|
| `--manifest` | (required) | Integrity manifest from backup |
| `--backup` | derived from manifest | Override backup file path |
| `--dest` | `.data/astranull-dev.json` | Restore target |
| `--dry-run` | off | Verify checksum and JSON only |
| `--yes` | off | Required to write `--dest` |

Restore validates the manifest before use: `backup_file` must be a simple filename (no path separators, no `..`, not absolute); `sha256` must be a 64-character hex digest; when `bytes` is present it must be a nonnegative integer matching the backup file size. It then verifies manifest SHA-256 against the backup, parses backup JSON, and refuses writes without `--yes`. Malformed manifests fail closed.

### Evidence for SEC-007 (developer scope)

- Unit tests: `tests/unit/dr-backup-restore.test.mjs`
- Operator steps: [`docs/operator-local-runbook.md`](operator-local-runbook.md) (developer validation section)

This satisfies **developer-validation** backup/restore evidence only.

## Production DR gate (not complete)

Production persistence targets **PostgreSQL** with the contract in [`db/schema.sql`](../db/schema.sql) and migrations in [`db/migrations/`](../db/migrations/). The control plane now initializes the Postgres runtime boundary for migrated service families, including safe test-run start/cancel and signed probe dispatch, and fails closed with `postgres_route_not_wired` for route families that are not yet backed by Postgres services. Production DR remains blocked until scheduled encrypted Postgres backups, restore/failover drills, immutable evidence recovery, and full release-route migration are evidenced.

| Capability | Status | Owner expectation |
|---|---|---|
| Postgres continuous / scheduled backups | **Not implemented** in this repo | Operators configure RDS/Cloud SQL (or equivalent) per environment policy |
| Restore drill with RPO/RTO targets | **Not evidenced** | Run at least annual drill; record actual RPO/RTO vs targets |
| Regional failover / multi-AZ | **Not documented for app tier** | DB HA per cloud provider; API/workers per deployment guide |
| Immutable evidence retention | **Policy in progress** | Audit, findings, and high-scale artifacts per retention ADR |
| Kill switch / SOC stop during incident | Governed adapter only | [`docs/operator-local-runbook.md`](operator-local-runbook.md) |

### Production DR checklist (pre-GA)

1. Postgres runtime live in staging and production for all release-required route families; migrations applied via `node scripts/migrate-postgres.mjs`.
2. Automated backups enabled with encryption; restore tested to a non-production clone.
3. Documented RPO (max acceptable data loss) and RTO (max acceptable downtime) signed by operations.
4. Failover drill: promote replica or restore backup; verify tenant RLS and `app.tenant_id` context (`src/persistence/postgres/tenantContext.mjs`).
5. Evidence vault and audit exports recoverable within retention policy.
6. Incident runbook links rollback, forward-fix migrations, and SOC kill switch before traffic adapters.

Do **not** treat `npm run dr:backup:dev` as production DR. It does not back up PostgreSQL, probe results at scale, or cross-region state.

### Production restore/failover drill evidence

Operators record **metadata-only** JSON for each production or staging restore/failover drill. The validator refuses raw database dumps, secrets, tokens, application logs, and customer payloads.

```bash
node scripts/dr-restore-evidence.mjs --input drill-evidence.json --out output/dr-drill-evidence.json
```

Use `--validate-only` to check evidence without writing a manifest. The CLI exits **nonzero** when RPO/RTO measurements exceed signed targets or required operator/custody signoff is missing, but still writes a metadata-only manifest when `--out` is set.

| Flag | Purpose |
|---|---|
| `--input` | Required drill evidence JSON |
| `--out` | Metadata-only validation manifest (no dump contents) |
| `--validate-only` | Validate only; do not write `--out` |

#### Required drill fields

| Section | Required metadata |
|---|---|
| Identity | `drill_id`, `environment`, `drill_type` (`restore` or `failover`), `started_at`, `completed_at` |
| Backup manifest | `backup_manifest.manifest_uri`, `backup_manifest.sha256` (64-char hex digest), `backup_manifest.backup_reference` |
| Restore target | `restore_target.cluster_reference`, `restore_target.database_reference`, `restore_target.restore_mode` |
| RPO/RTO | `rpo_rto.rpo_target_minutes`, `rpo_rto.rto_target_minutes`, `rpo_rto.measured_rpo_minutes`, `rpo_rto.measured_rto_minutes` (measured values must not exceed targets) |
| Operator approvals | `operator_approvals[]` with `role`, `operator`, `approved_at`, `signoff_reference` per approver |
| Evidence custody | Nonempty `evidence_custody_ids[]` referencing immutable custody records (URIs/ids only) |
| Recovery decision | `recovery_decision.decision` (`rollback` or `forward_fix`), `decision_reference`, `operator`, `decided_at` |
| Post-restore checks | `post_restore_verification.checks[]` with `check_id`, `status`, `evidence_uri`, plus `post_restore_verification.signoff_reference` |

Forbidden evidence keys include (non-exhaustive): `database_dump`, `pg_dump`, `sql_dump`, `dump`, `raw_log`, `logs`, `customer_payload`, `token`, `secret`, `database_url`, and other `raw_*` fields. Token-like strings in allowed text fields are redacted in written manifests.

#### Evidence for SEC-007 (production drill scope)

- Unit tests: `tests/unit/dr-restore-evidence.test.mjs`
- Developer backup/restore remains: `tests/unit/dr-backup-restore.test.mjs`

Production DR is still **not complete** until encrypted scheduled Postgres backups, executed restore/failover drills with signed RPO/RTO targets, and immutable custody storage are evidenced in staging and production.
