#!/usr/bin/env node
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  assertLatestMigrationApplied,
  getLatestMigrationVersion,
  listMigrationFiles,
  runMigrations,
} from '../src/persistence/postgres/migrations.mjs';
import {
  MIGRATIONS_DIR,
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
} from '../tests/helpers/pg-harness.mjs';

const REVAMP_MIGRATIONS = [
  '0025_dns_challenges',
  '0026_target_verifications',
  '0027_loa_signatures',
  '0028_finding_remediations',
  '0029_waf_coverage_summary_matview',
  '0030_target_group_archive_restore',
  '0031_signup_queue_events',
  '0032_targets_indexes_for_hydrator',
  '0033_high_scale_customer_view_index',
  '0034_privacy_settings_defaults',
  '0035_tenant_dashboard_rollup',
  '0036_signup_queue_events_public_rls',
];

/**
 * @param {Array<{ version: string, status: string }>} results
 * @param {'applied' | 'skipped'} status
 */
function versionsWithStatus(results, status) {
  return results.filter((entry) => entry.status === status).map((entry) => entry.version);
}

/**
 * @param {import('pg').Pool} pool
 */
async function assertPortalTablesExist(pool) {
  const expectedTables = [
    'dns_challenges',
    'target_verifications',
    'loa_signatures',
    'finding_remediations',
    'signup_queue_events',
  ];
  const result = await pool.query(
    `SELECT c.relname AS table_name
     FROM pg_class c
     JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public'
       AND c.relkind = 'r'
       AND c.relname = ANY($1::text[])`,
    [expectedTables],
  );
  const found = new Set(result.rows.map((row) => row.table_name));
  for (const tableName of expectedTables) {
    if (!found.has(tableName)) {
      throw new Error(`Expected portal revamp table "${tableName}" was not created.`);
    }
  }

  const matview = await pool.query(
    `SELECT to_regclass('public.waf_coverage_summary') AS view_name`,
  );
  if (!matview.rows[0]?.view_name) {
    throw new Error('Expected materialized view "waf_coverage_summary" was not created.');
  }
}

async function main() {
  const availability = await resolvePostgresHarnessAvailability(process.env);
  if (!availability.available) {
    console.log(`db-migrate-test: skipped — ${availability.reason}`);
    return;
  }

  await withEphemeralPostgres(
    async (pool, { latestVersion }) => {
      const files = listMigrationFiles(MIGRATIONS_DIR);
      const latest = getLatestMigrationVersion(files);
      if (latest !== latestVersion) {
        throw new Error(`Latest migration mismatch: harness=${latestVersion}, files=${latest}`);
      }

      const first = await runMigrations(pool, { migrationsDir: MIGRATIONS_DIR, files });
      await assertLatestMigrationApplied(pool, latest);
      await assertPortalTablesExist(pool);

      const firstApplied = versionsWithStatus(first.results, 'applied');
      const firstSkipped = versionsWithStatus(first.results, 'skipped');
      if (firstApplied.length > 0) {
        console.log(`db-migrate-test: first pass applied ${firstApplied.length} migration(s)`);
      }
      if (firstSkipped.length > 0) {
        console.log(`db-migrate-test: first pass skipped ${firstSkipped.length} migration(s)`);
      }

      for (const version of REVAMP_MIGRATIONS) {
        const entry = first.results.find((result) => result.version === version);
        if (!entry || entry.status !== 'applied') {
          throw new Error(`Expected revamp migration "${version}" to be applied on first pass.`);
        }
      }

      const second = await runMigrations(pool, { migrationsDir: MIGRATIONS_DIR, files });
      await assertLatestMigrationApplied(pool, latest);

      const unexpectedApplied = versionsWithStatus(second.results, 'applied');
      if (unexpectedApplied.length > 0) {
        throw new Error(
          `Second migration pass unexpectedly applied: ${unexpectedApplied.join(', ')}`,
        );
      }

      const secondSkipped = versionsWithStatus(second.results, 'skipped');
      if (secondSkipped.length !== files.length) {
        throw new Error(
          `Second migration pass expected all ${files.length} migrations skipped; got ${secondSkipped.length}.`,
        );
      }

      console.log('db-migrate-test: ok');
      console.log(`  latest_version: ${latest}`);
      console.log(`  revamp_migrations: ${REVAMP_MIGRATIONS.join(', ')}`);
      console.log('  idempotent_second_pass: all skipped');
    },
    process.env,
    { applyMigrations: false },
  );
}

const isMain =
  process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
  main().catch((err) => {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`db-migrate-test: failed: ${message}`);
    process.exitCode = 1;
  });
}