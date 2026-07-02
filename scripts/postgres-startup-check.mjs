#!/usr/bin/env node
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { redactDatabaseUrlInMessage } from '../src/lib/pgErrorRedact.mjs';
import { closePgPool, createPgPool, pingPostgres, resolvePgPoolConfig } from '../src/persistence/postgres/pool.mjs';
import {
  assertLatestMigrationApplied,
  getLatestMigrationVersion,
  listMigrationFiles,
  runMigrations,
} from '../src/persistence/postgres/migrations.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '..');
const MIGRATIONS_DIR = path.join(ROOT, 'db', 'migrations');

const USAGE = `postgres-startup-check: verify PostgreSQL connectivity and migration state.

This preflight verifies DB connectivity and migrations only; it does not start the control plane.

Environment:
  ASTRANULL_DATABASE_URL (required)
  ASTRANULL_PG_POOL_MAX, ASTRANULL_PG_IDLE_TIMEOUT_MS, ASTRANULL_PG_CONNECTION_TIMEOUT_MS (optional)

Options:
  --migrate  Apply pending migrations before verifying latest version
  --help     Show this message
`;

/**
 * @param {string[]} argv
 * @returns {{ migrate: boolean, help: boolean }}
 */
export function parseStartupCheckArgs(argv) {
  const args = argv.slice(2);
  let migrate = false;
  let help = false;

  for (const arg of args) {
    if (arg === '--help' || arg === '-h') {
      help = true;
      continue;
    }
    if (arg === '--migrate') {
      migrate = true;
      continue;
    }
    throw new Error(`postgres-startup-check: unknown argument "${arg}".`);
  }

  return { migrate, help };
}

/**
 * @param {unknown} message
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} [env]
 */
export function redactStartupCheckErrorMessage(message, env = process.env) {
  return redactDatabaseUrlInMessage(message, env);
}

/**
 * @param {Array<{ version: string, status: string }>} results
 */
export function summarizeMigrationResults(results) {
  const applied = results.filter((r) => r.status === 'applied').map((r) => r.version);
  const skipped = results.filter((r) => r.status === 'skipped').map((r) => r.version);
  return { applied, skipped };
}

/**
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} env
 * @param {{ migrate?: boolean }} [args]
 */
export function resolveStartupCheckConfig(env, args = {}) {
  const databaseUrl = String(env.ASTRANULL_DATABASE_URL ?? '').trim();
  if (!databaseUrl) {
    return {
      ok: false,
      message: 'postgres-startup-check: ASTRANULL_DATABASE_URL must be set.',
    };
  }

  let poolLabels;
  try {
    const cfg = resolvePgPoolConfig(env);
    poolLabels = {
      max: cfg.max,
      idleTimeoutMillis: cfg.idleTimeoutMillis,
      connectionTimeoutMillis: cfg.connectionTimeoutMillis,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, message };
  }

  return {
    ok: true,
    migrate: Boolean(args.migrate),
    poolLabels,
  };
}

/**
 * @param {import('pg').Pool} pool
 * @param {{ migrate: boolean }} options
 */
async function runStartupCheck(pool, { migrate }) {
  const files = listMigrationFiles(MIGRATIONS_DIR);
  const latest = getLatestMigrationVersion(files);

  await pingPostgres(pool);

  /** @type {Array<{ version: string, status: string }>} */
  let results = [];
  if (migrate) {
    ({ results } = await runMigrations(pool, { migrationsDir: MIGRATIONS_DIR, files }));
  }

  await assertLatestMigrationApplied(pool, latest);

  return { latest, results, migrationsMutated: migrate };
}

async function main() {
  const parsed = parseStartupCheckArgs(process.argv);
  if (parsed.help) {
    console.log(USAGE.trimEnd());
    return;
  }

  const config = resolveStartupCheckConfig(process.env, { migrate: parsed.migrate });
  if (!config.ok) {
    console.error(config.message);
    process.exitCode = 1;
    return;
  }

  /** @type {import('pg').Pool | undefined} */
  let pool;
  try {
    pool = createPgPool(process.env);
    const { latest, results, migrationsMutated } = await runStartupCheck(pool, {
      migrate: config.migrate,
    });
    const summary = summarizeMigrationResults(results);

    console.log('postgres-startup-check: ok');
    console.log('  runtime_adapter: not_wired');
    console.log(`  ping: ok`);
    console.log(`  latest_version: ${latest}`);
    console.log(`  migrations_mode: ${migrationsMutated ? 'apply_then_verify' : 'verify_only'}`);
    if (config.poolLabels) {
      console.log(`  pool_max: ${config.poolLabels.max}`);
      console.log(`  pool_idle_timeout_ms: ${config.poolLabels.idleTimeoutMillis}`);
      console.log(`  pool_connection_timeout_ms: ${config.poolLabels.connectionTimeoutMillis}`);
    }
    if (summary.applied.length) {
      console.log(`  applied: ${summary.applied.join(', ')}`);
    }
    if (summary.skipped.length) {
      console.log(`  skipped: ${summary.skipped.join(', ')}`);
    }
  } catch (err) {
    const message = redactStartupCheckErrorMessage(err, process.env);
    console.error(`postgres-startup-check: failed: ${message}`);
    process.exitCode = 1;
  } finally {
    if (pool) {
      await closePgPool(pool);
    }
  }
}

const isMain =
  process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
  main();
}