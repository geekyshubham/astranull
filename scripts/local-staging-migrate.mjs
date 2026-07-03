#!/usr/bin/env node
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { closePgPool, createPgPool } from '../src/persistence/postgres/pool.mjs';
import {
  assertLatestMigrationApplied,
  getLatestMigrationVersion,
  listMigrationFiles,
  runMigrations,
} from '../src/persistence/postgres/migrations.mjs';
import { grantPostgresAppRolePrivileges } from './postgres-grant-app-role.mjs';
import {
  buildLocalPostgresAdminDatabaseUrl,
} from './local-postgres-stack.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');
const MIGRATIONS_DIR = path.join(REPO_ROOT, 'db', 'migrations');

function resolveAdminDatabaseUrl(env = process.env) {
  const explicit = String(env.ASTRANULL_ADMIN_DATABASE_URL ?? '').trim();
  if (explicit) return explicit;

  const databaseUrl = String(env.ASTRANULL_DATABASE_URL ?? '').trim();
  if (databaseUrl) return databaseUrl;

  const host = String(env.ASTRANULL_PG_HOST ?? 'postgres').trim();
  const port = Number(env.ASTRANULL_LOCAL_PG_PORT ?? 5432);
  return buildLocalPostgresAdminDatabaseUrl({ host, port });
}

async function main() {
  const adminEnv = {
    ...process.env,
    ASTRANULL_DATABASE_URL: resolveAdminDatabaseUrl(process.env),
  };

  /** @type {import('pg').Pool | undefined} */
  let pool;
  try {
    pool = createPgPool(adminEnv);
    const files = listMigrationFiles(MIGRATIONS_DIR);
    const latest = getLatestMigrationVersion(files);
    const { results } = await runMigrations(pool, { migrationsDir: MIGRATIONS_DIR, files });
    await assertLatestMigrationApplied(pool, latest);
    await grantPostgresAppRolePrivileges(pool);

    const applied = results.filter((entry) => entry.status === 'applied').map((entry) => entry.version);
    console.log('local-staging-migrate: ok');
    console.log(`  latest_version: ${latest}`);
    if (applied.length > 0) {
      console.log(`  applied: ${applied.join(', ')}`);
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`local-staging-migrate: failed: ${message}`);
    process.exitCode = 1;
  } finally {
    if (pool) await closePgPool(pool);
  }
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main();
}