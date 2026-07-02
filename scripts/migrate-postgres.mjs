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

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '..');
const MIGRATIONS_DIR = path.join(ROOT, 'db', 'migrations');

async function main() {
  const pool = createPgPool(process.env);
  try {
    const files = listMigrationFiles(MIGRATIONS_DIR);
    const latest = getLatestMigrationVersion(files);
    const { results } = await runMigrations(pool, { migrationsDir: MIGRATIONS_DIR, files });
    await assertLatestMigrationApplied(pool, latest);

    const applied = results.filter((r) => r.status === 'applied').map((r) => r.version);
    const skipped = results.filter((r) => r.status === 'skipped').map((r) => r.version);

    console.log('migrate-postgres: ok');
    console.log(`  latest_version: ${latest}`);
    if (applied.length) {
      console.log(`  applied: ${applied.join(', ')}`);
    }
    if (skipped.length) {
      console.log(`  skipped: ${skipped.join(', ')}`);
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`migrate-postgres: failed: ${message}`);
    process.exitCode = 1;
  } finally {
    await closePgPool(pool);
  }
}

const isMain =
  process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
  main();
}