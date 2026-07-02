import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';

const UNDEFINED_TABLE = '42P01';

/** PostgreSQL advisory transaction lock key for serializing migration runs across processes. */
export const MIGRATION_ADVISORY_LOCK_KEY = 894273891;

/**
 * @param {string} filename
 */
export function migrationVersionFromFilename(filename) {
  if (!filename.endsWith('.sql')) {
    throw new Error(`Migration filename must end with .sql: ${filename}`);
  }
  return filename.slice(0, -'.sql'.length);
}

/**
 * @param {string} migrationsDir
 */
export function listMigrationFiles(migrationsDir) {
  const names = readdirSync(migrationsDir)
    .filter((name) => name.endsWith('.sql'))
    .sort();
  return names.map((name) => ({
    name,
    version: migrationVersionFromFilename(name),
    path: path.join(migrationsDir, name),
    sql: readFileSync(path.join(migrationsDir, name), 'utf8'),
  }));
}

/**
 * @param {Array<{ version: string }>} files
 */
export function getLatestMigrationVersion(files) {
  if (!files.length) {
    throw new Error('No migration files found.');
  }
  return files[files.length - 1].version;
}

/**
 * @param {import('pg').PoolClient | import('pg').Pool} db
 */
export async function fetchAppliedMigrationVersions(db) {
  const regResult = await db.query("SELECT to_regclass('schema_migrations') AS table_name");
  const tableName = regResult.rows[0]?.table_name;
  if (tableName == null) {
    return new Set();
  }
  try {
    const result = await db.query('SELECT version FROM schema_migrations');
    return new Set(result.rows.map((row) => row.version));
  } catch (err) {
    if (err && err.code === UNDEFINED_TABLE) {
      return new Set();
    }
    throw err;
  }
}

/**
 * @param {import('pg').Pool} pool
 * @param {{ migrationsDir: string, files?: ReturnType<typeof listMigrationFiles> }} options
 */
export async function runMigrations(pool, { migrationsDir, files: filesOverride }) {
  const files = filesOverride ?? listMigrationFiles(migrationsDir);
  const client = await pool.connect();
  const results = [];

  try {
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock($1)', [MIGRATION_ADVISORY_LOCK_KEY]);
    const appliedBefore = await fetchAppliedMigrationVersions(client);

    for (const file of files) {
      if (appliedBefore.has(file.version)) {
        results.push({ version: file.version, status: 'skipped' });
        continue;
      }

      await client.query(file.sql);
      await client.query(
        `INSERT INTO schema_migrations (version) VALUES ($1) ON CONFLICT (version) DO NOTHING`,
        [file.version],
      );
      appliedBefore.add(file.version);
      results.push({ version: file.version, status: 'applied' });
    }

    await client.query('COMMIT');
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch {
      // ignore rollback errors while surfacing original failure
    }
    throw err;
  } finally {
    client.release();
  }

  return { files, results };
}

/**
 * @param {import('pg').Pool} pool
 * @param {string} latestVersion
 */
export async function assertLatestMigrationApplied(pool, latestVersion) {
  const applied = await fetchAppliedMigrationVersions(pool);
  if (!applied.has(latestVersion)) {
    throw new Error(
      `Latest migration "${latestVersion}" is not recorded in schema_migrations.`,
    );
  }
}