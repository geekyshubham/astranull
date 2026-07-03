import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';

const UNDEFINED_TABLE = '42P01';

/** PostgreSQL advisory transaction lock key for serializing migration runs across processes. */
export const MIGRATION_ADVISORY_LOCK_KEY = 894273891;

const CREATE_INDEX_CONCURRENTLY = /CREATE\s+(?:UNIQUE\s+)?INDEX\s+CONCURRENTLY/i;
const CREATE_INDEX_CONCURRENTLY_NAME =
  /CREATE\s+(?:UNIQUE\s+)?INDEX\s+CONCURRENTLY\s+(?:IF\s+NOT\s+EXISTS\s+)?((?:"[^"]+"|[a-zA-Z_][\w$]*)(?:\.(?:"[^"]+"|[a-zA-Z_][\w$]*))?)/i;

/**
 * @param {string} sql
 */
export function migrationRequiresOutsideTransaction(sql) {
  return CREATE_INDEX_CONCURRENTLY.test(sql);
}

function splitSqlStatements(sql) {
  return sql
    .split(';')
    .map((statement) => statement.trim())
    .filter(Boolean)
    .map((statement) => `${statement};`);
}

function quoteIdentifier(identifier) {
  return `"${String(identifier).replace(/"/g, '""')}"`;
}

function splitSqlIdentifier(identifier) {
  const parts = [];
  let current = '';
  let inQuote = false;
  for (let i = 0; i < identifier.length; i += 1) {
    const ch = identifier[i];
    if (ch === '"') {
      current += ch;
      if (identifier[i + 1] === '"') {
        current += identifier[i + 1];
        i += 1;
      } else {
        inQuote = !inQuote;
      }
      continue;
    }
    if (ch === '.' && !inQuote) {
      parts.push(current);
      current = '';
      continue;
    }
    current += ch;
  }
  if (current) parts.push(current);
  return parts;
}

function unquoteIdentifier(identifier) {
  const trimmed = String(identifier).trim();
  if (trimmed.startsWith('"') && trimmed.endsWith('"')) {
    return trimmed.slice(1, -1).replace(/""/g, '"');
  }
  return trimmed;
}

function parseConcurrentIndexIdentifier(statement) {
  const match = String(statement).match(CREATE_INDEX_CONCURRENTLY_NAME);
  if (!match) return null;
  const parts = splitSqlIdentifier(match[1]).map(unquoteIdentifier);
  const indexName = parts.at(-1);
  if (!indexName) return null;
  const schemaName = parts.length > 1 ? parts[0] : null;
  return { schemaName, indexName };
}

async function dropInvalidConcurrentIndexIfPresent(client, statement) {
  const index = parseConcurrentIndexIdentifier(statement);
  if (!index) return;
  const params = [index.indexName];
  const schemaClause = index.schemaName ? 'AND n.nspname = $2' : '';
  if (index.schemaName) params.push(index.schemaName);
  const { rows } = await client.query(
    `SELECT n.nspname AS schema_name, c.relname AS index_name
     FROM pg_class c
     JOIN pg_index i ON i.indexrelid = c.oid
     JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE c.relname = $1
       ${schemaClause}
       AND i.indisvalid = false`,
    params,
  );
  for (const row of rows) {
    await client.query(
      `DROP INDEX CONCURRENTLY IF EXISTS ${quoteIdentifier(row.schema_name)}.${quoteIdentifier(row.index_name)}`,
    );
  }
}

async function assertConcurrentIndexValid(client, statement) {
  const index = parseConcurrentIndexIdentifier(statement);
  if (!index) return;
  const params = [index.indexName];
  const schemaClause = index.schemaName ? 'AND n.nspname = $2' : '';
  if (index.schemaName) params.push(index.schemaName);
  const { rows } = await client.query(
    `SELECT c.relname AS index_name
     FROM pg_class c
     JOIN pg_index i ON i.indexrelid = c.oid
     JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE c.relname = $1
       ${schemaClause}
       AND i.indisvalid = true`,
    params,
  );
  if (!rows.length) {
    throw new Error(`Concurrent index "${index.indexName}" was not valid after migration.`);
  }
}

async function applyOutsideTransactionStatement(client, statement) {
  if (!CREATE_INDEX_CONCURRENTLY.test(statement)) {
    await client.query(statement);
    return;
  }
  await dropInvalidConcurrentIndexIfPresent(client, statement);
  await client.query(statement);
  await assertConcurrentIndexValid(client, statement);
}

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
 * @param {import('pg').PoolClient} client
 */
async function beginTransactionalMigrationBatch(client) {
  await client.query('BEGIN');
  await client.query('SELECT pg_advisory_xact_lock($1)', [MIGRATION_ADVISORY_LOCK_KEY]);
}

/**
 * @param {import('pg').PoolClient} client
 * @param {string} sql
 * @param {string} version
 */
async function applyOutsideTransactionMigration(client, sql, version) {
  await client.query('SELECT pg_advisory_lock($1)', [MIGRATION_ADVISORY_LOCK_KEY]);
  try {
    const applied = await fetchAppliedMigrationVersions(client);
    if (applied.has(version)) {
      return 'skipped';
    }
    for (const statement of splitSqlStatements(sql)) {
      await applyOutsideTransactionStatement(client, statement);
    }
    await client.query(
      `INSERT INTO schema_migrations (version) VALUES ($1) ON CONFLICT (version) DO NOTHING`,
      [version],
    );
    return 'applied';
  } finally {
    await client.query('SELECT pg_advisory_unlock($1)', [MIGRATION_ADVISORY_LOCK_KEY]);
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
  let inTransaction = false;

  try {
    await beginTransactionalMigrationBatch(client);
    inTransaction = true;
    let appliedBefore = await fetchAppliedMigrationVersions(client);

    for (const file of files) {
      if (appliedBefore.has(file.version)) {
        results.push({ version: file.version, status: 'skipped' });
        continue;
      }

      if (migrationRequiresOutsideTransaction(file.sql)) {
        if (inTransaction) {
          await client.query('COMMIT');
          inTransaction = false;
        }
        const status = await applyOutsideTransactionMigration(client, file.sql, file.version);
        results.push({ version: file.version, status });
        await beginTransactionalMigrationBatch(client);
        inTransaction = true;
        appliedBefore = await fetchAppliedMigrationVersions(client);
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

    if (inTransaction) {
      await client.query('COMMIT');
      inTransaction = false;
    }
  } catch (err) {
    if (inTransaction) {
      try {
        await client.query('ROLLBACK');
      } catch {
        // ignore rollback errors while surfacing original failure
      }
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
