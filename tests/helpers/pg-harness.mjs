import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import { closePgPool, createPgPool, pingPostgres } from '../../src/persistence/postgres/pool.mjs';
import {
  assertLatestMigrationApplied,
  getLatestMigrationVersion,
  listMigrationFiles,
  runMigrations,
} from '../../src/persistence/postgres/migrations.mjs';
import {
  buildLocalPostgresAdminDatabaseUrl,
  buildLocalPostgresDatabaseUrl,
  buildLocalPostgresEnv,
  DEFAULT_LOCAL_PG_PORT,
  runDockerCompose,
  waitForPostgres,
} from '../../scripts/local-postgres-stack.mjs';
import { grantPostgresAppRolePrivileges } from '../../scripts/postgres-grant-app-role.mjs';

const APP_ROLE_NAME = 'astranull_app';

const ENSURE_APP_ROLE_SQL = `
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${APP_ROLE_NAME}') THEN
    CREATE ROLE ${APP_ROLE_NAME}
      WITH LOGIN PASSWORD 'astranull_app_local_dev'
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
  END IF;
END
$$;
`;

/**
 * @param {import('pg').Pool} pool
 */
export async function ensureHarnessAppRole(pool) {
  await pool.query(ENSURE_APP_ROLE_SQL);
  await pool.query(`GRANT ${APP_ROLE_NAME} TO CURRENT_USER`);
  try {
    await grantPostgresAppRolePrivileges(pool);
  } catch {
    // best-effort for harness-only databases
  }
}

/**
 * Run callback under the non-superuser app role so RLS policies are enforced.
 *
 * @param {import('pg').Pool} pool
 * @param {string} tenantId
 * @param {(client: import('pg').PoolClient) => Promise<unknown>} callback
 */
export async function withTenantContextAsAppRole(pool, tenantId, callback) {
  const normalized = String(tenantId ?? '').trim();
  if (!normalized) {
    throw new Error('tenant id must be a non-empty string.');
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`SET ROLE ${APP_ROLE_NAME}`);
    await client.query(`SELECT set_config('app.tenant_id', $1, true)`, [normalized]);
    const result = await callback(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch {
      // preserve original error
    }
    throw err;
  } finally {
    try {
      await client.query('RESET ROLE');
    } catch {
      // ignore reset failures during teardown
    }
    client.release();
  }
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = path.resolve(__dirname, '..', '..');
export const MIGRATIONS_DIR = path.join(REPO_ROOT, 'db', 'migrations');

const IDENT_RE = /^[a-z_][a-z0-9_]*$/;

/**
 * @param {string} identifier
 */
export function quotePgIdentifier(identifier) {
  const normalized = String(identifier ?? '').trim();
  if (!IDENT_RE.test(normalized)) {
    throw new Error(`Invalid PostgreSQL identifier: ${identifier}`);
  }
  return `"${normalized}"`;
}

/**
 * @param {string} databaseUrl
 */
export function databaseUrlWithDatabase(databaseUrl, database) {
  const url = new URL(String(databaseUrl).replace(/^postgresql:/i, 'postgres:'));
  url.pathname = `/${database}`;
  return url.toString().replace(/^postgres:/i, 'postgresql:');
}

/**
 * @param {string} command
 * @param {string[]} args
 */
function runCommandCapture(command, args) {
  return new Promise((resolve) => {
    const child = spawn(command, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout?.on('data', (chunk) => {
      stdout += chunk;
    });
    child.stderr?.on('data', (chunk) => {
      stderr += chunk;
    });
    child.on('error', () => resolve({ ok: false, stdout, stderr }));
    child.on('close', (code) => resolve({ ok: code === 0, stdout, stderr }));
  });
}

/**
 * @returns {Promise<boolean>}
 */
export async function isDockerAvailable() {
  const result = await runCommandCapture('docker', ['info']);
  return result.ok;
}

/**
 * @param {NodeJS.ProcessEnv} [env]
 */
export function buildHarnessEnv(env = process.env) {
  const port = env.ASTRANULL_LOCAL_PG_PORT
    ? Number(env.ASTRANULL_LOCAL_PG_PORT)
    : DEFAULT_LOCAL_PG_PORT;
  return buildLocalPostgresEnv({
    ...env,
    ASTRANULL_LOCAL_PG_PORT: String(port),
    ASTRANULL_DATABASE_URL:
      env.ASTRANULL_DATABASE_URL ?? buildLocalPostgresDatabaseUrl({ port }),
    ASTRANULL_ADMIN_DATABASE_URL:
      env.ASTRANULL_ADMIN_DATABASE_URL ?? buildLocalPostgresAdminDatabaseUrl({ port }),
  });
}

/**
 * @returns {string[]}
 */
export function buildHarnessDatabaseUrlCandidates(env = process.env) {
  const candidates = [];
  const explicit = String(env.ASTRANULL_DATABASE_URL ?? '').trim();
  if (explicit) {
    candidates.push(explicit);
  }

  const dockerEnv = buildHarnessEnv(env);
  candidates.push(
    dockerEnv.ASTRANULL_ADMIN_DATABASE_URL ?? dockerEnv.ASTRANULL_DATABASE_URL,
  );

  const user = String(env.USER ?? env.USERNAME ?? 'postgres').trim() || 'postgres';
  candidates.push(`postgresql://${encodeURIComponent(user)}@127.0.0.1:5432/postgres`);

  return [...new Set(candidates.filter(Boolean))];
}

/**
 * @param {NodeJS.ProcessEnv} env
 * @param {{ timeoutMs?: number, tryDocker?: boolean }} [options]
 * @returns {Promise<{ available: boolean, reason?: string, env?: NodeJS.ProcessEnv }>}
 */
export async function resolvePostgresHarnessAvailability(env = process.env, options = {}) {
  const harnessEnv = buildHarnessEnv(env);
  const timeoutMs = options.timeoutMs ?? 5_000;

  const tryPing = async (databaseUrl) => {
    /** @type {import('pg').Pool | undefined} */
    let pool;
    try {
      pool = createPgPool({
        ...harnessEnv,
        ASTRANULL_DATABASE_URL: databaseUrl,
      });
      await pingPostgres(pool);
      return true;
    } catch {
      return false;
    } finally {
      if (pool) await closePgPool(pool);
    }
  };

  for (const databaseUrl of buildHarnessDatabaseUrlCandidates(env)) {
    if (await tryPing(databaseUrl)) {
      return {
        available: true,
        env: {
          ...harnessEnv,
          ASTRANULL_DATABASE_URL: databaseUrl,
          ASTRANULL_ADMIN_DATABASE_URL: databaseUrl,
        },
      };
    }
  }

  if (options.tryDocker !== false && (await isDockerAvailable())) {
    try {
      await runDockerCompose('up', { port: Number(harnessEnv.ASTRANULL_LOCAL_PG_PORT) });
      await waitForPostgres(harnessEnv, { timeoutMs: Math.max(timeoutMs, 60_000) });
      const dockerUrl =
        harnessEnv.ASTRANULL_ADMIN_DATABASE_URL ?? harnessEnv.ASTRANULL_DATABASE_URL;
      if (await tryPing(dockerUrl)) {
        return { available: true, env: harnessEnv };
      }
    } catch {
      // fall through to skip message
    }
  }

  return {
    available: false,
    reason:
      'PostgreSQL unavailable (set ASTRANULL_DATABASE_URL or start Docker/local Postgres on port '
      + `${harnessEnv.ASTRANULL_LOCAL_PG_PORT ?? DEFAULT_LOCAL_PG_PORT}).`,
  };
}

/**
 * @param {import('pg').Pool} adminPool
 * @param {string} databaseName
 */
export async function createEphemeralDatabase(adminPool, databaseName) {
  const quoted = quotePgIdentifier(databaseName);
  await adminPool.query(`CREATE DATABASE ${quoted}`);
}

/**
 * @param {import('pg').Pool} adminPool
 * @param {string} databaseName
 */
export async function dropEphemeralDatabase(adminPool, databaseName) {
  const quoted = quotePgIdentifier(databaseName);
  await adminPool.query(
    `SELECT pg_terminate_backend(pid)
     FROM pg_stat_activity
     WHERE datname = $1 AND pid <> pg_backend_pid()`,
    [databaseName],
  );
  await adminPool.query(`DROP DATABASE IF EXISTS ${quoted}`);
}

/**
 * @param {string} [suffix]
 */
export function buildEphemeralDatabaseName(suffix = 'harness') {
  const token = `${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  return `astranull_test_${suffix}_${token}`.slice(0, 63);
}

/**
 * @param {NodeJS.ProcessEnv} harnessEnv
 * @param {string} databaseName
 */
export function buildEphemeralDatabaseEnv(harnessEnv, databaseName) {
  const adminUrl = harnessEnv.ASTRANULL_ADMIN_DATABASE_URL ?? harnessEnv.ASTRANULL_DATABASE_URL;
  const databaseUrl = databaseUrlWithDatabase(adminUrl, databaseName);
  return {
    ...harnessEnv,
    ASTRANULL_DATABASE_URL: databaseUrl,
    ASTRANULL_ADMIN_DATABASE_URL: adminUrl,
  };
}

/**
 * Provision a fresh ephemeral database, apply migrations, and tear down afterward.
 *
 * @param {(pool: import('pg').Pool, context: { databaseName: string, latestVersion: string }) => Promise<unknown>} callback
 * @param {NodeJS.ProcessEnv} [env]
 * @param {{ applyMigrations?: boolean, databaseName?: string }} [options]
 */
export async function withEphemeralPostgres(callback, env = process.env, options = {}) {
  const availability = await resolvePostgresHarnessAvailability(env);
  if (!availability.available || !availability.env) {
    throw new Error(availability.reason ?? 'PostgreSQL harness unavailable.');
  }

  const harnessEnv = availability.env;
  const databaseName = options.databaseName ?? buildEphemeralDatabaseName('migrate');
  const adminUrl = harnessEnv.ASTRANULL_ADMIN_DATABASE_URL ?? harnessEnv.ASTRANULL_DATABASE_URL;

  /** @type {import('pg').Pool | undefined} */
  let adminPool;
  /** @type {import('pg').Pool | undefined} */
  let pool;

  try {
    adminPool = createPgPool({ ...harnessEnv, ASTRANULL_DATABASE_URL: adminUrl });
    await createEphemeralDatabase(adminPool, databaseName);

    const ephemeralEnv = buildEphemeralDatabaseEnv(harnessEnv, databaseName);
    pool = createPgPool(ephemeralEnv);

    const files = listMigrationFiles(MIGRATIONS_DIR);
    const latestVersion = getLatestMigrationVersion(files);

    if (options.applyMigrations !== false) {
      await runMigrations(pool, { migrationsDir: MIGRATIONS_DIR, files });
      await assertLatestMigrationApplied(pool, latestVersion);
      await ensureHarnessAppRole(pool);
    }

    return await callback(pool, { databaseName, latestVersion });
  } finally {
    if (pool) await closePgPool(pool);
    if (adminPool) {
      try {
        await dropEphemeralDatabase(adminPool, databaseName);
      } catch {
        // best-effort cleanup
      }
      await closePgPool(adminPool);
    }
  }
}

/**
 * @param {import('pg').Pool} pool
 * @param {readonly string[]} policyNames
 */
export async function assertRlsPoliciesExist(pool, policyNames) {
  const result = await pool.query(
    `SELECT policyname
     FROM pg_policies
     WHERE schemaname = 'public'
       AND policyname = ANY($1::text[])`,
    [policyNames],
  );
  const found = new Set(result.rows.map((row) => row.policyname));
  for (const policyName of policyNames) {
    if (!found.has(policyName)) {
      throw new Error(`Expected RLS policy "${policyName}" was not found.`);
    }
  }
}

export { pg };