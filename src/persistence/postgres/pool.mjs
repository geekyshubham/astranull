import pg from 'pg';

const DEFAULT_POOL_MAX = 10;
const MIN_POOL_MAX = 1;
const MAX_POOL_MAX = 50;

const DEFAULT_IDLE_TIMEOUT_MS = 30_000;
const MIN_IDLE_TIMEOUT_MS = 1_000;
const MAX_IDLE_TIMEOUT_MS = 600_000;

const DEFAULT_CONNECTION_TIMEOUT_MS = 10_000;
const MIN_CONNECTION_TIMEOUT_MS = 1_000;
const MAX_CONNECTION_TIMEOUT_MS = 120_000;

function parseBoundedInt(raw, name, { min, max, fallback }) {
  if (raw === undefined || raw === null || String(raw).trim() === '') {
    return fallback;
  }
  const n = Number(raw);
  if (!Number.isInteger(n) || n < min || n > max) {
    throw new Error(`${name} must be an integer between ${min} and ${max}.`);
  }
  return n;
}

/**
 * @param {NodeJS.ProcessEnv} [env]
 */
export function resolvePgPoolConfig(env = process.env) {
  const connectionString = (env.ASTRANULL_DATABASE_URL ?? '').trim();
  if (!connectionString) {
    throw new Error('ASTRANULL_DATABASE_URL must be set for PostgreSQL.');
  }

  return {
    connectionString,
    max: parseBoundedInt(env.ASTRANULL_PG_POOL_MAX, 'ASTRANULL_PG_POOL_MAX', {
      min: MIN_POOL_MAX,
      max: MAX_POOL_MAX,
      fallback: DEFAULT_POOL_MAX,
    }),
    idleTimeoutMillis: parseBoundedInt(
      env.ASTRANULL_PG_IDLE_TIMEOUT_MS,
      'ASTRANULL_PG_IDLE_TIMEOUT_MS',
      {
        min: MIN_IDLE_TIMEOUT_MS,
        max: MAX_IDLE_TIMEOUT_MS,
        fallback: DEFAULT_IDLE_TIMEOUT_MS,
      },
    ),
    connectionTimeoutMillis: parseBoundedInt(
      env.ASTRANULL_PG_CONNECTION_TIMEOUT_MS,
      'ASTRANULL_PG_CONNECTION_TIMEOUT_MS',
      {
        min: MIN_CONNECTION_TIMEOUT_MS,
        max: MAX_CONNECTION_TIMEOUT_MS,
        fallback: DEFAULT_CONNECTION_TIMEOUT_MS,
      },
    ),
  };
}

/**
 * @param {import('pg').PoolConfig | NodeJS.ProcessEnv} configOrEnv
 * @returns {import('pg').Pool}
 */
export function createPgPool(configOrEnv = process.env) {
  const config =
    configOrEnv != null &&
    typeof configOrEnv === 'object' &&
    'connectionString' in configOrEnv &&
    configOrEnv.connectionString
      ? configOrEnv
      : resolvePgPoolConfig(configOrEnv);
  return new pg.Pool(config);
}

/**
 * @param {import('pg').Pool | null | undefined} pool
 */
export async function closePgPool(pool) {
  if (pool) {
    await pool.end();
  }
}

/**
 * Lightweight connectivity probe (no secrets logged).
 * @param {import('pg').Pool} pool
 */
export async function pingPostgres(pool) {
  const client = await pool.connect();
  try {
    await client.query('SELECT 1 AS ok');
    return { ok: true };
  } finally {
    client.release();
  }
}