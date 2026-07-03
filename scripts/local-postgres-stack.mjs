#!/usr/bin/env node
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { closePgPool, createPgPool, pingPostgres } from '../src/persistence/postgres/pool.mjs';
import {
  assertLatestMigrationApplied,
  getLatestMigrationVersion,
  listMigrationFiles,
  runMigrations,
} from '../src/persistence/postgres/migrations.mjs';
import { grantPostgresAppRolePrivileges } from './postgres-grant-app-role.mjs';
import { runPostgresAcceptance } from './postgres-acceptance.mjs';
import { runPostgresRuntimeSmoke } from './postgres-runtime-smoke.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');
const COMPOSE_FILE = path.join(REPO_ROOT, 'docker-compose.yml');
const MIGRATIONS_DIR = path.join(REPO_ROOT, 'db', 'migrations');

export const DEFAULT_LOCAL_PG_PORT = 54329;
export const DEFAULT_LOCAL_PG_ADMIN_USER = 'astranull';
export const DEFAULT_LOCAL_PG_ADMIN_PASSWORD = 'astranull_local_dev';
export const DEFAULT_LOCAL_PG_APP_USER = 'astranull_app';
export const DEFAULT_LOCAL_PG_APP_PASSWORD = 'astranull_app_local_dev';
export const DEFAULT_LOCAL_PG_DATABASE = 'astranull';

/**
 * @param {{
 *   host?: string,
 *   port?: number,
 *   user?: string,
 *   password?: string,
 *   database?: string,
 * }} [options]
 */
export function buildLocalPostgresDatabaseUrl(options = {}) {
  const host = options.host ?? options.pgHost ?? '127.0.0.1';
  const port = options.port ?? DEFAULT_LOCAL_PG_PORT;
  const user = options.user ?? DEFAULT_LOCAL_PG_APP_USER;
  const password = options.password ?? DEFAULT_LOCAL_PG_APP_PASSWORD;
  const database = options.database ?? DEFAULT_LOCAL_PG_DATABASE;
  const encodedUser = encodeURIComponent(user);
  const encodedPassword = encodeURIComponent(password);
  return `postgresql://${encodedUser}:${encodedPassword}@${host}:${port}/${database}`;
}

export function buildLocalPostgresAdminDatabaseUrl(options = {}) {
  return buildLocalPostgresDatabaseUrl({
    ...options,
    user: options.user ?? DEFAULT_LOCAL_PG_ADMIN_USER,
    password: options.password ?? DEFAULT_LOCAL_PG_ADMIN_PASSWORD,
  });
}

/**
 * @param {Record<string, string | undefined>} [overrides]
 * @returns {NodeJS.ProcessEnv}
 */
export function buildLocalPostgresEnv(overrides = {}) {
  const port = overrides.ASTRANULL_LOCAL_PG_PORT
    ? Number(overrides.ASTRANULL_LOCAL_PG_PORT)
    : undefined;
  const databaseUrl = overrides.ASTRANULL_DATABASE_URL
    ?? buildLocalPostgresDatabaseUrl({ port });
  const adminDatabaseUrl = overrides.ASTRANULL_ADMIN_DATABASE_URL
    ?? buildLocalPostgresAdminDatabaseUrl({ port });

  return {
    ...process.env,
    ASTRANULL_DATABASE_URL: databaseUrl,
    ASTRANULL_ADMIN_DATABASE_URL: adminDatabaseUrl,
    ASTRANULL_PERSISTENCE_MODE: 'postgres',
    ASTRANULL_POSTGRES_ACCEPTANCE: '1',
    ASTRANULL_POSTGRES_RUNTIME_SMOKE: '1',
    ...overrides,
  };
}

/**
 * @param {string[]} argv
 */
export function parseLocalPostgresStackArgs(argv = []) {
  const opts = {
    command: 'verify',
    port: DEFAULT_LOCAL_PG_PORT,
    timeoutMs: 60_000,
    help: false,
  };

  const positional = [];
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = () => {
      i += 1;
      if (i >= argv.length) throw new Error(`Missing value for ${arg}`);
      return argv[i];
    };

    if (arg === '--help' || arg === '-h') opts.help = true;
    else if (arg === '--port') opts.port = Number(next());
    else if (arg === '--timeout-ms') opts.timeoutMs = Number(next());
    else if (arg.startsWith('--')) throw new Error(`Unknown argument: ${arg}`);
    else positional.push(arg);
  }

  if (positional.length > 0) {
    opts.command = positional[0];
  }
  if (!['up', 'down', 'wait', 'verify', 'reset', 'status'].includes(opts.command)) {
    throw new Error(`Unknown command: ${opts.command}`);
  }
  if (!Number.isInteger(opts.port) || opts.port < 1 || opts.port > 65535) {
    throw new Error('--port must be an integer between 1 and 65535');
  }
  if (!Number.isInteger(opts.timeoutMs) || opts.timeoutMs < 1_000) {
    throw new Error('--timeout-ms must be an integer >= 1000');
  }

  return opts;
}

/**
 * @param {string} command
 * @param {string[]} args
 * @param {{ cwd?: string, env?: NodeJS.ProcessEnv }} [options]
 */
function runCommand(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd ?? REPO_ROOT,
      env: options.env ?? process.env,
      stdio: 'inherit',
    });
    child.on('error', reject);
    child.on('close', (code) => {
      if (code === 0) resolve();
      else reject(new Error(`${command} ${args.join(' ')} exited with code ${code}`));
    });
  });
}

/**
 * @param {string} subcommand
 * @param {{ port: number, env?: NodeJS.ProcessEnv, removeVolumes?: boolean }} options
 */
export async function runDockerCompose(subcommand, options) {
  const args = ['compose', '-f', COMPOSE_FILE, subcommand];
  if (subcommand === 'up') {
    args.push('-d', '--build');
  }
  if (subcommand === 'down' && options.removeVolumes) {
    args.push('-v');
  }
  await runCommand('docker', args, {
    env: {
      ...(options.env ?? process.env),
      ASTRANULL_LOCAL_PG_PORT: String(options.port),
    },
  });
}

/**
 * @param {NodeJS.ProcessEnv} env
 * @param {{ timeoutMs: number }} options
 */
export async function waitForPostgres(env, options) {
  const started = Date.now();
  /** @type {import('pg').Pool | undefined} */
  let pool;

  while (Date.now() - started < options.timeoutMs) {
    try {
      pool = createPgPool(env);
      await pingPostgres(pool);
      await closePgPool(pool);
      return;
    } catch {
      if (pool) {
        await closePgPool(pool);
        pool = undefined;
      }
      await new Promise((resolve) => setTimeout(resolve, 1_000));
    }
  }

  throw new Error(
    `Timed out after ${options.timeoutMs}ms waiting for PostgreSQL at configured ASTRANULL_DATABASE_URL`,
  );
}

/**
 * @param {NodeJS.ProcessEnv} env
 */
export async function runStartupMigrationCheck(env) {
  const adminEnv = {
    ...env,
    ASTRANULL_DATABASE_URL: env.ASTRANULL_ADMIN_DATABASE_URL ?? env.ASTRANULL_DATABASE_URL,
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
    return { latest, applied };
  } finally {
    if (pool) await closePgPool(pool);
  }
}

/**
 * @param {NodeJS.ProcessEnv} env
 */
export async function runLocalPostgresVerification(env) {
  const migration = await runStartupMigrationCheck(env);
  const acceptance = await runPostgresAcceptance(env);
  if (acceptance.outcome !== 'ok') {
    throw new Error(acceptance.message ?? 'postgres-acceptance did not complete');
  }
  const runtimeSmoke = await runPostgresRuntimeSmoke(env);
  if (runtimeSmoke.outcome !== 'ok') {
    throw new Error(runtimeSmoke.message ?? 'postgres-runtime-smoke did not complete');
  }
  return {
    migration,
    acceptance,
    runtimeSmoke,
  };
}

/**
 * @param {{ command: string, port: number, timeoutMs: number }} opts
 */
export async function runLocalPostgresStack(opts) {
  const env = buildLocalPostgresEnv({
    ASTRANULL_LOCAL_PG_PORT: String(opts.port),
  });

  switch (opts.command) {
    case 'up':
      await runDockerCompose('up', { port: opts.port });
      await waitForPostgres(env, { timeoutMs: opts.timeoutMs });
      console.log('local-postgres-stack: postgres is up and accepting connections');
      return 0;
    case 'down':
      await runDockerCompose('down', { port: opts.port });
      console.log('local-postgres-stack: postgres stack stopped');
      return 0;
    case 'status':
      await runDockerCompose('ps', { port: opts.port });
      return 0;
    case 'wait':
      await waitForPostgres(env, { timeoutMs: opts.timeoutMs });
      console.log('local-postgres-stack: postgres is ready');
      return 0;
    case 'reset':
      await runDockerCompose('down', { port: opts.port, removeVolumes: true });
      await runDockerCompose('up', { port: opts.port });
      await waitForPostgres(env, { timeoutMs: opts.timeoutMs });
      console.log('local-postgres-stack: postgres reset complete');
      return 0;
    case 'verify': {
      const result = await runLocalPostgresVerification(env);
      console.log('local-postgres-stack: verify ok');
      console.log(`  latest_migration: ${result.migration.latest}`);
      if (result.migration.applied.length > 0) {
        console.log(`  applied: ${result.migration.applied.join(', ')}`);
      }
      console.log(`  acceptance_checks: ${result.acceptance.checks?.join(', ')}`);
      console.log(`  runtime_smoke_families: ${result.runtimeSmoke.families?.join(', ')}`);
      return 0;
    }
    default:
      throw new Error(`Unhandled command: ${opts.command}`);
  }
}

async function main(argv = process.argv.slice(2)) {
  const opts = parseLocalPostgresStackArgs(argv);
  if (opts.help) {
    console.log(
      'Usage: node scripts/local-postgres-stack.mjs <up|down|wait|verify|reset|status> '
      + `[--port ${DEFAULT_LOCAL_PG_PORT}] [--timeout-ms 60000]`,
    );
    console.log('');
    console.log('Commands:');
    console.log('  up      Start docker compose PostgreSQL and wait for health');
    console.log('  down    Stop docker compose PostgreSQL');
    console.log('  wait    Wait until PostgreSQL accepts connections');
    console.log('  verify  Apply migrations, run acceptance + runtime-smoke harnesses');
    console.log('  reset   Stop stack, remove local volume, start fresh, and wait');
    console.log('  status  Show docker compose service status');
    return 0;
  }

  if (opts.command === 'verify') {
    try {
      await waitForPostgres(buildLocalPostgresEnv({ ASTRANULL_LOCAL_PG_PORT: String(opts.port) }), {
        timeoutMs: Math.min(opts.timeoutMs, 5_000),
      });
    } catch {
      console.log('local-postgres-stack: postgres not reachable; starting docker compose...');
      await runDockerCompose('up', { port: opts.port });
      await waitForPostgres(buildLocalPostgresEnv({ ASTRANULL_LOCAL_PG_PORT: String(opts.port) }), {
        timeoutMs: opts.timeoutMs,
      });
    }
  }

  return runLocalPostgresStack(opts);
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main().then(
    (code) => process.exit(code ?? 0),
    (err) => {
      console.error(`local-postgres-stack: ${err.message}`);
      process.exit(1);
    },
  );
}