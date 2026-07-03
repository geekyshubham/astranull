#!/usr/bin/env node
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createPostgresRuntime } from '../src/persistence/postgres/runtime.mjs';

const PG_URL_RE = /postgres(?:ql)?:\/\/[^\s'"]+/gi;

/** @type {readonly { family: string, keys: readonly string[] }[]} */
export const POSTGRES_RUNTIME_SMOKE_SERVICE_FAMILIES = Object.freeze([
  { family: 'catalog', keys: ['tenants', 'targetGroups'] },
  { family: 'auth', keys: ['tokens', 'serviceAccounts'] },
  { family: 'agents', keys: ['agents', 'agentAuth'] },
  { family: 'testRuns', keys: ['testRuns'] },
  { family: 'events', keys: ['events'] },
  { family: 'notifications', keys: ['notifications'] },
  { family: 'reports', keys: ['reports'] },
  { family: 'secretVault', keys: ['secretVault'] },
  { family: 'state', keys: ['state'] },
  { family: 'probeJobs', keys: ['probeJobs'] },
  { family: 'highScale', keys: ['highScale'] },
  { family: 'agentUpdates', keys: ['agentUpdates'] },
  { family: 'wafPosture', keys: ['wafPosture'] },
  { family: 'wafDrift', keys: ['wafDrift'] },
  { family: 'wafOrchestrator', keys: ['wafOrchestrator'] },
  { family: 'supplyChain', keys: ['supplyChainRisk'] },
  { family: 'productionReleaseEvidence', keys: ['productionReleaseEvidence'] },
  { family: 'retention', keys: ['retention'] },
  { family: 'audit', keys: ['audit'] },
]);

/**
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} env
 * @returns {{ action: 'skip' | 'run' | 'fail', message?: string }}
 */
export function resolvePostgresRuntimeSmokeDecision(env) {
  const enabled = env.ASTRANULL_POSTGRES_RUNTIME_SMOKE === '1';
  const required = env.ASTRANULL_REQUIRE_POSTGRES_RUNTIME_SMOKE === '1';

  if (!enabled) {
    if (required) {
      return {
        action: 'fail',
        message:
          'postgres-runtime-smoke: required (ASTRANULL_REQUIRE_POSTGRES_RUNTIME_SMOKE=1) but not enabled; set ASTRANULL_POSTGRES_RUNTIME_SMOKE=1.',
      };
    }
    return {
      action: 'skip',
      message:
        'postgres-runtime-smoke: skipped (set ASTRANULL_POSTGRES_RUNTIME_SMOKE=1 and ASTRANULL_DATABASE_URL to run DB-backed runtime wiring evidence).',
    };
  }

  const databaseUrl = String(env.ASTRANULL_DATABASE_URL ?? '').trim();
  if (!databaseUrl) {
    return {
      action: 'fail',
      message:
        'postgres-runtime-smoke: ASTRANULL_POSTGRES_RUNTIME_SMOKE=1 requires ASTRANULL_DATABASE_URL.',
    };
  }

  return { action: 'run' };
}

/**
 * @param {unknown} message
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} [env]
 */
export function redactRuntimeSmokeErrorMessage(message, env = process.env) {
  let text = message instanceof Error ? message.message : String(message ?? '');
  text = text.replace(PG_URL_RE, '[redacted-database-url]');
  const url = String(env.ASTRANULL_DATABASE_URL ?? '').trim();
  if (url && text.includes(url)) {
    text = text.split(url).join('[redacted-database-url]');
  }
  return text;
}

/**
 * @param {Record<string, unknown> | undefined | null} services
 * @returns {string[]}
 */
export function verifyRuntimeSmokeServiceFamilies(services) {
  if (!services || typeof services !== 'object') {
    throw new Error('postgres-runtime-smoke: runtime.services is missing.');
  }

  const verified = [];
  for (const { family, keys } of POSTGRES_RUNTIME_SMOKE_SERVICE_FAMILIES) {
    for (const key of keys) {
      const value = services[key];
      if (value === undefined || value === null) {
        throw new Error(
          `postgres-runtime-smoke: missing runtime.services.${key} (${family} family).`,
        );
      }
      if (typeof value !== 'object') {
        throw new Error(
          `postgres-runtime-smoke: runtime.services.${key} must be an object (${family} family).`,
        );
      }
    }
    verified.push(family);
  }
  return verified;
}

/**
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} env
 * @param {{
 *   createPostgresRuntime?: typeof createPostgresRuntime,
 *   postgresRuntimeOptions?: Parameters<typeof createPostgresRuntime>[1],
 * }} [options]
 * @returns {Promise<{ outcome: 'skip' | 'ok', families?: string[], health?: Record<string, unknown> }>}
 */
export async function runPostgresRuntimeSmoke(env, options = {}) {
  const decision = resolvePostgresRuntimeSmokeDecision(env);
  if (decision.action === 'skip') {
    return { outcome: 'skip', message: decision.message };
  }
  if (decision.action === 'fail') {
    throw new Error(decision.message);
  }

  const createRuntimeFn = options.createPostgresRuntime ?? createPostgresRuntime;

  /** @type {Awaited<ReturnType<typeof createPostgresRuntime>> | undefined} */
  let runtime;
  try {
    runtime = await createRuntimeFn(env, options.postgresRuntimeOptions);
    const families = verifyRuntimeSmokeServiceFamilies(runtime.services);
    const health = await runtime.health();
    return { outcome: 'ok', families, health };
  } finally {
    if (runtime) {
      await runtime.close();
    }
  }
}

async function main() {
  const decision = resolvePostgresRuntimeSmokeDecision(process.env);
  if (decision.action === 'skip') {
    console.log(decision.message);
    return;
  }
  if (decision.action === 'fail') {
    console.error(decision.message);
    process.exitCode = 1;
    return;
  }

  try {
    const result = await runPostgresRuntimeSmoke(process.env);
    console.log('postgres-runtime-smoke: ok');
    console.log(`  families: ${result.families?.join(', ')}`);
    if (result.health?.latestMigration) {
      console.log(`  latest_migration: ${result.health.latestMigration}`);
    }
  } catch (err) {
    const message = redactRuntimeSmokeErrorMessage(err, process.env);
    console.error(`postgres-runtime-smoke: failed: ${message}`);
    process.exitCode = 1;
  }
}

const isMain =
  process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
  main();
}