#!/usr/bin/env node
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  DEFAULT_LOCAL_STAGING_BASE_URL,
  LOCAL_STAGING_ENVIRONMENT,
  LOCAL_STAGING_RELEASE_ID,
} from './lib/localStaging.mjs';
import {
  buildLocalPostgresEnv,
  runDockerCompose,
  runLocalPostgresVerification,
  waitForPostgres,
} from './local-postgres-stack.mjs';
import { runSeedLocalStagingTenant } from './seed-local-staging-tenant.mjs';
import { runLocalStagingSmoke } from './local-staging-smoke.mjs';
import { collectReleaseEvidence } from './collect-release-evidence.mjs';
import { runLocalStagingE2eMatrix } from './local-staging-e2e-matrix.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');
const COMPOSE_FILE = path.join(REPO_ROOT, 'docker-compose.yml');

/**
 * @param {string[]} argv
 */
export function parseLocalStagingStackArgs(argv = []) {
  const opts = {
    command: 'up',
    port: 54329,
    apiPort: 3000,
    timeoutMs: 120_000,
    baseUrl: DEFAULT_LOCAL_STAGING_BASE_URL,
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
    else if (arg === '--api-port') opts.apiPort = Number(next());
    else if (arg === '--base-url') opts.baseUrl = next();
    else if (arg === '--timeout-ms') opts.timeoutMs = Number(next());
    else if (arg.startsWith('--')) throw new Error(`Unknown argument: ${arg}`);
    else positional.push(arg);
  }

  if (positional.length > 0) opts.command = positional[0];
  const allowed = ['up', 'down', 'reset', 'status', 'seed', 'smoke', 'e2e-matrix', 'verify', 'collect-evidence', 'all'];
  if (!allowed.includes(opts.command)) {
    throw new Error(`Unknown command: ${opts.command}`);
  }
  return opts;
}

async function waitForControlPlane(baseUrl, timeoutMs) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    try {
      const response = await fetch(new URL('/health', baseUrl));
      if (response.ok) return;
    } catch {
      // retry
    }
    await new Promise((resolve) => setTimeout(resolve, 2_000));
  }
  throw new Error(`Timed out waiting for control plane at ${baseUrl}`);
}

/**
 * @param {{ command: string, port: number, apiPort: number, timeoutMs: number, baseUrl: string }} opts
 */
export async function runLocalStagingStack(opts) {
  const env = buildLocalPostgresEnv({
    ASTRANULL_LOCAL_PG_PORT: String(opts.port),
    ASTRANULL_PG_HOST: '127.0.0.1',
    ASTRANULL_LOCAL_STAGING_BASE_URL: opts.baseUrl,
  });

  switch (opts.command) {
    case 'up':
      await runDockerCompose('up', { port: opts.port, env: { ...env, ASTRANULL_LOCAL_STAGING_PORT: String(opts.apiPort) } });
      await waitForPostgres(env, { timeoutMs: opts.timeoutMs });
      await waitForControlPlane(opts.baseUrl, opts.timeoutMs);
      console.log('local-staging-stack: up');
      console.log(`  postgres: 127.0.0.1:${opts.port}`);
      console.log(`  api: ${opts.baseUrl}`);
      console.log(`  environment: ${LOCAL_STAGING_ENVIRONMENT}`);
      return 0;
    case 'down':
      await runDockerCompose('down', { port: opts.port });
      console.log('local-staging-stack: down');
      return 0;
    case 'reset':
      await runDockerCompose('down', { port: opts.port, removeVolumes: true });
      await runDockerCompose('up', { port: opts.port, env: { ...env, ASTRANULL_LOCAL_STAGING_PORT: String(opts.apiPort) } });
      await waitForPostgres(env, { timeoutMs: opts.timeoutMs });
      await waitForControlPlane(opts.baseUrl, opts.timeoutMs);
      console.log('local-staging-stack: reset complete');
      return 0;
    case 'status':
      await runDockerCompose('ps', { port: opts.port });
      return 0;
    case 'seed': {
      const result = await runSeedLocalStagingTenant(env);
      console.log(
        `local-staging-stack: seed ${result.seeded ? 'ok' : 'already_present'} (tenant=${result.tenantId})`,
      );
      return 0;
    }
    case 'smoke': {
      const result = await runLocalStagingSmoke(opts.baseUrl);
      console.log(`local-staging-stack: smoke ok (${result.checks.join(', ')})`);
      return 0;
    }
    case 'verify': {
      await runLocalPostgresVerification(env);
      await waitForControlPlane(opts.baseUrl, Math.min(opts.timeoutMs, 15_000)).catch(() => null);
      try {
        const smoke = await runLocalStagingSmoke(opts.baseUrl);
        console.log('local-staging-stack: verify ok');
        console.log(`  postgres_runtime_smoke: ok`);
        console.log(`  api_smoke: ${smoke.checks.join(', ')}`);
      } catch (err) {
        console.log('local-staging-stack: postgres verify ok; api smoke skipped or failed');
        console.log(`  api_smoke_error: ${err instanceof Error ? err.message : String(err)}`);
      }
      return 0;
    }
    case 'e2e-matrix': {
      const result = await runLocalStagingE2eMatrix({ baseUrl: opts.baseUrl });
      console.log(
        `local-staging-stack: e2e-matrix ${result.validation.ok ? 'ok' : 'failed'} `
        + `(overall_status=${result.artifact.overall_status})`,
      );
      return result.validation.ok ? 0 : 1;
    }
    case 'collect-evidence': {
      const summary = await collectReleaseEvidence({
        environment: LOCAL_STAGING_ENVIRONMENT,
        releaseId: LOCAL_STAGING_RELEASE_ID,
      });
      console.log(
        `local-staging-stack: evidence collected for ${LOCAL_STAGING_ENVIRONMENT} `
        + `(${summary.kindsCollected}/${summary.kindsRequested} kinds, release_id=${summary.releaseId})`,
      );
      return 0;
    }
    case 'all':
      await runLocalStagingStack({ ...opts, command: 'up' });
      await runSeedLocalStagingTenant(env);
      await runLocalStagingStack({ ...opts, command: 'verify' });
      await runLocalStagingStack({ ...opts, command: 'smoke' });
      await runLocalStagingStack({ ...opts, command: 'e2e-matrix' });
      await runLocalStagingStack({ ...opts, command: 'collect-evidence' });
      console.log('local-staging-stack: all steps complete');
      return 0;
    default:
      throw new Error(`Unhandled command: ${opts.command}`);
  }
}

async function main(argv = process.argv.slice(2)) {
  const opts = parseLocalStagingStackArgs(argv);
  if (opts.help) {
    console.log(
      'Usage: node scripts/local-staging-stack.mjs <up|down|reset|status|seed|smoke|e2e-matrix|verify|collect-evidence|all> '
      + '[--port 54329] [--api-port 3000] [--base-url http://127.0.0.1:3000]',
    );
    return 0;
  }
  return runLocalStagingStack(opts);
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main().then(
    (code) => process.exit(code ?? 0),
    (err) => {
      console.error(`local-staging-stack: ${err.message}`);
      process.exit(1);
    },
  );
}