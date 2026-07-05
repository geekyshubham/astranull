#!/usr/bin/env node
/**
 * Railway hosted-staging bootstrap: migrate Postgres, seed demo tenant, start probe worker + API.
 */
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { applyBundledStagingOidcEnvDefaults } from '../src/lib/bundledStagingOidc.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');

/**
 * @param {string[]} args
 */
function runNode(args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, args, {
      cwd: REPO_ROOT,
      env: options.env ?? process.env,
      stdio: options.stdio ?? 'inherit',
      detached: options.detached === true,
    });
    child.on('error', reject);
    if (options.detached) {
      child.unref();
      resolve(child);
      return;
    }
    child.on('exit', (code, signal) => {
      if (code === 0) {
        resolve();
        return;
      }
      reject(new Error(`node ${args.join(' ')} failed (code=${code ?? 'null'}, signal=${signal ?? 'null'})`));
    });
  });
}

export function resolveProbeWorkerApiUrl(env, port) {
  const loopback = `http://127.0.0.1:${port}`;
  const explicit = String(env.ASTRANULL_PROBE_WORKER_API_URL ?? '').trim().replace(/\/$/, '');
  if (explicit) return explicit;
  return loopback;
}

function buildProbeWorkerEnv(env, port) {
  return {
    ...env,
    ASTRANULL_API_URL: resolveProbeWorkerApiUrl(env, port),
    ASTRANULL_PROBE_TENANT_ID: env.ASTRANULL_PROBE_TENANT_ID ?? 'ten_demo',
    ASTRANULL_PROBE_POLL_INTERVAL_MS: env.ASTRANULL_PROBE_POLL_INTERVAL_MS ?? '5000',
  };
}

async function waitForHealth(port, options = {}) {
  const maxMs = options.maxMs ?? 120_000;
  const url = `http://127.0.0.1:${port}/health`;
  const start = Date.now();
  while (Date.now() - start < maxMs) {
    try {
      const res = await fetch(url);
      if (res.ok) return;
    } catch {
      /* API not listening yet */
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  throw new Error(`railway-staging-start: timed out waiting for ${url}`);
}

function startProbeWorkerSupervised(env, port) {
  if (env.ASTRANULL_PROBE_MODE !== 'signed-worker') return null;
  const workerEnv = buildProbeWorkerEnv(env, port);

  const launch = () => {
    const child = spawn(process.execPath, ['workers/probe-worker.mjs'], {
      cwd: REPO_ROOT,
      env: workerEnv,
      stdio: 'inherit',
    });
    child.on('exit', (code, signal) => {
      if (code === 0 && !signal) return;
      console.error(
        `railway-staging-start: probe worker exited (code=${code ?? 'null'}, signal=${signal ?? 'null'}); restarting in 5s…`,
      );
      setTimeout(launch, 5000).unref();
    });
    return child;
  };

  console.log(
    `railway-staging-start: probe worker API base ${workerEnv.ASTRANULL_API_URL} (tenant=${workerEnv.ASTRANULL_PROBE_TENANT_ID})`,
  );
  return launch();
}

async function main() {
  const env = { ...process.env };
  if (!String(env.ASTRANULL_DATABASE_URL ?? '').trim()) {
    console.error('hosted-control-plane-start: ASTRANULL_DATABASE_URL is required (link managed Postgres).');
    process.exitCode = 1;
    return;
  }

  env.ASTRANULL_BUNDLED_STAGING_OIDC = env.ASTRANULL_BUNDLED_STAGING_OIDC ?? '1';
  env.ASTRANULL_DEPLOYMENT_PROFILE = env.ASTRANULL_DEPLOYMENT_PROFILE ?? 'hosted-staging';
  env.ASTRANULL_PERSISTENCE_MODE = env.ASTRANULL_PERSISTENCE_MODE ?? 'postgres';
  env.ASTRANULL_PROBE_MODE = env.ASTRANULL_PROBE_MODE ?? 'signed-worker';
  env.ASTRANULL_HIGH_SCALE_ADAPTER_MODE = env.ASTRANULL_HIGH_SCALE_ADAPTER_MODE ?? 'disabled';
  env.ASTRANULL_AGENT_IDENTITY_MODE = env.ASTRANULL_AGENT_IDENTITY_MODE ?? 'bearer';
  applyBundledStagingOidcEnvDefaults(env);
  Object.assign(process.env, env);

  console.log('railway-staging-start: applying migrations…');
  await runNode(['scripts/migrate-postgres.mjs'], { env });

  console.log('railway-staging-start: seeding demo tenant (idempotent)…');
  await runNode(['scripts/seed-local-staging-tenant.mjs'], { env });

  const port = env.PORT ?? '3000';
  console.log('railway-staging-start: starting control plane…');
  const apiChild = spawn(process.execPath, ['src/index.mjs'], {
    cwd: REPO_ROOT,
    env,
    stdio: 'inherit',
  });

  await waitForHealth(port);
  console.log('railway-staging-start: control plane healthy');

  if (env.ASTRANULL_PROBE_MODE === 'signed-worker') {
    console.log('railway-staging-start: starting signed probe worker…');
    startProbeWorkerSupervised(env, port);
  }

  await new Promise((resolve, reject) => {
    apiChild.on('error', reject);
    apiChild.on('exit', (code, signal) => {
      if (code === 0) {
        resolve();
        return;
      }
      reject(
        new Error(
          `node src/index.mjs failed (code=${code ?? 'null'}, signal=${signal ?? 'null'})`,
        ),
      );
    });
  });
}

const startEntry = fileURLToPath(import.meta.url);
const invokedAsMain =
  process.argv[1] != null && path.resolve(process.argv[1]) === startEntry;

if (invokedAsMain) {
  main().catch((err) => {
    console.error(`railway-staging-start: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  });
}