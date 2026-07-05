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

function startProbeWorker(env) {
  if (env.ASTRANULL_PROBE_MODE !== 'signed-worker') return null;
  const port = env.PORT ?? '3000';
  const apiUrl = env.ASTRANULL_PUBLIC_BASE_URL
    ?? (env.RAILWAY_PUBLIC_DOMAIN ? `https://${env.RAILWAY_PUBLIC_DOMAIN}` : `http://127.0.0.1:${port}`);
  const workerEnv = {
    ...env,
    ASTRANULL_API_URL: apiUrl,
    ASTRANULL_PROBE_TENANT_ID: env.ASTRANULL_PROBE_TENANT_ID ?? 'ten_demo',
    ASTRANULL_PROBE_POLL_INTERVAL_MS: env.ASTRANULL_PROBE_POLL_INTERVAL_MS ?? '5000',
  };
  return runNode(['workers/probe-worker.mjs'], { env: workerEnv, detached: true, stdio: 'ignore' });
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

  if (env.ASTRANULL_PROBE_MODE === 'signed-worker') {
    console.log('railway-staging-start: starting signed probe worker…');
    await startProbeWorker(env);
  }

  console.log('railway-staging-start: starting control plane…');
  await runNode(['src/index.mjs'], { env });
}

main().catch((err) => {
  console.error(`railway-staging-start: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});