#!/usr/bin/env node
/**
 * Seeds portal-baseline, serves the built React portal via createServer() on an ephemeral port,
 * and exports PORT + BASE_URL for Playwright portal journeys.
 */
import { existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import {
  applyPortalBaselineReadinessBoost,
} from '../tests/fixtures/portal-baseline/readiness.mjs';
import {
  startPortalPlaywrightServer,
  stopPortalPlaywrightServer,
} from '../tests/helpers/portal-playwright-server.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const REACT_BUNDLE = path.join(REPO_ROOT, 'apps/web/react-app.js');

function ensureReactBundle() {
  if (existsSync(REACT_BUNDLE)) return;
  const build = spawnSync('npm', ['run', 'web:build'], {
    cwd: REPO_ROOT,
    stdio: 'inherit',
    env: process.env,
  });
  if (build.status !== 0) {
    throw new Error('web:build failed — cannot serve portal for Playwright');
  }
}

async function main() {
  ensureReactBundle();
  const { baseUrl, port } = await startPortalPlaywrightServer({
    mutate: applyPortalBaselineReadinessBoost,
  });

  console.log(`portal-playwright-harness: PORT=${port}`);
  console.log(`portal-playwright-harness: BASE_URL=${baseUrl}`);

  const shutdown = async (signal) => {
    console.log(`portal-playwright-harness: received ${signal}, shutting down`);
    await stopPortalPlaywrightServer();
    process.exit(0);
  };

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

main().catch(async (err) => {
  console.error('portal-playwright-harness:', err instanceof Error ? err.message : err);
  await stopPortalPlaywrightServer();
  process.exit(1);
});