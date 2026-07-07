import { createServer } from '../../src/server.mjs';
import { getStore, resetStoreForTests } from '../../src/store.mjs';
import { computeReadiness } from '../../src/services/readiness.mjs';
import {
  buildPortalBaselineStore,
  PORTAL_BASELINE_IDS,
  seedPortalBaseline,
} from '../fixtures/portal-baseline/seed.mjs';
import { buildPortalEmptyStore } from '../fixtures/portal-empty/seed.mjs';
import { buildPortalEdgeStore } from '../fixtures/portal-edge/seed.mjs';
import {
  applyPortalBaselineReadinessBoost,
  applyPortalBaselineReadinessPenalty,
} from '../fixtures/portal-baseline/readiness.mjs';

const TEST_ENV = {
  NODE_ENV: 'test',
  ASTRANULL_AUTH_MODE: 'dev-headers',
  ASTRANULL_NO_PERSIST: '1',
  ASTRANULL_WAF_POSTURE_ENABLED: '1',
};

/** @type {{ server: import('node:http').Server | null, baseUrl: string | null, port: number | null }} */
const runtime = {
  server: null,
  baseUrl: null,
  port: null,
};

function applyTestEnv() {
  for (const [key, value] of Object.entries(TEST_ENV)) {
    process.env[key] = value;
  }
}

/**
 * @param {(store: ReturnType<typeof buildPortalBaselineStore>) => void} [mutate]
 */
export function seedPortalPlaywrightStore(mutate) {
  applyTestEnv();
  const store = buildPortalBaselineStore();
  mutate?.(store);
  resetStoreForTests(store);
  return getStore();
}

/**
 * @param {{ mutate?: (store: ReturnType<typeof buildPortalBaselineStore>) => void }} [options]
 */
export async function startPortalPlaywrightServer(options = {}) {
  await stopPortalPlaywrightServer();
  seedPortalPlaywrightStore(options.mutate ?? applyPortalBaselineReadinessBoost);

  const server = createServer({ env: { ...process.env, ...TEST_ENV } });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });

  const address = server.address();
  const port = typeof address === 'object' && address ? address.port : null;
  if (!port) throw new Error('portal playwright server failed to bind an ephemeral port');

  const baseUrl = `http://127.0.0.1:${port}`;
  runtime.server = server;
  runtime.baseUrl = baseUrl;
  runtime.port = port;
  process.env.PORT = String(port);
  process.env.BASE_URL = baseUrl;

  return { server, baseUrl, port };
}

export async function stopPortalPlaywrightServer() {
  const { server } = runtime;
  runtime.server = null;
  runtime.baseUrl = null;
  runtime.port = null;
  if (!server) return;
  await new Promise((resolve, reject) => {
    server.close((err) => (err ? reject(err) : resolve()));
  });
}

export function getPortalPlaywrightBaseUrl() {
  if (!runtime.baseUrl) throw new Error('portal playwright server is not running');
  return runtime.baseUrl;
}

export function getPortalPlaywrightPort() {
  if (!runtime.port) throw new Error('portal playwright server is not running');
  return runtime.port;
}

export async function restartPortalPlaywrightServer(options = {}) {
  return startPortalPlaywrightServer(options);
}

export async function restartPortalPlaywrightWithReadinessPenalty() {
  return restartPortalPlaywrightServer({ mutate: applyPortalBaselineReadinessPenalty });
}

export async function restartPortalPlaywrightWithEmptyStore() {
  return restartPortalPlaywrightServer({
    mutate: (store) => {
      Object.assign(store, buildPortalEmptyStore());
    },
  });
}

export async function restartPortalPlaywrightWithEdgeStore() {
  return restartPortalPlaywrightServer({
    mutate: (store) => {
      Object.assign(store, buildPortalEdgeStore());
    },
  });
}

export function portalOwnerHeaders() {
  return {
    'x-tenant-id': PORTAL_BASELINE_IDS.tenantId,
    'x-user-id': 'usr_owner',
    'x-role': 'owner',
    'Content-Type': 'application/json',
    accept: 'application/json',
  };
}

export async function fetchPortalReadinessScore(baseUrl = getPortalPlaywrightBaseUrl()) {
  const res = await fetch(`${baseUrl}/v1/state`, { headers: portalOwnerHeaders() });
  if (!res.ok) throw new Error(`GET /v1/state failed (${res.status})`);
  const json = await res.json();
  const score = json?.readiness?.score;
  if (typeof score !== 'number') {
    throw new Error('readiness.score missing from /v1/state');
  }
  return score;
}

export async function fetchPortalFindings(baseUrl = getPortalPlaywrightBaseUrl()) {
  const res = await fetch(`${baseUrl}/v1/findings`, { headers: portalOwnerHeaders() });
  if (!res.ok) throw new Error(`GET /v1/findings failed (${res.status})`);
  const json = await res.json();
  return Array.isArray(json?.items) ? json.items : [];
}

export function countOpenFindings(findings) {
  return findings.filter((row) => String(row.state ?? row.status ?? 'open').toLowerCase() === 'open').length;
}

export async function fetchPortalVerificationLadder(groupId = PORTAL_BASELINE_IDS.targetGroupId, baseUrl = getPortalPlaywrightBaseUrl()) {
  const res = await fetch(
    `${baseUrl}/v1/target-groups/${encodeURIComponent(groupId)}/verification-ladder`,
    { headers: portalOwnerHeaders() },
  );
  if (!res.ok) throw new Error(`GET verification-ladder failed (${res.status})`);
  return res.json();
}

export async function fetchPortalWafCoverageSummary(baseUrl = getPortalPlaywrightBaseUrl()) {
  const res = await fetch(`${baseUrl}/v1/waf/coverage/summary`, { headers: portalOwnerHeaders() });
  if (!res.ok) throw new Error(`GET /v1/waf/coverage/summary failed (${res.status})`);
  return res.json();
}

export async function fetchPortalTargetDetail(targetId = PORTAL_BASELINE_IDS.targetId, baseUrl = getPortalPlaywrightBaseUrl()) {
  const res = await fetch(`${baseUrl}/v1/targets/${encodeURIComponent(targetId)}`, { headers: portalOwnerHeaders() });
  if (!res.ok) throw new Error(`GET /v1/targets/${targetId} failed (${res.status})`);
  return res.json();
}

export async function fetchPortalHighScaleQueue(baseUrl = getPortalPlaywrightBaseUrl()) {
  const res = await fetch(`${baseUrl}/v1/high-scale-requests?scope=my-tenant`, { headers: portalOwnerHeaders() });
  if (!res.ok) throw new Error(`GET /v1/high-scale-requests failed (${res.status})`);
  const json = await res.json();
  return Array.isArray(json?.items) ? json.items : [];
}

export async function fetchPortalFinding(findingId = PORTAL_BASELINE_IDS.findingId, baseUrl = getPortalPlaywrightBaseUrl()) {
  const res = await fetch(`${baseUrl}/v1/findings/${encodeURIComponent(findingId)}`, { headers: portalOwnerHeaders() });
  if (!res.ok) throw new Error(`GET /v1/findings/${findingId} failed (${res.status})`);
  return res.json();
}

/** Seed baseline without starting a server (harness compatibility). */
export function seedPortalPlaywrightBaseline(mutate) {
  if (mutate) {
    return seedPortalPlaywrightStore(mutate);
  }
  return seedPortalBaseline();
}

export function expectedReadinessScores() {
  applyTestEnv();
  const boosted = buildPortalBaselineStore();
  applyPortalBaselineReadinessBoost(boosted);
  resetStoreForTests(boosted);
  const boostedScore = computeReadiness(PORTAL_BASELINE_IDS.tenantId).score;

  const penalized = buildPortalBaselineStore();
  applyPortalBaselineReadinessPenalty(penalized);
  resetStoreForTests(penalized);
  const penalizedScore = computeReadiness(PORTAL_BASELINE_IDS.tenantId).score;

  return { boostedScore, penalizedScore };
}

export { PORTAL_BASELINE_IDS };