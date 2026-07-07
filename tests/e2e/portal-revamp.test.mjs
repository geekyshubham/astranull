/**
 * Portal revamp node e2e: live API provenance from seeded store (docs/ux/17 §4–§5).
 */
import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { resetStoreForTests } from '../../src/store.mjs';
import {
  buildPortalBaselineStore,
  PORTAL_BASELINE_IDS,
} from '../fixtures/portal-baseline/seed.mjs';
import { buildPortalEmptyStore } from '../fixtures/portal-empty/seed.mjs';
import { applyPortalBaselineReadinessBoost } from '../fixtures/portal-baseline/readiness.mjs';
import { demoHeaders, request } from '../helpers/http.mjs';

const TEST_ENV = {
  NODE_ENV: 'test',
  ASTRANULL_AUTH_MODE: 'dev-headers',
  ASTRANULL_NO_PERSIST: '1',
  ASTRANULL_WAF_POSTURE_ENABLED: '1',
};

/** @type {import('node:http').Server | null} */
let server = null;
let baseUrl = '';

function bootStore(mutate) {
  for (const [key, value] of Object.entries(TEST_ENV)) {
    process.env[key] = value;
  }
  const store = buildPortalBaselineStore();
  mutate?.(store);
  resetStoreForTests(store);
  server?.close();
  server = createServer({ env: { ...process.env, ...TEST_ENV } });
  server.listen(0);
  const address = server.address();
  const port = typeof address === 'object' && address ? address.port : null;
  if (!port) throw new Error('portal revamp e2e server failed to bind');
  baseUrl = `http://127.0.0.1:${port}`;
}

function ownerHeaders(tenantId = PORTAL_BASELINE_IDS.tenantId) {
  return demoHeaders('owner', tenantId, 'usr_owner');
}

before(() => {
  bootStore(applyPortalBaselineReadinessBoost);
});

after(() => {
  server?.close();
});

describe('portal revamp API provenance (node e2e)', () => {
  it('FT-REV-API-01 GET /v1/state readiness score is computed from seeded store', async () => {
    const res = await request(baseUrl, 'GET', '/v1/state', { headers: ownerHeaders() });
    assert.equal(res.status, 200);
    assert.equal(typeof res.json?.readiness?.score, 'number');
    assert.ok(res.json.readiness.score > 0);
  });

  it('FT-REV-API-02 GET /v1/target-groups returns seeded group name from store', async () => {
    const res = await request(baseUrl, 'GET', '/v1/target-groups', { headers: ownerHeaders() });
    assert.equal(res.status, 200);
    const group = (res.json?.items ?? []).find((row) => row.id === PORTAL_BASELINE_IDS.targetGroupId);
    assert.ok(group, 'baseline target group must be listed');
    assert.equal(group.name, 'edge-checkout');
  });

  it('FT-REV-API-03 GET /v1/target-groups envelope includes server meta', async () => {
    const res = await request(baseUrl, 'GET', '/v1/target-groups', { headers: ownerHeaders() });
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.json?.items));
    assert.equal(typeof res.json?.count, 'number');
    assert.ok(res.json?.meta && typeof res.json.meta === 'object');
    assert.equal(res.json.count, res.json.items.length);
  });

  it('FT-REV-API-04 GET /v1/targets/:id hydrator returns seeded target value', async () => {
    const res = await request(
      baseUrl,
      'GET',
      `/v1/targets/${encodeURIComponent(PORTAL_BASELINE_IDS.targetId)}`,
      { headers: ownerHeaders() },
    );
    assert.equal(res.status, 200);
    assert.equal(res.json?.target?.id, PORTAL_BASELINE_IDS.targetId);
    assert.equal(res.json?.target?.value, 'checkout.acme.com');
  });

  it('FT-REV-API-05 GET verification-ladder returns server-computed step counts', async () => {
    const res = await request(
      baseUrl,
      'GET',
      `/v1/target-groups/${encodeURIComponent(PORTAL_BASELINE_IDS.targetGroupId)}/verification-ladder`,
      { headers: ownerHeaders() },
    );
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.json?.steps));
    assert.ok(res.json.steps.length >= 4);
    const declared = res.json.steps.find((step) => step.id === 'declared');
    assert.ok(declared);
    assert.equal(declared.total, 5);
    assert.equal(declared.count, 5);
  });

  it('FT-REV-API-06 empty tenant target-groups carries meta.empty_reason', async () => {
    bootStore((store) => {
      Object.assign(store, buildPortalEmptyStore());
    });
    const emptyTenantId = 'ten_portal_empty';
    const res = await request(baseUrl, 'GET', '/v1/target-groups', {
      headers: ownerHeaders(emptyTenantId),
    });
    assert.equal(res.status, 200);
    assert.equal(res.json?.count, 0);
    const emptyReason = String(res.json?.meta?.empty_reason ?? '').trim();
    assert.ok(emptyReason.length > 0);
    bootStore(applyPortalBaselineReadinessBoost);
  });
});