/**
 * FT-PROV-dyn dynamic provenance: node API checks (Playwright specs in portal-provenance.spec.mjs).
 */
import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { createServer } from '../../../src/server.mjs';
import { resetStoreForTests } from '../../../src/store.mjs';
import { computeReadiness } from '../../../src/services/readiness.mjs';
import {
  buildPortalBaselineStore,
  PORTAL_BASELINE_IDS,
} from '../../fixtures/portal-baseline/seed.mjs';
import {
  applyPortalBaselineReadinessBoost,
  applyPortalBaselineReadinessPenalty,
} from '../../fixtures/portal-baseline/readiness.mjs';
import { demoHeaders, request } from '../../helpers/http.mjs';

const TEST_ENV = {
  NODE_ENV: 'test',
  ASTRANULL_AUTH_MODE: 'dev-headers',
  ASTRANULL_NO_PERSIST: '1',
};

/** @type {import('node:http').Server | null} */
let server = null;
let baseUrl = '';

function bootServer(mutate) {
  for (const [key, value] of Object.entries(TEST_ENV)) {
    process.env[key] = value;
  }
  const store = buildPortalBaselineStore();
  mutate(store);
  resetStoreForTests(store);
  server?.close();
  server = createServer({ env: { ...process.env, ...TEST_ENV } });
  server.listen(0);
  const address = server.address();
  const port = typeof address === 'object' && address ? address.port : null;
  if (!port) throw new Error('portal provenance server failed to bind');
  baseUrl = `http://127.0.0.1:${port}`;
}

before(() => {
  bootServer(applyPortalBaselineReadinessBoost);
});

after(() => {
  server?.close();
});

describe('portal dynamic provenance (node API)', () => {
  it('FT-PROV-dyn-01 readiness score changes after store mutation and server restart', async () => {
    const headers = demoHeaders('owner', PORTAL_BASELINE_IDS.tenantId, 'usr_owner');
    const boosted = await request(baseUrl, 'GET', '/v1/state', { headers });
    assert.equal(boosted.status, 200);
    const boostedScore = boosted.json?.readiness?.score;
    assert.equal(typeof boostedScore, 'number');

    bootServer(applyPortalBaselineReadinessPenalty);
    const penalized = await request(baseUrl, 'GET', '/v1/state', { headers });
    assert.equal(penalized.status, 200);
    const penalizedScore = penalized.json?.readiness?.score;
    assert.equal(typeof penalizedScore, 'number');
    assert.notEqual(boostedScore, penalizedScore);
    assert.ok(penalizedScore < boostedScore);

    const storeScore = computeReadiness(PORTAL_BASELINE_IDS.tenantId).score;
    assert.equal(storeScore, penalizedScore);
  });

  it('FT-PROV-dyn-02 open findings count tracks store mutation', async () => {
    const headers = demoHeaders('owner', PORTAL_BASELINE_IDS.tenantId, 'usr_owner');
    const baseline = await request(baseUrl, 'GET', '/v1/findings?state=open', { headers });
    assert.equal(baseline.status, 200);
    const baselineCount = baseline.json.count;

    bootServer((store) => {
      applyPortalBaselineReadinessBoost(store);
      const openFindings = store.findings.filter(
        (f) => f.tenant_id === PORTAL_BASELINE_IDS.tenantId && f.state === 'open',
      );
      for (let i = 0; i < 3; i += 1) {
        store.findings.push({
          id: `fnd_prov_dyn_${i}`,
          tenant_id: PORTAL_BASELINE_IDS.tenantId,
          target_group_id: PORTAL_BASELINE_IDS.targetGroupId,
          target_id: PORTAL_BASELINE_IDS.targetId,
          severity: 's4',
          title: `Provenance dyn ${i}`,
          state: 'open',
          opened_at: PORTAL_BASELINE_IDS.frozenAt,
        });
      }
      assert.equal(openFindings.length + 3, store.findings.filter(
        (f) => f.tenant_id === PORTAL_BASELINE_IDS.tenantId && f.state === 'open',
      ).length);
    });

    const mutated = await request(baseUrl, 'GET', '/v1/findings?state=open', { headers });
    assert.equal(mutated.status, 200);
    assert.equal(mutated.json.count, baselineCount + 3);
  });
});