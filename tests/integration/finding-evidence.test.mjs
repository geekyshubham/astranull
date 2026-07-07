/**
 * Portal revamp finding evidence integration tests (docs/ux/17 §3.7).
 */
import assert from 'node:assert/strict';
import { after, before, beforeEach, describe, it } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { getStore } from '../../src/store.mjs';
import { demoHeaders, request } from '../helpers/http.mjs';
import { seedPortalBaseline, PORTAL_BASELINE_IDS } from '../fixtures/portal-baseline/seed.mjs';

let baseUrl;
let server;

function ownerHeaders() {
  return demoHeaders('owner', PORTAL_BASELINE_IDS.tenantId, 'usr_owner');
}

before(() => {
  seedPortalBaseline();
  server = createServer();
  server.listen(0);
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(() => server.close());

beforeEach(() => {
  seedPortalBaseline();
});

describe('finding evidence hydrator (FT-EV-01..03)', () => {
  it('FT-EV-01 returns §4.2 shape with artifact sha256 values from sealed ledger', async () => {
    const res = await request(
      baseUrl,
      'GET',
      `/v1/findings/${PORTAL_BASELINE_IDS.findingId}/evidence`,
      { headers: ownerHeaders() },
    );
    assert.equal(res.status, 200);
    assert.equal(res.json.finding.id, PORTAL_BASELINE_IDS.findingId);
    assert.ok(res.json.bundle?.id, 'baseline bundle must be present');
    assert.ok(Array.isArray(res.json.artifacts) && res.json.artifacts.length > 0);

    const vaultRow = getStore().evidenceVault.find((row) => row.test_run_id === 'run_checkout_1');
    assert.ok(vaultRow?.sha256, 'seeded vault row must carry sha256');
    const artifact = res.json.artifacts.find((row) => row.id === vaultRow.id);
    assert.ok(artifact, 'artifact id must map to evidence_vault row');
    assert.equal(artifact.sha256, vaultRow.sha256);
    assert.equal(res.json.bundle.sha256, getStore().evidenceBundles[0].sha256);
  });

  it('FT-EV-02 custody_chain is ordered by step and sha256 matches artifacts', async () => {
    const res = await request(
      baseUrl,
      'GET',
      `/v1/findings/${PORTAL_BASELINE_IDS.findingId}/evidence`,
      { headers: ownerHeaders() },
    );
    assert.equal(res.status, 200);
    const chain = res.json.custody_chain;
    assert.ok(Array.isArray(chain) && chain.length > 0);
    for (let index = 0; index < chain.length; index += 1) {
      assert.equal(chain[index].step, index + 1);
      const artifact = res.json.artifacts.find((row) => row.sha256 === chain[index].sha256);
      assert.ok(artifact, `custody step ${chain[index].step} must reference a sealed artifact`);
    }
    for (let index = 1; index < chain.length; index += 1) {
      assert.ok(chain[index].step > chain[index - 1].step);
    }
  });

  it('FT-EV-03 finding without sealed evidence returns empty bundle and meta.empty_reason', async () => {
    getStore().findings.push({
      id: 'fnd_no_evidence',
      tenant_id: PORTAL_BASELINE_IDS.tenantId,
      target_group_id: PORTAL_BASELINE_IDS.targetGroupId,
      target_id: PORTAL_BASELINE_IDS.targetId,
      severity: 's4',
      title: 'No evidence attached',
      state: 'open',
      opened_at: PORTAL_BASELINE_IDS.frozenAt,
      owner_group: 'edge-sre',
    });

    const res = await request(baseUrl, 'GET', '/v1/findings/fnd_no_evidence/evidence', {
      headers: ownerHeaders(),
    });
    assert.equal(res.status, 200);
    assert.equal(res.json.bundle, null);
    assert.deepEqual(res.json.artifacts, []);
    assert.deepEqual(res.json.custody_chain, []);
    assert.equal(typeof res.json.meta?.empty_reason, 'string');
    assert.ok(res.json.meta.empty_reason.trim().length > 0);
  });
});