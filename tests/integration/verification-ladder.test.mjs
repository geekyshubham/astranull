import assert from 'node:assert/strict';
import { after, before, beforeEach, describe, it } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { demoHeaders, request } from '../helpers/http.mjs';
import { seedPortalBaseline, PORTAL_BASELINE_IDS } from '../fixtures/portal-baseline/seed.mjs';

let baseUrl;
let server;

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

function ownerHeaders() {
  return demoHeaders('owner', PORTAL_BASELINE_IDS.tenantId, 'usr_owner');
}

describe('verification ladder (FT-VL-01..05)', () => {
  it('FT-VL-01 ladder returns server-computed counts 5/5, 3/5, 2/5, 0/5', async () => {
    const res = await request(
      baseUrl,
      'GET',
      `/v1/target-groups/${PORTAL_BASELINE_IDS.targetGroupId}/verification-ladder`,
      { headers: ownerHeaders() },
    );
    assert.equal(res.status, 200);
    const byId = Object.fromEntries(res.json.steps.map((step) => [step.id, step]));
    assert.equal(byId.declared.count, 5);
    assert.equal(byId.declared.total, 5);
    assert.equal(byId.dns_verified.count, 3);
    assert.equal(byId.agent_verified.count, 2);
    assert.equal(byId.user_confirmed.count, 0);
  });

  it('FT-VL-02 confirm elevates agent_verified target with active LOA', async () => {
    const res = await request(
      baseUrl,
      'POST',
      `/v1/target-groups/${PORTAL_BASELINE_IDS.targetGroupId}/targets/tgt_checkout_1:confirm`,
      { headers: ownerHeaders(), body: { signer: 'usr_owner' } },
    );
    assert.equal(res.status, 200);
    assert.equal(res.json.verification.state, 'user_confirmed');

    const ladder = await request(
      baseUrl,
      'GET',
      `/v1/target-groups/${PORTAL_BASELINE_IDS.targetGroupId}/verification-ladder`,
      { headers: ownerHeaders() },
    );
    const confirmed = ladder.json.steps.find((step) => step.id === 'user_confirmed');
    assert.equal(confirmed.count, 1);
  });

  it('FT-VL-03 confirm without LOA returns 409 loa_missing', async () => {
    const revoke = await request(
      baseUrl,
      'POST',
      `/v1/target-groups/${PORTAL_BASELINE_IDS.targetGroupId}/loa/${PORTAL_BASELINE_IDS.loaId}/revoke`,
      { headers: ownerHeaders(), body: { reason: 'test' } },
    );
    assert.equal(revoke.status, 200);

    const res = await request(
      baseUrl,
      'POST',
      `/v1/target-groups/${PORTAL_BASELINE_IDS.targetGroupId}/targets/tgt_checkout_2:confirm`,
      { headers: ownerHeaders(), body: { signer: 'usr_owner' } },
    );
    assert.equal(res.status, 409);
    assert.equal(res.json.error, 'loa_missing');
  });

  it('FT-VL-04 confirm on pending target returns 409 verify_prereq_not_met', async () => {
    const res = await request(
      baseUrl,
      'POST',
      `/v1/target-groups/${PORTAL_BASELINE_IDS.targetGroupId}/targets/tgt_checkout_3:confirm`,
      { headers: ownerHeaders(), body: { signer: 'usr_owner' } },
    );
    assert.equal(res.status, 409);
    assert.equal(res.json.error, 'verify_prereq_not_met');
  });

  it('FT-VL-05 ladder counts are server-side only (no client math required)', async () => {
    const res = await request(
      baseUrl,
      'GET',
      `/v1/target-groups/${PORTAL_BASELINE_IDS.targetGroupId}/verification-ladder`,
      { headers: ownerHeaders() },
    );
    for (const step of res.json.steps) {
      assert.equal(typeof step.count, 'number');
      assert.equal(typeof step.total, 'number');
      assert.equal(step.done, step.count >= step.total && step.total > 0);
    }
  });
});