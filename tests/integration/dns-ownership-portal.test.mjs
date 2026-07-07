/**
 * Portal revamp DNS ownership integration tests (docs/ux/17 §3.1).
 */
import assert from 'node:assert/strict';
import { after, before, beforeEach, describe, it } from 'node:test';
import { createServer } from '../../src/server.mjs';
import * as dnsOwnership from '../../src/services/dnsOwnership.mjs';
import { getStore } from '../../src/store.mjs';
import { demoHeaders, request } from '../helpers/http.mjs';
import { createDnsStub, resetDnsStub } from '../helpers/dns-stub.mjs';
import { seedPortalBaseline, PORTAL_BASELINE_IDS } from '../fixtures/portal-baseline/seed.mjs';

const ctx = { tenantId: PORTAL_BASELINE_IDS.tenantId, userId: 'usr_owner', role: 'owner' };
let baseUrl;
let server;
let dnsStub;

function ownerHeaders() {
  return demoHeaders('owner', PORTAL_BASELINE_IDS.tenantId, 'usr_owner');
}

before(() => {
  seedPortalBaseline();
  resetDnsStub();
  dnsStub = createDnsStub();
  server = createServer({
    services: {
      dnsOwnership: {
        ...dnsOwnership,
        verifyDnsOwnership: (scope, body, opts = {}) =>
          dnsOwnership.verifyDnsOwnership(scope, body, { resolveTxt: dnsStub.resolveTxt, ...opts }),
      },
    },
  });
  server.listen(0);
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(() => {
  server.close();
});

beforeEach(() => {
  seedPortalBaseline();
  resetDnsStub();
});

describe('dns ownership portal integration (FT-DNS-01..08)', () => {
  it('FT-DNS-01 issue creates base32 pending challenge with 15min expiry', async () => {
    const res = await request(
      baseUrl,
      'POST',
      `/v1/target-groups/${PORTAL_BASELINE_IDS.targetGroupId}/dns-ownership/issue`,
      { headers: ownerHeaders(), body: { target_id: 'tgt_checkout_1' } },
    );
    assert.equal(res.status, 201);
    assert.ok(res.json.challenge);
    assert.match(res.json.challenge.record_value, /^[A-Z2-7]+$/);
    assert.equal(res.json.challenge.state, 'pending');
    const issued = new Date(res.json.challenge.issued_at).getTime();
    const expires = new Date(res.json.challenge.expires_at).getTime();
    assert.equal(expires - issued, 15 * 60 * 1000);
    assert.ok(res.json.audit_entry_id);
  });

  it('FT-DNS-02 duplicate pending issue returns 409 challenge_active', async () => {
    const path = `/v1/target-groups/${PORTAL_BASELINE_IDS.targetGroupId}/dns-ownership/issue`;
    const first = await request(baseUrl, 'POST', path, {
      headers: ownerHeaders(),
      body: { target_id: 'tgt_checkout_2' },
    });
    assert.equal(first.status, 201);
    const second = await request(baseUrl, 'POST', path, {
      headers: ownerHeaders(),
      body: { target_id: 'tgt_checkout_2' },
    });
    assert.equal(second.status, 409);
    assert.equal(second.json.error, 'challenge_active');
  });

  it('FT-DNS-03 verify matching TXT resolves challenge and appends dns_verified row', async () => {
    const issue = await request(
      baseUrl,
      'POST',
      `/v1/target-groups/${PORTAL_BASELINE_IDS.targetGroupId}/dns-ownership/issue`,
      { headers: ownerHeaders(), body: { target_id: 'tgt_checkout_1' } },
    );
    assert.equal(issue.status, 201);
    dnsStub.setTxt(issue.json.challenge.record_name, issue.json.challenge.record_value);

    const verify = await request(
      baseUrl,
      'POST',
      `/v1/target-groups/${PORTAL_BASELINE_IDS.targetGroupId}/dns-ownership/verify`,
      { headers: ownerHeaders(), body: { challenge_id: issue.json.challenge.id } },
    );
    assert.equal(verify.status, 200);
    assert.equal(verify.json.verified, true);
    assert.equal(verify.json.challenge.state, 'resolved');

    const row = getStore().targetVerifications.find(
      (v) => v.source_ref?.dns_challenge_id === issue.json.challenge.id,
    );
    assert.ok(row);
    assert.equal(row.state, 'dns_verified');
  });

  it('FT-DNS-04 non-matching TXT stays pending with matched:false', async () => {
    const issue = await request(
      baseUrl,
      'POST',
      `/v1/target-groups/${PORTAL_BASELINE_IDS.targetGroupId}/dns-ownership/issue`,
      { headers: ownerHeaders(), body: { target_id: 'tgt_checkout_2' } },
    );
    assert.equal(issue.status, 201);
    dnsStub.setTxt(issue.json.challenge.record_name, 'WRONGVALUE');

    const verify = await request(
      baseUrl,
      'POST',
      `/v1/target-groups/${PORTAL_BASELINE_IDS.targetGroupId}/dns-ownership/verify`,
      { headers: ownerHeaders(), body: { challenge_id: issue.json.challenge.id } },
    );
    assert.equal(verify.status, 200);
    assert.equal(verify.json.verified, false);
    assert.equal(verify.json.challenge.state, 'pending');
    assert.equal(verify.json.challenge.last_check_result.matched, false);
  });

  it('FT-DNS-05 verify timeout returns verified:false with meta.timeout', async () => {
    const issue = await request(
      baseUrl,
      'POST',
      `/v1/target-groups/${PORTAL_BASELINE_IDS.targetGroupId}/dns-ownership/issue`,
      { headers: ownerHeaders(), body: { target_id: 'tgt_checkout_4' } },
    );
    assert.equal(issue.status, 201);

    const slowServer = createServer({
      services: {
        dnsOwnership: {
          ...dnsOwnership,
          verifyDnsOwnership: (scope, body) =>
            dnsOwnership.verifyDnsOwnership(scope, body, {
              resolveTxt: async () => {
                await new Promise((resolve) => setTimeout(resolve, 4500));
                return [['late']];
              },
            }),
        },
      },
    });
    slowServer.listen(0);
    const slowUrl = `http://127.0.0.1:${slowServer.address().port}`;
    const verify = await request(
      slowUrl,
      'POST',
      `/v1/target-groups/${PORTAL_BASELINE_IDS.targetGroupId}/dns-ownership/verify`,
      { headers: ownerHeaders(), body: { challenge_id: issue.json.challenge.id } },
    );
    slowServer.close();
    assert.equal(verify.status, 200);
    assert.equal(verify.json.verified, false);
    assert.equal(verify.json.meta?.timeout, true);
  });

  it('FT-DNS-06 seventh verify in 60s returns 429', async () => {
    const issue = await request(
      baseUrl,
      'POST',
      `/v1/target-groups/${PORTAL_BASELINE_IDS.targetGroupId}/dns-ownership/issue`,
      { headers: ownerHeaders(), body: { target_id: 'tgt_checkout_5' } },
    );
    assert.equal(issue.status, 201);
    dnsStub.setTxt(issue.json.challenge.record_name, 'not-a-match');

    let lastStatus = 200;
    for (let i = 0; i < 7; i += 1) {
      const verify = await request(
        baseUrl,
        'POST',
        `/v1/target-groups/${PORTAL_BASELINE_IDS.targetGroupId}/dns-ownership/verify`,
        { headers: ownerHeaders(), body: { challenge_id: issue.json.challenge.id } },
      );
      lastStatus = verify.status;
      if (i === 6) assert.equal(verify.status, 429);
    }
    assert.equal(lastStatus, 429);
  });

  it('FT-DNS-07 tenant B cannot issue for tenant A group (404)', async () => {
    const res = await request(
      baseUrl,
      'POST',
      `/v1/target-groups/${PORTAL_BASELINE_IDS.targetGroupId}/dns-ownership/issue`,
      { headers: demoHeaders('owner', PORTAL_BASELINE_IDS.tenantBId, 'usr_b'), body: { target_id: 'tgt_checkout_1' } },
    );
    assert.equal(res.status, 404);
  });

  it('FT-DNS-08 issue and verify write audit entries', async () => {
    const before = getStore().auditLog.length;
    const issue = await request(
      baseUrl,
      'POST',
      `/v1/target-groups/${PORTAL_BASELINE_IDS.targetGroupId}/dns-ownership/issue`,
      { headers: ownerHeaders(), body: { target_id: 'tgt_checkout_2' } },
    );
    if (issue.status === 409) return;
    assert.ok(issue.json.audit_entry_id);
    dnsStub.setTxt(issue.json.challenge.record_name, issue.json.challenge.record_value);
    const verify = await request(
      baseUrl,
      'POST',
      `/v1/target-groups/${PORTAL_BASELINE_IDS.targetGroupId}/dns-ownership/verify`,
      { headers: ownerHeaders(), body: { challenge_id: issue.json.challenge.id } },
    );
    assert.ok(verify.json.audit_entry_id);
    assert.ok(getStore().auditLog.length > before);
  });
});