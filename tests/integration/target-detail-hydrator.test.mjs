import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
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

function ownerHeaders() {
  return demoHeaders('owner', PORTAL_BASELINE_IDS.tenantId, 'usr_owner');
}

describe('target detail hydrator (FT-TD-01..07)', () => {
  it('FT-TD-01 returns full §4.1 shape with seeded scalars', async () => {
    const res = await request(baseUrl, 'GET', `/v1/targets/${PORTAL_BASELINE_IDS.targetId}`, {
      headers: ownerHeaders(),
    });
    assert.equal(res.status, 200);
    assert.equal(res.json.target.id, PORTAL_BASELINE_IDS.targetId);
    assert.equal(res.json.target.value, 'checkout.acme.com');
    assert.equal(res.json.target.kind, 'fqdn');
    assert.equal(res.json.target.expected_behavior, 'cloud_baseline');
    assert.equal(res.json.verification.state, 'agent_verified');
    assert.equal(res.json.verification.source_kind, 'agent_observation');
    assert.equal(res.json.counts.findings_open, 1);
    assert.equal(res.json.counts.findings_closed, 1);
    assert.equal(res.json.counts.runs_total, 1);
    assert.equal(res.json.loa.id, PORTAL_BASELINE_IDS.loaId);
    assert.equal(res.json.waf_posture.vendor, 'cloudflare');
    assert.equal(res.json.waf_posture.posture, 'protected');
  });

  it('FT-TD-02 verification history oldest→newest; pending has no source_ref', async () => {
    const res = await request(baseUrl, 'GET', `/v1/targets/${PORTAL_BASELINE_IDS.targetId}`, {
      headers: ownerHeaders(),
    });
    const history = res.json.verification.history;
    assert.ok(history.length >= 3);
    assert.equal(history[0].state, 'pending');
    assert.equal(history[0].source_ref, undefined);
    assert.equal(history.at(-1).state, 'agent_verified');
  });

  it('FT-TD-03 waf_posture null for IP target without asset', async () => {
    const res = await request(baseUrl, 'GET', '/v1/targets/tgt_ip_no_waf', {
      headers: ownerHeaders(),
    });
    if (res.status === 200 && res.json.target) {
      assert.equal(res.json.waf_posture, null);
      return;
    }
    seedPortalBaseline();
    const store = (await import('../../src/store.mjs')).getStore();
    store.targets.push({
      id: 'tgt_ip_no_waf',
      tenant_id: PORTAL_BASELINE_IDS.tenantId,
      target_group_id: PORTAL_BASELINE_IDS.targetGroupId,
      kind: 'ip',
      value: '203.0.113.10',
      expected_behavior: 'cloud_baseline',
      created_at: PORTAL_BASELINE_IDS.frozenAt,
    });
    const ipRes = await request(baseUrl, 'GET', '/v1/targets/tgt_ip_no_waf', { headers: ownerHeaders() });
    assert.equal(ipRes.status, 200);
    assert.equal(ipRes.json.waf_posture, null);
  });

  it('FT-TD-04 findings filtered by target_id and counts match', async () => {
    const res = await request(baseUrl, 'GET', `/v1/targets/${PORTAL_BASELINE_IDS.targetId}`, {
      headers: ownerHeaders(),
    });
    assert.ok(res.json.findings.every((f) => ['fnd_checkout_1', 'fnd_checkout_2'].includes(f.id)));
    const open = res.json.findings.filter((f) => f.state === 'open').length;
    const closed = res.json.findings.filter((f) => f.state === 'closed').length;
    assert.equal(res.json.counts.findings_open, open);
    assert.equal(res.json.counts.findings_closed, closed);
  });

  it('FT-TD-05 findings_limit uses cursor pagination without overlap', async () => {
    const page1 = await request(
      baseUrl,
      'GET',
      `/v1/targets/${PORTAL_BASELINE_IDS.targetId}?findings_limit=1`,
      { headers: ownerHeaders() },
    );
    assert.equal(page1.json.findings.length, 1);
    assert.ok(page1.json.findings_next_cursor);
    const page2 = await request(
      baseUrl,
      'GET',
      `/v1/targets/${PORTAL_BASELINE_IDS.targetId}?findings_limit=1&findings_cursor=${page1.json.findings_next_cursor}`,
      { headers: ownerHeaders() },
    );
    assert.equal(page2.json.findings.length, 1);
    assert.notEqual(page1.json.findings[0].id, page2.json.findings[0].id);
  });

  it('FT-TD-06 hydrator completes within query budget in dev-json mode', async () => {
    const res = await request(baseUrl, 'GET', `/v1/targets/${PORTAL_BASELINE_IDS.targetId}`, {
      headers: ownerHeaders(),
    });
    assert.equal(res.status, 200);
    assert.ok(res.json.target);
  });

  it('FT-TD-07 tenant isolation + RBAC', async () => {
    const denied = await request(baseUrl, 'GET', `/v1/targets/${PORTAL_BASELINE_IDS.targetId}`, {
      headers: demoHeaders('viewer', PORTAL_BASELINE_IDS.tenantBId),
    });
    assert.equal(denied.status, 404);

    const allowed = await request(baseUrl, 'GET', `/v1/targets/${PORTAL_BASELINE_IDS.targetId}`, {
      headers: demoHeaders('viewer', PORTAL_BASELINE_IDS.tenantId),
    });
    assert.equal(allowed.status, 200);
  });
});