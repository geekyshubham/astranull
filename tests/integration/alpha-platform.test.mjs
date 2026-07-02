import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { demoHeaders, request } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';
import { getStore } from '../../src/store.mjs';
import { REQUIRED_ARTIFACT_TYPES } from '../../src/services/highScale.mjs';
import { acceptHighScaleAuthorizationPack, validHighScaleRequestPayload } from '../helpers/highScalePayload.mjs';

let baseUrl;
let server;

const socPrimary = () => demoHeaders('soc', 'ten_demo', 'usr_soc');
const socSecondary = () => demoHeaders('soc', 'ten_demo', 'usr_soc2');

async function dualSocApprove(hsId) {
  const first = await request(baseUrl, 'POST', `/internal/soc/high-scale/${hsId}/approve`, {
    headers: socPrimary(),
  });
  assert.equal(first.status, 200);
  assert.equal(first.json.state, 'under_review');
  const second = await request(baseUrl, 'POST', `/internal/soc/high-scale/${hsId}/approve`, {
    headers: socSecondary(),
  });
  assert.equal(second.status, 200);
  assert.equal(second.json.state, 'approved');
  assert.ok(second.json.scope_hash);
}

before(() => {
  freshStore();
  server = createServer();
  server.listen(0);
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(() => server.close());

describe('alpha platform slice', () => {
  it('tenant and environment APIs scope and audit', async () => {
    const h = demoHeaders('admin');
    const tenant = await request(baseUrl, 'GET', '/v1/tenants/current', { headers: h });
    assert.equal(tenant.status, 200);
    const envs = await request(baseUrl, 'GET', '/v1/environments', { headers: h });
    assert.ok(envs.json.items.length >= 1);
    const created = await request(baseUrl, 'POST', '/v1/environments', {
      headers: h,
      body: { name: 'Staging' },
    });
    assert.equal(created.status, 201);
    assert.ok(getStore().auditLog.some((a) => a.action === 'environment.created'));
  });

  it('event ingestion idempotency and cross-tenant rejection', async () => {
    const h = demoHeaders('engineer');
    const body = {
      event_id: 'evt_dup_1',
      signal_type: 'health',
      metadata: { authorization: 'Bearer ast_leaktoken123456789012345678' },
    };
    const first = await request(baseUrl, 'POST', '/v1/events', { headers: h, body });
    assert.equal(first.status, 201);
    const dup = await request(baseUrl, 'POST', '/v1/events', { headers: h, body });
    assert.equal(dup.status, 200);
    assert.equal(dup.json.duplicate, true);

    const cross = await request(baseUrl, 'POST', '/v1/events', {
      headers: h,
      body: { event_id: 'evt_x', tenant_id: 'other_tenant' },
    });
    assert.equal(cross.status, 403);

    const vault = await request(baseUrl, 'GET', '/v1/evidence', { headers: h });
    assert.equal(vault.status, 200);
  });

  it('report markdown export redacts secrets', async () => {
    const h = demoHeaders('admin');
    const created = await request(baseUrl, 'POST', '/v1/reports', {
      headers: h,
      body: { title: 'Export Test', kind: 'technical' },
    });
    const exp = await request(baseUrl, 'GET', `/v1/reports/${created.json.id}/export?format=markdown`, {
      headers: h,
    });
    assert.equal(exp.status, 200);
    assert.match(exp.text, /Metadata-only export/);
    assert.doesNotMatch(exp.text, /ast_[A-Za-z0-9_-]{8,}/);
  });

  it('authorization pack blocks approve and scope hash blocks changed targets', async () => {
    const soc = demoHeaders('soc', 'ten_demo', 'usr_soc');
    const hs = await request(baseUrl, 'POST', '/v1/high-scale-requests', {
      headers: demoHeaders('engineer'),
      body: validHighScaleRequestPayload({ objective: 'pack test' }),
    });
    const hsId = hs.json.id;
    const blocked = await request(baseUrl, 'POST', `/internal/soc/high-scale/${hsId}/approve`, { headers: soc });
    assert.equal(blocked.status, 409);
    assert.equal(blocked.json.error, 'authorization_pack_incomplete');
    assert.ok(blocked.json.authorization_pack_status);
    assert.notEqual(blocked.json.authorization_pack_status.overall, 'accepted');

    await acceptHighScaleAuthorizationPack(baseUrl, hsId, soc);
    const packReady = getStore().highScaleRequests.find((r) => r.id === hsId);
    assert.equal(packReady.authorization_pack_status.overall, 'accepted');
    const firstApprove = await request(baseUrl, 'POST', `/internal/soc/high-scale/${hsId}/approve`, { headers: soc });
    assert.equal(firstApprove.status, 200);
    assert.equal(firstApprove.json.state, 'under_review');
    assert.equal(firstApprove.json.scope_hash, null);
    const secondApprove = await request(baseUrl, 'POST', `/internal/soc/high-scale/${hsId}/approve`, {
      headers: socSecondary(),
    });
    assert.equal(secondApprove.status, 200);
    assert.equal(secondApprove.json.state, 'approved');
    assert.ok(secondApprove.json.scope_hash);

    const activeStart = new Date(Date.now() - 60000).toISOString();
    const activeEnd = new Date(Date.now() + 3600000).toISOString();
    await request(baseUrl, 'POST', `/internal/soc/high-scale/${hsId}/schedule`, {
      headers: soc,
      body: { window_start: activeStart, window_end: activeEnd },
    });

    getStore().targets.push({
      id: 'tgt_new',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_1',
      kind: 'fqdn',
      value: 'new.origin.test',
      expected_behavior: 'must_block_before_origin',
    });

    const start = await request(baseUrl, 'POST', `/internal/soc/high-scale/${hsId}/start`, { headers: soc });
    assert.equal(start.status, 409);
    assert.equal(start.json.error, 'scope_hash_mismatch');
  });

  it('adapter status reports no traffic and kill switch stops with audit', async () => {
    const soc = demoHeaders('soc', 'ten_demo', 'usr_soc');
    const hs = await request(baseUrl, 'POST', '/v1/high-scale-requests', {
      headers: demoHeaders('engineer'),
      body: validHighScaleRequestPayload({ objective: 'adapter' }),
    });
    const hsId = hs.json.id;
    await acceptHighScaleAuthorizationPack(baseUrl, hsId, soc);
    await dualSocApprove(hsId);
    const activeStart = new Date(Date.now() - 60000).toISOString();
    const activeEnd = new Date(Date.now() + 3600000).toISOString();
    await request(baseUrl, 'POST', `/internal/soc/high-scale/${hsId}/schedule`, {
      headers: soc,
      body: { window_start: activeStart, window_end: activeEnd },
    });
    const started = await request(baseUrl, 'POST', `/internal/soc/high-scale/${hsId}/start`, { headers: soc });
    assert.equal(started.status, 200);
    const status = await request(baseUrl, 'GET', `/internal/soc/high-scale/${hsId}/adapter-status`, { headers: soc });
    assert.equal(status.json.adapter.traffic_generated, false);

    const ks = await request(baseUrl, 'POST', '/internal/soc/kill-switch', {
      headers: soc,
      body: { active: true, reason: 'test' },
    });
    assert.deepEqual(ks.json.stopped_request_ids, [hsId]);
    const stop = await request(baseUrl, 'POST', `/internal/soc/high-scale/${hsId}/stop`, { headers: soc });
    assert.equal(stop.status, 409);
    assert.equal(stop.json.error, 'not_running');
    assert.ok(getStore().auditLog.some((a) => a.action === 'high_scale.adapter_stub_stopped'));
    assert.ok(getStore().auditLog.some((a) => a.action === 'high_scale.kill_switch_auto_stop'));
  });

  it('creates notification records for rules', async () => {
    const h = demoHeaders('admin');
    await request(baseUrl, 'POST', '/v1/notifications', {
      headers: h,
      body: { channel: 'webhook', destination: 'https://example.invalid/hook', triggers: ['high_scale.state_change'] },
    });
    const hs = await request(baseUrl, 'POST', '/v1/high-scale-requests', {
      headers: demoHeaders('engineer'),
      body: validHighScaleRequestPayload({ objective: 'notify' }),
    });
    assert.ok(getStore().notificationEvents.some((e) => e.trigger === 'high_scale.state_change'));
    const listed = await request(baseUrl, 'GET', '/v1/notifications', { headers: h });
    assert.ok(listed.json.events.length >= 1);
  });
});