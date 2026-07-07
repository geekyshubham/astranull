import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { getStore } from '../../src/store.mjs';
import {
  appendSignupQueueEvent,
  createSignupRequest,
  resetSignupRateLimitsForTests,
} from '../../src/services/signupIntake.mjs';
import { DEFAULT_PRIVACY } from '../../src/lib/privacySettings.mjs';
import { demoHeaders, request } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';

let server;
let baseUrl;

function bootIsolatedServer() {
  process.env.ASTRANULL_NO_PERSIST = '1';
  freshStore();
  resetSignupRateLimitsForTests();
  server?.close();
  server = createServer();
  server.listen(0);
  baseUrl = `http://127.0.0.1:${server.address().port}`;
}

before(() => {
  bootIsolatedServer();
});

after(() => server?.close());

describe('misc portal endpoints (FT-RST-01, FT-SUP-01, FT-PRV-01)', () => {
  it('FT-RST-01 restore clears deleted_at/by and rejects non-archived groups', async () => {
    bootIsolatedServer();
    const headers = demoHeaders('engineer');
    const created = await request(baseUrl, 'POST', '/v1/target-groups', {
      headers,
      body: { name: 'restore-me', environment_id: 'env_demo' },
    });
    assert.equal(created.status, 201);
    const groupId = created.json.id;

    const archived = await request(baseUrl, 'DELETE', `/v1/target-groups/${groupId}`, { headers });
    assert.equal(archived.status, 200);
    const stored = getStore().targetGroups.find((g) => g.id === groupId);
    assert.ok(stored.deleted_at);
    assert.equal(stored.deleted_by, 'usr_admin');

    const restored = await request(baseUrl, 'POST', `/v1/target-groups/${groupId}/restore`, {
      headers,
    });
    assert.equal(restored.status, 200);
    assert.equal(restored.json.target_group.id, groupId);
    assert.equal(restored.json.target_group.deleted_at, undefined);

    const notArchived = await request(baseUrl, 'POST', `/v1/target-groups/${groupId}/restore`, {
      headers,
    });
    assert.equal(notArchived.status, 404);
    assert.equal(notArchived.json.error, 'not_archived');

    const activeList = await request(baseUrl, 'GET', '/v1/target-groups', { headers });
    assert.ok(activeList.json.items.some((g) => g.id === groupId));
  });

  it('FT-SUP-01 signup events are ordered, truncated, and rate-limited', async () => {
    bootIsolatedServer();
    const created = createSignupRequest({
      organization_name: 'Queue Co',
      contact_email: 'owner@queue.example',
      contact_name: 'Owner',
      email_domain: 'queue.example',
      requested_plan: 'starter',
      intended_use: 'evaluation',
      region: 'us',
    });
    assert.equal(created.request.id.length > 0, true);
    const requestId = created.request.id;

    const longMessage = 'x'.repeat(700);
    appendSignupQueueEvent({
      requestId,
      eventKind: 'info_requested',
      actor: 'staff:reviewer',
      message: longMessage,
    });

    const first = await request(baseUrl, 'GET', `/v1/signup-requests/${requestId}/events`);
    assert.equal(first.status, 200);
    assert.ok(first.json.events.length >= 2);
    assert.ok(
      first.json.events.every(
        (event, index, arr) =>
          index === 0 || String(arr[index - 1].created_at) <= String(event.created_at),
      ),
    );
    const truncated = first.json.events.find((event) => event.event_kind === 'info_requested');
    assert.equal(truncated.message.length, 500);

    for (let i = 0; i < 11; i += 1) {
      const res = await request(baseUrl, 'GET', `/v1/signup-requests/${requestId}/events`);
      assert.equal(res.status, 200, `expected 200 on prefetch ${i + 2}`);
    }
    const limited = await request(baseUrl, 'GET', `/v1/signup-requests/${requestId}/events`);
    assert.equal(limited.status, 429);
    assert.equal(limited.json.error, 'rate_limited');
  });

  it('FT-PRV-01 fresh tenant privacy defaults and PATCH retention persist', async () => {
    bootIsolatedServer();
    const headers = demoHeaders('admin');
    const tenant = await request(baseUrl, 'GET', '/v1/tenants/current', { headers });
    assert.equal(tenant.status, 200);
    assert.equal(tenant.json.privacy_settings.metadata_retention_days, DEFAULT_PRIVACY.metadata_retention_days);
    assert.equal(tenant.json.privacy_settings.evidence_retention_days, DEFAULT_PRIVACY.evidence_retention_days);
    assert.equal(tenant.json.privacy_settings.audit_retention_days, DEFAULT_PRIVACY.audit_retention_days);

    const patched = await request(baseUrl, 'PATCH', '/v1/tenants/current', {
      headers,
      body: {
        privacy_settings: {
          metadata_retention_days: 400,
          evidence_retention_days: 1900,
          audit_retention_days: 2600,
        },
      },
    });
    assert.equal(patched.status, 200);
    assert.equal(patched.json.privacy_settings.metadata_retention_days, 400);
    assert.equal(patched.json.privacy_settings.evidence_retention_days, 1900);
    assert.equal(patched.json.privacy_settings.audit_retention_days, 2600);

    const reloaded = await request(baseUrl, 'GET', '/v1/tenants/current', { headers });
    assert.equal(reloaded.json.privacy_settings.metadata_retention_days, 400);
  });
});