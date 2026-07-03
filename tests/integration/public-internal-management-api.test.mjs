import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { demoHeaders, request, staffHeaders } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';
import { getStore } from '../../src/store.mjs';
import { resetSignupRateLimitsForTests } from '../../src/services/signupIntake.mjs';

let baseUrl;
let server;

const signupPayload = () => ({
  organization_name: 'Northwind Defense',
  contact_email: 'security@northwind.example',
  contact_name: 'Alex Morgan',
  requested_plan: 'professional',
  intended_use: 'Defensive DDoS readiness validation for declared production origins.',
  region: 'us',
  high_scale_interest: true,
});

before(() => {
  process.env.ASTRANULL_NO_PERSIST = '1';
  freshStore();
  resetSignupRateLimitsForTests();
  server = createServer();
  server.listen(0);
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(() => server.close());

describe('public landing and internal management APIs', () => {
  it('serves public site config and landing without auth', async () => {
    const landing = await request(baseUrl, 'GET', '/');
    assert.equal(landing.status, 200);
    assert.match(landing.text, /No-access-first/);
    assert.match(landing.text, /Sign up/);
    const navMatch = landing.text.match(/<nav class="public-nav">([\s\S]*?)<\/nav>/);
    assert.ok(navMatch);
    assert.doesNotMatch(navMatch[1], /internal\/admin/);
    assert.match(landing.text, /\/login/);

    const appShell = await request(baseUrl, 'GET', '/app');
    assert.equal(appShell.status, 200);
    assert.match(appShell.text, /id="nav"/);

    const config = await request(baseUrl, 'GET', '/v1/public/site-config');
    assert.equal(config.status, 200);
    assert.equal(config.json.product_name, 'AstraNull');
    assert.equal(config.json.customer_portal_path, '/app');
    assert.equal(config.json.safety_framing.no_default_cloud_access, true);

    const loginPage = await request(baseUrl, 'GET', '/login');
    assert.equal(loginPage.status, 200);
    assert.match(loginPage.text, /Customer portal/);
  });

  it('accepts public signup requests and exposes public status', async () => {
    const created = await request(baseUrl, 'POST', '/v1/signup-requests', {
      body: signupPayload(),
    });
    assert.equal(created.status, 201);
    assert.equal(created.json.request.state, 'submitted');
    const requestId = created.json.request.id;

    const status = await request(baseUrl, 'GET', `/v1/signup-requests/${requestId}`);
    assert.equal(status.status, 200);
    assert.equal(status.json.request.id, requestId);

    const dup = await request(baseUrl, 'POST', '/v1/signup-requests', {
      body: signupPayload(),
    });
    assert.equal(dup.status, 409);
    assert.equal(dup.json.error, 'duplicate_request');
  });

  it('denies customer principals on internal admin routes', async () => {
    const denied = await request(baseUrl, 'GET', '/internal/admin/signup-requests', {
      headers: demoHeaders('admin'),
    });
    assert.equal(denied.status, 403);
    assert.equal(denied.json.error, 'staff_forbidden');
  });

  it('allows staff review, provisioning, subscription enforcement, and audit', async () => {
    const created = await request(baseUrl, 'POST', '/v1/signup-requests', {
      body: {
        ...signupPayload(),
        organization_name: 'Contoso Security',
        contact_email: 'ops@contoso.example',
      },
    });
    assert.equal(created.status, 201);
    const requestId = created.json.request.id;

    const queue = await request(baseUrl, 'GET', '/internal/admin/signup-requests', {
      headers: staffHeaders('internal_admin'),
    });
    assert.equal(queue.status, 200);
    assert.ok(queue.json.items.some((item) => item.id === requestId));

    const approved = await request(baseUrl, 'POST', `/internal/admin/signup-requests/${requestId}/approve`, {
      headers: staffHeaders('internal_admin'),
      body: { reason: 'Verified organization' },
    });
    assert.equal(approved.status, 200);
    assert.equal(approved.json.request.state, 'customer_invited');
    const tenantId = approved.json.provisioning.tenant_id;
    assert.ok(tenantId);

    const store = getStore();
    assert.ok(store.tenantSubscriptions.some((s) => s.tenant_id === tenantId));
    assert.ok(store.internalAuditLog.some((a) => a.action === 'signup.request_approved'));

    const suspended = await request(baseUrl, 'PATCH', `/internal/admin/tenants/${tenantId}`, {
      headers: staffHeaders('internal_admin'),
      body: { lifecycle_state: 'suspended', reason: 'policy hold' },
    });
    assert.equal(suspended.status, 200);
    assert.equal(suspended.json.account.lifecycle_state, 'suspended');

    const storeAfterSuspend = getStore();
    const tgId = 'tg_contoso_demo';
    storeAfterSuspend.targetGroups.push({
      id: tgId,
      tenant_id: tenantId,
      environment_id: approved.json.provisioning.environment_id,
      name: 'Origin Group',
      expected_behavior_default: 'must_block_before_origin',
    });
    storeAfterSuspend.targets.push({
      id: 'tgt_contoso_1',
      tenant_id: tenantId,
      target_group_id: tgId,
      kind: 'fqdn',
      value: 'origin.contoso.example',
      expected_behavior: 'must_block_before_origin',
    });

    const blockedRun = await request(baseUrl, 'POST', '/v1/test-runs', {
      headers: { ...demoHeaders('engineer'), 'x-tenant-id': tenantId, 'x-user-id': 'usr_owner' },
      body: {
        check_id: 'origin.direct_bypass.safe',
        target_group_id: tgId,
        target_id: 'tgt_contoso_1',
      },
    });
    assert.equal(blockedRun.status, 403);
    assert.equal(blockedRun.json.error, 'tenant_suspended');
  });

  it('records staff rejection with customer-safe notice', async () => {
    const created = await request(baseUrl, 'POST', '/v1/signup-requests', {
      body: {
        ...signupPayload(),
        organization_name: 'Rejected Co',
        contact_email: 'deny@rejected.example',
      },
    });
    assert.equal(created.status, 201);
    const requestId = created.json.request.id;

    const rejected = await request(baseUrl, 'POST', `/internal/admin/signup-requests/${requestId}/reject`, {
      headers: staffHeaders('internal_admin'),
      body: { reason: 'Could not verify business domain.' },
    });
    assert.equal(rejected.status, 200);
    assert.equal(rejected.json.request.state, 'rejected');
    assert.ok(rejected.json.request.customer_notice);
    assert.ok(getStore().internalAuditLog.some((a) => a.action === 'signup.request_rejected'));
  });

  it('serves internal management shell without customer nav leakage', async () => {
    const page = await request(baseUrl, 'GET', '/internal/admin');
    assert.equal(page.status, 200);
    assert.match(page.text, /AstraNull Staff/);
    assert.match(page.text, /Sign-up queue/);
    assert.doesNotMatch(page.text, /Target Groups/);
  });
});