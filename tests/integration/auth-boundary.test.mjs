import assert from 'node:assert/strict';
import { after, afterEach, before, describe, it } from 'node:test';
import { mintSignedSessionToken } from '../../src/context.mjs';
import { createServer } from '../../src/server.mjs';
import { createAddressedSecret } from '../../src/lib/addressedSecrets.mjs';
import { generateSalt, hashSecretWithSalt } from '../../src/lib/crypto.mjs';
import { createBootstrapToken } from '../../src/services/tokens.mjs';

import {
  agentHeaders,
  demoHeaders,
  request,
  signedSessionHeaders,
} from '../helpers/http.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';

const TEST_SECRET = 'integration-session-secret-32chars-min';
const envSnapshot = { ...process.env };

let baseUrl;
let server;

function restoreEnv() {
  for (const key of Object.keys(process.env)) {
    if (!(key in envSnapshot)) delete process.env[key];
  }
  Object.assign(process.env, envSnapshot);
}

function startSignedSessionServer() {
  freshStore();
  process.env.ASTRANULL_AUTH_MODE = 'signed-session';
  process.env.ASTRANULL_SESSION_SECRET = TEST_SECRET;
  delete process.env.NODE_ENV;
  server = createServer();
  server.listen(0);
  const { port } = server.address();
  baseUrl = `http://127.0.0.1:${port}`;
}

before(() => {
  startSignedSessionServer();
});

after(() => {
  server?.close();
  restoreEnv();
});

afterEach(() => {
  restoreEnv();
  process.env.ASTRANULL_AUTH_MODE = 'signed-session';
  process.env.ASTRANULL_SESSION_SECRET = TEST_SECRET;
});

describe('signed-session API boundary', () => {
  it('returns 401 for /v1/state without session token', async () => {
    const res = await request(baseUrl, 'GET', '/v1/state');
    assert.equal(res.status, 401);
    assert.equal(res.json.error, 'unauthorized');
  });

  it('allows tenant read with a valid signed session', async () => {
    const headers = signedSessionHeaders('engineer', 'ten_demo', 'usr_eng', TEST_SECRET, mintSignedSessionToken);
    const res = await request(baseUrl, 'GET', '/v1/tenants/current', { headers });
    assert.equal(res.status, 200);
    assert.equal(res.json.id, 'ten_demo');
  });

  it('ignores spoofed x-role when session role is viewer', async () => {
    const headers = {
      ...signedSessionHeaders('viewer', 'ten_demo', 'usr_view', TEST_SECRET, mintSignedSessionToken),
      'x-role': 'admin',
      'x-tenant-id': 'ten_demo',
    };
    const res = await request(baseUrl, 'POST', '/v1/bootstrap-tokens', {
      headers,
      body: { name: 'should-fail', max_registrations: 1 },
    });
    assert.equal(res.status, 403);
    assert.equal(res.json.error, 'forbidden');
  });

  it('invalid addressed service-account bearer audits without secret material', async () => {
    const tampered = createAddressedSecret('svc_', 'ten_demo', 'sacc_nonexistent');
    const bogus = `${tampered}x`;
    const before = getStore().auditLog.length;
    const res = await request(baseUrl, 'GET', '/v1/target-groups', {
      headers: { Authorization: `Bearer ${bogus}` },
    });
    assert.equal(res.status, 401);
    const failure = getStore().auditLog
      .slice(before)
      .find((a) => a.action === 'service_account.auth_failed');
    assert.ok(failure);
    assert.equal(failure.tenant_id, 'ten_demo');
    assert.equal(failure.resource_id, 'sacc_nonexistent');
    assert.deepEqual(failure.metadata, { reason: 'invalid_token' });
    assert.ok(!JSON.stringify(failure).includes(bogus));
  });

  it('opaque bogus service-account bearer does not write auth_failed audit', async () => {
    const bogus = 'svc_bogus_integration_token_not_real';
    const before = getStore().auditLog.length;
    const res = await request(baseUrl, 'GET', '/v1/target-groups', {
      headers: { Authorization: `Bearer ${bogus}` },
    });
    assert.equal(res.status, 401);
    const failures = getStore().auditLog
      .slice(before)
      .filter((a) => a.action === 'service_account.auth_failed');
    assert.equal(failures.length, 0);
  });

  it('admin service account with wildcard cannot use SOC-only routes', async () => {
    const adminHeaders = signedSessionHeaders('admin', 'ten_demo', 'usr_admin', TEST_SECRET, mintSignedSessionToken);
    const created = await request(baseUrl, 'POST', '/v1/service-accounts', {
      headers: adminHeaders,
      body: { name: 'wildcard-admin', role: 'admin', scopes: ['*'] },
    });
    assert.equal(created.status, 201);
    const svcHeaders = { Authorization: `Bearer ${created.json.secret}` };

    const killSwitch = await request(baseUrl, 'POST', '/internal/soc/kill-switch', {
      headers: svcHeaders,
      body: { active: true, reason: 'integration-test' },
    });
    assert.equal(killSwitch.status, 403);
    assert.equal(killSwitch.json.permission, 'soc:kill_switch');
  });

  it('service account bearer authenticates scoped API access', async () => {
    const adminHeaders = signedSessionHeaders('admin', 'ten_demo', 'usr_admin', TEST_SECRET, mintSignedSessionToken);
    const created = await request(baseUrl, 'POST', '/v1/service-accounts', {
      headers: adminHeaders,
      body: { name: 'integration-bot', role: 'engineer', scopes: ['target_group:read'] },
    });
    assert.equal(created.status, 201);
    assert.ok(created.json.secret?.startsWith('svc_'));
    const svcHeaders = { Authorization: `Bearer ${created.json.secret}` };

    const list = await request(baseUrl, 'GET', '/v1/target-groups', { headers: svcHeaders });
    assert.equal(list.status, 200);

    const denied = await request(baseUrl, 'POST', '/v1/test-runs', {
      headers: svcHeaders,
      body: { check_id: 'dns_authority_exposure', target_group_id: 'tg_1' },
    });
    assert.equal(denied.status, 403);
  });

  it('agent register and heartbeat work without human session', async () => {
    const adminCtx = { tenantId: 'ten_demo', userId: 'u1', role: 'admin' };
    const { secret } = createBootstrapToken(adminCtx, {
      target_group_id: 'tg_1',
      max_registrations: 2,
    });

    const reg = await request(baseUrl, 'POST', '/v1/agents/register', {
      body: {
        bootstrap_token: secret,
        hostname: 'signed-mode-host',
        name: 'signed-agent',
        capabilities: ['heartbeat'],
      },
    });
    assert.equal(reg.status, 201);
    assert.ok(reg.json.agent_credential?.startsWith('agc_v1.'));
    const agentId = reg.json.agent.id;
    const credential = reg.json.agent_credential;

    const hb = await request(baseUrl, 'POST', `/v1/agents/${agentId}/heartbeat`, {
      headers: agentHeaders(credential),
      body: { version: '0.1.0' },
    });
    assert.equal(hb.status, 200);

    const list = await request(baseUrl, 'GET', '/v1/agents', {
      headers: signedSessionHeaders('engineer', 'ten_demo', 'usr_eng', TEST_SECRET, mintSignedSessionToken),
    });
    assert.equal(list.status, 200);
    assert.ok(list.json.items.some((a) => a.id === agentId));

    const jobs = await request(baseUrl, 'GET', `/v1/agents/${agentId}/jobs`, {
      headers: agentHeaders(credential),
    });
    assert.equal(jobs.status, 200);
  });

  it('admin can revoke an agent and the old credential stops working', async () => {
    const adminCtx = { tenantId: 'ten_demo', userId: 'u1', role: 'admin' };
    const { secret } = createBootstrapToken(adminCtx, {
      target_group_id: 'tg_1',
      max_registrations: 1,
    });
    const reg = await request(baseUrl, 'POST', '/v1/agents/register', {
      body: {
        bootstrap_token: secret,
        hostname: 'revoke-host',
        name: 'revoke-agent',
        capabilities: ['heartbeat'],
      },
    });
    assert.equal(reg.status, 201);
    const agentId = reg.json.agent.id;
    const credential = reg.json.agent_credential;

    const viewerRevoke = await request(baseUrl, 'POST', `/v1/agents/${agentId}/revoke`, {
      headers: signedSessionHeaders('viewer', 'ten_demo', 'usr_view', TEST_SECRET, mintSignedSessionToken),
    });
    assert.equal(viewerRevoke.status, 403);
    assert.equal(viewerRevoke.json.permission, 'agent:revoke');

    const revoked = await request(baseUrl, 'POST', `/v1/agents/${agentId}/revoke`, {
      headers: signedSessionHeaders('admin', 'ten_demo', 'usr_admin', TEST_SECRET, mintSignedSessionToken),
    });
    assert.equal(revoked.status, 200);
    assert.equal(revoked.json.agent.id, agentId);
    assert.equal(revoked.json.agent.status, 'revoked');
    assert.equal(revoked.json.agent.credential_hash, undefined);
    assert.ok(getStore().auditLog.some((a) => a.action === 'agent.revoked' && a.resource_id === agentId));

    const hb = await request(baseUrl, 'POST', `/v1/agents/${agentId}/heartbeat`, {
      headers: agentHeaders(credential),
      body: { version: '0.1.1' },
    });
    assert.equal(hb.status, 401);
    const jobs = await request(baseUrl, 'GET', `/v1/agents/${agentId}/jobs`, {
      headers: agentHeaders(credential),
    });
    assert.equal(jobs.status, 401);
    const denial = getStore().auditLog.find(
      (a) => a.action === 'agent.auth_denied'
        && a.resource_id === agentId
        && a.metadata?.reason === 'revoked',
    );
    assert.ok(denial);
    assert.ok(!JSON.stringify(denial).includes(credential));
  });

  it('bogus nonexistent addressed agent bearer does not write tenant-local audit', async () => {
    const ghostId = 'agent_integration_ghost';
    const tampered = `${createAddressedSecret('agc_', 'ten_demo', ghostId)}tampered`;
    const before = getStore().auditLog.length;
    const res = await request(baseUrl, 'POST', `/v1/agents/${ghostId}/heartbeat`, {
      headers: agentHeaders(tampered),
      body: { version: '0.1.0' },
    });
    assert.equal(res.status, 401);
    const denials = getStore().auditLog
      .slice(before)
      .filter((a) => a.action === 'agent.auth_denied');
    assert.equal(denials.length, 0);
  });

  it('invalid addressed agent bearer audits without secret material', async () => {
    const adminCtx = { tenantId: 'ten_demo', userId: 'u1', role: 'admin' };
    const { secret } = createBootstrapToken(adminCtx, {
      target_group_id: 'tg_1',
      max_registrations: 2,
    });
    const reg = await request(baseUrl, 'POST', '/v1/agents/register', {
      body: {
        bootstrap_token: secret,
        hostname: 'audit-host',
        capabilities: ['heartbeat'],
      },
    });
    assert.equal(reg.status, 201);
    const agentId = reg.json.agent.id;
    const tampered = `${createAddressedSecret('agc_', 'ten_demo', agentId)}tampered`;
    const before = getStore().auditLog.length;
    const res = await request(baseUrl, 'POST', `/v1/agents/${agentId}/heartbeat`, {
      headers: agentHeaders(tampered),
      body: { version: '0.1.0' },
    });
    assert.equal(res.status, 401);
    const denial = getStore().auditLog
      .slice(before)
      .find((a) => a.action === 'agent.auth_denied');
    assert.ok(denial);
    assert.equal(denial.tenant_id, 'ten_demo');
    assert.equal(denial.resource_id, agentId);
    assert.ok(!JSON.stringify(denial).includes(tampered));
  });

  it('legacy opaque agc_ credential still authenticates when manually seeded', async () => {
    const legacyCredential = 'agc_manuallegacyopaque123456789012345';
    const agentId = 'agent_legacy';
    const salt = generateSalt();
    getStore().agents.push({
      id: agentId,
      tenant_id: 'ten_demo',
      name: 'legacy',
      hostname: 'legacy-host',
      status: 'online',
      credential_salt: salt,
      credential_hash: hashSecretWithSalt(legacyCredential, salt),
    });
    const hb = await request(baseUrl, 'POST', `/v1/agents/${agentId}/heartbeat`, {
      headers: agentHeaders(legacyCredential),
      body: { version: '0.0.0' },
    });
    assert.equal(hb.status, 200);
  });
});
