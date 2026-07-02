import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { mintSignedSessionToken } from '../../src/context.mjs';
import { requirePermission } from '../../src/rbac.mjs';
import { createServer } from '../../src/server.mjs';
import { parseAddressedSecret } from '../../src/lib/addressedSecrets.mjs';
import { generateSalt, hashSecretWithSalt } from '../../src/lib/crypto.mjs';
import {
  auditServiceAccountAuthFailure,
  authenticateServiceAccountBearer,
  createServiceAccount,
  generateServiceAccountSecret,
  listServiceAccounts,
  revokeServiceAccount,
  rotateServiceAccount,
  validateRequestedScopes,
} from '../../src/services/serviceAccounts.mjs';
import { getStore, migrateDevStore } from '../../src/store.mjs';
import { createBootstrapToken } from '../../src/services/tokens.mjs';
import { agentHeaders, demoHeaders, request } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';

const TEST_SECRET = 'unit-session-secret-32chars-minimum';

describe('service account scopes validation', () => {
  it('rejects wildcard for non-admin roles', () => {
    const r = validateRequestedScopes('engineer', ['*']);
    assert.equal(r.error, 'invalid_scopes');
  });

  it('allows admin wildcard only', () => {
    const r = validateRequestedScopes('admin', ['*']);
    assert.equal(r.ok, true);
    assert.deepEqual(r.scopes, ['*']);
  });

  it('rejects scopes outside role permissions', () => {
    const r = validateRequestedScopes('viewer', ['test_run:start']);
    assert.equal(r.error, 'invalid_scopes');
  });

  it('rejects owner role for service accounts', () => {
    const r = validateRequestedScopes('owner', ['target_group:read']);
    assert.equal(r.error, 'invalid_role');
  });

  it('rejects soc role for service accounts', () => {
    const r = validateRequestedScopes('soc', ['target_group:read']);
    assert.equal(r.error, 'invalid_role');
  });
});

describe('service account lifecycle', () => {
  before(() => {
    freshStore();
    migrateDevStore(getStore());
  });

  it('returns svc_ secret once and redacts on list', () => {
    const ctx = { tenantId: 'ten_demo', userId: 'u1', role: 'admin' };
    const { secret, account } = createServiceAccount(ctx, {
      name: 'ci-bot',
      role: 'engineer',
      scopes: ['target_group:read'],
    });
    assert.ok(secret.startsWith('svc_v1.'));
    const hints = parseAddressedSecret(secret, 'svc_');
    assert.deepEqual(hints, { tenantId: 'ten_demo', id: account.id, version: 'v1' });
    assert.ok(account.secret_hash);
    assert.ok(account.secret_salt);
    const listed = listServiceAccounts(ctx);
    assert.equal(listed.length, 1);
    assert.equal(listed[0].secret, undefined);
    assert.equal(listed[0].secret_hash, undefined);
    assert.equal(listed[0].secret_salt, undefined);
  });

  it('authenticates and enforces scopes separately from role', () => {
    const adminCtx = { tenantId: 'ten_demo', userId: 'u1', role: 'admin' };
    const { secret } = createServiceAccount(adminCtx, {
      role: 'admin',
      scopes: ['target_group:read'],
    });
    const authCtx = authenticateServiceAccountBearer(secret);
    assert.equal(authCtx.tenantId, 'ten_demo');
    assert.match(authCtx.userId, /^service_account:/);
    assert.equal(authCtx.role, 'admin');

    const allowed = requirePermission(authCtx, 'target_group:read');
    assert.equal(allowed.ok, true);

    const denied = requirePermission(authCtx, 'test_run:start');
    assert.equal(denied.ok, false);
    assert.equal(denied.status, 403);
    assert.match(denied.body.message, /Scope/);
  });

  it('rejects revoked tokens', () => {
    const ctx = { tenantId: 'ten_demo', userId: 'u1', role: 'admin' };
    const { secret, account } = createServiceAccount(ctx, {
      role: 'viewer',
      scopes: ['target_group:read'],
    });
    revokeServiceAccount(ctx, account.id);
    const auth = authenticateServiceAccountBearer(secret);
    assert.equal(auth.error, 'revoked');
  });

  it('rejects expired tokens', () => {
    const ctx = { tenantId: 'ten_demo', userId: 'u1', role: 'admin' };
    const past = new Date(Date.now() - 60_000).toISOString();
    const { secret } = createServiceAccount(ctx, {
      role: 'viewer',
      scopes: ['target_group:read'],
      expires_at: past,
    });
    const auth = authenticateServiceAccountBearer(secret);
    assert.equal(auth.error, 'expired');
  });

  it('rotate invalidates old secret and authenticates new secret', () => {
    const ctx = { tenantId: 'ten_demo', userId: 'u1', role: 'admin' };
    const { secret: oldSecret, account } = createServiceAccount(ctx, {
      role: 'engineer',
      scopes: ['target_group:read'],
    });
    const rotated = rotateServiceAccount(ctx, account.id);
    assert.ok(rotated.secret.startsWith('svc_v1.'));
    const hints = parseAddressedSecret(rotated.secret, 'svc_');
    assert.deepEqual(hints, { tenantId: 'ten_demo', id: account.id, version: 'v1' });
    assert.notEqual(rotated.secret, oldSecret);
    assert.equal(authenticateServiceAccountBearer(oldSecret).error, 'invalid_token');
    const auth = authenticateServiceAccountBearer(rotated.secret);
    assert.equal(auth.tenantId, 'ten_demo');
    assert.equal(auth.role, 'engineer');
    assert.ok(account.rotated_at);
  });

  it('revoked account rotation returns 409-style service error', () => {
    const ctx = { tenantId: 'ten_demo', userId: 'u1', role: 'admin' };
    const { account } = createServiceAccount(ctx, {
      role: 'viewer',
      scopes: ['target_group:read'],
    });
    revokeServiceAccount(ctx, account.id);
    const result = rotateServiceAccount(ctx, account.id);
    assert.equal(result.error, 'service_account_revoked');
    assert.equal(result.status, 409);
  });

  it('rotation audit metadata excludes old and new secrets', () => {
    const ctx = { tenantId: 'ten_demo', userId: 'u1', role: 'admin' };
    const { secret: oldSecret, account } = createServiceAccount(ctx, {
      role: 'engineer',
      scopes: ['target_group:read'],
    });
    const beforeCount = getStore().auditLog.length;
    const { secret: newSecret } = rotateServiceAccount(ctx, account.id);
    const entry = getStore().auditLog
      .slice(beforeCount)
      .find((a) => a.action === 'service_account.rotated');
    assert.ok(entry);
    const serialized = JSON.stringify(entry);
    assert.ok(!serialized.includes(oldSecret));
    assert.ok(!serialized.includes(newSecret));
    assert.deepEqual(entry.metadata, { role: 'engineer', scopes: ['target_group:read'] });
  });

  it('still verifies legacy opaque service-account tokens', () => {
    const legacySecret = generateServiceAccountSecret();
    const salt = generateSalt();
    const record = {
      id: 'sacc_legacy01',
      tenant_id: 'ten_demo',
      name: 'legacy-bot',
      role: 'viewer',
      scopes: ['target_group:read'],
      secret_salt: salt,
      secret_hash: hashSecretWithSalt(legacySecret, salt),
      expires_at: null,
      revoked_at: null,
      created_at: new Date().toISOString(),
      created_by: 'u1',
      last_used_at: null,
    };
    getStore().serviceAccounts.push(record);
    const auth = authenticateServiceAccountBearer(legacySecret);
    assert.equal(auth.tenantId, 'ten_demo');
    assert.equal(auth.serviceAccountId, 'sacc_legacy01');
  });

  it('audits invalid addressed service tokens under parsed tenant without secret material', () => {
    const ctx = { tenantId: 'ten_demo', userId: 'u1', role: 'admin' };
    const { secret, account } = createServiceAccount(ctx, {
      role: 'viewer',
      scopes: ['target_group:read'],
    });
    const parts = secret.split('.');
    parts[3] = `${parts[3]}tampered`;
    const tampered = parts.join('.');
    const before = getStore().auditLog.length;
    assert.equal(authenticateServiceAccountBearer(tampered).error, 'invalid_token');
    auditServiceAccountAuthFailure(tampered);
    const entry = getStore().auditLog.slice(before).find((a) => a.action === 'service_account.auth_failed');
    assert.ok(entry);
    assert.equal(entry.tenant_id, 'ten_demo');
    assert.equal(entry.resource_id, account.id);
    assert.deepEqual(entry.metadata, { reason: 'invalid_token' });
    assert.ok(!JSON.stringify(entry).includes(tampered));
    assert.ok(!JSON.stringify(entry).includes(secret));
  });

  it('does not audit opaque bogus svc tokens with null tenant', () => {
    const before = getStore().auditLog.length;
    const bogus = 'svc_opaque_garbage_not_addressed_format';
    auditServiceAccountAuthFailure(bogus);
    const failures = getStore().auditLog
      .slice(before)
      .filter((a) => a.action === 'service_account.auth_failed');
    assert.equal(failures.length, 0);
  });

  it('admin wildcard scope does not grant SOC-only permissions', () => {
    const adminCtx = { tenantId: 'ten_demo', userId: 'u1', role: 'admin' };
    const { secret } = createServiceAccount(adminCtx, {
      role: 'admin',
      scopes: ['*'],
    });
    const authCtx = authenticateServiceAccountBearer(secret);
    assert.equal(authCtx.role, 'admin');
    assert.deepEqual(authCtx.scopes, ['*']);

    const highScale = requirePermission(authCtx, 'soc:high_scale');
    assert.equal(highScale.ok, false);
    assert.equal(highScale.status, 403);
    assert.equal(highScale.body.permission, 'soc:high_scale');

    const killSwitch = requirePermission(authCtx, 'soc:kill_switch');
    assert.equal(killSwitch.ok, false);
    assert.equal(killSwitch.status, 403);
    assert.equal(killSwitch.body.permission, 'soc:kill_switch');
  });
});

describe('service account HTTP auth', () => {
  let baseUrl;
  let server;

  before(() => {
    freshStore();
    process.env.ASTRANULL_AUTH_MODE = 'signed-session';
    process.env.ASTRANULL_SESSION_SECRET = TEST_SECRET;
    delete process.env.NODE_ENV;
    server = createServer();
    server.listen(0);
    const { port } = server.address();
    baseUrl = `http://127.0.0.1:${port}`;
  });

  after(() => {
    server?.close();
    delete process.env.ASTRANULL_AUTH_MODE;
    delete process.env.ASTRANULL_SESSION_SECRET;
  });

  it('allows scoped GET target-groups and denies test-runs without scope', async () => {
    const adminHeaders = {
      Authorization: `Bearer ${mintSignedSessionToken(
        { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' },
        TEST_SECRET,
      )}`,
    };
    const created = await request(baseUrl, 'POST', '/v1/service-accounts', {
      headers: adminHeaders,
      body: { name: 'read-only', role: 'engineer', scopes: ['target_group:read'] },
    });
    assert.equal(created.status, 201);
    const svcSecret = created.json.secret;
    const svcHeaders = { Authorization: `Bearer ${svcSecret}` };

    const tg = await request(baseUrl, 'GET', '/v1/target-groups', { headers: svcHeaders });
    assert.equal(tg.status, 200);

    const run = await request(baseUrl, 'POST', '/v1/test-runs', {
      headers: svcHeaders,
      body: { check_id: 'dns_authority_exposure', target_group_id: 'tg_1' },
    });
    assert.equal(run.status, 403);
    assert.equal(run.json.permission, 'test_run:start');
  });

  it('rejects revoked bearer on API routes', async () => {
    const adminHeaders = {
      Authorization: `Bearer ${mintSignedSessionToken(
        { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' },
        TEST_SECRET,
      )}`,
    };
    const created = await request(baseUrl, 'POST', '/v1/service-accounts', {
      headers: adminHeaders,
      body: { name: 'revoke-me', role: 'viewer', scopes: ['target_group:read'] },
    });
    const id = created.json.id;
    const svcSecret = created.json.secret;
    const revoke = await request(baseUrl, 'POST', `/v1/service-accounts/${id}/revoke`, {
      headers: adminHeaders,
    });
    assert.equal(revoke.status, 200);

    const tg = await request(baseUrl, 'GET', '/v1/target-groups', {
      headers: { Authorization: `Bearer ${svcSecret}` },
    });
    assert.equal(tg.status, 401);
  });

  it('service token cannot authenticate agent heartbeat', async () => {
    const adminCtx = { tenantId: 'ten_demo', userId: 'u1', role: 'admin' };
    const { secret: bootstrap } = createBootstrapToken(adminCtx, { target_group_id: 'tg_1' });
    const reg = await request(baseUrl, 'POST', '/v1/agents/register', {
      body: { bootstrap_token: bootstrap, hostname: 'svc-agent-test' },
    });
    assert.equal(reg.status, 201);
    const agentId = reg.json.agent.id;

    const { secret: svcSecret } = createServiceAccount(adminCtx, {
      role: 'admin',
      scopes: ['*'],
    });

    const hb = await request(baseUrl, 'POST', `/v1/agents/${agentId}/heartbeat`, {
      headers: agentHeaders(svcSecret),
      body: { version: '0.1.0' },
    });
    assert.equal(hb.status, 401);

    const hbOk = await request(baseUrl, 'POST', `/v1/agents/${agentId}/heartbeat`, {
      headers: agentHeaders(reg.json.agent_credential),
      body: { version: '0.1.0' },
    });
    assert.equal(hbOk.status, 200);
  });

  it('POST and GET service-accounts responses omit secret_hash and secret_salt', async () => {
    const adminHeaders = {
      Authorization: `Bearer ${mintSignedSessionToken(
        { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' },
        TEST_SECRET,
      )}`,
    };
    const created = await request(baseUrl, 'POST', '/v1/service-accounts', {
      headers: adminHeaders,
      body: { name: 'redact-check', role: 'engineer', scopes: ['target_group:read'] },
    });
    assert.equal(created.status, 201);
    assert.ok(created.json.secret?.startsWith('svc_'));
    assert.equal(created.json.secret_hash, undefined);
    assert.equal(created.json.secret_salt, undefined);

    const listed = await request(baseUrl, 'GET', '/v1/service-accounts', { headers: adminHeaders });
    assert.equal(listed.status, 200);
    assert.ok(listed.json.items.length >= 1);
    for (const item of listed.json.items) {
      assert.equal(item.secret_hash, undefined);
      assert.equal(item.secret_salt, undefined);
      assert.equal(item.secret, undefined);
    }
  });

  it('POST rotate returns new secret once, omits hash/salt, and old bearer fails on target-groups', async () => {
    const adminHeaders = {
      Authorization: `Bearer ${mintSignedSessionToken(
        { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' },
        TEST_SECRET,
      )}`,
    };
    const created = await request(baseUrl, 'POST', '/v1/service-accounts', {
      headers: adminHeaders,
      body: { name: 'rotate-me', role: 'engineer', scopes: ['target_group:read'] },
    });
    assert.equal(created.status, 201);
    const id = created.json.id;
    const oldSecret = created.json.secret;

    const rotated = await request(baseUrl, 'POST', `/v1/service-accounts/${id}/rotate`, {
      headers: adminHeaders,
    });
    assert.equal(rotated.status, 200);
    assert.ok(rotated.json.secret?.startsWith('svc_'));
    assert.notEqual(rotated.json.secret, oldSecret);
    assert.equal(rotated.json.secret_hash, undefined);
    assert.equal(rotated.json.secret_salt, undefined);

    const oldAuth = await request(baseUrl, 'GET', '/v1/target-groups', {
      headers: { Authorization: `Bearer ${oldSecret}` },
    });
    assert.equal(oldAuth.status, 401);

    const newAuth = await request(baseUrl, 'GET', '/v1/target-groups', {
      headers: { Authorization: `Bearer ${rotated.json.secret}` },
    });
    assert.equal(newAuth.status, 200);
  });

  it('works with dev-headers mode when bearer svc is present', async () => {
    server.close();
    freshStore();
    process.env.ASTRANULL_AUTH_MODE = 'dev-headers';
    server = createServer();
    await new Promise((resolve) => server.listen(0, resolve));
    const { port } = server.address();
    baseUrl = `http://127.0.0.1:${port}`;

    const ctx = { tenantId: 'ten_demo', userId: 'u1', role: 'admin' };
    const { secret } = createServiceAccount(ctx, {
      role: 'viewer',
      scopes: ['target_group:read'],
    });

    const res = await request(baseUrl, 'GET', '/v1/target-groups', {
      headers: {
        ...demoHeaders('viewer'),
        Authorization: `Bearer ${secret}`,
      },
    });
    assert.equal(res.status, 200);
    assert.ok(getStore().serviceAccounts[0].last_used_at);
  });
});