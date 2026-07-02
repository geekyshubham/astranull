import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { after, afterEach, before, describe, it } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { demoHeaders, request } from '../helpers/http.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';

const TEST_ENC_KEY_B64 = randomBytes(32).toString('base64');
const PLAINTEXT_CREATE = 'integration-plaintext-create-abc123';
const PLAINTEXT_ROTATE = 'integration-plaintext-rotate-def456';
const envSnapshot = { ...process.env };

let baseUrl;
let server;

function restoreEnv() {
  for (const key of Object.keys(process.env)) {
    if (!(key in envSnapshot)) delete process.env[key];
  }
  Object.assign(process.env, envSnapshot);
}

function assertNoSecretLeak(obj, ...needles) {
  const blob = JSON.stringify(obj);
  for (const needle of needles) {
    assert.ok(!blob.includes(needle), `leaked ${needle}`);
  }
  assert.ok(!blob.includes('ciphertext'));
  assert.ok(!blob.includes('auth_tag'));
}

before(() => {
  freshStore();
  process.env.ASTRANULL_NO_PERSIST = '1';
  process.env.ASTRANULL_SECRET_ENCRYPTION_KEY = TEST_ENC_KEY_B64;
  server = createServer();
  server.listen(0);
  const { port } = server.address();
  baseUrl = `http://127.0.0.1:${port}`;
});

after(() => {
  server?.close();
  restoreEnv();
});

afterEach(() => {
  process.env.ASTRANULL_NO_PERSIST = '1';
  process.env.ASTRANULL_SECRET_ENCRYPTION_KEY = TEST_ENC_KEY_B64;
});

describe('secret vault API', () => {
  it('creates, lists, and rotates without leaking plaintext or crypto material', async () => {
    freshStore();
    const admin = demoHeaders('admin');
    const created = await request(baseUrl, 'POST', '/v1/secrets', {
      headers: admin,
      body: {
        purpose: 'webhook',
        name: 'primary-hook',
        plaintext: PLAINTEXT_CREATE,
        metadata: { api_key: 'should-redact', note: 'ok' },
      },
    });
    assert.equal(created.status, 201);
    assert.ok(created.json.secret?.id);
    assert.equal(created.json.secret.rotation, 0);
    assertNoSecretLeak(created.json, PLAINTEXT_CREATE, 'should-redact');
    assert.equal(created.json.secret.metadata.api_key, '[REDACTED]');

    const stored = getStore().encryptedSecrets.find((s) => s.id === created.json.secret.id);
    assert.ok(stored);
    assert.equal(stored.metadata.api_key, '[REDACTED]');
    assert.ok(stored.envelope?.ciphertext);

    const listed = await request(baseUrl, 'GET', '/v1/secrets', { headers: admin });
    assert.equal(listed.status, 200);
    assert.equal(listed.json.items.length, 1);
    assertNoSecretLeak(listed.json, PLAINTEXT_CREATE);

    const rotated = await request(baseUrl, 'POST', `/v1/secrets/${created.json.secret.id}/rotate`, {
      headers: admin,
      body: { plaintext: PLAINTEXT_ROTATE, metadata: { token: 'secret-token-value' } },
    });
    assert.equal(rotated.status, 200);
    assert.equal(rotated.json.rotation, 1);
    assertNoSecretLeak(rotated.json, PLAINTEXT_ROTATE, PLAINTEXT_CREATE, 'secret-token-value');
    assert.equal(rotated.json.metadata.token, '[REDACTED]');
  });

  it('scoped service account with secret:read can list but not write or rotate', async () => {
    freshStore();
    const admin = demoHeaders('admin');
    const created = await request(baseUrl, 'POST', '/v1/secrets', {
      headers: admin,
      body: { purpose: 'automation', name: 'scope-read-only', plaintext: PLAINTEXT_CREATE },
    });
    assert.equal(created.status, 201);
    const secretId = created.json.secret.id;

    const svc = await request(baseUrl, 'POST', '/v1/service-accounts', {
      headers: admin,
      body: { name: 'secret-reader', role: 'admin', scopes: ['secret:read'] },
    });
    assert.equal(svc.status, 201);
    const svcHeaders = { Authorization: `Bearer ${svc.json.secret}` };

    const listed = await request(baseUrl, 'GET', '/v1/secrets', { headers: svcHeaders });
    assert.equal(listed.status, 200);
    assert.ok(listed.json.items.some((s) => s.id === secretId));

    const writeAttempt = await request(baseUrl, 'POST', '/v1/secrets', {
      headers: svcHeaders,
      body: { purpose: 'automation', name: 'should-fail', plaintext: 'nope' },
    });
    assert.equal(writeAttempt.status, 403);

    const rotateAttempt = await request(baseUrl, 'POST', `/v1/secrets/${secretId}/rotate`, {
      headers: svcHeaders,
      body: { plaintext: PLAINTEXT_ROTATE },
    });
    assert.equal(rotateAttempt.status, 403);
  });

  it('forbids viewer from secret write and read', async () => {
    const viewer = demoHeaders('viewer');
    const createRes = await request(baseUrl, 'POST', '/v1/secrets', {
      headers: viewer,
      body: { purpose: 'x', name: 'y', plaintext: 'z' },
    });
    assert.equal(createRes.status, 403);
    const listRes = await request(baseUrl, 'GET', '/v1/secrets', { headers: viewer });
    assert.equal(listRes.status, 403);
  });

  it('isolates secrets by tenant', async () => {
    freshStore();
    const adminDemo = demoHeaders('admin', 'ten_demo');
    const created = await request(baseUrl, 'POST', '/v1/secrets', {
      headers: adminDemo,
      body: { purpose: 'provider', name: 'iso', plaintext: PLAINTEXT_CREATE },
    });
    assert.equal(created.status, 201);
    const secretId = created.json.secret.id;

    const otherTenantList = await request(baseUrl, 'GET', '/v1/secrets', {
      headers: demoHeaders('admin', 'ten_other'),
    });
    assert.equal(otherTenantList.status, 200);
    assert.equal(otherTenantList.json.items.length, 0);

    const otherRotate = await request(baseUrl, 'POST', `/v1/secrets/${secretId}/rotate`, {
      headers: demoHeaders('admin', 'ten_other'),
      body: { plaintext: PLAINTEXT_ROTATE },
    });
    assert.equal(otherRotate.status, 404);
    assert.equal(otherRotate.json.error, 'not_found');
  });

  it('returns 503 when encryption key is not configured', async () => {
    freshStore();
    let noKeyServer;
    let noKeyUrl;
    try {
      process.env.ASTRANULL_NO_PERSIST = '1';
      delete process.env.ASTRANULL_SECRET_ENCRYPTION_KEY;
      process.env.NODE_ENV = 'test';
      noKeyServer = createServer();
      noKeyServer.listen(0);
      noKeyUrl = `http://127.0.0.1:${noKeyServer.address().port}`;
      const admin = demoHeaders('admin');
      const createRes = await request(noKeyUrl, 'POST', '/v1/secrets', {
        headers: admin,
        body: { purpose: 'p', name: 'n', plaintext: 'x' },
      });
      assert.equal(createRes.status, 503);
      assert.equal(createRes.json.error, 'encryption_not_configured');
    } finally {
      noKeyServer?.close();
      process.env.ASTRANULL_SECRET_ENCRYPTION_KEY = TEST_ENC_KEY_B64;
    }
  });
});