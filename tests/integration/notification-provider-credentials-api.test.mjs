import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { after, afterEach, before, describe, it } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { getStore } from '../../src/store.mjs';
import { demoHeaders, request } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';

const TEST_ENC_KEY_B64 = randomBytes(32).toString('base64');
const PLAINTEXT_CREATE = 'provider-secret-create-value';
const PLAINTEXT_ROTATE = 'provider-secret-rotate-value';
const WEBHOOK_URL = 'https://hooks.example.invalid/services/T000/B000/XXXXXXXX';
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
  assert.ok(!blob.includes(WEBHOOK_URL));
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

describe('notification provider credentials API', () => {
  it('stores webhook credentials with webhook_url_hash and encrypted_secret_ref', async () => {
    freshStore();
    const admin = demoHeaders('admin');
    const created = await request(baseUrl, 'POST', '/v1/notifications/provider-credentials', {
      headers: admin,
      body: {
        channel: 'webhook',
        provider_id: 'primary',
        plaintext: PLAINTEXT_CREATE,
        webhook_url: WEBHOOK_URL,
      },
    });
    assert.equal(created.status, 201);
    assert.equal(created.json.provider_credential.channel, 'webhook');
    assert.equal(created.json.provider_credential.provider_id, 'primary');
    assert.equal(created.json.provider_credential.rotation, 0);
    assert.ok(created.json.provider_credential.webhook_url_hash);
    assert.equal(
      created.json.provider_credential.encrypted_secret_ref,
      created.json.provider_credential.id,
    );
    assertNoSecretLeak(created.json, PLAINTEXT_CREATE);

    const stored = getStore().encryptedSecrets.find(
      (s) => s.id === created.json.provider_credential.id,
    );
    assert.ok(stored);
    assert.equal(stored.purpose, 'notification_provider');
    assert.equal(stored.metadata.channel, 'webhook');
    assert.equal(stored.metadata.webhook_url_hash, created.json.provider_credential.webhook_url_hash);

    const audits = getStore().auditLog.filter(
      (e) => e.action === 'notification.provider_credential_stored',
    );
    assert.equal(audits.length, 1);
    assert.equal(audits[0].metadata.encrypted_secret_ref, created.json.provider_credential.id);
  });

  it('rotates credentials by channel/provider_id and by explicit credential_id', async () => {
    freshStore();
    const admin = demoHeaders('admin');
    const created = await request(baseUrl, 'POST', '/v1/notifications/provider-credentials', {
      headers: admin,
      body: {
        channel: 'slack',
        provider_id: 'default',
        plaintext: PLAINTEXT_CREATE,
      },
    });
    assert.equal(created.status, 201);
    const credentialId = created.json.provider_credential.id;

    const rotated = await request(baseUrl, 'POST', '/v1/notifications/provider-credentials', {
      headers: admin,
      body: {
        channel: 'slack',
        provider_id: 'default',
        plaintext: PLAINTEXT_ROTATE,
      },
    });
    assert.equal(rotated.status, 200);
    assert.equal(rotated.json.provider_credential.rotation, 1);
    assert.equal(rotated.json.provider_credential.id, credentialId);
    assertNoSecretLeak(rotated.json, PLAINTEXT_ROTATE, PLAINTEXT_CREATE);

    const explicit = await request(baseUrl, 'POST', '/v1/notifications/provider-credentials', {
      headers: admin,
      body: {
        channel: 'slack',
        provider_id: 'default',
        credential_id: credentialId,
        plaintext: 'provider-secret-explicit-rotate',
      },
    });
    assert.equal(explicit.status, 200);
    assert.equal(explicit.json.provider_credential.rotation, 2);

    const rotateAudits = getStore().auditLog.filter(
      (e) => e.action === 'notification.provider_credential_rotated',
    );
    assert.equal(rotateAudits.length, 2);
  });

  it('rejects plaintext leaks, invalid channels, and cross-tenant rotation', async () => {
    freshStore();
    const admin = demoHeaders('admin');
    const created = await request(baseUrl, 'POST', '/v1/notifications/provider-credentials', {
      headers: admin,
      body: {
        channel: 'email',
        plaintext: PLAINTEXT_CREATE,
      },
    });
    assert.equal(created.status, 201);
    const credentialId = created.json.provider_credential.id;

    const badChannel = await request(baseUrl, 'POST', '/v1/notifications/provider-credentials', {
      headers: admin,
      body: { channel: 'sms', plaintext: 'x' },
    });
    assert.equal(badChannel.status, 400);
    assert.equal(badChannel.json.error, 'invalid_channel');

    const missingWebhook = await request(baseUrl, 'POST', '/v1/notifications/provider-credentials', {
      headers: admin,
      body: { channel: 'webhook', plaintext: 'x' },
    });
    assert.equal(missingWebhook.status, 400);
    assert.equal(missingWebhook.json.error, 'missing_webhook_url');

    const otherRotate = await request(baseUrl, 'POST', '/v1/notifications/provider-credentials', {
      headers: demoHeaders('admin', 'ten_other'),
      body: {
        channel: 'email',
        credential_id: credentialId,
        plaintext: PLAINTEXT_ROTATE,
      },
    });
    assert.equal(otherRotate.status, 404);
    assert.equal(otherRotate.json.error, 'not_found');
  });

  it('enforces notification:write RBAC', async () => {
    const engineer = demoHeaders('engineer');
    const res = await request(baseUrl, 'POST', '/v1/notifications/provider-credentials', {
      headers: engineer,
      body: { channel: 'teams', plaintext: 'nope' },
    });
    assert.equal(res.status, 403);
    assert.equal(res.json.permission, 'notification:write');
  });
});