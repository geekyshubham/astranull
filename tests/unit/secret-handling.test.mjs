import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { afterEach, describe, it } from 'node:test';
import { loadRuntimeConfig } from '../../src/config.mjs';
import {
  decryptSecret,
  encryptSecret,
  loadSecretEncryptionKey,
  redactSecretEnvelope,
} from '../../src/lib/secrets.mjs';
import {
  decryptEncryptedSecretForUse,
  listEncryptedSecrets,
  rotateEncryptedSecret,
  storeEncryptedSecret,
} from '../../src/services/secretVault.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';

const TEST_ENC_KEY_B64 = randomBytes(32).toString('base64');
const OTHER_ENC_KEY_B64 = randomBytes(32).toString('base64');
const TEST_SESSION_SECRET = 'test-session-secret-at-least-32-chars!!';
const envSnapshot = { ...process.env };

function restoreEnv() {
  for (const key of Object.keys(process.env)) {
    if (!(key in envSnapshot)) delete process.env[key];
  }
  Object.assign(process.env, envSnapshot);
}

function ctx(tenantId = 'ten_demo', userId = 'usr_admin', role = 'admin') {
  return { tenantId, userId, role };
}

function loadKey(b64 = TEST_ENC_KEY_B64) {
  return loadSecretEncryptionKey({ ASTRANULL_SECRET_ENCRYPTION_KEY: b64 });
}

afterEach(() => {
  restoreEnv();
  process.env.ASTRANULL_NO_PERSIST = '1';
});

describe('secret envelope crypto', () => {
  it('encrypts and decrypts with AES-256-GCM envelope fields', () => {
    const key = loadKey();
    const aad = { tenant_id: 'ten_a', purpose: 'webhook', name: 'primary' };
    const envelope = encryptSecret('super-secret-value', key, aad);
    assert.equal(envelope.algorithm, 'AES-256-GCM');
    assert.equal(envelope.version, 1);
    assert.ok(envelope.iv);
    assert.ok(envelope.ciphertext);
    assert.ok(envelope.auth_tag);
    assert.ok(envelope.created_at);
    const plain = decryptSecret(envelope, key, aad);
    assert.equal(plain, 'super-secret-value');
  });

  it('accepts hex-encoded encryption key', () => {
    const hex = randomBytes(32).toString('hex');
    const key = loadSecretEncryptionKey({ ASTRANULL_SECRET_ENCRYPTION_KEY: hex });
    assert.equal(key.length, 32);
  });

  it('rejects invalid key size or encoding', () => {
    assert.throws(
      () => loadSecretEncryptionKey({ ASTRANULL_SECRET_ENCRYPTION_KEY: 'tooshort' }),
      /32-byte key/,
    );
    assert.throws(
      () => loadSecretEncryptionKey({ ASTRANULL_SECRET_ENCRYPTION_KEY: 'a'.repeat(63) }, { required: false }),
      /32-byte key/,
    );
  });

  it('fails decrypt when AAD, key, or auth tag does not match', () => {
    const key = loadKey();
    const aad = { tenant_id: 'ten_a', purpose: 'provider', name: 'api' };
    const envelope = encryptSecret('credential', key, aad);
    assert.throws(() => decryptSecret(envelope, loadKey(OTHER_ENC_KEY_B64), aad));
    assert.throws(() => decryptSecret(envelope, key, { ...aad, tenant_id: 'ten_other' }));
    const tampered = { ...envelope, auth_tag: randomBytes(16).toString('base64') };
    assert.throws(() => decryptSecret(tampered, key, aad));
  });

  it('redacts ciphertext and auth tag from envelope metadata', () => {
    const key = loadKey();
    const envelope = encryptSecret('x', key, { id: 'sec_1' });
    const redacted = redactSecretEnvelope(envelope);
    assert.equal(redacted.ciphertext, undefined);
    assert.equal(redacted.auth_tag, undefined);
    assert.equal(redacted.algorithm, 'AES-256-GCM');
    assert.ok(redacted.iv);
  });
});

describe('encrypted secret vault service', () => {
  it('stores, lists, rotates, and decrypts with tenant isolation', () => {
    freshStore();
    const key = loadKey();
    const stored = storeEncryptedSecret(
      ctx('ten_demo'),
      { purpose: 'webhook', name: 'outbound', plaintext: 'whsec_live_abc', metadata: { env: 'prod' } },
      key,
    );
    assert.ok(stored.secret?.id);
    assert.equal(stored.secret.purpose, 'webhook');
    assert.equal(stored.secret.envelope.ciphertext, undefined);
    assert.equal(stored.secret.envelope.auth_tag, undefined);

    const listed = listEncryptedSecrets(ctx('ten_demo'));
    assert.equal(listed.length, 1);
    assert.equal(listed[0].envelope.ciphertext, undefined);
    assert.equal(listed[0].envelope.auth_tag, undefined);

    const otherList = listEncryptedSecrets(ctx('ten_other'));
    assert.equal(otherList.length, 0);

    const rotated = rotateEncryptedSecret(
      ctx('ten_demo'),
      stored.secret.id,
      { plaintext: 'whsec_live_rotated' },
      key,
    );
    assert.equal(rotated.rotation, 1);
    assert.equal(rotated.envelope.ciphertext, undefined);

    const use = decryptEncryptedSecretForUse(ctx('ten_demo'), stored.secret.id, key);
    assert.equal(use.plaintext, 'whsec_live_rotated');

    assert.equal(decryptEncryptedSecretForUse(ctx('ten_other'), stored.secret.id, key), null);
    assert.equal(rotateEncryptedSecret(ctx('ten_other'), stored.secret.id, { plaintext: 'nope' }, key), null);
  });

  it('redacts secret-like metadata on store and rotate while preserving safe fields', () => {
    freshStore();
    const key = loadKey();
    const sensitiveMeta = {
      env: 'staging',
      api_key: 'ak_live_should_not_persist',
      nested: { password: 'nested-secret-value' },
    };
    const stored = storeEncryptedSecret(
      ctx(),
      {
        purpose: 'integration',
        name: 'provider',
        plaintext: 'plain-value-for-crypto-only',
        metadata: sensitiveMeta,
      },
      key,
    );
    assert.equal(stored.secret.metadata.env, 'staging');
    assert.equal(stored.secret.metadata.api_key, '[REDACTED]');
    assert.equal(stored.secret.metadata.nested.password, '[REDACTED]');

    const inStore = getStore().encryptedSecrets.find((s) => s.id === stored.secret.id);
    assert.equal(inStore.metadata.api_key, '[REDACTED]');
    assert.equal(inStore.metadata.nested.password, '[REDACTED]');

    const listed = listEncryptedSecrets(ctx());
    assert.equal(listed[0].metadata.token, undefined);
    assert.equal(listed[0].metadata.api_key, '[REDACTED]');

    const rotated = rotateEncryptedSecret(
      ctx(),
      stored.secret.id,
      {
        plaintext: 'rotated-plain-only',
        metadata: { env: 'prod', token: 'tok_rotate_me', label: 'primary' },
      },
      key,
    );
    assert.equal(rotated.metadata.env, 'prod');
    assert.equal(rotated.metadata.token, '[REDACTED]');
    assert.equal(rotated.metadata.label, 'primary');
    assert.equal(rotated.metadata.api_key, undefined);
  });

  it('audit metadata for secret lifecycle excludes plaintext and ciphertext', () => {
    freshStore();
    const key = loadKey();
    const plaintext = 'provider_api_key_super_sensitive';
    const stored = storeEncryptedSecret(
      ctx(),
      { purpose: 'integration', name: 'cdn', plaintext },
      key,
    );
    rotateEncryptedSecret(ctx(), stored.secret.id, { plaintext: 'rotated_provider_key' }, key);
    decryptEncryptedSecretForUse(ctx(), stored.secret.id, key);

    const audits = getStore().auditLog.filter((e) => e.action?.startsWith('secret.'));
    assert.equal(audits.length, 3);
    for (const entry of audits) {
      const blob = JSON.stringify(entry.metadata ?? {});
      assert.ok(!blob.includes(plaintext));
      assert.ok(!blob.includes('rotated_provider_key'));
      assert.ok(!blob.includes('ciphertext'));
      assert.ok(!blob.includes('auth_tag'));
    }
  });
});

describe('production secret encryption config', () => {
  it('allows missing encryption key outside production', () => {
    process.env.NODE_ENV = 'test';
    process.env.ASTRANULL_NO_PERSIST = '1';
    delete process.env.ASTRANULL_SECRET_ENCRYPTION_KEY;
    const cfg = loadRuntimeConfig();
    assert.equal(cfg.secretEncryptionConfigured, false);
    assert.equal(cfg.secretEncryptionKey, null);
  });

  it('requires valid encryption key in production', () => {
    process.env.NODE_ENV = 'production';
    process.env.ASTRANULL_AUTH_MODE = 'oidc-jwt';
    process.env.ASTRANULL_OIDC_ISSUER = 'https://idp.example';
    process.env.ASTRANULL_OIDC_AUDIENCE = 'astranull-api';
    process.env.ASTRANULL_OIDC_JWKS_URL = 'https://idp.example/jwks';
    process.env.ASTRANULL_PERSISTENCE_MODE = 'postgres';
    process.env.ASTRANULL_DATABASE_URL = 'postgres://user:pass@localhost/astranull';
    process.env.ASTRANULL_PROBE_WORKER_SECRET = 'p'.repeat(32);
    delete process.env.ASTRANULL_SECRET_ENCRYPTION_KEY;
    assert.throws(() => loadRuntimeConfig(), /ASTRANULL_SECRET_ENCRYPTION_KEY/);

    process.env.ASTRANULL_SECRET_ENCRYPTION_KEY = 'not-a-valid-key';
    assert.throws(() => loadRuntimeConfig(), /32-byte key/);

    process.env.ASTRANULL_SECRET_ENCRYPTION_KEY = TEST_ENC_KEY_B64;
    const cfg = loadRuntimeConfig();
    assert.equal(cfg.persistenceMode, 'postgres');
    assert.equal(cfg.secretEncryptionConfigured, true);
  });
});
