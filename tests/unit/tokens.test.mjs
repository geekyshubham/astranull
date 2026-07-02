import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { parseAddressedSecret } from '../../src/lib/addressedSecrets.mjs';
import {
  generateSalt,
  generateTokenSecret,
  hashSecretWithSalt,
} from '../../src/lib/crypto.mjs';
import {
  consumeBootstrapToken,
  createBootstrapToken,
  listBootstrapTokens,
} from '../../src/services/tokens.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';

describe('bootstrap tokens', () => {
  it('returns secret once and redacts on list', () => {
    freshStore();
    const ctx = { tenantId: 'ten_demo', userId: 'u1', role: 'admin' };
    const { secret, token } = createBootstrapToken(ctx, { target_group_id: 'tg_1' });
    assert.ok(secret);
    assert.ok(token.token_hash);
    assert.ok(token.token_salt);
    const listed = listBootstrapTokens(ctx);
    assert.equal(listed.length, 1);
    assert.equal(listed[0].secret, undefined);
    assert.equal(listed[0].token_hash, undefined);
    assert.equal(listed[0].token_salt, undefined);
  });

  it('issues addressed ast_ secrets with tenant and token id hints', () => {
    freshStore();
    const ctx = { tenantId: 'ten_demo', userId: 'u1', role: 'admin' };
    const { secret, token } = createBootstrapToken(ctx, {});
    assert.ok(secret.startsWith('ast_v1.'));
    const hints = parseAddressedSecret(secret, 'ast_');
    assert.deepEqual(hints, { tenantId: 'ten_demo', id: token.id, version: 'v1' });
  });

  it('consumes addressed bootstrap token and enforces tenant hint', () => {
    freshStore();
    const ctx = { tenantId: 'ten_demo', userId: 'u1', role: 'admin' };
    const { secret } = createBootstrapToken(ctx, { max_registrations: 2 });
    const ok = consumeBootstrapToken(secret, { hostname: 'host-a' }, 'ten_demo');
    assert.ok(ok.token);
    const mismatch = consumeBootstrapToken(secret, { hostname: 'host-b' }, 'ten_other');
    assert.deepEqual(mismatch, { error: 'invalid_token' });
  });

  it('still verifies manually seeded legacy opaque bootstrap tokens', () => {
    freshStore();
    const legacySecret = generateTokenSecret();
    const salt = generateSalt();
    const record = {
      id: 'token_legacy',
      tenant_id: 'ten_demo',
      name: 'legacy',
      environment_id: 'env_demo',
      target_group_id: null,
      token_salt: salt,
      token_hash: hashSecretWithSalt(legacySecret, salt),
      max_registrations: 1,
      registrations_used: 0,
      expires_at: new Date(Date.now() + 86400000).toISOString(),
      revoked_at: null,
      created_at: new Date().toISOString(),
      created_by: 'u1',
    };
    getStore().bootstrapTokens.push(record);
    const consumed = consumeBootstrapToken(legacySecret, { hostname: 'legacy-host' });
    assert.ok(consumed.token);
    assert.equal(consumed.token.id, 'token_legacy');
  });
});