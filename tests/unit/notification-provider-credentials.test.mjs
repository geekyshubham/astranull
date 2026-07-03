import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { afterEach, describe, it } from 'node:test';
import {
  hashWebhookUrl,
  normalizeNotificationProviderCredentialInput,
} from '../../src/lib/notificationProviderCredentials.mjs';
import { upsertNotificationProviderCredential } from '../../src/services/notificationProviderCredentials.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';

const TEST_ENC_KEY = randomBytes(32);
const demoCtx = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };

afterEach(() => {
  freshStore();
});

describe('notification provider credential helpers', () => {
  it('hashes webhook urls and rejects credential-bearing destinations', () => {
    const url = 'https://hooks.example.invalid/services/T000/B000/XXXXXXXX';
    const hash = hashWebhookUrl(url);
    assert.equal(typeof hash, 'string');
    assert.equal(hash.length, 64);

    const bad = normalizeNotificationProviderCredentialInput({
      channel: 'webhook',
      plaintext: 'secret',
      webhook_url: 'https://user:pass@hooks.example.invalid/x',
    });
    assert.equal(bad.error, 'webhook_url_credentials_not_allowed');
  });

  it('requires webhook_url only for webhook channel', () => {
    const slack = normalizeNotificationProviderCredentialInput({
      channel: 'slack',
      plaintext: 'xoxb-123',
    });
    assert.equal(slack.ok, true);
    assert.equal(slack.webhook_url_hash, null);

    const webhook = normalizeNotificationProviderCredentialInput({
      channel: 'webhook',
      plaintext: 'whsec_test',
    });
    assert.equal(webhook.error, 'missing_webhook_url');
  });
});

describe('notification provider credential service', () => {
  it('stores and rotates encrypted secret vault bindings without leaking plaintext', async () => {
    const created = await upsertNotificationProviderCredential(
      demoCtx,
      {
        channel: 'teams',
        provider_id: 'default',
        plaintext: 'teams-secret-one',
      },
      TEST_ENC_KEY,
    );
    assert.equal(created.rotated, false);
    assert.equal(created.provider_credential.rotation, 0);
    assert.equal(created.provider_credential.encrypted_secret_ref, created.provider_credential.id);

    const rotated = await upsertNotificationProviderCredential(
      demoCtx,
      {
        channel: 'teams',
        provider_id: 'default',
        plaintext: 'teams-secret-two',
      },
      TEST_ENC_KEY,
    );
    assert.equal(rotated.rotated, true);
    assert.equal(rotated.provider_credential.rotation, 1);
    assert.equal(rotated.provider_credential.id, created.provider_credential.id);

    const stored = getStore().encryptedSecrets.find((s) => s.id === created.provider_credential.id);
    assert.ok(stored?.envelope?.ciphertext);
    assert.equal(stored.metadata.channel, 'teams');
  });
});