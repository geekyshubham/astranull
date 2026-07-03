import { audit } from '../audit.mjs';
import {
  formatNotificationProviderCredential,
  matchesProviderCredentialBinding,
  normalizeNotificationProviderCredentialInput,
  NOTIFICATION_PROVIDER_SECRET_PURPOSE,
  providerCredentialMetadata,
} from '../lib/notificationProviderCredentials.mjs';
import * as secretVault from './secretVault.mjs';

function resolveSecretVault(deps = {}) {
  return deps.secretVault ?? secretVault;
}

async function findExistingCredential(ctx, channel, providerId, secretVaultSvc) {
  const items = await secretVaultSvc.listEncryptedSecrets(ctx);
  return items.find(
    (record) => matchesProviderCredentialBinding(record, channel, providerId),
  ) ?? null;
}

function assertNotificationProviderSecret(ctx, secretRecord, credentialId) {
  if (!secretRecord) return { error: 'not_found', status: 404, message: 'Provider credential not found.' };
  if (secretRecord.purpose !== NOTIFICATION_PROVIDER_SECRET_PURPOSE) {
    return {
      error: 'invalid_credential',
      status: 400,
      message: 'credential_id is not a notification provider credential.',
    };
  }
  if (credentialId && secretRecord.id !== credentialId) {
    return { error: 'not_found', status: 404, message: 'Provider credential not found.' };
  }
  return { ok: true, secret: secretRecord };
}

export async function upsertNotificationProviderCredential(ctx, body, encryptionKey, deps = {}) {
  const normalized = normalizeNotificationProviderCredentialInput(body);
  if (!normalized.ok) return normalized;

  const secretVaultSvc = resolveSecretVault(deps);
  const metadata = providerCredentialMetadata(
    normalized.channel,
    normalized.provider_id,
    normalized.webhook_url_hash,
  );

  let target = null;
  if (normalized.credential_id) {
    const items = await secretVaultSvc.listEncryptedSecrets(ctx);
    const existing = items.find((record) => record.id === normalized.credential_id);
    const guard = assertNotificationProviderSecret(ctx, existing, normalized.credential_id);
    if (!guard.ok) return guard;
    target = guard.secret;
    if (target.metadata?.channel && target.metadata.channel !== normalized.channel) {
      return {
        error: 'channel_mismatch',
        status: 400,
        message: 'channel does not match the existing provider credential.',
      };
    }
  } else {
    target = await findExistingCredential(ctx, normalized.channel, normalized.provider_id, secretVaultSvc);
  }

  if (target) {
    const rotateResult = await secretVaultSvc.rotateEncryptedSecret(
      ctx,
      target.id,
      {
        plaintext: normalized.plaintext,
        metadata,
      },
      encryptionKey,
    );
    if (!rotateResult) {
      return { error: 'not_found', status: 404, message: 'Provider credential not found.' };
    }
    if (rotateResult.error) return rotateResult;

    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'notification.provider_credential_rotated',
      resource_type: 'notification_provider_credential',
      resource_id: rotateResult.id,
      metadata: {
        channel: normalized.channel,
        provider_id: normalized.provider_id,
        rotation: rotateResult.rotation ?? 0,
        encrypted_secret_ref: rotateResult.id,
        ...(normalized.webhook_url_hash ? { webhook_url_hash: normalized.webhook_url_hash } : {}),
      },
    });

    return {
      rotated: true,
      provider_credential: formatNotificationProviderCredential(rotateResult),
    };
  }

  const storeResult = await secretVaultSvc.storeEncryptedSecret(
    ctx,
    {
      purpose: NOTIFICATION_PROVIDER_SECRET_PURPOSE,
      name: `${normalized.channel}:${normalized.provider_id}`,
      plaintext: normalized.plaintext,
      metadata,
    },
    encryptionKey,
  );
  if (storeResult.error) return storeResult;

  const record = storeResult.secret;
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'notification.provider_credential_stored',
    resource_type: 'notification_provider_credential',
    resource_id: record.id,
    metadata: {
      channel: normalized.channel,
      provider_id: normalized.provider_id,
      rotation: record.rotation ?? 0,
      encrypted_secret_ref: record.id,
      ...(normalized.webhook_url_hash ? { webhook_url_hash: normalized.webhook_url_hash } : {}),
    },
  });

  return {
    rotated: false,
    provider_credential: formatNotificationProviderCredential(record),
  };
}