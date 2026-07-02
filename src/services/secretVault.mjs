import { audit } from '../audit.mjs';
import {
  buildSecretAad,
  decryptSecret,
  encryptSecret,
  toRedactedSecretRecord,
} from '../lib/secrets.mjs';
import { newId } from '../lib/ids.mjs';
import { redactObject } from '../lib/redact.mjs';
import { getStore, persistStore } from '../store.mjs';

export function storeEncryptedSecret(ctx, body, key) {
  const purpose = String(body.purpose ?? '').trim();
  const name = String(body.name ?? '').trim();
  const plaintext = body.plaintext;
  if (!purpose || !name) {
    return { error: 'invalid_request', status: 400, message: 'purpose and name are required.' };
  }
  if (plaintext === undefined || plaintext === null || String(plaintext).length === 0) {
    return { error: 'invalid_request', status: 400, message: 'plaintext is required.' };
  }
  if (!key) {
    return { error: 'encryption_not_configured', status: 503, message: 'Secret encryption key is not configured.' };
  }

  const id = newId('secret');
  const now = new Date().toISOString();
  const record = {
    id,
    tenant_id: ctx.tenantId,
    purpose,
    name,
    metadata:
      body.metadata && typeof body.metadata === 'object' ? redactObject(body.metadata) : {},
    rotation: 0,
    envelope: null,
    created_at: now,
    updated_at: now,
    created_by: ctx.userId,
  };
  record.envelope = encryptSecret(plaintext, key, buildSecretAad(record));

  getStore().encryptedSecrets.push(record);
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'secret.stored',
    resource_type: 'encrypted_secret',
    resource_id: id,
    metadata: { purpose, name, rotation: 0 },
  });
  persistStore();
  return { secret: toRedactedSecretRecord(record) };
}

export function listEncryptedSecrets(ctx) {
  return getStore()
    .encryptedSecrets.filter((s) => s.tenant_id === ctx.tenantId)
    .map(toRedactedSecretRecord);
}

export function rotateEncryptedSecret(ctx, id, body, key) {
  if (!key) {
    return { error: 'encryption_not_configured', status: 503, message: 'Secret encryption key is not configured.' };
  }
  const store = getStore();
  const record = store.encryptedSecrets.find((s) => s.id === id && s.tenant_id === ctx.tenantId);
  if (!record) return null;

  const plaintext = body.plaintext;
  if (plaintext === undefined || plaintext === null || String(plaintext).length === 0) {
    return { error: 'invalid_request', status: 400, message: 'plaintext is required.' };
  }

  const nextRotation = (record.rotation ?? 0) + 1;
  if (body.metadata && typeof body.metadata === 'object') {
    record.metadata = redactObject(body.metadata);
  }
  record.rotation = nextRotation;
  record.updated_at = new Date().toISOString();
  record.envelope = encryptSecret(plaintext, key, buildSecretAad(record));

  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'secret.rotated',
    resource_type: 'encrypted_secret',
    resource_id: id,
    metadata: { purpose: record.purpose, name: record.name, rotation: nextRotation },
  });
  persistStore();
  return toRedactedSecretRecord(record);
}

export function decryptEncryptedSecretForUse(ctx, id, key) {
  if (!key) {
    return { error: 'encryption_not_configured', status: 503, message: 'Secret encryption key is not configured.' };
  }
  const store = getStore();
  const record = store.encryptedSecrets.find((s) => s.id === id && s.tenant_id === ctx.tenantId);
  if (!record) return null;

  const plaintext = decryptSecret(record.envelope, key, buildSecretAad(record));
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'secret.decrypted_for_use',
    resource_type: 'encrypted_secret',
    resource_id: id,
    metadata: { purpose: record.purpose, name: record.name, rotation: record.rotation ?? 0 },
  });
  persistStore();
  return { plaintext, purpose: record.purpose, name: record.name, rotation: record.rotation ?? 0 };
}