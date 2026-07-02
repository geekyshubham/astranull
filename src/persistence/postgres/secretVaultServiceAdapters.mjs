import { newId } from '../../lib/ids.mjs';
import { redactObject } from '../../lib/redact.mjs';
import {
  buildSecretAad,
  decryptSecret,
  encryptSecret,
  toRedactedSecretRecord,
} from '../../lib/secrets.mjs';

/** @type {readonly string[]} */
export const SECRET_VAULT_REPOSITORY_METHODS = Object.freeze([
  'createEncryptedSecret',
  'listEncryptedSecrets',
  'getEncryptedSecretById',
  'updateEncryptedSecret',
]);

/** @type {readonly string[]} */
export const POSTGRES_SECRET_VAULT_SERVICE_METHODS = Object.freeze([
  'storeEncryptedSecret',
  'listEncryptedSecrets',
  'rotateEncryptedSecret',
  'decryptEncryptedSecretForUse',
]);

function assertSecretVaultRepositories(repositories) {
  const secretVault = repositories?.secretVault;
  if (!secretVault || typeof secretVault !== 'object') {
    throw new Error('Postgres secret vault service adapter requires repositories.secretVault.');
  }
  for (const method of SECRET_VAULT_REPOSITORY_METHODS) {
    if (typeof secretVault[method] !== 'function') {
      throw new Error(`Postgres secret vault service adapter requires secretVault.${method}().`);
    }
  }

  const audit = repositories?.audit;
  if (!audit || typeof audit !== 'object') {
    throw new Error('Postgres secret vault service adapter requires repositories.audit.');
  }
  if (typeof audit.appendAuditEvent !== 'function') {
    throw new Error('Postgres secret vault service adapter requires audit.appendAuditEvent().');
  }
}

/**
 * @param {{
 *   secretVault?: Record<string, unknown>,
 *   audit?: { appendAuditEvent?: (...args: unknown[]) => unknown },
 * }} repositories
 * @param {{ now?: () => Date, newId?: typeof newId }} [options]
 */
export function createPostgresSecretVaultServices(repositories, options = {}) {
  assertSecretVaultRepositories(repositories);
  const secretVaultRepo = repositories.secretVault;
  const auditRepo = repositories.audit;
  const nowFn = options.now ?? (() => new Date());
  const newIdFn = options.newId ?? newId;

  return {
    async storeEncryptedSecret(ctx, body, key) {
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
        return {
          error: 'encryption_not_configured',
          status: 503,
          message: 'Secret encryption key is not configured.',
        };
      }

      const id = newIdFn('secret');
      const now = nowFn().toISOString();
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

      const persisted = await secretVaultRepo.createEncryptedSecret(ctx, record);
      await auditRepo.appendAuditEvent({
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId,
        actor_role: ctx.role,
        action: 'secret.stored',
        resource_type: 'encrypted_secret',
        resource_id: id,
        metadata: { purpose, name, rotation: 0 },
      });
      return { secret: toRedactedSecretRecord(persisted) };
    },

    async listEncryptedSecrets(ctx) {
      const rows = await secretVaultRepo.listEncryptedSecrets(ctx);
      return rows.map(toRedactedSecretRecord);
    },

    async rotateEncryptedSecret(ctx, id, body, key) {
      if (!key) {
        return {
          error: 'encryption_not_configured',
          status: 503,
          message: 'Secret encryption key is not configured.',
        };
      }
      const record = await secretVaultRepo.getEncryptedSecretById(ctx, id);
      if (!record) return null;

      const plaintext = body.plaintext;
      if (plaintext === undefined || plaintext === null || String(plaintext).length === 0) {
        return { error: 'invalid_request', status: 400, message: 'plaintext is required.' };
      }

      const nextRotation = (record.rotation ?? 0) + 1;
      const metadata =
        body.metadata && typeof body.metadata === 'object'
          ? redactObject(body.metadata)
          : record.metadata;
      const updated_at = nowFn().toISOString();
      const envelope = encryptSecret(plaintext, key, buildSecretAad({
        ...record,
        rotation: nextRotation,
        metadata,
      }));

      const persisted = await secretVaultRepo.updateEncryptedSecret(ctx, id, {
        metadata,
        rotation: nextRotation,
        envelope,
        updated_at,
      });
      if (!persisted) return null;

      await auditRepo.appendAuditEvent({
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId,
        actor_role: ctx.role,
        action: 'secret.rotated',
        resource_type: 'encrypted_secret',
        resource_id: id,
        metadata: { purpose: record.purpose, name: record.name, rotation: nextRotation },
      });
      return toRedactedSecretRecord(persisted);
    },

    async decryptEncryptedSecretForUse(ctx, id, key) {
      if (!key) {
        return {
          error: 'encryption_not_configured',
          status: 503,
          message: 'Secret encryption key is not configured.',
        };
      }
      const record = await secretVaultRepo.getEncryptedSecretById(ctx, id);
      if (!record) return null;

      const plaintext = decryptSecret(record.envelope, key, buildSecretAad(record));
      await auditRepo.appendAuditEvent({
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId,
        actor_role: ctx.role,
        action: 'secret.decrypted_for_use',
        resource_type: 'encrypted_secret',
        resource_id: id,
        metadata: {
          purpose: record.purpose,
          name: record.name,
          rotation: record.rotation ?? 0,
        },
      });
      return {
        plaintext,
        purpose: record.purpose,
        name: record.name,
        rotation: record.rotation ?? 0,
      };
    },
  };
}