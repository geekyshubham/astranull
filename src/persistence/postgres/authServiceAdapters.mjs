import { randomBytes } from 'node:crypto';
import { createAddressedSecret, parseAddressedSecret } from '../../lib/addressedSecrets.mjs';
import { generateSalt, hashSecretWithSalt, verifySecretWithSalt } from '../../lib/crypto.mjs';
import { newId } from '../../lib/ids.mjs';
import {
  generateServiceAccountSecret,
  redactServiceAccount,
  validateRequestedScopes,
} from '../../lib/serviceAccountPolicy.mjs';

/** @type {readonly string[]} */
export const AUTH_TOKEN_REPOSITORY_METHODS = Object.freeze([
  'createBootstrapToken',
  'listBootstrapTokens',
  'revokeBootstrapToken',
  'findBootstrapTokenByAddressedHint',
  'consumeBootstrapTokenRegistration',
]);

/** @type {readonly string[]} */
export const SERVICE_ACCOUNT_REPOSITORY_METHODS = Object.freeze([
  'createServiceAccount',
  'listServiceAccounts',
  'getServiceAccountById',
  'revokeServiceAccount',
  'findServiceAccountByAddressedHint',
  'rotateServiceAccountSecret',
  'recordServiceAccountLastUsed',
]);

/** @type {readonly string[]} */
export const POSTGRES_AUTH_TOKEN_SERVICE_METHODS = Object.freeze([
  'createBootstrapToken',
  'listBootstrapTokens',
  'revokeBootstrapToken',
  'consumeBootstrapToken',
]);

/** @type {readonly string[]} */
export const POSTGRES_SERVICE_ACCOUNT_SERVICE_METHODS = Object.freeze([
  'createServiceAccount',
  'listServiceAccounts',
  'revokeServiceAccount',
  'rotateServiceAccount',
  'authenticateServiceAccountBearer',
  'auditServiceAccountAuthFailure',
]);

function redactBootstrapToken(record) {
  if (!record) return record;
  const { token_hash, token_salt, ...rest } = record;
  return { ...rest, secret: undefined };
}

function verifyBootstrapTokenRecord(secret, candidate) {
  if (candidate?.token_salt && candidate?.token_hash) {
    return verifySecretWithSalt(secret, candidate.token_salt, candidate.token_hash);
  }
  return false;
}

function verifyServiceAccountRecord(secret, candidate) {
  if (!candidate?.secret_salt || !candidate?.secret_hash) return false;
  return verifySecretWithSalt(secret, candidate.secret_salt, candidate.secret_hash);
}

function assertAuthRepositories(repositories) {
  const authTokens = repositories?.authTokens;
  if (!authTokens || typeof authTokens !== 'object') {
    throw new Error('Postgres auth service adapter requires repositories.authTokens.');
  }
  for (const method of AUTH_TOKEN_REPOSITORY_METHODS) {
    if (typeof authTokens[method] !== 'function') {
      throw new Error(`Postgres auth service adapter requires authTokens.${method}().`);
    }
  }
  for (const method of SERVICE_ACCOUNT_REPOSITORY_METHODS) {
    if (typeof authTokens[method] !== 'function') {
      throw new Error(`Postgres auth service adapter requires authTokens.${method}().`);
    }
  }

  const audit = repositories?.audit;
  if (!audit || typeof audit !== 'object') {
    throw new Error('Postgres auth service adapter requires repositories.audit.');
  }
  if (typeof audit.appendAuditEvent !== 'function') {
    throw new Error('Postgres auth service adapter requires audit.appendAuditEvent().');
  }
}

/**
 * @param {{
 *   authTokens?: Record<string, unknown>,
 *   audit?: { appendAuditEvent?: (...args: unknown[]) => unknown },
 * }} repositories
 * @param {{
 *   now?: () => Date,
 *   newId?: typeof newId,
 *   newServiceAccountId?: () => string,
 * }} [options]
 */
export function createPostgresAuthServices(repositories, options = {}) {
  assertAuthRepositories(repositories);
  const authTokens = repositories.authTokens;
  const audit = repositories.audit;

  const nowFn = options.now ?? (() => new Date());
  const newIdFn = options.newId ?? newId;
  const newServiceAccountIdFn =
    options.newServiceAccountId ?? (() => `sacc_${randomBytes(8).toString('hex')}`);

  async function appendAudit(entry) {
    await audit.appendAuditEvent(entry, { now: nowFn() });
  }

  const tokens = {
    async createBootstrapToken(ctx, body) {
      const id = newIdFn('token');
      const secret = createAddressedSecret('ast_', ctx.tenantId, id);
      const tokenSalt = generateSalt();
      const tokenHash = hashSecretWithSalt(secret, tokenSalt);
      const createdAt = nowFn().toISOString();
      const record = {
        id,
        tenant_id: ctx.tenantId,
        name: body.name ?? 'Install token',
        environment_id: body.environment_id ?? 'env_demo',
        target_group_id: body.target_group_id ?? null,
        token_salt: tokenSalt,
        token_hash: tokenHash,
        max_registrations: body.max_registrations ?? 1,
        registrations_used: 0,
        expires_at: body.expires_at ?? new Date(nowFn().getTime() + 86400000).toISOString(),
        revoked_at: null,
        created_at: createdAt,
        created_by: ctx.userId,
      };
      const token = await authTokens.createBootstrapToken(ctx, record);
      await appendAudit({
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId,
        actor_role: ctx.role,
        action: 'bootstrap_token.created',
        resource_type: 'bootstrap_token',
        resource_id: id,
        metadata: { max_registrations: record.max_registrations },
      });
      return { token, secret };
    },

    async listBootstrapTokens(ctx) {
      const rows = await authTokens.listBootstrapTokens(ctx);
      return rows.map(redactBootstrapToken);
    },

    async revokeBootstrapToken(ctx, id) {
      const revokedAt = nowFn().toISOString();
      const token = await authTokens.revokeBootstrapToken(ctx, id, revokedAt);
      if (!token) return null;
      await appendAudit({
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId,
        actor_role: ctx.role,
        action: 'bootstrap_token.revoked',
        resource_type: 'bootstrap_token',
        resource_id: id,
      });
      return redactBootstrapToken(token);
    },

    async consumeBootstrapToken(secret, agentMeta, tenantIdHint) {
      const hints = parseAddressedSecret(secret, 'ast_');
      if (!hints) {
        return { error: 'invalid_token' };
      }
      const candidate = await authTokens.findBootstrapTokenByAddressedHint(hints);
      if (!candidate || !verifyBootstrapTokenRecord(secret, candidate)) {
        return { error: 'invalid_token' };
      }
      if (tenantIdHint && candidate.tenant_id !== tenantIdHint) {
        return { error: 'invalid_token' };
      }
      if (candidate.revoked_at) {
        return { error: 'revoked' };
      }
      if (new Date(candidate.expires_at) < nowFn()) {
        return { error: 'expired' };
      }
      if (candidate.registrations_used >= candidate.max_registrations) {
        await appendAudit({
          tenant_id: candidate.tenant_id,
          actor_user_id: 'agent',
          actor_role: 'agent',
          action: 'bootstrap_token.replay_rejected',
          resource_type: 'bootstrap_token',
          resource_id: candidate.id,
          metadata: { reason: 'max_registrations' },
        });
        return { error: 'max_registrations' };
      }

      const usedAt = nowFn().toISOString();
      const consumed = await authTokens.consumeBootstrapTokenRegistration(
        { tenantId: candidate.tenant_id, id: candidate.id },
        usedAt,
      );
      if (!consumed) {
        await appendAudit({
          tenant_id: candidate.tenant_id,
          actor_user_id: 'agent',
          actor_role: 'agent',
          action: 'bootstrap_token.replay_rejected',
          resource_type: 'bootstrap_token',
          resource_id: candidate.id,
          metadata: { reason: 'max_registrations' },
        });
        return { error: 'max_registrations' };
      }

      await appendAudit({
        tenant_id: consumed.tenant_id,
        actor_user_id: 'agent',
        actor_role: 'agent',
        action: 'bootstrap_token.used',
        resource_type: 'bootstrap_token',
        resource_id: consumed.id,
        metadata: { hostname: agentMeta?.hostname },
      });
      return { token: consumed };
    },
  };

  const serviceAccounts = {
    async createServiceAccount(ctx, body) {
      const role = String(body.role ?? 'viewer').toLowerCase();
      const scopeCheck = validateRequestedScopes(role, body.scopes ?? []);
      if (scopeCheck.error) {
        return { error: scopeCheck.error, status: 400, message: scopeCheck.message };
      }
      const id = newServiceAccountIdFn();
      const secret = generateServiceAccountSecret(ctx.tenantId, id);
      const secretSalt = generateSalt();
      const secretHash = hashSecretWithSalt(secret, secretSalt);
      const createdAt = nowFn().toISOString();
      const record = {
        id,
        tenant_id: ctx.tenantId,
        name: body.name ?? 'Automation account',
        role,
        scopes: scopeCheck.scopes,
        secret_salt: secretSalt,
        secret_hash: secretHash,
        expires_at: body.expires_at ?? null,
        revoked_at: null,
        created_at: createdAt,
        created_by: ctx.userId,
        last_used_at: null,
      };
      const account = await authTokens.createServiceAccount(ctx, record);
      await appendAudit({
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId,
        actor_role: ctx.role,
        action: 'service_account.created',
        resource_type: 'service_account',
        resource_id: id,
        metadata: { role, scopes: scopeCheck.scopes },
      });
      return { account, secret };
    },

    async listServiceAccounts(ctx) {
      const rows = await authTokens.listServiceAccounts(ctx);
      return rows.map(redactServiceAccount);
    },

    async revokeServiceAccount(ctx, id) {
      const revokedAt = nowFn().toISOString();
      const account = await authTokens.revokeServiceAccount(ctx, id, revokedAt);
      if (!account) return null;
      await appendAudit({
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId,
        actor_role: ctx.role,
        action: 'service_account.revoked',
        resource_type: 'service_account',
        resource_id: id,
      });
      return redactServiceAccount(account);
    },

    async rotateServiceAccount(ctx, id) {
      const account = await authTokens.getServiceAccountById(ctx, id);
      if (!account) return null;
      if (account.revoked_at) {
        return {
          error: 'service_account_revoked',
          status: 409,
          message: 'Revoked service accounts cannot be rotated.',
        };
      }
      const secret = generateServiceAccountSecret(account.tenant_id, account.id);
      const secretSalt = generateSalt();
      const secretHash = hashSecretWithSalt(secret, secretSalt);
      const rotatedAt = nowFn().toISOString();
      const updated = await authTokens.rotateServiceAccountSecret(ctx, id, {
        secret_hash: secretHash,
        secret_salt: secretSalt,
        rotated_at: rotatedAt,
      });
      await appendAudit({
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId,
        actor_role: ctx.role,
        action: 'service_account.rotated',
        resource_type: 'service_account',
        resource_id: id,
        metadata: { role: account.role, scopes: account.scopes },
      });
      return { account: updated, secret };
    },

    async authenticateServiceAccountBearer(secret) {
      if (!secret || !secret.startsWith('svc_')) {
        return { error: 'invalid_token' };
      }
      const hints = parseAddressedSecret(secret, 'svc_');
      if (!hints) {
        return { error: 'invalid_token' };
      }
      const account = await authTokens.findServiceAccountByAddressedHint(hints);
      if (!account || !verifyServiceAccountRecord(secret, account)) {
        return { error: 'invalid_token' };
      }
      if (account.revoked_at) {
        await appendAudit({
          tenant_id: account.tenant_id,
          actor_user_id: `service_account:${account.id}`,
          actor_role: account.role,
          action: 'service_account.auth_failed',
          resource_type: 'service_account',
          resource_id: account.id,
          metadata: { reason: 'revoked' },
        });
        return { error: 'revoked' };
      }
      if (account.expires_at && new Date(account.expires_at) < nowFn()) {
        await appendAudit({
          tenant_id: account.tenant_id,
          actor_user_id: `service_account:${account.id}`,
          actor_role: account.role,
          action: 'service_account.auth_failed',
          resource_type: 'service_account',
          resource_id: account.id,
          metadata: { reason: 'expired' },
        });
        return { error: 'expired' };
      }
      const usedAt = nowFn().toISOString();
      await authTokens.recordServiceAccountLastUsed(
        { tenantId: account.tenant_id, id: account.id },
        usedAt,
      );
      return {
        tenantId: account.tenant_id,
        userId: `service_account:${account.id}`,
        role: account.role,
        scopes: account.scopes,
        serviceAccountId: account.id,
      };
    },

    async auditServiceAccountAuthFailure(bearerSecret) {
      const hints = parseAddressedSecret(bearerSecret, 'svc_');
      if (!hints) return;
      await appendAudit({
        tenant_id: hints.tenantId,
        actor_user_id: `service_account:${hints.id}`,
        actor_role: 'unknown',
        action: 'service_account.auth_failed',
        resource_type: 'service_account',
        resource_id: hints.id,
        metadata: { reason: 'invalid_token' },
      });
    },
  };

  return { tokens, serviceAccounts };
}