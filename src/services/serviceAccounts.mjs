import { audit } from '../audit.mjs';
import { parseAddressedSecret } from '../lib/addressedSecrets.mjs';
import {
  generateSalt,
  hashSecretWithSalt,
  verifySecretWithSalt,
} from '../lib/crypto.mjs';
import {
  generateServiceAccountSecret,
  permissionsForRole,
  redactServiceAccount,
  validateRequestedScopes,
} from '../lib/serviceAccountPolicy.mjs';
import { getStore, persistStore } from '../store.mjs';
import { randomBytes } from 'node:crypto';

export {
  generateServiceAccountSecret,
  permissionsForRole,
  validateRequestedScopes,
} from '../lib/serviceAccountPolicy.mjs';

function newServiceAccountId() {
  return `sacc_${randomBytes(8).toString('hex')}`;
}

export function createServiceAccount(ctx, body) {
  const role = String(body.role ?? 'viewer').toLowerCase();
  const scopeCheck = validateRequestedScopes(role, body.scopes ?? []);
  if (scopeCheck.error) {
    return { error: scopeCheck.error, status: 400, message: scopeCheck.message };
  }
  const id = newServiceAccountId();
  const secret = generateServiceAccountSecret(ctx.tenantId, id);
  const secretSalt = generateSalt();
  const secretHash = hashSecretWithSalt(secret, secretSalt);
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
    created_at: new Date().toISOString(),
    created_by: ctx.userId,
    last_used_at: null,
  };
  getStore().serviceAccounts.push(record);
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'service_account.created',
    resource_type: 'service_account',
    resource_id: id,
    metadata: { role, scopes: scopeCheck.scopes },
  });
  persistStore();
  return { account: record, secret };
}

export function listServiceAccounts(ctx) {
  return getStore()
    .serviceAccounts.filter((a) => a.tenant_id === ctx.tenantId)
    .map(redactServiceAccount);
}

export function revokeServiceAccount(ctx, id) {
  const store = getStore();
  const account = store.serviceAccounts.find((a) => a.id === id && a.tenant_id === ctx.tenantId);
  if (!account) return null;
  account.revoked_at = new Date().toISOString();
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'service_account.revoked',
    resource_type: 'service_account',
    resource_id: id,
  });
  persistStore();
  return redactServiceAccount(account);
}

export function rotateServiceAccount(ctx, id) {
  const store = getStore();
  const account = store.serviceAccounts.find((a) => a.id === id && a.tenant_id === ctx.tenantId);
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
  account.secret_salt = secretSalt;
  account.secret_hash = secretHash;
  account.rotated_at = new Date().toISOString();
  account.last_used_at = null;
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'service_account.rotated',
    resource_type: 'service_account',
    resource_id: id,
    metadata: { role: account.role, scopes: account.scopes },
  });
  persistStore();
  return { account, secret };
}

function verifyServiceAccountRecord(secret, candidate) {
  if (!candidate?.secret_salt || !candidate?.secret_hash) return false;
  return verifySecretWithSalt(secret, candidate.secret_salt, candidate.secret_hash);
}

function findServiceAccountBySecret(secret) {
  if (!secret || !secret.startsWith('svc_')) return null;
  const store = getStore();
  const hints = parseAddressedSecret(secret, 'svc_');
  if (hints) {
    const candidate = store.serviceAccounts.find(
      (a) => a.id === hints.id && a.tenant_id === hints.tenantId,
    );
    if (candidate && verifyServiceAccountRecord(secret, candidate)) {
      return candidate;
    }
    return null;
  }
  for (const candidate of store.serviceAccounts) {
    if (verifyServiceAccountRecord(secret, candidate)) {
      return candidate;
    }
  }
  return null;
}

export function authenticateServiceAccountBearer(secret) {
  const account = findServiceAccountBySecret(secret);
  if (!account) {
    return { error: 'invalid_token' };
  }
  if (account.revoked_at) {
    audit({
      tenant_id: account.tenant_id,
      actor_user_id: `service_account:${account.id}`,
      actor_role: account.role,
      action: 'service_account.auth_failed',
      resource_type: 'service_account',
      resource_id: account.id,
      metadata: { reason: 'revoked' },
    });
    persistStore();
    return { error: 'revoked' };
  }
  if (account.expires_at && new Date(account.expires_at) < new Date()) {
    audit({
      tenant_id: account.tenant_id,
      actor_user_id: `service_account:${account.id}`,
      actor_role: account.role,
      action: 'service_account.auth_failed',
      resource_type: 'service_account',
      resource_id: account.id,
      metadata: { reason: 'expired' },
    });
    persistStore();
    return { error: 'expired' };
  }
  account.last_used_at = new Date().toISOString();
  persistStore();
  return {
    tenantId: account.tenant_id,
    userId: `service_account:${account.id}`,
    role: account.role,
    scopes: account.scopes,
    serviceAccountId: account.id,
  };
}

export function auditServiceAccountAuthFailure(bearerSecret) {
  const hints = parseAddressedSecret(bearerSecret, 'svc_');
  if (!hints) return;
  audit({
    tenant_id: hints.tenantId,
    actor_user_id: `service_account:${hints.id}`,
    actor_role: 'unknown',
    action: 'service_account.auth_failed',
    resource_type: 'service_account',
    resource_id: hints.id,
    metadata: { reason: 'invalid_token' },
  });
  persistStore();
}