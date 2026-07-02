import { audit } from '../audit.mjs';
import { createAddressedSecret, parseAddressedSecret } from '../lib/addressedSecrets.mjs';
import {
  generateSalt,
  hashSecretWithSalt,
  hashToken,
  safeEqualHex,
  verifySecretWithSalt,
} from '../lib/crypto.mjs';
import { newId } from '../lib/ids.mjs';
import { getStore, persistStore } from '../store.mjs';

export function createBootstrapToken(ctx, body) {
  const id = newId('token');
  const secret = createAddressedSecret('ast_', ctx.tenantId, id);
  const tokenSalt = generateSalt();
  const tokenHash = hashSecretWithSalt(secret, tokenSalt);
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
    expires_at: body.expires_at ?? new Date(Date.now() + 86400000).toISOString(),
    revoked_at: null,
    created_at: new Date().toISOString(),
    created_by: ctx.userId,
  };
  getStore().bootstrapTokens.push(record);
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'bootstrap_token.created',
    resource_type: 'bootstrap_token',
    resource_id: id,
    metadata: { max_registrations: record.max_registrations },
  });
  persistStore();
  return { token: record, secret };
}

export function listBootstrapTokens(ctx) {
  return getStore()
    .bootstrapTokens.filter((t) => t.tenant_id === ctx.tenantId)
    .map(redactToken);
}

function redactToken(t) {
  const { token_hash, token_salt, ...rest } = t;
  return { ...rest, secret: undefined };
}

export function revokeBootstrapToken(ctx, id) {
  const store = getStore();
  const token = store.bootstrapTokens.find((t) => t.id === id && t.tenant_id === ctx.tenantId);
  if (!token) return null;
  token.revoked_at = new Date().toISOString();
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'bootstrap_token.revoked',
    resource_type: 'bootstrap_token',
    resource_id: id,
  });
  persistStore();
  return redactToken(token);
}

function verifyBootstrapTokenRecord(secret, candidate) {
  if (candidate.token_salt && candidate.token_hash) {
    return verifySecretWithSalt(secret, candidate.token_salt, candidate.token_hash);
  }
  if (candidate.token_hash) {
    return safeEqualHex(hashToken(secret), candidate.token_hash);
  }
  return false;
}

function findBootstrapTokenBySecret(secret) {
  const store = getStore();
  const hints = parseAddressedSecret(secret, 'ast_');
  if (hints) {
    const candidate = store.bootstrapTokens.find(
      (t) => t.id === hints.id && t.tenant_id === hints.tenantId,
    );
    if (candidate && verifyBootstrapTokenRecord(secret, candidate)) {
      return candidate;
    }
    return null;
  }
  for (const candidate of store.bootstrapTokens) {
    if (verifyBootstrapTokenRecord(secret, candidate)) {
      return candidate;
    }
  }
  return null;
}

export function consumeBootstrapToken(secret, agentMeta, tenantIdHint) {
  const store = getStore();
  const token = findBootstrapTokenBySecret(secret);
  if (token && tenantIdHint && token.tenant_id !== tenantIdHint) {
    return { error: 'invalid_token' };
  }
  if (!token) return { error: 'invalid_token' };
  if (token.revoked_at) return { error: 'revoked' };
  if (new Date(token.expires_at) < new Date()) return { error: 'expired' };
  if (token.registrations_used >= token.max_registrations) {
    audit({
      tenant_id: token.tenant_id,
      actor_user_id: 'agent',
      actor_role: 'agent',
      action: 'bootstrap_token.replay_rejected',
      resource_type: 'bootstrap_token',
      resource_id: token.id,
      metadata: { reason: 'max_registrations' },
    });
    persistStore();
    return { error: 'max_registrations' };
  }
  token.registrations_used += 1;
  audit({
    tenant_id: token.tenant_id,
    actor_user_id: 'agent',
    actor_role: 'agent',
    action: 'bootstrap_token.used',
    resource_type: 'bootstrap_token',
    resource_id: token.id,
    metadata: { hostname: agentMeta.hostname },
  });
  persistStore();
  return { token };
}