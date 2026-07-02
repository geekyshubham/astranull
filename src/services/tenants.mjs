import { audit } from '../audit.mjs';
import { newId } from '../lib/ids.mjs';
import { DEFAULT_PRIVACY, normalizePrivacySettings } from '../lib/privacySettings.mjs';
import { enforceMetadataRetentionForTenant } from './privacyRetention.mjs';
import { getStore, persistStore } from '../store.mjs';

export function getCurrentTenant(ctx) {
  return getStore().tenants.find((t) => t.id === ctx.tenantId) ?? null;
}

export function patchCurrentTenant(ctx, body) {
  const tenant = getCurrentTenant(ctx);
  if (!tenant) return null;
  if (body.name) tenant.name = body.name;
  const privacyPatched = Boolean(body.privacy_settings);
  if (privacyPatched) {
    tenant.privacy_settings = normalizePrivacySettings({
      ...tenant.privacy_settings,
      ...body.privacy_settings,
    });
  }
  tenant.updated_at = new Date().toISOString();
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'tenant.updated',
    resource_type: 'tenant',
    resource_id: tenant.id,
    metadata: { fields: Object.keys(body) },
  });
  if (privacyPatched) {
    enforceMetadataRetentionForTenant(ctx.tenantId, { userId: ctx.userId, role: ctx.role });
  }
  persistStore();
  return tenant;
}

export function listEnvironments(ctx) {
  return getStore().environments.filter((e) => e.tenant_id === ctx.tenantId && e.status !== 'archived');
}

export function createEnvironment(ctx, body) {
  const id = newId('env');
  const env = {
    id,
    tenant_id: ctx.tenantId,
    name: body.name ?? 'Environment',
    description: body.description ?? '',
    status: 'active',
    privacy_settings: normalizePrivacySettings(body.privacy_settings),
    created_at: new Date().toISOString(),
    created_by: ctx.userId,
  };
  getStore().environments.push(env);
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'environment.created',
    resource_type: 'environment',
    resource_id: id,
  });
  persistStore();
  return env;
}

export function patchEnvironment(ctx, id, body) {
  const env = getStore().environments.find((e) => e.id === id && e.tenant_id === ctx.tenantId);
  if (!env) return null;
  if (body.name) env.name = body.name;
  if (body.description !== undefined) env.description = body.description;
  if (body.status) env.status = body.status;
  if (body.privacy_settings) {
    env.privacy_settings = normalizePrivacySettings({ ...env.privacy_settings, ...body.privacy_settings });
  }
  env.updated_at = new Date().toISOString();
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: body.status === 'archived' ? 'environment.archived' : 'environment.updated',
    resource_type: 'environment',
    resource_id: id,
  });
  persistStore();
  return env;
}

export { DEFAULT_PRIVACY };