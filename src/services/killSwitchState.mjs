import { getStore } from '../store.mjs';

/**
 * Returns whether the SOC kill switch blocks activity for the given tenant.
 * Legacy global: active with no tenant_id blocks all tenants.
 * Tenant-scoped: active with tenant_id blocks only that tenant.
 */
export function isKillSwitchActiveForTenant(tenantId) {
  const ks = getStore().socKillSwitch ?? { active: false };
  if (!ks.active) return false;

  if (ks.tenants && typeof ks.tenants === 'object') {
    return Boolean(ks.tenants[tenantId]);
  }

  const scopedTenant = ks.tenant_id ?? null;
  if (scopedTenant == null || scopedTenant === '') {
    return true;
  }
  return scopedTenant === tenantId;
}

export function buildKillSwitchState(ctx, active, reason, extraMetadata = {}) {
  return {
    active,
    reason: reason ?? null,
    updated_at: new Date().toISOString(),
    updated_by: ctx.userId,
    tenant_id: ctx.tenantId ?? null,
    ...extraMetadata,
  };
}