import {
  buildDefaultEntitlementGrants,
  buildDefaultSubscription,
  checkSubscriptionLimit,
  getSubscriptionPlan,
  mergeEntitlementOverrides,
  TENANT_LIFECYCLE_STATES,
} from '../contracts/subscriptions.mjs';
import { normalizePrivacySettings } from '../lib/privacySettings.mjs';
import { getStore, persistStore } from '../store.mjs';
import { auditInternal } from './internalAudit.mjs';

function subscriptionForTenant(tenantId) {
  const store = getStore();
  if (!Array.isArray(store.tenantSubscriptions)) return null;
  return store.tenantSubscriptions.find((s) => s.tenant_id === tenantId) ?? null;
}

function grantsForTenant(tenantId) {
  const store = getStore();
  if (!Array.isArray(store.entitlementGrants)) return [];
  return store.entitlementGrants.filter((g) => g.tenant_id === tenantId);
}

export function getTenantSubscription(tenantId) {
  const subscription = subscriptionForTenant(tenantId);
  if (!subscription) return null;
  const grants = grantsForTenant(tenantId);
  return {
    ...subscription,
    effective_entitlements: mergeEntitlementOverrides(subscription, grants),
    entitlement_grants: grants,
  };
}

export function assertTenantEntitlement(tenantId, feature) {
  const subscription = getTenantSubscription(tenantId);
  if (!subscription) return { ok: true };
  if (subscription.status === 'suspended') {
    return { ok: false, error: 'tenant_suspended' };
  }
  if (!subscription.effective_entitlements?.[feature]) {
    return { ok: false, error: 'entitlement_not_granted', feature };
  }
  return { ok: true };
}

export function assertSubscriptionLimit(tenantId, metric, currentCount) {
  const subscription = subscriptionForTenant(tenantId);
  if (!subscription) return { ok: true };
  if (subscription.status === 'suspended') {
    return { ok: false, error: 'tenant_suspended' };
  }
  return checkSubscriptionLimit(subscription, grantsForTenant(tenantId), metric, currentCount);
}

export function createTenantSubscription(tenantId, planId) {
  const store = getStore();
  if (!Array.isArray(store.tenantSubscriptions)) store.tenantSubscriptions = [];
  if (!Array.isArray(store.entitlementGrants)) store.entitlementGrants = [];
  if (subscriptionForTenant(tenantId)) {
    return { error: 'subscription_exists' };
  }
  const subscription = buildDefaultSubscription(planId, tenantId);
  const grants = buildDefaultEntitlementGrants(planId, tenantId);
  store.tenantSubscriptions.push(subscription);
  store.entitlementGrants.push(...grants);
  persistStore();
  return { subscription, grants };
}

export function patchTenantSubscription(staffCtx, tenantId, patch) {
  const store = getStore();
  const subscription = subscriptionForTenant(tenantId);
  if (!subscription) return null;

  const before = { ...subscription };
  if (patch.plan_id) {
    const plan = getSubscriptionPlan(patch.plan_id);
    if (!plan) return { error: 'invalid_plan' };
    subscription.plan_id = plan.id;
    subscription.limits = { ...plan.limits };
    subscription.feature_entitlements = { ...plan.feature_entitlements };
  }
  if (patch.status) subscription.status = String(patch.status);
  if (patch.billing_provider_ref !== undefined) {
    subscription.billing_provider_ref = patch.billing_provider_ref;
  }
  if (patch.effective_at) subscription.effective_at = patch.effective_at;
  if (patch.renewal_at !== undefined) subscription.renewal_at = patch.renewal_at;
  subscription.updated_at = new Date().toISOString();
  persistStore();

  auditInternal({
    staff_id: staffCtx.staffId ?? staffCtx.userId,
    staff_role: staffCtx.staffRole ?? staffCtx.role,
    tenant_id: tenantId,
    action: 'staff.subscription.updated',
    resource_type: 'tenant_subscription',
    resource_id: tenantId,
    reason: patch.reason ?? null,
    metadata: {
      before_plan_id: before.plan_id,
      after_plan_id: subscription.plan_id,
      before_status: before.status,
      after_status: subscription.status,
    },
  });

  return getTenantSubscription(tenantId);
}

export function upsertEntitlementGrant(staffCtx, tenantId, body) {
  const store = getStore();
  const feature = String(body?.feature ?? '').trim();
  if (!feature) return { error: 'invalid_feature' };
  const enabled = body?.enabled !== false;
  const now = new Date().toISOString();
  let grant = store.entitlementGrants.find((g) => g.tenant_id === tenantId && g.feature === feature);
  if (!grant) {
    grant = {
      tenant_id: tenantId,
      feature,
      enabled,
      limit_value: body?.limit_value ?? null,
      source: 'staff_override',
      created_at: now,
      expires_at: body?.expires_at ?? null,
    };
    store.entitlementGrants.push(grant);
  } else {
    grant.enabled = enabled;
    grant.limit_value = body?.limit_value ?? grant.limit_value;
    grant.expires_at = body?.expires_at ?? grant.expires_at;
    grant.updated_at = now;
  }
  persistStore();

  auditInternal({
    staff_id: staffCtx.staffId ?? staffCtx.userId,
    staff_role: staffCtx.staffRole ?? staffCtx.role,
    tenant_id: tenantId,
    action: enabled ? 'staff.entitlement.granted' : 'staff.entitlement.revoked',
    resource_type: 'entitlement_grant',
    resource_id: feature,
    reason: body?.reason ?? null,
    metadata: { feature, enabled },
  });

  return grant;
}

export function getTenantAccount(tenantId) {
  const store = getStore();
  if (!Array.isArray(store.tenantAccounts)) return null;
  return store.tenantAccounts.find((a) => a.tenant_id === tenantId) ?? null;
}

export function upsertTenantAccount(tenantId, patch = {}) {
  const store = getStore();
  if (!Array.isArray(store.tenantAccounts)) store.tenantAccounts = [];
  let account = store.tenantAccounts.find((a) => a.tenant_id === tenantId);
  const now = new Date().toISOString();
  if (!account) {
    account = {
      tenant_id: tenantId,
      legal_name: patch.legal_name ?? null,
      support_owner: patch.support_owner ?? null,
      region: patch.region ?? 'us',
      lifecycle_state: patch.lifecycle_state ?? 'active',
      contract_reference: patch.contract_reference ?? null,
      created_at: now,
    };
    store.tenantAccounts.push(account);
  } else {
    if (patch.legal_name !== undefined) account.legal_name = patch.legal_name;
    if (patch.support_owner !== undefined) account.support_owner = patch.support_owner;
    if (patch.region !== undefined) account.region = patch.region;
    if (patch.lifecycle_state !== undefined) {
      if (!TENANT_LIFECYCLE_STATES.includes(patch.lifecycle_state)) {
        return { error: 'invalid_lifecycle_state' };
      }
      account.lifecycle_state = patch.lifecycle_state;
    }
    if (patch.contract_reference !== undefined) account.contract_reference = patch.contract_reference;
    account.updated_at = now;
  }
  persistStore();
  return account;
}

export function applyPlanRetentionToTenant(tenantId, planId) {
  const store = getStore();
  const tenant = store.tenants.find((t) => t.id === tenantId);
  if (!tenant) return null;
  const plan = getSubscriptionPlan(planId) ?? getSubscriptionPlan('starter');
  tenant.privacy_settings = normalizePrivacySettings({
    ...tenant.privacy_settings,
    metadata_retention_days: plan.default_retention.metadata_retention_days,
    evidence_retention: {
      ...(tenant.privacy_settings?.evidence_retention ?? {}),
      ...plan.default_retention,
    },
  });
  persistStore();
  return tenant;
}