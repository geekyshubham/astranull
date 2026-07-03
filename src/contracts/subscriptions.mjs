export const SUBSCRIPTION_PLANS = Object.freeze({
  starter: {
    id: 'starter',
    name: 'Starter',
    limits: {
      users: 5,
      target_groups: 3,
      agents: 10,
      safe_runs_per_hour: 20,
      retention_days: 90,
    },
    feature_entitlements: {
      waf_posture: false,
      external_discovery: false,
      connectors: false,
      high_scale_program: false,
    },
    default_retention: {
      metadata_retention_days: 90,
      report_days: 365,
      audit_log_days: 2555,
      high_scale_artifact_days: 2555,
      legal_hold: false,
    },
  },
  professional: {
    id: 'professional',
    name: 'Professional',
    limits: {
      users: 25,
      target_groups: 15,
      agents: 50,
      safe_runs_per_hour: 60,
      retention_days: 180,
    },
    feature_entitlements: {
      waf_posture: true,
      external_discovery: false,
      connectors: false,
      high_scale_program: true,
    },
    default_retention: {
      metadata_retention_days: 180,
      report_days: 365,
      audit_log_days: 2555,
      high_scale_artifact_days: 2555,
      legal_hold: false,
    },
  },
  enterprise: {
    id: 'enterprise',
    name: 'Enterprise',
    limits: {
      users: 200,
      target_groups: 100,
      agents: 500,
      safe_runs_per_hour: 200,
      retention_days: 365,
    },
    feature_entitlements: {
      waf_posture: true,
      external_discovery: true,
      connectors: true,
      high_scale_program: true,
    },
    default_retention: {
      metadata_retention_days: 365,
      report_days: 365,
      audit_log_days: 2555,
      high_scale_artifact_days: 2555,
      legal_hold: false,
    },
  },
});

export const TENANT_LIFECYCLE_STATES = Object.freeze([
  'active',
  'suspended',
  'provisioning',
  'closed',
]);

export function getSubscriptionPlan(planId) {
  return SUBSCRIPTION_PLANS[planId] ?? null;
}

export function buildDefaultSubscription(planId, tenantId) {
  const plan = getSubscriptionPlan(planId) ?? SUBSCRIPTION_PLANS.starter;
  const now = new Date().toISOString();
  return {
    tenant_id: tenantId,
    plan_id: plan.id,
    status: 'active',
    billing_provider_ref: null,
    effective_at: now,
    renewal_at: null,
    limits: { ...plan.limits },
    feature_entitlements: { ...plan.feature_entitlements },
  };
}

export function buildDefaultEntitlementGrants(planId, tenantId) {
  const plan = getSubscriptionPlan(planId) ?? SUBSCRIPTION_PLANS.starter;
  const now = new Date().toISOString();
  return Object.entries(plan.feature_entitlements).map(([feature, enabled]) => ({
    tenant_id: tenantId,
    feature,
    enabled,
    limit_value: null,
    source: `plan:${plan.id}`,
    created_at: now,
    expires_at: null,
  }));
}

export function mergeEntitlementOverrides(subscription, grants = []) {
  const merged = { ...(subscription?.feature_entitlements ?? {}) };
  for (const grant of grants) {
    if (grant.enabled === false) {
      merged[grant.feature] = false;
    } else {
      merged[grant.feature] = true;
    }
  }
  return merged;
}

export function checkSubscriptionLimit(subscription, grants, metric, currentCount) {
  const plan = getSubscriptionPlan(subscription?.plan_id);
  const entitlements = mergeEntitlementOverrides(subscription, grants);
  const limits = subscription?.limits ?? plan?.limits ?? {};
  const limitKey = metric;
  const max = limits[limitKey];
  if (max == null) return { ok: true };
  if (currentCount >= max) {
    return {
      ok: false,
      error: 'entitlement_limit_exceeded',
      metric: limitKey,
      limit: max,
      current: currentCount,
    };
  }
  return { ok: true, entitlements };
}