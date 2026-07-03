import { newId } from '../../lib/ids.mjs';
import { normalizePrivacySettings } from '../../lib/privacySettings.mjs';
import {
  canTransitionSignupState,
  customerSafeRejectionReason,
  validateSignupRequestInput,
} from '../../contracts/signupIntake.mjs';
import {
  buildDefaultEntitlementGrants,
  buildDefaultSubscription,
  getSubscriptionPlan,
  mergeEntitlementOverrides,
} from '../../contracts/subscriptions.mjs';

export const INTERNAL_MANAGEMENT_REPOSITORY_METHODS = Object.freeze([
  'createSignupRequest',
  'findActiveSignupByDomainOrOrg',
  'getSignupRequest',
  'listSignupRequests',
  'updateSignupRequest',
  'provisionTenantFromSignup',
  'appendInternalAudit',
  'getInternalOverview',
  'listTenants',
  'getTenantDetail',
  'patchTenant',
  'getTenantSubscription',
  'patchTenantSubscription',
  'upsertEntitlementGrant',
  'updateUserInvite',
  'disableTenantUser',
  'listApprovalRequests',
  'decideApprovalRequest',
  'getApprovalRequest',
  'listInternalAudit',
]);

export const POSTGRES_INTERNAL_MANAGEMENT_SERVICE_METHODS = Object.freeze([
  'createSignupRequest',
  'getSignupRequest',
  'sanitizeSignupForPublic',
  'listSignupRequests',
  'approveSignupRequest',
  'rejectSignupRequest',
  'getInternalOverview',
  'listTenants',
  'getTenantDetail',
  'patchTenant',
  'getTenantSubscription',
  'patchTenantSubscription',
  'upsertEntitlementGrant',
  'resendOwnerInvite',
  'disableTenantUser',
  'listApprovalRequests',
  'decideApprovalRequest',
  'listInternalAudit',
]);

function staffId(ctx) {
  return ctx.staffId ?? ctx.userId;
}

function staffRole(ctx) {
  return ctx.staffRole ?? ctx.role;
}

function auditEntry(ctx, action, patch = {}) {
  return {
    id: newId('internalAudit'),
    staff_id: patch.staff_id ?? staffId(ctx) ?? null,
    staff_role: patch.staff_role ?? staffRole(ctx) ?? null,
    action,
    resource_type: patch.resource_type ?? null,
    resource_id: patch.resource_id ?? null,
    tenant_id: patch.tenant_id ?? null,
    reason: patch.reason ?? null,
    metadata: patch.metadata ?? {},
    created_at: patch.created_at ?? new Date().toISOString(),
  };
}

function sanitizeSignupForPublic(record) {
  return {
    id: record.id,
    organization_name: record.organization_name,
    state: record.state,
    requested_plan: record.requested_plan,
    region: record.region,
    created_at: record.created_at,
    updated_at: record.updated_at,
    customer_notice: record.customer_notice ?? null,
    provisioned_tenant_id: record.state === 'customer_invited' ? record.provisioned_tenant_id : null,
  };
}

function transition(record, toState, patch = {}) {
  if (!canTransitionSignupState(record.state, toState)) {
    return { error: 'invalid_state_transition', from: record.state, to: toState };
  }
  const now = patch.updated_at ?? new Date().toISOString();
  return {
    ...record,
    state: toState,
    updated_at: now,
    reviewer_staff_id: patch.reviewer_staff_id ?? record.reviewer_staff_id,
    decision_reason:
      patch.decision_reason !== undefined ? patch.decision_reason : record.decision_reason,
    customer_notice:
      patch.customer_notice !== undefined ? patch.customer_notice : record.customer_notice,
    provisioned_tenant_id:
      patch.provisioned_tenant_id !== undefined ? patch.provisioned_tenant_id : record.provisioned_tenant_id,
    decided_at:
      ['approved', 'rejected', 'provisioned', 'customer_invited'].includes(toState)
        ? now
        : record.decided_at,
  };
}

function effectiveSubscription(subscription) {
  if (!subscription) return null;
  return {
    ...subscription,
    effective_entitlements: mergeEntitlementOverrides(
      subscription,
      subscription.entitlement_grants ?? [],
    ),
  };
}

export function createPostgresInternalManagementServices(repositories) {
  const repo = repositories?.internalManagement;
  if (!repo || typeof repo !== 'object') {
    throw new Error('Postgres internal management service adapter requires repositories.internalManagement.');
  }
  for (const method of INTERNAL_MANAGEMENT_REPOSITORY_METHODS) {
    if (typeof repo[method] !== 'function') {
      throw new Error(`Postgres internal management service adapter requires internalManagement.${method}().`);
    }
  }

  return {
    sanitizeSignupForPublic,

    async createSignupRequest(body) {
      const validated = validateSignupRequestInput(body);
      if (!validated.ok) return { error: 'validation_failed', fields: validated.errors };
      const duplicate = await repo.findActiveSignupByDomainOrOrg(
        validated.value.email_domain,
        validated.value.organization_name,
      );
      if (duplicate) return { error: 'duplicate_request', existing_id: duplicate.id };
      const now = new Date().toISOString();
      const record = await repo.createSignupRequest({
        id: newId('signup'),
        ...validated.value,
        state: 'submitted',
        reviewer_staff_id: null,
        decision_reason: null,
        customer_notice: null,
        provisioned_tenant_id: null,
        created_at: now,
        updated_at: now,
        decided_at: null,
      });
      await repo.appendInternalAudit(auditEntry({}, 'signup.request_submitted', {
        staff_id: null,
        staff_role: null,
        resource_type: 'signup_request',
        resource_id: record.id,
        metadata: {
          organization_name: record.organization_name,
          email_domain: record.email_domain,
          requested_plan: record.requested_plan,
          region: record.region,
          high_scale_interest: record.high_scale_interest,
        },
      }));
      return { request: sanitizeSignupForPublic(record) };
    },

    async getSignupRequest(id) {
      return repo.getSignupRequest(id);
    },

    async listSignupRequests(filters = {}) {
      return repo.listSignupRequests(filters);
    },

    async approveSignupRequest(ctx, id, body = {}) {
      let record = await repo.getSignupRequest(id);
      if (!record) return null;
      if (record.state === 'submitted') {
        const reviewed = transition(record, 'under_review', { reviewer_staff_id: staffId(ctx) });
        if (reviewed.error) return reviewed;
        record = await repo.updateSignupRequest(id, reviewed);
      }
      const approved = transition(record, 'approved', {
        reviewer_staff_id: staffId(ctx),
        decision_reason: body.reason ?? 'approved',
      });
      if (approved.error) return approved;
      record = await repo.updateSignupRequest(id, approved);
      await repo.appendInternalAudit(auditEntry(ctx, 'signup.request_approved', {
        resource_type: 'signup_request',
        resource_id: id,
        reason: body.reason ?? null,
        metadata: { requested_plan: record.requested_plan },
      }));

      if (body.provision === false) return { request: record };

      const tenantId = newId('tenant');
      const envId = newId('env');
      const ownerUserId = newId('user');
      const now = new Date().toISOString();
      const plan = getSubscriptionPlan(record.requested_plan) ?? getSubscriptionPlan('starter');
      const subscription = buildDefaultSubscription(plan.id, tenantId);
      const grants = buildDefaultEntitlementGrants(plan.id, tenantId);
      const privacy = normalizePrivacySettings({
        store_packet_payloads: false,
        metadata_retention_days: plan.default_retention.metadata_retention_days,
        redact_headers_by_default: true,
        evidence_retention: plan.default_retention,
      });
      await repo.provisionTenantFromSignup({
        tenant: {
          id: tenantId,
          name: record.organization_name,
          privacy_settings: privacy,
          created_at: now,
        },
        environment: {
          id: envId,
          name: 'Production Validation',
          privacy_settings: privacy,
          settings_json: {},
          created_at: now,
        },
        user: {
          id: ownerUserId,
          email: record.contact_email,
          name: record.contact_name,
          role: 'owner',
          status: 'invited',
          invited_at: now,
          created_at: now,
        },
        account: {
          legal_name: record.organization_name,
          support_owner: staffId(ctx),
          region: record.region,
          lifecycle_state: 'active',
          contract_reference: null,
          created_at: now,
        },
        subscription,
        grants,
      });
      await repo.appendInternalAudit(auditEntry(ctx, 'tenant.provisioned_from_signup', {
        tenant_id: tenantId,
        resource_type: 'tenant',
        resource_id: tenantId,
        metadata: {
          signup_request_id: id,
          requested_plan: record.requested_plan,
          owner_user_id: ownerUserId,
        },
      }));
      record = await repo.updateSignupRequest(id, transition(record, 'provisioned', {
        provisioned_tenant_id: tenantId,
      }));
      record = await repo.updateSignupRequest(id, transition(record, 'customer_invited', {
        customer_notice: 'Your AstraNull account is ready. Check your email for login instructions.',
        provisioned_tenant_id: tenantId,
      }));
      return {
        request: record,
        provisioning: {
          tenant_id: tenantId,
          environment_id: envId,
          owner_user_id: ownerUserId,
          owner_invite: { user_id: ownerUserId, email: record.contact_email, status: 'invited' },
        },
      };
    },

    async rejectSignupRequest(ctx, id, body = {}) {
      let record = await repo.getSignupRequest(id);
      if (!record) return null;
      if (record.state === 'submitted') {
        const reviewed = transition(record, 'under_review', { reviewer_staff_id: staffId(ctx) });
        if (reviewed.error) return reviewed;
        record = await repo.updateSignupRequest(id, reviewed);
      }
      const staffReason = String(body.reason ?? '').trim() || 'Request declined during review.';
      const rejected = transition(record, 'rejected', {
        reviewer_staff_id: staffId(ctx),
        decision_reason: staffReason,
        customer_notice: customerSafeRejectionReason(body.customer_notice ?? staffReason),
      });
      if (rejected.error) return rejected;
      record = await repo.updateSignupRequest(id, rejected);
      await repo.appendInternalAudit(auditEntry(ctx, 'signup.request_rejected', {
        resource_type: 'signup_request',
        resource_id: id,
        reason: staffReason,
        metadata: { customer_notice_length: record.customer_notice?.length ?? 0 },
      }));
      return { request: record };
    },

    getInternalOverview: () => repo.getInternalOverview(),
    listTenants: (query) => repo.listTenants(query),
    getTenantDetail: (tenantId) => repo.getTenantDetail(tenantId),

    async patchTenant(ctx, tenantId, body) {
      const detail = await repo.patchTenant(tenantId, body);
      if (!detail) return null;
      await repo.appendInternalAudit(auditEntry(ctx, 'staff.tenant.updated', {
        tenant_id: tenantId,
        resource_type: 'tenant',
        resource_id: tenantId,
        reason: body.reason ?? null,
        metadata: {
          lifecycle_state: detail.account?.lifecycle_state ?? null,
          support_owner: detail.account?.support_owner ?? null,
        },
      }));
      return detail;
    },

    async getTenantSubscription(tenantId) {
      return effectiveSubscription(await repo.getTenantSubscription(tenantId));
    },

    async patchTenantSubscription(ctx, tenantId, patch) {
      const current = await repo.getTenantSubscription(tenantId);
      if (!current) return null;
      const next = { ...current };
      if (patch.plan_id) {
        const plan = getSubscriptionPlan(patch.plan_id);
        if (!plan) return { error: 'invalid_plan' };
        next.plan_id = plan.id;
        next.limits = { ...plan.limits };
        next.feature_entitlements = { ...plan.feature_entitlements };
      }
      if (patch.status) next.status = String(patch.status);
      if (patch.billing_provider_ref !== undefined) next.billing_provider_ref = patch.billing_provider_ref;
      if (patch.effective_at) next.effective_at = patch.effective_at;
      if (patch.renewal_at !== undefined) next.renewal_at = patch.renewal_at;
      const updated = await repo.patchTenantSubscription(tenantId, next);
      await repo.appendInternalAudit(auditEntry(ctx, 'staff.subscription.updated', {
        tenant_id: tenantId,
        resource_type: 'tenant_subscription',
        resource_id: tenantId,
        reason: patch.reason ?? null,
        metadata: {
          before_plan_id: current.plan_id,
          after_plan_id: updated?.plan_id,
          before_status: current.status,
          after_status: updated?.status,
        },
      }));
      return effectiveSubscription(updated);
    },

    async upsertEntitlementGrant(ctx, tenantId, body) {
      const feature = String(body?.feature ?? '').trim();
      if (!feature) return { error: 'invalid_feature' };
      const enabled = body?.enabled !== false;
      const grant = await repo.upsertEntitlementGrant(tenantId, {
        feature,
        enabled,
        limit_value: body?.limit_value ?? null,
        source: 'staff_override',
        expires_at: body?.expires_at ?? null,
      });
      await repo.appendInternalAudit(auditEntry(ctx, enabled ? 'staff.entitlement.granted' : 'staff.entitlement.revoked', {
        tenant_id: tenantId,
        resource_type: 'entitlement_grant',
        resource_id: feature,
        reason: body?.reason ?? null,
        metadata: { feature, enabled },
      }));
      return grant;
    },

    async resendOwnerInvite(ctx, tenantId, body = {}) {
      const invited_at = new Date().toISOString();
      const user = await repo.updateUserInvite(tenantId, body.user_id, { invited_at });
      if (!user) return null;
      await repo.appendInternalAudit(auditEntry(ctx, 'staff.user.invite_resent', {
        tenant_id: tenantId,
        resource_type: 'user',
        resource_id: user.id,
        reason: body.reason ?? null,
        metadata: { email_domain: user.email?.split('@')[1] ?? null },
      }));
      return { user_id: user.id, email: user.email, status: user.status, invited_at };
    },

    async disableTenantUser(ctx, tenantId, userId, body = {}) {
      const disabled_at = new Date().toISOString();
      const user = await repo.disableTenantUser(tenantId, userId, {
        disabled_at,
        disabled_by: staffId(ctx),
        disabled_reason: body.reason ?? null,
      });
      if (!user) return null;
      await repo.appendInternalAudit(auditEntry(ctx, 'staff.user.disabled', {
        tenant_id: tenantId,
        resource_type: 'user',
        resource_id: user.id,
        reason: body.reason ?? null,
      }));
      return { user_id: user.id, status: user.status, disabled_at };
    },

    listApprovalRequests: (filters) => repo.listApprovalRequests(filters),

    async decideApprovalRequest(ctx, id, body) {
      const existing = await repo.getApprovalRequest(id);
      if (!existing) return null;
      if (!['submitted', 'under_review'].includes(existing.state)) return { error: 'approval_not_pending' };
      const decision = String(body?.decision ?? '').trim().toLowerCase();
      if (!['approve', 'reject'].includes(decision)) return { error: 'invalid_decision' };
      const updated = await repo.decideApprovalRequest(id, {
        state: decision === 'approve' ? 'approved' : 'rejected',
        decision,
        reason: body.reason ?? null,
        reviewer_staff_id: staffId(ctx),
        decided_at: new Date().toISOString(),
      });
      await repo.appendInternalAudit(auditEntry(ctx, `staff.approval.${decision}d`, {
        tenant_id: updated.tenant_id ?? null,
        resource_type: 'internal_approval_request',
        resource_id: id,
        reason: updated.reason,
        metadata: { kind: updated.kind },
      }));
      return { request: updated };
    },

    listInternalAudit: (filters) => repo.listInternalAudit(filters),
  };
}
