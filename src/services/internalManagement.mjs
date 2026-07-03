import { getStore, persistStore } from '../store.mjs';
import { auditInternal } from './internalAudit.mjs';
import {
  getTenantAccount,
  getTenantSubscription,
  patchTenantSubscription,
  upsertEntitlementGrant,
  upsertTenantAccount,
} from './subscriptions.mjs';
import { listSignupRequests } from './signupIntake.mjs';

export function getInternalOverview() {
  const store = getStore();
  const signupRequests = store.signupRequests ?? [];
  const tenantAccounts = store.tenantAccounts ?? [];
  const approvalRequests = store.internalApprovalRequests ?? [];
  const pendingSignups = signupRequests.filter((r) =>
    ['submitted', 'under_review', 'approved'].includes(r.state),
  ).length;
  const blockedTenants = tenantAccounts.filter((a) => a.lifecycle_state === 'suspended').length;
  const pendingApprovals = approvalRequests.filter((r) =>
    ['submitted', 'under_review'].includes(r.state),
  ).length;
  const highScaleReviews = store.highScaleRequests.filter((r) =>
    ['submitted', 'under_review'].includes(r.state),
  ).length;

  return {
    pending_signups: pendingSignups,
    blocked_tenants: blockedTenants,
    pending_approval_requests: pendingApprovals,
    high_scale_reviews: highScaleReviews,
    tenant_count: store.tenants.length,
  };
}

export function listTenants(query = {}) {
  const store = getStore();
  const q = String(query.q ?? '').trim().toLowerCase();
  let items = store.tenants.map((tenant) => {
    const account = getTenantAccount(tenant.id);
    const subscription = getTenantSubscription(tenant.id);
    const users = store.users.filter((u) => u.tenant_id === tenant.id);
    return {
      tenant_id: tenant.id,
      name: tenant.name,
      created_at: tenant.created_at,
      lifecycle_state: account?.lifecycle_state ?? 'active',
      region: account?.region ?? null,
      plan_id: subscription?.plan_id ?? null,
      subscription_status: subscription?.status ?? null,
      user_count: users.length,
      support_owner: account?.support_owner ?? null,
    };
  });
  if (q) {
    items = items.filter((t) =>
      t.name.toLowerCase().includes(q)
      || t.tenant_id.toLowerCase().includes(q),
    );
  }
  items.sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
  return items;
}

export function getTenantDetail(tenantId) {
  const store = getStore();
  const tenant = store.tenants.find((t) => t.id === tenantId);
  if (!tenant) return null;
  const account = getTenantAccount(tenantId);
  const subscription = getTenantSubscription(tenantId);
  const users = store.users.filter((u) => u.tenant_id === tenantId);
  const recentAudit = store.auditLog
    .filter((a) => a.tenant_id === tenantId)
    .slice(-20)
    .reverse();
  const signup = store.signupRequests.find((r) => r.provisioned_tenant_id === tenantId) ?? null;

  return {
    tenant: {
      id: tenant.id,
      name: tenant.name,
      created_at: tenant.created_at,
      privacy_settings: tenant.privacy_settings,
    },
    account,
    subscription,
    users: users.map((u) => ({
      id: u.id,
      email: u.email,
      name: u.name,
      role: u.role,
      status: u.status ?? 'active',
      invited_at: u.invited_at ?? null,
      disabled_at: u.disabled_at ?? null,
    })),
    signup_request: signup ? { id: signup.id, state: signup.state } : null,
    recent_tenant_audit: recentAudit,
  };
}

export function patchTenant(staffCtx, tenantId, body) {
  const store = getStore();
  const tenant = store.tenants.find((t) => t.id === tenantId);
  if (!tenant) return null;

  if (body.name) tenant.name = String(body.name).trim();
  persistStore();
  const accountPatch = {};
  if (body.legal_name !== undefined) accountPatch.legal_name = body.legal_name;
  if (body.support_owner !== undefined) accountPatch.support_owner = body.support_owner;
  if (body.region !== undefined) accountPatch.region = body.region;
  if (body.lifecycle_state !== undefined) accountPatch.lifecycle_state = body.lifecycle_state;
  if (body.contract_reference !== undefined) accountPatch.contract_reference = body.contract_reference;

  const account = Object.keys(accountPatch).length > 0
    ? upsertTenantAccount(tenantId, accountPatch)
    : getTenantAccount(tenantId);
  if (account?.error) return account;

  auditInternal({
    staff_id: staffCtx.staffId ?? staffCtx.userId,
    staff_role: staffCtx.staffRole ?? staffCtx.role,
    tenant_id: tenantId,
    action: 'staff.tenant.updated',
    resource_type: 'tenant',
    resource_id: tenantId,
    reason: body.reason ?? null,
    metadata: {
      lifecycle_state: account?.lifecycle_state ?? null,
      support_owner: account?.support_owner ?? null,
    },
  });

  return getTenantDetail(tenantId);
}

export function listApprovalRequests(filters = {}) {
  const store = getStore();
  let items = [...store.internalApprovalRequests];
  if (filters.state) items = items.filter((r) => r.state === filters.state);
  if (filters.kind) items = items.filter((r) => r.kind === filters.kind);
  items.sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
  return items;
}

export function decideApprovalRequest(staffCtx, id, body) {
  const store = getStore();
  const record = store.internalApprovalRequests.find((r) => r.id === id);
  if (!record) return null;
  if (!['submitted', 'under_review'].includes(record.state)) {
    return { error: 'approval_not_pending' };
  }
  const decision = String(body?.decision ?? '').trim().toLowerCase();
  if (!['approve', 'reject'].includes(decision)) {
    return { error: 'invalid_decision' };
  }
  record.state = decision === 'approve' ? 'approved' : 'rejected';
  record.decision = decision;
  record.reason = body?.reason ?? null;
  record.reviewer_staff_id = staffCtx.staffId ?? staffCtx.userId;
  record.decided_at = new Date().toISOString();
  record.updated_at = record.decided_at;

  auditInternal({
    staff_id: staffCtx.staffId ?? staffCtx.userId,
    staff_role: staffCtx.staffRole ?? staffCtx.role,
    tenant_id: record.tenant_id ?? null,
    action: `staff.approval.${decision}d`,
    resource_type: 'internal_approval_request',
    resource_id: id,
    reason: record.reason,
    metadata: { kind: record.kind },
  });

  return { request: record };
}

export function resendOwnerInvite(staffCtx, tenantId, body = {}) {
  const store = getStore();
  const userId = body.user_id;
  const user = store.users.find((u) =>
    u.tenant_id === tenantId && (!userId || u.id === userId) && u.role === 'owner',
  );
  if (!user) return null;
  user.status = 'invited';
  user.invited_at = new Date().toISOString();
  user.invite_resent_by = staffCtx.staffId ?? staffCtx.userId;

  auditInternal({
    staff_id: staffCtx.staffId ?? staffCtx.userId,
    staff_role: staffCtx.staffRole ?? staffCtx.role,
    tenant_id: tenantId,
    action: 'staff.user.invite_resent',
    resource_type: 'user',
    resource_id: user.id,
    reason: body.reason ?? null,
    metadata: { email_domain: user.email?.split('@')[1] ?? null },
  });

  return {
    user_id: user.id,
    email: user.email,
    status: user.status,
    invited_at: user.invited_at,
  };
}

export function disableTenantUser(staffCtx, tenantId, userId, body = {}) {
  const store = getStore();
  const user = store.users.find((u) => u.tenant_id === tenantId && u.id === userId);
  if (!user) return null;
  user.status = 'disabled';
  user.disabled_at = new Date().toISOString();
  user.disabled_by = staffCtx.staffId ?? staffCtx.userId;
  user.disabled_reason = body.reason ?? null;

  auditInternal({
    staff_id: staffCtx.staffId ?? staffCtx.userId,
    staff_role: staffCtx.staffRole ?? staffCtx.role,
    tenant_id: tenantId,
    action: 'staff.user.disabled',
    resource_type: 'user',
    resource_id: user.id,
    reason: body.reason ?? null,
  });

  return {
    user_id: user.id,
    status: user.status,
    disabled_at: user.disabled_at,
  };
}

export function listInternalAudit(filters = {}) {
  const store = getStore();
  let items = [...(store.internalAuditLog ?? [])];
  if (filters.tenant_id) items = items.filter((a) => a.tenant_id === filters.tenant_id);
  if (filters.staff_id) items = items.filter((a) => a.staff_id === filters.staff_id);
  if (filters.action) items = items.filter((a) => a.action === filters.action);
  items.sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
  return items.slice(0, filters.limit ?? 100);
}

export {
  listSignupRequests,
  getTenantSubscription,
  patchTenantSubscription,
  upsertEntitlementGrant,
};