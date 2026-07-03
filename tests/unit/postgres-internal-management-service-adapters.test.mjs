import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createPostgresInternalManagementServices } from '../../src/persistence/postgres/internalManagementServiceAdapters.mjs';

function createRepo() {
  const repo = {
    signups: [],
    audits: [],
    tenants: [],
    subscriptions: new Map(),
    grants: new Map(),
    async createSignupRequest(record) {
      this.signups.push(record);
      return record;
    },
    async findActiveSignupByDomainOrOrg(domain, org) {
      return this.signups.find((r) =>
        r.state !== 'rejected'
        && (r.email_domain === domain || r.organization_name.toLowerCase() === org.toLowerCase()),
      ) ?? null;
    },
    async getSignupRequest(id) {
      return this.signups.find((r) => r.id === id) ?? null;
    },
    async listSignupRequests() {
      return [...this.signups];
    },
    async updateSignupRequest(id, patch) {
      const idx = this.signups.findIndex((r) => r.id === id);
      if (idx < 0) return null;
      this.signups[idx] = { ...this.signups[idx], ...patch };
      return this.signups[idx];
    },
    async provisionTenantFromSignup(payload) {
      this.tenants.push(payload);
      this.subscriptions.set(payload.tenant.id, payload.subscription);
      this.grants.set(payload.tenant.id, payload.grants);
    },
    async appendInternalAudit(entry) {
      this.audits.push(entry);
      return entry;
    },
    async getInternalOverview() {
      return { pending_signups: this.signups.length, blocked_tenants: 0, pending_approval_requests: 0, high_scale_reviews: 0, tenant_count: this.tenants.length };
    },
    async listTenants() { return []; },
    async getTenantDetail() { return null; },
    async patchTenant() { return null; },
    async getTenantSubscription(tenantId) {
      const sub = this.subscriptions.get(tenantId);
      return sub ? { ...sub, entitlement_grants: this.grants.get(tenantId) ?? [] } : null;
    },
    async patchTenantSubscription(tenantId, sub) {
      this.subscriptions.set(tenantId, sub);
      return { ...sub, entitlement_grants: this.grants.get(tenantId) ?? [] };
    },
    async upsertEntitlementGrant(tenantId, grant) {
      const list = this.grants.get(tenantId) ?? [];
      list.push({ tenant_id: tenantId, ...grant });
      this.grants.set(tenantId, list);
      return { tenant_id: tenantId, ...grant };
    },
    async updateUserInvite() { return null; },
    async disableTenantUser() { return null; },
    async listApprovalRequests() { return []; },
    async decideApprovalRequest() { return null; },
    async getApprovalRequest() { return null; },
    async listInternalAudit() { return this.audits; },
  };
  return repo;
}

const signupPayload = {
  organization_name: 'Northwind Defense',
  contact_email: 'security@northwind.example',
  contact_name: 'Alex Morgan',
  requested_plan: 'professional',
  intended_use: 'Defensive DDoS readiness validation for declared production origins.',
  region: 'us',
  high_scale_interest: true,
};

describe('Postgres internal management service adapter', () => {
  it('creates sanitized public sign-up requests and rejects active duplicates', async () => {
    const repo = createRepo();
    const svc = createPostgresInternalManagementServices({ internalManagement: repo });
    const created = await svc.createSignupRequest(signupPayload);
    assert.equal(created.request.state, 'submitted');
    assert.equal(created.request.contact_email, undefined);
    assert.equal(repo.audits.at(-1).action, 'signup.request_submitted');

    const duplicate = await svc.createSignupRequest(signupPayload);
    assert.equal(duplicate.error, 'duplicate_request');
  });

  it('approves, provisions tenant defaults, and records internal audit', async () => {
    const repo = createRepo();
    const svc = createPostgresInternalManagementServices({ internalManagement: repo });
    const created = await svc.createSignupRequest(signupPayload);
    const approved = await svc.approveSignupRequest(
      { staffId: 'staff_1', staffRole: 'internal_admin' },
      created.request.id,
      { reason: 'Verified organization' },
    );
    assert.equal(approved.request.state, 'customer_invited');
    assert.ok(approved.provisioning.tenant_id);
    assert.equal(repo.tenants[0].subscription.plan_id, 'professional');
    assert.ok(repo.tenants[0].grants.some((g) => g.feature === 'high_scale_program'));
    assert.ok(repo.audits.some((a) => a.action === 'signup.request_approved'));
    assert.ok(repo.audits.some((a) => a.action === 'tenant.provisioned_from_signup'));
  });

  it('patches subscriptions with effective entitlements and audits the change', async () => {
    const repo = createRepo();
    const svc = createPostgresInternalManagementServices({ internalManagement: repo });
    const created = await svc.createSignupRequest(signupPayload);
    const approved = await svc.approveSignupRequest(
      { staffId: 'staff_1', staffRole: 'internal_admin' },
      created.request.id,
      {},
    );
    const tenantId = approved.provisioning.tenant_id;
    const updated = await svc.patchTenantSubscription(
      { staffId: 'staff_1', staffRole: 'billing_ops' },
      tenantId,
      { plan_id: 'enterprise', reason: 'contract upgraded' },
    );
    assert.equal(updated.plan_id, 'enterprise');
    assert.equal(updated.effective_entitlements.high_scale_program, true);
    assert.ok(repo.audits.some((a) => a.action === 'staff.subscription.updated'));
  });
});
