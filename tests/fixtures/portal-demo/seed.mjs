/**
 * Full local portal demo fixture — every customer/staff route has list + detail data.
 * Built on portal-baseline, remapped to ten_demo (default dev-headers session).
 */
import { CHECK_CATALOG } from '../../../src/contracts/checks.mjs';
import { validateProductionReleaseEvidence } from '../../../src/contracts/productionReleaseEvidence.mjs';
import {
  buildDefaultEntitlementGrants,
  buildDefaultSubscription,
} from '../../../src/contracts/subscriptions.mjs';
import { buildAuditRecord } from '../../../src/audit.mjs';
import { seedWafProductsIfEmpty } from '../../../src/lib/wafProductCatalog.mjs';
import { PORTAL_BASELINE_IDS, buildPortalBaselineStore } from '../portal-baseline/seed.mjs';
import { applyPortalBaselineReadinessBoost } from '../portal-baseline/readiness.mjs';

export const PORTAL_DEMO_IDS = Object.freeze({
  tenantId: 'ten_demo',
  tenantBId: 'ten_demo_b',
  environmentId: 'env_prod',
  stagingEnvironmentId: 'env_staging',
  targetGroupId: 'tg_checkout',
  targetId: 'tgt_checkout_1',
  findingId: 'fnd_checkout_1',
  agentId: 'agt_edge_01',
  connectorId: 'cn_cf_checkout',
  runId: 'run_checkout_1',
  reportId: 'rpt_checkout_baseline',
  policyId: 'pol_checkout',
  evidenceId: 'art_probe_checkout_1',
  highScaleId: 'hsr_checkout_scheduled',
  signupSubmittedId: 'signup_demo_pending',
  signupApprovedId: 'signup_demo_approved',
  provisionedTenantId: 'ten_northwind',
  frozenAt: PORTAL_BASELINE_IDS.frozenAt,
});

const FROZEN = PORTAL_DEMO_IDS.frozenAt;
const IDS = PORTAL_DEMO_IDS;

function replaceTenantReferences(store, fromTenant, toTenant) {
  const walk = (value) => {
    if (!value || typeof value !== 'object') return;
    if (Array.isArray(value)) {
      for (const item of value) walk(item);
      return;
    }
    if (value.tenant_id === fromTenant) value.tenant_id = toTenant;
    for (const nested of Object.values(value)) walk(nested);
  };
  walk(store);
  for (const tenant of store.tenants) {
    if (tenant.id === fromTenant) tenant.id = toTenant;
  }
}

function replaceTenantBReferences(store, fromTenant, toTenant) {
  const walk = (value) => {
    if (!value || typeof value !== 'object') return;
    if (Array.isArray(value)) {
      for (const item of value) walk(item);
      return;
    }
    if (value.tenant_id === fromTenant) value.tenant_id = toTenant;
    for (const nested of Object.values(value)) walk(nested);
  };
  walk(store);
  for (const tenant of store.tenants) {
    if (tenant.id === fromTenant) tenant.id = toTenant;
  }
}

function pushAuditEntries(store, entries) {
  let prior = store.auditLog.at(-1) ?? null;
  for (const entry of entries) {
    const record = buildAuditRecord(entry, prior, new Date(entry.timestamp ?? FROZEN));
    store.auditLog.push(record);
    prior = record;
  }
}

function buildReleaseEvidenceRecord(kind, evidence, releaseId = 'rel_local_demo_2026') {
  const validation = validateProductionReleaseEvidence(kind, evidence);
  return {
    id: `evidence_demo_${kind}`,
    tenant_id: IDS.tenantId,
    kind,
    release_id: releaseId,
    status: 'accepted',
    evidence,
    notes: 'Seeded for local portal walkthrough.',
    validation,
    created_at: FROZEN,
    created_by: 'usr_admin',
  };
}

function enrichPortalDemoStore(store) {
  const ids = IDS;

  store.tenants = store.tenants.map((tenant) => ({
    ...tenant,
    privacy_settings: tenant.privacy_settings ?? {
      store_packet_payloads: false,
      metadata_retention_days: 180,
      redact_headers_by_default: true,
    },
  }));

  const demoUsers = [
    { id: 'usr_admin', tenant_id: ids.tenantId, email: 'admin@demo.astranull.local', name: 'Demo Admin', role: 'admin' },
    { id: 'usr_owner', tenant_id: ids.tenantId, email: 'owner@demo.astranull.local', name: 'Demo Owner', role: 'owner' },
    { id: 'usr_engineer', tenant_id: ids.tenantId, email: 'engineer@demo.astranull.local', name: 'Demo Engineer', role: 'engineer' },
    { id: 'usr_soc', tenant_id: ids.tenantId, email: 'soc@demo.astranull.local', name: 'Demo SOC', role: 'soc' },
    { id: 'usr_soc2', tenant_id: ids.tenantId, email: 'soc2@demo.astranull.local', name: 'Demo SOC 2', role: 'soc' },
    { id: 'usr_viewer', tenant_id: ids.tenantId, email: 'viewer@demo.astranull.local', name: 'Demo Viewer', role: 'viewer' },
    { id: 'usr_auditor', tenant_id: ids.tenantId, email: 'auditor@demo.astranull.local', name: 'Demo Auditor', role: 'auditor' },
  ];
  store.users = demoUsers;

  store.testPolicies = [
    {
      id: ids.policyId,
      tenant_id: ids.tenantId,
      name: 'Checkout hourly bypass check',
      target_group_id: ids.targetGroupId,
      check_id: 'origin.direct_bypass.safe',
      cadence: 'hourly',
      enabled: true,
      created_at: FROZEN,
      updated_at: FROZEN,
      created_by: 'usr_admin',
    },
    {
      id: 'pol_dns_weekly',
      tenant_id: ids.tenantId,
      name: 'DNS authoritative weekly',
      target_group_id: ids.targetGroupId,
      check_id: 'dns.authoritative_response.safe',
      cadence: 'weekly',
      enabled: true,
      created_at: FROZEN,
      updated_at: FROZEN,
      created_by: 'usr_engineer',
    },
  ];

  store.reports = [
    {
      id: ids.reportId,
      tenant_id: ids.tenantId,
      kind: 'technical',
      title: 'Checkout edge readiness summary',
      status: 'ready',
      summary: {
        readiness_score: 82,
        open_findings: 1,
        recent_runs: [{ id: ids.runId, status: 'completed', check_id: 'origin.direct_bypass.safe' }],
      },
      run_ids: [ids.runId],
      created_at: FROZEN,
      created_by: 'usr_admin',
    },
    {
      id: 'rpt_executive_demo',
      tenant_id: ids.tenantId,
      kind: 'executive',
      title: 'Executive readiness briefing',
      status: 'ready',
      summary: { readiness_score: 82, open_findings: 1 },
      run_ids: [ids.runId],
      created_at: FROZEN,
      created_by: 'usr_owner',
    },
  ];

  store.notificationRules = [
    {
      id: 'nrule_demo_webhook',
      tenant_id: ids.tenantId,
      channel: 'webhook',
      destination: 'https://hooks.demo.astranull.local/v1/alerts',
      triggers: ['finding.opened', 'report.ready'],
      enabled: true,
      created_at: FROZEN,
      created_by: 'usr_admin',
      delivery_note: 'Developer validation — metadata only.',
    },
    {
      id: 'nrule_demo_email',
      tenant_id: ids.tenantId,
      channel: 'email',
      destination: 'soc@demo.astranull.local',
      triggers: ['high_scale.state_change'],
      enabled: true,
      created_at: FROZEN,
      created_by: 'usr_soc',
      delivery_note: 'Developer validation — metadata only.',
    },
  ];

  store.notificationEvents = [
    {
      id: 'nevt_demo_report',
      tenant_id: ids.tenantId,
      trigger: 'report.ready',
      subject: 'Report ready: Checkout edge readiness summary',
      metadata: { report_id: ids.reportId },
      delivery_attempts: [
        {
          id: 'natt_demo_ok',
          status: 'delivered',
          channel: 'webhook',
          attempt_number: 1,
          max_attempts: 3,
          created_at: FROZEN,
        },
      ],
      created_at: FROZEN,
    },
    {
      id: 'nevt_demo_dlq',
      tenant_id: ids.tenantId,
      trigger: 'finding.opened',
      subject: 'Finding opened: Origin direct bypass',
      metadata: { finding_id: ids.findingId },
      delivery_attempts: [
        {
          id: 'natt_demo_dlq',
          status: 'provider_failed_dlq',
          channel: 'webhook',
          reason: 'webhook_http_error',
          attempt_number: 3,
          max_attempts: 3,
          exhausted: true,
          created_at: FROZEN,
        },
      ],
      created_at: FROZEN,
    },
  ];

  store.auditLog = [];
  pushAuditEntries(store, [
    {
      tenant_id: ids.tenantId,
      actor_user_id: 'usr_admin',
      actor_role: 'admin',
      action: 'target_group.created',
      resource_type: 'target_group',
      resource_id: ids.targetGroupId,
      timestamp: FROZEN,
    },
    {
      tenant_id: ids.tenantId,
      actor_user_id: 'usr_engineer',
      actor_role: 'engineer',
      action: 'test_run.started',
      resource_type: 'test_run',
      resource_id: ids.runId,
      timestamp: FROZEN,
    },
    {
      tenant_id: ids.tenantId,
      actor_user_id: 'usr_soc',
      actor_role: 'soc',
      action: 'high_scale.request_created',
      resource_type: 'high_scale_request',
      resource_id: ids.highScaleId,
      timestamp: FROZEN,
    },
    {
      tenant_id: ids.tenantId,
      actor_user_id: 'usr_admin',
      actor_role: 'admin',
      action: 'notification.rule_created',
      resource_type: 'notification_rule',
      resource_id: 'nrule_demo_webhook',
      timestamp: FROZEN,
    },
  ]);

  store.bootstrapTokens = [
    {
      id: 'bt_demo_install',
      tenant_id: ids.tenantId,
      name: 'Edge agent install',
      environment_id: ids.environmentId,
      target_group_id: ids.targetGroupId,
      max_registrations: 5,
      registrations_used: 1,
      expires_at: '2026-12-31T23:59:59.000Z',
      revoked_at: null,
      created_at: FROZEN,
      created_by: 'usr_admin',
      deployment_packaging: 'standalone',
    },
  ];

  store.serviceAccounts = [
    {
      id: 'sacc_demo_ci',
      tenant_id: ids.tenantId,
      name: 'CI automation',
      role: 'engineer',
      status: 'active',
      created_at: FROZEN,
      created_by: 'usr_admin',
      last_used_at: FROZEN,
    },
  ];

  store.tenantAccounts = [
    {
      tenant_id: ids.tenantId,
      legal_name: 'Demo Organization',
      support_owner: 'ops@demo.astranull.local',
      region: 'us',
      lifecycle_state: 'active',
      contract_reference: 'DEMO-CONTRACT-001',
      created_at: FROZEN,
    },
    {
      tenant_id: ids.provisionedTenantId,
      legal_name: 'Northwind Defense',
      support_owner: 'staff_admin',
      region: 'us',
      lifecycle_state: 'active',
      contract_reference: 'NW-2026-014',
      created_at: FROZEN,
    },
  ];

  store.tenantSubscriptions = [
    buildDefaultSubscription('enterprise', ids.tenantId),
    buildDefaultSubscription('professional', ids.provisionedTenantId),
  ];

  store.entitlementGrants = [
    ...buildDefaultEntitlementGrants('enterprise', ids.tenantId),
    ...buildDefaultEntitlementGrants('professional', ids.provisionedTenantId),
  ];

  store.signupRequests = [
    {
      id: ids.signupSubmittedId,
      organization_name: 'Aurora Payments',
      contact_email: 'security@aurora.example',
      contact_name: 'Jamie Chen',
      email_domain: 'aurora.example',
      requested_plan: 'professional',
      intended_use: 'DDoS readiness validation for declared payment origins.',
      region: 'us',
      high_scale_interest: true,
      state: 'submitted',
      reviewer_staff_id: null,
      decision_reason: null,
      customer_notice: null,
      provisioned_tenant_id: null,
      created_at: FROZEN,
      updated_at: FROZEN,
      decided_at: null,
    },
    {
      id: ids.signupApprovedId,
      organization_name: 'Northwind Defense',
      contact_email: 'ops@northwind.example',
      contact_name: 'Alex Morgan',
      email_domain: 'northwind.example',
      requested_plan: 'professional',
      intended_use: 'Defensive validation for declared production origins.',
      region: 'us',
      high_scale_interest: true,
      state: 'customer_invited',
      reviewer_staff_id: 'staff_admin',
      decision_reason: 'Verified organization',
      customer_notice: 'Your workspace is ready.',
      provisioned_tenant_id: ids.provisionedTenantId,
      created_at: FROZEN,
      updated_at: FROZEN,
      decided_at: FROZEN,
    },
  ];

  store.internalAuditLog = [
    {
      id: 'iaud_demo_signup',
      staff_id: 'staff_admin',
      staff_role: 'internal_admin',
      action: 'signup.request_approved',
      resource_type: 'signup_request',
      resource_id: ids.signupApprovedId,
      metadata: { tenant_id: ids.provisionedTenantId },
      created_at: FROZEN,
    },
    {
      id: 'iaud_demo_entitlement',
      staff_id: 'staff_admin',
      staff_role: 'internal_admin',
      action: 'tenant.entitlement_granted',
      resource_type: 'tenant',
      resource_id: ids.provisionedTenantId,
      metadata: { feature: 'safe_validation' },
      created_at: FROZEN,
    },
  ];

  store.highScaleRequests.push(
    {
      id: 'hsr_demo_draft',
      tenant_id: ids.tenantId,
      target_group_id: ids.targetGroupId,
      state: 'draft',
      reason: 'Q3 capacity drill',
      objective: 'Q3 capacity drill',
      emergency_contacts: [{ name: 'Ops', contact: 'ops@demo.astranull.local' }],
      scope_confirmation: false,
      created_at: FROZEN,
      created_by: 'usr_owner',
      audit_trail: [],
      artifacts: [],
    },
    {
      id: 'hsr_demo_approved',
      tenant_id: ids.tenantId,
      target_group_id: ids.targetGroupId,
      state: 'approved',
      reason: 'Approved drill window',
      objective: 'Approved drill window',
      emergency_contacts: [{ name: 'SOC', contact: 'soc@demo.astranull.local' }],
      scope_confirmation: true,
      created_at: FROZEN,
      created_by: 'usr_owner',
      audit_trail: [],
      scope_hash: 'scope_hash_approved_demo',
      soc_approvals: [{ user_id: 'usr_soc', at: FROZEN }, { user_id: 'usr_soc2', at: FROZEN }],
      artifacts: [],
    },
  );

  store.socNotes = [
    {
      id: 'socnote_demo_1',
      tenant_id: ids.tenantId,
      high_scale_request_id: ids.highScaleId,
      author_id: 'usr_soc',
      body: 'Provider window confirmed. Kill switch tested before drill.',
      created_at: FROZEN,
    },
  ];

  store.testRuns.push(
    {
      id: 'run_demo_dns',
      tenant_id: ids.tenantId,
      target_group_id: ids.targetGroupId,
      target_id: 'tgt_checkout_3',
      policy_id: 'pol_dns_weekly',
      check_id: 'dns.authoritative_response.safe',
      status: 'completed',
      verdict: 'pass',
      started_at: FROZEN,
      completed_at: FROZEN,
      created_at: FROZEN,
      agent_id: ids.agentId,
    },
    {
      id: 'run_demo_running',
      tenant_id: ids.tenantId,
      target_group_id: ids.targetGroupId,
      target_id: ids.targetId,
      check_id: 'origin.direct_bypass.safe',
      status: 'running',
      started_at: FROZEN,
      created_at: FROZEN,
      agent_id: ids.agentId,
    },
  );

  store.productionReleaseEvidence = [
    buildReleaseEvidenceRecord('support_readiness', {
      schema_version: 1,
      artifact_type: 'support_on_call_readiness_evidence',
      created_at: FROZEN,
      validation: { ok: true, missing_fields: [], forbidden_fields: [], missing_owner: false },
      readiness_summary: {
        readiness_id: 'support-readiness-demo',
        environment: 'local',
        support_signoff_owner: 'support-lead',
      },
      evidence_uri: 'evidence://support/readiness',
    }),
    buildReleaseEvidenceRecord('vector_safety_policy', {
      schema_version: 1,
      artifact_type: 'vector_safety_policy_evidence',
      created_at: FROZEN,
      validation: { ok: true, missing_fields: [], forbidden_fields: [], missing_owner: false },
      policy_reference: 'policy://vector-safety/demo',
      bounded_rate_ceiling: 'safe_default',
      owner: 'security-lead',
      evidence_uri: 'evidence://vector/safety-policy',
    }),
  ];

  store.cvePipelineItems = [
    {
      id: 'cve_demo_1',
      tenant_id: ids.tenantId,
      cve_id: 'CVE-2026-12345',
      severity: 'high',
      state: 'triaged',
      public_poc_signal: false,
      known_exploited: false,
      created_at: FROZEN,
      updated_at: FROZEN,
    },
  ];

  store.wafDriftEvents = [
    {
      id: 'drift_demo_1',
      tenant_id: ids.tenantId,
      waf_asset_id: 'wa_checkout_1',
      target_id: ids.targetId,
      drift_type: 'rule_removed',
      severity: 'medium',
      observed_at: FROZEN,
      summary: 'Managed rule bundle drift detected on checkout edge.',
    },
  ];

  store.discoveryEntities = [
    {
      id: 'disc_entity_demo_1',
      tenant_id: ids.tenantId,
      source: 'connector:cloudflare',
      kind: 'fqdn',
      value: 'legacy-origin.acme.com',
      confidence: 0.78,
      discovered_at: FROZEN,
      importable: true,
    },
  ];

  store.discoveryCandidates = [
    {
      id: 'disc_cand_demo_1',
      tenant_id: ids.tenantId,
      entity_id: 'disc_entity_demo_1',
      state: 'pending_review',
      suggested_target_group_id: ids.targetGroupId,
      created_at: FROZEN,
    },
  ];

  store.wafActionItems = [
    {
      id: 'wai_demo_1',
      tenant_id: ids.tenantId,
      finding_id: ids.findingId,
      title: 'Tighten origin ACL on checkout edge',
      status: 'open',
      owner_group: 'edge-sre',
      created_at: FROZEN,
    },
  ];

  store.agentUpdateReleases = [
    {
      id: 'aurel_demo_1',
      tenant_id: ids.tenantId,
      version: '0.2.0-demo',
      channel: 'stable',
      status: 'published',
      rollout_percentage: 25,
      created_at: FROZEN,
      created_by: 'usr_admin',
    },
  ];

  store.agentUpdateTrustKeys = [
    {
      id: 'autk_demo_1',
      tenant_id: ids.tenantId,
      name: 'Demo signing key',
      fingerprint_sha256: 'aabbccdd00112233445566778899aabbccdd00112233445566778899aabbccdd',
      status: 'active',
      created_at: FROZEN,
    },
  ];

  store.readiness = {
    [ids.tenantId]: { score: 82, factors: [], updated_at: FROZEN },
  };

  store.checkCatalog = CHECK_CATALOG.map((check) => ({
    ...check,
    default_enabled: ['origin.direct_bypass.safe', 'dns.authoritative_response.safe', 'chk_l7_rate'].includes(check.id),
    cadence: check.id === 'chk_l7_rate' ? 'hourly' : 'daily',
    last_verdict: 'pass',
    last_ran_at: FROZEN,
  }));

  seedWafProductsIfEmpty(store);

  return store;
}

export function buildPortalDemoStore() {
  const store = buildPortalBaselineStore();
  replaceTenantReferences(store, PORTAL_BASELINE_IDS.tenantId, IDS.tenantId);
  replaceTenantBReferences(store, PORTAL_BASELINE_IDS.tenantBId, IDS.tenantBId);
  applyPortalBaselineReadinessBoost(store);
  enrichPortalDemoStore(store);
  return store;
}