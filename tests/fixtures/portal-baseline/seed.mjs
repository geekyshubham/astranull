/**
 * Golden baseline fixture for portal revamp tests (docs/ux/17 §2).
 */
import { CHECK_CATALOG } from '../../../src/contracts/checks.mjs';
import { resetStoreForTests } from '../../../src/store.mjs';
import { buildLoaCustodyDigest } from '../../../src/lib/authorizationArtifactLedger.mjs';

export const PORTAL_BASELINE_IDS = Object.freeze({
  tenantId: 'ten_portal_baseline',
  tenantBId: 'ten_portal_baseline_b',
  environmentId: 'env_prod',
  targetGroupId: 'tg_checkout',
  targetId: 'tgt_checkout_1',
  findingId: 'fnd_checkout_1',
  agentId: 'agt_edge_01',
  connectorId: 'cn_cf_checkout',
  loaId: 'loa_checkout_active',
  frozenAt: '2026-07-01T12:00:00.000Z',
});

const FROZEN = PORTAL_BASELINE_IDS.frozenAt;

function verificationHistory(targetId, finalState) {
  const base = [
    {
      id: `tv_${targetId}_pending`,
      tenant_id: PORTAL_BASELINE_IDS.tenantId,
      target_id: targetId,
      state: 'pending',
      source_kind: 'manual_override',
      source_ref: { seeded: true },
      transitioned_at: FROZEN,
      transitioned_by: 'system',
      audit_entry_id: `aud_${targetId}_pending`,
    },
  ];
  if (finalState === 'dns_verified' || finalState === 'agent_verified') {
    base.push({
      id: `tv_${targetId}_dns`,
      tenant_id: PORTAL_BASELINE_IDS.tenantId,
      target_id: targetId,
      state: 'dns_verified',
      source_kind: 'dns_txt',
      source_ref: { dns_challenge_id: `dns_${targetId}` },
      transitioned_at: FROZEN,
      transitioned_by: 'system',
      audit_entry_id: `aud_${targetId}_dns`,
    });
  }
  if (finalState === 'agent_verified') {
    base.push({
      id: `tv_${targetId}_agent`,
      tenant_id: PORTAL_BASELINE_IDS.tenantId,
      target_id: targetId,
      state: 'agent_verified',
      source_kind: 'agent_observation',
      source_ref: {
        agent_id: PORTAL_BASELINE_IDS.agentId,
        observation_id: `obs_${targetId}`,
        correlated_at: FROZEN,
      },
      transitioned_at: FROZEN,
      transitioned_by: 'system',
      audit_entry_id: `aud_${targetId}_agent`,
    });
  }
  return base;
}

export function buildPortalBaselineStore() {
  const ids = PORTAL_BASELINE_IDS;
  const checkoutTargets = [
    { id: 'tgt_checkout_1', value: 'checkout.acme.com', state: 'agent_verified' },
    { id: 'tgt_checkout_2', value: 'pay.acme.com', state: 'agent_verified' },
    { id: 'tgt_checkout_3', value: 'api.acme.com', state: 'dns_verified' },
    { id: 'tgt_checkout_4', value: 'cdn.acme.com', state: 'dns_verified' },
    { id: 'tgt_checkout_5', value: 'static.acme.com', state: 'dns_verified' },
  ];

  const loaScope = {
    targets: ['tgt_checkout_1', 'tgt_checkout_2'],
    excluded: [
      { target_id: 'tgt_checkout_3', reason: 'unverified' },
      { target_id: 'tgt_checkout_4', reason: 'unverified' },
      { target_id: 'tgt_checkout_5', reason: 'unverified' },
    ],
  };
  const loaDigest = buildLoaCustodyDigest({
    tenant_id: ids.tenantId,
    target_group_id: ids.targetGroupId,
    signer_name: 'Alex Owner',
    signer_email: 'alex@acme.com',
    signed_at: FROZEN,
    scope_snapshot: loaScope,
  });

  const inventoryItems = Array.from({ length: 500 }, (_, index) => ({
    kind: index % 3 === 0 ? 'ip' : 'fqdn',
    value: index % 3 === 0 ? `203.0.113.${index % 250}` : `zone-${index}.baseline.test`,
    label: `resource-${index}`,
    resource_ref: `cf:zone:${index}`,
    importable: true,
  }));

  return {
    tenants: [
      { id: ids.tenantId, name: 'Portal Baseline Tenant' },
      { id: ids.tenantBId, name: 'Portal Baseline Tenant B' },
    ],
    environments: [
      { id: ids.environmentId, tenant_id: ids.tenantId, name: 'Production' },
      { id: 'env_staging', tenant_id: ids.tenantId, name: 'Staging' },
    ],
    users: [{ id: 'usr_owner', tenant_id: ids.tenantId, email: 'owner@baseline.local', name: 'Owner', role: 'owner' }],
    targetGroups: [
      {
        id: ids.targetGroupId,
        tenant_id: ids.tenantId,
        environment_id: ids.environmentId,
        name: 'edge-checkout',
        expected_behavior_default: 'cloud_baseline',
      },
      {
        id: 'tg_other',
        tenant_id: ids.tenantBId,
        environment_id: ids.environmentId,
        name: 'other-group',
        expected_behavior_default: 'cloud_baseline',
      },
    ],
    targets: checkoutTargets.map((entry) => ({
      id: entry.id,
      tenant_id: ids.tenantId,
      target_group_id: ids.targetGroupId,
      kind: 'fqdn',
      value: entry.value,
      expected_behavior: 'cloud_baseline',
      verify_state: entry.state,
      eligibility: 'eligible',
      eligibility_reason: null,
      created_at: FROZEN,
      agent_binding:
        entry.state === 'agent_verified'
          ? { agent_id: ids.agentId, bound_at: FROZEN }
          : null,
    })),
    targetVerifications: checkoutTargets.flatMap((entry) => verificationHistory(entry.id, entry.state)),
    dnsChallenges: [
      {
        id: 'dns_pending_1',
        tenant_id: ids.tenantId,
        target_group_id: ids.targetGroupId,
        target_id: 'tgt_checkout_3',
        record_name: '_astranull-challenge.api.acme.com',
        record_value: 'JBSWY3DPEBLW64TMMQQQ',
        ttl_seconds: 60,
        state: 'pending',
        issued_at: FROZEN,
        expires_at: '2026-07-01T12:15:00.000Z',
        audit_entry_id: 'aud_dns_pending',
      },
      {
        id: 'dns_resolved_1',
        tenant_id: ids.tenantId,
        target_group_id: ids.targetGroupId,
        target_id: 'tgt_checkout_4',
        record_name: '_astranull-challenge.cdn.acme.com',
        record_value: 'KRSXG5BAORUWC2LTMUZQ',
        ttl_seconds: 60,
        state: 'resolved',
        issued_at: FROZEN,
        resolved_at: FROZEN,
        expires_at: '2026-07-01T12:15:00.000Z',
        audit_entry_id: 'aud_dns_resolved',
      },
    ],
    loaSignatures: [
      {
        id: ids.loaId,
        tenant_id: ids.tenantId,
        target_group_id: ids.targetGroupId,
        state: 'signed',
        signer_name: 'Alex Owner',
        signer_title: 'CISO',
        signer_email: 'alex@acme.com',
        signed_at: FROZEN,
        expires_at: null,
        emergency_contact: { name: 'Ops', role: 'SRE', phone: '+1', email: 'ops@acme.com' },
        attested: true,
        scope_snapshot: loaScope,
        custody_artifact_id: 'art_loa_checkout',
        custody_digest_sha256: loaDigest,
        audit_entry_id: 'aud_loa_signed',
      },
    ],
    highScaleAuthorizationArtifacts: [
      {
        id: 'art_loa_checkout',
        custody_id: 'cust_loa_checkout',
        tenant_id: ids.tenantId,
        artifact_type: 'loa_signature',
        content_sha256: loaDigest,
        custody_uri: 'custody://art_loa_checkout',
        status: 'sealed',
        created_at: FROZEN,
        created_by: 'usr_owner',
      },
    ],
    testPolicies: [{ id: 'pol_checkout', tenant_id: ids.tenantId, name: 'Checkout policy' }],
    bootstrapTokens: [],
    serviceAccounts: [],
    agents: [
      {
        id: ids.agentId,
        tenant_id: ids.tenantId,
        target_group_id: ids.targetGroupId,
        hostname: 'edge-01.acme',
        name: 'edge-01',
        status: 'healthy',
        bound_at: FROZEN,
        enrolled_at: FROZEN,
      },
    ],
    agentJobs: [],
    probeJobs: [],
    testRuns: [
      {
        id: 'run_checkout_1',
        tenant_id: ids.tenantId,
        target_group_id: ids.targetGroupId,
        target_id: ids.targetId,
        policy_id: 'pol_checkout',
        verdict: 'pass',
        status: 'completed',
        started_at: FROZEN,
        created_at: FROZEN,
        agent_id: ids.agentId,
      },
    ],
    events: [],
    verdicts: [],
    findings: [
      {
        id: ids.findingId,
        tenant_id: ids.tenantId,
        target_group_id: ids.targetGroupId,
        target_id: ids.targetId,
        test_run_id: 'run_checkout_1',
        severity: 's2',
        title: 'Origin direct bypass',
        state: 'open',
        opened_at: FROZEN,
        owner_group: 'edge-sre',
      },
      {
        id: 'fnd_checkout_2',
        tenant_id: ids.tenantId,
        target_group_id: ids.targetGroupId,
        target_id: ids.targetId,
        severity: 's3',
        title: 'Rate limit drift',
        state: 'closed',
        opened_at: FROZEN,
        owner_group: 'edge-sre',
      },
    ],
    reports: [],
    highScaleRequests: [
      {
        id: 'hsr_checkout_scheduled',
        tenant_id: ids.tenantId,
        target_group_id: ids.targetGroupId,
        state: 'scheduled',
        reason: 'SOC drill',
        objective: 'SOC drill',
        emergency_contacts: [],
        scope_confirmation: true,
        created_at: FROZEN,
        created_by: 'usr_owner',
        audit_trail: [],
        scheduled_window: {
          window_start: '2026-07-01T11:00:00.000Z',
          window_end: '2026-07-01T14:00:00.000Z',
          scope_hash: 'scope_hash_checkout',
        },
        scope_hash: 'scope_hash_checkout',
        soc_approvals: [{ user_id: 'soc1', at: FROZEN }, { user_id: 'soc2', at: FROZEN }],
        artifacts: [],
      },
    ],
    highScaleTelemetry: [],
    socKillSwitch: { active: false },
    socNotes: [],
    evidenceVault: [
      {
        id: 'art_probe_checkout_1',
        tenant_id: ids.tenantId,
        test_run_id: 'run_checkout_1',
        label: 'probe_result',
        kind: 'probe_result',
        sha256: 'aabbccdd00112233445566778899aabbccdd00112233445566778899aabb',
        sealed_at: FROZEN,
        size_bytes: 812,
        created_at: FROZEN,
      },
    ],
    evidenceBundles: [
      {
        id: 'bundle_checkout_1',
        tenant_id: ids.tenantId,
        finding_id: ids.findingId,
        test_run_id: 'run_checkout_1',
        sha256: '11a7abc9d4c01112233445566778899aabbccdd00112233445566778899ab',
        sealed_at: FROZEN,
        size_bytes: 4820,
        custody_schema_version: 'astranull.custody.v1',
      },
    ],
    productionReleaseEvidence: [],
    ingestedEventIds: {},
    notificationRules: [],
    notificationEvents: [],
    metrics: null,
    readiness: { score: 82 },
    auditLog: [],
    checkCatalog: CHECK_CATALOG.map((c) => ({
      ...c,
      default_enabled: c.id === 'chk_l7_rate',
      cadence: c.id === 'chk_l7_rate' ? 'hourly' : 'daily',
      last_verdict: 'pass',
      last_ran_at: FROZEN,
    })),
    encryptedSecrets: [],
    agentUpdateReleases: [],
    agentUpdateStatuses: [],
    agentUpdateTrustKeys: [],
    wafAssets: [
      {
        id: 'wa_checkout_1',
        tenant_id: ids.tenantId,
        target_id: ids.targetId,
        target_group_id: ids.targetGroupId,
        vendor: 'cloudflare',
        connector_id: ids.connectorId,
        marker_rules: 12,
        origin_bypass_state: 'not_exposed',
        origin_bypass_checked_at: FROZEN,
        raw_context_yaml: 'asset_id: wa_checkout_1\nvendor: cloudflare\ntarget_id: tgt_checkout_1\n',
      },
    ],
    wafFingerprints: [
      { id: 'wf_checkout_1', waf_asset_id: 'wa_checkout_1', signature: 'cf_managed_v3', score: 0.94 },
    ],
    wafValidationRuns: [
      {
        id: 'wvr_checkout_1',
        waf_asset_id: 'wa_checkout_1',
        verdict: 'pass',
        started_at: FROZEN,
        completed_at: FROZEN,
      },
    ],
    wafPostureSnapshots: [
      {
        id: 'wps_checkout_1',
        waf_asset_id: 'wa_checkout_1',
        state: 'protected',
        posture: 'protected',
        observed_at: FROZEN,
      },
    ],
    wafConnectors: [
      {
        id: ids.connectorId,
        tenant_id: ids.tenantId,
        provider: 'cloudflare',
        name: 'Cloudflare checkout',
        status: 'active',
        account: 'acct_cf_baseline',
        scope: 'Zone:Read',
        last_success_at: FROZEN,
        inventory_cache: { discovered_at: FROZEN, items: inventoryItems },
        config_json: { account: 'acct_cf_baseline', scope: 'Zone:Read' },
        created_at: FROZEN,
        updated_at: FROZEN,
      },
    ],
    wafConnectorSnapshots: [],
    ownershipVerifications: [],
    findingRemediations: [],
    signupQueueEvents: [],
  };
}

export function seedPortalBaseline() {
  process.env.ASTRANULL_NO_PERSIST = '1';
  return resetStoreForTests(buildPortalBaselineStore());
}