import { CHECK_CATALOG } from '../../src/contracts/checks.mjs';
import { resetStoreForTests } from '../../src/store.mjs';

export function freshStore() {
  process.env.ASTRANULL_NO_PERSIST = '1';
  return resetStoreForTests({
    tenants: [{ id: 'ten_demo', name: 'Demo' }],
    environments: [{ id: 'env_demo', tenant_id: 'ten_demo', name: 'Prod' }],
    users: [],
    targetGroups: [
      {
        id: 'tg_1',
        tenant_id: 'ten_demo',
        environment_id: 'env_demo',
        name: 'TG',
        expected_behavior_default: 'must_block_before_origin',
      },
    ],
    targets: [
      {
        id: 'tgt_1',
        tenant_id: 'ten_demo',
        target_group_id: 'tg_1',
        kind: 'fqdn',
        value: 'origin.test',
        expected_behavior: 'must_block_before_origin',
      },
    ],
    testPolicies: [],
    bootstrapTokens: [],
    serviceAccounts: [],
    agents: [],
    agentJobs: [],
    probeJobs: [],
    testRuns: [],
    events: [],
    verdicts: [],
    findings: [],
    reports: [],
    highScaleRequests: [],
    highScaleTelemetry: [],
    socKillSwitch: { active: false },
    socNotes: [],
    evidenceVault: [],
    productionReleaseEvidence: [],
    ingestedEventIds: {},
    notificationRules: [],
    notificationEvents: [],
    metrics: null,
    readiness: {},
    stateRollups: {},
    loaSignatures: [
      {
        id: 'loa_hardening_active',
        tenant_id: 'ten_demo',
        target_group_id: 'tg_1',
        state: 'signed',
        signer_name: 'Hardening Signer',
        signer_email: 'signer@example.invalid',
        signed_at: new Date().toISOString(),
      },
    ],
    auditLog: [],
    checkCatalog: CHECK_CATALOG.map((c) => ({ ...c })),
    encryptedSecrets: [],
    agentUpdateReleases: [],
    agentUpdateStatuses: [],
    agentUpdateTrustKeys: [],
  });
}
