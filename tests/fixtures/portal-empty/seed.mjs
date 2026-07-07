/**
 * Freshly provisioned tenant with zero portal entities (docs/ux/17 §2).
 */
import { CHECK_CATALOG } from '../../../src/contracts/checks.mjs';
import { resetStoreForTests } from '../../../src/store.mjs';

export const PORTAL_EMPTY_IDS = Object.freeze({
  tenantId: 'ten_portal_empty',
  environmentId: 'env_empty',
});

export function buildPortalEmptyStore() {
  const ids = PORTAL_EMPTY_IDS;
  return {
    tenants: [{ id: ids.tenantId, name: 'Portal Empty Tenant' }],
    environments: [{ id: ids.environmentId, tenant_id: ids.tenantId, name: 'Empty' }],
    users: [],
    targetGroups: [],
    targets: [],
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
    evidenceBundles: [],
    productionReleaseEvidence: [],
    ingestedEventIds: {},
    notificationRules: [],
    notificationEvents: [],
    metrics: null,
    readiness: {},
    auditLog: [],
    checkCatalog: CHECK_CATALOG.map((c) => ({ ...c })),
    encryptedSecrets: [],
    agentUpdateReleases: [],
    agentUpdateStatuses: [],
    agentUpdateTrustKeys: [],
  };
}

export function seedPortalEmpty() {
  process.env.ASTRANULL_NO_PERSIST = '1';
  return resetStoreForTests(buildPortalEmptyStore());
}