import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { CHECK_CATALOG } from './contracts/checks.mjs';
import { normalizePrivacySettings } from './lib/privacySettings.mjs';


function resolveDataDir() {
  const override = process.env.ASTRANULL_DEV_DATA_DIR?.trim();
  if (override) {
    return path.isAbsolute(override) ? override : path.join(process.cwd(), override);
  }
  return path.join(process.cwd(), '.data');
}

function resolveDataFile() {
  return path.join(resolveDataDir(), 'astranull-dev.json');
}

let store = null;

function emptyStore() {
  return {
    tenants: [],
    environments: [],
    users: [],
    targetGroups: [],
    targets: [],
    testPolicies: [],
    bootstrapTokens: [],
    serviceAccounts: [],
    agents: [],
    agentJobs: [],
    ownershipVerifications: [],
    dnsChallenges: [],
    targetVerifications: [],
    loaSignatures: [],
    findingRemediations: [],
    signupQueueEvents: [],
    probeJobs: [],
    testRuns: [],
    events: [],
    verdicts: [],
    findings: [],
    reports: [],
    highScaleRequests: [],
    highScaleAuthorizationArtifacts: [],
    socReports: [],
    socKillSwitch: { active: false, reason: null, updated_at: null },
    socNotes: [],
    highScaleTelemetry: [],
    evidenceVault: [],
    evidenceBundles: [],
    productionReleaseEvidence: [],
    ingestedEventIds: {},
    notificationRules: [],
    notificationEvents: [],
    metrics: null,
    readiness: {},
    stateRollups: {},
    auditLog: [],
    checkCatalog: [],
    encryptedSecrets: [],
    agentUpdateReleases: [],
    agentUpdateStatuses: [],
    agentUpdateTrustKeys: [],
    wafAssets: [],
    wafProducts: [],
    wafScenarioIntakes: [],
    wafFingerprints: [],
    wafValidationRuns: [],
    wafScenarioResults: [],
    wafPostureSnapshots: [],
    wafBaselines: [],
    wafExceptions: [],
    wafDriftEvents: [],
    wafDriftScanResults: [],
    wafCoverageDailyRollups: [],
    wafCoverageSummaries: {},
    externalAssetCandidates: [],
    wafConnectors: [],
    wafConnectorSnapshots: [],
    cvePipelineItems: [],
    cveAssetMatches: [],
    cveMitigationPlaybooks: [],
    wafRuleRecommendations: [],
    discoveryEntities: [],
    discoveryCandidates: [],
    supplyChainRisks: [],
    wafActionItems: [],
    wafOffensiveRequests: [],
    wafOffensiveReports: [],
    supplyChainTickets: [],
    signupRequests: [],
    staffUsers: [],
    tenantAccounts: [],
    tenantSubscriptions: [],
    entitlementGrants: [],
    internalApprovalRequests: [],
    internalAuditLog: [],
  };
}

/** Idempotent dev JSON store upgrades (preserves tenant/demo records). */
export function migrateDevStore(target) {
  let changed = false;
  const baseline = emptyStore();

  for (const [key, value] of Object.entries(baseline)) {
    if (target[key] === undefined) {
      if (Array.isArray(value)) {
        target[key] = [];
      } else if (value !== null && typeof value === 'object') {
        target[key] = { ...value };
      } else {
        target[key] = value;
      }
      changed = true;
    }
  }

  const nextCatalog = CHECK_CATALOG.map((c) => ({ ...c }));
  if (JSON.stringify(target.checkCatalog) !== JSON.stringify(nextCatalog)) {
    target.checkCatalog = nextCatalog;
    changed = true;
  }

  const killSwitch = { active: false, reason: null, updated_at: null, ...target.socKillSwitch };
  if (JSON.stringify(target.socKillSwitch) !== JSON.stringify(killSwitch)) {
    target.socKillSwitch = killSwitch;
    changed = true;
  }

  for (const tenant of target.tenants) {
    const privacy = normalizePrivacySettings(tenant.privacy_settings);
    if (!tenant.privacy_settings || JSON.stringify(tenant.privacy_settings) !== JSON.stringify(privacy)) {
      tenant.privacy_settings = privacy;
      changed = true;
    }
  }

  for (const env of target.environments) {
    if (!env.status) {
      env.status = 'active';
      changed = true;
    }
    const privacy = normalizePrivacySettings(env.privacy_settings);
    if (!env.privacy_settings || JSON.stringify(env.privacy_settings) !== JSON.stringify(privacy)) {
      env.privacy_settings = privacy;
      changed = true;
    }
  }

  return changed;
}

export function getStore() {
  if (!store) {
    store = loadStore();
  }
  return store;
}

export function resetStoreForTests(data) {
  store = data ?? emptyStore();
  return store;
}

/** Clears the in-memory singleton so the next `getStore()` reloads from disk. */
export function clearStoreCacheForTests() {
  store = null;
}

/** Writes dev store JSON without calling `getStore()` (safe during `loadStore`). */
export function writeDevStoreToDisk(target) {
  if (process.env.ASTRANULL_NO_PERSIST === '1') return;
  const dataDir = resolveDataDir();
  const dataFile = resolveDataFile();
  mkdirSync(dataDir, { recursive: true });
  writeFileSync(dataFile, JSON.stringify(target, null, 2), 'utf8');
}

function loadStore() {
  const dataFile = resolveDataFile();
  let loaded = emptyStore();
  if (existsSync(dataFile)) {
    try {
      const raw = readFileSync(dataFile, 'utf8');
      loaded = { ...emptyStore(), ...JSON.parse(raw) };
    } catch {
      loaded = emptyStore();
    }
  }
  const changed = migrateDevStore(loaded);
  if (changed) {
    writeDevStoreToDisk(loaded);
  }
  return loaded;
}

export function persistStore() {
  if (process.env.ASTRANULL_NO_PERSIST === '1') return;
  writeDevStoreToDisk(getStore());
}

export function tenantFilter(items, tenantId) {
  return items.filter((i) => i.tenant_id === tenantId);
}
