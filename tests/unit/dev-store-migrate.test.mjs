import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { after, describe, it } from 'node:test';
import { CHECK_CATALOG } from '../../src/contracts/checks.mjs';
import { seedIfEmpty } from '../../src/seed.mjs';
import { listChecks } from '../../src/services/testRuns.mjs';
import { createServer } from '../../src/server.mjs';
import { request } from '../helpers/http.mjs';
import {
  clearStoreCacheForTests,
  getStore,
  migrateDevStore,
  resetStoreForTests,
} from '../../src/store.mjs';

describe('dev store migration', () => {
  after(() => {
    delete process.env.ASTRANULL_NO_PERSIST;
    delete process.env.ASTRANULL_DEV_DATA_DIR;
    clearStoreCacheForTests();
  });

  it('upgrades a legacy 4-check catalog without dropping demo records', () => {
    process.env.ASTRANULL_NO_PERSIST = '1';
    const legacyCatalog = CHECK_CATALOG.slice(0, 4).map((c) => ({ ...c }));
    resetStoreForTests({
      tenants: [{ id: 'ten_demo', name: 'Demo Organization' }],
      environments: [{ id: 'env_demo', tenant_id: 'ten_demo', name: 'Production Validation' }],
      users: [{ id: 'usr_admin', tenant_id: 'ten_demo', email: 'admin@demo.astranull.local', role: 'admin' }],
      targetGroups: [
        {
          id: 'tg_demo_origin',
          tenant_id: 'ten_demo',
          environment_id: 'env_demo',
          name: 'Origin Protection Group',
        },
      ],
      targets: [
        {
          id: 'tgt_demo_1',
          tenant_id: 'ten_demo',
          target_group_id: 'tg_demo_origin',
          kind: 'fqdn',
          value: 'origin.demo.customer.example',
        },
      ],
      bootstrapTokens: [],
      agents: [],
      agentJobs: [],
      testRuns: [{ id: 'run_legacy_1', tenant_id: 'ten_demo', status: 'verdicted', check_id: legacyCatalog[0].check_id }],
      events: [],
      verdicts: [],
      findings: [{ id: 'find_legacy_1', tenant_id: 'ten_demo', status: 'open', title: 'Legacy finding' }],
      reports: [{ id: 'rpt_legacy_1', tenant_id: 'ten_demo', title: 'Legacy report' }],
      highScaleRequests: [],
      readiness: { ten_demo: { score: 42, factors: [] } },
      auditLog: [{ id: 'aud_1', tenant_id: 'ten_demo', action: 'tenant.updated' }],
      checkCatalog: legacyCatalog,
    });

    seedIfEmpty();

    const after = getStore();
    assert.equal(after.checkCatalog.length, CHECK_CATALOG.length);
    assert.equal(after.testRuns.length, 1);
    assert.equal(after.findings.length, 1);
    assert.equal(after.reports.length, 1);
    assert.equal(after.auditLog.length, 1);
    assert.equal(after.targetGroups.length, 1);
    assert.deepEqual(after.serviceAccounts, []);
    assert.deepEqual(after.encryptedSecrets, []);
    assert.deepEqual(after.agentUpdateReleases, []);
    assert.deepEqual(after.agentUpdateStatuses, []);
    assert.deepEqual(after.agentUpdateTrustKeys, []);
    assert.deepEqual(after.wafAssets, []);
    assert.deepEqual(after.wafProducts, []);
    assert.deepEqual(after.wafFingerprints, []);
    assert.deepEqual(after.wafValidationRuns, []);
    assert.deepEqual(after.wafScenarioResults, []);
    assert.deepEqual(after.wafPostureSnapshots, []);
    assert.deepEqual(after.wafBaselines, []);
    assert.deepEqual(after.wafDriftEvents, []);
    assert.deepEqual(after.externalAssetCandidates, []);
    assert.deepEqual(after.wafConnectors, []);
    assert.deepEqual(after.wafConnectorSnapshots, []);
    assert.deepEqual(after.cvePipelineItems, []);
    assert.deepEqual(after.cveAssetMatches, []);
    assert.deepEqual(after.wafRuleRecommendations, []);
    assert.deepEqual(after.discoveryEntities, []);
    assert.deepEqual(after.discoveryCandidates, []);
    assert.deepEqual(after.supplyChainRisks, []);
    assert.deepEqual(after.wafActionItems, []);
    assert.deepEqual(after.supplyChainTickets, []);
    assert.equal(listChecks().length, CHECK_CATALOG.length);
    assert.ok(after.tenants[0].privacy_settings?.metadata_retention_days === 365);
  });

  it('persists migrated catalog to disk on load without dropping demo records', () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), 'astranull-dev-store-'));
    const dataFile = path.join(tmpDir, 'astranull-dev.json');
    const legacyCatalog = CHECK_CATALOG.slice(0, 4).map((c) => ({ ...c }));
    const legacyPayload = {
      tenants: [{ id: 'ten_demo', name: 'Demo Organization' }],
      environments: [{ id: 'env_demo', tenant_id: 'ten_demo', name: 'Production Validation' }],
      users: [],
      targetGroups: [],
      targets: [],
      testRuns: [{ id: 'run_legacy_1', tenant_id: 'ten_demo', status: 'verdicted', check_id: legacyCatalog[0].check_id }],
      findings: [{ id: 'find_legacy_1', tenant_id: 'ten_demo', status: 'open', title: 'Legacy finding' }],
      reports: [{ id: 'rpt_legacy_1', tenant_id: 'ten_demo', title: 'Legacy report' }],
      auditLog: [{ id: 'aud_1', tenant_id: 'ten_demo', action: 'tenant.updated' }],
      checkCatalog: legacyCatalog,
    };
    writeFileSync(dataFile, JSON.stringify(legacyPayload), 'utf8');

    delete process.env.ASTRANULL_NO_PERSIST;
    process.env.ASTRANULL_DEV_DATA_DIR = tmpDir;
    clearStoreCacheForTests();

    const loaded = getStore();
    assert.equal(loaded.checkCatalog.length, CHECK_CATALOG.length);
    assert.equal(loaded.testRuns.length, 1);
    assert.equal(loaded.findings.length, 1);

    const onDisk = JSON.parse(readFileSync(dataFile, 'utf8'));
    assert.equal(onDisk.checkCatalog.length, CHECK_CATALOG.length);
    assert.equal(onDisk.testRuns.length, 1);
    assert.equal(onDisk.findings.length, 1);

    rmSync(tmpDir, { recursive: true, force: true });
    delete process.env.ASTRANULL_DEV_DATA_DIR;
    clearStoreCacheForTests();
    process.env.ASTRANULL_NO_PERSIST = '1';
  });

  it('clamps invalid tenant privacy retention days during migration', () => {
    process.env.ASTRANULL_NO_PERSIST = '1';
    resetStoreForTests({
      tenants: [
        { id: 'ten_low', name: 'Low', privacy_settings: { metadata_retention_days: 0 } },
        { id: 'ten_high', name: 'High', privacy_settings: { metadata_retention_days: 5000 } },
        { id: 'ten_bad', name: 'Bad', privacy_settings: { metadata_retention_days: 'nope' } },
      ],
      environments: [],
      users: [],
      targetGroups: [],
      targets: [],
      bootstrapTokens: [],
      agents: [],
      agentJobs: [],
      probeJobs: [],
      testRuns: [],
      events: [],
      verdicts: [],
      findings: [],
      reports: [],
      highScaleRequests: [],
      socKillSwitch: { active: false, reason: null, updated_at: null },
      socNotes: [],
      socReports: [],
      evidenceVault: [],
      productionReleaseEvidence: [],
      ingestedEventIds: {},
      notificationRules: [],
      notificationEvents: [],
      metrics: null,
      readiness: {},
      stateRollups: {},
      auditLog: [],
      checkCatalog: CHECK_CATALOG.map((c) => ({ ...c })),
    });

    assert.equal(migrateDevStore(getStore()), true);
    const tenants = getStore().tenants;
    assert.equal(tenants.find((t) => t.id === 'ten_low').privacy_settings.metadata_retention_days, 1);
    assert.equal(tenants.find((t) => t.id === 'ten_high').privacy_settings.metadata_retention_days, 3650);
    assert.equal(tenants.find((t) => t.id === 'ten_bad').privacy_settings.metadata_retention_days, 365);
  });

  it('migrateDevStore is idempotent on an already-current store', () => {
    process.env.ASTRANULL_NO_PERSIST = '1';
    const full = CHECK_CATALOG.map((c) => ({ ...c }));
    const data = {
      tenants: [{
        id: 'ten_demo',
        name: 'Demo',
        privacy_settings: {
          store_packet_payloads: false,
          metadata_retention_days: 365,
          evidence_retention_days: 1825,
          audit_retention_days: 2555,
          redact_headers_by_default: true,
          evidence_retention: {
            audit_log_days: 2555,
            high_scale_artifact_days: 2555,
            report_days: 365,
            legal_hold: false,
          },
        },
      }],
      environments: [],
      users: [],
      targetGroups: [],
      targets: [],
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
      highScaleTelemetry: [],
      socKillSwitch: { active: false, reason: null, updated_at: null },
      socNotes: [],
      socReports: [],
      evidenceVault: [],
      productionReleaseEvidence: [],
      ingestedEventIds: {},
      notificationRules: [],
      notificationEvents: [],
      metrics: null,
      readiness: {},
      stateRollups: {},
      auditLog: [],
      checkCatalog: full,
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
      supplyChainTickets: [],
      signupRequests: [],
      staffUsers: [],
      tenantAccounts: [],
      tenantSubscriptions: [],
      entitlementGrants: [],
      internalApprovalRequests: [],
      internalAuditLog: [],
      testPolicies: [],
      wafOffensiveRequests: [],
      wafOffensiveReports: [],
      evidenceBundles: [],
    };
    resetStoreForTests(data);
    assert.equal(migrateDevStore(getStore()), false);
    assert.equal(migrateDevStore(getStore()), false);
  });

  it('migrateDevStore adds Wave 1 collections idempotently without dropping data', () => {
    process.env.ASTRANULL_NO_PERSIST = '1';
    const legacy = {
      tenants: [{ id: 'ten_demo', name: 'Demo' }],
      cvePipelineItems: [{ id: 'cve_1', tenant_id: 'ten_demo', cve_id: 'CVE-2026-0001' }],
      discoveryEntities: [{ id: 'ent_1', tenant_id: 'ten_demo', entity_id: 'ent_parent_1' }],
      discoveryCandidates: [{ id: 'cand_1', tenant_id: 'ten_demo', hostname: 'shop.example.com' }],
      supplyChainRisks: [{ id: 'scr_1', tenant_id: 'ten_demo', vendor: 'Acme' }],
      wafActionItems: [{ id: 'wai_1', tenant_id: 'ten_demo', title: 'Tune rule' }],
      supplyChainTickets: [{ id: 'sct_1', tenant_id: 'ten_demo', risk_id: 'scr_1' }],
    };
    resetStoreForTests(legacy);

    assert.equal(migrateDevStore(legacy), true);
    assert.deepEqual(legacy.cvePipelineItems, [{ id: 'cve_1', tenant_id: 'ten_demo', cve_id: 'CVE-2026-0001' }]);
    assert.deepEqual(legacy.discoveryEntities, [{ id: 'ent_1', tenant_id: 'ten_demo', entity_id: 'ent_parent_1' }]);
    assert.deepEqual(legacy.discoveryCandidates, [{ id: 'cand_1', tenant_id: 'ten_demo', hostname: 'shop.example.com' }]);
    assert.deepEqual(legacy.supplyChainRisks, [{ id: 'scr_1', tenant_id: 'ten_demo', vendor: 'Acme' }]);
    assert.deepEqual(legacy.wafActionItems, [{ id: 'wai_1', tenant_id: 'ten_demo', title: 'Tune rule' }]);
    assert.deepEqual(legacy.supplyChainTickets, [{ id: 'sct_1', tenant_id: 'ten_demo', risk_id: 'scr_1' }]);
    assert.deepEqual(legacy.cveAssetMatches, []);
    assert.deepEqual(legacy.externalAssetCandidates, []);

    assert.equal(migrateDevStore(legacy), false);
    assert.equal(legacy.cvePipelineItems.length, 1);
    assert.equal(legacy.discoveryEntities.length, 1);
    assert.equal(legacy.discoveryCandidates.length, 1);
    assert.equal(legacy.supplyChainRisks.length, 1);
    assert.equal(legacy.wafActionItems.length, 1);
    assert.equal(legacy.supplyChainTickets.length, 1);
  });

  it('serves expanded catalog from /v1/checks after legacy store migration', async () => {
    process.env.ASTRANULL_NO_PERSIST = '1';
    const legacyCatalog = CHECK_CATALOG.slice(0, 4).map((c) => ({ ...c }));
    resetStoreForTests({
      tenants: [{ id: 'ten_demo', name: 'Demo' }],
      environments: [{ id: 'env_demo', tenant_id: 'ten_demo', name: 'Prod' }],
      users: [],
      targetGroups: [],
      targets: [],
      bootstrapTokens: [],
      agents: [],
      agentJobs: [],
      testRuns: [],
      events: [],
      verdicts: [],
      findings: [],
      reports: [],
      highScaleRequests: [],
      socKillSwitch: { active: false, reason: null, updated_at: null },
      socNotes: [],
      socReports: [],
      evidenceVault: [],
      ingestedEventIds: {},
      notificationRules: [],
      notificationEvents: [],
      metrics: null,
      readiness: {},
      stateRollups: {},
      auditLog: [],
      checkCatalog: legacyCatalog,
    });

    const server = createServer();
    await new Promise((resolve) => server.listen(0, resolve));
    const { port } = server.address();
    const baseUrl = `http://127.0.0.1:${port}`;
    try {
      const res = await request(baseUrl, 'GET', '/v1/checks');
      assert.equal(res.status, 200);
      assert.equal(res.json.items.length, CHECK_CATALOG.length);
    } finally {
      server.close();
    }
  });
});
