import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { after, describe, it } from 'node:test';
import { CHECK_CATALOG } from '../../src/contracts/checks.mjs';
import {
  DEFAULT_EVIDENCE_RETENTION,
  normalizePrivacySettings,
} from '../../src/lib/privacySettings.mjs';
import {
  PROTECTED_GOVERNANCE_COLLECTIONS,
  buildRetentionPolicySnapshot,
  enforceMetadataRetentionForTenant,
} from '../../src/services/privacyRetention.mjs';
import { patchCurrentTenant } from '../../src/services/tenants.mjs';
import { clearStoreCacheForTests, getStore, resetStoreForTests } from '../../src/store.mjs';

function daysAgo(n) {
  return new Date(Date.now() - n * 24 * 60 * 60 * 1000).toISOString();
}

function baseStore(overrides = {}) {
  return {
    tenants: [
      {
        id: 'ten_demo',
        name: 'Demo',
        privacy_settings: { metadata_retention_days: 30 },
      },
      { id: 'ten_other', name: 'Other', privacy_settings: { metadata_retention_days: 30 } },
    ],
    environments: [],
    users: [],
    targetGroups: [],
    targets: [],
    bootstrapTokens: [],
    agents: [],
    agentJobs: [],
    probeJobs: [],
    testRuns: [{ id: 'run_old', tenant_id: 'ten_demo', created_at: daysAgo(100) }],
    events: [
      { id: 'evt_old', tenant_id: 'ten_demo', timestamp: daysAgo(60) },
      { id: 'evt_new', tenant_id: 'ten_demo', timestamp: daysAgo(5) },
      { id: 'evt_other_old', tenant_id: 'ten_other', timestamp: daysAgo(60) },
      { id: 'evt_bad_ts', tenant_id: 'ten_demo', timestamp: 'not-a-date' },
    ],
    verdicts: [],
    findings: [{ id: 'find_old', tenant_id: 'ten_demo', created_at: daysAgo(60) }],
    reports: [
      { id: 'rpt_old', tenant_id: 'ten_demo', created_at: daysAgo(60) },
      { id: 'rpt_new', tenant_id: 'ten_demo', created_at: daysAgo(1) },
      { id: 'rpt_other_old', tenant_id: 'ten_other', created_at: daysAgo(60) },
      { id: 'rpt_bad_ts', tenant_id: 'ten_demo', created_at: 'not-a-date' },
    ],
    highScaleRequests: [{ id: 'hsr_old', tenant_id: 'ten_demo', created_at: daysAgo(60) }],
    socKillSwitch: { active: false, reason: null, updated_at: null },
    socNotes: [],
    evidenceVault: [
      { id: 'ev_old', tenant_id: 'ten_demo', created_at: daysAgo(45) },
      { id: 'ev_new', tenant_id: 'ten_demo', created_at: daysAgo(2) },
      { id: 'ev_other_old', tenant_id: 'ten_other', created_at: daysAgo(45) },
      { id: 'ev_bad_ts', tenant_id: 'ten_demo', created_at: 'not-a-date' },
    ],
    ingestedEventIds: {},
    notificationRules: [],
    notificationEvents: [
      { id: 'ne_old', tenant_id: 'ten_demo', created_at: daysAgo(40) },
      { id: 'ne_new', tenant_id: 'ten_demo', created_at: daysAgo(3) },
      { id: 'ne_other_old', tenant_id: 'ten_other', created_at: daysAgo(40) },
      { id: 'ne_bad_ts', tenant_id: 'ten_demo', created_at: 'not-a-date' },
    ],
    metrics: null,
    readiness: {},
    auditLog: [{ id: 'aud_keep', tenant_id: 'ten_demo', action: 'tenant.updated', timestamp: daysAgo(200) }],
    checkCatalog: CHECK_CATALOG.map((c) => ({ ...c })),
    ...overrides,
  };
}

describe('metadata privacy retention', () => {
  after(() => {
    process.env.ASTRANULL_NO_PERSIST = '1';
    delete process.env.ASTRANULL_DEV_DATA_DIR;
    clearStoreCacheForTests();
  });

  it('purges expired metadata for the target tenant only', () => {
    process.env.ASTRANULL_NO_PERSIST = '1';
    resetStoreForTests(baseStore());

    const summary = enforceMetadataRetentionForTenant('ten_demo');
    assert.equal(summary.deleted.events, 1);
    assert.equal(summary.deleted.evidenceVault, 1);
    assert.equal(summary.deleted.reports, 0);
    assert.equal(summary.deleted.notificationEvents, 1);

    const store = getStore();
    assert.deepEqual(
      store.events.map((e) => e.id).sort(),
      ['evt_bad_ts', 'evt_new', 'evt_other_old'].sort(),
    );
    assert.deepEqual(
      store.evidenceVault.map((e) => e.id).sort(),
      ['ev_bad_ts', 'ev_new', 'ev_other_old'].sort(),
    );
    assert.deepEqual(
      store.reports.map((e) => e.id).sort(),
      ['rpt_bad_ts', 'rpt_new', 'rpt_old', 'rpt_other_old'].sort(),
    );
    assert.deepEqual(
      store.notificationEvents.map((e) => e.id).sort(),
      ['ne_bad_ts', 'ne_new', 'ne_other_old'].sort(),
    );
    assert.equal(store.findings.length, 1);
    assert.equal(store.testRuns.length, 1);
    assert.equal(store.highScaleRequests.length, 1);
    assert.equal(store.auditLog.length, 2);
    assert.equal(store.auditLog[1].action, 'privacy.retention_purged');
    assert.deepEqual(store.auditLog[1].metadata.deleted, summary.deleted);
  });

  it('does not add a purge audit entry when nothing is removed', () => {
    process.env.ASTRANULL_NO_PERSIST = '1';
    resetStoreForTests(
      baseStore({
        events: [{ id: 'evt_new', tenant_id: 'ten_demo', timestamp: daysAgo(1) }],
        evidenceVault: [],
        reports: [],
        notificationEvents: [],
        auditLog: [],
      }),
    );

    enforceMetadataRetentionForTenant('ten_demo');
    assert.equal(getStore().auditLog.length, 0);
  });

  it('normalizes invalid retention days', () => {
    assert.equal(normalizePrivacySettings({ metadata_retention_days: 0 }).metadata_retention_days, 1);
    assert.equal(normalizePrivacySettings({ metadata_retention_days: 99999 }).metadata_retention_days, 3650);
    assert.equal(normalizePrivacySettings({ metadata_retention_days: 'bad' }).metadata_retention_days, 365);
  });

  it('defaults and clamps evidence_retention on normalize', () => {
    const defaults = normalizePrivacySettings({});
    assert.deepEqual(defaults.evidence_retention, { ...DEFAULT_EVIDENCE_RETENTION });

    const legacy = normalizePrivacySettings({ metadata_retention_days: 30 });
    assert.deepEqual(legacy.evidence_retention, { ...DEFAULT_EVIDENCE_RETENTION });

    const clamped = normalizePrivacySettings({
      evidence_retention: {
        audit_log_days: 1,
        high_scale_artifact_days: 99999,
        report_days: 10,
        legal_hold: true,
      },
    });
    assert.equal(clamped.evidence_retention.audit_log_days, 365);
    assert.equal(clamped.evidence_retention.high_scale_artifact_days, 3650);
    assert.equal(clamped.evidence_retention.report_days, 30);
    assert.equal(clamped.evidence_retention.legal_hold, true);
  });

  it('uses the larger report retention window when purging reports', () => {
    process.env.ASTRANULL_NO_PERSIST = '1';
    resetStoreForTests(
      baseStore({
        tenants: [
          {
            id: 'ten_demo',
            name: 'Demo',
            privacy_settings: {
              metadata_retention_days: 30,
              evidence_retention: { report_days: 365 },
            },
          },
          { id: 'ten_other', name: 'Other', privacy_settings: { metadata_retention_days: 30 } },
        ],
      }),
    );

    const summary = enforceMetadataRetentionForTenant('ten_demo');
    assert.equal(summary.deleted.reports, 0);
    assert.equal(summary.deleted.events, 1);
    assert.ok(getStore().reports.some((r) => r.id === 'rpt_old'));
  });

  it('blocks metadata deletion under legal hold and audits retention_legal_hold', () => {
    process.env.ASTRANULL_NO_PERSIST = '1';
    resetStoreForTests(
      baseStore({
        tenants: [
          {
            id: 'ten_demo',
            name: 'Demo',
            privacy_settings: {
              metadata_retention_days: 30,
              evidence_retention: { legal_hold: true },
            },
          },
          { id: 'ten_other', name: 'Other', privacy_settings: { metadata_retention_days: 30 } },
        ],
        auditLog: [],
      }),
    );

    const summary = enforceMetadataRetentionForTenant('ten_demo');
    assert.equal(summary.legal_hold, true);
    assert.deepEqual(summary.deleted, {
      events: 0,
      evidenceVault: 0,
      reports: 0,
      notificationEvents: 0,
    });
    assert.equal(getStore().events.length, 4);
    const holdAudit = getStore().auditLog.find((e) => e.action === 'privacy.retention_legal_hold');
    assert.ok(holdAudit);
    assert.deepEqual(holdAudit.metadata.blocked_deletions, {
      events: 1,
      evidenceVault: 1,
      reports: 0,
      notificationEvents: 1,
    });
    assert.ok(holdAudit.metadata.policy_snapshot);
  });

  it('policy snapshot lists protected collections and effective deletion windows', () => {
    const tenant = {
      id: 'ten_demo',
      privacy_settings: { metadata_retention_days: 30, evidence_retention: { report_days: 365 } },
    };
    const snapshot = buildRetentionPolicySnapshot(tenant);
    assert.equal(snapshot.tenant_id, 'ten_demo');
    assert.equal(snapshot.metadata_retention_days, 30);
    assert.deepEqual(snapshot.protected_collections, PROTECTED_GOVERNANCE_COLLECTIONS);
    const reports = snapshot.deletion_collections.find((c) => c.collection === 'reports');
    assert.equal(reports.effective_retention_days, 365);
    const events = snapshot.deletion_collections.find((c) => c.collection === 'events');
    assert.equal(events.effective_retention_days, 30);
    assert.ok(snapshot.evidence_retention);
  });

  it('clamps invalid retention days when tenant privacy settings are patched', () => {
    process.env.ASTRANULL_NO_PERSIST = '1';
    resetStoreForTests(baseStore());

    const ctx = { tenantId: 'ten_demo', userId: 'usr_1', role: 'admin' };
    patchCurrentTenant(ctx, { privacy_settings: { metadata_retention_days: 0 } });

    const store = getStore();
    assert.equal(store.tenants[0].privacy_settings.metadata_retention_days, 1);
    assert.ok(store.auditLog.some((e) => e.action === 'tenant.updated'));
  });

  it('enforces retention when tenant privacy settings are patched', () => {
    process.env.ASTRANULL_NO_PERSIST = '1';
    resetStoreForTests(baseStore());

    const ctx = { tenantId: 'ten_demo', userId: 'usr_1', role: 'admin' };
    patchCurrentTenant(ctx, { privacy_settings: { metadata_retention_days: 7 } });

    const store = getStore();
    assert.equal(store.tenants[0].privacy_settings.metadata_retention_days, 7);
    assert.ok(store.events.every((e) => e.id !== 'evt_old'));
    assert.ok(store.auditLog.some((e) => e.action === 'privacy.retention_purged'));
    assert.ok(store.auditLog.some((e) => e.action === 'tenant.updated'));
  });

  it('persists normalized privacy settings when retention removes nothing', () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), 'astranull-retention-'));
    delete process.env.ASTRANULL_NO_PERSIST;
    process.env.ASTRANULL_DEV_DATA_DIR = tmpDir;
    clearStoreCacheForTests();

    resetStoreForTests(
      baseStore({
        tenants: [
          {
            id: 'ten_demo',
            name: 'Demo',
            privacy_settings: { metadata_retention_days: 5000 },
          },
        ],
        events: [{ id: 'evt_new', tenant_id: 'ten_demo', timestamp: daysAgo(1) }],
        evidenceVault: [],
        reports: [],
        notificationEvents: [],
        auditLog: [],
      }),
    );

    enforceMetadataRetentionForTenant('ten_demo');

    const dataFile = path.join(tmpDir, 'astranull-dev.json');
    const onDisk = JSON.parse(readFileSync(dataFile, 'utf8'));
    assert.equal(onDisk.tenants[0].privacy_settings.metadata_retention_days, 3650);
    assert.equal(onDisk.auditLog.length, 0);

    rmSync(tmpDir, { recursive: true, force: true });
    delete process.env.ASTRANULL_DEV_DATA_DIR;
    clearStoreCacheForTests();
    process.env.ASTRANULL_NO_PERSIST = '1';
  });
});