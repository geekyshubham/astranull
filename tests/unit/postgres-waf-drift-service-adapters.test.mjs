import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, it } from 'node:test';
import {
  POSTGRES_WAF_DRIFT_SERVICE_METHODS,
  WAF_DRIFT_REPOSITORY_METHODS,
  createPostgresWafDriftServices,
} from '../../src/persistence/postgres/wafDriftServiceAdapters.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '../..');
const ADAPTER_SOURCE = readFileSync(
  path.join(ROOT, 'src/persistence/postgres/wafDriftServiceAdapters.mjs'),
  'utf8',
);

const envSnapshot = { ...process.env };
const FIXED_NOW = new Date('2026-06-15T12:00:00.000Z');

function restoreEnv() {
  for (const key of Object.keys(process.env)) {
    if (!(key in envSnapshot)) delete process.env[key];
  }
  Object.assign(process.env, envSnapshot);
}

function wafEnabledEnv() {
  return {
    ...process.env,
    ASTRANULL_WAF_POSTURE_ENABLED: '1',
  };
}

function demoCtx(tenantId = 'ten_demo') {
  return { tenantId, userId: 'usr_worker', role: 'system' };
}

function stubRepositories(overrides = {}) {
  const assets = overrides.assets ?? [
    {
      id: 'waf_asset_1',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_1',
      canonical_url: 'https://waf-app.example.com',
      expected_waf_required: true,
      created_at: '2026-01-01T00:00:00.000Z',
      updated_at: '2026-01-01T00:00:00.000Z',
    },
  ];
  const connectorSnapshots = overrides.connectorSnapshots ?? [
    {
      id: 'snap_prev',
      tenant_id: 'ten_demo',
      connector_id: 'conn_1',
      provider: 'cloudflare',
      snapshot_kind: 'policy',
      resource_ref_hash: 'hash_prev',
      summary_json: {
        hostnames: ['waf-app.example.com'],
        policy_mode: 'blocking',
        rule_count: 140,
      },
      observed_at: '2026-05-01T00:00:00.000Z',
      created_at: '2026-05-01T00:00:00.000Z',
    },
    {
      id: 'snap_curr',
      tenant_id: 'ten_demo',
      connector_id: 'conn_1',
      provider: 'cloudflare',
      snapshot_kind: 'policy',
      resource_ref_hash: 'hash_curr',
      summary_json: {
        hostnames: ['waf-app.example.com'],
        policy_mode: 'monitor',
        rule_count: 110,
      },
      observed_at: '2026-06-01T00:00:00.000Z',
      created_at: '2026-06-01T00:00:00.000Z',
    },
  ];
  const postureSnapshots = overrides.postureSnapshots ?? [];
  const driftEvents = overrides.driftEvents ?? [];
  const scanResults = overrides.scanResults ?? [];
  const tenantIds = overrides.tenantIds ?? ['ten_demo'];
  const auditEvents = [];

  const wafPosture = {
    listWafAssets: async (ctx) => assets.filter((asset) => asset.tenant_id === ctx.tenantId),
    listWafConnectorSnapshotsForTenant: async (ctx) =>
      connectorSnapshots.filter((snap) => snap.tenant_id === ctx.tenantId),
    listWafPostureSnapshotsForTenant: async (ctx) =>
      postureSnapshots.filter((snap) => snap.tenant_id === ctx.tenantId),
    upsertWafDriftEvent: async (ctx, record) => {
      const existing = driftEvents.find(
        (event) =>
          event.tenant_id === ctx.tenantId
          && event.waf_asset_id === record.waf_asset_id
          && event.drift_type === record.drift_type
          && event.status === 'open',
      );
      if (existing) {
        existing.severity = record.severity ?? existing.severity;
        existing.after_summary_json = record.after_summary ?? record.after_summary_json ?? {};
        return { drift_event: existing, inserted: false };
      }
      const created = {
        id: record.id,
        tenant_id: ctx.tenantId,
        waf_asset_id: record.waf_asset_id,
        baseline_id: record.baseline_id ?? null,
        drift_type: record.drift_type,
        severity: record.severity ?? 'medium',
        before_summary_json: record.before_summary ?? record.before_summary_json ?? {},
        after_summary_json: record.after_summary ?? record.after_summary_json ?? {},
        status: record.status ?? 'open',
        finding_id: record.finding_id ?? null,
        created_at: record.created_at ?? FIXED_NOW.toISOString(),
        resolved_at: null,
      };
      driftEvents.push(created);
      return { drift_event: created, inserted: true };
    },
    createWafDriftScanResult: async (ctx, record) => {
      const persisted = {
        id: record.id,
        tenant_id: ctx.tenantId,
        scan_type: record.scan_type,
        assets_scanned: record.assets_scanned,
        drifts_detected: record.drifts_detected,
        scan_duration_ms: record.scan_duration_ms,
        completed_at: record.completed_at,
        state: record.state ?? 'completed',
        assets_with_connector_snapshots: record.assets_with_connector_snapshots ?? null,
        drift_check_types: record.drift_check_types ?? [],
        created_at: record.created_at ?? record.completed_at,
      };
      scanResults.push(persisted);
      return persisted;
    },
    getLatestWafDriftScanResult: async (ctx) => {
      const rows = scanResults
        .filter((row) => row.tenant_id === ctx.tenantId)
        .sort((a, b) => String(b.completed_at).localeCompare(String(a.completed_at)));
      return rows[0] ?? null;
    },
  };

  const audit = {
    appendAuditEvent: async (event) => {
      auditEvents.push(event);
    },
  };

  return {
    wafPosture,
    audit,
    state: {
      assets,
      connectorSnapshots,
      postureSnapshots,
      driftEvents,
      scanResults,
      auditEvents,
    },
  };
}

afterEach(() => {
  restoreEnv();
});

describe('postgres waf drift service adapter', () => {
  it('exposes drift scan service method contract', () => {
    assert.deepEqual(POSTGRES_WAF_DRIFT_SERVICE_METHODS, [
      'runDriftScan',
      'getLastScanResult',
      'runScheduledDriftScans',
    ]);
    for (const method of WAF_DRIFT_REPOSITORY_METHODS) {
      assert.ok(method.length > 0, method);
    }
  });

  it('throws when required repositories or methods are missing', () => {
    assert.throws(() => createPostgresWafDriftServices({}), /wafPosture/);
    const partial = stubRepositories();
    delete partial.wafPosture.listWafAssets;
    assert.throws(
      () => createPostgresWafDriftServices(partial),
      /wafPosture\.listWafAssets/,
    );
    const noAudit = stubRepositories();
    delete noAudit.audit.appendAuditEvent;
    assert.throws(
      () => createPostgresWafDriftServices(noAudit),
      /audit\.appendAuditEvent/,
    );
  });

  it('does not import dev store modules', () => {
    assert.equal(/\bgetStore\b/.test(ADAPTER_SOURCE), false);
    assert.equal(/\bpersistStore\b/.test(ADAPTER_SOURCE), false);
    assert.equal(/from\s+['"].*\/services\/wafDriftWorker/.test(ADAPTER_SOURCE), false);
  });

  it('skips scans when WAF feature is disabled', async () => {
    Object.assign(process.env, {
      ...process.env,
      ASTRANULL_WAF_POSTURE_ENABLED: '0',
    });
    const repositories = stubRepositories();
    const service = createPostgresWafDriftServices(repositories, { now: () => FIXED_NOW });

    const outcome = await service.runDriftScan(demoCtx());
    assert.equal(outcome.skipped, true);
    assert.equal(outcome.reason, 'waf_feature_disabled');
    assert.equal(repositories.state.scanResults.length, 0);
  });

  it('runs tenant drift scan, persists metadata-only scan result, and audits completion', async () => {
    Object.assign(process.env, wafEnabledEnv());
    const repositories = stubRepositories();
    const service = createPostgresWafDriftServices(repositories, {
      now: () => FIXED_NOW,
      newId: (prefix) => `${prefix}_test`,
    });

    const outcome = await service.runDriftScan(demoCtx());
    assert.equal(outcome.scan_result.tenant_id, 'ten_demo');
    assert.equal(outcome.scan_result.assets_scanned, 1);
    assert.ok(outcome.scan_result.drifts_detected >= 1);
    assert.equal(repositories.state.scanResults.length, 1);
    assert.equal(repositories.state.driftEvents.length >= 1, true);
    assert.ok(
      repositories.state.auditEvents.some((event) => event.action === 'waf.drift_scan.completed'),
    );
    assert.ok(
      repositories.state.auditEvents.some((event) => event.action === 'waf.drift.detected'),
    );
    assert.equal(outcome.scan_result.raw_config, undefined);
  });

  it('returns latest scan result for tenant and null when none exist', async () => {
    Object.assign(process.env, wafEnabledEnv());
    const repositories = stubRepositories();
    const service = createPostgresWafDriftServices(repositories, { now: () => FIXED_NOW });

    const empty = await service.getLastScanResult(demoCtx());
    assert.equal(empty.scan_result, null);

    await service.runDriftScan(demoCtx());
    const latest = await service.getLastScanResult(demoCtx());
    assert.equal(latest.scan_result.tenant_id, 'ten_demo');
    assert.equal(latest.scan_result.assets_scanned, 1);
  });

  it('runs scheduled scans across distinct tenant ids', async () => {
    Object.assign(process.env, wafEnabledEnv());
    const repositories = stubRepositories({
      tenantIds: ['ten_alpha', 'ten_beta'],
      assets: [
        {
          id: 'waf_a',
          tenant_id: 'ten_alpha',
          target_group_id: 'tg_1',
          canonical_url: 'https://alpha.example.com',
        },
        {
          id: 'waf_b',
          tenant_id: 'ten_beta',
          target_group_id: 'tg_2',
          canonical_url: 'https://beta.example.com',
        },
      ],
      connectorSnapshots: [],
    });
    const service = createPostgresWafDriftServices(repositories, { now: () => FIXED_NOW });

    const outcome = await service.runScheduledDriftScans({
      userId: 'runner',
      role: 'system',
      tenantIds: ['ten_alpha', 'ten_beta'],
    });
    assert.equal(outcome.tenants_scanned, 2);
    assert.equal(outcome.scan_results.length, 2);
    assert.deepEqual(
      outcome.scan_results.map((row) => row.tenant_id).sort(),
      ['ten_alpha', 'ten_beta'],
    );
  });

  it('fails closed for scheduled scans without explicit tenant scope', async () => {
    Object.assign(process.env, wafEnabledEnv());
    const repositories = stubRepositories();
    const service = createPostgresWafDriftServices(repositories, { now: () => FIXED_NOW });
    const outcome = await service.runScheduledDriftScans({ userId: 'runner', role: 'system' });
    assert.equal(outcome.error, 'tenant_scope_required');
    assert.equal(outcome.status, 400);
  });

  it('detects posture weakening drift from stored snapshots', async () => {
    Object.assign(process.env, wafEnabledEnv());
    const repositories = stubRepositories({
      connectorSnapshots: [],
      postureSnapshots: [
        {
          id: 'post_prev',
          tenant_id: 'ten_demo',
          waf_asset_id: 'waf_asset_1',
          status: 'protected',
          reason_codes: [],
          detected_vendor: 'cloudflare',
          created_at: '2026-05-01T00:00:00.000Z',
          is_current: false,
        },
        {
          id: 'post_curr',
          tenant_id: 'ten_demo',
          waf_asset_id: 'waf_asset_1',
          status: 'underprotected',
          reason_codes: ['origin_bypass_confirmed'],
          detected_vendor: 'cloudflare',
          created_at: '2026-06-01T00:00:00.000Z',
          is_current: true,
        },
      ],
    });
    const service = createPostgresWafDriftServices(repositories, { now: () => FIXED_NOW });

    const outcome = await service.detectAssetDrift(demoCtx(), 'waf_asset_1');
    assert.equal(outcome.drifts_detected, 1);
    assert.equal(outcome.drift_events[0].drift_type, 'origin_bypass_new');
  });
});