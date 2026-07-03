import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import {
  buildWafDriftRunnerSummary,
  parseTenantIdsFromJson,
  parseWafDriftRunnerArgs,
  redactWafDriftRunnerMessage,
  resolveTenantIdsFromStore,
  resolveWafDriftRunnerConfig,
  runDevJsonWafDriftScans,
  runWafDriftRunner,
  summarizeTenantDriftScope,
  toMetadataOnlyScanResult,
} from '../../scripts/waf-drift-runner.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';

const tempDirs = [];
const envSnapshot = { ...process.env };

function restoreEnv() {
  for (const key of Object.keys(process.env)) {
    if (!(key in envSnapshot)) delete process.env[key];
  }
  Object.assign(process.env, envSnapshot);
}

function tempDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-waf-drift-runner-'));
  tempDirs.push(dir);
  return dir;
}

function wafEnabledEnv() {
  return {
    ...process.env,
    ASTRANULL_NO_PERSIST: '1',
    ASTRANULL_WAF_POSTURE_ENABLED: '1',
  };
}

function ensureWafStore() {
  const store = getStore();
  for (const key of [
    'wafAssets',
    'wafPostureSnapshots',
    'wafDriftEvents',
    'wafConnectorSnapshots',
    'wafDriftScanResults',
    'auditLog',
  ]) {
    if (!Array.isArray(store[key])) store[key] = [];
  }
  return store;
}

function seedWafAsset(overrides = {}) {
  const store = ensureWafStore();
  const asset = {
    id: 'waf_asset_1',
    tenant_id: 'ten_demo',
    target_group_id: 'tg_1',
    canonical_url: 'https://waf-app.example.com',
    expected_waf_required: true,
    status: 'protected',
    created_at: '2026-01-01T00:00:00.000Z',
    updated_at: '2026-01-01T00:00:00.000Z',
    ...overrides,
  };
  store.wafAssets.push(asset);
  return asset;
}

afterEach(() => {
  restoreEnv();
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop(), { recursive: true, force: true });
  }
});

describe('waf drift runner args', () => {
  it('parses defaults when only argv0/argv1 are present', () => {
    assert.deepEqual(parseWafDriftRunnerArgs(['node', 'waf-drift-runner.mjs']), {
      tenantId: null,
      tenantIdsFile: null,
      allTenants: false,
      dryRun: false,
      out: null,
      help: false,
    });
  });

  it('parses tenant, dry-run, all-tenants, out, and help', () => {
    assert.deepEqual(
      parseWafDriftRunnerArgs([
        'node',
        'waf-drift-runner.mjs',
        '--tenant-id',
        'ten_alpha',
        '--dry-run',
        '--all-tenants',
        '--out',
        '/tmp/summary.json',
        '--help',
      ]),
      {
        tenantId: 'ten_alpha',
        tenantIdsFile: null,
        allTenants: true,
        dryRun: true,
        out: '/tmp/summary.json',
        help: true,
      },
    );
  });

  it('rejects unknown arguments and missing values', () => {
    assert.throws(
      () => parseWafDriftRunnerArgs(['node', 'script.mjs', '--tenant-id']),
      /--tenant-id requires a value/,
    );
    assert.throws(
      () => parseWafDriftRunnerArgs(['node', 'script.mjs', '--bogus']),
      /unknown argument/,
    );
  });
});

describe('waf drift runner config', () => {
  it('requires WAF posture feature enabled', () => {
    const config = resolveWafDriftRunnerConfig(
      { ASTRANULL_WAF_POSTURE_ENABLED: '0' },
      parseWafDriftRunnerArgs(['node', 'script.mjs', '--tenant-id', 'ten_a']),
    );
    assert.equal(config.ok, false);
    assert.match(config.message, /WAF posture feature must be enabled/);
  });

  it('resolves dev-json mode without database URL', () => {
    const config = resolveWafDriftRunnerConfig(
      wafEnabledEnv(),
      parseWafDriftRunnerArgs(['node', 'script.mjs', '--tenant-id', 'ten_a']),
    );
    assert.equal(config.ok, true);
    assert.equal(config.persistenceMode, 'dev-json');
    assert.deepEqual(config.tenantIds, ['ten_a']);
    assert.equal(config.allTenants, false);
  });

  it('defaults to all tenants when tenant scope is omitted', () => {
    const config = resolveWafDriftRunnerConfig(
      wafEnabledEnv(),
      parseWafDriftRunnerArgs(['node', 'script.mjs']),
    );
    assert.equal(config.ok, true);
    assert.equal(config.tenantIds, null);
    assert.equal(config.allTenants, true);
  });

  it('selects postgres mode when database URL is set', () => {
    const config = resolveWafDriftRunnerConfig(
      {
        ...wafEnabledEnv(),
        ASTRANULL_DATABASE_URL: 'postgresql://user:secret@db.example.invalid/astranull',
      },
      parseWafDriftRunnerArgs(['node', 'script.mjs', '--tenant-id', 'ten_a']),
    );
    assert.equal(config.ok, true);
    assert.equal(config.persistenceMode, 'postgres');
  });
});

describe('waf drift runner scope summary', () => {
  it('counts connector and posture snapshot pairs per tenant', () => {
    Object.assign(process.env, wafEnabledEnv());
    freshStore();
    const asset = seedWafAsset();
    const store = getStore();

    store.wafConnectorSnapshots.push(
      {
        id: 'snap_prev',
        tenant_id: 'ten_demo',
        summary_json: { hostnames: ['waf-app.example.com'], policy_mode: 'blocking' },
        observed_at: '2026-05-01T00:00:00.000Z',
      },
      {
        id: 'snap_curr',
        tenant_id: 'ten_demo',
        summary_json: { hostnames: ['waf-app.example.com'], policy_mode: 'monitor' },
        observed_at: '2026-06-01T00:00:00.000Z',
      },
    );
    store.wafPostureSnapshots.push(
      {
        id: 'post_prev',
        tenant_id: 'ten_demo',
        waf_asset_id: asset.id,
        status: 'protected',
        created_at: '2026-05-01T00:00:00.000Z',
      },
      {
        id: 'post_curr',
        tenant_id: 'ten_demo',
        waf_asset_id: asset.id,
        status: 'underprotected',
        created_at: '2026-06-01T00:00:00.000Z',
      },
    );

    const scope = summarizeTenantDriftScope(store, 'ten_demo');
    assert.equal(scope.assets_count, 1);
    assert.equal(scope.assets_with_connector_snapshot_pairs, 1);
    assert.equal(scope.assets_with_posture_snapshot_pairs, 1);
  });
});

describe('waf drift runner dev-json execution', () => {
  it('dry-run reports scope without persisting scan results', () => {
    Object.assign(process.env, wafEnabledEnv());
    freshStore();
    seedWafAsset({ tenant_id: 'ten_alpha' });

    const tenantResults = runDevJsonWafDriftScans({
      tenantIds: ['ten_alpha'],
      dryRun: true,
    });

    assert.equal(tenantResults.length, 1);
    assert.equal(tenantResults[0].dry_run, true);
    assert.equal(tenantResults[0].scope.assets_count, 1);
    assert.equal(getStore().wafDriftScanResults.length, 0);
  });

  it('apply mode runs drift scan and records metadata-only scan results', () => {
    Object.assign(process.env, wafEnabledEnv());
    freshStore();
    seedWafAsset();

    const tenantResults = runDevJsonWafDriftScans({
      tenantIds: ['ten_demo'],
      dryRun: false,
    });

    assert.equal(tenantResults.length, 1);
    assert.equal(tenantResults[0].scan_result.tenant_id, 'ten_demo');
    assert.equal(tenantResults[0].scan_result.assets_scanned, 1);
    assert.equal(getStore().wafDriftScanResults.length, 1);
    assert.ok(!JSON.stringify(tenantResults[0]).includes('raw_config'));
  });

  it('scans all tenants with assets when tenant scope is empty', () => {
    Object.assign(process.env, wafEnabledEnv());
    freshStore();
    seedWafAsset({ id: 'waf_a', tenant_id: 'ten_alpha' });
    seedWafAsset({ id: 'waf_b', tenant_id: 'ten_beta', canonical_url: 'https://beta.example.com' });

    const tenantResults = runDevJsonWafDriftScans({
      tenantIds: [],
      dryRun: false,
    });

    assert.equal(tenantResults.length, 2);
    assert.deepEqual(
      tenantResults.map((row) => row.tenant_id).sort(),
      ['ten_alpha', 'ten_beta'],
    );
  });

  it('creates drift events from connector snapshot weakening', () => {
    Object.assign(process.env, wafEnabledEnv());
    freshStore();
    seedWafAsset();
    const store = getStore();
    store.wafConnectorSnapshots.push(
      {
        id: 'snap_prev',
        tenant_id: 'ten_demo',
        summary_json: {
          hostnames: ['waf-app.example.com'],
          policy_mode: 'blocking',
          rule_count: 140,
        },
        observed_at: '2026-05-01T00:00:00.000Z',
      },
      {
        id: 'snap_curr',
        tenant_id: 'ten_demo',
        summary_json: {
          hostnames: ['waf-app.example.com'],
          policy_mode: 'monitor',
          rule_count: 110,
        },
        observed_at: '2026-06-01T00:00:00.000Z',
      },
    );

    runDevJsonWafDriftScans({ tenantIds: ['ten_demo'], dryRun: false });

    const driftTypes = getStore().wafDriftEvents.map((e) => e.drift_type);
    assert.ok(driftTypes.includes('mode_downgrade') || driftTypes.includes('rule_removal'));
  });
});

describe('waf drift runner summary artifact', () => {
  it('builds metadata-only summary and writes output file', async () => {
    Object.assign(process.env, wafEnabledEnv());
    freshStore();
    seedWafAsset();

    const outPath = path.join(tempDir(), 'drift-run.json');
    const { summary, exitCode } = await runWafDriftRunner(
      wafEnabledEnv(),
      {
        dryRun: false,
        tenantIds: ['ten_demo'],
        allTenants: false,
        out: outPath,
        persistenceMode: 'dev-json',
      },
    );

    assert.equal(exitCode, 0);
    assert.equal(summary.artifact_type, 'waf_drift_runtime_run');
    assert.equal(summary.persistence_mode, 'dev-json');
    assert.equal(summary.tenant_count, 1);
    const written = JSON.parse(readFileSync(outPath, 'utf8'));
    assert.equal(written.total_drifts_detected, summary.total_drifts_detected);
    assert.ok(!JSON.stringify(written).includes('postgresql://'));
  });

  it('redacts database URLs from error messages', () => {
    const redacted = redactWafDriftRunnerMessage(
      new Error('connect failed postgresql://user:secret@db.example.invalid/astranull'),
      { ASTRANULL_DATABASE_URL: 'postgresql://user:secret@db.example.invalid/astranull' },
    );
    assert.ok(!String(redacted).includes('postgresql://user:secret'));
  });
});

describe('waf drift runner helpers', () => {
  it('parses tenant id file forms', () => {
    assert.deepEqual(parseTenantIdsFromJson(['ten_a', ' ten_b ']), ['ten_a', 'ten_b']);
    assert.deepEqual(parseTenantIdsFromJson({ tenant_ids: ['ten_x'] }), ['ten_x']);
  });

  it('resolves tenant ids from store assets', () => {
    const tenantIds = resolveTenantIdsFromStore([], {
      wafAssets: [{ tenant_id: 'ten_a' }, { tenant_id: 'ten_b' }, { tenant_id: 'ten_a' }],
    });
    assert.deepEqual(tenantIds.sort(), ['ten_a', 'ten_b']);
  });

  it('strips forbidden fields from scan result summaries', () => {
    const summary = toMetadataOnlyScanResult({
      tenant_id: 'ten_demo',
      scan_type: 'connector_config_change',
      assets_scanned: 2,
      drifts_detected: 1,
      scan_duration_ms: 12,
      completed_at: '2026-06-01T00:00:00.000Z',
      state: 'completed',
      raw_config: { mode: 'off' },
    });
    assert.equal(summary.tenant_id, 'ten_demo');
    assert.equal(summary.raw_config, undefined);
  });

  it('builds summary with dry-run tenant scope only', () => {
    const summary = buildWafDriftRunnerSummary({
      dryRun: true,
      tenantResults: [{
        tenant_id: 'ten_demo',
        dry_run: true,
        scope: { tenant_id: 'ten_demo', assets_count: 3 },
        scan_result: null,
      }],
      startedAt: '2026-06-01T00:00:00.000Z',
      finishedAt: '2026-06-01T00:00:01.000Z',
      persistenceMode: 'dev-json',
    });
    assert.equal(summary.dry_run, true);
    assert.equal(summary.tenants_scanned, 0);
    assert.equal(summary.total_drifts_detected, 0);
  });
});