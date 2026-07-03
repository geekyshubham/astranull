import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import {
  buildWafCoverageRollupRunnerSummary,
  parseTenantIdsFromJson,
  parseWafCoverageRollupRunnerArgs,
  resolveRollupDate,
  resolveTenantIdsFromStore,
  resolveWafCoverageRollupRunnerConfig,
  runDevJsonWafCoverageRollups,
  runWafCoverageRollupRunner,
} from '../../scripts/waf-coverage-rollup-runner.mjs';
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
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-waf-coverage-rollup-runner-'));
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
  for (const key of ['wafAssets', 'wafPostureSnapshots', 'wafCoverageDailyRollups']) {
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
  freshStore();
});

describe('waf coverage rollup runner', () => {
  it('parses tenant and rollup-date flags', () => {
    const parsed = parseWafCoverageRollupRunnerArgs([
      'node',
      'script',
      '--tenant-id',
      'ten_demo',
      '--rollup-date',
      '2026-07-02',
      '--dry-run',
    ]);
    assert.equal(parsed.tenantId, 'ten_demo');
    assert.equal(parsed.rollupDate, '2026-07-02');
    assert.equal(parsed.dryRun, true);
  });

  it('defaults rollup date to today UTC', () => {
    const today = new Date().toISOString().slice(0, 10);
    assert.equal(resolveRollupDate(null), today);
    assert.equal(resolveRollupDate('2026-07-02'), '2026-07-02');
  });

  it('parses tenant id files as array or object envelope', () => {
    assert.deepEqual(parseTenantIdsFromJson(['ten_a', 'ten_b']), ['ten_a', 'ten_b']);
    assert.deepEqual(
      parseTenantIdsFromJson({ tenant_ids: ['ten_a'] }),
      ['ten_a'],
    );
  });

  it('resolves tenant ids from store when scope omitted', () => {
    const store = ensureWafStore();
    seedWafAsset({ tenant_id: 'ten_a' });
    seedWafAsset({ id: 'waf_asset_2', tenant_id: 'ten_b' });
    const ids = resolveTenantIdsFromStore([], store);
    assert.deepEqual(ids.sort(), ['ten_a', 'ten_b']);
  });

  it('requires WAF posture feature flag', () => {
    const config = resolveWafCoverageRollupRunnerConfig(
      { ...process.env, ASTRANULL_WAF_POSTURE_ENABLED: '0' },
      parseWafCoverageRollupRunnerArgs(['node', 'script']),
    );
    assert.equal(config.ok, false);
    assert.match(config.message, /WAF posture feature must be enabled/);
  });

  it('runs dev-json rollups and writes metadata-only summary', async () => {
    Object.assign(process.env, wafEnabledEnv());
    freshStore();
    const store = ensureWafStore();
    seedWafAsset();
    store.wafPostureSnapshots.push({
      id: 'snap_1',
      tenant_id: 'ten_demo',
      waf_asset_id: 'waf_asset_1',
      status: 'protected',
      is_current: true,
      created_at: '2026-07-01T12:00:00.000Z',
    });

    const outPath = path.join(tempDir(), 'rollup-run.json');
    const { summary, exitCode } = await runWafCoverageRollupRunner(
      process.env,
      {
        dryRun: false,
        tenantIds: ['ten_demo'],
        allTenants: false,
        rollupDate: '2026-07-02',
        out: outPath,
        persistenceMode: 'dev-json',
      },
      { persistStoreFn: () => {} },
    );

    assert.equal(exitCode, 0);
    assert.equal(summary.artifact_type, 'waf_coverage_rollup_runtime_run');
    assert.equal(summary.rollup_date, '2026-07-02');
    assert.equal(summary.total_assets_rolled_up, 1);
    const written = JSON.parse(readFileSync(outPath, 'utf8'));
    assert.equal(written.tenants[0].rollup_result.protected, 1);
    assert.equal(store.wafCoverageDailyRollups.length, 1);
    assert.equal(store.wafCoverageDailyRollups[0].protected, 1);
  });

  it('dry-run does not persist rollups', () => {
    Object.assign(process.env, wafEnabledEnv());
    freshStore();
    seedWafAsset();
    const tenantResults = runDevJsonWafCoverageRollups({
      tenantIds: ['ten_demo'],
      dryRun: true,
      rollupDate: '2026-07-02',
    });
    const summary = buildWafCoverageRollupRunnerSummary({
      dryRun: true,
      tenantResults,
      startedAt: '2026-07-02T00:00:00.000Z',
      finishedAt: '2026-07-02T00:00:01.000Z',
      persistenceMode: 'dev-json',
      rollupDate: '2026-07-02',
    });
    assert.equal(summary.dry_run, true);
    assert.equal(summary.tenants_processed, 0);
    assert.equal(getStore().wafCoverageDailyRollups.length, 0);
  });
});