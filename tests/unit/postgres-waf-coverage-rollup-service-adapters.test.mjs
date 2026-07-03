import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';
import {
  POSTGRES_WAF_COVERAGE_ROLLUP_SERVICE_METHODS,
  WAF_COVERAGE_ROLLUP_REPOSITORY_METHODS,
  createPostgresWafCoverageRollupServices,
} from '../../src/persistence/postgres/wafCoverageRollupServiceAdapters.mjs';

const envSnapshot = { ...process.env };
const CTX = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };

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

afterEach(() => {
  restoreEnv();
});

function createRepositories(overrides = {}) {
  const wafPosture = {};
  for (const method of WAF_COVERAGE_ROLLUP_REPOSITORY_METHODS) {
    wafPosture[method] = async () => [];
  }
  return {
    wafPosture: { ...wafPosture, ...overrides.wafPosture },
  };
}

describe('postgres WAF coverage rollup service adapters', () => {
  it('exposes stable repository and service method lists', () => {
    assert.deepEqual(WAF_COVERAGE_ROLLUP_REPOSITORY_METHODS, [
      'listWafAssets',
      'listCurrentPostureSnapshots',
      'upsertWafCoverageDailyRollup',

    ]);
    assert.deepEqual(POSTGRES_WAF_COVERAGE_ROLLUP_SERVICE_METHODS, [
      'runCoverageRollup',
      'runScheduledCoverageRollups',
    ]);
  });

  it('requires repository methods before wiring services', () => {
    assert.throws(
      () => createPostgresWafCoverageRollupServices({}),
      /requires repositories\.wafPosture/,
    );
    assert.throws(
      () => createPostgresWafCoverageRollupServices({
        wafPosture: { listWafAssets: async () => [] },
      }),
      /requires wafPosture\.listCurrentPostureSnapshots/,
    );
  });

  it('runs tenant rollup from current snapshots', async () => {
    Object.assign(process.env, wafEnabledEnv());
    const repositories = createRepositories({
      wafPosture: {
        listWafAssets: async () => [
          { id: 'waf_1', tenant_id: CTX.tenantId },
          { id: 'waf_2', tenant_id: CTX.tenantId },
        ],
        listCurrentPostureSnapshots: async () => [
          { waf_asset_id: 'waf_1', status: 'protected' },
          { waf_asset_id: 'waf_2', status: 'unprotected' },
        ],
        upsertWafCoverageDailyRollup: async (_ctx, record) => ({
          ...record,
          tenant_id: CTX.tenantId,
        }),
      },
    });
    const services = createPostgresWafCoverageRollupServices(repositories);
    const outcome = await services.runCoverageRollup({
      ...CTX,
      rollupDate: '2026-07-02',
    });
    assert.equal(outcome.rollup_result.total_assets, 2);
    assert.equal(outcome.rollup_result.protected, 1);
    assert.equal(outcome.rollup_result.unprotected, 1);
    assert.equal(outcome.rollup_result.coverage_ratio, 0.5);
  });
});