import { loadRuntimeConfig } from '../../config.mjs';
import { newId } from '../../lib/ids.mjs';
import { buildCoverageRollupRecord } from '../../services/wafCoverageRollupWorker.mjs';
import { resolveScheduledTenantIds } from '../../lib/scheduledTenantScope.mjs';

/** @type {readonly string[]} */
export const WAF_COVERAGE_ROLLUP_REPOSITORY_METHODS = Object.freeze([
  'listWafAssets',
  'listCurrentPostureSnapshots',
  'upsertWafCoverageDailyRollup',
]);

/** @type {readonly string[]} */
export const POSTGRES_WAF_COVERAGE_ROLLUP_SERVICE_METHODS = Object.freeze([
  'runCoverageRollup',
  'runScheduledCoverageRollups',
]);

function assertWafCoverageRollupRepositories(repositories) {
  const wafPosture = repositories?.wafPosture;
  if (!wafPosture || typeof wafPosture !== 'object') {
    throw new Error('Postgres WAF coverage rollup adapter requires repositories.wafPosture.');
  }
  for (const method of WAF_COVERAGE_ROLLUP_REPOSITORY_METHODS) {
    if (typeof wafPosture[method] !== 'function') {
      throw new Error(`Postgres WAF coverage rollup adapter requires wafPosture.${method}().`);
    }
  }
}

function wafFeatureGate() {
  const enabled = loadRuntimeConfig().featureFlags.wafPostureEnabled === true;
  if (!enabled) return { skipped: true, reason: 'waf_feature_disabled' };
  return null;
}

function indexCurrentSnapshots(snapshots = []) {
  const byAsset = new Map();
  for (const snapshot of snapshots) {
    if (!snapshot?.waf_asset_id) continue;
    byAsset.set(snapshot.waf_asset_id, snapshot);
  }
  return byAsset;
}

/**
 * @param {Record<string, unknown>} repositories
 */
export function createPostgresWafCoverageRollupServices(repositories) {
  assertWafCoverageRollupRepositories(repositories);
  const wafPosture = repositories.wafPosture;

  return {
    async runCoverageRollup(ctx) {
      const gate = wafFeatureGate();
      if (gate) return gate;

      const tenantId = ctx.tenantId;
      const now = ctx.now instanceof Date ? ctx.now : new Date();
      const rollupDate = ctx.rollupDate ?? now.toISOString().slice(0, 10);

      if (ctx.dryRun) {
        const assets = await wafPosture.listWafAssets(ctx);
        const snapshots = await wafPosture.listCurrentPostureSnapshots(ctx);
        return {
          dry_run: true,
          scope: {
            tenant_id: tenantId,
            rollup_date: rollupDate,
            assets_count: assets.length,
            current_snapshots_count: snapshots.length,
          },
          rollup_result: null,
        };
      }

      const assets = await wafPosture.listWafAssets(ctx);
      const snapshots = await wafPosture.listCurrentPostureSnapshots(ctx);
      const currentSnapshotsByAsset = indexCurrentSnapshots(snapshots);
      const metrics = buildCoverageRollupRecord({
        assets,
        currentSnapshotsByAsset,
        rollupDate,
        now,
      });

      const record = await wafPosture.upsertWafCoverageDailyRollup(ctx, {
        id: newId('waf_cov_rollup'),
        rollup_date: rollupDate,
        ...metrics,
      });

      return {
        rollup_result: {
          tenant_id: tenantId,
          rollup_date: record.rollup_date,
          total_assets: record.total_assets,
          protected: record.protected,
          underprotected: record.underprotected,
          unprotected: record.unprotected,
          unknown: record.unknown,
          excluded: record.excluded,
          coverage_ratio: record.coverage_ratio,
          created_at: record.created_at,
        },
      };
    },

    async runScheduledCoverageRollups(ctx = {}) {
      const gate = wafFeatureGate();
      if (gate) return gate;

      const scope = resolveScheduledTenantIds(ctx, { label: 'WAF coverage rollup runner' });
      if ('error' in scope) return scope;

      const tenantIds = scope.tenantIds;
      const results = [];

      for (const tenantId of tenantIds) {
        const tenantCtx = {
          tenantId,
          userId: ctx.userId ?? 'system',
          role: ctx.role ?? 'system',
        };
        const outcome = await this.runCoverageRollup({
          ...tenantCtx,
          rollupDate: ctx.rollupDate,
          dryRun: ctx.dryRun,
          now: ctx.now,
        });
        if (outcome.skipped) return outcome;
        results.push(outcome.rollup_result ?? outcome.scope ?? { tenant_id: tenantId });
      }

      return {
        tenants_processed: tenantIds.length,
        rollup_results: results,
      };
    },
  };
}