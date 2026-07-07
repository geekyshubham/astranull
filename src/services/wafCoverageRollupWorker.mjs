import { loadRuntimeConfig } from '../config.mjs';
import { computeWafCoverageSummaryRow } from '../lib/wafCoverageSummary.mjs';
import { newId } from '../lib/ids.mjs';
import { computeCoverageDailyRollup } from './wafCoverageService.mjs';
import { getStore, persistStore } from '../store.mjs';

function wafFeatureGate() {
  const enabled = loadRuntimeConfig().featureFlags.wafPostureEnabled === true;
  if (!enabled) return { skipped: true, reason: 'waf_feature_disabled' };
  return null;
}

function ensureStoreShape() {
  const store = getStore();
  if (!Array.isArray(store.wafCoverageDailyRollups)) {
    store.wafCoverageDailyRollups = [];
  }
  if (!store.wafCoverageSummaries || typeof store.wafCoverageSummaries !== 'object') {
    store.wafCoverageSummaries = {};
  }
  return store;
}

/**
 * @param {string} tenantId
 * @param {Date} [now]
 */
export function refreshWafCoverageSummaryForTenant(tenantId, now = new Date()) {
  const store = ensureStoreShape();
  const assets = store.wafAssets.filter((asset) => asset.tenant_id === tenantId);
  const snapshots = store.wafPostureSnapshots.filter((snap) => snap.tenant_id === tenantId);
  const connectors = (store.wafConnectors ?? []).filter((row) => row.tenant_id === tenantId);
  const currentSnapshotsByAsset = indexCurrentSnapshots(snapshots);
  const summary = computeWafCoverageSummaryRow({
    assets,
    currentSnapshotsByAsset,
    connectors,
    refreshedAt: now,
  });
  store.wafCoverageSummaries[tenantId] = summary;
  return summary;
}

function indexCurrentSnapshots(snapshots = []) {
  const byAsset = new Map();
  for (const snapshot of snapshots) {
    if (!snapshot?.waf_asset_id) continue;
    if (snapshot.is_current === true) {
      byAsset.set(snapshot.waf_asset_id, snapshot);
      continue;
    }
    const existing = byAsset.get(snapshot.waf_asset_id);
    if (!existing || String(snapshot.created_at).localeCompare(String(existing.created_at)) > 0) {
      byAsset.set(snapshot.waf_asset_id, snapshot);
    }
  }
  return byAsset;
}

/**
 * @param {{
 *   assets?: unknown[],
 *   currentSnapshotsByAsset?: Map<string, unknown>,
 *   rollupDate?: string,
 *   now?: Date,
 * }} [input]
 */
export function buildCoverageRollupRecord(input = {}) {
  const now = input.now ?? new Date();
  const rollupDate = input.rollupDate ?? now.toISOString().slice(0, 10);
  const metrics = computeCoverageDailyRollup({
    assets: input.assets ?? [],
    currentSnapshotsByAsset: input.currentSnapshotsByAsset ?? new Map(),
    rollupDate,
  });
  return {
    ...metrics,
    created_at: now.toISOString(),
  };
}

/**
 * @param {string} tenantId
 * @param {string} rollupDate
 * @param {unknown} store
 */
export function summarizeTenantCoverageRollupScope(tenantId, rollupDate, store) {
  const assets = (store?.wafAssets ?? []).filter((asset) => asset.tenant_id === tenantId);
  const snapshots = (store?.wafPostureSnapshots ?? []).filter((snap) => snap.tenant_id === tenantId);
  const existingRollup = (store?.wafCoverageDailyRollups ?? []).find(
    (row) => row.tenant_id === tenantId && row.rollup_date === rollupDate,
  );
  return {
    tenant_id: tenantId,
    rollup_date: rollupDate,
    assets_count: assets.length,
    current_snapshots_count: snapshots.filter((snap) => snap.is_current === true).length,
    existing_rollup: existingRollup
      ? {
        id: existingRollup.id,
        coverage_ratio: existingRollup.coverage_ratio,
        total_assets: existingRollup.total_assets,
      }
      : null,
  };
}

/**
 * @param {{
 *   tenantId: string,
 *   userId?: string,
 *   role?: string,
 *   rollupDate?: string,
 *   dryRun?: boolean,
 *   now?: Date,
 * }} ctx
 */
export function runCoverageRollup(ctx) {
  const gate = wafFeatureGate();
  if (gate) return gate;

  const store = ensureStoreShape();
  const tenantId = ctx.tenantId;
  const now = ctx.now ?? new Date();
  const rollupDate = ctx.rollupDate ?? now.toISOString().slice(0, 10);

  if (ctx.dryRun) {
    return {
      dry_run: true,
      scope: summarizeTenantCoverageRollupScope(tenantId, rollupDate, store),
      rollup_result: null,
    };
  }

  const assets = store.wafAssets.filter((asset) => asset.tenant_id === tenantId);
  const snapshots = store.wafPostureSnapshots.filter((snap) => snap.tenant_id === tenantId);
  const currentSnapshotsByAsset = indexCurrentSnapshots(snapshots);
  const metrics = buildCoverageRollupRecord({ assets, currentSnapshotsByAsset, rollupDate, now });

  const existingIndex = store.wafCoverageDailyRollups.findIndex(
    (row) => row.tenant_id === tenantId && row.rollup_date === rollupDate,
  );
  const record = {
    id: existingIndex >= 0 ? store.wafCoverageDailyRollups[existingIndex].id : newId('waf_cov_rollup'),
    tenant_id: tenantId,
    ...metrics,
  };

  if (existingIndex >= 0) {
    store.wafCoverageDailyRollups[existingIndex] = record;
  } else {
    store.wafCoverageDailyRollups.push(record);
  }

  refreshWafCoverageSummaryForTenant(tenantId, now);
  persistStore();

  return {
    rollup_result: {
      tenant_id: tenantId,
      rollup_date: rollupDate,
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
}

/**
 * @param {{
 *   userId?: string,
 *   role?: string,
 *   rollupDate?: string,
 *   dryRun?: boolean,
 *   now?: Date,
 * }} [ctx]
 */
export function runScheduledCoverageRollups(ctx = {}) {
  const gate = wafFeatureGate();
  if (gate) return gate;

  const store = ensureStoreShape();
  const tenantIds = [...new Set(store.wafAssets.map((asset) => asset.tenant_id).filter(Boolean))];
  const results = [];

  for (const tenantId of tenantIds) {
    const outcome = runCoverageRollup({
      tenantId,
      userId: ctx.userId ?? 'system',
      role: ctx.role ?? 'system',
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
}