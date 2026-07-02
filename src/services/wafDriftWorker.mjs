import { audit } from '../audit.mjs';
import { loadRuntimeConfig } from '../config.mjs';
import {
  computeDriftSeverity,
  createDriftScanResult,
  detectConnectorConfigDrift,
  DRIFT_CHECK_TYPES,
  mapConnectorSignalToDriftType,
  mapConnectorSignalsToCheckTypes,
} from '../contracts/wafDriftWorker.mjs';
import { newId } from '../lib/ids.mjs';
import { getStore, persistStore } from '../store.mjs';

const WAF_DRIFT_OPEN_STATUS = 'open';
const BLOCKING_POLICY_MODES = new Set(['blocking', 'block', 'prevention', 'on', 'enabled']);
const MONITOR_POLICY_MODES = new Set(['monitor', 'detect', 'log', 'log_only', 'simulate', 'count']);

function ensureStoreShape() {
  const store = getStore();
  const keys = [
    'wafAssets',
    'wafPostureSnapshots',
    'wafDriftEvents',
    'wafConnectorSnapshots',
    'wafDriftScanResults',
  ];
  for (const key of keys) {
    if (!Array.isArray(store[key])) store[key] = [];
  }
  return store;
}

function wafFeatureGate() {
  const enabled = loadRuntimeConfig().featureFlags.wafPostureEnabled === true;
  if (!enabled) return { skipped: true, reason: 'waf_feature_disabled' };
  return null;
}

function hostnameFromAsset(asset) {
  const canonical = typeof asset?.canonical_url === 'string' ? asset.canonical_url.trim() : '';
  if (canonical) {
    try {
      return new URL(canonical).hostname.toLowerCase();
    } catch {
      return canonical.replace(/^https?:\/\//i, '').split('/')[0].toLowerCase();
    }
  }
  const hostname = typeof asset?.hostname === 'string' ? asset.hostname.trim() : '';
  return hostname ? hostname.toLowerCase() : null;
}

function snapshotSummary(snapshot) {
  return snapshot?.summary_json ?? snapshot?.summary ?? {};
}

function normalizePolicyMode(value) {
  return String(value ?? '').trim().toLowerCase();
}

function isConnectorModeDowngrade(previousSnapshot, currentSnapshot) {
  const previous = snapshotSummary(previousSnapshot);
  const current = snapshotSummary(currentSnapshot);
  const prevMode = normalizePolicyMode(previous.policy_mode ?? previous.mode_summary);
  const currMode = normalizePolicyMode(current.policy_mode ?? current.mode_summary);
  if (!prevMode || !currMode || prevMode === currMode) return false;
  if (BLOCKING_POLICY_MODES.has(prevMode) && MONITOR_POLICY_MODES.has(currMode)) return true;
  if (BLOCKING_POLICY_MODES.has(prevMode) && (currMode === 'off' || currMode === 'disabled')) return true;
  return false;
}

function connectorSnapshotsForAsset(ctx, asset) {
  ensureStoreShape();
  const hostname = hostnameFromAsset(asset);
  if (!hostname) return [];

  return getStore()
    .wafConnectorSnapshots.filter((snap) => {
      if (snap.tenant_id !== ctx.tenantId) return false;
      const hostnames = snap.summary_json?.hostnames ?? snap.summary?.hostnames ?? [];
      if (!Array.isArray(hostnames)) return false;
      return hostnames.some((h) => String(h).trim().toLowerCase() === hostname);
    })
    .sort((a, b) => String(b.observed_at ?? b.created_at).localeCompare(String(a.observed_at ?? a.created_at)));
}

function latestConnectorPair(snapshots) {
  if (snapshots.length < 2) return { current: snapshots[0] ?? null, previous: null };
  return { current: snapshots[0], previous: snapshots[1] };
}

function postureSnapshotsForAsset(ctx, assetId) {
  ensureStoreShape();
  return getStore()
    .wafPostureSnapshots.filter((s) => s.tenant_id === ctx.tenantId && s.waf_asset_id === assetId)
    .sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
}

function latestPosturePair(snapshots) {
  if (snapshots.length < 2) return { current: snapshots[0] ?? null, previous: snapshots[1] ?? null };
  return { current: snapshots[0], previous: snapshots[1] };
}

function postureSummaryFromSnapshot(snapshot) {
  if (!snapshot) return {};
  return {
    status: snapshot.status,
    reason_codes: snapshot.reason_codes ?? [],
    ...(snapshot.detected_vendor ? { detected_vendor: snapshot.detected_vendor } : {}),
    ...(snapshot.detected_product ? { detected_product: snapshot.detected_product } : {}),
  };
}

function detectPostureDrifts(previous, current) {
  if (!previous || !current) return [];
  const drifts = [];
  const before = postureSummaryFromSnapshot(previous);
  const after = postureSummaryFromSnapshot(current);

  if (previous.status === 'protected' && current.status === 'unprotected') {
    const driftType = after.detected_vendor || after.detected_product ? 'mode_downgrade' : 'fingerprint_loss';
    drifts.push({
      drift_type: driftType,
      severity: 'critical',
      before_summary_json: before,
      after_summary_json: after,
      reason_codes: current.reason_codes ?? [],
    });
  }

  if (
    previous.detected_vendor
    && !current.detected_vendor
    && current.status !== 'protected'
  ) {
    drifts.push({
      drift_type: 'fingerprint_loss',
      severity: 'high',
      before_summary_json: before,
      after_summary_json: after,
      reason_codes: current.reason_codes ?? [],
    });
  }

  if (previous.status === 'protected' && current.status === 'underprotected') {
    const codes = new Set(current.reason_codes ?? []);
    if (codes.has('origin_bypass_confirmed')) {
      drifts.push({
        drift_type: 'origin_bypass_new',
        severity: 'critical',
        before_summary_json: before,
        after_summary_json: after,
        reason_codes: current.reason_codes ?? [],
      });
    }
    if (codes.has('monitor_only_behavior') || codes.has('rule_mode_changed')) {
      drifts.push({
        drift_type: 'mode_downgrade',
        severity: 'critical',
        before_summary_json: before,
        after_summary_json: after,
        reason_codes: current.reason_codes ?? [],
      });
    }
  }

  return drifts;
}

function findOpenWafDriftEvent(ctx, wafAssetId, driftType) {
  ensureStoreShape();
  return (
    getStore().wafDriftEvents.find(
      (e) =>
        e.tenant_id === ctx.tenantId
        && e.waf_asset_id === wafAssetId
        && e.drift_type === driftType
        && e.status === WAF_DRIFT_OPEN_STATUS,
    ) ?? null
  );
}

function upsertConnectorDriftEvent(ctx, asset, signal, connectorDrift, {
  previousSnapshot,
  currentSnapshot,
}) {
  const modeDowngrade = signal === 'waf_mode_changed'
    && isConnectorModeDowngrade(previousSnapshot, currentSnapshot);
  const driftType = mapConnectorSignalToDriftType(signal, { modeDowngrade });
  const severity = computeDriftSeverity([
    { signal, check_type: driftType },
    ...mapConnectorSignalsToCheckTypes([signal]).map((check_type) => ({ check_type })),
  ]);
  const before = {
    connector_signal: signal,
    field: connectorDrift.field,
    old_value_hash: connectorDrift.old_value_hash,
    resource_ref_hash: previousSnapshot?.resource_ref_hash ?? null,
  };
  const after = {
    connector_signal: signal,
    field: connectorDrift.field,
    new_value_hash: connectorDrift.new_value_hash,
    resource_ref_hash: currentSnapshot?.resource_ref_hash ?? null,
  };
  return upsertDriftEvent(ctx, asset, {
    drift_type: driftType,
    severity,
    before_summary_json: before,
    after_summary_json: after,
    reason_codes: [signal],
  });
}

function upsertDriftEvent(ctx, asset, spec) {
  const now = new Date().toISOString();
  const existing = findOpenWafDriftEvent(ctx, asset.id, spec.drift_type);
  const auditMetadata = {
    waf_asset_id: asset.id,
    drift_type: spec.drift_type,
    severity: spec.severity,
    reason_codes: spec.reason_codes ?? [],
    source: 'waf_drift_worker',
  };

  if (existing) {
    existing.severity = spec.severity;
    existing.after_summary_json = spec.after_summary_json;
    existing.updated_at = now;
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId ?? null,
      actor_role: ctx.role ?? 'system',
      action: 'waf.drift.detected',
      resource_type: 'waf_drift_event',
      resource_id: existing.id,
      metadata: auditMetadata,
    });
    return existing;
  }

  const record = {
    id: newId('id'),
    tenant_id: ctx.tenantId,
    waf_asset_id: asset.id,
    baseline_id: null,
    drift_type: spec.drift_type,
    severity: spec.severity,
    before_summary_json: spec.before_summary_json,
    after_summary_json: spec.after_summary_json,
    status: WAF_DRIFT_OPEN_STATUS,
    finding_id: null,
    created_at: now,
    updated_at: now,
    resolved_at: null,
  };
  getStore().wafDriftEvents.push(record);
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId ?? null,
    actor_role: ctx.role ?? 'system',
    action: 'waf.drift.detected',
    resource_type: 'waf_drift_event',
    resource_id: record.id,
    metadata: auditMetadata,
  });
  return record;
}

function recordScanResult(ctx, result) {
  ensureStoreShape();
  const entry = {
    id: newId('id'),
    ...result,
    created_at: result.completed_at,
  };
  getStore().wafDriftScanResults.push(entry);
  return entry;
}

export function detectAssetDrift(ctx, assetId) {
  const gate = wafFeatureGate();
  if (gate) return gate;

  ensureStoreShape();
  const asset = getStore().wafAssets.find(
    (a) => a.id === assetId && a.tenant_id === ctx.tenantId,
  );
  if (!asset) {
    return { error: 'waf_asset_not_found', status: 404 };
  }

  const drifts = [];
  const checkTypes = new Set();

  const connectorSnapshots = connectorSnapshotsForAsset(ctx, asset);
  const { current: currentConnector, previous: previousConnector } = latestConnectorPair(connectorSnapshots);
  if (currentConnector && previousConnector) {
    const connectorDrifts = detectConnectorConfigDrift(currentConnector, previousConnector);
    for (const connectorDrift of connectorDrifts) {
      const event = upsertConnectorDriftEvent(ctx, asset, connectorDrift.signal, connectorDrift, {
        previousSnapshot: previousConnector,
        currentSnapshot: currentConnector,
      });
      drifts.push(event);
      for (const checkType of mapConnectorSignalsToCheckTypes([connectorDrift])) {
        checkTypes.add(checkType);
      }
      const mappedType = mapConnectorSignalToDriftType(connectorDrift.signal, {
        modeDowngrade: connectorDrift.signal === 'waf_mode_changed'
          && isConnectorModeDowngrade(previousConnector, currentConnector),
      });
      checkTypes.add(mappedType);
    }
  }

  const postureSnapshots = postureSnapshotsForAsset(ctx, asset.id);
  const { current: currentPosture, previous: previousPosture } = latestPosturePair(postureSnapshots);
  const postureDrifts = detectPostureDrifts(previousPosture, currentPosture);
  for (const spec of postureDrifts) {
    const event = upsertDriftEvent(ctx, asset, spec);
    drifts.push(event);
    checkTypes.add(spec.drift_type);
  }

  return {
    waf_asset_id: asset.id,
    drifts_detected: drifts.length,
    drift_events: drifts.map((e) => ({
      id: e.id,
      drift_type: e.drift_type,
      severity: e.severity,
      status: e.status,
    })),
    drift_check_types: [...checkTypes].filter((t) => DRIFT_CHECK_TYPES.includes(t)),
    connector_snapshots_compared: currentConnector && previousConnector ? 1 : 0,
    posture_snapshots_compared: currentPosture && previousPosture ? 1 : 0,
  };
}

export function runDriftScan(ctx) {
  const gate = wafFeatureGate();
  if (gate) return gate;

  const started = Date.now();
  ensureStoreShape();

  const assets = getStore().wafAssets.filter((a) => a.tenant_id === ctx.tenantId);
  let driftsDetected = 0;
  let assetsWithConnectorSnapshots = 0;
  const driftCheckTypes = new Set();

  for (const asset of assets) {
    const outcome = detectAssetDrift(ctx, asset.id);
    if (outcome.error) continue;
    driftsDetected += outcome.drifts_detected ?? 0;
    if ((outcome.connector_snapshots_compared ?? 0) > 0) {
      assetsWithConnectorSnapshots += 1;
    }
    for (const checkType of outcome.drift_check_types ?? []) {
      driftCheckTypes.add(checkType);
    }
  }

  const completedAt = new Date().toISOString();
  const scanResult = createDriftScanResult({
    tenant_id: ctx.tenantId,
    scan_type: 'connector_config_change',
    assets_scanned: assets.length,
    drifts_detected: driftsDetected,
    scan_duration_ms: Date.now() - started,
    completed_at: completedAt,
    state: 'completed',
    assets_with_connector_snapshots: assetsWithConnectorSnapshots,
    drift_check_types: [...driftCheckTypes],
  });

  recordScanResult(ctx, scanResult);
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId ?? null,
    actor_role: ctx.role ?? 'system',
    action: 'waf.drift_scan.completed',
    resource_type: 'waf_drift_scan',
    resource_id: scanResult.tenant_id,
    metadata: {
      assets_scanned: scanResult.assets_scanned,
      drifts_detected: scanResult.drifts_detected,
      scan_duration_ms: scanResult.scan_duration_ms,
      drift_check_types: scanResult.drift_check_types ?? [],
    },
  });
  persistStore();

  return { scan_result: scanResult };
}

export function runScheduledDriftScans(ctx = {}) {
  const gate = wafFeatureGate();
  if (gate) return gate;

  ensureStoreShape();
  const tenantIds = [...new Set(getStore().wafAssets.map((a) => a.tenant_id).filter(Boolean))];
  const results = [];

  for (const tenantId of tenantIds) {
    const tenantCtx = {
      tenantId,
      userId: ctx.userId ?? 'system',
      role: ctx.role ?? 'system',
    };
    const outcome = runDriftScan(tenantCtx);
    if (outcome.skipped) return outcome;
    results.push(outcome.scan_result);
  }

  return {
    tenants_scanned: tenantIds.length,
    scan_results: results,
  };
}

export function getLastScanResult(ctx) {
  const gate = wafFeatureGate();
  if (gate) return gate;

  ensureStoreShape();
  const results = getStore()
    .wafDriftScanResults.filter((r) => r.tenant_id === ctx.tenantId)
    .sort((a, b) => String(b.completed_at).localeCompare(String(a.completed_at)));

  if (results.length === 0) return { scan_result: null };
  return { scan_result: results[0] };
}