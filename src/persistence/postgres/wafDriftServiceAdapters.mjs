import { loadRuntimeConfig } from '../../config.mjs';
import {
  computeDriftSeverity,
  createDriftScanResult,
  detectConnectorConfigDrift,
  DRIFT_CHECK_TYPES,
  mapConnectorSignalToDriftType,
  mapConnectorSignalsToCheckTypes,
} from '../../contracts/wafDriftWorker.mjs';
import { newId } from '../../lib/ids.mjs';
import { redactObject } from '../../lib/redact.mjs';
import { resolveScheduledTenantIds } from '../../lib/scheduledTenantScope.mjs';

/** @type {readonly string[]} */
export const WAF_DRIFT_REPOSITORY_METHODS = Object.freeze([
  'listWafAssets',
  'listWafConnectorSnapshotsForTenant',
  'listWafPostureSnapshotsForTenant',
  'upsertWafDriftEvent',
  'createWafDriftScanResult',
  'getLatestWafDriftScanResult',
]);

/** @type {readonly string[]} */
export const POSTGRES_WAF_DRIFT_SERVICE_METHODS = Object.freeze([
  'runDriftScan',
  'getLastScanResult',
  'runScheduledDriftScans',
]);

const WAF_DRIFT_OPEN_STATUS = 'open';
const BLOCKING_POLICY_MODES = new Set(['blocking', 'block', 'prevention', 'on', 'enabled']);
const MONITOR_POLICY_MODES = new Set(['monitor', 'detect', 'log', 'log_only', 'simulate', 'count']);

function assertWafDriftRepositories(repositories) {
  const wafPosture = repositories?.wafPosture;
  if (!wafPosture || typeof wafPosture !== 'object') {
    throw new Error('Postgres WAF drift service adapter requires repositories.wafPosture.');
  }
  for (const method of WAF_DRIFT_REPOSITORY_METHODS) {
    if (typeof wafPosture[method] !== 'function') {
      throw new Error(`Postgres WAF drift service adapter requires wafPosture.${method}().`);
    }
  }

  const audit = repositories?.audit;
  if (!audit || typeof audit.appendAuditEvent !== 'function') {
    throw new Error('Postgres WAF drift service adapter requires audit.appendAuditEvent().');
  }
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

function connectorSnapshotsForAsset(ctx, asset, connectorSnapshots) {
  const hostname = hostnameFromAsset(asset);
  if (!hostname) return [];

  return connectorSnapshots
    .filter((snap) => {
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

function postureSnapshotsForAsset(ctx, assetId, postureSnapshots) {
  return postureSnapshots
    .filter((s) => s.tenant_id === ctx.tenantId && s.waf_asset_id === assetId)
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

function formatScanResultForApi(scanResult) {
  if (!scanResult) return null;
  return {
    tenant_id: scanResult.tenant_id,
    scan_type: scanResult.scan_type,
    assets_scanned: scanResult.assets_scanned,
    drifts_detected: scanResult.drifts_detected,
    scan_duration_ms: scanResult.scan_duration_ms,
    completed_at: scanResult.completed_at,
    state: scanResult.state,
    ...(scanResult.assets_with_connector_snapshots == null
      ? {}
      : { assets_with_connector_snapshots: scanResult.assets_with_connector_snapshots }),
    ...(Array.isArray(scanResult.drift_check_types) && scanResult.drift_check_types.length > 0
      ? { drift_check_types: scanResult.drift_check_types }
      : {}),
  };
}

/**
 * @param {{
 *   wafPosture?: Record<string, unknown>,
 *   audit?: { appendAuditEvent?: (...args: unknown[]) => unknown },
 * }} repositories
 * @param {{ now?: () => Date, newId?: typeof newId }} [options]
 */
export function createPostgresWafDriftServices(repositories, options = {}) {
  assertWafDriftRepositories(repositories);
  const wafRepo = repositories.wafPosture;
  const auditRepo = repositories.audit;
  const nowFn = options.now ?? (() => new Date());
  const newIdFn = options.newId ?? newId;

  async function auditDriftDetected(ctx, driftEvent, metadata) {
    await auditRepo.appendAuditEvent({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId ?? null,
      actor_role: ctx.role ?? 'system',
      action: 'waf.drift.detected',
      resource_type: 'waf_drift_event',
      resource_id: driftEvent.id,
      metadata: redactObject(metadata),
    });
  }

  async function upsertDriftEvent(ctx, asset, spec) {
    const now = nowFn().toISOString();
    const driftId = newIdFn('id');
    const upsertResult = await wafRepo.upsertWafDriftEvent(ctx, {
      id: driftId,
      waf_asset_id: asset.id,
      drift_type: spec.drift_type,
      severity: spec.severity,
      before_summary: spec.before_summary_json,
      after_summary: spec.after_summary_json,
      status: WAF_DRIFT_OPEN_STATUS,
      finding_id: null,
      created_at: now,
    });
    const driftEvent = upsertResult.drift_event;
    await auditDriftDetected(ctx, driftEvent, {
      waf_asset_id: asset.id,
      drift_type: spec.drift_type,
      severity: spec.severity,
      reason_codes: spec.reason_codes ?? [],
      source: 'waf_drift_worker',
    });
    return driftEvent;
  }

  async function upsertConnectorDriftEvent(ctx, asset, signal, connectorDrift, {
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

  async function detectAssetDrift(ctx, assetId, {
    connectorSnapshots = null,
    postureSnapshots = null,
  } = {}) {
    const gate = wafFeatureGate();
    if (gate) return gate;

    const asset = (await wafRepo.listWafAssets(ctx)).find((row) => row.id === assetId) ?? null;
    if (!asset) {
      return { error: 'waf_asset_not_found', status: 404 };
    }

    const tenantConnectorSnapshots = connectorSnapshots
      ?? await wafRepo.listWafConnectorSnapshotsForTenant(ctx);
    const tenantPostureSnapshots = postureSnapshots
      ?? await wafRepo.listWafPostureSnapshotsForTenant(ctx);

    const drifts = [];
    const checkTypes = new Set();

    const assetConnectorSnapshots = connectorSnapshotsForAsset(ctx, asset, tenantConnectorSnapshots);
    const { current: currentConnector, previous: previousConnector } = latestConnectorPair(assetConnectorSnapshots);
    if (currentConnector && previousConnector) {
      const connectorDrifts = detectConnectorConfigDrift(currentConnector, previousConnector);
      for (const connectorDrift of connectorDrifts) {
        const event = await upsertConnectorDriftEvent(ctx, asset, connectorDrift.signal, connectorDrift, {
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

    const assetPostureSnapshots = postureSnapshotsForAsset(ctx, asset.id, tenantPostureSnapshots);
    const { current: currentPosture, previous: previousPosture } = latestPosturePair(assetPostureSnapshots);
    const postureDrifts = detectPostureDrifts(previousPosture, currentPosture);
    for (const spec of postureDrifts) {
      const event = await upsertDriftEvent(ctx, asset, spec);
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

  async function runDriftScan(ctx) {
      const gate = wafFeatureGate();
      if (gate) return gate;

      const started = Date.now();
      const assets = await wafRepo.listWafAssets(ctx);
      const connectorSnapshots = await wafRepo.listWafConnectorSnapshotsForTenant(ctx);
      const postureSnapshots = await wafRepo.listWafPostureSnapshotsForTenant(ctx);

      let driftsDetected = 0;
      let assetsWithConnectorSnapshots = 0;
      const driftCheckTypes = new Set();

      for (const asset of assets) {
        const outcome = await detectAssetDrift(ctx, asset.id, {
          connectorSnapshots,
          postureSnapshots,
        });
        if (outcome.error) continue;
        driftsDetected += outcome.drifts_detected ?? 0;
        if ((outcome.connector_snapshots_compared ?? 0) > 0) {
          assetsWithConnectorSnapshots += 1;
        }
        for (const checkType of outcome.drift_check_types ?? []) {
          driftCheckTypes.add(checkType);
        }
      }

      const completedAt = nowFn().toISOString();
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

      await wafRepo.createWafDriftScanResult(ctx, {
        id: newIdFn('id'),
        ...scanResult,
        created_at: completedAt,
      });

      await auditRepo.appendAuditEvent({
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId ?? null,
        actor_role: ctx.role ?? 'system',
        action: 'waf.drift_scan.completed',
        resource_type: 'waf_drift_scan',
        resource_id: scanResult.tenant_id,
        metadata: redactObject({
          assets_scanned: scanResult.assets_scanned,
          drifts_detected: scanResult.drifts_detected,
          scan_duration_ms: scanResult.scan_duration_ms,
          drift_check_types: scanResult.drift_check_types ?? [],
        }),
      });

      return { scan_result: scanResult };
  }

  async function runScheduledDriftScans(ctx = {}) {
    const gate = wafFeatureGate();
    if (gate) return gate;

    const scope = resolveScheduledTenantIds(ctx, { label: 'WAF drift scan runner' });
    if ('error' in scope) return scope;

    const tenantIds = scope.tenantIds;
    const results = [];

    for (const tenantId of tenantIds) {
      const tenantCtx = {
        tenantId,
        userId: ctx.userId ?? 'system',
        role: ctx.role ?? 'system',
      };
      const outcome = await runDriftScan(tenantCtx);
      if (outcome.skipped) return outcome;
      results.push(outcome.scan_result);
    }

    return {
      tenants_scanned: tenantIds.length,
      scan_results: results,
    };
  }

  async function getLastScanResult(ctx) {
      const gate = wafFeatureGate();
      if (gate) return gate;

      const latest = await wafRepo.getLatestWafDriftScanResult(ctx);
      if (!latest) return { scan_result: null };
      return { scan_result: formatScanResultForApi(latest) };
  }

  return {
    detectAssetDrift,
    runDriftScan,
    runScheduledDriftScans,
    getLastScanResult,
  };
}