import {
  audit,
  getLatestChainedAuditEntry,
  getLatestChainedAuditEntryForTenant,
} from '../audit.mjs';
import {
  ACTION_ITEM_STATUSES,
  assertNoRawWafEvidence,
  buildSiemEventPayload,
  classifyWafPosture,
  createActionItem,
  deriveControlBypassStatus,
  extractFindingRemediationContext,
  formatControlBypassUxLabel,
  mapReasonCodesToControlBypassClasses,
  normalizeScenarioIntakeInput,
  normalizeWafAssetInput,
  normalizeWafEvidenceSummary,
  normalizeWafExceptionBody,
  normalizeSocOffensiveWafValidationRequest,
  normalizeWafValidationRequest,
  REMEDIATION_CONNECTOR_TYPES,
  validateActionItem,
  WAF_EXPECTED_ACTIONS,
  WAF_SCENARIO_FAMILIES,
  WAF_SCENARIO_INTAKE_STAGES,
} from '../contracts/wafPosture.mjs';
import {
  seedWafProductsIfEmpty,
  summarizeWafProductCatalog,
} from '../lib/wafProductCatalog.mjs';
import {
  buildProviderPollFailure,
  executeConnectorProviderPoll,
  shouldAttemptOutboundConnectorPoll,
} from '../lib/connectorProviders/pollWorker.mjs';
import { supportsOutboundProviderPoll } from '../lib/connectorProviders/index.mjs';
import { paginateItems } from '../lib/cursorPagination.mjs';
import { computeWafCoverageSummaryRow, mapWafCoverageSummaryRow } from '../lib/wafCoverageSummary.mjs';
import { markFindingRemediationDelivered } from './remediation.mjs';
import { newId } from '../lib/ids.mjs';
import { loadSecretEncryptionKey } from '../lib/secrets.mjs';
import {
  buildWafReportPayload,
  custodyAuditMetadata,
  normalizeWafReportKind,
  prepareWafReportExport,
  WAF_REPORT_DRIFT_LIMIT,
  WAF_REPORT_KINDS,
} from '../lib/wafReports.mjs';
import { getStore, persistStore } from '../store.mjs';
import {
  executeRemediationDelivery,
  normalizeRemediationDeliverChannel,
  resolveRemediationConnectorType,
} from '../lib/remediationDelivery.mjs';
import { emitNotification } from './notifications.mjs';
import { decryptEncryptedSecretForUse } from './secretVault.mjs';
import {
  booleanFieldExplicit,
  deriveWafSignalsFromBoundEvents,
} from '../lib/wafBoundRunCorrelation.mjs';
import {
  buildCorroborationFromEvents,
  buildWafEvidenceCorroboration,
  protectedFinalizeEvidenceRequired,
  stripClientAssertedAgentEvidence,
} from '../lib/wafProtectedEvidence.mjs';
import {
  buildCoverageSummary,
  buildCriticalityRollup,
  buildEntityRollup,
  buildGeographyRollup,
  buildRiskRoadmap,
  buildVendorBreakdown,
  buildVendorConsolidation,
} from './wafCoverageService.mjs';
import {
  computeAssetRiskAssessment,
  enrichSnapshotWithRisk,
} from './wafRiskService.mjs';

const PATCHABLE_ASSET_FIELDS = new Set([
  'target_id',
  'asset_kind',
  'expected_vendor_hint',
  'business_criticality',
  'traffic_tier',
  'compliance_tags',
  'owner_hint',
  'expected_waf_required',
  'canonical_url',
  'hostname',
]);

function ensureStoreShape() {
  const store = getStore();
  const keys = [
    'wafAssets',
    'wafProducts',
    'wafScenarioIntakes',
    'wafValidationRuns',
    'wafScenarioResults',
    'wafPostureSnapshots',
    'wafDriftEvents',
    'wafExceptions',
    'wafCoverageDailyRollups',
    'wafConnectors',
    'wafConnectorSnapshots',
    'wafActionItems',
    'cvePipelineItems',
    'cveAssetMatches',
  ];
  for (const key of keys) {
    if (!Array.isArray(store[key])) store[key] = [];
  }
  seedWafProductsIfEmpty(store);
  return store;
}

function contractError(err, fallbackStatus = 400) {
  return {
    error: err.code ?? 'invalid_request',
    status: fallbackStatus,
    message: err.message,
  };
}

function findAsset(ctx, id) {
  ensureStoreShape();
  return getStore().wafAssets.find((a) => a.id === id && a.tenant_id === ctx.tenantId) ?? null;
}

function findValidationRun(ctx, id) {
  ensureStoreShape();
  return getStore().wafValidationRuns.find((r) => r.id === id && r.tenant_id === ctx.tenantId) ?? null;
}

function getCurrentSnapshot(ctx, wafAssetId) {
  ensureStoreShape();
  const snaps = getStore().wafPostureSnapshots.filter(
    (s) => s.tenant_id === ctx.tenantId && s.waf_asset_id === wafAssetId && s.is_current,
  );
  if (snaps.length === 0) return null;
  return snaps.sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)))[0];
}

function targetGroupExists(ctx, targetGroupId) {
  return getStore().targetGroups.some(
    (g) => g.id === targetGroupId && g.tenant_id === ctx.tenantId,
  );
}

function findTenantTestRun(ctx, testRunId) {
  return (
    getStore().testRuns.find((r) => r.id === testRunId && r.tenant_id === ctx.tenantId) ?? null
  );
}

function validateTestRunBinding(ctx, testRunId, asset) {
  const testRun = findTenantTestRun(ctx, testRunId);
  if (!testRun) {
    return {
      error: 'test_run_not_found',
      status: 404,
      message: 'test_run_id not found for tenant.',
    };
  }
  if (testRun.target_group_id !== asset.target_group_id) {
    return {
      error: 'invalid_request',
      status: 400,
      message: 'test_run_id target group does not match WAF asset target group.',
    };
  }
  return { testRun };
}

function probeEventsForRun(ctx, testRunId) {
  return getStore().events.filter(
    (e) =>
      e.tenant_id === ctx.tenantId
      && e.test_run_id === testRunId
      && e.signal_type === 'probe_result',
  );
}

function agentObservationsForRun(ctx, testRunId) {
  return getStore().events.filter(
    (e) =>
      e.tenant_id === ctx.tenantId
      && e.test_run_id === testRunId
      && e.signal_type === 'agent_observation',
  );
}

function deriveWafSignalsFromBoundRun(ctx, testRunId) {
  return deriveWafSignalsFromBoundEvents({
    probes: probeEventsForRun(ctx, testRunId),
    agents: agentObservationsForRun(ctx, testRunId),
  });
}

const WAF_POSTURE_REMEDIATION_TEMPLATE = 'waf_posture_remediation';
const HIGH_BUSINESS_CRITICALITY = new Set(['critical', 'high']);

function wafPostureCheckId(wafAssetId) {
  return `waf.posture.${wafAssetId}`;
}

function assetTargetIdForFinding(asset) {
  return typeof asset.target_id === 'string' && asset.target_id.trim()
    ? asset.target_id.trim()
    : null;
}

function findingTargetIdMatches(findingTargetId, assetTargetId) {
  const normalizedAsset = assetTargetId ?? null;
  const normalizedFinding = findingTargetId ?? null;
  return normalizedFinding === normalizedAsset;
}

function isHighBusinessCriticality(asset) {
  const tier = String(asset.business_criticality ?? '').trim().toLowerCase();
  return HIGH_BUSINESS_CRITICALITY.has(tier);
}

function wafPostureFindingSeverity({ postureStatus, reasonCodes, asset }) {
  const codes = new Set(reasonCodes ?? []);
  if (postureStatus === 'unprotected') {
    return isHighBusinessCriticality(asset) ? 'critical' : 'high';
  }
  if (postureStatus === 'underprotected') {
    if (codes.has('origin_bypass_confirmed')) return 'critical';
    return isHighBusinessCriticality(asset) ? 'high' : 'medium';
  }
  return 'medium';
}

function wafPostureFindingTitle({ postureStatus, canonicalUrl }) {
  const url = typeof canonicalUrl === 'string' && canonicalUrl.trim()
    ? canonicalUrl.trim()
    : 'declared asset';
  return `WAF posture ${postureStatus}: ${url}`;
}

function wafPostureFindingNotes({
  postureStatus,
  reasonCodes,
  wafAssetId,
  wafValidationRunId,
  lastWafValidationRunId,
}) {
  const codes = (reasonCodes ?? []).filter(Boolean).join(', ') || 'none';
  const lines = [
    `Posture status: ${postureStatus}.`,
    `Reason codes: ${codes}.`,
    `WAF asset id: ${wafAssetId}.`,
    `WAF validation run id: ${wafValidationRunId}.`,
    `Last WAF validation run id: ${lastWafValidationRunId}.`,
    'Retest: run a safe marker validation after WAF rule or edge changes.',
  ];
  return lines.join(' ');
}

function findOpenWafPostureFinding(ctx, asset) {
  const checkId = wafPostureCheckId(asset.id);
  const targetId = assetTargetIdForFinding(asset);
  return (
    getStore().findings.find(
      (f) =>
        f.tenant_id === ctx.tenantId
        && f.target_group_id === asset.target_group_id
        && findingTargetIdMatches(f.target_id, targetId)
        && f.check_id === checkId
        && f.status === 'open',
    ) ?? null
  );
}

function upsertWafPostureFinding(ctx, {
  asset,
  validationRun,
  classification,
  snapshotId,
  scenarioResultIds,
}) {
  const postureStatus = classification.status;
  if (postureStatus !== 'underprotected' && postureStatus !== 'unprotected') {
    return null;
  }

  const checkId = wafPostureCheckId(asset.id);
  const targetId = assetTargetIdForFinding(asset);
  const boundTestRunId =
    typeof validationRun.test_run_id === 'string' && validationRun.test_run_id.trim()
      ? validationRun.test_run_id.trim()
      : null;
  const evidenceIds = [
    ...scenarioResultIds,
    ...(snapshotId ? [snapshotId] : []),
  ].filter(Boolean);
  const severity = wafPostureFindingSeverity({
    postureStatus,
    reasonCodes: classification.reason_codes,
    asset,
  });
  const title = wafPostureFindingTitle({
    postureStatus,
    canonicalUrl: asset.canonical_url,
  });
  const notes = wafPostureFindingNotes({
    postureStatus,
    reasonCodes: classification.reason_codes,
    wafAssetId: asset.id,
    wafValidationRunId: validationRun.id,
    lastWafValidationRunId: validationRun.id,
  });

  const auditMetadata = {
    waf_asset_id: asset.id,
    waf_validation_run_id: validationRun.id,
    posture_status: postureStatus,
    reason_codes: classification.reason_codes ?? [],
  };

  const existing = findOpenWafPostureFinding(ctx, asset);
  const now = new Date().toISOString();
  if (existing) {
    existing.last_waf_validation_run_id = validationRun.id;
    existing.test_run_id = boundTestRunId;
    existing.severity = severity;
    existing.notes = notes;
    existing.evidence_ids = evidenceIds;
    existing.remediation_template = WAF_POSTURE_REMEDIATION_TEMPLATE;
    existing.title = title;
    existing.updated_at = now;
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'finding.updated',
      resource_type: 'finding',
      resource_id: existing.id,
      metadata: auditMetadata,
    });
    return existing;
  }

  const finding = {
    id: newId('finding'),
    tenant_id: ctx.tenantId,
    target_group_id: asset.target_group_id,
    target_id: targetId,
    check_id: checkId,
    test_run_id: boundTestRunId,
    last_waf_validation_run_id: validationRun.id,
    title,
    severity,
    status: 'open',
    assignee: null,
    notes,
    evidence_ids: evidenceIds,
    remediation_template: WAF_POSTURE_REMEDIATION_TEMPLATE,
    verdict_id: null,
    last_verdict_id: null,
    created_at: now,
    updated_at: now,
  };
  getStore().findings.push(finding);
  if (['high', 'critical'].includes(finding.severity)) {
    emitNotification(ctx, {
      trigger: 'finding.high_severity',
      subject: finding.title,
      metadata: { finding_id: finding.id, severity: finding.severity },
    });
  }
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'finding.created',
    resource_type: 'finding',
    resource_id: finding.id,
    metadata: auditMetadata,
  });
  return finding;
}

const WAF_DRIFT_OPEN_STATUS = 'open';
const WAF_DRIFT_TERMINAL_STATUSES = new Set(['resolved', 'accepted_risk', 'false_positive']);
const WAF_DRIFT_PATCHABLE_STATUSES = new Set([
  'open',
  'acknowledged',
  'remediation_started',
  'retest_pending',
  'resolved',
  'accepted_risk',
  'false_positive',
]);

function postureSummaryFromSnapshot(snapshot) {
  if (!snapshot) return {};
  return {
    status: snapshot.status,
    reason_codes: snapshot.reason_codes ?? [],
    ...(snapshot.detected_vendor ? { detected_vendor: snapshot.detected_vendor } : {}),
    ...(snapshot.detected_product ? { detected_product: snapshot.detected_product } : {}),
  };
}

function postureSummaryAfter(classification, wafDetected) {
  return {
    status: classification.status,
    reason_codes: classification.reason_codes ?? [],
    waf_detected: wafDetected,
  };
}

function computeWafDriftSpecs({
  previous,
  classification,
  wafDetected,
  asset,
}) {
  if (!previous || previous.status !== 'protected') return [];

  const newStatus = classification.status;
  const codes = new Set(classification.reason_codes ?? []);
  const before = postureSummaryFromSnapshot(previous);
  const after = postureSummaryAfter(classification, wafDetected);
  const specs = [];

  if (newStatus === 'unprotected') {
    const drift_type = wafDetected ? 'mode_change' : 'fingerprint_lost';
    specs.push({
      drift_type,
      severity: 'critical',
      before_summary_json: before,
      after_summary_json: after,
      reason_codes: classification.reason_codes ?? [],
    });
  }

  if (newStatus === 'underprotected') {
    if (codes.has('origin_bypass_confirmed')) {
      specs.push({
        drift_type: 'origin_bypass_new',
        severity: 'critical',
        before_summary_json: before,
        after_summary_json: after,
        reason_codes: classification.reason_codes ?? [],
      });
    }
    if (codes.has('marker_rule_not_blocking')) {
      specs.push({
        drift_type: 'marker_failed',
        severity: isHighBusinessCriticality(asset) ? 'critical' : 'high',
        before_summary_json: before,
        after_summary_json: after,
        reason_codes: classification.reason_codes ?? [],
      });
    }
    if (codes.has('monitor_only_behavior')) {
      specs.push({
        drift_type: 'mode_change',
        severity: isHighBusinessCriticality(asset) ? 'critical' : 'high',
        before_summary_json: before,
        after_summary_json: after,
        reason_codes: classification.reason_codes ?? [],
      });
    }
  }

  if (newStatus === 'unknown' && !wafDetected) {
    specs.push({
      drift_type: 'fingerprint_lost',
      severity: isHighBusinessCriticality(asset) ? 'high' : 'medium',
      before_summary_json: before,
      after_summary_json: after,
      reason_codes: classification.reason_codes ?? [],
    });
  }

  return specs;
}

function activeDriftTypesForPosture(classification, wafDetected) {
  const newStatus = classification.status;
  const codes = new Set(classification.reason_codes ?? []);
  const types = [];

  if (newStatus === 'unprotected') {
    types.push(wafDetected ? 'mode_change' : 'fingerprint_lost');
  }
  if (newStatus === 'underprotected') {
    if (codes.has('origin_bypass_confirmed')) types.push('origin_bypass_new');
    if (codes.has('marker_rule_not_blocking')) types.push('marker_failed');
    if (codes.has('monitor_only_behavior')) types.push('mode_change');
  }
  if (newStatus === 'unknown' && !wafDetected) {
    types.push('fingerprint_lost');
  }
  return types;
}

function refreshOpenWafDriftEvents(ctx, {
  asset,
  classification,
  wafDetected,
  finding,
}) {
  const after = postureSummaryAfter(classification, wafDetected);
  const now = new Date().toISOString();
  const refreshed = [];

  for (const driftType of activeDriftTypesForPosture(classification, wafDetected)) {
    const existing = findOpenWafDriftEvent(ctx, asset.id, driftType);
    if (!existing) continue;

    let severity = existing.severity;
    if (driftType === 'marker_failed') {
      severity = isHighBusinessCriticality(asset) ? 'critical' : 'high';
    } else if (driftType === 'origin_bypass_new') {
      severity = 'critical';
    } else if (driftType === 'mode_change' && classification.status === 'underprotected') {
      severity = isHighBusinessCriticality(asset) ? 'critical' : 'high';
    } else if (driftType === 'fingerprint_lost' && classification.status === 'unknown') {
      severity = isHighBusinessCriticality(asset) ? 'high' : 'medium';
    }

    existing.severity = severity;
    existing.after_summary_json = after;
    existing.finding_id = finding?.id ?? existing.finding_id ?? null;
    existing.updated_at = now;
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'waf.drift.detected',
      resource_type: 'waf_drift_event',
      resource_id: existing.id,
      metadata: {
        waf_asset_id: asset.id,
        drift_type: driftType,
        severity,
        posture_from: existing.before_summary_json?.status ?? null,
        posture_to: classification.status,
        reason_codes: classification.reason_codes ?? [],
      },
    });
    refreshed.push(existing);
  }

  return refreshed;
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

function upsertWafDriftEvents(ctx, {
  asset,
  previous,
  classification,
  wafDetected,
  finding,
}) {
  const specs = computeWafDriftSpecs({
    previous,
    classification,
    wafDetected,
    asset,
  });
  if (specs.length === 0) {
    return refreshOpenWafDriftEvents(ctx, {
      asset,
      classification,
      wafDetected,
      finding,
    });
  }

  const now = new Date().toISOString();
  const postureFrom = previous?.status ?? null;
  const postureTo = classification.status;
  const upserted = [];

  for (const spec of specs) {
    const auditBase = {
      waf_asset_id: asset.id,
      drift_type: spec.drift_type,
      severity: spec.severity,
      posture_from: postureFrom,
      posture_to: postureTo,
      reason_codes: spec.reason_codes,
    };

    const existing = findOpenWafDriftEvent(ctx, asset.id, spec.drift_type);
    if (existing) {
      existing.severity = spec.severity;
      existing.after_summary_json = spec.after_summary_json;
      existing.finding_id = finding?.id ?? existing.finding_id ?? null;
      existing.updated_at = now;
      audit({
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId,
        actor_role: ctx.role,
        action: 'waf.drift.detected',
        resource_type: 'waf_drift_event',
        resource_id: existing.id,
        metadata: auditBase,
      });
      upserted.push(existing);
      continue;
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
      finding_id: finding?.id ?? null,
      created_at: now,
      updated_at: now,
      resolved_at: null,
    };
    getStore().wafDriftEvents.push(record);
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'waf.drift.detected',
      resource_type: 'waf_drift_event',
      resource_id: record.id,
      metadata: auditBase,
    });
    if (['high', 'critical'].includes(record.severity)) {
      emitNotification(ctx, {
        trigger: 'finding.high_severity',
        subject: `WAF drift ${record.drift_type}: ${asset.canonical_url ?? asset.id}`,
        metadata: {
          waf_asset_id: asset.id,
          drift_type: record.drift_type,
          severity: record.severity,
          drift_event_id: record.id,
        },
      });
    }
    upserted.push(record);
  }

  return upserted;
}

export function formatWafDriftEvent(record) {
  return {
    id: record.id,
    waf_asset_id: record.waf_asset_id,
    drift_type: record.drift_type,
    severity: record.severity,
    status: record.status,
    before_summary: record.before_summary_json ?? {},
    after_summary: record.after_summary_json ?? {},
    finding_id: record.finding_id ?? null,
    created_at: record.created_at,
    ...(record.updated_at ? { updated_at: record.updated_at } : {}),
    ...(record.resolved_at ? { resolved_at: record.resolved_at } : {}),
    ...(typeof record.notes === 'string' && record.notes.trim()
      ? { notes: record.notes.trim() }
      : {}),
  };
}

export function listWafDriftEvents(ctx, options = {}) {
  ensureStoreShape();
  const events = getStore()
    .wafDriftEvents.filter((e) => e.tenant_id === ctx.tenantId)
    .sort((a, b) => String(b.created_at ?? '').localeCompare(String(a.created_at ?? '')));
  const limit = Number.isFinite(Number(options.limit)) && Number(options.limit) > 0
    ? Math.floor(Number(options.limit))
    : null;
  const sliced = limit ? events.slice(0, limit) : events;
  return sliced.map((e) => formatWafDriftEvent(e));
}

export function patchWafDriftEvent(ctx, id, body = {}) {
  ensureStoreShape();
  try {
    assertNoRawWafEvidence(body);
  } catch (err) {
    return contractError(err);
  }

  const record = getStore().wafDriftEvents.find(
    (e) => e.id === id && e.tenant_id === ctx.tenantId,
  );
  if (!record) {
    return { error: 'waf_drift_event_not_found', status: 404 };
  }

  const nextStatus =
    typeof body.status === 'string' ? body.status.trim() : '';
  if (!nextStatus || !WAF_DRIFT_PATCHABLE_STATUSES.has(nextStatus)) {
    return {
      error: 'invalid_request',
      status: 400,
      message: 'status must be a supported WAF drift workflow state.',
    };
  }

  const now = new Date().toISOString();
  const previousStatus = record.status;
  record.status = nextStatus;
  record.updated_at = now;
  if (typeof body.notes === 'string' && body.notes.trim()) {
    record.notes = body.notes.trim();
  }
  if (WAF_DRIFT_TERMINAL_STATUSES.has(nextStatus)) {
    record.resolved_at = now;
  } else {
    record.resolved_at = null;
  }

  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'waf.drift.updated',
    resource_type: 'waf_drift_event',
    resource_id: record.id,
    metadata: {
      waf_asset_id: record.waf_asset_id,
      drift_type: record.drift_type,
      previous_status: previousStatus,
      status: nextStatus,
    },
  });
  persistStore();
  return { drift_event: formatWafDriftEvent(record) };
}

export function listWafAssets(ctx) {
  ensureStoreShape();
  return getStore().wafAssets.filter((a) => a.tenant_id === ctx.tenantId);
}

export function createWafAsset(ctx, body) {
  ensureStoreShape();
  try {
    assertNoRawWafEvidence(body);
    const normalized = normalizeWafAssetInput(body);
    if (!targetGroupExists(ctx, normalized.target_group_id)) {
      return { error: 'waf_asset_not_found', status: 404, message: 'Target group not found for tenant.' };
    }
    const id = newId('id');
    const now = new Date().toISOString();
    const record = {
      id,
      tenant_id: ctx.tenantId,
      ...normalized,
      created_at: now,
      updated_at: now,
    };
    getStore().wafAssets.push(record);
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'waf.asset.created',
      resource_type: 'waf_asset',
      resource_id: id,
      metadata: {
        target_group_id: record.target_group_id,
        ...(record.target_id ? { target_id: record.target_id } : {}),
      },
    });
    persistStore();
    return { asset: record };
  } catch (err) {
    return contractError(err);
  }
}

function buildAssetEffectiveness(ctx, assetId, reasonCodes = []) {
  const codes = Array.isArray(reasonCodes) ? reasonCodes : [];
  const bypassClasses = mapReasonCodesToControlBypassClasses(codes);
  const control_bypass_status = deriveControlBypassStatus({ reason_codes: codes });
  const validationSummary = latestValidationSummaryByAsset(ctx).get(assetId) ?? {};
  const scenario_pass_rate = typeof validationSummary.scenario_pass_rate === 'number'
    ? validationSummary.scenario_pass_rate
    : null;
  return {
    scenario_pass_rate,
    control_bypass_status,
    control_bypass_label: formatControlBypassUxLabel(control_bypass_status),
    control_bypass_classes: bypassClasses.map((bypassClass) => ({
      id: bypassClass.id,
      label: bypassClass.label,
    })),
  };
}

export function getWafAsset(ctx, id) {
  const asset = findAsset(ctx, id);
  if (!asset) return null;
  const current = getCurrentSnapshot(ctx, id);
  const reasonCodes = current?.reason_codes ?? [];
  return {
    asset,
    ...(current ? { current_posture: formatSnapshot(current) } : {}),
    effectiveness: buildAssetEffectiveness(ctx, id, reasonCodes),
  };
}

function formatSnapshot(snapshot) {
  return {
    id: snapshot.id,
    waf_asset_id: snapshot.waf_asset_id,
    status: snapshot.status,
    reason_codes: snapshot.reason_codes ?? [],
    detected_vendor: snapshot.detected_vendor ?? null,
    detected_product: snapshot.detected_product ?? null,
    coverage_required: snapshot.coverage_required,
    risk_score: snapshot.risk_score,
    ...(Array.isArray(snapshot.risk_factors_json) ? { risk_factors: snapshot.risk_factors_json } : {}),
    ...(snapshot.priority_band ? { priority_band: snapshot.priority_band } : {}),
    ...(snapshot.recommended_action ? { recommended_action: snapshot.recommended_action } : {}),
    confidence: snapshot.confidence,
    source_mix: snapshot.source_mix_json ?? {},
    created_at: snapshot.created_at,
    is_current: snapshot.is_current,
  };
}

function currentSnapshotsByAsset(ctx) {
  ensureStoreShape();
  const map = new Map();
  for (const asset of listWafAssets(ctx)) {
    const snapshot = getCurrentSnapshot(ctx, asset.id);
    if (snapshot) map.set(asset.id, snapshot);
  }
  return map;
}

function latestValidationSummaryByAsset(ctx) {
  const byAsset = new Map();
  const runs = getStore()
    .wafValidationRuns.filter(
      (run) => run.tenant_id === ctx.tenantId && run.status === 'finalized',
    )
    .sort((a, b) => String(b.finalized_at ?? '').localeCompare(String(a.finalized_at ?? '')));
  for (const run of runs) {
    if (!byAsset.has(run.waf_asset_id)) {
      byAsset.set(run.waf_asset_id, run.summary_json ?? {});
    }
  }
  return byAsset;
}

function cveMatchesByAsset(ctx) {
  const byAsset = new Map();
  for (const match of getStore().cveAssetMatches ?? []) {
    if (match.tenant_id !== ctx.tenantId || !match.waf_asset_id) continue;
    const rows = byAsset.get(match.waf_asset_id) ?? [];
    rows.push(match);
    byAsset.set(match.waf_asset_id, rows);
  }
  return byAsset;
}

function findingsByAsset(ctx) {
  const byAsset = new Map();
  for (const finding of getStore().findings ?? []) {
    if (finding.tenant_id !== ctx.tenantId) continue;
    const checkId = finding.check_id ?? '';
    const match = checkId.match(/^waf\.posture\.(.+)$/);
    if (!match) continue;
    const assetId = match[1];
    const rows = byAsset.get(assetId) ?? [];
    rows.push(finding.id);
    byAsset.set(assetId, rows);
  }
  return byAsset;
}

function actionItemsByAsset(ctx) {
  const byAsset = new Map();
  for (const item of getStore().wafActionItems ?? []) {
    if (item.tenant_id !== ctx.tenantId || !item.waf_asset_id) continue;
    const rows = byAsset.get(item.waf_asset_id) ?? [];
    rows.push(item.action_item_id ?? item.id);
    byAsset.set(item.waf_asset_id, rows);
  }
  return byAsset;
}

function gatherWafAnalyticsContext(ctx, options = {}) {
  ensureStoreShape();
  const windowDays = Number(options.window_days ?? options.windowDays ?? 90);
  const assets = listWafAssets(ctx);
  const snapshotsByAsset = currentSnapshotsByAsset(ctx);
  const cutoff = new Date();
  cutoff.setUTCDate(cutoff.getUTCDate() - Math.max(1, windowDays));
  const historicalSnapshots = getStore().wafPostureSnapshots.filter(
    (snapshot) =>
      snapshot.tenant_id === ctx.tenantId
      && String(snapshot.created_at) >= cutoff.toISOString(),
  );
  return {
    assets,
    currentSnapshotsByAsset: snapshotsByAsset,
    historicalSnapshots,
    targetGroups: getStore().targetGroups.filter((group) => group.tenant_id === ctx.tenantId),
    environments: getStore().environments.filter((env) => env.tenant_id === ctx.tenantId),
    entities: getStore().discoveryEntities?.filter((entity) => entity.tenant_id === ctx.tenantId) ?? [],
    validationSummaryByAsset: latestValidationSummaryByAsset(ctx),
    cveMatchesByAsset: cveMatchesByAsset(ctx),
    findingsByAsset: findingsByAsset(ctx),
    actionItemsByAsset: actionItemsByAsset(ctx),
    connectors: getStore().wafConnectors.filter((connector) => connector.tenant_id === ctx.tenantId),
    driftEvents: getStore().wafDriftEvents.filter((event) => event.tenant_id === ctx.tenantId),
    windowDays,
  };
}

function listWafCoverageRollups(ctx, windowDays = 90) {
  ensureStoreShape();
  const cutoff = new Date();
  cutoff.setUTCDate(cutoff.getUTCDate() - Math.max(1, Number(windowDays) || 90));
  const cutoffDate = cutoff.toISOString().slice(0, 10);
  return getStore().wafCoverageDailyRollups
    .filter((row) =>
      row.tenant_id === ctx.tenantId
      && typeof row.rollup_date === 'string'
      && row.rollup_date >= cutoffDate,
    )
    .sort((a, b) => String(a.rollup_date).localeCompare(String(b.rollup_date)));
}

function buildRiskAssessmentForFinalize(ctx, asset, snapshot, summary) {
  const targetGroup =
    getStore().targetGroups.find(
      (group) => group.id === asset.target_group_id && group.tenant_id === ctx.tenantId,
    ) ?? null;
  return computeAssetRiskAssessment({
    asset,
    snapshot,
    validationSummary: summary,
    cveMatches: cveMatchesByAsset(ctx).get(asset.id) ?? [],
    targetGroup,
    computedAt: snapshot.created_at,
  });
}

export function patchWafAsset(ctx, id, body) {
  ensureStoreShape();
  const asset = findAsset(ctx, id);
  if (!asset) return { error: 'waf_asset_not_found', status: 404 };
  try {
    assertNoRawWafEvidence(body);
    for (const key of Object.keys(body)) {
      if (!PATCHABLE_ASSET_FIELDS.has(key)) {
        const err = new Error(`Field ${key} cannot be updated on WAF assets.`);
        err.code = 'invalid_waf_asset';
        throw err;
      }
    }
    if (body.canonical_url !== undefined || body.hostname !== undefined) {
      const merged = {
        canonical_url: body.canonical_url,
        hostname: body.hostname,
      };
      const value =
        typeof merged.canonical_url === 'string' && merged.canonical_url.trim()
          ? merged.canonical_url.trim()
          : typeof merged.hostname === 'string' && merged.hostname.trim()
            ? merged.hostname.trim()
            : null;
      if (value) asset.canonical_url = value;
    }
    if (body.target_id !== undefined) {
      asset.target_id = typeof body.target_id === 'string' ? body.target_id.trim() : body.target_id;
    }
    if (body.asset_kind !== undefined) {
      asset.asset_kind = typeof body.asset_kind === 'string' ? body.asset_kind.trim() : body.asset_kind;
    }
    if (body.expected_vendor_hint !== undefined) {
      asset.expected_vendor_hint =
        typeof body.expected_vendor_hint === 'string' ? body.expected_vendor_hint.trim() : body.expected_vendor_hint;
    }
    if (body.business_criticality !== undefined) {
      asset.business_criticality =
        typeof body.business_criticality === 'string' ? body.business_criticality.trim() : body.business_criticality;
    }
    if (body.traffic_tier !== undefined) {
      asset.traffic_tier =
        typeof body.traffic_tier === 'string' ? body.traffic_tier.trim() : body.traffic_tier;
    }
    if (body.owner_hint !== undefined) {
      asset.owner_hint = typeof body.owner_hint === 'string' ? body.owner_hint.trim() : body.owner_hint;
    }
    if (Array.isArray(body.compliance_tags)) {
      asset.compliance_tags = body.compliance_tags.map((t) => String(t).trim()).filter(Boolean);
    }
    if (body.expected_waf_required !== undefined) {
      asset.expected_waf_required = body.expected_waf_required === true
        || body.expected_waf_required === '1'
        || body.expected_waf_required === 1
        || body.expected_waf_required === 'true';
    }
    asset.updated_at = new Date().toISOString();
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'waf.asset.updated',
      resource_type: 'waf_asset',
      resource_id: id,
    });
    persistStore();
    return { asset };
  } catch (err) {
    return contractError(err);
  }
}

export function getWafCoverage(ctx, options = {}) {
  const context = gatherWafAnalyticsContext(ctx, options);
  return buildCoverageSummary({
    assets: context.assets,
    currentSnapshotsByAsset: context.currentSnapshotsByAsset,
    historicalSnapshots: context.historicalSnapshots,
    coverageRollups: listWafCoverageRollups(ctx, context.windowDays),
    windowDays: context.windowDays,
  });
}

export function getWafCoverageVendors(ctx) {
  const context = gatherWafAnalyticsContext(ctx);
  return buildVendorBreakdown({
    assets: context.assets,
    currentSnapshotsByAsset: context.currentSnapshotsByAsset,
  });
}

export function getWafCoverageEntities(ctx, options = {}) {
  const context = gatherWafAnalyticsContext(ctx, options);
  return buildEntityRollup({
    assets: context.assets,
    currentSnapshotsByAsset: context.currentSnapshotsByAsset,
    entities: context.entities,
    targetGroups: context.targetGroups,
    entityTypeFilter: options.entity_type ?? options.entityType ?? null,
  });
}

export function getWafCoverageGeography(ctx, options = {}) {
  const context = gatherWafAnalyticsContext(ctx, options);
  return buildGeographyRollup({
    assets: context.assets,
    currentSnapshotsByAsset: context.currentSnapshotsByAsset,
    targetGroups: context.targetGroups,
    environments: context.environments,
    entities: context.entities,
    regionCodeFilter: options.region_code ?? options.regionCode ?? null,
  });
}

export function getWafCoverageCriticality(ctx, options = {}) {
  const context = gatherWafAnalyticsContext(ctx, options);
  return buildCriticalityRollup({
    assets: context.assets,
    currentSnapshotsByAsset: context.currentSnapshotsByAsset,
    criticalityFilter: options.business_criticality ?? options.criticality ?? null,
  });
}

export function getWafRiskRoadmap(ctx, options = {}) {
  const context = gatherWafAnalyticsContext(ctx, options);
  return buildRiskRoadmap({
    assets: context.assets,
    currentSnapshotsByAsset: context.currentSnapshotsByAsset,
    validationSummaryByAsset: context.validationSummaryByAsset,
    cveMatchesByAsset: context.cveMatchesByAsset,
    targetGroups: context.targetGroups,
    entities: context.entities,
    findingsByAsset: context.findingsByAsset,
    actionItemsByAsset: context.actionItemsByAsset,
    filters: {
      entity_id: options.entity_id ?? options.entityId ?? null,
      region_code: options.region_code ?? options.regionCode ?? null,
      vendor: options.vendor ?? null,
      min_score:
        options.min_score != null
          ? Number(options.min_score)
          : options.minScore != null
            ? Number(options.minScore)
            : null,
      limit_per_tier:
        options.limit_per_tier != null
          ? Number(options.limit_per_tier)
          : options.limitPerTier != null
            ? Number(options.limitPerTier)
            : 50,
    },
  });
}

export function getWafVendorConsolidation(ctx) {
  const context = gatherWafAnalyticsContext(ctx);
  return buildVendorConsolidation({
    assets: context.assets,
    currentSnapshotsByAsset: context.currentSnapshotsByAsset,
    connectors: context.connectors,
    driftEvents: context.driftEvents,
  });
}

export function createSocOffensiveWafValidation(ctx, body) {
  ensureStoreShape();
  try {
    const profile = normalizeSocOffensiveWafValidationRequest(body);
    const asset = findAsset(ctx, profile.waf_asset_id);
    if (!asset) {
      return { error: 'waf_asset_not_found', status: 404 };
    }
    const id = newId('id');
    const now = new Date().toISOString();
    const run = {
      id,
      tenant_id: ctx.tenantId,
      waf_asset_id: profile.waf_asset_id,
      offensive_request_id: profile.offensive_request_id,
      mode: profile.modes[0] ?? 'sqli_offensive',
      status: 'planned',
      execution_class: 'offensive_suite',
      safety_profile_json: {
        modes: profile.modes,
        probe_profile: profile.probe_profile,
        marker_profile: profile.marker_profile,
        risk_class: 'soc_gated',
      },
      summary_json: {},
      created_at: now,
    };
    getStore().wafValidationRuns.push(run);
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'waf.offensive_validation.started',
      resource_type: 'waf_validation_run',
      resource_id: id,
      metadata: {
        waf_asset_id: profile.waf_asset_id,
        offensive_request_id: profile.offensive_request_id,
        modes: profile.modes,
      },
    });
    persistStore();
    return { validation_run: run };
  } catch (err) {
    return contractError(err);
  }
}

export function createWafValidation(ctx, body) {
  ensureStoreShape();
  try {
    const profile = normalizeWafValidationRequest(body);
    const asset = findAsset(ctx, profile.waf_asset_id);
    if (!asset) {
      return { error: 'waf_asset_not_found', status: 404 };
    }
    const id = newId('id');
    const now = new Date().toISOString();
    const run = {
      id,
      tenant_id: ctx.tenantId,
      waf_asset_id: profile.waf_asset_id,
      mode: profile.modes[0] ?? 'marker',
      status: 'planned',
      safety_profile_json: {
        modes: profile.modes,
        probe_profile: profile.probe_profile,
        marker_profile: profile.marker_profile,
      },
      summary_json: {},
      created_at: now,
    };
    const testRunId =
      typeof body.test_run_id === 'string' ? body.test_run_id.trim() : '';
    if (testRunId) {
      const binding = validateTestRunBinding(ctx, testRunId, asset);
      if (binding.error) return binding;
      run.test_run_id = testRunId;
    }
    getStore().wafValidationRuns.push(run);
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'waf.validation.started',
      resource_type: 'waf_validation_run',
      resource_id: id,
      metadata: {
        waf_asset_id: profile.waf_asset_id,
        modes: profile.modes,
      },
    });
    persistStore();
    return { validation_run: run };
  } catch (err) {
    return contractError(err);
  }
}

export function listWafValidations(ctx) {
  ensureStoreShape();
  return getStore().wafValidationRuns.filter((r) => r.tenant_id === ctx.tenantId);
}

export function getWafValidation(ctx, id) {
  const run = findValidationRun(ctx, id);
  if (!run) return null;
  const scenario_results = getStore().wafScenarioResults.filter(
    (r) => r.tenant_id === ctx.tenantId && r.waf_validation_run_id === id,
  );
  return { validation_run: run, scenario_results };
}

function parseBooleanField(body, snake, camel, fallback = false) {
  const value = body[snake] ?? body[camel];
  if (value === undefined || value === null) return fallback;
  if (typeof value === 'boolean') return value;
  if (value === '1' || value === 1 || value === 'true') return true;
  if (value === '0' || value === 0 || value === 'false') return false;
  return fallback;
}



function normalizeScenarioResultInput(entry) {
  if (entry === null || entry === undefined || typeof entry !== 'object' || Array.isArray(entry)) {
    const err = new Error('Scenario result must be a plain object.');
    err.code = 'unsafe_waf_evidence';
    throw err;
  }
  assertNoRawWafEvidence(entry);
  const scenario_family = String(entry.scenario_family ?? 'marker').trim();
  if (!WAF_SCENARIO_FAMILIES.includes(scenario_family)) {
    const err = new Error(`Unsupported scenario_family: ${scenario_family}`);
    err.code = 'unsafe_waf_evidence';
    throw err;
  }
  const expected_action = String(entry.expected_action ?? 'block').trim();
  if (!WAF_EXPECTED_ACTIONS.includes(expected_action)) {
    const err = new Error(`expected_action must be one of: ${WAF_EXPECTED_ACTIONS.join(', ')}.`);
    err.code = 'unsafe_waf_evidence';
    throw err;
  }
  const observed_action = String(entry.observed_action ?? 'inconclusive').trim();
  let passed = null;
  if (entry.passed !== undefined && entry.passed !== null) {
    passed = Boolean(entry.passed);
  }
  const confidence = Number(entry.confidence ?? 0);
  const evidenceRaw = entry.evidence_summary ?? entry.evidence_summary_json ?? {};
  const evidence_summary_json = normalizeWafEvidenceSummary(evidenceRaw);
  return {
    scenario_family,
    test_material_type: 'metadata_only',
    expected_action,
    observed_action,
    passed,
    confidence: Number.isFinite(confidence) ? confidence : 0,
    evidence_summary_json,
  };
}

export function finalizeWafValidation(ctx, id, body = {}) {
  ensureStoreShape();
  const run = findValidationRun(ctx, id);
  if (!run) return { error: 'waf_asset_not_found', status: 404, message: 'Validation run not found.' };
  if (run.status === 'finalized') {
    return { error: 'validation_already_finalized', status: 409 };
  }
  try {
    assertNoRawWafEvidence(body);
    const scenarioInputs = Array.isArray(body.scenario_results) ? body.scenario_results : [];
    const hasExplicitScenarios = scenarioInputs.length > 0;
    let normalizedScenarios = hasExplicitScenarios
      ? scenarioInputs.map((entry) => {
        const normalized = normalizeScenarioResultInput(entry);
        return {
          ...normalized,
          evidence_summary_json: normalizeWafEvidenceSummary(
            stripClientAssertedAgentEvidence(normalized.evidence_summary_json),
          ),
        };
      })
      : [];

    let wafDetected = parseBooleanField(body, 'waf_detected', 'wafDetected', false);
    let validationPassed = parseBooleanField(body, 'validation_passed', 'validationPassed', false);
    let validationFailed = parseBooleanField(body, 'validation_failed', 'validationFailed', false);
    let originBypassConfirmed = parseBooleanField(
      body,
      'origin_bypass_confirmed',
      'originBypassConfirmed',
      false,
    );
    let sourceExternal = Boolean(body.source_external);
    let sourceAgent = Boolean(body.source_agent);
    const connectorMode = body.connector_mode ?? body.connectorMode ?? null;

    const usedBoundRunDerivation = Boolean(run.test_run_id && !hasExplicitScenarios);
    let corroboration;
    if (usedBoundRunDerivation) {
      const probes = probeEventsForRun(ctx, run.test_run_id);
      const agents = agentObservationsForRun(ctx, run.test_run_id);
      corroboration = buildWafEvidenceCorroboration({ probes, agents });
      const derived = deriveWafSignalsFromBoundEvents({ probes, agents });
      normalizedScenarios = derived.scenarioResults.map((entry) => normalizeScenarioResultInput(entry));
      if (!booleanFieldExplicit(body, 'waf_detected', 'wafDetected')) {
        wafDetected = derived.wafDetected;
      }
      if (!booleanFieldExplicit(body, 'validation_passed', 'validationPassed')) {
        validationPassed = derived.validationPassed;
      }
      if (!booleanFieldExplicit(body, 'validation_failed', 'validationFailed')) {
        validationFailed = derived.validationFailed;
      }
      if (!booleanFieldExplicit(body, 'origin_bypass_confirmed', 'originBypassConfirmed')) {
        originBypassConfirmed = derived.originBypassConfirmed;
      }
      if (body.source_external === undefined && body.sourceExternal === undefined) {
        sourceExternal = derived.source_external;
      }
      if (body.source_agent === undefined && body.sourceAgent === undefined) {
        sourceAgent = derived.source_agent;
      }
    }

    if (!corroboration) {
      corroboration = buildCorroborationFromEvents(
        getStore().events,
        run.test_run_id ?? null,
        normalizedScenarios,
      );
    }
    const evidenceGate = protectedFinalizeEvidenceRequired({
      validationPassed,
      normalizedScenarios,
      corroboration,
    });
    if (evidenceGate) return evidenceGate;

    const asset = findAsset(ctx, run.waf_asset_id);
    if (!asset) return { error: 'waf_asset_not_found', status: 404 };

    const previous = getCurrentSnapshot(ctx, asset.id);
    const classification = classifyWafPosture({
      wafDetected,
      validationPassed,
      validationFailed,
      originBypassConfirmed,
      wafRequired: asset.expected_waf_required !== false,
      connectorMode,
    });

    const now = new Date().toISOString();
    for (const snap of getStore().wafPostureSnapshots) {
      if (snap.tenant_id === ctx.tenantId && snap.waf_asset_id === asset.id && snap.is_current) {
        snap.is_current = false;
      }
    }

    const snapshotId = newId('id');
    const snapshot = enrichSnapshotWithRisk(
      {
        id: snapshotId,
        tenant_id: ctx.tenantId,
        waf_asset_id: asset.id,
        status: classification.status,
        reason_codes: classification.reason_codes,
        detected_vendor: typeof body.detected_vendor === 'string' ? body.detected_vendor.trim() : null,
        detected_product: typeof body.detected_product === 'string' ? body.detected_product.trim() : null,
        coverage_required: asset.expected_waf_required !== false,
        risk_score: 0,
        confidence: Number(body.confidence ?? 0) || 0,
        source_mix_json: {
          validation: true,
          external: sourceExternal,
          agent: sourceAgent,
          connector: Boolean(body.source_connector),
        },
        created_at: now,
        is_current: true,
      },
      buildRiskAssessmentForFinalize(ctx, asset, {
        status: classification.status,
        reason_codes: classification.reason_codes,
        waf_asset_id: asset.id,
        created_at: now,
      }, {
        waf_detected: wafDetected,
        validation_passed: validationPassed,
        validation_failed: validationFailed,
        origin_bypass_confirmed: originBypassConfirmed,
        posture_status: classification.status,
        reason_codes: classification.reason_codes,
      }),
    );
    getStore().wafPostureSnapshots.push(snapshot);

    const scenarioResultIds = [];
    for (const scenario of normalizedScenarios) {
      const scenarioId = newId('id');
      scenarioResultIds.push(scenarioId);
      getStore().wafScenarioResults.push({
        id: scenarioId,
        tenant_id: ctx.tenantId,
        waf_validation_run_id: run.id,
        ...scenario,
        created_at: now,
      });
    }

    run.status = 'finalized';
    run.finalized_at = now;
    run.summary_json = {
      waf_detected: wafDetected,
      validation_passed: validationPassed,
      validation_failed: validationFailed,
      origin_bypass_confirmed: originBypassConfirmed,
      posture_status: classification.status,
      reason_codes: classification.reason_codes,
    };

    asset.status = classification.status;
    asset.updated_at = now;

    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'waf.validation.finalized',
      resource_type: 'waf_validation_run',
      resource_id: run.id,
      metadata: { waf_asset_id: asset.id },
    });
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'waf.posture.updated',
      resource_type: 'waf_posture_snapshot',
      resource_id: snapshotId,
      metadata: {
        waf_asset_id: asset.id,
        old_status: previous?.status ?? asset.status,
        new_status: classification.status,
        reason_codes: classification.reason_codes,
      },
    });

    const finding = upsertWafPostureFinding(ctx, {
      asset,
      validationRun: run,
      classification,
      snapshotId,
      scenarioResultIds,
    });

    upsertWafDriftEvents(ctx, {
      asset,
      previous,
      classification,
      wafDetected,
      finding,
    });

    persistStore();

    return {
      validation_run: run,
      posture: formatSnapshot(snapshot),
    };
  } catch (err) {
    return contractError(err);
  }
}

const CONNECTOR_PROVIDERS = new Set([
  'generic_waf',
  'cloudflare',
  'aws_waf',
  'akamai',
  'fastly',
  'imperva',
  'azure_waf',
  'gcp_cloud_armor',
  'webhook',
]);

const CONNECTOR_CONFIG_SAFE_KEYS = new Set([
  'account_ref_hash',
  'zone_ref_hash',
  'resource_ref_hash',
  'default_snapshot_kind',
  'read_only',
  'owner_hint',
  'tag_summary',
  'polling_interval_minutes',
  'region_summary',
  'notes_hash',
]);

const CONNECTOR_SNAPSHOT_SUMMARY_SAFE_KEYS = new Set([
  'hostnames',
  'policy_mode',
  'rule_count',
  'managed_rule_versions',
  'last_rule_update_at',
  'rate_limit_summary',
  'origin_protection_summary',
  'tags',
  'config_hash',
  'permission_gaps',
]);

const CONNECTOR_SNAPSHOT_KINDS = new Set([
  'waf_policy',
  'cdn_property',
  'dns_zone',
  'cloud_asset',
  'vulnerability',
]);

const CONNECTOR_ACTIVATABLE_STATUSES = new Set(['active', 'validating']);

const CONNECTOR_EXTRA_FORBIDDEN_KEY_FRAGMENTS = new Set([
  'body',
  'log',
  'logs',
  'cookie',
  'authorization',
]);

const PLAINTEXT_CONNECTOR_SECRET_FIELDS = new Set([
  'secret',
  'api_key',
  'api_token',
  'token',
  'password',
  'credential',
  'credentials',
  'client_secret',
]);

function normalizeConnectorKey(key) {
  return String(key)
    .replace(/([a-z])([A-Z])/g, '$1_$2')
    .replace(/[^A-Za-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase();
}

function collectConnectorExtraForbiddenKeys(value, path = '') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return [];
  }
  const findings = [];
  if (Array.isArray(value)) {
    value.forEach((entry, index) => {
      findings.push(...collectConnectorExtraForbiddenKeys(entry, `${path}[${index}]`));
    });
    return findings;
  }
  for (const [key, nested] of Object.entries(value)) {
    const keyPath = path ? `${path}.${key}` : key;
    const normalized = normalizeConnectorKey(key);
    if (CONNECTOR_EXTRA_FORBIDDEN_KEY_FRAGMENTS.has(normalized)) {
      findings.push(keyPath);
    }
    findings.push(...collectConnectorExtraForbiddenKeys(nested, keyPath));
  }
  return findings;
}

function assertSafeConnectorPayload(value) {
  assertNoRawWafEvidence(value);
  const extra = collectConnectorExtraForbiddenKeys(value);
  if (extra.length > 0) {
    const err = new Error(`Forbidden connector field: ${extra[0]}`);
    err.code = 'unsafe_waf_evidence';
    throw err;
  }
}

function parseConnectorBoolean(value) {
  if (value === true || value === '1' || value === 1 || value === 'true') return true;
  if (value === false || value === '0' || value === 0 || value === 'false') return false;
  return null;
}

function redactConnectorConfig(raw) {
  const input = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
  const out = {};
  for (const [key, value] of Object.entries(input)) {
    const normalized = normalizeConnectorKey(key);
    if (!CONNECTOR_CONFIG_SAFE_KEYS.has(normalized)) continue;
    if (normalized === 'read_only') {
      const parsed = parseConnectorBoolean(value);
      if (parsed !== null) out.read_only = parsed;
      continue;
    }
    if (normalized === 'polling_interval_minutes') {
      const n = Number(value);
      if (Number.isFinite(n) && n > 0) out.polling_interval_minutes = Math.floor(n);
      continue;
    }
    if (normalized === 'tag_summary' && value && typeof value === 'object' && !Array.isArray(value)) {
      out.tag_summary = value;
      continue;
    }
    if (typeof value === 'string' && value.trim()) {
      out[normalized] = value.trim();
    }
  }
  return out;
}

function normalizeConnectorSnapshotSummary(raw) {
  const input = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
  const out = {};
  for (const [key, value] of Object.entries(input)) {
    const normalized = normalizeConnectorKey(key);
    if (!CONNECTOR_SNAPSHOT_SUMMARY_SAFE_KEYS.has(normalized)) continue;
    if (normalized === 'hostnames' && Array.isArray(value)) {
      out.hostnames = value.map((h) => String(h).trim()).filter(Boolean);
      continue;
    }
    if (normalized === 'rule_count') {
      const n = Number(value);
      if (Number.isFinite(n) && n >= 0) out.rule_count = Math.floor(n);
      continue;
    }
    if (normalized === 'managed_rule_versions' && Array.isArray(value)) {
      out.managed_rule_versions = value.map((v) => String(v).trim()).filter(Boolean);
      continue;
    }
    if (normalized === 'tags' && Array.isArray(value)) {
      out.tags = value.map((t) => String(t).trim()).filter(Boolean);
      continue;
    }
    if (normalized === 'permission_gaps' && Array.isArray(value)) {
      out.permission_gaps = value.map((g) => String(g).trim()).filter(Boolean);
      continue;
    }
    if (typeof value === 'string' && value.trim()) {
      out[normalized] = value.trim();
    }
  }
  return out;
}

function providerCapabilities(provider, connector = null) {
  const snapshot_kinds = provider === 'webhook'
    ? ['waf_policy']
    : ['waf_policy', 'cdn_property', 'dns_zone'];
  const outbound_polling = supportsOutboundProviderPoll(provider)
    && Boolean(connector?.secret_id);
  return {
    provider,
    read_only_metadata: true,
    outbound_polling,
    snapshot_kinds,
  };
}

async function defaultConnectorSecretResolver(ctx, secretId) {
  const key = loadSecretEncryptionKey();
  if (!key) return { error: 'encryption_not_configured' };
  const decrypted = decryptEncryptedSecretForUse(ctx, secretId, key);
  if (!decrypted || decrypted.error) return { error: 'secret_not_found' };
  return { plaintext: decrypted.plaintext };
}

function applyConnectorPollHealth(connector, health, now) {
  connector.updated_at = now;
  if (health?.status === 'active' || health?.status === 'degraded') {
    connector.status = health.status;
    connector.last_success_at = now;
    connector.last_error_at = null;
    return;
  }
  if (connector.status !== 'disabled') {
    connector.status = health?.status ?? 'error';
  }
  connector.last_error_at = now;
}

function findConnector(ctx, id) {
  ensureStoreShape();
  return getStore().wafConnectors.find((c) => c.id === id && c.tenant_id === ctx.tenantId) ?? null;
}

export function formatConnector(record) {
  return {
    id: record.id,
    provider: record.provider,
    name: record.name,
    status: record.status,
    ...(typeof record.secret_id === 'string' && record.secret_id.trim()
      ? { secret_id: record.secret_id.trim() }
      : {}),
    config: record.config_json ?? {},
    created_at: record.created_at,
    updated_at: record.updated_at,
    ...(record.last_success_at ? { last_success_at: record.last_success_at } : {}),
  };
}

function formatConnectorSnapshot(record) {
  return {
    id: record.id,
    connector_id: record.connector_id,
    snapshot_kind: record.snapshot_kind,
    resource_ref_hash: record.resource_ref_hash,
    display_ref: record.display_ref,
    summary: record.summary_json ?? {},
    config_hash: record.config_hash,
    observed_at: record.observed_at,
    created_at: record.created_at,
  };
}

export function listConnectors(ctx) {
  ensureStoreShape();
  return getStore()
    .wafConnectors.filter((c) => c.tenant_id === ctx.tenantId)
    .map((c) => formatConnector(c));
}

export function listConnectorsEnvelope(ctx) {
  const items = listConnectors(ctx);
  return {
    items,
    count: items.length,
    meta: {
      empty_reason: items.length
        ? null
        : 'No connectors are configured for this tenant.',
    },
  };
}

export function createConnector(ctx, body = {}) {
  ensureStoreShape();
  try {
    assertSafeConnectorPayload(body);
    for (const key of Object.keys(body)) {
      const normalized = normalizeConnectorKey(key);
      if (PLAINTEXT_CONNECTOR_SECRET_FIELDS.has(normalized)) {
        const err = new Error(`Plaintext secret field ${key} is not allowed; use secret_id.`);
        err.code = 'unsafe_waf_evidence';
        throw err;
      }
    }

    const provider = String(body.provider ?? '').trim().toLowerCase();
    if (!CONNECTOR_PROVIDERS.has(provider)) {
      const err = new Error(`Unsupported connector provider: ${provider || '(empty)'}`);
      err.code = 'invalid_request';
      throw err;
    }
    const name = String(body.name ?? '').trim();
    if (!name) {
      const err = new Error('Connector name is required.');
      err.code = 'invalid_request';
      throw err;
    }

    const rawConfig = body.config ?? body.config_json ?? {};
    assertSafeConnectorPayload(rawConfig);
    for (const key of Object.keys(rawConfig)) {
      const normalized = normalizeConnectorKey(key);
      if (PLAINTEXT_CONNECTOR_SECRET_FIELDS.has(normalized)) {
        const err = new Error(`Plaintext secret field ${key} is not allowed in config; use secret_id.`);
        err.code = 'unsafe_waf_evidence';
        throw err;
      }
    }
    const config_json = redactConnectorConfig(rawConfig);
    const secret_id =
      typeof body.secret_id === 'string' && body.secret_id.trim() ? body.secret_id.trim() : null;

    const requestedStatus = String(body.status ?? 'disabled').trim().toLowerCase();
    let status = 'disabled';
    if (CONNECTOR_ACTIVATABLE_STATUSES.has(requestedStatus) && config_json.read_only === true) {
      status = requestedStatus;
    }

    const now = new Date().toISOString();
    const id = newId('id');
    const record = {
      id,
      tenant_id: ctx.tenantId,
      provider,
      name,
      secret_id,
      config_json,
      status,
      created_at: now,
      updated_at: now,
      last_success_at: null,
    };
    getStore().wafConnectors.push(record);
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'connector.created',
      resource_type: 'waf_connector',
      resource_id: id,
      metadata: { provider, connector_id: id },
    });
    persistStore();
    return { connector: formatConnector(record) };
  } catch (err) {
    return contractError(err);
  }
}

export function validateConnector(ctx, id) {
  ensureStoreShape();
  const connector = findConnector(ctx, id);
  if (!connector) {
    return { error: 'connector_not_found', status: 404 };
  }

  const readOnly = connector.config_json?.read_only === true;
  const capabilities = providerCapabilities(connector.provider, connector);
  const now = new Date().toISOString();

  if (!readOnly) {
    connector.status = 'error';
    connector.updated_at = now;
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'connector.validated',
      resource_type: 'waf_connector',
      resource_id: connector.id,
      metadata: { provider: connector.provider, connector_id: connector.id, status: 'error' },
    });
    persistStore();
    return {
      status: 'error',
      capabilities,
      redacted_errors: [
        'read_only_required: set config.read_only=true for metadata-only connector validation.',
      ],
    };
  }

  connector.status = 'active';
  connector.updated_at = now;
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'connector.validated',
    resource_type: 'waf_connector',
    resource_id: connector.id,
    metadata: { provider: connector.provider, connector_id: connector.id, status: 'active' },
  });
  persistStore();
  return { status: 'active', capabilities };
}

function normalizePollSnapshotInput(entry, connectorId) {
  if (entry === null || entry === undefined || typeof entry !== 'object' || Array.isArray(entry)) {
    const err = new Error('Each snapshot must be a plain object.');
    err.code = 'invalid_request';
    throw err;
  }
  assertSafeConnectorPayload(entry);
  const snapshot_kind = String(entry.snapshot_kind ?? '').trim().toLowerCase();
  if (!CONNECTOR_SNAPSHOT_KINDS.has(snapshot_kind)) {
    const err = new Error(`Unsupported snapshot_kind: ${snapshot_kind || '(empty)'}`);
    err.code = 'invalid_request';
    throw err;
  }
  const resource_ref_hash = String(entry.resource_ref_hash ?? '').trim();
  const display_ref = String(entry.display_ref ?? '').trim();
  const config_hash = String(entry.config_hash ?? '').trim();
  if (!resource_ref_hash || !display_ref || !config_hash) {
    const err = new Error('snapshot_kind, resource_ref_hash, display_ref, and config_hash are required.');
    err.code = 'invalid_request';
    throw err;
  }
  const observed_at =
    typeof entry.observed_at === 'string' && entry.observed_at.trim()
      ? entry.observed_at.trim()
      : new Date().toISOString();
  const summary_json = normalizeConnectorSnapshotSummary(entry.summary ?? entry.summary_json ?? {});
  return {
    connector_id: connectorId,
    snapshot_kind,
    resource_ref_hash,
    display_ref,
    summary_json,
    config_hash,
    observed_at,
  };
}

function persistManualConnectorSnapshots(ctx, connector, snapshotInputs, now) {
  const created = [];
  const kindCounts = {};
  for (const entry of snapshotInputs) {
    const normalized = normalizePollSnapshotInput(entry, connector.id);
    const record = {
      id: newId('id'),
      tenant_id: ctx.tenantId,
      ...normalized,
      created_at: now,
    };
    getStore().wafConnectorSnapshots.push(record);
    created.push(formatConnectorSnapshot(record));
    kindCounts[normalized.snapshot_kind] = (kindCounts[normalized.snapshot_kind] ?? 0) + 1;
  }
  return { created, kindCounts };
}

function buildConnectorPollJob({
  connectorId,
  now,
  status,
  snapshotCount,
  health = null,
  attempts = null,
}) {
  return {
    id: newId('poll'),
    connector_id: connectorId,
    status,
    snapshot_count: snapshotCount,
    created_at: now,
    ...(health ? { health } : {}),
    ...(attempts != null ? { attempts } : {}),
  };
}

export async function pollConnector(ctx, id, body = {}, options = {}) {
  ensureStoreShape();
  const connector = findConnector(ctx, id);
  if (!connector) {
    return { error: 'connector_not_found', status: 404 };
  }
  try {
    assertSafeConnectorPayload(body);
    const snapshotInputs = Array.isArray(body.snapshots) ? body.snapshots : [];
    const now = new Date().toISOString();
    const secretResolver = options.secretResolver ?? defaultConnectorSecretResolver;
    const fetchFn = options.fetchFn ?? fetch;
    const prefetchedMetadata = options.prefetchedMetadata ?? body.prefetched_metadata ?? null;

    let outboundHealth = null;
    let outboundAttempts = null;
    let outboundSnapshots = [];

    if (shouldAttemptOutboundConnectorPoll(connector, body)) {
      try {
        const outbound = await executeConnectorProviderPoll({
          connector,
          secretResolver,
          ctx,
          fetchFn,
          prefetchedMetadata,
          now,
          maxAttempts: options.maxAttempts,
        });
        outboundSnapshots = outbound.snapshots ?? [];
        outboundHealth = outbound.health ?? null;
        outboundAttempts = outbound.health?.attempts ?? null;
      } catch (err) {
        const failure = buildProviderPollFailure(connector, err, err?.attempts ?? null);
        applyConnectorPollHealth(connector, failure.health, now);
        audit({
          tenant_id: ctx.tenantId,
          actor_user_id: ctx.userId,
          actor_role: ctx.role,
          action: 'connector.poll.failed',
          resource_type: 'waf_connector',
          resource_id: connector.id,
          metadata: {
            provider: connector.provider,
            connector_id: connector.id,
            health_status: failure.health.status,
            health_code: failure.health.health_code,
            attempts: failure.health.attempts,
          },
        });
        persistStore();
        return {
          error: 'connector_poll_failed',
          status: failure.health.status === 'rate_limited' ? 429 : 503,
          message: 'Outbound connector poll failed; manual metadata snapshots remain supported.',
          health: failure.health,
        };
      }
    }

    const manualResult = snapshotInputs.length > 0
      ? persistManualConnectorSnapshots(ctx, connector, snapshotInputs, now)
      : { created: [], kindCounts: {} };

    const providerSnapshots = outboundSnapshots.map((entry) => normalizePollSnapshotInput(entry, connector.id));
    const created = [...manualResult.created];
    const kindCounts = { ...manualResult.kindCounts };

    for (const normalized of providerSnapshots) {
      const record = {
        id: newId('id'),
        tenant_id: ctx.tenantId,
        ...normalized,
        created_at: now,
      };
      getStore().wafConnectorSnapshots.push(record);
      created.push(formatConnectorSnapshot(record));
      kindCounts[normalized.snapshot_kind] = (kindCounts[normalized.snapshot_kind] ?? 0) + 1;
    }

    if (outboundHealth) {
      applyConnectorPollHealth(connector, outboundHealth, now);
    } else if (created.length > 0) {
      connector.last_success_at = now;
      connector.updated_at = now;
      if (connector.status !== 'disabled') {
        connector.status = 'active';
      }
      connector.last_error_at = null;
    }

    const pollStatus = outboundHealth
      ? (created.length > 0 ? 'completed' : 'completed_empty')
      : 'completed';
    const poll_job = buildConnectorPollJob({
      connectorId: connector.id,
      now,
      status: pollStatus,
      snapshotCount: created.length,
      health: outboundHealth,
      attempts: outboundAttempts,
    });

    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'connector.snapshot.created',
      resource_type: 'waf_connector',
      resource_id: connector.id,
      metadata: {
        provider: connector.provider,
        connector_id: connector.id,
        snapshot_count: created.length,
        snapshot_kinds: kindCounts,
        outbound: Boolean(outboundHealth),
        ...(outboundHealth ? { health_status: outboundHealth.status } : {}),
      },
    });
    persistStore();
    return { poll_job, snapshots: created };
  } catch (err) {
    return contractError(err);
  }
}

export function listConnectorSnapshots(ctx, id) {
  ensureStoreShape();
  const connector = findConnector(ctx, id);
  if (!connector) {
    return { error: 'connector_not_found', status: 404 };
  }
  const items = getStore()
    .wafConnectorSnapshots.filter(
      (s) => s.tenant_id === ctx.tenantId && s.connector_id === connector.id,
    )
    .map((s) => formatConnectorSnapshot(s));
  return { items };
}

function actionItemCategoryForReasonCodes(reasonCodes = []) {
  const codes = new Set(reasonCodes);
  if (codes.has('origin_bypass_confirmed')) return 'origin_bypass';
  if (codes.has('vendor_changed_unapproved') || codes.has('rule_mode_changed') || codes.has('rule_count_decreased')) {
    return 'waf_drift';
  }
  if (codes.has('connector_health_changed') || codes.has('rule_update_stale')) return 'connector_setup';
  if (codes.has('cve_exposed') || codes.has('mitigation_recommended')) return 'cve_mitigation';
  return 'waf_coverage';
}

function recommendedSolutionForPosture({ reasonCodes = [], vendorHint = null, postureStatus = null } = {}) {
  const codes = new Set(reasonCodes);
  const vendor = vendorHint ? `${vendorHint} ` : '';
  if (codes.has('origin_bypass_confirmed')) {
    return `${vendor}Restrict origin access to WAF/CDN egress only and enable authenticated origin pull where supported.`;
  }
  if (codes.has('marker_rule_not_blocking')) {
    return `${vendor}Review WAF rule mode and ensure marker/managed rules are in blocking mode.`;
  }
  if (codes.has('monitor_only_behavior')) {
    return `${vendor}Move affected WAF rules from monitor/log-only to blocking mode after staging validation.`;
  }
  if (postureStatus === 'unprotected') {
    return `${vendor}Enable WAF coverage for the declared asset and validate with a safe marker retest.`;
  }
  return `${vendor}Review WAF posture findings and apply vendor-aware remediation before retest.`;
}

function portalPath(pathname) {
  return `/v1${pathname.startsWith('/') ? pathname : `/${pathname}`}`;
}

function findingEvidenceUrl(findingId) {
  return portalPath(`/findings/${findingId}`);
}

function wafRetestUrl(wafAssetId) {
  return portalPath(`/waf/validations?waf_asset_id=${encodeURIComponent(wafAssetId)}`);
}

function actionItemDedupeKey(wafAssetId, primaryReason) {
  return `${wafAssetId}:${primaryReason}`;
}

export function formatActionItem(record) {
  return {
    action_item_id: record.action_item_id,
    category: record.category,
    title: record.title,
    asset: record.asset,
    owner: record.owner,
    severity: record.severity,
    evidence: record.evidence,
    recommended_solution: record.recommended_solution,
    retest_url: record.retest_url,
    status: record.status,
    ...(Array.isArray(record.finding_ids) ? { finding_ids: record.finding_ids } : {}),
    ...(record.created_at ? { created_at: record.created_at } : {}),
    ...(record.updated_at ? { updated_at: record.updated_at } : {}),
  };
}

export function listActionItems(ctx) {
  ensureStoreShape();
  return getStore()
    .wafActionItems.filter((item) => item.tenant_id === ctx.tenantId)
    .map((item) => formatActionItem(item));
}

export function createActionItemFromFinding(ctx, finding, opts = {}) {
  ensureStoreShape();
  try {
    assertNoRawWafEvidence(opts);
    if (!finding || finding.tenant_id !== ctx.tenantId) {
      return { error: 'finding_not_found', status: 404 };
    }

    const remediationCtx = extractFindingRemediationContext(finding);
    const wafAssetId = remediationCtx.waf_asset_id;
    if (!wafAssetId) {
      return {
        error: 'invalid_request',
        status: 400,
        message: 'Finding is not linked to a WAF asset.',
      };
    }

    const asset = findAsset(ctx, wafAssetId);
    const assetDisplay = asset?.canonical_url ?? `asset:${wafAssetId}`;
    const owner = remediationCtx.owner ?? asset?.owner_hint ?? 'security-operations';
    const reasonCodes = remediationCtx.reason_codes;
    const primaryReason = remediationCtx.primary_reason;
    const dedupeKey = actionItemDedupeKey(wafAssetId, primaryReason);
    const now = new Date().toISOString();

    const evidenceSummary = typeof opts.evidence_summary === 'string' && opts.evidence_summary.trim()
      ? opts.evidence_summary.trim()
      : `WAF posture finding ${finding.id} for ${assetDisplay}. Reason codes: ${reasonCodes.join(', ') || 'unknown'}.`;

    const fields = {
      action_item_id: newId('id'),
      tenant_id: ctx.tenantId,
      category: opts.category ?? actionItemCategoryForReasonCodes(reasonCodes),
      title: opts.title ?? finding.title ?? `WAF remediation: ${assetDisplay}`,
      asset: {
        id: wafAssetId,
        display: assetDisplay,
        ...(asset?.owner_hint ? { owner_hint: asset.owner_hint } : {}),
        ...(asset?.business_criticality ? { business_criticality: asset.business_criticality } : {}),
      },
      owner,
      severity: finding.severity ?? 'medium',
      evidence: {
        summary: evidenceSummary,
        links: [
          { type: 'finding', url: findingEvidenceUrl(finding.id), label: 'Finding evidence' },
          ...(finding.last_waf_validation_run_id
            ? [{
                type: 'validation',
                url: portalPath(`/waf/validations/${finding.last_waf_validation_run_id}`),
                label: 'Validation run',
              }]
            : []),
        ],
      },
      recommended_solution: opts.recommended_solution
        ?? recommendedSolutionForPosture({
          reasonCodes,
          vendorHint: asset?.expected_vendor_hint ?? null,
          postureStatus: opts.posture_status ?? null,
        }),
      retest_url: opts.retest_url ?? wafRetestUrl(wafAssetId),
      status: 'open',
      finding_ids: [finding.id],
      dedupe_key: dedupeKey,
    };

    const existing = getStore().wafActionItems.find(
      (item) =>
        item.tenant_id === ctx.tenantId
        && item.dedupe_key === dedupeKey
        && item.status !== 'resolved'
        && item.status !== 'accepted_risk',
    );

    if (existing) {
      const mergedFindingIds = [...new Set([...(existing.finding_ids ?? []), finding.id])];
      existing.title = fields.title;
      existing.severity = fields.severity;
      existing.owner = fields.owner;
      existing.evidence = fields.evidence;
      existing.recommended_solution = fields.recommended_solution;
      existing.retest_url = fields.retest_url;
      existing.finding_ids = mergedFindingIds;
      existing.updated_at = now;
      validateActionItem(existing);
      audit({
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId,
        actor_role: ctx.role,
        action: 'waf.action_item.updated',
        resource_type: 'waf_action_item',
        resource_id: existing.action_item_id,
        metadata: {
          finding_id: finding.id,
          dedupe_key: dedupeKey,
          reason_codes: reasonCodes,
        },
      });
      persistStore();
      return { action_item: formatActionItem(existing), created: false };
    }

    const normalized = createActionItem(fields);
    const record = {
      ...normalized,
      tenant_id: ctx.tenantId,
      dedupe_key: dedupeKey,
      created_at: now,
      updated_at: now,
    };
    getStore().wafActionItems.push(record);
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'waf.action_item.created',
      resource_type: 'waf_action_item',
      resource_id: record.action_item_id,
      metadata: {
        finding_id: finding.id,
        dedupe_key: dedupeKey,
        category: record.category,
        reason_codes: reasonCodes,
      },
    });
    persistStore();
    return { action_item: formatActionItem(record), created: true };
  } catch (err) {
    return contractError(err);
  }
}

export function patchActionItemStatus(ctx, id, body = {}) {
  ensureStoreShape();
  try {
    assertNoRawWafEvidence(body);
  } catch (err) {
    return contractError(err);
  }

  const record = getStore().wafActionItems.find(
    (item) => item.action_item_id === id && item.tenant_id === ctx.tenantId,
  );
  if (!record) {
    return { error: 'waf_action_item_not_found', status: 404 };
  }

  const nextStatus = typeof body.status === 'string' ? body.status.trim() : '';
  if (!nextStatus || !ACTION_ITEM_STATUSES.includes(nextStatus)) {
    return {
      error: 'invalid_request',
      status: 400,
      message: 'status must be a supported WAF action item workflow state.',
    };
  }

  const previousStatus = record.status;
  const now = new Date().toISOString();
  record.status = nextStatus;
  record.updated_at = now;
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'waf.action_item.updated',
    resource_type: 'waf_action_item',
    resource_id: record.action_item_id,
    metadata: {
      previous_status: previousStatus,
      status: nextStatus,
      ...(typeof body.notes === 'string' && body.notes.trim() ? { notes: body.notes.trim() } : {}),
    },
  });
  persistStore();
  return { action_item: formatActionItem(record) };
}

function parseRemediationDryRunDefault(body, options = {}) {
  if (options.dry_run !== undefined || options.dryRun !== undefined) {
    const value = options.dry_run ?? options.dryRun;
    if (typeof value === 'boolean') return value;
    if (value === '1' || value === 1 || value === 'true') return true;
    if (value === '0' || value === 0 || value === 'false') return false;
    return true;
  }
  if (body?.dry_run !== undefined || body?.dryRun !== undefined) {
    const value = body.dry_run ?? body.dryRun;
    if (typeof value === 'boolean') return value;
    if (value === '1' || value === 1 || value === 'true') return true;
    if (value === '0' || value === 0 || value === 'false') return false;
    return true;
  }
  return true;
}

export async function deliverActionItem(ctx, actionItemId, channel, options = {}) {
  ensureStoreShape();
  try {
    assertNoRawWafEvidence(options);
  } catch (err) {
    return contractError(err);
  }

  const normalizedChannel = normalizeRemediationDeliverChannel(channel);
  if (!normalizedChannel) {
    return {
      error: 'invalid_request',
      status: 400,
      message: `channel must be one of: jira, servicenow, slack, webhook, siem.`,
    };
  }

  const record = getStore().wafActionItems.find(
    (item) => item.action_item_id === actionItemId && item.tenant_id === ctx.tenantId,
  );
  if (!record) {
    return { error: 'waf_action_item_not_found', status: 404 };
  }

  const dryRun = parseRemediationDryRunDefault(options.body, options);
  const connectorType = resolveRemediationConnectorType(normalizedChannel, options);
  const actionItem = {
    ...formatActionItem(record),
    tenant_id: record.tenant_id,
    finding_ids: record.finding_ids,
  };

  let payload;
  try {
    payload = buildRemediationPayload(actionItem, connectorType);
  } catch (err) {
    return contractError(err, err.status ?? 400);
  }

  const delivery = await executeRemediationDelivery({
    channel: normalizedChannel,
    connectorType,
    payload,
    dryRun,
    deliveryMode: options.deliveryMode,
    fetchFn: options.fetchFn,
    destination: options.destination,
  });

  const findingId = record.finding_ids?.[0] ?? null;
  let remediationRecord = null;
  if (findingId) {
    remediationRecord = markFindingRemediationDelivered(ctx, {
      findingId,
      actionItemId: record.action_item_id,
      channel: normalizedChannel,
      targetRef: options.body?.target_ref ?? options.targetRef ?? null,
      dryRun,
    });
  }

  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'waf.action_item.delivered',
    resource_type: 'waf_action_item',
    resource_id: record.action_item_id,
    metadata: {
      channel: normalizedChannel,
      connector: connectorType,
      status: delivery.status,
      dry_run: delivery.dry_run,
      ...(findingId ? { finding_id: findingId } : {}),
      ...(remediationRecord ? { remediation_id: remediationRecord.id } : {}),
      ...(delivery.destination_preview ? { destination_preview: delivery.destination_preview } : {}),
    },
  });
  persistStore();
  return {
    action_item: formatActionItem(record),
    delivery_receipt: {
      action_item_id: record.action_item_id,
      ...delivery,
      ...(remediationRecord
        ? {
            remediation_id: remediationRecord.id,
            remediation_state: remediationRecord.state,
          }
        : {}),
    },
    delivery: {
      action_item_id: record.action_item_id,
      ...delivery,
    },
  };
}

function severityToJiraPriority(severity) {
  const map = { critical: 'Highest', high: 'High', medium: 'Medium', low: 'Low' };
  return map[String(severity ?? '').toLowerCase()] ?? 'Medium';
}

function severityToServiceNowUrgency(severity) {
  const map = { critical: '1', high: '2', medium: '3', low: '4' };
  return map[String(severity ?? '').toLowerCase()] ?? '3';
}

export function buildRemediationPayload(actionItem, connectorType) {
  try {
    const connector = String(connectorType ?? '').trim().toLowerCase();
    if (!REMEDIATION_CONNECTOR_TYPES.includes(connector)) {
      const err = new Error(`Unsupported remediation connector: ${connector || '(empty)'}`);
      err.code = 'invalid_request';
      throw err;
    }
    validateActionItem(actionItem);

    const base = {
      source: 'astranull',
      action_item_id: actionItem.action_item_id,
      category: actionItem.category,
      title: actionItem.title,
      severity: actionItem.severity,
      owner: actionItem.owner,
      asset: actionItem.asset,
      evidence: actionItem.evidence,
      recommended_solution: actionItem.recommended_solution,
      retest_url: actionItem.retest_url,
      status: actionItem.status,
    };

    let payload;
    switch (connector) {
      case 'jira':
        payload = {
          connector: 'jira',
          issue: {
            summary: actionItem.title,
            description: [
              actionItem.evidence.summary,
              '',
              `Recommended fix: ${actionItem.recommended_solution}`,
              `Retest: ${actionItem.retest_url}`,
            ].join('\n'),
            priority: severityToJiraPriority(actionItem.severity),
            labels: ['astranull', 'waf', actionItem.category],
            fields: base,
          },
        };
        break;
      case 'servicenow':
        payload = {
          connector: 'servicenow',
          incident: {
            short_description: actionItem.title,
            description: actionItem.evidence.summary,
            urgency: severityToServiceNowUrgency(actionItem.severity),
            category: 'security',
            subcategory: 'waf_posture',
            assignment_group: actionItem.owner,
            work_notes: actionItem.recommended_solution,
            u_retest_url: actionItem.retest_url,
            fields: base,
          },
        };
        break;
      case 'splunk_hec':
        payload = {
          connector: 'splunk_hec',
          event: buildSiemEventPayload({
            event_type: 'waf.validation.failed',
            tenant_id: actionItem.tenant_id ?? null,
            event_id: actionItem.action_item_id,
            occurred_at: actionItem.updated_at ?? actionItem.created_at ?? new Date().toISOString(),
            severity: actionItem.severity,
            asset: actionItem.asset,
            finding: {
              id: actionItem.finding_ids?.[0] ?? actionItem.action_item_id,
              reason_codes: [],
              summary: actionItem.evidence.summary,
              evidence_url: actionItem.evidence.links?.[0]?.url ?? null,
              retest_url: actionItem.retest_url,
            },
            recommendation: {
              vendor: actionItem.asset?.owner_hint ? 'declared' : 'generic',
              type: actionItem.category,
              summary: actionItem.recommended_solution,
            },
          }),
        };
        break;
      case 'sentinel':
        payload = {
          connector: 'sentinel',
          log_type: 'AstraNull_WAF_Event_CL',
          records: [
            buildSiemEventPayload({
              event_type: 'waf.posture.updated',
              tenant_id: actionItem.tenant_id ?? null,
              event_id: actionItem.action_item_id,
              occurred_at: actionItem.updated_at ?? actionItem.created_at ?? new Date().toISOString(),
              severity: actionItem.severity,
              asset: actionItem.asset,
              finding: {
                id: actionItem.finding_ids?.[0] ?? actionItem.action_item_id,
                reason_codes: [],
                summary: actionItem.evidence.summary,
                evidence_url: actionItem.evidence.links?.[0]?.url ?? null,
                retest_url: actionItem.retest_url,
              },
              recommendation: {
                vendor: 'generic',
                type: actionItem.category,
                summary: actionItem.recommended_solution,
              },
            }),
          ],
        };
        break;
      case 'xsoar':
        payload = {
          connector: 'xsoar',
          incident: {
            name: actionItem.title,
            type: actionItem.category,
            severity: actionItem.severity,
            owner: actionItem.owner,
            domain: actionItem.asset.display,
            description: actionItem.evidence.summary,
            recommended_solution: actionItem.recommended_solution,
            retest_url: actionItem.retest_url,
            customFields: base,
          },
        };
        break;
      case 'slack':
        payload = {
          connector: 'slack',
          text: `[${actionItem.severity}] ${actionItem.title}`,
          blocks: [
            { type: 'section', text: { type: 'mrkdwn', text: `*${actionItem.title}*` } },
            { type: 'section', text: { type: 'mrkdwn', text: actionItem.evidence.summary } },
            { type: 'section', text: { type: 'mrkdwn', text: `Retest: ${actionItem.retest_url}` } },
          ],
          metadata: base,
        };
        break;
      case 'teams':
        payload = {
          connector: 'teams',
          title: actionItem.title,
          summary: actionItem.evidence.summary,
          severity: actionItem.severity,
          retest_url: actionItem.retest_url,
          recommended_solution: actionItem.recommended_solution,
          metadata: base,
        };
        break;
      case 'email':
        payload = {
          connector: 'email',
          subject: `[AstraNull][WAF][${actionItem.severity}] ${actionItem.asset.display}`,
          body: [
            actionItem.title,
            '',
            actionItem.evidence.summary,
            '',
            `Recommended fix: ${actionItem.recommended_solution}`,
            `Retest: ${actionItem.retest_url}`,
          ].join('\n'),
          metadata: base,
        };
        break;
      case 'webhook':
      default:
        payload = {
          connector: 'webhook',
          action_item: base,
        };
        break;
    }

    assertNoRawWafEvidence(payload);
    return payload;
  } catch (err) {
    const wrapped = err;
    wrapped.status = wrapped.status ?? 400;
    throw wrapped;
  }
}

/*
 * Planned HTTP routes (wired in src/server.mjs during integration):
 * - GET  /v1/waf/action-items       requires waf:read
 * - POST /v1/waf/action-items       requires waf:write
 * - PATCH /v1/waf/action-items/:id  requires waf:write
 * - POST /v1/waf/action-items/:id/deliver  requires waf:write
 */

function formatWafException(entry) {
  return {
    ...(entry.id ? { id: entry.id } : {}),
    waf_asset_id: entry.waf_asset_id,
    owner: entry.owner,
    reason: entry.reason,
    expires_at: entry.expires_at,
    scope_hash: entry.scope_hash ?? null,
    approved_at: entry.approved_at,
    approved_by: entry.approved_by,
  };
}

export function listWafExceptions(ctx) {
  ensureStoreShape();
  const now = Date.now();
  return getStore()
    .wafExceptions.filter((entry) => entry.tenant_id === ctx.tenantId)
    .filter((entry) => {
      const expiresAt = entry.expires_at ? Date.parse(entry.expires_at) : Number.NaN;
      return Number.isFinite(expiresAt) && expiresAt > now;
    })
    .map((entry) => formatWafException(entry));
}

export function createWafException(ctx, wafAssetId, body = {}) {
  ensureStoreShape();
  const asset = findAsset(ctx, wafAssetId);
  if (!asset) {
    return { error: 'waf_asset_not_found', status: 404 };
  }
  try {
    assertNoRawWafEvidence(body);
    const normalized = normalizeWafExceptionBody(body);
    const now = new Date().toISOString();
    const id = newId('wafexc');
    const record = {
      id,
      tenant_id: ctx.tenantId,
      waf_asset_id: wafAssetId,
      ...normalized,
      approved_at: now,
      approved_by: ctx.userId,
    };
    getStore().wafExceptions.push(record);
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'waf.exception.created',
      resource_type: 'waf_exception',
      resource_id: id,
      metadata: {
        waf_asset_id: wafAssetId,
        owner: record.owner,
        expires_at: record.expires_at,
        ...(record.scope_hash ? { scope_hash: record.scope_hash } : {}),
      },
    });
    persistStore();
    const current = getCurrentSnapshot(ctx, wafAssetId);
    return {
      exception: formatWafException(record),
      posture: current ? formatSnapshot(current) : null,
    };
  } catch (err) {
    return contractError(err);
  }
}

function listCveItemsForWafReport(ctx, assetIds) {
  ensureStoreShape();
  const matchedItemIds = new Set(
    getStore()
      .cveAssetMatches.filter(
        (match) => match.tenant_id === ctx.tenantId && assetIds.has(match.waf_asset_id),
      )
      .map((match) => match.cve_pipeline_item_id ?? match.cve_item_id)
      .filter(Boolean),
  );
  return getStore()
    .cvePipelineItems.filter((item) => item.tenant_id === ctx.tenantId)
    .filter((item) => matchedItemIds.size === 0 || matchedItemIds.has(item.id))
    .map((item) => ({
      id: item.id,
      cve_id: item.cve_id,
      status: item.status,
      severity: item.severity ?? null,
      triage_score: item.triage_score ?? null,
    }));
}

function listCveMatchesForWafReport(ctx, assetIds) {
  ensureStoreShape();
  return getStore()
    .cveAssetMatches.filter(
      (match) => match.tenant_id === ctx.tenantId && assetIds.has(match.waf_asset_id),
    )
    .map((match) => ({
      waf_asset_id: match.waf_asset_id,
      cve_pipeline_item_id: match.cve_pipeline_item_id ?? match.cve_item_id ?? null,
      cve_item_id: match.cve_item_id ?? match.cve_pipeline_item_id ?? null,
    }));
}

function gatherWafReportSourcesFromStore(ctx) {
  const assets = listWafAssets(ctx);
  const assetIds = new Set(assets.map((asset) => asset.id));
  const snapshotsByAssetId = new Map();
  for (const asset of assets) {
    const snapshot = getCurrentSnapshot(ctx, asset.id);
    if (snapshot) snapshotsByAssetId.set(asset.id, formatSnapshot(snapshot));
  }
  const validations = listWafValidations(ctx);
  const scenarioResultsByRunId = new Map();
  for (const run of validations) {
    const detail = getWafValidation(ctx, run.id);
    scenarioResultsByRunId.set(run.id, detail?.scenario_results ?? []);
  }
  const coverage = getWafCoverage(ctx);
  const analyticsContext = gatherWafAnalyticsContext(ctx);
  const allDriftEvents = listWafDriftEvents(ctx);
  const driftEvents = allDriftEvents.slice(0, WAF_REPORT_DRIFT_LIMIT);
  const driftEventsTruncation = {
    truncated: allDriftEvents.length > driftEvents.length,
    limit: WAF_REPORT_DRIFT_LIMIT,
    total_available: allDriftEvents.length,
    included_count: driftEvents.length,
  };
  return {
    tenantId: ctx.tenantId,
    coverage,
    coverageTrend: coverage.trend ?? [],
    assets,
    snapshotsByAssetId,
    validations,
    scenarioResultsByRunId,
    driftEvents,
    driftEventsTruncation,
    connectors: listConnectors(ctx),
    exceptions: listWafExceptions(ctx),
    cveItems: listCveItemsForWafReport(ctx, assetIds),
    cveMatches: listCveMatchesForWafReport(ctx, assetIds),
    riskRoadmap: buildRiskRoadmap({
      assets: analyticsContext.assets,
      currentSnapshotsByAsset: analyticsContext.currentSnapshotsByAsset,
      validationSummaryByAsset: analyticsContext.validationSummaryByAsset,
      cveMatchesByAsset: analyticsContext.cveMatchesByAsset,
      targetGroups: analyticsContext.targetGroups,
      entities: analyticsContext.entities,
      findingsByAsset: analyticsContext.findingsByAsset,
      actionItemsByAsset: analyticsContext.actionItemsByAsset,
      filters: { limit_per_tier: 50 },
    }),
    vendorBreakdown: buildVendorBreakdown({
      assets: analyticsContext.assets,
      currentSnapshotsByAsset: analyticsContext.currentSnapshotsByAsset,
    }),
    geographyRollup: buildGeographyRollup({
      assets: analyticsContext.assets,
      currentSnapshotsByAsset: analyticsContext.currentSnapshotsByAsset,
      targetGroups: analyticsContext.targetGroups,
      environments: analyticsContext.environments,
      entities: analyticsContext.entities,
    }),
  };
}

export function composeWafReportExport(ctx, kind, format, payload) {
  const priorGlobal = getLatestChainedAuditEntry();
  const priorTenant = getLatestChainedAuditEntryForTenant(ctx.tenantId);
  const prepared = prepareWafReportExport(ctx, kind, format, payload, {
    previousAuditHash: priorGlobal?.entry_hash ?? null,
    previousTenantAuditHash: priorTenant?.entry_hash ?? null,
  });
  if (prepared.error) return prepared;

  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'waf.report.exported',
    resource_type: 'waf_report',
    resource_id: kind,
    metadata: custodyAuditMetadata(prepared.custody),
  });
  persistStore();
  return prepared;
}

export function exportWafReport(ctx, kind, format = 'json') {
  const normalizedKind = normalizeWafReportKind(kind);
  if (!WAF_REPORT_KINDS.has(normalizedKind)) {
    return { error: 'waf_report_kind_invalid', status: 400 };
  }
  const sources = gatherWafReportSourcesFromStore(ctx);
  const payload = buildWafReportPayload(normalizedKind, sources);
  return composeWafReportExport(ctx, normalizedKind, format, payload);
}

function formatWafProduct(product) {
  return {
    id: product.id,
    vendor: product.vendor,
    product: product.product,
    deployment_type: product.deployment_type,
    fingerprint_version: product.fingerprint_version,
    enabled: product.enabled !== false,
    confidence_rules_json: product.confidence_rules_json ?? {},
  };
}

function formatScenarioIntake(record) {
  return {
    id: record.id,
    pattern_title: record.pattern_title,
    advisory_refs: record.advisory_refs ?? [],
    proposed_scenario_family: record.proposed_scenario_family ?? null,
    risk_class: record.risk_class,
    intake_stage: record.intake_stage,
    notes: record.notes ?? null,
    threat_summary: record.threat_summary ?? null,
    created_at: record.created_at,
    updated_at: record.updated_at,
  };
}

export function listWafProducts(ctx) {
  ensureStoreShape();
  const products = getStore().wafProducts.filter((product) => product.enabled !== false);
  return {
    items: products.map(formatWafProduct),
    summary: summarizeWafProductCatalog(products),
  };
}

export function listScenarioIntakes(ctx) {
  ensureStoreShape();
  const items = getStore()
    .wafScenarioIntakes
    .filter((record) => record.tenant_id === ctx.tenantId)
    .sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)))
    .map(formatScenarioIntake);
  return { items };
}

export function submitScenarioIntake(ctx, body = {}) {
  ensureStoreShape();
  try {
    assertNoRawWafEvidence(body);
    const normalized = normalizeScenarioIntakeInput(body);
    const now = new Date().toISOString();
    const id = newId('wafintake');
    const record = {
      id,
      tenant_id: ctx.tenantId,
      ...normalized,
      intake_stage: WAF_SCENARIO_INTAKE_STAGES[0],
      created_at: now,
      updated_at: now,
    };
    getStore().wafScenarioIntakes.push(record);
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'waf.scenario_intake.submitted',
      resource_type: 'waf_scenario_intake',
      resource_id: id,
      metadata: {
        pattern_title: record.pattern_title,
        advisory_refs: record.advisory_refs,
        proposed_scenario_family: record.proposed_scenario_family ?? null,
        risk_class: record.risk_class,
      },
    });
    persistStore();
    return { intake: formatScenarioIntake(record), status: 'accepted' };
  } catch (err) {
    return contractError(err);
  }
}

export function disableConnector(ctx, id, body = {}) {
  ensureStoreShape();
  try {
    assertSafeConnectorPayload(body);
  } catch (err) {
    return contractError(err);
  }
  const connector = findConnector(ctx, id);
  if (!connector) {
    return { error: 'connector_not_found', status: 404 };
  }
  const now = new Date().toISOString();
  connector.status = 'disabled';
  connector.updated_at = now;
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'connector.disabled',
    resource_type: 'waf_connector',
    resource_id: connector.id,
    metadata: { provider: connector.provider, connector_id: connector.id },
  });
  persistStore();
  return { connector: formatConnector(connector) };
}

const EMPTY_COVERAGE_SUMMARY = Object.freeze({
  assets_total: 0,
  protected: 0,
  underprotected: 0,
  unknown: 0,
  coverage_pct: 0,
  by_vendor: {},
  connectors_active: 0,
  connectors_degraded: 0,
  connectors_disabled: 0,
  refreshed_at: null,
});

function indexCurrentSnapshotsForSummary(snapshots = []) {
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

function readCoverageSummaryForTenant(tenantId) {
  const store = getStore();
  const cached = store.wafCoverageSummaries?.[tenantId];
  if (cached) return mapWafCoverageSummaryRow(cached);

  const assets = (store.wafAssets ?? []).filter((asset) => asset.tenant_id === tenantId);
  const snapshots = (store.wafPostureSnapshots ?? []).filter((snap) => snap.tenant_id === tenantId);
  const connectors = (store.wafConnectors ?? []).filter((row) => row.tenant_id === tenantId);
  if (assets.length === 0 && connectors.length === 0) return null;

  const summary = computeWafCoverageSummaryRow({
    assets,
    currentSnapshotsByAsset: indexCurrentSnapshotsForSummary(snapshots),
    connectors,
  });
  if (!store.wafCoverageSummaries || typeof store.wafCoverageSummaries !== 'object') {
    store.wafCoverageSummaries = {};
  }
  store.wafCoverageSummaries[tenantId] = summary;
  return mapWafCoverageSummaryRow(summary);
}

/**
 * WAF coverage summary from materialized view (portal revamp §4.3).
 *
 * @param {import('../context.mjs').TenantScope} ctx
 */
export function getCoverageSummary(ctx) {
  const row = readCoverageSummaryForTenant(ctx.tenantId);
  if (row) return row;
  return {
    ...EMPTY_COVERAGE_SUMMARY,
    meta: { empty_reason: 'coverage_summary_not_populated', tenant_id: ctx.tenantId },
  };
}

/**
 * Connector inventory picker stub (portal revamp §3.5).
 *
 * @param {import('../context.mjs').TenantScope} ctx
 * @param {string} connectorId
 * @param {{ cursor?: string, limit?: number }} [_query]
 */
export function getConnectorInventory(ctx, connectorId, query = {}) {
  const connector = findConnector(ctx, connectorId);
  if (!connector) {
    return { error: 'connector_not_found', status: 404 };
  }
  if (connector.status === 'disabled') {
    return { error: 'connector_disabled', status: 409 };
  }

  const inventory = Array.isArray(connector.inventory_items)
    ? connector.inventory_items
    : (connector.inventory_cache?.items ?? []);

  const limit = Number(query.limit) || 50;
  const paged = paginateItems(inventory, {
    limit,
    cursor: query.cursor,
    cursorField: 'value',
  });

  return {
    provider: connector.provider ?? null,
    account: connector.account_id ?? connector.account ?? connector.config_json?.account ?? null,
    scope: connector.scope ?? connector.config_json?.scope ?? 'read_only',
    discovered_at: connector.inventory_cache?.discovered_at
      ?? connector.last_success_at
      ?? connector.last_polled_at
      ?? null,
    items: paged.items,
    count: paged.items.length,
    next_cursor: paged.next_cursor ?? undefined,
    meta: paged.items.length
      ? undefined
      : { empty_reason: 'connector_inventory_not_populated', connector_id: connectorId },
  };
}
