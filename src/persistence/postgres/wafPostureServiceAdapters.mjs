import {
  assertNoRawWafEvidence,
  classifyWafPosture,
  deriveControlBypassStatus,
  formatControlBypassUxLabel,
  mapReasonCodesToControlBypassClasses,
  normalizeScenarioIntakeInput,
  normalizeWafAssetInput,
  normalizeWafEvidenceSummary,
  normalizeWafExceptionBody,
  normalizeWafValidationRequest,
  WAF_EXPECTED_ACTIONS,
  WAF_SCENARIO_FAMILIES,
  WAF_SCENARIO_INTAKE_STAGES,
} from '../../contracts/wafPosture.mjs';
import {
  listWafProductCatalogEntries,
  summarizeWafProductCatalog,
} from '../../lib/wafProductCatalog.mjs';
import {
  buildProviderPollFailure,
  executeConnectorProviderPoll,
  shouldAttemptOutboundConnectorPoll,
} from '../../lib/connectorProviders/pollWorker.mjs';
import { supportsOutboundProviderPoll } from '../../lib/connectorProviders/index.mjs';
import {
  booleanFieldExplicit,
  deriveWafSignalsFromBoundEvents,
} from '../../lib/wafBoundRunCorrelation.mjs';
import {
  buildCorroborationFromValidationEvidence,
  buildWafEvidenceCorroboration,
  protectedFinalizeEvidenceRequired,
  stripClientAssertedAgentEvidence,
} from '../../lib/wafProtectedEvidence.mjs';
import { newId } from '../../lib/ids.mjs';
import { redactObject } from '../../lib/redact.mjs';
import { buildSecretAad, decryptSecret, loadSecretEncryptionKey } from '../../lib/secrets.mjs';
import {
  buildWafReportPayload,
  prepareWafReportExport,
  WAF_REPORT_DRIFT_LIMIT,
  WAF_REPORT_KINDS,
  WAF_REPORT_VALIDATION_LIMIT,
} from '../../lib/wafReports.mjs';
import {
  formatConnectorForApi,
  formatConnectorSnapshotForApi,
  formatDriftEventForApi,
  formatPostureSnapshotForApi,
} from './wafPostureRepository.mjs';
import {
  buildCoverageSummary,
  buildCriticalityRollup,
  buildEntityRollup,
  buildGeographyRollup,
  buildRiskRoadmap,
  buildVendorBreakdown,
  buildVendorConsolidation,
} from '../../services/wafCoverageService.mjs';
import {
  computeAssetRiskAssessment,
  enrichSnapshotWithRisk,
} from '../../services/wafRiskService.mjs';

export const WAF_POSTURE_REPOSITORY_METHODS = Object.freeze([
  'listWafAssets',
  'createWafAsset',
  'getWafAsset',
  'updateWafAsset',
  'listCurrentPostureSnapshots',
  'getCurrentPostureSnapshot',
  'listPostureSnapshotsSince',
  'listLatestValidationSummariesByAsset',
  'listTenantCveAssetMatches',
  'listWafFindingIdsByAsset',
  'listWafActionItemIdsByAsset',
  'listWafValidationRuns',
  'createWafValidationRun',
  'getWafValidationRun',
  'listWafScenarioResultsForRun',
  'finalizeWafValidationBundle',
  'upsertWafPostureFinding',
  'listWafDriftEvents',
  'upsertWafDriftEvent',
  'patchWafDriftEvent',
  'listConnectors',
  'createConnector',
  'getConnector',
  'updateConnectorStatus',
  'createConnectorSnapshots',
  'listConnectorSnapshots',
  'listWafExceptions',
  'createWafException',
]);

export const POSTGRES_WAF_POSTURE_SERVICE_METHODS = Object.freeze([
  'listWafAssets',
  'createWafAsset',
  'getWafAsset',
  'patchWafAsset',
  'getWafCoverage',
  'getWafCoverageVendors',
  'getWafCoverageEntities',
  'getWafCoverageGeography',
  'getWafCoverageCriticality',
  'getWafRiskRoadmap',
  'getWafVendorConsolidation',
  'listWafProducts',
  'listScenarioIntakes',
  'submitScenarioIntake',
  'createWafValidation',
  'listWafValidations',
  'getWafValidation',
  'finalizeWafValidation',
  'listWafDriftEvents',
  'patchWafDriftEvent',
  'listConnectors',
  'createConnector',
  'validateConnector',
  'pollConnector',
  'listConnectorSnapshots',
  'disableConnector',
  'exportWafReport',
  'listWafExceptions',
  'createWafException',
]);

function formatPostgresScenarioIntake(record) {
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

function buildPostgresAssetEffectiveness(reasonCodes = []) {
  const codes = Array.isArray(reasonCodes) ? reasonCodes : [];
  const control_bypass_status = deriveControlBypassStatus({ reason_codes: codes });
  return {
    scenario_pass_rate: null,
    control_bypass_status,
    control_bypass_label: formatControlBypassUxLabel(control_bypass_status),
    control_bypass_classes: mapReasonCodesToControlBypassClasses(codes).map((bypassClass) => ({
      id: bypassClass.id,
      label: bypassClass.label,
    })),
  };
}

const WAF_DRIFT_EVENT_STATUSES = new Set([
  'open',
  'acknowledged',
  'remediation_started',
  'retest_pending',
  'resolved',
  'accepted_risk',
  'false_positive',
]);

const WAF_DRIFT_RESOLVED_STATUSES = new Set(['resolved', 'accepted_risk', 'false_positive']);

const WAF_CONNECTOR_PROVIDERS = new Set([
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

const WAF_CONNECTOR_CONFIG_ALLOWLIST = new Set([
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

const WAF_CONNECTOR_SNAPSHOT_SUMMARY_ALLOWLIST = new Set([
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

const WAF_CONNECTOR_SLICE_CAPABILITIES = Object.freeze([
  'metadata_snapshot_ingest',
  'read_only_config',
]);



const WAF_POSTURE_VALIDATION_EVIDENCE_METHODS = Object.freeze([
  'getTestRun',
  'listRunEvents',
]);

const WAF_BOUND_RUN_EVENTS_LIMIT = 1000;

function connectorProviderCapabilities(provider, connector = null) {
  return {
    provider,
    read_only_metadata: true,
    outbound_polling: supportsOutboundProviderPoll(provider) && Boolean(connector?.secret_id),
    snapshot_kinds: provider === 'webhook'
      ? ['waf_policy']
      : ['waf_policy', 'cdn_property', 'dns_zone'],
  };
}

function connectorPollHealthUpdates(health, now) {
  if (health?.status === 'active' || health?.status === 'degraded') {
    return {
      status: health.status,
      last_success_at: now,
      last_error_at: null,
      updated_at: now,
    };
  }
  return {
    status: health?.status ?? 'error',
    last_error_at: now,
    updated_at: now,
  };
}

function normalizeConnectorFieldKey(key) {
  return String(key)
    .replace(/([a-z])([A-Z])/g, '$1_$2')
    .replace(/[^A-Za-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase();
}

function normalizeConnectorConfig(input) {
  const raw = input === null || input === undefined ? {} : input;
  if (typeof raw !== 'object' || Array.isArray(raw)) {
    const err = new Error('Connector config must be a plain object.');
    err.code = 'invalid_connector_config';
    throw err;
  }
  assertNoRawWafEvidence(raw);
  const config = {};
  for (const [key, value] of Object.entries(raw)) {
    const normalizedKey = normalizeConnectorFieldKey(key);
    if (!WAF_CONNECTOR_CONFIG_ALLOWLIST.has(normalizedKey)) {
      const err = new Error(`Disallowed connector config field: ${key}`);
      err.code = 'invalid_connector_config';
      throw err;
    }
    if (normalizedKey === 'read_only') {
      config.read_only = parseBooleanField({ read_only: value }, 'read_only', 'readOnly', false);
    } else if (normalizedKey === 'polling_interval_minutes') {
      const minutes = Number(value);
      config.polling_interval_minutes = Number.isFinite(minutes) && minutes > 0 ? minutes : null;
    } else if (normalizedKey === 'tag_summary') {
      config.tag_summary = Array.isArray(value)
        ? value.map((entry) => String(entry).trim()).filter(Boolean)
        : value;
    } else if (typeof value === 'string') {
      config[normalizedKey] = value.trim();
    } else {
      config[normalizedKey] = value;
    }
  }
  return config;
}

function normalizeConnectorSnapshotSummary(input) {
  const raw = input === null || input === undefined ? {} : input;
  if (typeof raw !== 'object' || Array.isArray(raw)) {
    const err = new Error('Connector snapshot summary must be a plain object.');
    err.code = 'invalid_connector_snapshot';
    throw err;
  }
  assertNoRawWafEvidence(raw);
  const summary = {};
  for (const [key, value] of Object.entries(raw)) {
    const normalizedKey = normalizeConnectorFieldKey(key);
    if (!WAF_CONNECTOR_SNAPSHOT_SUMMARY_ALLOWLIST.has(normalizedKey)) {
      const err = new Error(`Disallowed connector snapshot summary field: ${key}`);
      err.code = 'invalid_connector_snapshot';
      throw err;
    }
    if (normalizedKey === 'hostnames') {
      summary.hostnames = Array.isArray(value)
        ? value.map((entry) => String(entry).trim()).filter(Boolean)
        : [];
    } else if (normalizedKey === 'tags') {
      summary.tags = Array.isArray(value)
        ? value.map((entry) => String(entry).trim()).filter(Boolean)
        : [];
    } else if (normalizedKey === 'rule_count') {
      const count = Number(value);
      summary.rule_count = Number.isFinite(count) ? count : null;
    } else if (typeof value === 'string') {
      summary[normalizedKey] = value.trim();
    } else {
      summary[normalizedKey] = value;
    }
  }
  return summary;
}

function normalizeConnectorSnapshotInput(entry, provider) {
  if (entry === null || entry === undefined || typeof entry !== 'object' || Array.isArray(entry)) {
    const err = new Error('Connector snapshot must be a plain object.');
    err.code = 'invalid_connector_snapshot';
    throw err;
  }
  assertNoRawWafEvidence(entry);
  const snapshotKind = String(entry.snapshot_kind ?? entry.snapshotKind ?? 'waf_policy').trim();
  const resourceRefHash = String(entry.resource_ref_hash ?? entry.resourceRefHash ?? '').trim();
  if (!resourceRefHash) {
    const err = new Error('Connector snapshot requires resource_ref_hash.');
    err.code = 'invalid_connector_snapshot';
    throw err;
  }
  const summaryRaw = entry.summary ?? entry.summary_json ?? {};
  const summary = normalizeConnectorSnapshotSummary(summaryRaw);
  const configHash =
    typeof entry.config_hash === 'string'
      ? entry.config_hash.trim()
      : typeof entry.configHash === 'string'
        ? entry.configHash.trim()
        : summary.config_hash ?? null;
  const displayRef =
    typeof entry.display_ref === 'string'
      ? entry.display_ref.trim()
      : typeof entry.displayRef === 'string'
        ? entry.displayRef.trim()
        : null;
  const observedAt =
    typeof entry.observed_at === 'string' && entry.observed_at.trim()
      ? entry.observed_at.trim()
      : typeof entry.observedAt === 'string' && entry.observedAt.trim()
        ? entry.observedAt.trim()
        : null;
  return {
    snapshot_kind: snapshotKind,
    resource_ref_hash: resourceRefHash,
    display_ref: displayRef,
    summary_json: summary,
    config_hash: configHash,
    observed_at: observedAt,
    provider,
  };
}

function deriveInitialConnectorStatus(body, config) {
  const requested = typeof body.status === 'string' ? body.status.trim() : '';
  if ((requested === 'active' || requested === 'validating') && config.read_only === true) {
    return requested;
  }
  return 'disabled';
}

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

function assertWafPostureRepositories(repositories) {
  const wafPosture = repositories?.wafPosture;
  if (!wafPosture || typeof wafPosture !== 'object') {
    throw new Error('Postgres WAF posture service adapter requires repositories.wafPosture.');
  }
  for (const method of WAF_POSTURE_REPOSITORY_METHODS) {
    if (typeof wafPosture[method] !== 'function') {
      throw new Error(`Postgres WAF posture service adapter requires wafPosture.${method}().`);
    }
  }

  const coreCatalog = repositories?.coreCatalog;
  if (!coreCatalog || typeof coreCatalog.getTargetGroup !== 'function') {
    throw new Error('Postgres WAF posture service adapter requires coreCatalog.getTargetGroup().');
  }

  const audit = repositories?.audit;
  if (!audit || typeof audit.appendAuditEvent !== 'function') {
    throw new Error('Postgres WAF posture service adapter requires audit.appendAuditEvent().');
  }
  if (typeof audit.getLastAuditEntry !== 'function') {
    throw new Error('Postgres WAF posture service adapter requires audit.getLastAuditEntry().');
  }

  const validationEvidence = repositories?.validationEvidence;
  if (!validationEvidence || typeof validationEvidence !== 'object') {
    throw new Error('Postgres WAF posture service adapter requires repositories.validationEvidence.');
  }
  for (const method of WAF_POSTURE_VALIDATION_EVIDENCE_METHODS) {
    if (typeof validationEvidence[method] !== 'function') {
      throw new Error(
        `Postgres WAF posture service adapter requires validationEvidence.${method}().`,
      );
    }
  }
}

const CVE_REPORT_STATUS_BY_STAGE = Object.freeze({
  ingest: 'ingested',
  triage: 'triaged',
  match: 'matched',
  validate: 'validation_pending',
  recommend: 'mitigation_recommended',
  ticket: 'mitigation_recommended',
  retest: 'exposed',
  resolved: 'resolved',
});

function normalizeCveReportStatus(item = {}) {
  const raw = String(item.status ?? item.stage ?? item.state ?? '').trim();
  return CVE_REPORT_STATUS_BY_STAGE[raw] ?? raw;
}

function normalizePostgresCveItemForReport(item = {}) {
  const triageResult = item.triage_result ?? item.triage_summary_json?.triage_result ?? null;
  return {
    id: item.id,
    cve_id: item.cve_id,
    status: normalizeCveReportStatus(item),
    severity: item.severity ?? null,
    triage_score: item.triage_score ?? triageResult?.score ?? null,
  };
}

function normalizePostgresCveMatchForReport(match = {}) {
  return {
    waf_asset_id: match.waf_asset_id,
    cve_pipeline_item_id: match.cve_pipeline_item_id ?? match.cve_item_id ?? null,
    cve_item_id: match.cve_item_id ?? match.cve_pipeline_item_id ?? null,
  };
}

async function listPostgresWafExceptionsForReport(wafRepo, ctx, assetIds) {
  const now = Date.now();
  const records = await wafRepo.listWafExceptions(ctx);
  return (Array.isArray(records) ? records : [])
    .filter((entry) => assetIds.has(entry.waf_asset_id))
    .filter((entry) => {
      const expiresAt = entry.expires_at ? Date.parse(entry.expires_at) : Number.NaN;
      return Number.isFinite(expiresAt) && expiresAt > now;
    });
}

async function listPostgresCveSourcesForReport(cveRepo, ctx, assetIds) {
  if (
    !cveRepo
    || typeof cveRepo.listCvePipelineItems !== 'function'
    || typeof cveRepo.listCveAssetMatches !== 'function'
  ) {
    return { cveItems: [], cveMatches: [] };
  }

  const items = await cveRepo.listCvePipelineItems(ctx);
  const normalizedItems = Array.isArray(items) ? items : [];
  const cveMatches = [];
  const matchedItemIds = new Set();
  for (const item of normalizedItems) {
    const matches = await cveRepo.listCveAssetMatches(ctx, item.id);
    for (const match of Array.isArray(matches) ? matches : []) {
      if (!assetIds.has(match.waf_asset_id)) continue;
      cveMatches.push(normalizePostgresCveMatchForReport(match));
      matchedItemIds.add(item.id);
    }
  }

  const cveItems = normalizedItems
    .filter((item) => matchedItemIds.has(item.id))
    .map((item) => normalizePostgresCveItemForReport(item));

  return { cveItems, cveMatches };
}

async function deriveWafSignalsFromBoundRun(validationEvidence, ctx, testRunId) {
  const [probes, agents] = await Promise.all([
    validationEvidence.listRunEvents(ctx, testRunId, {
      signalType: 'probe_result',
      limit: WAF_BOUND_RUN_EVENTS_LIMIT,
    }),
    validationEvidence.listRunEvents(ctx, testRunId, {
      signalType: 'agent_observation',
      limit: WAF_BOUND_RUN_EVENTS_LIMIT,
    }),
  ]);
  return deriveWafSignalsFromBoundEvents({ probes, agents });
}

async function validateWafTestRunBinding(validationEvidence, ctx, testRunId, asset) {
  const testRun = await validationEvidence.getTestRun(ctx, testRunId);
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

function contractError(err, fallbackStatus = 400) {
  return {
    error: err.code ?? 'invalid_request',
    status: fallbackStatus,
    message: err.message,
  };
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

const WAF_POSTURE_FINDING_REMEDIATION = 'waf_posture_remediation';

function wafPostureCheckId(assetId) {
  return `waf.posture.${assetId}`;
}

function deriveWafFindingSeverity({
  postureStatus,
  reasonCodes,
  businessCriticality,
  originBypassConfirmed,
}) {
  const highCritAsset =
    businessCriticality === 'critical' || businessCriticality === 'high';
  if (postureStatus === 'unprotected') {
    return highCritAsset ? 'critical' : 'high';
  }
  if (postureStatus === 'underprotected') {
    if (originBypassConfirmed || reasonCodes.includes('origin_bypass_confirmed')) {
      return 'critical';
    }
    return highCritAsset ? 'high' : 'medium';
  }
  return 'medium';
}

function buildWafFindingTitle(postureStatus, canonicalUrl) {
  const label = typeof canonicalUrl === 'string' && canonicalUrl.trim()
    ? canonicalUrl.trim()
    : 'WAF asset';
  return `WAF posture ${postureStatus}: ${label}`;
}

function buildWafFindingNotes({ reasonCodes, validationRunId, wafAssetId }) {
  const codes = Array.isArray(reasonCodes) ? reasonCodes.join(', ') : 'none';
  return [
    'WAF posture finding.',
    `reason_codes: ${codes}`,
    `waf_validation_run_id: ${validationRunId}`,
    `waf_asset_id: ${wafAssetId}`,
    'Retest with a safe WAF validation after remediation.',
  ].join(' ');
}

function postureStatusNeedsFinding(status) {
  return status === 'underprotected' || status === 'unprotected';
}

function buildDriftBeforeSummary(snapshot) {
  if (!snapshot) return {};
  return {
    posture_status: snapshot.status,
    reason_codes: snapshot.reason_codes ?? [],
    detected_vendor: snapshot.detected_vendor ?? null,
    detected_product: snapshot.detected_product ?? null,
  };
}

function buildDriftAfterSummary({
  postureStatus,
  reasonCodes,
  wafDetected,
  validationRunId,
}) {
  return {
    posture_status: postureStatus,
    reason_codes: reasonCodes ?? [],
    waf_detected: wafDetected,
    waf_validation_run_id: validationRunId,
  };
}

function deriveWafDriftEventSpecs({
  previousSnapshot,
  postureStatus,
  reasonCodes,
  wafDetected,
  businessCriticality,
}) {
  const previousStatus = previousSnapshot?.status ?? null;
  if (previousStatus !== 'protected') return [];

  const beforeSummary = buildDriftBeforeSummary(previousSnapshot);
  const afterSummary = buildDriftAfterSummary({
    postureStatus,
    reasonCodes,
    wafDetected,
    validationRunId: null,
  });
  const highCritAsset =
    businessCriticality === 'critical' || businessCriticality === 'high';
  const specs = [];

  if (postureStatus === 'unprotected') {
    const driftType = wafDetected ? 'mode_change' : 'fingerprint_lost';
    specs.push({
      drift_type: driftType,
      severity: 'critical',
      before_summary: beforeSummary,
      after_summary: afterSummary,
    });
  } else if (postureStatus === 'underprotected') {
    if (reasonCodes.includes('origin_bypass_confirmed')) {
      specs.push({
        drift_type: 'origin_bypass_new',
        severity: 'critical',
        before_summary: beforeSummary,
        after_summary: afterSummary,
      });
    }
    if (reasonCodes.includes('marker_rule_not_blocking')) {
      specs.push({
        drift_type: 'marker_failed',
        severity: highCritAsset ? 'critical' : 'high',
        before_summary: beforeSummary,
        after_summary: afterSummary,
      });
    }
  } else if (postureStatus === 'unknown') {
    const evidenceLost =
      !wafDetected
      || reasonCodes.includes('waf_fingerprint_lost')
      || reasonCodes.includes('insufficient_validation_evidence');
    if (evidenceLost) {
      specs.push({
        drift_type: 'fingerprint_lost',
        severity: highCritAsset ? 'high' : 'medium',
        before_summary: beforeSummary,
        after_summary: afterSummary,
      });
    }
  }

  return specs;
}

async function persistWafDriftEventsFromFinalize({
  wafRepo,
  auditRepo,
  ctx,
  specs,
  wafAssetId,
  validationRunId,
  findingId,
  postureFrom,
  postureTo,
  reasonCodes,
  now,
  newIdFn,
}) {
  for (const spec of specs) {
    const driftId = newIdFn('id');
    const afterSummary = {
      ...spec.after_summary,
      waf_validation_run_id: validationRunId,
    };
    const upsertResult = await wafRepo.upsertWafDriftEvent(ctx, {
      id: driftId,
      waf_asset_id: wafAssetId,
      drift_type: spec.drift_type,
      severity: spec.severity,
      before_summary: spec.before_summary,
      after_summary: afterSummary,
      status: 'open',
      finding_id: findingId ?? null,
      created_at: now,
    });
    const driftEvent = upsertResult?.drift_event;
    await auditRepo.appendAuditEvent({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'waf.drift.detected',
      resource_type: 'waf_drift_event',
      resource_id: driftEvent?.id ?? driftId,
      metadata: redactObject({
        waf_asset_id: wafAssetId,
        drift_type: spec.drift_type,
        severity: spec.severity,
        posture_from: postureFrom,
        posture_to: postureTo,
        reason_codes: reasonCodes,
      }),
    });
  }
}

function enrichAssetWithPostureStatus(asset, snapshotByAssetId) {
  const snap = snapshotByAssetId.get(asset.id);
  if (!snap) {
    return { ...asset, status: 'unknown' };
  }
  return { ...asset, status: snap.status };
}

function resolveWindowDays(options = {}) {
  const raw = options.window_days ?? options.windowDays ?? 90;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed <= 0) return 90;
  return Math.min(Math.max(Math.trunc(parsed), 1), 365);
}

async function gatherPostgresWafAnalyticsContext(ctx, wafRepo, coreCatalog, options = {}) {
  const windowDays = resolveWindowDays(options);
  const since = new Date();
  since.setUTCDate(since.getUTCDate() - windowDays);
  const [
    assets,
    snapshots,
    historicalSnapshots,
    targetGroups,
    environments,
    validationSummaryByAsset,
    cveMatchesByAsset,
    findingsByAsset,
    actionItemsByAsset,
    connectors,
    driftEvents,
  ] = await Promise.all([
    wafRepo.listWafAssets(ctx),
    wafRepo.listCurrentPostureSnapshots(ctx),
    wafRepo.listPostureSnapshotsSince(ctx, since.toISOString()),
    coreCatalog.listTargetGroups(ctx),
    coreCatalog.listEnvironments(ctx),
    wafRepo.listLatestValidationSummariesByAsset(ctx),
    wafRepo.listTenantCveAssetMatches(ctx),
    wafRepo.listWafFindingIdsByAsset(ctx),
    wafRepo.listWafActionItemIdsByAsset(ctx),
    wafRepo.listConnectors(ctx),
    wafRepo.listWafDriftEvents(ctx),
  ]);
  const currentSnapshotsByAsset = new Map(snapshots.map((snapshot) => [snapshot.waf_asset_id, snapshot]));
  return {
    assets,
    currentSnapshotsByAsset,
    historicalSnapshots,
    targetGroups,
    environments,
    entities: [],
    validationSummaryByAsset,
    cveMatchesByAsset,
    findingsByAsset,
    actionItemsByAsset,
    connectors,
    driftEvents,
    windowDays,
  };
}

function buildPostgresRiskAssessment(asset, snapshot, summary, targetGroups, cveMatchesByAsset, computedAt) {
  const targetGroup = targetGroups.find((group) => group.id === asset.target_group_id) ?? null;
  return computeAssetRiskAssessment({
    asset,
    snapshot,
    validationSummary: summary,
    cveMatches: cveMatchesByAsset.get(asset.id) ?? [],
    targetGroup,
    computedAt,
  });
}

export function createPostgresWafPostureServices(repositories, options = {}) {
  assertWafPostureRepositories(repositories);
  const wafRepo = repositories.wafPosture;
  const coreCatalog = repositories.coreCatalog;
  const auditRepo = repositories.audit;
  const validationEvidence = repositories.validationEvidence;
  const secretVaultRepo = repositories.secretVault;
  const cveRepo = repositories.cvePipeline;
  const nowFn = options.now ?? (() => new Date());
  const newIdFn = options.newId ?? newId;
  const encryptionKey = options.encryptionKey
    ?? loadSecretEncryptionKey(options.env ?? process.env);

  async function postgresConnectorSecretResolver(ctx, secretId) {
    if (!secretVaultRepo || typeof secretVaultRepo.getEncryptedSecretById !== 'function') {
      return { error: 'encryption_not_configured' };
    }
    if (!encryptionKey) return { error: 'encryption_not_configured' };
    const record = await secretVaultRepo.getEncryptedSecretById(ctx, secretId);
    if (!record) return { error: 'secret_not_found' };
    const plaintext = decryptSecret(record.envelope, encryptionKey, buildSecretAad(record));
    return { plaintext };
  }

  return {
    async listWafAssets(ctx) {
      const assets = await wafRepo.listWafAssets(ctx);
      const snapshots = await wafRepo.listCurrentPostureSnapshots(ctx);
      const byAsset = new Map(snapshots.map((s) => [s.waf_asset_id, s]));
      return assets.map((asset) => enrichAssetWithPostureStatus(asset, byAsset));
    },

    async createWafAsset(ctx, body) {
      try {
        assertNoRawWafEvidence(body);
        const normalized = normalizeWafAssetInput(body);
        const targetGroup = await coreCatalog.getTargetGroup(ctx, normalized.target_group_id);
        if (!targetGroup) {
          return {
            error: 'waf_asset_not_found',
            status: 404,
            message: 'Target group not found for tenant.',
          };
        }
        const id = newIdFn('id');
        const now = nowFn().toISOString();
        const record = {
          id,
          tenant_id: ctx.tenantId,
          target_group_id: normalized.target_group_id,
          target_id: normalized.target_id,
          canonical_url: normalized.canonical_url,
          asset_kind: normalized.asset_kind,
          expected_waf_required: normalized.expected_waf_required,
          expected_vendor_hint: normalized.expected_vendor_hint,
          business_criticality: normalized.business_criticality,
          traffic_tier: normalized.traffic_tier,
          compliance_tags: normalized.compliance_tags,
          owner_hint: normalized.owner_hint,
          created_at: now,
          updated_at: now,
        };
        const asset = await wafRepo.createWafAsset(ctx, record);
        await auditRepo.appendAuditEvent({
          tenant_id: ctx.tenantId,
          actor_user_id: ctx.userId,
          actor_role: ctx.role,
          action: 'waf.asset.created',
          resource_type: 'waf_asset',
          resource_id: id,
          metadata: redactObject({
            target_group_id: asset.target_group_id,
            ...(asset.target_id ? { target_id: asset.target_id } : {}),
          }),
        });
        return { asset: enrichAssetWithPostureStatus(asset, new Map()) };
      } catch (err) {
        return contractError(err);
      }
    },

    async getWafAsset(ctx, id) {
      const asset = await wafRepo.getWafAsset(ctx, id);
      if (!asset) return null;
      const current = await wafRepo.getCurrentPostureSnapshot(ctx, id);
      const reasonCodes = current?.reason_codes ?? [];
      return {
        asset: enrichAssetWithPostureStatus(asset, current ? new Map([[id, current]]) : new Map()),
        ...(current ? { current_posture: formatPostureSnapshotForApi(current) } : {}),
        effectiveness: buildPostgresAssetEffectiveness(reasonCodes),
      };
    },

    async patchWafAsset(ctx, id, body) {
      const asset = await wafRepo.getWafAsset(ctx, id);
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
        const updates = { updated_at: nowFn().toISOString() };
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
          if (value) updates.canonical_url = value;
        }
        if (body.target_id !== undefined) {
          updates.target_id =
            typeof body.target_id === 'string' ? body.target_id.trim() : body.target_id;
        }
        if (body.asset_kind !== undefined) {
          updates.asset_kind =
            typeof body.asset_kind === 'string' ? body.asset_kind.trim() : body.asset_kind;
        }
        if (body.expected_vendor_hint !== undefined) {
          updates.expected_vendor_hint =
            typeof body.expected_vendor_hint === 'string'
              ? body.expected_vendor_hint.trim()
              : body.expected_vendor_hint;
        }
        if (body.business_criticality !== undefined) {
          updates.business_criticality =
            typeof body.business_criticality === 'string'
              ? body.business_criticality.trim()
              : body.business_criticality;
        }
        if (body.traffic_tier !== undefined) {
          updates.traffic_tier =
            typeof body.traffic_tier === 'string' ? body.traffic_tier.trim() : body.traffic_tier;
        }
        if (body.owner_hint !== undefined) {
          updates.owner_hint =
            typeof body.owner_hint === 'string' ? body.owner_hint.trim() : body.owner_hint;
        }
        if (Array.isArray(body.compliance_tags)) {
          updates.compliance_tags = body.compliance_tags.map((t) => String(t).trim()).filter(Boolean);
        }
        if (body.expected_waf_required !== undefined) {
          updates.expected_waf_required =
            body.expected_waf_required === true
            || body.expected_waf_required === '1'
            || body.expected_waf_required === 1
            || body.expected_waf_required === 'true';
        }
        const patched = await wafRepo.updateWafAsset(ctx, id, updates);
        if (!patched) return { error: 'waf_asset_not_found', status: 404 };
        await auditRepo.appendAuditEvent({
          tenant_id: ctx.tenantId,
          actor_user_id: ctx.userId,
          actor_role: ctx.role,
          action: 'waf.asset.updated',
          resource_type: 'waf_asset',
          resource_id: id,
        });
        const current = await wafRepo.getCurrentPostureSnapshot(ctx, id);
        return {
          asset: enrichAssetWithPostureStatus(
            patched,
            current ? new Map([[id, current]]) : new Map(),
          ),
        };
      } catch (err) {
        return contractError(err);
      }
    },

    async getWafCoverage(ctx, options = {}) {
      const context = await gatherPostgresWafAnalyticsContext(ctx, wafRepo, coreCatalog, options);
      const coverageRollups = typeof wafRepo.listWafCoverageDailyRollups === 'function'
        ? await wafRepo.listWafCoverageDailyRollups(ctx, { windowDays: context.windowDays })
        : [];
      return buildCoverageSummary({
        assets: context.assets,
        currentSnapshotsByAsset: context.currentSnapshotsByAsset,
        historicalSnapshots: context.historicalSnapshots,
        coverageRollups,
        windowDays: context.windowDays,
      });
    },

    async getWafCoverageVendors(ctx) {
      const context = await gatherPostgresWafAnalyticsContext(ctx, wafRepo, coreCatalog);
      return buildVendorBreakdown({
        assets: context.assets,
        currentSnapshotsByAsset: context.currentSnapshotsByAsset,
      });
    },

    async getWafCoverageEntities(ctx, options = {}) {
      const context = await gatherPostgresWafAnalyticsContext(ctx, wafRepo, coreCatalog, options);
      return buildEntityRollup({
        assets: context.assets,
        currentSnapshotsByAsset: context.currentSnapshotsByAsset,
        entities: context.entities,
        targetGroups: context.targetGroups,
        entityTypeFilter: options.entity_type ?? options.entityType ?? null,
      });
    },

    async getWafCoverageGeography(ctx, options = {}) {
      const context = await gatherPostgresWafAnalyticsContext(ctx, wafRepo, coreCatalog, options);
      return buildGeographyRollup({
        assets: context.assets,
        currentSnapshotsByAsset: context.currentSnapshotsByAsset,
        targetGroups: context.targetGroups,
        environments: context.environments,
        entities: context.entities,
        regionCodeFilter: options.region_code ?? options.regionCode ?? null,
      });
    },

    async getWafCoverageCriticality(ctx, options = {}) {
      const context = await gatherPostgresWafAnalyticsContext(ctx, wafRepo, coreCatalog, options);
      return buildCriticalityRollup({
        assets: context.assets,
        currentSnapshotsByAsset: context.currentSnapshotsByAsset,
        criticalityFilter: options.business_criticality ?? options.criticality ?? null,
      });
    },

    async getWafRiskRoadmap(ctx, options = {}) {
      const context = await gatherPostgresWafAnalyticsContext(ctx, wafRepo, coreCatalog, options);
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
    },

    async getWafVendorConsolidation(ctx) {
      const context = await gatherPostgresWafAnalyticsContext(ctx, wafRepo, coreCatalog);
      return buildVendorConsolidation({
        assets: context.assets,
        currentSnapshotsByAsset: context.currentSnapshotsByAsset,
        connectors: context.connectors,
        driftEvents: context.driftEvents,
      });
    },

    async createWafValidation(ctx, body) {
      try {
        const profile = normalizeWafValidationRequest(body);
        const asset = await wafRepo.getWafAsset(ctx, profile.waf_asset_id);
        if (!asset) {
          return { error: 'waf_asset_not_found', status: 404 };
        }
        const id = newIdFn('id');
        const now = nowFn().toISOString();
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
          const binding = await validateWafTestRunBinding(validationEvidence, ctx, testRunId, asset);
          if (binding.error) return binding;
          run.test_run_id = testRunId;
        }
        const persisted = await wafRepo.createWafValidationRun(ctx, run);
        await auditRepo.appendAuditEvent({
          tenant_id: ctx.tenantId,
          actor_user_id: ctx.userId,
          actor_role: ctx.role,
          action: 'waf.validation.started',
          resource_type: 'waf_validation_run',
          resource_id: id,
          metadata: redactObject({
            waf_asset_id: profile.waf_asset_id,
            modes: profile.modes,
          }),
        });
        return { validation_run: persisted };
      } catch (err) {
        return contractError(err);
      }
    },

    async listWafValidations(ctx) {
      return wafRepo.listWafValidationRuns(ctx);
    },

    async getWafValidation(ctx, id) {
      const run = await wafRepo.getWafValidationRun(ctx, id);
      if (!run) return null;
      const scenario_results = await wafRepo.listWafScenarioResultsForRun(ctx, id);
      return { validation_run: run, scenario_results };
    },

    async finalizeWafValidation(ctx, id, body = {}) {
      const run = await wafRepo.getWafValidationRun(ctx, id);
      if (!run) {
        return { error: 'waf_asset_not_found', status: 404, message: 'Validation run not found.' };
      }
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
          const [probes, agents] = await Promise.all([
            validationEvidence.listRunEvents(ctx, run.test_run_id, {
              signalType: 'probe_result',
              limit: WAF_BOUND_RUN_EVENTS_LIMIT,
            }),
            validationEvidence.listRunEvents(ctx, run.test_run_id, {
              signalType: 'agent_observation',
              limit: WAF_BOUND_RUN_EVENTS_LIMIT,
            }),
          ]);
          corroboration = buildWafEvidenceCorroboration({ probes, agents });
          const derived = deriveWafSignalsFromBoundEvents({ probes, agents });
          normalizedScenarios = derived.scenarioResults.map((entry) =>
            normalizeScenarioResultInput(entry),
          );
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
          corroboration = await buildCorroborationFromValidationEvidence(
            validationEvidence,
            ctx,
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

        const asset = await wafRepo.getWafAsset(ctx, run.waf_asset_id);
        if (!asset) return { error: 'waf_asset_not_found', status: 404 };

        const previous = await wafRepo.getCurrentPostureSnapshot(ctx, asset.id);
        const classification = classifyWafPosture({
          wafDetected,
          validationPassed,
          validationFailed,
          originBypassConfirmed,
          wafRequired: asset.expected_waf_required !== false,
          connectorMode,
        });

        const now = nowFn().toISOString();
        const snapshotId = newIdFn('id');
        const targetGroups = await coreCatalog.listTargetGroups(ctx);
        const cveMatchesByAsset = await wafRepo.listTenantCveAssetMatches(ctx);
        const summary = {
          waf_detected: wafDetected,
          validation_passed: validationPassed,
          validation_failed: validationFailed,
          origin_bypass_confirmed: originBypassConfirmed,
          posture_status: classification.status,
          reason_codes: classification.reason_codes,
        };
        const snapshot = enrichSnapshotWithRisk(
          {
            id: snapshotId,
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
          },
          buildPostgresRiskAssessment(
            asset,
            {
              status: classification.status,
              reason_codes: classification.reason_codes,
              waf_asset_id: asset.id,
              created_at: now,
            },
            summary,
            targetGroups,
            cveMatchesByAsset,
            now,
          ),
        );

        const scenarios = normalizedScenarios.map((scenario) => ({
          id: newIdFn('id'),
          ...scenario,
          created_at: now,
        }));

        const { validation_run: finalizedRun, snapshot: persistedSnapshot } =
          await wafRepo.finalizeWafValidationBundle(ctx, {
            run_id: run.id,
            waf_asset_id: asset.id,
            asset_updated_at: now,
            snapshot,
            scenarios,
            run_updates: {
              status: 'finalized',
              finalized_at: now,
              summary_json: summary,
            },
          });

        await auditRepo.appendAuditEvent({
          tenant_id: ctx.tenantId,
          actor_user_id: ctx.userId,
          actor_role: ctx.role,
          action: 'waf.validation.finalized',
          resource_type: 'waf_validation_run',
          resource_id: run.id,
          metadata: redactObject({ waf_asset_id: asset.id }),
        });
        await auditRepo.appendAuditEvent({
          tenant_id: ctx.tenantId,
          actor_user_id: ctx.userId,
          actor_role: ctx.role,
          action: 'waf.posture.updated',
          resource_type: 'waf_posture_snapshot',
          resource_id: snapshotId,
          metadata: redactObject({
            waf_asset_id: asset.id,
            old_status: previous?.status ?? 'unknown',
            new_status: classification.status,
            reason_codes: classification.reason_codes,
          }),
        });

        let persistedFindingId = null;
        if (postureStatusNeedsFinding(classification.status)) {
          const findingId = newIdFn('finding');
          const evidenceIds = [
            snapshotId,
            ...scenarios.map((scenario) => scenario.id),
          ];
          const upsertResult = await wafRepo.upsertWafPostureFinding(ctx, {
            id: findingId,
            target_group_id: asset.target_group_id,
            target_id: asset.target_id ?? null,
            test_run_id: run.test_run_id ?? null,
            check_id: wafPostureCheckId(asset.id),
            title: buildWafFindingTitle(classification.status, asset.canonical_url),
            severity: deriveWafFindingSeverity({
              postureStatus: classification.status,
              reasonCodes: classification.reason_codes,
              businessCriticality: asset.business_criticality,
              originBypassConfirmed,
            }),
            status: 'open',
            notes: buildWafFindingNotes({
              reasonCodes: classification.reason_codes,
              validationRunId: run.id,
              wafAssetId: asset.id,
            }),
            remediation_template: WAF_POSTURE_FINDING_REMEDIATION,
            evidence_ids: evidenceIds,
            created_at: now,
            updated_at: now,
          });
          const persistedFinding = upsertResult?.finding;
          persistedFindingId = persistedFinding?.id ?? findingId;
          await auditRepo.appendAuditEvent({
            tenant_id: ctx.tenantId,
            actor_user_id: ctx.userId,
            actor_role: ctx.role,
            action: upsertResult?.inserted ? 'finding.created' : 'finding.updated',
            resource_type: 'finding',
            resource_id: persistedFindingId,
            metadata: redactObject({
              waf_asset_id: asset.id,
              waf_validation_run_id: run.id,
              posture_status: classification.status,
              reason_codes: classification.reason_codes,
            }),
          });
        }

        const driftSpecs = deriveWafDriftEventSpecs({
          previousSnapshot: previous,
          postureStatus: classification.status,
          reasonCodes: classification.reason_codes,
          wafDetected,
          businessCriticality: asset.business_criticality,
        });
        if (driftSpecs.length > 0) {
          await persistWafDriftEventsFromFinalize({
            wafRepo,
            auditRepo,
            ctx,
            specs: driftSpecs,
            wafAssetId: asset.id,
            validationRunId: run.id,
            findingId: persistedFindingId,
            postureFrom: previous?.status ?? 'unknown',
            postureTo: classification.status,
            reasonCodes: classification.reason_codes,
            now,
            newIdFn,
          });
        }

        return {
          validation_run: finalizedRun,
          posture: formatPostureSnapshotForApi(persistedSnapshot),
        };
      } catch (err) {
        return contractError(err);
      }
    },

    async listWafDriftEvents(ctx) {
      const items = await wafRepo.listWafDriftEvents(ctx);
      return items.map((item) => formatDriftEventForApi(item));
    },

    async patchWafDriftEvent(ctx, id, body = {}) {
      try {
        assertNoRawWafEvidence(body);
        const status =
          typeof body.status === 'string' ? body.status.trim() : body.status;
        if (!status || !WAF_DRIFT_EVENT_STATUSES.has(status)) {
          return {
            error: 'invalid_waf_drift_status',
            status: 400,
            message: `status must be one of: ${[...WAF_DRIFT_EVENT_STATUSES].join(', ')}.`,
          };
        }
        const updates = { status };
        if (WAF_DRIFT_RESOLVED_STATUSES.has(status)) {
          updates.resolved_at = nowFn().toISOString();
        }
        const patched = await wafRepo.patchWafDriftEvent(ctx, id, updates);
        if (!patched) {
          return { error: 'waf_drift_event_not_found', status: 404 };
        }
        await auditRepo.appendAuditEvent({
          tenant_id: ctx.tenantId,
          actor_user_id: ctx.userId,
          actor_role: ctx.role,
          action: 'waf.drift.updated',
          resource_type: 'waf_drift_event',
          resource_id: id,
          metadata: redactObject({
            waf_asset_id: patched.waf_asset_id,
            drift_type: patched.drift_type,
            status,
          }),
        });
        return { drift_event: formatDriftEventForApi(patched) };
      } catch (err) {
        return contractError(err);
      }
    },

    async listConnectors(ctx) {
      const items = await wafRepo.listConnectors(ctx);
      return items.map((item) => formatConnectorForApi(item));
    },

    async listConnectorsEnvelope(ctx) {
      const items = await wafRepo.listConnectors(ctx);
      const formatted = items.map((item) => formatConnectorForApi(item));
      return {
        items: formatted,
        count: formatted.length,
        meta: {
          empty_reason: formatted.length
            ? null
            : 'No connectors are configured for this tenant.',
        },
      };
    },

    async createConnector(ctx, body) {
      try {
        assertNoRawWafEvidence(body);
        const provider = String(body.provider ?? '').trim().toLowerCase();
        if (!WAF_CONNECTOR_PROVIDERS.has(provider)) {
          const err = new Error(`Unsupported connector provider: ${provider || '(empty)'}`);
          err.code = 'invalid_connector';
          throw err;
        }
        const name = String(body.name ?? '').trim();
        if (!name) {
          const err = new Error('Connector name is required.');
          err.code = 'invalid_connector';
          throw err;
        }
        const config = normalizeConnectorConfig(body.config ?? {});
        const secretId =
          typeof body.secret_id === 'string'
            ? body.secret_id.trim() || null
            : typeof body.secretId === 'string'
              ? body.secretId.trim() || null
              : null;
        const id = newIdFn('id');
        const now = nowFn().toISOString();
        const record = {
          id,
          provider,
          name,
          secret_id: secretId,
          config_json: config,
          status: deriveInitialConnectorStatus(body, config),
          created_at: now,
          updated_at: now,
        };
        const connector = await wafRepo.createConnector(ctx, record);
        await auditRepo.appendAuditEvent({
          tenant_id: ctx.tenantId,
          actor_user_id: ctx.userId,
          actor_role: ctx.role,
          action: 'connector.created',
          resource_type: 'waf_connector',
          resource_id: id,
          metadata: redactObject({ provider }),
        });
        return { connector: formatConnectorForApi(connector) };
      } catch (err) {
        return contractError(err);
      }
    },

    async validateConnector(ctx, id) {
      const connector = await wafRepo.getConnector(ctx, id);
      if (!connector) {
        return { error: 'connector_not_found', status: 404 };
      }
      const now = nowFn().toISOString();
      const readOnly = connector.config?.read_only === true;
      if (readOnly) {
        const updated = await wafRepo.updateConnectorStatus(ctx, id, {
          status: 'active',
          last_error_at: null,
          updated_at: now,
        });
        await auditRepo.appendAuditEvent({
          tenant_id: ctx.tenantId,
          actor_user_id: ctx.userId,
          actor_role: ctx.role,
          action: 'connector.validated',
          resource_type: 'waf_connector',
          resource_id: id,
          metadata: redactObject({ provider: connector.provider, status: 'active' }),
        });
        return {
          status: 'active',
          capabilities: connectorProviderCapabilities(connector.provider, connector),
          connector: formatConnectorForApi(updated),
        };
      }
      const redactedErrors = [
        'read_only must be true for first-slice connector validation without outbound provider calls.',
      ];
      const updated = await wafRepo.updateConnectorStatus(ctx, id, {
        status: 'error',
        last_error_at: now,
        updated_at: now,
      });
      await auditRepo.appendAuditEvent({
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId,
        actor_role: ctx.role,
        action: 'connector.validated',
        resource_type: 'waf_connector',
        resource_id: id,
        metadata: redactObject({ provider: connector.provider, status: 'error' }),
      });
      return {
        status: 'error',
        capabilities: [],
        redacted_errors: redactedErrors,
        connector: formatConnectorForApi(updated),
      };
    },

    async pollConnector(ctx, id, body = {}, pollOptions = {}) {
      const connector = await wafRepo.getConnector(ctx, id);
      if (!connector) {
        return { error: 'connector_not_found', status: 404 };
      }
      try {
        assertNoRawWafEvidence(body);
        const snapshotInputs = Array.isArray(body.snapshots) ? body.snapshots : [];
        const now = nowFn().toISOString();
        const secretResolver = pollOptions.secretResolver ?? postgresConnectorSecretResolver;
        const fetchFn = pollOptions.fetchFn ?? fetch;
        const prefetchedMetadata = pollOptions.prefetchedMetadata ?? body.prefetched_metadata ?? null;

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
              maxAttempts: pollOptions.maxAttempts,
            });
            outboundSnapshots = outbound.snapshots ?? [];
            outboundHealth = outbound.health ?? null;
            outboundAttempts = outbound.health?.attempts ?? null;
          } catch (err) {
            const failure = buildProviderPollFailure(connector, err, err?.attempts ?? null);
            await wafRepo.updateConnectorStatus(ctx, id, connectorPollHealthUpdates(failure.health, now));
            await auditRepo.appendAuditEvent({
              tenant_id: ctx.tenantId,
              actor_user_id: ctx.userId,
              actor_role: ctx.role,
              action: 'connector.poll.failed',
              resource_type: 'waf_connector',
              resource_id: id,
              metadata: redactObject({
                provider: connector.provider,
                health_status: failure.health.status,
                health_code: failure.health.health_code,
                attempts: failure.health.attempts,
              }),
            });
            return {
              error: 'connector_poll_failed',
              status: failure.health.status === 'rate_limited' ? 429 : 503,
              message: 'Outbound connector poll failed; manual metadata snapshots remain supported.',
              health: failure.health,
            };
          }
        }

        const records = [
          ...snapshotInputs.map((entry) => {
            const normalized = normalizeConnectorSnapshotInput(entry, connector.provider);
            return {
              id: newIdFn('id'),
              connector_id: id,
              provider: normalized.provider,
              snapshot_kind: normalized.snapshot_kind,
              resource_ref_hash: normalized.resource_ref_hash,
              display_ref: normalized.display_ref,
              summary_json: normalized.summary_json,
              config_hash: normalized.config_hash,
              observed_at: normalized.observed_at ?? now,
              created_at: now,
            };
          }),
          ...outboundSnapshots.map((entry) => {
            const normalized = normalizeConnectorSnapshotInput(entry, connector.provider);
            return {
              id: newIdFn('id'),
              connector_id: id,
              provider: normalized.provider,
              snapshot_kind: normalized.snapshot_kind,
              resource_ref_hash: normalized.resource_ref_hash,
              display_ref: normalized.display_ref,
              summary_json: normalized.summary_json,
              config_hash: normalized.config_hash,
              observed_at: normalized.observed_at ?? now,
              created_at: now,
            };
          }),
        ];

        const snapshots = records.length > 0
          ? await wafRepo.createConnectorSnapshots(ctx, records)
          : [];

        if (outboundHealth) {
          await wafRepo.updateConnectorStatus(ctx, id, connectorPollHealthUpdates(outboundHealth, now));
        } else if (snapshots.length > 0) {
          await wafRepo.updateConnectorStatus(ctx, id, {
            status: connector.status === 'disabled' ? 'disabled' : 'active',
            last_success_at: now,
            last_error_at: null,
            updated_at: now,
          });
        }

        const pollJobId = newIdFn('poll');
        const pollStatus = outboundHealth
          ? (snapshots.length > 0 ? 'completed' : 'completed_empty')
          : 'completed';
        await auditRepo.appendAuditEvent({
          tenant_id: ctx.tenantId,
          actor_user_id: ctx.userId,
          actor_role: ctx.role,
          action: 'connector.snapshot.created',
          resource_type: 'waf_connector',
          resource_id: id,
          metadata: redactObject({
            provider: connector.provider,
            snapshot_count: snapshots.length,
            outbound: Boolean(outboundHealth),
            ...(outboundHealth ? { health_status: outboundHealth.status } : {}),
          }),
        });
        return {
          status: 202,
          poll_job: {
            id: pollJobId,
            connector_id: id,
            status: pollStatus,
            snapshot_count: snapshots.length,
            completed_at: now,
            ...(outboundHealth ? { health: outboundHealth, attempts: outboundAttempts } : {}),
          },
          snapshots: snapshots.map((item) => formatConnectorSnapshotForApi(item)),
        };
      } catch (err) {
        return contractError(err);
      }
    },

    async listConnectorSnapshots(ctx, id) {
      const connector = await wafRepo.getConnector(ctx, id);
      if (!connector) {
        return { error: 'connector_not_found', status: 404 };
      }
      const items = await wafRepo.listConnectorSnapshots(ctx, id);
      return items.map((item) => formatConnectorSnapshotForApi(item));
    },

    async disableConnector(ctx, id, body = {}) {
      try {
        assertNoRawWafEvidence(body);
        const connector = await wafRepo.getConnector(ctx, id);
        if (!connector) {
          return { error: 'connector_not_found', status: 404 };
        }
        const now = nowFn().toISOString();
        const updated = await wafRepo.updateConnectorStatus(ctx, id, {
          status: 'disabled',
          updated_at: now,
        });
        await auditRepo.appendAuditEvent({
          tenant_id: ctx.tenantId,
          actor_user_id: ctx.userId,
          actor_role: ctx.role,
          action: 'connector.disabled',
          resource_type: 'waf_connector',
          resource_id: id,
          metadata: redactObject({ provider: connector.provider }),
        });
        return { connector: formatConnectorForApi(updated) };
      } catch (err) {
        return contractError(err);
      }
    },

    async exportWafReport(ctx, kind, format = 'json') {
      const normalizedKind = String(kind ?? '').trim().toLowerCase();
      if (!WAF_REPORT_KINDS.has(normalizedKind)) {
        return { error: 'waf_report_kind_invalid', status: 400 };
      }

      const needsComplianceAudit = normalizedKind === 'compliance_audit';
      const needsBoardRoadmapBrief = normalizedKind === 'board_roadmap_brief';
      const needsCoverage =
        normalizedKind === 'executive_coverage' || needsComplianceAudit || needsBoardRoadmapBrief;
      const needsValidations = normalizedKind === 'technical_evidence' || needsComplianceAudit;
      const needsDrift =
        normalizedKind === 'drift_audit'
        || normalizedKind === 'executive_coverage'
        || needsComplianceAudit;
      const needsConnectors = normalizedKind === 'connector_health' || needsComplianceAudit;
      const needsAnalytics = needsBoardRoadmapBrief;

      const assets = needsCoverage ? await wafRepo.listWafAssets(ctx) : [];
      const snapshots = needsCoverage ? await wafRepo.listCurrentPostureSnapshots(ctx) : [];
      const snapshotsByAssetId = new Map(
        snapshots.map((snapshot) => [snapshot.waf_asset_id, formatPostureSnapshotForApi(snapshot)]),
      );
      const allValidations = needsValidations ? await wafRepo.listWafValidationRuns(ctx) : [];
      const validations = needsValidations
        ? allValidations.slice(0, WAF_REPORT_VALIDATION_LIMIT)
        : [];
      const validationRunsTruncation = needsValidations
        ? {
            truncated: allValidations.length > validations.length,
            limit: WAF_REPORT_VALIDATION_LIMIT,
            total_available: allValidations.length,
            included_count: validations.length,
          }
        : null;
      const scenarioResultsByRunId = new Map();
      for (const run of validations) {
        const scenarioResults = await wafRepo.listWafScenarioResultsForRun(ctx, run.id);
        scenarioResultsByRunId.set(run.id, scenarioResults);
      }
      const allDriftEvents = needsDrift
        ? await wafRepo.listWafDriftEvents(ctx)
        : [];
      const driftEvents = needsDrift
        ? allDriftEvents
          .slice(0, WAF_REPORT_DRIFT_LIMIT)
          .map((event) => formatDriftEventForApi(event))
        : [];
      const driftEventsTruncation = needsDrift
        ? {
            truncated: allDriftEvents.length > driftEvents.length,
            limit: WAF_REPORT_DRIFT_LIMIT,
            total_available: allDriftEvents.length,
            included_count: driftEvents.length,
          }
        : null;
      const connectors = needsConnectors
        ? (await wafRepo.listConnectors(ctx)).map((connector) => formatConnectorForApi(connector))
        : [];
      const assetIds = new Set(assets.map((asset) => asset.id));
      const exceptions = needsComplianceAudit
        ? await listPostgresWafExceptionsForReport(wafRepo, ctx, assetIds)
        : [];
      const cveSources = needsComplianceAudit
        ? await listPostgresCveSourcesForReport(cveRepo, ctx, assetIds)
        : { cveItems: [], cveMatches: [] };

      const counts = {
        protected: 0,
        underprotected: 0,
        unprotected: 0,
        unknown: 0,
        excluded: 0,
      };
      for (const asset of assets) {
        const snap = snapshotsByAssetId.get(asset.id);
        const status = snap?.status ?? 'unknown';
        if (Object.prototype.hasOwnProperty.call(counts, status)) {
          counts[status] += 1;
        } else {
          counts.unknown += 1;
        }
      }
      const total_assets = assets.length;
      const percentages = {};
      for (const key of Object.keys(counts)) {
        percentages[key] = total_assets === 0 ? 0 : Math.round((counts[key] / total_assets) * 10000) / 100;
      }
      let coverage = { total_assets, ...counts, percentages };
      let riskRoadmap = null;
      let vendorBreakdown = null;
      let geographyRollup = null;
      let coverageTrend = [];

      if (needsAnalytics) {
        const analyticsContext = await gatherPostgresWafAnalyticsContext(ctx, wafRepo, coreCatalog);
        coverage = buildCoverageSummary({
          assets: analyticsContext.assets,
          currentSnapshotsByAsset: analyticsContext.currentSnapshotsByAsset,
          historicalSnapshots: analyticsContext.historicalSnapshots,
          windowDays: analyticsContext.windowDays,
        });
        coverageTrend = coverage.trend ?? [];
        riskRoadmap = buildRiskRoadmap({
          assets: analyticsContext.assets,
          currentSnapshotsByAsset: analyticsContext.currentSnapshotsByAsset,
          validationSummaryByAsset: analyticsContext.validationSummaryByAsset,
          cveMatchesByAsset: analyticsContext.cveMatchesByAsset,
          targetGroups: analyticsContext.targetGroups,
          entities: analyticsContext.entities,
          findingsByAsset: analyticsContext.findingsByAsset,
          actionItemsByAsset: analyticsContext.actionItemsByAsset,
          filters: { limit_per_tier: 50 },
        });
        vendorBreakdown = buildVendorBreakdown({
          assets: analyticsContext.assets,
          currentSnapshotsByAsset: analyticsContext.currentSnapshotsByAsset,
        });
        geographyRollup = buildGeographyRollup({
          assets: analyticsContext.assets,
          currentSnapshotsByAsset: analyticsContext.currentSnapshotsByAsset,
          targetGroups: analyticsContext.targetGroups,
          environments: analyticsContext.environments,
          entities: analyticsContext.entities,
        });
      }

      const payload = buildWafReportPayload(normalizedKind, {
        tenantId: ctx.tenantId,
        coverage,
        coverageTrend,
        assets,
        snapshotsByAssetId,
        validations,
        validationRunsTruncation,
        scenarioResultsByRunId,
        driftEvents,
        driftEventsTruncation,
        connectors,
        exceptions,
        cveItems: cveSources.cveItems,
        cveMatches: cveSources.cveMatches,
        riskRoadmap,
        vendorBreakdown,
        geographyRollup,
      });

      if (typeof auditRepo.withTenantAuditLock !== 'function') {
        throw new Error('Postgres WAF posture service adapter requires audit.withTenantAuditLock().');
      }

      return auditRepo.withTenantAuditLock(ctx.tenantId, async ({ client, prior }) => {
        const priorHash = prior?.entry_hash ?? null;
        const exported = prepareWafReportExport(ctx, normalizedKind, format, payload, {
          previousAuditHash: priorHash,
          previousTenantAuditHash: priorHash,
        });
        if (exported.error) return exported;

        await auditRepo.appendAuditEvent({
          tenant_id: ctx.tenantId,
          actor_user_id: ctx.userId,
          actor_role: ctx.role,
          action: 'waf.report.exported',
          resource_type: 'waf_report',
          resource_id: normalizedKind,
          metadata: redactObject({
            format: exported.custody?.format ?? format,
            content_sha256: exported.custody?.content_sha256 ?? null,
            custody_schema_version: exported.custody?.schema_version ?? null,
            report_kind: normalizedKind,
          }),
        }, { client });

        return exported;
      });
    },

    async listWafProducts() {
      const products = listWafProductCatalogEntries();
      return {
        items: products,
        summary: summarizeWafProductCatalog(products),
      };
    },

    async listScenarioIntakes(ctx) {
      const items = (await wafRepo.listWafScenarioIntakes(ctx))
        .map(formatPostgresScenarioIntake);
      return { items };
    },

    async listWafExceptions(ctx) {
      return wafRepo.listWafExceptions(ctx);
    },

    async createWafException(ctx, wafAssetId, body = {}) {
      const asset = await wafRepo.getWafAsset(ctx, wafAssetId);
      if (!asset) {
        return { error: 'waf_asset_not_found', status: 404 };
      }
      try {
        assertNoRawWafEvidence(body);
        const nowDate = nowFn();
        const normalized = normalizeWafExceptionBody(body, { nowMs: nowDate.getTime() });
        const now = nowDate.toISOString();
        const id = newIdFn('wafexc');
        const exception = await wafRepo.createWafException(ctx, {
          id,
          waf_asset_id: wafAssetId,
          ...normalized,
          approved_at: now,
          approved_by: ctx.userId,
          created_at: now,
          updated_at: now,
        });
        await auditRepo.appendAuditEvent({
          tenant_id: ctx.tenantId,
          actor_user_id: ctx.userId,
          actor_role: ctx.role,
          action: 'waf.exception.created',
          resource_type: 'waf_exception',
          resource_id: id,
          metadata: redactObject({
            waf_asset_id: wafAssetId,
            owner: exception.owner,
            expires_at: exception.expires_at,
            ...(exception.scope_hash ? { scope_hash: exception.scope_hash } : {}),
          }),
        });
        const current = await wafRepo.getCurrentPostureSnapshot(ctx, wafAssetId);
        return {
          exception,
          posture: current ? formatPostureSnapshotForApi(current) : null,
        };
      } catch (err) {
        return contractError(err);
      }
    },

    async submitScenarioIntake(ctx, body = {}) {
      try {
        assertNoRawWafEvidence(body);
        const normalized = normalizeScenarioIntakeInput(body);
        const now = nowFn().toISOString();
        const id = newId('wafintake');
        const record = await wafRepo.insertWafScenarioIntake(ctx, {
          id,
          ...normalized,
          intake_stage: WAF_SCENARIO_INTAKE_STAGES[0],
          created_at: now,
          updated_at: now,
        });
        await auditRepo.appendAuditEvent({
          tenant_id: ctx.tenantId,
          actor_user_id: ctx.userId,
          actor_role: ctx.role,
          action: 'waf.scenario_intake.submitted',
          resource_type: 'waf_scenario_intake',
          resource_id: id,
          metadata: redactObject({
            pattern_title: record.pattern_title,
            advisory_refs: record.advisory_refs,
            proposed_scenario_family: record.proposed_scenario_family ?? null,
            risk_class: record.risk_class,
          }),
        });
        return { intake: formatPostgresScenarioIntake(record), status: 'accepted' };
      } catch (err) {
        return {
          error: err.code ?? 'invalid_request',
          status: 400,
          message: err.message,
        };
      }
    },
  };
}
