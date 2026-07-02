import {
  assertNoRawWafEvidence,
  classifyWafPosture,
  normalizeWafAssetInput,
  normalizeWafEvidenceSummary,
  normalizeWafValidationRequest,
  WAF_EXPECTED_ACTIONS,
  WAF_SCENARIO_FAMILIES,
} from '../../contracts/wafPosture.mjs';
import { newId } from '../../lib/ids.mjs';
import { redactObject } from '../../lib/redact.mjs';
import {
  formatConnectorForApi,
  formatConnectorSnapshotForApi,
  formatDriftEventForApi,
  formatPostureSnapshotForApi,
} from './wafPostureRepository.mjs';

export const WAF_POSTURE_REPOSITORY_METHODS = Object.freeze([
  'listWafAssets',
  'createWafAsset',
  'getWafAsset',
  'updateWafAsset',
  'listCurrentPostureSnapshots',
  'getCurrentPostureSnapshot',
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
]);

export const POSTGRES_WAF_POSTURE_SERVICE_METHODS = Object.freeze([
  'listWafAssets',
  'createWafAsset',
  'getWafAsset',
  'patchWafAsset',
  'getWafCoverage',
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
]);

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

function scenarioSupportsProtectedClaim(normalizedScenarios) {
  return normalizedScenarios.some(
    (scenario) =>
      scenario.passed === true
      && scenario.evidence_summary_json
      && Object.keys(scenario.evidence_summary_json).length > 0,
  );
}

function manualProtectedEvidenceRequired({
  validationPassed,
  usedBoundRunDerivation,
  normalizedScenarios,
}) {
  if (!validationPassed) return null;
  if (usedBoundRunDerivation) return null;
  if (scenarioSupportsProtectedClaim(normalizedScenarios)) return null;
  return {
    error: 'waf_validation_evidence_required',
    status: 400,
  };
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

export function createPostgresWafPostureServices(repositories, options = {}) {
  assertWafPostureRepositories(repositories);
  const wafRepo = repositories.wafPosture;
  const coreCatalog = repositories.coreCatalog;
  const auditRepo = repositories.audit;
  const nowFn = options.now ?? (() => new Date());
  const newIdFn = options.newId ?? newId;

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
      return {
        asset: enrichAssetWithPostureStatus(asset, current ? new Map([[id, current]]) : new Map()),
        ...(current ? { current_posture: formatPostureSnapshotForApi(current) } : {}),
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

    async getWafCoverage(ctx) {
      const assets = await wafRepo.listWafAssets(ctx);
      const snapshots = await wafRepo.listCurrentPostureSnapshots(ctx);
      const byAsset = new Map(snapshots.map((s) => [s.waf_asset_id, s]));
      const counts = {
        protected: 0,
        underprotected: 0,
        unprotected: 0,
        unknown: 0,
        excluded: 0,
      };
      for (const asset of assets) {
        const snap = byAsset.get(asset.id);
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
      return {
        total_assets,
        ...counts,
        percentages,
      };
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
        const normalizedScenarios = scenarioInputs.map((entry) => normalizeScenarioResultInput(entry));

        const wafDetected = parseBooleanField(body, 'waf_detected', 'wafDetected', false);
        const validationPassed = parseBooleanField(body, 'validation_passed', 'validationPassed', false);
        const evidenceGate = manualProtectedEvidenceRequired({
          validationPassed,
          usedBoundRunDerivation: false,
          normalizedScenarios,
        });
        if (evidenceGate) return evidenceGate;
        const validationFailed = parseBooleanField(body, 'validation_failed', 'validationFailed', false);
        const originBypassConfirmed = parseBooleanField(
          body,
          'origin_bypass_confirmed',
          'originBypassConfirmed',
          false,
        );
        const connectorMode = body.connector_mode ?? body.connectorMode ?? null;

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
        const snapshot = {
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
            external: Boolean(body.source_external),
            agent: Boolean(body.source_agent),
            connector: Boolean(body.source_connector),
          },
          created_at: now,
        };

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
              summary_json: {
                waf_detected: wafDetected,
                validation_passed: validationPassed,
                validation_failed: validationFailed,
                origin_bypass_confirmed: originBypassConfirmed,
                posture_status: classification.status,
                reason_codes: classification.reason_codes,
              },
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
          capabilities: [...WAF_CONNECTOR_SLICE_CAPABILITIES],
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

    async pollConnector(ctx, id, body = {}) {
      const connector = await wafRepo.getConnector(ctx, id);
      if (!connector) {
        return { error: 'connector_not_found', status: 404 };
      }
      try {
        assertNoRawWafEvidence(body);
        const snapshotInputs = Array.isArray(body.snapshots) ? body.snapshots : [];
        const now = nowFn().toISOString();
        const records = snapshotInputs.map((entry) => {
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
        });
        const snapshots = await wafRepo.createConnectorSnapshots(ctx, records);
        await wafRepo.updateConnectorStatus(ctx, id, {
          last_success_at: now,
          updated_at: now,
        });
        const pollJobId = newIdFn('poll');
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
          }),
        });
        return {
          status: 202,
          poll_job: {
            id: pollJobId,
            connector_id: id,
            status: 'completed',
            snapshot_count: snapshots.length,
            completed_at: now,
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
  };
}
