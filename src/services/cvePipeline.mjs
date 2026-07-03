import { audit } from '../audit.mjs';
import { loadRuntimeConfig } from '../config.mjs';
import {
  assertCvePlaybookApprovable,
  assertCvePlaybookCoordinatedRetestAllowed,
  assertCvePostMitigationRetestAllowed,
  assertCveSafeValidationAllowed,
  assertValidStageTransition,
  buildCveMitigationPlaybook,
  buildCvePostMitigationRetestRequest,
  buildCveRetestEvidenceBinding,
  buildCveValidationEvidenceBinding,
  buildPlaybookChildActionItem,
  buildPlaybookParentActionItem,
  buildSafeCveValidationRequest,
  buildWafRuleRecommendation,
  createCvePipelineItem as normalizeCvePipelineItem,
  deriveCveRetestOutcomeFromValidationRun,
  isCveRecommendationDeployed,
  matchCveToAssets,
  resolveCvePipelineRetestClosure,
  resolvePlaybookStatusFromRetestClosure,
  resolveSafeCveValidationCheck,
  triageCveItem,
  validateCvePipelineItem,
} from '../contracts/cvePipeline.mjs';
import { createActionItem } from '../contracts/wafPosture.mjs';
import { newId } from '../lib/ids.mjs';
import { getStore, persistStore } from '../store.mjs';
import { createWafValidation } from './wafPosture.mjs';

function wafFeatureDisabled() {
  const { featureFlags } = loadRuntimeConfig();
  return featureFlags.wafPostureEnabled !== true;
}

function featureDisabledResponse() {
  return { error: 'waf_feature_disabled', status: 404 };
}

function contractError(err, fallbackStatus = 400) {
  return {
    error: err.code ?? 'invalid_request',
    status: fallbackStatus,
    message: err.message,
  };
}

function ensureStoreShape() {
  const store = getStore();
  const keys = [
    'cvePipelineItems',
    'cveAssetMatches',
    'cveMitigationPlaybooks',
    'wafRuleRecommendations',
    'wafAssets',
    'wafActionItems',
  ];
  for (const key of keys) {
    if (!Array.isArray(store[key])) store[key] = [];
  }
  return store;
}

function findPipelineItem(ctx, id) {
  ensureStoreShape();
  return getStore().cvePipelineItems.find((i) => i.id === id && i.tenant_id === ctx.tenantId) ?? null;
}

function findAssetMatch(ctx, id) {
  ensureStoreShape();
  return getStore().cveAssetMatches.find((m) => m.id === id && m.tenant_id === ctx.tenantId) ?? null;
}

function listTenantWafAssets(ctx) {
  ensureStoreShape();
  return getStore().wafAssets.filter((a) => a.tenant_id === ctx.tenantId);
}

function buildTenantTechFootprint(ctx) {
  const assets = listTenantWafAssets(ctx);
  const products = new Set();
  for (const asset of assets) {
    for (const value of [
      asset.detected_product,
      asset.expected_vendor_hint,
      asset.asset_kind,
      ...(Array.isArray(asset.compliance_tags) ? asset.compliance_tags : []),
    ]) {
      if (typeof value === 'string' && value.trim()) {
        products.add(value.trim());
      }
    }
  }
  return {
    assets: assets.map((asset) => ({
      id: asset.id,
      canonical_url: asset.canonical_url,
      business_criticality: asset.business_criticality,
      posture_status: asset.status,
      internet_facing: true,
      detected_product: asset.detected_product,
      platform_product: asset.expected_vendor_hint,
    })),
    products: [...products],
    internet_facing: assets.length > 0,
  };
}

function formatPipelineItem(record) {
  return {
    id: record.id,
    cve_id: record.cve_id,
    severity: record.severity,
    affected_products: record.affected_products ?? [],
    known_exploited: record.known_exploited ?? false,
    poc_indicator: record.poc_indicator ?? false,
    vendor_advisories: record.vendor_advisories ?? [],
    stage: record.stage,
    triage_result: record.triage_result ?? null,
    created_at: record.created_at,
    updated_at: record.updated_at,
  };
}

function formatAssetMatch(record) {
  return {
    id: record.id,
    cve_pipeline_item_id: record.cve_pipeline_item_id,
    waf_asset_id: record.waf_asset_id,
    asset_display: record.asset_display,
    match_source: record.match_source,
    confidence_level: record.confidence_level,
    match_confidence: record.match_confidence,
    match_reasons: record.match_reasons ?? [],
    requires_review: record.requires_review ?? false,
    exposure_claim_allowed: record.exposure_claim_allowed ?? false,
    validation_status: record.validation_status ?? 'pending',
    last_waf_validation_run_id: record.last_waf_validation_run_id ?? null,
    validation_evidence_json: record.validation_evidence_json ?? null,
    created_at: record.created_at,
    updated_at: record.updated_at,
  };
}

function listPipelineMatches(ctx, pipelineItemId) {
  ensureStoreShape();
  return getStore().cveAssetMatches.filter(
    (match) => match.tenant_id === ctx.tenantId && match.cve_pipeline_item_id === pipelineItemId,
  );
}

function listPipelineRecommendations(ctx, pipelineItemId) {
  ensureStoreShape();
  const matchIds = new Set(listPipelineMatches(ctx, pipelineItemId).map((match) => match.id));
  return getStore().wafRuleRecommendations.filter(
    (rec) => rec.tenant_id === ctx.tenantId && matchIds.has(rec.cve_asset_match_id),
  );
}

function findValidationRun(ctx, id) {
  ensureStoreShape();
  return getStore().wafValidationRuns.find((run) => run.id === id && run.tenant_id === ctx.tenantId) ?? null;
}

function isRetestEvidenceBinding(evidence) {
  return evidence?.retest_phase === 'post_mitigation';
}

function selectLatestDeployedRecommendation(recommendations = []) {
  const deployed = recommendations.filter((rec) => isCveRecommendationDeployed(rec));
  if (deployed.length === 0) return null;
  return deployed[deployed.length - 1];
}

function findWafAsset(ctx, id) {
  ensureStoreShape();
  return getStore().wafAssets.find((asset) => asset.id === id && asset.tenant_id === ctx.tenantId) ?? null;
}

function formatRecommendation(record) {
  return {
    id: record.id,
    cve_asset_match_id: record.cve_asset_match_id,
    waf_asset_id: record.waf_asset_id,
    vendor: record.vendor,
    recommendation_type: record.recommendation_type,
    recommendation: record.recommendation_json ?? {},
    approval_status: record.approval_status ?? 'draft',
    created_at: record.created_at,
    updated_at: record.updated_at,
  };
}

function formatPlaybook(record) {
  return {
    playbook_id: record.playbook_id,
    cve_id: record.cve_id,
    pipeline_item_id: record.pipeline_item_id,
    severity: record.severity,
    known_exploited: record.known_exploited ?? false,
    affected_asset_count: record.affected_asset_count ?? 0,
    vendor_slices: record.vendor_slices ?? [],
    coordinated_retest_plan_id: record.coordinated_retest_plan_id ?? record.pipeline_item_id,
    status: record.status ?? 'draft',
    human_approval_required: record.human_approval_required ?? true,
    parent_action_item_id: record.parent_action_item_id ?? null,
    approved_at: record.approved_at ?? null,
    approval_note: record.approval_note ?? null,
    created_at: record.created_at,
    updated_at: record.updated_at,
  };
}

function formatPlaybookActionItem(record) {
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
    ...(record.parent_action_item_id ? { parent_action_item_id: record.parent_action_item_id } : {}),
    ...(record.playbook_id ? { playbook_id: record.playbook_id } : {}),
    ...(record.created_at ? { created_at: record.created_at } : {}),
    ...(record.updated_at ? { updated_at: record.updated_at } : {}),
  };
}

function findPlaybookByPipelineItemId(ctx, pipelineItemId) {
  ensureStoreShape();
  return (
    getStore().cveMitigationPlaybooks.find(
      (entry) => entry.tenant_id === ctx.tenantId && entry.pipeline_item_id === pipelineItemId,
    ) ?? null
  );
}

function persistPlaybook(ctx, playbook) {
  ensureStoreShape();
  const existingIndex = getStore().cveMitigationPlaybooks.findIndex(
    (entry) => entry.tenant_id === ctx.tenantId && entry.playbook_id === playbook.playbook_id,
  );
  const record = {
    ...playbook,
    tenant_id: ctx.tenantId,
  };
  if (existingIndex >= 0) {
    getStore().cveMitigationPlaybooks[existingIndex] = record;
  } else {
    getStore().cveMitigationPlaybooks.push(record);
  }
  return record;
}

function upsertPlaybookActionItem(ctx, fields) {
  const normalized = createActionItem(fields);
  const now = new Date().toISOString();
  const record = {
    ...normalized,
    tenant_id: ctx.tenantId,
    dedupe_key: fields.dedupe_key,
    cve_pipeline_item_id: fields.cve_pipeline_item_id ?? null,
    waf_asset_id: fields.waf_asset_id ?? normalized.asset?.id ?? null,
    primary_reason: fields.primary_reason ?? null,
    parent_action_item_id: fields.parent_action_item_id ?? null,
    playbook_id: fields.playbook_id ?? null,
    created_at: now,
    updated_at: now,
  };

  const existing = getStore().wafActionItems.find(
    (item) => item.tenant_id === ctx.tenantId && item.dedupe_key === record.dedupe_key,
  );
  if (existing) {
    existing.title = record.title;
    existing.severity = record.severity;
    existing.owner = record.owner;
    existing.evidence = record.evidence;
    existing.recommended_solution = record.recommended_solution;
    existing.retest_url = record.retest_url;
    existing.status = record.status;
    existing.parent_action_item_id = record.parent_action_item_id ?? existing.parent_action_item_id;
    existing.playbook_id = record.playbook_id ?? existing.playbook_id;
    existing.updated_at = now;
    return formatPlaybookActionItem(existing);
  }

  getStore().wafActionItems.push(record);
  return formatPlaybookActionItem(record);
}

function syncPlaybookActionItemStatuses(ctx, playbook, status) {
  const items = getStore().wafActionItems.filter(
    (item) => item.tenant_id === ctx.tenantId && item.playbook_id === playbook.playbook_id,
  );
  const now = new Date().toISOString();
  for (const item of items) {
    item.status = status;
    item.updated_at = now;
  }
  return items.map((item) => formatPlaybookActionItem(item));
}

function buildOrRefreshPlaybook(ctx, item) {
  const matches = listPipelineMatches(ctx, item.id);
  const recommendations = listPipelineRecommendations(ctx, item.id);
  const existing = findPlaybookByPipelineItemId(ctx, item.id);
  const now = new Date().toISOString();
  const draft = buildCveMitigationPlaybook(item, recommendations, matches, existing);
  const playbook = {
    ...draft,
    playbook_id: existing?.playbook_id ?? newId('id'),
    pipeline_item_id: item.id,
    created_at: existing?.created_at ?? now,
    updated_at: now,
    parent_action_item_id: existing?.parent_action_item_id ?? null,
    approved_at: existing?.approved_at ?? null,
    approval_note: existing?.approval_note ?? null,
    status: existing?.status ?? 'draft',
    vendor_slices: draft.vendor_slices.map((slice) => {
      const existingSlice = (existing?.vendor_slices ?? []).find((entry) => entry.vendor === slice.vendor);
      return {
        ...slice,
        child_action_item_id: existingSlice?.child_action_item_id ?? slice.child_action_item_id ?? null,
      };
    }),
  };
  return persistPlaybook(ctx, playbook);
}

export function listCvePipelineItems(ctx) {
  if (wafFeatureDisabled()) return featureDisabledResponse();
  ensureStoreShape();
  const items = getStore()
    .cvePipelineItems.filter((i) => i.tenant_id === ctx.tenantId)
    .map((i) => formatPipelineItem(i));
  return { items };
}

function findPipelineItemByCveId(ctx, cveId) {
  ensureStoreShape();
  const normalized = String(cveId ?? '').trim().toUpperCase();
  return (
    getStore().cvePipelineItems.find(
      (item) => item.tenant_id === ctx.tenantId && String(item.cve_id).toUpperCase() === normalized,
    ) ?? null
  );
}

export function ingestCveFeed(ctx, feedItems = []) {
  if (wafFeatureDisabled()) return featureDisabledResponse();
  if (!Array.isArray(feedItems)) {
    return {
      error: 'invalid_cve_feed_request',
      status: 400,
      message: 'feedItems must be an array.',
    };
  }

  ensureStoreShape();
  const created = [];
  const skipped = [];
  const errors = [];

  for (let index = 0; index < feedItems.length; index += 1) {
    const fields = feedItems[index];
    try {
      validateCvePipelineItem(fields);
      const normalized = normalizeCvePipelineItem(fields);
      const existing = findPipelineItemByCveId(ctx, normalized.cve_id);
      if (existing) {
        skipped.push({
          cve_id: normalized.cve_id,
          existing_item_id: existing.id,
          reason: 'duplicate_cve_id',
        });
        continue;
      }

      const id = newId('id');
      const now = new Date().toISOString();
      const record = {
        id,
        tenant_id: ctx.tenantId,
        ...normalized,
        published_at: fields.published_at ?? normalized.created_at,
        description_summary: fields.description_summary ?? '',
        triage_result: null,
        updated_at: now,
      };
      getStore().cvePipelineItems.push(record);
      created.push(formatPipelineItem(record));

      audit({
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId,
        actor_role: ctx.role,
        action: 'cve.feed_item.ingested',
        resource_type: 'cve_pipeline_item',
        resource_id: id,
        metadata: {
          cve_id: record.cve_id,
          severity: record.severity,
          source: 'feed',
        },
      });
    } catch (err) {
      errors.push({
        index,
        cve_id: typeof fields?.cve_id === 'string' ? fields.cve_id : null,
        error: err.code ?? 'invalid_cve_feed_item',
        message: err.message,
      });
    }
  }

  if (created.length > 0) {
    persistStore();
  }

  return {
    created_count: created.length,
    skipped_count: skipped.length,
    error_count: errors.length,
    items: created,
    skipped,
    errors,
  };
}

export function createCvePipelineItem(ctx, body = {}) {
  if (wafFeatureDisabled()) return featureDisabledResponse();
  ensureStoreShape();
  try {
    validateCvePipelineItem(body);
    const normalized = normalizeCvePipelineItem(body);
    const id = newId('id');
    const now = new Date().toISOString();
    const record = {
      id,
      tenant_id: ctx.tenantId,
      ...normalized,
      triage_result: null,
      updated_at: now,
    };
    getStore().cvePipelineItems.push(record);
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'cve.pipeline_item.created',
      resource_type: 'cve_pipeline_item',
      resource_id: id,
      metadata: {
        cve_id: record.cve_id,
        severity: record.severity,
        stage: record.stage,
      },
    });
    persistStore();
    return { item: formatPipelineItem(record) };
  } catch (err) {
    return contractError(err);
  }
}

export function triageCvePipelineItem(ctx, id) {
  if (wafFeatureDisabled()) return featureDisabledResponse();
  ensureStoreShape();
  const item = findPipelineItem(ctx, id);
  if (!item) {
    return { error: 'cve_pipeline_item_not_found', status: 404 };
  }

  try {
    const footprint = buildTenantTechFootprint(ctx);
    const triage_result = triageCveItem(item, footprint);
    const now = new Date().toISOString();
    item.triage_result = triage_result;
    item.updated_at = now;
    if (item.stage === 'ingest') {
      item.stage = assertValidStageTransition(item.stage, 'triage');
    }

    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'cve.pipeline_item.triaged',
      resource_type: 'cve_pipeline_item',
      resource_id: item.id,
      metadata: {
        cve_id: item.cve_id,
        outcome: triage_result.outcome,
        score: triage_result.score,
      },
    });
    persistStore();
    return { item: formatPipelineItem(item), triage_result };
  } catch (err) {
    return contractError(err);
  }
}

export function matchCveAssets(ctx, id) {
  if (wafFeatureDisabled()) return featureDisabledResponse();
  ensureStoreShape();
  const item = findPipelineItem(ctx, id);
  if (!item) {
    return { error: 'cve_pipeline_item_not_found', status: 404 };
  }

  try {
    const assets = listTenantWafAssets(ctx);
    const matches = matchCveToAssets(item, assets);
    const now = new Date().toISOString();
    const created = [];

    for (const match of matches) {
      const existing = getStore().cveAssetMatches.find(
        (m) =>
          m.tenant_id === ctx.tenantId
          && m.cve_pipeline_item_id === item.id
          && m.waf_asset_id === match.waf_asset_id,
      );
      if (existing) {
        created.push(formatAssetMatch(existing));
        continue;
      }

      const record = {
        id: newId('id'),
        tenant_id: ctx.tenantId,
        cve_pipeline_item_id: item.id,
        waf_asset_id: match.waf_asset_id,
        asset_display: match.asset_display,
        match_source: match.match_source,
        confidence_level: match.confidence_level,
        match_confidence: match.match_confidence,
        match_reasons: match.match_reasons,
        requires_review: match.requires_review,
        exposure_claim_allowed: match.exposure_claim_allowed,
        validation_status: match.validation_status,
        created_at: now,
        updated_at: now,
      };
      getStore().cveAssetMatches.push(record);
      created.push(formatAssetMatch(record));

      audit({
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId,
        actor_role: ctx.role,
        action: 'cve.asset_match.created',
        resource_type: 'cve_asset_match',
        resource_id: record.id,
        metadata: {
          cve_id: item.cve_id,
          cve_pipeline_item_id: item.id,
          waf_asset_id: record.waf_asset_id,
          match_source: record.match_source,
          confidence_level: record.confidence_level,
        },
      });
    }

    if (item.stage === 'triage') {
      item.stage = assertValidStageTransition(item.stage, 'match');
    }
    item.updated_at = now;

    persistStore();
    return { matches: created };
  } catch (err) {
    return contractError(err);
  }
}

export function createRecommendation(ctx, matchId, vendor) {
  if (wafFeatureDisabled()) return featureDisabledResponse();
  ensureStoreShape();
  const matchRecord = findAssetMatch(ctx, matchId);
  if (!matchRecord) {
    return { error: 'cve_asset_match_not_found', status: 404 };
  }

  const item = findPipelineItem(ctx, matchRecord.cve_pipeline_item_id);
  if (!item) {
    return { error: 'cve_pipeline_item_not_found', status: 404 };
  }

  try {
    const recommendation = buildWafRuleRecommendation(
      {
        asset_display: matchRecord.asset_display,
        confidence_level: matchRecord.confidence_level,
        requires_review: matchRecord.requires_review,
        exposure_claim_allowed: matchRecord.exposure_claim_allowed,
      },
      vendor,
      item,
    );

    const now = new Date().toISOString();
    const record = {
      id: newId('id'),
      tenant_id: ctx.tenantId,
      cve_asset_match_id: matchRecord.id,
      waf_asset_id: matchRecord.waf_asset_id,
      vendor: recommendation.vendor,
      recommendation_type: recommendation.recommendation_type,
      recommendation_json: recommendation,
      approval_status: 'draft',
      created_at: now,
      updated_at: now,
    };
    getStore().wafRuleRecommendations.push(record);

    if (item.stage === 'validate') {
      item.stage = assertValidStageTransition(item.stage, 'recommend');
      item.updated_at = now;
    }

    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'cve.recommendation.created',
      resource_type: 'waf_rule_recommendation',
      resource_id: record.id,
      metadata: {
        cve_id: item.cve_id,
        cve_asset_match_id: matchRecord.id,
        vendor: record.vendor,
        recommendation_type: record.recommendation_type,
      },
    });
    persistStore();
    return { recommendation: formatRecommendation(record) };
  } catch (err) {
    return contractError(err);
  }
}

export function executeSafeCveValidation(ctx, pipelineItemId, body = {}) {
  if (wafFeatureDisabled()) return featureDisabledResponse();
  ensureStoreShape();
  const item = findPipelineItem(ctx, pipelineItemId);
  if (!item) {
    return { error: 'cve_pipeline_item_not_found', status: 404 };
  }

  const matches = listPipelineMatches(ctx, item.id);
  if (matches.length === 0) {
    return {
      error: 'cve_asset_matches_required',
      status: 409,
      message: 'Run asset matching before safe CVE validation.',
    };
  }

  const currentStage = item.stage ?? 'ingest';
  if (currentStage !== 'match' && currentStage !== 'validate') {
    return {
      error: 'invalid_cve_pipeline_stage',
      status: 409,
      message: `Safe validation requires match or validate stage; current stage is ${currentStage}.`,
    };
  }

  try {
    const now = new Date().toISOString();
    const validation_runs = [];
    const updated_matches = [];
    const skipped_matches = [];

    for (const matchRecord of matches) {
      const formattedMatch = formatAssetMatch(matchRecord);
      const checkId = resolveSafeCveValidationCheck(item, formattedMatch);
      if (!checkId) {
        matchRecord.validation_status = 'skipped';
        matchRecord.updated_at = now;
        skipped_matches.push(formatAssetMatch(matchRecord));
        continue;
      }

      assertCveSafeValidationAllowed(item, formattedMatch, body);
      const asset = findWafAsset(ctx, matchRecord.waf_asset_id);
      if (!asset) {
        return { error: 'waf_asset_not_found', status: 404 };
      }

      const validationRequest = buildSafeCveValidationRequest(item, formattedMatch, asset);
      const created = createWafValidation(ctx, validationRequest);
      if (created.error) {
        return created;
      }

      const validationRun = created.validation_run;
      const evidence = buildCveValidationEvidenceBinding(item, formattedMatch, validationRun, checkId);
      validationRun.summary_json = {
        ...(validationRun.summary_json ?? {}),
        cve_validation_binding: evidence,
      };
      validationRun.cve_pipeline_item_id = item.id;
      validationRun.cve_asset_match_id = matchRecord.id;
      validationRun.check_id = checkId;

      matchRecord.validation_status = 'validation_pending';
      matchRecord.last_waf_validation_run_id = validationRun.id;
      matchRecord.validation_evidence_json = evidence;
      matchRecord.updated_at = now;

      validation_runs.push(validationRun);
      updated_matches.push(formatAssetMatch(matchRecord));

      audit({
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId,
        actor_role: ctx.role,
        action: 'cve.asset_match.validation_bound',
        resource_type: 'cve_asset_match',
        resource_id: matchRecord.id,
        metadata: {
          cve_id: item.cve_id,
          cve_pipeline_item_id: item.id,
          waf_asset_id: matchRecord.waf_asset_id,
          waf_validation_run_id: validationRun.id,
          check_id: checkId,
        },
      });
    }

    if (currentStage === 'match') {
      item.stage = assertValidStageTransition(currentStage, 'validate');
    }
    item.updated_at = now;

    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'cve.pipeline_item.validated',
      resource_type: 'cve_pipeline_item',
      resource_id: item.id,
      metadata: {
        cve_id: item.cve_id,
        validation_run_count: validation_runs.length,
        skipped_match_count: skipped_matches.length,
        stage: item.stage,
      },
    });

    persistStore();
    return {
      item: formatPipelineItem(item),
      validation_runs,
      matches: updated_matches,
      skipped_matches,
    };
  } catch (err) {
    return contractError(err);
  }
}

export function executeCvePostMitigationRetest(ctx, pipelineItemId, body = {}) {
  if (wafFeatureDisabled()) return featureDisabledResponse();
  ensureStoreShape();
  const item = findPipelineItem(ctx, pipelineItemId);
  if (!item) {
    return { error: 'cve_pipeline_item_not_found', status: 404 };
  }

  const matches = listPipelineMatches(ctx, item.id);
  if (matches.length === 0) {
    return {
      error: 'cve_asset_matches_required',
      status: 409,
      message: 'Run asset matching before post-mitigation retest.',
    };
  }

  const recommendations = listPipelineRecommendations(ctx, item.id);
  const deployedRecommendations = recommendations.filter((rec) => isCveRecommendationDeployed(rec));
  if (deployedRecommendations.length === 0) {
    return {
      error: 'cve_deployed_recommendations_required',
      status: 409,
      message: 'Mark at least one WAF recommendation deployed before post-mitigation retest.',
    };
  }

  const currentStage = item.stage ?? 'ingest';
  if (currentStage !== 'ticket' && currentStage !== 'retest') {
    return {
      error: 'invalid_cve_pipeline_stage',
      status: 409,
      message: `Post-mitigation retest requires ticket or retest stage; current stage is ${currentStage}.`,
    };
  }

  try {
    const now = new Date().toISOString();
    const validation_runs = [];
    const updated_matches = [];
    const updated_recommendations = [];
    const matchOutcomes = [];
    const recommendationsByMatchId = new Map();

    for (const recommendation of deployedRecommendations) {
      const existing = recommendationsByMatchId.get(recommendation.cve_asset_match_id) ?? [];
      existing.push(recommendation);
      recommendationsByMatchId.set(recommendation.cve_asset_match_id, existing);
    }

    for (const matchRecord of matches) {
      const matchRecommendations = recommendationsByMatchId.get(matchRecord.id) ?? [];
      const recommendation = selectLatestDeployedRecommendation(matchRecommendations);
      if (!recommendation) {
        continue;
      }

      const formattedMatch = formatAssetMatch(matchRecord);
      const existingRun = matchRecord.last_waf_validation_run_id
        ? findValidationRun(ctx, matchRecord.last_waf_validation_run_id)
        : null;
      const existingEvidence = matchRecord.validation_evidence_json ?? null;
      const hasPendingRetest =
        existingRun
        && existingRun.status !== 'finalized'
        && isRetestEvidenceBinding(existingEvidence);

      if (hasPendingRetest) {
        const outcome = deriveCveRetestOutcomeFromValidationRun(existingRun);
        matchOutcomes.push({ match_id: matchRecord.id, ...outcome });
        updated_matches.push(formatAssetMatch(matchRecord));
        continue;
      }

      if (existingRun?.status === 'finalized' && isRetestEvidenceBinding(existingEvidence)) {
        const outcome = deriveCveRetestOutcomeFromValidationRun(existingRun);
        matchRecord.validation_status = outcome.status;
        matchRecord.updated_at = now;
        if (matchRecord.validation_evidence_json) {
          matchRecord.validation_evidence_json = {
            ...matchRecord.validation_evidence_json,
            validation_status: outcome.status,
            retest_verdict: outcome.verdict,
            finalized_at: existingRun.finalized_at ?? now,
          };
        }
        matchOutcomes.push({ match_id: matchRecord.id, ...outcome });
        updated_matches.push(formatAssetMatch(matchRecord));
        continue;
      }

      const checkId = resolveSafeCveValidationCheck(item, formattedMatch);
      if (!checkId) {
        matchRecord.validation_status = 'skipped';
        matchRecord.updated_at = now;
        matchOutcomes.push({
          match_id: matchRecord.id,
          status: 'skipped',
          closure_ready: true,
          verdict: 'skipped',
        });
        updated_matches.push(formatAssetMatch(matchRecord));
        continue;
      }

      assertCvePostMitigationRetestAllowed(item, formattedMatch, recommendation, body);
      const asset = findWafAsset(ctx, matchRecord.waf_asset_id);
      if (!asset) {
        return { error: 'waf_asset_not_found', status: 404 };
      }

      const validationRequest = buildCvePostMitigationRetestRequest(
        item,
        formattedMatch,
        asset,
        recommendation,
      );
      const created = createWafValidation(ctx, validationRequest);
      if (created.error) {
        return created;
      }

      const validationRun = created.validation_run;
      const evidence = buildCveRetestEvidenceBinding(
        item,
        formattedMatch,
        validationRun,
        checkId,
        recommendation,
      );
      validationRun.summary_json = {
        ...(validationRun.summary_json ?? {}),
        cve_validation_binding: evidence,
      };
      validationRun.cve_pipeline_item_id = item.id;
      validationRun.cve_asset_match_id = matchRecord.id;
      validationRun.check_id = checkId;

      matchRecord.validation_status = 'retest_pending';
      matchRecord.last_waf_validation_run_id = validationRun.id;
      matchRecord.validation_evidence_json = evidence;
      matchRecord.updated_at = now;

      const recIndex = getStore().wafRuleRecommendations.findIndex(
        (rec) => rec.id === recommendation.id && rec.tenant_id === ctx.tenantId,
      );
      if (recIndex >= 0 && getStore().wafRuleRecommendations[recIndex].approval_status !== 'retest_pending') {
        getStore().wafRuleRecommendations[recIndex].approval_status = 'retest_pending';
        getStore().wafRuleRecommendations[recIndex].updated_at = now;
        updated_recommendations.push(formatRecommendation(getStore().wafRuleRecommendations[recIndex]));
      }

      validation_runs.push(validationRun);
      updated_matches.push(formatAssetMatch(matchRecord));
      matchOutcomes.push({
        match_id: matchRecord.id,
        status: 'retest_pending',
        closure_ready: false,
        verdict: null,
      });

      audit({
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId,
        actor_role: ctx.role,
        action: 'cve.asset_match.retest_bound',
        resource_type: 'cve_asset_match',
        resource_id: matchRecord.id,
        metadata: {
          cve_id: item.cve_id,
          cve_pipeline_item_id: item.id,
          waf_asset_id: matchRecord.waf_asset_id,
          waf_validation_run_id: validationRun.id,
          waf_rule_recommendation_id: recommendation.id,
          check_id: checkId,
        },
      });
    }

    if (matchOutcomes.length === 0) {
      return {
        error: 'cve_deployed_recommendations_required',
        status: 409,
        message: 'No deployed recommendations are linked to pipeline asset matches.',
      };
    }

    const closure = resolveCvePipelineRetestClosure(matchOutcomes);
    let nextStage = currentStage;
    if (closure.ready) {
      nextStage = assertValidStageTransition(currentStage, 'resolved');
    } else if (currentStage === 'ticket') {
      nextStage = assertValidStageTransition(currentStage, 'retest');
    }
    item.stage = nextStage;
    item.updated_at = now;

    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: closure.ready ? 'cve.pipeline_item.resolved' : 'cve.pipeline_item.retest_started',
      resource_type: 'cve_pipeline_item',
      resource_id: item.id,
      metadata: {
        cve_id: item.cve_id,
        validation_run_count: validation_runs.length,
        closure_ready: closure.ready,
        closure_verdict: closure.verdict,
        stage: nextStage,
      },
    });

    persistStore();
    return {
      item: formatPipelineItem(item),
      validation_runs,
      matches: updated_matches,
      recommendations: deployedRecommendations.map((rec) => formatRecommendation(rec)),
      closure,
      ...(updated_recommendations.length > 0 ? { updated_recommendations } : {}),
    };
  } catch (err) {
    return contractError(err);
  }
}

export function patchCveItemStage(ctx, id, stage) {
  if (wafFeatureDisabled()) return featureDisabledResponse();
  ensureStoreShape();
  const item = findPipelineItem(ctx, id);
  if (!item) {
    return { error: 'cve_pipeline_item_not_found', status: 404 };
  }

  try {
    const nextStage = assertValidStageTransition(item.stage, stage);
    const now = new Date().toISOString();
    const previousStage = item.stage;
    item.stage = nextStage;
    item.updated_at = now;

    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'cve.pipeline_item.stage_updated',
      resource_type: 'cve_pipeline_item',
      resource_id: item.id,
      metadata: {
        cve_id: item.cve_id,
        previous_stage: previousStage,
        stage: nextStage,
      },
    });
    persistStore();
    return { item: formatPipelineItem(item) };
  } catch (err) {
    return contractError(err);
  }
}

export function getCveMitigationPlaybook(ctx, pipelineItemId) {
  if (wafFeatureDisabled()) return featureDisabledResponse();
  ensureStoreShape();
  const item = findPipelineItem(ctx, pipelineItemId);
  if (!item) {
    return { error: 'cve_pipeline_item_not_found', status: 404 };
  }

  try {
    const playbook = buildOrRefreshPlaybook(ctx, item);
    persistStore();
    return { playbook: formatPlaybook(playbook) };
  } catch (err) {
    return contractError(err, err.code === 'cve_playbook_recommendations_required' ? 409 : 400);
  }
}

export function approveCveMitigationPlaybook(ctx, pipelineItemId, body = {}) {
  if (wafFeatureDisabled()) return featureDisabledResponse();
  ensureStoreShape();
  const item = findPipelineItem(ctx, pipelineItemId);
  if (!item) {
    return { error: 'cve_pipeline_item_not_found', status: 404 };
  }

  try {
    const playbook = buildOrRefreshPlaybook(ctx, item);
    assertCvePlaybookApprovable(playbook, item);
    const now = new Date().toISOString();
    const parentId = newId('id');
    const parentFields = buildPlaybookParentActionItem(playbook, item.id, parentId);
    const parentActionItem = upsertPlaybookActionItem(ctx, parentFields);

    const childActionItems = [];
    const vendorSlices = playbook.vendor_slices.map((slice) => {
      const childId = newId('id');
      const childFields = buildPlaybookChildActionItem(
        playbook,
        slice,
        item.id,
        childId,
        parentActionItem.action_item_id,
      );
      const childActionItem = upsertPlaybookActionItem(ctx, childFields);
      childActionItems.push(childActionItem);
      return {
        ...slice,
        child_action_item_id: childActionItem.action_item_id,
      };
    });

    const approvedPlaybook = persistPlaybook(ctx, {
      ...playbook,
      status: 'approved',
      parent_action_item_id: parentActionItem.action_item_id,
      vendor_slices: vendorSlices,
      approved_at: now,
      approval_note: typeof body.note === 'string' ? body.note.trim() : null,
      updated_at: now,
    });

    const currentStage = item.stage ?? 'ingest';
    if (currentStage === 'recommend') {
      item.stage = assertValidStageTransition(currentStage, 'ticket');
      item.updated_at = now;
    }

    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'cve.playbook.approved',
      resource_type: 'cve_mitigation_playbook',
      resource_id: approvedPlaybook.playbook_id,
      metadata: {
        cve_id: item.cve_id,
        pipeline_item_id: item.id,
        parent_action_item_id: parentActionItem.action_item_id,
        child_action_item_count: childActionItems.length,
        vendor_slice_count: vendorSlices.length,
      },
    });

    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'waf.action_item.created',
      resource_type: 'waf_action_item',
      resource_id: parentActionItem.action_item_id,
      metadata: {
        playbook_id: approvedPlaybook.playbook_id,
        category: 'cve_mitigation',
        linkage: 'parent',
      },
    });

    for (const childActionItem of childActionItems) {
      audit({
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId,
        actor_role: ctx.role,
        action: 'waf.action_item.created',
        resource_type: 'waf_action_item',
        resource_id: childActionItem.action_item_id,
        metadata: {
          playbook_id: approvedPlaybook.playbook_id,
          parent_action_item_id: parentActionItem.action_item_id,
          category: 'cve_mitigation',
          linkage: 'child',
        },
      });
    }

    persistStore();
    return {
      playbook: formatPlaybook(approvedPlaybook),
      parent_action_item: parentActionItem,
      child_action_items: childActionItems,
      item: formatPipelineItem(item),
    };
  } catch (err) {
    return contractError(err, err.code === 'cve_playbook_not_approvable' ? 409 : 400);
  }
}

export function executeCoordinatedCveRetest(ctx, pipelineItemId, body = {}) {
  if (wafFeatureDisabled()) return featureDisabledResponse();
  ensureStoreShape();
  const item = findPipelineItem(ctx, pipelineItemId);
  if (!item) {
    return { error: 'cve_pipeline_item_not_found', status: 404 };
  }

  const playbook = findPlaybookByPipelineItemId(ctx, pipelineItemId);
  if (!playbook) {
    return {
      error: 'cve_playbook_not_found',
      status: 404,
      message: 'Approve a mitigation playbook before coordinated retest.',
    };
  }

  try {
    assertCvePlaybookCoordinatedRetestAllowed(playbook);
    const retestResult = executeCvePostMitigationRetest(ctx, pipelineItemId, body);
    if (retestResult.error) {
      return retestResult;
    }

    const now = new Date().toISOString();
    const nextStatus = resolvePlaybookStatusFromRetestClosure(
      retestResult.closure,
      playbook.status,
    );
    const updatedPlaybook = persistPlaybook(ctx, {
      ...playbook,
      status: nextStatus,
      updated_at: now,
    });

    let action_items = [];
    if (retestResult.closure?.ready) {
      action_items = syncPlaybookActionItemStatuses(ctx, updatedPlaybook, 'resolved');
      audit({
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId,
        actor_role: ctx.role,
        action: 'cve.playbook.resolved',
        resource_type: 'cve_mitigation_playbook',
        resource_id: updatedPlaybook.playbook_id,
        metadata: {
          cve_id: item.cve_id,
          pipeline_item_id: item.id,
          closure_verdict: retestResult.closure.verdict,
        },
      });
    } else if (playbook.status === 'approved') {
      action_items = syncPlaybookActionItemStatuses(ctx, updatedPlaybook, 'retest_pending');
      audit({
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId,
        actor_role: ctx.role,
        action: 'cve.playbook.retest_started',
        resource_type: 'cve_mitigation_playbook',
        resource_id: updatedPlaybook.playbook_id,
        metadata: {
          cve_id: item.cve_id,
          pipeline_item_id: item.id,
        },
      });
    }

    persistStore();
    return {
      ...retestResult,
      playbook: formatPlaybook(updatedPlaybook),
      ...(action_items.length > 0 ? { action_items } : {}),
    };
  } catch (err) {
    return contractError(err, err.code === 'cve_playbook_not_approved' ? 409 : 400);
  }
}