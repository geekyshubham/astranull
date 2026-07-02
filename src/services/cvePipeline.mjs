import { audit } from '../audit.mjs';
import { loadRuntimeConfig } from '../config.mjs';
import {
  assertValidStageTransition,
  buildWafRuleRecommendation,
  createCvePipelineItem as normalizeCvePipelineItem,
  matchCveToAssets,
  triageCveItem,
  validateCvePipelineItem,
} from '../contracts/cvePipeline.mjs';
import { newId } from '../lib/ids.mjs';
import { getStore, persistStore } from '../store.mjs';

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
  const keys = ['cvePipelineItems', 'cveAssetMatches', 'wafRuleRecommendations', 'wafAssets'];
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
    created_at: record.created_at,
    updated_at: record.updated_at,
  };
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

export function listCvePipelineItems(ctx) {
  if (wafFeatureDisabled()) return featureDisabledResponse();
  ensureStoreShape();
  const items = getStore()
    .cvePipelineItems.filter((i) => i.tenant_id === ctx.tenantId)
    .map((i) => formatPipelineItem(i));
  return { items };
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