import { loadRuntimeConfig } from '../../config.mjs';
import {
  assertValidStageTransition,
  buildWafRuleRecommendation,
  createCvePipelineItem as normalizeCvePipelineItem,
  matchCveToAssets,
  triageCveItem,
  validateCvePipelineItem,
} from '../../contracts/cvePipeline.mjs';
import { newId } from '../../lib/ids.mjs';
import { redactObject } from '../../lib/redact.mjs';
import { createAuditRepository } from './auditRepository.mjs';
import { createCvePipelineRepository } from './cvePipelineRepository.mjs';
import { createWafPostureRepository } from './wafPostureRepository.mjs';

function contractError(err, fallbackStatus = 400) {
  return {
    error: err.code ?? 'invalid_request',
    status: fallbackStatus,
    message: err.message,
  };
}

function wafFeatureDisabled() {
  const { featureFlags } = loadRuntimeConfig();
  return featureFlags.wafPostureEnabled !== true;
}

function featureDisabledResponse() {
  return { error: 'waf_feature_disabled', status: 404 };
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
    stage: record.stage ?? record.state,
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

function buildTenantTechFootprint(assets) {
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

/**
 * @param {import('pg').Pool} pool
 * @param {{
 *   now?: () => Date,
 *   newId?: typeof newId,
 * }} [options]
 */
export function createPostgresCvePipelineServices(pool, options = {}) {
  const cveRepo = createCvePipelineRepository(pool);
  const wafRepo = createWafPostureRepository(pool);
  const auditRepo = createAuditRepository(pool);
  const nowFn = options.now ?? (() => new Date());
  const newIdFn = options.newId ?? newId;

  return {
    async listCvePipelineItems(ctx) {
      if (wafFeatureDisabled()) return featureDisabledResponse();
      const items = await cveRepo.listCvePipelineItems(ctx);
      return { items: items.map((item) => formatPipelineItem(item)) };
    },

    async createCvePipelineItem(ctx, body = {}) {
      if (wafFeatureDisabled()) return featureDisabledResponse();
      try {
        validateCvePipelineItem(body);
        const normalized = normalizeCvePipelineItem(body);
        const id = newIdFn('id');
        const now = nowFn().toISOString();
        const record = await cveRepo.insertCvePipelineItem(ctx, {
          id,
          tenant_id: ctx.tenantId,
          ...normalized,
          triage_result: null,
          updated_at: now,
        });
        await auditRepo.appendAuditEvent({
          tenant_id: ctx.tenantId,
          actor_user_id: ctx.userId,
          actor_role: ctx.role,
          action: 'cve.pipeline_item.created',
          resource_type: 'cve_pipeline_item',
          resource_id: id,
          metadata: redactObject({
            cve_id: record.cve_id,
            severity: record.severity,
            stage: record.stage,
          }),
        });
        return { item: formatPipelineItem(record) };
      } catch (err) {
        return contractError(err);
      }
    },

    async triageCvePipelineItem(ctx, id) {
      if (wafFeatureDisabled()) return featureDisabledResponse();
      const item = await cveRepo.getCvePipelineItem(ctx, id);
      if (!item) {
        return { error: 'cve_pipeline_item_not_found', status: 404 };
      }

      try {
        const wafAssets = await wafRepo.listWafAssets(ctx);
        const footprint = buildTenantTechFootprint(wafAssets);
        const triage_result = triageCveItem(item, footprint);
        const now = nowFn().toISOString();
        let stage = item.stage ?? item.state;
        if (stage === 'ingest') {
          stage = assertValidStageTransition(stage, 'triage');
        }
        const updated = await cveRepo.updateCvePipelineItemStage(ctx, id, stage, {
          triage_result,
          updated_at: now,
        });

        await auditRepo.appendAuditEvent({
          tenant_id: ctx.tenantId,
          actor_user_id: ctx.userId,
          actor_role: ctx.role,
          action: 'cve.pipeline_item.triaged',
          resource_type: 'cve_pipeline_item',
          resource_id: item.id,
          metadata: redactObject({
            cve_id: item.cve_id,
            outcome: triage_result.outcome,
            score: triage_result.score,
          }),
        });
        return { item: formatPipelineItem(updated), triage_result };
      } catch (err) {
        return contractError(err);
      }
    },

    async matchCveAssets(ctx, id) {
      if (wafFeatureDisabled()) return featureDisabledResponse();
      const item = await cveRepo.getCvePipelineItem(ctx, id);
      if (!item) {
        return { error: 'cve_pipeline_item_not_found', status: 404 };
      }

      try {
        const assets = await wafRepo.listWafAssets(ctx);
        const matches = matchCveToAssets(item, assets);
        const now = nowFn().toISOString();
        const created = [];

        for (const match of matches) {
          const existing = (await cveRepo.listCveAssetMatches(ctx, item.id)).find(
            (entry) => entry.waf_asset_id === match.waf_asset_id,
          );
          if (existing) {
            created.push(formatAssetMatch(existing));
            continue;
          }

          const asset = assets.find((entry) => entry.id === match.waf_asset_id);
          const record = await cveRepo.insertCveAssetMatch(ctx, {
            id: newIdFn('id'),
            tenant_id: ctx.tenantId,
            cve_pipeline_item_id: item.id,
            waf_asset_id: match.waf_asset_id,
            asset_display: match.asset_display ?? asset?.canonical_url ?? null,
            match_source: match.match_source,
            confidence_level: match.confidence_level,
            match_confidence: match.match_confidence,
            match_reasons: match.match_reasons,
            requires_review: match.requires_review,
            exposure_claim_allowed: match.exposure_claim_allowed,
            validation_status: match.validation_status,
            created_at: now,
            updated_at: now,
          });
          created.push(formatAssetMatch(record));

          await auditRepo.appendAuditEvent({
            tenant_id: ctx.tenantId,
            actor_user_id: ctx.userId,
            actor_role: ctx.role,
            action: 'cve.asset_match.created',
            resource_type: 'cve_asset_match',
            resource_id: record.id,
            metadata: redactObject({
              cve_id: item.cve_id,
              cve_pipeline_item_id: item.id,
              waf_asset_id: record.waf_asset_id,
              match_source: record.match_source,
              confidence_level: record.confidence_level,
            }),
          });
        }

        if ((item.stage ?? item.state) === 'triage') {
          const nextStage = assertValidStageTransition(item.stage ?? item.state, 'match');
          await cveRepo.updateCvePipelineItemStage(ctx, item.id, nextStage, { updated_at: now });
        }

        return { matches: created };
      } catch (err) {
        return contractError(err);
      }
    },

    async createRecommendation(ctx, matchId, vendor) {
      if (wafFeatureDisabled()) return featureDisabledResponse();
      const matchRecord = await cveRepo.getCveAssetMatch(ctx, matchId);
      if (!matchRecord) {
        return { error: 'cve_asset_match_not_found', status: 404 };
      }

      const item = await cveRepo.getCvePipelineItem(ctx, matchRecord.cve_pipeline_item_id);
      if (!item) {
        return { error: 'cve_pipeline_item_not_found', status: 404 };
      }

      try {
        const asset = await wafRepo.getWafAsset(ctx, matchRecord.waf_asset_id);
        const assetDisplay = matchRecord.asset_display ?? asset?.canonical_url ?? 'declared asset';
        const recommendation = buildWafRuleRecommendation(
          {
            asset_display: assetDisplay,
            confidence_level: matchRecord.confidence_level,
            requires_review: matchRecord.requires_review,
            exposure_claim_allowed: matchRecord.exposure_claim_allowed,
          },
          vendor,
          item,
        );

        const now = nowFn().toISOString();
        const record = await cveRepo.insertWafRuleRecommendation(ctx, {
          id: newIdFn('id'),
          tenant_id: ctx.tenantId,
          cve_asset_match_id: matchRecord.id,
          waf_asset_id: matchRecord.waf_asset_id,
          vendor: recommendation.vendor,
          recommendation_type: recommendation.recommendation_type,
          recommendation_json: recommendation,
          approval_status: 'draft',
          created_at: now,
          updated_at: now,
        });

        if ((item.stage ?? item.state) === 'validate') {
          const nextStage = assertValidStageTransition(item.stage ?? item.state, 'recommend');
          await cveRepo.updateCvePipelineItemStage(ctx, item.id, nextStage, { updated_at: now });
        }

        await auditRepo.appendAuditEvent({
          tenant_id: ctx.tenantId,
          actor_user_id: ctx.userId,
          actor_role: ctx.role,
          action: 'cve.recommendation.created',
          resource_type: 'waf_rule_recommendation',
          resource_id: record.id,
          metadata: redactObject({
            cve_id: item.cve_id,
            cve_asset_match_id: matchRecord.id,
            vendor: record.vendor,
            recommendation_type: record.recommendation_type,
          }),
        });
        return { recommendation: formatRecommendation(record) };
      } catch (err) {
        return contractError(err);
      }
    },

    async patchCveItemStage(ctx, id, stage) {
      if (wafFeatureDisabled()) return featureDisabledResponse();
      const item = await cveRepo.getCvePipelineItem(ctx, id);
      if (!item) {
        return { error: 'cve_pipeline_item_not_found', status: 404 };
      }

      try {
        const nextStage = assertValidStageTransition(item.stage ?? item.state, stage);
        const now = nowFn().toISOString();
        const previousStage = item.stage ?? item.state;
        const updated = await cveRepo.updateCvePipelineItemStage(ctx, id, nextStage, {
          updated_at: now,
        });

        await auditRepo.appendAuditEvent({
          tenant_id: ctx.tenantId,
          actor_user_id: ctx.userId,
          actor_role: ctx.role,
          action: 'cve.pipeline_item.stage_updated',
          resource_type: 'cve_pipeline_item',
          resource_id: item.id,
          metadata: redactObject({
            cve_id: item.cve_id,
            previous_stage: previousStage,
            stage: nextStage,
          }),
        });
        return { item: formatPipelineItem(updated) };
      } catch (err) {
        return contractError(err);
      }
    },
  };
}