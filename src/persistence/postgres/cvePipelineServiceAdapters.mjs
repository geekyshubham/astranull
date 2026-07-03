import { loadRuntimeConfig } from '../../config.mjs';
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
} from '../../contracts/cvePipeline.mjs';
import { createActionItem } from '../../contracts/wafPosture.mjs';
import { normalizeWafValidationRequest } from '../../contracts/wafPosture.mjs';
import { newId } from '../../lib/ids.mjs';
import { redactObject } from '../../lib/redact.mjs';
import { createActionItemRepository } from './actionItemRepository.mjs';
import { createAuditRepository } from './auditRepository.mjs';
import { createCvePipelineRepository } from './cvePipelineRepository.mjs';
import { withTenantContext } from './tenantContext.mjs';
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
    last_waf_validation_run_id: record.last_waf_validation_run_id ?? null,
    validation_evidence_json: record.validation_evidence_json ?? null,
    created_at: record.created_at,
    updated_at: record.updated_at,
  };
}

function attachValidationEvidence(matches, validationBindings = {}) {
  return matches.map((match) => ({
    ...match,
    validation_evidence_json: validationBindings[match.id] ?? match.validation_evidence_json ?? null,
  }));
}

function isRetestEvidenceBinding(evidence) {
  return evidence?.retest_phase === 'post_mitigation';
}

function selectLatestDeployedRecommendation(recommendations = []) {
  const deployed = recommendations.filter((rec) => isCveRecommendationDeployed(rec));
  if (deployed.length === 0) return null;
  return deployed[deployed.length - 1];
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
  const evidence = record.evidence ?? record.evidence_json ?? {};
  return {
    action_item_id: record.action_item_id ?? record.id,
    category: record.category,
    title: record.title,
    asset: record.asset ?? evidence.asset ?? { display: record.asset_display ?? 'declared asset' },
    owner: record.owner,
    severity: record.severity,
    evidence: {
      summary: evidence.summary ?? '',
      links: evidence.links ?? [],
      ...(evidence.vendor_checklist ? { vendor_checklist: evidence.vendor_checklist } : {}),
      ...(evidence.hostname_scope_hashes ? { hostname_scope_hashes: evidence.hostname_scope_hashes } : {}),
    },
    recommended_solution: record.recommended_solution,
    retest_url: record.retest_url,
    status: record.status,
    ...(evidence.parent_action_item_id || record.parent_action_item_id
      ? { parent_action_item_id: evidence.parent_action_item_id ?? record.parent_action_item_id }
      : {}),
    ...(evidence.playbook_id || record.playbook_id
      ? { playbook_id: evidence.playbook_id ?? record.playbook_id }
      : {}),
    ...(record.created_at ? { created_at: record.created_at } : {}),
    ...(record.updated_at ? { updated_at: record.updated_at } : {}),
  };
}

function readMitigationPlaybook(item) {
  return item?.triage_summary_json?.mitigation_playbook ?? null;
}

async function buildOrRefreshPlaybook(ctx, item, cveRepo) {
  const matches = await cveRepo.listCveAssetMatches(ctx, item.id);
  const recommendations = await cveRepo.listWafRuleRecommendationsForPipelineItem(ctx, item.id);
  const existing = readMitigationPlaybook(item);
  const nowFn = () => new Date().toISOString();
  const now = nowFn();
  const draft = buildCveMitigationPlaybook(item, recommendations, matches, existing);
  return {
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
}

async function upsertPlaybookActionItem(actionRepo, ctx, fields, now) {
  const normalized = createActionItem({
    ...fields,
    evidence: {
      ...fields.evidence,
      parent_action_item_id: fields.parent_action_item_id ?? null,
      playbook_id: fields.playbook_id ?? null,
      dedupe_key: fields.dedupe_key,
    },
  });
  const record = await actionRepo.insertActionItem(ctx, {
    ...normalized,
    action_item_id: fields.action_item_id,
    asset_display: normalized.asset.display,
    waf_asset_id: fields.waf_asset_id,
    primary_reason: fields.primary_reason,
    cve_pipeline_item_id: fields.cve_pipeline_item_id,
    dedupe_key: fields.dedupe_key,
    created_at: now,
    updated_at: now,
  });
  return formatPlaybookActionItem(record);
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
  const cveRepo = options.repositories?.cvePipeline ?? createCvePipelineRepository(pool);
  const wafRepo = options.repositories?.wafPosture ?? createWafPostureRepository(pool);
  const auditRepo = options.repositories?.audit ?? createAuditRepository(pool);
  const actionRepo = options.repositories?.actionItems ?? createActionItemRepository(pool);
  const nowFn = options.now ?? (() => new Date());
  const newIdFn = options.newId ?? newId;

  return {
    async listCvePipelineItems(ctx) {
      if (wafFeatureDisabled()) return featureDisabledResponse();
      const items = await cveRepo.listCvePipelineItems(ctx);
      return { items: items.map((item) => formatPipelineItem(item)) };
    },

    async ingestCveFeed(ctx, feedItems = []) {
      if (wafFeatureDisabled()) return featureDisabledResponse();
      if (!Array.isArray(feedItems)) {
        return {
          error: 'invalid_cve_feed_request',
          status: 400,
          message: 'feedItems must be an array.',
        };
      }

      const created = [];
      const skipped = [];
      const errors = [];
      const existingItems = await cveRepo.listCvePipelineItems(ctx);
      const byCveId = new Map(
        existingItems.map((item) => [String(item.cve_id).toUpperCase(), item]),
      );

      for (let index = 0; index < feedItems.length; index += 1) {
        const fields = feedItems[index];
        try {
          validateCvePipelineItem(fields);
          const normalized = normalizeCvePipelineItem(fields);
          const existing = byCveId.get(normalized.cve_id);
          if (existing) {
            skipped.push({
              cve_id: normalized.cve_id,
              existing_item_id: existing.id,
              reason: 'duplicate_cve_id',
            });
            continue;
          }

          const id = newIdFn('id');
          const now = nowFn().toISOString();
          const record = await cveRepo.insertCvePipelineItem(ctx, {
            id,
            tenant_id: ctx.tenantId,
            ...normalized,
            published_at: fields.published_at ?? normalized.created_at,
            description_summary: fields.description_summary ?? '',
            triage_result: null,
            updated_at: now,
          });
          byCveId.set(normalized.cve_id, record);
          created.push(formatPipelineItem(record));

          await auditRepo.appendAuditEvent({
            tenant_id: ctx.tenantId,
            actor_user_id: ctx.userId,
            actor_role: ctx.role,
            action: 'cve.feed_item.ingested',
            resource_type: 'cve_pipeline_item',
            resource_id: id,
            metadata: redactObject({
              cve_id: record.cve_id,
              severity: record.severity,
              source: 'feed',
            }),
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

      return {
        created_count: created.length,
        skipped_count: skipped.length,
        error_count: errors.length,
        items: created,
        skipped,
        errors,
      };
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

    async executeSafeCveValidation(ctx, pipelineItemId, body = {}) {
      if (wafFeatureDisabled()) return featureDisabledResponse();
      const item = await cveRepo.getCvePipelineItem(ctx, pipelineItemId);
      if (!item) {
        return { error: 'cve_pipeline_item_not_found', status: 404 };
      }

      const matches = await cveRepo.listCveAssetMatches(ctx, item.id);
      if (matches.length === 0) {
        return {
          error: 'cve_asset_matches_required',
          status: 409,
          message: 'Run asset matching before safe CVE validation.',
        };
      }

      const currentStage = item.stage ?? item.state ?? 'ingest';
      if (currentStage !== 'match' && currentStage !== 'validate') {
        return {
          error: 'invalid_cve_pipeline_stage',
          status: 409,
          message: `Safe validation requires match or validate stage; current stage is ${currentStage}.`,
        };
      }

      try {
        const now = nowFn().toISOString();
        const txResult = await withTenantContext(pool, ctx.tenantId, async (client) => {
          const validation_runs = [];
          const updated_matches = [];
          const skipped_matches = [];
          const validation_bindings = {
            ...(item.triage_summary_json?.validation_bindings ?? {}),
          };
          const txOptions = { client };

          for (const matchRecord of matches) {
            const formattedMatch = formatAssetMatch(matchRecord);
            const checkId = resolveSafeCveValidationCheck(item, formattedMatch);
            if (!checkId) {
              const skipped = await cveRepo.updateCveAssetMatch(ctx, matchRecord.id, {
                validation_status: 'skipped',
                updated_at: now,
              }, txOptions);
              skipped_matches.push(formatAssetMatch(skipped));
              continue;
            }

            assertCveSafeValidationAllowed(item, formattedMatch, body);
            const asset = await wafRepo.getWafAsset(ctx, matchRecord.waf_asset_id, txOptions);
            if (!asset) {
              const err = new Error('WAF asset not found.');
              err.code = 'waf_asset_not_found';
              throw err;
            }

            const validationRequest = buildSafeCveValidationRequest(item, formattedMatch, asset);
            const profile = normalizeWafValidationRequest(validationRequest);
            const runId = newIdFn('id');
            const evidence = buildCveValidationEvidenceBinding(
              item,
              formattedMatch,
              { id: runId },
              checkId,
            );
            const validationRun = await wafRepo.createWafValidationRun(ctx, {
              id: runId,
              tenant_id: ctx.tenantId,
              waf_asset_id: profile.waf_asset_id,
              mode: profile.modes[0] ?? 'fingerprint',
              status: 'planned',
              safety_profile_json: {
                modes: profile.modes,
                probe_profile: profile.probe_profile,
                marker_profile: profile.marker_profile,
              },
              summary_json: {
                cve_validation_binding: evidence,
              },
              created_at: now,
            }, txOptions);
            validationRun.summary_json = {
              ...(validationRun.summary_json ?? {}),
              cve_validation_binding: evidence,
            };
            validationRun.cve_pipeline_item_id = item.id;
            validationRun.cve_asset_match_id = matchRecord.id;
            validationRun.check_id = checkId;
            validation_bindings[matchRecord.id] = evidence;

            const updated = await cveRepo.updateCveAssetMatch(ctx, matchRecord.id, {
              validation_status: 'validation_pending',
              last_waf_validation_run_id: validationRun.id,
              updated_at: now,
            }, txOptions);
            updated_matches.push(
              formatAssetMatch({
                ...updated,
                validation_evidence_json: evidence,
              }),
            );
            validation_runs.push(validationRun);

            await auditRepo.appendAuditEvent({
              tenant_id: ctx.tenantId,
              actor_user_id: ctx.userId,
              actor_role: ctx.role,
              action: 'waf.validation.started',
              resource_type: 'waf_validation_run',
              resource_id: validationRun.id,
              metadata: redactObject({
                waf_asset_id: profile.waf_asset_id,
                modes: profile.modes,
              }),
            }, txOptions);

            await auditRepo.appendAuditEvent({
              tenant_id: ctx.tenantId,
              actor_user_id: ctx.userId,
              actor_role: ctx.role,
              action: 'cve.asset_match.validation_bound',
              resource_type: 'cve_asset_match',
              resource_id: matchRecord.id,
              metadata: redactObject({
                cve_id: item.cve_id,
                cve_pipeline_item_id: item.id,
                waf_asset_id: matchRecord.waf_asset_id,
                waf_validation_run_id: validationRun.id,
                check_id: checkId,
              }),
            }, txOptions);
          }

          let nextStage = currentStage;
          if (currentStage === 'match') {
            nextStage = assertValidStageTransition(currentStage, 'validate');
          }
          const updatedItem = await cveRepo.updateCvePipelineItemStage(ctx, item.id, nextStage, {
            updated_at: now,
            validation_bindings,
          }, txOptions);

          await auditRepo.appendAuditEvent({
            tenant_id: ctx.tenantId,
            actor_user_id: ctx.userId,
            actor_role: ctx.role,
            action: 'cve.pipeline_item.validated',
            resource_type: 'cve_pipeline_item',
            resource_id: item.id,
            metadata: redactObject({
              cve_id: item.cve_id,
              validation_run_count: validation_runs.length,
              skipped_match_count: skipped_matches.length,
              stage: nextStage,
            }),
          }, txOptions);

          return {
            validation_runs,
            updated_matches,
            skipped_matches,
            validation_bindings,
            updatedItem,
          };
        });

        return {
          item: formatPipelineItem(txResult.updatedItem),
          validation_runs: txResult.validation_runs,
          matches: attachValidationEvidence(txResult.updated_matches, txResult.validation_bindings),
          skipped_matches: attachValidationEvidence(
            txResult.skipped_matches,
            txResult.validation_bindings,
          ),
        };
      } catch (err) {
        if (err?.code === 'waf_asset_not_found') {
          return { error: 'waf_asset_not_found', status: 404 };
        }
        return contractError(err);
      }
    },

    async executeCvePostMitigationRetest(ctx, pipelineItemId, body = {}) {
      if (wafFeatureDisabled()) return featureDisabledResponse();
      const item = await cveRepo.getCvePipelineItem(ctx, pipelineItemId);
      if (!item) {
        return { error: 'cve_pipeline_item_not_found', status: 404 };
      }

      const matches = await cveRepo.listCveAssetMatches(ctx, item.id);
      if (matches.length === 0) {
        return {
          error: 'cve_asset_matches_required',
          status: 409,
          message: 'Run asset matching before post-mitigation retest.',
        };
      }

      const recommendations = await cveRepo.listWafRuleRecommendationsForPipelineItem(ctx, item.id);
      const deployedRecommendations = recommendations.filter((rec) => isCveRecommendationDeployed(rec));
      if (deployedRecommendations.length === 0) {
        return {
          error: 'cve_deployed_recommendations_required',
          status: 409,
          message: 'Mark at least one WAF recommendation deployed before post-mitigation retest.',
        };
      }

      const currentStage = item.stage ?? item.state ?? 'ingest';
      if (currentStage !== 'ticket' && currentStage !== 'retest') {
        return {
          error: 'invalid_cve_pipeline_stage',
          status: 409,
          message: `Post-mitigation retest requires ticket or retest stage; current stage is ${currentStage}.`,
        };
      }

      try {
        const now = nowFn().toISOString();
        const txResult = await withTenantContext(pool, ctx.tenantId, async (client) => {
          const validation_runs = [];
          const updated_matches = [];
          const updated_recommendations = [];
          const matchOutcomes = [];
          const validation_bindings = {
            ...(item.triage_summary_json?.validation_bindings ?? {}),
          };
          const txOptions = { client };
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
            const existingEvidence =
              validation_bindings[matchRecord.id] ?? formattedMatch.validation_evidence_json ?? null;
            const existingRun = matchRecord.last_waf_validation_run_id
              ? await wafRepo.getWafValidationRun(ctx, matchRecord.last_waf_validation_run_id, txOptions)
              : null;
            const hasPendingRetest =
              existingRun
              && existingRun.status !== 'finalized'
              && isRetestEvidenceBinding(existingEvidence);

            if (hasPendingRetest) {
              const outcome = deriveCveRetestOutcomeFromValidationRun(existingRun);
              matchOutcomes.push({ match_id: matchRecord.id, ...outcome });
              updated_matches.push(
                formatAssetMatch({
                  ...matchRecord,
                  validation_evidence_json: existingEvidence,
                }),
              );
              continue;
            }

            if (existingRun?.status === 'finalized' && isRetestEvidenceBinding(existingEvidence)) {
              const outcome = deriveCveRetestOutcomeFromValidationRun(existingRun);
              const evidence = {
                ...existingEvidence,
                validation_status: outcome.status,
                retest_verdict: outcome.verdict,
                finalized_at: existingRun.finalized_at ?? now,
              };
              validation_bindings[matchRecord.id] = evidence;
              const updated = await cveRepo.updateCveAssetMatch(ctx, matchRecord.id, {
                validation_status: outcome.status,
                updated_at: now,
              }, txOptions);
              matchOutcomes.push({ match_id: matchRecord.id, ...outcome });
              updated_matches.push(
                formatAssetMatch({
                  ...updated,
                  validation_evidence_json: evidence,
                }),
              );
              continue;
            }

            const checkId = resolveSafeCveValidationCheck(item, formattedMatch);
            if (!checkId) {
              const skipped = await cveRepo.updateCveAssetMatch(ctx, matchRecord.id, {
                validation_status: 'skipped',
                updated_at: now,
              }, txOptions);
              matchOutcomes.push({
                match_id: matchRecord.id,
                status: 'skipped',
                closure_ready: true,
                verdict: 'skipped',
              });
              updated_matches.push(formatAssetMatch(skipped));
              continue;
            }

            assertCvePostMitigationRetestAllowed(item, formattedMatch, recommendation, body);
            const asset = await wafRepo.getWafAsset(ctx, matchRecord.waf_asset_id, txOptions);
            if (!asset) {
              const err = new Error('WAF asset not found.');
              err.code = 'waf_asset_not_found';
              throw err;
            }

            const validationRequest = buildCvePostMitigationRetestRequest(
              item,
              formattedMatch,
              asset,
              recommendation,
            );
            const profile = normalizeWafValidationRequest(validationRequest);
            const runId = newIdFn('id');
            const evidence = buildCveRetestEvidenceBinding(
              item,
              formattedMatch,
              { id: runId },
              checkId,
              recommendation,
            );
            const validationRun = await wafRepo.createWafValidationRun(ctx, {
              id: runId,
              tenant_id: ctx.tenantId,
              waf_asset_id: profile.waf_asset_id,
              mode: profile.modes[0] ?? 'fingerprint',
              status: 'planned',
              safety_profile_json: {
                modes: profile.modes,
                probe_profile: profile.probe_profile,
                marker_profile: profile.marker_profile,
              },
              summary_json: {
                cve_validation_binding: evidence,
              },
              created_at: now,
            }, txOptions);
            validationRun.summary_json = {
              ...(validationRun.summary_json ?? {}),
              cve_validation_binding: evidence,
            };
            validationRun.cve_pipeline_item_id = item.id;
            validationRun.cve_asset_match_id = matchRecord.id;
            validationRun.check_id = checkId;
            validation_bindings[matchRecord.id] = evidence;

            const updated = await cveRepo.updateCveAssetMatch(ctx, matchRecord.id, {
              validation_status: 'retest_pending',
              last_waf_validation_run_id: validationRun.id,
              updated_at: now,
            }, txOptions);
            if (recommendation.approval_status !== 'retest_pending') {
              const updatedRecommendation = await cveRepo.updateWafRuleRecommendation(
                ctx,
                recommendation.id,
                { approval_status: 'retest_pending', updated_at: now },
                txOptions,
              );
              if (updatedRecommendation) {
                updated_recommendations.push(formatRecommendation(updatedRecommendation));
              }
            }

            validation_runs.push(validationRun);
            updated_matches.push(
              formatAssetMatch({
                ...updated,
                validation_evidence_json: evidence,
              }),
            );
            matchOutcomes.push({
              match_id: matchRecord.id,
              status: 'retest_pending',
              closure_ready: false,
              verdict: null,
            });

            await auditRepo.appendAuditEvent({
              tenant_id: ctx.tenantId,
              actor_user_id: ctx.userId,
              actor_role: ctx.role,
              action: 'waf.validation.started',
              resource_type: 'waf_validation_run',
              resource_id: validationRun.id,
              metadata: redactObject({
                waf_asset_id: profile.waf_asset_id,
                modes: profile.modes,
                retest_phase: 'post_mitigation',
              }),
            }, txOptions);

            await auditRepo.appendAuditEvent({
              tenant_id: ctx.tenantId,
              actor_user_id: ctx.userId,
              actor_role: ctx.role,
              action: 'cve.asset_match.retest_bound',
              resource_type: 'cve_asset_match',
              resource_id: matchRecord.id,
              metadata: redactObject({
                cve_id: item.cve_id,
                cve_pipeline_item_id: item.id,
                waf_asset_id: matchRecord.waf_asset_id,
                waf_validation_run_id: validationRun.id,
                waf_rule_recommendation_id: recommendation.id,
                check_id: checkId,
              }),
            }, txOptions);
          }

          if (matchOutcomes.length === 0) {
            const err = new Error('No deployed recommendations are linked to pipeline asset matches.');
            err.code = 'cve_deployed_recommendations_required';
            throw err;
          }

          const closure = resolveCvePipelineRetestClosure(matchOutcomes);
          let nextStage = currentStage;
          if (closure.ready) {
            nextStage = assertValidStageTransition(currentStage, 'resolved');
          } else if (currentStage === 'ticket') {
            nextStage = assertValidStageTransition(currentStage, 'retest');
          }

          const updatedItem = await cveRepo.updateCvePipelineItemStage(ctx, item.id, nextStage, {
            updated_at: now,
            validation_bindings,
          }, txOptions);

          await auditRepo.appendAuditEvent({
            tenant_id: ctx.tenantId,
            actor_user_id: ctx.userId,
            actor_role: ctx.role,
            action: closure.ready ? 'cve.pipeline_item.resolved' : 'cve.pipeline_item.retest_started',
            resource_type: 'cve_pipeline_item',
            resource_id: item.id,
            metadata: redactObject({
              cve_id: item.cve_id,
              validation_run_count: validation_runs.length,
              closure_ready: closure.ready,
              closure_verdict: closure.verdict,
              stage: nextStage,
            }),
          }, txOptions);

          return {
            validation_runs,
            updated_matches,
            updated_recommendations,
            validation_bindings,
            updatedItem,
            closure,
          };
        });

        return {
          item: formatPipelineItem(txResult.updatedItem),
          validation_runs: txResult.validation_runs,
          matches: attachValidationEvidence(txResult.updated_matches, txResult.validation_bindings),
          recommendations: deployedRecommendations.map((rec) => formatRecommendation(rec)),
          closure: txResult.closure,
          ...(txResult.updated_recommendations.length > 0
            ? { updated_recommendations: txResult.updated_recommendations }
            : {}),
        };
      } catch (err) {
        if (err?.code === 'waf_asset_not_found') {
          return { error: 'waf_asset_not_found', status: 404 };
        }
        if (err?.code === 'cve_deployed_recommendations_required') {
          return {
            error: 'cve_deployed_recommendations_required',
            status: 409,
            message: err.message,
          };
        }
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

    async getCveMitigationPlaybook(ctx, pipelineItemId) {
      if (wafFeatureDisabled()) return featureDisabledResponse();
      const item = await cveRepo.getCvePipelineItem(ctx, pipelineItemId);
      if (!item) {
        return { error: 'cve_pipeline_item_not_found', status: 404 };
      }

      try {
        const playbook = await buildOrRefreshPlaybook(ctx, item, cveRepo);
        await cveRepo.saveMitigationPlaybook(ctx, item.id, playbook);
        return { playbook: formatPlaybook(playbook) };
      } catch (err) {
        return contractError(err, err.code === 'cve_playbook_recommendations_required' ? 409 : 400);
      }
    },

    async approveCveMitigationPlaybook(ctx, pipelineItemId, body = {}) {
      if (wafFeatureDisabled()) return featureDisabledResponse();
      const item = await cveRepo.getCvePipelineItem(ctx, pipelineItemId);
      if (!item) {
        return { error: 'cve_pipeline_item_not_found', status: 404 };
      }

      try {
        const playbook = await buildOrRefreshPlaybook(ctx, item, cveRepo);
        assertCvePlaybookApprovable(playbook, item);
        const now = nowFn().toISOString();
        const parentId = newIdFn('id');
        const parentActionItem = await upsertPlaybookActionItem(
          actionRepo,
          ctx,
          buildPlaybookParentActionItem(playbook, item.id, parentId),
          now,
        );

        const childActionItems = [];
        const vendorSlices = [];
        for (const slice of playbook.vendor_slices) {
          const childId = newIdFn('id');
          const childActionItem = await upsertPlaybookActionItem(
            actionRepo,
            ctx,
            buildPlaybookChildActionItem(
              playbook,
              slice,
              item.id,
              childId,
              parentActionItem.action_item_id,
            ),
            now,
          );
          childActionItems.push(childActionItem);
          vendorSlices.push({
            ...slice,
            child_action_item_id: childActionItem.action_item_id,
          });
        }

        const approvedPlaybook = {
          ...playbook,
          status: 'approved',
          parent_action_item_id: parentActionItem.action_item_id,
          vendor_slices: vendorSlices,
          approved_at: now,
          approval_note: typeof body.note === 'string' ? body.note.trim() : null,
          updated_at: now,
        };

        let updatedItem = item;
        const currentStage = item.stage ?? item.state ?? 'ingest';
        if (currentStage === 'recommend') {
          const nextStage = assertValidStageTransition(currentStage, 'ticket');
          updatedItem = await cveRepo.updateCvePipelineItemStage(ctx, item.id, nextStage, {
            updated_at: now,
            mitigation_playbook: approvedPlaybook,
          });
        } else {
          await cveRepo.saveMitigationPlaybook(ctx, item.id, approvedPlaybook);
        }

        await auditRepo.appendAuditEvent({
          tenant_id: ctx.tenantId,
          actor_user_id: ctx.userId,
          actor_role: ctx.role,
          action: 'cve.playbook.approved',
          resource_type: 'cve_mitigation_playbook',
          resource_id: approvedPlaybook.playbook_id,
          metadata: redactObject({
            cve_id: item.cve_id,
            pipeline_item_id: item.id,
            parent_action_item_id: parentActionItem.action_item_id,
            child_action_item_count: childActionItems.length,
            vendor_slice_count: vendorSlices.length,
          }),
        });

        return {
          playbook: formatPlaybook(approvedPlaybook),
          parent_action_item: parentActionItem,
          child_action_items: childActionItems,
          item: formatPipelineItem(updatedItem),
        };
      } catch (err) {
        return contractError(err, err.code === 'cve_playbook_not_approvable' ? 409 : 400);
      }
    },

    async executeCoordinatedCveRetest(ctx, pipelineItemId, body = {}) {
      if (wafFeatureDisabled()) return featureDisabledResponse();
      const item = await cveRepo.getCvePipelineItem(ctx, pipelineItemId);
      if (!item) {
        return { error: 'cve_pipeline_item_not_found', status: 404 };
      }

      const playbook = readMitigationPlaybook(item);
      if (!playbook) {
        return {
          error: 'cve_playbook_not_found',
          status: 404,
          message: 'Approve a mitigation playbook before coordinated retest.',
        };
      }

      try {
        assertCvePlaybookCoordinatedRetestAllowed(playbook);
        const retestResult = await this.executeCvePostMitigationRetest(ctx, pipelineItemId, body);
        if (retestResult.error) {
          return retestResult;
        }

        const now = nowFn().toISOString();
        const nextStatus = resolvePlaybookStatusFromRetestClosure(
          retestResult.closure,
          playbook.status,
        );
        const updatedPlaybook = {
          ...playbook,
          status: nextStatus,
          updated_at: now,
        };
        await cveRepo.saveMitigationPlaybook(ctx, item.id, updatedPlaybook);

        if (retestResult.closure?.ready) {
          await auditRepo.appendAuditEvent({
            tenant_id: ctx.tenantId,
            actor_user_id: ctx.userId,
            actor_role: ctx.role,
            action: 'cve.playbook.resolved',
            resource_type: 'cve_mitigation_playbook',
            resource_id: updatedPlaybook.playbook_id,
            metadata: redactObject({
              cve_id: item.cve_id,
              pipeline_item_id: item.id,
              closure_verdict: retestResult.closure.verdict,
            }),
          });
        } else if (playbook.status === 'approved') {
          await auditRepo.appendAuditEvent({
            tenant_id: ctx.tenantId,
            actor_user_id: ctx.userId,
            actor_role: ctx.role,
            action: 'cve.playbook.retest_started',
            resource_type: 'cve_mitigation_playbook',
            resource_id: updatedPlaybook.playbook_id,
            metadata: redactObject({
              cve_id: item.cve_id,
              pipeline_item_id: item.id,
            }),
          });
        }

        return {
          ...retestResult,
          playbook: formatPlaybook(updatedPlaybook),
        };
      } catch (err) {
        return contractError(err, err.code === 'cve_playbook_not_approved' ? 409 : 400);
      }
    },
  };
}