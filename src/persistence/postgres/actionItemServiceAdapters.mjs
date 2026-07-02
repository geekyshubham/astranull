import {
  ACTION_ITEM_STATUSES,
  assertNoRawWafEvidence,
  buildSiemEventPayload,
  createActionItem,
  extractFindingRemediationContext,
  REMEDIATION_CONNECTOR_TYPES,
  validateActionItem,
} from '../../contracts/wafPosture.mjs';
import { newId } from '../../lib/ids.mjs';
import { redactObject } from '../../lib/redact.mjs';
import { createActionItemRepository } from './actionItemRepository.mjs';
import { createAuditRepository } from './auditRepository.mjs';
import { createWafPostureRepository } from './wafPostureRepository.mjs';

function contractError(err, fallbackStatus = 400) {
  return {
    error: err.code ?? 'invalid_request',
    status: fallbackStatus,
    message: err.message,
  };
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
    action_item_id: record.action_item_id ?? record.id,
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

function severityToJiraPriority(severity) {
  const map = { critical: 'Highest', high: 'High', medium: 'Medium', low: 'Low' };
  return map[String(severity ?? '').toLowerCase()] ?? 'Medium';
}

function severityToServiceNowUrgency(severity) {
  const map = { critical: '1', high: '2', medium: '3', low: '4' };
  return map[String(severity ?? '').toLowerCase()] ?? '3';
}

/**
 * @param {import('pg').Pool} pool
 * @param {{
 *   now?: () => Date,
 *   newId?: typeof newId,
 * }} [options]
 */
export function createPostgresActionItemServices(pool, options = {}) {
  const actionRepo = createActionItemRepository(pool);
  const wafRepo = createWafPostureRepository(pool);
  const auditRepo = createAuditRepository(pool);
  const nowFn = options.now ?? (() => new Date());
  const newIdFn = options.newId ?? newId;

  return {
    async listActionItems(ctx) {
      const items = await actionRepo.listActionItems(ctx);
      return items.map((item) => formatActionItem(item));
    },

    async createActionItemFromFinding(ctx, finding, opts = {}) {
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

        const asset = await wafRepo.getWafAsset(ctx, wafAssetId);
        const assetDisplay = asset?.canonical_url ?? `asset:${wafAssetId}`;
        const owner = remediationCtx.owner ?? asset?.owner_hint ?? 'security-operations';
        const reasonCodes = remediationCtx.reason_codes;
        const primaryReason = remediationCtx.primary_reason;
        const dedupeKey = actionItemDedupeKey(wafAssetId, primaryReason);
        const now = nowFn().toISOString();

        const evidenceSummary = typeof opts.evidence_summary === 'string' && opts.evidence_summary.trim()
          ? opts.evidence_summary.trim()
          : `WAF posture finding ${finding.id} for ${assetDisplay}. Reason codes: ${reasonCodes.join(', ') || 'unknown'}.`;

        const fields = {
          action_item_id: newIdFn('id'),
          tenant_id: ctx.tenantId,
          category: opts.category ?? actionItemCategoryForReasonCodes(reasonCodes),
          title: opts.title ?? finding.title ?? `WAF remediation: ${assetDisplay}`,
          asset: {
            id: wafAssetId,
            display: assetDisplay,
            ...(asset?.owner_hint ? { owner_hint: asset.owner_hint } : {}),
            ...(asset?.business_criticality ? { business_criticality: asset.business_criticality } : {}),
          },
          asset_display: assetDisplay,
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
          primary_reason: primaryReason,
        };

        const existing = await actionRepo.findOpenActionItemByDedupe(ctx, assetDisplay, primaryReason);
        if (existing) {
          const mergedFindingIds = [...new Set([...(existing.finding_ids ?? []), finding.id])];
          const updated = await actionRepo.insertActionItem(ctx, {
            ...existing,
            title: fields.title,
            severity: fields.severity,
            owner: fields.owner,
            evidence: fields.evidence,
            recommended_solution: fields.recommended_solution,
            retest_url: fields.retest_url,
            finding_ids: mergedFindingIds,
            updated_at: now,
          });
          await auditRepo.appendAuditEvent({
            tenant_id: ctx.tenantId,
            actor_user_id: ctx.userId,
            actor_role: ctx.role,
            action: 'waf.action_item.updated',
            resource_type: 'waf_action_item',
            resource_id: updated.action_item_id,
            metadata: redactObject({
              finding_id: finding.id,
              dedupe_key: dedupeKey,
              reason_codes: reasonCodes,
            }),
          });
          return { action_item: formatActionItem(updated), created: false };
        }

        const normalized = createActionItem(fields);
        const record = await actionRepo.insertActionItem(ctx, {
          ...normalized,
          tenant_id: ctx.tenantId,
          dedupe_key: dedupeKey,
          primary_reason: primaryReason,
          asset_display: assetDisplay,
          created_at: now,
          updated_at: now,
        });
        await auditRepo.appendAuditEvent({
          tenant_id: ctx.tenantId,
          actor_user_id: ctx.userId,
          actor_role: ctx.role,
          action: 'waf.action_item.created',
          resource_type: 'waf_action_item',
          resource_id: record.action_item_id,
          metadata: redactObject({
            finding_id: finding.id,
            dedupe_key: dedupeKey,
            category: record.category,
            reason_codes: reasonCodes,
          }),
        });
        return { action_item: formatActionItem(record), created: true };
      } catch (err) {
        return contractError(err);
      }
    },

    async patchActionItemStatus(ctx, id, body = {}) {
      try {
        assertNoRawWafEvidence(body);
      } catch (err) {
        return contractError(err);
      }

      const record = await actionRepo.getActionItem(ctx, id);
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
      const now = nowFn().toISOString();
      const patched = await actionRepo.updateActionItemStatus(ctx, id, nextStatus, {
        updated_at: now,
      });
      await auditRepo.appendAuditEvent({
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId,
        actor_role: ctx.role,
        action: 'waf.action_item.updated',
        resource_type: 'waf_action_item',
        resource_id: record.action_item_id,
        metadata: redactObject({
          previous_status: previousStatus,
          status: nextStatus,
          ...(typeof body.notes === 'string' && body.notes.trim() ? { notes: body.notes.trim() } : {}),
        }),
      });
      return { action_item: formatActionItem(patched) };
    },

    buildRemediationPayload(actionItem, connectorType) {
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
    },
  };
}