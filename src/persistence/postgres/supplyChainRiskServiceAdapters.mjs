import { loadRuntimeConfig } from '../../config.mjs';
import {
  createSupplyChainRisk as buildSupplyChainRisk,
  validateRiskItem,
  scoreRiskSeverity,
  canTransitionRiskState,
  RISK_PHASES,
} from '../../contracts/supplyChainRisk.mjs';
import { newId } from '../../lib/ids.mjs';
import { redactObject } from '../../lib/redact.mjs';
import { createAuditRepository } from './auditRepository.mjs';
import { createSupplyChainRiskRepository } from './supplyChainRiskRepository.mjs';

const CONFIDENCE_THRESHOLD = 0.5;
const DEFAULT_PHASE = RISK_PHASES[0];

const PROHIBITED_ACQUISITION_FIELDS = new Set([
  'acquire',
  'acquire_resource',
  'claim',
  'claim_resource',
  'auto_claim',
  'dns_modify',
  'modify_dns',
  'create_account',
  'create_resource',
  'register_domain',
]);

function contractError(err, fallbackStatus = 400) {
  return {
    error: err.code ?? 'invalid_request',
    status: fallbackStatus,
    message: err.message,
  };
}

function wafFeatureGate() {
  const enabled = loadRuntimeConfig().featureFlags.wafPostureEnabled === true;
  if (!enabled) return { error: 'waf_feature_disabled' };
  return null;
}

function rejectProhibitedAcquisition(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return null;
  for (const key of Object.keys(body)) {
    const normalized = String(key).replace(/([a-z])([A-Z])/g, '$1_$2').toLowerCase();
    if (PROHIBITED_ACQUISITION_FIELDS.has(normalized)) {
      const err = new Error(`Field ${key} is not permitted; automated acquisition is disabled.`);
      err.code = 'prohibited_acquisition';
      throw err;
    }
  }
  return null;
}

function formatRisk(record) {
  return {
    id: record.id,
    risk_id: record.risk_id,
    exposure_type: record.exposure_type,
    hostname: record.hostname,
    evidence_summary: record.evidence_summary ?? {},
    confidence: record.confidence,
    severity: record.severity,
    state: record.state,
    phase: record.phase,
    owner_hint: record.owner_hint ?? '',
    remediation_steps: record.remediation_steps ?? [],
    created_at: record.created_at,
    ...(record.updated_at ? { updated_at: record.updated_at } : {}),
  };
}

function defaultCnameRemediation(hostname) {
  return [
    `Review DNS CNAME records for ${hostname}.`,
    'Remove or repoint dangling CNAME targets to owned resources.',
    'Retest DNS resolution and provider error signatures after cleanup.',
  ];
}

function defaultDependencyRemediation(hostname, scriptHost) {
  const host = scriptHost || 'third-party host';
  return [
    `Review page dependencies loading from ${host} on ${hostname}.`,
    'Remove or replace missing third-party script inclusions.',
    'Retest page dependency scan metadata after cleanup.',
  ];
}

function buildRetestLink(risk) {
  return `/v1/supply-chain/risks/${risk.id}/retest`;
}

/**
 * @param {import('pg').Pool} pool
 * @param {{
 *   now?: () => Date,
 *   newId?: typeof newId,
 * }} [options]
 */
export function createPostgresSupplyChainRiskServices(pool, options = {}) {
  const riskRepo = createSupplyChainRiskRepository(pool);
  const auditRepo = createAuditRepository(pool);
  const nowFn = options.now ?? (() => new Date());
  const newIdFn = options.newId ?? newId;

  return {
    async listSupplyChainRisks(ctx) {
      const gate = wafFeatureGate();
      if (gate) return gate;
      const items = await riskRepo.listRisks(ctx);
      return items.map((entry) => formatRisk(entry));
    },

    async createSupplyChainRisk(ctx, body = {}) {
      const gate = wafFeatureGate();
      if (gate) return gate;
      try {
        rejectProhibitedAcquisition(body);
        validateRiskItem(body);

        const normalized = buildSupplyChainRisk({
          risk_id: body.risk_id ?? newIdFn('id'),
          exposure_type: body.exposure_type,
          hostname: body.hostname,
          evidence_summary: body.evidence_summary ?? {},
          confidence: body.confidence,
          severity: body.severity,
          state: body.state,
          owner_hint: body.owner_hint,
          remediation_steps: body.remediation_steps ?? [],
        });

        const existing = await riskRepo.findRiskByHostnameAndExposure(
          ctx,
          normalized.hostname,
          normalized.exposure_type,
        );
        if (existing) {
          return { risk: formatRisk(existing), deduplicated: true };
        }

        const now = nowFn().toISOString();
        const record = await riskRepo.insertRisk(ctx, {
          id: newIdFn('id'),
          tenant_id: ctx.tenantId,
          phase: body.phase && RISK_PHASES.includes(body.phase) ? body.phase : DEFAULT_PHASE,
          ...normalized,
          created_at: now,
          updated_at: now,
        });
        await auditRepo.appendAuditEvent({
          tenant_id: ctx.tenantId,
          actor_user_id: ctx.userId,
          actor_role: ctx.role,
          action: 'supply_chain.risk.created',
          resource_type: 'supply_chain_risk',
          resource_id: record.id,
          metadata: redactObject({
            exposure_type: record.exposure_type,
            hostname: record.hostname,
            severity: record.severity,
            state: record.state,
          }),
        });
        return { risk: formatRisk(record), deduplicated: false };
      } catch (err) {
        return contractError(err);
      }
    },

    async patchRiskState(ctx, id, state, body = {}) {
      const gate = wafFeatureGate();
      if (gate) return gate;
      try {
        rejectProhibitedAcquisition(body);
        validateRiskItem(body);

        const record = await riskRepo.getRisk(ctx, id);
        if (!record) {
          return { error: 'supply_chain_risk_not_found', status: 404 };
        }

        const nextState = typeof state === 'string' ? state.trim() : '';
        if (!nextState) {
          return { error: 'invalid_request', status: 400, message: 'state is required.' };
        }
        if (!canTransitionRiskState(record.state, nextState)) {
          return {
            error: 'invalid_state_transition',
            status: 400,
            message: `Cannot transition from ${record.state} to ${nextState}.`,
          };
        }

        const previousState = record.state;
        const now = nowFn().toISOString();
        const updates = { updated_at: now };
        if (typeof body.owner_hint === 'string' && body.owner_hint.trim()) {
          updates.owner_hint = body.owner_hint.trim();
        }
        if (Array.isArray(body.remediation_steps) && body.remediation_steps.length > 0) {
          updates.remediation_steps = body.remediation_steps.map((s) => String(s).trim()).filter(Boolean);
        }
        const updated = await riskRepo.updateRiskState(ctx, id, nextState, updates);

        await auditRepo.appendAuditEvent({
          tenant_id: ctx.tenantId,
          actor_user_id: ctx.userId,
          actor_role: ctx.role,
          action: 'supply_chain.risk.state_changed',
          resource_type: 'supply_chain_risk',
          resource_id: record.id,
          metadata: redactObject({
            previous_state: previousState,
            state: nextState,
            hostname: record.hostname,
            exposure_type: record.exposure_type,
          }),
        });
        return { risk: formatRisk(updated) };
      } catch (err) {
        return contractError(err);
      }
    },

    async createRemediationTicket(ctx, riskId, body = {}) {
      const gate = wafFeatureGate();
      if (gate) return gate;
      try {
        rejectProhibitedAcquisition(body);
        validateRiskItem(body);

        const risk = await riskRepo.getRisk(ctx, riskId);
        if (!risk) {
          return { error: 'supply_chain_risk_not_found', status: 404 };
        }

        const ticket = {
          id: newIdFn('id'),
          risk_id: risk.id,
          title: `Supply chain risk (${risk.exposure_type}): ${risk.hostname}`,
          severity: risk.severity,
          hostname: risk.hostname,
          evidence_summary: { ...risk.evidence_summary },
          remediation_steps: [...(risk.remediation_steps ?? [])],
          retest_link: buildRetestLink(risk),
          owner_hint: typeof body.owner_hint === 'string' && body.owner_hint.trim()
            ? body.owner_hint.trim()
            : (risk.owner_hint ?? ''),
          phase: RISK_PHASES[1],
          created_at: nowFn().toISOString(),
        };

        validateRiskItem(ticket);
        await auditRepo.appendAuditEvent({
          tenant_id: ctx.tenantId,
          actor_user_id: ctx.userId,
          actor_role: ctx.role,
          action: 'supply_chain.ticket.created',
          resource_type: 'supply_chain_ticket',
          resource_id: ticket.id,
          metadata: redactObject({
            supply_chain_risk_id: risk.id,
            hostname: risk.hostname,
            exposure_type: risk.exposure_type,
            severity: risk.severity,
          }),
        });
        return { ticket };
      } catch (err) {
        return contractError(err);
      }
    },

    async assessDanglingCname(ctx, body = {}) {
      const gate = wafFeatureGate();
      if (gate) return gate;
      try {
        rejectProhibitedAcquisition(body);
        validateRiskItem(body);

        const hostname = typeof body.hostname === 'string' ? body.hostname.trim() : '';
        if (!hostname) {
          return { error: 'invalid_request', status: 400, message: 'hostname is required.' };
        }

        const cnameChainHash = typeof body.cname_chain_hash === 'string' ? body.cname_chain_hash.trim() : '';
        const providerErrorSignatureId = typeof body.provider_error_signature_id === 'string'
          ? body.provider_error_signature_id.trim()
          : '';
        const connectorConfirmation = body.connector_confirmation === true;

        const evidence_summary = {
          ...(cnameChainHash ? { cname_chain_hash: cnameChainHash } : {}),
          ...(providerErrorSignatureId ? { provider_error_signature_id: providerErrorSignatureId } : {}),
          ...(connectorConfirmation ? { connector_confirmation: true } : {}),
          data_source: 'dns_cname_chain',
          ...(body.subsidiary_acquisition === true ? { subsidiary_acquisition: true } : {}),
          ...(body.claimable_provider_signature === true ? { claimable_provider_signature: true } : {}),
          ...(typeof body.page_type === 'string' && body.page_type.trim()
            ? { page_type: body.page_type.trim() }
            : {}),
        };

        const scored = scoreRiskSeverity({
          exposure_type: 'dangling_cname',
          hostname,
          evidence_summary,
          confidence: body.confidence ?? (connectorConfirmation ? 0.75 : providerErrorSignatureId ? 0.7 : 0.4),
          state: 'suspected',
          severity: 'medium',
          remediation_steps: defaultCnameRemediation(hostname),
          owner_hint: typeof body.owner_hint === 'string' ? body.owner_hint : '',
          risk_id: 'pending',
        });

        if (scored.confidence < CONFIDENCE_THRESHOLD) {
          return {
            assessed: true,
            created: false,
            reason: 'below_confidence_threshold',
            scoring: scored,
          };
        }

        const result = await this.createSupplyChainRisk(ctx, {
          exposure_type: 'dangling_cname',
          hostname,
          evidence_summary: {
            ...evidence_summary,
            confidence: scored.confidence,
          },
          confidence: scored.confidence,
          severity: scored.severity,
          state: scored.state,
          owner_hint: typeof body.owner_hint === 'string' ? body.owner_hint : '',
          remediation_steps: defaultCnameRemediation(hostname),
          phase: DEFAULT_PHASE,
        });
        if (result.error) return result;
        return {
          assessed: true,
          created: !result.deduplicated,
          deduplicated: Boolean(result.deduplicated),
          risk: result.risk,
          scoring: scored,
        };
      } catch (err) {
        return contractError(err);
      }
    },

    async assessDanglingDependency(ctx, body = {}) {
      const gate = wafFeatureGate();
      if (gate) return gate;
      try {
        rejectProhibitedAcquisition(body);
        validateRiskItem(body);

        const hostname = typeof body.hostname === 'string' ? body.hostname.trim() : '';
        if (!hostname) {
          return { error: 'invalid_request', status: 400, message: 'hostname is required.' };
        }

        const scriptHost = typeof body.script_host === 'string' ? body.script_host.trim() : '';
        const dependencyUrlHash = typeof body.dependency_url_hash === 'string'
          ? body.dependency_url_hash.trim()
          : '';
        const statusCode = body.status_code !== undefined ? Number(body.status_code) : null;
        const contentType = typeof body.content_type === 'string' ? body.content_type.trim() : '';

        const evidence_summary = {
          ...(scriptHost ? { script_host: scriptHost } : {}),
          ...(dependencyUrlHash ? { dependency_url_hash: dependencyUrlHash } : {}),
          ...(Number.isFinite(statusCode) ? { status_code: statusCode } : {}),
          ...(contentType ? { content_type: contentType } : {}),
          data_source: 'page_dependency_scan',
          ...(typeof body.page_type === 'string' && body.page_type.trim()
            ? { page_type: body.page_type.trim() }
            : {}),
          ...(body.claimable_provider_signature === true ? { claimable_provider_signature: true } : {}),
        };

        let baseConfidence = 0.45;
        if (statusCode === 404 || statusCode === 410) baseConfidence = 0.7;
        if (dependencyUrlHash) baseConfidence = Math.min(1, baseConfidence + 0.1);

        const scored = scoreRiskSeverity({
          exposure_type: 'dangling_script_inclusion',
          hostname,
          evidence_summary,
          confidence: body.confidence ?? baseConfidence,
          state: 'suspected',
          severity: 'medium',
          remediation_steps: defaultDependencyRemediation(hostname, scriptHost),
          owner_hint: typeof body.owner_hint === 'string' ? body.owner_hint : '',
          risk_id: 'pending',
        });

        if (scored.confidence < CONFIDENCE_THRESHOLD) {
          return {
            assessed: true,
            created: false,
            reason: 'below_confidence_threshold',
            scoring: scored,
          };
        }

        const result = await this.createSupplyChainRisk(ctx, {
          exposure_type: 'dangling_script_inclusion',
          hostname,
          evidence_summary: {
            ...evidence_summary,
            confidence: scored.confidence,
          },
          confidence: scored.confidence,
          severity: scored.severity,
          state: scored.state,
          owner_hint: typeof body.owner_hint === 'string' ? body.owner_hint : '',
          remediation_steps: defaultDependencyRemediation(hostname, scriptHost),
          phase: DEFAULT_PHASE,
        });
        if (result.error) return result;
        return {
          assessed: true,
          created: !result.deduplicated,
          deduplicated: Boolean(result.deduplicated),
          risk: result.risk,
          scoring: scored,
        };
      } catch (err) {
        return contractError(err);
      }
    },
  };
}