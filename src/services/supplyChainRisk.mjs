import { audit } from '../audit.mjs';
import { loadRuntimeConfig } from '../config.mjs';
import {
  createSupplyChainRisk as buildSupplyChainRisk,
  validateRiskItem,
  scoreRiskSeverity,
  canTransitionRiskState,
  RISK_PHASES,
  TICKET_WORKFLOW_PHASE,
  shouldAdvanceToTicketWorkflowPhase,
} from '../contracts/supplyChainRisk.mjs';
import {
  normalizePhaseAuthorization,
  validatePhaseAuthorizationGate,
} from '../contracts/supplyChainPhaseAuthorization.mjs';
import { newId } from '../lib/ids.mjs';
import { parseSupplyChainSourceRecords } from '../lib/supplyChainSources.mjs';
import { getStore, persistStore } from '../store.mjs';

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

function ensureStoreShape() {
  const store = getStore();
  if (!Array.isArray(store.supplyChainRisks)) store.supplyChainRisks = [];
  if (!Array.isArray(store.supplyChainTickets)) store.supplyChainTickets = [];
  return store;
}

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

function findRiskById(ctx, id) {
  ensureStoreShape();
  return getStore().supplyChainRisks.find(
    (r) => r.id === id && r.tenant_id === ctx.tenantId,
  ) ?? null;
}

function findDedupedRisk(ctx, hostname, exposureType) {
  ensureStoreShape();
  return getStore().supplyChainRisks.find(
    (r) =>
      r.tenant_id === ctx.tenantId
      && r.hostname === hostname
      && r.exposure_type === exposureType,
  ) ?? null;
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
    phase_authorizations: record.phase_authorizations ?? [],
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

function defaultVendorDependencyRemediation(hostname, scriptHost) {
  const host = scriptHost || 'third-party vendor';
  return [
    `Review vendor-managed dependencies from ${host} on ${hostname}.`,
    'Confirm ownership and approval for third-party service inclusions.',
    'Retest dependency graph metadata after remediation.',
  ];
}

function buildRetestLink(risk) {
  return `/v1/waf/supply-chain/risks?risk_id=${encodeURIComponent(risk.id)}`;
}

export function listSupplyChainRisks(ctx) {
  const gate = wafFeatureGate();
  if (gate) return gate;
  ensureStoreShape();
  return getStore()
    .supplyChainRisks.filter((r) => r.tenant_id === ctx.tenantId)
    .map((r) => formatRisk(r));
}

export function getSupplyChainRisk(ctx, id) {
  const gate = wafFeatureGate();
  if (gate) return gate;
  ensureStoreShape();

  const record = findRiskById(ctx, id);
  if (!record) {
    return { error: 'supply_chain_risk_not_found', status: 404 };
  }
  return { risk: formatRisk(record) };
}

export function createSupplyChainRisk(ctx, body = {}) {
  const gate = wafFeatureGate();
  if (gate) return gate;
  ensureStoreShape();
  try {
    rejectProhibitedAcquisition(body);
    validateRiskItem(body);

    const normalized = buildSupplyChainRisk({
      risk_id: body.risk_id ?? newId('id'),
      exposure_type: body.exposure_type,
      hostname: body.hostname,
      evidence_summary: body.evidence_summary ?? {},
      confidence: body.confidence,
      severity: body.severity,
      state: body.state,
      owner_hint: body.owner_hint,
      remediation_steps: body.remediation_steps ?? [],
    });

    const existing = findDedupedRisk(ctx, normalized.hostname, normalized.exposure_type);
    if (existing) {
      return { risk: formatRisk(existing), deduplicated: true };
    }

    const now = new Date().toISOString();
    const record = {
      id: newId('id'),
      tenant_id: ctx.tenantId,
      phase: body.phase && RISK_PHASES.includes(body.phase) ? body.phase : DEFAULT_PHASE,
      phase_authorizations: [],
      ...normalized,
      created_at: now,
      updated_at: now,
    };
    getStore().supplyChainRisks.push(record);
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'supply_chain.risk.created',
      resource_type: 'supply_chain_risk',
      resource_id: record.id,
      metadata: {
        exposure_type: record.exposure_type,
        hostname: record.hostname,
        severity: record.severity,
        state: record.state,
      },
    });
    persistStore();
    return { risk: formatRisk(record), deduplicated: false };
  } catch (err) {
    return contractError(err);
  }
}

export function patchRiskState(ctx, id, state, body = {}) {
  const gate = wafFeatureGate();
  if (gate) return gate;
  ensureStoreShape();
  try {
    rejectProhibitedAcquisition(body);
    validateRiskItem(body);

    const record = findRiskById(ctx, id);
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
    record.state = nextState;
    record.updated_at = new Date().toISOString();
    if (typeof body.owner_hint === 'string' && body.owner_hint.trim()) {
      record.owner_hint = body.owner_hint.trim();
    }
    if (Array.isArray(body.remediation_steps) && body.remediation_steps.length > 0) {
      record.remediation_steps = body.remediation_steps.map((s) => String(s).trim()).filter(Boolean);
    }

    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'supply_chain.risk.state_changed',
      resource_type: 'supply_chain_risk',
      resource_id: record.id,
      metadata: {
        previous_state: previousState,
        state: nextState,
        hostname: record.hostname,
        exposure_type: record.exposure_type,
      },
    });
    persistStore();
    return { risk: formatRisk(record) };
  } catch (err) {
    return contractError(err);
  }
}

export function createRemediationTicket(ctx, riskId, body = {}) {
  const gate = wafFeatureGate();
  if (gate) return gate;
  ensureStoreShape();
  try {
    rejectProhibitedAcquisition(body);
    validateRiskItem(body);

    const risk = findRiskById(ctx, riskId);
    if (!risk) {
      return { error: 'supply_chain_risk_not_found', status: 404 };
    }

    const ticket = {
      id: newId('id'),
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
      phase: TICKET_WORKFLOW_PHASE,
      created_at: new Date().toISOString(),
    };

    validateRiskItem(ticket);
    getStore().supplyChainTickets.push({
      ...ticket,
      tenant_id: ctx.tenantId,
    });
    if (shouldAdvanceToTicketWorkflowPhase(risk.phase)) {
      risk.phase = TICKET_WORKFLOW_PHASE;
      risk.updated_at = ticket.created_at;
    }

    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'supply_chain.ticket.created',
      resource_type: 'supply_chain_ticket',
      resource_id: ticket.id,
      metadata: {
        supply_chain_risk_id: risk.id,
        hostname: risk.hostname,
        exposure_type: risk.exposure_type,
        severity: risk.severity,
      },
    });
    persistStore();
    return { ticket };
  } catch (err) {
    return contractError(err);
  }
}

export function assessDanglingCname(ctx, body = {}) {
  const gate = wafFeatureGate();
  if (gate) return gate;
  ensureStoreShape();
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

    const result = createSupplyChainRisk(ctx, {
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
}

function assessVendorDependency(ctx, body = {}) {
  const gate = wafFeatureGate();
  if (gate) return gate;
  ensureStoreShape();
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
    const connectorConfirmation = body.connector_confirmation === true;

    const evidence_summary = {
      ...(scriptHost ? { script_host: scriptHost } : {}),
      ...(dependencyUrlHash ? { dependency_url_hash: dependencyUrlHash } : {}),
      ...(Number.isFinite(statusCode) ? { status_code: statusCode } : {}),
      ...(contentType ? { content_type: contentType } : {}),
      ...(connectorConfirmation ? { connector_confirmation: true } : {}),
      data_source: 'customer_imports',
      ...(typeof body.page_type === 'string' && body.page_type.trim()
        ? { page_type: body.page_type.trim() }
        : {}),
      ...(body.claimable_provider_signature === true ? { claimable_provider_signature: true } : {}),
    };

    let baseConfidence = 0.45;
    if (statusCode === 404 || statusCode === 410) baseConfidence = 0.7;
    if (dependencyUrlHash) baseConfidence = Math.min(1, baseConfidence + 0.1);
    if (connectorConfirmation) baseConfidence = Math.min(1, baseConfidence + 0.15);

    const scored = scoreRiskSeverity({
      exposure_type: 'vendor_dependency_risk',
      hostname,
      evidence_summary,
      confidence: body.confidence ?? baseConfidence,
      state: 'suspected',
      severity: 'medium',
      remediation_steps: defaultVendorDependencyRemediation(hostname, scriptHost),
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

    const result = createSupplyChainRisk(ctx, {
      exposure_type: 'vendor_dependency_risk',
      hostname,
      evidence_summary: {
        ...evidence_summary,
        confidence: scored.confidence,
      },
      confidence: scored.confidence,
      severity: scored.severity,
      state: scored.state,
      owner_hint: typeof body.owner_hint === 'string' ? body.owner_hint : '',
      remediation_steps: defaultVendorDependencyRemediation(hostname, scriptHost),
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
}

export function assessDanglingDependency(ctx, body = {}) {
  const gate = wafFeatureGate();
  if (gate) return gate;
  ensureStoreShape();
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

    const result = createSupplyChainRisk(ctx, {
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
}

export function getPhaseAuthorizations(ctx, riskId) {
  const gate = wafFeatureGate();
  if (gate) return gate;
  ensureStoreShape();

  const record = findRiskById(ctx, riskId);
  if (!record) {
    return { error: 'supply_chain_risk_not_found', status: 404 };
  }

  return {
    risk_id: record.id,
    phase: record.phase,
    phase_authorizations: record.phase_authorizations ?? [],
  };
}

export function submitPhaseAuthorization(ctx, riskId, body = {}) {
  const gate = wafFeatureGate();
  if (gate) return gate;
  ensureStoreShape();
  try {
    rejectProhibitedAcquisition(body);
    validateRiskItem(body);

    const record = findRiskById(ctx, riskId);
    if (!record) {
      return { error: 'supply_chain_risk_not_found', status: 404 };
    }

    const targetPhase = typeof body.target_phase === 'string' ? body.target_phase.trim() : '';
    const { target_phase: _ignored, authorization: nestedAuthorization, ...authorizationFields } = body;
    const { target_phase: normalizedPhase, authorization } = normalizePhaseAuthorization(
      targetPhase,
      nestedAuthorization ?? authorizationFields,
    );
    validatePhaseAuthorizationGate({
      currentPhase: record.phase,
      targetPhase: normalizedPhase,
      riskState: record.state,
    });

    const now = new Date().toISOString();
    const entry = {
      id: newId('id'),
      target_phase: normalizedPhase,
      authorization,
      approved_by_user_id: ctx.userId,
      approved_by_role: ctx.role,
      approved_at: now,
    };

    if (!Array.isArray(record.phase_authorizations)) record.phase_authorizations = [];
    record.phase_authorizations.push(entry);
    record.phase = normalizedPhase;
    record.updated_at = now;
    if (normalizedPhase === 'AP2_manual_custody') {
      record.state = 'customer_custody';
      if (authorization.manual_workflow_owner) {
        record.owner_hint = authorization.manual_workflow_owner;
      }
    }

    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'supply_chain.phase_authorized',
      resource_type: 'supply_chain_risk',
      resource_id: record.id,
      metadata: {
        target_phase: normalizedPhase,
        hostname: record.hostname,
        exposure_type: record.exposure_type,
        custody_ids: authorization.custody_ids,
      },
    });
    persistStore();

    return {
      risk: formatRisk(record),
      authorization: entry,
    };
  } catch (err) {
    return contractError(err);
  }
}

export function ingestSupplyChainSignals(ctx, source, records) {
  const gate = wafFeatureGate();
  if (gate) return gate;
  ensureStoreShape();
  try {
    const parsedRecords = parseSupplyChainSourceRecords(source, records);
    let assessed = 0;
    let created = 0;
    let deduplicated = 0;
    let skippedBelowThreshold = 0;
    const results = [];

    for (const parsed of parsedRecords) {
      const assessment = parsed.source === 'dangling_cname'
        ? assessDanglingCname(ctx, parsed.assess_body)
        : assessVendorDependency(ctx, parsed.assess_body);
      if (assessment.error) return assessment;

      assessed += 1;
      if (assessment.created) created += 1;
      if (assessment.deduplicated) deduplicated += 1;
      if (assessment.reason === 'below_confidence_threshold') skippedBelowThreshold += 1;

      results.push({
        source_ref: parsed.source_ref,
        hostname: parsed.hostname,
        exposure_type: parsed.exposure_type,
        assessed: assessment.assessed,
        created: assessment.created,
        deduplicated: Boolean(assessment.deduplicated),
        ...(assessment.reason ? { reason: assessment.reason } : {}),
        ...(assessment.risk ? { risk: assessment.risk } : {}),
      });
    }

    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'supply_chain.source_ingested',
      resource_type: 'supply_chain_source_batch',
      resource_id: String(source),
      metadata: {
        source,
        record_count: parsedRecords.length,
        assessed_count: assessed,
        created_count: created,
        deduplicated_count: deduplicated,
        skipped_below_threshold_count: skippedBelowThreshold,
      },
    });
    persistStore();

    return {
      source,
      ingested: parsedRecords.length,
      assessed,
      created,
      deduplicated,
      skipped_below_threshold: skippedBelowThreshold,
      results,
    };
  } catch (err) {
    return contractError(err);
  }
}