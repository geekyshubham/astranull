import { RISK_PHASES } from './supplyChainRisk.mjs';

export const PHASE_AUTHORIZATION_TARGETS = Object.freeze({
  AP2_manual_custody: {
    from_phases: ['AP1_ticket_workflow'],
    allowed_risk_states: ['confirmed', 'remediation_pending', 'customer_custody'],
    required_fields: [
      'customer_approval_reference',
      'customer_signed_at',
      'custody_ids',
      'manual_workflow_owner',
    ],
    optional_fields: ['legal_review_reference', 'provider_terms_reference', 'notes'],
  },
  AP3_governed_active: {
    from_phases: ['AP2_manual_custody'],
    allowed_risk_states: ['customer_custody'],
    required_fields: [
      'customer_approval_reference',
      'legal_approval_reference',
      'legal_signed_at',
      'provider_terms_reference',
      'custody_ids',
      'insurance_review_reference',
      'release_back_workflow_reference',
    ],
    optional_fields: ['provider_path', 'notes'],
  },
});

const ISO_TIMESTAMP_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})$/;

function normalizeFieldKey(key) {
  return String(key)
    .replace(/([a-z])([A-Z])/g, '$1_$2')
    .replace(/[^A-Za-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase();
}

function isIsoTimestamp(value) {
  if (typeof value !== 'string' || !value.trim()) return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && ISO_TIMESTAMP_RE.test(value.trim());
}

function normalizeStringField(value) {
  if (value == null) return '';
  return String(value).trim();
}

function normalizeCustodyIds(value) {
  if (!Array.isArray(value)) return [];
  return value.map((entry) => String(entry).trim()).filter(Boolean);
}

export function canAdvanceSupplyChainPhase(currentPhase, targetPhase) {
  const current = String(currentPhase ?? '').trim();
  const target = String(targetPhase ?? '').trim();
  if (!RISK_PHASES.includes(current) || !RISK_PHASES.includes(target)) return false;
  const requirements = PHASE_AUTHORIZATION_TARGETS[target];
  if (!requirements) return false;
  return requirements.from_phases.includes(current);
}

export function normalizePhaseAuthorization(targetPhase, body = {}) {
  const phase = String(targetPhase ?? '').trim();
  const requirements = PHASE_AUTHORIZATION_TARGETS[phase];
  if (!requirements) {
    const err = new Error(`target_phase must be one of: ${Object.keys(PHASE_AUTHORIZATION_TARGETS).join(', ')}.`);
    err.code = 'invalid_supply_chain_phase_authorization';
    throw err;
  }
  if (body === null || body === undefined || typeof body !== 'object' || Array.isArray(body)) {
    const err = new Error('Phase authorization body must be a plain object.');
    err.code = 'invalid_supply_chain_phase_authorization';
    throw err;
  }

  const normalized = {};
  const allowed = new Set([
    ...requirements.required_fields,
    ...requirements.optional_fields,
  ]);

  for (const [key, value] of Object.entries(body)) {
    const field = normalizeFieldKey(key);
    if (!allowed.has(field)) {
      const err = new Error(`Disallowed phase authorization field: ${key}`);
      err.code = 'invalid_supply_chain_phase_authorization';
      throw err;
    }
    if (field === 'custody_ids') {
      normalized.custody_ids = normalizeCustodyIds(value);
      continue;
    }
    normalized[field] = normalizeStringField(value);
  }

  const missing = requirements.required_fields.filter((field) => {
    if (field === 'custody_ids') return normalized.custody_ids.length === 0;
    return !normalized[field];
  });
  if (missing.length > 0) {
    const err = new Error(`Missing required phase authorization fields: ${missing.join(', ')}.`);
    err.code = 'missing_phase_authorization_fields';
    err.missing_fields = missing;
    throw err;
  }

  for (const timestampField of ['customer_signed_at', 'legal_signed_at']) {
    if (normalized[timestampField] && !isIsoTimestamp(normalized[timestampField])) {
      const err = new Error(`${timestampField} must be an ISO-8601 timestamp.`);
      err.code = 'invalid_supply_chain_phase_authorization';
      throw err;
    }
  }

  return {
    target_phase: phase,
    authorization: normalized,
  };
}

export function validatePhaseAuthorizationGate({
  currentPhase,
  targetPhase,
  riskState,
}) {
  if (!canAdvanceSupplyChainPhase(currentPhase, targetPhase)) {
    const err = new Error(`Cannot advance from ${currentPhase} to ${targetPhase}.`);
    err.code = 'invalid_phase_transition';
    throw err;
  }
  const requirements = PHASE_AUTHORIZATION_TARGETS[targetPhase];
  const state = String(riskState ?? '').trim();
  if (!requirements.allowed_risk_states.includes(state)) {
    const err = new Error(
      `Risk state ${state} is not eligible for ${targetPhase}; allowed: ${requirements.allowed_risk_states.join(', ')}.`,
    );
    err.code = 'invalid_risk_state_for_phase';
    throw err;
  }
  return true;
}