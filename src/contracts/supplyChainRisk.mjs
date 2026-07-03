export const EXPOSURE_TYPES = Object.freeze([
  'dangling_cname',
  'deleted_cloud_app',
  'dangling_script_inclusion',
  'orphaned_redirect',
  'vendor_dependency_risk',
  'subdomain_takeover_risk',
]);

export const RISK_PHASES = Object.freeze([
  'AP0_detect_only',
  'AP1_ticket_workflow',
  'AP2_manual_custody',
  'AP3_governed_active',
]);

export const TICKET_WORKFLOW_PHASE = RISK_PHASES[1];

export function shouldAdvanceToTicketWorkflowPhase(phase) {
  const currentIndex = RISK_PHASES.indexOf(String(phase ?? '').trim());
  const ticketIndex = RISK_PHASES.indexOf(TICKET_WORKFLOW_PHASE);
  return currentIndex >= 0 && currentIndex < ticketIndex;
}

export const RISK_STATES = Object.freeze([
  'suspected',
  'confirmed',
  'remediation_pending',
  'resolved',
  'accepted_risk',
  'customer_custody',
]);

export const DATA_SOURCES = Object.freeze([
  'dns_cname_chain',
  'certificate_transparency',
  'http_metadata',
  'page_dependency_scan',
  'cloud_connectors',
  'customer_imports',
]);

export const RISK_SEVERITIES = Object.freeze([
  'critical',
  'high',
  'medium',
  'low',
]);

export const FORBIDDEN_RAW_RISK_KEYS = Object.freeze([
  'exploit_code',
  'page_body',
  'html_source',
  'raw_response',
  'cookies',
  'credentials',
  'tokens',
  'secrets',
  'dns_zone_file',
  'private_key',
]);

const FORBIDDEN_KEY_SET = new Set(
  FORBIDDEN_RAW_RISK_KEYS.map((k) => normalizeRiskKey(k)),
);

const EVIDENCE_SUMMARY_ALLOWLIST = new Set([
  'dns_chain_hash',
  'cname_chain_hash',
  'error_signature_id',
  'provider_error_signature_id',
  'dependency_url',
  'dependency_url_hash',
  'confidence',
  'connector_confirmation',
  'connector_confirms_missing',
  'claimable_provider_signature',
  'page_type',
  'subsidiary_acquisition',
  'script_host',
  'status_code',
  'content_type',
  'data_source',
]);

const ALLOWED_STATE_TRANSITIONS = Object.freeze({
  suspected: new Set(['suspected', 'confirmed', 'accepted_risk', 'resolved']),
  confirmed: new Set(['confirmed', 'remediation_pending', 'accepted_risk', 'customer_custody', 'suspected']),
  remediation_pending: new Set(['remediation_pending', 'resolved', 'confirmed', 'accepted_risk']),
  resolved: new Set(['resolved']),
  accepted_risk: new Set(['accepted_risk']),
  customer_custody: new Set(['customer_custody', 'resolved', 'remediation_pending']),
});

function normalizeRiskKey(key) {
  return String(key)
    .replace(/([a-z])([A-Z])/g, '$1_$2')
    .replace(/[^A-Za-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase();
}

function collectForbiddenRawKeys(value, path = '') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return [];
  }
  const findings = [];
  if (Array.isArray(value)) {
    value.forEach((entry, index) => {
      findings.push(...collectForbiddenRawKeys(entry, `${path}[${index}]`));
    });
    return findings;
  }
  for (const [key, nested] of Object.entries(value)) {
    const keyPath = path ? `${path}.${key}` : key;
    const normalized = normalizeRiskKey(key);
    if (FORBIDDEN_KEY_SET.has(normalized) || normalized.startsWith('raw_')) {
      findings.push(keyPath);
    }
    findings.push(...collectForbiddenRawKeys(nested, keyPath));
  }
  return findings;
}

export function validateRiskItem(item) {
  if (item === null || item === undefined || typeof item !== 'object' || Array.isArray(item)) {
    const err = new Error('Supply chain risk item must be a plain object.');
    err.code = 'invalid_supply_chain_risk';
    throw err;
  }
  const forbidden = collectForbiddenRawKeys(item);
  if (forbidden.length > 0) {
    const err = new Error(`Forbidden supply chain risk field at ${forbidden[0]}`);
    err.code = 'unsafe_supply_chain_evidence';
    err.forbidden_paths = forbidden;
    throw err;
  }
  return true;
}

function normalizeEvidenceSummary(input) {
  if (input === null || input === undefined || typeof input !== 'object' || Array.isArray(input)) {
    const err = new Error('Evidence summary must be a plain object.');
    err.code = 'invalid_supply_chain_evidence';
    throw err;
  }
  validateRiskItem(input);
  const summary = {};
  for (const [key, value] of Object.entries(input)) {
    const normalizedKey = normalizeRiskKey(key);
    if (!EVIDENCE_SUMMARY_ALLOWLIST.has(normalizedKey)) {
      const err = new Error(`Disallowed evidence summary field: ${key}`);
      err.code = 'invalid_supply_chain_evidence';
      throw err;
    }
    summary[normalizedKey] = value;
  }
  return summary;
}

function normalizeRemediationSteps(input) {
  if (!Array.isArray(input)) {
    const err = new Error('remediation_steps must be an array.');
    err.code = 'invalid_supply_chain_risk';
    throw err;
  }
  return input.map((step) => String(step).trim()).filter(Boolean);
}

export function scoreRiskSeverity(item) {
  validateRiskItem(item);
  const evidence = item.evidence_summary && typeof item.evidence_summary === 'object'
    ? item.evidence_summary
    : {};

  let severity = typeof item.severity === 'string' && RISK_SEVERITIES.includes(item.severity)
    ? item.severity
    : 'medium';
  let state = typeof item.state === 'string' && RISK_STATES.includes(item.state)
    ? item.state
    : 'suspected';
  let confidence = Number(item.confidence ?? evidence.confidence ?? 0);
  if (!Number.isFinite(confidence)) confidence = 0;
  confidence = Math.max(0, Math.min(1, confidence));

  const claimable = evidence.claimable_provider_signature === true
    || Boolean(
      (typeof evidence.provider_error_signature_id === 'string' && evidence.provider_error_signature_id.trim())
      || (typeof evidence.error_signature_id === 'string' && evidence.error_signature_id.trim()),
    );
  if (claimable) {
    severity = 'critical';
  }

  const pageType = String(evidence.page_type ?? item.page_type ?? '').trim().toLowerCase();
  if (pageType === 'payment' || pageType === 'login' || pageType === 'pii_page' || pageType === 'pii') {
    severity = 'critical';
  }

  if (evidence.subsidiary_acquisition === true || item.subsidiary_acquisition === true) {
    confidence = Math.min(confidence, 0.65);
  }

  if (evidence.connector_confirms_missing === true || evidence.connector_confirmation === true) {
    confidence = Math.min(1, confidence + 0.2);
  }

  const hasClaimabilityProof = claimable
    || evidence.connector_confirms_missing === true
    || evidence.connector_confirmation === true;
  if (!hasClaimabilityProof) {
    state = 'suspected';
  } else if (state === 'suspected' && confidence >= 0.7) {
    state = 'confirmed';
  }

  return { severity, state, confidence };
}

export function canTransitionRiskState(from, to) {
  const fromState = String(from ?? '').trim();
  const toState = String(to ?? '').trim();
  if (!RISK_STATES.includes(fromState) || !RISK_STATES.includes(toState)) {
    return false;
  }
  const allowed = ALLOWED_STATE_TRANSITIONS[fromState];
  return allowed ? allowed.has(toState) : false;
}

export function createSupplyChainRisk(fields) {
  if (fields === null || fields === undefined || typeof fields !== 'object' || Array.isArray(fields)) {
    const err = new Error('Supply chain risk input must be a plain object.');
    err.code = 'invalid_supply_chain_risk';
    throw err;
  }
  validateRiskItem(fields);

  const riskId = typeof fields.risk_id === 'string' ? fields.risk_id.trim() : '';
  if (!riskId) {
    const err = new Error('risk_id is required.');
    err.code = 'invalid_supply_chain_risk';
    throw err;
  }

  const exposureType = typeof fields.exposure_type === 'string' ? fields.exposure_type.trim() : '';
  if (!EXPOSURE_TYPES.includes(exposureType)) {
    const err = new Error(`exposure_type must be one of: ${EXPOSURE_TYPES.join(', ')}.`);
    err.code = 'invalid_supply_chain_risk';
    throw err;
  }

  const hostname = typeof fields.hostname === 'string' ? fields.hostname.trim() : '';
  if (!hostname) {
    const err = new Error('hostname is required.');
    err.code = 'invalid_supply_chain_risk';
    throw err;
  }

  const evidence_summary = normalizeEvidenceSummary(fields.evidence_summary ?? {});

  let confidence = Number(fields.confidence ?? evidence_summary.confidence ?? 0);
  if (!Number.isFinite(confidence) || confidence < 0 || confidence > 1) {
    const err = new Error('confidence must be a number between 0 and 1.');
    err.code = 'invalid_supply_chain_risk';
    throw err;
  }

  const remediation_steps = normalizeRemediationSteps(fields.remediation_steps ?? []);

  const draft = {
    risk_id: riskId,
    exposure_type: exposureType,
    hostname,
    evidence_summary,
    confidence,
    severity: typeof fields.severity === 'string' ? fields.severity.trim() : 'medium',
    state: typeof fields.state === 'string' ? fields.state.trim() : 'suspected',
    owner_hint: typeof fields.owner_hint === 'string' ? fields.owner_hint.trim() : '',
    remediation_steps,
  };

  const scored = scoreRiskSeverity(draft);
  draft.severity = scored.severity;
  draft.state = scored.state;
  draft.confidence = scored.confidence;
  evidence_summary.confidence = scored.confidence;
  draft.evidence_summary = evidence_summary;

  if (!RISK_SEVERITIES.includes(draft.severity)) {
    const err = new Error(`severity must be one of: ${RISK_SEVERITIES.join(', ')}.`);
    err.code = 'invalid_supply_chain_risk';
    throw err;
  }
  if (!RISK_STATES.includes(draft.state)) {
    const err = new Error(`state must be one of: ${RISK_STATES.join(', ')}.`);
    err.code = 'invalid_supply_chain_risk';
    throw err;
  }

  return draft;
}