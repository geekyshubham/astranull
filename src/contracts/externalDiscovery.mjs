export const ENTITY_TYPES = Object.freeze([
  'parent_organization',
  'subsidiary',
  'acquisition',
  'brand',
  'region',
  'region_business_unit',
  'vendor_managed_property',
]);

export const DISCOVERY_MODES = Object.freeze([
  'D0_declared_only',
  'D1_import_assisted',
  'D2_connector_assisted',
  'D3_entity_discovery',
  'D4_continuous_discovery',
]);

export const CANDIDATE_STATES = Object.freeze([
  'discovered',
  'candidate',
  'needs_review',
  'approved_target',
  'tested',
  'posture_tracked',
  'rejected',
  'exception',
]);

export const SOURCE_TYPES = Object.freeze([
  'dns',
  'ct_log',
  'connector',
  'customer_import',
  'registry',
  'page_link',
  'passive_dns',
]);

export const OWNERSHIP_STATUSES = Object.freeze([
  'unknown',
  'likely_owned',
  'confirmed_owned',
  'third_party',
  'rejected',
]);

export const APPROVAL_STATUSES = Object.freeze([
  'not_requested',
  'pending',
  'approved',
  'rejected',
  'exception',
]);

export const FORBIDDEN_CANDIDATE_FIELDS = Object.freeze([
  'raw_page_body',
  'html_content',
  'page_source',
  'cookies',
  'credentials',
  'tokens',
  'secrets',
  'pii_data',
]);

const FORBIDDEN_CANDIDATE_KEY_SET = new Set(
  FORBIDDEN_CANDIDATE_FIELDS.map((k) => normalizeFieldKey(k)),
);

const EVIDENCE_SUMMARY_ALLOWLIST = new Set([
  'source_kind',
  'dns_record_type',
  'cert_cn_hash',
  'cert_san_count',
  'redirect_count',
  'link_host_count',
  'connector_snapshot_id',
  'entity_ref_hash',
  'root_domain_match',
  'observed_status_code_class',
  'confidence_signals',
  'signal_count',
  'ownership_hint',
  'registry_ref_hash',
  'import_batch_id',
  'first_observed_at',
  'last_observed_at',
]);

const CONFIDENCE_SIGNAL_WEIGHTS = Object.freeze({
  customer_provided_target: 0.95,
  customer_provided: 0.95,
  connector_owned_asset: 0.85,
  connector_owned: 0.85,
  certificate_cn_san_under_root: 0.75,
  cert_cn_san_under_root: 0.75,
  dns_under_approved_root: 0.8,
  brand_name_active_web: 0.6,
  passive_dns_only: 0.4,
  third_party_script: 0.25,
  registrar_mismatch: -0.2,
});

const ALLOWED_TRANSITIONS = Object.freeze({
  discovered: new Set(['candidate', 'rejected']),
  candidate: new Set(['needs_review', 'approved_target', 'rejected', 'exception']),
  needs_review: new Set(['approved_target', 'rejected', 'exception']),
  approved_target: new Set(['tested']),
  tested: new Set(['posture_tracked']),
  posture_tracked: new Set(),
  rejected: new Set(),
  exception: new Set(),
});

const TESTABLE_CANDIDATE_STATES = new Set(['approved_target', 'tested', 'posture_tracked']);

function normalizeFieldKey(key) {
  return String(key)
    .replace(/([a-z])([A-Z])/g, '$1_$2')
    .replace(/[^A-Za-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase();
}

function contractError(message, code) {
  const err = new Error(message);
  err.code = code;
  return err;
}

function requirePlainObject(input, message, code) {
  if (input === null || input === undefined || typeof input !== 'object' || Array.isArray(input)) {
    throw contractError(message, code);
  }
}

function requireString(value, fieldName, code) {
  const trimmed = typeof value === 'string' ? value.trim() : '';
  if (!trimmed) {
    throw contractError(`${fieldName} is required.`, code);
  }
  return trimmed;
}

function requireConfidence(value, fieldName, code) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0 || n > 1) {
    throw contractError(`${fieldName} must be a number between 0 and 1.`, code);
  }
  return n;
}

function requireIsoTimestamp(value, fieldName, code) {
  const trimmed = requireString(value, fieldName, code);
  const parsed = Date.parse(trimmed);
  if (Number.isNaN(parsed)) {
    throw contractError(`${fieldName} must be a valid ISO timestamp.`, code);
  }
  return trimmed;
}

function collectForbiddenCandidateKeys(value, path = '') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return [];
  }
  const findings = [];
  if (Array.isArray(value)) {
    value.forEach((entry, index) => {
      findings.push(...collectForbiddenCandidateKeys(entry, `${path}[${index}]`));
    });
    return findings;
  }
  for (const [key, nested] of Object.entries(value)) {
    const keyPath = path ? `${path}.${key}` : key;
    const normalized = normalizeFieldKey(key);
    if (FORBIDDEN_CANDIDATE_KEY_SET.has(normalized) || normalized.startsWith('raw_')) {
      findings.push(keyPath);
    }
    findings.push(...collectForbiddenCandidateKeys(nested, keyPath));
  }
  return findings;
}

export function validateCandidate(candidate) {
  requirePlainObject(candidate, 'Candidate must be a plain object.', 'invalid_discovery_candidate');
  const forbidden = collectForbiddenCandidateKeys(candidate);
  if (forbidden.length > 0) {
    const err = contractError(`Forbidden candidate field at ${forbidden[0]}`, 'unsafe_discovery_candidate');
    err.forbidden_paths = forbidden;
    throw err;
  }
  return true;
}

function normalizeEvidenceSummary(input) {
  if (input === null || input === undefined) {
    return {};
  }
  requirePlainObject(input, 'evidence_summary must be a plain object.', 'invalid_discovery_candidate');
  validateCandidate({ evidence_summary: input });
  const summary = {};
  for (const [key, value] of Object.entries(input)) {
    const normalizedKey = normalizeFieldKey(key);
    if (!EVIDENCE_SUMMARY_ALLOWLIST.has(normalizedKey)) {
      throw contractError(`Disallowed evidence_summary field: ${key}`, 'invalid_discovery_candidate');
    }
    summary[normalizedKey] = value;
  }
  return summary;
}

export function createEntity(fields) {
  requirePlainObject(fields, 'Entity input must be a plain object.', 'invalid_discovery_entity');
  validateCandidate(fields);

  const entity_id = requireString(fields.entity_id, 'entity_id', 'invalid_discovery_entity');
  const entity_type = requireString(fields.entity_type, 'entity_type', 'invalid_discovery_entity');
  if (!ENTITY_TYPES.includes(entity_type)) {
    throw contractError(`entity_type must be one of: ${ENTITY_TYPES.join(', ')}.`, 'invalid_discovery_entity');
  }

  const name = requireString(fields.name, 'name', 'invalid_discovery_entity');
  const display_name = requireString(fields.display_name, 'display_name', 'invalid_discovery_entity');
  const country = requireString(fields.country, 'country', 'invalid_discovery_entity');
  const source = requireString(fields.source, 'source', 'invalid_discovery_entity');
  const confidence = requireConfidence(fields.confidence, 'confidence', 'invalid_discovery_entity');

  if (!Array.isArray(fields.root_domains) || fields.root_domains.length === 0) {
    throw contractError('root_domains must be a non-empty array.', 'invalid_discovery_entity');
  }
  const root_domains = fields.root_domains.map((d) => String(d).trim()).filter(Boolean);
  if (root_domains.length === 0) {
    throw contractError('root_domains must include at least one domain.', 'invalid_discovery_entity');
  }

  const entity = {
    entity_id,
    entity_type,
    name,
    display_name,
    root_domains,
    country,
    confidence,
    source,
  };

  if (fields.parent_entity_id !== undefined && fields.parent_entity_id !== null) {
    entity.parent_entity_id = requireString(
      fields.parent_entity_id,
      'parent_entity_id',
      'invalid_discovery_entity',
    );
  }

  return entity;
}

export function createCandidate(fields) {
  requirePlainObject(fields, 'Candidate input must be a plain object.', 'invalid_discovery_candidate');
  validateCandidate(fields);

  const candidate_id = requireString(fields.candidate_id, 'candidate_id', 'invalid_discovery_candidate');
  const hostname = requireString(fields.hostname, 'hostname', 'invalid_discovery_candidate');
  const source_type = requireString(fields.source_type, 'source_type', 'invalid_discovery_candidate');
  if (!SOURCE_TYPES.includes(source_type)) {
    throw contractError(
      `source_type must be one of: ${SOURCE_TYPES.join(', ')}.`,
      'invalid_discovery_candidate',
    );
  }

  const source_ref = requireString(fields.source_ref, 'source_ref', 'invalid_discovery_candidate');
  const confidence = requireConfidence(fields.confidence, 'confidence', 'invalid_discovery_candidate');
  const ownership_status = requireString(
    fields.ownership_status,
    'ownership_status',
    'invalid_discovery_candidate',
  );
  if (!OWNERSHIP_STATUSES.includes(ownership_status)) {
    throw contractError(
      `ownership_status must be one of: ${OWNERSHIP_STATUSES.join(', ')}.`,
      'invalid_discovery_candidate',
    );
  }

  const approval_status = requireString(
    fields.approval_status,
    'approval_status',
    'invalid_discovery_candidate',
  );
  if (!APPROVAL_STATUSES.includes(approval_status)) {
    throw contractError(
      `approval_status must be one of: ${APPROVAL_STATUSES.join(', ')}.`,
      'invalid_discovery_candidate',
    );
  }

  const first_seen_at = requireIsoTimestamp(fields.first_seen_at, 'first_seen_at', 'invalid_discovery_candidate');
  const last_seen_at = requireIsoTimestamp(fields.last_seen_at, 'last_seen_at', 'invalid_discovery_candidate');
  const evidence_summary = normalizeEvidenceSummary(fields.evidence_summary ?? {});

  const candidate = {
    candidate_id,
    hostname,
    source_type,
    source_ref,
    confidence,
    ownership_status,
    approval_status,
    first_seen_at,
    last_seen_at,
    evidence_summary,
  };

  if (fields.entity_id !== undefined && fields.entity_id !== null) {
    candidate.entity_id = requireString(fields.entity_id, 'entity_id', 'invalid_discovery_candidate');
  }

  if (fields.state !== undefined && fields.state !== null) {
    const state = requireString(fields.state, 'state', 'invalid_discovery_candidate');
    if (!CANDIDATE_STATES.includes(state)) {
      throw contractError(`state must be one of: ${CANDIDATE_STATES.join(', ')}.`, 'invalid_discovery_candidate');
    }
    candidate.state = state;
  }

  return candidate;
}

function normalizeSignalKey(signal) {
  return normalizeFieldKey(String(signal));
}

function collectActiveSignals(signals) {
  if (Array.isArray(signals)) {
    return signals.map((s) => normalizeSignalKey(s)).filter(Boolean);
  }
  if (signals && typeof signals === 'object') {
    return Object.entries(signals)
      .filter(([, value]) => value === true || (typeof value === 'number' && value > 0))
      .map(([key]) => normalizeSignalKey(key));
  }
  return [];
}

export function scoreConfidence(signals) {
  const active = collectActiveSignals(signals);
  if (active.length === 0) return 0;

  let positive = 0;
  let penalty = 0;
  for (const signal of active) {
    const weight = CONFIDENCE_SIGNAL_WEIGHTS[signal];
    if (weight === undefined) continue;
    if (weight < 0) {
      penalty += Math.abs(weight);
    } else {
      positive = Math.max(positive, weight);
    }
  }
  return Math.max(0, Math.min(1, Math.round((positive - penalty) * 1000) / 1000));
}

export function canTransition(fromState, toState) {
  const from = typeof fromState === 'string' ? fromState.trim() : '';
  const to = typeof toState === 'string' ? toState.trim() : '';
  if (!from || !to) return false;
  if (!CANDIDATE_STATES.includes(from) || !CANDIDATE_STATES.includes(to)) return false;
  if (from === to) return true;
  const allowed = ALLOWED_TRANSITIONS[from];
  return Boolean(allowed?.has(to));
}

export function isDeclaredOnlyDiscoveryMode(mode) {
  return String(mode ?? '').trim() === 'D0_declared_only';
}

export function isCandidateApprovedForTesting(candidate) {
  if (!candidate || typeof candidate !== 'object') return false;
  return TESTABLE_CANDIDATE_STATES.has(candidate.state);
}

export function canTransitionToTesting(fromState) {
  return canTransition(fromState, 'tested');
}

export function assertCandidateTestable(candidate) {
  if (!isCandidateApprovedForTesting(candidate)) {
    const err = contractError(
      'Candidate must be approved before testing or target group import.',
      'discovery_candidate_not_approved',
    );
    throw err;
  }
}

export const CONFIDENCE_HISTOGRAM_BUCKETS = Object.freeze([
  '0.0-0.2',
  '0.2-0.4',
  '0.4-0.6',
  '0.6-0.8',
  '0.8-1.0',
]);

export function confidenceHistogramBucket(confidence) {
  const n = Number(confidence);
  if (!Number.isFinite(n) || n < 0) {
    return CONFIDENCE_HISTOGRAM_BUCKETS[0];
  }
  if (n >= 1) {
    return CONFIDENCE_HISTOGRAM_BUCKETS[CONFIDENCE_HISTOGRAM_BUCKETS.length - 1];
  }
  const idx = Math.min(
    CONFIDENCE_HISTOGRAM_BUCKETS.length - 1,
    Math.floor(n * CONFIDENCE_HISTOGRAM_BUCKETS.length),
  );
  return CONFIDENCE_HISTOGRAM_BUCKETS[idx];
}

function emptySourceTypeCounts() {
  return Object.fromEntries(SOURCE_TYPES.map((sourceType) => [sourceType, 0]));
}

function emptyConfidenceHistogram() {
  return Object.fromEntries(CONFIDENCE_HISTOGRAM_BUCKETS.map((bucket) => [bucket, 0]));
}

function emptyApprovalStateCounts() {
  return Object.fromEntries(APPROVAL_STATUSES.map((status) => [status, 0]));
}

/**
 * Build metadata-only discovery report aggregates. Never includes hostnames,
 * source_ref, evidence_summary, or raw CT/DNS payloads.
 */
export function buildDiscoveryReportSummary(candidates, options = {}) {
  const generated_at =
    typeof options.generated_at === 'string' && options.generated_at.trim()
      ? options.generated_at.trim()
      : new Date().toISOString();
  const candidate_sources = emptySourceTypeCounts();
  const confidence_histogram = emptyConfidenceHistogram();
  const approval_states = emptyApprovalStateCounts();
  let total_candidates = 0;

  for (const candidate of candidates ?? []) {
    if (!candidate || typeof candidate !== 'object') continue;
    total_candidates += 1;

    const sourceType = String(candidate.source_type ?? '').trim();
    if (sourceType && Object.prototype.hasOwnProperty.call(candidate_sources, sourceType)) {
      candidate_sources[sourceType] += 1;
    }

    const bucket = confidenceHistogramBucket(candidate.confidence);
    confidence_histogram[bucket] += 1;

    const approvalStatus = String(candidate.approval_status ?? 'not_requested').trim();
    if (Object.prototype.hasOwnProperty.call(approval_states, approvalStatus)) {
      approval_states[approvalStatus] += 1;
    }
  }

  return {
    generated_at,
    total_candidates,
    candidate_sources,
    confidence_histogram,
    approval_states,
  };
}