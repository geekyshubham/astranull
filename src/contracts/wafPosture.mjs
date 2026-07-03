export const WAF_POSTURE_STATUSES = Object.freeze([
  'protected',
  'underprotected',
  'unprotected',
  'unknown',
  'excluded',
]);

export const WAF_POSTURE_REASON_CODES = Object.freeze([
  'monitor_only_behavior',
  'marker_rule_not_blocking',
  'scenario_category_failed',
  'origin_bypass_confirmed',
  'waf_fingerprint_lost',
  'fingerprint_lost',
  'policy_detached',
  'vendor_changed_unapproved',
  'rule_count_decreased',
  'rule_mode_changed',
  'rule_update_stale',
  'rate_threshold_weakened',
  'insufficient_validation_evidence',
  'policy_exception_active',
]);

export const WAF_VALIDATION_STATES = Object.freeze([
  'planned',
  'running',
  'collecting',
  'finalized',
  'failed',
  'canceled',
]);

export const WAF_VALIDATION_MODES = Object.freeze([
  'fingerprint',
  'marker',
  'origin_bypass',
  'rate_limit_safe',
  'connector_only',
  'combined',
]);

export const WAF_SCENARIO_FAMILIES = Object.freeze([
  'marker',
  'fingerprint',
  'sqli_marker',
  'xss_marker',
  'rce_marker',
  'path_traversal_marker',
  'protocol_evasion_marker',
  'rate_limit_marker',
  'origin_bypass',
  'block_page_expectation',
  'content_type_confusion_marker',
  'http2_parser_marker',
  'bot_challenge_marker',
]);

export const WAF_SCENARIO_INTAKE_STAGES = Object.freeze([
  'intake',
  'safety_review',
  'catalog_update',
  'rollout',
]);

export const SCENARIO_INTAKE_RISK_CLASSES = Object.freeze([
  'metadata_only',
  'safe',
  'soc_gated',
  'manual_review_required',
]);

export const CONTROL_BYPASS_STATUSES = Object.freeze([
  'none',
  'suspected',
  'confirmed',
]);

/** Control-bypass taxonomy — umbrella framing for CDN/WAF protection gaps (metadata-only detection). */
export const CONTROL_BYPASS_CLASSES = Object.freeze([
  {
    id: 'direct_origin_reachability',
    label: 'Direct origin reachability',
    description: 'Declared WAF/CDN protection does not block traffic before origin.',
    detection_method: 'Origin-bypass safe check + agent observation',
    reason_codes: ['origin_bypass_confirmed'],
  },
  {
    id: 'unproxied_dns_grey_cloud',
    label: 'Unproxied DNS / grey-cloud asset',
    description: 'DNS or connector signals show the asset is not fully proxied.',
    detection_method: 'Connector DNS summary + fingerprint loss',
    reason_codes: ['waf_fingerprint_lost', 'fingerprint_lost'],
  },
  {
    id: 'cdn_present_waf_unvalidated',
    label: 'CDN present, WAF not validated',
    description: 'Edge fingerprint exists but blocking validation has not passed.',
    detection_method: 'Fingerprint without blocking validation',
    reason_codes: ['marker_rule_not_blocking', 'monitor_only_behavior', 'insufficient_validation_evidence'],
  },
  {
    id: 'allowlisted_probe_path',
    label: 'Allowlisted probe/source path',
    description: 'Marker allowed despite WAF fingerprint — allowlisting invalidates validation.',
    detection_method: 'Marker allowed despite WAF fingerprint',
    reason_codes: ['monitor_only_behavior'],
  },
  {
    id: 'host_sni_mismatch',
    label: 'Host/SNI mismatch to origin',
    description: 'TLS/SNI or host routing reaches origin without expected edge policy.',
    detection_method: 'Origin-bypass + TLS metadata',
    reason_codes: ['origin_bypass_confirmed'],
  },
  {
    id: 'policy_detached_hostname',
    label: 'Policy detached from hostname',
    description: 'Connector snapshot drift shows WAF policy no longer attached to the asset.',
    detection_method: 'Connector snapshot drift',
    reason_codes: ['waf_fingerprint_lost', 'fingerprint_lost', 'policy_detached'],
  },
]);

export const WAF_RISK_CLASSES = Object.freeze([
  'safe',
  'controlled',
  'soc_gated',
  'prohibited',
]);

export const WAF_MARKER_TYPES = Object.freeze([
  'header',
  'path',
  'query',
  'user_agent',
]);

export const WAF_EXPECTED_ACTIONS = Object.freeze([
  'block',
  'challenge',
  'rate_limit',
  'log_only_expected',
  'allow_expected',
]);

export const WAF_CONNECTOR_STATUSES = Object.freeze([
  'disabled',
  'validating',
  'active',
  'error',
  'revoked',
]);

export const WAF_CONNECTOR_HEALTH = Object.freeze([
  'healthy',
  'degraded',
  'unhealthy',
  'unknown',
]);

export const DISCOVERY_APPROVAL_STATUSES = Object.freeze([
  'not_requested',
  'pending',
  'approved',
  'rejected',
  'exception',
]);

export const CVE_PIPELINE_STATES = Object.freeze([
  'ingested',
  'triaged',
  'matched',
  'validation_pending',
  'exposed',
  'not_relevant',
  'not_exploitable',
  'mitigation_recommended',
  'resolved',
]);

export const WAF_RECOMMENDATION_APPROVAL_STATUSES = Object.freeze([
  'draft',
  'pending_review',
  'approved_for_ticket',
  'rejected',
  'ticket_created',
  'deployed',
  'retest_pending',
]);

export const FORBIDDEN_RAW_WAF_EVIDENCE_KEYS = Object.freeze([
  'raw_payload',
  'payload',
  'request_body',
  'response_body',
  'raw_headers',
  'headers',
  'packets',
  'packet_capture',
  'auth_header',
  'request_headers',
  'response_headers',
  'secret',
  'token',
  'api_key',
  'api_token',
  'password',
  'credential',
  'credentials',
  'client_secret',
  'cookie_values',
  'log',
  'logs',
  'full_policy_body',
  'exploit_code',
  'exploit_payload',
]);

const FORBIDDEN_KEY_SET = new Set(
  FORBIDDEN_RAW_WAF_EVIDENCE_KEYS.map((k) => normalizeEvidenceKey(k)),
);

const CUSTOMER_SAFE_RISK_CLASSES = new Set(['safe', 'controlled']);
const CUSTOMER_SAFE_EXPECTED_ACTIONS = new Set(WAF_EXPECTED_ACTIONS);
const CUSTOMER_SAFE_MARKER_TYPES = new Set(WAF_MARKER_TYPES);

const EVIDENCE_SUMMARY_ALLOWLIST = new Set([
  'request_id',
  'test_run_id',
  'probe_job_id',
  'nonce_hash',
  'scenario_id',
  'scenario_family',
  'timestamp',
  'target_id',
  'waf_asset_id',
  'validation_run_id',
  'response_code_class',
  'blocked',
  'challenged',
  'allowed',
  'timed_out',
  'observed_at_agent',
  'header_names',
  'header_name_hashes',
  'block_page_fingerprint_hash',
  'connector_config_hash',
  'rule_count',
  'mode_summary',
  'confidence',
  'marker_result',
  'observed_action',
  'expected_action',
]);

const MONITOR_ONLY_CONNECTOR_MODES = new Set([
  'monitor',
  'detect',
  'log',
  'log_only',
  'simulate',
  'count',
]);

export function normalizeEvidenceKey(key) {
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
    const normalized = normalizeEvidenceKey(key);
    if (FORBIDDEN_KEY_SET.has(normalized) || normalized.startsWith('raw_')) {
      findings.push(keyPath);
    }
    findings.push(...collectForbiddenRawKeys(nested, keyPath));
  }
  return findings;
}

export function assertNoRawWafEvidence(value, path = '') {
  const forbidden = collectForbiddenRawKeys(value, path);
  if (forbidden.length > 0) {
    const err = new Error(`Forbidden raw WAF evidence at ${forbidden[0]}`);
    err.code = 'unsafe_waf_evidence';
    err.forbidden_paths = forbidden;
    throw err;
  }
}

export function normalizeWafEvidenceSummary(input) {
  if (input === null || input === undefined || typeof input !== 'object' || Array.isArray(input)) {
    const err = new Error('WAF evidence summary must be a plain object.');
    err.code = 'invalid_waf_evidence_summary';
    throw err;
  }
  assertNoRawWafEvidence(input);
  const summary = {};
  for (const [key, value] of Object.entries(input)) {
    const normalizedKey = normalizeEvidenceKey(key);
    if (!EVIDENCE_SUMMARY_ALLOWLIST.has(normalizedKey)) {
      const err = new Error(`Disallowed WAF evidence summary field: ${key}`);
      err.code = 'invalid_waf_evidence_summary';
      throw err;
    }
    summary[normalizedKey] = value;
  }
  return summary;
}

function parseBooleanDefault(value, fallback) {
  if (value === undefined || value === null) return fallback;
  if (typeof value === 'boolean') return value;
  if (value === '1' || value === 1 || value === 'true') return true;
  if (value === '0' || value === 0 || value === 'false') return false;
  return fallback;
}

function normalizeCanonicalTarget(input) {
  const canonicalUrl = typeof input.canonical_url === 'string' ? input.canonical_url.trim() : '';
  const hostname = typeof input.hostname === 'string' ? input.hostname.trim() : '';
  const value = canonicalUrl || hostname;
  if (!value) {
    const err = new Error('WAF asset requires canonical_url or hostname.');
    err.code = 'invalid_waf_asset';
    throw err;
  }
  return value;
}

export function normalizeWafAssetInput(input) {
  if (input === null || input === undefined || typeof input !== 'object' || Array.isArray(input)) {
    const err = new Error('WAF asset input must be a plain object.');
    err.code = 'invalid_waf_asset';
    throw err;
  }
  assertNoRawWafEvidence(input);

  const targetGroupId = typeof input.target_group_id === 'string' ? input.target_group_id.trim() : '';
  if (!targetGroupId) {
    const err = new Error('WAF asset requires target_group_id.');
    err.code = 'invalid_waf_asset';
    throw err;
  }

  if (input.approval_status === 'approved' && input.source_type === 'discovery') {
    const err = new Error('Discovery candidates cannot be auto-approved via asset input.');
    err.code = 'waf_asset_not_approved';
    throw err;
  }
  if (input.auto_approve === true || input.discovery_auto_import === true) {
    const err = new Error('Automatic discovery approval is not permitted.');
    err.code = 'waf_asset_not_approved';
    throw err;
  }

  const canonical_url = normalizeCanonicalTarget(input);
  const expected_waf_required = parseBooleanDefault(input.expected_waf_required, true);

  const asset = {
    target_group_id: targetGroupId,
    canonical_url,
    expected_waf_required,
    status: 'unknown',
  };

  if (typeof input.target_id === 'string' && input.target_id.trim()) {
    asset.target_id = input.target_id.trim();
  }
  if (typeof input.asset_kind === 'string' && input.asset_kind.trim()) {
    asset.asset_kind = input.asset_kind.trim();
  }
  if (typeof input.expected_vendor_hint === 'string' && input.expected_vendor_hint.trim()) {
    asset.expected_vendor_hint = input.expected_vendor_hint.trim();
  }
  if (typeof input.business_criticality === 'string' && input.business_criticality.trim()) {
    asset.business_criticality = input.business_criticality.trim();
  }
  if (typeof input.traffic_tier === 'string' && input.traffic_tier.trim()) {
    asset.traffic_tier = input.traffic_tier.trim();
  }
  if (Array.isArray(input.compliance_tags)) {
    asset.compliance_tags = input.compliance_tags.map((t) => String(t).trim()).filter(Boolean);
  }
  if (typeof input.owner_hint === 'string' && input.owner_hint.trim()) {
    asset.owner_hint = input.owner_hint.trim();
  }

  return asset;
}

function rejectUnsafeProfileField(input, fieldName) {
  if (input[fieldName] !== undefined && input[fieldName] !== null) {
    const err = new Error(`Field ${fieldName} is not permitted in customer WAF validation requests.`);
    err.code = 'unsafe_waf_profile';
    throw err;
  }
}

export function normalizeWafValidationRequest(input) {
  if (input === null || input === undefined || typeof input !== 'object' || Array.isArray(input)) {
    const err = new Error('WAF validation request must be a plain object.');
    err.code = 'unsafe_waf_profile';
    throw err;
  }
  assertNoRawWafEvidence(input);

  const prohibitedFields = [
    'raw_payload',
    'payload',
    'request_body',
    'response_body',
    'exploit_code',
    'exploit_payload',
    'soc_gated',
    'prohibited',
    'concurrency',
    'attack_profile',
    'amplification',
  ];
  for (const field of prohibitedFields) {
    rejectUnsafeProfileField(input, field);
  }

  const wafAssetId = typeof input.waf_asset_id === 'string' ? input.waf_asset_id.trim() : '';
  if (!wafAssetId) {
    const err = new Error('WAF validation requires waf_asset_id.');
    err.code = 'unsafe_waf_profile';
    throw err;
  }

  const modesRaw = input.modes ?? input.scenario_families ?? ['marker'];
  if (!Array.isArray(modesRaw) || modesRaw.length === 0) {
    const err = new Error('WAF validation requires at least one safe mode.');
    err.code = 'unsafe_waf_profile';
    throw err;
  }
  const modes = [...new Set(modesRaw.map((m) => String(m).trim()).filter(Boolean))];
  for (const mode of modes) {
    if (!WAF_VALIDATION_MODES.includes(mode) && !WAF_SCENARIO_FAMILIES.includes(mode)) {
      const err = new Error(`Unsupported WAF validation mode: ${mode}`);
      err.code = 'unsafe_waf_profile';
      throw err;
    }
  }

  const probe = input.probe_profile && typeof input.probe_profile === 'object' && !Array.isArray(input.probe_profile)
    ? input.probe_profile
    : {};
  const marker = input.marker_profile && typeof input.marker_profile === 'object' && !Array.isArray(input.marker_profile)
    ? input.marker_profile
    : {};

  assertNoRawWafEvidence(probe);
  assertNoRawWafEvidence(marker);

  const maxRequests = probe.max_requests ?? input.max_requests ?? 1;
  const timeoutMs = probe.timeout_ms ?? input.timeout_ms ?? 3000;
  const maxN = Number(maxRequests);
  const timeoutN = Number(timeoutMs);
  if (!Number.isInteger(maxN) || maxN < 1 || maxN > 5) {
    const err = new Error('max_requests must be an integer between 1 and 5.');
    err.code = 'unsafe_waf_profile';
    throw err;
  }
  if (!Number.isInteger(timeoutN) || timeoutN < 100 || timeoutN > 5000) {
    const err = new Error('timeout_ms must be an integer between 100 and 5000.');
    err.code = 'unsafe_waf_profile';
    throw err;
  }

  const markerType = String(marker.marker_type ?? input.marker_type ?? 'header').trim();
  if (!CUSTOMER_SAFE_MARKER_TYPES.has(markerType)) {
    const err = new Error(`marker_type must be one of: ${[...CUSTOMER_SAFE_MARKER_TYPES].join(', ')}.`);
    err.code = 'unsafe_waf_profile';
    throw err;
  }

  const expectedAction = String(marker.expected_action ?? input.expected_action ?? 'block').trim();
  if (!CUSTOMER_SAFE_EXPECTED_ACTIONS.has(expectedAction)) {
    const err = new Error(`expected_action must be one of: ${[...CUSTOMER_SAFE_EXPECTED_ACTIONS].join(', ')}.`);
    err.code = 'unsafe_waf_profile';
    throw err;
  }

  const riskClass = String(input.risk_class ?? probe.risk_class ?? marker.risk_class ?? 'safe').trim();
  if (!CUSTOMER_SAFE_RISK_CLASSES.has(riskClass)) {
    const err = new Error('risk_class must be safe or controlled for customer-runnable validations.');
    err.code = 'unsafe_waf_profile';
    throw err;
  }

  if (input.risk_class === 'soc_gated' || input.risk_class === 'prohibited') {
    const err = new Error('soc_gated and prohibited validations require SOC workflow.');
    err.code = 'unsafe_waf_profile';
    throw err;
  }

  return {
    waf_asset_id: wafAssetId,
    modes,
    probe_profile: {
      max_requests: maxN,
      timeout_ms: timeoutN,
      risk_class: riskClass,
    },
    marker_profile: {
      marker_type: markerType,
      expected_action: expectedAction,
    },
  };
}

export function classifyWafPosture({
  wafDetected = false,
  validationPassed = false,
  validationFailed = false,
  originBypassConfirmed = false,
  wafRequired = true,
  connectorMode = null,
} = {}) {
  const reason_codes = [];

  if (originBypassConfirmed) {
    reason_codes.push('origin_bypass_confirmed');
  }
  if (validationFailed) {
    reason_codes.push('marker_rule_not_blocking');
  }
  const modeKey = connectorMode ? String(connectorMode).trim().toLowerCase() : null;
  if (modeKey && MONITOR_ONLY_CONNECTOR_MODES.has(modeKey)) {
    reason_codes.push('monitor_only_behavior');
  }

  if (validationPassed && wafDetected && !originBypassConfirmed) {
    return { status: 'protected', reason_codes };
  }

  if (
    originBypassConfirmed
    || validationFailed
    || (wafDetected && modeKey && MONITOR_ONLY_CONNECTOR_MODES.has(modeKey))
  ) {
    return { status: 'underprotected', reason_codes };
  }

  if (wafDetected && !validationPassed) {
    return {
      status: 'unknown',
      reason_codes: [...new Set([...reason_codes, 'insufficient_validation_evidence'])],
    };
  }

  if (!wafDetected && wafRequired) {
    return { status: 'unprotected', reason_codes };
  }

  return { status: 'unknown', reason_codes };
}

export const ACTION_ITEM_CATEGORIES = Object.freeze([
  'waf_coverage',
  'waf_drift',
  'origin_bypass',
  'cve_mitigation',
  'connector_setup',
]);

export const ACTION_ITEM_STATUSES = Object.freeze([
  'open',
  'ticketed',
  'remediation_started',
  'retest_pending',
  'resolved',
  'accepted_risk',
]);

export const WAF_SIEM_EVENT_TYPES = Object.freeze([
  'waf.posture.updated',
  'waf.drift.detected',
  'waf.validation.failed',
  'cve.asset.exposed',
  'connector.health_changed',
]);

export const REMEDIATION_CONNECTOR_TYPES = Object.freeze([
  'jira',
  'servicenow',
  'webhook',
  'splunk_hec',
  'sentinel',
  'xsoar',
  'slack',
  'teams',
  'email',
]);

const ACTION_ITEM_FORBIDDEN_KEY_FRAGMENTS = new Set([
  'raw_payload',
  'headers',
  'exploit',
  'cookie',
  'secret',
  'token',
  'credentials',
  'credential',
  'password',
  'api_key',
  'api_token',
]);

function collectActionItemForbiddenKeys(value, path = '') {
  if (value === null || value === undefined || typeof value !== 'object') {
    return [];
  }
  const findings = [];
  if (Array.isArray(value)) {
    value.forEach((entry, index) => {
      findings.push(...collectActionItemForbiddenKeys(entry, `${path}[${index}]`));
    });
    return findings;
  }
  for (const [key, nested] of Object.entries(value)) {
    const keyPath = path ? `${path}.${key}` : key;
    const normalized = normalizeEvidenceKey(key);
    if (
      ACTION_ITEM_FORBIDDEN_KEY_FRAGMENTS.has(normalized)
      || normalized.includes('exploit')
      || normalized.startsWith('raw_')
    ) {
      findings.push(keyPath);
    }
    findings.push(...collectActionItemForbiddenKeys(nested, keyPath));
  }
  return findings;
}

export function validateActionItem(item) {
  if (item === null || item === undefined || typeof item !== 'object' || Array.isArray(item)) {
    const err = new Error('Action item must be a plain object.');
    err.code = 'invalid_action_item';
    throw err;
  }
  const forbidden = collectActionItemForbiddenKeys(item);
  if (forbidden.length > 0) {
    const err = new Error(`Forbidden action item field: ${forbidden[0]}`);
    err.code = 'unsafe_action_item';
    err.forbidden_paths = forbidden;
    throw err;
  }
  assertNoRawWafEvidence(item);

  const id = typeof item.action_item_id === 'string' ? item.action_item_id.trim() : '';
  if (!id) {
    const err = new Error('action_item_id is required.');
    err.code = 'invalid_action_item';
    throw err;
  }
  if (!ACTION_ITEM_CATEGORIES.includes(item.category)) {
    const err = new Error(`category must be one of: ${ACTION_ITEM_CATEGORIES.join(', ')}.`);
    err.code = 'invalid_action_item';
    throw err;
  }
  if (!ACTION_ITEM_STATUSES.includes(item.status)) {
    const err = new Error(`status must be one of: ${ACTION_ITEM_STATUSES.join(', ')}.`);
    err.code = 'invalid_action_item';
    throw err;
  }
  const severity = String(item.severity ?? '').trim().toLowerCase();
  if (!['critical', 'high', 'medium', 'low'].includes(severity)) {
    const err = new Error('severity must be critical, high, medium, or low.');
    err.code = 'invalid_action_item';
    throw err;
  }
  if (typeof item.title !== 'string' || !item.title.trim()) {
    const err = new Error('title is required.');
    err.code = 'invalid_action_item';
    throw err;
  }
  if (!item.asset || typeof item.asset !== 'object' || Array.isArray(item.asset)) {
    const err = new Error('asset display object is required.');
    err.code = 'invalid_action_item';
    throw err;
  }
  if (typeof item.asset.display !== 'string' || !item.asset.display.trim()) {
    const err = new Error('asset.display is required.');
    err.code = 'invalid_action_item';
    throw err;
  }
  if (!item.evidence || typeof item.evidence !== 'object' || Array.isArray(item.evidence)) {
    const err = new Error('evidence summary object is required.');
    err.code = 'invalid_action_item';
    throw err;
  }
  if (typeof item.evidence.summary !== 'string' || !item.evidence.summary.trim()) {
    const err = new Error('evidence.summary is required.');
    err.code = 'invalid_action_item';
    throw err;
  }
  if (!Array.isArray(item.evidence.links)) {
    const err = new Error('evidence.links must be an array.');
    err.code = 'invalid_action_item';
    throw err;
  }
  if (typeof item.recommended_solution !== 'string' || !item.recommended_solution.trim()) {
    const err = new Error('recommended_solution is required.');
    err.code = 'invalid_action_item';
    throw err;
  }
  if (typeof item.retest_url !== 'string' || !item.retest_url.trim()) {
    const err = new Error('retest_url is required.');
    err.code = 'invalid_action_item';
    throw err;
  }
  return true;
}

function normalizeActionItemEvidence(input) {
  const raw = input && typeof input === 'object' && !Array.isArray(input) ? input : {};
  assertNoRawWafEvidence(raw);
  const summary = typeof raw.summary === 'string' ? raw.summary.trim() : '';
  if (!summary) {
    const err = new Error('evidence.summary is required.');
    err.code = 'invalid_action_item';
    throw err;
  }
  const links = Array.isArray(raw.links)
    ? raw.links
        .map((link) => {
          if (!link || typeof link !== 'object' || Array.isArray(link)) return null;
          assertNoRawWafEvidence(link);
          const type = typeof link.type === 'string' ? link.type.trim() : 'reference';
          const url = typeof link.url === 'string' ? link.url.trim() : '';
          const label = typeof link.label === 'string' ? link.label.trim() : '';
          if (!url) return null;
          return { type, url, ...(label ? { label } : {}) };
        })
        .filter(Boolean)
    : [];
  return { summary, links };
}

function normalizeActionItemAsset(input) {
  const raw = input && typeof input === 'object' && !Array.isArray(input) ? input : {};
  assertNoRawWafEvidence(raw);
  const display = typeof raw.display === 'string'
    ? raw.display.trim()
    : typeof raw.canonical_url === 'string'
      ? raw.canonical_url.trim()
      : '';
  if (!display) {
    const err = new Error('asset display is required.');
    err.code = 'invalid_action_item';
    throw err;
  }
  const asset = { display };
  if (typeof raw.id === 'string' && raw.id.trim()) asset.id = raw.id.trim();
  if (typeof raw.owner_hint === 'string' && raw.owner_hint.trim()) {
    asset.owner_hint = raw.owner_hint.trim();
  }
  if (typeof raw.business_criticality === 'string' && raw.business_criticality.trim()) {
    asset.business_criticality = raw.business_criticality.trim();
  }
  return asset;
}

export function createActionItem(fields = {}) {
  if (fields === null || fields === undefined || typeof fields !== 'object' || Array.isArray(fields)) {
    const err = new Error('Action item fields must be a plain object.');
    err.code = 'invalid_action_item';
    throw err;
  }
  assertNoRawWafEvidence(fields);

  const action_item_id = typeof fields.action_item_id === 'string' ? fields.action_item_id.trim() : '';
  if (!action_item_id) {
    const err = new Error('action_item_id is required.');
    err.code = 'invalid_action_item';
    throw err;
  }

  const category = String(fields.category ?? 'waf_coverage').trim();
  if (!ACTION_ITEM_CATEGORIES.includes(category)) {
    const err = new Error(`category must be one of: ${ACTION_ITEM_CATEGORIES.join(', ')}.`);
    err.code = 'invalid_action_item';
    throw err;
  }

  const title = typeof fields.title === 'string' ? fields.title.trim() : '';
  if (!title) {
    const err = new Error('title is required.');
    err.code = 'invalid_action_item';
    throw err;
  }

  const owner = typeof fields.owner === 'string' && fields.owner.trim()
    ? fields.owner.trim()
    : typeof fields.owner_hint === 'string' && fields.owner_hint.trim()
      ? fields.owner_hint.trim()
      : 'security-operations';

  const severity = String(fields.severity ?? 'medium').trim().toLowerCase();
  const status = String(fields.status ?? 'open').trim();
  const recommended_solution = typeof fields.recommended_solution === 'string'
    ? fields.recommended_solution.trim()
    : '';
  const retest_url = typeof fields.retest_url === 'string' ? fields.retest_url.trim() : '';

  const item = {
    action_item_id,
    category,
    title,
    asset: normalizeActionItemAsset(fields.asset ?? {}),
    owner,
    severity,
    evidence: normalizeActionItemEvidence(fields.evidence ?? {}),
    recommended_solution,
    retest_url,
    status,
    ...(Array.isArray(fields.finding_ids) ? { finding_ids: [...new Set(fields.finding_ids.map(String))] } : {}),
    ...(typeof fields.dedupe_key === 'string' && fields.dedupe_key.trim()
      ? { dedupe_key: fields.dedupe_key.trim() }
      : {}),
    ...(typeof fields.tenant_id === 'string' && fields.tenant_id.trim()
      ? { tenant_id: fields.tenant_id.trim() }
      : {}),
  };

  validateActionItem(item);
  return item;
}

function parseReasonCodesFromNotes(notes) {
  if (typeof notes !== 'string' || !notes.trim()) return [];
  const match = notes.match(/Reason codes:\s*([^.]+)/i);
  if (!match) return [];
  return match[1]
    .split(',')
    .map((c) => c.trim())
    .filter(Boolean);
}

export function extractFindingRemediationContext(finding) {
  const waf_asset_id = typeof finding?.waf_asset_id === 'string' && finding.waf_asset_id.trim()
    ? finding.waf_asset_id.trim()
    : typeof finding?.check_id === 'string' && finding.check_id.startsWith('waf.posture.')
      ? finding.check_id.slice('waf.posture.'.length)
      : null;
  const reason_codes = Array.isArray(finding?.reason_codes) && finding.reason_codes.length > 0
    ? finding.reason_codes.map((c) => String(c).trim()).filter(Boolean)
    : parseReasonCodesFromNotes(finding?.notes);
  const primary_reason = reason_codes[0] ?? 'unknown';
  const owner = typeof finding?.owner === 'string' && finding.owner.trim()
    ? finding.owner.trim()
    : typeof finding?.owner_hint === 'string' && finding.owner_hint.trim()
      ? finding.owner_hint.trim()
      : null;
  return {
    waf_asset_id,
    reason_codes,
    primary_reason,
    owner,
    policy_ref: typeof finding?.policy_ref === 'string' ? finding.policy_ref.trim() : null,
    waf_policy_ref: typeof finding?.waf_policy_ref === 'string' ? finding.waf_policy_ref.trim() : null,
    cve_id: typeof finding?.cve_id === 'string' ? finding.cve_id.trim() : null,
    origin_bypass_path: typeof finding?.origin_bypass_path === 'string'
      ? finding.origin_bypass_path.trim()
      : null,
  };
}

function groupKey(parts) {
  return parts.filter(Boolean).join('::');
}

export function groupFindings(findings) {
  if (!Array.isArray(findings) || findings.length === 0) return [];

  const entries = findings.map((finding) => ({
    finding,
    ctx: extractFindingRemediationContext(finding),
  }));
  const assigned = new Set();
  const groups = [];

  function addGroup(group_type, merge_key, matched) {
    if (matched.length === 0) return;
    for (const entry of matched) assigned.add(entry.finding.id ?? entry.finding);
    groups.push({
      group_type,
      merge_key,
      findings: matched.map((e) => e.finding),
    });
  }

  const originBuckets = new Map();
  for (const entry of entries) {
    if (!entry.ctx.origin_bypass_path || assigned.has(entry.finding.id ?? entry.finding)) continue;
    const key = entry.ctx.origin_bypass_path;
    const bucket = originBuckets.get(key) ?? [];
    bucket.push(entry);
    originBuckets.set(key, bucket);
  }
  for (const [path, bucket] of originBuckets) {
    addGroup('origin_bypass', groupKey(['origin_bypass', path]), bucket);
  }

  const cveBuckets = new Map();
  for (const entry of entries) {
    if (!entry.ctx.cve_id || assigned.has(entry.finding.id ?? entry.finding)) continue;
    const key = groupKey(['cve', entry.ctx.cve_id, entry.ctx.owner ?? 'unassigned']);
    const bucket = cveBuckets.get(key) ?? [];
    bucket.push(entry);
    cveBuckets.set(key, bucket);
  }
  for (const [key, bucket] of cveBuckets) {
    addGroup('cve_owner', key, bucket);
  }

  const policyBuckets = new Map();
  for (const entry of entries) {
    const policyRef = entry.ctx.waf_policy_ref ?? entry.ctx.policy_ref;
    if (!policyRef || assigned.has(entry.finding.id ?? entry.finding)) continue;
    const bucket = policyBuckets.get(policyRef) ?? [];
    bucket.push(entry);
    policyBuckets.set(policyRef, bucket);
  }
  for (const [policyRef, bucket] of policyBuckets) {
    const assetIds = new Set(bucket.map((e) => e.ctx.waf_asset_id).filter(Boolean));
    if (assetIds.size < 2) continue;
    addGroup('policy_assets', groupKey(['policy', policyRef]), bucket);
  }

  const assetReasonBuckets = new Map();
  for (const entry of entries) {
    if (!entry.ctx.waf_asset_id || assigned.has(entry.finding.id ?? entry.finding)) continue;
    const key = groupKey(['asset', entry.ctx.waf_asset_id, entry.ctx.primary_reason]);
    const bucket = assetReasonBuckets.get(key) ?? [];
    bucket.push(entry);
    assetReasonBuckets.set(key, bucket);
  }
  for (const [key, bucket] of assetReasonBuckets) {
    addGroup('asset_reason', key, bucket);
  }

  return groups;
}

function redactTenantIdForExternal(tenantId) {
  if (typeof tenantId !== 'string' || !tenantId.trim()) return null;
  return `redacted:${tenantId.trim().slice(0, 8)}`;
}

function normalizeSiemAsset(input = {}) {
  assertNoRawWafEvidence(input);
  const display = typeof input.display === 'string'
    ? input.display.trim()
    : typeof input.canonical_url === 'string'
      ? input.canonical_url.trim()
      : '';
  const asset = {};
  if (typeof input.id === 'string' && input.id.trim()) asset.id = input.id.trim();
  if (display) asset.display = display;
  if (typeof input.owner_hint === 'string' && input.owner_hint.trim()) {
    asset.owner_hint = input.owner_hint.trim();
  }
  if (typeof input.business_criticality === 'string' && input.business_criticality.trim()) {
    asset.business_criticality = input.business_criticality.trim();
  }
  return asset;
}

export function buildSiemEventPayload(event = {}) {
  if (event === null || event === undefined || typeof event !== 'object' || Array.isArray(event)) {
    const err = new Error('SIEM event input must be a plain object.');
    err.code = 'invalid_siem_event';
    throw err;
  }
  assertNoRawWafEvidence(event);

  const event_type = String(event.event_type ?? '').trim();
  if (!WAF_SIEM_EVENT_TYPES.includes(event_type)) {
    const err = new Error(`event_type must be one of: ${WAF_SIEM_EVENT_TYPES.join(', ')}.`);
    err.code = 'invalid_siem_event';
    throw err;
  }

  const event_id = typeof event.event_id === 'string' && event.event_id.trim()
    ? event.event_id.trim()
    : null;
  if (!event_id) {
    const err = new Error('event_id is required.');
    err.code = 'invalid_siem_event';
    throw err;
  }

  const occurred_at = typeof event.occurred_at === 'string' && event.occurred_at.trim()
    ? event.occurred_at.trim()
    : new Date().toISOString();

  const severity = String(event.severity ?? 'medium').trim().toLowerCase();
  if (!['critical', 'high', 'medium', 'low', 'info'].includes(severity)) {
    const err = new Error('severity must be critical, high, medium, low, or info.');
    err.code = 'invalid_siem_event';
    throw err;
  }

  const findingRaw = event.finding && typeof event.finding === 'object' && !Array.isArray(event.finding)
    ? event.finding
    : {};
  assertNoRawWafEvidence(findingRaw);
  const finding_id = typeof findingRaw.id === 'string' ? findingRaw.id.trim() : '';
  if (!finding_id) {
    const err = new Error('finding.id is required.');
    err.code = 'invalid_siem_event';
    throw err;
  }
  const reason_codes = Array.isArray(findingRaw.reason_codes)
    ? findingRaw.reason_codes.map((c) => String(c).trim()).filter(Boolean)
    : [];
  const summary = typeof findingRaw.summary === 'string' ? findingRaw.summary.trim() : '';
  if (!summary) {
    const err = new Error('finding.summary is required.');
    err.code = 'invalid_siem_event';
    throw err;
  }

  const recommendationRaw = event.recommendation
    && typeof event.recommendation === 'object'
    && !Array.isArray(event.recommendation)
    ? event.recommendation
    : {};
  assertNoRawWafEvidence(recommendationRaw);
  const recommendation = {
    vendor: typeof recommendationRaw.vendor === 'string' ? recommendationRaw.vendor.trim() : 'generic',
    type: typeof recommendationRaw.type === 'string' ? recommendationRaw.type.trim() : 'guidance',
    summary: typeof recommendationRaw.summary === 'string'
      ? recommendationRaw.summary.trim()
      : 'Review WAF posture remediation guidance.',
  };

  const payload = {
    schema_version: 'astranull.waf_event.v1',
    event_type,
    event_id,
    occurred_at,
    severity,
    asset: normalizeSiemAsset(event.asset ?? {}),
    finding: {
      id: finding_id,
      reason_codes,
      summary,
      ...(typeof findingRaw.evidence_url === 'string' && findingRaw.evidence_url.trim()
        ? { evidence_url: findingRaw.evidence_url.trim() }
        : {}),
      ...(typeof findingRaw.retest_url === 'string' && findingRaw.retest_url.trim()
        ? { retest_url: findingRaw.retest_url.trim() }
        : {}),
    },
    recommendation,
  };

  const tenant_id = redactTenantIdForExternal(event.tenant_id);
  if (tenant_id) payload.tenant_id = tenant_id;

  assertNoRawWafEvidence(payload);
  return payload;
}

const CONTROL_BYPASS_CONFIRMED_REASONS = new Set([
  'origin_bypass_confirmed',
  'policy_detached',
]);

const CONTROL_BYPASS_SUSPECTED_REASONS = new Set([
  'marker_rule_not_blocking',
  'monitor_only_behavior',
  'waf_fingerprint_lost',
  'fingerprint_lost',
  'scenario_category_failed',
  'insufficient_validation_evidence',
]);

const SCENARIO_INTAKE_FORBIDDEN_KEYS = new Set([
  'exploit_code',
  'exploit_payload',
  'raw_payload',
  'payload',
  'request_body',
  'response_body',
  'poc_code',
  'attack_script',
]);

const ADVISORY_REF_PATTERN = /^(CVE-\d{4}-\d{4,}|advisory:[a-z0-9._-]+|bulletin:[a-z0-9._-]+)$/i;

export function mapReasonCodesToControlBypassClasses(reasonCodes = []) {
  const normalized = new Set(
    (Array.isArray(reasonCodes) ? reasonCodes : [])
      .map((code) => String(code).trim())
      .filter(Boolean),
  );
  if (normalized.size === 0) return [];
  return CONTROL_BYPASS_CLASSES.filter((bypassClass) =>
    bypassClass.reason_codes.some((code) => normalized.has(code)),
  );
}

export function deriveControlBypassStatus({
  reason_codes: reasonCodes = [],
  origin_bypass_confirmed: originBypassConfirmed = false,
  marker_validation_failed: markerValidationFailed = false,
} = {}) {
  const codes = new Set(
    (Array.isArray(reasonCodes) ? reasonCodes : [])
      .map((code) => String(code).trim())
      .filter(Boolean),
  );
  if (originBypassConfirmed) codes.add('origin_bypass_confirmed');
  if (markerValidationFailed) codes.add('marker_rule_not_blocking');

  if ([...codes].some((code) => CONTROL_BYPASS_CONFIRMED_REASONS.has(code))) {
    return 'confirmed';
  }
  if ([...codes].some((code) => CONTROL_BYPASS_SUSPECTED_REASONS.has(code))) {
    return 'suspected';
  }
  return 'none';
}

export function formatControlBypassUxLabel(status) {
  const key = String(status ?? 'none').trim().toLowerCase();
  if (key === 'confirmed') return 'Control bypass confirmed';
  if (key === 'suspected') return 'Control bypass suspected';
  return 'No control bypass detected';
}

export function normalizeScenarioIntakeInput(input) {
  if (input === null || input === undefined || typeof input !== 'object' || Array.isArray(input)) {
    const err = new Error('Scenario intake input must be a plain object.');
    err.code = 'invalid_scenario_intake';
    throw err;
  }
  assertNoRawWafEvidence(input);

  for (const [key, value] of Object.entries(input)) {
    const normalizedKey = normalizeEvidenceKey(key);
    if (
      SCENARIO_INTAKE_FORBIDDEN_KEYS.has(normalizedKey)
      || normalizedKey.includes('exploit')
      || normalizedKey.startsWith('raw_')
    ) {
      const err = new Error(`Forbidden scenario intake field: ${key}`);
      err.code = 'unsafe_scenario_intake';
      throw err;
    }
    if (value !== null && typeof value === 'object') {
      assertNoRawWafEvidence(value);
    }
  }

  const pattern_title = typeof input.pattern_title === 'string' ? input.pattern_title.trim() : '';
  if (!pattern_title) {
    const err = new Error('pattern_title is required.');
    err.code = 'invalid_scenario_intake';
    throw err;
  }

  const advisory_refs_raw = Array.isArray(input.advisory_refs) ? input.advisory_refs : [];
  const advisory_refs = [...new Set(
    advisory_refs_raw
      .map((ref) => String(ref).trim())
      .filter(Boolean),
  )];
  if (advisory_refs.length === 0) {
    const err = new Error('advisory_refs must include at least one CVE, advisory, or bulletin reference.');
    err.code = 'invalid_scenario_intake';
    throw err;
  }
  for (const ref of advisory_refs) {
    if (!ADVISORY_REF_PATTERN.test(ref)) {
      const err = new Error(
        `advisory_refs entries must match CVE-YYYY-NNNN, advisory:<id>, or bulletin:<id>. Got: ${ref}`,
      );
      err.code = 'invalid_scenario_intake';
      throw err;
    }
  }

  let proposed_scenario_family = null;
  if (input.proposed_scenario_family !== undefined && input.proposed_scenario_family !== null) {
    proposed_scenario_family = String(input.proposed_scenario_family).trim();
    if (!WAF_SCENARIO_FAMILIES.includes(proposed_scenario_family)) {
      const err = new Error(`proposed_scenario_family must be one of: ${WAF_SCENARIO_FAMILIES.join(', ')}.`);
      err.code = 'invalid_scenario_intake';
      throw err;
    }
  }

  const risk_class = String(input.risk_class ?? 'metadata_only').trim();
  if (!SCENARIO_INTAKE_RISK_CLASSES.includes(risk_class)) {
    const err = new Error(`risk_class must be one of: ${SCENARIO_INTAKE_RISK_CLASSES.join(', ')}.`);
    err.code = 'invalid_scenario_intake';
    throw err;
  }

  const notes = typeof input.notes === 'string' ? input.notes.trim().slice(0, 2000) : '';
  const threat_summary = typeof input.threat_summary === 'string'
    ? input.threat_summary.trim().slice(0, 2000)
    : '';

  return {
    pattern_title,
    advisory_refs,
    ...(proposed_scenario_family ? { proposed_scenario_family } : {}),
    risk_class,
    ...(notes ? { notes } : {}),
    ...(threat_summary ? { threat_summary } : {}),
  };
}
