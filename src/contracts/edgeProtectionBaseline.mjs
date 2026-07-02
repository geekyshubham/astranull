export const EDGE_PROTECTION_REQUIRED_CONTROLS = Object.freeze([
  {
    control_id: 'tls_termination',
    title: 'TLS Termination',
    required_fields: Object.freeze(['evidence_uri', 'validated_at', 'owner', 'tls_policy']),
  },
  {
    control_id: 'host_allowlist',
    title: 'Host Allowlist',
    required_fields: Object.freeze(['evidence_uri', 'validated_at', 'owner', 'allowed_hosts']),
  },
  {
    control_id: 'request_size_limits',
    title: 'Request Size, Header, and Body Limits',
    required_fields: Object.freeze(['evidence_uri', 'validated_at', 'owner', 'limit_summary']),
  },
  {
    control_id: 'bot_and_credential_stuffing_protection',
    title: 'Bot and Credential-Stuffing Protection',
    required_fields: Object.freeze(['evidence_uri', 'validated_at', 'owner', 'protection_summary']),
  },
  {
    control_id: 'managed_waf_or_equivalent_rules',
    title: 'Managed WAF or Equivalent Rules',
    required_fields: Object.freeze(['evidence_uri', 'validated_at', 'owner', 'rule_family_summary']),
  },
  {
    control_id: 'origin_shielding',
    title: 'Origin Shielding and Direct-Origin Bypass Prevention',
    required_fields: Object.freeze(['evidence_uri', 'validated_at', 'owner', 'origin_exposure_summary']),
  },
  {
    control_id: 'edge_logging_and_audit',
    title: 'Edge Logging and Audit Routing',
    required_fields: Object.freeze(['evidence_uri', 'validated_at', 'owner', 'log_destination']),
  },
  {
    control_id: 'health_endpoint_handling',
    title: 'Health Endpoint Handling',
    required_fields: Object.freeze(['evidence_uri', 'validated_at', 'owner', 'health_path_policy']),
  },
  {
    control_id: 'security_headers',
    title: 'Security Headers',
    required_fields: Object.freeze(['evidence_uri', 'validated_at', 'owner', 'header_policy_summary']),
  },
  {
    control_id: 'proxy_header_spoofing_controls',
    title: 'Proxy Header Spoofing Controls',
    required_fields: Object.freeze(['evidence_uri', 'validated_at', 'owner', 'spoofing_control_summary']),
  },
]);

export const EDGE_PROTECTION_CONTROL_IDS = Object.freeze(
  EDGE_PROTECTION_REQUIRED_CONTROLS.map((control) => control.control_id),
);

export const EDGE_PROTECTION_EVIDENCE_FIELDS = Object.freeze(
  Object.fromEntries(
    EDGE_PROTECTION_REQUIRED_CONTROLS.map((control) => [
      control.control_id,
      control.required_fields,
    ]),
  ),
);

const CONTROL_BY_ID = Object.freeze(
  Object.fromEntries(
    EDGE_PROTECTION_REQUIRED_CONTROLS.map((control) => [control.control_id, control]),
  ),
);

const FORBIDDEN_EVIDENCE_KEYS = new Set([
  'authorization',
  'cookie',
  'credentials',
  'credential',
  'headers',
  'header',
  'http_headers',
  'request_headers',
  'response_headers',
  'body',
  'request_body',
  'response_body',
  'logs',
  'log',
  'log_line',
  'log_lines',
  'packet',
  'packet_payload',
  'password',
  'payload',
  'raw_body',
  'raw_headers',
  'raw_log',
  'raw_logs',
  'raw_packet',
  'raw_payload',
  'secret',
  'set_cookie',
  'setcookie',
  'token',
]);

function normalizeKey(key) {
  return key
    .replace(/([a-z])([A-Z])/g, '$1_$2')
    .replace(/[^A-Za-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase();
}

export function listEdgeProtectionControls() {
  return EDGE_PROTECTION_REQUIRED_CONTROLS;
}

function hasValue(value) {
  if (value === null || value === undefined) return false;
  if (typeof value === 'string' && value.trim() === '') return false;
  if (Array.isArray(value) && value.length === 0) return false;
  return true;
}

function collectForbiddenKeys(value, path = '') {
  if (value === null || value === undefined || typeof value !== 'object') return [];
  const findings = [];
  if (Array.isArray(value)) {
    value.forEach((entry, index) => {
      findings.push(...collectForbiddenKeys(entry, `${path}[${index}]`));
    });
    return findings;
  }
  for (const [key, nested] of Object.entries(value)) {
    const keyPath = path ? `${path}.${key}` : key;
    const normalized = normalizeKey(key);
    if (FORBIDDEN_EVIDENCE_KEYS.has(normalized) || normalized.startsWith('raw_')) {
      findings.push(keyPath);
    }
    findings.push(...collectForbiddenKeys(nested, keyPath));
  }
  return findings;
}

function normalizeEvidenceControls(evidence) {
  if (Array.isArray(evidence)) return evidence;
  if (Array.isArray(evidence?.controls)) return evidence.controls;
  return [];
}

export function validateEdgeProtectionEvidence(evidence) {
  const controls = normalizeEvidenceControls(evidence);
  const seen = new Set();
  const invalid_controls = [];
  const missing_fields = [];
  const forbidden_fields = collectForbiddenKeys(evidence);

  for (const control of controls) {
    const controlId = control?.control_id;
    if (!controlId || typeof controlId !== 'string') {
      invalid_controls.push({ control_id: controlId ?? null, reason: 'missing_control_id' });
      continue;
    }
    const baseline = CONTROL_BY_ID[controlId];
    if (!baseline) {
      invalid_controls.push({ control_id: controlId, reason: 'unknown_control' });
      continue;
    }
    seen.add(controlId);
    const missing = baseline.required_fields.filter((field) => !hasValue(control[field]));
    if (missing.length > 0) {
      missing_fields.push({ control_id: controlId, fields: missing });
    }
  }

  const missing_controls = EDGE_PROTECTION_CONTROL_IDS.filter((controlId) => !seen.has(controlId));

  return {
    ok:
      missing_controls.length === 0
      && invalid_controls.length === 0
      && missing_fields.length === 0
      && forbidden_fields.length === 0,
    missing_controls,
    invalid_controls,
    missing_fields,
    forbidden_fields,
  };
}
