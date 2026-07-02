const TOKEN_PATTERNS = [
  /ast_v1\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){2}/g,
  /svc_v1\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){2}/g,
  /agc_v1\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){2}/g,
  /ast_[A-Za-z0-9_-]{8,}/g,
  /svc_[A-Za-z0-9_-]{8,}/g,
  /agc_[A-Za-z0-9_-]{8,}/g,
  /Bearer\s+[A-Za-z0-9._-]+/gi,
  /sk-[A-Za-z0-9]{16,}/g,
];

/** Normalized keys that look secret-like but are allowed in evidence metadata. */
export const BENIGN_EVIDENCE_KEYS = Object.freeze([
  'evidence_uri',
  'provider_key',
  'security_signoff',
  'signoff_reference',
]);

const BENIGN_NORMALIZED_KEYS = new Set(BENIGN_EVIDENCE_KEYS);

const EXACT_SENSITIVE_NORMALIZED_KEYS = new Set([
  'api_key',
  'apikey',
  'authorization',
  'bearer_token',
  'client_secret',
  'access_token',
  'refresh_token',
  'id_token',
  'cookie',
  'credential',
  'key_material',
  'password',
  'private_key',
  'public_key_der_base64',
  'secret',
  'set_cookie',
  'token',
  'x_api_key',
]);

const SENSITIVE_KEY_SUFFIXES = Object.freeze([
  '_secret',
  '_token',
  '_credential',
  '_credentials',
  '_password',
  '_api_key',
]);

export const EVIDENCE_TOKEN_STRING_PATTERNS = Object.freeze([
  { pattern: /ast_v1\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){2}/, reason: 'token_pattern' },
  { pattern: /svc_v1\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){2}/, reason: 'token_pattern' },
  { pattern: /agc_v1\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){2}/, reason: 'token_pattern' },
  { pattern: /Bearer\s+[A-Za-z0-9._-]+/i, reason: 'bearer_token' },
  {
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
    reason: 'private_key_marker',
  },
]);

export const EVIDENCE_EMAIL_GATED_STRING_PATTERNS = Object.freeze([
  { pattern: /password\s*[:=]\s*\S+/i, reason: 'password_in_text' },
  { pattern: /api[_-]?key\s*[:=]\s*\S+/i, reason: 'api_key_in_text' },
]);

export function normalizeEvidenceKey(key) {
  return String(key)
    .replace(/([a-z])([A-Z])/g, '$1_$2')
    .replace(/[^A-Za-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase();
}

export function isVariantSensitiveKey(key) {
  const normalized = normalizeEvidenceKey(key);
  if (BENIGN_NORMALIZED_KEYS.has(normalized)) return false;
  if (EXACT_SENSITIVE_NORMALIZED_KEYS.has(normalized)) return true;
  return SENSITIVE_KEY_SUFFIXES.some((suffix) => normalized.endsWith(suffix));
}

function isSensitiveRedactionKey(key) {
  return isVariantSensitiveKey(key);
}

export function collectForbiddenEvidenceFields(
  value,
  fieldPath = '',
  options = {},
) {
  const extraForbidden = options.extraForbiddenKeys ?? new Set();
  if (value === null || value === undefined || typeof value !== 'object') return [];
  const findings = [];
  if (Array.isArray(value)) {
    value.forEach((entry, index) => {
      findings.push(
        ...collectForbiddenEvidenceFields(entry, `${fieldPath}[${index}]`, options),
      );
    });
    return findings;
  }
  for (const [key, nested] of Object.entries(value)) {
    const keyPath = fieldPath ? `${fieldPath}.${key}` : key;
    const normalized = normalizeEvidenceKey(key);
    if (
      extraForbidden.has(normalized)
      || normalized.startsWith('raw_')
      || (options.extraForbiddenPredicate?.(normalized, keyPath) ?? false)
      || isVariantSensitiveKey(key)
    ) {
      findings.push(keyPath);
    }
    findings.push(...collectForbiddenEvidenceFields(nested, keyPath, options));
  }
  return findings;
}

function stringMatchesEvidenceTokenPattern(value) {
  for (const { pattern, reason } of EVIDENCE_TOKEN_STRING_PATTERNS) {
    if (pattern.test(value)) {
      pattern.lastIndex = 0;
      return reason;
    }
    pattern.lastIndex = 0;
  }
  return null;
}

function stringMatchesEmailGatedPattern(value) {
  const trimmed = value.trim();
  const hasEmailLike = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed) || /@/.test(trimmed);
  if (!hasEmailLike) return null;
  for (const { pattern, reason } of EVIDENCE_EMAIL_GATED_STRING_PATTERNS) {
    if (pattern.test(value)) {
      pattern.lastIndex = 0;
      return reason;
    }
    pattern.lastIndex = 0;
  }
  return null;
}

export function sanitizeForbiddenFieldPath(path) {
  return String(path)
    .split('.')
    .map((segment) => {
      const bracketIndex = segment.indexOf('[');
      const base = bracketIndex === -1 ? segment : segment.slice(0, bracketIndex);
      const suffix = bracketIndex === -1 ? '' : segment.slice(bracketIndex);
      if (isVariantSensitiveKey(base)) {
        return `[sensitive_key]${suffix}`;
      }
      return segment;
    })
    .join('.');
}

export function sanitizeForbiddenFieldPaths(paths) {
  if (!Array.isArray(paths)) return [];
  return paths.map((path) => sanitizeForbiddenFieldPath(path));
}

export function collectForbiddenEvidenceStringPatterns(value, fieldPath = '') {
  if (value === null || value === undefined) return [];
  if (typeof value === 'string') {
    const findings = [];
    const tokenReason = stringMatchesEvidenceTokenPattern(value);
    if (tokenReason) {
      findings.push(`${fieldPath}:${tokenReason}`);
    }
    const emailReason = stringMatchesEmailGatedPattern(value);
    if (emailReason) {
      findings.push(`${fieldPath}:${emailReason}`);
    }
    return findings;
  }
  if (Array.isArray(value)) {
    return value.flatMap((entry, index) =>
      collectForbiddenEvidenceStringPatterns(entry, `${fieldPath}[${index}]`),
    );
  }
  if (typeof value === 'object') {
    return Object.entries(value).flatMap(([key, nested]) =>
      collectForbiddenEvidenceStringPatterns(
        nested,
        fieldPath ? `${fieldPath}.${key}` : key,
      ),
    );
  }
  return [];
}

export function redactString(value) {
  if (typeof value !== 'string') return value;
  let out = value;
  for (const pattern of TOKEN_PATTERNS) {
    out = out.replace(pattern, '[REDACTED]');
  }
  return out;
}

export function redactObject(input, depth = 0, options = {}) {
  const omitSensitiveKeys = options.omitSensitiveKeys === true;
  if (depth > 8) return '[REDACTED_DEPTH]';
  if (input === null || input === undefined) return input;
  if (typeof input === 'string') return redactString(input);
  if (Array.isArray(input)) {
    return input.map((v) => redactObject(v, depth + 1, options));
  }
  if (typeof input !== 'object') return input;
  const out = {};
  for (const [key, val] of Object.entries(input)) {
    if (isSensitiveRedactionKey(key)) {
      if (omitSensitiveKeys) continue;
      out[key] = '[REDACTED]';
    } else {
      out[key] = redactObject(val, depth + 1, options);
    }
  }
  return out;
}