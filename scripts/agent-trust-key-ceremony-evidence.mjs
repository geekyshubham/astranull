#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { redactObject, redactString } from '../src/lib/redact.mjs';

const DEFAULT_OUT = 'output/agent-trust-key-ceremony-evidence.json';

export const AGENT_TRUST_KEY_CEREMONY_REQUIRED_FIELDS = Object.freeze([
  'drill_id',
  'environment',
  'tenant_id',
  'started_at',
  'completed_at',
  'signing_key_ceremony',
  'active_trust_key_registration',
  'staged_release_binding',
  'trust_key_rotation',
  'trust_key_revocation',
  'rollback_trust_behavior',
  'custody_uris',
  'operator_signoff',
  'security_signoff',
  'audit_event_ids',
]);

const SIGNING_KEY_CEREMONY_FIELDS = Object.freeze([
  'method',
  'signing_key_reference',
  'custody_uri',
]);

const ACTIVE_REGISTRATION_FIELDS = Object.freeze([
  'trust_key_id',
  'name',
  'fingerprint_sha256',
  'registration_reference',
]);

const STAGED_RELEASE_FIELDS = Object.freeze([
  'release_id',
  'signing_fingerprint_sha256',
  'rollout_percentage',
  'binding_verified',
  'binding_reference',
]);

const ROTATION_FIELDS = Object.freeze([
  'previous_trust_key_id',
  'new_trust_key_id',
  'previous_fingerprint_sha256',
  'new_fingerprint_sha256',
  'rotation_reference',
]);

const REVOCATION_FIELDS = Object.freeze([
  'revoked_trust_key_id',
  'fingerprint_sha256',
  'revocation_reference',
]);

const ROLLBACK_TRUST_FIELDS = Object.freeze([
  'scenario',
  'untrusted_signing_key_observed',
  'behavior_reference',
  'verified_at',
]);

const SIGNOFF_FIELDS = Object.freeze([
  'operator',
  'role',
  'signed_at',
  'signoff_reference',
]);

const ALLOWED_CEREMONY_METHODS = new Set(['generate', 'import']);

const FINGERPRINT_SHA256_RE = /^[a-f0-9]{64}$/;

const FORBIDDEN_KEYS = new Set([
  'api_key',
  'apikey',
  'auth_tag',
  'authentication_tag',
  'authorization',
  'body',
  'cipher_text',
  'ciphertext',
  'connection_string',
  'credential',
  'credentials',
  'database_url',
  'decrypted_value',
  'encrypted_value',
  'gcm_tag',
  'headers',
  'initialization_vector',
  'iv',
  'key_material',
  'log',
  'logs',
  'nonce',
  'password',
  'payload',
  'plaintext',
  'private_key',
  'private_key_pem',
  'private_key_der',
  'public_key_der',
  'public_key_der_base64',
  'public_key_pem',
  'raw_body',
  'raw_headers',
  'raw_log',
  'secret',
  'secret_value',
  'signing_key_pem',
  'signing_key_private',
  'token',
]);

const SECRET_STRING_PATTERNS = [
  /ast_v1\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){2}/,
  /svc_v1\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){2}/,
  /agc_v1\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){2}/,
  /Bearer\s+[A-Za-z0-9._-]+/i,
  /postgres(?:ql)?:\/\/[^\s'"]+/gi,
  /mongodb(\+srv)?:\/\/[^\s'"]+/gi,
  /https?:\/\/[^/\s'"]+:[^@\s'"]+@/i,
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
  /BEGIN PRIVATE KEY/,
];

function normalizeKey(key) {
  return key
    .replace(/([a-z])([A-Z])/g, '$1_$2')
    .replace(/[^A-Za-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase();
}

function hasValue(value) {
  if (value === null || value === undefined) return false;
  if (typeof value === 'string' && value.trim() === '') return false;
  if (Array.isArray(value) && value.length === 0) return false;
  return true;
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function collectForbiddenFields(value, fieldPath = '') {
  if (value === null || value === undefined || typeof value !== 'object') return [];
  const findings = [];
  if (Array.isArray(value)) {
    value.forEach((entry, index) => {
      findings.push(...collectForbiddenFields(entry, `${fieldPath}[${index}]`));
    });
    return findings;
  }
  for (const [key, nested] of Object.entries(value)) {
    const keyPath = fieldPath ? `${fieldPath}.${key}` : key;
    const normalized = normalizeKey(key);
    if (
      FORBIDDEN_KEYS.has(normalized)
      || normalized.startsWith('raw_')
      || normalized.endsWith('_secret')
      || normalized.endsWith('_credential')
      || normalized.includes('private_key')
      || normalized.includes('public_key_der')
    ) {
      findings.push(keyPath);
    }
    findings.push(...collectForbiddenFields(nested, keyPath));
  }
  return findings;
}

function collectForbiddenStringPatterns(value, fieldPath = '') {
  if (value === null || value === undefined) return [];
  if (typeof value === 'string') {
    const findings = [];
    for (const pattern of SECRET_STRING_PATTERNS) {
      if (pattern.test(value)) {
        pattern.lastIndex = 0;
        findings.push(`${fieldPath}:forbidden_pattern`);
        break;
      }
      pattern.lastIndex = 0;
    }
    return findings;
  }
  if (Array.isArray(value)) {
    return value.flatMap((entry, index) =>
      collectForbiddenStringPatterns(entry, `${fieldPath}[${index}]`),
    );
  }
  if (typeof value === 'object') {
    return Object.entries(value).flatMap(([key, nested]) =>
      collectForbiddenStringPatterns(nested, fieldPath ? `${fieldPath}.${key}` : key),
    );
  }
  return [];
}

function validateNestedObject(obj, requiredFields, prefix) {
  const missing = [];
  if (!isObject(obj)) {
    missing.push(prefix);
    return missing;
  }
  for (const field of requiredFields) {
    if (!hasValue(obj[field])) {
      missing.push(`${prefix}.${field}`);
    }
  }
  return missing;
}

function validateFingerprint(value, fieldPath, missing) {
  if (!hasValue(value)) {
    missing.push(fieldPath);
    return;
  }
  if (typeof value !== 'string' || !FINGERPRINT_SHA256_RE.test(value)) {
    missing.push(fieldPath);
  }
}

function validateSignoff(signoff, prefix) {
  const missing = validateNestedObject(signoff, SIGNOFF_FIELDS, prefix);
  return { missing, missing_signoff: missing.some((f) => f.endsWith('.signoff_reference')) };
}

function fieldSummary(fields) {
  return fields.length > 0 ? fields.join(', ') : 'none';
}

/**
 * @param {unknown} evidence
 */
export function validateAgentTrustKeyCeremonyEvidence(evidence) {
  const missing_fields = AGENT_TRUST_KEY_CEREMONY_REQUIRED_FIELDS.filter(
    (field) => !hasValue(evidence?.[field]),
  );

  const forbidden_fields = [
    ...new Set([
      ...collectForbiddenFields(evidence),
      ...collectForbiddenStringPatterns(evidence),
    ]),
  ].sort();

  missing_fields.push(
    ...validateNestedObject(evidence?.signing_key_ceremony, SIGNING_KEY_CEREMONY_FIELDS, 'signing_key_ceremony'),
  );
  if (isObject(evidence?.signing_key_ceremony)) {
    const method = evidence.signing_key_ceremony.method;
    if (!ALLOWED_CEREMONY_METHODS.has(method)) {
      missing_fields.push('signing_key_ceremony.method');
    }
  }

  missing_fields.push(
    ...validateNestedObject(
      evidence?.active_trust_key_registration,
      ACTIVE_REGISTRATION_FIELDS,
      'active_trust_key_registration',
    ),
  );
  validateFingerprint(
    evidence?.active_trust_key_registration?.fingerprint_sha256,
    'active_trust_key_registration.fingerprint_sha256',
    missing_fields,
  );

  missing_fields.push(
    ...validateNestedObject(evidence?.staged_release_binding, STAGED_RELEASE_FIELDS, 'staged_release_binding'),
  );
  validateFingerprint(
    evidence?.staged_release_binding?.signing_fingerprint_sha256,
    'staged_release_binding.signing_fingerprint_sha256',
    missing_fields,
  );
  if (isObject(evidence?.staged_release_binding)) {
    const pct = evidence.staged_release_binding.rollout_percentage;
    if (!Number.isFinite(pct) || pct < 0 || pct > 100) {
      missing_fields.push('staged_release_binding.rollout_percentage');
    }
    if (evidence.staged_release_binding.binding_verified !== true) {
      missing_fields.push('staged_release_binding.binding_verified');
    }
  }

  missing_fields.push(
    ...validateNestedObject(evidence?.trust_key_rotation, ROTATION_FIELDS, 'trust_key_rotation'),
  );
  validateFingerprint(
    evidence?.trust_key_rotation?.previous_fingerprint_sha256,
    'trust_key_rotation.previous_fingerprint_sha256',
    missing_fields,
  );
  validateFingerprint(
    evidence?.trust_key_rotation?.new_fingerprint_sha256,
    'trust_key_rotation.new_fingerprint_sha256',
    missing_fields,
  );

  missing_fields.push(
    ...validateNestedObject(evidence?.trust_key_revocation, REVOCATION_FIELDS, 'trust_key_revocation'),
  );
  validateFingerprint(
    evidence?.trust_key_revocation?.fingerprint_sha256,
    'trust_key_revocation.fingerprint_sha256',
    missing_fields,
  );

  missing_fields.push(
    ...validateNestedObject(evidence?.rollback_trust_behavior, ROLLBACK_TRUST_FIELDS, 'rollback_trust_behavior'),
  );
  if (isObject(evidence?.rollback_trust_behavior)) {
    if (evidence.rollback_trust_behavior.untrusted_signing_key_observed !== true) {
      missing_fields.push('rollback_trust_behavior.untrusted_signing_key_observed');
    }
  }

  const operatorSignoff = validateSignoff(evidence?.operator_signoff, 'operator_signoff');
  const securitySignoff = validateSignoff(evidence?.security_signoff, 'security_signoff');
  missing_fields.push(...operatorSignoff.missing, ...securitySignoff.missing);

  if (!Array.isArray(evidence?.audit_event_ids) || evidence.audit_event_ids.length === 0) {
    if (!missing_fields.includes('audit_event_ids')) {
      missing_fields.push('audit_event_ids');
    }
  }

  if (!Array.isArray(evidence?.custody_uris) || evidence.custody_uris.length === 0) {
    if (!missing_fields.includes('custody_uris')) {
      missing_fields.push('custody_uris');
    }
  }

  const missing_signoff =
    operatorSignoff.missing_signoff
    || securitySignoff.missing_signoff
    || operatorSignoff.missing.length > 0
    || securitySignoff.missing.length > 0;

  const uniqueMissing = [...new Set(missing_fields)].sort();

  const ok =
    uniqueMissing.length === 0
    && forbidden_fields.length === 0
    && !missing_signoff;

  return {
    ok,
    missing_fields: uniqueMissing,
    forbidden_fields,
    missing_signoff,
  };
}

export function validateAndPrepareAgentTrustKeyCeremonyEvidence(evidence) {
  const validation = validateAgentTrustKeyCeremonyEvidence(evidence);
  if (validation.forbidden_fields.length > 0) {
    throw new Error(
      `Agent trust-key ceremony evidence contains forbidden field(s): ${fieldSummary(validation.forbidden_fields)}`,
    );
  }
  if (validation.missing_signoff) {
    throw new Error('Agent trust-key ceremony evidence missing operator or security signoff');
  }
  if (validation.missing_fields.length > 0) {
    throw new Error(
      `Agent trust-key ceremony evidence missing required field(s): ${fieldSummary(validation.missing_fields)}`,
    );
  }
  return {
    evidence: redactObject(evidence),
    validation,
    ...(typeof evidence?.notes === 'string' ? { notes: redactString(evidence.notes) } : {}),
  };
}

export function parseArgs(argv = []) {
  const opts = {
    input: null,
    out: DEFAULT_OUT,
    validateOnly: false,
    help: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = () => {
      i += 1;
      if (i >= argv.length) throw new Error(`Missing value for ${arg}`);
      return argv[i];
    };
    if (arg === '--input') opts.input = next();
    else if (arg === '--out') opts.out = next();
    else if (arg === '--validate-only') opts.validateOnly = true;
    else if (arg === '--help' || arg === '-h') opts.help = true;
    else throw new Error(`Unknown argument: ${arg}`);
  }
  if (!opts.help && !opts.input) throw new Error('--input is required');
  return opts;
}

function readCeremonyEvidence(inputPath) {
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(inputPath, 'utf8'));
  } catch {
    throw new Error(`agent-trust-key-ceremony-evidence: input is not valid JSON: ${inputPath}`);
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('agent-trust-key-ceremony-evidence: input must be a JSON object');
  }
  if (parsed.evidence && typeof parsed.evidence === 'object' && !Array.isArray(parsed.evidence)) {
    return parsed.evidence;
  }
  return parsed;
}

/**
 * @param {{ evidence: Record<string, unknown>, validation: ReturnType<typeof validateAgentTrustKeyCeremonyEvidence>, createdAt?: string }} input
 */
export function createAgentTrustKeyCeremonyEvidenceManifest(input) {
  const { evidence, validation, createdAt } = input;
  const redacted = redactObject(evidence);
  return {
    schema_version: 1,
    artifact_type: 'agent_trust_key_ceremony_evidence',
    created_at: createdAt ?? new Date().toISOString(),
    validation: {
      ok: validation.ok,
      missing_fields: validation.missing_fields,
      forbidden_fields: validation.forbidden_fields,
      missing_signoff: validation.missing_signoff,
    },
    ceremony_summary: {
      drill_id: redacted.drill_id ?? null,
      environment: redacted.environment ?? null,
      tenant_id: redacted.tenant_id ?? null,
      signing_key_method: redacted.signing_key_ceremony?.method ?? null,
      signing_key_reference: redacted.signing_key_ceremony?.signing_key_reference ?? null,
      active_trust_key_id: redacted.active_trust_key_registration?.trust_key_id ?? null,
      active_fingerprint_sha256: redacted.active_trust_key_registration?.fingerprint_sha256 ?? null,
      staged_release_id: redacted.staged_release_binding?.release_id ?? null,
      rollout_percentage: redacted.staged_release_binding?.rollout_percentage ?? null,
      rotation_previous_id: redacted.trust_key_rotation?.previous_trust_key_id ?? null,
      rotation_new_id: redacted.trust_key_rotation?.new_trust_key_id ?? null,
      revoked_trust_key_id: redacted.trust_key_revocation?.revoked_trust_key_id ?? null,
      rollback_scenario: redacted.rollback_trust_behavior?.scenario ?? null,
      custody_uri_count: Array.isArray(redacted.custody_uris) ? redacted.custody_uris.length : 0,
      audit_event_count: Array.isArray(redacted.audit_event_ids) ? redacted.audit_event_ids.length : 0,
    },
    custody_uris: Array.isArray(redacted.custody_uris) ? redacted.custody_uris : [],
    ...(typeof evidence?.notes === 'string' ? { notes: redactString(evidence.notes) } : {}),
    caveats: [
      'Metadata-only agent update trust-key ceremony, rotation, and revocation drill evidence.',
      'No private keys, DER/PEM key material, tokens, passwords, database URLs, raw logs, or HTTP bodies.',
      'Production promotion still requires live drill execution, installer/update-daemon trust-key enforcement, and security signoff outside this validator.',
    ],
  };
}

export async function main(argv = process.argv.slice(2)) {
  const opts = parseArgs(argv);
  if (opts.help) {
    console.log(
      'Usage: node scripts/agent-trust-key-ceremony-evidence.mjs --input ceremony.json [--out file] [--validate-only]',
    );
    return 0;
  }

  const evidence = readCeremonyEvidence(opts.input);
  const validation = validateAgentTrustKeyCeremonyEvidence(evidence);
  const manifest = createAgentTrustKeyCeremonyEvidenceManifest({ evidence, validation });

  if (opts.validateOnly) {
    console.log(
      `agent-trust-key-ceremony-evidence: ${validation.ok ? 'ok' : 'failed'} (drill_id=${manifest.ceremony_summary.drill_id ?? 'none'})`,
    );
    return validation.ok ? 0 : 1;
  }

  mkdirSync(path.dirname(path.resolve(opts.out)), { recursive: true });
  writeFileSync(opts.out, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`agent-trust-key-ceremony-evidence: wrote ${opts.out}`);
  return validation.ok ? 0 : 1;
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(`agent-trust-key-ceremony-evidence: ${err.message}`);
      process.exit(1);
    },
  );
}