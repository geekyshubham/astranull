#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { redactObject, redactString } from '../src/lib/redact.mjs';

const DEFAULT_OUT = 'output/secret-rotation-drill-evidence.json';

export const SECRET_ROTATION_DRILL_REQUIRED_FIELDS = Object.freeze([
  'drill_id',
  'environment',
  'started_at',
  'completed_at',
  'key_rotation',
  'tenant_count',
  'envelope_rekey',
  'failed_rotations',
  'rollback_plan',
  'operator_signoff',
  'security_signoff',
  'audit_event_ids',
  'zero_plaintext_exposure',
]);

const KEY_ROTATION_REQUIRED_FIELDS = Object.freeze([
  'key_reference_before',
  'key_reference_after',
  'provider_reference',
]);

const ENVELOPE_REKEY_REQUIRED_FIELDS = Object.freeze([
  'envelopes_total',
  'envelopes_rekeyed',
]);

const ROLLBACK_PLAN_REQUIRED_FIELDS = Object.freeze([
  'plan_reference',
  'rollback_tested',
  'rollback_test_reference',
]);

const SIGNOFF_REQUIRED_FIELDS = Object.freeze([
  'operator',
  'role',
  'signed_at',
  'signoff_reference',
]);

const ZERO_PLAINTEXT_REQUIRED_FIELDS = Object.freeze([
  'attested',
  'attestation_reference',
  'attested_at',
  'attested_by',
]);

const FAILED_ROTATION_ENTRY_FIELDS = Object.freeze([
  'envelope_reference',
  'failure_code',
  'accepted',
]);

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
  'envelope_ciphertext',
  'envelope_json',
  'gcm_tag',
  'headers',
  'initialization_vector',
  'iv',
  'log',
  'logs',
  'nonce',
  'password',
  'payload',
  'plaintext',
  'plaintext_secret',
  'plaintext_value',
  'raw_body',
  'raw_headers',
  'raw_log',
  'secret',
  'secret_value',
  'token',
]);

const PG_URL_RE = /postgres(?:ql)?:\/\/[^\s'"]+/gi;

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
    if (PG_URL_RE.test(value)) {
      PG_URL_RE.lastIndex = 0;
      findings.push(`${fieldPath}:database_url_pattern`);
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

function validateSignoff(signoff, prefix) {
  const missing = validateNestedObject(signoff, SIGNOFF_REQUIRED_FIELDS, prefix);
  return { missing, missing_signoff: missing.some((field) => field.endsWith('.signoff_reference')) };
}

function validateFailedRotations(entries) {
  const missing = [];
  const unaccepted = [];
  if (!Array.isArray(entries)) {
    return { missing: ['failed_rotations'], unaccepted_failed_rotations: [] };
  }
  entries.forEach((entry, index) => {
    if (!isObject(entry)) {
      missing.push(`failed_rotations[${index}]`);
      unaccepted.push({ index, reason: 'invalid_entry' });
      return;
    }
    for (const field of FAILED_ROTATION_ENTRY_FIELDS) {
      if (field === 'accepted') {
        if (entry.accepted !== true && entry.accepted !== false) {
          missing.push(`failed_rotations[${index}].accepted`);
        }
        continue;
      }
      if (!hasValue(entry[field])) {
        missing.push(`failed_rotations[${index}].${field}`);
      }
    }
    if (entry.accepted === true && !hasValue(entry.acceptance_reference)) {
      missing.push(`failed_rotations[${index}].acceptance_reference`);
    }
    if (entry.accepted !== true) {
      unaccepted.push({
        index,
        envelope_reference: entry.envelope_reference ?? null,
        failure_code: entry.failure_code ?? null,
      });
    }
  });
  return { missing, unaccepted_failed_rotations: unaccepted };
}

function validateZeroPlaintextExposure(attestation) {
  const missing = validateNestedObject(
    attestation,
    ZERO_PLAINTEXT_REQUIRED_FIELDS,
    'zero_plaintext_exposure',
  );
  let attestation_invalid = false;
  if (isObject(attestation) && attestation.attested !== true) {
    attestation_invalid = true;
    if (!missing.includes('zero_plaintext_exposure.attested')) {
      missing.push('zero_plaintext_exposure.attested');
    }
  }
  return { missing, attestation_invalid };
}

function fieldSummary(fields) {
  return fields.length > 0 ? fields.join(', ') : 'none';
}

/**
 * @param {unknown} evidence
 */
export function validateSecretRotationDrillEvidence(evidence) {
  const missing_fields = SECRET_ROTATION_DRILL_REQUIRED_FIELDS.filter(
    (field) => !hasValue(evidence?.[field]),
  );

  if (Array.isArray(evidence?.failed_rotations) && evidence.failed_rotations.length === 0) {
    const idx = missing_fields.indexOf('failed_rotations');
    if (idx >= 0) missing_fields.splice(idx, 1);
  }

  const forbidden_fields = [
    ...new Set([
      ...collectForbiddenFields(evidence),
      ...collectForbiddenStringPatterns(evidence),
    ]),
  ].sort();

  missing_fields.push(
    ...validateNestedObject(evidence?.key_rotation, KEY_ROTATION_REQUIRED_FIELDS, 'key_rotation'),
  );
  missing_fields.push(
    ...validateNestedObject(evidence?.envelope_rekey, ENVELOPE_REKEY_REQUIRED_FIELDS, 'envelope_rekey'),
  );
  missing_fields.push(
    ...validateNestedObject(evidence?.rollback_plan, ROLLBACK_PLAN_REQUIRED_FIELDS, 'rollback_plan'),
  );

  const operatorSignoff = validateSignoff(evidence?.operator_signoff, 'operator_signoff');
  const securitySignoff = validateSignoff(evidence?.security_signoff, 'security_signoff');
  missing_fields.push(...operatorSignoff.missing, ...securitySignoff.missing);

  const failedRotations = validateFailedRotations(evidence?.failed_rotations);
  missing_fields.push(...failedRotations.missing);

  const zeroPlaintext = validateZeroPlaintextExposure(evidence?.zero_plaintext_exposure);
  missing_fields.push(...zeroPlaintext.missing);

  const tenantCount = evidence?.tenant_count;
  if (tenantCount !== undefined && (!Number.isFinite(tenantCount) || tenantCount < 0)) {
    missing_fields.push('tenant_count');
  }

  const envelopeRekey = evidence?.envelope_rekey;
  if (isObject(envelopeRekey)) {
    const { envelopes_total: total, envelopes_rekeyed: rekeyed } = envelopeRekey;
    if (
      Number.isFinite(total)
      && Number.isFinite(rekeyed)
      && rekeyed > total
    ) {
      missing_fields.push('envelope_rekey.envelopes_rekeyed');
    }
  }

  const missing_signoff =
    operatorSignoff.missing_signoff
    || securitySignoff.missing_signoff
    || operatorSignoff.missing.length > 0
    || securitySignoff.missing.length > 0;

  const unaccepted_failed_rotations = failedRotations.unaccepted_failed_rotations;
  const has_unaccepted_failures = unaccepted_failed_rotations.length > 0;

  const uniqueMissing = [...new Set(missing_fields)].sort();

  const ok =
    uniqueMissing.length === 0
    && forbidden_fields.length === 0
    && !missing_signoff
    && !has_unaccepted_failures
    && !zeroPlaintext.attestation_invalid;

  return {
    ok,
    missing_fields: uniqueMissing,
    forbidden_fields,
    missing_signoff,
    unaccepted_failed_rotations,
    has_unaccepted_failures,
    zero_plaintext_attestation_invalid: zeroPlaintext.attestation_invalid,
  };
}

export function validateAndPrepareSecretRotationDrillEvidence(evidence) {
  const validation = validateSecretRotationDrillEvidence(evidence);
  if (validation.forbidden_fields.length > 0) {
    throw new Error(
      `Secret rotation drill evidence contains forbidden field(s): ${fieldSummary(validation.forbidden_fields)}`,
    );
  }
  if (validation.missing_signoff) {
    throw new Error('Secret rotation drill evidence missing operator or security signoff');
  }
  if (validation.missing_fields.length > 0) {
    throw new Error(
      `Secret rotation drill evidence missing required field(s): ${fieldSummary(validation.missing_fields)}`,
    );
  }
  if (validation.has_unaccepted_failures) {
    throw new Error(
      `Secret rotation drill has unaccepted failed rotation(s): ${validation.unaccepted_failed_rotations.length}`,
    );
  }
  if (validation.zero_plaintext_attestation_invalid) {
    throw new Error('zero_plaintext_exposure.attested must be true');
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

function readDrillEvidence(inputPath) {
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(inputPath, 'utf8'));
  } catch {
    throw new Error(`secret-rotation-drill-evidence: input is not valid JSON: ${inputPath}`);
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('secret-rotation-drill-evidence: input must be a JSON object');
  }
  if (parsed.evidence && typeof parsed.evidence === 'object' && !Array.isArray(parsed.evidence)) {
    return parsed.evidence;
  }
  return parsed;
}

/**
 * @param {{ evidence: Record<string, unknown>, validation: ReturnType<typeof validateSecretRotationDrillEvidence>, createdAt?: string }} input
 */
export function createSecretRotationDrillEvidenceManifest(input) {
  const { evidence, validation, createdAt } = input;
  const redacted = redactObject(evidence);
  const failedCount = Array.isArray(redacted.failed_rotations)
    ? redacted.failed_rotations.length
    : 0;
  return {
    schema_version: 1,
    artifact_type: 'secret_rotation_drill_evidence',
    created_at: createdAt ?? new Date().toISOString(),
    validation: {
      ok: validation.ok,
      missing_fields: validation.missing_fields,
      forbidden_fields: validation.forbidden_fields,
      missing_signoff: validation.missing_signoff,
      unaccepted_failed_rotations: validation.unaccepted_failed_rotations,
      has_unaccepted_failures: validation.has_unaccepted_failures,
      zero_plaintext_attestation_invalid: validation.zero_plaintext_attestation_invalid,
    },
    drill_summary: {
      drill_id: redacted.drill_id ?? null,
      environment: redacted.environment ?? null,
      tenant_count: redacted.tenant_count ?? null,
      key_reference_before: redacted.key_rotation?.key_reference_before ?? null,
      key_reference_after: redacted.key_rotation?.key_reference_after ?? null,
      provider_reference: redacted.key_rotation?.provider_reference ?? null,
      envelopes_total: redacted.envelope_rekey?.envelopes_total ?? null,
      envelopes_rekeyed: redacted.envelope_rekey?.envelopes_rekeyed ?? null,
      failed_rotation_count: failedCount,
      rollback_plan_reference: redacted.rollback_plan?.plan_reference ?? null,
      rollback_tested: redacted.rollback_plan?.rollback_tested ?? null,
      audit_event_count: Array.isArray(redacted.audit_event_ids)
        ? redacted.audit_event_ids.length
        : 0,
      zero_plaintext_attested: redacted.zero_plaintext_exposure?.attested === true,
    },
    ...(typeof evidence?.notes === 'string' ? { notes: redactString(evidence.notes) } : {}),
    caveats: [
      'Metadata-only secret/envelope rotation drill evidence; no plaintext, ciphertext, auth tags, database URLs, logs, or credentials.',
      'Production signoff still requires live KMS/vault operator evidence, envelope re-key verification, and security approval outside this validator.',
    ],
  };
}

export async function main(argv = process.argv.slice(2)) {
  const opts = parseArgs(argv);
  if (opts.help) {
    console.log(
      'Usage: node scripts/secret-rotation-drill-evidence.mjs --input drill.json [--out file] [--validate-only]',
    );
    return 0;
  }

  const evidence = readDrillEvidence(opts.input);
  const validation = validateSecretRotationDrillEvidence(evidence);
  const manifest = createSecretRotationDrillEvidenceManifest({ evidence, validation });

  if (opts.validateOnly) {
    console.log(
      `secret-rotation-drill-evidence: ${validation.ok ? 'ok' : 'failed'} (drill_id=${manifest.drill_summary.drill_id ?? 'none'})`,
    );
    return validation.ok ? 0 : 1;
  }

  mkdirSync(path.dirname(path.resolve(opts.out)), { recursive: true });
  writeFileSync(opts.out, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`secret-rotation-drill-evidence: wrote ${opts.out}`);
  return validation.ok ? 0 : 1;
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(`secret-rotation-drill-evidence: ${err.message}`);
      process.exit(1);
    },
  );
}