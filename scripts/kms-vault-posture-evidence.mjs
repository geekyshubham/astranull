#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { redactObject, redactString } from '../src/lib/redact.mjs';

const DEFAULT_OUT = 'output/kms-vault-posture-evidence.json';

const ALLOWED_ENVIRONMENTS = new Set(['production', 'staging']);
const ALLOWED_PROVIDER_CLASSES = new Set([
  'approved_vault',
  'cloud_hsm',
  'external_kms',
  'hybrid_kms_hsm',
]);

export const KMS_VAULT_POSTURE_INPUT_REQUIRED_FIELDS = Object.freeze([
  'environment',
  'evidence_uri',
  'vault_posture',
  'key_rotation_policy',
  'access_control_summary',
  'drill_reference',
  'security_signoff',
]);

const VAULT_POSTURE_FIELDS = Object.freeze([
  'provider_class',
  'vault_reference',
  'kms_key_references',
]);

const KEY_ROTATION_POLICY_FIELDS = Object.freeze([
  'policy_reference',
  'rotation_interval_days',
  'auto_rotation_enabled',
]);

const ACCESS_CONTROL_SUMMARY_FIELDS = Object.freeze([
  'rbac_reference',
  'break_glass_reference',
  'audit_logging_reference',
  'least_privilege_attested',
]);

const DRILL_REFERENCE_FIELDS = Object.freeze([
  'drill_id',
  'drill_evidence_uri',
  'completed_at',
]);

const SECURITY_SIGNOFF_FIELDS = Object.freeze([
  'owner',
  'role',
  'signed_at',
  'signoff_reference',
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
  'plaintext_secret',
  'plaintext_value',
  'private_key',
  'private_key_pem',
  'public_key_der_base64',
  'raw_body',
  'raw_dump',
  'raw_headers',
  'raw_log',
  'raw_logs',
  'raw_sql',
  'secret',
  'secret_value',
  'token',
]);

const PG_URL_RE = /postgres(?:ql)?:\/\/[^\s'"]+/gi;
const PEM_PRIVATE_KEY_RE = /-----BEGIN (?:RSA |EC |ENCRYPTED |)PRIVATE KEY-----/i;

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
    if (PEM_PRIVATE_KEY_RE.test(value)) {
      findings.push(`${fieldPath}:private_key_pem`);
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

function validateVaultPosture(vaultPosture) {
  const missing = validateNestedObject(vaultPosture, VAULT_POSTURE_FIELDS, 'vault_posture');
  if (isObject(vaultPosture)) {
    const providerClass = String(vaultPosture.provider_class ?? '').trim();
    if (!ALLOWED_PROVIDER_CLASSES.has(providerClass)) {
      missing.push('vault_posture.provider_class');
    }
    if (!Array.isArray(vaultPosture.kms_key_references) || vaultPosture.kms_key_references.length === 0) {
      if (!missing.includes('vault_posture.kms_key_references')) {
        missing.push('vault_posture.kms_key_references');
      }
    } else {
      vaultPosture.kms_key_references.forEach((entry, index) => {
        if (!hasValue(entry)) {
          missing.push(`vault_posture.kms_key_references[${index}]`);
        }
      });
    }
  }
  return missing;
}

function validateKeyRotationPolicy(policy) {
  const missing = validateNestedObject(policy, KEY_ROTATION_POLICY_FIELDS, 'key_rotation_policy');
  if (isObject(policy)) {
    const interval = policy.rotation_interval_days;
    if (!Number.isFinite(interval) || interval <= 0) {
      if (!missing.includes('key_rotation_policy.rotation_interval_days')) {
        missing.push('key_rotation_policy.rotation_interval_days');
      }
    }
    if (policy.auto_rotation_enabled !== true && policy.auto_rotation_enabled !== false) {
      missing.push('key_rotation_policy.auto_rotation_enabled');
    }
  }
  return missing;
}

function validateAccessControlSummary(summary) {
  const missing = validateNestedObject(
    summary,
    ACCESS_CONTROL_SUMMARY_FIELDS,
    'access_control_summary',
  );
  if (isObject(summary) && summary.least_privilege_attested !== true) {
    missing.push('access_control_summary.least_privilege_attested');
  }
  return missing;
}

function validateSecuritySignoff(signoff) {
  const missing = validateNestedObject(signoff, SECURITY_SIGNOFF_FIELDS, 'security_signoff');
  const missing_signoff = missing.some((field) => field.endsWith('.signoff_reference'));
  return { missing, missing_signoff };
}

function fieldSummary(fields) {
  return fields.length > 0 ? fields.join(', ') : 'none';
}

function summarizeVaultPosture(vaultPosture) {
  if (!isObject(vaultPosture)) {
    return {
      provider_class: null,
      vault_reference: null,
      kms_key_reference_count: 0,
      kms_key_references: [],
    };
  }
  const refs = Array.isArray(vaultPosture.kms_key_references)
    ? vaultPosture.kms_key_references.filter((entry) => hasValue(entry)).map(String)
    : [];
  return {
    provider_class: vaultPosture.provider_class ?? null,
    vault_reference: vaultPosture.vault_reference ?? null,
    kms_key_reference_count: refs.length,
    kms_key_references: refs,
  };
}

function summarizeKeyRotationPolicy(policy) {
  if (!isObject(policy)) return null;
  return {
    policy_reference: policy.policy_reference ?? null,
    rotation_interval_days: policy.rotation_interval_days ?? null,
    auto_rotation_enabled: policy.auto_rotation_enabled === true,
  };
}

function summarizeAccessControlSummary(summary) {
  if (!isObject(summary)) return null;
  return {
    rbac_reference: summary.rbac_reference ?? null,
    break_glass_reference: summary.break_glass_reference ?? null,
    audit_logging_reference: summary.audit_logging_reference ?? null,
    least_privilege_attested: summary.least_privilege_attested === true,
  };
}

function summarizeDrillReference(drill) {
  if (!isObject(drill)) return null;
  return {
    drill_id: drill.drill_id ?? null,
    drill_evidence_uri: drill.drill_evidence_uri ?? null,
    completed_at: drill.completed_at ?? null,
  };
}

function summarizeSecuritySignoff(signoff) {
  if (!isObject(signoff)) return null;
  return {
    owner: signoff.owner ?? null,
    role: signoff.role ?? null,
    signed_at: signoff.signed_at ?? null,
    signoff_reference: signoff.signoff_reference ?? null,
  };
}

/**
 * @param {unknown} evidence
 */
export function validateKmsVaultPostureEvidence(evidence) {
  const missing_fields = KMS_VAULT_POSTURE_INPUT_REQUIRED_FIELDS.filter(
    (field) => !hasValue(evidence?.[field]),
  );

  const environment = evidence?.environment;
  if (hasValue(environment) && !ALLOWED_ENVIRONMENTS.has(String(environment))) {
    missing_fields.push('environment');
  }

  missing_fields.push(...validateVaultPosture(evidence?.vault_posture));
  missing_fields.push(...validateKeyRotationPolicy(evidence?.key_rotation_policy));
  missing_fields.push(...validateAccessControlSummary(evidence?.access_control_summary));
  missing_fields.push(
    ...validateNestedObject(evidence?.drill_reference, DRILL_REFERENCE_FIELDS, 'drill_reference'),
  );

  const securitySignoff = validateSecuritySignoff(evidence?.security_signoff);
  missing_fields.push(...securitySignoff.missing);

  const forbidden_fields = [
    ...new Set([
      ...collectForbiddenFields(evidence),
      ...collectForbiddenStringPatterns(evidence),
    ]),
  ].sort();

  const uniqueMissing = [...new Set(missing_fields)].sort();

  const ok =
    uniqueMissing.length === 0
    && forbidden_fields.length === 0
    && !securitySignoff.missing_signoff;

  return {
    ok,
    missing_fields: uniqueMissing,
    forbidden_fields,
    missing_signoff: securitySignoff.missing_signoff,
  };
}

export function validateAndPrepareKmsVaultPostureEvidence(evidence) {
  const validation = validateKmsVaultPostureEvidence(evidence);
  if (validation.forbidden_fields.length > 0) {
    throw new Error(
      `KMS/vault posture evidence contains forbidden field(s): ${fieldSummary(validation.forbidden_fields)}`,
    );
  }
  if (validation.missing_signoff) {
    throw new Error('KMS/vault posture evidence missing security signoff reference');
  }
  if (validation.missing_fields.length > 0) {
    throw new Error(
      `KMS/vault posture evidence missing required field(s): ${fieldSummary(validation.missing_fields)}`,
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
    releaseId: null,
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
    else if (arg === '--release-id') opts.releaseId = next();
    else if (arg === '--validate-only') opts.validateOnly = true;
    else if (arg === '--help' || arg === '-h') opts.help = true;
    else throw new Error(`Unknown argument: ${arg}`);
  }
  if (!opts.help && !opts.input) throw new Error('--input is required');
  return opts;
}

function readPostureEvidence(inputPath) {
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(inputPath, 'utf8'));
  } catch {
    throw new Error(`kms-vault-posture-evidence: input is not valid JSON: ${inputPath}`);
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('kms-vault-posture-evidence: input must be a JSON object');
  }
  if (parsed.evidence && typeof parsed.evidence === 'object' && !Array.isArray(parsed.evidence)) {
    return parsed.evidence;
  }
  return parsed;
}

/**
 * @param {{ manifest: Record<string, unknown> }} input
 */
export function buildProductionKmsVaultPostureReleaseEvidence(input) {
  const { manifest } = input;
  return {
    schema_version: manifest.schema_version,
    artifact_type: manifest.artifact_type,
    created_at: manifest.created_at,
    validation: manifest.validation,
    environment: manifest.environment,
    vault_summary: manifest.vault_summary,
    key_rotation_policy: manifest.key_rotation_policy,
    access_control_summary: manifest.access_control_summary,
    drill_reference: manifest.drill_reference,
    security_signoff: manifest.security_signoff,
    evidence_uri: manifest.evidence_uri,
  };
}

/**
 * @param {{ evidence: Record<string, unknown>, validation: ReturnType<typeof validateKmsVaultPostureEvidence>, createdAt?: string, releaseId?: string | null }} input
 */
export function createKmsVaultPostureEvidenceManifest(input) {
  const { evidence, validation, createdAt, releaseId } = input;
  const redacted = redactObject(evidence);
  const created_at = createdAt ?? new Date().toISOString();

  const vault_summary = summarizeVaultPosture(redacted.vault_posture);
  const key_rotation_policy = summarizeKeyRotationPolicy(redacted.key_rotation_policy);
  const access_control_summary = summarizeAccessControlSummary(redacted.access_control_summary);
  const drill_reference = summarizeDrillReference(redacted.drill_reference);
  const security_signoff = summarizeSecuritySignoff(redacted.security_signoff);

  const manifest = {
    schema_version: 1,
    artifact_type: 'kms_vault_posture_evidence',
    created_at,
    validation: {
      ok: validation.ok,
      missing_fields: validation.missing_fields,
      forbidden_fields: validation.forbidden_fields,
    },
    release_id: releaseId ?? redacted.release_id ?? null,
    environment: redacted.environment ?? null,
    vault_summary,
    key_rotation_policy,
    access_control_summary,
    drill_reference,
    security_signoff,
    evidence_uri: redacted.evidence_uri ?? null,
    ...(typeof evidence?.notes === 'string' ? { notes: redactString(evidence.notes) } : {}),
    caveats: [
      'Metadata-only KMS/HSM/approved vault posture evidence; no plaintext, ciphertext, key material, tokens, passwords, database URLs, raw logs, or credentials.',
      'This validator does not contact cloud KMS, HSM, or vault APIs; operator custody URIs and signoff references must be validated out of band.',
      'Production release still requires live rotation drill execution, access-control review, and security approval outside this script.',
    ],
  };

  manifest.production_release_evidence = {
    kind: 'kms_vault_posture',
    evidence: buildProductionKmsVaultPostureReleaseEvidence({ manifest }),
  };

  return manifest;
}

export async function main(argv = process.argv.slice(2)) {
  const opts = parseArgs(argv);
  if (opts.help) {
    console.log(
      'Usage: node scripts/kms-vault-posture-evidence.mjs --input evidence.json [--out file] [--release-id rel] [--validate-only]',
    );
    return 0;
  }

  const evidence = readPostureEvidence(opts.input);
  const validation = validateKmsVaultPostureEvidence(evidence);
  const manifest = createKmsVaultPostureEvidenceManifest({
    evidence,
    validation,
    releaseId: opts.releaseId,
  });

  if (opts.validateOnly) {
    console.log(
      `kms-vault-posture-evidence: ${validation.ok ? 'ok' : 'failed'} (environment=${manifest.environment ?? 'none'})`,
    );
    return validation.ok ? 0 : 1;
  }

  mkdirSync(path.dirname(path.resolve(opts.out)), { recursive: true });
  writeFileSync(opts.out, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`kms-vault-posture-evidence: wrote ${opts.out}`);
  return validation.ok ? 0 : 1;
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(`kms-vault-posture-evidence: ${err.message}`);
      process.exit(1);
    },
  );
}