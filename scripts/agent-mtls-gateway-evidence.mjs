#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { redactObject, redactString } from '../src/lib/redact.mjs';

const DEFAULT_OUT = 'output/agent-mtls-gateway-evidence.json';

export const AGENT_MTLS_GATEWAY_REQUIRED_FIELDS = Object.freeze([
  'release_id',
  'environment',
  'gateway_proxy',
  'client_certificate_issuance',
  'fingerprint_forwarding',
  'header_spoofing_protection',
  'agent_registration_heartbeat_proof',
  'rotation_revocation_drill',
  'security_signoff',
]);

const GATEWAY_PROXY_FIELDS = Object.freeze([
  'gateway_reference',
  'proxy_type',
  'tls_termination_point',
  'validated_at',
]);

const CLIENT_CERT_ISSUANCE_FIELDS = Object.freeze([
  'issuer_reference',
  'issuance_runbook_reference',
  'validated_at',
]);

const FINGERPRINT_FORWARDING_FIELDS = Object.freeze([
  'allowed_header_names',
  'gateway_sets_fingerprint_header',
  'strips_untrusted_client_headers',
  'control_reference',
  'validated_at',
]);

const HEADER_SPOOFING_FIELDS = Object.freeze([
  'rejects_untrusted_fingerprint_headers',
  'trusted_proxy_hop_policy',
  'control_reference',
  'validated_at',
]);

const REGISTRATION_HEARTBEAT_FIELDS = Object.freeze([
  'staging_agent_reference',
  'registration_evidence_uri',
  'heartbeat_evidence_uri',
  'fingerprint_match_confirmed',
  'validated_at',
]);

const ROTATION_REVOCATION_FIELDS = Object.freeze([
  'drill_reference',
  'rotation_tested',
  'revocation_tested',
  'validated_at',
]);

const SECURITY_SIGNOFF_FIELDS = Object.freeze([
  'owner',
  'role',
  'signed_at',
  'signoff_reference',
]);

export const ALLOWED_FINGERPRINT_HEADER_NAMES = Object.freeze([
  'x-client-cert-fingerprint',
  'x-astranull-client-cert-fingerprint',
  'x-forwarded-client-cert-sha256',
]);

const FORBIDDEN_KEYS = new Set([
  'api_key',
  'apikey',
  'auth_tag',
  'authorization',
  'body',
  'bootstrap_token',
  'cert_pem',
  'certificate_pem',
  'cipher_text',
  'ciphertext',
  'client_cert',
  'client_certificate_body',
  'connection_string',
  'credential',
  'credentials',
  'database_url',
  'decrypted_value',
  'encrypted_value',
  'headers',
  'initialization_vector',
  'iv',
  'log',
  'logs',
  'nonce',
  'password',
  'payload',
  'pem',
  'plaintext',
  'private_key',
  'raw_body',
  'raw_headers',
  'raw_log',
  'secret',
  'secret_value',
  'token',
]);

const PG_URL_RE = /postgres(?:ql)?:\/\/[^\s'"]+/gi;
const PEM_PRIVATE_KEY_RE = /-----BEGIN (?:RSA |EC |ENCRYPTED |)PRIVATE KEY-----/i;
const PEM_CERT_RE = /-----BEGIN CERTIFICATE-----/i;

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
      || normalized.endsWith('_pem')
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
    if (PEM_CERT_RE.test(value)) {
      findings.push(`${fieldPath}:certificate_pem`);
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

function normalizeHeaderName(name) {
  return typeof name === 'string' ? name.trim().toLowerCase() : '';
}

function validateFingerprintForwarding(forwarding) {
  const missing = validateNestedObject(
    forwarding,
    FINGERPRINT_FORWARDING_FIELDS,
    'fingerprint_forwarding',
  );
  const invalid_headers = [];
  if (isObject(forwarding) && Array.isArray(forwarding.allowed_header_names)) {
    const allowedSet = new Set(ALLOWED_FINGERPRINT_HEADER_NAMES);
    forwarding.allowed_header_names.forEach((name, index) => {
      const normalized = normalizeHeaderName(name);
      if (!allowedSet.has(normalized)) {
        invalid_headers.push({
          index,
          header_name: typeof name === 'string' ? name : String(name),
          reason: 'not_platform_allowed_header',
        });
      }
    });
    if (forwarding.gateway_sets_fingerprint_header !== true) {
      missing.push('fingerprint_forwarding.gateway_sets_fingerprint_header');
    }
    if (forwarding.strips_untrusted_client_headers !== true) {
      missing.push('fingerprint_forwarding.strips_untrusted_client_headers');
    }
  }
  return { missing, invalid_headers };
}

function validateHeaderSpoofingProtection(protection) {
  const missing = validateNestedObject(
    protection,
    HEADER_SPOOFING_FIELDS,
    'header_spoofing_protection',
  );
  if (isObject(protection) && protection.rejects_untrusted_fingerprint_headers !== true) {
    missing.push('header_spoofing_protection.rejects_untrusted_fingerprint_headers');
  }
  return { missing };
}

function validateRegistrationHeartbeat(proof) {
  const missing = validateNestedObject(
    proof,
    REGISTRATION_HEARTBEAT_FIELDS,
    'agent_registration_heartbeat_proof',
  );
  if (isObject(proof) && proof.fingerprint_match_confirmed !== true) {
    missing.push('agent_registration_heartbeat_proof.fingerprint_match_confirmed');
  }
  return { missing };
}

function validateRotationRevocation(drill) {
  const missing = validateNestedObject(
    drill,
    ROTATION_REVOCATION_FIELDS,
    'rotation_revocation_drill',
  );
  if (isObject(drill)) {
    if (drill.rotation_tested !== true) {
      missing.push('rotation_revocation_drill.rotation_tested');
    }
    if (drill.revocation_tested !== true) {
      missing.push('rotation_revocation_drill.revocation_tested');
    }
  }
  return { missing };
}

function validateSecuritySignoff(signoff) {
  return validateNestedObject(signoff, SECURITY_SIGNOFF_FIELDS, 'security_signoff');
}

function fieldSummary(fields) {
  return fields.length > 0 ? fields.join(', ') : 'none';
}

/**
 * @param {unknown} evidence
 */
export function validateAgentMtlsGatewayEvidence(evidence) {
  const missing_fields = AGENT_MTLS_GATEWAY_REQUIRED_FIELDS.filter(
    (field) => !hasValue(evidence?.[field]),
  );

  missing_fields.push(
    ...validateNestedObject(evidence?.gateway_proxy, GATEWAY_PROXY_FIELDS, 'gateway_proxy'),
  );
  missing_fields.push(
    ...validateNestedObject(
      evidence?.client_certificate_issuance,
      CLIENT_CERT_ISSUANCE_FIELDS,
      'client_certificate_issuance',
    ),
  );

  const fingerprintForwarding = validateFingerprintForwarding(evidence?.fingerprint_forwarding);
  missing_fields.push(...fingerprintForwarding.missing);

  const headerSpoofing = validateHeaderSpoofingProtection(evidence?.header_spoofing_protection);
  missing_fields.push(...headerSpoofing.missing);

  const registrationProof = validateRegistrationHeartbeat(
    evidence?.agent_registration_heartbeat_proof,
  );
  missing_fields.push(...registrationProof.missing);

  const rotationDrill = validateRotationRevocation(evidence?.rotation_revocation_drill);
  missing_fields.push(...rotationDrill.missing);

  missing_fields.push(...validateSecuritySignoff(evidence?.security_signoff));

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
    && fingerprintForwarding.invalid_headers.length === 0;

  return {
    ok,
    missing_fields: uniqueMissing,
    forbidden_fields,
    invalid_fingerprint_headers: fingerprintForwarding.invalid_headers,
  };
}

export function validateAndPrepareAgentMtlsGatewayEvidence(evidence) {
  const validation = validateAgentMtlsGatewayEvidence(evidence);
  if (validation.forbidden_fields.length > 0) {
    throw new Error(
      `Agent mTLS gateway evidence contains forbidden field(s): ${fieldSummary(validation.forbidden_fields)}`,
    );
  }
  if (validation.invalid_fingerprint_headers.length > 0) {
    const detail = validation.invalid_fingerprint_headers
      .map((entry) => `${entry.header_name}:${entry.reason}`)
      .join('; ');
    throw new Error(`Invalid fingerprint forwarding header name(s): ${detail}`);
  }
  if (validation.missing_fields.length > 0) {
    throw new Error(
      `Agent mTLS gateway evidence missing required field(s): ${fieldSummary(validation.missing_fields)}`,
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

function readEvidence(inputPath) {
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(inputPath, 'utf8'));
  } catch {
    throw new Error(`agent-mtls-gateway-evidence: input is not valid JSON: ${inputPath}`);
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('agent-mtls-gateway-evidence: input must be a JSON object');
  }
  if (parsed.evidence && typeof parsed.evidence === 'object' && !Array.isArray(parsed.evidence)) {
    return parsed.evidence;
  }
  return parsed;
}

/**
 * @param {{ evidence: Record<string, unknown>, validation: ReturnType<typeof validateAgentMtlsGatewayEvidence>, createdAt?: string }} input
 */
export function createAgentMtlsGatewayEvidenceManifest(input) {
  const { evidence, validation, createdAt } = input;
  const redacted = redactObject(evidence);
  return {
    schema_version: 1,
    artifact_type: 'agent_mtls_gateway_evidence',
    created_at: createdAt ?? new Date().toISOString(),
    validation: {
      ok: validation.ok,
      missing_fields: validation.missing_fields,
      forbidden_fields: validation.forbidden_fields,
      invalid_fingerprint_headers: validation.invalid_fingerprint_headers,
    },
    release_id: redacted.release_id ?? null,
    environment: redacted.environment ?? null,
    gateway_summary: {
      gateway_reference: redacted.gateway_proxy?.gateway_reference ?? null,
      proxy_type: redacted.gateway_proxy?.proxy_type ?? null,
      tls_termination_point: redacted.gateway_proxy?.tls_termination_point ?? null,
    },
    issuance_summary: {
      issuer_reference: redacted.client_certificate_issuance?.issuer_reference ?? null,
      issuance_runbook_reference:
        redacted.client_certificate_issuance?.issuance_runbook_reference ?? null,
    },
    fingerprint_forwarding_summary: {
      allowed_header_names: redacted.fingerprint_forwarding?.allowed_header_names ?? [],
      control_reference: redacted.fingerprint_forwarding?.control_reference ?? null,
    },
    header_spoofing_summary: {
      trusted_proxy_hop_policy:
        redacted.header_spoofing_protection?.trusted_proxy_hop_policy ?? null,
      control_reference: redacted.header_spoofing_protection?.control_reference ?? null,
    },
    staging_proof_summary: {
      staging_agent_reference:
        redacted.agent_registration_heartbeat_proof?.staging_agent_reference ?? null,
      registration_evidence_uri:
        redacted.agent_registration_heartbeat_proof?.registration_evidence_uri ?? null,
      heartbeat_evidence_uri:
        redacted.agent_registration_heartbeat_proof?.heartbeat_evidence_uri ?? null,
      fingerprint_match_confirmed:
        redacted.agent_registration_heartbeat_proof?.fingerprint_match_confirmed === true,
    },
    rotation_revocation_summary: {
      drill_reference: redacted.rotation_revocation_drill?.drill_reference ?? null,
      rotation_tested: redacted.rotation_revocation_drill?.rotation_tested === true,
      revocation_tested: redacted.rotation_revocation_drill?.revocation_tested === true,
    },
    security_signoff: {
      owner: redacted.security_signoff?.owner ?? null,
      role: redacted.security_signoff?.role ?? null,
      signed_at: redacted.security_signoff?.signed_at ?? null,
      signoff_reference: redacted.security_signoff?.signoff_reference ?? null,
    },
    ...(typeof evidence?.notes === 'string' ? { notes: redactString(evidence.notes) } : {}),
    caveats: [
      'Metadata-only agent gateway mTLS evidence; no PEM bodies, private keys, tokens, passwords, database URLs, ciphertext, raw logs, or request headers/bodies.',
      'Passing validation does not prove live gateway termination, PKI operations, or fleet-wide rollout; staging execution and security signoff remain required.',
    ],
  };
}

export async function main(argv = process.argv.slice(2)) {
  const opts = parseArgs(argv);
  if (opts.help) {
    console.log(
      'Usage: node scripts/agent-mtls-gateway-evidence.mjs --input evidence.json [--out file] [--validate-only]',
    );
    return 0;
  }

  const evidence = readEvidence(opts.input);
  const validation = validateAgentMtlsGatewayEvidence(evidence);
  const manifest = createAgentMtlsGatewayEvidenceManifest({ evidence, validation });

  if (opts.validateOnly) {
    console.log(
      `agent-mtls-gateway-evidence: ${validation.ok ? 'ok' : 'failed'} (release_id=${manifest.release_id ?? 'none'})`,
    );
    return validation.ok ? 0 : 1;
  }

  if (!validation.ok) {
    validateAndPrepareAgentMtlsGatewayEvidence(evidence);
  }

  mkdirSync(path.dirname(path.resolve(opts.out)), { recursive: true });
  writeFileSync(opts.out, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`agent-mtls-gateway-evidence: wrote ${opts.out}`);
  return 0;
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(`agent-mtls-gateway-evidence: ${err.message}`);
      process.exit(1);
    },
  );
}