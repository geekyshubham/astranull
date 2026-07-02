#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { REQUIRED_ARTIFACT_TYPES } from '../src/lib/highScalePolicy.mjs';
import { validateProductionReleaseEvidence } from '../src/contracts/productionReleaseEvidence.mjs';
import { redactObject } from '../src/lib/redact.mjs';

const DEFAULT_OUT = 'output/authorization-custody-evidence.json';
const PRODUCTION_RELEASE_KIND = 'authorization_custody';

export const AUTHORIZATION_CUSTODY_INPUT_REQUIRED_FIELDS = Object.freeze([
  'high_scale_request_id',
  'soc_reviewer',
  'legal_signoff',
  'retention_policy',
  'scoped_authorization_references',
  'artifact_custody',
  'evidence_uri',
]);

export const CUSTODY_SUMMARY_REQUIRED_FIELDS = Object.freeze([
  'custody_system_reference',
  'chain_of_custody_verified',
]);

export const RETENTION_POLICY_REQUIRED_FIELDS = Object.freeze([
  'policy_reference',
  'retention_years',
]);

export const LEGAL_SIGNOFF_REQUIRED_FIELDS = Object.freeze(['reference', 'signed_at']);

export const ARTIFACT_CUSTODY_REQUIRED_FIELDS = Object.freeze([
  'artifact_type',
  'custody_id',
  'custody_uri',
]);

export const SCOPED_AUTHORIZATION_REQUIRED_FIELDS = Object.freeze([
  'valid_window',
  'scenario_families',
  'rate_caps',
]);

export const VALID_WINDOW_REQUIRED_FIELDS = Object.freeze(['valid_from', 'valid_to']);

export const RATE_CAPS_REQUIRED_FIELDS = Object.freeze(['max_rate', 'max_duration_minutes']);

export const EXPECTED_AUTHORIZATION_ARTIFACT_TYPES = Object.freeze([
  ...REQUIRED_ARTIFACT_TYPES,
  'provider_approval',
]);

const UNAPPROVED_EXECUTION_STATES = new Set([
  'live_traffic',
  'traffic_active',
  'production_execution',
  'attack_running',
  'traffic_generation_enabled',
]);

const FORBIDDEN_KEYS = new Set([
  'api_key',
  'apikey',
  'attachment',
  'attachments',
  'authorization',
  'body',
  'connection_string',
  'contract_body',
  'contract_document',
  'credential',
  'credentials',
  'customer_contract',
  'customer_payload',
  'database_url',
  'headers',
  'ip_inventory',
  'ip_list',
  'log',
  'log_blob',
  'logs',
  'packet',
  'packet_payload',
  'password',
  'payload',
  'raw_authorization',
  'raw_body',
  'raw_contract',
  'raw_headers',
  'raw_log',
  'raw_packet',
  'secret',
  'target_ip_inventory',
  'target_ips',
  'token',
]);

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
  if (typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === 0) return false;
  return true;
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function collectForbiddenFields(value, pathPrefix = '') {
  if (value === null || value === undefined || typeof value !== 'object') return [];
  const findings = [];
  if (Array.isArray(value)) {
    value.forEach((entry, index) => {
      findings.push(...collectForbiddenFields(entry, `${pathPrefix}[${index}]`));
    });
    return findings;
  }
  for (const [key, nested] of Object.entries(value)) {
    const keyPath = pathPrefix ? `${pathPrefix}.${key}` : key;
    const normalized = normalizeKey(key);
    if (FORBIDDEN_KEYS.has(normalized) || normalized.startsWith('raw_')) {
      findings.push(keyPath);
    }
    findings.push(...collectForbiddenFields(nested, keyPath));
  }
  return findings;
}

function missingNestedFields(object, requiredFields, prefix) {
  if (!hasValue(object) || typeof object !== 'object' || Array.isArray(object)) {
    return requiredFields.map((field) => `${prefix}.${field}`);
  }
  return requiredFields
    .filter((field) => !hasValue(object[field]))
    .map((field) => `${prefix}.${field}`);
}

function expectedArtifactTypes(evidence) {
  const requiresProvider = evidence?.requires_provider_approval === true;
  if (requiresProvider) {
    return [...EXPECTED_AUTHORIZATION_ARTIFACT_TYPES];
  }
  return [...REQUIRED_ARTIFACT_TYPES];
}

function missingArtifactTypeCoverage(evidence) {
  const expected = new Set(expectedArtifactTypes(evidence));
  const entries = Array.isArray(evidence?.artifact_custody) ? evidence.artifact_custody : [];
  const present = new Set(
    entries
      .map((entry) => (entry && typeof entry === 'object' ? String(entry.artifact_type ?? '') : ''))
      .filter((type) => type.trim() !== ''),
  );
  return [...expected].filter((type) => !present.has(type)).map((type) => `artifact_type:${type}`);
}

function missingArtifactCustodyEntries(evidence) {
  const missing = [];
  const entries = Array.isArray(evidence?.artifact_custody) ? evidence.artifact_custody : [];
  if (!hasValue(evidence?.artifact_custody)) {
    missing.push('artifact_custody');
    return missing;
  }
  entries.forEach((entry, index) => {
    if (!isObject(entry)) {
      missing.push(`artifact_custody[${index}]`);
      return;
    }
    for (const field of ARTIFACT_CUSTODY_REQUIRED_FIELDS) {
      if (!hasValue(entry[field])) {
        missing.push(`artifact_custody[${index}].${field}`);
      }
    }
  });
  return missing;
}

function invalidExecutionFields(evidence) {
  const invalid_fields = [];
  if (evidence?.traffic_generation_enabled === true || evidence?.live_traffic_started === true) {
    invalid_fields.push({
      field: evidence?.traffic_generation_enabled === true
        ? 'traffic_generation_enabled'
        : 'live_traffic_started',
      reason: 'unapproved_high_scale_execution',
    });
  }
  const executionState = evidence?.high_scale_execution_state;
  if (hasValue(executionState) && UNAPPROVED_EXECUTION_STATES.has(String(executionState))) {
    invalid_fields.push({
      field: 'high_scale_execution_state',
      reason: 'unapproved_execution_state',
      value: executionState,
    });
  }
  return invalid_fields;
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

function parseInputJson(inputPath) {
  const parsed = JSON.parse(readFileSync(inputPath, 'utf8'));
  if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed;
  throw new Error('Input must be a JSON object.');
}

export function validateAuthorizationCustodyEvidence(evidence) {
  const missing_requirements = AUTHORIZATION_CUSTODY_INPUT_REQUIRED_FIELDS
    .filter((field) => !hasValue(evidence?.[field]));

  missing_requirements.push(
    ...missingNestedFields(evidence?.custody_summary, CUSTODY_SUMMARY_REQUIRED_FIELDS, 'custody_summary'),
    ...missingNestedFields(evidence?.retention_policy, RETENTION_POLICY_REQUIRED_FIELDS, 'retention_policy'),
    ...missingNestedFields(evidence?.legal_signoff, LEGAL_SIGNOFF_REQUIRED_FIELDS, 'legal_signoff'),
    ...missingNestedFields(
      evidence?.scoped_authorization_references,
      SCOPED_AUTHORIZATION_REQUIRED_FIELDS,
      'scoped_authorization_references',
    ),
    ...missingNestedFields(
      evidence?.scoped_authorization_references?.valid_window,
      VALID_WINDOW_REQUIRED_FIELDS,
      'scoped_authorization_references.valid_window',
    ),
    ...missingNestedFields(
      evidence?.scoped_authorization_references?.rate_caps,
      RATE_CAPS_REQUIRED_FIELDS,
      'scoped_authorization_references.rate_caps',
    ),
    ...missingArtifactCustodyEntries(evidence),
  );

  const missing_artifact_types = missingArtifactTypeCoverage(evidence);
  const forbidden_fields = [...new Set(collectForbiddenFields(evidence))].sort();
  const invalid_fields = invalidExecutionFields(evidence);

  const uniqueMissing = [...new Set([
    ...missing_requirements,
    ...missing_artifact_types,
  ])].sort();

  const ok =
    uniqueMissing.length === 0
    && forbidden_fields.length === 0
    && invalid_fields.length === 0;

  return {
    ok,
    missing_requirements: uniqueMissing,
    missing_artifact_types,
    forbidden_fields,
    invalid_fields,
    expected_artifact_types: expectedArtifactTypes(evidence),
  };
}

export function buildAuthorizationCustodyProductionReleaseEvidence(input = {}) {
  const evidence = input.evidence ?? {};
  const validation = input.validation ?? validateAuthorizationCustodyEvidence(evidence);
  const redacted = redactObject(evidence);
  const entries = Array.isArray(redacted.artifact_custody) ? redacted.artifact_custody : [];
  const scoped = redacted.scoped_authorization_references ?? {};

  return {
    schema_version: 1,
    artifact_type: 'authorization_custody_evidence',
    created_at: input.createdAt ?? new Date().toISOString(),
    release_id: input.releaseId ?? redacted.release_id ?? null,
    custody_summary: {
      custody_system_reference: redacted.custody_summary?.custody_system_reference ?? null,
      artifact_count: entries.length,
      chain_of_custody_verified: redacted.custody_summary?.chain_of_custody_verified === true,
      high_scale_request_id: redacted.high_scale_request_id ?? null,
      soc_reviewer: redacted.soc_reviewer ?? null,
      scoped_authorization_references: {
        valid_window: scoped.valid_window ?? null,
        scenario_families: scoped.scenario_families ?? [],
        rate_caps: scoped.rate_caps ?? null,
      },
    },
    required_artifacts: entries.map((entry, index) => ({
      artifact_type: entry.artifact_type ?? null,
      artifact_id: entry.artifact_id ?? `${entry.artifact_type ?? 'artifact'}:${index + 1}`,
      custody_id: entry.custody_id ?? null,
      custody_uri: entry.custody_uri ?? null,
      status: entry.status ?? 'sealed',
    })),
    retention_policy: {
      policy_reference: redacted.retention_policy?.policy_reference ?? null,
      retention_years: redacted.retention_policy?.retention_years ?? null,
      retention_classification: redacted.retention_policy?.retention_classification ?? null,
    },
    legal_signoff: {
      reference: redacted.legal_signoff?.reference ?? null,
      signed_at: redacted.legal_signoff?.signed_at ?? null,
    },
    evidence_uri: redacted.evidence_uri ?? null,
  };
}

export function validateAuthorizationCustodyProductionReleaseContract(productionEvidence) {
  return validateProductionReleaseEvidence(PRODUCTION_RELEASE_KIND, productionEvidence);
}

function buildRedactedInputMetadata(evidence, validation) {
  const redacted = redactObject(evidence);
  return {
    high_scale_request_id: redacted.high_scale_request_id ?? null,
    soc_reviewer: redacted.soc_reviewer ?? null,
    requires_provider_approval: redacted.requires_provider_approval === true,
    expected_artifact_types: validation.expected_artifact_types,
    custody_summary: redacted.custody_summary ?? null,
    retention_policy: redacted.retention_policy ?? null,
    legal_signoff: redacted.legal_signoff ?? null,
    scoped_authorization_references: redacted.scoped_authorization_references ?? null,
    artifact_custody: Array.isArray(redacted.artifact_custody)
      ? redacted.artifact_custody.map((entry) => ({
          artifact_type: entry?.artifact_type ?? null,
          custody_id: entry?.custody_id ?? null,
          custody_uri: entry?.custody_uri ?? null,
          status: entry?.status ?? null,
          ...(entry?.contact_path ? { contact_path: entry.contact_path } : {}),
        }))
      : [],
    evidence_uri: redacted.evidence_uri ?? null,
  };
}

export function createAuthorizationCustodyEvidenceManifest(input = {}) {
  const evidence = input.evidence ?? {};
  const validation = validateAuthorizationCustodyEvidence(evidence);
  const production_release_evidence = buildAuthorizationCustodyProductionReleaseEvidence({
    evidence,
    validation,
    releaseId: input.releaseId,
    createdAt: input.createdAt,
  });
  const contract_validation = validateAuthorizationCustodyProductionReleaseContract(
    production_release_evidence,
  );

  const ok = validation.ok && contract_validation.ok;

  return {
    schema_version: 1,
    artifact_type: 'authorization_custody_evidence_manifest',
    created_at: input.createdAt ?? production_release_evidence.created_at,
    validation: {
      ok,
      missing_requirements: validation.missing_requirements,
      missing_artifact_types: validation.missing_artifact_types,
      forbidden_fields: validation.forbidden_fields,
      invalid_fields: validation.invalid_fields,
      contract_missing_fields: contract_validation.missing_fields,
      contract_forbidden_fields: contract_validation.forbidden_fields,
    },
    production_release_evidence: {
      kind: PRODUCTION_RELEASE_KIND,
      evidence: production_release_evidence,
      contract_validation,
    },
    metadata: buildRedactedInputMetadata(evidence, validation),
    caveats: [
      'Manifest records metadata-only authorization artifact custody evidence for SOC high-scale readiness review.',
      'Production scheduling still requires durable document custody, legal retention, and live SOC/legal coordination.',
      'This validator does not start or schedule high-scale execution.',
    ],
  };
}

export async function main(argv = process.argv.slice(2)) {
  const opts = parseArgs(argv);
  if (opts.help) {
    console.log(
      'Usage: node scripts/authorization-custody-evidence.mjs --input evidence.json '
      + '[--out output/authorization-custody-evidence.json] [--release-id rel] [--validate-only]',
    );
    return 0;
  }

  const evidence = parseInputJson(opts.input);
  if (opts.releaseId) {
    evidence.release_id = opts.releaseId;
  }

  const manifest = createAuthorizationCustodyEvidenceManifest({
    evidence,
    releaseId: opts.releaseId ?? evidence.release_id ?? null,
  });

  if (!manifest.validation.ok) {
    const parts = [];
    if (manifest.validation.missing_requirements.length > 0) {
      parts.push(`missing: ${manifest.validation.missing_requirements.join(', ')}`);
    }
    if (manifest.validation.missing_artifact_types.length > 0) {
      parts.push(`artifact coverage: ${manifest.validation.missing_artifact_types.join(', ')}`);
    }
    if (manifest.validation.forbidden_fields.length > 0) {
      parts.push(`forbidden: ${manifest.validation.forbidden_fields.join(', ')}`);
    }
    if (manifest.validation.invalid_fields.length > 0) {
      parts.push(
        `invalid: ${manifest.validation.invalid_fields.map((entry) => entry.field).join(', ')}`,
      );
    }
    if (manifest.validation.contract_missing_fields.length > 0) {
      parts.push(`contract missing: ${manifest.validation.contract_missing_fields.join(', ')}`);
    }
    if (!opts.validateOnly) {
      mkdirSync(path.dirname(opts.out), { recursive: true });
      writeFileSync(opts.out, `${JSON.stringify(manifest, null, 2)}\n`);
      console.log(`authorization-custody-evidence: wrote ${opts.out}`);
    }
    throw new Error(`Authorization custody evidence invalid (${parts.join('; ')})`);
  }

  if (opts.validateOnly) {
    console.log(
      `authorization-custody-evidence: ok (release_id=${manifest.production_release_evidence.evidence.release_id}, `
      + `artifacts=${manifest.production_release_evidence.evidence.required_artifacts.length})`,
    );
    return 0;
  }

  mkdirSync(path.dirname(opts.out), { recursive: true });
  writeFileSync(opts.out, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`authorization-custody-evidence: wrote ${opts.out}`);
  return 0;
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(`authorization-custody-evidence: ${err.message}`);
      process.exit(1);
    },
  );
}