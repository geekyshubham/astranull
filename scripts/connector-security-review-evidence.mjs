#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { isConnectorsEnabledForTenant, loadRuntimeConfig } from '../src/config.mjs';
import {
  collectForbiddenEvidenceFields,
  collectForbiddenEvidenceStringPatterns,
  redactObject,
} from '../src/lib/redact.mjs';

const DEFAULT_OUT = 'output/connector-security-review-evidence.json';

export const REQUIRED_CONNECTOR_PROVIDERS = Object.freeze([
  'cloudflare',
  'akamai',
  'aws',
  'azure',
  'gcp',
]);

export const TOP_LEVEL_REQUIRED_FIELDS = Object.freeze([
  'release_id',
  'tenant_scope',
  'connector_providers',
  'read_only_enforced',
  'vault_only_secret_refs',
  'feature_flag_plan',
  'security_signoff',
  'soc_signoff',
]);

export const FEATURE_FLAG_PLAN_REQUIRED_FIELDS = Object.freeze([
  'flag_name',
  'default_enabled',
  'tenant_overrides',
]);

export const SIGNOFF_REQUIRED_FIELDS = Object.freeze(['owner', 'signed_at', 'reference']);

const FORBIDDEN_KEYS = new Set([
  'access_key',
  'api_key',
  'apikey',
  'authorization',
  'body',
  'client_secret',
  'config_body',
  'connection_string',
  'credential',
  'credentials',
  'database_url',
  'headers',
  'log_blob',
  'log_lines',
  'packet',
  'packet_payload',
  'password',
  'payload',
  'policy_body',
  'raw_body',
  'raw_config',
  'raw_headers',
  'raw_log',
  'raw_packet',
  'secret',
  'secret_id',
  'token',
  'webhook_secret',
  'webhook_url',
]);

function hasValue(value) {
  if (value === null || value === undefined) return false;
  if (typeof value === 'string' && value.trim() === '') return false;
  if (Array.isArray(value) && value.length === 0) return false;
  return true;
}

function collectForbiddenFields(value, fieldPath = '') {
  return collectForbiddenEvidenceFields(value, fieldPath, {
    extraForbiddenKeys: FORBIDDEN_KEYS,
  });
}

function missingSignoffFields(signoff, prefix) {
  if (!hasValue(signoff) || typeof signoff !== 'object' || Array.isArray(signoff)) {
    return SIGNOFF_REQUIRED_FIELDS.map((field) => `${prefix}.${field}`);
  }
  return SIGNOFF_REQUIRED_FIELDS
    .filter((field) => !hasValue(signoff[field]))
    .map((field) => `${prefix}.${field}`);
}

function validateFeatureFlagPlan(plan, runtimeConfig) {
  const prefix = 'feature_flag_plan';
  const missing_fields = FEATURE_FLAG_PLAN_REQUIRED_FIELDS
    .filter((field) => !hasValue(plan?.[field]) && plan?.[field] !== false)
    .map((field) => `${prefix}.${field}`);

  const invalid_fields = [];
  if (hasValue(plan?.flag_name) && String(plan.flag_name).trim() !== 'ASTRANULL_CONNECTORS_ENABLED') {
    invalid_fields.push({
      field: `${prefix}.flag_name`,
      reason: 'unexpected_flag_name',
      expected: 'ASTRANULL_CONNECTORS_ENABLED',
    });
  }

  if (hasValue(plan?.default_enabled) && typeof plan.default_enabled !== 'boolean') {
    invalid_fields.push({
      field: `${prefix}.default_enabled`,
      reason: 'default_enabled_must_be_boolean',
    });
  }

  const tenantOverrides = plan?.tenant_overrides;
  if (hasValue(tenantOverrides)) {
    if (!Array.isArray(tenantOverrides) || tenantOverrides.length === 0) {
      invalid_fields.push({
        field: `${prefix}.tenant_overrides`,
        reason: 'tenant_overrides_must_be_non_empty_array',
      });
    } else {
      tenantOverrides.forEach((entry, index) => {
        const entryPrefix = `${prefix}.tenant_overrides[${index}]`;
        if (!hasValue(entry?.tenant_id)) missing_fields.push(`${entryPrefix}.tenant_id`);
        if (typeof entry?.enabled !== 'boolean') {
          invalid_fields.push({
            field: `${entryPrefix}.enabled`,
            reason: 'enabled_must_be_boolean',
          });
        } else if (runtimeConfig && hasValue(entry?.tenant_id)) {
          const expected = isConnectorsEnabledForTenant(runtimeConfig, entry.tenant_id);
          if (entry.enabled !== expected) {
            invalid_fields.push({
              field: `${entryPrefix}.enabled`,
              reason: 'tenant_override_does_not_match_runtime_config',
            });
          }
        }
      });
    }
  }

  return { missing_fields, invalid_fields };
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

export function validateConnectorSecurityReviewEvidence(evidence, options = {}) {
  const runtimeConfig = options.runtimeConfig ?? null;
  const forbidden_fields = [
    ...new Set([
      ...collectForbiddenFields(evidence),
      ...collectForbiddenEvidenceStringPatterns(evidence),
    ]),
  ];

  if (forbidden_fields.length > 0) {
    return {
      ok: false,
      missing_fields: [],
      invalid_fields: [],
      forbidden_fields,
      coverage_gaps: [],
    };
  }

  const missing_fields = TOP_LEVEL_REQUIRED_FIELDS
    .filter((field) => !hasValue(evidence?.[field]) && evidence?.[field] !== false)
    .map((field) => field);

  missing_fields.push(
    ...missingSignoffFields(evidence?.soc_signoff, 'soc_signoff'),
    ...missingSignoffFields(evidence?.security_signoff, 'security_signoff'),
  );

  const invalid_fields = [];
  const providers = Array.isArray(evidence?.connector_providers) ? evidence.connector_providers : [];
  if (providers.length === 0 && hasValue(evidence?.connector_providers)) {
    invalid_fields.push({ field: 'connector_providers', reason: 'connector_providers_must_be_non_empty_array' });
  }

  const providersPresent = new Set();
  providers.forEach((provider, index) => {
    const value = String(provider ?? '').trim().toLowerCase();
    if (!value) {
      missing_fields.push(`connector_providers[${index}]`);
      return;
    }
    if (!REQUIRED_CONNECTOR_PROVIDERS.includes(value)) {
      invalid_fields.push({
        field: `connector_providers[${index}]`,
        reason: 'unsupported_connector_provider',
        allowed: [...REQUIRED_CONNECTOR_PROVIDERS],
      });
    }
    providersPresent.add(value);
  });

  const coverage_gaps = REQUIRED_CONNECTOR_PROVIDERS
    .filter((provider) => !providersPresent.has(provider))
    .map((provider) => `missing_provider:${provider}`);

  const featureFlagPlan = validateFeatureFlagPlan(evidence?.feature_flag_plan, runtimeConfig);
  missing_fields.push(...featureFlagPlan.missing_fields);
  invalid_fields.push(...featureFlagPlan.invalid_fields);

  if (evidence?.read_only_enforced !== true) {
    invalid_fields.push({
      field: 'read_only_enforced',
      reason: 'read_only_enforced_must_be_true',
    });
  }
  if (evidence?.vault_only_secret_refs !== true) {
    invalid_fields.push({
      field: 'vault_only_secret_refs',
      reason: 'vault_only_secret_refs_must_be_true',
    });
  }

  const uniqueMissing = [...new Set(missing_fields)];

  return {
    ok: uniqueMissing.length === 0 && invalid_fields.length === 0 && coverage_gaps.length === 0,
    missing_fields: uniqueMissing,
    invalid_fields,
    forbidden_fields,
    coverage_gaps,
  };
}

function formatValidationError(validation) {
  const parts = [];
  if (validation.missing_fields.length > 0) {
    parts.push(`missing field(s): ${validation.missing_fields.join(', ')}`);
  }
  if (validation.invalid_fields.length > 0) {
    parts.push(
      `invalid field(s): ${validation.invalid_fields.map((entry) => entry.field).join(', ')}`,
    );
  }
  if (validation.forbidden_fields.length > 0) {
    parts.push(`forbidden field(s): ${validation.forbidden_fields.join(', ')}`);
  }
  if (validation.coverage_gaps.length > 0) {
    parts.push(`coverage gap(s): ${validation.coverage_gaps.join(', ')}`);
  }
  return parts.join('; ');
}

export function createConnectorSecurityReviewManifest(input = {}) {
  const evidence = input.evidence ?? null;
  const runtimeConfig = input.runtimeConfig ?? loadRuntimeConfig(input.env ?? process.env);
  const validation = validateConnectorSecurityReviewEvidence(evidence, { runtimeConfig });
  if (validation.forbidden_fields.length > 0) {
    throw new Error(`Forbidden content in evidence: ${validation.forbidden_fields.join(', ')}`);
  }

  const redacted = redactObject(evidence, 0, { omitSensitiveKeys: true });
  const manifest = {
    schema_version: 1,
    artifact_type: 'connector_security_review_evidence',
    created_at: input.createdAt ?? new Date().toISOString(),
    release_id: redacted?.release_id ?? null,
    tenant_scope: redacted?.tenant_scope ?? null,
    validation: {
      ok: validation.ok,
      missing_fields: validation.missing_fields,
      invalid_fields: validation.invalid_fields,
      forbidden_fields: [],
      coverage_gaps: validation.coverage_gaps,
    },
    required_providers: [...REQUIRED_CONNECTOR_PROVIDERS],
    coverage_gaps: validation.coverage_gaps,
    connector_providers: redacted?.connector_providers ?? [],
    feature_flag_plan: redacted?.feature_flag_plan ?? null,
    signoff: {
      soc: redacted?.soc_signoff ?? null,
      security: redacted?.security_signoff ?? null,
    },
    caveats: [
      'Metadata-only connector security review evidence; no provider credentials, configs, or API bodies.',
      'Passing validation does not enable connectors automatically; per-tenant ASTRANULL_CONNECTORS_ENABLED runtime flags still gate API access.',
      'Production promotion still requires completed security review, SOC signoff, and staging connector evidence.',
    ],
  };

  if (!validation.ok) {
    throw new Error(formatValidationError(validation));
  }

  return manifest;
}

function parseInputJson(inputPath) {
  return JSON.parse(readFileSync(inputPath, 'utf8'));
}

export async function main(argv = process.argv.slice(2)) {
  const opts = parseArgs(argv);
  if (opts.help) {
    console.log(
      'Usage: node scripts/connector-security-review-evidence.mjs --input evidence.json '
      + '[--out file] [--validate-only]',
    );
    return 0;
  }

  const evidence = parseInputJson(opts.input);
  const manifest = createConnectorSecurityReviewManifest({ evidence });

  if (opts.validateOnly) {
    console.log(
      `connector-security-review-evidence: ok (release_id=${manifest.release_id}, `
      + `providers=${manifest.connector_providers.length})`,
    );
    return 0;
  }

  mkdirSync(path.dirname(opts.out), { recursive: true });
  writeFileSync(opts.out, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`connector-security-review-evidence: wrote ${opts.out}`);
  return 0;
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(`connector-security-review-evidence: ${err.message}`);
      process.exit(1);
    },
  );
}