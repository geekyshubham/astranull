#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { rejectWebhookDestinationWithCredentials } from '../src/lib/notificationDelivery.mjs';
import {
  collectForbiddenEvidenceFields,
  collectForbiddenEvidenceStringPatterns,
  redactObject,
  sanitizeForbiddenFieldPaths,
} from '../src/lib/redact.mjs';

const DEFAULT_OUT = 'output/notification-provider-config-evidence.json';

export const REQUIRED_NOTIFICATION_CHANNELS = Object.freeze([
  'webhook',
  'email',
  'slack',
  'teams',
]);

export const PROVIDER_REQUIRED_FIELDS = Object.freeze([
  'provider_id',
  'channel',
  'encrypted_credential_ref_id',
  'rotation_owner',
  'retry_dlq_policy',
  'tenant_scope',
  'test_delivery_artifact_ids',
]);

export const RETRY_DLQ_REQUIRED_FIELDS = Object.freeze([
  'max_attempts',
  'backoff_summary',
  'dlq_reference',
]);

export const TOP_LEVEL_REQUIRED_FIELDS = Object.freeze([
  'release_id',
  'tenant_scope',
  'providers',
  'soc_signoff',
  'security_signoff',
]);

export const SIGNOFF_REQUIRED_FIELDS = Object.freeze(['owner', 'signed_at', 'reference']);

const ENCRYPTED_CREDENTIAL_REF_RE = /^(?:secret|vault|encref):\/\/.+/i;

const PLAINTEXT_CREDENTIAL_VALUE_RE = /^(?:whsec_|xox[baprs]-|sk-[A-Za-z0-9]|Bearer\s)/i;

const FORBIDDEN_KEYS = new Set([
  'api_key',
  'apikey',
  'authorization',
  'body',
  'bot_token',
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
  'raw_body',
  'raw_headers',
  'raw_log',
  'raw_packet',
  'secret',
  'slack_webhook_url',
  'smtp_password',
  'teams_incoming_webhook',
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

function collectUrlCredentialViolations(value, fieldPath = '') {
  if (value === null || value === undefined) return [];
  if (typeof value === 'string') {
    if (!/^https?:\/\//i.test(value)) return [];
    const check = rejectWebhookDestinationWithCredentials(value);
    if (!check.ok && check.error === 'webhook_url_credentials_not_allowed') {
      return [`${fieldPath}:url_credentials`];
    }
    return [];
  }
  if (Array.isArray(value)) {
    return value.flatMap((entry, index) =>
      collectUrlCredentialViolations(entry, `${fieldPath}[${index}]`),
    );
  }
  if (typeof value === 'object') {
    return Object.entries(value).flatMap(([key, nested]) =>
      collectUrlCredentialViolations(nested, fieldPath ? `${fieldPath}.${key}` : key),
    );
  }
  return [];
}

function missingSignoffFields(signoff, prefix) {
  if (!hasValue(signoff) || typeof signoff !== 'object' || Array.isArray(signoff)) {
    return SIGNOFF_REQUIRED_FIELDS.map((field) => `${prefix}.${field}`);
  }
  return SIGNOFF_REQUIRED_FIELDS
    .filter((field) => !hasValue(signoff[field]))
    .map((field) => `${prefix}.${field}`);
}

function validateEncryptedCredentialRef(ref, fieldPath) {
  const invalid = [];
  if (!hasValue(ref)) {
    invalid.push({ field: fieldPath, reason: 'missing_encrypted_credential_ref' });
    return invalid;
  }
  const value = String(ref).trim();
  if (PLAINTEXT_CREDENTIAL_VALUE_RE.test(value)) {
    invalid.push({ field: fieldPath, reason: 'plaintext_credential_not_allowed' });
  }
  if (/^https?:\/\//i.test(value)) {
    const urlCheck = rejectWebhookDestinationWithCredentials(value);
    if (!urlCheck.ok) {
      invalid.push({ field: fieldPath, reason: urlCheck.error });
    } else {
      invalid.push({ field: fieldPath, reason: 'raw_webhook_url_not_allowed' });
    }
  }
  if (!ENCRYPTED_CREDENTIAL_REF_RE.test(value) && !/^sec_[a-z0-9_]+$/i.test(value)) {
    invalid.push({ field: fieldPath, reason: 'invalid_encrypted_credential_ref' });
  }
  return invalid;
}

function validateProviderEntry(provider, index) {
  const prefix = `providers[${index}]`;
  const missing_fields = PROVIDER_REQUIRED_FIELDS
    .filter((field) => !hasValue(provider?.[field]))
    .map((field) => `${prefix}.${field}`);

  const invalid_fields = [];
  if (hasValue(provider?.channel)) {
    const channel = String(provider.channel).trim().toLowerCase();
    if (!REQUIRED_NOTIFICATION_CHANNELS.includes(channel)) {
      invalid_fields.push({
        field: `${prefix}.channel`,
        reason: 'unsupported_channel',
        allowed: [...REQUIRED_NOTIFICATION_CHANNELS],
      });
    }
  }

  invalid_fields.push(
    ...validateEncryptedCredentialRef(
      provider?.encrypted_credential_ref_id,
      `${prefix}.encrypted_credential_ref_id`,
    ),
  );

  const retryPolicy = provider?.retry_dlq_policy;
  if (!hasValue(retryPolicy) || typeof retryPolicy !== 'object' || Array.isArray(retryPolicy)) {
    missing_fields.push(
      ...RETRY_DLQ_REQUIRED_FIELDS.map((field) => `${prefix}.retry_dlq_policy.${field}`),
    );
  } else {
    for (const field of RETRY_DLQ_REQUIRED_FIELDS) {
      if (!hasValue(retryPolicy[field])) {
        missing_fields.push(`${prefix}.retry_dlq_policy.${field}`);
      }
    }
    const maxAttempts = Number(retryPolicy.max_attempts);
    if (Number.isFinite(maxAttempts) && (!Number.isInteger(maxAttempts) || maxAttempts < 1)) {
      invalid_fields.push({
        field: `${prefix}.retry_dlq_policy.max_attempts`,
        reason: 'max_attempts_must_be_positive_integer',
      });
    }
  }

  const artifactIds = provider?.test_delivery_artifact_ids;
  if (Array.isArray(artifactIds)) {
    artifactIds.forEach((artifactId, artifactIndex) => {
      if (!hasValue(artifactId)) {
        missing_fields.push(`${prefix}.test_delivery_artifact_ids[${artifactIndex}]`);
      } else if (/^https?:\/\//i.test(String(artifactId))) {
        invalid_fields.push({
          field: `${prefix}.test_delivery_artifact_ids[${artifactIndex}]`,
          reason: 'raw_url_artifact_id_not_allowed',
        });
      }
    });
  }

  return { missing_fields, invalid_fields, channel: provider?.channel };
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

export function validateNotificationProviderConfigEvidence(evidence) {
  const forbidden_fields = [
    ...new Set([
      ...collectForbiddenFields(evidence),
      ...collectForbiddenEvidenceStringPatterns(evidence),
      ...collectUrlCredentialViolations(evidence),
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
    .filter((field) => !hasValue(evidence?.[field]))
    .map((field) => field);

  missing_fields.push(
    ...missingSignoffFields(evidence?.soc_signoff, 'soc_signoff'),
    ...missingSignoffFields(evidence?.security_signoff, 'security_signoff'),
  );

  const invalid_fields = [];
  const providers = Array.isArray(evidence?.providers) ? evidence.providers : [];
  if (providers.length === 0 && hasValue(evidence?.providers)) {
    invalid_fields.push({ field: 'providers', reason: 'providers_must_be_non_empty_array' });
  }

  const channelsPresent = new Set();
  providers.forEach((provider, index) => {
    const result = validateProviderEntry(provider, index);
    missing_fields.push(...result.missing_fields);
    invalid_fields.push(...result.invalid_fields);
    if (hasValue(result.channel)) {
      channelsPresent.add(String(result.channel).trim().toLowerCase());
    }
  });

  const coverage_gaps = REQUIRED_NOTIFICATION_CHANNELS
    .filter((channel) => !channelsPresent.has(channel))
    .map((channel) => `missing_channel:${channel}`);

  const uniqueMissing = [...new Set(missing_fields)];

  return {
    ok: uniqueMissing.length === 0 && invalid_fields.length === 0 && coverage_gaps.length === 0,
    missing_fields: uniqueMissing,
    invalid_fields,
    forbidden_fields,
    coverage_gaps,
  };
}

function redactedProviderSummaries(providers) {
  const redacted = redactObject(providers, 0, { omitSensitiveKeys: true });
  if (!Array.isArray(redacted)) return [];
  return redacted.map((provider) => ({
    provider_id: provider.provider_id,
    channel: provider.channel,
    encrypted_credential_ref_id: provider.encrypted_credential_ref_id,
    rotation_owner: provider.rotation_owner,
    tenant_scope: provider.tenant_scope,
    retry_dlq_policy: provider.retry_dlq_policy
      ? {
          max_attempts: provider.retry_dlq_policy.max_attempts,
          backoff_summary: provider.retry_dlq_policy.backoff_summary,
          dlq_reference: provider.retry_dlq_policy.dlq_reference,
        }
      : null,
    test_delivery_artifact_ids: provider.test_delivery_artifact_ids ?? [],
  }));
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

export function createNotificationProviderConfigManifest(input = {}) {
  const evidence = input.evidence ?? null;
  const validation = validateNotificationProviderConfigEvidence(evidence);
  if (validation.forbidden_fields.length > 0) {
    throw new Error(`Forbidden content in evidence: ${validation.forbidden_fields.join(', ')}`);
  }

  const redacted = redactObject(evidence, 0, { omitSensitiveKeys: true });
  const manifest = {
    schema_version: 1,
    artifact_type: 'notification_provider_config_evidence',
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
    required_channels: [...REQUIRED_NOTIFICATION_CHANNELS],
    coverage_gaps: validation.coverage_gaps,
    providers: redactedProviderSummaries(redacted?.providers),
    signoff: {
      soc: redacted?.soc_signoff ?? null,
      security: redacted?.security_signoff ?? null,
    },
    caveats: [
      'Manifest records metadata-only notification provider configuration evidence.',
      'Passing validation does not prove live email, Slack, Teams, or webhook delivery; staging provider tests and SOC/security signoff are still required.',
      'Do not attach raw webhook URLs, provider credentials, HTTP headers/bodies, or log payloads to this artifact.',
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
      'Usage: node scripts/notification-provider-config-evidence.mjs --input evidence.json '
      + '[--out file] [--validate-only]',
    );
    return 0;
  }

  const evidence = parseInputJson(opts.input);
  const manifest = createNotificationProviderConfigManifest({ evidence });

  if (opts.validateOnly) {
    console.log(
      `notification-provider-config-evidence: ok (release_id=${manifest.release_id}, `
      + `providers=${manifest.providers.length}, channels=${REQUIRED_NOTIFICATION_CHANNELS.length})`,
    );
    return 0;
  }

  mkdirSync(path.dirname(opts.out), { recursive: true });
  writeFileSync(opts.out, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`notification-provider-config-evidence: wrote ${opts.out}`);
  return 0;
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(`notification-provider-config-evidence: ${err.message}`);
      process.exit(1);
    },
  );
}