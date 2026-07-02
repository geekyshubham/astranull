#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateProductionReleaseEvidence } from '../src/contracts/productionReleaseEvidence.mjs';
import { redactObject, redactString } from '../src/lib/redact.mjs';

const DEFAULT_OUT = 'output/gateway-load-abuse-evidence.json';

const ALLOWED_ENVIRONMENTS = new Set(['staging', 'production']);

export const GATEWAY_LOAD_ABUSE_RATE_LIMIT_CONTROL_IDS = Object.freeze([
  'api-global-rate-limit',
  'ui-global-rate-limit',
]);

export const GATEWAY_LOAD_ABUSE_ABUSE_CONTROL_IDS = Object.freeze([
  'anomaly-detection',
  'credential-stuffing-detection',
]);

export const GATEWAY_LOAD_ABUSE_CAPTURE_REQUIRED_FIELDS = Object.freeze([
  'release_id',
  'environment',
  'gateway_summary',
  'waf_edge_summary',
  'rate_limit_results',
  'abuse_detection_results',
  'edge_alerting_summary',
  'signoff',
  'evidence_uri',
]);

const RATE_LIMIT_RESULT_FIELDS = Object.freeze([
  'control_id',
  'status',
  'threshold_metadata',
  'evidence_uri',
]);

const ABUSE_RESULT_FIELDS = Object.freeze([
  'control_id',
  'status',
  'alert_fired',
  'evidence_uri',
]);

const EDGE_ALERTING_FIELDS = Object.freeze([
  'siem_route_reference',
  'alert_count',
  'false_positive_rate_metadata',
]);

const SIGNOFF_FIELDS = Object.freeze(['owner', 'signed_at', 'signoff_reference']);

const ALLOWED_CONTROL_STATUS = new Set(['passed', 'failed', 'skipped']);

const FORBIDDEN_KEYS = new Set([
  'amplification',
  'api_key',
  'apikey',
  'attack_command',
  'attack_profile',
  'attack_recipe',
  'attack_script',
  'attachment',
  'attachments',
  'authorization',
  'body',
  'connection_string',
  'credential',
  'credentials',
  'database_url',
  'generator',
  'headers',
  'ip_inventory',
  'ip_list',
  'log',
  'logs',
  'packet',
  'packet_capture',
  'packet_payload',
  'password',
  'payload',
  'pcap',
  'raw_body',
  'raw_dump',
  'raw_headers',
  'raw_log',
  'raw_logs',
  'raw_packet',
  'raw_request',
  'raw_response',
  'request',
  'response',
  'secret',
  'shell_command',
  'target_ip_inventory',
  'target_ips',
  'token',
  `traffic_${'generator'}`,
]);

const PG_URL_RE = /postgres(?:ql)?:\/\/[^\s'"]+/gi;
const IPV4_CSV_RE = /\b(?:\d{1,3}\.){3}\d{1,3}(?:\s*,\s*(?:\d{1,3}\.){3}\d{1,3}){2,}/;

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

export function collectForbiddenFields(value, fieldPath = '') {
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
      || normalized.endsWith('_recipe')
      || normalized.includes('attack_')
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
    if (IPV4_CSV_RE.test(value)) {
      findings.push(`${fieldPath}:target_ip_inventory_pattern`);
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

function missingNestedFields(object, requiredFields, prefix) {
  if (!isObject(object)) {
    return requiredFields.map((field) => `${prefix}.${field}`);
  }
  return requiredFields
    .filter((field) => !hasValue(object[field]))
    .map((field) => `${prefix}.${field}`);
}

function fieldSummary(fields) {
  return fields.length > 0 ? fields.join(', ') : 'none';
}

function validateControlEntries(entries, requiredIds, entryFields, listName) {
  const missing_fields = [];
  const missing_controls = [];
  const failed_controls = [];
  const invalid_fields = [];

  if (!Array.isArray(entries) || entries.length === 0) {
    return {
      missing_fields: [listName],
      missing_controls: [...requiredIds],
      failed_controls,
      invalid_fields,
    };
  }

  const presentIds = new Set();
  entries.forEach((entry, index) => {
    const prefix = `${listName}[${index}]`;
    if (!isObject(entry)) {
      missing_fields.push(prefix);
      invalid_fields.push(prefix);
      return;
    }
    for (const field of entryFields) {
      if (field === 'alert_fired') {
        if (entry.status === 'passed' && entry.alert_fired !== true && entry.alert_fired !== false) {
          invalid_fields.push(`${prefix}.alert_fired`);
        }
        continue;
      }
      if (!hasValue(entry[field])) {
        missing_fields.push(`${prefix}.${field}`);
      }
    }
    const status = entry.status;
    if (!ALLOWED_CONTROL_STATUS.has(status)) {
      invalid_fields.push(`${prefix}.status`);
    } else if (status === 'failed') {
      failed_controls.push(entry.control_id ?? `${listName}[${index}]`);
    }
    if (hasValue(entry.control_id)) {
      presentIds.add(String(entry.control_id));
    }
  });

  for (const controlId of requiredIds) {
    if (!presentIds.has(controlId)) {
      missing_controls.push(controlId);
    }
  }

  return { missing_fields, missing_controls, failed_controls, invalid_fields };
}

/**
 * @param {unknown} evidence
 */
export function validateGatewayLoadAbuseCaptureEvidence(evidence) {
  const forbidden_fields = [
    ...new Set([
      ...collectForbiddenFields(evidence),
      ...collectForbiddenStringPatterns(evidence),
    ]),
  ].sort();

  const missing_fields = GATEWAY_LOAD_ABUSE_CAPTURE_REQUIRED_FIELDS.filter(
    (field) => !hasValue(evidence?.[field]),
  );

  const env = hasValue(evidence?.environment)
    ? String(evidence.environment).trim().toLowerCase()
    : null;
  if (env && !ALLOWED_ENVIRONMENTS.has(env)) {
    missing_fields.push('environment');
  }

  missing_fields.push(...missingNestedFields(evidence?.signoff, SIGNOFF_FIELDS, 'signoff'));
  missing_fields.push(
    ...missingNestedFields(evidence?.edge_alerting_summary, EDGE_ALERTING_FIELDS, 'edge_alerting_summary'),
  );

  const rateLimitValidation = validateControlEntries(
    evidence?.rate_limit_results,
    GATEWAY_LOAD_ABUSE_RATE_LIMIT_CONTROL_IDS,
    RATE_LIMIT_RESULT_FIELDS,
    'rate_limit_results',
  );
  const abuseValidation = validateControlEntries(
    evidence?.abuse_detection_results,
    GATEWAY_LOAD_ABUSE_ABUSE_CONTROL_IDS,
    ABUSE_RESULT_FIELDS,
    'abuse_detection_results',
  );

  const missing_controls = [
    ...rateLimitValidation.missing_controls,
    ...abuseValidation.missing_controls,
  ];
  const failed_controls = [
    ...new Set([...rateLimitValidation.failed_controls, ...abuseValidation.failed_controls]),
  ].sort();
  const invalid_fields = [
    ...new Set([
      ...rateLimitValidation.invalid_fields,
      ...abuseValidation.invalid_fields,
    ]),
  ].sort();

  missing_fields.push(
    ...rateLimitValidation.missing_fields,
    ...abuseValidation.missing_fields,
  );

  const uniqueMissing = [...new Set(missing_fields)].sort();

  const ok =
    forbidden_fields.length === 0
    && uniqueMissing.length === 0
    && missing_controls.length === 0
    && failed_controls.length === 0
    && invalid_fields.length === 0;

  return {
    ok,
    missing_fields: uniqueMissing,
    missing_controls: [...new Set(missing_controls)].sort(),
    failed_controls,
    invalid_fields,
    forbidden_fields,
    environment: env,
  };
}

export function assertValidGatewayLoadAbuseCaptureEvidence(evidence) {
  const validation = validateGatewayLoadAbuseCaptureEvidence(evidence);
  if (validation.forbidden_fields.length > 0) {
    throw new Error(`Forbidden field(s): ${fieldSummary(validation.forbidden_fields)}`);
  }
  if (validation.missing_fields.length > 0) {
    throw new Error(`Missing field(s): ${fieldSummary(validation.missing_fields)}`);
  }
  if (validation.missing_controls.length > 0) {
    throw new Error(`Missing gateway control(s): ${fieldSummary(validation.missing_controls)}`);
  }
  if (validation.failed_controls.length > 0) {
    throw new Error(`Failed control result(s): ${fieldSummary(validation.failed_controls)}`);
  }
  if (validation.invalid_fields.length > 0) {
    throw new Error(`Invalid field(s): ${fieldSummary(validation.invalid_fields)}`);
  }
  return validation;
}

function summarizeControlResults(entries) {
  if (!Array.isArray(entries)) return [];
  return entries.map((entry) => ({
    control_id: entry?.control_id ?? null,
    status: entry?.status ?? null,
    evidence_uri: entry?.evidence_uri ?? null,
    ...(hasValue(entry?.threshold_metadata)
      ? { threshold_metadata: entry.threshold_metadata }
      : {}),
    ...(typeof entry?.alert_fired === 'boolean' ? { alert_fired: entry.alert_fired } : {}),
  }));
}

/**
 * @param {{ evidence: Record<string, unknown>, validation: ReturnType<typeof validateGatewayLoadAbuseCaptureEvidence>, createdAt?: string }} input
 */
export function buildGatewayLoadAbuseProductionReleaseEvidence(input) {
  const { evidence, validation, createdAt } = input;
  const redacted = redactObject(evidence);
  const payload = {
    schema_version: 1,
    artifact_type: 'gateway_load_abuse_evidence',
    created_at: createdAt ?? new Date().toISOString(),
    release_id: redacted.release_id ?? null,
    environment: validation.environment ?? redacted.environment ?? null,
    rate_limit_results: summarizeControlResults(redacted.rate_limit_results),
    abuse_detection_results: summarizeControlResults(redacted.abuse_detection_results),
    edge_alerting_summary: isObject(redacted.edge_alerting_summary)
      ? {
          siem_route_reference: redacted.edge_alerting_summary.siem_route_reference ?? null,
          alert_count: redacted.edge_alerting_summary.alert_count ?? null,
          false_positive_rate_metadata:
            redacted.edge_alerting_summary.false_positive_rate_metadata ?? null,
        }
      : null,
    signoff: isObject(redacted.signoff)
      ? {
          owner: redacted.signoff.owner ?? null,
          signed_at: redacted.signoff.signed_at ?? null,
          signoff_reference: redacted.signoff.signoff_reference ?? null,
        }
      : null,
    evidence_uri: redacted.evidence_uri ?? null,
  };

  const contract = validateProductionReleaseEvidence('gateway_load_abuse', payload);
  return {
    kind: 'gateway_load_abuse',
    evidence: payload,
    validation,
    contract_validation: contract,
    ...(typeof evidence?.notes === 'string' ? { notes: redactString(evidence.notes) } : {}),
    caveats: [
      'Metadata-only gateway load and abuse validation evidence; no raw requests, responses, headers, logs, credentials, tokens, database URLs, target IP inventories, or attack recipes.',
      'This validator does not run load tests or generate traffic; it only checks already-captured staging metadata and signoff references.',
      'Passing validation does not prove live gateway/WAF enforcement; production promotion still requires operator and security signoff outside this artifact.',
    ],
  };
}

export function createGatewayLoadAbuseEvidenceArtifact(input = {}) {
  const evidence = input.evidence;
  const validation = validateGatewayLoadAbuseCaptureEvidence(evidence);
  const release = buildGatewayLoadAbuseProductionReleaseEvidence({
    evidence,
    validation,
    createdAt: input.createdAt,
  });

  return {
    schema_version: 1,
    artifact_type: 'gateway_load_abuse_release_evidence',
    created_at: release.evidence.created_at,
    release_id: release.evidence.release_id,
    environment: release.evidence.environment,
    validation: {
      ok: validation.ok && release.contract_validation.ok,
      missing_fields: validation.missing_fields,
      missing_controls: validation.missing_controls,
      failed_controls: validation.failed_controls,
      invalid_fields: validation.invalid_fields,
      forbidden_fields: validation.forbidden_fields,
      contract_missing_fields: release.contract_validation.missing_fields,
      contract_forbidden_fields: release.contract_validation.forbidden_fields,
    },
    gateway_summary: redactObject(evidence)?.gateway_summary ?? null,
    waf_edge_summary: redactObject(evidence)?.waf_edge_summary ?? null,
    production_release_evidence: release,
    caveats: release.caveats,
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

function readCaptureEvidence(inputPath) {
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(inputPath, 'utf8'));
  } catch {
    throw new Error(`gateway-load-abuse-evidence: input is not valid JSON: ${inputPath}`);
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('gateway-load-abuse-evidence: input must be a JSON object');
  }
  if (parsed.evidence && typeof parsed.evidence === 'object' && !Array.isArray(parsed.evidence)) {
    return parsed.evidence;
  }
  return parsed;
}

export function mergeCaptureOptions(opts, fileEvidence = {}) {
  return {
    ...fileEvidence,
    ...(opts.releaseId ? { release_id: opts.releaseId } : {}),
  };
}

export async function main(argv = process.argv.slice(2)) {
  const opts = parseArgs(argv);
  if (opts.help) {
    console.log(
      'Usage: node scripts/gateway-load-abuse-evidence.mjs --input evidence.json '
      + '[--out output/gateway-load-abuse-evidence.json] [--release-id rel] [--validate-only]',
    );
    return 0;
  }

  const fileEvidence = readCaptureEvidence(opts.input);
  const evidence = mergeCaptureOptions(opts, fileEvidence);
  const artifact = createGatewayLoadAbuseEvidenceArtifact({ evidence });

  if (opts.validateOnly) {
    console.log(
      `gateway-load-abuse-evidence: ${artifact.validation.ok ? 'ok' : 'failed'} `
      + `(release_id=${artifact.release_id ?? 'none'}, environment=${artifact.environment ?? 'none'})`,
    );
    return artifact.validation.ok ? 0 : 1;
  }

  mkdirSync(path.dirname(path.resolve(opts.out)), { recursive: true });
  writeFileSync(opts.out, `${JSON.stringify(artifact, null, 2)}\n`);
  console.log(`gateway-load-abuse-evidence: wrote ${opts.out}`);
  return artifact.validation.ok ? 0 : 1;
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(`gateway-load-abuse-evidence: ${err.message}`);
      process.exit(1);
    },
  );
}