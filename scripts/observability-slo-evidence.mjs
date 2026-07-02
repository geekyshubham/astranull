#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { redactObject, redactString } from '../src/lib/redact.mjs';

const DEFAULT_OUT = 'output/observability-slo-evidence.json';

const ALLOWED_ENVIRONMENTS = new Set(['production', 'staging']);

export const OBSERVABILITY_CONTROL_IDS = Object.freeze([
  'metric_scrape_auth',
  'dashboard_ids',
  'alert_routes',
  'slo_targets',
  'incident_drill',
  'on_call',
  'redaction_policy',
  'environment',
]);

/** Release gate fails when any of these controls are absent or invalid. */
export const CRITICAL_OBSERVABILITY_CONTROLS = Object.freeze([
  'metric_scrape_auth',
  'alert_routes',
  'slo_targets',
  'incident_drill',
  'on_call',
  'redaction_policy',
  'environment',
]);

const METRIC_SCRAPE_AUTH_FIELDS = Object.freeze([
  'auth_mechanism',
  'gateway_reference',
  'evidence_uri',
  'validated_at',
]);

const ALERT_ROUTE_FIELDS = Object.freeze(['route_id', 'alert_name', 'destination_reference']);

const SLO_TARGET_FIELDS = Object.freeze(['slo_id', 'target', 'measurement_window']);

const REDACTION_POLICY_FIELDS = Object.freeze(['policy_reference', 'summary']);

const ON_CALL_FIELDS = Object.freeze(['owner', 'rotation_reference', 'evidence_uri']);

const FORBIDDEN_KEYS = new Set([
  'authorization',
  'body',
  'connection_string',
  'credential',
  'credentials',
  'database_url',
  'headers',
  'log',
  'logs',
  'password',
  'payload',
  'raw_body',
  'raw_headers',
  'raw_log',
  'raw_logs',
  'raw_trace',
  'secret',
  'span_payload',
  'token',
  'trace_payload',
  'trace_span_payload',
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
      || normalized.endsWith('_payload')
      || normalized.endsWith('_secret')
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
    if (PG_URL_RE.test(value)) {
      PG_URL_RE.lastIndex = 0;
      return [`${fieldPath}:database_url_pattern`];
    }
    return [];
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

function validateAlertRoutes(routes) {
  if (!Array.isArray(routes) || routes.length === 0) {
    return { control: 'alert_routes', missing: true, field_errors: ['alert_routes'] };
  }
  const field_errors = [];
  routes.forEach((route, index) => {
    if (!isObject(route)) {
      field_errors.push(`alert_routes[${index}]`);
      return;
    }
    for (const field of ALERT_ROUTE_FIELDS) {
      if (!hasValue(route[field])) {
        field_errors.push(`alert_routes[${index}].${field}`);
      }
    }
  });
  return {
    control: 'alert_routes',
    missing: false,
    field_errors,
  };
}

function validateSloTargets(slos) {
  if (!Array.isArray(slos) || slos.length === 0) {
    return { control: 'slo_targets', missing: true, field_errors: ['slo_targets'] };
  }
  const field_errors = [];
  slos.forEach((slo, index) => {
    if (!isObject(slo)) {
      field_errors.push(`slo_targets[${index}]`);
      return;
    }
    for (const field of SLO_TARGET_FIELDS) {
      if (!hasValue(slo[field])) {
        field_errors.push(`slo_targets[${index}].${field}`);
      }
    }
  });
  return {
    control: 'slo_targets',
    missing: false,
    field_errors,
  };
}

function validateDashboardIds(dashboardIds) {
  if (!Array.isArray(dashboardIds) || dashboardIds.length === 0) {
    return { control: 'dashboard_ids', missing: true, field_errors: ['dashboard_ids'] };
  }
  const field_errors = [];
  dashboardIds.forEach((id, index) => {
    if (!hasValue(id)) {
      field_errors.push(`dashboard_ids[${index}]`);
    }
  });
  return {
    control: 'dashboard_ids',
    missing: field_errors.includes('dashboard_ids'),
    field_errors,
  };
}

/**
 * @param {unknown} evidence
 */
export function validateObservabilitySloReleaseEvidence(evidence) {
  const forbidden_fields = [
    ...new Set([
      ...collectForbiddenFields(evidence),
      ...collectForbiddenStringPatterns(evidence),
    ]),
  ].sort();

  const missing_controls = [];
  const missing_critical_controls = [];
  const invalid_fields = [];

  const env = hasValue(evidence?.environment) ? String(evidence.environment).trim().toLowerCase() : null;
  if (!env || !ALLOWED_ENVIRONMENTS.has(env)) {
    missing_controls.push('environment');
    if (CRITICAL_OBSERVABILITY_CONTROLS.includes('environment')) {
      missing_critical_controls.push('environment');
    }
  }

  const scrapeAuth = evidence?.metric_scrape_auth;
  const scrapeMissing = missingNestedFields(scrapeAuth, METRIC_SCRAPE_AUTH_FIELDS, 'metric_scrape_auth');
  if (scrapeMissing.length > 0) {
    missing_controls.push('metric_scrape_auth');
    missing_critical_controls.push('metric_scrape_auth');
    invalid_fields.push(...scrapeMissing);
  }

  const dashboardResult = validateDashboardIds(evidence?.dashboard_ids);
  if (dashboardResult.missing) {
    missing_controls.push('dashboard_ids');
  }
  if (dashboardResult.field_errors.length > 0) {
    invalid_fields.push(...dashboardResult.field_errors);
  }

  const alertResult = validateAlertRoutes(evidence?.alert_routes);
  if (alertResult.missing) {
    missing_controls.push('alert_routes');
    missing_critical_controls.push('alert_routes');
  }
  if (alertResult.field_errors.length > 0) {
    invalid_fields.push(...alertResult.field_errors);
  }

  const sloResult = validateSloTargets(evidence?.slo_targets);
  if (sloResult.missing) {
    missing_controls.push('slo_targets');
    missing_critical_controls.push('slo_targets');
  }
  if (sloResult.field_errors.length > 0) {
    invalid_fields.push(...sloResult.field_errors);
  }

  if (!hasValue(evidence?.incident_drill_id)) {
    missing_controls.push('incident_drill');
    missing_critical_controls.push('incident_drill');
    invalid_fields.push('incident_drill_id');
  }

  const onCall = evidence?.on_call;
  const onCallMissing = missingNestedFields(onCall, ON_CALL_FIELDS, 'on_call');
  if (onCallMissing.length > 0) {
    missing_controls.push('on_call');
    missing_critical_controls.push('on_call');
    invalid_fields.push(...onCallMissing);
  }

  const redaction = evidence?.redaction_policy;
  const redactionMissing = missingNestedFields(redaction, REDACTION_POLICY_FIELDS, 'redaction_policy');
  if (redactionMissing.length > 0) {
    missing_controls.push('redaction_policy');
    missing_critical_controls.push('redaction_policy');
    invalid_fields.push(...redactionMissing);
  }

  const uniqueMissingControls = [...new Set(missing_controls)].sort();
  const uniqueMissingCritical = [...new Set(missing_critical_controls)].sort();
  const uniqueInvalid = [...new Set(invalid_fields)].sort();

  const ok =
    forbidden_fields.length === 0
    && uniqueMissingCritical.length === 0
    && uniqueInvalid.length === 0;

  return {
    ok,
    missing_controls: uniqueMissingControls,
    missing_critical_controls: uniqueMissingCritical,
    invalid_fields: uniqueInvalid,
    forbidden_fields,
    environment: env,
  };
}

function fieldSummary(fields) {
  return fields.length > 0 ? fields.join(', ') : 'none';
}

export function assertValidObservabilitySloReleaseEvidence(evidence) {
  const validation = validateObservabilitySloReleaseEvidence(evidence);
  if (validation.forbidden_fields.length > 0) {
    throw new Error(`Forbidden field(s): ${fieldSummary(validation.forbidden_fields)}`);
  }
  if (validation.missing_critical_controls.length > 0) {
    throw new Error(
      `Missing critical observability control(s): ${fieldSummary(validation.missing_critical_controls)}`,
    );
  }
  if (validation.invalid_fields.length > 0) {
    throw new Error(`Invalid observability evidence field(s): ${fieldSummary(validation.invalid_fields)}`);
  }
  return validation;
}

function summarizeAlertRoutes(routes) {
  if (!Array.isArray(routes)) return [];
  return routes.map((route) => ({
    route_id: route?.route_id ?? null,
    alert_name: route?.alert_name ?? null,
    destination_reference: route?.destination_reference ?? null,
  }));
}

function summarizeSloTargets(slos) {
  if (!Array.isArray(slos)) return [];
  return slos.map((slo) => ({
    slo_id: slo?.slo_id ?? null,
    target: slo?.target ?? null,
    measurement_window: slo?.measurement_window ?? null,
  }));
}

export function createObservabilitySloEvidenceManifest(input = {}) {
  const evidence = input.evidence;
  const validation = validateObservabilitySloReleaseEvidence(evidence);
  const redacted = redactObject(evidence ?? {});

  return {
    schema_version: 1,
    artifact_type: 'observability_slo_release_evidence',
    created_at: input.createdAt ?? new Date().toISOString(),
    release_id: redacted.release_id ?? null,
    validation: {
      ok: validation.ok,
      missing_controls: validation.missing_controls,
      missing_critical_controls: validation.missing_critical_controls,
      invalid_fields: validation.invalid_fields,
      forbidden_fields: validation.forbidden_fields,
    },
    environment: validation.environment ?? redacted.environment ?? null,
    incident_drill_id: redacted.incident_drill_id ?? null,
    metric_scrape_auth: redacted.metric_scrape_auth
      ? {
          auth_mechanism: redacted.metric_scrape_auth.auth_mechanism ?? null,
          gateway_reference: redacted.metric_scrape_auth.gateway_reference ?? null,
          evidence_uri: redacted.metric_scrape_auth.evidence_uri ?? null,
          validated_at: redacted.metric_scrape_auth.validated_at ?? null,
        }
      : null,
    dashboard_ids: Array.isArray(redacted.dashboard_ids) ? redacted.dashboard_ids : [],
    alert_routes: summarizeAlertRoutes(redacted.alert_routes),
    slo_targets: summarizeSloTargets(redacted.slo_targets),
    on_call: redacted.on_call
      ? {
          owner: redacted.on_call.owner ?? null,
          rotation_reference: redacted.on_call.rotation_reference ?? null,
          evidence_uri: redacted.on_call.evidence_uri ?? null,
        }
      : null,
    redaction_policy: redacted.redaction_policy
      ? {
          policy_reference: redacted.redaction_policy.policy_reference ?? null,
          summary: redacted.redaction_policy.summary ?? null,
        }
      : null,
    ...(hasValue(redacted.notes) ? { notes: redactString(String(redacted.notes)) } : {}),
    caveats: [
      'Metadata-only observability and SLO release evidence; no raw logs, trace payloads, tokens, headers, database URLs, or secrets.',
      'Passing validation does not prove live alert delivery or SLO attainment; staging incident drills and on-call staffing signoff are still required.',
    ],
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

function readInputJson(inputPath) {
  return JSON.parse(readFileSync(inputPath, 'utf8'));
}

export async function main(argv = process.argv.slice(2)) {
  const opts = parseArgs(argv);
  if (opts.help) {
    console.log(
      'Usage: node scripts/observability-slo-evidence.mjs --input evidence.json [--out file] [--validate-only]',
    );
    return 0;
  }

  const evidence = readInputJson(opts.input);
  const validation = validateObservabilitySloReleaseEvidence(evidence);
  const manifest = createObservabilitySloEvidenceManifest({
    evidence,
    createdAt: inputCreatedAt(evidence),
  });

  if (opts.validateOnly) {
    console.log(
      `observability-slo-evidence: ${validation.ok ? 'ok' : 'failed'} (environment=${manifest.environment ?? 'none'})`,
    );
    return validation.ok ? 0 : 1;
  }

  mkdirSync(path.dirname(opts.out), { recursive: true });
  writeFileSync(opts.out, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`observability-slo-evidence: wrote ${opts.out}`);

  if (!validation.ok) {
    if (validation.forbidden_fields.length > 0) {
      console.error(
        `observability-slo-evidence: forbidden field(s): ${fieldSummary(validation.forbidden_fields)}`,
      );
    }
    if (validation.missing_critical_controls.length > 0) {
      console.error(
        `observability-slo-evidence: missing critical control(s): ${fieldSummary(validation.missing_critical_controls)}`,
      );
    }
    if (validation.invalid_fields.length > 0) {
      console.error(
        `observability-slo-evidence: invalid field(s): ${fieldSummary(validation.invalid_fields)}`,
      );
    }
    return 1;
  }

  return 0;
}

function inputCreatedAt(evidence) {
  return hasValue(evidence?.created_at) ? String(evidence.created_at) : undefined;
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(`observability-slo-evidence: ${err.message}`);
      process.exit(1);
    },
  );
}