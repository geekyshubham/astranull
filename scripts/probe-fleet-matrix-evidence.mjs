#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ALLOWED_PROBE_PROFILE_KINDS } from '../src/contracts/checks.mjs';
import { redactObject, redactString } from '../src/lib/redact.mjs';

const DEFAULT_OUT = 'output/probe-fleet-matrix-evidence.json';

export const PROBE_FLEET_MATRIX_REGIONS = Object.freeze([
  'us-east',
  'eu-west',
  'ap-southeast',
]);

export const PROBE_FLEET_MATRIX_CONTROLS = Object.freeze([
  'signed_job_route',
  'job_signature_verified',
  'tenant_header_signing',
  'worker_hmac_auth',
  'health_status',
  'rate_budget',
  'egress_controls',
  'abuse_monitoring',
]);

export const PROBE_FLEET_SIGNATURE_CONTROLS = Object.freeze([
  'job_signature_verified',
  'tenant_header_signing',
  'worker_hmac_auth',
]);

export const PROBE_FLEET_REQUIRED_PROBE_PROFILES = Object.freeze([...ALLOWED_PROBE_PROFILE_KINDS]);

const ALLOWED_CHECK_STATUS = new Set(['passed', 'failed', 'not_run']);
const ALLOWED_HEALTH_STATUS = new Set(['healthy', 'degraded', 'unhealthy']);

const POLL_ROUTE = '/internal/probe/jobs';
const RESULT_ROUTE_RE = /^\/internal\/probe\/jobs\/[^/]+\/result$/;

const FORBIDDEN_KEYS = new Set([
  'authorization',
  'body',
  'connection_string',
  'credential',
  'customer_payload',
  'database_url',
  'headers',
  'hmac_secret',
  'ip_inventory',
  'log',
  'log_lines',
  'logs',
  'packet',
  'packet_capture',
  'packet_payload',
  'password',
  'payload',
  'pcap',
  'probe_worker_secret',
  'raw_body',
  'raw_headers',
  'raw_log',
  'raw_packet',
  'raw_request',
  'raw_response',
  'raw_traffic',
  'request',
  'response',
  'secret',
  'target_ip_inventory',
  'target_ips',
  'token',
  'traffic',
  'traffic_capture',
  'worker_hmac_secret',
]);

const IPV4_CSV_RE = /\b(?:\d{1,3}\.){3}\d{1,3}(?:\s*,\s*(?:\d{1,3}\.){3}\d{1,3}){2,}/;

function normalizeKey(key) {
  return key
    .replace(/([a-z])([A-Z])/g, '$1_$2')
    .replace(/[^A-Za-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase();
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

function hasValue(value) {
  if (value === null || value === undefined) return false;
  if (typeof value === 'string' && value.trim() === '') return false;
  if (Array.isArray(value) && value.length === 0) return false;
  return true;
}

function parseInputJson(inputPath) {
  const parsed = JSON.parse(readFileSync(inputPath, 'utf8'));
  if (Array.isArray(parsed?.rows)) {
    return {
      fleet_id: parsed.fleet_id ?? null,
      rows: parsed.rows,
    };
  }
  if (Array.isArray(parsed)) {
    return { fleet_id: null, rows: parsed };
  }
  throw new Error('Input must be { rows: [...] } or a top-level array of fleet matrix rows.');
}

export function parseArgs(argv = []) {
  const opts = {
    input: null,
    out: DEFAULT_OUT,
    fleetId: null,
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
    else if (arg === '--fleet-id') opts.fleetId = next();
    else if (arg === '--validate-only') opts.validateOnly = true;
    else if (arg === '--help' || arg === '-h') opts.help = true;
    else throw new Error(`Unknown argument: ${arg}`);
  }
  if (!opts.help && !opts.input) throw new Error('--input is required');
  return opts;
}

function validateControlEntry(controlName, control, prefix) {
  const issues = [];
  if (!control || typeof control !== 'object') {
    issues.push(`${prefix}.${controlName}: missing control object`);
    return issues;
  }
  const status = control.status;
  if (!ALLOWED_CHECK_STATUS.has(status)) {
    issues.push(`${prefix}.${controlName}: invalid status "${status ?? 'missing'}"`);
    return issues;
  }
  if (status === 'passed' || status === 'failed') {
    if (!hasValue(control.observed_at)) {
      issues.push(`${prefix}.${controlName}: observed_at required when status is ${status}`);
    }
  }

  if (controlName === 'signed_job_route' && status === 'passed') {
    const routes = Array.isArray(control.route_paths) ? control.route_paths : [];
    if (!routes.includes(POLL_ROUTE)) {
      issues.push(`${prefix}.signed_job_route: route_paths must include ${POLL_ROUTE}`);
    }
    if (!routes.some((route) => RESULT_ROUTE_RE.test(String(route)))) {
      issues.push(`${prefix}.signed_job_route: route_paths must include a result submission path`);
    }
  }

  if (controlName === 'health_status' && status === 'passed') {
    const health = control.health;
    if (!ALLOWED_HEALTH_STATUS.has(health)) {
      issues.push(`${prefix}.health_status: health must be healthy, degraded, or unhealthy when passed`);
    }
  }

  if (controlName === 'rate_budget' && status === 'passed') {
    const maxJobs = control.max_jobs_per_minute;
    const maxRequests = control.max_requests_per_job;
    if (!Number.isFinite(Number(maxJobs)) || Number(maxJobs) <= 0) {
      issues.push(`${prefix}.rate_budget: max_jobs_per_minute must be a positive number when passed`);
    }
    if (!Number.isFinite(Number(maxRequests)) || Number(maxRequests) <= 0 || Number(maxRequests) > 5) {
      issues.push(`${prefix}.rate_budget: max_requests_per_job must be 1–5 when passed`);
    }
  }

  if (controlName === 'egress_controls' && status === 'passed') {
    if (control.default_deny !== true) {
      issues.push(`${prefix}.egress_controls: default_deny must be true when passed`);
    }
  }

  if (controlName === 'abuse_monitoring' && status === 'passed') {
    if (control.alerts_enabled !== true) {
      issues.push(`${prefix}.abuse_monitoring: alerts_enabled must be true when passed`);
    }
  }

  return issues;
}

function validateProbeProfiles(profiles, prefix) {
  const issues = [];
  if (!Array.isArray(profiles) || profiles.length === 0) {
    issues.push(`${prefix}: probe_profiles_exercised must be a non-empty array`);
    return issues;
  }
  for (const profile of profiles) {
    if (!PROBE_FLEET_REQUIRED_PROBE_PROFILES.includes(profile)) {
      issues.push(`${prefix}: unknown probe profile "${profile}"`);
    }
  }
  return issues;
}

export function validateMatrixRow(row, index = 0) {
  const region = row?.region;
  const prefix = region ?? `row[${index}]`;
  const issues = [];

  if (!PROBE_FLEET_MATRIX_REGIONS.includes(region)) {
    issues.push(`${prefix}: unknown or missing region`);
    return { ok: false, region: region ?? null, issues };
  }

  const forbidden = [
    ...collectForbiddenFields(row),
    ...collectForbiddenStringPatterns(row),
  ];
  if (forbidden.length > 0) {
    issues.push(`${prefix}: forbidden field(s): ${[...new Set(forbidden)].join(', ')}`);
  }

  if (!hasValue(row?.worker_id_redacted)) {
    issues.push(`${prefix}: worker_id_redacted is required`);
  }

  const controls = row?.controls;
  if (!controls || typeof controls !== 'object') {
    issues.push(`${prefix}: controls object is required`);
    return { ok: false, region, issues };
  }

  for (const controlName of PROBE_FLEET_MATRIX_CONTROLS) {
    issues.push(...validateControlEntry(controlName, controls[controlName], prefix));
  }

  issues.push(...validateProbeProfiles(row?.probe_profiles_exercised, prefix));

  return { ok: issues.length === 0, region, issues };
}

export function validateMatrixEvidence(input) {
  const rows = Array.isArray(input?.rows) ? input.rows : [];
  if (rows.length === 0) throw new Error('At least one fleet matrix row is required.');

  const envelopeForbidden = [
    ...collectForbiddenFields(input),
    ...collectForbiddenStringPatterns(input),
  ].filter((field) => !field.startsWith('rows'));
  if (envelopeForbidden.length > 0) {
    throw new Error(`Forbidden envelope field(s): ${[...new Set(envelopeForbidden)].join(', ')}`);
  }

  const rowResults = rows.map((row, index) => validateMatrixRow(row, index));
  const structuralIssues = rowResults.flatMap((r) => r.issues);
  if (structuralIssues.length > 0) {
    throw new Error(structuralIssues.join('; '));
  }
  return rowResults;
}

function summarizeRowControls(controls) {
  const summary = {};
  for (const name of PROBE_FLEET_MATRIX_CONTROLS) {
    summary[name] = controls?.[name]?.status ?? 'not_run';
  }
  return summary;
}

function rowOverallStatus(controlSummary) {
  if (Object.values(controlSummary).some((s) => s === 'failed')) return 'failed';
  if (Object.values(controlSummary).every((s) => s === 'passed')) return 'passed';
  return 'incomplete';
}

function sanitizeControlDetail(control) {
  if (!control || typeof control !== 'object') return null;
  const detail = {
    status: control.status,
    observed_at: control.observed_at ?? null,
  };
  if (Array.isArray(control.route_paths)) {
    detail.route_paths = control.route_paths.map((route) => redactString(String(route)));
  }
  if (control.health != null) detail.health = String(control.health);
  if (Number.isFinite(Number(control.max_jobs_per_minute))) {
    detail.max_jobs_per_minute = Number(control.max_jobs_per_minute);
  }
  if (Number.isFinite(Number(control.max_requests_per_job))) {
    detail.max_requests_per_job = Number(control.max_requests_per_job);
  }
  if (typeof control.default_deny === 'boolean') detail.default_deny = control.default_deny;
  if (typeof control.alerts_enabled === 'boolean') detail.alerts_enabled = control.alerts_enabled;
  if (Number.isFinite(Number(control.allowed_destination_count))) {
    detail.allowed_destination_count = Number(control.allowed_destination_count);
  }
  return detail;
}

function sanitizeRowMetadata(row) {
  return {
    region: row.region,
    environment: row.environment != null ? redactString(String(row.environment)) : null,
    worker_id_redacted: row.worker_id_redacted != null
      ? redactString(String(row.worker_id_redacted))
      : null,
    probe_profiles_exercised: Array.isArray(row.probe_profiles_exercised)
      ? [...row.probe_profiles_exercised]
      : [],
  };
}

function signatureCoverageGaps(rows) {
  const gaps = [];
  for (const row of rows) {
    const missing = PROBE_FLEET_SIGNATURE_CONTROLS.filter(
      (name) => row.controls?.[name]?.status !== 'passed',
    );
    if (missing.length > 0) {
      gaps.push({ region: row.region, missing_controls: missing });
    }
  }
  return gaps;
}

export function createProbeFleetMatrixSummary(input = {}) {
  const rows = Array.isArray(input.rows) ? input.rows : [];
  validateMatrixEvidence({ rows });

  const regionsPresent = new Set(rows.map((r) => r.region));
  const missingRegions = PROBE_FLEET_MATRIX_REGIONS.filter((r) => !regionsPresent.has(r));

  const profilesExercised = new Set();
  rows.forEach((row) => {
    (row.probe_profiles_exercised ?? []).forEach((profile) => profilesExercised.add(profile));
  });
  const missingProbeProfiles = PROBE_FLEET_REQUIRED_PROBE_PROFILES.filter(
    (profile) => !profilesExercised.has(profile),
  );

  const summaryRows = rows.map((row) => {
    const controlSummary = summarizeRowControls(row.controls);
    const failedControls = PROBE_FLEET_MATRIX_CONTROLS.filter(
      (name) => controlSummary[name] === 'failed',
    );
    return {
      ...sanitizeRowMetadata(row),
      status: rowOverallStatus(controlSummary),
      controls: controlSummary,
      failed_controls: failedControls,
      control_details: redactObject(
        Object.fromEntries(
          PROBE_FLEET_MATRIX_CONTROLS.map((name) => [
            name,
            sanitizeControlDetail(row.controls?.[name]),
          ]),
        ),
      ),
    };
  });

  const failedControlsGlobal = summaryRows.flatMap((r) =>
    r.failed_controls.map((control) => `${r.region}.${control}`),
  );

  const missingSignatureCoverage = signatureCoverageGaps(rows);

  let overallStatus = 'passed';
  if (
    missingRegions.length > 0
    || missingProbeProfiles.length > 0
    || missingSignatureCoverage.length > 0
    || summaryRows.some((r) => r.status === 'incomplete')
  ) {
    overallStatus = 'incomplete';
  }
  if (summaryRows.some((r) => r.status === 'failed') || failedControlsGlobal.length > 0) {
    overallStatus = 'failed';
  }
  if (
    overallStatus !== 'failed'
    && missingRegions.length === 0
    && missingProbeProfiles.length === 0
    && missingSignatureCoverage.length === 0
    && summaryRows.every((r) => r.status === 'passed')
  ) {
    overallStatus = 'passed';
  }

  return {
    schema_version: 1,
    artifact_type: 'probe_fleet_matrix_evidence',
    created_at: input.createdAt ?? new Date().toISOString(),
    fleet_id: input.fleetId ?? input.fleet_id ?? null,
    overall_status: overallStatus,
    required_regions: [...PROBE_FLEET_MATRIX_REGIONS],
    required_controls: [...PROBE_FLEET_MATRIX_CONTROLS],
    required_probe_profiles: [...PROBE_FLEET_REQUIRED_PROBE_PROFILES],
    coverage_gaps: {
      missing_regions: missingRegions,
      missing_probe_profiles: missingProbeProfiles,
      missing_signature_coverage: missingSignatureCoverage,
      failed_controls: failedControlsGlobal,
      regions_covered: [...regionsPresent].sort(),
      probe_profiles_covered: [...profilesExercised].sort(),
    },
    rows: summaryRows,
    caveats: [
      'Summary records metadata-only signed probe fleet matrix evidence (regions, redacted worker IDs, control pass/fail, bounded profile kinds).',
      'Workers remain outbound-only HMAC clients; this validator does not execute probes or generate traffic.',
      'Staging fleet execution, live lease/result paths, and operator signoff remain required for production promotion.',
    ],
  };
}

export async function main(argv = process.argv.slice(2)) {
  const opts = parseArgs(argv);
  if (opts.help) {
    console.log(
      'Usage: node scripts/probe-fleet-matrix-evidence.mjs --input matrix.json [--fleet-id id] [--out file] [--validate-only]',
    );
    return 0;
  }

  const parsed = parseInputJson(opts.input);
  const summary = createProbeFleetMatrixSummary({
    fleetId: opts.fleetId ?? parsed.fleet_id,
    rows: parsed.rows,
  });

  if (opts.validateOnly) {
    console.log(
      `probe-fleet-matrix-evidence: ok (overall_status=${summary.overall_status}, rows=${summary.rows.length})`,
    );
    return summary.overall_status === 'passed' ? 0 : 1;
  }

  mkdirSync(path.dirname(opts.out), { recursive: true });
  writeFileSync(opts.out, `${JSON.stringify(summary, null, 2)}\n`);
  console.log(
    `probe-fleet-matrix-evidence: wrote ${opts.out} (overall_status=${summary.overall_status})`,
  );
  return summary.overall_status === 'passed' ? 0 : 1;
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(`probe-fleet-matrix-evidence: ${err.message}`);
      process.exit(1);
    },
  );
}