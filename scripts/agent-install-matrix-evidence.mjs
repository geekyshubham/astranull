#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { redactObject, redactString } from '../src/lib/redact.mjs';

const DEFAULT_OUT = 'output/agent-install-matrix-evidence.json';

export const AGENT_INSTALL_MATRIX_FORMATS = Object.freeze([
  'generic',
  'deb',
  'rpm',
  'container',
  'kubernetes',
]);

export const AGENT_INSTALL_MATRIX_CHECKS = Object.freeze([
  'install',
  'heartbeat',
  'job_poll',
  'upgrade_rollback',
  'revoke',
  'uninstall',
  'no_inbound_port',
]);

const ALLOWED_CHECK_STATUS = new Set(['passed', 'failed', 'not_run']);

const FORBIDDEN_KEYS = new Set([
  'authorization',
  'body',
  'bootstrap_token',
  'connection_string',
  'credential',
  'database_url',
  'headers',
  'log',
  'log_lines',
  'logs',
  'password',
  'payload',
  'raw_body',
  'raw_headers',
  'raw_log',
  'secret',
  'token',
]);

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
    if (FORBIDDEN_KEYS.has(normalized) || normalized.startsWith('raw_')) {
      findings.push(keyPath);
    }
    findings.push(...collectForbiddenFields(nested, keyPath));
  }
  return findings;
}

function hasValue(value) {
  if (value === null || value === undefined) return false;
  if (typeof value === 'string' && value.trim() === '') return false;
  return true;
}

function parseInputJson(inputPath) {
  const parsed = JSON.parse(readFileSync(inputPath, 'utf8'));
  if (Array.isArray(parsed?.rows)) {
    return {
      matrix_id: parsed.matrix_id ?? null,
      rows: parsed.rows,
    };
  }
  if (Array.isArray(parsed)) {
    return { matrix_id: null, rows: parsed };
  }
  throw new Error('Input must be { rows: [...] } or a top-level array of matrix rows.');
}

export function parseArgs(argv = []) {
  const opts = {
    input: null,
    out: DEFAULT_OUT,
    matrixId: null,
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
    else if (arg === '--matrix-id') opts.matrixId = next();
    else if (arg === '--validate-only') opts.validateOnly = true;
    else if (arg === '--help' || arg === '-h') opts.help = true;
    else throw new Error(`Unknown argument: ${arg}`);
  }
  if (!opts.help && !opts.input) throw new Error('--input is required');
  return opts;
}

function validateCheckEntry(checkName, check, format) {
  const issues = [];
  if (!check || typeof check !== 'object') {
    issues.push(`${format}.${checkName}: missing check object`);
    return issues;
  }
  const status = check.status;
  if (!ALLOWED_CHECK_STATUS.has(status)) {
    issues.push(`${format}.${checkName}: invalid status "${status ?? 'missing'}"`);
    return issues;
  }
  if (status === 'passed' || status === 'failed') {
    if (!hasValue(check.observed_at)) {
      issues.push(`${format}.${checkName}: observed_at required when status is ${status}`);
    }
  }
  if (checkName === 'no_inbound_port' && status === 'passed') {
    if (check.inbound_listener_count !== 0) {
      issues.push(`${format}.${checkName}: inbound_listener_count must be 0 when passed`);
    }
  }
  return issues;
}

export function validateMatrixRow(row, index = 0) {
  const format = row?.format;
  const prefix = format ?? `row[${index}]`;
  const issues = [];

  if (!AGENT_INSTALL_MATRIX_FORMATS.includes(format)) {
    issues.push(`${prefix}: unknown or missing format`);
    return { ok: false, format: format ?? null, issues };
  }

  const forbidden = collectForbiddenFields(row);
  if (forbidden.length > 0) {
    issues.push(`${prefix}: forbidden field(s): ${forbidden.join(', ')}`);
  }

  const checks = row?.checks;
  if (!checks || typeof checks !== 'object') {
    issues.push(`${prefix}: checks object is required`);
    return { ok: false, format, issues };
  }

  for (const checkName of AGENT_INSTALL_MATRIX_CHECKS) {
    issues.push(...validateCheckEntry(checkName, checks[checkName], prefix));
  }

  return { ok: issues.length === 0, format, issues };
}

export function validateMatrixEvidence(input) {
  const rows = Array.isArray(input?.rows) ? input.rows : [];
  if (rows.length === 0) throw new Error('At least one matrix row is required.');

  const rowResults = rows.map((row, index) => validateMatrixRow(row, index));
  const structuralIssues = rowResults.flatMap((r) => r.issues);
  if (structuralIssues.length > 0) {
    throw new Error(structuralIssues.join('; '));
  }
  return rowResults;
}

function summarizeRowChecks(checks) {
  const summary = {};
  for (const name of AGENT_INSTALL_MATRIX_CHECKS) {
    summary[name] = checks?.[name]?.status ?? 'not_run';
  }
  return summary;
}

function rowOverallStatus(checkSummary) {
  if (Object.values(checkSummary).some((s) => s === 'failed')) return 'failed';
  if (Object.values(checkSummary).every((s) => s === 'passed')) return 'passed';
  return 'incomplete';
}

function sanitizeRowMetadata(row) {
  const out = {
    format: row.format,
    environment: row.environment != null ? redactString(String(row.environment)) : null,
    distro: row.distro != null ? redactString(String(row.distro)) : null,
  };
  if (row.agent_id_redacted != null) {
    out.agent_id_redacted = redactString(String(row.agent_id_redacted));
  }
  if (typeof row.heartbeat_count === 'number') out.heartbeat_count = row.heartbeat_count;
  if (typeof row.job_poll_count === 'number') out.job_poll_count = row.job_poll_count;
  return out;
}

function sanitizeCheckDetail(check) {
  if (!check || typeof check !== 'object') return null;
  const detail = {
    status: check.status,
    observed_at: check.observed_at ?? null,
  };
  if (typeof check.heartbeat_count === 'number') detail.heartbeat_count = check.heartbeat_count;
  if (typeof check.job_poll_count === 'number') detail.job_poll_count = check.job_poll_count;
  if (typeof check.inbound_listener_count === 'number') {
    detail.inbound_listener_count = check.inbound_listener_count;
  }
  if (check.agent_id_redacted != null) {
    detail.agent_id_redacted = redactString(String(check.agent_id_redacted));
  }
  return detail;
}

export function createAgentInstallMatrixSummary(input = {}) {
  const rows = Array.isArray(input.rows) ? input.rows : [];
  validateMatrixEvidence({ rows });

  const formatsPresent = new Set(rows.map((r) => r.format));
  const missingFormats = AGENT_INSTALL_MATRIX_FORMATS.filter((f) => !formatsPresent.has(f));

  const summaryRows = rows.map((row) => {
    const checkSummary = summarizeRowChecks(row.checks);
    const failedChecks = AGENT_INSTALL_MATRIX_CHECKS.filter((name) => checkSummary[name] === 'failed');
    return {
      ...sanitizeRowMetadata(row),
      status: rowOverallStatus(checkSummary),
      checks: checkSummary,
      failed_checks: failedChecks,
      check_details: redactObject(
        Object.fromEntries(
          AGENT_INSTALL_MATRIX_CHECKS.map((name) => [name, sanitizeCheckDetail(row.checks?.[name])]),
        ),
      ),
    };
  });

  const failedChecksGlobal = summaryRows.flatMap((r) =>
    r.failed_checks.map((check) => `${r.format}.${check}`),
  );

  let overallStatus = 'passed';
  if (missingFormats.length > 0 || summaryRows.some((r) => r.status === 'incomplete')) {
    overallStatus = 'incomplete';
  }
  if (summaryRows.some((r) => r.status === 'failed') || failedChecksGlobal.length > 0) {
    overallStatus = 'failed';
  }
  if (
    overallStatus !== 'failed'
    && missingFormats.length === 0
    && summaryRows.every((r) => r.status === 'passed')
  ) {
    overallStatus = 'passed';
  }

  return {
    schema_version: 1,
    artifact_type: 'agent_install_matrix_evidence',
    created_at: input.createdAt ?? new Date().toISOString(),
    matrix_id: input.matrixId ?? input.matrix_id ?? null,
    overall_status: overallStatus,
    required_formats: [...AGENT_INSTALL_MATRIX_FORMATS],
    required_checks: [...AGENT_INSTALL_MATRIX_CHECKS],
    coverage_gaps: {
      missing_formats: missingFormats,
      failed_checks: failedChecksGlobal,
      formats_covered: [...formatsPresent].sort(),
    },
    rows: summaryRows,
    caveats: [
      'Summary records metadata-only install/uninstall matrix evidence (pass/fail, counts, redacted IDs, timestamps).',
      'Agents remain outbound-only; no inbound management port requirement is validated via no_inbound_port rows.',
      'Production promotion still requires signed packages, hosted artifact custody, distro/Kubernetes fleet drills, and operator signoff.',
    ],
  };
}

export async function main(argv = process.argv.slice(2)) {
  const opts = parseArgs(argv);
  if (opts.help) {
    console.log(
      'Usage: node scripts/agent-install-matrix-evidence.mjs --input matrix.json [--matrix-id id] [--out file] [--validate-only]',
    );
    return 0;
  }

  const parsed = parseInputJson(opts.input);
  const summary = createAgentInstallMatrixSummary({
    matrixId: opts.matrixId ?? parsed.matrix_id,
    rows: parsed.rows,
  });

  if (opts.validateOnly) {
    console.log(
      `agent-install-matrix-evidence: ok (overall_status=${summary.overall_status}, rows=${summary.rows.length})`,
    );
    return summary.overall_status === 'passed' ? 0 : 1;
  }

  mkdirSync(path.dirname(opts.out), { recursive: true });
  writeFileSync(opts.out, `${JSON.stringify(summary, null, 2)}\n`);
  console.log(`agent-install-matrix-evidence: wrote ${opts.out} (overall_status=${summary.overall_status})`);
  return summary.overall_status === 'passed' ? 0 : 1;
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(`agent-install-matrix-evidence: ${err.message}`);
      process.exit(1);
    },
  );
}