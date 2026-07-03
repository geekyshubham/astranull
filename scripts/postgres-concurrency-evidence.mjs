#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { redactObject, redactString } from '../src/lib/redact.mjs';

const DEFAULT_OUT = 'output/postgres-concurrency-evidence-manifest.json';

/** Route families that staging concurrency load must exercise (aligned with runtime-smoke wiring). */
export const REQUIRED_CONCURRENCY_ROUTE_FAMILIES = Object.freeze([
  'catalog',
  'auth',
  'agents',
  'agentUpdates',
  'testRuns',
  'events',
  'notifications',
  'reports',
  'secretVault',
  'state',
  'probeJobs',
  'highScale',
  'wafPosture',
  'wafDrift',
  'wafOrchestrator',
  'supplyChain',
  'productionReleaseEvidence',
  'retention',
  'audit',
]);

const FORBIDDEN_KEYS = new Set([
  'authorization',
  'body',
  'connection_string',
  'credential',
  'customer_data',
  'database_url',
  'headers',
  'password',
  'payload',
  'raw_body',
  'raw_headers',
  'raw_log',
  'raw_sql',
  'row_payload',
  'row_payloads',
  'rows',
  'secret',
  'sql_dump',
  'token',
  'query_text',
]);

const PG_URL_RE = /postgres(?:ql)?:\/\/[^\s'"]+/gi;
const RAW_SQL_RE =
  /\b(INSERT\s+INTO\s+[a-z_][a-z0-9_]*\s*\(|SELECT\s+[\w*,\s]+\s+FROM\s+[a-z_][a-z0-9_]*|COPY\s+[a-z_][a-z0-9_]*\s+\(|\\connect\s)/i;

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

function collectForbiddenKeys(value, keyPath = '') {
  if (value === null || value === undefined || typeof value !== 'object') return [];
  const findings = [];
  if (Array.isArray(value)) {
    value.forEach((entry, index) => {
      findings.push(...collectForbiddenKeys(entry, `${keyPath}[${index}]`));
    });
    return findings;
  }
  for (const [key, nested] of Object.entries(value)) {
    const pathLabel = keyPath ? `${keyPath}.${key}` : key;
    const normalized = normalizeKey(key);
    if (FORBIDDEN_KEYS.has(normalized) || normalized.startsWith('raw_')) {
      findings.push(pathLabel);
    }
    findings.push(...collectForbiddenKeys(nested, pathLabel));
  }
  return findings;
}

function collectForbiddenStringPatterns(value, keyPath = '') {
  if (value === null || value === undefined) return [];
  if (typeof value === 'string') {
    const findings = [];
    if (PG_URL_RE.test(value)) {
      PG_URL_RE.lastIndex = 0;
      findings.push(`${keyPath}:database_url_pattern`);
    }
    if (RAW_SQL_RE.test(value)) {
      findings.push(`${keyPath}:raw_sql_pattern`);
    }
    return findings;
  }
  if (Array.isArray(value)) {
    return value.flatMap((entry, index) =>
      collectForbiddenStringPatterns(entry, `${keyPath}[${index}]`),
    );
  }
  if (typeof value === 'object') {
    return Object.entries(value).flatMap(([key, nested]) =>
      collectForbiddenStringPatterns(nested, keyPath ? `${keyPath}.${key}` : key),
    );
  }
  return [];
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

/**
 * @param {unknown} evidence
 * @returns {{
 *   ok: boolean,
 *   errors: string[],
 *   forbidden_fields: string[],
 *   coverage_gaps: string[],
 * }}
 */
export function validatePostgresConcurrencyEvidence(evidence) {
  const errors = [];
  const forbidden_fields = [
    ...new Set([
      ...collectForbiddenKeys(evidence),
      ...collectForbiddenStringPatterns(evidence),
    ]),
  ];

  if (forbidden_fields.length > 0) {
    return { ok: false, errors, forbidden_fields, coverage_gaps: [] };
  }

  if (!evidence || typeof evidence !== 'object' || Array.isArray(evidence)) {
    return {
      ok: false,
      errors: ['evidence must be a JSON object'],
      forbidden_fields,
      coverage_gaps: [],
    };
  }

  const doc = /** @type {Record<string, unknown>} */ (evidence);

  if (doc.schema_version !== 1) {
    errors.push('schema_version must be 1');
  }
  if (doc.artifact_type !== 'postgres_tenant_concurrency_evidence') {
    errors.push('artifact_type must be postgres_tenant_concurrency_evidence');
  }
  if (!hasValue(doc.environment)) {
    errors.push('environment is required');
  }

  const tenantCount = Number(doc.tenant_count);
  if (!Number.isInteger(tenantCount) || tenantCount < 2) {
    errors.push('tenant_count must be an integer >= 2');
  }

  const concurrentActors = Number(doc.concurrent_actors);
  if (!Number.isInteger(concurrentActors) || concurrentActors < 1) {
    errors.push('concurrent_actors must be an integer >= 1');
  }

  const durationSeconds = Number(doc.duration_seconds);
  if (!Number.isFinite(durationSeconds) || durationSeconds <= 0) {
    errors.push('duration_seconds must be a positive number');
  }

  const routeFamilies = Array.isArray(doc.route_families_exercised)
    ? doc.route_families_exercised.map(String)
    : [];
  if (routeFamilies.length === 0) {
    errors.push('route_families_exercised must be a non-empty array');
  }

  const coverage_gaps = REQUIRED_CONCURRENCY_ROUTE_FAMILIES.filter(
    (family) => !routeFamilies.includes(family),
  ).map((family) => `missing_route_family:${family}`);

  const isolation =
    doc.isolation && typeof doc.isolation === 'object' && !Array.isArray(doc.isolation)
      ? /** @type {Record<string, unknown>} */ (doc.isolation)
      : null;
  if (!isolation) {
    errors.push('isolation object is required');
  } else {
    for (const field of ['cross_tenant_read_rejections', 'cross_tenant_write_rejections']) {
      const value = Number(isolation[field]);
      if (!Number.isInteger(value) || value < 0) {
        errors.push(`${field} must be a non-negative integer`);
      }
    }
    const leaks = Number(isolation.cross_tenant_leaks);
    if (!Number.isInteger(leaks) || leaks < 0) {
      errors.push('cross_tenant_leaks must be a non-negative integer');
    } else if (leaks > 0) {
      errors.push(`cross_tenant_leaks must be 0 (observed ${leaks})`);
    }
  }

  const rlsEvidence =
    doc.rls_evidence && typeof doc.rls_evidence === 'object' && !Array.isArray(doc.rls_evidence)
      ? /** @type {Record<string, unknown>} */ (doc.rls_evidence)
      : null;
  if (!rlsEvidence) {
    errors.push('rls_evidence object is required');
  } else {
    for (const field of ['error_ids', 'audit_evidence_ids']) {
      const ids = rlsEvidence[field];
      if (!Array.isArray(ids) || ids.length === 0 || ids.some((id) => !hasValue(id))) {
        errors.push(`${field} must be a non-empty array of metadata ids`);
      }
    }
  }

  const signoff =
    doc.operator_signoff &&
    typeof doc.operator_signoff === 'object' &&
    !Array.isArray(doc.operator_signoff)
      ? /** @type {Record<string, unknown>} */ (doc.operator_signoff)
      : null;
  if (!signoff) {
    errors.push('operator_signoff object is required');
  } else {
    for (const field of ['operator', 'signed_at', 'reference']) {
      if (!hasValue(signoff[field])) {
        errors.push(`operator_signoff.${field} is required`);
      }
    }
  }

  const ok =
    errors.length === 0 && forbidden_fields.length === 0 && coverage_gaps.length === 0;
  return { ok, errors, forbidden_fields, coverage_gaps };
}

/**
 * @param {Record<string, unknown>} input
 */
export function createPostgresConcurrencyManifest(input) {
  const evidence = input.evidence;
  const validation = validatePostgresConcurrencyEvidence(evidence);
  if (validation.forbidden_fields.length > 0) {
    throw new Error(
      `evidence contains forbidden content: ${validation.forbidden_fields.join(', ')}`,
    );
  }
  if (!validation.ok) {
    const parts = [...validation.errors, ...validation.coverage_gaps];
    throw new Error(parts.length > 0 ? parts.join('; ') : 'evidence validation failed');
  }

  const redacted = redactObject(evidence);
  return {
    schema_version: 1,
    artifact_type: 'postgres_tenant_concurrency_manifest',
    created_at: input.createdAt ?? new Date().toISOString(),
    validation_ok: true,
    coverage_gaps: validation.coverage_gaps,
    summary: {
      environment: redacted.environment ?? null,
      tenant_count: redacted.tenant_count ?? null,
      concurrent_actors: redacted.concurrent_actors ?? null,
      duration_seconds: redacted.duration_seconds ?? null,
      route_families_exercised: redacted.route_families_exercised ?? [],
      isolation: redacted.isolation ?? null,
      rls_evidence: redacted.rls_evidence ?? null,
      operator_signoff: redacted.operator_signoff ?? null,
    },
    caveats: [
      'Manifest records metadata-only staging concurrency/isolation evidence.',
      'Production readiness still requires live load execution, RLS audit review, and security signoff.',
    ],
  };
}

function parseInputJson(inputPath) {
  return JSON.parse(readFileSync(inputPath, 'utf8'));
}

export async function main(argv = process.argv.slice(2)) {
  const opts = parseArgs(argv);
  if (opts.help) {
    console.log(
      'Usage: node scripts/postgres-concurrency-evidence.mjs --input evidence.json [--out file] [--validate-only]',
    );
    return 0;
  }

  const evidence = parseInputJson(opts.input);
  const manifest = createPostgresConcurrencyManifest({ evidence });

  if (opts.validateOnly) {
    console.log(
      `postgres-concurrency-evidence: ok (tenant_count=${manifest.summary.tenant_count}, actors=${manifest.summary.concurrent_actors})`,
    );
    return 0;
  }

  mkdirSync(path.dirname(opts.out), { recursive: true });
  writeFileSync(opts.out, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`postgres-concurrency-evidence: wrote ${opts.out}`);
  return 0;
}

const isCli =
  process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(`postgres-concurrency-evidence: ${redactString(err.message)}`);
      process.exit(1);
    },
  );
}