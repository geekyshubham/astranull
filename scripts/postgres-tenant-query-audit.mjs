#!/usr/bin/env node
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateProductionReleaseEvidence } from '../src/contracts/productionReleaseEvidence.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
export const ROOT = path.resolve(__dirname, '..');

export const ARTIFACT_TYPE = 'postgres_tenant_query_audit';
export const SCHEMA_VERSION = 1;

/** Basenames skipped entirely (migrations, pool, runtime wiring, tenant helper). */
export const SKIP_FILE_BASENAMES = new Set([
  'migrations.mjs',
  'pool.mjs',
  'tenantContext.mjs',
  'runtime.mjs',
]);

/** Tables without per-tenant RLS (documented global exceptions). */
export const GLOBAL_TABLES = new Set(['schema_migrations', 'platform_metrics']);

/** Tenant-scoped tables (aligned with docs/backend/09-database-schema.md RLS set). */
export const TENANT_SCOPED_TABLES = Object.freeze([
  'tenants',
  'environments',
  'users',
  'target_groups',
  'targets',
  'bootstrap_tokens',
  'agents',
  'test_runs',
  'probe_jobs',
  'agent_jobs',
  'events',
  'verdicts',
  'findings',
  'evidence_vault',
  'reports',
  'high_scale_requests',
  'authorization_artifacts',
  'soc_notes',
  'soc_kill_switch',
  'notification_rules',
  'notification_events',
  'audit_logs',
  'service_accounts',
  'encrypted_secrets',
  'agent_update_trust_keys',
  'agent_update_releases',
  'agent_update_statuses',
  'high_scale_telemetry',
  'soc_reports',
  'notification_delivery_attempts',
  'production_release_evidence',
  'external_asset_candidates',
  'waf_assets',
  'waf_fingerprints',
  'waf_validation_runs',
  'waf_scenario_results',
  'waf_posture_snapshots',
  'waf_baselines',
  'waf_validation_plans',
  'waf_baseline_approvals',
  'waf_retest_requests',
  'waf_drift_events',
  'waf_drift_scan_results',
  'waf_connectors',
  'waf_connector_snapshots',
  'cve_pipeline_items',
  'cve_asset_matches',
  'waf_rule_recommendations',
  'discovery_entities',
  'supply_chain_risks',
  'waf_action_items',
  'waf_coverage_daily_rollups',
  'waf_scenario_intakes',
]);

const TENANT_TABLE_RE = new RegExp(
  `\\b(?:FROM|INTO|UPDATE|JOIN|DELETE\\s+FROM)\\s+(${TENANT_SCOPED_TABLES.join('|')})\\b`,
  'gi',
);

const CONTEXT_BEFORE_CHARS = 2400;
const MAX_QUERY_LABEL_LEN = 48;

const FORBIDDEN_OUTPUT_PATTERNS = [
  /\bcustomer_data\b/i,
  /postgres(?:ql)?:\/\//i,
  /\bINSERT\s+INTO\s+\w+\s*\([^)]{40,}/i,
  /\bSELECT\s+[\w*,\s]{60,}\s+FROM\b/i,
];

const ALLOW_COMMENT_RE = /tenant-query-audit:\s*(?:allow|global)/i;

/**
 * @param {string} root
 */
export function defaultPostgresAuditPaths(root = ROOT) {
  const dir = path.join(root, 'src', 'persistence', 'postgres');
  return readdirSync(dir)
    .filter(
      (name) =>
        (name.endsWith('Repository.mjs') || name.endsWith('ServiceAdapters.mjs')) &&
        !SKIP_FILE_BASENAMES.has(name),
    )
    .map((name) => path.join(dir, name))
    .sort();
}

/**
 * @param {string[]} argv
 */
export function parseArgs(argv) {
  const options = {
    paths: [],
    out: '',
    evidenceUri: '',
    allowFindings: false,
    help: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') {
      options.help = true;
      continue;
    }
    if (arg === '--allow-findings') {
      options.allowFindings = true;
      continue;
    }
    if (arg === '--evidence-uri') {
      options.evidenceUri = argv[i + 1] ?? '';
      i += 1;
      continue;
    }
    if (arg === '--out') {
      options.out = argv[i + 1] ?? '';
      i += 1;
      continue;
    }
    if (arg === '--paths') {
      const value = argv[i + 1] ?? '';
      i += 1;
      if (!value.trim()) {
        throw new Error('--paths requires a comma-separated file list.');
      }
      options.paths.push(
        ...value
          .split(',')
          .map((entry) => entry.trim())
          .filter(Boolean),
      );
      continue;
    }
    throw new Error(`Unknown argument: ${arg}`);
  }

  return options;
}

function lineNumberAt(source, index) {
  let line = 1;
  for (let i = 0; i < index && i < source.length; i += 1) {
    if (source[i] === '\n') line += 1;
  }
  return line;
}

/**
 * @param {string} source
 */
export function extractTemplateLiteralRegions(source) {
  /** @type {Array<{ content: string, startIndex: number, startLine: number }>} */
  const regions = [];
  let i = 0;
  while (i < source.length) {
    if (source[i] !== '`') {
      i += 1;
      continue;
    }
    const startIndex = i;
    const startLine = lineNumberAt(source, startIndex);
    i += 1;
    let content = '';
    while (i < source.length) {
      const ch = source[i];
      if (ch === '\\') {
        content += ' ';
        i += 2;
        continue;
      }
      if (ch === '$' && source[i + 1] === '{') {
        content += ' ';
        i += 2;
        let depth = 1;
        while (i < source.length && depth > 0) {
          if (source[i] === '{') depth += 1;
          else if (source[i] === '}') depth -= 1;
          i += 1;
        }
        continue;
      }
      if (ch === '`') {
        i += 1;
        regions.push({ content, startIndex, startLine });
        break;
      }
      content += ch;
      i += 1;
    }
  }
  return regions;
}

/**
 * @param {string} sql
 * @param {string} table
 */
export function buildQueryLabel(sql, table) {
  const compact = sql.replace(/\s+/g, ' ').trim();
  const match = compact.match(
    /\b(SELECT|INSERT|UPDATE|DELETE)\b[\s\S]*?\b(?:FROM|INTO)\s+([a-z_][a-z0-9_]*)/i,
  );
  const verb = match?.[1]?.toUpperCase() ?? 'QUERY';
  const label = `${verb}:${table}`;
  if (label.length <= MAX_QUERY_LABEL_LEN) return label;
  return label.slice(0, MAX_QUERY_LABEL_LEN);
}

/**
 * @param {string} sql
 * @param {string} table
 * @param {string} contextBefore
 */
const CROSS_TENANT_ENUMERATION_RE = /\bSELECT\s+DISTINCT\s+tenant_id\b/i;

export function hasTenantContext(sql, table, contextBefore) {
  if (ALLOW_COMMENT_RE.test(contextBefore)) return true;
  if (CROSS_TENANT_ENUMERATION_RE.test(sql) && !/\bwithTenantContext\b/.test(contextBefore)) {
    return false;
  }
  if (/\btenant_id\b/i.test(sql) && !CROSS_TENANT_ENUMERATION_RE.test(sql)) return true;
  if (/app\.tenant_id|set_config\s*\(\s*['"]app\.tenant_id['"]|current_setting\s*\(\s*['"]app\.tenant_id['"]/i.test(
    `${contextBefore}\n${sql}`,
  )) {
    return true;
  }
  if (/\bwithTenantContext\b/.test(contextBefore)) return true;
  if (/\btenant_id\s*=\s*\$/i.test(contextBefore)) return true;
  if (/['"]tenant_id\s*=\s*\$1['"]/.test(contextBefore)) return true;
  if (/\['tenant_id\s*=\s*\$1'\]/.test(contextBefore)) return true;
  if (/\bconditions\s*=\s*\[[^\]]*tenant_id\s*=\s*\$1/.test(contextBefore)) return true;
  if (table === 'tenants' && /\bWHERE\s+id\s*=\s*\$/i.test(sql)) return true;
  return false;
}

/**
 * @param {string} filePath
 * @param {string} root
 */
export function normalizeAuditPath(filePath, root = ROOT) {
  const resolved = path.resolve(filePath);
  const rootResolved = path.resolve(root);
  const prefix = `${rootResolved}${path.sep}`;
  if (resolved === rootResolved) return '';
  if (resolved.startsWith(prefix)) {
    return path.relative(rootResolved, resolved).split(path.sep).join('/');
  }
  return filePath;
}

/**
 * @param {ReturnType<typeof auditFiles>} report
 * @param {string} [root]
 */
export function normalizeAuditReport(report, root = ROOT) {
  return {
    ...report,
    scanned_files: report.scanned_files.map((file) => normalizeAuditPath(file, root)),
    findings: report.findings.map((finding) => ({
      ...finding,
      file: normalizeAuditPath(finding.file, root),
    })),
  };
}

/**
 * @param {string} source
 */
export function extractSingleQuotedQueryRegions(source) {
  /** @type {Array<{ content: string, startIndex: number, startLine: number }>} */
  const regions = [];
  const re = /\.query\s*\(\s*'((?:\\'|[^'])*)'/g;
  let match = re.exec(source);
  while (match) {
    const content = match[1].replace(/\\'/g, "'");
    const startIndex = match.index;
    regions.push({
      content,
      startIndex,
      startLine: lineNumberAt(source, startIndex),
    });
    match = re.exec(source);
  }
  return regions;
}

function auditSqlRegions(filePath, source, regions) {
  /** @type {Array<{ file: string, line: number, check: string, table: string, query_label: string }>} */
  const findings = [];

  for (const region of regions) {
    const contextBefore = source.slice(
      Math.max(0, region.startIndex - CONTEXT_BEFORE_CHARS),
      region.startIndex,
    );
    TENANT_TABLE_RE.lastIndex = 0;
    let match = TENANT_TABLE_RE.exec(region.content);
    while (match) {
      const table = match[1].toLowerCase();
      if (!GLOBAL_TABLES.has(table)) {
        if (!hasTenantContext(region.content, table, contextBefore)) {
          const line = region.startLine + (region.content.slice(0, match.index).match(/\n/g)?.length ?? 0);
          findings.push({
            file: filePath,
            line,
            check: 'missing_tenant_context',
            table,
            query_label: buildQueryLabel(region.content, table),
          });
        }
      }
      match = TENANT_TABLE_RE.exec(region.content);
    }
  }

  return findings;
}

/**
 * @param {string} filePath
 * @param {string} source
 */
export function auditSourceFile(filePath, source) {
  const basename = path.basename(filePath);
  if (SKIP_FILE_BASENAMES.has(basename)) {
    return [];
  }

  const templateRegions = extractTemplateLiteralRegions(source);
  const quotedRegions = extractSingleQuotedQueryRegions(source);
  return auditSqlRegions(filePath, source, [...templateRegions, ...quotedRegions]);
}

/**
 * @param {{ root?: string, paths?: string[], evidenceUri?: string, allowFindings?: boolean }} [options]
 */
export function buildProductionTenantQueryAuditEvidence(options = {}) {
  const root = options.root ?? ROOT;
  const filePaths =
    options.paths?.length > 0
      ? options.paths.map((entry) => path.resolve(root, entry))
      : defaultPostgresAuditPaths(root);
  const report = normalizeAuditReport(auditFiles(filePaths), root);
  assertReportMetadataOnly(report);
  if (report.finding_count > 0 && !options.allowFindings) {
    throw new Error(`postgres tenant query audit has ${report.finding_count} finding(s)`);
  }
  const evidence = {
    ...report,
    evidence_uri: options.evidenceUri ?? 'evidence://db/tenant-query-audit',
  };
  const validation = validateProductionReleaseEvidence('postgres_tenant_query_audit', evidence);
  if (!validation.ok) {
    const problems = [
      ...validation.missing_fields.map((field) => `missing:${field}`),
      ...validation.forbidden_fields.map((field) => `forbidden:${field}`),
      validation.invalid_kind ? `invalid_kind:${validation.invalid_kind}` : null,
    ].filter(Boolean);
    throw new Error(`postgres tenant query audit evidence invalid (${problems.join(', ')})`);
  }
  return evidence;
}

/**
 * @param {string[]} filePaths
 */
export function auditFiles(filePaths) {
  /** @type {Array<{ file: string, line: number, check: string, table: string, query_label: string }>} */
  const findings = [];
  const scanned_files = [];

  for (const filePath of filePaths) {
    const basename = path.basename(filePath);
    if (SKIP_FILE_BASENAMES.has(basename)) continue;
    scanned_files.push(filePath);
    const source = readFileSync(filePath, 'utf8');
    findings.push(...auditSourceFile(filePath, source));
  }

  return {
    artifact_type: ARTIFACT_TYPE,
    schema_version: SCHEMA_VERSION,
    scanned_files,
    finding_count: findings.length,
    findings,
  };
}

/**
 * @param {ReturnType<typeof auditFiles>} report
 */
export function assertReportMetadataOnly(report) {
  const serialized = JSON.stringify(report);
  for (const pattern of FORBIDDEN_OUTPUT_PATTERNS) {
    if (pattern.test(serialized)) {
      throw new Error(`Report violates metadata-only contract: ${pattern}`);
    }
  }
  for (const finding of report.findings) {
    if (!finding.query_label || finding.query_label.length > MAX_QUERY_LABEL_LEN) {
      throw new Error('query_label exceeds allowed length.');
    }
    if (/\b(WHERE|VALUES|RETURNING)\b/i.test(finding.query_label)) {
      throw new Error('query_label must not embed SQL fragments.');
    }
  }
  return true;
}

/**
 * @param {string[]} argv
 */
export function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  if (options.help) {
    process.stdout.write(
      [
        'Usage: node scripts/postgres-tenant-query-audit.mjs [options]',
        '',
        '  --paths <a.mjs,b.mjs>   Comma-separated files (default: postgres repositories/adapters)',
        '  --out <file.json>       Write metadata-only JSON report',
        '  --evidence-uri <uri>    Attach production release evidence custody pointer',
        '  --allow-findings        Exit 0 even when findings are present',
        '  -h, --help              Show help',
        '',
      ].join('\n'),
    );
    return 0;
  }

  const filePaths =
    options.paths.length > 0 ? options.paths.map((p) => path.resolve(p)) : defaultPostgresAuditPaths();

  let report = auditFiles(filePaths);
  report = normalizeAuditReport(report, ROOT);
  assertReportMetadataOnly(report);
  if (options.evidenceUri) {
    report = { ...report, evidence_uri: options.evidenceUri };
  }

  const payload = `${JSON.stringify(report, null, 2)}\n`;
  if (options.out) {
    const outPath = path.resolve(options.out);
    mkdirSync(path.dirname(outPath), { recursive: true });
    writeFileSync(outPath, payload);
  } else {
    process.stdout.write(payload);
  }

  if (report.finding_count > 0 && !options.allowFindings) {
    return 1;
  }
  return 0;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  process.exitCode = main();
}