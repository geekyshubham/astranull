#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { redactObject, redactString } from '../src/lib/redact.mjs';

const DEFAULT_OUT = 'output/rollback-fixforward-evidence.json';

const SAFE_MIGRATION_STRATEGIES = new Set(['rollback', 'forward_fix']);

export const ROLLBACK_FIXFORWARD_REQUIRED_FIELDS = Object.freeze([
  'release_id',
  'environment',
  'owner',
  'migration_plan',
  'postgres_backup_reference',
  'tested_command_references',
  'adapter_disablement_plan',
  'probe_worker_flag_plan',
  'notification_comms_plan',
  'support_comms_plan',
  'success_criteria',
  'signoffs',
]);

const MIGRATION_PLAN_REQUIRED_FIELDS = Object.freeze([
  'plan_reference',
  'strategy',
  'migration_version',
  'decision_reference',
]);

const POSTGRES_BACKUP_REQUIRED_FIELDS = Object.freeze([
  'backup_reference',
  'manifest_uri',
]);

const PLAN_BLOCK_REQUIRED_FIELDS = Object.freeze(['plan_reference', 'runbook_reference', 'flag_reference']);

const COMMS_PLAN_REQUIRED_FIELDS = Object.freeze(['plan_reference', 'owner', 'template_references']);

const TESTED_COMMAND_ENTRY_FIELDS = Object.freeze(['command_id', 'reference_uri', 'tested_at']);

const SUCCESS_CRITERION_FIELDS = Object.freeze([
  'criterion_id',
  'check_reference',
  'expected_outcome_reference',
]);

const SIGNOFF_REQUIRED_FIELDS = Object.freeze(['role', 'operator', 'signed_at', 'signoff_reference']);

const TEMPLATE_REFERENCE_FIELDS = Object.freeze(['template_id', 'reference_uri']);

const FORBIDDEN_KEYS = new Set([
  'api_key',
  'apikey',
  'attachment',
  'attachments',
  'authorization',
  'body',
  'command_body',
  'connection_string',
  'credential',
  'credentials',
  'customer_payload',
  'database_dump',
  'database_url',
  'dump',
  'dump_contents',
  'headers',
  'log',
  'logs',
  'packet',
  'packet_capture',
  'packet_payload',
  'password',
  'payload',
  'pcap',
  'pg_dump',
  'raw_body',
  'raw_command',
  'raw_dump',
  'raw_headers',
  'raw_log',
  'raw_logs',
  'raw_packet',
  'raw_shell',
  'raw_sql',
  'script',
  'script_body',
  'secret',
  'shell_script',
  'sql_dump',
  'token',
]);

const PG_URL_RE = /postgres(?:ql)?:\/\/[^\s'"]+/gi;

const SECRET_IN_STRING_PATTERNS = [
  { pattern: /ast_v1\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){2}/, reason: 'token_pattern' },
  { pattern: /svc_v1\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){2}/, reason: 'token_pattern' },
  { pattern: /agc_v1\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){2}/, reason: 'token_pattern' },
  { pattern: /password\s*[:=]\s*\S+/i, reason: 'password_in_text' },
  { pattern: /api[_-]?key\s*[:=]\s*\S+/i, reason: 'api_key_in_text' },
];

const RAW_SHELL_PATTERNS = [
  { pattern: /^#!\/bin\//m, reason: 'raw_shell_script' },
  { pattern: /^\s*(?:sudo\s+)?(?:bash|sh|zsh)\s+-c\s+/m, reason: 'raw_shell_invocation' },
];

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
      || normalized.endsWith('_dump')
      || normalized.includes('customer_payload')
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
    for (const { pattern, reason } of SECRET_IN_STRING_PATTERNS) {
      if (pattern.test(value)) {
        pattern.lastIndex = 0;
        findings.push(`${fieldPath}:${reason}`);
      }
    }
    for (const { pattern, reason } of RAW_SHELL_PATTERNS) {
      if (pattern.test(value)) {
        pattern.lastIndex = 0;
        findings.push(`${fieldPath}:${reason}`);
      }
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

function validateMigrationPlan(plan) {
  const missing = validateNestedObject(plan, MIGRATION_PLAN_REQUIRED_FIELDS, 'migration_plan');
  if (isObject(plan) && (!hasValue(plan.strategy) || !SAFE_MIGRATION_STRATEGIES.has(plan.strategy))) {
    if (!missing.includes('migration_plan.strategy')) {
      missing.push('migration_plan.strategy');
    }
  }
  return missing;
}

function validatePostgresBackupReference(reference) {
  return validateNestedObject(reference, POSTGRES_BACKUP_REQUIRED_FIELDS, 'postgres_backup_reference');
}

function validateFlagPlan(plan, prefix) {
  return validateNestedObject(plan, PLAN_BLOCK_REQUIRED_FIELDS, prefix);
}

function validateTemplateReferences(templates, prefix) {
  const missing = [];
  if (!Array.isArray(templates) || templates.length === 0) {
    return [`${prefix}.template_references`];
  }
  templates.forEach((entry, index) => {
    if (!isObject(entry)) {
      missing.push(`${prefix}.template_references[${index}]`);
      return;
    }
    for (const field of TEMPLATE_REFERENCE_FIELDS) {
      if (!hasValue(entry[field])) {
        missing.push(`${prefix}.template_references[${index}].${field}`);
      }
    }
  });
  return missing;
}

function validateCommsPlan(plan, prefix) {
  const missing = validateNestedObject(plan, COMMS_PLAN_REQUIRED_FIELDS, prefix);
  missing.push(...validateTemplateReferences(plan?.template_references, prefix));
  return missing;
}

function validateTestedCommandReferences(entries) {
  const missing = [];
  if (!Array.isArray(entries) || entries.length === 0) {
    return { missing: ['tested_command_references'], invalid_entries: [] };
  }
  const invalid_entries = [];
  entries.forEach((entry, index) => {
    if (!isObject(entry)) {
      missing.push(`tested_command_references[${index}]`);
      invalid_entries.push({ index, reason: 'invalid_entry' });
      return;
    }
    for (const field of TESTED_COMMAND_ENTRY_FIELDS) {
      if (!hasValue(entry[field])) {
        missing.push(`tested_command_references[${index}].${field}`);
      }
    }
    const forbiddenInEntry = [
      ...collectForbiddenFields(entry, `tested_command_references[${index}]`),
      ...collectForbiddenStringPatterns(entry, `tested_command_references[${index}]`),
    ];
    if (forbiddenInEntry.length > 0) {
      invalid_entries.push({ index, reason: 'forbidden_command_metadata', fields: forbiddenInEntry });
    }
  });
  return { missing, invalid_entries };
}

function validateSuccessCriteria(criteria) {
  const missing = [];
  if (!Array.isArray(criteria) || criteria.length === 0) {
    return ['success_criteria'];
  }
  criteria.forEach((entry, index) => {
    if (!isObject(entry)) {
      missing.push(`success_criteria[${index}]`);
      return;
    }
    for (const field of SUCCESS_CRITERION_FIELDS) {
      if (!hasValue(entry[field])) {
        missing.push(`success_criteria[${index}].${field}`);
      }
    }
  });
  return missing;
}

function validateSignoffs(signoffs) {
  const missing = [];
  let missing_signoff = false;
  if (!Array.isArray(signoffs) || signoffs.length === 0) {
    return { missing: ['signoffs'], missing_signoff: true };
  }
  signoffs.forEach((entry, index) => {
    if (!isObject(entry)) {
      missing.push(`signoffs[${index}]`);
      missing_signoff = true;
      return;
    }
    for (const field of SIGNOFF_REQUIRED_FIELDS) {
      if (!hasValue(entry[field])) {
        missing.push(`signoffs[${index}].${field}`);
        if (field === 'signoff_reference') missing_signoff = true;
      }
    }
  });
  const roles = signoffs
    .filter((entry) => isObject(entry) && hasValue(entry.role))
    .map((entry) => entry.role);
  if (!roles.includes('release-owner') && !roles.includes('release_owner')) {
    missing.push('signoffs.release_owner');
    missing_signoff = true;
  }
  if (!roles.some((role) => role === 'database-operator' || role === 'database_operator')) {
    missing.push('signoffs.database_operator');
    missing_signoff = true;
  }
  return { missing, missing_signoff };
}

/**
 * @param {unknown} evidence
 */
export function validateRollbackFixforwardEvidence(evidence) {
  const missing_fields = ROLLBACK_FIXFORWARD_REQUIRED_FIELDS.filter(
    (field) => !hasValue(evidence?.[field]),
  );

  const forbidden_fields = [
    ...new Set([
      ...collectForbiddenFields(evidence),
      ...collectForbiddenStringPatterns(evidence),
    ]),
  ].sort();

  missing_fields.push(...validateMigrationPlan(evidence?.migration_plan));
  missing_fields.push(...validatePostgresBackupReference(evidence?.postgres_backup_reference));

  const testedCommands = validateTestedCommandReferences(evidence?.tested_command_references);
  missing_fields.push(...testedCommands.missing);
  if (testedCommands.invalid_entries.length > 0) {
    for (const invalid of testedCommands.invalid_entries) {
      if (invalid.fields) {
        forbidden_fields.push(...invalid.fields);
      }
    }
  }

  missing_fields.push(
    ...validateFlagPlan(evidence?.adapter_disablement_plan, 'adapter_disablement_plan'),
  );
  missing_fields.push(...validateFlagPlan(evidence?.probe_worker_flag_plan, 'probe_worker_flag_plan'));
  missing_fields.push(...validateCommsPlan(evidence?.notification_comms_plan, 'notification_comms_plan'));
  missing_fields.push(...validateCommsPlan(evidence?.support_comms_plan, 'support_comms_plan'));
  missing_fields.push(...validateSuccessCriteria(evidence?.success_criteria));

  const signoffs = validateSignoffs(evidence?.signoffs);
  missing_fields.push(...signoffs.missing);

  const uniqueMissing = [...new Set(missing_fields)].sort();
  const uniqueForbidden = [...new Set(forbidden_fields)].sort();

  const ok =
    uniqueMissing.length === 0
    && uniqueForbidden.length === 0
    && !signoffs.missing_signoff
    && testedCommands.invalid_entries.filter((entry) => entry.reason === 'forbidden_command_metadata').length === 0;

  return {
    ok,
    missing_fields: uniqueMissing,
    forbidden_fields: uniqueForbidden,
    missing_signoff: signoffs.missing_signoff,
    invalid_command_references: testedCommands.invalid_entries,
  };
}

export function parseRollbackFixforwardEvidenceArgs(argv = []) {
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
      if (i >= argv.length) throw new Error(`rollback-fixforward-evidence: missing value for ${arg}`);
      return argv[i];
    };
    if (arg === '--input') opts.input = next();
    else if (arg === '--out') opts.out = next();
    else if (arg === '--validate-only') opts.validateOnly = true;
    else if (arg === '--help' || arg === '-h') opts.help = true;
    else throw new Error(`rollback-fixforward-evidence: unknown argument ${arg}`);
  }
  if (!opts.help && !opts.input) {
    throw new Error('rollback-fixforward-evidence: --input is required');
  }
  return opts;
}

function readPlanEvidence(inputPath) {
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(inputPath, 'utf8'));
  } catch {
    throw new Error(`rollback-fixforward-evidence: input is not valid JSON: ${inputPath}`);
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('rollback-fixforward-evidence: input must be a JSON object');
  }
  if (parsed.evidence && typeof parsed.evidence === 'object' && !Array.isArray(parsed.evidence)) {
    return parsed.evidence;
  }
  return parsed;
}

/**
 * @param {{ evidence: Record<string, unknown>, validation: ReturnType<typeof validateRollbackFixforwardEvidence>, createdAt?: string }} input
 */
export function createRollbackFixforwardEvidenceManifest(input) {
  const { evidence, validation, createdAt } = input;
  const redacted = redactObject(evidence);
  return {
    schema_version: 1,
    artifact_type: 'rollback_fixforward_release_evidence',
    created_at: createdAt ?? new Date().toISOString(),
    validation: {
      ok: validation.ok,
      missing_fields: validation.missing_fields,
      forbidden_fields: validation.forbidden_fields,
      missing_signoff: validation.missing_signoff,
      invalid_command_references: validation.invalid_command_references,
    },
    plan_summary: {
      release_id: redacted.release_id ?? null,
      environment: redacted.environment ?? null,
      owner: redacted.owner ?? null,
      migration_strategy: redacted.migration_plan?.strategy ?? null,
      migration_version: redacted.migration_plan?.migration_version ?? null,
      migration_plan_reference: redacted.migration_plan?.plan_reference ?? null,
      postgres_backup_reference: redacted.postgres_backup_reference?.backup_reference ?? null,
      tested_command_count: Array.isArray(redacted.tested_command_references)
        ? redacted.tested_command_references.length
        : 0,
      adapter_disablement_plan_reference: redacted.adapter_disablement_plan?.plan_reference ?? null,
      probe_worker_flag_plan_reference: redacted.probe_worker_flag_plan?.plan_reference ?? null,
      success_criterion_count: Array.isArray(redacted.success_criteria)
        ? redacted.success_criteria.length
        : 0,
      signoff_count: Array.isArray(redacted.signoffs) ? redacted.signoffs.length : 0,
    },
    ...(typeof evidence?.notes === 'string' ? { notes: redactString(evidence.notes) } : {}),
    caveats: [
      'Metadata-only rollback/fix-forward plan evidence; no raw shell scripts, SQL dumps, packet captures, database URLs, logs, or credentials.',
      'Tested command entries must be references to approved runbooks or checklists, not executable command bodies.',
      'Production rollback or forward-fix execution still requires operator approval, immutable custody, and staging drill evidence outside this validator.',
    ],
  };
}

export async function main(argv = process.argv.slice(2)) {
  const opts = parseRollbackFixforwardEvidenceArgs(argv);
  if (opts.help) {
    console.log(`Usage: node scripts/rollback-fixforward-evidence.mjs --input plan-evidence.json [--out manifest.json] [--validate-only]

Validates production rollback/fix-forward plan metadata (release id, migration plan, backup reference,
tested command references, adapter/probe flag plans, notification/support comms, success criteria, signoffs).
Rejects credentials, raw logs, SQL dumps, packet captures, database URLs, tokens, and raw command bodies.`);
    return 0;
  }

  const evidence = readPlanEvidence(opts.input);
  const validation = validateRollbackFixforwardEvidence(evidence);
  const manifest = createRollbackFixforwardEvidenceManifest({ evidence, validation });

  if (opts.validateOnly) {
    console.log(
      `rollback-fixforward-evidence: ${validation.ok ? 'ok' : 'failed'} (release_id=${manifest.plan_summary.release_id ?? 'none'})`,
    );
    return validation.ok ? 0 : 1;
  }

  mkdirSync(path.dirname(path.resolve(opts.out)), { recursive: true });
  writeFileSync(opts.out, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`rollback-fixforward-evidence: wrote ${opts.out}`);
  return validation.ok ? 0 : 1;
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(err instanceof Error ? err.message : String(err));
      process.exit(1);
    },
  );
}