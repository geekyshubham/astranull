#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { redactObject, redactString } from '../src/lib/redact.mjs';

const SHA256_HEX_RE = /^[a-fA-F0-9]{64}$/;
const SAFE_DRILL_TYPES = new Set(['restore', 'failover']);
const SAFE_RECOVERY_DECISIONS = new Set(['rollback', 'forward_fix']);
const SAFE_CHECK_STATUS = new Set(['passed', 'failed', 'skipped']);

export const DR_RESTORE_REQUIRED_FIELDS = Object.freeze([
  'drill_id',
  'environment',
  'drill_type',
  'started_at',
  'completed_at',
  'backup_manifest',
  'restore_target',
  'rpo_rto',
  'operator_approvals',
  'evidence_custody_ids',
  'recovery_decision',
  'post_restore_verification',
]);

const FORBIDDEN_KEYS = new Set([
  'authorization',
  'body',
  'connection_string',
  'credential',
  'customer_payload',
  'database_dump',
  'database_url',
  'dump',
  'dump_contents',
  'headers',
  'log',
  'logs',
  'password',
  'payload',
  'pg_dump',
  'raw_body',
  'raw_dump',
  'raw_headers',
  'raw_log',
  'secret',
  'sql_dump',
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
  return true;
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

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function validateBackupManifest(manifest) {
  const missing = [];
  if (!isObject(manifest)) {
    return ['backup_manifest'];
  }
  if (!hasValue(manifest.manifest_uri)) missing.push('backup_manifest.manifest_uri');
  if (!hasValue(manifest.sha256) || !SHA256_HEX_RE.test(String(manifest.sha256))) {
    missing.push('backup_manifest.sha256');
  }
  if (!hasValue(manifest.backup_reference)) missing.push('backup_manifest.backup_reference');
  return missing;
}

function validateRestoreTarget(target) {
  const missing = [];
  if (!isObject(target)) {
    return ['restore_target'];
  }
  if (!hasValue(target.cluster_reference)) missing.push('restore_target.cluster_reference');
  if (!hasValue(target.database_reference)) missing.push('restore_target.database_reference');
  if (!hasValue(target.restore_mode)) missing.push('restore_target.restore_mode');
  return missing;
}

function evaluateRpoRto(rpoRto) {
  const missing = [];
  if (!isObject(rpoRto)) {
    return { missing: ['rpo_rto'], within_targets: false, failures: ['rpo_rto_missing'] };
  }
  const numericFields = [
    'rpo_target_minutes',
    'rto_target_minutes',
    'measured_rpo_minutes',
    'measured_rto_minutes',
  ];
  for (const field of numericFields) {
    const value = rpoRto[field];
    if (!Number.isFinite(value) || value < 0) {
      missing.push(`rpo_rto.${field}`);
    }
  }
  if (missing.length > 0) {
    return { missing, within_targets: false, failures: ['rpo_rto_incomplete'] };
  }
  const failures = [];
  if (rpoRto.measured_rpo_minutes > rpoRto.rpo_target_minutes) {
    failures.push('rpo_exceeded');
  }
  if (rpoRto.measured_rto_minutes > rpoRto.rto_target_minutes) {
    failures.push('rto_exceeded');
  }
  return {
    missing,
    within_targets: failures.length === 0,
    failures,
  };
}

function validateOperatorApprovals(approvals) {
  const missing = [];
  if (!Array.isArray(approvals) || approvals.length === 0) {
    return { missing: ['operator_approvals'], missing_signoff: true };
  }
  const approvalFields = ['role', 'operator', 'approved_at', 'signoff_reference'];
  let missingSignoff = false;
  for (let i = 0; i < approvals.length; i += 1) {
    const entry = approvals[i];
    if (!isObject(entry)) {
      missing.push(`operator_approvals[${i}]`);
      missingSignoff = true;
      continue;
    }
    for (const field of approvalFields) {
      if (!hasValue(entry[field])) {
        missing.push(`operator_approvals[${i}].${field}`);
        if (field === 'signoff_reference') missingSignoff = true;
      }
    }
  }
  return { missing, missing_signoff: missingSignoff };
}

function validateEvidenceCustodyIds(ids) {
  if (!Array.isArray(ids) || ids.length === 0) {
    return { missing: ['evidence_custody_ids'], invalid_ids: [] };
  }
  const invalid_ids = [];
  ids.forEach((id, index) => {
    if (typeof id !== 'string' || id.trim() === '') {
      invalid_ids.push({ index, reason: 'empty' });
    }
  });
  return {
    missing: invalid_ids.length > 0 ? ['evidence_custody_ids'] : [],
    invalid_ids,
  };
}

function validateRecoveryDecision(decision) {
  const missing = [];
  if (!isObject(decision)) {
    return ['recovery_decision'];
  }
  if (!hasValue(decision.decision) || !SAFE_RECOVERY_DECISIONS.has(decision.decision)) {
    missing.push('recovery_decision.decision');
  }
  if (!hasValue(decision.decision_reference)) missing.push('recovery_decision.decision_reference');
  if (!hasValue(decision.operator)) missing.push('recovery_decision.operator');
  if (!hasValue(decision.decided_at)) missing.push('recovery_decision.decided_at');
  return missing;
}

function validatePostRestoreVerification(verification) {
  const missing = [];
  let missingSignoff = false;
  if (!isObject(verification)) {
    return { missing: ['post_restore_verification'], missing_signoff: true };
  }
  if (!hasValue(verification.signoff_reference)) {
    missing.push('post_restore_verification.signoff_reference');
    missingSignoff = true;
  }
  const checks = verification.checks;
  if (!Array.isArray(checks) || checks.length === 0) {
    missing.push('post_restore_verification.checks');
    return { missing, missing_signoff: missingSignoff };
  }
  checks.forEach((check, index) => {
    if (!isObject(check)) {
      missing.push(`post_restore_verification.checks[${index}]`);
      return;
    }
    if (!hasValue(check.check_id)) missing.push(`post_restore_verification.checks[${index}].check_id`);
    if (!hasValue(check.status) || !SAFE_CHECK_STATUS.has(check.status)) {
      missing.push(`post_restore_verification.checks[${index}].status`);
    }
    if (!hasValue(check.evidence_uri)) {
      missing.push(`post_restore_verification.checks[${index}].evidence_uri`);
    }
  });
  return { missing, missing_signoff: missingSignoff };
}

/**
 * @param {unknown} evidence
 */
export function validateDrRestoreDrillEvidence(evidence) {
  const missing_fields = DR_RESTORE_REQUIRED_FIELDS.filter((field) => !hasValue(evidence?.[field]));
  const forbidden_fields = [...new Set(collectForbiddenFields(evidence))].sort();

  if (!hasValue(evidence?.drill_type) || !SAFE_DRILL_TYPES.has(evidence.drill_type)) {
    if (!missing_fields.includes('drill_type')) {
      missing_fields.push('drill_type');
    }
  }

  missing_fields.push(...validateBackupManifest(evidence?.backup_manifest));
  missing_fields.push(...validateRestoreTarget(evidence?.restore_target));

  const rpoRto = evaluateRpoRto(evidence?.rpo_rto);
  missing_fields.push(...rpoRto.missing);

  const approvals = validateOperatorApprovals(evidence?.operator_approvals);
  missing_fields.push(...approvals.missing);

  const custody = validateEvidenceCustodyIds(evidence?.evidence_custody_ids);
  missing_fields.push(...custody.missing);

  missing_fields.push(...validateRecoveryDecision(evidence?.recovery_decision));

  const postRestore = validatePostRestoreVerification(evidence?.post_restore_verification);
  missing_fields.push(...postRestore.missing);

  const missing_signoff = approvals.missing_signoff || postRestore.missing_signoff;

  const uniqueMissing = [...new Set(missing_fields)].sort();

  const ok =
    uniqueMissing.length === 0
    && forbidden_fields.length === 0
    && rpoRto.within_targets
    && !missing_signoff;

  return {
    ok,
    missing_fields: uniqueMissing,
    forbidden_fields,
    rpo_rto_within_targets: rpoRto.within_targets,
    rpo_rto_failures: rpoRto.failures,
    missing_signoff,
    invalid_custody_ids: custody.invalid_ids,
  };
}

export function parseDrRestoreEvidenceArgs(argv = []) {
  const opts = {
    input: null,
    out: null,
    validateOnly: false,
    help: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = () => {
      i += 1;
      if (i >= argv.length) throw new Error(`dr-restore-evidence: missing value for ${arg}`);
      return argv[i];
    };
    if (arg === '--input') opts.input = next();
    else if (arg === '--out') opts.out = next();
    else if (arg === '--validate-only') opts.validateOnly = true;
    else if (arg === '--help' || arg === '-h') opts.help = true;
    else throw new Error(`dr-restore-evidence: unknown argument ${arg}`);
  }
  if (!opts.help && !opts.input) {
    throw new Error('dr-restore-evidence: --input is required');
  }
  return opts;
}

function readDrillEvidence(inputPath) {
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(inputPath, 'utf8'));
  } catch {
    throw new Error(`dr-restore-evidence: input is not valid JSON: ${inputPath}`);
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('dr-restore-evidence: input must be a JSON object');
  }
  return parsed;
}

/**
 * @param {{ evidence: Record<string, unknown>, validation: ReturnType<typeof validateDrRestoreDrillEvidence>, createdAt?: string, notes?: string }} input
 */
export function createDrRestoreEvidenceManifest(input) {
  const { evidence, validation, createdAt, notes } = input;
  const redactedEvidence = redactObject(evidence);
  return {
    schema_version: 1,
    artifact_type: 'dr_restore_failover_drill_evidence',
    created_at: createdAt ?? new Date().toISOString(),
    validation: {
      ok: validation.ok,
      missing_fields: validation.missing_fields,
      forbidden_fields: validation.forbidden_fields,
      rpo_rto_within_targets: validation.rpo_rto_within_targets,
      rpo_rto_failures: validation.rpo_rto_failures,
      missing_signoff: validation.missing_signoff,
      invalid_custody_ids: validation.invalid_custody_ids,
    },
    drill_summary: {
      drill_id: redactedEvidence.drill_id ?? null,
      environment: redactedEvidence.environment ?? null,
      drill_type: redactedEvidence.drill_type ?? null,
      backup_manifest_sha256: redactedEvidence.backup_manifest?.sha256 ?? null,
      restore_target: redactedEvidence.restore_target
        ? {
            cluster_reference: redactedEvidence.restore_target.cluster_reference ?? null,
            database_reference: redactedEvidence.restore_target.database_reference ?? null,
            restore_mode: redactedEvidence.restore_target.restore_mode ?? null,
          }
        : null,
      recovery_decision: redactedEvidence.recovery_decision?.decision ?? null,
      evidence_custody_ids: Array.isArray(redactedEvidence.evidence_custody_ids)
        ? redactedEvidence.evidence_custody_ids
        : [],
    },
    ...(notes ? { notes: redactString(String(notes)) } : {}),
    caveats: [
      'Metadata-only DR drill evidence manifest; no database dumps, secrets, tokens, logs, or customer payloads.',
      'Production DR signoff still requires immutable custody storage and operations/security approval outside this validator.',
    ],
  };
}

export async function main(argv = process.argv.slice(2)) {
  const opts = parseDrRestoreEvidenceArgs(argv);
  if (opts.help) {
    console.log(`Usage: node scripts/dr-restore-evidence.mjs --input drill-evidence.json [--out manifest.json] [--validate-only]

Validates production restore/failover drill evidence (manifest digest, restore target, RPO/RTO, approvals, custody ids, recovery decision, post-restore checks).
Rejects raw dumps, secrets, tokens, logs, and customer payloads. Writes a metadata-only manifest when --out is set.`);
    return 0;
  }

  const evidence = readDrillEvidence(opts.input);
  const validation = validateDrRestoreDrillEvidence(evidence);
  const manifest = createDrRestoreEvidenceManifest({
    evidence,
    validation,
    notes: typeof evidence.notes === 'string' ? evidence.notes : undefined,
  });

  if (opts.validateOnly) {
    console.log(
      `dr-restore-evidence: ${validation.ok ? 'ok' : 'failed'} (drill_id=${manifest.drill_summary.drill_id ?? 'none'})`,
    );
    return validation.ok ? 0 : 1;
  }

  if (opts.out) {
    mkdirSync(path.dirname(path.resolve(opts.out)), { recursive: true });
    writeFileSync(opts.out, `${JSON.stringify(manifest, null, 2)}\n`);
    console.log(`dr-restore-evidence: wrote ${opts.out}`);
  } else {
    console.log(`dr-restore-evidence: ${validation.ok ? 'ok' : 'failed'}`);
  }

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