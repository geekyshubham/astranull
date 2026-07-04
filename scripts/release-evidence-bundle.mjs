#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  PRODUCTION_RELEASE_EVIDENCE_KINDS,
  validateProductionReleaseEvidence,
} from '../src/contracts/productionReleaseEvidence.mjs';
import {
  assertSubmittableEvidencePayload,
  assertSubmittableEvidenceRecord,
} from '../src/contracts/releaseEvidenceProvenance.mjs';
import { redactObject, redactString } from '../src/lib/redact.mjs';
import {
  isRehearsalOrSampleEvidenceInput,
} from './staging-readiness-attestation.mjs';

const DEFAULT_OUT = 'output/release-evidence-bundle.json';

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

export function parseInputJson(inputPath) {
  const parsed = JSON.parse(readFileSync(inputPath, 'utf8'));
  if (Array.isArray(parsed)) {
    return { records: parsed };
  }
  if (parsed && typeof parsed === 'object' && Array.isArray(parsed.records)) {
    return {
      records: parsed.records,
      release_id: parsed.release_id ?? null,
      rehearsal_only: parsed.rehearsal_only === true ? true : undefined,
      createdAt: parsed.created_at ?? null,
      notes: parsed.notes ?? null,
    };
  }
  throw new Error('Input must be an array or an object with records[].');
}

function fieldSummary(fields) {
  return fields.length > 0 ? fields.join(', ') : 'none';
}

function invalidFieldSummary(invalidFields) {
  return invalidFields
    .map((entry) => (typeof entry === 'string' ? entry : entry?.field ?? String(entry)))
    .join(', ');
}

function assertProductionBundleInput(input = {}, options = {}) {
  if (options.allowRehearsalSampleBundle === true) return;
  if (isRehearsalOrSampleEvidenceInput(input)) {
    throw new Error(
      'Rehearsal/sample evidence cannot be bundled for production submission.',
    );
  }
}

export function summarizeBundleCoverage(records) {
  const kindsPresent = [...new Set(records.map((record) => record?.kind).filter(Boolean))].sort();
  const kindsMissing = PRODUCTION_RELEASE_EVIDENCE_KINDS.filter((kind) => !kindsPresent.includes(kind));
  return {
    supported_kinds: [...PRODUCTION_RELEASE_EVIDENCE_KINDS],
    kinds_present: kindsPresent,
    kinds_missing: kindsMissing,
    complete: kindsMissing.length === 0,
  };
}

export function validateEvidenceRecord(record) {
  const kind = record?.kind;
  const evidence = record?.evidence;
  const validation = validateProductionReleaseEvidence(kind, evidence);
  if (validation.invalid_kind) {
    throw new Error(`Invalid evidence kind: ${validation.invalid_kind}`);
  }
  if (validation.missing_fields.length > 0) {
    throw new Error(`${kind} missing required field(s): ${fieldSummary(validation.missing_fields)}`);
  }
  if (validation.forbidden_fields.length > 0) {
    throw new Error(`${kind} contains forbidden field(s): ${fieldSummary(validation.forbidden_fields)}`);
  }
  const invalidFields = validation.invalid_fields ?? [];
  if (invalidFields.length > 0) {
    throw new Error(`${kind} contains invalid field(s): ${invalidFieldSummary(invalidFields)}`);
  }
  return {
    kind,
    evidence: redactObject(evidence),
    validation,
    ...(record.notes ? { notes: redactString(String(record.notes)) } : {}),
  };
}

export function createReleaseEvidenceBundle(input = {}, options = {}) {
  const records = Array.isArray(input.records) ? input.records : [];
  if (records.length === 0) throw new Error('At least one evidence record is required.');
  assertSubmittableEvidencePayload(input, 'Bundle input');
  for (const record of records) {
    assertSubmittableEvidenceRecord(record, 'Bundle record');
  }
  assertProductionBundleInput(
    {
      rehearsal_only: input.rehearsal_only,
      releaseId: input.releaseId ?? input.release_id ?? null,
      records,
    },
    options,
  );
  const releaseId = input.releaseId ?? input.release_id ?? null;
  return {
    schema_version: 1,
    artifact_type: 'production_release_evidence_bundle',
    created_at: input.createdAt ?? new Date().toISOString(),
    release_id: releaseId,
    coverage: summarizeBundleCoverage(records),
    records: records.map((record) => ({
      ...validateEvidenceRecord(record),
      release_id: record.release_id ?? releaseId,
    })),
    caveats: [
      'Bundle records metadata-only release evidence for API submission or review.',
      'Production readiness still requires staging execution, operator/security signoff, and durable artifact custody.',
    ],
  };
}

export async function main(argv = process.argv.slice(2)) {
  const opts = parseArgs(argv);
  if (opts.help) {
    console.log('Usage: node scripts/release-evidence-bundle.mjs --input evidence.json [--release-id rel] [--out file] [--validate-only]');
    console.log(`Supported evidence kinds (${PRODUCTION_RELEASE_EVIDENCE_KINDS.length}): ${PRODUCTION_RELEASE_EVIDENCE_KINDS.join(', ')}`);
    return 0;
  }

  const parsed = parseInputJson(opts.input);
  const bundle = createReleaseEvidenceBundle({
    releaseId: opts.releaseId ?? parsed.release_id ?? null,
    rehearsal_only: parsed.rehearsal_only,
    records: parsed.records,
    createdAt: parsed.createdAt ?? undefined,
    notes: parsed.notes ?? undefined,
  });

  if (opts.validateOnly) {
    const { kinds_present: kindsPresent, kinds_missing: kindsMissing, complete } = bundle.coverage;
    const coverageSummary = complete
      ? 'all supported kinds present'
      : `${kindsMissing.length} kind(s) missing: ${fieldSummary(kindsMissing)}`;
    console.log(
      `release-evidence-bundle: ok (${bundle.records.length} record(s), `
      + `kinds=${fieldSummary(kindsPresent)}, release_id=${bundle.release_id ?? 'none'}, ${coverageSummary})`,
    );
    return 0;
  }

  mkdirSync(path.dirname(opts.out), { recursive: true });
  writeFileSync(opts.out, `${JSON.stringify(bundle, null, 2)}\n`);
  console.log(`release-evidence-bundle: wrote ${opts.out}`);
  return 0;
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(`release-evidence-bundle: ${err.message}`);
      process.exit(1);
    },
  );
}
