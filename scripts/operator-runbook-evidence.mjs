#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateProductionReleaseEvidence } from '../src/contracts/productionReleaseEvidence.mjs';
import { redactObject, redactString } from '../src/lib/redact.mjs';

const DEFAULT_OUT = 'output/operator-runbook-evidence.json';
const EVIDENCE_KIND = 'operator_runbook_exercise';

export function parseArgs(argv = []) {
  const opts = {
    input: null,
    out: DEFAULT_OUT,
    releaseId: null,
    environment: 'staging-sim',
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
    else if (arg === '--environment') opts.environment = next();
    else if (arg === '--validate-only') opts.validateOnly = true;
    else if (arg === '--help' || arg === '-h') opts.help = true;
    else throw new Error(`Unknown argument: ${arg}`);
  }
  return opts;
}

function readInputEvidence(inputPath) {
  const parsed = JSON.parse(readFileSync(inputPath, 'utf8'));
  if (parsed?.evidence && typeof parsed.evidence === 'object') return parsed.evidence;
  return parsed;
}

export function buildDefaultOperatorRunbookEvidence(input = {}) {
  const createdAt = input.createdAt ?? new Date().toISOString();
  const environment = input.environment ?? 'staging-sim';
  const endAt = input.exerciseEndAt ?? createdAt;
  return {
    environment,
    runbook_version: input.runbookVersion ?? '2026-07-03',
    exercise_window: `${createdAt}/${endAt}`,
    operator: input.operator ?? 'release-manager',
    evidence_uri: `evidence://runbook/${environment}-exercise`,
    exceptions: [],
    signoff_reference: 'signoff://ops-security/staging-sim',
  };
}

export function createOperatorRunbookEvidenceArtifact(input = {}) {
  const evidence = input.evidence ?? buildDefaultOperatorRunbookEvidence(input);
  const validation = validateProductionReleaseEvidence(EVIDENCE_KIND, evidence);
  const redactedEvidence = redactObject(evidence);
  const releaseId = input.releaseId ?? null;

  return {
    schema_version: 1,
    artifact_type: 'operator_runbook_exercise_evidence',
    created_at: input.createdAt ?? new Date().toISOString(),
    release_id: releaseId,
    validation: {
      ok: validation.ok,
      missing_fields: validation.missing_fields,
      forbidden_fields: validation.forbidden_fields,
      invalid_fields: validation.invalid_fields ?? [],
    },
    production_release_evidence: {
      kind: EVIDENCE_KIND,
      evidence: redactedEvidence,
      ...(releaseId ? { release_id: releaseId } : {}),
    },
    ...(input.notes ? { notes: redactString(String(input.notes)) } : {}),
    caveats: [
      'Metadata-only operator runbook exercise attestation; no raw logs, credentials, or customer payloads.',
      'Signoff references are custody pointers; staging execution proof remains out of band.',
      'Production promotion still requires live staging runbook exercise and ops/security signoff.',
    ],
  };
}

export async function main(argv = process.argv.slice(2)) {
  const opts = parseArgs(argv);
  if (opts.help) {
    console.log(
      'Usage: node scripts/operator-runbook-evidence.mjs '
      + '[--input evidence.json] [--out file] [--release-id rel] '
      + '[--environment staging-sim] [--validate-only]',
    );
    return 0;
  }

  const evidence = opts.input
    ? readInputEvidence(opts.input)
    : buildDefaultOperatorRunbookEvidence({ environment: opts.environment });
  const artifact = createOperatorRunbookEvidenceArtifact({
    evidence,
    releaseId: opts.releaseId,
    environment: opts.environment,
  });

  if (!artifact.validation.ok) {
    throw new Error(
      `operator-runbook-evidence: invalid (${artifact.validation.missing_fields.join(', ') || 'validation failed'})`,
    );
  }

  if (opts.validateOnly) {
    console.log(`operator-runbook-evidence: ok (environment=${evidence.environment})`);
    return 0;
  }

  mkdirSync(path.dirname(path.resolve(opts.out)), { recursive: true });
  writeFileSync(opts.out, `${JSON.stringify(artifact, null, 2)}\n`);
  console.log(`operator-runbook-evidence: wrote ${opts.out}`);
  return 0;
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(`operator-runbook-evidence: ${err.message}`);
      process.exit(1);
    },
  );
}