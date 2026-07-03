#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateProductionReleaseEvidence } from '../src/contracts/productionReleaseEvidence.mjs';
import { redactObject, redactString } from '../src/lib/redact.mjs';

const DEFAULT_OUT = 'output/migration-apply-evidence.json';
const EVIDENCE_KIND = 'migration_apply';

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

export function buildDefaultMigrationApplyEvidence(input = {}) {
  const createdAt = input.createdAt ?? new Date().toISOString();
  const environment = input.environment ?? 'staging-sim';
  return {
    environment,
    database_cluster_reference: `db-cluster/${environment}/astranull`,
    migration_version: input.migrationVersion ?? '0007_production_release_evidence',
    runner_evidence_uri: `evidence://db/migration-run-${environment}`,
    started_at: input.startedAt ?? createdAt,
    completed_at: input.completedAt ?? createdAt,
    operator: input.operator ?? 'database-operator',
    post_apply_check_uri: `evidence://db/post-apply-check-${environment}`,
  };
}

export function createMigrationApplyEvidenceArtifact(input = {}) {
  const evidence = input.evidence ?? buildDefaultMigrationApplyEvidence(input);
  const validation = validateProductionReleaseEvidence(EVIDENCE_KIND, evidence);
  const redactedEvidence = redactObject(evidence);
  const releaseId = input.releaseId ?? null;

  return {
    schema_version: 1,
    artifact_type: 'migration_apply_evidence',
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
      'Metadata-only migration apply attestation; no connection strings, SQL dumps, runner logs, or credentials.',
      'Operator custody URIs reference immutable runner and post-apply check artifacts outside this validator.',
      'Production promotion still requires live migration execution in staging/production and DBA signoff.',
    ],
  };
}

export async function main(argv = process.argv.slice(2)) {
  const opts = parseArgs(argv);
  if (opts.help) {
    console.log(
      'Usage: node scripts/migration-apply-evidence.mjs '
      + '[--input evidence.json] [--out file] [--release-id rel] '
      + '[--environment staging-sim] [--validate-only]',
    );
    return 0;
  }

  const evidence = opts.input
    ? readInputEvidence(opts.input)
    : buildDefaultMigrationApplyEvidence({ environment: opts.environment });
  const artifact = createMigrationApplyEvidenceArtifact({
    evidence,
    releaseId: opts.releaseId,
    environment: opts.environment,
  });

  if (!artifact.validation.ok) {
    throw new Error(
      `migration-apply-evidence: invalid (${artifact.validation.missing_fields.join(', ') || 'validation failed'})`,
    );
  }

  if (opts.validateOnly) {
    console.log(`migration-apply-evidence: ok (environment=${evidence.environment})`);
    return 0;
  }

  mkdirSync(path.dirname(path.resolve(opts.out)), { recursive: true });
  writeFileSync(opts.out, `${JSON.stringify(artifact, null, 2)}\n`);
  console.log(`migration-apply-evidence: wrote ${opts.out}`);
  return 0;
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(`migration-apply-evidence: ${err.message}`);
      process.exit(1);
    },
  );
}