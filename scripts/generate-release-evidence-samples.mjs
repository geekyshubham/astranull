#!/usr/bin/env node
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  PRODUCTION_RELEASE_EVIDENCE_KINDS,
  validateProductionReleaseEvidence,
} from '../src/contracts/productionReleaseEvidence.mjs';
import {
  completeEvidenceRecords,
} from '../tests/fixtures/productionReleaseEvidenceComplete.mjs';
import { createReleaseEvidenceBundle } from './release-evidence-bundle.mjs';
import { aggregateStagingReadinessAttestation } from './staging-readiness-attestation.mjs';

const DEFAULT_OUT_DIR = 'output';
const DEFAULT_RELEASE_ID = 'rel-sample-rehearsal';

export const SAMPLE_REHEARSAL_CAVEATS = Object.freeze([
  'Generated sample artifacts for local operator rehearsal only.',
  'These records are metadata-only fixtures; they are not real production signoff or staging execution proof.',
  'Do not submit sample bundles to production release APIs without replacing every record with operator-attested evidence.',
]);

export const SAMPLE_OUTPUT_FILES = Object.freeze({
  records: 'release-evidence-sample-records.json',
  bundle: 'release-evidence-sample-bundle.json',
  attestation: 'release-evidence-sample-attestation.json',
});

/** Substrings that must not appear in generated sample JSON (fake secrets / raw dumps). */
export const FORBIDDEN_SECRET_MARKERS = Object.freeze([
  'postgres://secret',
  'ast_v1.fake',
  'svc_v1.fake',
  '"api_key":',
  '"password":',
  '"private_key":',
  '"connection_string":',
  '"database_url":',
  '"raw_log":',
  '"raw_logs":',
  '"ip_inventory":',
  '"target_ips":',
]);

export function parseArgs(argv = []) {
  const opts = {
    outDir: DEFAULT_OUT_DIR,
    releaseId: DEFAULT_RELEASE_ID,
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
    if (arg === '--out-dir') opts.outDir = next();
    else if (arg === '--release-id') opts.releaseId = next();
    else if (arg === '--validate-only') opts.validateOnly = true;
    else if (arg === '--help' || arg === '-h') opts.help = true;
    else throw new Error(`Unknown argument: ${arg}`);
  }
  return opts;
}

function scanForbiddenMetadata(value) {
  return validateProductionReleaseEvidence('__metadata_scan__', value).forbidden_fields;
}

export function buildSampleEvidenceRecords(input = {}) {
  const releaseId = input.releaseId ?? DEFAULT_RELEASE_ID;
  const createdAt = input.createdAt ?? new Date().toISOString();
  const records = completeEvidenceRecords(PRODUCTION_RELEASE_EVIDENCE_KINDS).map((record) => ({
    kind: record.kind,
    evidence: record.evidence,
    status: 'accepted',
    release_id: releaseId,
  }));

  return {
    schema_version: 1,
    artifact_type: 'production_release_evidence_sample_records',
    created_at: createdAt,
    release_id: releaseId,
    rehearsal_only: true,
    records,
    caveats: [...SAMPLE_REHEARSAL_CAVEATS],
  };
}

export function generateSampleArtifacts(input = {}) {
  const releaseId = input.releaseId ?? DEFAULT_RELEASE_ID;
  const createdAt = input.createdAt ?? new Date().toISOString();
  const recordsPayload = buildSampleEvidenceRecords({ releaseId, createdAt });

  const bundle = createReleaseEvidenceBundle({
    releaseId,
    createdAt,
    records: recordsPayload.records.map(({ kind, evidence, release_id: recordReleaseId }) => ({
      kind,
      evidence,
      release_id: recordReleaseId,
    })),
  }, { allowRehearsalSampleBundle: true });
  bundle.caveats = [...bundle.caveats, ...SAMPLE_REHEARSAL_CAVEATS];
  bundle.rehearsal_only = true;

  const attestation = aggregateStagingReadinessAttestation({
    releaseId,
    createdAt,
    rehearsal_only: true,
    records: recordsPayload.records,
  });
  attestation.caveats = [...attestation.caveats, ...SAMPLE_REHEARSAL_CAVEATS];

  return {
    records: recordsPayload,
    bundle,
    attestation,
  };
}

export function assertSampleArtifactsValid(artifacts) {
  const forbiddenInRecords = scanForbiddenMetadata(artifacts.records);
  if (forbiddenInRecords.length > 0) {
    throw new Error(`Sample records contain forbidden metadata field(s): ${forbiddenInRecords.join(', ')}`);
  }

  if (!artifacts.bundle.coverage.complete) {
    throw new Error(
      `Sample bundle missing kind(s): ${artifacts.bundle.coverage.kinds_missing.join(', ')}`,
    );
  }
  for (const record of artifacts.bundle.records) {
    if (!record.validation?.ok) {
      throw new Error(`Sample bundle record failed validation: ${record.kind}`);
    }
  }

  const kindsInRecords = new Set(artifacts.records.records.map((entry) => entry.kind));
  for (const kind of PRODUCTION_RELEASE_EVIDENCE_KINDS) {
    if (!kindsInRecords.has(kind)) {
      throw new Error(`Sample records missing required evidence kind: ${kind}`);
    }
  }

  if (artifacts.attestation.production_ready) {
    throw new Error('Sample attestation must not be production_ready (rehearsal-only inventory).');
  }
  if (!artifacts.attestation.rehearsal_only) {
    throw new Error('Sample attestation must include rehearsal_only=true.');
  }
  if (!artifacts.attestation.blocker_summary.some((line) => /Rehearsal\/sample evidence/.test(line))) {
    throw new Error('Sample attestation missing rehearsal production-readiness blocker.');
  }

  for (const marker of FORBIDDEN_SECRET_MARKERS) {
    const blob = JSON.stringify(artifacts);
    if (blob.includes(marker)) {
      throw new Error(`Sample artifacts contain forbidden secret marker: ${marker}`);
    }
  }

  const caveatBlob = JSON.stringify([
    artifacts.records.caveats,
    artifacts.bundle.caveats,
    artifacts.attestation.caveats,
  ]);
  for (const caveat of SAMPLE_REHEARSAL_CAVEATS) {
    if (!caveatBlob.includes(caveat)) {
      throw new Error(`Missing rehearsal caveat: ${caveat}`);
    }
  }
}

export async function main(argv = process.argv.slice(2)) {
  const opts = parseArgs(argv);
  if (opts.help) {
    console.log(
      'Usage: node scripts/generate-release-evidence-samples.mjs '
      + '[--out-dir dir] [--release-id rel] [--validate-only]',
    );
    console.log(
      `Writes metadata-only rehearsal samples for all ${PRODUCTION_RELEASE_EVIDENCE_KINDS.length} `
      + 'production release evidence kinds.',
    );
    return 0;
  }

  const artifacts = generateSampleArtifacts({ releaseId: opts.releaseId });
  assertSampleArtifactsValid(artifacts);

  if (opts.validateOnly) {
    console.log(
      'generate-release-evidence-samples: ok (validate-only, '
      + `${artifacts.records.records.length} record(s), production_ready=false rehearsal inventory)`,
    );
    return 0;
  }

  mkdirSync(opts.outDir, { recursive: true });
  const paths = {
    records: path.join(opts.outDir, SAMPLE_OUTPUT_FILES.records),
    bundle: path.join(opts.outDir, SAMPLE_OUTPUT_FILES.bundle),
    attestation: path.join(opts.outDir, SAMPLE_OUTPUT_FILES.attestation),
  };

  writeFileSync(paths.records, `${JSON.stringify(artifacts.records, null, 2)}\n`);
  writeFileSync(paths.bundle, `${JSON.stringify(artifacts.bundle, null, 2)}\n`);
  writeFileSync(paths.attestation, `${JSON.stringify(artifacts.attestation, null, 2)}\n`);

  console.log('generate-release-evidence-samples: wrote rehearsal sample artifacts (not production signoff):');
  console.log(`  - ${paths.records}`);
  console.log(`  - ${paths.bundle}`);
  console.log(`  - ${paths.attestation}`);
  return 0;
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(`generate-release-evidence-samples: ${err.message}`);
      process.exit(1);
    },
  );
}