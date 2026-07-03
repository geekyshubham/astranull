#!/usr/bin/env node
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DEFAULT_LOCAL_STAGING_BASE_URL } from './lib/localStaging.mjs';
import { runLocalStagingE2eScenarios } from './lib/localStagingE2eScenarios.mjs';
import {
  createStagingE2eMatrixArtifact,
  validateStagingE2eMatrixEvidence,
} from './staging-e2e-matrix-evidence.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_OUT = 'output/release-evidence/local-staging-e2e-matrix-input.json';
const DEFAULT_ARTIFACT_OUT = 'output/release-evidence/staging_e2e_matrix.json';

export function parseArgs(argv = []) {
  const opts = {
    baseUrl: DEFAULT_LOCAL_STAGING_BASE_URL,
    out: DEFAULT_OUT,
    artifactOut: DEFAULT_ARTIFACT_OUT,
    help: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = () => {
      i += 1;
      if (i >= argv.length) throw new Error(`Missing value for ${arg}`);
      return argv[i];
    };
    if (arg === '--base-url') opts.baseUrl = next();
    else if (arg === '--out') opts.out = next();
    else if (arg === '--artifact-out') opts.artifactOut = next();
    else if (arg === '--help' || arg === '-h') opts.help = true;
    else throw new Error(`Unknown argument: ${arg}`);
  }
  return opts;
}

export async function runLocalStagingE2eMatrix(options = {}) {
  const baseUrl = options.baseUrl ?? DEFAULT_LOCAL_STAGING_BASE_URL;
  const evidence = await runLocalStagingE2eScenarios(baseUrl);
  const validation = validateStagingE2eMatrixEvidence(evidence, { releaseId: evidence.release_id });
  const artifact = createStagingE2eMatrixArtifact({
    evidence,
    validation,
    releaseId: evidence.release_id,
  });

  const out = options.out ?? DEFAULT_OUT;
  const artifactOut = options.artifactOut ?? DEFAULT_ARTIFACT_OUT;
  mkdirSync(path.dirname(path.resolve(out)), { recursive: true });
  writeFileSync(out, `${JSON.stringify(evidence, null, 2)}\n`);
  mkdirSync(path.dirname(path.resolve(artifactOut)), { recursive: true });
  writeFileSync(artifactOut, `${JSON.stringify(artifact, null, 2)}\n`);

  return { evidence, validation, artifact, out, artifactOut };
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) {
    console.log(
      'Usage: node scripts/local-staging-e2e-matrix.mjs '
      + `[--base-url ${DEFAULT_LOCAL_STAGING_BASE_URL}] [--out input.json] [--artifact-out artifact.json]`,
    );
    return 0;
  }

  const result = await runLocalStagingE2eMatrix(opts);
  console.log(
    `local-staging-e2e-matrix: ${result.validation.ok ? 'ok' : 'failed'} `
    + `(overall_status=${result.artifact.overall_status}, scenarios=${result.evidence.scenarios.length})`,
  );
  console.log(`  input: ${result.out}`);
  console.log(`  artifact: ${result.artifactOut}`);
  return result.validation.ok ? 0 : 1;
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(`local-staging-e2e-matrix: ${err.message}`);
      process.exit(1);
    },
  );
}