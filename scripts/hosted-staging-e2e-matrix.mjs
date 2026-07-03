#!/usr/bin/env node
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { HOSTED_STAGING_ENVIRONMENT, HOSTED_STAGING_RELEASE_ID, resolveHostedStagingBaseUrl } from './lib/hostedStaging.mjs';
import { runLocalStagingE2eScenarios } from './lib/localStagingE2eScenarios.mjs';
import {
  createStagingE2eMatrixArtifact,
  validateStagingE2eMatrixEvidence,
} from './staging-e2e-matrix-evidence.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');
const DEFAULT_OUT = 'output/release-evidence/hosted-staging-e2e-matrix-input.json';
const DEFAULT_ARTIFACT_OUT = 'output/release-evidence/staging_e2e_matrix.json';

/**
 * @param {string[]} argv
 */
export function parseHostedStagingE2eArgs(argv = []) {
  const opts = {
    baseUrl: resolveHostedStagingBaseUrl(),
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
    if (arg === '--help' || arg === '-h') opts.help = true;
    else if (arg === '--base-url') opts.baseUrl = next();
    else if (arg === '--out') opts.out = next();
    else if (arg === '--artifact-out') opts.artifactOut = next();
    else if (arg.startsWith('--')) throw new Error(`Unknown argument: ${arg}`);
  }
  return opts;
}

/**
 * @param {{ baseUrl: string, out?: string, artifactOut?: string }} opts
 */
export async function runHostedStagingE2eMatrix(opts) {
  const baseUrl = String(opts.baseUrl ?? '').trim().replace(/\/$/, '');
  if (!baseUrl) {
    throw new Error('Hosted staging base URL is required (--base-url or ASTRANULL_HOSTED_STAGING_BASE_URL)');
  }

  process.env.ASTRANULL_HOSTED_STAGING_USE_OIDC = '1';
  const matrixInput = await runLocalStagingE2eScenarios(baseUrl);
  matrixInput.environment = HOSTED_STAGING_ENVIRONMENT;
  matrixInput.release_id = HOSTED_STAGING_RELEASE_ID;
  matrixInput.evidence_uri = 'evidence://release/staging-e2e-matrix-hosted-staging';
  matrixInput.execution_notes = [
    ...(matrixInput.execution_notes ?? []),
    'Hosted staging internal evidence from scripts/hosted-staging-e2e-matrix.mjs.',
    'Uses bundled staging OIDC fixture when control plane auth_mode=oidc-jwt.',
  ];

  const outPath = path.resolve(REPO_ROOT, opts.out ?? DEFAULT_OUT);
  mkdirSync(path.dirname(outPath), { recursive: true });
  writeFileSync(outPath, `${JSON.stringify(matrixInput, null, 2)}\n`);

  const validation = validateStagingE2eMatrixEvidence(matrixInput, { releaseId: matrixInput.release_id });
  const artifact = createStagingE2eMatrixArtifact({
    evidence: matrixInput,
    validation,
    releaseId: matrixInput.release_id,
  });
  const artifactPath = path.resolve(REPO_ROOT, opts.artifactOut ?? DEFAULT_ARTIFACT_OUT);
  mkdirSync(path.dirname(artifactPath), { recursive: true });
  writeFileSync(artifactPath, `${JSON.stringify(artifact, null, 2)}\n`);

  return { inputPath: outPath, artifactPath, validation: artifact.validation, artifact };
}

async function main(argv = process.argv.slice(2)) {
  const opts = parseHostedStagingE2eArgs(argv);
  if (opts.help) {
    console.log(
      'Usage: node scripts/hosted-staging-e2e-matrix.mjs '
      + '[--base-url https://host] [--out input.json] [--artifact-out staging_e2e_matrix.json]',
    );
    return 0;
  }
  const result = await runHostedStagingE2eMatrix(opts);
  console.log(
    `hosted-staging-e2e-matrix: ${result.validation.ok ? 'ok' : 'failed'} `
    + `(overall_status=${result.artifact.overall_status})`,
  );
  return result.validation.ok ? 0 : 1;
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
  main().catch((err) => {
    console.error(`hosted-staging-e2e-matrix: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  });
}