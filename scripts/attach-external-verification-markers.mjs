#!/usr/bin/env node
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  aggregateExternalProductionVerification,
  buildLiveExternalVerificationManifestTemplate,
  validateExternalVerificationManifest,
} from '../src/contracts/externalProductionVerification.mjs';
import { parseEvidenceInput } from './production-readiness-gap-audit.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');
const DEFAULT_EVIDENCE = path.join(REPO_ROOT, 'output/release-evidence/records.json');
const DEFAULT_OUT = path.join(REPO_ROOT, 'output/external-production-verification.json');

export function parseArgs(argv = []) {
  const opts = {
    evidence: DEFAULT_EVIDENCE,
    out: DEFAULT_OUT,
    releaseId: null,
    operatorReference: null,
    force: false,
    help: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = () => {
      i += 1;
      if (i >= argv.length) throw new Error(`Missing value for ${arg}`);
      return argv[i];
    };
    if (arg === '--evidence') opts.evidence = next();
    else if (arg === '--out') opts.out = next();
    else if (arg === '--release-id') opts.releaseId = next();
    else if (arg === '--operator-reference') opts.operatorReference = next();
    else if (arg === '--force') opts.force = true;
    else if (arg === '--help' || arg === '-h') opts.help = true;
    else throw new Error(`Unknown argument: ${arg}`);
  }
  return opts;
}

export function resolveReleaseIdFromEvidence(evidencePath) {
  if (!existsSync(evidencePath)) return null;
  const parsed = JSON.parse(readFileSync(evidencePath, 'utf8'));
  const normalized = parseEvidenceInput(parsed);
  return normalized.releaseId ?? null;
}

export function ensureExternalVerificationManifest(options = {}) {
  const out = options.out ?? DEFAULT_OUT;
  const evidencePath = options.evidence ?? DEFAULT_EVIDENCE;
  const force = options.force === true;

  if (existsSync(out) && !force) {
    return JSON.parse(readFileSync(out, 'utf8'));
  }

  const releaseId = options.releaseId ?? resolveReleaseIdFromEvidence(evidencePath);
  const manifest = buildLiveExternalVerificationManifestTemplate({
    releaseId,
    operatorReference: options.operatorReference ?? undefined,
    createdAt: options.createdAt ?? undefined,
  });

  const validation = validateExternalVerificationManifest(manifest);
  if (!validation.ok) {
    throw new Error(`Generated manifest failed validation: ${validation.gaps.join(', ')}`);
  }

  mkdirSync(path.dirname(out), { recursive: true });
  writeFileSync(out, `${JSON.stringify(manifest, null, 2)}\n`);
  return manifest;
}

export async function main(argv = process.argv.slice(2)) {
  const opts = parseArgs(argv);
  if (opts.help) {
    console.log(
      'Usage: node scripts/attach-external-verification-markers.mjs '
      + '[--evidence records.json] [--out external-production-verification.json] '
      + '[--release-id rel] [--operator-reference operator://team/lead] [--force]',
    );
    return 0;
  }

  if (existsSync(opts.out) && !opts.force) {
    throw new Error(`${opts.out} already exists; pass --force to overwrite`);
  }

  const releaseId = opts.releaseId ?? resolveReleaseIdFromEvidence(opts.evidence);
  const manifest = ensureExternalVerificationManifest({
    out: opts.out,
    evidence: opts.evidence,
    releaseId,
    operatorReference: opts.operatorReference ?? undefined,
    force: true,
  });

  let records = [];
  if (existsSync(opts.evidence)) {
    const parsed = JSON.parse(readFileSync(opts.evidence, 'utf8'));
    records = parseEvidenceInput(parsed).records;
  }
  const preview = aggregateExternalProductionVerification(records, { manifest });
  console.log(
    `attach-external-verification-markers: wrote ${opts.out} `
    + `(release_id=${releaseId ?? 'none'}; preview_complete=${preview.complete})`,
  );
  if (!preview.complete) {
    console.log(
      'attach-external-verification-markers: replace custody_uri values with retained artifacts '
      + 'and ensure live evidence prerequisites before customer launch.',
    );
  }
  return 0;
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main().then(
    (code) => process.exit(code ?? 0),
    (err) => {
      console.error(`attach-external-verification-markers: ${err.message}`);
      process.exit(1);
    },
  );
}