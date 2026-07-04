#!/usr/bin/env node
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  aggregateExternalProductionVerification,
  validateExternalVerificationManifest,
} from '../src/contracts/externalProductionVerification.mjs';
import { ensureExternalVerificationManifest } from './attach-external-verification-markers.mjs';
import { parseEvidenceInput } from './production-readiness-gap-audit.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');
const DEFAULT_EVIDENCE = path.join(REPO_ROOT, 'output/release-evidence/records.json');
const DEFAULT_MANIFEST = path.join(REPO_ROOT, 'output/external-production-verification.json');
const DEFAULT_OUT = path.join(REPO_ROOT, 'output/external-production-verification-report.json');

export function parseArgs(argv = []) {
  const opts = {
    evidence: DEFAULT_EVIDENCE,
    manifest: DEFAULT_MANIFEST,
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
    if (arg === '--evidence') opts.evidence = next();
    else if (arg === '--manifest') opts.manifest = next();
    else if (arg === '--out') opts.out = next();
    else if (arg === '--release-id') opts.releaseId = next();
    else if (arg === '--validate-only') opts.validateOnly = true;
    else if (arg === '--help' || arg === '-h') opts.help = true;
    else throw new Error(`Unknown argument: ${arg}`);
  }
  return opts;
}

function readJsonFile(filePath, label) {
  try {
    return JSON.parse(readFileSync(filePath, 'utf8'));
  } catch (err) {
    throw new Error(`${label} is not valid JSON (${filePath}): ${err.message}`);
  }
}

export function loadExternalVerificationInputs(options = {}) {
  const evidencePath = options.evidence ?? DEFAULT_EVIDENCE;
  let records = [];
  let releaseId = options.releaseId ?? null;
  if (existsSync(evidencePath)) {
    const parsed = readJsonFile(evidencePath, 'Evidence bundle');
    const normalized = parseEvidenceInput(parsed);
    records = normalized.records;
    releaseId = releaseId ?? normalized.releaseId;
  }

  const manifestPath = options.manifest ?? DEFAULT_MANIFEST;
  let manifest = null;
  if (options.autoAttachManifest !== false && existsSync(evidencePath)) {
    manifest = ensureExternalVerificationManifest({
      out: manifestPath,
      evidence: evidencePath,
      releaseId,
      force: options.forceManifest === true,
    });
  } else if (existsSync(manifestPath)) {
    manifest = readJsonFile(manifestPath, 'External verification manifest');
  }

  return { records, manifest, releaseId, evidencePath, manifestPath };
}

export function externalVerificationExitCode(report) {
  return report?.complete === true ? 0 : 1;
}

function formatSummary(report) {
  return [
    `external-production-verification: complete=${report.complete}`,
    `  live_external=${report.live_external_count}/${report.required_domain_count}`,
    `  metadata_only=${report.metadata_only_count}`,
    `  unverified=${report.unverified_count}`,
    `  manifest_present=${report.manifest_present} manifest_valid=${report.manifest_valid}`,
  ].join('\n');
}

export async function main(argv = process.argv.slice(2)) {
  const opts = parseArgs(argv);
  if (opts.help) {
    console.log(
      'Usage: node scripts/verify-external-production-readiness.mjs '
      + '[--evidence records.json] [--manifest external-production-verification.json] '
      + '[--out report.json] [--release-id rel] [--validate-only]',
    );
    return 0;
  }

  const { records, manifest, releaseId } = loadExternalVerificationInputs(opts);
  const report = aggregateExternalProductionVerification(records, { manifest });
  report.release_id = releaseId;
  report.evidence_path = opts.evidence;
  report.manifest_path = existsSync(opts.manifest) ? opts.manifest : null;

  if (manifest) {
    const manifestValidation = validateExternalVerificationManifest(manifest);
    report.manifest_validation = manifestValidation;
  }

  if (opts.validateOnly) {
    console.log(formatSummary(report));
    if (!report.complete && report.blocker_summary.length > 0) {
      console.log(`  blockers: ${report.blocker_summary.slice(0, 5).join(' | ')}`);
    }
    return externalVerificationExitCode(report);
  }

  writeFileSync(opts.out, `${JSON.stringify(report, null, 2)}\n`);
  console.log(`${formatSummary(report)}\n  wrote ${opts.out}`);
  return externalVerificationExitCode(report);
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(`verify-external-production-readiness: ${err.message}`);
      process.exit(1);
    },
  );
}