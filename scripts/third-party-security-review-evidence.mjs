#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateProductionReleaseEvidence } from '../src/contracts/productionReleaseEvidence.mjs';
import { redactObject, redactString } from '../src/lib/redact.mjs';

const DEFAULT_OUT = 'output/third-party-security-review-evidence.json';
const EVIDENCE_KIND = 'third_party_security_review';

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
  return opts;
}

function readInputEvidence(inputPath) {
  const parsed = JSON.parse(readFileSync(inputPath, 'utf8'));
  if (parsed?.evidence && typeof parsed.evidence === 'object') return parsed.evidence;
  return parsed;
}

export function buildDefaultThirdPartySecurityReviewEvidence(input = {}) {
  const reviewedAt = input.reviewedAt ?? new Date().toISOString();
  return {
    reviewer_org: input.reviewerOrg ?? 'Independent Security Review Co',
    scope_summary: 'Production API, UI, SOC workflow, agent control, and release process (staging-sim attestation).',
    review_report_uri: 'evidence://security-review/report-staging-sim',
    findings_status: 'all-critical-high-remediated',
    remediation_tracker_uri: 'evidence://security-review/remediation-tracker-staging-sim',
    risk_acceptance_reference: 'risk://accepted-medium-items-staging-sim',
    reviewed_at: reviewedAt,
    security_owner: input.securityOwner ?? 'security-lead',
  };
}

export function createThirdPartySecurityReviewEvidenceArtifact(input = {}) {
  const evidence = input.evidence ?? buildDefaultThirdPartySecurityReviewEvidence(input);
  const validation = validateProductionReleaseEvidence(EVIDENCE_KIND, evidence);
  const redactedEvidence = redactObject(evidence);
  const releaseId = input.releaseId ?? null;

  return {
    schema_version: 1,
    artifact_type: 'third_party_security_review_evidence',
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
      'Metadata-only third-party security review attestation; no raw findings, credentials, or report bodies.',
      'Report and remediation tracker URIs are custody pointers; independent review execution remains external.',
      'Production promotion still requires completed review, remediation, and security signoff.',
    ],
  };
}

export async function main(argv = process.argv.slice(2)) {
  const opts = parseArgs(argv);
  if (opts.help) {
    console.log(
      'Usage: node scripts/third-party-security-review-evidence.mjs '
      + '[--input evidence.json] [--out file] [--release-id rel] [--validate-only]',
    );
    return 0;
  }

  const evidence = opts.input
    ? readInputEvidence(opts.input)
    : buildDefaultThirdPartySecurityReviewEvidence();
  const artifact = createThirdPartySecurityReviewEvidenceArtifact({
    evidence,
    releaseId: opts.releaseId,
  });

  if (!artifact.validation.ok) {
    throw new Error(
      `third-party-security-review-evidence: invalid (${artifact.validation.missing_fields.join(', ') || 'validation failed'})`,
    );
  }

  if (opts.validateOnly) {
    console.log(`third-party-security-review-evidence: ok (reviewer=${evidence.reviewer_org})`);
    return 0;
  }

  mkdirSync(path.dirname(path.resolve(opts.out)), { recursive: true });
  writeFileSync(opts.out, `${JSON.stringify(artifact, null, 2)}\n`);
  console.log(`third-party-security-review-evidence: wrote ${opts.out}`);
  return 0;
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(`third-party-security-review-evidence: ${err.message}`);
      process.exit(1);
    },
  );
}