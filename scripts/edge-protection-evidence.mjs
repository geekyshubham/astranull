#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  EDGE_PROTECTION_REQUIRED_CONTROLS,
  validateEdgeProtectionEvidence,
} from '../src/contracts/edgeProtectionBaseline.mjs';
import { redactObject } from '../src/lib/redact.mjs';

const DEFAULT_OUT = 'output/edge-protection-evidence.json';

const RELEASE_METADATA_FIELDS = Object.freeze([
  'release_id',
  'edge_stack_summary',
  'rate_limiting_summary',
  'logging_redaction_summary',
  'signoff_owner',
  'signoff_at',
]);

export function parseArgs(argv = []) {
  const opts = {
    input: null,
    controlsFile: null,
    out: DEFAULT_OUT,
    releaseId: null,
    edgeStackSummary: null,
    rateLimitingSummary: null,
    loggingRedactionSummary: null,
    signoffOwner: null,
    signoffAt: null,
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
    else if (arg === '--controls-file') opts.controlsFile = next();
    else if (arg === '--out') opts.out = next();
    else if (arg === '--release-id') opts.releaseId = next();
    else if (arg === '--edge-stack-summary') opts.edgeStackSummary = next();
    else if (arg === '--rate-limiting-summary') opts.rateLimitingSummary = next();
    else if (arg === '--logging-redaction-summary') opts.loggingRedactionSummary = next();
    else if (arg === '--signoff-owner') opts.signoffOwner = next();
    else if (arg === '--signoff-at') opts.signoffAt = next();
    else if (arg === '--validate-only') opts.validateOnly = true;
    else if (arg === '--help' || arg === '-h') opts.help = true;
    else throw new Error(`Unknown argument: ${arg}`);
  }
  if (!opts.help && !opts.input && !opts.controlsFile) {
    throw new Error('--input or --controls-file is required');
  }
  return opts;
}

function hasValue(value) {
  if (value === null || value === undefined) return false;
  if (typeof value === 'string' && value.trim() === '') return false;
  if (Array.isArray(value) && value.length === 0) return false;
  return true;
}

function readJsonFile(filePath) {
  return JSON.parse(readFileSync(filePath, 'utf8'));
}

export function mergeEvidenceSources(opts, sources = {}) {
  const fileEvidence = sources.fileEvidence ?? {};
  const controlsFileEvidence = sources.controlsFileEvidence ?? {};
  const controls = Array.isArray(fileEvidence.controls)
    ? fileEvidence.controls
    : (Array.isArray(controlsFileEvidence.controls)
      ? controlsFileEvidence.controls
      : (Array.isArray(controlsFileEvidence) ? controlsFileEvidence : []));

  return {
    release_id: opts.releaseId ?? fileEvidence.release_id ?? controlsFileEvidence.release_id,
    edge_stack_summary:
      opts.edgeStackSummary
      ?? fileEvidence.edge_stack_summary
      ?? controlsFileEvidence.edge_stack_summary,
    rate_limiting_summary:
      opts.rateLimitingSummary
      ?? fileEvidence.rate_limiting_summary
      ?? controlsFileEvidence.rate_limiting_summary,
    logging_redaction_summary:
      opts.loggingRedactionSummary
      ?? fileEvidence.logging_redaction_summary
      ?? controlsFileEvidence.logging_redaction_summary,
    signoff_owner:
      opts.signoffOwner
      ?? fileEvidence.signoff_owner
      ?? fileEvidence.signoff?.owner
      ?? controlsFileEvidence.signoff_owner
      ?? controlsFileEvidence.signoff?.owner,
    signoff_at:
      opts.signoffAt
      ?? fileEvidence.signoff_at
      ?? fileEvidence.signoff?.signed_at
      ?? controlsFileEvidence.signoff_at
      ?? controlsFileEvidence.signoff?.signed_at,
    controls,
  };
}

export function validateEdgeProtectionReleaseEvidence(evidence) {
  const missing_release_fields = RELEASE_METADATA_FIELDS.filter((field) => !hasValue(evidence[field]));
  const baseline = validateEdgeProtectionEvidence(evidence);
  return {
    ok: baseline.ok && missing_release_fields.length === 0,
    missing_release_fields,
    ...baseline,
  };
}

function fieldSummary(fields) {
  return fields.length > 0 ? fields.join(', ') : 'none';
}

export function assertValidEdgeProtectionReleaseEvidence(evidence) {
  const validation = validateEdgeProtectionReleaseEvidence(evidence);
  if (validation.missing_release_fields.length > 0) {
    throw new Error(
      `Missing release metadata field(s): ${fieldSummary(validation.missing_release_fields)}`,
    );
  }
  if (validation.missing_controls.length > 0) {
    throw new Error(`Missing edge control(s): ${fieldSummary(validation.missing_controls)}`);
  }
  if (validation.invalid_controls.length > 0) {
    const detail = validation.invalid_controls
      .map((entry) => `${entry.control_id ?? 'unknown'}:${entry.reason}`)
      .join('; ');
    throw new Error(`Invalid edge control(s): ${detail}`);
  }
  if (validation.missing_fields.length > 0) {
    const detail = validation.missing_fields
      .map((entry) => `${entry.control_id}(${fieldSummary(entry.fields)})`)
      .join('; ');
    throw new Error(`Missing control metadata field(s): ${detail}`);
  }
  if (validation.forbidden_fields.length > 0) {
    throw new Error(`Forbidden field(s): ${fieldSummary(validation.forbidden_fields)}`);
  }
  return validation;
}

function controlTitle(controlId) {
  return EDGE_PROTECTION_REQUIRED_CONTROLS.find((control) => control.control_id === controlId)?.title
    ?? controlId;
}

function redactedControlSummaries(controls) {
  const redacted = redactObject(controls);
  if (!Array.isArray(redacted)) return [];
  return redacted.map((control) => ({
    control_id: control.control_id,
    title: controlTitle(control.control_id),
    owner: control.owner,
    evidence_uri: control.evidence_uri,
    validated_at: control.validated_at,
  }));
}

export function createEdgeProtectionEvidenceSummary(input = {}) {
  const evidence = input.evidence;
  const validation = assertValidEdgeProtectionReleaseEvidence(evidence);
  const redacted = redactObject(evidence);
  return {
    schema_version: 1,
    artifact_type: 'edge_protection_release_evidence',
    created_at: input.createdAt ?? new Date().toISOString(),
    release_id: redacted.release_id,
    validation: {
      ok: validation.ok,
      missing_controls: validation.missing_controls,
      invalid_controls: validation.invalid_controls,
      missing_fields: validation.missing_fields,
      forbidden_fields: validation.forbidden_fields,
      missing_release_fields: validation.missing_release_fields,
    },
    edge_stack_summary: redacted.edge_stack_summary,
    rate_limiting_summary: redacted.rate_limiting_summary,
    logging_redaction_summary: redacted.logging_redaction_summary,
    signoff: {
      owner: redacted.signoff_owner,
      signed_at: redacted.signoff_at,
    },
    controls: redactedControlSummaries(redacted.controls),
    caveats: [
      'Summary records metadata-only edge protection evidence for release gates.',
      'Passing validation does not prove live WAF, API gateway, or CDN deployment; staging abuse/load evidence and security signoff are still required.',
      'Do not attach raw headers, bodies, logs, packet payloads, credentials, or tokens to this artifact.',
    ],
  };
}

export function loadEvidenceFromOptions(opts) {
  const fileEvidence = opts.input ? readJsonFile(opts.input) : {};
  const controlsFileEvidence = opts.controlsFile ? readJsonFile(opts.controlsFile) : {};
  return mergeEvidenceSources(opts, { fileEvidence, controlsFileEvidence });
}

export async function main(argv = process.argv.slice(2)) {
  const opts = parseArgs(argv);
  if (opts.help) {
    console.log(
      'Usage: node scripts/edge-protection-evidence.mjs (--input evidence.json | --controls-file controls.json) '
      + '[--release-id id] [--edge-stack-summary text] [--rate-limiting-summary text] '
      + '[--logging-redaction-summary text] [--signoff-owner name] [--signoff-at iso] '
      + '[--out file] [--validate-only]',
    );
    return 0;
  }

  const evidence = loadEvidenceFromOptions(opts);
  const summary = createEdgeProtectionEvidenceSummary({ evidence });

  if (opts.validateOnly) {
    console.log(
      `edge-protection-evidence: ok (release_id=${summary.release_id}, controls=${summary.controls.length})`,
    );
    return 0;
  }

  mkdirSync(path.dirname(opts.out), { recursive: true });
  writeFileSync(opts.out, `${JSON.stringify(summary, null, 2)}\n`);
  console.log(`edge-protection-evidence: wrote ${opts.out}`);
  return 0;
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(`edge-protection-evidence: ${err.message}`);
      process.exit(1);
    },
  );
}