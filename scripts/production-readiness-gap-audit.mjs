#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateProductionReleaseEvidence } from '../src/contracts/productionReleaseEvidence.mjs';
import {
  aggregateStagingReadinessAttestation,
  DEFAULT_STAGING_READINESS_PROFILE,
  normalizeEvidenceRecords,
  resolveReleaseProfileKinds,
} from './staging-readiness-attestation.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');
const DEFAULT_OUT = 'output/production-readiness-gap-audit.json';
const DEFAULT_RELEASE_CHECKLIST = path.join(REPO_ROOT, 'docs/release-checklist.md');
const DEFAULT_RELEASE_PLAN = path.join(REPO_ROOT, 'docs/product/06-release-plan.md');

export const EXTERNAL_PRODUCTION_GATE_CATEGORIES = Object.freeze([
  Object.freeze({
    id: 'staging',
    label: 'Staging execution, live DB acceptance, and operator E2E matrices',
    satisfied_by_local_validation: false,
  }),
  Object.freeze({
    id: 'security',
    label: 'Independent security review, penetration test remediation, and security signoff',
    satisfied_by_local_validation: false,
  }),
  Object.freeze({
    id: 'soc',
    label: 'SOC-governed high-scale workflows, kill-switch drills, and provider approvals',
    satisfied_by_local_validation: false,
  }),
  Object.freeze({
    id: 'legal',
    label: 'Legal/compliance retention, authorization packs, and board or auditor signoff',
    satisfied_by_local_validation: false,
  }),
]);

export function parseArgs(argv = []) {
  const opts = {
    evidence: null,
    out: DEFAULT_OUT,
    releaseId: null,
    profile: DEFAULT_STAGING_READINESS_PROFILE,
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
    else if (arg === '--out') opts.out = next();
    else if (arg === '--release-id') opts.releaseId = next();
    else if (arg === '--profile') opts.profile = next();
    else if (arg === '--validate-only') opts.validateOnly = true;
    else if (arg === '--help' || arg === '-h') opts.help = true;
    else throw new Error(`Unknown argument: ${arg}`);
  }
  if (!opts.help) resolveReleaseProfileKinds(opts.profile);
  return opts;
}

export function parseChecklistGateCounts(markdown = '') {
  let unchecked = 0;
  let in_progress = 0;
  let complete = 0;
  const open_items = [];
  for (const line of markdown.split('\n')) {
    const uncheckedMatch = /^- \[ \]\s*(.*)$/.exec(line);
    if (uncheckedMatch) {
      unchecked += 1;
      open_items.push({ status: 'unchecked', text: uncheckedMatch[1].trim() });
      continue;
    }
    const inProgressMatch = /^- \[~]\s*(.*)$/.exec(line);
    if (inProgressMatch) {
      in_progress += 1;
      open_items.push({ status: 'in_progress', text: inProgressMatch[1].trim() });
      continue;
    }
    if (/^- \[x\]/i.test(line)) complete += 1;
  }
  const open_gates = unchecked > 0 || in_progress > 0;
  return {
    unchecked,
    in_progress,
    complete,
    open_gates,
    total_items: unchecked + in_progress + complete,
    open_items,
  };
}

function readDocFile(filePath, overrideContent) {
  if (overrideContent !== undefined) return overrideContent;
  return readFileSync(filePath, 'utf8');
}

export function loadReleaseDocGateCounts(options = {}) {
  const releaseChecklist = readDocFile(
    options.releaseChecklistPath ?? DEFAULT_RELEASE_CHECKLIST,
    options.releaseChecklistMarkdown,
  );
  const releasePlan = readDocFile(
    options.releasePlanPath ?? DEFAULT_RELEASE_PLAN,
    options.releasePlanMarkdown,
  );
  const checklist = parseChecklistGateCounts(releaseChecklist);
  const release_plan = parseChecklistGateCounts(releasePlan);
  return {
    release_checklist: {
      source: 'docs/release-checklist.md',
      ...checklist,
    },
    release_plan: {
      source: 'docs/product/06-release-plan.md',
      ...release_plan,
    },
    combined: {
      unchecked: checklist.unchecked + release_plan.unchecked,
      in_progress: checklist.in_progress + release_plan.in_progress,
      complete: checklist.complete + release_plan.complete,
      open_gates: checklist.open_gates || release_plan.open_gates,
      total_items: checklist.total_items + release_plan.total_items,
      open_items: [
        ...checklist.open_items.map((item) => ({
          source: 'docs/release-checklist.md',
          ...item,
        })),
        ...release_plan.open_items.map((item) => ({
          source: 'docs/product/06-release-plan.md',
          ...item,
        })),
      ],
    },
  };
}

function evidenceKindCounts(attestation) {
  const kinds = attestation.required_evidence_kinds;
  return {
    required: kinds.required.length,
    present: kinds.present.length,
    missing: kinds.missing.length,
    invalid: kinds.invalid.length,
    rejected: kinds.rejected.length,
  };
}

function buildChecklistBlockers(docGates) {
  const blockers = [];
  const { combined, release_checklist, release_plan } = docGates;
  if (combined.open_gates) {
    if (release_checklist.open_gates) {
      blockers.push(
        `Release checklist has ${release_checklist.unchecked} unchecked and `
        + `${release_checklist.in_progress} in-progress gate(s) in ${release_checklist.source}`,
      );
    }
    if (release_plan.open_gates) {
      blockers.push(
        `Release plan has ${release_plan.unchecked} unchecked and `
        + `${release_plan.in_progress} in-progress verification item(s) in ${release_plan.source}`,
      );
    }
  }
  return blockers;
}

export function aggregateProductionReadinessGapAudit(input = {}, options = {}) {
  const records = Array.isArray(input.records) ? input.records : [];
  const releaseId = input.releaseId ?? input.release_id ?? null;
  const profile = options.profile ?? DEFAULT_STAGING_READINESS_PROFILE;
  const attestationOptions = { profile };
  if (options.requiredKinds !== undefined) {
    attestationOptions.requiredKinds = options.requiredKinds;
  }
  const attestation = aggregateStagingReadinessAttestation({
    releaseId,
    records,
    createdAt: input.createdAt ?? null,
    notes: input.notes ?? null,
  }, attestationOptions);

  const docGates = loadReleaseDocGateCounts(options);
  const evidence_complete = attestation.production_ready;
  const checklist_gates_open = docGates.combined.open_gates;
  const production_ready = evidence_complete && !checklist_gates_open;

  const checklistBlockers = buildChecklistBlockers(docGates);
  const blocker_summary = [
    ...attestation.blocker_summary,
    ...checklistBlockers,
  ];
  if (!production_ready && evidence_complete && checklist_gates_open) {
    blocker_summary.push(
      'Accepted local evidence inventory is complete, but documented release checklist gates remain open.',
    );
  }

  const external_gates = {
    local_developer_validation_cannot_satisfy: true,
    message:
      'Local developer validation (header auth, dev store, metadata-only CLIs) cannot satisfy '
      + 'external staging, security, SOC, or legal production gates.',
    categories: EXTERNAL_PRODUCTION_GATE_CATEGORIES.map((entry) => ({
      id: entry.id,
      label: entry.label,
      satisfied_by_local_validation: entry.satisfied_by_local_validation,
      status: 'external_gate_required',
    })),
    checklist_gates_open,
    evidence_attestation_complete: evidence_complete,
  };

  return {
    schema_version: 1,
    artifact_type: 'production_readiness_gap_audit',
    created_at: input.createdAt ?? new Date().toISOString(),
    release_id: releaseId ?? attestation.release_id ?? null,
    profile,
    production_ready,
    evidence_attestation_complete: evidence_complete,
    checklist_gates_open,
    required_evidence_kinds: {
      required: attestation.required_evidence_kinds.required,
      present: attestation.required_evidence_kinds.present,
      missing: attestation.required_evidence_kinds.missing,
      invalid: attestation.required_evidence_kinds.invalid.map((entry) => ({
        kind: entry.kind,
        missing_fields: entry.missing_fields ?? [],
        forbidden_fields: entry.forbidden_fields ?? [],
        invalid_fields: entry.invalid_fields ?? [],
      })),
      rejected: attestation.required_evidence_kinds.rejected.map((entry) => ({
        kind: entry.kind,
        status: entry.status,
      })),
      counts: evidenceKindCounts(attestation),
    },
    release_checklist_gates: docGates,
    external_gates,
    attestation_signoff_status: attestation.signoff_status,
    blocker_summary,
    caveats: [
      'Metadata-only gap audit; does not execute staging workloads, probes, or SOC drills.',
      'production_ready=true requires complete accepted inventory and closed documented checklist gates; local validation still does not replace external signoff evidence.',
      'Local evidence validation does not replace staging, security, SOC, or legal signoff.',
      ...attestation.caveats,
    ],
  };
}

function scanForbiddenMetadata(value) {
  return validateProductionReleaseEvidence('__metadata_scan__', value).forbidden_fields;
}

export function parseEvidenceInput(parsed) {
  const forbidden = scanForbiddenMetadata(parsed);
  if (forbidden.length > 0) {
    throw new Error(`Evidence input contains forbidden metadata field(s): ${forbidden.join(', ')}`);
  }
  return {
    releaseId: parsed.release_id ?? null,
    records: normalizeEvidenceRecords(parsed),
    createdAt: parsed.created_at ?? null,
    notes: parsed.notes ?? null,
  };
}

function formatValidateOnlySummary(report) {
  const counts = report.required_evidence_kinds.counts;
  const gates = report.release_checklist_gates.combined;
  return [
    `production-readiness-gap-audit: production_ready=${report.production_ready}`,
    `  evidence: present=${counts.present} missing=${counts.missing} invalid=${counts.invalid} rejected=${counts.rejected}`,
    `  checklist: unchecked=${gates.unchecked} in_progress=${gates.in_progress} complete=${gates.complete}`,
    `  external_gates: local_validation_cannot_satisfy=${report.external_gates.local_developer_validation_cannot_satisfy}`,
  ].join('\n');
}

export async function main(argv = process.argv.slice(2)) {
  const opts = parseArgs(argv);
  if (opts.help) {
    console.log(
      'Usage: node scripts/production-readiness-gap-audit.mjs '
      + '[--evidence bundle.json] [--release-id rel] '
      + `[--profile ${DEFAULT_STAGING_READINESS_PROFILE}|safe-validation-ga|high-scale-ga] `
      + '[--out file] [--validate-only]',
    );
    return 0;
  }

  let input = { records: [], releaseId: opts.releaseId ?? null };
  if (opts.evidence) {
    let parsed;
    try {
      parsed = JSON.parse(readFileSync(opts.evidence, 'utf8'));
    } catch (err) {
      throw new Error(`Malformed evidence JSON: ${err.message}`);
    }
    const normalized = parseEvidenceInput(parsed);
    input = {
      releaseId: opts.releaseId ?? normalized.releaseId,
      records: normalized.records,
      createdAt: normalized.createdAt,
      notes: normalized.notes,
    };
  }

  const report = aggregateProductionReadinessGapAudit(input, { profile: opts.profile });

  if (opts.validateOnly) {
    console.log(formatValidateOnlySummary(report));
    return report.production_ready ? 0 : 1;
  }

  mkdirSync(path.dirname(opts.out), { recursive: true });
  writeFileSync(opts.out, `${JSON.stringify(report, null, 2)}\n`);
  console.log(
    `production-readiness-gap-audit: wrote ${opts.out} (production_ready=${report.production_ready})`,
  );
  return report.production_ready ? 0 : 1;
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(`production-readiness-gap-audit: ${err.message}`);
      process.exit(1);
    },
  );
}