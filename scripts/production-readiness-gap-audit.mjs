#!/usr/bin/env node
import { execSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ensureExternalVerificationManifest } from './attach-external-verification-markers.mjs';
import { aggregateExternalProductionVerification } from '../src/contracts/externalProductionVerification.mjs';
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
const DEFAULT_ENTERPRISE_GAP_BACKLOG = path.join(REPO_ROOT, 'docs/product/08-enterprise-production-gap-backlog.md');
const DEFAULT_PROGRESS = path.join(REPO_ROOT, 'PROGRESS.md');
const DEFAULT_EXTERNAL_VERIFICATION_MANIFEST = path.join(
  REPO_ROOT,
  'output/external-production-verification.json',
);

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
    allowExternalBlockersOnly: false,
    externalVerification: null,
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
    else if (arg === '--allow-external-blockers-only') opts.allowExternalBlockersOnly = true;
    else if (arg === '--external-verification') opts.externalVerification = next();
    else if (arg === '--help' || arg === '-h') opts.help = true;
    else throw new Error(`Unknown argument: ${arg}`);
  }
  if (!opts.help) resolveReleaseProfileKinds(opts.profile);
  return opts;
}

const EXTERNAL_REMAINING_PATTERN = /(?:^|[^\w])(?:Remaining\s*\(external\)|Deferred\s*\(operational config\))(?=$|[^\w])/i;
const RELEASE_PLAN_GATES_HEADING = /^##\s+(?:Open\s+)?production release gates(?:\s+\([^)]+\))?\b/i;
const P0_DISPOSITION_HEADING = /^###\s+P0 disposition and signoff map\b/i;
const NEXT_HEADING = /^##\s+/;
const NEXT_H2_OR_H3_HEADING = /^#{2,3}\s+/;
const TABLE_SEPARATOR = /^:?-{3,}:?$/;

function stripMarkdownInline(value = '') {
  return String(value)
    .replace(/\*\*/g, '')
    .replace(/`/g, '')
    .trim();
}

/** Split a Markdown table row on unescaped `|` delimiters only. */
export function splitMarkdownTableRowCells(line = '') {
  const cells = [];
  let current = '';
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (ch === '\\' && line[i + 1] === '|') {
      current += '|';
      i += 1;
      continue;
    }
    if (ch === '|') {
      cells.push(current);
      current = '';
      continue;
    }
    current += ch;
  }
  cells.push(current);
  return cells.slice(1, -1).map(stripMarkdownInline);
}

export function parseChecklistGateCounts(markdown = '') {
  let unchecked = 0;
  let in_progress = 0;
  let complete = 0;
  let external_blockers = 0;
  const open_items = [];
  const external_blocker_items = [];
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
    const completeMatch = /^- \[x\]\s*(.*)$/i.exec(line);
    if (completeMatch) {
      complete += 1;
      const text = completeMatch[1].trim();
      if (EXTERNAL_REMAINING_PATTERN.test(text)) {
        external_blockers += 1;
        external_blocker_items.push({ status: 'external_blocker', text });
      }
      continue;
    }
  }
  const open_gates = unchecked > 0 || in_progress > 0 || external_blockers > 0;
  return {
    unchecked,
    in_progress,
    complete,
    external_blockers,
    open_gates,
    total_items: unchecked + in_progress + complete,
    open_items,
    external_blocker_items,
  };
}

export function parseReleasePlanGateTableCounts(markdown = '') {
  const counts = {
    unchecked: 0,
    in_progress: 0,
    complete: 0,
    external_blockers: 0,
    open_gates: false,
    total_items: 0,
    open_items: [],
    external_blocker_items: [],
  };

  let insideGateSection = false;
  let sawRows = false;
  for (const line of markdown.split('\n')) {
    if (RELEASE_PLAN_GATES_HEADING.test(line)) {
      insideGateSection = true;
      continue;
    }
    if (insideGateSection && NEXT_HEADING.test(line)) break;
    if (!insideGateSection || !line.trim().startsWith('|')) continue;

    const cells = splitMarkdownTableRowCells(line);
    if (cells.length < 4) continue;
    const [gate, owner, evidence, status] = cells;
    if (!gate || /^gate$/i.test(gate)) continue;
    if (cells.every((cell) => TABLE_SEPARATOR.test(cell))) continue;

    sawRows = true;
    const normalizedStatus = status.toLowerCase();
    if (/\b(open|blocked|pending|required)\b/.test(normalizedStatus)) {
      counts.external_blockers += 1;
      const text = `${gate}: ${status}${owner ? ` (${owner})` : ''}`;
      const item = {
        status: 'external_blocker',
        text,
        gate,
        owner,
        evidence,
        table_status: status,
      };
      counts.open_items.push(item);
      counts.external_blocker_items.push(item);
      continue;
    }
    if (/\b(closed|complete|completed|accepted|done|resolved|signed off|signed-off)\b/.test(normalizedStatus)) {
      counts.complete += 1;
      continue;
    }
    if (status.trim()) {
      counts.external_blockers += 1;
      const text = `${gate}: unrecognized status "${status}"${owner ? ` (${owner})` : ''}`;
      const item = {
        status: 'external_blocker',
        text,
        gate,
        owner,
        evidence,
        table_status: status,
      };
      counts.open_items.push(item);
      counts.external_blocker_items.push(item);
    }
  }

  if (insideGateSection && !sawRows) {
    const item = {
      status: 'external_blocker',
      text: 'Production release gates table: missing or empty',
      gate: 'Production release gates table',
      owner: null,
      evidence: null,
      table_status: 'missing',
    };
    counts.external_blockers = 1;
    counts.open_items.push(item);
    counts.external_blocker_items.push(item);
  }

  counts.total_items = counts.complete + counts.external_blockers;
  counts.open_gates = counts.external_blockers > 0;
  return counts;
}

export function parseP0DispositionGateCounts(markdown = '') {
  const counts = {
    unchecked: 0,
    in_progress: 0,
    complete: 0,
    external_blockers: 0,
    open_gates: false,
    total_items: 0,
    open_items: [],
    external_blocker_items: [],
  };

  let insideDispositionSection = false;
  let sawRows = false;
  for (const line of markdown.split('\n')) {
    if (P0_DISPOSITION_HEADING.test(line)) {
      insideDispositionSection = true;
      continue;
    }
    if (insideDispositionSection && NEXT_H2_OR_H3_HEADING.test(line)) break;
    if (!insideDispositionSection || !line.trim().startsWith('|')) continue;

    const cells = splitMarkdownTableRowCells(line);
    if (cells.length < 5) continue;
    if (/^p0 gap$/i.test(cells[0]) || cells.every((cell) => TABLE_SEPARATOR.test(cell))) continue;

    sawRows = true;
    const [gap, localDisposition, owner, evidence, externalCloseout] = cells;
    const missing = [];
    if (!gap) missing.push('gap');
    if (!owner) missing.push('owner');
    if (!evidence) missing.push('evidence');
    if (!externalCloseout) missing.push('external_closeout');
    if (!/\b(implemented|deferred)\b/i.test(localDisposition)) {
      missing.push('local_disposition');
    }

    counts.total_items += 1;
    if (missing.length === 0) {
      counts.complete += 1;
      continue;
    }

    const item = {
      status: 'external_blocker',
      text: `${gap || 'P0 disposition row'}: missing ${missing.join(', ')}`,
      gate: gap || null,
      owner,
      evidence,
      missing,
    };
    counts.external_blockers += 1;
    counts.open_items.push(item);
    counts.external_blocker_items.push(item);
  }

  if (!sawRows) {
    const item = {
      status: 'external_blocker',
      text: 'P0 disposition and signoff map is missing or empty',
      gate: 'P0 enterprise gap backlog',
      owner: null,
      evidence: null,
      missing: ['p0_disposition_rows'],
    };
    counts.total_items = 1;
    counts.external_blockers = 1;
    counts.open_items.push(item);
    counts.external_blocker_items.push(item);
  }

  counts.open_gates = counts.external_blockers > 0;
  return counts;
}

function mergeGateCounts(...gateCounts) {
  return {
    unchecked: gateCounts.reduce((sum, counts) => sum + counts.unchecked, 0),
    in_progress: gateCounts.reduce((sum, counts) => sum + counts.in_progress, 0),
    complete: gateCounts.reduce((sum, counts) => sum + counts.complete, 0),
    external_blockers: gateCounts.reduce((sum, counts) => sum + counts.external_blockers, 0),
    open_gates: gateCounts.some((counts) => counts.open_gates || counts.external_blockers > 0),
    total_items: gateCounts.reduce((sum, counts) => sum + counts.total_items, 0),
    open_items: gateCounts.flatMap((counts) => counts.open_items),
    external_blocker_items: gateCounts.flatMap((counts) => counts.external_blocker_items),
  };
}

function readDocFile(filePath, overrideContent) {
  if (overrideContent !== undefined) return overrideContent;
  return readFileSync(filePath, 'utf8');
}

export function parseProgressTaskCounts(markdown = '') {
  const counts = {
    total: 0,
    complete: 0,
    unchecked: 0,
    in_progress: 0,
    blocked: 0,
    needs_decision: 0,
  };
  const statusToKey = {
    '[x]': 'complete',
    '[ ]': 'unchecked',
    '[~]': 'in_progress',
    '[!]': 'blocked',
    '[?]': 'needs_decision',
  };

  for (const line of markdown.split('\n')) {
    if (!line.trim().startsWith('|')) continue;
    const cells = line.split('|').slice(1, -1).map((cell) => cell.trim());
    if (cells.length < 4) continue;
    const [status, taskId] = cells;
    const key = statusToKey[status];
    if (!key || !taskId) continue;
    counts.total += 1;
    counts[key] += 1;
  }

  return counts;
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
  const enterpriseGapBacklog = readDocFile(
    options.enterpriseGapBacklogPath ?? DEFAULT_ENTERPRISE_GAP_BACKLOG,
    options.enterpriseGapBacklogMarkdown,
  );
  const checklist = parseChecklistGateCounts(releaseChecklist);
  const release_plan = mergeGateCounts(
    parseChecklistGateCounts(releasePlan),
    parseReleasePlanGateTableCounts(releasePlan),
  );
  const enterprise_gap_backlog = parseP0DispositionGateCounts(enterpriseGapBacklog);
  const combined = mergeGateCounts(checklist, release_plan, enterprise_gap_backlog);
  return {
    release_checklist: {
      source: 'docs/release-checklist.md',
      ...checklist,
    },
    release_plan: {
      source: 'docs/product/06-release-plan.md',
      ...release_plan,
    },
    enterprise_gap_backlog: {
      source: 'docs/product/08-enterprise-production-gap-backlog.md',
      ...enterprise_gap_backlog,
    },
    combined: {
      unchecked: combined.unchecked,
      in_progress: combined.in_progress,
      complete: combined.complete,
      external_blockers: combined.external_blockers,
      open_gates: combined.open_gates,
      total_items: combined.total_items,
      open_items: [
        ...checklist.open_items.map((item) => ({
          source: 'docs/release-checklist.md',
          ...item,
        })),
        ...release_plan.open_items.map((item) => ({
          source: 'docs/product/06-release-plan.md',
          ...item,
        })),
        ...enterprise_gap_backlog.open_items.map((item) => ({
          source: 'docs/product/08-enterprise-production-gap-backlog.md',
          ...item,
        })),
      ],
      external_blocker_items: [
        ...checklist.external_blocker_items.map((item) => ({
          source: 'docs/release-checklist.md',
          ...item,
        })),
        ...release_plan.external_blocker_items.map((item) => ({
          source: 'docs/product/06-release-plan.md',
          ...item,
        })),
        ...enterprise_gap_backlog.external_blocker_items.map((item) => ({
          source: 'docs/product/08-enterprise-production-gap-backlog.md',
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

const SOC_GOVERNANCE_SCENARIO_IDS = Object.freeze([
  'soc_high_scale_governance',
  'soc-approval-gate',
]);

function extractStagingE2eMatrixEvidence(record) {
  if (record?.kind === 'staging_e2e_matrix') return record.evidence ?? record.metadata ?? record;
  if (record?.evidence?.artifact_type === 'staging_e2e_matrix_evidence') return record.evidence;
  return null;
}

function acceptedEvidenceForKind(record, kind) {
  if (!record || record.status === 'rejected') return null;
  if (record.kind === kind) return record.evidence ?? record.metadata ?? record;
  if (kind === 'staging_e2e_matrix') return extractStagingE2eMatrixEvidence(record);
  return null;
}

function isContractValidEvidence(kind, evidence) {
  return validateProductionReleaseEvidence(kind, evidence).ok;
}

function findValidEvidenceRecord(records = [], kind) {
  for (const record of records) {
    const evidence = acceptedEvidenceForKind(record, kind);
    if (evidence && isContractValidEvidence(kind, evidence)) return evidence;
  }
  return null;
}

function findStagingE2eMatrixRecord(records = []) {
  const matrices = records
    .map((record) => acceptedEvidenceForKind(record, 'staging_e2e_matrix'))
    .filter((matrix) => matrix && isContractValidEvidence('staging_e2e_matrix', matrix))
    .filter(Boolean);
  if (matrices.length === 0) return null;
  const passed = matrices.filter((matrix) => matrix.overall_status === 'passed');
  const pool = passed.length > 0 ? passed : matrices;
  return pool.find((matrix) => (matrix.scenarios ?? []).some(
    (scenario) => SOC_GOVERNANCE_SCENARIO_IDS.includes(scenario.scenario_id ?? scenario.id)
      && scenario.status === 'passed',
  )) ?? pool[0];
}

function stagingSocGovernancePassed(matrix) {
  return (matrix?.scenarios ?? []).some(
    (scenario) => SOC_GOVERNANCE_SCENARIO_IDS.includes(scenario.scenario_id ?? scenario.id)
      && scenario.status === 'passed',
  );
}

function hasValidAcceptedEvidenceKind(records = [], kind) {
  return findValidEvidenceRecord(records, kind) !== null;
}

export function resolveExternalGateStatuses(records = []) {
  const matrix = findStagingE2eMatrixRecord(records);
  const matrixPassed = matrix?.overall_status === 'passed';
  const socPassed = stagingSocGovernancePassed(matrix);

  return EXTERNAL_PRODUCTION_GATE_CATEGORIES.map((entry) => {
    let status = 'external_gate_required';
    if (entry.id === 'staging' && matrixPassed) status = 'satisfied_by_staging_evidence';
    if (entry.id === 'soc' && socPassed) status = 'satisfied_by_staging_evidence';
    if (entry.id === 'security' && hasValidAcceptedEvidenceKind(records, 'third_party_security_review')) {
      status = 'satisfied_by_metadata_evidence';
    }
    if (entry.id === 'legal' && hasValidAcceptedEvidenceKind(records, 'compliance_legal_signoff')) {
      status = 'satisfied_by_metadata_evidence';
    }
    return {
      id: entry.id,
      label: entry.label,
      satisfied_by_local_validation: entry.satisfied_by_local_validation,
      status,
    };
  });
}

export function resolveMergeHygieneOk(explicit, env = process.env) {
  if (explicit === true || explicit === false) return explicit;
  if (env.ASTRANULL_MERGE_HYGIENE_OK === '1') return true;
  if (env.ASTRANULL_MERGE_HYGIENE_OK === '0') return false;
  try {
    const status = execSync('git status --porcelain', { cwd: REPO_ROOT, encoding: 'utf8' });
    return status.trim() === '';
  } catch {
    return true;
  }
}

export function buildProductionReadinessScorecard(report, records = [], options = {}) {
  const counts = report.required_evidence_kinds?.counts ?? {};
  const inventoryPct = counts.required > 0
    ? Math.round((counts.present / counts.required) * 100)
    : 0;
  const matrix = findStagingE2eMatrixRecord(records);
  const portalE2e = options.customerPortalBrowserE2e ?? null;
  const checklistPct = report.checklist_gates_open ? 0 : 100;
  const customerFacingPct = report.production_ready
    && matrix?.overall_status === 'passed'
    && portalE2e?.ok === true
    ? 100
    : Math.min(99, Math.round((inventoryPct + checklistPct) / 2));
  const mergeHygieneOk = resolveMergeHygieneOk(options.mergeHygieneOk);
  let progressMarkdown = options.progressMarkdown;
  if (progressMarkdown === undefined) {
    try {
      progressMarkdown = readDocFile(DEFAULT_PROGRESS);
    } catch {
      progressMarkdown = '';
    }
  }
  const progressCounts = parseProgressTaskCounts(progressMarkdown);
  const progressPct = progressCounts.total > 0
    ? Math.round((progressCounts.complete / progressCounts.total) * 100)
    : 0;
  const openProgress = progressCounts.unchecked
    + progressCounts.in_progress
    + progressCounts.blocked
    + progressCounts.needs_decision;
  const progressReason = progressCounts.total > 0
    ? [
      `PROGRESS.md ${progressCounts.complete}/${progressCounts.total} tasks complete`,
      openProgress > 0
        ? `open=${progressCounts.unchecked}, in_progress=${progressCounts.in_progress}, blocked=${progressCounts.blocked}, needs_decision=${progressCounts.needs_decision}`
        : null,
    ].filter(Boolean).join('; ')
    : 'PROGRESS.md has no tracked task rows';
  const releaseChecklistCounts = options.releaseChecklistGates?.release_checklist ?? null;
  const releaseChecklistReason = releaseChecklistCounts
    ? `docs/release-checklist.md ${releaseChecklistCounts.complete}/${releaseChecklistCounts.total_items} checked`
    : 'docs/release-checklist.md checked';

  const areas = {
    tracked_implementation_scope: {
      percent: progressPct,
      reason: progressReason,
    },
    release_checklist_gate: {
      percent: checklistPct,
      reason: report.checklist_gates_open
        ? 'Open checklist or release-plan gates remain'
        : releaseChecklistReason,
    },
    staging_evidence_gate: {
      percent: report.evidence_attestation_complete ? 100 : 0,
      reason: report.evidence_attestation_complete
        ? 'staging_e2e_matrix and attestation inventory complete'
        : 'Missing or invalid release evidence kinds',
    },
    evidence_inventory: {
      percent: inventoryPct,
      reason: `${counts.present ?? 0}/${counts.required ?? 0} required evidence kinds present`,
    },
    customer_facing_production_launch: {
      percent: customerFacingPct,
      reason: customerFacingPct === 100
        ? 'Hosted staging portal login, customer routes, APIs, and privacy gates verified'
        : 'Complete hosted attest and customer portal browser E2E for full launch claim',
    },
    merge_release_hygiene: {
      percent: mergeHygieneOk ? 100 : 85,
      reason: mergeHygieneOk
        ? 'Working tree clean; gap-audit artifacts synced'
        : 'Stale artifacts or unpushed commits remain',
    },
  };
  const values = Object.values(areas).map((entry) => entry.percent);
  const overall = Math.round(values.reduce((sum, n) => sum + n, 0) / values.length);
  return {
    overall_percent: overall,
    production_ready: report.production_ready === true,
    areas,
  };
}

function buildChecklistBlockers(docGates) {
  const blockers = [];
  const { combined, release_checklist, release_plan } = docGates;
  if (combined.open_gates) {
    if (release_checklist.open_gates) {
      blockers.push(
        `Release checklist has ${release_checklist.unchecked} unchecked, `
        + `${release_checklist.in_progress} in-progress, and `
        + `${release_checklist.external_blockers} externally-blocked checked gate(s) in `
        + `${release_checklist.source}`,
      );
    }
    if (release_plan.open_gates) {
      blockers.push(
        `Release plan has ${release_plan.unchecked} unchecked, `
        + `${release_plan.in_progress} in-progress, and `
        + `${release_plan.external_blockers} externally-blocked checked verification item(s) in `
        + `${release_plan.source}`,
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
    rehearsal_only: input.rehearsal_only === true || input.rehearsalOnly === true,
  }, attestationOptions);

  const docGates = loadReleaseDocGateCounts(options);
  const evidence_complete = attestation.production_ready;
  const checklist_gates_open = docGates.combined.open_gates;
  const production_ready = evidence_complete && !checklist_gates_open;

  const externalVerificationManifest = loadExternalVerificationManifest(options);
  const external_verification = aggregateExternalProductionVerification(records, {
    manifest: externalVerificationManifest,
  });
  const customer_production_ready = production_ready && external_verification.complete === true;

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
  if (production_ready && !customer_production_ready) {
    blocker_summary.push(
      'Repo production_ready is true but customer_production_ready is false — live external verification markers are incomplete.',
    );
    blocker_summary.push(...external_verification.blocker_summary);
  }

  const externalCategories = resolveExternalGateStatuses(records);
  const externalPending = externalCategories.filter((entry) => entry.status === 'external_gate_required');
  const external_gates = {
    local_developer_validation_cannot_satisfy: externalPending.length > 0,
    message: externalPending.length === 0
      ? 'All external gate categories have accepted evidence per metadata validation.'
      : 'Local developer validation cannot satisfy some external production gates; operator evidence beyond local validation is still required.',
    categories: externalCategories,
    checklist_gates_open,
    evidence_attestation_complete: evidence_complete,
  };

  const scorecard = buildProductionReadinessScorecard(
    {
      production_ready,
      evidence_attestation_complete: evidence_complete,
      checklist_gates_open,
      required_evidence_kinds: {
        counts: evidenceKindCounts(attestation),
      },
    },
    records,
    {
      ...(options.scorecard ?? {}),
      releaseChecklistGates: docGates,
    },
  );

  return {
    schema_version: 1,
    artifact_type: 'production_readiness_gap_audit',
    created_at: input.createdAt ?? new Date().toISOString(),
    release_id: releaseId ?? attestation.release_id ?? null,
    profile,
    production_ready,
    customer_production_ready,
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
    external_verification,
    production_readiness_scorecard: scorecard,
    attestation_signoff_status: attestation.signoff_status,
    blocker_summary,
    caveats: [
      'Metadata-only gap audit; does not execute staging workloads, probes, or SOC drills.',
      'production_ready=true requires complete accepted inventory and closed documented checklist gates; local validation still does not replace external signoff evidence.',
      'customer_production_ready=true additionally requires live_external verification for IdP/MFA, KMS/HSM custody, notification credentials, artifact-pinned deploy/rollback, and retained security/legal/SOC artifacts.',
      'Local evidence validation does not replace staging, security, SOC, or legal signoff.',
      ...attestation.caveats,
    ],
  };
}

function loadExternalVerificationManifest(options = {}) {
  if (options.externalVerificationManifest !== undefined) {
    return options.externalVerificationManifest;
  }
  const manifestPath = options.externalVerificationPath ?? DEFAULT_EXTERNAL_VERIFICATION_MANIFEST;
  if (!existsSync(manifestPath)) return null;
  try {
    return JSON.parse(readFileSync(manifestPath, 'utf8'));
  } catch {
    return null;
  }
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
    rehearsalOnly: parsed.rehearsal_only === true,
  };
}

function formatOpenGatePreview(report, limit = 5) {
  const items = report.release_checklist_gates.combined.open_items.slice(0, limit);
  if (items.length === 0) return '  open_gate_preview: none';
  const lines = ['  open_gate_preview:'];
  for (const item of items) {
    const text = item.text.length > 160 ? `${item.text.slice(0, 157)}...` : item.text;
    lines.push(`    - [${item.status}] ${item.source}: ${text}`);
  }
  const remaining = report.release_checklist_gates.combined.open_items.length - items.length;
  if (remaining > 0) lines.push(`    ... ${remaining} more open gate(s) in JSON output`);
  return lines.join('\n');
}

function formatValidateOnlySummary(report) {
  const counts = report.required_evidence_kinds.counts;
  const gates = report.release_checklist_gates.combined;
  return [
    `production-readiness-gap-audit: production_ready=${report.production_ready}`,
    `  customer_production_ready=${report.customer_production_ready}`,
    `  evidence: present=${counts.present} missing=${counts.missing} invalid=${counts.invalid} rejected=${counts.rejected}`,
    `  checklist: unchecked=${gates.unchecked} in_progress=${gates.in_progress} complete=${gates.complete}`,
    `  external_gates: local_validation_cannot_satisfy=${report.external_gates.local_developer_validation_cannot_satisfy}`,
    `  external_verification: complete=${report.external_verification?.complete} live=${report.external_verification?.live_external_count}/${report.external_verification?.required_domain_count}`,
    formatOpenGatePreview(report),
  ].join('\n');
}

export function gapAuditExitCode(report, options = {}) {
  if (report?.production_ready) return 0;
  if (!report?.evidence_attestation_complete) return 1;
  const combined = report.release_checklist_gates?.combined ?? {};
  if ((combined.unchecked ?? 0) > 0 || (combined.in_progress ?? 0) > 0) return 1;
  if (
    options.allowExternalBlockersOnly === true
    && (combined.external_blockers ?? 0) > 0
    && (combined.unchecked ?? 0) === 0
    && (combined.in_progress ?? 0) === 0
  ) {
    return 0;
  }
  return 1;
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
      rehearsalOnly: normalized.rehearsalOnly,
    };
  }

  let customerPortalBrowserE2e = null;
  try {
    customerPortalBrowserE2e = JSON.parse(
      readFileSync(path.join(REPO_ROOT, 'output/release-evidence/customer_portal_browser_e2e.json'), 'utf8'),
    );
  } catch {
    // optional attest artifact
  }
  if (opts.evidence && existsSync(opts.evidence)) {
    ensureExternalVerificationManifest({
      out: opts.externalVerification ?? DEFAULT_EXTERNAL_VERIFICATION_MANIFEST,
      evidence: opts.evidence,
      releaseId: input.releaseId ?? opts.releaseId ?? null,
    });
  }
  const report = aggregateProductionReadinessGapAudit(input, {
    profile: opts.profile,
    externalVerificationPath: opts.externalVerification ?? DEFAULT_EXTERNAL_VERIFICATION_MANIFEST,
    scorecard: {
      customerPortalBrowserE2e,
    },
  });
  const exitOptions = { allowExternalBlockersOnly: opts.allowExternalBlockersOnly };

  if (opts.validateOnly) {
    console.log(formatValidateOnlySummary(report));
    return gapAuditExitCode(report, exitOptions);
  }

  mkdirSync(path.dirname(opts.out), { recursive: true });
  writeFileSync(opts.out, `${JSON.stringify(report, null, 2)}\n`);
  if (opts.evidence?.includes('output/release-evidence/records.json')) {
    const releaseEvidenceAudit = path.join(REPO_ROOT, 'output/release-evidence/gap-audit.json');
    writeFileSync(releaseEvidenceAudit, `${JSON.stringify(report, null, 2)}\n`);
  }
  const counts = report.required_evidence_kinds.counts;
  const gates = report.release_checklist_gates.combined;
  console.log(
    `production-readiness-gap-audit: wrote ${opts.out} `
    + `(production_ready=${report.production_ready}; customer_production_ready=${report.customer_production_ready}; evidence missing=${counts.missing} `
    + `invalid=${counts.invalid} rejected=${counts.rejected}; checklist unchecked=${gates.unchecked} `
    + `in_progress=${gates.in_progress} external_blockers=${gates.external_blockers ?? 0})`,
  );
  return gapAuditExitCode(report, exitOptions);
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
