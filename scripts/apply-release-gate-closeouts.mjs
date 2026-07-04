#!/usr/bin/env node
/**
 * Close release gates only when current evidence manifest supports each gate.
 */
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { PRODUCTION_RELEASE_EVIDENCE_KINDS } from '../src/contracts/productionReleaseEvidence.mjs';
import { assertSubmittableEvidenceRecord } from '../src/contracts/releaseEvidenceProvenance.mjs';
import { splitMarkdownTableRowCells } from './production-readiness-gap-audit.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DEFAULT_MANIFEST_PATH = path.join(REPO_ROOT, 'output/release-evidence/records.json');
const CHECKLIST = path.join(REPO_ROOT, 'docs/release-checklist.md');
const RELEASE_PLAN = path.join(REPO_ROOT, 'docs/product/06-release-plan.md');

export const RELEASE_GATE_REQUIRED_KINDS = Object.freeze({
  'Product and API contract accuracy': ['evidence_snapshot_manifest'],
  'Public entry and internal management boundary': ['staging_e2e_matrix', 'postgres_tenant_query_audit'],
  'P0 enterprise gap backlog': [],
  'Signed agent packages and install matrix': ['agent_install_matrix', 'agent_sbom_provenance'],
  'Database migrations': ['migration_apply', 'rollback_fixforward'],
  'Rollback and kill-switch drills': ['kill_switch_drill', 'operator_runbook_exercise', 'rollback_fixforward'],
  'Independent security review': ['third_party_security_review'],
  'SOC high-scale governance': ['governed_adapter', 'provider_approval', 'authorization_custody'],
  'Staging QA / E2E matrix': ['staging_e2e_matrix', 'ui_accessibility_matrix', 'placement_confidence_staging'],
  'Staging readiness attestation (profile-aware)': [],
  'Production readiness gap audit': ['evidence_snapshot_manifest'],
  'KMS/vault, edge, and control-plane release': [
    'kms_vault_posture',
    'edge_protection',
    'control_plane_container_release',
    'gateway_load_abuse',
    'secret_rotation_drill',
  ],
  'Compliance and legal signoff': ['compliance_legal_signoff', 'authorization_custody'],
  'Support and observability readiness': ['support_readiness', 'observability_slo', 'notification_provider_config'],
});

const OPEN_STATUS_PATTERN = /\b(open|blocked|pending|required)\b/i;
const CLOSED_STATUS_PATTERN = /\b(closed|complete|completed|accepted|done|resolved|signed off|signed-off)\b/i;

function normalizeKindsPresent(records = []) {
  const kinds = new Set();
  for (const record of records) {
    if (!record?.kind) continue;
    const status = typeof record.status === 'string' ? record.status.trim().toLowerCase() : 'accepted';
    if (status !== 'accepted' && status !== 'approved') continue;
    if (record.submittable === false || record.dry_run === true) continue;
    kinds.add(record.kind);
  }
  return kinds;
}

export function loadEvidenceCloseoutManifest(manifestPath = DEFAULT_MANIFEST_PATH) {
  if (!existsSync(manifestPath)) {
    throw new Error(`Evidence manifest not found: ${manifestPath}`);
  }
  const parsed = JSON.parse(readFileSync(manifestPath, 'utf8'));
  if (parsed.submittable === false || parsed.dry_run === true) {
    throw new Error('Evidence manifest is dry-run or non-submittable; gate closeout refused.');
  }
  const records = Array.isArray(parsed.records) ? parsed.records : [];
  for (const record of records) {
    assertSubmittableEvidenceRecord(record, 'Manifest record');
  }
  const kindsPresent = normalizeKindsPresent(records);
  const inventoryComplete = PRODUCTION_RELEASE_EVIDENCE_KINDS.every((kind) => kindsPresent.has(kind));
  return {
    manifestPath,
    releaseId: parsed.release_id ?? null,
    environment: parsed.environment ?? null,
    recordCount: records.length,
    kindsPresent,
    inventoryComplete,
    records,
  };
}

export function gateHasRequiredEvidence(gateName, manifest) {
  const requiredKinds = RELEASE_GATE_REQUIRED_KINDS[gateName];
  if (requiredKinds === undefined) return false;
  if (requiredKinds.length === 0) {
    return manifest.inventoryComplete;
  }
  return requiredKinds.every((kind) => manifest.kindsPresent.has(kind));
}

function buildCloseoutSuffix(manifest) {
  const releaseId = manifest.releaseId ?? 'unknown-release';
  const kindCount = manifest.kindsPresent.size;
  return `**Closed (staging execution):** \`${releaseId}\`; evidence manifest ${kindCount}/${PRODUCTION_RELEASE_EVIDENCE_KINDS.length} accepted kinds from ${path.basename(manifest.manifestPath)}. Per-customer enterprise IdP/domain/provider wiring remains a tenant onboarding step — not a repo gate.`;
}

export function applyReleaseChecklistCloseouts(markdown, manifest) {
  if (!manifest.inventoryComplete) return markdown;
  const suffix = buildCloseoutSuffix(manifest);
  return markdown.replace(
    /\*\*Deferred \(operational config\):\*\*[^\n]*/g,
    suffix,
  );
}

function isOpenReleasePlanStatus(status) {
  return OPEN_STATUS_PATTERN.test(status) && !CLOSED_STATUS_PATTERN.test(status);
}

export function applyReleasePlanCloseouts(markdown, manifest) {
  let updated = markdown.replace(
    /^##\s+Open production release gates\b/im,
    '## Production release gates',
  );

  const lines = updated.split('\n');
  const rewritten = [];
  for (const line of lines) {
    if (!line.trim().startsWith('|')) {
      rewritten.push(line);
      continue;
    }
    const cells = splitMarkdownTableRowCells(line);
    if (cells.length < 4) {
      rewritten.push(line);
      continue;
    }
    const [gate, owner, evidence, status] = cells;
    if (!gate || /^gate$/i.test(gate) || cells.every((cell) => /^-+$/.test(cell))) {
      rewritten.push(line);
      continue;
    }
    if (!isOpenReleasePlanStatus(status)) {
      rewritten.push(line);
      continue;
    }
    if (!gateHasRequiredEvidence(gate, manifest)) {
      rewritten.push(line);
      continue;
    }
    const releaseId = manifest.releaseId ?? 'unknown-release';
    const closedStatus = `**Closed** — staging execution (${releaseId}; evidence manifest)`;
    rewritten.push(`| ${gate} | ${owner} | ${evidence} | ${closedStatus} |`);
  }
  return rewritten.join('\n');
}

export function applyAllReleaseGateCloseouts(options = {}) {
  const manifest = loadEvidenceCloseoutManifest(options.manifestPath ?? DEFAULT_MANIFEST_PATH);
  const checklist = applyReleaseChecklistCloseouts(
    readFileSync(options.checklistPath ?? CHECKLIST, 'utf8'),
    manifest,
  );
  const releasePlan = applyReleasePlanCloseouts(
    readFileSync(options.releasePlanPath ?? RELEASE_PLAN, 'utf8'),
    manifest,
  );
  if (options.write !== false) {
    writeFileSync(options.checklistPath ?? CHECKLIST, checklist);
    writeFileSync(options.releasePlanPath ?? RELEASE_PLAN, releasePlan);
  }
  const deferredRemaining = (checklist.match(/\*\*Deferred \(operational config\):\*\*/g) ?? []).length;
  const openRemaining = (releasePlan.match(/\|\s*\*\*Open\*\*/g) ?? []).length;
  return {
    deferredRemaining,
    openRemaining,
    manifest,
    inventoryComplete: manifest.inventoryComplete,
  };
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  try {
    const result = applyAllReleaseGateCloseouts();
    console.log(
      `apply-release-gate-closeouts: inventory_complete=${result.inventoryComplete} `
      + `checklist deferred=${result.deferredRemaining} release-plan open=${result.openRemaining}`,
    );
    if (!result.inventoryComplete) process.exit(1);
  } catch (err) {
    console.error(`apply-release-gate-closeouts: ${err.message}`);
    process.exit(1);
  }
}