import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import { PRODUCTION_RELEASE_EVIDENCE_KINDS } from '../../src/contracts/productionReleaseEvidence.mjs';
import {
  aggregateProductionReadinessGapAudit,
  buildProductionReadinessScorecard,
  EXTERNAL_PRODUCTION_GATE_CATEGORIES,
  gapAuditExitCode,
  resolveExternalGateStatuses,
  resolveMergeHygieneOk,
  loadReleaseDocGateCounts,
  main,
  parseArgs,
  parseChecklistGateCounts,
  parseEvidenceInput,
  parseP0DispositionGateCounts,
  parseProgressTaskCounts,
  parseReleasePlanGateTableCounts,
  splitMarkdownTableRowCells,
} from '../../scripts/production-readiness-gap-audit.mjs';
import {
  DEFAULT_STAGING_READINESS_PROFILE,
  resolveReleaseProfileKinds,
} from '../../scripts/staging-readiness-attestation.mjs';
import {
  completeEvidenceRecords,
  PRODUCTION_RELEASE_EVIDENCE_COMPLETE,
  stampAcceptedReleaseRecords,
} from '../fixtures/productionReleaseEvidenceComplete.mjs';

const tempDirs = [];

function tempDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-gap-audit-'));
  tempDirs.push(dir);
  return dir;
}

function writeJson(file, value) {
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

const STAGING_E2E_MATRIX = PRODUCTION_RELEASE_EVIDENCE_COMPLETE.staging_e2e_matrix;

const CONTROL_PLANE_CONTAINER_RELEASE = {
  schema_version: 1,
  artifact_type: 'control_plane_container_release_evidence',
  created_at: '2026-07-02T00:00:00.000Z',
  release_id: 'rel-2026-07-02',
  image: 'registry.example/astranull-control-plane@sha256:abc',
  scan_summary: { scanner: 'trivy', status: 'passed' },
  signing_summary: { status: 'signed', reference: 'signing://control-plane/001' },
  promotion_summary: { target: 'staging', digest: 'sha256:abc' },
  rollback_reference: 'rollback://control-plane/001',
  evidence_uri: 'evidence://release/control-plane-container',
};

const KMS_VAULT_POSTURE = {
  schema_version: 1,
  artifact_type: 'kms_vault_posture_evidence',
  created_at: '2026-07-02T00:00:00.000Z',
  validation: { ok: true, missing_fields: [], forbidden_fields: [] },
  environment: 'staging',
  vault_summary: { vault_reference: 'vault://staging', kms_mode: 'envelope' },
  key_rotation_policy: { policy_reference: 'policy://kms/rotation', summary: '90d rotation' },
  access_control_summary: { summary: 'break-glass audited' },
  drill_reference: 'drill://kms/rotation-2026-07-02',
  security_signoff: { owner: 'security-lead', reference: 'signoff://kms' },
  evidence_uri: 'evidence://security/kms-vault-posture',
};

function safeValidationGaBaselineRecords(releaseId = 'rel_safe_validation_ga') {
  const kinds = resolveReleaseProfileKinds('safe-validation-ga');
  const contractKinds = kinds.filter((kind) => PRODUCTION_RELEASE_EVIDENCE_COMPLETE[kind]);
  const records = completeEvidenceRecords(contractKinds);
  for (const kind of ['staging_e2e_matrix', 'control_plane_container_release', 'kms_vault_posture']) {
    if (!kinds.includes(kind)) continue;
    const evidenceByKind = {
      staging_e2e_matrix: STAGING_E2E_MATRIX,
      control_plane_container_release: CONTROL_PLANE_CONTAINER_RELEASE,
      kms_vault_posture: KMS_VAULT_POSTURE,
    };
    records.push({ kind, evidence: evidenceByKind[kind] });
  }
  return stampAcceptedReleaseRecords(records, releaseId);
}

function acceptedRecordsForRelease(releaseId, kinds = PRODUCTION_RELEASE_EVIDENCE_KINDS) {
  return stampAcceptedReleaseRecords(completeEvidenceRecords(kinds), releaseId);
}

const closedChecklistOptions = {
  releaseChecklistMarkdown: '- [x] release checklist closed\n',
  releasePlanMarkdown: '- [x] release plan closed\n',
};

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop(), { recursive: true, force: true });
  }
});

describe('production readiness gap audit', () => {
  it('parses CLI arguments', () => {
    assert.deepEqual(parseArgs(['--out', 'out.json']), {
      evidence: null,
      out: 'out.json',
      releaseId: null,
      profile: DEFAULT_STAGING_READINESS_PROFILE,
      validateOnly: false,
      allowExternalBlockersOnly: false,
      externalVerification: null,
      help: false,
    });
    assert.deepEqual(parseArgs(['--evidence', 'bundle.json', '--validate-only']), {
      evidence: 'bundle.json',
      out: 'output/production-readiness-gap-audit.json',
      releaseId: null,
      profile: DEFAULT_STAGING_READINESS_PROFILE,
      validateOnly: true,
      allowExternalBlockersOnly: false,
      externalVerification: null,
      help: false,
    });
    assert.equal(parseArgs(['--profile', 'high-scale-ga']).profile, 'high-scale-ga');
    assert.throws(() => parseArgs(['--profile', 'nope']), /Unknown release profile/);
  });

  it('parses checklist gate counts from markdown', () => {
    const counts = parseChecklistGateCounts(`
- [ ] unchecked item
- [~] in progress item
- [x] done item
- [x] checked but **Remaining (external):** staging signoff
- [x] checked but **Deferred (operational config):** provider signoff
`);
    assert.deepEqual(counts, {
      unchecked: 1,
      in_progress: 1,
      complete: 3,
      external_blockers: 2,
      open_gates: true,
      total_items: 5,
      open_items: [
        { status: 'unchecked', text: 'unchecked item' },
        { status: 'in_progress', text: 'in progress item' },
      ],
      external_blocker_items: [
        {
          status: 'external_blocker',
          text: 'checked but **Remaining (external):** staging signoff',
        },
        {
          status: 'external_blocker',
          text: 'checked but **Deferred (operational config):** provider signoff',
        },
      ],
    });
  });

  it('parses checklist open items without counting unrelated markdown', () => {
    const counts = parseChecklistGateCounts(`
# Release gates
- [ ] open gate
Not a checklist - [ ] fake
- [x] done gate
`);
    assert.equal(counts.unchecked, 1);
    assert.equal(counts.complete, 1);
    assert.deepEqual(counts.open_items, [{ status: 'unchecked', text: 'open gate' }]);
  });

  it('parses release-plan open gate table rows as external blockers', () => {
    const counts = parseReleasePlanGateTableCounts(`
## Open production release gates (all releases)

| Gate | Owner | Evidence / artifact | Status |
|---|---|---|---|
| Product and API contract accuracy | Product + Backend | Published docs | **Open** — ongoing doc alignment |
| Staging QA / E2E matrix | QA | Accepted matrix | Closed |

## Current developer-validation evidence

| Area | Evidence |
|---|---|
| Not a release gate | **Open** |
`);

    assert.equal(counts.total_items, 2);
    assert.equal(counts.complete, 1);
    assert.equal(counts.external_blockers, 1);
    assert.equal(counts.open_gates, true);
    assert.equal(counts.external_blocker_items[0].gate, 'Product and API contract accuracy');
    assert.match(counts.open_items[0].text, /Product and API contract accuracy/);
  });

  it('parses release-plan gate rows when evidence cells contain escaped pipes', () => {
    const counts = parseReleasePlanGateTableCounts(`
## Production release gates (all releases)

| Gate | Owner | Evidence / artifact | Status |
|---|---|---|---|
| Staging readiness attestation (profile-aware) | Platform + QA | full\\|safe-validation-ga\\|high-scale-ga | **Closed** — profile matrix |
| Staging QA / E2E matrix | QA | Accepted matrix | Signed off |
`);

    assert.equal(counts.total_items, 2);
    assert.equal(counts.complete, 2);
    assert.equal(counts.external_blockers, 0);
    assert.equal(counts.open_gates, false);
    assert.deepEqual(
      splitMarkdownTableRowCells(
        '| Staging readiness attestation (profile-aware) | Platform + QA | full\\|safe-validation-ga\\|high-scale-ga | **Closed** — profile matrix |',
      ),
      [
        'Staging readiness attestation (profile-aware)',
        'Platform + QA',
        'full|safe-validation-ga|high-scale-ga',
        'Closed — profile matrix',
      ],
    );
  });

  it('treats closed release-plan gate table rows as complete', () => {
    const counts = parseReleasePlanGateTableCounts(`
## Open production release gates (all releases)

| Gate | Owner | Evidence / artifact | Status |
|---|---|---|---|
| Product and API contract accuracy | Product + Backend | Published docs | Resolved |
| Staging QA / E2E matrix | QA | Accepted matrix | Signed off |
`);

    assert.equal(counts.total_items, 2);
    assert.equal(counts.complete, 2);
    assert.equal(counts.external_blockers, 0);
    assert.equal(counts.open_gates, false);
  });

  it('treats unrecognized release-plan statuses as external blockers', () => {
    const counts = parseReleasePlanGateTableCounts(`
## Production release gates (all releases)

| Gate | Owner | Evidence / artifact | Status |
|---|---|---|---|
| Product and API contract accuracy | Product | docs | In review |
| Staging QA / E2E matrix | QA | matrix | Waiting on signoff |
| Independent security review | Security | report | **Closed** |
`);

    assert.equal(counts.total_items, 3);
    assert.equal(counts.complete, 1);
    assert.equal(counts.external_blockers, 2);
    assert.equal(counts.open_gates, true);
    assert.equal(counts.external_blocker_items.length, 2);
    assert.match(counts.external_blocker_items[0].text, /unrecognized status/i);
  });

  it('parses Production release gates (all releases) heading and counts closed rows', () => {
    const counts = parseReleasePlanGateTableCounts(`
## Production release gates (all releases)

| Gate | Owner | Evidence / artifact | Status |
|---|---|---|---|
| Product and API contract accuracy | Product + Backend | Published docs | **Closed** — staging execution |
| Staging QA / E2E matrix | QA | Accepted matrix | **Closed** |
`);

    assert.equal(counts.total_items, 2);
    assert.equal(counts.complete, 2);
    assert.equal(counts.external_blockers, 0);
    assert.equal(counts.open_gates, false);
  });

  it('loadReleaseDocGateCounts release_plan has gate table rows from repo docs', () => {
    const gates = loadReleaseDocGateCounts();
    assert.equal(
      gates.release_plan.total_items,
      14,
      `expected release_plan.total_items === 14, got ${JSON.stringify(gates.release_plan)}`,
    );
  });

  it('parses valid P0 disposition rows as complete local tracker dispositions', () => {
    const counts = parseP0DispositionGateCounts(`
### P0 disposition and signoff map

| P0 gap | Local disposition | Owner | Evidence / signoff reference | External closeout still required |
|---|---|---|---|---|
| Runtime Postgres adapter | Implemented locally with staging closeout remaining | Backend + Platform | PROGRESS.md SEC-001/QA-006; node scripts/validate-db-schema.mjs | Staging DB signoff |
| Notification delivery operations | Deferred externally with local implementation complete | Backend + SRE | PROGRESS.md BE-016/SEC-006/QA-005 | Provider delivery signoff |

## Next Section
`);

    assert.equal(counts.total_items, 2);
    assert.equal(counts.complete, 2);
    assert.equal(counts.external_blockers, 0);
    assert.equal(counts.open_gates, false);
  });

  it('keeps P0 disposition gates open when required owner or evidence fields are missing', () => {
    const counts = parseP0DispositionGateCounts(`
### P0 disposition and signoff map

| P0 gap | Local disposition | Owner | Evidence / signoff reference | External closeout still required |
|---|---|---|---|---|
| Safe vector execution policy | Locally tracked |  |  | Staging fleet signoff |
`);

    assert.equal(counts.total_items, 1);
    assert.equal(counts.complete, 0);
    assert.equal(counts.external_blockers, 1);
    assert.equal(counts.open_gates, true);
    assert.equal(counts.external_blocker_items[0].gate, 'Safe vector execution policy');
    assert.deepEqual(
      counts.external_blocker_items[0].missing.sort(),
      ['evidence', 'local_disposition', 'owner'].sort(),
    );
  });

  it('parses PROGRESS.md task rows without counting status convention rows', () => {
    const counts = parseProgressTaskCounts(`
| Symbol | Meaning |
|---|---|
| \`[ ]\` | Not started |
| [x] | P0-001 | Done task | docs/a.md | Complete. |
| [ ] | BE-002 | Open task | docs/b.md | Needs work. |
| [~] | UX-003 | Active task | docs/c.md | In progress. |
| [!] | SEC-004 | Blocked task | docs/d.md | Blocked. |
| [?] | QA-005 | Decision task | docs/e.md | Needs decision. |
`);

    assert.deepEqual(counts, {
      total: 5,
      complete: 1,
      unchecked: 1,
      in_progress: 1,
      blocked: 1,
      needs_decision: 1,
    });
  });

  it('passes profile into attestation so high-scale-ga requires high-scale-only evidence', () => {
    const safeReport = aggregateProductionReadinessGapAudit(
      { records: safeValidationGaBaselineRecords('rel_safe'), releaseId: 'rel_safe' },
      { profile: 'safe-validation-ga', ...closedChecklistOptions },
    );
    const highReport = aggregateProductionReadinessGapAudit(
      { records: safeValidationGaBaselineRecords('rel_high'), releaseId: 'rel_high' },
      { profile: 'high-scale-ga', ...closedChecklistOptions },
    );

    assert.equal(safeReport.profile, 'safe-validation-ga');
    assert.equal(safeReport.evidence_attestation_complete, true);
    assert.equal(highReport.profile, 'high-scale-ga');
    assert.equal(highReport.evidence_attestation_complete, false);
    assert.ok(highReport.required_evidence_kinds.missing.includes('governed_adapter'));
    assert.ok(highReport.required_evidence_kinds.missing.includes('provider_approval'));
  });

  it('loadReleaseDocGateCounts surfaces open item details per source', () => {
    const gates = loadReleaseDocGateCounts({
      releaseChecklistMarkdown: '- [ ] checklist gate\n',
      releasePlanMarkdown: `
- [~] plan verification

## Open production release gates

| Gate | Owner | Evidence / artifact | Status |
|---|---|---|---|
| Staging QA / E2E matrix | QA | Accepted matrix | **Open** |
`,
      enterpriseGapBacklogMarkdown: `
### P0 disposition and signoff map

| P0 gap | Local disposition | Owner | Evidence / signoff reference | External closeout still required |
|---|---|---|---|---|
| Runtime Postgres adapter | Implemented locally | Backend + Platform | PROGRESS.md SEC-001 | Staging signoff |
`,
    });
    assert.deepEqual(gates.release_checklist.open_items, [
      { status: 'unchecked', text: 'checklist gate' },
    ]);
    assert.equal(gates.release_plan.open_items.length, 2);
    assert.equal(gates.enterprise_gap_backlog.complete, 1);
    assert.equal(gates.enterprise_gap_backlog.open_gates, false);
    assert.deepEqual(gates.release_plan.open_items[0], { status: 'in_progress', text: 'plan verification' });
    assert.equal(gates.release_plan.open_items[1].gate, 'Staging QA / E2E matrix');
    assert.deepEqual(gates.combined.open_items, [
      { source: 'docs/release-checklist.md', status: 'unchecked', text: 'checklist gate' },
      { source: 'docs/product/06-release-plan.md', status: 'in_progress', text: 'plan verification' },
      {
        source: 'docs/product/06-release-plan.md',
        status: 'external_blocker',
        text: 'Staging QA / E2E matrix: Open (QA)',
        gate: 'Staging QA / E2E matrix',
        owner: 'QA',
        evidence: 'Accepted matrix',
        table_status: 'Open',
      },
    ]);
  });

  it('audits with no evidence and keeps production_ready false', () => {
    const report = aggregateProductionReadinessGapAudit(
      { records: [], releaseId: 'rel_none' },
      {
        releaseChecklistMarkdown: '- [x] only complete gate\n',
        releasePlanMarkdown: '- [x] release verification complete\n',
      },
    );

    assert.equal(report.production_ready, false);
    assert.equal(report.evidence_attestation_complete, false);
    assert.equal(report.required_evidence_kinds.counts.required, PRODUCTION_RELEASE_EVIDENCE_KINDS.length);
    assert.equal(report.required_evidence_kinds.counts.present, 0);
    assert.equal(report.required_evidence_kinds.counts.missing, PRODUCTION_RELEASE_EVIDENCE_KINDS.length);
    assert.equal(report.external_gates.local_developer_validation_cannot_satisfy, true);
    assert.ok(report.external_gates.message.includes('cannot satisfy'));
    assert.equal(EXTERNAL_PRODUCTION_GATE_CATEGORIES.length, 4);
    assert.equal(JSON.stringify(report).includes('Independent Security Review Co'), false);
    assert.ok(
      report.caveats.some((line) => /production_ready=true requires complete accepted inventory/.test(line)),
    );
    assert.ok(
      report.caveats.every(
        (line) => !(line.includes('production_ready') && line.includes('stays false')),
      ),
    );
  });

  it('does not count unscoped records toward a filtered release gap audit', () => {
    const records = stampAcceptedReleaseRecords(
      completeEvidenceRecords(['third_party_security_review', 'migration_apply']),
      'rel_A',
    ).map((record, index) => (index === 1 ? { ...record, release_id: undefined } : record));
    const report = aggregateProductionReadinessGapAudit(
      { releaseId: 'rel_A', records },
      {
        requiredKinds: ['third_party_security_review', 'migration_apply'],
        ...closedChecklistOptions,
      },
    );
    assert.equal(report.evidence_attestation_complete, false);
    assert.equal(report.production_ready, false);
    assert.ok(report.required_evidence_kinds.missing.includes('migration_apply'));
  });

  it('exits zero when evidence is complete and only external checklist blockers remain', () => {
    const report = aggregateProductionReadinessGapAudit(
      { releaseId: 'rel_external_only', records: acceptedRecordsForRelease('rel_external_only') },
      {
        releaseChecklistMarkdown: '- [x] OIDC ready. **Remaining (external):** IdP signoff\n',
        releasePlanMarkdown: '- [x] release verification complete\n',
      },
    );

    assert.equal(report.evidence_attestation_complete, true);
    assert.equal(report.production_ready, false);
    assert.equal(report.release_checklist_gates.combined.external_blockers, 1);
    assert.equal(gapAuditExitCode(report, { allowExternalBlockersOnly: true }), 0);
    assert.equal(gapAuditExitCode(report), 1);
  });

  it('accepts legacy soc-approval-gate scenario id for SOC external gate', () => {
    const records = [{
      kind: 'staging_e2e_matrix',
      status: 'accepted',
      evidence: {
        ...STAGING_E2E_MATRIX,
        scenarios: [{ scenario_id: 'soc-approval-gate', status: 'passed' }],
      },
    }];
    const soc = resolveExternalGateStatuses(records).find((entry) => entry.id === 'soc');
    assert.equal(soc?.status, 'satisfied_by_staging_evidence');
  });

  it('marks staging and SOC external gates satisfied when staging_e2e_matrix passed', () => {
    const records = [{
      kind: 'staging_e2e_matrix',
      status: 'accepted',
      evidence: STAGING_E2E_MATRIX,
    }];
    const categories = resolveExternalGateStatuses(records);
    const staging = categories.find((entry) => entry.id === 'staging');
    const soc = categories.find((entry) => entry.id === 'soc');
    assert.equal(staging?.status, 'satisfied_by_staging_evidence');
    assert.equal(soc?.status, 'satisfied_by_staging_evidence');
  });

  it('does not satisfy external gates from malformed or rejected evidence', () => {
    const categories = resolveExternalGateStatuses([
      {
        kind: 'staging_e2e_matrix',
        status: 'accepted',
        evidence: {
          ...STAGING_E2E_MATRIX,
          scenarios: [
            ...STAGING_E2E_MATRIX.scenarios.slice(0, -1),
            { ...STAGING_E2E_MATRIX.scenarios.at(-1), status: 'failed' },
          ],
        },
      },
      {
        kind: 'third_party_security_review',
        status: 'accepted',
        evidence: {
          ...PRODUCTION_RELEASE_EVIDENCE_COMPLETE.third_party_security_review,
          password: 'forbidden',
        },
      },
      {
        kind: 'compliance_legal_signoff',
        status: 'rejected',
        evidence: PRODUCTION_RELEASE_EVIDENCE_COMPLETE.compliance_legal_signoff,
      },
    ]);

    assert.equal(categories.find((entry) => entry.id === 'staging')?.status, 'external_gate_required');
    assert.equal(categories.find((entry) => entry.id === 'soc')?.status, 'external_gate_required');
    assert.equal(categories.find((entry) => entry.id === 'security')?.status, 'external_gate_required');
    assert.equal(categories.find((entry) => entry.id === 'legal')?.status, 'external_gate_required');
  });

  it('resolveMergeHygieneOk honors explicit override and env flag', () => {
    assert.equal(resolveMergeHygieneOk(true), true);
    assert.equal(resolveMergeHygieneOk(false), false);
    assert.equal(resolveMergeHygieneOk(undefined, { ASTRANULL_MERGE_HYGIENE_OK: '0' }), false);
    assert.equal(resolveMergeHygieneOk(undefined, { ASTRANULL_MERGE_HYGIENE_OK: '1' }), true);
  });

  it('builds 100% production readiness scorecard for complete hosted inventory', () => {
    const records = stampAcceptedReleaseRecords([
      ...completeEvidenceRecords(PRODUCTION_RELEASE_EVIDENCE_KINDS),
      { kind: 'staging_e2e_matrix', evidence: STAGING_E2E_MATRIX },
    ], 'rel_score');
    const report = aggregateProductionReadinessGapAudit(
      { releaseId: 'rel_score', records },
      {
        ...closedChecklistOptions,
        scorecard: {
          mergeHygieneOk: true,
          customerPortalBrowserE2e: { ok: true, release_id: 'rel_score' },
          progressMarkdown: `
| Status | ID | Task | Docs | Goal |
|---|---|---|---|---|
| [x] | P0-001 | Complete one | docs/a.md | Done. |
| [x] | BE-002 | Complete two | docs/b.md | Done. |
`,
        },
      },
    );
    assert.equal(report.production_ready, true);
    assert.equal(report.production_readiness_scorecard.overall_percent, 100);
    assert.equal(report.production_readiness_scorecard.areas.tracked_implementation_scope.percent, 100);
    assert.equal(
      report.production_readiness_scorecard.areas.tracked_implementation_scope.reason,
      'PROGRESS.md 2/2 tasks complete',
    );
    assert.equal(report.production_readiness_scorecard.areas.customer_facing_production_launch.percent, 100);
    assert.equal(report.external_gates.local_developer_validation_cannot_satisfy, false);
    assert.equal(
      report.external_gates.message,
      'All external gate categories have accepted evidence per metadata validation.',
    );
  });

  it('keeps rehearsal evidence from satisfying production readiness', () => {
    const report = aggregateProductionReadinessGapAudit(
      {
        releaseId: 'rel_rehearsal',
        rehearsal_only: true,
        records: acceptedRecordsForRelease('rel_rehearsal'),
      },
      {
        ...closedChecklistOptions,
        scorecard: {
          mergeHygieneOk: true,
          customerPortalBrowserE2e: { ok: true, release_id: 'rel_rehearsal' },
          progressMarkdown: `
| Status | ID | Task | Docs | Goal |
|---|---|---|---|---|
| [x] | P0-001 | Complete one | docs/a.md | Done. |
`,
        },
      },
    );

    assert.equal(report.evidence_attestation_complete, false);
    assert.equal(report.production_ready, false);
    assert.ok(report.caveats.some((line) => /Sample\/rehearsal evidence/.test(line)));
  });

  it('does not give customer-facing launch 100% without portal browser E2E evidence', () => {
    const report = aggregateProductionReadinessGapAudit(
      { releaseId: 'rel_no_portal', records: acceptedRecordsForRelease('rel_no_portal') },
      {
        ...closedChecklistOptions,
        scorecard: {
          mergeHygieneOk: true,
          progressMarkdown: `
| Status | ID | Task | Docs | Goal |
|---|---|---|---|---|
| [x] | P0-001 | Complete one | docs/a.md | Done. |
`,
        },
      },
    );

    assert.equal(report.production_ready, true);
    assert.ok(report.production_readiness_scorecard.areas.customer_facing_production_launch.percent < 100);
  });

  it('lowers tracked implementation scorecard area when PROGRESS.md has open rows', () => {
    const scorecard = buildProductionReadinessScorecard(
      {
        production_ready: false,
        evidence_attestation_complete: false,
        checklist_gates_open: true,
        required_evidence_kinds: {
          counts: { required: 2, present: 1 },
        },
      },
      [],
      {
        mergeHygieneOk: true,
        progressMarkdown: `
| Status | ID | Task | Docs | Goal |
|---|---|---|---|---|
| [x] | P0-001 | Complete one | docs/a.md | Done. |
| [ ] | BE-002 | Open one | docs/b.md | Open. |
| [~] | UX-003 | Active one | docs/c.md | Active. |
| [!] | SEC-004 | Blocked one | docs/d.md | Blocked. |
| [?] | QA-005 | Decision one | docs/e.md | Decision. |
`,
      },
    );

    assert.equal(scorecard.areas.tracked_implementation_scope.percent, 20);
    assert.match(
      scorecard.areas.tracked_implementation_scope.reason,
      /PROGRESS\.md 1\/5 tasks complete; open=1, in_progress=1, blocked=1, needs_decision=1/,
    );
  });

  it('derives closed release checklist scorecard counts from doc gates', () => {
    const scorecard = buildProductionReadinessScorecard(
      {
        production_ready: false,
        evidence_attestation_complete: true,
        checklist_gates_open: false,
        required_evidence_kinds: {
          counts: { required: 31, present: 31 },
        },
      },
      [],
      {
        mergeHygieneOk: true,
        progressMarkdown: '| [x] | P0-001 | Done | docs/a.md | Done. |\n',
        releaseChecklistGates: {
          release_checklist: { complete: 55, total_items: 55 },
        },
      },
    );

    assert.equal(
      scorecard.areas.release_checklist_gate.reason,
      'docs/release-checklist.md 55/55 checked',
    );
  });

  it('keeps production_ready false when evidence is complete but checklist gates remain open', () => {
    const report = aggregateProductionReadinessGapAudit(
      {
        releaseId: 'rel_complete_local',
        records: acceptedRecordsForRelease('rel_complete_local'),
      },
      {
        releaseChecklistMarkdown: '- [~] placement review UX still open\n',
        releasePlanMarkdown: '- [x] release verification complete\n',
      },
    );

    assert.equal(report.evidence_attestation_complete, true);
    assert.equal(report.checklist_gates_open, true);
    assert.equal(report.production_ready, false);
    assert.ok(report.release_checklist_gates.release_checklist.in_progress > 0
      || report.release_checklist_gates.release_plan.unchecked > 0);
    assert.ok(report.blocker_summary.some((line) => /checklist|Release plan|checklist gates/i.test(line)));
  });

  it('keeps production_ready false when release-plan table gates remain open', () => {
    const report = aggregateProductionReadinessGapAudit(
      { releaseId: 'rel_plan_open', records: acceptedRecordsForRelease('rel_plan_open') },
      {
        releaseChecklistMarkdown: '- [x] checklist closed\n',
        releasePlanMarkdown: `
## Open production release gates

| Gate | Owner | Evidence / artifact | Status |
|---|---|---|---|
| Staging QA / E2E matrix | QA | Accepted matrix | **Open** |
`,
      },
    );

    assert.equal(report.evidence_attestation_complete, true);
    assert.equal(report.checklist_gates_open, true);
    assert.equal(report.production_ready, false);
    assert.equal(report.release_checklist_gates.release_plan.external_blockers, 1);
    assert.match(report.release_checklist_gates.combined.open_items[0].text, /Staging QA/);
  });

  it('rejects forbidden metadata in evidence input', () => {
    assert.throws(
      () => parseEvidenceInput({
        records: [{
          kind: 'third_party_security_review',
          evidence: {
            ...PRODUCTION_RELEASE_EVIDENCE_COMPLETE.third_party_security_review,
            password: 'not-allowed',
          },
        }],
      }),
      /forbidden metadata field/,
    );
  });

  it('validate-only exits nonzero when release gates remain open', async () => {
    const openPlan = `
## Open production release gates
| Gate | Owner | Evidence | Status |
| Product and API contract accuracy | Product | docs | **Open** |
`;
    const report = aggregateProductionReadinessGapAudit(
      {
        releaseId: 'rel_validate',
        records: acceptedRecordsForRelease('rel_validate', resolveReleaseProfileKinds('full')),
      },
      {
        releaseChecklistMarkdown: '- [x] OIDC ready. **Deferred (operational config):** IdP signoff\n',
        releasePlanMarkdown: openPlan,
      },
    );
    assert.equal(report.production_ready, false);
    assert.equal(report.checklist_gates_open, true);
    assert.equal(gapAuditExitCode(report), 1);
    assert.ok(report.release_checklist_gates.combined.open_items.length > 0);
    assert.match(
      report.release_checklist_gates.combined.open_items[0].text,
      /Deferred \(operational config\)|Product and API contract accuracy/,
    );
  });

  it('CLI exits nonzero for malformed evidence JSON', async () => {
    const dir = tempDir();
    const evidence = path.join(dir, 'bad.json');
    writeFileSync(evidence, '{not-json');
    await assert.rejects(
      () => main(['--evidence', evidence, '--validate-only']),
      /Malformed evidence JSON/,
    );
  });

  it('CLI exits nonzero when evidence file contains forbidden metadata', async () => {
    const dir = tempDir();
    const evidence = path.join(dir, 'forbidden.json');
    writeJson(evidence, {
      records: [{
        kind: 'third_party_security_review',
        evidence: {
          ...PRODUCTION_RELEASE_EVIDENCE_COMPLETE.third_party_security_review,
          secret: 'vault://hidden',
        },
      }],
    });
    await assert.rejects(
      () => main(['--evidence', evidence, '--validate-only']),
      /forbidden metadata field/,
    );
  });

  it('writes metadata-only gap audit output with exit code one when evidence inventory is incomplete', async () => {
    const dir = tempDir();
    const out = path.join(dir, 'gap-audit.json');
    const logs = [];
    const originalLog = console.log;
    console.log = (message) => logs.push(String(message));
    let code;
    try {
      code = await main(['--out', out, '--release-id', 'rel_write']);
    } finally {
      console.log = originalLog;
    }
    assert.equal(code, 1);
    assert.equal(existsSync(out), true);
    assert.match(logs.join('\n'), /checklist unchecked=\d+ in_progress=\d+/);
    const report = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(report.artifact_type, 'production_readiness_gap_audit');
    assert.equal(report.production_ready, false);
    assert.ok(report.required_evidence_kinds.counts);
    assert.ok(report.release_checklist_gates.combined);
    assert.equal(typeof report.release_checklist_gates.combined.open_gates, 'boolean');
    assert.equal(report.checklist_gates_open, loadReleaseDocGateCounts().combined.open_gates);
    assert.equal(report.production_ready, false);
  });

  it('preserves invalid_fields on required_evidence_kinds.invalid in gap reports', () => {
    const report = aggregateProductionReadinessGapAudit(
      {
        releaseId: 'rel_invalid_adapter',
        records: stampAcceptedReleaseRecords([{
          kind: 'governed_adapter',
          evidence: {
            ...PRODUCTION_RELEASE_EVIDENCE_COMPLETE.governed_adapter,
            adapter_type: 'partner_http',
          },
        }], 'rel_invalid_adapter'),
      },
      {
        requiredKinds: ['governed_adapter'],
        ...closedChecklistOptions,
      },
    );

    assert.equal(report.evidence_attestation_complete, false);
    assert.equal(report.production_ready, false);
    const invalid = report.required_evidence_kinds.invalid.find((entry) => entry.kind === 'governed_adapter');
    assert.ok(invalid, 'expected governed_adapter in invalid list');
    assert.ok(
      invalid.invalid_fields.some((entry) => entry.field === 'adapter_type'),
      `expected adapter_type in invalid_fields: ${JSON.stringify(invalid.invalid_fields)}`,
    );
  });

  it('treats incomplete staging E2E matrix evidence as invalid production evidence', () => {
    const report = aggregateProductionReadinessGapAudit(
      {
        releaseId: 'rel_incomplete_staging_matrix',
        records: stampAcceptedReleaseRecords([{
          kind: 'staging_e2e_matrix',
          evidence: {
            ...STAGING_E2E_MATRIX,
            environment: 'local-staging',
            overall_status: 'incomplete',
            scenarios: [
              { scenario_id: 'oidc_login', status: 'not_run' },
              { scenario_id: 'safe_validation_loop', status: 'passed' },
            ],
          },
        }], 'rel_incomplete_staging_matrix'),
      },
      {
        requiredKinds: ['staging_e2e_matrix'],
        ...closedChecklistOptions,
      },
    );

    assert.equal(report.evidence_attestation_complete, false);
    assert.equal(report.production_ready, false);
    const invalid = report.required_evidence_kinds.invalid.find((entry) => entry.kind === 'staging_e2e_matrix');
    assert.ok(invalid, 'expected staging_e2e_matrix in invalid list');
    assert.ok(
      invalid.invalid_fields.some(
        (entry) => entry.field === 'overall_status' && entry.reason === 'matrix_not_passed',
      ),
    );
    assert.ok(
      invalid.invalid_fields.some(
        (entry) => entry.field === 'scenarios[0].status' && entry.reason === 'scenario_not_passed',
      ),
    );
  });

  it('closed checklist and complete accepted evidence yields production_ready and exit code zero', () => {
    const report = aggregateProductionReadinessGapAudit(
      { records: acceptedRecordsForRelease('rel_ready'), releaseId: 'rel_ready' },
      closedChecklistOptions,
    );
    assert.equal(report.evidence_attestation_complete, true);
    assert.equal(report.checklist_gates_open, false);
    assert.equal(report.production_ready, true);
    assert.equal(report.production_ready ? 0 : 1, 0);
  });

  it('main returns zero for --help', async () => {
    assert.equal(await main(['--help']), 0);
  });
});
