import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import { PRODUCTION_RELEASE_EVIDENCE_KINDS } from '../../src/contracts/productionReleaseEvidence.mjs';
import {
  aggregateProductionReadinessGapAudit,
  EXTERNAL_PRODUCTION_GATE_CATEGORIES,
  gapAuditExitCode,
  loadReleaseDocGateCounts,
  main,
  parseArgs,
  parseChecklistGateCounts,
  parseEvidenceInput,
} from '../../scripts/production-readiness-gap-audit.mjs';
import {
  DEFAULT_STAGING_READINESS_PROFILE,
  resolveReleaseProfileKinds,
} from '../../scripts/staging-readiness-attestation.mjs';
import {
  completeEvidenceRecords,
  PRODUCTION_RELEASE_EVIDENCE_COMPLETE,
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

const STAGING_E2E_MATRIX = {
  schema_version: 1,
  artifact_type: 'staging_e2e_matrix_evidence',
  created_at: '2026-07-02T00:00:00.000Z',
  release_id: 'rel-2026-07-02',
  environment: 'staging',
  scenarios: [{ id: 'sso-ui', status: 'passed' }],
  overall_status: 'passed',
  signoff: { owner: 'qa-lead', reference: 'signoff://qa/staging-e2e' },
  evidence_uri: 'evidence://qa/staging-e2e',
};

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

function safeValidationGaBaselineRecords() {
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
  return records.map((record) => ({ ...record, status: 'accepted' }));
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
      help: false,
    });
    assert.deepEqual(parseArgs(['--evidence', 'bundle.json', '--validate-only']), {
      evidence: 'bundle.json',
      out: 'output/production-readiness-gap-audit.json',
      releaseId: null,
      profile: DEFAULT_STAGING_READINESS_PROFILE,
      validateOnly: true,
      allowExternalBlockersOnly: false,
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
`);
    assert.deepEqual(counts, {
      unchecked: 1,
      in_progress: 1,
      complete: 2,
      external_blockers: 1,
      open_gates: true,
      total_items: 4,
      open_items: [
        { status: 'unchecked', text: 'unchecked item' },
        { status: 'in_progress', text: 'in progress item' },
      ],
      external_blocker_items: [
        {
          status: 'external_blocker',
          text: 'checked but **Remaining (external):** staging signoff',
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

  it('passes profile into attestation so high-scale-ga requires high-scale-only evidence', () => {
    const records = safeValidationGaBaselineRecords();
    const safeReport = aggregateProductionReadinessGapAudit(
      { records, releaseId: 'rel_safe' },
      { profile: 'safe-validation-ga', ...closedChecklistOptions },
    );
    const highReport = aggregateProductionReadinessGapAudit(
      { records, releaseId: 'rel_high' },
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
      releasePlanMarkdown: '- [~] plan verification\n',
    });
    assert.deepEqual(gates.release_checklist.open_items, [
      { status: 'unchecked', text: 'checklist gate' },
    ]);
    assert.deepEqual(gates.release_plan.open_items, [
      { status: 'in_progress', text: 'plan verification' },
    ]);
    assert.deepEqual(gates.combined.open_items, [
      { source: 'docs/release-checklist.md', status: 'unchecked', text: 'checklist gate' },
      { source: 'docs/product/06-release-plan.md', status: 'in_progress', text: 'plan verification' },
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

  it('exits zero when evidence is complete and only external checklist blockers remain', () => {
    const records = completeEvidenceRecords(PRODUCTION_RELEASE_EVIDENCE_KINDS).map((entry) => ({
      ...entry,
      status: 'accepted',
    }));
    const report = aggregateProductionReadinessGapAudit(
      { releaseId: 'rel_external_only', records },
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

  it('keeps production_ready false when evidence is complete but checklist gates remain open', () => {
    const records = completeEvidenceRecords(PRODUCTION_RELEASE_EVIDENCE_KINDS).map((entry) => ({
      ...entry,
      status: 'accepted',
    }));
    const report = aggregateProductionReadinessGapAudit(
      {
        releaseId: 'rel_complete_local',
        records,
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

  it('validate-only prints summary and exits nonzero when release gates remain open', async () => {
    const dir = tempDir();
    const out = path.join(dir, 'gap-audit.json');
    const logs = [];
    const originalLog = console.log;
    console.log = (message) => logs.push(String(message));
    try {
      const code = await main(['--validate-only', '--out', out, '--release-id', 'rel_validate']);
      assert.equal(code, 1);
    } finally {
      console.log = originalLog;
    }
    assert.equal(existsSync(out), false);
    const summary = logs.join('\n');
    assert.match(summary, /production_ready=false/);
    assert.match(summary, /open_gate_preview:/);
    assert.match(summary, /open_gate_preview: (none|docs\/release-checklist\.md|docs\/product\/06-release-plan\.md)/);
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
    const liveGates = loadReleaseDocGateCounts();
    assert.equal(liveGates.combined.open_gates, false);
    assert.equal(liveGates.combined.external_blockers, 0);
    assert.equal(liveGates.combined.unchecked, 0);
    assert.equal(liveGates.combined.in_progress, 0);
  });

  it('preserves invalid_fields on required_evidence_kinds.invalid in gap reports', () => {
    const report = aggregateProductionReadinessGapAudit(
      {
        releaseId: 'rel_invalid_adapter',
        records: [{
          kind: 'governed_adapter',
          status: 'accepted',
          evidence: {
            ...PRODUCTION_RELEASE_EVIDENCE_COMPLETE.governed_adapter,
            adapter_type: 'partner_http',
          },
        }],
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
        records: [{
          kind: 'staging_e2e_matrix',
          status: 'accepted',
          evidence: {
            ...STAGING_E2E_MATRIX,
            environment: 'local-staging',
            overall_status: 'incomplete',
            scenarios: [
              { scenario_id: 'oidc_login', status: 'not_run' },
              { scenario_id: 'safe_validation_loop', status: 'passed' },
            ],
          },
        }],
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
    const records = completeEvidenceRecords(PRODUCTION_RELEASE_EVIDENCE_KINDS).map((entry) => ({
      ...entry,
      status: 'accepted',
    }));
    const report = aggregateProductionReadinessGapAudit(
      { records, releaseId: 'rel_ready' },
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
