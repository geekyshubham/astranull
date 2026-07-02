import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import {
  createDrRestoreEvidenceManifest,
  main,
  parseDrRestoreEvidenceArgs,
  validateDrRestoreDrillEvidence,
} from '../../scripts/dr-restore-evidence.mjs';

const SHA256_SAMPLE = 'a'.repeat(64);

const VALID_DRILL = {
  drill_id: 'dr_2026_07_02_staging_restore',
  environment: 'staging',
  drill_type: 'restore',
  started_at: '2026-07-02T00:00:00.000Z',
  completed_at: '2026-07-02T01:30:00.000Z',
  backup_manifest: {
    manifest_uri: 'evidence://dr/backup-manifest/staging-2026-07-01',
    sha256: SHA256_SAMPLE,
    backup_reference: 'rds-snapshot/staging/astranull-2026-07-01',
  },
  restore_target: {
    cluster_reference: 'db-cluster/staging/astranull-restore-clone',
    database_reference: 'postgres/staging/astranull',
    restore_mode: 'non_production_clone',
  },
  rpo_rto: {
    rpo_target_minutes: 60,
    rto_target_minutes: 240,
    measured_rpo_minutes: 15,
    measured_rto_minutes: 90,
  },
  operator_approvals: [
    {
      role: 'database-operator',
      operator: 'db-oncall',
      approved_at: '2026-07-02T00:00:00.000Z',
      signoff_reference: 'signoff://ops/db-restore-approval',
    },
    {
      role: 'security-owner',
      operator: 'security-lead',
      approved_at: '2026-07-02T00:05:00.000Z',
      signoff_reference: 'signoff://security/dr-drill',
    },
  ],
  evidence_custody_ids: [
    'custody://dr/staging/backup-manifest',
    'custody://dr/staging/restore-runbook',
  ],
  recovery_decision: {
    decision: 'forward_fix',
    decision_reference: 'change://drill-forward-fix-migration-0007',
    operator: 'release-manager',
    decided_at: '2026-07-02T01:00:00.000Z',
  },
  post_restore_verification: {
    signoff_reference: 'signoff://ops/post-restore-verification',
    checks: [
      {
        check_id: 'tenant_rls_smoke',
        status: 'passed',
        evidence_uri: 'evidence://dr/checks/tenant-rls',
      },
      {
        check_id: 'migration_head',
        status: 'passed',
        evidence_uri: 'evidence://dr/checks/migration-head',
      },
    ],
  },
};

const tempDirs = [];

function tempDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-dr-evidence-'));
  tempDirs.push(dir);
  return dir;
}

function writeJson(file, value) {
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop(), { recursive: true, force: true });
  }
});

describe('dr restore drill evidence validator', () => {
  it('parses CLI arguments', () => {
    assert.deepEqual(parseDrRestoreEvidenceArgs(['--input', 'drill.json']), {
      input: 'drill.json',
      out: null,
      validateOnly: false,
      help: false,
    });
    assert.deepEqual(parseDrRestoreEvidenceArgs(['--input', 'drill.json', '--out', 'out.json', '--validate-only']), {
      input: 'drill.json',
      out: 'out.json',
      validateOnly: true,
      help: false,
    });
    assert.throws(() => parseDrRestoreEvidenceArgs([]), /--input is required/);
  });

  it('accepts a complete valid drill', () => {
    const result = validateDrRestoreDrillEvidence(VALID_DRILL);
    assert.equal(result.ok, true);
    assert.deepEqual(result.missing_fields, []);
    assert.deepEqual(result.forbidden_fields, []);
    assert.equal(result.rpo_rto_within_targets, true);
    assert.equal(result.missing_signoff, false);
  });

  it('fails when RPO or RTO measurements exceed targets', () => {
    const evidence = {
      ...VALID_DRILL,
      rpo_rto: {
        rpo_target_minutes: 30,
        rto_target_minutes: 120,
        measured_rpo_minutes: 45,
        measured_rto_minutes: 180,
      },
    };
    const result = validateDrRestoreDrillEvidence(evidence);
    assert.equal(result.ok, false);
    assert.equal(result.rpo_rto_within_targets, false);
    assert.deepEqual(result.rpo_rto_failures.sort(), ['rpo_exceeded', 'rto_exceeded']);
  });

  it('fails when custody ids or signoff references are missing', () => {
    const missingCustody = { ...VALID_DRILL, evidence_custody_ids: [] };
    assert.equal(validateDrRestoreDrillEvidence(missingCustody).ok, false);
    assert.deepEqual(validateDrRestoreDrillEvidence(missingCustody).missing_fields, ['evidence_custody_ids']);

    const missingApprovalSignoff = {
      ...VALID_DRILL,
      operator_approvals: [{
        role: 'database-operator',
        operator: 'db-oncall',
        approved_at: '2026-07-02T00:00:00.000Z',
      }],
    };
    const approvalResult = validateDrRestoreDrillEvidence(missingApprovalSignoff);
    assert.equal(approvalResult.ok, false);
    assert.equal(approvalResult.missing_signoff, true);
    assert.ok(approvalResult.missing_fields.includes('operator_approvals[0].signoff_reference'));

    const missingPostSignoff = {
      ...VALID_DRILL,
      post_restore_verification: {
        ...VALID_DRILL.post_restore_verification,
        signoff_reference: '',
      },
    };
    const postResult = validateDrRestoreDrillEvidence(missingPostSignoff);
    assert.equal(postResult.ok, false);
    assert.equal(postResult.missing_signoff, true);
    assert.ok(postResult.missing_fields.includes('post_restore_verification.signoff_reference'));
  });

  it('rejects forbidden raw dump or log fields', () => {
    const withDump = {
      ...VALID_DRILL,
      database_dump: 'COPY tenants TO stdout',
    };
    const dumpResult = validateDrRestoreDrillEvidence(withDump);
    assert.equal(dumpResult.ok, false);
    assert.deepEqual(dumpResult.forbidden_fields, ['database_dump']);

    const withLog = {
      ...VALID_DRILL,
      attachments: { raw_log: 'restore stderr output' },
    };
    const logResult = validateDrRestoreDrillEvidence(withLog);
    assert.equal(logResult.ok, false);
    assert.deepEqual(logResult.forbidden_fields.sort(), ['attachments.raw_log']);
  });

  it('writes redacted metadata-only manifest and exits nonzero on validation failure', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'input.json');
    const out = path.join(dir, 'manifest.json');
    writeJson(input, {
      ...VALID_DRILL,
      notes: 'operator carried ast_v1.fake.fake.fake during drill',
      rpo_rto: {
        rpo_target_minutes: 30,
        rto_target_minutes: 120,
        measured_rpo_minutes: 45,
        measured_rto_minutes: 90,
      },
      token: 'must-not-appear',
    });

    const code = await main(['--input', input, '--out', out]);
    assert.equal(code, 1);
    assert.equal(existsSync(out), true);

    const manifest = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(manifest.artifact_type, 'dr_restore_failover_drill_evidence');
    assert.equal(manifest.validation.ok, false);
    assert.equal(manifest.validation.rpo_rto_within_targets, false);
    assert.equal(manifest.drill_summary.backup_manifest_sha256, SHA256_SAMPLE);

    const blob = JSON.stringify(manifest);
    assert.equal(blob.includes('ast_v1.fake.fake.fake'), false);
    assert.equal(blob.includes('must-not-appear'), false);
    assert.match(blob, /\[REDACTED\]/);
  });

  it('validate-only succeeds for valid drill without writing output', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'input.json');
    const out = path.join(dir, 'manifest.json');
    writeJson(input, VALID_DRILL);

    const code = await main(['--input', input, '--out', out, '--validate-only']);
    assert.equal(code, 0);
    assert.equal(existsSync(out), false);
  });

  it('createDrRestoreEvidenceManifest omits forbidden extras from drill summary', () => {
    const manifest = createDrRestoreEvidenceManifest({
      evidence: {
        ...VALID_DRILL,
        database_url: 'postgres://secret',
      },
      validation: validateDrRestoreDrillEvidence(VALID_DRILL),
    });
    const blob = JSON.stringify(manifest);
    assert.equal(blob.includes('postgres://secret'), false);
    assert.equal(manifest.validation.ok, true);
  });
});