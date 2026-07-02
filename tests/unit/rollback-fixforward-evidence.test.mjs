import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import {
  createRollbackFixforwardEvidenceManifest,
  main,
  parseRollbackFixforwardEvidenceArgs,
  validateRollbackFixforwardEvidence,
} from '../../scripts/rollback-fixforward-evidence.mjs';

const tempDirs = [];

function tempDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-rollback-evidence-'));
  tempDirs.push(dir);
  return dir;
}

function writeJson(file, value) {
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function templateRef(id) {
  return { template_id: id, reference_uri: `template://${id}` };
}

function validPlan(overrides = {}) {
  return {
    release_id: 'rel_2026_07_02_prod',
    environment: 'production',
    owner: 'release-manager',
    migration_plan: {
      plan_reference: 'runbook://db/migration-rollback-forward-fix',
      strategy: 'forward_fix',
      migration_version: '0007_production_release_evidence',
      decision_reference: 'change://release/rel_2026_07_02/migration-plan',
    },
    postgres_backup_reference: {
      backup_reference: 'rds-snapshot/prod/astranull-pre-rel-2026-07-02',
      manifest_uri: 'evidence://db/backup-manifest/pre-rel-2026-07-02',
    },
    tested_command_references: [
      {
        command_id: 'postgres_startup_check',
        reference_uri: 'runbook://db/postgres-startup-check',
        tested_at: '2026-07-01T18:00:00.000Z',
      },
      {
        command_id: 'adapter_disable_flag',
        reference_uri: 'runbook://soc/disable-high-scale-adapter',
        tested_at: '2026-07-01T18:30:00.000Z',
      },
    ],
    adapter_disablement_plan: {
      plan_reference: 'runbook://soc/adapter-disablement',
      flag_reference: 'config://env/ASTRANULL_HIGH_SCALE_ADAPTER_MODE=disabled',
      runbook_reference: 'runbook://soc/stop-the-line',
    },
    probe_worker_flag_plan: {
      plan_reference: 'runbook://probe/worker-flag-plan',
      flag_reference: 'config://env/ASTRANULL_PROBE_MODE=signed-worker',
      runbook_reference: 'runbook://probe/worker-incident',
    },
    notification_comms_plan: {
      plan_reference: 'runbook://comms/notification-incident',
      owner: 'support-lead',
      template_references: [templateRef('incident-customer-update')],
    },
    support_comms_plan: {
      plan_reference: 'runbook://support/escalation',
      owner: 'support-lead',
      template_references: [templateRef('severity-1-bridge')],
    },
    success_criteria: [
      {
        criterion_id: 'api_ready',
        check_reference: 'checklist://rollback/api-ready',
        expected_outcome_reference: 'outcome://rollback/api-200-ready',
      },
      {
        criterion_id: 'migration_head',
        check_reference: 'checklist://rollback/migration-head',
        expected_outcome_reference: 'outcome://rollback/migration-at-target',
      },
    ],
    signoffs: [
      {
        role: 'release-owner',
        operator: 'release-manager',
        signed_at: '2026-07-02T00:00:00.000Z',
        signoff_reference: 'signoff://release/rollback-plan',
      },
      {
        role: 'database-operator',
        operator: 'db-oncall',
        signed_at: '2026-07-02T00:05:00.000Z',
        signoff_reference: 'signoff://db/rollback-plan',
      },
    ],
    ...overrides,
  };
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop(), { recursive: true, force: true });
  }
});

describe('rollback fixforward evidence validator', () => {
  it('parses CLI arguments', () => {
    assert.deepEqual(parseRollbackFixforwardEvidenceArgs(['--input', 'plan.json']), {
      input: 'plan.json',
      out: 'output/rollback-fixforward-evidence.json',
      validateOnly: false,
      help: false,
    });
    assert.deepEqual(
      parseRollbackFixforwardEvidenceArgs(['--input', 'plan.json', '--out', 'out.json', '--validate-only']),
      {
        input: 'plan.json',
        out: 'out.json',
        validateOnly: true,
        help: false,
      },
    );
    assert.throws(() => parseRollbackFixforwardEvidenceArgs([]), /--input is required/);
  });

  it('accepts a complete metadata-only plan', () => {
    const result = validateRollbackFixforwardEvidence(validPlan());
    assert.equal(result.ok, true);
    assert.deepEqual(result.missing_fields, []);
    assert.deepEqual(result.forbidden_fields, []);
    assert.equal(result.missing_signoff, false);
  });

  it('writes manifest via CLI', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'input.json');
    const out = path.join(dir, 'manifest.json');
    writeJson(input, validPlan());
    const code = await main(['--input', input, '--out', out]);
    assert.equal(code, 0);
    const manifest = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(manifest.artifact_type, 'rollback_fixforward_release_evidence');
    assert.equal(manifest.validation.ok, true);
    assert.equal(manifest.plan_summary.release_id, 'rel_2026_07_02_prod');
    assert.equal(manifest.plan_summary.tested_command_count, 2);
  });

  it('validate-only does not write output', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'input.json');
    const out = path.join(dir, 'manifest.json');
    writeJson(input, validPlan());
    const code = await main(['--input', input, '--out', out, '--validate-only']);
    assert.equal(code, 0);
    assert.equal(existsSync(out), false);
  });

  it('requires release owner and database operator signoffs', () => {
    const missingDb = validPlan({
      signoffs: [
        {
          role: 'release-owner',
          operator: 'release-manager',
          signed_at: '2026-07-02T00:00:00.000Z',
          signoff_reference: 'signoff://release/rollback-plan',
        },
      ],
    });
    const result = validateRollbackFixforwardEvidence(missingDb);
    assert.equal(result.ok, false);
    assert.equal(result.missing_signoff, true);
    assert.ok(result.missing_fields.includes('signoffs.database_operator'));
  });

  it('rejects forbidden credentials dumps logs and database URLs', () => {
    const result = validateRollbackFixforwardEvidence(
      validPlan({
        notes: 'postgres://user:pass@host/db',
        attachment: { sql_dump: 'CREATE TABLE x;' },
        token: 'svc_v1.fake.fake.fake',
      }),
    );
    assert.equal(result.ok, false);
    assert.ok(result.forbidden_fields.includes('attachment'));
    assert.ok(result.forbidden_fields.includes('attachment.sql_dump'));
    assert.ok(result.forbidden_fields.includes('token'));
    assert.ok(result.forbidden_fields.some((field) => field.includes('database_url_pattern')));
  });

  it('rejects raw shell command bodies in tested command references', () => {
    const result = validateRollbackFixforwardEvidence(
      validPlan({
        tested_command_references: [
          {
            command_id: 'bad_shell',
            reference_uri: '#!/bin/bash\nexport PASSWORD=secret',
            tested_at: '2026-07-01T18:00:00.000Z',
          },
        ],
      }),
    );
    assert.equal(result.ok, false);
    assert.ok(
      result.forbidden_fields.some((field) => field.includes('raw_shell_script')),
    );
  });

  it('rejects shell_script field on command references', () => {
    const result = validateRollbackFixforwardEvidence(
      validPlan({
        tested_command_references: [
          {
            command_id: 'inline_script',
            reference_uri: 'runbook://ops/bad',
            tested_at: '2026-07-01T18:00:00.000Z',
            shell_script: 'curl -H "Authorization: Bearer x"',
          },
        ],
      }),
    );
    assert.equal(result.ok, false);
    assert.ok(result.forbidden_fields.includes('tested_command_references[0].shell_script'));
  });

  it('manifest redacts notes with token patterns', () => {
    const validation = validateRollbackFixforwardEvidence(validPlan());
    const manifest = createRollbackFixforwardEvidenceManifest({
      evidence: {
        ...validPlan(),
        notes: 'reviewed ast_v1.fake.fake.fake in staging',
      },
      validation,
      createdAt: '2026-07-02T12:00:00.000Z',
    });
    const blob = JSON.stringify(manifest);
    assert.equal(blob.includes('ast_v1.fake.fake.fake'), false);
    assert.match(blob, /\[REDACTED\]/);
  });
});