import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import {
  PRODUCTION_RELEASE_EVIDENCE_KINDS,
  validateProductionReleaseEvidence,
} from '../../src/contracts/productionReleaseEvidence.mjs';
import {
  createKmsVaultPostureEvidenceManifest,
  main,
  parseArgs,
  validateAndPrepareKmsVaultPostureEvidence,
  validateKmsVaultPostureEvidence,
} from '../../scripts/kms-vault-posture-evidence.mjs';

const tempDirs = [];

function tempDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-kms-vault-posture-'));
  tempDirs.push(dir);
  return dir;
}

function writeJson(file, value) {
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function validPosture(overrides = {}) {
  return {
    environment: 'production',
    evidence_uri: 'evidence://security/kms-vault-posture-2026-07-02',
    vault_posture: {
      provider_class: 'cloud_hsm',
      vault_reference: 'vaultref://vendor/prod/astranull-secrets',
      kms_key_references: [
        'keyref://prod/astranull-envelope/v1',
        'keyref://prod/astranull-bootstrap/v2',
      ],
    },
    key_rotation_policy: {
      policy_reference: 'policy://security/envelope-key-rotation',
      rotation_interval_days: 90,
      auto_rotation_enabled: true,
    },
    access_control_summary: {
      rbac_reference: 'rbac://security/kms-operators',
      break_glass_reference: 'runbook://security/kms-break-glass',
      audit_logging_reference: 'audit://kms/vault-access',
      least_privilege_attested: true,
    },
    drill_reference: {
      drill_id: 'kms_posture_drill_2026_07_02',
      drill_evidence_uri: 'evidence://drill/secret-rotation-2026-07-02',
      completed_at: '2026-07-02T10:30:00.000Z',
    },
    security_signoff: {
      owner: 'security-lead',
      role: 'security-owner',
      signed_at: '2026-07-02T11:30:00.000Z',
      signoff_reference: 'signoff://security/kms-vault-posture',
    },
    ...overrides,
  };
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop(), { recursive: true, force: true });
  }
});

describe('kms vault posture evidence validator', () => {
  it('parses CLI arguments', () => {
    assert.deepEqual(parseArgs(['--input', 'evidence.json']), {
      input: 'evidence.json',
      out: 'output/kms-vault-posture-evidence.json',
      releaseId: null,
      validateOnly: false,
      help: false,
    });
    assert.deepEqual(
      parseArgs(['--input', 'evidence.json', '--out', 'out.json', '--release-id', 'rel-1', '--validate-only']),
      {
        input: 'evidence.json',
        out: 'out.json',
        releaseId: 'rel-1',
        validateOnly: true,
        help: false,
      },
    );
    assert.throws(() => parseArgs([]), /--input is required/);
  });

  it('accepts valid metadata-only posture evidence', () => {
    const result = validateKmsVaultPostureEvidence(validPosture());
    assert.equal(result.ok, true);
    assert.deepEqual(result.missing_fields, []);
    assert.deepEqual(result.forbidden_fields, []);
    assert.equal(result.missing_signoff, false);
  });

  it('accepts valid evidence via CLI and writes manifest with production_release_evidence', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'input.json');
    const out = path.join(dir, 'manifest.json');
    writeJson(input, validPosture());
    const code = await main(['--input', input, '--out', out, '--release-id', 'rel-kms-2026-07-02']);
    assert.equal(code, 0);

    const manifest = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(manifest.artifact_type, 'kms_vault_posture_evidence');
    assert.equal(manifest.validation.ok, true);
    assert.equal(manifest.release_id, 'rel-kms-2026-07-02');
    assert.equal(manifest.vault_summary.provider_class, 'cloud_hsm');
    assert.equal(manifest.production_release_evidence.kind, 'kms_vault_posture');
    assert.equal(manifest.production_release_evidence.evidence.environment, 'production');
    assert.equal(manifest.production_release_evidence.evidence.evidence_uri, validPosture().evidence_uri);
  });

  it('fails when required fields are missing', () => {
    const missingVault = validPosture({ vault_posture: { provider_class: 'cloud_hsm' } });
    const result = validateKmsVaultPostureEvidence(missingVault);
    assert.equal(result.ok, false);
    assert.ok(result.missing_fields.includes('vault_posture.vault_reference'));
    assert.ok(result.missing_fields.includes('vault_posture.kms_key_references'));

    const missingSignoff = validPosture({
      security_signoff: {
        owner: 'security-lead',
        role: 'security-owner',
        signed_at: '2026-07-02T11:30:00.000Z',
      },
    });
    const signoffResult = validateKmsVaultPostureEvidence(missingSignoff);
    assert.equal(signoffResult.ok, false);
    assert.equal(signoffResult.missing_signoff, true);
    assert.throws(
      () => validateAndPrepareKmsVaultPostureEvidence(missingSignoff),
      /missing security signoff reference/,
    );
  });

  it('rejects forbidden nested secret, crypto, and raw fields', () => {
    const withToken = validPosture({
      audit: { nested: { token: 'must-not-appear' } },
    });
    let result = validateKmsVaultPostureEvidence(withToken);
    assert.equal(result.ok, false);
    assert.ok(result.forbidden_fields.includes('audit.nested.token'));

    const withPlaintext = validPosture({
      debug: { plaintext_value: 'super-secret' },
    });
    result = validateKmsVaultPostureEvidence(withPlaintext);
    assert.equal(result.ok, false);
    assert.ok(result.forbidden_fields.includes('debug.plaintext_value'));

    const withKeyMaterial = validPosture({
      samples: { key_material: 'deadbeef' },
    });
    result = validateKmsVaultPostureEvidence(withKeyMaterial);
    assert.equal(result.ok, false);
    assert.ok(result.forbidden_fields.includes('samples.key_material'));

    const withDbUrl = validPosture({
      notes: 'reviewed postgresql://user:pass@db.internal:5432/astranull',
    });
    result = validateKmsVaultPostureEvidence(withDbUrl);
    assert.equal(result.ok, false);
    assert.ok(result.forbidden_fields.some((field) => field.includes('database_url_pattern')));

    assert.throws(
      () => validateAndPrepareKmsVaultPostureEvidence(withToken),
      /forbidden field\(s\):/,
    );
  });

  it('validate-only succeeds for valid evidence without writing output', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'input.json');
    const out = path.join(dir, 'manifest.json');
    writeJson(input, validPosture());

    const code = await main(['--input', input, '--out', out, '--validate-only']);
    assert.equal(code, 0);
    assert.equal(existsSync(out), false);
  });

  it('createKmsVaultPostureEvidenceManifest redacts sensitive strings', () => {
    const manifest = createKmsVaultPostureEvidenceManifest({
      evidence: validPosture({
        notes: 'ast_v1.fake.fake.fake referenced in custody review only',
      }),
      validation: validateKmsVaultPostureEvidence(validPosture()),
      releaseId: 'rel-kms',
      createdAt: '2026-07-02T12:00:00.000Z',
    });
    const blob = JSON.stringify(manifest);
    assert.equal(blob.includes('ast_v1.fake.fake.fake'), false);
    assert.match(blob, /\[REDACTED\]/);
    assert.equal(manifest.validation.ok, true);
  });

  if (PRODUCTION_RELEASE_EVIDENCE_KINDS.includes('kms_vault_posture')) {
    it('production release evidence contract accepts manifest evidence payload', () => {
      const manifest = createKmsVaultPostureEvidenceManifest({
        evidence: validPosture(),
        validation: validateKmsVaultPostureEvidence(validPosture()),
        createdAt: '2026-07-02T12:00:00.000Z',
      });
      const contractResult = validateProductionReleaseEvidence(
        'kms_vault_posture',
        manifest.production_release_evidence.evidence,
      );
      assert.equal(contractResult.ok, true, JSON.stringify(contractResult));
    });
  }
});