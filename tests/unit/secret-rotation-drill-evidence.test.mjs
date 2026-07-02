import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import {
  createSecretRotationDrillEvidenceManifest,
  main,
  parseArgs,
  validateAndPrepareSecretRotationDrillEvidence,
  validateSecretRotationDrillEvidence,
} from '../../scripts/secret-rotation-drill-evidence.mjs';

const tempDirs = [];

function tempDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-secret-rotation-drill-'));
  tempDirs.push(dir);
  return dir;
}

function writeJson(file, value) {
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function validDrill(overrides = {}) {
  return {
    drill_id: 'sec_rot_drill_2026_07_02',
    environment: 'staging',
    started_at: '2026-07-02T08:00:00.000Z',
    completed_at: '2026-07-02T10:30:00.000Z',
    key_rotation: {
      provider_reference: 'kms://vendor/staging/astranull-secrets',
      key_reference_before: 'keyref://staging/astranull-secrets/v3',
      key_reference_after: 'keyref://staging/astranull-secrets/v4',
    },
    tenant_count: 12,
    envelope_rekey: {
      envelopes_total: 48,
      envelopes_rekeyed: 48,
    },
    failed_rotations: [],
    rollback_plan: {
      plan_reference: 'runbook://security/envelope-rotation-rollback',
      rollback_tested: true,
      rollback_test_reference: 'evidence://drill/rollback-tabletop-2026-07-02',
    },
    operator_signoff: {
      operator: 'platform-oncall',
      role: 'secrets-operator',
      signed_at: '2026-07-02T11:00:00.000Z',
      signoff_reference: 'signoff://ops/envelope-rotation-drill',
    },
    security_signoff: {
      operator: 'security-lead',
      role: 'security-owner',
      signed_at: '2026-07-02T11:15:00.000Z',
      signoff_reference: 'signoff://security/envelope-rotation-drill',
    },
    audit_event_ids: ['audit_sec_rot_1', 'audit_sec_rot_2', 'audit_sec_rot_3'],
    zero_plaintext_exposure: {
      attested: true,
      attestation_reference: 'attestation://security/zero-plaintext-envelope-rotation',
      attested_at: '2026-07-02T11:20:00.000Z',
      attested_by: 'security-lead',
    },
    ...overrides,
  };
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop(), { recursive: true, force: true });
  }
});

describe('secret rotation drill evidence validator', () => {
  it('parses CLI arguments', () => {
    assert.deepEqual(parseArgs(['--input', 'drill.json']), {
      input: 'drill.json',
      out: 'output/secret-rotation-drill-evidence.json',
      validateOnly: false,
      help: false,
    });
    assert.deepEqual(parseArgs(['--input', 'drill.json', '--out', 'out.json', '--validate-only']), {
      input: 'drill.json',
      out: 'out.json',
      validateOnly: true,
      help: false,
    });
    assert.throws(() => parseArgs([]), /--input is required/);
  });

  it('accepts a valid metadata-only drill transcript', () => {
    const result = validateSecretRotationDrillEvidence(validDrill());
    assert.equal(result.ok, true);
    assert.deepEqual(result.missing_fields, []);
    assert.deepEqual(result.forbidden_fields, []);
    assert.equal(result.missing_signoff, false);
    assert.equal(result.has_unaccepted_failures, false);
  });

  it('accepts valid drill via CLI and writes manifest', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'input.json');
    const out = path.join(dir, 'manifest.json');
    writeJson(input, validDrill());
    const code = await main(['--input', input, '--out', out]);
    assert.equal(code, 0);
    const manifest = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(manifest.artifact_type, 'secret_rotation_drill_evidence');
    assert.equal(manifest.validation.ok, true);
    assert.equal(manifest.drill_summary.tenant_count, 12);
    assert.equal(manifest.drill_summary.envelopes_rekeyed, 48);
  });

  it('fails when operator or security signoff is missing', () => {
    const missingOperatorRef = validDrill({
      operator_signoff: {
        operator: 'platform-oncall',
        role: 'secrets-operator',
        signed_at: '2026-07-02T11:00:00.000Z',
      },
    });
    const operatorResult = validateSecretRotationDrillEvidence(missingOperatorRef);
    assert.equal(operatorResult.ok, false);
    assert.equal(operatorResult.missing_signoff, true);
    assert.ok(operatorResult.missing_fields.includes('operator_signoff.signoff_reference'));

    assert.throws(
      () => validateAndPrepareSecretRotationDrillEvidence(missingOperatorRef),
      /missing operator or security signoff/,
    );

    const missingSecurity = validDrill({ security_signoff: null });
    const securityResult = validateSecretRotationDrillEvidence(missingSecurity);
    assert.equal(securityResult.ok, false);
    assert.equal(securityResult.missing_signoff, true);
    assert.ok(securityResult.missing_fields.includes('security_signoff'));
  });

  it('fails when failed rotations are not accepted', () => {
    const withUnaccepted = validDrill({
      failed_rotations: [
        {
          envelope_reference: 'secret://ten_a/webhook_hmac',
          failure_code: 'rekey_timeout',
          accepted: false,
        },
      ],
    });
    const result = validateSecretRotationDrillEvidence(withUnaccepted);
    assert.equal(result.ok, false);
    assert.equal(result.has_unaccepted_failures, true);
    assert.equal(result.unaccepted_failed_rotations.length, 1);

    assert.throws(
      () => validateAndPrepareSecretRotationDrillEvidence(withUnaccepted),
      /unaccepted failed rotation/,
    );

    const withAccepted = validDrill({
      failed_rotations: [
        {
          envelope_reference: 'secret://ten_b/integration_token',
          failure_code: 'transient_kms_throttle',
          accepted: true,
          acceptance_reference: 'signoff://security/accepted-transient-failure',
        },
      ],
    });
    assert.equal(validateSecretRotationDrillEvidence(withAccepted).ok, true);
  });

  it('rejects forbidden crypto, plaintext, credential, and database URL fields', () => {
    const withCiphertext = validDrill({
      samples: { envelope_ciphertext: 'base64-deadbeef' },
    });
    let result = validateSecretRotationDrillEvidence(withCiphertext);
    assert.equal(result.ok, false);
    assert.ok(result.forbidden_fields.includes('samples.envelope_ciphertext'));

    const withPlaintext = validDrill({
      debug: { plaintext_value: 'super-secret' },
    });
    result = validateSecretRotationDrillEvidence(withPlaintext);
    assert.equal(result.ok, false);
    assert.ok(result.forbidden_fields.includes('debug.plaintext_value'));

    const withAuthTag = validDrill({
      crypto: { auth_tag: 'aabbccee' },
    });
    result = validateSecretRotationDrillEvidence(withAuthTag);
    assert.equal(result.ok, false);
    assert.ok(result.forbidden_fields.includes('crypto.auth_tag'));

    const withDbUrl = validDrill({
      notes: 'connected via postgresql://user:pass@db.internal:5432/astranull',
    });
    result = validateSecretRotationDrillEvidence(withDbUrl);
    assert.equal(result.ok, false);
    assert.ok(result.forbidden_fields.some((field) => field.includes('database_url_pattern')));

    assert.throws(
      () => validateAndPrepareSecretRotationDrillEvidence(withCiphertext),
      /forbidden field\(s\):/,
    );
  });

  it('writes redacted manifest and exits nonzero on validation failure', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'input.json');
    const out = path.join(dir, 'manifest.json');
    writeJson(input, {
      ...validDrill(),
      notes: 'reviewed svc_v1.fake.fake.fake during drill',
      security_signoff: {
        operator: 'security-lead',
        role: 'security-owner',
        signed_at: '2026-07-02T11:15:00.000Z',
      },
      token: 'must-not-appear',
    });

    const code = await main(['--input', input, '--out', out]);
    assert.equal(code, 1);
    assert.equal(existsSync(out), true);

    const manifest = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(manifest.validation.ok, false);
    assert.equal(manifest.validation.missing_signoff, true);
    assert.ok(manifest.forbidden_fields === undefined);
    assert.ok(manifest.validation.forbidden_fields.includes('token'));

    const blob = JSON.stringify(manifest);
    assert.equal(blob.includes('svc_v1.fake.fake.fake'), false);
    assert.equal(blob.includes('must-not-appear'), false);
    assert.match(blob, /\[REDACTED\]/);
    assert.equal(manifest.notes, 'reviewed [REDACTED] during drill');
  });

  it('validate-only succeeds for valid drill without writing output', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'input.json');
    const out = path.join(dir, 'manifest.json');
    writeJson(input, validDrill());

    const code = await main(['--input', input, '--out', out, '--validate-only']);
    assert.equal(code, 0);
    assert.equal(existsSync(out), false);
  });

  it('createSecretRotationDrillEvidenceManifest redacts sensitive strings in summary paths', () => {
    const manifest = createSecretRotationDrillEvidenceManifest({
      evidence: validDrill({
        notes: 'ast_v1.fake.fake.fake observed in log review only',
      }),
      validation: validateSecretRotationDrillEvidence(validDrill()),
    });
    const blob = JSON.stringify(manifest);
    assert.equal(blob.includes('ast_v1.fake.fake.fake'), false);
    assert.match(blob, /\[REDACTED\]/);
    assert.equal(manifest.validation.ok, true);
  });
});