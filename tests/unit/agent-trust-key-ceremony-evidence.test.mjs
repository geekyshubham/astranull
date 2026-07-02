import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import {
  createAgentTrustKeyCeremonyEvidenceManifest,
  main,
  parseArgs,
  validateAgentTrustKeyCeremonyEvidence,
  validateAndPrepareAgentTrustKeyCeremonyEvidence,
} from '../../scripts/agent-trust-key-ceremony-evidence.mjs';

const tempDirs = [];

function tempDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-agent-trust-key-'));
  tempDirs.push(dir);
  return dir;
}

function writeJson(file, value) {
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

const FP_A = 'a'.repeat(64);
const FP_B = 'b'.repeat(64);
const FP_C = 'c'.repeat(64);

function validCeremony(overrides = {}) {
  return {
    drill_id: 'agent_trust_key_drill_2026_07_02',
    environment: 'staging',
    tenant_id: 'ten_demo',
    started_at: '2026-07-02T08:00:00.000Z',
    completed_at: '2026-07-02T10:00:00.000Z',
    signing_key_ceremony: {
      method: 'generate',
      signing_key_reference: 'keyref://hsm/agent-update-signing/v1',
      custody_uri: 'custody://security/agent-signing-key/v1',
    },
    active_trust_key_registration: {
      trust_key_id: 'autk_0123456789abcdef',
      name: 'staging-agent-update-signing',
      fingerprint_sha256: FP_A,
      registration_reference: 'evidence://agent/trust-key/register-001',
    },
    staged_release_binding: {
      release_id: 'aurel_0123456789abcdef',
      signing_fingerprint_sha256: FP_A,
      rollout_percentage: 25,
      binding_verified: true,
      binding_reference: 'evidence://agent/release/staged-binding-001',
    },
    trust_key_rotation: {
      previous_trust_key_id: 'autk_aaaaaaaaaaaaaaaa',
      new_trust_key_id: 'autk_bbbbbbbbbbbbbbbb',
      previous_fingerprint_sha256: FP_B,
      new_fingerprint_sha256: FP_A,
      rotation_reference: 'evidence://agent/trust-key/rotation-001',
    },
    trust_key_revocation: {
      revoked_trust_key_id: 'autk_bbbbbbbbbbbbbbbb',
      fingerprint_sha256: FP_B,
      revocation_reference: 'evidence://agent/trust-key/revoke-001',
    },
    rollback_trust_behavior: {
      scenario: 'revoked_signing_key_release_rejected',
      untrusted_signing_key_observed: true,
      behavior_reference: 'evidence://agent/trust-key/rollback-trust-001',
      verified_at: '2026-07-02T09:45:00.000Z',
    },
    custody_uris: [
      'custody://security/agent-trust-key-ceremony/2026-07-02',
      'custody://audit/agent-update-trust-key-drill',
    ],
    operator_signoff: {
      operator: 'release-admin',
      role: 'agent-update-operator',
      signed_at: '2026-07-02T10:30:00.000Z',
      signoff_reference: 'signoff://ops/agent-trust-key-drill',
    },
    security_signoff: {
      operator: 'security-lead',
      role: 'security-owner',
      signed_at: '2026-07-02T10:45:00.000Z',
      signoff_reference: 'signoff://security/agent-trust-key-drill',
    },
    audit_event_ids: ['audit_trust_key_1', 'audit_trust_key_2', 'audit_trust_key_3'],
    ...overrides,
  };
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop(), { recursive: true, force: true });
  }
});

describe('agent trust-key ceremony evidence validator', () => {
  it('parses CLI arguments', () => {
    assert.deepEqual(parseArgs(['--input', 'ceremony.json']), {
      input: 'ceremony.json',
      out: 'output/agent-trust-key-ceremony-evidence.json',
      validateOnly: false,
      help: false,
    });
    assert.throws(() => parseArgs([]), /--input is required/);
  });

  it('accepts valid metadata-only ceremony transcript', () => {
    const result = validateAgentTrustKeyCeremonyEvidence(validCeremony());
    assert.equal(result.ok, true);
    assert.deepEqual(result.missing_fields, []);
    assert.deepEqual(result.forbidden_fields, []);
    assert.equal(result.missing_signoff, false);
  });

  it('accepts import signing-key ceremony method', () => {
    const result = validateAgentTrustKeyCeremonyEvidence(validCeremony({
      signing_key_ceremony: {
        method: 'import',
        signing_key_reference: 'keyref://vault/imported/agent-signing',
        custody_uri: 'custody://vault/agent-signing-import',
      },
    }));
    assert.equal(result.ok, true);
  });

  it('writes manifest via CLI when validation passes', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'input.json');
    const out = path.join(dir, 'manifest.json');
    writeJson(input, validCeremony());
    const code = await main(['--input', input, '--out', out]);
    assert.equal(code, 0);
    assert.equal(existsSync(out), true);
    const manifest = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(manifest.artifact_type, 'agent_trust_key_ceremony_evidence');
    assert.equal(manifest.validation.ok, true);
    assert.equal(manifest.ceremony_summary.custody_uri_count, 2);
    assert.equal(manifest.custody_uris.length, 2);
  });

  it('rejects missing operator signoff reference', () => {
    const result = validateAgentTrustKeyCeremonyEvidence(validCeremony({
      operator_signoff: {
        operator: 'release-admin',
        role: 'agent-update-operator',
        signed_at: '2026-07-02T10:30:00.000Z',
      },
    }));
    assert.equal(result.ok, false);
    assert.equal(result.missing_signoff, true);
    assert.ok(result.missing_fields.includes('operator_signoff.signoff_reference'));
  });

  it('rejects binding_verified false and invalid fingerprints', () => {
    const binding = validateAgentTrustKeyCeremonyEvidence(validCeremony({
      staged_release_binding: {
        release_id: 'aurel_x',
        signing_fingerprint_sha256: 'not-a-fingerprint',
        rollout_percentage: 25,
        binding_verified: false,
        binding_reference: 'evidence://x',
      },
    }));
    assert.equal(binding.ok, false);
    assert.ok(binding.missing_fields.includes('staged_release_binding.binding_verified'));
    assert.ok(binding.missing_fields.includes('staged_release_binding.signing_fingerprint_sha256'));
  });

  it('rejects forbidden key material and nested secrets', () => {
    const withKey = validateAgentTrustKeyCeremonyEvidence(validCeremony({
      public_key_der_base64: 'MCowBQYDK2VwAyEAfake',
    }));
    assert.equal(withKey.ok, false);
    assert.ok(withKey.forbidden_fields.includes('public_key_der_base64'));

    const withToken = validateAgentTrustKeyCeremonyEvidence(validCeremony({
      notes: 'leaked svc_v1.ten_demo.svc_abc.secretpart',
    }));
    assert.equal(withToken.ok, false);
    assert.ok(withToken.forbidden_fields.some((f) => f.includes('forbidden_pattern')));

    const withDbUrl = validateAgentTrustKeyCeremonyEvidence(validCeremony({
      signing_key_ceremony: {
        method: 'generate',
        signing_key_reference: 'postgres://user:pass@db.example/astranull',
        custody_uri: 'custody://x',
      },
    }));
    assert.equal(withDbUrl.ok, false);
  });

  it('rejects private keys, ciphertext, and URL credentials in strings', () => {
    const privateKey = validateAgentTrustKeyCeremonyEvidence(validCeremony({
      rollback_trust_behavior: {
        scenario: 'x',
        untrusted_signing_key_observed: true,
        behavior_reference: '-----BEGIN PRIVATE KEY-----',
        verified_at: '2026-07-02T09:45:00.000Z',
      },
    }));
    assert.equal(privateKey.ok, false);

    assert.throws(
      () => validateAndPrepareAgentTrustKeyCeremonyEvidence(validCeremony({ ciphertext: 'deadbeef' })),
      /forbidden field/,
    );

    const urlCreds = validateAgentTrustKeyCeremonyEvidence(validCeremony({
      custody_uris: ['https://user:pass@cdn.example/evidence'],
    }));
    assert.equal(urlCreds.ok, false);
  });

  it('createAgentTrustKeyCeremonyEvidenceManifest omits raw drill secrets from summary', () => {
    const evidence = validCeremony({ extra_safe_field: 'metadata-only' });
    const validation = validateAgentTrustKeyCeremonyEvidence(evidence);
    const manifest = createAgentTrustKeyCeremonyEvidenceManifest({ evidence, validation });
    const blob = JSON.stringify(manifest);
    assert.equal(blob.includes('svc_v1'), false);
    assert.match(blob, /Metadata-only agent update trust-key ceremony/);
  });
});