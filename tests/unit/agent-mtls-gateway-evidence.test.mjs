import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import {
  ALLOWED_FINGERPRINT_HEADER_NAMES,
  createAgentMtlsGatewayEvidenceManifest,
  main,
  parseArgs,
  validateAgentMtlsGatewayEvidence,
  validateAndPrepareAgentMtlsGatewayEvidence,
} from '../../scripts/agent-mtls-gateway-evidence.mjs';

const tempDirs = [];

function tempDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-agent-mtls-gateway-'));
  tempDirs.push(dir);
  return dir;
}

function writeJson(file, value) {
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function validEvidence(overrides = {}) {
  return {
    release_id: 'rel-agent-mtls-2026-07-02',
    environment: 'staging',
    gateway_proxy: {
      gateway_reference: 'gateway://staging/agent-control',
      proxy_type: 'nginx-ingress',
      tls_termination_point: 'edge_gateway',
      validated_at: '2026-07-02T10:00:00.000Z',
    },
    client_certificate_issuance: {
      issuer_reference: 'pki://corp/agent-client-ca',
      issuance_runbook_reference: 'runbook://agent/client-cert-issuance',
      validated_at: '2026-07-02T10:05:00.000Z',
    },
    fingerprint_forwarding: {
      allowed_header_names: [...ALLOWED_FINGERPRINT_HEADER_NAMES],
      gateway_sets_fingerprint_header: true,
      strips_untrusted_client_headers: true,
      control_reference: 'config://gateway/agent-mtls-fingerprint-forwarding',
      validated_at: '2026-07-02T10:10:00.000Z',
    },
    header_spoofing_protection: {
      rejects_untrusted_fingerprint_headers: true,
      trusted_proxy_hop_policy: 'single_trusted_hop_strips_client_supplied_fingerprint',
      control_reference: 'config://gateway/agent-mtls-spoofing-controls',
      validated_at: '2026-07-02T10:15:00.000Z',
    },
    agent_registration_heartbeat_proof: {
      staging_agent_reference: 'agent://staging/prod-origin-01',
      registration_evidence_uri: 'evidence://agent/staging-registration-2026-07-02',
      heartbeat_evidence_uri: 'evidence://agent/staging-heartbeat-2026-07-02',
      fingerprint_match_confirmed: true,
      validated_at: '2026-07-02T10:20:00.000Z',
    },
    rotation_revocation_drill: {
      drill_reference: 'drill://agent/client-cert-rotation-revocation-2026-07-02',
      rotation_tested: true,
      revocation_tested: true,
      validated_at: '2026-07-02T11:00:00.000Z',
    },
    security_signoff: {
      owner: 'security-lead',
      role: 'security-owner',
      signed_at: '2026-07-02T11:30:00.000Z',
      signoff_reference: 'signoff://security/agent-mtls-gateway',
    },
    ...overrides,
  };
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop(), { recursive: true, force: true });
  }
});

describe('agent mTLS gateway evidence validator', () => {
  it('parses CLI arguments', () => {
    assert.deepEqual(parseArgs(['--input', 'evidence.json']), {
      input: 'evidence.json',
      out: 'output/agent-mtls-gateway-evidence.json',
      validateOnly: false,
      help: false,
    });
    assert.throws(() => parseArgs([]), /--input is required/);
  });

  it('accepts valid metadata-only evidence', () => {
    const result = validateAgentMtlsGatewayEvidence(validEvidence());
    assert.equal(result.ok, true);
    assert.deepEqual(result.missing_fields, []);
    assert.deepEqual(result.forbidden_fields, []);
    assert.deepEqual(result.invalid_fingerprint_headers, []);
  });

  it('accepts valid evidence via CLI and writes manifest', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'input.json');
    const out = path.join(dir, 'manifest.json');
    writeJson(input, validEvidence());
    const code = await main(['--input', input, '--out', out]);
    assert.equal(code, 0);
    assert.equal(existsSync(out), true);
    const manifest = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(manifest.artifact_type, 'agent_mtls_gateway_evidence');
    assert.equal(manifest.validation.ok, true);
    assert.equal(manifest.staging_proof_summary.fingerprint_match_confirmed, true);
  });

  it('rejects missing security signoff fields', () => {
    const evidence = validEvidence({
      security_signoff: {
        owner: 'security-lead',
        role: 'security-owner',
        signed_at: '2026-07-02T11:30:00.000Z',
      },
    });
    const result = validateAgentMtlsGatewayEvidence(evidence);
    assert.equal(result.ok, false);
    assert.ok(result.missing_fields.includes('security_signoff.signoff_reference'));
  });

  it('rejects disallowed fingerprint header names', () => {
    const evidence = validEvidence({
      fingerprint_forwarding: {
        ...validEvidence().fingerprint_forwarding,
        allowed_header_names: ['x-client-cert-fingerprint', 'x-evil-fingerprint'],
      },
    });
    const result = validateAgentMtlsGatewayEvidence(evidence);
    assert.equal(result.ok, false);
    assert.equal(result.invalid_fingerprint_headers.length, 1);
    assert.throws(
      () => validateAndPrepareAgentMtlsGatewayEvidence(evidence),
      /Invalid fingerprint forwarding header name/,
    );
  });

  it('rejects forbidden keys and PEM bodies', () => {
    const withToken = validEvidence({ token: 'agc_secret_value' });
    assert.equal(validateAgentMtlsGatewayEvidence(withToken).ok, false);

    const withPem = validEvidence({
      gateway_proxy: {
        ...validEvidence().gateway_proxy,
        notes: '-----BEGIN CERTIFICATE-----\nMIIB',
      },
    });
    const pemResult = validateAgentMtlsGatewayEvidence(withPem);
    assert.equal(pemResult.ok, false);
    assert.ok(pemResult.forbidden_fields.some((field) => field.includes('certificate_pem')));

    const withDbUrl = validEvidence({
      environment: 'postgresql://user:pass@db.example/astranull',
    });
    const dbResult = validateAgentMtlsGatewayEvidence(withDbUrl);
    assert.equal(dbResult.ok, false);
    assert.ok(dbResult.forbidden_fields.some((field) => field.includes('database_url_pattern')));
  });

  it('builds manifest summary via createAgentMtlsGatewayEvidenceManifest', () => {
    const evidence = validEvidence();
    const validation = validateAgentMtlsGatewayEvidence(evidence);
    const manifest = createAgentMtlsGatewayEvidenceManifest({ evidence, validation });
    assert.equal(manifest.gateway_summary.gateway_reference, 'gateway://staging/agent-control');
    assert.equal(manifest.rotation_revocation_summary.rotation_tested, true);
    assert.equal(manifest.security_signoff.signoff_reference, 'signoff://security/agent-mtls-gateway');
  });

  it('validate-only exits nonzero when evidence is incomplete', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'bad.json');
    writeJson(input, { release_id: 'rel-only' });
    const code = await main(['--input', input, '--validate-only']);
    assert.equal(code, 1);
  });
});