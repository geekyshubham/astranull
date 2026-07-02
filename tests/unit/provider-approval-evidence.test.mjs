import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import {
  createProviderApprovalEvidenceManifest,
  main,
  parseArgs,
  validateProviderApprovalEvidence,
} from '../../scripts/provider-approval-evidence.mjs';

const tempDirs = [];

const AS_OF = '2026-07-02T12:00:00.000Z';
const AS_OF_MS = Date.parse(AS_OF);

function futureWindow() {
  return { valid_from: '2026-07-01T00:00:00.000Z', valid_to: '2026-07-10T00:00:00.000Z' };
}

function completeEvidence(overrides = {}) {
  return {
    high_scale_request_id: 'hsr_provider_evidence',
    requested_scenario_families: ['volumetric_metadata'],
    authorized_scope_hash: 'sha256:scope-demo-001',
    soc_reviewer: 'usr_soc_reviewer',
    legal_signoff: {
      reference: 'legal://signoff/provider-approval/1',
      signed_at: '2026-07-01T10:00:00.000Z',
    },
    custody_ids: ['cust_doc_provider_approval_1'],
    provider_approval: {
      provider_name: 'Cloudflare',
      approval_reference: 'CF-1001',
      valid_window: futureWindow(),
      approved_targets: ['tg_demo'],
      approved_scenario_families: ['volumetric_metadata'],
      contact_path: 'provider-war-room@example.invalid',
      approved_limits: { max_rate: '500_rps_metadata', max_duration_minutes: 30 },
      provider_specific_evidence: { provider_ticket: 'CF-1001' },
      emergency_stop_path: 'provider-stop-bridge',
    },
    ...overrides,
  };
}

function tempDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-provider-approval-evidence-'));
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

describe('provider approval evidence utility', () => {
  it('parses CLI arguments', () => {
    assert.deepEqual(parseArgs(['--input', 'evidence.json']), {
      input: 'evidence.json',
      out: 'output/provider-approval-evidence.json',
      validateOnly: false,
      asOf: null,
      help: false,
    });
    assert.throws(() => parseArgs([]), /--input is required/);
  });

  it('accepts complete provider approval evidence', () => {
    const validation = validateProviderApprovalEvidence(completeEvidence(), { asOfMs: AS_OF_MS });
    assert.equal(validation.ok, true);
    assert.deepEqual(validation.missing_requirements, []);
    assert.deepEqual(validation.forbidden_fields, []);
    assert.equal(validation.expired, false);
    assert.equal(validation.provider_key, 'cloudflare');
    assert.equal(validation.approval_path, 'provider_fire_drill');
  });

  it('reports missing provider path requirements', () => {
    const evidence = completeEvidence();
    delete evidence.provider_approval.approval_reference;
    delete evidence.provider_approval.emergency_stop_path;
    const validation = validateProviderApprovalEvidence(evidence, { asOfMs: AS_OF_MS });
    assert.equal(validation.ok, false);
    assert.ok(validation.missing_requirements.includes('provider_approval.approval_reference'));
    assert.ok(validation.missing_requirements.includes('provider_approval.emergency_stop_path'));
  });

  it('rejects expired approval windows', () => {
    const evidence = completeEvidence({
      provider_approval: {
        ...completeEvidence().provider_approval,
        valid_window: { valid_to: '2026-01-01T00:00:00.000Z' },
      },
    });
    const validation = validateProviderApprovalEvidence(evidence, { asOfMs: AS_OF_MS });
    assert.equal(validation.ok, false);
    assert.equal(validation.expired, true);
    assert.ok(validation.missing_requirements.includes('approval_expired'));
  });

  it('rejects nested provider_specific_evidence client_secret and omits it from manifest', () => {
    const evidence = completeEvidence({
      provider_approval: {
        ...completeEvidence().provider_approval,
        provider_specific_evidence: {
          provider_ticket: 'CF-1001',
          client_secret: 'supersecret123',
        },
      },
    });
    const validation = validateProviderApprovalEvidence(evidence, { asOfMs: AS_OF_MS });
    assert.equal(validation.ok, false);
    assert.ok(
      validation.forbidden_fields.some((field) => field.includes('client_secret')),
    );

    const manifest = createProviderApprovalEvidenceManifest({
      evidence,
      asOfMs: AS_OF_MS,
      createdAt: AS_OF,
    });
    const blob = JSON.stringify(manifest);
    assert.equal(blob.includes('client_secret'), false);
    assert.equal(blob.includes('supersecret123'), false);
  });

  it('rejects forbidden credentials and target IP inventory dumps', () => {
    const evidence = completeEvidence({
      credential: 'cloudflare_api_key_secret',
      provider_approval: {
        ...completeEvidence().provider_approval,
        target_ip_inventory: ['203.0.113.10', '203.0.113.11'],
      },
    });
    const validation = validateProviderApprovalEvidence(evidence, { asOfMs: AS_OF_MS });
    assert.equal(validation.ok, false);
    assert.ok(validation.forbidden_fields.includes('credential'));
    assert.ok(validation.forbidden_fields.includes('provider_approval.target_ip_inventory'));
  });

  it('creates a redacted metadata-only manifest with missing requirements', () => {
    const evidence = completeEvidence();
    delete evidence.soc_reviewer;
    delete evidence.provider_approval.approval_reference;
    evidence.provider_approval.contact_path = 'war-room@example.invalid with token svc_v1.fake.fake.fake';

    const manifest = createProviderApprovalEvidenceManifest({
      evidence,
      asOfMs: AS_OF_MS,
      createdAt: AS_OF,
    });

    assert.equal(manifest.artifact_type, 'provider_approval_evidence');
    assert.equal(manifest.validation.ok, false);
    assert.ok(manifest.validation.missing_requirements.includes('soc_reviewer'));
    assert.ok(manifest.validation.missing_requirements.includes('provider_approval.approval_reference'));

    const blob = JSON.stringify(manifest);
    assert.equal(blob.includes('svc_v1.fake.fake.fake'), false);
    assert.equal(blob.includes('cloudflare_api_key_secret'), false);
    assert.equal(blob.includes('war-room@example.invalid'), true);
    assert.match(blob, /\[REDACTED\]/);
    assert.equal(manifest.metadata.authorized_scope_hash, 'sha256:scope-demo-001');
    assert.equal(manifest.metadata.provider_key, 'cloudflare');
  });

  it('writes output on invalid evidence and validate-only skips write for valid evidence', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'input.json');
    const out = path.join(dir, 'manifest.json');
    writeJson(input, completeEvidence());

    const validCode = await main(['--input', input, '--out', out, '--as-of', AS_OF, '--validate-only']);
    assert.equal(validCode, 0);
    assert.equal(existsSync(out), false);

    writeJson(input, completeEvidence({ soc_reviewer: null }));
    await assert.rejects(
      () => main(['--input', input, '--out', out, '--as-of', AS_OF]),
      /Provider approval evidence invalid/,
    );
    assert.equal(existsSync(out), true);
    const manifest = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(manifest.validation.ok, false);
    assert.ok(manifest.validation.missing_requirements.includes('soc_reviewer'));
  });
});