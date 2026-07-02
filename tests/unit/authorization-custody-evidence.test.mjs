import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import { REQUIRED_ARTIFACT_TYPES } from '../../src/lib/highScalePolicy.mjs';
import {
  buildAuthorizationCustodyProductionReleaseEvidence,
  createAuthorizationCustodyEvidenceManifest,
  main,
  parseArgs,
  validateAuthorizationCustodyEvidence,
  validateAuthorizationCustodyProductionReleaseContract,
} from '../../scripts/authorization-custody-evidence.mjs';

const tempDirs = [];
const CREATED_AT = '2026-07-02T12:00:00.000Z';

function artifactCustodyEntry(artifactType, index) {
  return {
    artifact_type: artifactType,
    custody_id: `custody://${artifactType}/${index}`,
    custody_uri: `metadata://custody/${artifactType}/${index}`,
    status: 'sealed',
  };
}

function completeEvidence(overrides = {}) {
  const artifact_custody = REQUIRED_ARTIFACT_TYPES.map((type, index) => artifactCustodyEntry(type, index));
  return {
    high_scale_request_id: 'hsr_custody_evidence_001',
    release_id: 'rel-2026-07-02',
    soc_reviewer: 'usr_soc_custody_reviewer',
    requires_provider_approval: false,
    custody_summary: {
      custody_system_reference: 'custody://soc/authorization-vault',
      chain_of_custody_verified: true,
    },
    retention_policy: {
      policy_reference: 'policy://custody/retention/v1',
      retention_years: 7,
      retention_classification: 'high_scale_authorization',
    },
    legal_signoff: {
      reference: 'signoff://legal/custody-2026-07-02',
      signed_at: '2026-07-02T00:00:00.000Z',
    },
    scoped_authorization_references: {
      valid_window: {
        valid_from: '2026-07-03T00:00:00.000Z',
        valid_to: '2026-07-04T00:00:00.000Z',
      },
      scenario_families: ['volumetric_metadata', 'protocol_metadata'],
      rate_caps: {
        max_rate: '500_rps_metadata',
        max_duration_minutes: 30,
      },
    },
    artifact_custody,
    evidence_uri: 'evidence://soc/authorization-custody',
    ...overrides,
  };
}

function tempDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-authorization-custody-evidence-'));
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

describe('authorization custody evidence utility', () => {
  it('parses CLI arguments', () => {
    assert.deepEqual(parseArgs(['--input', 'evidence.json']), {
      input: 'evidence.json',
      out: 'output/authorization-custody-evidence.json',
      releaseId: null,
      validateOnly: false,
      help: false,
    });
    assert.throws(() => parseArgs([]), /--input is required/);
  });

  it('accepts complete authorization custody evidence', () => {
    const evidence = completeEvidence();
    const validation = validateAuthorizationCustodyEvidence(evidence);
    assert.equal(validation.ok, true);
    assert.deepEqual(validation.missing_requirements, []);
    assert.deepEqual(validation.missing_artifact_types, []);
    assert.deepEqual(validation.forbidden_fields, []);
  });

  it('reports missing required artifact type coverage', () => {
    const evidence = completeEvidence();
    evidence.artifact_custody = evidence.artifact_custody.filter(
      (entry) => entry.artifact_type !== 'legal_approval',
    );
    const validation = validateAuthorizationCustodyEvidence(evidence);
    assert.equal(validation.ok, false);
    assert.ok(validation.missing_artifact_types.includes('artifact_type:legal_approval'));
    assert.ok(validation.missing_requirements.includes('artifact_type:legal_approval'));
  });

  it('reports missing legal signoff fields', () => {
    const evidence = completeEvidence({
      legal_signoff: { reference: 'signoff://legal/incomplete' },
    });
    const validation = validateAuthorizationCustodyEvidence(evidence);
    assert.equal(validation.ok, false);
    assert.ok(validation.missing_requirements.includes('legal_signoff.signed_at'));
  });

  it('rejects forbidden IP inventory and attachment fields', () => {
    const evidence = completeEvidence({
      attachments: [{ name: 'authorization.pdf' }],
      artifact_custody: [
        ...completeEvidence().artifact_custody,
        {
          artifact_type: 'provider_approval',
          custody_id: 'custody://bad',
          custody_uri: 'metadata://bad',
          target_ip_inventory: ['203.0.113.10'],
        },
      ],
    });
    const validation = validateAuthorizationCustodyEvidence(evidence);
    assert.equal(validation.ok, false);
    assert.ok(validation.forbidden_fields.includes('attachments'));
    const nestedInventory = validation.forbidden_fields.find((field) => field.includes('target_ip_inventory'));
    assert.ok(nestedInventory);
  });

  it('validates production release contract for authorization_custody', () => {
    const evidence = completeEvidence();
    const validation = validateAuthorizationCustodyEvidence(evidence);
    const productionEvidence = buildAuthorizationCustodyProductionReleaseEvidence({
      evidence,
      validation,
      releaseId: evidence.release_id,
      createdAt: CREATED_AT,
    });
    const contract = validateAuthorizationCustodyProductionReleaseContract(productionEvidence);
    assert.equal(contract.ok, true);
    assert.deepEqual(contract.missing_fields, []);
    assert.deepEqual(contract.forbidden_fields, []);
    assert.equal(productionEvidence.artifact_type, 'authorization_custody_evidence');
    assert.equal(productionEvidence.custody_summary.soc_reviewer, evidence.soc_reviewer);
    assert.equal(productionEvidence.required_artifacts.length, REQUIRED_ARTIFACT_TYPES.length);
  });

  it('creates a metadata-only manifest and rejects unapproved execution markers', () => {
    const evidence = completeEvidence({
      traffic_generation_enabled: true,
      artifact_custody: [
        {
          ...artifactCustodyEntry('customer_authorization_letter', 0),
          contact_path: 'war-room@example.invalid token svc_v1.fake.fake.fake',
        },
      ],
    });
    const manifest = createAuthorizationCustodyEvidenceManifest({
      evidence,
      createdAt: CREATED_AT,
    });
    assert.equal(manifest.validation.ok, false);
    assert.ok(manifest.validation.invalid_fields.some((entry) => entry.field === 'traffic_generation_enabled'));

    const blob = JSON.stringify(manifest);
    assert.equal(blob.includes('svc_v1.fake.fake.fake'), false);
    assert.match(blob, /\[REDACTED\]/);
    assert.equal(manifest.production_release_evidence.kind, 'authorization_custody');
  });

  it('writes output on invalid evidence and validate-only skips write for valid evidence', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'input.json');
    const out = path.join(dir, 'manifest.json');
    writeJson(input, completeEvidence());

    const validCode = await main(['--input', input, '--out', out, '--release-id', 'rel-cli', '--validate-only']);
    assert.equal(validCode, 0);
    assert.equal(existsSync(out), false);

    writeJson(input, completeEvidence({ soc_reviewer: null }));
    await assert.rejects(
      () => main(['--input', input, '--out', out, '--release-id', 'rel-cli']),
      /Authorization custody evidence invalid/,
    );
    assert.equal(existsSync(out), true);
    const manifest = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(manifest.validation.ok, false);
    assert.ok(manifest.validation.missing_requirements.includes('soc_reviewer'));
  });
});