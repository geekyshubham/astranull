import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import { validateProductionReleaseEvidence } from '../../src/contracts/productionReleaseEvidence.mjs';
import {
  buildComplianceLegalSignoffProductionEvidence,
  createComplianceLegalSignoffEvidenceManifest,
  main,
  parseComplianceLegalSignoffEvidenceArgs,
  validateComplianceLegalSignoffEvidence,
} from '../../scripts/compliance-legal-signoff-evidence.mjs';

const tempDirs = [];

function tempDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-compliance-legal-'));
  tempDirs.push(dir);
  return dir;
}

function writeJson(file, value) {
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function validPack(overrides = {}) {
  return {
    release_id: 'rel-2026-07-02',
    legal_owner: 'legal-counsel',
    auditor_owner: 'compliance-auditor',
    review_date: '2026-07-02T00:00:00.000Z',
    signoffs: [
      {
        role: 'legal',
        signoff_reference: 'signoff://legal/release-2026-07-02',
        signed_at: '2026-07-02T00:00:00.000Z',
      },
      {
        role: 'compliance',
        signoff_reference: 'signoff://compliance/release-2026-07-02',
        signed_at: '2026-07-02T00:05:00.000Z',
      },
    ],
    reviewed_templates: [
      {
        template_kind: 'soc2',
        review_date: '2026-07-01T12:00:00.000Z',
        signoff_reference: 'signoff://compliance/soc2-mapping-review',
        review_status: 'approved',
        evidence_uri: 'evidence://compliance/soc2-review',
      },
      {
        template_kind: 'iso27001',
        review_date: '2026-07-01T13:00:00.000Z',
        signoff_reference: 'signoff://compliance/iso27001-mapping-review',
        review_status: 'approved',
        evidence_uri: 'evidence://compliance/iso27001-review',
      },
      {
        local_contract_name: 'customer-dpa-v2026',
        review_date: '2026-07-01T14:00:00.000Z',
        signoff_reference: 'signoff://legal/dpa-review',
        review_status: 'approved',
        evidence_uri: 'evidence://legal/dpa-review',
      },
    ],
    caveats: [
      'Compliance mappings orient report packaging only; they do not certify control satisfaction.',
      'Immutable legal and auditor signoff artifacts remain in custody outside this metadata pack.',
    ],
    evidence_uri: 'evidence://compliance/legal-signoff',
    ...overrides,
  };
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop(), { recursive: true, force: true });
  }
});

describe('compliance legal signoff evidence validator', () => {
  it('parses CLI arguments', () => {
    assert.deepEqual(parseComplianceLegalSignoffEvidenceArgs(['--input', 'evidence.json']), {
      input: 'evidence.json',
      out: 'output/compliance-legal-signoff-evidence.json',
      releaseId: null,
      validateOnly: false,
      help: false,
    });
    assert.deepEqual(
      parseComplianceLegalSignoffEvidenceArgs([
        '--input',
        'evidence.json',
        '--out',
        'out.json',
        '--release-id',
        'rel-ga',
        '--validate-only',
      ]),
      {
        input: 'evidence.json',
        out: 'out.json',
        releaseId: 'rel-ga',
        validateOnly: true,
        help: false,
      },
    );
    assert.throws(() => parseComplianceLegalSignoffEvidenceArgs([]), /--input is required/);
  });

  it('accepts complete valid metadata-only signoff pack', () => {
    const result = validateComplianceLegalSignoffEvidence(validPack());
    assert.equal(result.ok, true);
    assert.deepEqual(result.missing_fields, []);
    assert.deepEqual(result.forbidden_fields, []);
    assert.equal(result.missing_owner, false);
    assert.equal(result.missing_signoffs, false);
    assert.equal(result.reviewed_template_gaps, false);
  });

  it('fails when legal or auditor owners or signoffs are missing', () => {
    const missingOwners = validPack({ legal_owner: '', auditor_owner: null });
    const ownerResult = validateComplianceLegalSignoffEvidence(missingOwners);
    assert.equal(ownerResult.ok, false);
    assert.equal(ownerResult.missing_owner, true);
    assert.ok(ownerResult.missing_fields.includes('legal_owner'));
    assert.ok(ownerResult.missing_fields.includes('auditor_owner'));

    const missingAuditorSignoff = validPack({
      signoffs: [
        {
          role: 'legal',
          signoff_reference: 'signoff://legal/release-2026-07-02',
          signed_at: '2026-07-02T00:00:00.000Z',
        },
      ],
    });
    const signoffResult = validateComplianceLegalSignoffEvidence(missingAuditorSignoff);
    assert.equal(signoffResult.ok, false);
    assert.equal(signoffResult.missing_signoffs, true);
    assert.equal(signoffResult.missing_auditor_signoff, true);
    assert.ok(signoffResult.missing_fields.includes('signoffs.auditor'));
  });

  it('fails when reviewed compliance templates have gaps', () => {
    const emptyTemplates = validPack({ reviewed_templates: [] });
    const emptyResult = validateComplianceLegalSignoffEvidence(emptyTemplates);
    assert.equal(emptyResult.ok, false);
    assert.equal(emptyResult.reviewed_template_gaps, true);
    assert.ok(emptyResult.missing_fields.includes('reviewed_templates'));

    const missingReviewDate = validPack({
      reviewed_templates: [
        {
          template_kind: 'dora',
          signoff_reference: 'signoff://compliance/dora-review',
        },
      ],
    });
    const gapResult = validateComplianceLegalSignoffEvidence(missingReviewDate);
    assert.equal(gapResult.ok, false);
    assert.equal(gapResult.reviewed_template_gaps, true);
    assert.ok(gapResult.missing_fields.includes('reviewed_templates[0].review_date'));

    const noFrameworkOrLocal = validPack({
      reviewed_templates: [
        {
          template_kind: 'executive',
          review_date: '2026-07-01T12:00:00.000Z',
          signoff_reference: 'signoff://compliance/exec-only',
        },
      ],
    });
    const frameworkGap = validateComplianceLegalSignoffEvidence(noFrameworkOrLocal);
    assert.equal(frameworkGap.ok, false);
    assert.equal(frameworkGap.reviewed_template_gaps, true);
    assert.ok(frameworkGap.missing_framework_templates.length > 0);
  });

  it('rejects forbidden nested contract, customer data, and raw fields', () => {
    const withContractAttachment = validPack({
      contracts: [{ contract_body: 'full legal agreement text' }],
    });
    const contractResult = validateComplianceLegalSignoffEvidence(withContractAttachment);
    assert.equal(contractResult.ok, false);
    assert.ok(contractResult.forbidden_fields.includes('contracts'));
    assert.ok(contractResult.forbidden_fields.includes('contracts[0].contract_body'));

    const withCustomerData = validPack({
      reviewed_templates: [
        {
          template_kind: 'nis2',
          review_date: '2026-07-01T12:00:00.000Z',
          signoff_reference: 'signoff://compliance/nis2-review',
          customer_data: { tenant: 'acme' },
        },
      ],
    });
    const customerResult = validateComplianceLegalSignoffEvidence(withCustomerData);
    assert.equal(customerResult.ok, false);
    assert.ok(customerResult.forbidden_fields.includes('reviewed_templates[0].customer_data'));

    const withRawFields = validPack({
      attachment: { raw_body: 'paste of legal memo' },
      headers: { authorization: 'Bearer secret' },
      logs: ['audit stderr'],
      token: 'must-not-appear',
      notes: 'connected via postgresql://user:pass@db.internal:5432/astranull',
    });
    const rawResult = validateComplianceLegalSignoffEvidence(withRawFields);
    assert.equal(rawResult.ok, false);
    assert.ok(rawResult.forbidden_fields.includes('attachment'));
    assert.ok(rawResult.forbidden_fields.includes('headers'));
    assert.ok(rawResult.forbidden_fields.includes('logs'));
    assert.ok(rawResult.forbidden_fields.includes('token'));
    assert.ok(rawResult.forbidden_fields.some((field) => field.includes('database_url_pattern')));
  });

  it('builds production release evidence that satisfies compliance_legal_signoff contract', () => {
    const pack = validPack();
    const validation = validateComplianceLegalSignoffEvidence(pack);
    const manifest = buildComplianceLegalSignoffProductionEvidence(pack, validation, {
      createdAt: '2026-07-02T12:00:00.000Z',
    });

    const contract = validateProductionReleaseEvidence('compliance_legal_signoff', {
      schema_version: manifest.schema_version,
      artifact_type: manifest.artifact_type,
      created_at: manifest.created_at,
      release_id: manifest.release_id,
      legal_owner: manifest.legal_owner,
      auditor_owner: manifest.auditor_owner,
      signoffs: manifest.signoffs,
      reviewed_templates: manifest.reviewed_templates,
      evidence_uri: manifest.evidence_uri,
    });

    assert.deepEqual(contract, {
      ok: true,
      invalid_kind: null,
      missing_fields: [],
      forbidden_fields: [],
      invalid_fields: [],
    });
    assert.equal(manifest.validation.production_release_contract.ok, true);
    assert.equal(manifest.artifact_type, 'compliance_legal_signoff_evidence');
  });

  it('validate-only succeeds without writing output', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'input.json');
    const out = path.join(dir, 'manifest.json');
    writeJson(input, validPack());

    const code = await main(['--input', input, '--out', out, '--validate-only']);
    assert.equal(code, 0);
    assert.equal(existsSync(out), false);
  });

  it('writes manifest and exits nonzero on validation failure with redacted notes', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'input.json');
    const out = path.join(dir, 'manifest.json');
    writeJson(input, {
      ...validPack(),
      notes: 'reviewed ast_v1.fake.fake.fake in legal memo',
      signoffs: [
        {
          role: 'legal',
          signoff_reference: 'signoff://legal/release-2026-07-02',
          signed_at: '2026-07-02T00:00:00.000Z',
        },
      ],
      token: 'must-not-appear',
    });

    const code = await main(['--input', input, '--out', out]);
    assert.equal(code, 1);
    assert.equal(existsSync(out), true);

    const manifest = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(manifest.validation.ok, false);
    assert.equal(manifest.validation.missing_signoffs, true);
    assert.ok(manifest.validation.forbidden_fields.includes('token'));

    const blob = JSON.stringify(manifest);
    assert.equal(blob.includes('ast_v1.fake.fake.fake'), false);
    assert.equal(blob.includes('must-not-appear'), false);
    assert.match(blob, /\[REDACTED\]/);
  });

  it('createComplianceLegalSignoffEvidenceManifest applies --release-id override', () => {
    const pack = validPack({ release_id: 'rel-from-file' });
    const manifest = createComplianceLegalSignoffEvidenceManifest({
      pack,
      releaseId: 'rel-from-cli',
      createdAt: '2026-07-02T12:00:00.000Z',
    });
    assert.equal(manifest.release_id, 'rel-from-cli');
    assert.equal(manifest.validation.ok, true);
  });
});