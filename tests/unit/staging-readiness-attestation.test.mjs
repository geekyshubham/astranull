import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import {
  PRODUCTION_RELEASE_EVIDENCE_KINDS,
} from '../../src/contracts/productionReleaseEvidence.mjs';
import {
  completeEvidenceRecords,
  PRODUCTION_RELEASE_EVIDENCE_COMPLETE,
} from '../../tests/fixtures/productionReleaseEvidenceComplete.mjs';
import {
  aggregateStagingReadinessAttestation,
  assessEvidenceRecord,
  DEFAULT_STAGING_READINESS_PROFILE,
  isRehearsalOrSampleEvidenceInput,
  isSampleOrRehearsalReleaseId,
  main,
  normalizeEvidenceRecords,
  parseArgs,
  resolveReleaseProfileKinds,
  STAGING_READINESS_OPTIONAL_EVIDENCE_KINDS,
  STAGING_READINESS_RELEASE_PROFILES,
} from '../../scripts/staging-readiness-attestation.mjs';

const tempDirs = [];

const SECURITY_REVIEW = {
  reviewer_org: 'Independent Security Review Co',
  scope_summary: 'Production API, UI, SOC workflow, agent control, and release process.',
  review_report_uri: 'evidence://security-review/report',
  findings_status: 'all-critical-high-remediated',
  remediation_tracker_uri: 'evidence://security-review/remediation-tracker',
  risk_acceptance_reference: 'risk://accepted-medium-items',
  reviewed_at: '2026-07-02T00:00:00.000Z',
  security_owner: 'security-lead',
};

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

function tempDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-staging-attest-'));
  tempDirs.push(dir);
  return dir;
}

function writeJson(file, value) {
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function acceptedRecords(records) {
  return records.map((record) => ({ ...record, status: 'accepted' }));
}

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
  return acceptedRecords(records);
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop(), { recursive: true, force: true });
  }
});

describe('staging readiness attestation', () => {
  it('parses CLI arguments with default full profile', () => {
    assert.deepEqual(parseArgs(['--input', 'bundle.json']), {
      input: 'bundle.json',
      out: 'output/staging-readiness-attestation.json',
      releaseId: null,
      profile: DEFAULT_STAGING_READINESS_PROFILE,
      validateOnly: false,
      help: false,
    });
    assert.deepEqual(parseArgs(['--input', 'bundle.json', '--profile', 'safe-validation-ga']).profile, 'safe-validation-ga');
    assert.throws(() => parseArgs([]), /--input is required/);
    assert.throws(() => parseArgs(['--input', 'x.json', '--profile', 'nope']), /Unknown release profile/);
  });

  it('normalizes array and bundle record shapes', () => {
    assert.deepEqual(normalizeEvidenceRecords([{ kind: 'a' }]), [{ kind: 'a' }]);
    assert.deepEqual(normalizeEvidenceRecords({ records: [{ kind: 'b' }] }), [{ kind: 'b' }]);
    assert.throws(() => normalizeEvidenceRecords({}), /records/);
  });

  it('defaults production_ready to false when required kinds are missing', () => {
    const attestation = aggregateStagingReadinessAttestation({
      releaseId: 'rel_partial',
      records: [{ kind: 'third_party_security_review', evidence: SECURITY_REVIEW, status: 'accepted' }],
    }, { requiredKinds: ['third_party_security_review', 'migration_apply'] });

    assert.equal(attestation.production_ready, false);
    assert.equal(attestation.signoff_status, 'missing_evidence');
    assert.deepEqual(attestation.required_evidence_kinds.present, ['third_party_security_review']);
    assert.deepEqual(attestation.required_evidence_kinds.missing, ['migration_apply']);
    assert.ok(attestation.blocker_summary.some((line) => /Missing required/.test(line)));
    assert.ok(
      attestation.caveats.some((line) => /production_ready=false means required profile inventory/.test(line)),
    );
    assert.ok(
      attestation.caveats.every(
        (line) => !(line.includes('production_ready') && line.includes('remains false')),
      ),
    );
  });

  it('sets production_ready true when all required kinds are accepted and valid', () => {
    const attestation = aggregateStagingReadinessAttestation({
      records: [{ kind: 'third_party_security_review', evidence: SECURITY_REVIEW, status: 'accepted' }],
    }, { requiredKinds: ['third_party_security_review'] });

    assert.equal(attestation.production_ready, true);
    assert.equal(attestation.signoff_status, 'evidence_complete');
    assert.equal(attestation.blocker_summary.length, 0);
    assert.ok(
      attestation.caveats.some((line) => /production_ready=true means profile inventory complete/.test(line)),
    );
  });

  it('identifies sample and rehearsal release id patterns', () => {
    assert.equal(isSampleOrRehearsalReleaseId('rel-sample-rehearsal'), true);
    assert.equal(isSampleOrRehearsalReleaseId('rel_sample_prod'), true);
    assert.equal(isSampleOrRehearsalReleaseId('rel-sample-2026'), true);
    assert.equal(isSampleOrRehearsalReleaseId('rel_2026_rehearsal_gate'), true);
    assert.equal(isSampleOrRehearsalReleaseId('rel_attestation_complete'), false);
  });

  it('forces production_ready false for rehearsal inventory even when evidence is complete', () => {
    const records = acceptedRecords(
      completeEvidenceRecords(['third_party_security_review'].filter((k) => PRODUCTION_RELEASE_EVIDENCE_COMPLETE[k])),
    );
    if (records.length === 0) {
      records.push({
        kind: 'third_party_security_review',
        evidence: SECURITY_REVIEW,
        status: 'accepted',
      });
    }
    const attestation = aggregateStagingReadinessAttestation({
      releaseId: 'rel-sample-rehearsal',
      records,
    }, { requiredKinds: ['third_party_security_review'] });

    assert.equal(isRehearsalOrSampleEvidenceInput({ releaseId: 'rel-sample-rehearsal', records }), true);
    assert.equal(attestation.production_ready, false);
    assert.equal(attestation.signoff_status, 'rehearsal_only');
    assert.equal(attestation.rehearsal_only, true);
    assert.ok(attestation.blocker_summary.some((line) => /Rehearsal\/sample evidence/.test(line)));
    assert.ok(
      attestation.caveats.some((line) => /local walkthrough only/.test(line)),
    );
  });

  it('rejects forbidden metadata in evidence and input', () => {
    assert.throws(
      () => aggregateStagingReadinessAttestation({
        records: [{
          kind: 'third_party_security_review',
          evidence: { ...SECURITY_REVIEW, token: 'svc_v1.fake.fake.fake' },
        }],
      }, { requiredKinds: ['third_party_security_review'] }),
      /forbidden metadata/,
    );

    const assessment = assessEvidenceRecord({
      kind: 'third_party_security_review',
      evidence: { ...SECURITY_REVIEW, sql_dump: 'dump' },
    });
    assert.equal(assessment.accepted, false);
    assert.ok(assessment.validation.forbidden_fields.includes('sql_dump'));
  });

  it('does not treat staging or container gates as optional documented kinds', () => {
    assert.equal(STAGING_READINESS_OPTIONAL_EVIDENCE_KINDS.length, 0);
    const attestation = aggregateStagingReadinessAttestation({
      records: [{ kind: 'third_party_security_review', evidence: SECURITY_REVIEW, status: 'accepted' }],
    }, { requiredKinds: ['third_party_security_review', 'staging_e2e_matrix'] });

    assert.equal(attestation.production_ready, false);
    assert.deepEqual(attestation.required_evidence_kinds.missing, ['staging_e2e_matrix']);
    assert.equal(attestation.optional_evidence_kinds.present.length, 0);
  });

  it('flags unknown kinds as blockers', () => {
    const attestation = aggregateStagingReadinessAttestation({
      records: [
        { kind: 'third_party_security_review', evidence: SECURITY_REVIEW, status: 'accepted' },
        { kind: 'not_a_real_kind', evidence: { evidence_uri: 'evidence://x' }, status: 'accepted' },
      ],
    }, { requiredKinds: ['third_party_security_review'] });

    assert.equal(attestation.production_ready, false);
    assert.ok(attestation.blocker_summary.some((line) => /Unknown evidence kind/.test(line)));
  });

  it('validate-only exits non-zero when not production ready', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'input.json');
    writeJson(input, {
      records: [{ kind: 'third_party_security_review', evidence: SECURITY_REVIEW }],
    });
    const code = await main(['--input', input, '--validate-only', '--release-id', 'rel_gate']);
    assert.equal(code, 1);
  });

  it('writes attestation output without echoing secrets from input extras', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'input.json');
    const out = path.join(dir, 'attestation.json');
    writeJson(input, {
      release_id: 'rel_write',
      records: [{ kind: 'third_party_security_review', evidence: SECURITY_REVIEW, status: 'accepted' }],
    });
    const code = await main([
      '--input',
      input,
      '--out',
      out,
      '--release-id',
      'rel_write',
    ]);
    assert.equal(code, 1);
    assert.equal(existsSync(out), true);
    const attestation = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(attestation.artifact_type, 'staging_readiness_attestation');
    assert.equal(attestation.profile, DEFAULT_STAGING_READINESS_PROFILE);
    assert.equal(attestation.production_ready, false);
    const blob = JSON.stringify(attestation);
    assert.equal(blob.includes('postgres://secret'), false);
    assert.ok(attestation.required_evidence_kinds.missing.length > 0);
  });

  it('covers full required kind list from production release evidence contract by default', () => {
    const attestation = aggregateStagingReadinessAttestation({ records: [] });
    assert.equal(attestation.profile, DEFAULT_STAGING_READINESS_PROFILE);
    assert.equal(
      attestation.required_evidence_kinds.required.length,
      PRODUCTION_RELEASE_EVIDENCE_KINDS.length,
    );
    assert.equal(attestation.required_evidence_kinds.profile, 'full');
  });

  it('safe-validation-ga does not require high-scale-only governed adapter or provider approval evidence', () => {
    const required = resolveReleaseProfileKinds('safe-validation-ga');
    assert.equal(required.includes('governed_adapter'), false);
    assert.equal(required.includes('provider_approval'), false);
    assert.equal(required.includes('kill_switch_drill'), false);
    assert.equal(required.includes('authorization_custody'), false);

    const attestation = aggregateStagingReadinessAttestation({
      records: safeValidationGaBaselineRecords(),
    }, { profile: 'safe-validation-ga' });

    assert.equal(attestation.profile, 'safe-validation-ga');
    assert.equal(attestation.production_ready, true);
    assert.equal(attestation.required_evidence_kinds.missing.length, 0);
  });

  it('high-scale-ga requires high-scale custody and SOC provider evidence kinds', () => {
    const required = resolveReleaseProfileKinds('high-scale-ga');
    for (const kind of [
      'governed_adapter',
      'provider_approval',
      'kill_switch_drill',
      'authorization_custody',
      'placement_confidence_staging',
      'gateway_load_abuse',
    ]) {
      assert.ok(required.includes(kind), `expected ${kind} in high-scale-ga profile`);
    }

    const records = safeValidationGaBaselineRecords();
    const attestation = aggregateStagingReadinessAttestation({ records }, { profile: 'high-scale-ga' });
    assert.equal(attestation.production_ready, false);
    assert.ok(attestation.required_evidence_kinds.missing.includes('governed_adapter'));
    assert.ok(attestation.required_evidence_kinds.missing.includes('provider_approval'));
    assert.ok(attestation.required_evidence_kinds.missing.includes('authorization_custody'));
  });

  it('staging_e2e_matrix and control_plane_container_release block safe-validation-ga when missing', () => {
    const records = safeValidationGaBaselineRecords().filter(
      (record) => !['staging_e2e_matrix', 'control_plane_container_release'].includes(record.kind),
    );
    const attestation = aggregateStagingReadinessAttestation({ records }, { profile: 'safe-validation-ga' });
    assert.equal(attestation.production_ready, false);
    assert.ok(attestation.required_evidence_kinds.missing.includes('staging_e2e_matrix'));
    assert.ok(attestation.required_evidence_kinds.missing.includes('control_plane_container_release'));
  });

  it('rejects unknown release profiles', () => {
    assert.throws(
      () => resolveReleaseProfileKinds('release-99'),
      /Unknown release profile/,
    );
    assert.throws(
      () => aggregateStagingReadinessAttestation({ records: [] }, { profile: 'release-99' }),
      /Unknown release profile/,
    );
  });

  it('complete fixture can pass full profile once contract expansion is present', () => {
    const fullKinds = STAGING_READINESS_RELEASE_PROFILES.full;
    const records = acceptedRecords(
      completeEvidenceRecords(fullKinds.filter((kind) => PRODUCTION_RELEASE_EVIDENCE_COMPLETE[kind])),
    );
    const attestation = aggregateStagingReadinessAttestation({ records }, { profile: 'full' });
    const missingWithoutFixture = attestation.required_evidence_kinds.missing.filter(
      (kind) => !PRODUCTION_RELEASE_EVIDENCE_COMPLETE[kind],
    );
    assert.equal(
      missingWithoutFixture.length,
      0,
      `missing fixture samples for: ${missingWithoutFixture.join(', ')}`,
    );
    assert.equal(attestation.production_ready, true);
  });
});