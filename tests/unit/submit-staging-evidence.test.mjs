import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import { recordProductionReleaseEvidence } from '../../src/services/productionReleaseEvidence.mjs';
import { freshStore } from '../helpers/reset.mjs';
import {
  buildSubmissionBodies,
  isLocalStagingSimulatorEnvironment,
  isOperatorAttestedEnvironment,
  isPromotionEligibleEnvironment,
  isSimulatedEnvironment,
  main,
  operatorAttestedEnvironmentRejection,
  parseArgs,
  submitStagingEvidence,
  validateOperatorAttestedRecords,
  validateRecordPromotionEnvironment,
} from '../../scripts/submit-staging-evidence.mjs';
import {
  completeEvidenceRecords,
  PRODUCTION_RELEASE_EVIDENCE_COMPLETE,
} from '../fixtures/productionReleaseEvidenceComplete.mjs';

const tempDirs = [];

function tempDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-submit-staging-evidence-'));
  tempDirs.push(dir);
  return dir;
}

function writeJson(file, value) {
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function operatorAttestedRecord(kind, overrides = {}) {
  const base = completeEvidenceRecords([kind])[0];
  return {
    ...base,
    status: 'accepted',
    release_id: 'rel-staging-2026-07-03',
    ...overrides,
  };
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop(), { recursive: true, force: true });
  }
});

describe('submit staging evidence utility', () => {
  it('parses CLI defaults and required base-url guard', () => {
    assert.deepEqual(parseArgs(['--input', 'records.json', '--validate-only']), {
      input: 'records.json',
      out: 'output/staging-evidence-submission-summary.json',
      baseUrl: null,
      releaseId: null,
      profile: 'full',
      tenantId: 'ten_demo',
      userId: 'usr_release_operator',
      role: 'admin',
      authToken: null,
      validateOnly: true,
      dryRun: false,
      allowRehearsal: false,
      allowLocalStaging: false,
      continueOnError: false,
      help: false,
    });
    assert.throws(
      () => parseArgs(['--input', 'records.json']),
      /--base-url is required/,
    );
  });

  it('classifies operator-attested and simulated environments', () => {
    assert.equal(isSimulatedEnvironment('staging-sim'), true);
    assert.equal(isSimulatedEnvironment('STAGING-SIM'), true);
    assert.equal(isOperatorAttestedEnvironment('staging'), true);
    assert.equal(isOperatorAttestedEnvironment('production'), true);
    assert.equal(isLocalStagingSimulatorEnvironment('local-staging'), true);
    assert.equal(isPromotionEligibleEnvironment('local-staging', { allowLocalStaging: true }), true);
    assert.equal(isOperatorAttestedEnvironment('staging-sim'), false);
  });

  it('accepts operator-attested staging records for promotion profile', () => {
    const records = completeEvidenceRecords(['migration_apply', 'operator_runbook_exercise']);
    const validated = validateOperatorAttestedRecords({
      release_id: 'rel-staging-2026-07-03',
      environment: 'staging',
      records,
    });
    assert.equal(validated.records.length, 2);
    assert.equal(validated.environment, 'staging');
    assert.equal(validated.records[0].validation.ok, true);
  });

  it('rejects top-level staging-sim environment', () => {
    const records = completeEvidenceRecords(['migration_apply']);
    assert.throws(
      () => validateOperatorAttestedRecords({
        release_id: 'rel-staging-2026-07-03',
        environment: 'staging-sim',
        records,
      }),
      /simulated environment "staging-sim"/,
    );
  });

  it('rejects per-record staging-sim evidence environments', () => {
    const record = operatorAttestedRecord('migration_apply', {
      evidence: {
        ...PRODUCTION_RELEASE_EVIDENCE_COMPLETE.migration_apply,
        environment: 'staging-sim',
      },
    });
    assert.throws(
      () => validateRecordPromotionEnvironment(record),
      /simulated environment "staging-sim"/,
    );
    assert.throws(
      () => validateOperatorAttestedRecords({
        release_id: 'rel-staging-2026-07-03',
        records: [record],
      }),
      /simulated environment "staging-sim"/,
    );
  });

  it('requires staging or production for kinds with environment fields', () => {
    const record = operatorAttestedRecord('staging_e2e_matrix', {
      evidence: {
        ...PRODUCTION_RELEASE_EVIDENCE_COMPLETE.staging_e2e_matrix,
        environment: 'developer-validation',
      },
    });
    assert.throws(
      () => validateRecordPromotionEnvironment(record),
      /environment must be one of staging, production/,
    );
  });

  it('rejects rehearsal markers by default', () => {
    const records = completeEvidenceRecords(['third_party_security_review']);
    assert.throws(
      () => validateOperatorAttestedRecords({
        release_id: 'rel-sample-rehearsal',
        records,
      }),
      /Rehearsal\/sample evidence cannot be submitted/,
    );
    assert.throws(
      () => validateOperatorAttestedRecords({
        release_id: 'rel-staging-2026-07-03',
        records: records.map((record) => ({ ...record, rehearsal_only: true })),
      }),
      /Rehearsal\/sample evidence cannot be submitted/,
    );
  });

  it('allows rehearsal markers only with --allow-rehearsal', () => {
    const records = completeEvidenceRecords(['third_party_security_review']).map((record) => ({
      ...record,
      rehearsal_only: true,
      release_id: 'rel-sample-rehearsal',
    }));
    const validated = validateOperatorAttestedRecords({
      release_id: 'rel-sample-rehearsal',
      rehearsal_only: true,
      records,
    }, { allowRehearsal: true });
    assert.equal(validated.records.length, 1);
  });

  it('builds API submission bodies with release ids', () => {
    const bodies = buildSubmissionBodies({
      release_id: 'rel-staging-2026-07-03',
      environment: 'staging',
      records: completeEvidenceRecords(['migration_apply']),
    });
    assert.equal(bodies.length, 1);
    assert.equal(bodies[0].kind, 'migration_apply');
    assert.equal(bodies[0].release_id, 'rel-staging-2026-07-03');
    assert.equal(bodies[0].evidence.environment, 'staging');
  });

  it('validate-only CLI path accepts operator-attested input', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'records.json');
    writeJson(input, {
      schema_version: 1,
      artifact_type: 'production_release_evidence_records',
      release_id: 'rel-staging-2026-07-03',
      environment: 'staging',
      records: completeEvidenceRecords(['migration_apply', 'operator_runbook_exercise']),
    });
    const code = await main(['--input', input, '--validate-only']);
    assert.equal(code, 0);
  });

  it('dry-run writes a submission summary without posting', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'records.json');
    const out = path.join(dir, 'summary.json');
    writeJson(input, {
      release_id: 'rel-staging-2026-07-03',
      environment: 'staging',
      records: completeEvidenceRecords(['migration_apply']),
    });
    const summary = await submitStagingEvidence({
      input,
      dryRun: true,
      out,
    });
    assert.equal(summary.dry_run, true);
    assert.equal(summary.submitted, false);
    assert.equal(summary.results.length, 0);
    assert.equal(existsSync(out), true);
    const written = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(written.record_count, 1);
  });

  it('submits validated records to POST /v1/production-release-evidence', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'records.json');
    writeJson(input, {
      release_id: 'rel-staging-2026-07-03',
      environment: 'staging',
      records: completeEvidenceRecords(['migration_apply', 'operator_runbook_exercise']),
    });

    const posted = [];
    const summary = await submitStagingEvidence({
      input,
      baseUrl: 'https://control-plane.example',
      fetchFn: async (url, init) => {
        posted.push({ url, body: JSON.parse(init.body) });
        return {
          status: 201,
          text: async () => JSON.stringify({
            evidence: {
              id: `evidence_${posted.length}`,
              kind: JSON.parse(init.body).kind,
              status: 'accepted',
            },
          }),
        };
      },
    });

    assert.equal(summary.submitted, true);
    assert.equal(summary.results.length, 2);
    assert.equal(posted.length, 2);
    assert.match(posted[0].url, /\/v1\/production-release-evidence$/);
    assert.equal(posted[0].body.evidence.environment, 'staging');
    assert.equal(posted[1].body.kind, 'operator_runbook_exercise');
  });

  it('operatorAttestedEnvironmentRejection mirrors API promotion environment policy', () => {
    assert.deepEqual(
      operatorAttestedEnvironmentRejection({
        kind: 'migration_apply',
        evidence: { environment: 'staging-sim' },
      }),
      {
        error: 'simulated_environment_rejected',
        status: 400,
        environment: 'staging-sim',
      },
    );
    assert.deepEqual(
      operatorAttestedEnvironmentRejection({
        kind: 'migration_apply',
        evidence: { environment: 'qa-lab' },
      }),
      {
        error: 'invalid_promotion_environment',
        status: 400,
        environment: 'qa-lab',
        allowed: ['staging', 'production'],
      },
    );
    assert.deepEqual(
      operatorAttestedEnvironmentRejection({
        kind: 'migration_apply',
        evidence: { environment: 'local-staging' },
      }),
      {
        error: 'local_staging_evidence_rejected',
        status: 400,
        environment: 'local-staging',
        allowed: ['staging', 'production'],
      },
    );
    assert.equal(
      operatorAttestedEnvironmentRejection({
        kind: 'third_party_security_review',
        evidence: PRODUCTION_RELEASE_EVIDENCE_COMPLETE.third_party_security_review,
      }),
      null,
    );
  });

  it('rejects dry-run records during submission validation', () => {
    const records = completeEvidenceRecords(['migration_apply']).map((record) => ({
      ...record,
      dry_run: true,
      submittable: false,
      status: 'draft',
    }));
    assert.throws(
      () => validateOperatorAttestedRecords({
        release_id: 'rel-staging-2026-07-03',
        dry_run: true,
        submittable: false,
        records,
      }),
      /Dry-run or non-submittable evidence cannot be submitted/,
    );
  });

  it('recordProductionReleaseEvidence rejects staging-sim environments at the service boundary', () => {
    freshStore();
    const rejected = recordProductionReleaseEvidence(
      { tenantId: 'ten_demo', userId: 'usr_operator', role: 'admin' },
      {
        kind: 'migration_apply',
        release_id: 'rel-staging-2026-07-03',
        evidence: {
          ...PRODUCTION_RELEASE_EVIDENCE_COMPLETE.migration_apply,
          environment: 'staging-sim',
        },
      },
    );
    assert.equal(rejected.error, 'simulated_environment_rejected');
    assert.equal(rejected.status, 400);
  });

  it('recordProductionReleaseEvidence rejects local-staging environments at the service boundary', () => {
    freshStore();
    const rejected = recordProductionReleaseEvidence(
      { tenantId: 'ten_demo', userId: 'usr_operator', role: 'admin' },
      {
        kind: 'migration_apply',
        release_id: 'rel-staging-2026-07-03',
        evidence: {
          ...PRODUCTION_RELEASE_EVIDENCE_COMPLETE.migration_apply,
          environment: 'local-staging',
        },
      },
    );
    assert.equal(rejected.error, 'local_staging_evidence_rejected');
    assert.equal(rejected.status, 400);
  });
});