import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import { validateProductionReleaseEvidence } from '../../src/contracts/productionReleaseEvidence.mjs';
import {
  REQUIRED_SCENARIOS,
  createStagingE2eMatrixArtifact,
  main,
  parseArgs,
  validateStagingE2eMatrixEvidence,
} from '../../scripts/staging-e2e-matrix-evidence.mjs';

const tempDirs = [];

function tempDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-staging-e2e-matrix-'));
  tempDirs.push(dir);
  return dir;
}

function writeJson(file, value) {
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function passedScenario(scenarioId, overrides = {}) {
  return {
    scenario_id: scenarioId,
    status: 'passed',
    evidence_uri: `evidence://staging-e2e/${scenarioId}`,
    owner: 'qa-oncall',
    completed_at: '2026-07-02T12:00:00.000Z',
    ...overrides,
  };
}

function validMatrixEvidence(overrides = {}) {
  return {
    release_id: 'rel_staging_e2e_2026_07_02',
    environment: 'staging',
    evidence_uri: 'evidence://release/staging-e2e-matrix',
    signoff: {
      owner: 'qa-lead',
      signed_at: '2026-07-02T13:00:00.000Z',
      signoff_reference: 'signoff://qa/staging-e2e-matrix',
    },
    scenarios: REQUIRED_SCENARIOS.map((scenarioId) => passedScenario(scenarioId)),
    ...overrides,
  };
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop(), { recursive: true, force: true });
  }
});

describe('staging e2e matrix evidence validator', () => {
  it('parses CLI arguments', () => {
    assert.deepEqual(parseArgs(['--input', 'evidence.json']), {
      input: 'evidence.json',
      out: 'output/staging-e2e-matrix-evidence.json',
      releaseId: null,
      validateOnly: false,
      help: false,
    });
    assert.deepEqual(
      parseArgs(['--input', 'evidence.json', '--out', 'out.json', '--release-id', 'rel_x', '--validate-only']),
      {
        input: 'evidence.json',
        out: 'out.json',
        releaseId: 'rel_x',
        validateOnly: true,
        help: false,
      },
    );
    assert.throws(() => parseArgs([]), /--input is required/);
  });

  it('accepts a valid passed staging E2E matrix', () => {
    const evidence = validMatrixEvidence();
    const validation = validateStagingE2eMatrixEvidence(evidence);
    assert.equal(validation.ok, true);
    assert.equal(validation.overall_status, 'passed');
    assert.deepEqual(validation.missing_scenarios, []);
    assert.deepEqual(validation.failed_scenarios, []);
    assert.deepEqual(validation.forbidden_fields, []);
    assert.deepEqual(validation.validation_gaps, []);

    const artifact = createStagingE2eMatrixArtifact({ evidence, validation });
    assert.equal(artifact.production_release_evidence.kind, 'staging_e2e_matrix');
    assert.equal(artifact.validation.ok, true);
    assert.equal(artifact.overall_status, 'passed');
    assert.equal(artifact.scenarios.length, REQUIRED_SCENARIOS.length);

    const contract = validateProductionReleaseEvidence(
      'staging_e2e_matrix',
      artifact.production_release_evidence.evidence,
    );
    assert.equal(contract.ok, true);
  });

  it('reports missing required scenario coverage', () => {
    const evidence = validMatrixEvidence({
      scenarios: REQUIRED_SCENARIOS
        .filter((id) => id !== 'oidc_login' && id !== 'report_export_custody')
        .map((scenarioId) => passedScenario(scenarioId)),
    });
    const validation = validateStagingE2eMatrixEvidence(evidence);
    assert.equal(validation.ok, false);
    assert.equal(validation.overall_status, 'incomplete');
    assert.deepEqual(validation.missing_scenarios, ['oidc_login', 'report_export_custody']);
    assert.ok(validation.validation_gaps.includes('missing_scenario:oidc_login'));
    assert.ok(validation.validation_gaps.includes('missing_scenario:report_export_custody'));
  });

  it('records validation gaps when a required scenario failed', () => {
    const evidence = validMatrixEvidence({
      scenarios: REQUIRED_SCENARIOS.map((scenarioId) => (
        scenarioId === 'safe_validation_loop'
          ? passedScenario(scenarioId, { status: 'failed' })
          : passedScenario(scenarioId)
      )),
    });
    const validation = validateStagingE2eMatrixEvidence(evidence);
    assert.equal(validation.ok, false);
    assert.equal(validation.overall_status, 'failed');
    assert.deepEqual(validation.failed_scenarios, ['safe_validation_loop']);
    assert.ok(validation.validation_gaps.includes('failed_scenario:safe_validation_loop'));
  });

  it('allows local-staging matrices to record external scenarios as not_run without fabricating a pass', async () => {
    const evidence = validMatrixEvidence({
      environment: 'local-staging',
      scenarios: REQUIRED_SCENARIOS.map((scenarioId) => (
        ['safe_validation_loop', 'verdict_explanation', 'report_export_custody'].includes(scenarioId)
          ? passedScenario(scenarioId, { evidence_uri: `evidence://local-staging/smoke/${scenarioId}` })
          : passedScenario(scenarioId, { status: 'not_run' })
      )),
    });
    const validation = validateStagingE2eMatrixEvidence(evidence);
    assert.equal(validation.ok, false);
    assert.equal(validation.overall_status, 'incomplete');
    assert.deepEqual(validation.failed_scenarios, []);
    assert.ok(validation.validation_gaps.includes('oidc_login.status'));
    assert.ok(validation.validation_gaps.includes('signed_probe_worker.status'));

    const dir = tempDir();
    const input = path.join(dir, 'input.json');
    const out = path.join(dir, 'artifact.json');
    writeJson(input, evidence);
    const code = await main(['--input', input, '--out', out]);
    assert.equal(code, 0);
    const artifact = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(artifact.validation.ok, false);
    assert.equal(artifact.overall_status, 'incomplete');
  });

  it('rejects missing top-level fields and signoff metadata', () => {
    const evidence = validMatrixEvidence({
      release_id: '',
      environment: '',
      evidence_uri: '',
      signoff: { owner: 'qa-lead' },
    });
    const validation = validateStagingE2eMatrixEvidence(evidence);
    assert.equal(validation.ok, false);
    assert.ok(validation.missing_fields.includes('release_id'));
    assert.ok(validation.missing_fields.includes('environment'));
    assert.ok(validation.missing_fields.includes('evidence_uri'));
    assert.ok(validation.missing_fields.includes('signoff.signed_at'));
    assert.ok(validation.missing_fields.includes('signoff.signoff_reference'));
  });

  it('rejects forbidden nested browser and secret fields', () => {
    const evidence = validMatrixEvidence({
      scenarios: [
        {
          ...passedScenario('oidc_login'),
          screenshot: 'base64-image',
          request: { method: 'GET', body: 'secret' },
        },
        ...REQUIRED_SCENARIOS.filter((id) => id !== 'oidc_login').map((id) => passedScenario(id)),
      ],
      token: 'ast_v1.fake.fake.fake',
    });
    const validation = validateStagingE2eMatrixEvidence(evidence);
    assert.equal(validation.ok, false);
    assert.ok(validation.forbidden_fields.includes('token'));
    assert.ok(validation.forbidden_fields.includes('scenarios[0].screenshot'));
    assert.ok(validation.forbidden_fields.some((field) => field.includes('request')));
  });

  it('validate-only does not write output', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'input.json');
    const out = path.join(dir, 'artifact.json');
    writeJson(input, validMatrixEvidence());
    const code = await main(['--input', input, '--out', out, '--validate-only']);
    assert.equal(code, 0);
    assert.equal(existsSync(out), false);
  });

  it('writes a metadata-only artifact with production release evidence wrapper', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'input.json');
    const out = path.join(dir, 'artifact.json');
    writeJson(input, validMatrixEvidence());
    const code = await main(['--input', input, '--out', out, '--release-id', 'rel_cli']);
    assert.equal(code, 0);
    const artifact = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(artifact.production_release_evidence.kind, 'staging_e2e_matrix');
    assert.equal(artifact.release_id, 'rel_staging_e2e_2026_07_02');
    const blob = JSON.stringify(artifact);
    assert.equal(blob.includes('base64-image'), false);
    assert.equal(blob.includes('ast_v1.fake'), false);

    const contract = validateProductionReleaseEvidence(
      'staging_e2e_matrix',
      artifact.production_release_evidence.evidence,
    );
    assert.equal(contract.ok, true);
  });
});
