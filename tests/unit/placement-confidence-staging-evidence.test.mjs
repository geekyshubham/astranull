import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import {
  PLACEMENT_CONFIDENCE_STAGING_REQUIRED_SCENARIOS,
  assertValidPlacementConfidenceStagingEvidence,
  buildPlacementConfidenceStagingReleaseEvidence,
  createPlacementConfidenceStagingEvidenceManifest,
  main,
  parseArgs,
  validatePlacementConfidenceStagingEvidence,
  validatePlacementConfidenceStagingReleaseContract,
} from '../../scripts/placement-confidence-staging-evidence.mjs';

const tempDirs = [];

function tempDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-placement-confidence-staging-'));
  tempDirs.push(dir);
  return dir;
}

function writeJson(file, value) {
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function scenario(scenarioId, overrides = {}) {
  const defaults = {
    strong_agent_observation: {
      status: 'passed',
      confidence_label: 'High',
      target_group_reference: 'tg://staging/edge-primary',
      run_reference: 'run://staging/strong-agent-01',
      verdict_reference: 'verdict://staging/strong-agent-01',
    },
    misplaced_agent_detection: {
      status: 'passed',
      confidence_label: 'Invalid',
      target_group_reference: 'tg://staging/misplaced-edge',
      run_reference: 'run://staging/misplaced-agent-01',
      verdict_reference: 'verdict://staging/misplaced-agent-01',
    },
    external_only_inconclusive: {
      status: 'passed',
      confidence_label: 'Low',
      target_group_reference: 'tg://staging/external-only',
      run_reference: 'run://staging/external-only-01',
      verdict_reference: 'verdict://staging/external-only-01',
    },
    canary_path_observation: {
      status: 'passed',
      confidence_label: 'High',
      target_group_reference: 'tg://staging/canary-path',
      run_reference: 'run://staging/canary-path-01',
      verdict_reference: 'verdict://staging/canary-path-01',
    },
  }[scenarioId];

  return {
    scenario_id: scenarioId,
    evidence_uri: `evidence://placement/${scenarioId}`,
    owner: 'detection-lead',
    completed_at: '2026-07-02T12:00:00.000Z',
    ...defaults,
    ...overrides,
  };
}

function validEvidence(overrides = {}) {
  return {
    release_id: 'rel_placement_confidence_20260702',
    environment: 'staging',
    created_at: '2026-07-02T12:00:00.000Z',
    evidence_uri: 'evidence://detection/placement-confidence-staging',
    signoff: {
      owner: 'detection-lead',
      signed_at: '2026-07-02T12:30:00.000Z',
      signoff_reference: 'signoff://detection/placement-confidence',
    },
    evidence_correlation_summary: {
      probe_evidence_count: 12,
      agent_evidence_count: 9,
      correlated_pairs: 7,
      gaps: [],
    },
    scenarios: PLACEMENT_CONFIDENCE_STAGING_REQUIRED_SCENARIOS.map((scenarioId) => scenario(scenarioId)),
    ...overrides,
  };
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop(), { recursive: true, force: true });
  }
});

describe('placement confidence staging evidence validator', () => {
  it('parses CLI arguments', () => {
    assert.deepEqual(parseArgs(['--input', 'evidence.json']), {
      input: 'evidence.json',
      out: 'output/placement-confidence-staging-evidence.json',
      releaseId: null,
      validateOnly: false,
      help: false,
    });
    assert.deepEqual(
      parseArgs([
        '--input',
        'evidence.json',
        '--out',
        'out.json',
        '--release-id',
        'rel_2026_07',
        '--validate-only',
      ]),
      {
        input: 'evidence.json',
        out: 'out.json',
        releaseId: 'rel_2026_07',
        validateOnly: true,
        help: false,
      },
    );
    assert.throws(() => parseArgs([]), /--input is required/);
  });

  it('accepts valid metadata-only staging scenarios', () => {
    const validation = validatePlacementConfidenceStagingEvidence(validEvidence());
    assert.equal(validation.ok, true);
    assert.deepEqual(validation.missing_fields, []);
    assert.deepEqual(validation.forbidden_fields, []);
    assert.deepEqual(validation.missing_scenarios, []);
    assert.deepEqual(validation.failed_scenarios, []);
    assert.doesNotThrow(() => assertValidPlacementConfidenceStagingEvidence(validEvidence()));
  });

  it('reports missing required scenario coverage', () => {
    const evidence = validEvidence({
      scenarios: PLACEMENT_CONFIDENCE_STAGING_REQUIRED_SCENARIOS.filter(
        (id) => id !== 'canary_path_observation',
      ).map((scenarioId) => scenario(scenarioId)),
    });
    const validation = validatePlacementConfidenceStagingEvidence(evidence);
    assert.equal(validation.ok, false);
    assert.deepEqual(validation.missing_scenarios, ['missing_scenario:canary_path_observation']);
    assert.throws(
      () => assertValidPlacementConfidenceStagingEvidence(evidence),
      /Missing required scenario\(s\): missing_scenario:canary_path_observation/,
    );
  });

  it('rejects failed or invalid scenario status', () => {
    const failed = validEvidence({
      scenarios: PLACEMENT_CONFIDENCE_STAGING_REQUIRED_SCENARIOS.map((scenarioId) =>
        scenario(scenarioId, scenarioId === 'misplaced_agent_detection' ? { status: 'failed' } : {}),
      ),
    });
    const failedValidation = validatePlacementConfidenceStagingEvidence(failed);
    assert.equal(failedValidation.ok, false);
    assert.deepEqual(failedValidation.failed_scenarios, ['failed_scenario:misplaced_agent_detection']);

    const invalidStatus = validEvidence({
      scenarios: PLACEMENT_CONFIDENCE_STAGING_REQUIRED_SCENARIOS.map((scenarioId) =>
        scenario(scenarioId, scenarioId === 'external_only_inconclusive' ? { status: 'bogus' } : {}),
      ),
    });
    const invalidValidation = validatePlacementConfidenceStagingEvidence(invalidStatus);
    assert.equal(invalidValidation.ok, false);
    assert.ok(
      invalidValidation.invalid_fields.some((entry) => entry.field === 'scenarios[2].status'),
    );
    assert.throws(
      () => assertValidPlacementConfidenceStagingEvidence(failed),
      /Failed or invalid scenario\(s\): failed_scenario:misplaced_agent_detection/,
    );
  });

  it('rejects forbidden nested raw fields and sensitive metadata', () => {
    const evidence = validEvidence({
      scenarios: [
        {
          ...scenario('strong_agent_observation'),
          metadata: { raw_packet: 'must-not-persist' },
        },
        ...PLACEMENT_CONFIDENCE_STAGING_REQUIRED_SCENARIOS.filter(
          (id) => id !== 'strong_agent_observation',
        ).map((scenarioId) => scenario(scenarioId)),
      ],
      notes: '203.0.113.1, 203.0.113.2, 203.0.113.3',
      attachment: { screenshot_data: 'base64' },
      token: 'ast_v1.fake.fake.fake',
    });
    const validation = validatePlacementConfidenceStagingEvidence(evidence);
    assert.equal(validation.ok, false);
    assert.ok(validation.forbidden_fields.includes('scenarios[0].metadata.raw_packet'));
    assert.ok(validation.forbidden_fields.includes('attachment'));
    assert.ok(validation.forbidden_fields.includes('token'));
    assert.ok(validation.forbidden_fields.some((field) => field.includes('target_ip_inventory_pattern')));
    assert.throws(
      () => assertValidPlacementConfidenceStagingEvidence(evidence),
      /Forbidden field\(s\):/,
    );
  });

  it('builds production release evidence that passes contract validation', () => {
    const evidence = validEvidence();
    const releaseEvidence = buildPlacementConfidenceStagingReleaseEvidence(evidence, {
      releaseId: evidence.release_id,
      createdAt: evidence.created_at,
    });
    const contract = validatePlacementConfidenceStagingReleaseContract(releaseEvidence);
    assert.deepEqual(contract, {
      ok: true,
      invalid_kind: null,
      missing_fields: [],
      forbidden_fields: [],
      invalid_fields: [],
    });

    const manifest = createPlacementConfidenceStagingEvidenceManifest({
      evidence,
      releaseId: evidence.release_id,
      createdAt: evidence.created_at,
    });
    assert.equal(manifest.production_release_evidence.kind, 'placement_confidence_staging');
    assert.equal(manifest.validation.contract.ok, true);
    assert.equal(manifest.validation.ok, true);
    assert.equal(manifest.scenarios.length, PLACEMENT_CONFIDENCE_STAGING_REQUIRED_SCENARIOS.length);
  });

  it('validate-only does not write output', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'input.json');
    const out = path.join(dir, 'manifest.json');
    writeJson(input, validEvidence());
    const code = await main(['--input', input, '--out', out, '--validate-only']);
    assert.equal(code, 0);
    assert.equal(existsSync(out), false);
  });

  it('writes manifest with production release evidence payload', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'input.json');
    const out = path.join(dir, 'manifest.json');
    writeJson(input, validEvidence());
    const code = await main(['--input', input, '--out', out, '--release-id', 'rel_placement_confidence_20260702']);
    assert.equal(code, 0);
    const manifest = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(manifest.validation.ok, true);
    assert.equal(manifest.production_release_evidence.kind, 'placement_confidence_staging');
    assert.equal(
      manifest.production_release_evidence.evidence.release_id,
      'rel_placement_confidence_20260702',
    );
    assert.equal(
      manifest.production_release_evidence.evidence.scenarios.length,
      PLACEMENT_CONFIDENCE_STAGING_REQUIRED_SCENARIOS.length,
    );
  });
});