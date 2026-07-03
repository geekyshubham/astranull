import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';
import { REQUIRED_SCENARIOS, validateStagingE2eMatrixEvidence } from '../../scripts/staging-e2e-matrix-evidence.mjs';
import { runLocalStagingOidcLoginProof } from '../../scripts/lib/localStagingOidcHarness.mjs';
import { parseArgs } from '../../scripts/local-staging-e2e-matrix.mjs';

describe('local staging e2e matrix', () => {
  it('parses CLI arguments', () => {
    assert.deepEqual(parseArgs([]), {
      baseUrl: 'http://127.0.0.1:3000',
      out: 'output/release-evidence/local-staging-e2e-matrix-input.json',
      artifactOut: 'output/release-evidence/staging_e2e_matrix.json',
      help: false,
    });
  });

  it('runs local OIDC JWKS fixture proof', async () => {
    const result = await runLocalStagingOidcLoginProof();
    assert.ok(result.checks.includes('oidc_bearer_login'));
    assert.ok(result.checks.includes('header_only_negative'));
    assert.ok(result.checks.includes('mfa_enforcement'));
    assert.ok(result.evidence_uri.startsWith('evidence://'));
  });
});

describe('local staging e2e matrix evidence shape', () => {
  it('requires all scenarios passed for local-staging contract', () => {
    const evidence = {
      release_id: 'rel-local-staging-2026-07-03',
      environment: 'local-staging',
      evidence_uri: 'evidence://release/staging-e2e-matrix-local-staging',
      signoff: {
        owner: 'internal-soc-qa',
        signed_at: '2026-07-03T00:00:00.000Z',
        signoff_reference: 'signoff://internal-soc/local-staging-e2e-matrix',
      },
      scenarios: REQUIRED_SCENARIOS.map((scenarioId) => ({
        scenario_id: scenarioId,
        status: 'passed',
        evidence_uri: `evidence://local-staging/e2e/${scenarioId}`,
        owner: 'internal-soc-qa',
        completed_at: '2026-07-03T00:00:00.000Z',
      })),
    };
    const validation = validateStagingE2eMatrixEvidence(evidence);
    assert.equal(validation.ok, true);
    assert.equal(validation.overall_status, 'passed');
  });

  it('rejects not_run scenarios for local-staging', () => {
    const evidence = {
      release_id: 'rel-local-staging-2026-07-03',
      environment: 'local-staging',
      evidence_uri: 'evidence://release/staging-e2e-matrix-local-staging',
      signoff: {
        owner: 'internal-soc-qa',
        signed_at: '2026-07-03T00:00:00.000Z',
        signoff_reference: 'signoff://internal-soc/local-staging-e2e-matrix',
      },
      scenarios: REQUIRED_SCENARIOS.map((scenarioId) => ({
        scenario_id: scenarioId,
        status: scenarioId === 'oidc_login' ? 'not_run' : 'passed',
        evidence_uri: `evidence://local-staging/e2e/${scenarioId}`,
        owner: 'internal-soc-qa',
        completed_at: '2026-07-03T00:00:00.000Z',
      })),
    };
    const validation = validateStagingE2eMatrixEvidence(evidence);
    assert.equal(validation.ok, false);
    assert.equal(validation.overall_status, 'incomplete');
    assert.ok(validation.validation_gaps.includes('oidc_login.status'));
  });
});