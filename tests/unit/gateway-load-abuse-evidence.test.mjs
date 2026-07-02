import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import { validateProductionReleaseEvidence } from '../../src/contracts/productionReleaseEvidence.mjs';
import {
  GATEWAY_LOAD_ABUSE_ABUSE_CONTROL_IDS,
  GATEWAY_LOAD_ABUSE_RATE_LIMIT_CONTROL_IDS,
  assertValidGatewayLoadAbuseCaptureEvidence,
  buildGatewayLoadAbuseProductionReleaseEvidence,
  createGatewayLoadAbuseEvidenceArtifact,
  main,
  mergeCaptureOptions,
  parseArgs,
  validateGatewayLoadAbuseCaptureEvidence,
} from '../../scripts/gateway-load-abuse-evidence.mjs';

const tempDirs = [];

function tempDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-gateway-load-abuse-'));
  tempDirs.push(dir);
  return dir;
}

function writeJson(file, value) {
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function rateLimitEntry(controlId, overrides = {}) {
  return {
    control_id: controlId,
    status: 'passed',
    threshold_metadata: 'metadata-only-bounded-staging-exercise',
    evidence_uri: `evidence://edge/rate-limit/${controlId}`,
    ...overrides,
  };
}

function abuseEntry(controlId, overrides = {}) {
  return {
    control_id: controlId,
    status: 'passed',
    alert_fired: true,
    evidence_uri: `evidence://edge/abuse/${controlId}`,
    ...overrides,
  };
}

function completeCapture(overrides = {}) {
  return {
    release_id: 'rel_2026_07_02',
    environment: 'staging',
    gateway_summary:
      'API and UI traffic terminate at managed gateway with per-route rate policies on /v1 and static UI paths.',
    waf_edge_summary:
      'Managed WAF rule groups in challenge/block mode; edge alerts route to SIEM with redacted fields.',
    rate_limit_results: GATEWAY_LOAD_ABUSE_RATE_LIMIT_CONTROL_IDS.map((controlId) =>
      rateLimitEntry(controlId),
    ),
    abuse_detection_results: GATEWAY_LOAD_ABUSE_ABUSE_CONTROL_IDS.map((controlId) =>
      abuseEntry(controlId),
    ),
    edge_alerting_summary: {
      siem_route_reference: 'siem://edge-alerts/staging',
      alert_count: 2,
      false_positive_rate_metadata: 'within-threshold',
    },
    signoff: {
      owner: 'security-lead',
      signed_at: '2026-07-02T12:00:00.000Z',
      signoff_reference: 'signoff://security/gateway-load-abuse',
    },
    evidence_uri: 'evidence://edge/gateway-load-abuse',
    ...overrides,
  };
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop(), { recursive: true, force: true });
  }
});

describe('gateway load abuse evidence CLI', () => {
  it('parses defaults and explicit CLI arguments', () => {
    assert.deepEqual(parseArgs(['--input', 'evidence.json']), {
      input: 'evidence.json',
      out: 'output/gateway-load-abuse-evidence.json',
      releaseId: null,
      validateOnly: false,
      help: false,
    });
    assert.deepEqual(parseArgs([
      '--input',
      'evidence.json',
      '--out',
      'summary.json',
      '--release-id',
      'rel_cli',
      '--validate-only',
    ]), {
      input: 'evidence.json',
      out: 'summary.json',
      releaseId: 'rel_cli',
      validateOnly: true,
      help: false,
    });
    assert.throws(() => parseArgs([]), /--input is required/);
  });

  it('merges --release-id over file evidence', () => {
    const merged = mergeCaptureOptions(
      { releaseId: 'rel_from_flag' },
      { release_id: 'rel_from_file', environment: 'staging' },
    );
    assert.equal(merged.release_id, 'rel_from_flag');
    assert.equal(merged.environment, 'staging');
  });

  it('accepts complete metadata-only capture evidence', () => {
    const evidence = completeCapture();
    const validation = validateGatewayLoadAbuseCaptureEvidence(evidence);
    assert.equal(validation.ok, true);
    assert.deepEqual(validation.missing_controls, []);
    assert.deepEqual(validation.failed_controls, []);

    const artifact = createGatewayLoadAbuseEvidenceArtifact({
      createdAt: '2026-07-02T00:00:00.000Z',
      evidence,
    });
    assert.equal(artifact.artifact_type, 'gateway_load_abuse_release_evidence');
    assert.equal(artifact.validation.ok, true);
    assert.equal(artifact.production_release_evidence.kind, 'gateway_load_abuse');
  });

  it('reports missing gateway, WAF, and signoff fields', () => {
    const evidence = completeCapture();
    delete evidence.gateway_summary;
    delete evidence.waf_edge_summary;
    delete evidence.signoff.signed_at;

    const validation = validateGatewayLoadAbuseCaptureEvidence(evidence);
    assert.equal(validation.ok, false);
    assert.ok(validation.missing_fields.includes('gateway_summary'));
    assert.ok(validation.missing_fields.includes('waf_edge_summary'));
    assert.ok(validation.missing_fields.includes('signoff.signed_at'));
    assert.throws(
      () => assertValidGatewayLoadAbuseCaptureEvidence(evidence),
      /Missing field\(s\):.*gateway_summary/,
    );
  });

  it('rejects failed control results', () => {
    const evidence = completeCapture({
      rate_limit_results: GATEWAY_LOAD_ABUSE_RATE_LIMIT_CONTROL_IDS.map((controlId, index) =>
        rateLimitEntry(controlId, index === 0 ? { status: 'failed' } : {}),
      ),
    });
    const validation = validateGatewayLoadAbuseCaptureEvidence(evidence);
    assert.equal(validation.ok, false);
    assert.deepEqual(validation.failed_controls, ['api-global-rate-limit']);
    assert.throws(
      () => assertValidGatewayLoadAbuseCaptureEvidence(evidence),
      /Failed control result\(s\): api-global-rate-limit/,
    );
  });

  it('rejects composed traffic-generator metadata keys at runtime', () => {
    const trafficGenKey = ['traffic', 'generator'].join('_');
    const evidence = completeCapture({
      edge_alerting_summary: {
        siem_route_reference: 'siem://edge-alerts/staging',
        alert_count: 2,
        false_positive_rate_metadata: 'within-threshold',
        [trafficGenKey]: { enabled: true },
      },
    });
    const validation = validateGatewayLoadAbuseCaptureEvidence(evidence);
    assert.equal(validation.ok, false);
    assert.ok(
      validation.forbidden_fields.includes(`edge_alerting_summary.${trafficGenKey}`),
    );
  });

  it('rejects forbidden nested fields and attack recipes', () => {
    const evidence = completeCapture({
      rate_limit_results: [
        rateLimitEntry('api-global-rate-limit'),
        rateLimitEntry('ui-global-rate-limit', {
          metadata: { attack_recipe: 'curl flood script' },
        }),
      ],
      debug: { raw_headers: { authorization: 'Bearer secret' } },
    });
    const validation = validateGatewayLoadAbuseCaptureEvidence(evidence);
    assert.equal(validation.ok, false);
    assert.ok(validation.forbidden_fields.includes('rate_limit_results[1].metadata.attack_recipe'));
    assert.ok(validation.forbidden_fields.includes('debug.raw_headers'));
    assert.throws(
      () => assertValidGatewayLoadAbuseCaptureEvidence(evidence),
      /Forbidden field\(s\):/,
    );
  });

  it('builds production release evidence that satisfies gateway_load_abuse contract', () => {
    const evidence = completeCapture();
    const validation = validateGatewayLoadAbuseCaptureEvidence(evidence);
    const release = buildGatewayLoadAbuseProductionReleaseEvidence({
      createdAt: '2026-07-02T00:00:00.000Z',
      evidence,
      validation,
    });
    assert.equal(release.kind, 'gateway_load_abuse');
    assert.equal(release.contract_validation.ok, true);
    assert.deepEqual(validateProductionReleaseEvidence('gateway_load_abuse', release.evidence), {
      ok: true,
      invalid_kind: null,
      missing_fields: [],
      forbidden_fields: [],
      invalid_fields: [],
    });
    assert.equal(release.evidence.rate_limit_results.length, 2);
    assert.equal(release.evidence.abuse_detection_results.length, 2);
    assert.equal(release.evidence.signoff.owner, 'security-lead');
  });

  it('validate-only does not write output', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'input.json');
    const out = path.join(dir, 'summary.json');
    writeJson(input, completeCapture());
    const code = await main(['--input', input, '--out', out, '--validate-only']);
    assert.equal(code, 0);
    assert.equal(existsSync(out), false);
  });

  it('writes redacted artifact output from JSON input', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'input.json');
    const out = path.join(dir, 'summary.json');
    writeJson(input, completeCapture({
      gateway_summary: 'reviewed svc_v1.fake.fake.fake at gateway edge',
    }));
    const code = await main(['--input', input, '--out', out]);
    assert.equal(code, 0);
    const artifact = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(artifact.validation.ok, true);
    assert.match(artifact.gateway_summary, /\[REDACTED\]/);
    const blob = JSON.stringify(artifact);
    assert.equal(blob.includes('svc_v1.fake.fake.fake'), false);

    assert.equal(blob.includes('raw_headers'), false);
    assert.equal(blob.includes('attack_recipe'), false);
  });
});