import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import {
  PROBE_FLEET_MATRIX_CONTROLS,
  PROBE_FLEET_MATRIX_REGIONS,
  PROBE_FLEET_REQUIRED_PROBE_PROFILES,
  createProbeFleetMatrixSummary,
  main,
  parseArgs,
  validateMatrixEvidence,
} from '../../scripts/probe-fleet-matrix-evidence.mjs';

const tempDirs = [];

function tempDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-probe-fleet-'));
  tempDirs.push(dir);
  return dir;
}

function writeJson(file, value) {
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function controlPassed(extra = {}) {
  return {
    status: 'passed',
    observed_at: '2026-07-02T00:00:00.000Z',
    ...extra,
  };
}

function defaultControls(overrides = {}) {
  return {
    signed_job_route: controlPassed({
      route_paths: [
        '/internal/probe/jobs',
        '/internal/probe/jobs/pjob_staging_1/result',
      ],
    }),
    job_signature_verified: controlPassed(),
    tenant_header_signing: controlPassed(),
    worker_hmac_auth: controlPassed(),
    health_status: controlPassed({ health: 'healthy' }),
    rate_budget: controlPassed({ max_jobs_per_minute: 30, max_requests_per_job: 1 }),
    egress_controls: controlPassed({ default_deny: true, allowed_destination_count: 2 }),
    abuse_monitoring: controlPassed({ alerts_enabled: true }),
    ...overrides,
  };
}

function buildRow(region, overrides = {}) {
  const { controls: controlOverrides, ...rest } = overrides;
  return {
    region,
    environment: 'staging',
    worker_id_redacted: `pw_${region}_…01`,
    probe_profiles_exercised: [...PROBE_FLEET_REQUIRED_PROBE_PROFILES],
    controls: defaultControls(controlOverrides),
    ...rest,
  };
}

function completeMatrixRows() {
  return PROBE_FLEET_MATRIX_REGIONS.map((region) => buildRow(region));
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop(), { recursive: true, force: true });
  }
});

describe('probe fleet matrix evidence utility', () => {
  it('parses defaults and explicit CLI arguments', () => {
    assert.deepEqual(parseArgs(['--input', 'matrix.json']), {
      input: 'matrix.json',
      out: 'output/probe-fleet-matrix-evidence.json',
      fleetId: null,
      validateOnly: false,
      help: false,
    });
    assert.deepEqual(parseArgs([
      '--input',
      'matrix.json',
      '--out',
      'summary.json',
      '--fleet-id',
      'fleet_staging_2026_07',
      '--validate-only',
    ]), {
      input: 'matrix.json',
      out: 'summary.json',
      fleetId: 'fleet_staging_2026_07',
      validateOnly: true,
      help: false,
    });
    assert.throws(() => parseArgs([]), /--input is required/);
  });

  it('accepts a complete matrix across all required regions and profiles', () => {
    const summary = createProbeFleetMatrixSummary({
      fleetId: 'fleet_complete',
      rows: completeMatrixRows(),
    });
    assert.equal(summary.overall_status, 'passed');
    assert.equal(summary.rows.length, PROBE_FLEET_MATRIX_REGIONS.length);
    assert.deepEqual(summary.coverage_gaps.missing_regions, []);
    assert.deepEqual(summary.coverage_gaps.missing_probe_profiles, []);
    assert.deepEqual(summary.coverage_gaps.missing_signature_coverage, []);
    for (const region of PROBE_FLEET_MATRIX_REGIONS) {
      const row = summary.rows.find((r) => r.region === region);
      assert.ok(row, `missing summary row for ${region}`);
      assert.equal(row.status, 'passed');
      for (const control of PROBE_FLEET_MATRIX_CONTROLS) {
        assert.equal(row.controls[control], 'passed');
      }
    }
  });

  it('reports missing region and probe profile coverage gaps', () => {
    const missingRegionRows = completeMatrixRows().filter((r) => r.region !== 'ap-southeast');
    const regionGap = createProbeFleetMatrixSummary({ rows: missingRegionRows });
    assert.equal(regionGap.overall_status, 'incomplete');
    assert.deepEqual(regionGap.coverage_gaps.missing_regions, ['ap-southeast']);

    const profileGap = createProbeFleetMatrixSummary({
      rows: [
        buildRow('us-east', {
          probe_profiles_exercised: ['http_head', 'tcp_connect'],
        }),
      ],
    });
    assert.equal(profileGap.overall_status, 'incomplete');
    assert.equal(profileGap.coverage_gaps.missing_probe_profiles.includes('dns_resolve'), true);
    assert.equal(profileGap.coverage_gaps.missing_probe_profiles.includes('metadata_marker'), true);
  });

  it('reports missing signature coverage when signing controls are not passed', () => {
    const summary = createProbeFleetMatrixSummary({
      rows: [
        buildRow('us-east', {
          controls: {
            tenant_header_signing: { status: 'not_run' },
            worker_hmac_auth: { status: 'failed', observed_at: '2026-07-02T01:00:00.000Z' },
          },
        }),
      ],
    });
    assert.equal(summary.overall_status, 'failed');
    assert.equal(summary.coverage_gaps.missing_signature_coverage.length, 1);
    assert.equal(summary.coverage_gaps.missing_signature_coverage[0].region, 'us-east');
    assert.equal(
      summary.coverage_gaps.missing_signature_coverage[0].missing_controls.includes('tenant_header_signing'),
      true,
    );
    assert.equal(
      summary.coverage_gaps.missing_signature_coverage[0].missing_controls.includes('worker_hmac_auth'),
      true,
    );
  });

  it('rejects forbidden secret, raw, and inventory fields', () => {
    assert.throws(
      () => validateMatrixEvidence({
        rows: [
          buildRow('us-east', {
            probe_worker_secret: 'x'.repeat(40),
          }),
        ],
      }),
      /forbidden field\(s\): probe_worker_secret/,
    );
    assert.throws(
      () => validateMatrixEvidence({
        rows: [
          buildRow('eu-west', {
            attachment: { raw_response: 'must not persist' },
          }),
        ],
      }),
      /forbidden field\(s\): attachment.raw_response/,
    );
    assert.throws(
      () => validateMatrixEvidence({
        rows: [
          buildRow('ap-southeast', {
            notes: '203.0.113.1, 203.0.113.2, 203.0.113.3',
          }),
        ],
      }),
      /target_ip_inventory_pattern/,
    );
    assert.throws(
      () => validateMatrixEvidence({
        fleet_id: 'fleet_bad',
        rows: completeMatrixRows(),
        customer_payload: { target: 'secret' },
      }),
      /Forbidden envelope field\(s\): customer_payload/,
    );
  });

  it('validate-only does not write output', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'input.json');
    const out = path.join(dir, 'summary.json');
    writeJson(input, { fleet_id: 'fleet_validate', rows: completeMatrixRows() });
    const code = await main(['--input', input, '--out', out, '--validate-only']);
    assert.equal(code, 0);
    assert.equal(existsSync(out), false);
  });

  it('writes generated output and omits secret extras from input envelope', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'input.json');
    const out = path.join(dir, 'summary.json');
    writeJson(input, {
      fleet_id: 'fleet_write',
      rows: completeMatrixRows(),
      worker_hmac_secret: 'x'.repeat(40),
      token: 'ast_v1.fake.fake.fake',
    });
    const code = await main(['--input', input, '--out', out, '--fleet-id', 'fleet_write']);
    assert.equal(code, 0);
    const summary = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(summary.fleet_id, 'fleet_write');
    assert.equal(summary.overall_status, 'passed');
    const blob = JSON.stringify(summary);
    assert.equal(blob.includes('worker_hmac_secret'), false);
    assert.equal(blob.includes('ast_v1.fake.fake.fake'), false);
    assert.equal(blob.includes('token'), false);
  });

  it('redacts token-like strings in allowed metadata fields', () => {
    const summary = createProbeFleetMatrixSummary({
      rows: [
        buildRow('us-east', {
          worker_id_redacted: 'pw svc_v1.fake.fake.fake note',
        }),
      ],
    });
    const blob = JSON.stringify(summary);
    assert.equal(blob.includes('svc_v1.fake.fake.fake'), false);
    assert.match(blob, /\[REDACTED\]/);
  });
});