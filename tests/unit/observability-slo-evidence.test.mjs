import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import {
  assertValidObservabilitySloReleaseEvidence,
  createObservabilitySloEvidenceManifest,
  main,
  parseArgs,
  validateObservabilitySloReleaseEvidence,
} from '../../scripts/observability-slo-evidence.mjs';

const tempDirs = [];

function tempDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-obs-slo-'));
  tempDirs.push(dir);
  return dir;
}

function writeJson(file, value) {
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function validEvidence(overrides = {}) {
  return {
    release_id: 'rel_obs_2026_07_02',
    environment: 'staging',
    incident_drill_id: 'obs_incident_drill_2026_07_02',
    metric_scrape_auth: {
      auth_mechanism: 'mTLS via internal scrape gateway',
      gateway_reference: 'scrape-gateway/staging/astranull',
      evidence_uri: 'evidence://observability/scrape-auth/staging',
      validated_at: '2026-07-02T08:00:00.000Z',
    },
    dashboard_ids: [
      'dash_platform_availability',
      'dash_agent_heartbeat_lag',
      'dash_probe_worker_queue',
    ],
    alert_routes: [
      {
        route_id: 'route_api_5xx',
        alert_name: 'API error rate high',
        destination_reference: 'pagerduty://astranull-platform-oncall',
      },
      {
        route_id: 'route_kill_switch',
        alert_name: 'Kill switch not accepted',
        destination_reference: 'pagerduty://astranull-soc-oncall',
      },
    ],
    slo_targets: [
      {
        slo_id: 'agent_heartbeat_ingestion',
        target: '99% under 60 seconds',
        measurement_window: '30d',
      },
      {
        slo_id: 'kill_switch_acceptance',
        target: '99.9% under 5 seconds',
        measurement_window: '30d',
      },
    ],
    on_call: {
      owner: 'platform-oncall',
      rotation_reference: 'oncall://platform/rotation-2026-q3',
      evidence_uri: 'evidence://oncall/rotation-2026-q3',
    },
    redaction_policy: {
      policy_reference: 'policy://logging/redaction-v3',
      summary: 'Strip authorization, cookies, bodies, tokens, and database URLs from logs and traces.',
    },
    ...overrides,
  };
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop(), { recursive: true, force: true });
  }
});

describe('observability SLO release evidence utility', () => {
  it('parses defaults and explicit CLI arguments', () => {
    assert.deepEqual(parseArgs(['--input', 'evidence.json']), {
      input: 'evidence.json',
      out: 'output/observability-slo-evidence.json',
      validateOnly: false,
      help: false,
    });
    assert.deepEqual(parseArgs(['--input', 'evidence.json', '--out', 'manifest.json', '--validate-only']), {
      input: 'evidence.json',
      out: 'manifest.json',
      validateOnly: true,
      help: false,
    });
    assert.throws(() => parseArgs([]), /--input is required/);
  });

  it('accepts valid metadata-only evidence and writes manifest', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'input.json');
    const out = path.join(dir, 'manifest.json');
    writeJson(input, validEvidence());
    const code = await main(['--input', input, '--out', out]);
    assert.equal(code, 0);
    const manifest = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(manifest.artifact_type, 'observability_slo_release_evidence');
    assert.equal(manifest.validation.ok, true);
    assert.equal(manifest.environment, 'staging');
    assert.equal(manifest.incident_drill_id, 'obs_incident_drill_2026_07_02');
    assert.equal(manifest.alert_routes.length, 2);
    assert.equal(manifest.slo_targets.length, 2);
    assert.equal(manifest.dashboard_ids.length, 3);
  });

  it('fails when alert routes or SLO targets are missing', async () => {
    const missingAlerts = validateObservabilitySloReleaseEvidence(validEvidence({ alert_routes: [] }));
    assert.equal(missingAlerts.ok, false);
    assert.ok(missingAlerts.missing_controls.includes('alert_routes'));
    assert.ok(missingAlerts.missing_critical_controls.includes('alert_routes'));

    const missingSlos = validateObservabilitySloReleaseEvidence(validEvidence({ slo_targets: [] }));
    assert.equal(missingSlos.ok, false);
    assert.ok(missingSlos.missing_controls.includes('slo_targets'));
    assert.ok(missingSlos.missing_critical_controls.includes('slo_targets'));

    assert.throws(
      () => assertValidObservabilitySloReleaseEvidence(validEvidence({ alert_routes: [] })),
      /Missing critical observability control\(s\): alert_routes/,
    );

    const dir = tempDir();
    const input = path.join(dir, 'input.json');
    const out = path.join(dir, 'manifest.json');
    writeJson(input, validEvidence({ slo_targets: [] }));
    const code = await main(['--input', input, '--out', out]);
    assert.equal(code, 1);
    const manifest = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(manifest.validation.ok, false);
    assert.ok(manifest.validation.missing_critical_controls.includes('slo_targets'));
  });

  it('rejects forbidden raw logs, trace payloads, secrets, headers, tokens, and database URLs', () => {
    const withForbidden = validEvidence({
      debug: { raw_log: '2026-07-02 error line' },
      traces: [{ trace_payload: { body: 'span data' } }],
      scrape_notes: 'uses postgres://user:pass@db.internal:5432/astranull',
    });
    const result = validateObservabilitySloReleaseEvidence(withForbidden);
    assert.equal(result.ok, false);
    assert.ok(result.forbidden_fields.includes('debug.raw_log'));
    assert.ok(result.forbidden_fields.some((field) => field.includes('trace_payload')));
    assert.ok(result.forbidden_fields.some((field) => field.includes('database_url_pattern')));

    assert.throws(
      () => assertValidObservabilitySloReleaseEvidence(withForbidden),
      /Forbidden field\(s\):/,
    );
  });

  it('redacts token-looking strings in manifest output', () => {
    const manifest = createObservabilitySloEvidenceManifest({
      createdAt: '2026-07-02T12:00:00.000Z',
      evidence: validEvidence({
        notes: 'validated with ast_v1.fake.fake.fake during staging drill',
        on_call: {
          ...validEvidence().on_call,
          evidence_uri: 'evidence://oncall svc_v1.fake.fake.fake',
        },
      }),
    });
    const blob = JSON.stringify(manifest);
    assert.equal(blob.includes('ast_v1.fake.fake.fake'), false);
    assert.equal(blob.includes('svc_v1.fake.fake.fake'), false);
    assert.match(blob, /\[REDACTED\]/);
    assert.equal(manifest.notes, 'validated with [REDACTED] during staging drill');
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
});