import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import {
  KILL_SWITCH_REQUIRED_STEPS,
} from '../../src/contracts/killSwitchValidation.mjs';
import {
  computeResponseLatencyMs,
  createKillSwitchDrillEvidenceManifest,
  main,
  parseArgs,
  validateAndPrepareDrillTranscript,
  validateDrillTranscript,
} from '../../scripts/kill-switch-drill-evidence.mjs';

const tempDirs = [];

function tempDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-kill-switch-drill-'));
  tempDirs.push(dir);
  return dir;
}

function writeJson(file, value) {
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function completeExercise() {
  return {
    exercise_id: 'ks_2026_07_02',
    steps: KILL_SWITCH_REQUIRED_STEPS.map((step) => ({
      step_id: step.step_id,
      evidence_uri: `evidence://kill-switch/${step.step_id}`,
      validated_at: '2026-07-02T10:00:30.000Z',
      operator: 'soc-shift-lead',
      tenant_id: 'ten_demo',
      blocked_run_reference: 'run_blocked_after_ks',
      cancelled_run_ids: ['run_active_1'],
      worker_pool_reference: 'probe-fleet/staging/pool-a',
      adapter_stop_reference: 'adapter-stop/staging/request-1',
      audit_event_ids: ['audit_step_1', 'audit_step_2'],
      resume_decision_reference: 'change://resume-after-review',
    })),
  };
}

function validDrillTranscript(overrides = {}) {
  return {
    drill_id: 'ks_drill_2026_07_02',
    tenant_id: 'ten_demo',
    activation_at: '2026-07-02T10:00:00.000Z',
    stop_signal_at: '2026-07-02T10:00:45.000Z',
    affected_request_ids: ['hs_req_1'],
    cancelled_safe_run_ids: ['run_active_1'],
    soc_actors: [
      { actor_id: 'soc_analyst_1', role: 'soc_analyst' },
      { actor_id: 'soc_lead_1', role: 'soc_lead' },
    ],
    audit_event_ids: ['audit_ks_1', 'audit_ks_2', 'audit_ks_3'],
    closeout: {
      signoff_by: 'soc_lead_1',
      signoff_role: 'soc_lead',
      signed_at: '2026-07-02T11:00:00.000Z',
      signoff_reference: 'evidence://kill-switch-drill/signoff',
    },
    exercise: completeExercise(),
    ...overrides,
  };
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop(), { recursive: true, force: true });
  }
});

describe('kill switch drill evidence utility', () => {
  it('parses defaults and explicit CLI arguments', () => {
    assert.deepEqual(parseArgs(['--input', 'drill.json']), {
      input: 'drill.json',
      out: 'output/kill-switch-drill-evidence.json',
      maxLatencyMs: 120_000,
      validateOnly: false,
      help: false,
    });
    assert.deepEqual(parseArgs([
      '--input',
      'drill.json',
      '--out',
      'manifest.json',
      '--max-latency-ms',
      '60000',
      '--validate-only',
    ]), {
      input: 'drill.json',
      out: 'manifest.json',
      maxLatencyMs: 60_000,
      validateOnly: true,
      help: false,
    });
    assert.throws(() => parseArgs([]), /--input is required/);
    assert.throws(() => parseArgs(['--max-latency-ms', '0']), /positive number/);
  });

  it('accepts a valid metadata-only drill transcript and writes manifest', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'input.json');
    const out = path.join(dir, 'manifest.json');
    writeJson(input, validDrillTranscript());
    const code = await main(['--input', input, '--out', out]);
    assert.equal(code, 0);
    const manifest = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(manifest.artifact_type, 'kill_switch_drill_evidence');
    assert.equal(manifest.drill_id, 'ks_drill_2026_07_02');
    assert.equal(manifest.response_latency_ms, 45_000);
    assert.equal(manifest.latency_ok, true);
    assert.equal(manifest.validation.ok, true);
    assert.equal(manifest.validation.audit_event_count, 3);
  });

  it('computes response latency and fails when max latency is exceeded', () => {
    const transcript = validDrillTranscript({
      stop_signal_at: '2026-07-02T10:03:00.000Z',
    });
    assert.equal(computeResponseLatencyMs(transcript), 180_000);
    const validation = validateDrillTranscript(transcript, { maxLatencyMs: 120_000 });
    assert.equal(validation.ok, false);
    assert.equal(validation.latency_exceeded, true);
    assert.throws(
      () => validateAndPrepareDrillTranscript(transcript, { maxLatencyMs: 120_000 }),
      /exceeds max 120000ms/,
    );
  });

  it('rejects missing audit ids and closeout signoff fields', () => {
    const missingAudit = validDrillTranscript({ audit_event_ids: [] });
    let result = validateDrillTranscript(missingAudit);
    assert.equal(result.ok, false);
    assert.ok(result.missing_fields.includes('audit_event_ids'));

    const missingSignoff = validDrillTranscript({
      closeout: {
        signoff_by: 'soc_lead_1',
        signoff_role: 'soc_lead',
        signed_at: '2026-07-02T11:00:00.000Z',
      },
    });
    result = validateDrillTranscript(missingSignoff);
    assert.equal(result.ok, false);
    assert.ok(result.missing_fields.includes('closeout.signoff_reference'));

    assert.throws(
      () => validateAndPrepareDrillTranscript(missingSignoff),
      /missing required field\(s\): closeout.signoff_reference/,
    );
  });

  it('rejects forbidden raw traffic, captures, secrets, and provider credentials', () => {
    const withRaw = validDrillTranscript({
      metadata: { raw_traffic: 'pcap-bytes' },
      provider_credentials: { api_key: 'unsafe' },
    });
    const result = validateDrillTranscript(withRaw);
    assert.equal(result.ok, false);
    assert.ok(result.forbidden_fields.includes('metadata.raw_traffic'));
    assert.ok(result.forbidden_fields.includes('provider_credentials'));
    assert.ok(result.forbidden_fields.includes('provider_credentials.api_key'));

    assert.throws(
      () => validateAndPrepareDrillTranscript(withRaw),
      /forbidden field\(s\):/,
    );
  });

  it('redacts token-looking strings in manifest output', () => {
    const manifest = createKillSwitchDrillEvidenceManifest({
      createdAt: '2026-07-02T12:00:00.000Z',
      transcript: validDrillTranscript({
        notes: 'reviewed ast_v1.fake.fake.fake during drill',
        closeout: {
          ...validDrillTranscript().closeout,
          signoff_reference: 'evidence://signoff svc_v1.fake.fake.fake',
        },
      }),
    });
    const blob = JSON.stringify(manifest);
    assert.equal(blob.includes('ast_v1.fake.fake.fake'), false);
    assert.equal(blob.includes('svc_v1.fake.fake.fake'), false);
    assert.match(blob, /\[REDACTED\]/);
    assert.equal(manifest.notes, 'reviewed [REDACTED] during drill');
  });

  it('validate-only does not write output', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'input.json');
    const out = path.join(dir, 'manifest.json');
    writeJson(input, validDrillTranscript());
    const code = await main(['--input', input, '--out', out, '--validate-only']);
    assert.equal(code, 0);
    assert.equal(existsSync(out), false);
  });
});