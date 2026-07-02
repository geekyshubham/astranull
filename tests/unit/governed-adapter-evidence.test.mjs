import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import {
  GOVERNED_ADAPTER_EVIDENCE_REQUIRED_FIELDS,
  createGovernedAdapterEvidenceManifest,
  main,
  parseArgs,
  validateGovernedAdapterReadinessEvidence,
} from '../../scripts/governed-adapter-evidence.mjs';

const tempDirs = [];

function tempDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-governed-adapter-evidence-'));
  tempDirs.push(dir);
  return dir;
}

function writeJson(file, value) {
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function completeEvidence() {
  return {
    adapter_id: 'adapter_partner_lab_1',
    adapter_type: 'partner_adapter',
    authorization_pack_id: 'pack_hs_2026_07_02',
    scheduled_window: {
      start_at: '2026-07-02T10:00:00.000Z',
      end_at: '2026-07-02T12:00:00.000Z',
    },
    soc_approvers: ['soc-lead-1', 'soc-lead-2'],
    provider_approval_reference: 'provider://partner-lab/approval/ref-1',
    kill_switch_hook: 'kill-switch://tenant/ten_demo/adapter-stop-path',
    telemetry_metadata: {
      feed: 'metadata_summary',
      provider_run_id: 'run_meta_1',
      recorded_at: '2026-07-02T11:00:00.000Z',
    },
    dry_run_status: {
      mode: 'dry_run',
      traffic_generated: false,
      validated_at: '2026-07-02T10:05:00.000Z',
    },
    stop_close_evidence: {
      stop_reference: 'evidence://adapter/stop/ref-1',
      close_reference: 'evidence://adapter/close/ref-1',
      stopped_at: '2026-07-02T11:30:00.000Z',
      closed_at: '2026-07-02T11:35:00.000Z',
    },
  };
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop(), { recursive: true, force: true });
  }
});

describe('governed adapter readiness evidence', () => {
  it('lists required metadata fields for adapter readiness', () => {
    assert.ok(GOVERNED_ADAPTER_EVIDENCE_REQUIRED_FIELDS.includes('authorization_pack_id'));
    assert.ok(GOVERNED_ADAPTER_EVIDENCE_REQUIRED_FIELDS.includes('provider_approval_reference'));
    assert.ok(GOVERNED_ADAPTER_EVIDENCE_REQUIRED_FIELDS.includes('kill_switch_hook'));
  });

  it('accepts valid dry-run adapter evidence', () => {
    assert.deepEqual(validateGovernedAdapterReadinessEvidence(completeEvidence()), {
      ok: true,
      missing_fields: [],
      invalid_fields: [],
      forbidden_fields: [],
    });
  });

  it('reports missing SOC and provider approval gates', () => {
    const evidence = completeEvidence();
    delete evidence.soc_approvers;
    delete evidence.provider_approval_reference;

    const result = validateGovernedAdapterReadinessEvidence(evidence);
    assert.equal(result.ok, false);
    assert.deepEqual(result.missing_fields.sort(), [
      'provider_approval_reference',
      'soc_approvers',
    ]);
  });

  it('rejects forbidden attack-command, payload, inventory, and credential fields', () => {
    const evidence = completeEvidence();
    evidence.raw_command = 'curl attack-target';
    evidence.telemetry_metadata = {
      ...evidence.telemetry_metadata,
      packet_payload: 'unsafe',
      target_ips: ['203.0.113.10'],
    };
    evidence.connection = { api_key: 'secret-key' };

    const result = validateGovernedAdapterReadinessEvidence(evidence);
    assert.equal(result.ok, false);
    assert.deepEqual(result.forbidden_fields.sort(), [
      'connection.api_key',
      'raw_command',
      'telemetry_metadata.packet_payload',
      'telemetry_metadata.target_ips',
    ]);
  });

  it('rejects unapproved high-scale execution state', () => {
    const evidence = completeEvidence();
    evidence.high_scale_execution_state = 'live_traffic';
    evidence.dry_run_status = {
      ...evidence.dry_run_status,
      traffic_generated: true,
    };

    const result = validateGovernedAdapterReadinessEvidence(evidence);
    assert.equal(result.ok, false);
    assert.equal(
      result.invalid_fields.some((field) => field.field === 'high_scale_execution_state'),
      true,
    );
    assert.equal(
      result.invalid_fields.some((field) => field.field === 'dry_run_status.traffic_generated'),
      true,
    );
  });

  it('creates a redacted manifest without token-like strings', () => {
    const evidence = completeEvidence();
    evidence.telemetry_metadata.summary = 'validated svc_v1.fake.fake.fake in staging';

    const manifest = createGovernedAdapterEvidenceManifest({
      createdAt: '2026-07-02T12:00:00.000Z',
      evidence,
    });
    assert.equal(manifest.artifact_type, 'governed_adapter_readiness');
    assert.equal(manifest.dry_run_mode, true);
    assert.equal(manifest.adapter_id, 'adapter_partner_lab_1');
    const blob = JSON.stringify(manifest);
    assert.equal(blob.includes('svc_v1.fake.fake.fake'), false);
    assert.match(blob, /\[REDACTED\]/);
  });

  it('parses CLI arguments', () => {
    assert.deepEqual(parseArgs(['--input', 'evidence.json']), {
      input: 'evidence.json',
      out: 'output/governed-adapter-evidence.json',
      validateOnly: false,
      help: false,
    });
    assert.throws(() => parseArgs([]), /--input is required/);
  });

  it('validate-only does not write output', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'input.json');
    const out = path.join(dir, 'manifest.json');
    writeJson(input, completeEvidence());
    const code = await main(['--input', input, '--out', out, '--validate-only']);
    assert.equal(code, 0);
    assert.equal(existsSync(out), false);
  });

  it('writes redacted manifest output', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'input.json');
    const out = path.join(dir, 'manifest.json');
    const evidence = completeEvidence();
    evidence.notes = 'operator ast_v1.fake.fake.fake';
    writeJson(input, evidence);

    const code = await main(['--input', input, '--out', out]);
    assert.equal(code, 0);
    assert.equal(existsSync(out), true);

    const manifest = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(manifest.validation.ok, true);
    assert.equal(manifest.evidence.adapter_id, 'adapter_partner_lab_1');
    const blob = JSON.stringify(manifest);
    assert.equal(blob.includes('ast_v1.fake.fake.fake'), false);
  });
});