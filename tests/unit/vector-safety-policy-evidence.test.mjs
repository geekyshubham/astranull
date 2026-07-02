import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import { CHECK_CATALOG, isCustomerRunnable } from '../../src/contracts/checks.mjs';
import {
  CUSTOMER_RUNNABLE_POLICY_REQUIRED_FIELDS,
  createVectorSafetyPolicyManifest,
  extractCustomerRunnablePolicy,
  extractSocRequestMarkerPolicy,
  main,
  parseArgs,
  validateCatalogVectorSafetyPolicy,
  validateCheckVectorSafetyPolicy,
} from '../../scripts/vector-safety-policy-evidence.mjs';

const tempDirs = [];

function tempDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-vector-safety-policy-'));
  tempDirs.push(dir);
  return dir;
}

function minimalSafeCheck(overrides = {}) {
  return {
    check_id: 'test.vector.safe',
    version: '1.0.0',
    name: 'Test Safe Vector',
    vector_family: 'test',
    safety_class: 'safe',
    risk_class: 'safe',
    remediation_template: 'Remediate test vector.',
    explanation_template: 'Explain test vector.',
    evidence_required: ['probe_result'],
    stop_conditions: ['max_events_reached', 'customer_cancel'],
    safety_constraints: {
      max_events: 3,
      max_duration_seconds: 60,
      max_concurrent_runs_per_target_group: 1,
    },
    probe_profile: {
      kind: 'metadata_marker',
      max_requests: 1,
      timeout_ms: 5000,
      marker: 'test-marker',
    },
    ...overrides,
  };
}

function minimalSocMarker(overrides = {}) {
  return {
    check_id: 'high_scale.test.request_only',
    version: '1.0.0',
    name: 'Test SOC Marker',
    vector_family: 'high_scale',
    safety_class: 'soc_gated',
    risk_class: 'soc_gated',
    prerequisites: ['soc_approval_required'],
    evidence_required: ['approval_artifact', 'soc_runbook_ack'],
    stop_conditions: ['soc_kill_switch', 'max_approved_duration'],
    safety_constraints: { customer_runnable: false },
    default_expected_behavior: 'soc_approval_required',
    probe_simulation_profile: 'none',
    ...overrides,
  };
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop(), { recursive: true, force: true });
  }
});

describe('vector safety policy evidence', () => {
  it('lists required customer-runnable policy metadata fields', () => {
    assert.ok(CUSTOMER_RUNNABLE_POLICY_REQUIRED_FIELDS.includes('allowed_payload_type'));
    assert.ok(CUSTOMER_RUNNABLE_POLICY_REQUIRED_FIELDS.includes('probe_profile'));
    assert.ok(CUSTOMER_RUNNABLE_POLICY_REQUIRED_FIELDS.includes('failure_handling'));
  });

  it('passes validation for the current CHECK_CATALOG', () => {
    const result = validateCatalogVectorSafetyPolicy(CHECK_CATALOG);
    assert.equal(result.ok, true, formatGaps(result));
    assert.equal(result.gaps.length, 0);
    assert.equal(
      result.customer_runnable_count,
      CHECK_CATALOG.filter((c) => isCustomerRunnable(c)).length,
    );
    assert.equal(
      result.soc_request_only_count,
      CHECK_CATALOG.filter((c) => c.risk_class === 'soc_gated').length,
    );
  });

  it('reports synthetic missing-field failures for customer-runnable checks', () => {
    const check = minimalSafeCheck({ remediation_template: '', probe_profile: undefined });
    const result = validateCheckVectorSafetyPolicy(check);
    assert.equal(result.ok, false);
    assert.ok(result.missing_fields.includes('allowed_payload_type'));
    assert.ok(result.missing_fields.includes('probe_profile'));
    assert.ok(result.missing_fields.includes('failure_handling'));
  });

  it('enforces SOC-gated entries as non-customer-runnable request markers', () => {
    for (const check of CHECK_CATALOG.filter((c) => c.risk_class === 'soc_gated')) {
      const result = validateCheckVectorSafetyPolicy(check);
      assert.equal(result.ok, true, check.check_id);
      assert.equal(result.policy_class, 'soc_request_only');
      assert.equal(isCustomerRunnable(check), false);
      assert.equal(check.probe_profile, undefined);
    }

    const badSoc = minimalSocMarker({
      probe_profile: { kind: 'http_head', max_requests: 1, timeout_ms: 5000 },
      safety_constraints: { customer_runnable: true },
    });
    const badResult = validateCheckVectorSafetyPolicy(badSoc);
    assert.equal(badResult.ok, false);
    assert.ok(
      badResult.invalid_fields.some((f) => f.field === 'probe_profile'),
      'expected probe_profile invalidation',
    );
    assert.ok(
      badResult.invalid_fields.some((f) => f.field === 'safety_constraints.customer_runnable'),
    );
  });

  it('creates a metadata-only manifest with policy summaries and empty gaps', () => {
    const manifest = createVectorSafetyPolicyManifest({
      catalog: CHECK_CATALOG,
      createdAt: '2026-07-02T12:00:00.000Z',
    });
    assert.equal(manifest.artifact_type, 'vector_safety_policy_catalog');
    assert.equal(manifest.validation.ok, true);
    assert.deepEqual(manifest.validation.gaps, []);
    assert.equal(
      manifest.customer_runnable_policies.length,
      CHECK_CATALOG.filter((c) => isCustomerRunnable(c)).length,
    );
    assert.equal(
      manifest.soc_request_only_markers.length,
      CHECK_CATALOG.filter((c) => c.risk_class === 'soc_gated').length,
    );

    const sample = manifest.customer_runnable_policies.find(
      (p) => p.check_id === 'origin.direct_reachability.safe',
    );
    assert.ok(sample);
    assert.equal(sample.allowed_payload_type, 'http_head');
    assert.equal(sample.approval_level, 'customer_self_service');
    assert.ok(sample.failure_handling?.remediation_template);

    const blob = JSON.stringify(manifest);
    assert.equal(blob.includes('attack_script'), false);
    assert.equal(blob.includes('packet_payload'), false);
  });

  it('manifest includes gaps when synthetic catalog entries are incomplete', () => {
    const catalog = [...CHECK_CATALOG, minimalSafeCheck({ check_id: 'broken.vector.safe', remediation_template: '' })];
    const manifest = createVectorSafetyPolicyManifest({ catalog });
    assert.equal(manifest.validation.ok, false);
    assert.ok(manifest.validation.gaps.some((g) => g.check_id === 'broken.vector.safe'));
  });

  it('parses CLI arguments', () => {
    assert.deepEqual(parseArgs(['--validate-only']), {
      out: 'output/vector-safety-policy-evidence.json',
      validateOnly: true,
      help: false,
    });
  });

  it('validate-only succeeds for current catalog', async () => {
    const code = await main(['--validate-only']);
    assert.equal(code, 0);
  });

  it('writes manifest output on success', async () => {
    const dir = tempDir();
    const out = path.join(dir, 'manifest.json');
    const code = await main(['--out', out]);
    assert.equal(code, 0);
    assert.equal(existsSync(out), true);
    const manifest = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(manifest.validation.ok, true);
    assert.ok(manifest.customer_runnable_policies.length > 0);
  });
});

function formatGaps(result) {
  return result.gaps.map((g) => `${g.check_id}: ${g.missing_fields.join(',')}`).join('; ');
}