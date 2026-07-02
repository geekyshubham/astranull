import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  MAX_PROBE_PROFILE_REQUESTS,
  MAX_PROBE_PROFILE_TIMEOUT_MS,
  WAF_SAFE_CHECK_IDS,
  WAF_SAFE_PROBE_METADATA_KEYS,
  getCheckById,
  isCustomerRunnable,
} from '../../src/contracts/checks.mjs';
import { freshStore } from '../helpers/reset.mjs';
import { startTestRun } from '../../src/services/testRuns.mjs';

const FORBIDDEN_WAF_PROFILE_TERMS = [
  /raw_payload/i,
  /exploit/i,
  /attack_recipe/i,
  /payload_body/i,
  /traffic_generator/i,
];

function executableProbeProfileBlob(check) {
  const profile = check.probe_profile ?? {};
  const keys = ['kind', 'method', 'marker', 'max_requests', 'timeout_ms', ...WAF_SAFE_PROBE_METADATA_KEYS];
  const parts = [];
  for (const key of keys) {
    const value = profile[key];
    if (value === undefined) continue;
    parts.push(typeof value === 'string' ? value : JSON.stringify(value));
  }
  return parts.join('\n');
}

describe('safety catalog', () => {
  it('requires WAF-safe checks with explicit customer setup and metadata-only evidence classes', () => {
    const allowedEvidence = new Set(['probe_result', 'agent_observation', 'health_signal']);
    for (const checkId of WAF_SAFE_CHECK_IDS) {
      const check = getCheckById(checkId);
      assert.equal(isCustomerRunnable(check), true, checkId);
      assert.ok(check.required_customer_setup.includes('declared_waf_asset'), checkId);
      for (const ev of check.evidence_required) {
        assert.ok(allowedEvidence.has(ev), `${checkId}: ${ev}`);
      }
      assert.equal(check.probe_profile.nonce_hash_only, true, checkId);
    }
  });

  it('WAF probe profiles omit forbidden raw/exploit/payload terms in executable fields', () => {
    for (const checkId of WAF_SAFE_CHECK_IDS) {
      const check = getCheckById(checkId);
      const blob = executableProbeProfileBlob(check);
      for (const pattern of FORBIDDEN_WAF_PROFILE_TERMS) {
        assert.equal(pattern.test(blob), false, `${checkId} matched ${pattern}`);
      }
    }
  });

  it('caps WAF probe profile requests and timeout', () => {
    for (const checkId of WAF_SAFE_CHECK_IDS) {
      const check = getCheckById(checkId);
      const profile = check.probe_profile;
      assert.ok(profile.max_requests >= 1 && profile.max_requests <= MAX_PROBE_PROFILE_REQUESTS, checkId);
      assert.ok(profile.timeout_ms >= 100 && profile.timeout_ms <= MAX_PROBE_PROFILE_TIMEOUT_MS, checkId);
    }
  });

  it('blocks soc_gated check from customer safe run', () => {
    freshStore();
    const ctx = { tenantId: 'ten_demo', userId: 'u1', role: 'engineer' };
    const check = getCheckById('high_scale.volumetric.request_only');
    assert.equal(isCustomerRunnable(check), false);
    const result = startTestRun(ctx, {
      check_id: 'high_scale.volumetric.request_only',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
    });
    assert.equal(result.error, 'soc_gated_check');
    assert.equal(result.status, 403);
  });
});