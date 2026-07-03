import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { deriveWafSignalsFromBoundEvents } from '../../src/lib/wafBoundRunCorrelation.mjs';

describe('waf bound run correlation', () => {
  it('classifies marker leak when blocked externally but agent observes marker', () => {
    const nonceHash = 'sha256:marker_leak';
    const derived = deriveWafSignalsFromBoundEvents({
      probes: [{
        id: 'evt_probe_1',
        nonce_hash: nonceHash,
        metadata: { external_result: 'blocked' },
      }],
      agents: [{
        nonce_hash: nonceHash,
        metadata: { waf_marker: true, marker_type: 'header' },
      }],
    });

    assert.equal(derived.wafDetected, true);
    assert.equal(derived.validationPassed, false);
    assert.equal(derived.validationFailed, true);
    assert.equal(derived.source_external, true);
    assert.equal(derived.source_agent, true);
    assert.equal(derived.scenarioResults.length, 1);
    assert.equal(derived.scenarioResults[0].passed, false);
    assert.equal(derived.scenarioResults[0].observed_action, 'allow');
    assert.equal(derived.scenarioResults[0].evidence_summary.observed_at_agent, true);
  });

  it('stays inconclusive when blocked externally without fingerprint or agent block evidence', () => {
    const derived = deriveWafSignalsFromBoundEvents({
      probes: [{
        id: 'evt_probe_2',
        nonce_hash: 'sha256:blocked_only',
        metadata: { external_result: 'blocked' },
      }],
      agents: [],
    });

    assert.equal(derived.validationPassed, false);
    assert.equal(derived.validationFailed, false);
    assert.equal(derived.scenarioResults[0].passed, null);
    assert.equal(derived.scenarioResults[0].observed_action, 'inconclusive');
  });

  it('classifies protected when blocked externally with WAF fingerprint hint and nonce', () => {
    const derived = deriveWafSignalsFromBoundEvents({
      probes: [{
        id: 'evt_probe_2b',
        nonce_hash: 'sha256:blocked_fingerprint',
        metadata: {
          external_result: 'blocked',
          waf_fingerprint_detected: true,
          waf_product_hint: 'cloudflare',
        },
      }],
      agents: [],
    });

    assert.equal(derived.validationPassed, true);
    assert.equal(derived.scenarioResults[0].passed, true);
    assert.equal(derived.scenarioResults[0].observed_action, 'block');
  });

  it('does not correlate agent observations without matching nonce', () => {
    const derived = deriveWafSignalsFromBoundEvents({
      probes: [{
        id: 'evt_probe_3',
        nonce_hash: 'sha256:probe_nonce',
        metadata: { external_result: 'blocked' },
      }],
      agents: [{
        nonce_hash: 'sha256:other_nonce',
        metadata: { waf_marker: true },
      }],
    });

    assert.equal(derived.validationPassed, false);
    assert.equal(derived.scenarioResults[0].evidence_summary.observed_at_agent, false);
  });
});