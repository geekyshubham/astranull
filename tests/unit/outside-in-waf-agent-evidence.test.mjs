import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  enrichOutsideInWafProbeMetadata,
  resolveDomXssValidation,
  resolveOutsideInAgentCorroboration,
} from '../../src/lib/outsideInWafAgentEvidence.mjs';

describe('outside-in WAF agent evidence', () => {
  it('resolves agent corroboration when block is observed for matching nonce', () => {
    const corroborated = resolveOutsideInAgentCorroboration({
      nonceHash: 'sha256:abc',
      probeValidationPassed: true,
      agents: [{
        nonce_hash: 'sha256:abc',
        metadata: {
          waf_marker: true,
          observed_action: 'block',
          waf_blocked: true,
        },
      }],
    });
    assert.equal(corroborated, true);
  });

  it('rejects corroboration when marker leaks to origin', () => {
    const corroborated = resolveOutsideInAgentCorroboration({
      nonceHash: 'sha256:abc',
      probeValidationPassed: true,
      agents: [{
        nonce_hash: 'sha256:abc',
        metadata: {
          observation_type: 'waf_marker_seen',
          marker_reached_origin: true,
        },
      }],
    });
    assert.equal(corroborated, false);
  });

  it('resolves DOM XSS validation from canary observations', () => {
    assert.equal(resolveDomXssValidation({ nonceHash: null }), 'agent_required');
    assert.equal(resolveDomXssValidation({
      nonceHash: 'sha256:dom',
      agents: [{
        nonce_hash: 'sha256:dom',
        metadata: { dom_xss_probe: true, dom_xss_blocked: true },
      }],
    }), 'agent_corroborated_blocked');
    assert.equal(resolveDomXssValidation({
      nonceHash: 'sha256:dom',
      agents: [{
        nonce_hash: 'sha256:dom',
        metadata: { dom_xss_probe: true, marker_reached_origin: true },
      }],
    }), 'marker_reached_origin');
  });

  it('enrichOutsideInWafProbeMetadata upgrades posture to Protected with agent evidence', () => {
    const enriched = enrichOutsideInWafProbeMetadata({
      probe_kind: 'outside_in_waf_scan',
      waf_detected: true,
      generic_waf_detected: true,
      probe_validation_passed: true,
      agent_corroborated: false,
      agent_corroboration_required: true,
      evasion_bypass_suspected: false,
      origin_bypass_confirmed: false,
      detected_vendor: 'cloudflare',
      detected_product: 'waf',
      waf_confidence: 0.9,
      marker_probes: [
        { family: 'sqli_marker', variant: 'plain', blocked: true, allowed: false },
      ],
    }, {
      nonceHash: 'sha256:upgrade',
      agents: [{
        nonce_hash: 'sha256:upgrade',
        metadata: { waf_marker: true, observed_action: 'block', waf_blocked: true },
      }],
    });

    assert.equal(enriched.agent_corroborated, true);
    assert.equal(enriched.posture_label, 'Protected');
    assert.equal(enriched.validation_passed, true);
  });
});