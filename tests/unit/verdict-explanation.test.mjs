import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  formatPlacementConfidenceFromVerdict,
  renderFindingVerdictExplanation,
  renderVerdictExplanation,
  summarizeExternalProbeEvidence,
} from '../../apps/web/verdict-explanation.mjs';

describe('verdict-explanation', () => {
  it('summarizeExternalProbeEvidence reads external_result from metadata', () => {
    const html = summarizeExternalProbeEvidence([
      {
        signal_type: 'probe_result',
        timestamp: '2026-01-01T00:00:00Z',
        metadata: { external_result: 'tcp_connect_ok' },
      },
    ]);
    assert.match(html, /external_result tcp_connect_ok/);
  });

  it('renderVerdictExplanation prefers backend placement_confidence', () => {
    const html = renderVerdictExplanation(
      {
        remediation_template: 'Fix edge path.',
        verdict: {
          verdict: 'bypassable',
          confidence: 'high',
          explanation: 'Marker reached origin.',
          placement_confidence: { level: 'high', observation_mode: 'packet_metadata' },
        },
        correlation: { nonce_hash: 'n1' },
      },
      {
        items: [
          { signal_type: 'probe_result', metadata: { external_result: 'ok' } },
          { signal_type: 'agent_observation', nonce_hash: 'n1', agent_id: 'ag_1' },
        ],
      },
    );
    assert.match(html, /Why this verdict\?/);
    assert.match(html, /External probe evidence/);
    assert.match(html, /high/);
    assert.match(html, /packet_metadata/);
    assert.match(html, /bypassable/);
    assert.match(html, /Fix edge path\./);
  });

  it('renderFindingVerdictExplanation uses finding heading and remediation', () => {
    const html = renderFindingVerdictExplanation(
      {
        id: 'find_1',
        test_run_id: 'run_1',
        remediation_template: 'Restrict origin ingress.',
        notes: 'fallback',
      },
      {
        check_id: 'chk_1',
        remediation_template: 'Run-level template.',
        verdict: {
          verdict: 'penetrated',
          confidence: 'medium',
          explanation: 'Reach confirmed.',
        },
        correlation: {},
      },
      { items: [{ signal_type: 'probe_result', metadata: { external_result: 'reach' } }] },
    );
    assert.match(html, /Why this finding\?/);
    assert.match(html, /Restrict origin ingress\./);
    assert.equal(html.includes('Run-level template.'), false);
  });

  it('renderFindingVerdictExplanation without test run shows notes and remediation only', () => {
    const html = renderFindingVerdictExplanation(
      { notes: 'Declared gap.', remediation_template: 'Close ingress.' },
      null,
      null,
    );
    assert.match(html, /no linked test run/i);
    assert.match(html, /Declared gap\./);
    assert.match(html, /Close ingress\./);
    assert.equal(html.includes('External probe evidence'), false);
  });

  it('formatPlacementConfidenceFromVerdict returns null for invalid input', () => {
    assert.equal(formatPlacementConfidenceFromVerdict(null), null);
    assert.equal(formatPlacementConfidenceFromVerdict('high'), null);
  });
});