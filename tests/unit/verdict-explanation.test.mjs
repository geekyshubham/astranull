import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  buildVerdictExplanationFields,
  normalizeVerdictKey,
  summarizeExternalProbeEvidence,
  summarizePlacementConfidence,
  trafficHopState,
} from '../../apps/web/react/src/lib/verdict-explanation.ts';

describe('verdict-explanation (React portal)', () => {
  it('summarizeExternalProbeEvidence reads external_result from metadata', () => {
    const summary = summarizeExternalProbeEvidence([
      {
        signal_type: 'probe_result',
        timestamp: '2026-01-01T00:00:00Z',
        metadata: { external_result: 'tcp_connect_ok' },
      },
    ]);
    assert.match(summary, /external_result tcp_connect_ok/);
  });

  it('buildVerdictExplanationFields prefers backend placement_confidence', () => {
    const fields = buildVerdictExplanationFields(
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
      [
        { signal_type: 'probe_result', metadata: { external_result: 'ok' } },
        { signal_type: 'agent_observation', nonce_hash: 'n1', agent_id: 'ag_1' },
      ],
    );

    const labels = fields.map((field) => field.label);
    assert.deepEqual(labels, [
      'External probe evidence',
      'Internal agent evidence',
      'Observation mode',
      'Placement confidence',
      'Conclusion',
      'Remediation',
    ]);
    const placement = fields.find((field) => field.label === 'Placement confidence');
    assert.match(placement?.value ?? '', /high/);
    assert.match(placement?.value ?? '', /packet_metadata/);
    const conclusion = fields.find((field) => field.label === 'Conclusion');
    assert.match(conclusion?.value ?? '', /bypassable/);
    const remediation = fields.find((field) => field.label === 'Remediation');
    assert.equal(remediation?.value, 'Fix edge path.');
  });

  it('buildVerdictExplanationFields returns empty array without verdict payload', () => {
    assert.deepEqual(buildVerdictExplanationFields({}, []), []);
    assert.deepEqual(buildVerdictExplanationFields(null, []), []);
  });

  it('summarizePlacementConfidence falls back when backend placement is absent', () => {
    const supported = summarizePlacementConfidence(
      [{ signal_type: 'agent_observation', nonce_hash: 'n1' }],
      [],
      undefined,
    );
    assert.match(supported, /supported by job-bound agent observation/);

    const limited = summarizePlacementConfidence(
      [],
      [{ signal_type: 'agent_no_observation' }],
      undefined,
    );
    assert.match(limited, /limited/);
  });

  it('normalizeVerdictKey and trafficHopState support visualization helpers', () => {
    assert.equal(normalizeVerdictKey('misplaced_agent'), 'misplaced');
    assert.equal(trafficHopState('origin', 'bypassable'), 'danger');
    assert.equal(trafficHopState('edge', 'protected'), 'ok');
  });
});