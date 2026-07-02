import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { correlateVerdict } from '../../src/services/correlation.mjs';

describe('correlation truth table', () => {
  it('protected when blocked and not observed', () => {
    const r = correlateVerdict({
      externalResult: 'blocked',
      agentObserved: false,
      expectedBehavior: 'must_block_before_origin',
      agentOnline: true,
      agentBound: true,
    });
    assert.equal(r.verdict, 'protected');
    assert.equal(r.confidence, 'medium');
  });

  it('bypassable when connected and observed', () => {
    const r = correlateVerdict({
      externalResult: 'connected',
      agentObserved: true,
      expectedBehavior: 'must_block_before_origin',
      agentOnline: true,
      agentBound: true,
    });
    assert.equal(r.verdict, 'bypassable');
    assert.equal(r.createsFinding, true);
  });

  it('penetrated when blocked but observed', () => {
    const r = correlateVerdict({
      externalResult: 'timeout',
      agentObserved: true,
      expectedBehavior: 'must_block_before_origin',
      agentOnline: true,
      agentBound: true,
    });
    assert.equal(r.verdict, 'penetrated');
  });

  it('misplaced when connected without observation', () => {
    const r = correlateVerdict({
      externalResult: 'allowed',
      agentObserved: false,
      expectedBehavior: 'must_block_before_origin',
      agentOnline: true,
      agentBound: true,
    });
    assert.equal(r.verdict, 'misplaced_agent');
  });
});