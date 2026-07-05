import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { correlateExternalOnlyVerdict, correlateVerdict } from '../../src/services/correlation.mjs';

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

describe('correlateExternalOnlyVerdict', () => {
  it('edge_protected when blocked with external_only confidence', () => {
    const r = correlateExternalOnlyVerdict({
      externalResult: 'blocked',
      expectedBehavior: 'must_block_before_origin',
    });
    assert.equal(r.verdict, 'edge_protected');
    assert.equal(r.confidence, 'external_only');
    assert.equal(r.placement, 'unverified');
  });

  it('edge_exposed when connected with external_only confidence', () => {
    const r = correlateExternalOnlyVerdict({
      externalResult: 'connected',
      expectedBehavior: 'must_block_before_origin',
    });
    assert.equal(r.verdict, 'edge_exposed');
    assert.equal(r.confidence, 'external_only');
    assert.equal(r.createsFinding, true);
  });

  it('inconclusive for unknown external result', () => {
    const r = correlateExternalOnlyVerdict({
      externalResult: 'weird',
      expectedBehavior: 'must_block_before_origin',
    });
    assert.equal(r.verdict, 'inconclusive');
    assert.equal(r.confidence, 'external_only');
  });
});