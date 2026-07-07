import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { resolveExpectedBehaviorForCheck } from '../../src/contracts/checks.mjs';

describe('checks contract helpers', () => {
  it('resolveExpectedBehaviorForCheck uses check default_expected_behavior', () => {
    assert.equal(
      resolveExpectedBehaviorForCheck('path.protected_canary.safe'),
      'must_reach_canary',
    );
    assert.equal(
      resolveExpectedBehaviorForCheck('origin.direct_bypass.safe'),
      'must_block_before_origin',
    );
  });

  it('resolveExpectedBehaviorForCheck falls back when check is unknown', () => {
    assert.equal(
      resolveExpectedBehaviorForCheck('unknown.check.id'),
      'must_block_before_origin',
    );
  });
});