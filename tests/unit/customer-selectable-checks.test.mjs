import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  CHECK_CATALOG,
  checkRequiresAdditionalInput,
  customerSelectableChecks,
  getCheckById,
} from '../../src/contracts/checks.mjs';

const INPUT_REQUIRING = [
  'origin.direct_reachability.safe',
  'origin.direct_bypass.safe',
  'origin.host_sni_bypass.safe',
  'path.protected_canary.safe',
  'waf.origin_bypass.safe',
];

test('checkRequiresAdditionalInput flags host_sni_bypass and agent_mode prerequisites', () => {
  for (const id of INPUT_REQUIRING) {
    const check = getCheckById(id);
    assert.ok(check, `check ${id} should still exist in the catalog`);
    assert.equal(checkRequiresAdditionalInput(check), true, `${id} should require additional input`);
  }
});

test('customerSelectableChecks excludes every input-requiring check', () => {
  const selectable = customerSelectableChecks(CHECK_CATALOG);
  const ids = new Set(selectable.map((c) => c.check_id));
  for (const id of INPUT_REQUIRING) {
    assert.equal(ids.has(id), false, `${id} must not be customer-selectable`);
  }
  // No selectable check requires additional input.
  assert.equal(selectable.some((c) => checkRequiresAdditionalInput(c)), false);
  // Sanity: filtering removed exactly the known set and left a non-empty catalog.
  assert.equal(CHECK_CATALOG.length - selectable.length, INPUT_REQUIRING.length);
  assert.ok(selectable.length > 0);
});

test('definitions remain resolvable for internal/orchestrator use', () => {
  for (const id of INPUT_REQUIRING) {
    assert.ok(getCheckById(id), `${id} must remain in CHECK_CATALOG for getCheckById`);
  }
});
