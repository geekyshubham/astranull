import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  assertRunnerTenantScope,
  resolveScheduledTenantIds,
} from '../../src/lib/scheduledTenantScope.mjs';

describe('scheduled tenant scope', () => {
  it('requires explicit tenant ids for scheduled jobs', () => {
    const outcome = resolveScheduledTenantIds({}, { label: 'test runner' });
    assert.equal(outcome.error, 'tenant_scope_required');
    assert.equal(outcome.status, 400);
  });

  it('normalizes and deduplicates tenant ids', () => {
    const outcome = resolveScheduledTenantIds({
      tenantIds: [' ten_a ', 'ten_b', 'ten_a'],
    });
    assert.deepEqual(outcome.tenantIds, ['ten_a', 'ten_b']);
  });

  it('assertRunnerTenantScope fails closed for postgres without scope', () => {
    const outcome = assertRunnerTenantScope([], 'postgres', 'waf-drift-runner');
    assert.equal(outcome.ok, false);
    assert.match(outcome.message, /explicit tenant_ids/i);
  });

  it('assertRunnerTenantScope allows dev-json without scope', () => {
    assert.equal(assertRunnerTenantScope([], 'dev-json', 'waf-drift-runner'), null);
  });
});