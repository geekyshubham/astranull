import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { listFindings, listFindingsEnvelope } from '../../src/services/findings.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';

const CTX = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };

function seedFindings() {
  freshStore();
  const store = getStore();
  store.findings.push(
    {
      id: 'find_1',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      test_run_id: 'run_1',
      check_id: 'dns.safe',
      status: 'open',
      created_at: '2026-07-01T00:00:00.000Z',
    },
    {
      id: 'find_2',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_1',
      target_id: 'tgt_2',
      test_run_id: 'run_2',
      check_id: 'dns.safe',
      status: 'open',
      created_at: '2026-07-02T00:00:00.000Z',
    },
    {
      id: 'find_other_tenant',
      tenant_id: 'ten_other',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      test_run_id: 'run_1',
      check_id: 'dns.safe',
      status: 'open',
      created_at: '2026-07-03T00:00:00.000Z',
    },
  );
}

describe('findings service list filters', () => {
  it('filters by test_run_id within tenant scope', () => {
    seedFindings();
    const runOne = listFindings(CTX, { test_run_id: 'run_1' });
    assert.equal(runOne.length, 1);
    assert.equal(runOne[0].id, 'find_1');

    const runTwo = listFindings(CTX, { test_run_id: 'run_2' });
    assert.equal(runTwo.length, 1);
    assert.equal(runTwo[0].id, 'find_2');

    assert.equal(listFindings(CTX, { test_run_id: 'run_missing' }).length, 0);
  });

  it('combines test_run_id with target filters', () => {
    seedFindings();
    assert.equal(
      listFindings(CTX, { test_run_id: 'run_1', target_id: 'tgt_1' }).length,
      1,
    );
    assert.equal(
      listFindings(CTX, { test_run_id: 'run_1', target_id: 'tgt_2' }).length,
      0,
    );
  });

  it('envelope reports a test-run empty reason when no match', () => {
    seedFindings();
    const envelope = listFindingsEnvelope(CTX, { test_run_id: 'run_missing' });
    assert.equal(envelope.items.length, 0);
    assert.equal(envelope.count, 0);
    assert.equal(envelope.meta.empty_reason, 'No findings match this test run filter.');
  });
});
