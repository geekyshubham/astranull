import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createKillSwitchRepository } from '../../src/persistence/postgres/killSwitchRepository.mjs';

const CTX = { tenantId: 'ten_demo', userId: 'usr_1', role: 'admin' };

function createRecordingPool(handler) {
  const client = {
    queries: [],
    released: false,
    async query(text, params) {
      this.queries.push({ text, params });
      return handler(text, params, this.queries);
    },
    release() {
      this.released = true;
    },
  };
  return {
    client,
    async connect() {
      return client;
    },
  };
}

function dataQueries(client) {
  return client.queries.filter((q) => {
    const t = q.text.trim();
    return t !== 'BEGIN' && t !== 'COMMIT' && t !== 'ROLLBACK' && !t.startsWith("SELECT set_config('app.tenant_id'");
  });
}

function assertTenantWrapped(client, tenantId) {
  assert.equal(client.queries[0].text.trim(), 'BEGIN');
  assert.equal(client.queries[1].text.trim(), "SELECT set_config('app.tenant_id', $1, true)");
  assert.deepEqual(client.queries[1].params, [tenantId]);
  assert.equal(client.queries.at(-1).text.trim(), 'COMMIT');
  assert.equal(client.released, true);
}

describe('postgres kill switch repository', () => {
  it('isKillSwitchActiveForTenant queries soc_kill_switch under tenant context', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.includes('FROM soc_kill_switch')) {
        assert.deepEqual(params, [CTX.tenantId]);
        return { rows: [{ active: true }] };
      }
      return { rows: [] };
    });
    const repo = createKillSwitchRepository(pool);

    const active = await repo.isKillSwitchActiveForTenant(CTX);
    assert.equal(active, true);
    assertTenantWrapped(pool.client, CTX.tenantId);
    assert.equal(dataQueries(pool.client).length, 1);
    assert.ok(dataQueries(pool.client)[0].text.includes('soc_kill_switch'));
  });

  it('returns false when tenant has no kill switch row', async () => {
    const pool = createRecordingPool((text) => {
      if (text.includes('FROM soc_kill_switch')) {
        return { rows: [] };
      }
      return { rows: [] };
    });
    const repo = createKillSwitchRepository(pool);

    assert.equal(await repo.isKillSwitchActiveForTenant(CTX), false);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('returns false when row exists but active is false', async () => {
    const pool = createRecordingPool((text) => {
      if (text.includes('FROM soc_kill_switch')) {
        return { rows: [{ active: false }] };
      }
      return { rows: [] };
    });
    const repo = createKillSwitchRepository(pool);

    assert.equal(await repo.isKillSwitchActiveForTenant(CTX), false);
  });
});