import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';

function createFakePool() {
  const client = {
    queries: [],
    released: false,
    async query(text, params) {
      this.queries.push({ text, params });
      return { rows: [] };
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

describe('postgres tenant context', () => {
  it('runs BEGIN, set_config tenant id, callback, COMMIT, and releases client', async () => {
    const pool = createFakePool();
    const seen = [];
    const result = await withTenantContext(pool, 'ten_demo', async (client) => {
      await client.query('SELECT 1');
      seen.push('callback');
      return 'ok';
    });
    assert.equal(result, 'ok');
    assert.deepEqual(
      pool.client.queries.map((q) => ({ text: q.text.trim(), params: q.params })),
      [
        { text: 'BEGIN', params: undefined },
        { text: "SELECT set_config('app.tenant_id', $1, true)", params: ['ten_demo'] },
        { text: 'SELECT 1', params: undefined },
        { text: 'COMMIT', params: undefined },
      ],
    );
    assert.equal(pool.client.released, true);
    assert.deepEqual(seen, ['callback']);
  });

  it('rolls back and releases on callback failure', async () => {
    const pool = createFakePool();
    await assert.rejects(
      () =>
        withTenantContext(pool, 'ten_demo', async () => {
          throw new Error('query failed');
        }),
      /query failed/,
    );
    assert.ok(pool.client.queries.some((q) => q.text.trim() === 'ROLLBACK'));
    assert.equal(pool.client.released, true);
  });

  it('rejects empty tenant id', async () => {
    const pool = createFakePool();
    await assert.rejects(() => withTenantContext(pool, '  ', async () => {}), /non-empty/);
  });

  it('trims tenant id before set_config', async () => {
    const pool = createFakePool();
    await withTenantContext(pool, '  ten_trimmed  ', async () => {});
    const setConfig = pool.client.queries.find((q) =>
      /set_config\('app\.tenant_id'/.test(q.text),
    );
    assert.deepEqual(setConfig?.params, ['ten_trimmed']);
  });

  it('releases client and preserves COMMIT failure', async () => {
    const pool = createFakePool();
    pool.client.query = async function query(text, params) {
      this.queries.push({ text, params });
      if (String(text).trim() === 'COMMIT') {
        throw new Error('commit failed');
      }
      return { rows: [] };
    };

    await assert.rejects(
      () => withTenantContext(pool, 'ten_demo', async () => 'ok'),
      /commit failed/,
    );
    assert.equal(pool.client.released, true);
  });

  it('releases client and preserves callback error when ROLLBACK also fails', async () => {
    const pool = createFakePool();
    pool.client.query = async function query(text, params) {
      this.queries.push({ text, params });
      const normalized = String(text).trim();
      if (normalized === 'ROLLBACK') {
        throw new Error('rollback failed');
      }
      return { rows: [] };
    };

    await assert.rejects(
      () =>
        withTenantContext(pool, 'ten_demo', async () => {
          throw new Error('query failed');
        }),
      /query failed/,
    );
    assert.equal(pool.client.released, true);
  });
});