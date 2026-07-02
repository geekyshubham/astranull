import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { computeEntryHash } from '../../src/audit.mjs';
import {
  createAuditRepository,
  DEFAULT_AUDIT_LIST_LIMIT,
  MAX_AUDIT_LIST_LIMIT,
} from '../../src/persistence/postgres/auditRepository.mjs';

function createFakePool({ onQuery } = {}) {
  const client = {
    queries: [],
    released: false,
    async query(text, params) {
      const record = { text, params };
      this.queries.push(record);
      if (onQuery) {
        return onQuery(record, this);
      }
      return { rows: [] };
    },
    release() {
      this.released = true;
    },
  };
  let connectCount = 0;
  return {
    client,
    poolQueries: [],
    get connectCount() {
      return connectCount;
    },
    async connect() {
      connectCount += 1;
      return client;
    },
    async query() {
      throw new Error('repository must not use pool.query');
    },
  };
}

function assertTenantContext(pool) {
  const queries = pool.client.queries.map((q) => q.text.trim());
  assert.ok(queries.includes('BEGIN'));
  assert.ok(
    pool.client.queries.some(
      (q) => q.text.includes("set_config('app.tenant_id'") && q.params?.[0] === 'ten_demo',
    ),
  );
  assert.ok(queries.includes('COMMIT'));
  assert.equal(pool.client.released, true);
}

const sampleEntry = {
  id: 'event_abc',
  tenant_id: 'ten_demo',
  timestamp: '2026-07-01T12:00:00.000Z',
  sequence: 3,
  prev_hash: 'prevhash',
  entry_hash: 'entryhash',
  actor_user_id: 'usr_1',
  actor_role: 'admin',
  action: 'tenant.updated',
  resource_type: 'tenant',
  resource_id: 'ten_demo',
  metadata: { reason: 'test' },
};

describe('postgres audit repository', () => {
  it('listAuditEntries uses tenant predicate, default limit, ascending sequence order', async () => {
    const pool = createFakePool({
      onQuery({ text }) {
        if (text.includes('FROM audit_logs')) {
          return {
            rows: [
              {
                id: 'e2',
                tenant_id: 'ten_demo',
                timestamp: new Date('2026-07-01T12:01:00.000Z'),
                sequence: '2',
                prev_hash: 'h1',
                entry_hash: 'h2',
                actor_user_id: null,
                actor_role: null,
                action: 'b',
                resource_type: null,
                resource_id: null,
                metadata_json: {},
              },
              {
                id: 'e1',
                tenant_id: 'ten_demo',
                timestamp: new Date('2026-07-01T12:00:00.000Z'),
                sequence: '1',
                prev_hash: null,
                entry_hash: 'h1',
                actor_user_id: null,
                actor_role: null,
                action: 'a',
                resource_type: null,
                resource_id: null,
                metadata_json: { k: 1 },
              },
            ],
          };
        }
        return { rows: [] };
      },
    });
    const repo = createAuditRepository(pool);
    const items = await repo.listAuditEntries({ tenantId: 'ten_demo' });

    assert.equal(items.length, 2);
    assert.equal(items[0].sequence, 1);
    assert.equal(items[1].sequence, 2);
    assert.deepEqual(items[0].metadata, { k: 1 });

    const listQuery = pool.client.queries.find((q) => q.text.includes('FROM audit_logs'));
    assert.ok(listQuery);
    assert.match(listQuery.text, /WHERE tenant_id = \$1/);
    assert.equal(listQuery.params[0], 'ten_demo');
    assert.equal(listQuery.params[1], DEFAULT_AUDIT_LIST_LIMIT);
    assertTenantContext(pool);
  });

  it('listAuditEntries caps limit at MAX_AUDIT_LIST_LIMIT', async () => {
    const pool = createFakePool();
    const repo = createAuditRepository(pool);
    await repo.listAuditEntries({ tenantId: 'ten_demo' }, { limit: 99999 });
    const listQuery = pool.client.queries.find((q) => q.text.includes('FROM audit_logs'));
    assert.equal(listQuery.params[1], MAX_AUDIT_LIST_LIMIT);
  });

  it('appendAuditEntry inserts with parameterized values and jsonb metadata', async () => {
    const pool = createFakePool();
    const repo = createAuditRepository(pool);
    await repo.appendAuditEntry(sampleEntry);

    const insert = pool.client.queries.find((q) => q.text.includes('INSERT INTO audit_logs'));
    assert.ok(insert);
    assert.doesNotMatch(insert.text, /tenant\.updated/);
    assert.doesNotMatch(insert.text, /ten_demo/);
    assert.equal(insert.params[0], sampleEntry.id);
    assert.equal(insert.params[1], sampleEntry.tenant_id);
    assert.equal(insert.params[8], sampleEntry.action);
    assert.equal(insert.params[10], sampleEntry.resource_id);
    assert.equal(insert.params[11], JSON.stringify(sampleEntry.metadata));
    assert.match(insert.text, /metadata_json/);
    assertTenantContext(pool);
  });

  it('getLastAuditEntry orders by sequence and returns mapped row', async () => {
    const pool = createFakePool({
      onQuery({ text }) {
        if (text.includes('ORDER BY sequence DESC')) {
          return {
            rows: [
              {
                id: 'event_last',
                tenant_id: 'ten_demo',
                timestamp: new Date('2026-07-01T12:02:00.000Z'),
                sequence: '9',
                prev_hash: 'p9',
                entry_hash: 'h9',
                actor_user_id: null,
                actor_role: null,
                action: 'last',
                resource_type: null,
                resource_id: null,
                metadata_json: null,
              },
            ],
          };
        }
        return { rows: [] };
      },
    });
    const repo = createAuditRepository(pool);
    const last = await repo.getLastAuditEntry('ten_demo');
    assert.equal(last.sequence, 9);
    assert.equal(last.entry_hash, 'h9');
    const getQuery = pool.client.queries.find((q) => q.text.includes('ORDER BY sequence DESC'));
    assert.match(getQuery.text, /WHERE tenant_id = \$1/);
    assert.equal(getQuery.params[0], 'ten_demo');
    assertTenantContext(pool);
  });

  it('rolls back when a tenant-scoped query throws', async () => {
    const pool = createFakePool({
      onQuery({ text }) {
        if (text.includes('INSERT INTO audit_logs')) {
          throw new Error('insert failed');
        }
        return { rows: [] };
      },
    });
    const repo = createAuditRepository(pool);
    await assert.rejects(() => repo.appendAuditEntry(sampleEntry), /insert failed/);
    assert.ok(pool.client.queries.some((q) => q.text.trim() === 'ROLLBACK'));
    assert.equal(pool.client.released, true);
  });

  it('appendAuditEvent rejects missing or blank tenant before connecting', async () => {
    const pool = createFakePool();
    const repo = createAuditRepository(pool);
    await assert.rejects(
      () => repo.appendAuditEvent({ action: 'x' }),
      /tenant id must be a non-empty string/,
    );
    await assert.rejects(
      () => repo.appendAuditEvent({ tenant_id: '   ', action: 'x' }),
      /tenant id must be a non-empty string/,
    );
    assert.equal(pool.connectCount, 0);
  });

  it('appendAuditEvent locks, chains, inserts redacted row, and returns built record', async () => {
    const fixedNow = new Date('2026-07-01T12:30:00.000Z');
    const pool = createFakePool({
      onQuery({ text }) {
        if (text.includes('ORDER BY sequence DESC')) {
          return {
            rows: [
              {
                id: 'event_prev',
                tenant_id: 'ten_demo',
                timestamp: new Date('2026-07-01T12:00:00.000Z'),
                sequence: '2',
                prev_hash: 'ph1',
                entry_hash: 'eh2',
                actor_user_id: null,
                actor_role: null,
                action: 'prior.action',
                resource_type: null,
                resource_id: null,
                metadata_json: {},
              },
            ],
          };
        }
        return { rows: [] };
      },
    });
    const repo = createAuditRepository(pool);
    const record = await repo.appendAuditEvent(
      {
        tenant_id: 'ten_demo',
        actor_user_id: 'usr_1',
        actor_role: 'admin',
        action: 'tenant.updated',
        resource_type: 'tenant',
        resource_id: 'ten_demo',
        metadata: { api_key: 'ast_supersecret1234567890' },
      },
      { now: fixedNow },
    );

    const lockQuery = pool.client.queries.find((q) =>
      q.text.includes('pg_advisory_xact_lock(hashtext($1))'),
    );
    assert.ok(lockQuery);
    assert.equal(lockQuery.params[0], 'ten_demo');
    assert.doesNotMatch(lockQuery.text, /ten_demo/);

    const lastQuery = pool.client.queries.find(
      (q) => q.text.includes('FROM audit_logs') && q.text.includes('ORDER BY sequence DESC'),
    );
    assert.ok(lastQuery);
    assert.equal(lastQuery.params[0], 'ten_demo');

    assert.equal(record.sequence, 3);
    assert.equal(record.prev_hash, 'eh2');
    assert.equal(record.timestamp, fixedNow.toISOString());
    assert.equal(record.metadata.api_key, '[REDACTED]');
    assert.equal(record.entry_hash, computeEntryHash(record));

    const insert = pool.client.queries.find((q) => q.text.includes('INSERT INTO audit_logs'));
    assert.ok(insert);
    assert.doesNotMatch(insert.text, /tenant\.updated/);
    assert.doesNotMatch(insert.text, /ten_demo/);
    assert.doesNotMatch(insert.text, /ast_supersecret/);
    assert.equal(insert.params[1], 'ten_demo');
    assert.equal(insert.params[3], 3);
    assert.equal(insert.params[4], 'eh2');
    assert.equal(insert.params[8], 'tenant.updated');
    assertTenantContext(pool);
  });

  it('appendAuditEvent rolls back when insert fails after lock and read', async () => {
    const pool = createFakePool({
      onQuery({ text }) {
        if (text.includes('INSERT INTO audit_logs')) {
          throw new Error('insert failed');
        }
        return { rows: [] };
      },
    });
    const repo = createAuditRepository(pool);
    await assert.rejects(
      () =>
        repo.appendAuditEvent({
          tenant_id: 'ten_demo',
          action: 'fail.after.read',
          resource_type: 'r',
          resource_id: '1',
        }),
      /insert failed/,
    );
    assert.ok(
      pool.client.queries.some((q) => q.text.includes('pg_advisory_xact_lock(hashtext($1))')),
    );
    assert.ok(pool.client.queries.some((q) => q.text.includes('ORDER BY sequence DESC')));
    assert.ok(pool.client.queries.some((q) => q.text.trim() === 'ROLLBACK'));
    assert.equal(pool.client.released, true);
  });
});