import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createRetentionRepository } from '../../src/persistence/postgres/retentionRepository.mjs';

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

function assertTenantContext(pool, tenantId = 'ten_demo') {
  const queries = pool.client.queries.map((q) => q.text.trim());
  assert.ok(queries.includes('BEGIN'));
  assert.ok(
    pool.client.queries.some(
      (q) => q.text.includes("set_config('app.tenant_id'") && q.params?.[0] === tenantId,
    ),
  );
  assert.ok(queries.includes('COMMIT'));
  assert.equal(pool.client.released, true);
}

describe('postgres retention repository', () => {
  it('enforces metadata retention with report window protection and audit evidence', async () => {
    const now = new Date('2026-07-02T12:00:00.000Z');
    const pool = createFakePool({
      onQuery({ text, params }) {
        if (text.includes('FROM tenants') && text.includes('FOR UPDATE')) {
          return {
            rows: [
              {
                id: 'ten_demo',
                privacy_settings: {
                  metadata_retention_days: 30,
                  evidence_retention: { report_days: 365 },
                },
              },
            ],
          };
        }
        if (text.includes('FROM events') && text.includes('COUNT(*)')) return { rows: [{ count: '1' }] };
        if (text.includes('FROM evidence_vault') && text.includes('COUNT(*)')) {
          return { rows: [{ count: '2' }] };
        }
        if (text.includes('FROM reports') && text.includes('COUNT(*)')) return { rows: [{ count: '0' }] };
        if (text.includes('FROM notification_events') && text.includes('COUNT(*)')) {
          return { rows: [{ count: '3' }] };
        }
        if (text.startsWith('DELETE FROM events')) return { rowCount: 1, rows: [] };
        if (text.startsWith('DELETE FROM evidence_vault')) return { rowCount: 2, rows: [] };
        if (text.startsWith('DELETE FROM reports')) return { rowCount: 0, rows: [] };
        if (text.startsWith('DELETE FROM notification_events')) return { rowCount: 3, rows: [] };
        if (text.includes('pg_advisory_xact_lock(hashtext($1))')) return { rows: [] };
        if (text.includes('FROM audit_logs') && text.includes('ORDER BY sequence DESC')) {
          return { rows: [] };
        }
        if (text.startsWith('INSERT INTO audit_logs')) return { rows: [] };
        return { rows: [] };
      },
    });

    const repo = createRetentionRepository(pool);
    const summary = await repo.runMetadataRetention(
      'ten_demo',
      { userId: 'usr_1', role: 'admin' },
      { now },
    );

    assert.equal(summary.tenant_id, 'ten_demo');
    assert.equal(summary.legal_hold, false);
    assert.equal(summary.dry_run, false);
    assert.deepEqual(summary.deleted, {
      events: 1,
      evidenceVault: 2,
      reports: 0,
      notificationEvents: 3,
    });
    assert.deepEqual(summary.would_delete, summary.deleted);
    assert.equal(
      summary.policy_snapshot.deletion_collections.find((item) => item.collection === 'reports')
        .effective_retention_days,
      365,
    );

    const reportCountQuery = pool.client.queries.find(
      (q) => q.text.includes('FROM reports') && q.text.includes('COUNT(*)'),
    );
    assert.ok(reportCountQuery);
    assert.equal(reportCountQuery.params[1], '2025-07-02T12:00:00.000Z');

    const auditInsert = pool.client.queries.find((q) => q.text.startsWith('INSERT INTO audit_logs'));
    assert.ok(auditInsert);
    const auditMetadata = JSON.parse(auditInsert.params[11]);
    assert.deepEqual(auditMetadata.deleted, summary.deleted);
    assert.equal(auditInsert.params[8], 'privacy.retention_purged');
    assertTenantContext(pool);
  });

  it('blocks deletions under legal hold and audits blocked counts', async () => {
    const pool = createFakePool({
      onQuery({ text }) {
        if (text.includes('FROM tenants') && text.includes('FOR UPDATE')) {
          return {
            rows: [
              {
                id: 'ten_demo',
                privacy_settings: {
                  metadata_retention_days: 30,
                  evidence_retention: { legal_hold: true, report_days: 365 },
                },
              },
            ],
          };
        }
        if (text.includes('COUNT(*)')) return { rows: [{ count: '2' }] };
        if (text.includes('pg_advisory_xact_lock(hashtext($1))')) return { rows: [] };
        if (text.includes('FROM audit_logs') && text.includes('ORDER BY sequence DESC')) {
          return { rows: [] };
        }
        if (text.startsWith('INSERT INTO audit_logs')) return { rows: [] };
        if (text.startsWith('DELETE FROM ')) {
          throw new Error('delete should not run under legal hold');
        }
        return { rows: [] };
      },
    });

    const repo = createRetentionRepository(pool);
    const summary = await repo.runMetadataRetention('ten_demo', { role: 'system' });

    assert.equal(summary.legal_hold, true);
    assert.deepEqual(summary.deleted, {
      events: 0,
      evidenceVault: 0,
      reports: 0,
      notificationEvents: 0,
    });
    assert.deepEqual(summary.blocked_deletions, {
      events: 2,
      evidenceVault: 2,
      reports: 2,
      notificationEvents: 2,
    });
    const auditInsert = pool.client.queries.find((q) => q.text.startsWith('INSERT INTO audit_logs'));
    assert.ok(auditInsert);
    assert.equal(auditInsert.params[8], 'privacy.retention_legal_hold');
    assertTenantContext(pool);
  });

  it('supports dry-run reporting without deletes or audit writes', async () => {
    const pool = createFakePool({
      onQuery({ text }) {
        if (text.includes('FROM tenants') && text.includes('FOR UPDATE')) {
          return {
            rows: [
              {
                id: 'ten_demo',
                privacy_settings: { metadata_retention_days: 7 },
              },
            ],
          };
        }
        if (text.includes('COUNT(*)')) return { rows: [{ count: '4' }] };
        if (text.startsWith('DELETE FROM ') || text.startsWith('INSERT INTO audit_logs')) {
          throw new Error('dry run must not delete or audit');
        }
        return { rows: [] };
      },
    });

    const repo = createRetentionRepository(pool);
    const summary = await repo.runMetadataRetention('ten_demo', { role: 'system' }, { dryRun: true });

    assert.equal(summary.dry_run, true);
    assert.deepEqual(summary.deleted, {
      events: 0,
      evidenceVault: 0,
      reports: 0,
      notificationEvents: 0,
    });
    assert.deepEqual(summary.would_delete, {
      events: 4,
      evidenceVault: 4,
      reports: 4,
      notificationEvents: 4,
    });
    assert.ok(pool.client.queries.every((q) => !q.text.startsWith('DELETE FROM ')));
    assert.ok(pool.client.queries.every((q) => !q.text.startsWith('INSERT INTO audit_logs')));
    assertTenantContext(pool);
  });

  it('rolls back when a delete fails', async () => {
    const pool = createFakePool({
      onQuery({ text }) {
        if (text.includes('FROM tenants') && text.includes('FOR UPDATE')) {
          return {
            rows: [
              {
                id: 'ten_demo',
                privacy_settings: { metadata_retention_days: 30 },
              },
            ],
          };
        }
        if (text.includes('COUNT(*)')) return { rows: [{ count: '1' }] };
        if (text.startsWith('DELETE FROM events')) {
          throw new Error('delete failed');
        }
        return { rows: [] };
      },
    });

    const repo = createRetentionRepository(pool);
    await assert.rejects(
      () => repo.runMetadataRetention('ten_demo', { role: 'system' }),
      /delete failed/,
    );
    assert.ok(pool.client.queries.some((q) => q.text.trim() === 'ROLLBACK'));
    assert.equal(pool.client.released, true);
  });
});
