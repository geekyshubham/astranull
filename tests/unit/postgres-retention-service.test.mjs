import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  createPostgresRetentionServices,
  POSTGRES_RETENTION_SERVICE_METHODS,
  RETENTION_REPOSITORY_METHODS,
} from '../../src/persistence/postgres/retentionServiceAdapters.mjs';

describe('postgres retention service adapters', () => {
  it('exposes stable retention method lists', () => {
    assert.deepEqual(RETENTION_REPOSITORY_METHODS, ['runMetadataRetention']);
    assert.deepEqual(POSTGRES_RETENTION_SERVICE_METHODS, [
      'enforceMetadataRetentionForTenant',
      'previewMetadataRetentionForTenant',
    ]);
  });

  it('fails early when retention repository is missing', () => {
    assert.throws(
      () => createPostgresRetentionServices({}),
      /requires repositories\.retention/,
    );
    assert.throws(
      () => createPostgresRetentionServices({ retention: {} }),
      /requires retention\.runMetadataRetention\(\)/,
    );
  });

  it('maps enforce and preview calls onto repository dry-run mode', async () => {
    const calls = [];
    const services = createPostgresRetentionServices({
      retention: {
        async runMetadataRetention(tenantId, auditContext, options) {
          calls.push({ tenantId, auditContext, options });
          return { tenant_id: tenantId, dry_run: Boolean(options?.dryRun) };
        },
      },
    });

    const ctx = { tenantId: 'ten_demo', userId: 'usr_1', role: 'admin' };
    const enforced = await services.enforceMetadataRetentionForTenant(ctx);
    const preview = await services.previewMetadataRetentionForTenant(ctx, 'ten_demo', {
      now: new Date('2026-07-02T12:00:00.000Z'),
    });

    assert.equal(enforced.dry_run, false);
    assert.equal(preview.dry_run, true);
    assert.deepEqual(calls[0], {
      tenantId: 'ten_demo',
      auditContext: { userId: 'usr_1', role: 'admin' },
      options: {},
    });
    assert.equal(calls[1].tenantId, 'ten_demo');
    assert.equal(calls[1].auditContext.userId, 'usr_1');
    assert.equal(calls[1].options.dryRun, true);
  });
});
