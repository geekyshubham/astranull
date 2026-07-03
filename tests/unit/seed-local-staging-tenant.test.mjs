import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { LOCAL_STAGING_DEMO_IDS } from '../../scripts/lib/localStaging.mjs';
import { seedLocalStagingTenant } from '../../scripts/seed-local-staging-tenant.mjs';

describe('seed local staging tenant', () => {
  it('inserts demo tenant rows when absent', async () => {
    const queries = [];
    const client = {
      async query(sql, params = []) {
        queries.push({ sql, params });
        if (sql.includes('SELECT id FROM tenants')) return { rows: [] };
        return { rows: [] };
      },
    };

    const result = await seedLocalStagingTenant(client);
    assert.equal(result.seeded, true);
    assert.equal(result.tenantId, LOCAL_STAGING_DEMO_IDS.tenantId);
    assert.ok(queries.some((entry) => entry.sql.includes('INSERT INTO tenants')));
    assert.ok(queries.some((entry) => entry.sql.includes('INSERT INTO target_groups')));
  });

  it('is idempotent when tenant already exists', async () => {
    const client = {
      async query(sql) {
        if (sql.includes('SELECT id FROM tenants')) {
          return { rows: [{ id: LOCAL_STAGING_DEMO_IDS.tenantId }] };
        }
        return { rows: [] };
      },
    };

    const result = await seedLocalStagingTenant(client);
    assert.equal(result.seeded, false);
  });
});