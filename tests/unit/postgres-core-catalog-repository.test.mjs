import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';
import {
  createCoreCatalogRepository,
  mapEnvironmentRow,
  mapTargetGroupRow,
  mapTargetRow,
  mapTenantRow,
} from '../../src/persistence/postgres/coreCatalogRepository.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '../..');
const CORE_CATALOG_REPO_SOURCE = readFileSync(
  path.join(ROOT, 'src/persistence/postgres/coreCatalogRepository.mjs'),
  'utf8',
);

const CTX = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };
const FIXED_NOW = '2026-06-01T12:00:00.000Z';

function createRecordingPool(handler) {
  const client = {
    queries: [],
    released: false,
    failOn: null,
    async query(text, params) {
      this.queries.push({ text, params });
      if (this.failOn && this.failOn(text)) {
        throw new Error('simulated query failure');
      }
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

function assertUsesTenantPredicate(sql, params, tenantId) {
  const hasWherePredicate = /tenant_id\s*=\s*\$\d+/i.test(sql);
  const hasInsertColumn = /INSERT\s+INTO\s+\w+\s*\([^)]*tenant_id/i.test(sql);
  assert.ok(
    hasWherePredicate || hasInsertColumn,
    `expected tenant_id predicate or INSERT column in: ${sql}`,
  );
  assert.ok(params.includes(tenantId), `expected tenant id in params for: ${sql}`);
}

function assertNoInterpolatedValue(sql, value) {
  if (value == null || value === '') return;
  assert.ok(!sql.includes(String(value)), `value must not be interpolated into SQL: ${value}`);
}

describe('postgres core catalog repository', () => {
  it('does not reference dev store or safeTestPolicy service module in source', () => {
    assert.equal(/\bservices\/safeTestPolicy\b/.test(CORE_CATALOG_REPO_SOURCE), false);
    assert.equal(/\bgetStore\b/.test(CORE_CATALOG_REPO_SOURCE), false);
    assert.equal(/\bpersistStore\b/.test(CORE_CATALOG_REPO_SOURCE), false);
  });

  it('maps tenant, environment, target group, and target rows', () => {
    const tenant = mapTenantRow({
      id: 'ten_demo',
      name: 'Demo',
      privacy_settings: {},
      created_at: new Date(FIXED_NOW),
    });
    assert.equal(tenant.id, 'ten_demo');
    assert.equal(tenant.privacy_settings.metadata_retention_days, 90);

    const env = mapEnvironmentRow({
      id: 'env_1',
      tenant_id: 'ten_demo',
      name: 'Prod',
      status: 'active',
      privacy_settings: {},
      settings_json: { description: 'desc', created_by: 'usr_admin', updated_at: FIXED_NOW },
      created_at: FIXED_NOW,
    });
    assert.equal(env.description, 'desc');
    assert.equal(env.created_by, 'usr_admin');
    assert.equal(env.updated_at, FIXED_NOW);

    const group = mapTargetGroupRow({
      id: 'tg_1',
      tenant_id: 'ten_demo',
      environment_id: 'env_1',
      name: 'G',
      safety_policy: {},
      safe_test_windows: [{ start_at: FIXED_NOW, end_at: FIXED_NOW }],
      created_at: FIXED_NOW,
    });
    assert.equal(group.safety_policy.max_runs_per_hour, 60);
    assert.equal(group.timezone, 'UTC');

    const target = mapTargetRow({
      id: 'tgt_1',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_1',
      kind: 'fqdn',
      value: 'a.example',
      metadata_json: { note: 'x' },
      created_at: FIXED_NOW,
    });
    assert.deepEqual(target.metadata, { note: 'x' });
  });

  it('getCurrentTenant uses tenant context and parameterized tenant id', async () => {
    const pool = createRecordingPool((text) => {
      if (text.includes('FROM tenants')) {
        return {
          rows: [
            {
              id: 'ten_demo',
              name: 'Demo Organization',
              privacy_settings: {},
              created_at: FIXED_NOW,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createCoreCatalogRepository(pool);
    const tenant = await repo.getCurrentTenant(CTX);
    assert.equal(tenant.name, 'Demo Organization');
    assertTenantWrapped(pool.client, CTX.tenantId);
    const [q] = dataQueries(pool.client);
    assert.match(q.text, /WHERE id = \$1/);
    assert.deepEqual(q.params, [CTX.tenantId]);
    assertNoInterpolatedValue(q.text, CTX.tenantId);
  });

  it('getCurrentTenant returns null when row missing', async () => {
    const pool = createRecordingPool(() => ({ rows: [] }));
    const repo = createCoreCatalogRepository(pool);
    assert.equal(await repo.getCurrentTenant(CTX), null);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('patchCurrentTenant returns null when tenant missing and only selects', async () => {
    const pool = createRecordingPool((text) => {
      if (text.includes('FROM tenants')) return { rows: [] };
      return { rows: [] };
    });
    const repo = createCoreCatalogRepository(pool);
    assert.equal(await repo.patchCurrentTenant(CTX, { name: 'x' }), null);
    assertTenantWrapped(pool.client, CTX.tenantId);
    const selects = dataQueries(pool.client).filter((q) => q.text.includes('SELECT'));
    assert.equal(selects.length, 1);
    assert.match(selects[0].text, /FROM tenants/);
    assert.match(selects[0].text, /WHERE id = \$1/);
    assert.deepEqual(selects[0].params, [CTX.tenantId]);
    assertNoInterpolatedValue(selects[0].text, CTX.tenantId);
    assert.ok(!dataQueries(pool.client).some((q) => q.text.startsWith('UPDATE tenants')));
  });

  it('patchCurrentTenant no-op returns current tenant without UPDATE', async () => {
    const pool = createRecordingPool((text) => {
      if (text.includes('FROM tenants')) {
        return {
          rows: [
            {
              id: 'ten_demo',
              name: 'Demo Organization',
              privacy_settings: {},
              created_at: FIXED_NOW,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createCoreCatalogRepository(pool);
    const tenant = await repo.patchCurrentTenant(CTX, {});
    assert.equal(tenant.name, 'Demo Organization');
    assertTenantWrapped(pool.client, CTX.tenantId);
    assert.ok(!dataQueries(pool.client).some((q) => q.text.startsWith('UPDATE tenants')));
  });

  it('patchCurrentTenant updates name and merged normalized privacy settings', async () => {
    const existingPrivacy = {
      evidence_retention: { legal_hold: true },
    };
    const pool = createRecordingPool((text, params) => {
      if (text.includes('FROM tenants') && text.includes('SELECT')) {
        return {
          rows: [
            {
              id: 'ten_demo',
              name: 'Old Name',
              privacy_settings: existingPrivacy,
              created_at: FIXED_NOW,
            },
          ],
        };
      }
      if (text.startsWith('UPDATE tenants')) {
        assert.match(text, /name = \$1/);
        assert.match(text, /privacy_settings = \$2::jsonb/);
        assert.match(text, /WHERE id = \$3/);
        assert.deepEqual(params[0], 'New Name');
        assertNoInterpolatedValue(text, 'New Name');
        assertNoInterpolatedValue(text, CTX.tenantId);
        const merged = JSON.parse(params[1]);
        assert.equal(merged.metadata_retention_days, 3650);
        assert.equal(merged.evidence_retention.legal_hold, true);
        assert.deepEqual(params[2], CTX.tenantId);
        return {
          rows: [
            {
              id: 'ten_demo',
              name: params[0],
              privacy_settings: merged,
              created_at: FIXED_NOW,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createCoreCatalogRepository(pool);
    const tenant = await repo.patchCurrentTenant(CTX, {
      name: 'New Name',
      privacy_settings: { metadata_retention_days: 5000 },
    });
    assert.equal(tenant.name, 'New Name');
    assert.equal(tenant.privacy_settings.metadata_retention_days, 3650);
    assert.equal(tenant.privacy_settings.evidence_retention.legal_hold, true);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('patchCurrentTenant enforces retention in the same tenant transaction when privacy changes', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.includes('FROM tenants') && text.includes('SELECT')) {
        return {
          rows: [
            {
              id: 'ten_demo',
              name: 'Old Name',
              privacy_settings: { metadata_retention_days: 30 },
              created_at: FIXED_NOW,
            },
          ],
        };
      }
      if (text.startsWith('UPDATE tenants')) {
        return {
          rows: [
            {
              id: 'ten_demo',
              name: 'Old Name',
              privacy_settings: JSON.parse(params[0]),
              created_at: FIXED_NOW,
            },
          ],
        };
      }
      if (text.includes('FROM events') && text.includes('COUNT(*)')) return { rows: [{ count: '1' }] };
      if (text.includes('FROM evidence_vault') && text.includes('COUNT(*)')) {
        return { rows: [{ count: '0' }] };
      }
      if (text.includes('FROM reports') && text.includes('COUNT(*)')) return { rows: [{ count: '0' }] };
      if (text.includes('FROM notification_events') && text.includes('COUNT(*)')) {
        return { rows: [{ count: '0' }] };
      }
      if (text.startsWith('DELETE FROM events')) return { rowCount: 1, rows: [] };
      if (text.startsWith('DELETE FROM evidence_vault')) return { rowCount: 0, rows: [] };
      if (text.startsWith('DELETE FROM reports')) return { rowCount: 0, rows: [] };
      if (text.startsWith('DELETE FROM notification_events')) return { rowCount: 0, rows: [] };
      if (text.includes('pg_advisory_xact_lock(hashtext($1))')) return { rows: [] };
      if (text.includes('FROM audit_logs') && text.includes('ORDER BY sequence DESC')) {
        return { rows: [] };
      }
      if (text.startsWith('INSERT INTO audit_logs')) return { rows: [] };
      return { rows: [] };
    });
    const repo = createCoreCatalogRepository(pool);
    const tenant = await repo.patchCurrentTenant(
      CTX,
      { privacy_settings: { metadata_retention_days: 7 } },
      { now: FIXED_NOW },
    );

    assert.equal(tenant.privacy_settings.metadata_retention_days, 7);
    assertTenantWrapped(pool.client, CTX.tenantId);
    const dataSql = dataQueries(pool.client).map((q) => q.text);
    assert.ok(dataSql.some((sql) => sql.includes('DELETE FROM events')));
    assert.ok(dataSql.some((sql) => sql.includes('INSERT INTO audit_logs')));
  });

  it('listEnvironments filters archived and scopes tenant', async () => {
    const pool = createRecordingPool((text) => {
      if (text.includes('FROM environments')) {
        return {
          rows: [
            {
              id: 'env_1',
              tenant_id: 'ten_demo',
              name: 'Prod',
              status: 'active',
              privacy_settings: {},
              settings_json: {},
              created_at: FIXED_NOW,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createCoreCatalogRepository(pool);
    const items = await repo.listEnvironments(CTX);
    assert.equal(items.length, 1);
    assertTenantWrapped(pool.client, CTX.tenantId);
    const [q] = dataQueries(pool.client);
    assertUsesTenantPredicate(q.text, q.params, CTX.tenantId);
    assert.match(q.text, /status <> \$\d+/);
    assert.equal(q.params.includes('archived'), true);
  });

  it('createEnvironment inserts with tenant_id param and maps settings_json', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('INSERT INTO environments')) {
        assertUsesTenantPredicate(text, params, CTX.tenantId);
        assertNoInterpolatedValue(text, 'My Env');
        return {
          rows: [
            {
              id: params[0],
              tenant_id: params[1],
              name: params[2],
              status: 'active',
              privacy_settings: JSON.parse(params[4]),
              settings_json: JSON.parse(params[5]),
              created_at: params[6],
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createCoreCatalogRepository(pool);
    const env = await repo.createEnvironment(
      CTX,
      { name: 'My Env', description: 'line', privacy_settings: { metadata_retention_days: 30 } },
      { id: 'env_test', now: FIXED_NOW },
    );
    assert.equal(env.id, 'env_test');
    assert.equal(env.description, 'line');
    assert.equal(env.created_by, CTX.userId);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('patchEnvironment returns null when not found', async () => {
    const pool = createRecordingPool((text) => {
      if (text.includes('FROM environments')) return { rows: [] };
      return { rows: [] };
    });
    const repo = createCoreCatalogRepository(pool);
    assert.equal(await repo.patchEnvironment(CTX, 'env_missing', { name: 'x' }), null);
    assertTenantWrapped(pool.client, CTX.tenantId);
    const selects = dataQueries(pool.client).filter((q) => q.text.includes('SELECT'));
    assert.equal(selects.length, 1);
    assertUsesTenantPredicate(selects[0].text, selects[0].params, CTX.tenantId);
    assertNoInterpolatedValue(selects[0].text, 'env_missing');
    assert.ok(selects[0].params.includes('env_missing'));
  });

  it('patchEnvironment updates with tenant predicate', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.includes('FROM environments')) {
        return {
          rows: [
            {
              id: 'env_1',
              tenant_id: 'ten_demo',
              name: 'Old',
              status: 'active',
              privacy_settings: {},
              settings_json: { description: '' },
              created_at: FIXED_NOW,
            },
          ],
        };
      }
      if (text.startsWith('UPDATE environments')) {
        assertUsesTenantPredicate(text, params, CTX.tenantId);
        assertNoInterpolatedValue(text, 'env_1');
        return {
          rows: [
            {
              id: 'env_1',
              tenant_id: 'ten_demo',
              name: 'New',
              status: 'active',
              privacy_settings: {},
              settings_json: { description: 'd', updated_at: FIXED_NOW },
              created_at: FIXED_NOW,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createCoreCatalogRepository(pool);
    const env = await repo.patchEnvironment(
      CTX,
      'env_1',
      { name: 'New', description: 'd' },
      { now: FIXED_NOW },
    );
    assert.equal(env.name, 'New');
    assert.equal(env.updated_at, FIXED_NOW);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('listTargetGroups scopes by tenant_id', async () => {
    const pool = createRecordingPool((text) => {
      if (text.includes('FROM target_groups')) {
        return {
          rows: [
            {
              id: 'tg_1',
              tenant_id: 'ten_demo',
              environment_id: 'env_1',
              name: 'G',
              safety_policy: {},
              safe_test_windows: [],
              created_at: FIXED_NOW,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createCoreCatalogRepository(pool);
    const groups = await repo.listTargetGroups(CTX);
    assert.equal(groups.length, 1);
    assertTenantWrapped(pool.client, CTX.tenantId);
    const [q] = dataQueries(pool.client);
    assertUsesTenantPredicate(q.text, q.params, CTX.tenantId);
  });

  it('getTargetGroup returns null when group missing', async () => {
    const pool = createRecordingPool((text) => {
      if (text.includes('FROM target_groups')) return { rows: [] };
      return { rows: [] };
    });
    const repo = createCoreCatalogRepository(pool);
    assert.equal(await repo.getTargetGroup(CTX, 'tg_missing'), null);
    assertTenantWrapped(pool.client, CTX.tenantId);
    const groupQ = dataQueries(pool.client)[0];
    assertUsesTenantPredicate(groupQ.text, groupQ.params, CTX.tenantId);
    assertNoInterpolatedValue(groupQ.text, 'tg_missing');
  });

  it('getTargetGroup returns group with targets array', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.includes('FROM target_groups')) {
        return {
          rows: [
            {
              id: 'tg_1',
              tenant_id: 'ten_demo',
              environment_id: 'env_1',
              name: 'G',
              safety_policy: {},
              safe_test_windows: [],
              created_at: FIXED_NOW,
            },
          ],
        };
      }
      if (text.includes('FROM targets')) {
        assertUsesTenantPredicate(text, params, CTX.tenantId);
        assertNoInterpolatedValue(text, 'tg_1');
        return {
          rows: [
            {
              id: 'tgt_1',
              tenant_id: 'ten_demo',
              target_group_id: 'tg_1',
              kind: 'fqdn',
              value: 'origin.example',
              created_at: FIXED_NOW,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createCoreCatalogRepository(pool);
    const group = await repo.getTargetGroup(CTX, 'tg_1');
    assert.equal(group.id, 'tg_1');
    assert.equal(group.targets.length, 1);
    assert.equal(group.targets[0].value, 'origin.example');
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('createTargetGroup inserts tenant-scoped row with normalized policy', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('INSERT INTO target_groups')) {
        assertUsesTenantPredicate(text, params, CTX.tenantId);
        assertNoInterpolatedValue(text, 'tg_new');
        return {
          rows: [
            {
              id: params[0],
              tenant_id: params[1],
              environment_id: params[2],
              name: params[3],
              description: params[4],
              expected_behavior_default: params[5],
              timezone: params[6],
              safe_test_windows: JSON.parse(params[7]),
              safety_policy: JSON.parse(params[8]),
              created_at: params[9],
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createCoreCatalogRepository(pool);
    const group = await repo.createTargetGroup(
      CTX,
      { name: 'Origin', safety_policy: { max_runs_per_hour: 10 } },
      { id: 'tg_new', now: FIXED_NOW },
    );
    assert.equal(group.id, 'tg_new');
    assert.equal(group.safety_policy.max_runs_per_hour, 10);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('addTarget returns null when group missing', async () => {
    const pool = createRecordingPool((text) => {
      if (text.includes('FROM target_groups')) return { rows: [] };
      return { rows: [] };
    });
    const repo = createCoreCatalogRepository(pool);
    assert.equal(await repo.addTarget(CTX, 'tg_missing', { value: 'a.example' }), null);
    assertTenantWrapped(pool.client, CTX.tenantId);
    const [q] = dataQueries(pool.client);
    assertUsesTenantPredicate(q.text, q.params, CTX.tenantId);
  });

  it('addTarget inserts with tenant_id and group id params', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.includes('FROM target_groups')) {
        return { rows: [{ id: 'tg_1', expected_behavior_default: 'must_block_before_origin' }] };
      }
      if (text.startsWith('INSERT INTO targets')) {
        assertUsesTenantPredicate(text, params, CTX.tenantId);
        assertNoInterpolatedValue(text, 'origin.demo.example');
        assert.ok(params.includes('tg_1'));
        return {
          rows: [
            {
              id: params[0],
              tenant_id: params[1],
              target_group_id: params[2],
              kind: params[3],
              value: params[4],
              expected_behavior: params[5],
              metadata_json: JSON.parse(params[6]),
              created_at: params[7],
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createCoreCatalogRepository(pool);
    const target = await repo.addTarget(
      CTX,
      'tg_1',
      { value: 'origin.demo.example' },
      { id: 'tgt_new', now: FIXED_NOW },
    );
    assert.equal(target.id, 'tgt_new');
    assert.equal(target.expected_behavior, 'must_block_before_origin');
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('rolls back when a catalog query fails inside tenant context', async () => {
    const pool = createRecordingPool((text) => {
      if (text.includes('FROM target_groups')) {
        throw new Error('db read failed');
      }
      return { rows: [] };
    });
    const repo = createCoreCatalogRepository(pool);
    await assert.rejects(() => repo.getTargetGroup(CTX, 'tg_1'), /db read failed/);
    assert.ok(pool.client.queries.some((q) => q.text.trim() === 'ROLLBACK'));
    assert.ok(!pool.client.queries.some((q) => q.text.trim() === 'COMMIT'));
    assert.equal(pool.client.released, true);
  });
});
