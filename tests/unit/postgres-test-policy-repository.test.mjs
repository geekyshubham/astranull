import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';
import {
  createPostgresTestPolicyRepository,
  mapTestPolicyRow,
} from '../../src/persistence/postgres/testPolicyRepository.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '../..');
const TEST_POLICY_REPO_SOURCE = readFileSync(
  path.join(ROOT, 'src/persistence/postgres/testPolicyRepository.mjs'),
  'utf8',
);

const CTX = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };
const FIXED_NOW = '2026-06-01T12:00:00.000Z';
const POLICY_ID = 'policy_1';

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

function policyRow(overrides = {}) {
  return {
    id: POLICY_ID,
    tenant_id: CTX.tenantId,
    target_group_id: 'tg_1',
    check_id: 'dns.authoritative_response.safe',
    cadence: 'weekly',
    expected_verdict: 'pass',
    safe_windows: [{ day: 'Mon', start: '09:00', end: '11:00', timezone: 'UTC' }],
    state: 'active',
    safety_policy_snapshot: { target_group_safety_policy: null },
    archived_at: null,
    created_at: FIXED_NOW,
    updated_at: FIXED_NOW,
    ...overrides,
  };
}

describe('postgres test policy repository', () => {
  it('does not reference the dev store in source', () => {
    assert.equal(/\bgetStore\b/.test(TEST_POLICY_REPO_SOURCE), false);
    assert.equal(/\bpersistStore\b/.test(TEST_POLICY_REPO_SOURCE), false);
  });

  it('maps rows into normalized policy objects', () => {
    const mapped = mapTestPolicyRow(policyRow({ archived_at: null, created_at: new Date(FIXED_NOW) }));
    assert.equal(mapped.id, POLICY_ID);
    assert.equal(mapped.cadence, 'weekly');
    assert.deepEqual(mapped.safe_windows, [{ day: 'Mon', start: '09:00', end: '11:00', timezone: 'UTC' }]);
    assert.equal(mapped.created_at, FIXED_NOW);
    assert.equal('archived_at' in mapped, false);

    const archived = mapTestPolicyRow(policyRow({ archived_at: FIXED_NOW }));
    assert.equal(archived.archived_at, FIXED_NOW);
  });

  it('listTestPolicies scopes to tenant and excludes archived rows', async () => {
    const pool = createRecordingPool((text) => {
      if (text.includes('FROM test_policies')) return { rows: [policyRow()] };
      return { rows: [] };
    });
    const repo = createPostgresTestPolicyRepository(pool);
    const items = await repo.listTestPolicies(CTX);
    assert.equal(items.length, 1);
    assertTenantWrapped(pool.client, CTX.tenantId);
    const [q] = dataQueries(pool.client);
    assertUsesTenantPredicate(q.text, q.params, CTX.tenantId);
    assert.match(q.text, /archived_at IS NULL/);
  });

  it('getActiveTestPolicy filters by id, tenant, and archived_at', async () => {
    const pool = createRecordingPool((text) => {
      if (text.includes('FROM test_policies')) return { rows: [policyRow()] };
      return { rows: [] };
    });
    const repo = createPostgresTestPolicyRepository(pool);
    const policy = await repo.getActiveTestPolicy(CTX, POLICY_ID);
    assert.equal(policy.id, POLICY_ID);
    assertTenantWrapped(pool.client, CTX.tenantId);
    const [q] = dataQueries(pool.client);
    assertUsesTenantPredicate(q.text, q.params, CTX.tenantId);
    assert.match(q.text, /WHERE id = \$1 AND tenant_id = \$2 AND archived_at IS NULL/);
    assertNoInterpolatedValue(q.text, POLICY_ID);
    assert.ok(q.params.includes(POLICY_ID));
  });

  it('createTestPolicy inserts a tenant-scoped row with parameterized values', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('INSERT INTO test_policies')) {
        assertUsesTenantPredicate(text, params, CTX.tenantId);
        assertNoInterpolatedValue(text, POLICY_ID);
        return {
          rows: [
            policyRow({
              id: params[0],
              tenant_id: params[1],
              target_group_id: params[2],
              check_id: params[3],
              cadence: params[4],
              expected_verdict: params[5],
              safe_windows: JSON.parse(params[6]),
              state: params[7],
              safety_policy_snapshot: JSON.parse(params[8]),
              created_at: params[9],
              updated_at: params[10],
            }),
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createPostgresTestPolicyRepository(pool);
    const created = await repo.createTestPolicy(CTX, {
      id: POLICY_ID,
      tenant_id: CTX.tenantId,
      target_group_id: 'tg_1',
      check_id: 'dns.authoritative_response.safe',
      cadence: 'weekly',
      expected_verdict: 'pass',
      safe_windows: [{ day: 'Mon', start: '09:00', end: '11:00', timezone: 'UTC' }],
      state: 'active',
      safety_policy_snapshot: { target_group_safety_policy: null },
      created_at: FIXED_NOW,
      updated_at: FIXED_NOW,
    });
    assert.equal(created.id, POLICY_ID);
    assert.equal(created.cadence, 'weekly');
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('updateTestPolicy sets provided fields plus updated_at under a tenant + active predicate', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('UPDATE test_policies')) {
        assertUsesTenantPredicate(text, params, CTX.tenantId);
        assert.match(text, /cadence = \$1/);
        assert.match(text, /updated_at = \$\d+::timestamptz/);
        assert.match(text, /archived_at IS NULL/);
        return { rows: [policyRow({ cadence: 'monthly', expected_verdict: 'warn' })] };
      }
      return { rows: [] };
    });
    const repo = createPostgresTestPolicyRepository(pool);
    const updated = await repo.updateTestPolicy(CTX, POLICY_ID, {
      cadence: 'monthly',
      expected_verdict: 'warn',
      updated_at: FIXED_NOW,
    });
    assert.equal(updated.cadence, 'monthly');
    assert.equal(updated.expected_verdict, 'warn');
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('archiveTestPolicy marks archived under tenant + active predicate', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('UPDATE test_policies')) {
        assertUsesTenantPredicate(text, params, CTX.tenantId);
        assert.match(text, /state = 'archived'/);
        assert.match(text, /archived_at = \$3::timestamptz/);
        assert.match(text, /archived_at IS NULL/);
        return { rows: [policyRow({ state: 'archived', archived_at: FIXED_NOW })] };
      }
      return { rows: [] };
    });
    const repo = createPostgresTestPolicyRepository(pool);
    const archived = await repo.archiveTestPolicy(CTX, POLICY_ID, { now: FIXED_NOW });
    assert.equal(archived.state, 'archived');
    assert.equal(archived.archived_at, FIXED_NOW);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('returns null when update/archive affect no active row', async () => {
    const pool = createRecordingPool(() => ({ rows: [] }));
    const repo = createPostgresTestPolicyRepository(pool);
    assert.equal(await repo.updateTestPolicy(CTX, 'policy_missing', { cadence: 'daily' }), null);
    assert.equal(await repo.archiveTestPolicy(CTX, 'policy_missing'), null);
  });
});
