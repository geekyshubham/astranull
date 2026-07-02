import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  createAuthTokenRepository,
  mapBootstrapTokenRow,
  mapServiceAccountRow,
} from '../../src/persistence/postgres/authTokenRepository.mjs';

const CTX = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };
const FIXED_NOW = '2026-06-01T12:00:00.000Z';
const TOKEN_ID = 'token_abc';
const SACC_ID = 'sacc_deadbeef';

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

function assertKeyedTenantIdLookup(sql, params, tenantId, id) {
  assert.match(sql, /WHERE tenant_id = \$1 AND id = \$2/);
  assert.deepEqual(params, [tenantId, id]);
  assert.doesNotMatch(sql, /FROM bootstrap_tokens\s*(?:\n|$)(?!.*WHERE)/s);
  assert.doesNotMatch(sql, /FROM service_accounts\s*(?:\n|$)(?!.*WHERE)/s);
}

const bootstrapRecord = {
  id: TOKEN_ID,
  tenant_id: CTX.tenantId,
  name: 'Install token',
  token_hash: 'hash_a',
  token_salt: 'salt_a',
  environment_id: 'env_demo',
  target_group_id: null,
  max_registrations: 2,
  registrations_used: 0,
  expires_at: FIXED_NOW,
  revoked_at: null,
  created_at: FIXED_NOW,
  created_by: CTX.userId,
};

const serviceAccountRecord = {
  id: SACC_ID,
  tenant_id: CTX.tenantId,
  name: 'CI bot',
  role: 'engineer',
  scopes: ['runs.read', 'runs.write'],
  secret_hash: 'shash',
  secret_salt: 'ssalt',
  expires_at: null,
  revoked_at: null,
  created_at: FIXED_NOW,
  created_by: CTX.userId,
  last_used_at: null,
};

describe('postgres auth token repository', () => {
  it('maps bootstrap and service account rows with ISO dates and arrays', () => {
    const token = mapBootstrapTokenRow({
      id: TOKEN_ID,
      tenant_id: CTX.tenantId,
      name: 'T',
      token_hash: 'h',
      token_salt: 's',
      environment_id: 'env_1',
      target_group_id: null,
      allowed_modes: null,
      max_registrations: '3',
      registrations_used: '1',
      allowed_cidrs: ['10.0.0.0/8'],
      expires_at: new Date(FIXED_NOW),
      revoked_at: null,
      created_by: 'usr_1',
      created_at: FIXED_NOW,
    });
    assert.equal(token.expires_at, FIXED_NOW);
    assert.equal(token.max_registrations, 3);
    assert.deepEqual(token.allowed_modes, []);
    assert.deepEqual(token.allowed_cidrs, ['10.0.0.0/8']);
    assert.equal(token.secret, undefined);

    const account = mapServiceAccountRow({
      id: SACC_ID,
      tenant_id: CTX.tenantId,
      name: 'A',
      role: 'viewer',
      scopes: ['audit.read'],
      secret_hash: 'x',
      secret_salt: 'y',
      expires_at: null,
      revoked_at: null,
      created_at: new Date(FIXED_NOW),
      created_by: 'usr_1',
      rotated_at: null,
      last_used_at: new Date('2026-06-02T00:00:00.000Z'),
    });
    assert.equal(account.created_at, FIXED_NOW);
    assert.equal(account.last_used_at, '2026-06-02T00:00:00.000Z');
    assert.deepEqual(account.scopes, ['audit.read']);
    assert.equal(account.secret, undefined);
  });

  it('createBootstrapToken inserts with tenant context and parameterized values', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('INSERT INTO bootstrap_tokens')) {
        assertUsesTenantPredicate(text, params, CTX.tenantId);
        assertNoInterpolatedValue(text, TOKEN_ID);
        assertNoInterpolatedValue(text, 'hash_a');
        return {
          rows: [
            {
              ...bootstrapRecord,
              allowed_modes: [],
              allowed_cidrs: [],
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createAuthTokenRepository(pool);
    const row = await repo.createBootstrapToken(CTX, bootstrapRecord);
    assert.equal(row.id, TOKEN_ID);
    assert.equal(row.token_hash, 'hash_a');
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('listBootstrapTokens scopes by tenant_id and orders by created_at', async () => {
    const pool = createRecordingPool((text) => {
      if (text.includes('FROM bootstrap_tokens')) {
        return {
          rows: [
            {
              ...bootstrapRecord,
              allowed_modes: [],
              allowed_cidrs: [],
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createAuthTokenRepository(pool);
    const items = await repo.listBootstrapTokens(CTX);
    assert.equal(items.length, 1);
    assertTenantWrapped(pool.client, CTX.tenantId);
    const [q] = dataQueries(pool.client);
    assertUsesTenantPredicate(q.text, q.params, CTX.tenantId);
    assert.match(q.text, /ORDER BY created_at/);
    assert.doesNotMatch(q.text, /secret/);
  });

  it('getBootstrapTokenById uses tenant and id predicates', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.includes('FROM bootstrap_tokens')) {
        assertUsesTenantPredicate(text, params, CTX.tenantId);
        assertNoInterpolatedValue(text, TOKEN_ID);
        return {
          rows: [{ ...bootstrapRecord, allowed_modes: [], allowed_cidrs: [] }],
        };
      }
      return { rows: [] };
    });
    const repo = createAuthTokenRepository(pool);
    const row = await repo.getBootstrapTokenById(CTX, TOKEN_ID);
    assert.equal(row.id, TOKEN_ID);
    assertTenantWrapped(pool.client, CTX.tenantId);
    assert.ok(pool.client.queries[2].params.includes(TOKEN_ID));
  });

  it('findBootstrapTokenByAddressedHint uses hint tenant context and keyed lookup', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.includes('FROM bootstrap_tokens')) {
        assertKeyedTenantIdLookup(text, params, CTX.tenantId, TOKEN_ID);
        return {
          rows: [{ ...bootstrapRecord, allowed_modes: [], allowed_cidrs: [] }],
        };
      }
      return { rows: [] };
    });
    const repo = createAuthTokenRepository(pool);
    const row = await repo.findBootstrapTokenByAddressedHint({
      tenantId: CTX.tenantId,
      id: TOKEN_ID,
    });
    assert.equal(row.tenant_id, CTX.tenantId);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('revokeBootstrapToken updates with tenant predicate', async () => {
    const revokedAt = '2026-06-02T09:00:00.000Z';
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('UPDATE bootstrap_tokens')) {
        assertUsesTenantPredicate(text, params, CTX.tenantId);
        assertNoInterpolatedValue(text, revokedAt);
        assert.equal(params[0], revokedAt);
        return {
          rows: [
            {
              ...bootstrapRecord,
              revoked_at: revokedAt,
              allowed_modes: [],
              allowed_cidrs: [],
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createAuthTokenRepository(pool);
    const row = await repo.revokeBootstrapToken(CTX, TOKEN_ID, revokedAt);
    assert.equal(row.revoked_at, revokedAt);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('incrementBootstrapTokenRegistrations increments under addressed tenant', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('UPDATE bootstrap_tokens') && !text.includes('revoked_at IS NULL')) {
        assert.match(text, /registrations_used = registrations_used \+ 1/);
        assertUsesTenantPredicate(text, params, CTX.tenantId);
        return {
          rows: [
            {
              ...bootstrapRecord,
              registrations_used: 1,
              allowed_modes: [],
              allowed_cidrs: [],
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createAuthTokenRepository(pool);
    const row = await repo.incrementBootstrapTokenRegistrations({
      tenantId: CTX.tenantId,
      id: TOKEN_ID,
    });
    assert.equal(row.registrations_used, 1);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('consumeBootstrapTokenRegistration performs gated atomic UPDATE with usedAt', async () => {
    const usedAt = '2026-06-01T12:00:00.000Z';
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('UPDATE bootstrap_tokens') && text.includes('revoked_at IS NULL')) {
        assert.match(text, /registrations_used = registrations_used \+ 1/);
        assert.match(text, /WHERE tenant_id = \$1 AND id = \$2/);
        assert.match(text, /revoked_at IS NULL/);
        assert.match(text, /expires_at >= \$3::timestamptz/);
        assert.match(text, /registrations_used < max_registrations/);
        assert.deepEqual(params, [CTX.tenantId, TOKEN_ID, usedAt]);
        assertNoInterpolatedValue(text, usedAt);
        return {
          rows: [
            {
              ...bootstrapRecord,
              registrations_used: 1,
              allowed_modes: [],
              allowed_cidrs: [],
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createAuthTokenRepository(pool);
    const row = await repo.consumeBootstrapTokenRegistration(
      { tenantId: CTX.tenantId, id: TOKEN_ID },
      usedAt,
    );
    assert.equal(row.registrations_used, 1);
    assert.equal(row.id, TOKEN_ID);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('consumeBootstrapTokenRegistration returns null when gated UPDATE matches no row', async () => {
    const usedAt = '2026-06-01T12:00:00.000Z';
    const pool = createRecordingPool((text) => {
      if (text.startsWith('UPDATE bootstrap_tokens') && text.includes('revoked_at IS NULL')) {
        return { rows: [] };
      }
      return { rows: [] };
    });
    const repo = createAuthTokenRepository(pool);
    const row = await repo.consumeBootstrapTokenRegistration(
      { tenantId: CTX.tenantId, id: TOKEN_ID },
      usedAt,
    );
    assert.equal(row, null);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('createServiceAccount inserts with tenant_id param', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('INSERT INTO service_accounts')) {
        assertUsesTenantPredicate(text, params, CTX.tenantId);
        assertNoInterpolatedValue(text, SACC_ID);
        assertNoInterpolatedValue(text, 'shash');
        return { rows: [serviceAccountRecord] };
      }
      return { rows: [] };
    });
    const repo = createAuthTokenRepository(pool);
    const row = await repo.createServiceAccount(CTX, serviceAccountRecord);
    assert.equal(row.id, SACC_ID);
    assert.deepEqual(row.scopes, serviceAccountRecord.scopes);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('listServiceAccounts scopes by tenant_id and orders by created_at', async () => {
    const pool = createRecordingPool((text) => {
      if (text.includes('FROM service_accounts')) {
        return { rows: [serviceAccountRecord] };
      }
      return { rows: [] };
    });
    const repo = createAuthTokenRepository(pool);
    const items = await repo.listServiceAccounts(CTX);
    assert.equal(items.length, 1);
    assertTenantWrapped(pool.client, CTX.tenantId);
    const [q] = dataQueries(pool.client);
    assertUsesTenantPredicate(q.text, q.params, CTX.tenantId);
    assert.match(q.text, /ORDER BY created_at/);
  });

  it('getServiceAccountById returns null when missing', async () => {
    const pool = createRecordingPool((text) => {
      if (text.includes('FROM service_accounts')) return { rows: [] };
      return { rows: [] };
    });
    const repo = createAuthTokenRepository(pool);
    assert.equal(await repo.getServiceAccountById(CTX, 'sacc_missing'), null);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('findServiceAccountByAddressedHint uses keyed lookup without scan', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.includes('FROM service_accounts') && text.includes('WHERE tenant_id = $1 AND id = $2')) {
        assertKeyedTenantIdLookup(text, params, CTX.tenantId, SACC_ID);
        return { rows: [serviceAccountRecord] };
      }
      return { rows: [] };
    });
    const repo = createAuthTokenRepository(pool);
    const row = await repo.findServiceAccountByAddressedHint({
      tenantId: CTX.tenantId,
      id: SACC_ID,
    });
    assert.equal(row.id, SACC_ID);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('revokeServiceAccount updates revoked_at with tenant predicate', async () => {
    const revokedAt = '2026-06-03T10:00:00.000Z';
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('UPDATE service_accounts') && text.includes('revoked_at')) {
        assertUsesTenantPredicate(text, params, CTX.tenantId);
        return { rows: [{ ...serviceAccountRecord, revoked_at: revokedAt }] };
      }
      return { rows: [] };
    });
    const repo = createAuthTokenRepository(pool);
    const row = await repo.revokeServiceAccount(CTX, SACC_ID, revokedAt);
    assert.equal(row.revoked_at, revokedAt);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('rotateServiceAccountSecret clears last_used_at and updates hash fields', async () => {
    const rotatedAt = '2026-06-04T11:00:00.000Z';
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('UPDATE service_accounts') && text.includes('secret_hash')) {
        assert.match(text, /last_used_at = NULL/i);
        assertUsesTenantPredicate(text, params, CTX.tenantId);
        assert.equal(params[0], 'new_hash');
        assert.equal(params[1], 'new_salt');
        assert.equal(params[2], rotatedAt);
        return {
          rows: [
            {
              ...serviceAccountRecord,
              secret_hash: 'new_hash',
              secret_salt: 'new_salt',
              rotated_at: rotatedAt,
              last_used_at: null,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createAuthTokenRepository(pool);
    const row = await repo.rotateServiceAccountSecret(CTX, SACC_ID, {
      secret_hash: 'new_hash',
      secret_salt: 'new_salt',
      rotated_at: rotatedAt,
    });
    assert.equal(row.secret_hash, 'new_hash');
    assert.equal(row.last_used_at, null);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('recordServiceAccountLastUsed updates under addressed tenant context', async () => {
    const usedAt = '2026-06-05T12:00:00.000Z';
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('UPDATE service_accounts') && text.includes('last_used_at')) {
        assertUsesTenantPredicate(text, params, CTX.tenantId);
        assert.equal(params[0], usedAt);
        return { rows: [{ ...serviceAccountRecord, last_used_at: usedAt }] };
      }
      return { rows: [] };
    });
    const repo = createAuthTokenRepository(pool);
    const row = await repo.recordServiceAccountLastUsed(
      { tenantId: CTX.tenantId, id: SACC_ID },
      usedAt,
    );
    assert.equal(row.last_used_at, usedAt);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('rolls back when a tenant-scoped query fails inside tenant context', async () => {
    const pool = createRecordingPool((text) => {
      if (text.includes('FROM bootstrap_tokens')) {
        throw new Error('db read failed');
      }
      return { rows: [] };
    });
    const repo = createAuthTokenRepository(pool);
    await assert.rejects(() => repo.getBootstrapTokenById(CTX, TOKEN_ID), /db read failed/);
    assert.ok(pool.client.queries.some((q) => q.text.trim() === 'ROLLBACK'));
    assert.ok(!pool.client.queries.some((q) => q.text.trim() === 'COMMIT'));
    assert.equal(pool.client.released, true);
  });
});