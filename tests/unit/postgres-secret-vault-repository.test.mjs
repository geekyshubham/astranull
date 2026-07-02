import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { describe, it } from 'node:test';
import {
  createSecretVaultRepository,
  mapEncryptedSecretRow,
} from '../../src/persistence/postgres/secretVaultRepository.mjs';
import { encryptSecret } from '../../src/lib/secrets.mjs';

const CTX = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };
const FIXED_NOW = '2026-06-01T12:00:00.000Z';
const SECRET_ID = 'secret_abc';
const ENC_KEY = randomBytes(32);

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
  const hasInsertColumn = /INSERT\s+INTO\s+encrypted_secrets\s*\([^)]*tenant_id/i.test(sql);
  assert.ok(
    hasWherePredicate || hasInsertColumn,
    `expected tenant_id predicate or INSERT column in: ${sql}`,
  );
  assert.ok(params.includes(tenantId), `expected tenant id in params for: ${sql}`);
}

const sampleEnvelope = encryptSecret('vault-plaintext', ENC_KEY, {
  id: SECRET_ID,
  tenant_id: CTX.tenantId,
  purpose: 'webhook',
  name: 'primary',
  rotation: 0,
});

describe('postgres secret vault repository', () => {
  it('maps encrypted secret rows with metadata and envelope JSON', () => {
    const mapped = mapEncryptedSecretRow({
      id: SECRET_ID,
      tenant_id: CTX.tenantId,
      purpose: 'webhook',
      name: 'primary',
      metadata_json: { env: 'prod' },
      rotation: '2',
      envelope_json: sampleEnvelope,
      created_at: new Date(FIXED_NOW),
      updated_at: FIXED_NOW,
      created_by: CTX.userId,
    });
    assert.equal(mapped.id, SECRET_ID);
    assert.deepEqual(mapped.metadata, { env: 'prod' });
    assert.deepEqual(mapped.envelope, sampleEnvelope);
    assert.equal(mapped.rotation, 2);
    assert.equal(mapped.created_at, FIXED_NOW);
    assert.equal(mapped.updated_at, FIXED_NOW);
  });

  it('createEncryptedSecret inserts envelope JSON only with tenant context', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/INSERT INTO encrypted_secrets/i.test(sql)) {
        assertUsesTenantPredicate(sql, params, CTX.tenantId);
        assert.match(sql, /envelope_json/i);
        assert.ok(!params.some((p) => typeof p === 'string' && p.includes('vault-plaintext')));
        const envelopeParam = params.find((p) => typeof p === 'string' && p.includes('ciphertext'));
        assert.ok(envelopeParam);
        return {
          rows: [
            {
              id: SECRET_ID,
              tenant_id: CTX.tenantId,
              purpose: 'webhook',
              name: 'primary',
              metadata_json: {},
              rotation: 0,
              envelope_json: sampleEnvelope,
              created_at: FIXED_NOW,
              updated_at: FIXED_NOW,
              created_by: CTX.userId,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createSecretVaultRepository(pool);
    const record = await repo.createEncryptedSecret(CTX, {
      id: SECRET_ID,
      purpose: 'webhook',
      name: 'primary',
      metadata: {},
      rotation: 0,
      envelope: sampleEnvelope,
      created_at: FIXED_NOW,
      updated_at: FIXED_NOW,
      created_by: CTX.userId,
    });
    assert.equal(record.id, SECRET_ID);
    assertTenantWrapped(pool.client, CTX.tenantId);
    assert.equal(dataQueries(pool.client).length, 1);
  });

  it('listEncryptedSecrets scopes by tenant_id', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/FROM encrypted_secrets/i.test(sql)) {
        assertUsesTenantPredicate(sql, params, CTX.tenantId);
        return { rows: [] };
      }
      return { rows: [] };
    });
    const repo = createSecretVaultRepository(pool);
    const items = await repo.listEncryptedSecrets(CTX);
    assert.deepEqual(items, []);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('getEncryptedSecretById uses tenant_id and id predicates', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/FROM encrypted_secrets/i.test(sql)) {
        assert.match(sql, /WHERE tenant_id = \$1 AND id = \$2/);
        assert.deepEqual(params, [CTX.tenantId, SECRET_ID]);
        return {
          rows: [
            {
              id: SECRET_ID,
              tenant_id: CTX.tenantId,
              purpose: 'webhook',
              name: 'primary',
              metadata_json: {},
              rotation: 1,
              envelope_json: sampleEnvelope,
              created_at: FIXED_NOW,
              updated_at: FIXED_NOW,
              created_by: CTX.userId,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createSecretVaultRepository(pool);
    const row = await repo.getEncryptedSecretById(CTX, SECRET_ID);
    assert.equal(row.rotation, 1);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('updateEncryptedSecret rotates envelope under tenant_id and id', async () => {
    const rotatedEnvelope = encryptSecret('rotated', ENC_KEY, {
      id: SECRET_ID,
      tenant_id: CTX.tenantId,
      purpose: 'webhook',
      name: 'primary',
      rotation: 2,
    });
    const pool = createRecordingPool((sql, params) => {
      if (/UPDATE encrypted_secrets/i.test(sql)) {
        assert.match(sql, /WHERE tenant_id = \$1 AND id = \$2/);
        assert.deepEqual(params.slice(0, 2), [CTX.tenantId, SECRET_ID]);
        assert.ok(!params.some((p) => typeof p === 'string' && p === 'rotated'));
        return {
          rows: [
            {
              id: SECRET_ID,
              tenant_id: CTX.tenantId,
              purpose: 'webhook',
              name: 'primary',
              metadata_json: { env: 'prod' },
              rotation: 2,
              envelope_json: rotatedEnvelope,
              created_at: FIXED_NOW,
              updated_at: '2026-06-02T00:00:00.000Z',
              created_by: CTX.userId,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createSecretVaultRepository(pool);
    const updated = await repo.updateEncryptedSecret(CTX, SECRET_ID, {
      metadata: { env: 'prod' },
      rotation: 2,
      envelope: rotatedEnvelope,
      updated_at: '2026-06-02T00:00:00.000Z',
    });
    assert.equal(updated.rotation, 2);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });
});