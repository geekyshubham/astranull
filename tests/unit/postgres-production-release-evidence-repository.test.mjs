import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  createProductionReleaseEvidenceRepository,
  mapProductionReleaseEvidenceRow,
} from '../../src/persistence/postgres/productionReleaseEvidenceRepository.mjs';

const CTX = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };
const FIXED_NOW = '2026-07-02T12:00:00.000Z';

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
    const text = q.text.trim();
    return text !== 'BEGIN' &&
      text !== 'COMMIT' &&
      text !== 'ROLLBACK' &&
      !text.startsWith("SELECT set_config('app.tenant_id'");
  });
}

function assertTenantWrapped(client) {
  assert.equal(client.queries[0].text.trim(), 'BEGIN');
  assert.equal(client.queries[1].text.trim(), "SELECT set_config('app.tenant_id', $1, true)");
  assert.deepEqual(client.queries[1].params, [CTX.tenantId]);
  assert.equal(client.queries.at(-1).text.trim(), 'COMMIT');
  assert.equal(client.released, true);
}

function assertTenantScoped(sql, params) {
  const hasTenantPredicate = /tenant_id\s*=\s*\$\d+/i.test(sql);
  const hasInsertTenantColumn =
    /INSERT\s+INTO\s+production_release_evidence\s*\([\s\S]*tenant_id/i.test(sql);
  assert.ok(hasTenantPredicate || hasInsertTenantColumn, `expected tenant scope in: ${sql}`);
  assert.ok(params.includes(CTX.tenantId), `expected tenant id param in: ${sql}`);
}

describe('postgres production release evidence repository', () => {
  it('maps rows to the route-facing release evidence shape', () => {
    const mapped = mapProductionReleaseEvidenceRow({
      id: 'evd_1',
      tenant_id: CTX.tenantId,
      kind: 'third_party_security_review',
      release_id: 'rel_1',
      status: 'accepted',
      evidence_json: { review_report_uri: 'evidence://report' },
      notes: null,
      validation_json: { ok: true },
      created_at: new Date(FIXED_NOW),
      created_by: CTX.userId,
    });
    assert.deepEqual(mapped, {
      id: 'evd_1',
      tenant_id: CTX.tenantId,
      kind: 'third_party_security_review',
      release_id: 'rel_1',
      status: 'accepted',
      evidence: { review_report_uri: 'evidence://report' },
      notes: null,
      validation: { ok: true },
      created_at: FIXED_NOW,
      created_by: CTX.userId,
    });
  });

  it('inserts JSON evidence inside tenant context', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/INSERT INTO production_release_evidence/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.match(sql, /evidence_json/);
        assert.match(sql, /validation_json/);
        assert.equal(params[0], 'evd_1');
        assert.equal(params[1], CTX.tenantId);
        assert.equal(params[2], 'third_party_security_review');
        assert.equal(params[3], 'rel_1');
        assert.deepEqual(JSON.parse(params[5]), { review_report_uri: 'evidence://report' });
        assert.deepEqual(JSON.parse(params[7]), { ok: true });
        return {
          rows: [
            {
              id: 'evd_1',
              tenant_id: CTX.tenantId,
              kind: 'third_party_security_review',
              release_id: 'rel_1',
              status: 'accepted',
              evidence_json: { review_report_uri: 'evidence://report' },
              notes: 'ok',
              validation_json: { ok: true },
              created_at: FIXED_NOW,
              created_by: CTX.userId,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createProductionReleaseEvidenceRepository(pool);
    const row = await repo.createProductionReleaseEvidence(CTX, {
      id: 'evd_1',
      kind: 'third_party_security_review',
      release_id: 'rel_1',
      status: 'accepted',
      evidence: { review_report_uri: 'evidence://report' },
      notes: 'ok',
      validation: { ok: true },
      created_at: FIXED_NOW,
      created_by: CTX.userId,
    });
    assert.equal(row.id, 'evd_1');
    assertTenantWrapped(pool.client);
    assert.equal(dataQueries(pool.client).length, 1);
  });

  it('lists current tenant rows ordered by created_at', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/FROM production_release_evidence/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.match(sql, /ORDER BY created_at ASC/i);
        return { rows: [] };
      }
      return { rows: [] };
    });
    const repo = createProductionReleaseEvidenceRepository(pool);
    assert.deepEqual(await repo.listProductionReleaseEvidence(CTX), []);
    assertTenantWrapped(pool.client);
  });

  it('gets current tenant rows by id and maps missing rows to null', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/FROM production_release_evidence/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.equal(params[1], 'evd_missing');
        return { rows: [] };
      }
      return { rows: [] };
    });
    const repo = createProductionReleaseEvidenceRepository(pool);
    assert.equal(await repo.getProductionReleaseEvidence(CTX, 'evd_missing'), null);
    assertTenantWrapped(pool.client);
  });
});
