import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';
import {
  createHighScaleRepository,
  mapRequestRow,
} from '../../src/persistence/postgres/highScaleRepository.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '../..');
const REPO_SOURCE = readFileSync(
  path.join(ROOT, 'src/persistence/postgres/highScaleRepository.mjs'),
  'utf8',
);

const CTX = { tenantId: 'ten_demo', userId: 'usr_1', role: 'admin' };

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
  return { client, async connect() { return client; } };
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

describe('postgres high-scale repository', () => {
  it('does not import dev store in source', () => {
    assert.ok(!REPO_SOURCE.includes('../store.mjs'));
    assert.ok(!REPO_SOURCE.includes('getStore'));
  });

  it('mapRequestRow exposes adapter and risk_review intake fields', () => {
    const mapped = mapRequestRow({
      id: 'hs_1',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_1',
      state: 'submitted',
      reason: 'drill',
      objective: 'drill',
      requested_window: {},
      emergency_contacts: [],
      scope_confirmation: true,
      created_by: 'u1',
      audit_trail: [],
      artifacts: [],
      scope_hash: null,
      soc_approvals: [],
      provider_approval_checklist: [],
      adapter_json: { status: 'idle', traffic_generated: false },
      scheduled_window: null,
      provider_context_json: { provider_name: 'Edge' },
      risk_review_json: {
        environment: 'staging',
        business_criticality: 'high',
        requested_scenario_families: ['meta'],
        requested_limits: { max_rate: '1' },
        stop_criteria: { a: 1 },
        abort_criteria: { b: 2 },
      },
      created_at: new Date('2026-01-01T00:00:00.000Z'),
      updated_at: null,
    });
    assert.equal(mapped.adapter.traffic_generated, false);
    assert.equal(mapped.environment, 'staging');
    assert.equal(mapped.provider_context.provider_name, 'Edge');
  });

  it('getHighScaleRequest uses tenant-scoped parameterized SQL', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.includes('FROM high_scale_requests')) {
        assert.deepEqual(params, [CTX.tenantId, 'hs_1']);
        return {
          rows: [{
            id: 'hs_1',
            tenant_id: CTX.tenantId,
            target_group_id: 'tg_1',
            state: 'submitted',
            reason: 'x',
            objective: 'x',
            requested_window: {},
            emergency_contacts: [],
            scope_confirmation: true,
            created_by: 'u1',
            audit_trail: [],
            artifacts: [],
            scope_hash: null,
            soc_approvals: [],
            provider_approval_checklist: [],
            adapter_json: {},
            scheduled_window: null,
            provider_context_json: {},
            risk_review_json: {},
            created_at: new Date(),
            updated_at: null,
          }],
        };
      }
      return { rows: [] };
    });
    const repo = createHighScaleRepository(pool);
    const req = await repo.getHighScaleRequest(CTX, 'hs_1');
    assert.equal(req.id, 'hs_1');
    assertTenantWrapped(pool.client, CTX.tenantId);
    assert.equal(dataQueries(pool.client).length, 1);
  });
});