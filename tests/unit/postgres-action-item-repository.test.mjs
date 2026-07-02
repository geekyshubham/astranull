import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createPostgresActionItemServices } from '../../src/persistence/postgres/actionItemServiceAdapters.mjs';
import {
  createActionItemRepository,
  mapActionItemRow,
} from '../../src/persistence/postgres/actionItemRepository.mjs';

const CTX = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };
const FIXED_NOW = '2026-07-02T12:00:00.000Z';

const ACTION_ITEM_REPOSITORY_METHODS = [
  'listActionItems',
  'getActionItem',
  'findOpenActionItemByDedupe',
  'insertActionItem',
  'updateActionItemStatus',
];

const POSTGRES_ACTION_ITEM_SERVICE_METHODS = [
  'listActionItems',
  'createActionItemFromFinding',
  'patchActionItemStatus',
  'buildRemediationPayload',
];

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

function assertTenantWrapped(client) {
  assert.equal(client.queries[0].text.trim(), 'BEGIN');
  assert.equal(client.queries[1].text.trim(), "SELECT set_config('app.tenant_id', $1, true)");
  assert.deepEqual(client.queries[1].params, [CTX.tenantId]);
  assert.equal(client.queries.at(-1).text.trim(), 'COMMIT');
  assert.equal(client.released, true);
}

function assertTenantScoped(sql, params) {
  const hasTenantPredicate = /tenant_id\s*=\s*\$\d+/i.test(sql);
  const hasInsertTenantColumn = /INSERT\s+INTO\s+waf_action_items/i.test(sql) && /tenant_id/i.test(sql);
  assert.ok(hasTenantPredicate || hasInsertTenantColumn, `expected tenant scope in: ${sql}`);
  assert.ok(params.includes(CTX.tenantId), `expected tenant id param in: ${sql}`);
}

function assertParameterized(sql) {
  assert.doesNotMatch(sql, new RegExp(`tenant_id\\s*=\\s*'${CTX.tenantId}'`, 'i'));
  assert.doesNotMatch(sql, /\$\{.*\}/);
}

function assertJsonbParam(params, index, expectedSubset) {
  const value = params[index];
  assert.equal(typeof value, 'string');
  const parsed = JSON.parse(value);
  for (const [key, expected] of Object.entries(expectedSubset)) {
    assert.deepEqual(parsed[key], expected);
  }
}

function actionItemRowFixture(overrides = {}) {
  return {
    id: 'act_1',
    tenant_id: CTX.tenantId,
    category: 'waf_coverage',
    title: 'WAF remediation: https://app.example.com',
    asset_display: 'https://app.example.com',
    owner: 'security-operations',
    severity: 'high',
    evidence_json: {
      summary: 'Marker rule not blocking.',
      links: [{ type: 'finding', url: '/v1/findings/fnd_1', label: 'Finding evidence' }],
      asset: { id: 'waf_1', display: 'https://app.example.com' },
      finding_ids: ['fnd_1'],
      dedupe_key: 'waf_1:marker_rule_not_blocking',
    },
    recommended_solution: 'Review WAF rule mode.',
    retest_url: '/v1/waf/validations?waf_asset_id=waf_1',
    status: 'open',
    primary_reason: 'marker_rule_not_blocking',
    cve_pipeline_item_id: null,
    created_at: new Date(FIXED_NOW),
    updated_at: new Date(FIXED_NOW),
    ...overrides,
  };
}

describe('postgres action item repository', () => {
  it('exports repository factory and row mapper', () => {
    assert.equal(typeof createActionItemRepository, 'function');
    const repo = createActionItemRepository(createRecordingPool(() => ({ rows: [] })));
    for (const method of ACTION_ITEM_REPOSITORY_METHODS) {
      assert.equal(typeof repo[method], 'function', method);
    }
  });

  it('requires tenantId for all repository methods', async () => {
    const pool = createRecordingPool(() => ({ rows: [] }));
    const repo = createActionItemRepository(pool);
    const calls = [
      () => repo.listActionItems({}),
      () => repo.getActionItem({}, 'act_1'),
      () => repo.findOpenActionItemByDedupe({}, 'https://app.example.com', 'marker_rule_not_blocking'),
      () => repo.insertActionItem({}, {}),
      () => repo.updateActionItemStatus({}, 'act_1', 'resolved', {}),
    ];
    for (const call of calls) {
      await assert.rejects(call, /tenant id must be a non-empty string/);
    }
  });

  it('maps action item rows with parsed evidence json', () => {
    const mapped = mapActionItemRow(actionItemRowFixture());
    assert.equal(mapped.action_item_id, 'act_1');
    assert.equal(mapped.evidence.summary, 'Marker rule not blocking.');
    assert.deepEqual(mapped.finding_ids, ['fnd_1']);
    assert.equal(mapped.created_at, FIXED_NOW);
  });

  it('lists action items with tenant-scoped parameterized sql', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/FROM waf_action_items/i.test(sql)) {
        assertParameterized(sql);
        assertTenantScoped(sql, params);
        return { rows: [actionItemRowFixture()] };
      }
      return { rows: [] };
    });
    const repo = createActionItemRepository(pool);
    const items = await repo.listActionItems(CTX);
    assertTenantWrapped(pool.client);
    assert.equal(items.length, 1);
    assert.equal(items[0].category, 'waf_coverage');
  });

  it('inserts action item with jsonb evidence via JSON.stringify', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/INSERT INTO waf_action_items/i.test(sql)) {
        assertParameterized(sql);
        assertTenantScoped(sql, params);
        assertJsonbParam(params, 7, {
          summary: 'WAF posture finding.',
          finding_ids: ['fnd_1'],
        });
        return { rows: [actionItemRowFixture({ id: 'act_new' })] };
      }
      return { rows: [] };
    });
    const repo = createActionItemRepository(pool);
    const created = await repo.insertActionItem(CTX, {
      action_item_id: 'act_new',
      category: 'waf_coverage',
      title: 'WAF remediation: https://app.example.com',
      asset_display: 'https://app.example.com',
      owner: 'security-operations',
      severity: 'high',
      evidence: {
        summary: 'WAF posture finding.',
        links: [],
      },
      recommended_solution: 'Review WAF rule mode.',
      retest_url: '/v1/waf/validations?waf_asset_id=waf_1',
      status: 'open',
      finding_ids: ['fnd_1'],
      dedupe_key: 'waf_1:marker_rule_not_blocking',
      primary_reason: 'marker_rule_not_blocking',
      created_at: FIXED_NOW,
      updated_at: FIXED_NOW,
    });
    assert.equal(created.action_item_id, 'act_new');
    assert.deepEqual(created.finding_ids, ['fnd_1']);
  });

  it('updates action item status with tenant scope and jsonb evidence round-trip', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/SELECT evidence_json/i.test(sql)) {
        return { rows: [{ evidence_json: actionItemRowFixture().evidence_json }] };
      }
      if (/UPDATE waf_action_items/i.test(sql)) {
        assertParameterized(sql);
        assertTenantScoped(sql, params);
        assert.equal(typeof params[3], 'string');
        assert.deepEqual(JSON.parse(params[3]).summary, 'Marker rule not blocking.');
        return {
          rows: [actionItemRowFixture({ status: 'in_progress' })],
        };
      }
      return { rows: [] };
    });
    const repo = createActionItemRepository(pool);
    const updated = await repo.updateActionItemStatus(CTX, 'act_1', 'in_progress', {
      updated_at: FIXED_NOW,
    });
    assertTenantWrapped(pool.client);
    assert.equal(updated.status, 'in_progress');
  });

  it('postgres action item service adapter exposes expected methods', () => {
    const services = createPostgresActionItemServices({
      connect: async () => {
        throw new Error('pool should not connect during signature check');
      },
    });
    assert.deepEqual(
      POSTGRES_ACTION_ITEM_SERVICE_METHODS.sort(),
      Object.keys(services).filter((key) => typeof services[key] === 'function').sort(),
    );
    for (const method of POSTGRES_ACTION_ITEM_SERVICE_METHODS) {
      assert.equal(typeof services[method], 'function', method);
    }
  });
});