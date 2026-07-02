import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createPostgresSupplyChainRiskServices } from '../../src/persistence/postgres/supplyChainRiskServiceAdapters.mjs';
import {
  createSupplyChainRiskRepository,
  mapSupplyChainRiskRow,
} from '../../src/persistence/postgres/supplyChainRiskRepository.mjs';

const CTX = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };
const FIXED_NOW = '2026-07-02T12:00:00.000Z';

const SUPPLY_CHAIN_RISK_REPOSITORY_METHODS = [
  'listRisks',
  'getRisk',
  'findRiskByHostnameAndExposure',
  'insertRisk',
  'updateRiskState',
];

const POSTGRES_SUPPLY_CHAIN_RISK_SERVICE_METHODS = [
  'listSupplyChainRisks',
  'createSupplyChainRisk',
  'patchRiskState',
  'createRemediationTicket',
  'assessDanglingCname',
  'assessDanglingDependency',
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
  const hasInsertTenantColumn = /INSERT\s+INTO\s+supply_chain_risks/i.test(sql) && /tenant_id/i.test(sql);
  assert.ok(hasTenantPredicate || hasInsertTenantColumn, `expected tenant scope in: ${sql}`);
  assert.ok(params.includes(CTX.tenantId), `expected tenant id param in: ${sql}`);
}

function assertParameterized(sql) {
  assert.doesNotMatch(sql, new RegExp(`tenant_id\\s*=\\s*'${CTX.tenantId}'`, 'i'));
  assert.doesNotMatch(sql, /\$\{.*\}/);
}

function assertJsonbParam(params, index, expected) {
  const value = params[index];
  assert.equal(typeof value, 'string');
  assert.deepEqual(JSON.parse(value), expected);
}

function riskRowFixture(overrides = {}) {
  return {
    id: 'risk_1',
    tenant_id: CTX.tenantId,
    exposure_type: 'dangling_cname',
    hostname: 'legacy.example.com',
    evidence_summary_json: { cname_chain_hash: 'hash_abc', data_source: 'dns_cname_chain' },
    confidence: 0.75,
    severity: 'high',
    state: 'suspected',
    owner_hint: 'dns-team',
    remediation_steps: ['Review DNS CNAME records'],
    assessment_metadata_json: { risk_id: 'risk_1', phase: 'AP0_detect_only' },
    created_at: new Date(FIXED_NOW),
    updated_at: new Date(FIXED_NOW),
    ...overrides,
  };
}

describe('postgres supply chain risk repository', () => {
  it('exports repository factory and row mapper', () => {
    assert.equal(typeof createSupplyChainRiskRepository, 'function');
    const repo = createSupplyChainRiskRepository(createRecordingPool(() => ({ rows: [] })));
    for (const method of SUPPLY_CHAIN_RISK_REPOSITORY_METHODS) {
      assert.equal(typeof repo[method], 'function', method);
    }
  });

  it('requires tenantId for all repository methods', async () => {
    const pool = createRecordingPool(() => ({ rows: [] }));
    const repo = createSupplyChainRiskRepository(pool);
    const calls = [
      () => repo.listRisks({}),
      () => repo.getRisk({}, 'risk_1'),
      () => repo.findRiskByHostnameAndExposure({}, 'legacy.example.com', 'dangling_cname'),
      () => repo.insertRisk({}, {}),
      () => repo.updateRiskState({}, 'risk_1', 'confirmed', {}),
    ];
    for (const call of calls) {
      await assert.rejects(call, /tenant id must be a non-empty string/);
    }
  });

  it('maps supply chain risk rows with parsed json fields', () => {
    const mapped = mapSupplyChainRiskRow(riskRowFixture());
    assert.equal(mapped.exposure_type, 'dangling_cname');
    assert.equal(mapped.evidence_summary.cname_chain_hash, 'hash_abc');
    assert.equal(mapped.phase, 'AP0_detect_only');
    assert.equal(mapped.created_at, FIXED_NOW);
  });

  it('lists risks with tenant-scoped parameterized sql', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/FROM supply_chain_risks/i.test(sql)) {
        assertParameterized(sql);
        assertTenantScoped(sql, params);
        return { rows: [riskRowFixture()] };
      }
      return { rows: [] };
    });
    const repo = createSupplyChainRiskRepository(pool);
    const items = await repo.listRisks(CTX);
    assertTenantWrapped(pool.client);
    assert.equal(items.length, 1);
    assert.equal(items[0].hostname, 'legacy.example.com');
  });

  it('inserts risk with jsonb evidence and assessment metadata via JSON.stringify', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/INSERT INTO supply_chain_risks/i.test(sql)) {
        assertParameterized(sql);
        assertTenantScoped(sql, params);
        assertJsonbParam(params, 4, {
          cname_chain_hash: 'hash_abc',
          data_source: 'dns_cname_chain',
        });
        assertJsonbParam(params, 10, {
          risk_id: 'risk_new',
          phase: 'AP0_detect_only',
        });
        return { rows: [riskRowFixture({ id: 'risk_new', assessment_metadata_json: { risk_id: 'risk_new', phase: 'AP0_detect_only' } })] };
      }
      return { rows: [] };
    });
    const repo = createSupplyChainRiskRepository(pool);
    const created = await repo.insertRisk(CTX, {
      id: 'risk_new',
      risk_id: 'risk_new',
      exposure_type: 'dangling_cname',
      hostname: 'legacy.example.com',
      evidence_summary: { cname_chain_hash: 'hash_abc', data_source: 'dns_cname_chain' },
      confidence: 0.75,
      severity: 'high',
      state: 'suspected',
      phase: 'AP0_detect_only',
      owner_hint: 'dns-team',
      remediation_steps: ['Review DNS CNAME records'],
      created_at: FIXED_NOW,
      updated_at: FIXED_NOW,
    });
    assert.equal(created.risk_id, 'risk_new');
    assert.equal(created.evidence_summary.data_source, 'dns_cname_chain');
  });

  it('updates risk state inside tenant context without string concatenation', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/UPDATE supply_chain_risks/i.test(sql)) {
        assertParameterized(sql);
        assertTenantScoped(sql, params);
        assert.deepEqual(params.slice(0, 3), [CTX.tenantId, 'risk_1', 'confirmed']);
        return {
          rows: [riskRowFixture({ state: 'confirmed', owner_hint: 'platform-team' })],
        };
      }
      return { rows: [] };
    });
    const repo = createSupplyChainRiskRepository(pool);
    const updated = await repo.updateRiskState(CTX, 'risk_1', 'confirmed', {
      owner_hint: 'platform-team',
      updated_at: FIXED_NOW,
    });
    assertTenantWrapped(pool.client);
    assert.equal(updated.state, 'confirmed');
    assert.equal(updated.owner_hint, 'platform-team');
  });

  it('postgres supply chain risk service adapter exposes expected methods', () => {
    const services = createPostgresSupplyChainRiskServices({
      connect: async () => {
        throw new Error('pool should not connect during signature check');
      },
    });
    assert.deepEqual(
      POSTGRES_SUPPLY_CHAIN_RISK_SERVICE_METHODS.sort(),
      Object.keys(services).filter((key) => typeof services[key] === 'function').sort(),
    );
    for (const method of POSTGRES_SUPPLY_CHAIN_RISK_SERVICE_METHODS) {
      assert.equal(typeof services[method], 'function', method);
    }
  });
});