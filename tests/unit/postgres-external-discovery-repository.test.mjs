import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createPostgresExternalDiscoveryServices } from '../../src/persistence/postgres/externalDiscoveryServiceAdapters.mjs';
import {
  createExternalDiscoveryRepository,
  mapDiscoveryEntityRow,
  mapExternalCandidateRow,
} from '../../src/persistence/postgres/externalDiscoveryRepository.mjs';

const CTX = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };
const FIXED_NOW = '2026-07-02T12:00:00.000Z';

const EXTERNAL_DISCOVERY_REPOSITORY_METHODS = [
  'listEntities',
  'insertEntity',
  'listCandidates',
  'getCandidate',
  'findCandidateByHostname',
  'insertCandidate',
  'updateCandidateState',
  'listInboxCandidates',
];

const POSTGRES_EXTERNAL_DISCOVERY_SERVICE_METHODS = [
  'listEntities',
  'createEntity',
  'listCandidates',
  'createCandidate',
  'ingestDiscoveryCandidates',
  'approveCandidateToTarget',
  'rejectCandidate',
  'patchCandidateState',
  'getDiscoveryInbox',
  'getDiscoveryReportSummary',
  'importCandidateToTargetGroup',
  'canImportCandidateToTargetGroup',
  'declaredOnlyModeActive',
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
  const hasInsertTenantColumn = /INSERT\s+INTO\s+(discovery_entities|external_asset_candidates)/i.test(sql)
    && /tenant_id/i.test(sql);
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

describe('postgres external discovery repository', () => {
  it('exports repository factory and row mappers', () => {
    assert.equal(typeof createExternalDiscoveryRepository, 'function');
    const repo = createExternalDiscoveryRepository(createRecordingPool(() => ({ rows: [] })));
    for (const method of EXTERNAL_DISCOVERY_REPOSITORY_METHODS) {
      assert.equal(typeof repo[method], 'function', method);
    }
  });

  it('requires tenantId for all repository methods', async () => {
    const pool = createRecordingPool(() => ({ rows: [] }));
    const repo = createExternalDiscoveryRepository(pool);
    const calls = [
      () => repo.listEntities({}),
      () => repo.insertEntity({}, {}),
      () => repo.listCandidates({}),
      () => repo.getCandidate({}, 'cand_1'),
      () => repo.findCandidateByHostname({}, 'app.example.com'),
      () => repo.insertCandidate({}, {}),
      () => repo.updateCandidateState({}, 'cand_1', {}),
      () => repo.listInboxCandidates({}),
    ];
    for (const call of calls) {
      await assert.rejects(call, /tenant id must be a non-empty string/);
    }
  });

  it('maps discovery entity rows', () => {
    const mapped = mapDiscoveryEntityRow({
      id: 'ent_1',
      tenant_id: CTX.tenantId,
      entity_type: 'subsidiary',
      name: 'Example Sub',
      display_name: 'Example Subsidiary',
      parent_entity_id: null,
      root_domains: ['example.com'],
      country: 'US',
      confidence: 0.9,
      source: 'declared',
      created_at: new Date(FIXED_NOW),
      updated_at: new Date(FIXED_NOW),
    });
    assert.equal(mapped.entity_id, 'ent_1');
    assert.deepEqual(mapped.root_domains, ['example.com']);
    assert.equal(mapped.created_at, FIXED_NOW);
  });

  it('inserts discovery entity using caller-supplied entity_id as primary key', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/INSERT INTO discovery_entities/i.test(sql)) {
        assertParameterized(sql);
        assertTenantScoped(sql, params);
        assert.equal(params[0], 'ent_custom_1');
        return {
          rows: [
            {
              id: 'ent_custom_1',
              tenant_id: CTX.tenantId,
              entity_type: 'subsidiary',
              name: 'Example Sub',
              display_name: 'Example Subsidiary',
              parent_entity_id: null,
              root_domains: ['example.com'],
              country: 'US',
              confidence: 0.9,
              source: 'declared',
              created_at: new Date(FIXED_NOW),
              updated_at: new Date(FIXED_NOW),
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createExternalDiscoveryRepository(pool);
    const created = await repo.insertEntity(CTX, {
      entity_id: 'ent_custom_1',
      entity_type: 'subsidiary',
      name: 'Example Sub',
      display_name: 'Example Subsidiary',
      root_domains: ['example.com'],
      country: 'US',
      confidence: 0.9,
      source: 'declared',
      created_at: FIXED_NOW,
      updated_at: FIXED_NOW,
    });
    assertTenantWrapped(pool.client);
    assert.equal(created.id, 'ent_custom_1');
    assert.equal(created.entity_id, 'ent_custom_1');
  });

  it('lists entities with tenant-scoped parameterized sql', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/FROM discovery_entities/i.test(sql)) {
        assertParameterized(sql);
        assertTenantScoped(sql, params);
        return {
          rows: [
            {
              id: 'ent_1',
              tenant_id: CTX.tenantId,
              entity_type: 'subsidiary',
              name: 'Example Sub',
              display_name: 'Example Subsidiary',
              parent_entity_id: null,
              root_domains: ['example.com'],
              country: 'US',
              confidence: 0.9,
              source: 'declared',
              created_at: new Date(FIXED_NOW),
              updated_at: new Date(FIXED_NOW),
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createExternalDiscoveryRepository(pool);
    const items = await repo.listEntities(CTX);
    assertTenantWrapped(pool.client);
    assert.equal(items[0].name, 'Example Sub');
  });

  it('inserts candidate with jsonb evidence summary via JSON.stringify', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/FROM external_asset_candidates/i.test(sql) && /asset_value_hash/i.test(sql)) {
        return { rows: [] };
      }
      if (/INSERT INTO external_asset_candidates/i.test(sql)) {
        assertParameterized(sql);
        assertTenantScoped(sql, params);
        assertJsonbParam(params, 11, {
          state: 'candidate',
          ownership_status: 'unknown',
          source_summary: { ct_log: true },
        });
        return {
          rows: [
            {
              id: 'cand_1',
              tenant_id: CTX.tenantId,
              entity_id: null,
              asset_type: 'hostname',
              asset_value_hash: 'hash_1',
              display_value: 'app.example.com',
              source_type: 'certificate_transparency',
              source_ref: 'ct_1',
              confidence: 0.7,
              approval_status: 'not_requested',
              approved_target_id: null,
              first_seen_at: new Date(FIXED_NOW),
              last_seen_at: new Date(FIXED_NOW),
              evidence_summary_json: {
                state: 'candidate',
                ownership_status: 'unknown',
                source_summary: { ct_log: true },
              },
              created_at: new Date(FIXED_NOW),
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createExternalDiscoveryRepository(pool);
    const result = await repo.insertCandidate(CTX, {
      id: 'cand_1',
      hostname: 'app.example.com',
      source_type: 'certificate_transparency',
      source_ref: 'ct_1',
      confidence: 0.7,
      state: 'candidate',
      evidence_summary: { source_summary: { ct_log: true } },
      first_seen_at: FIXED_NOW,
      last_seen_at: FIXED_NOW,
      created_at: FIXED_NOW,
    });
    assert.equal(result.deduplicated, false);
    assert.equal(result.candidate.hostname, 'app.example.com');
    assert.deepEqual(result.candidate.evidence_summary.source_summary, { ct_log: true });
  });

  it('maps external candidate rows with parsed evidence summary', () => {
    const mapped = mapExternalCandidateRow({
      id: 'cand_1',
      tenant_id: CTX.tenantId,
      entity_id: null,
      asset_type: 'hostname',
      asset_value_hash: 'hash_1',
      display_value: 'app.example.com',
      source_type: 'dns_passive',
      source_ref: 'dns_1',
      confidence: 0.6,
      approval_status: 'pending',
      approved_target_id: null,
      first_seen_at: new Date(FIXED_NOW),
      last_seen_at: new Date(FIXED_NOW),
      evidence_summary_json: {
        state: 'needs_review',
        ownership_status: 'unknown',
        note: 'needs approval',
      },
      created_at: new Date(FIXED_NOW),
    });
    assert.equal(mapped.state, 'needs_review');
    assert.equal(mapped.evidence_summary.note, 'needs approval');
  });

  it('updates candidate state with jsonb evidence merge and tenant scope', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/SELECT evidence_summary_json/i.test(sql)) {
        return {
          rows: [{
            evidence_summary_json: { state: 'candidate', ownership_status: 'unknown' },
            approval_status: 'not_requested',
          }],
        };
      }
      if (/UPDATE external_asset_candidates/i.test(sql)) {
        assertParameterized(sql);
        assertTenantScoped(sql, params);
        assertJsonbParam(params, 7, { state: 'approved_target' });
        return {
          rows: [
            {
              id: 'cand_1',
              tenant_id: CTX.tenantId,
              entity_id: null,
              asset_type: 'hostname',
              asset_value_hash: 'hash_1',
              display_value: 'app.example.com',
              source_type: 'dns_passive',
              source_ref: 'dns_1',
              confidence: 0.6,
              approval_status: 'approved',
              approved_target_id: null,
              first_seen_at: new Date(FIXED_NOW),
              last_seen_at: new Date(FIXED_NOW),
              evidence_summary_json: {
                state: 'approved_target',
                ownership_status: 'unknown',
                scope_hash: 'scope_1',
              },
              created_at: new Date(FIXED_NOW),
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createExternalDiscoveryRepository(pool);
    const updated = await repo.updateCandidateState(CTX, 'cand_1', {
      state: 'approved_target',
      approval_status: 'approved',
      scope_hash: 'scope_1',
      updated_at: FIXED_NOW,
    });
    assert.equal(updated.state, 'approved_target');
    assert.equal(updated.approval_status, 'approved');
  });

  it('postgres external discovery service adapter exposes expected methods', () => {
    const services = createPostgresExternalDiscoveryServices(
      {
        coreCatalog: { addTarget: async () => null, getTargetGroup: async () => null },
        wafPosture: { createWafAsset: async () => null },
      },
      {
        pool: {
          connect: async () => {
            throw new Error('pool should not connect during signature check');
          },
        },
      },
    );
    assert.deepEqual(
      POSTGRES_EXTERNAL_DISCOVERY_SERVICE_METHODS.sort(),
      Object.keys(services).filter((key) => typeof services[key] === 'function').sort(),
    );
    for (const method of POSTGRES_EXTERNAL_DISCOVERY_SERVICE_METHODS) {
      assert.equal(typeof services[method], 'function', method);
    }
  });
});