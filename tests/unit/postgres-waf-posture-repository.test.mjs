import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  createWafPostureRepository,
  mapWafAssetRow,
  mapWafConnectorRow,
  mapWafConnectorSnapshotRow,
  mapWafDriftEventRow,
  mapWafPostureSnapshotRow,
  mapWafValidationRunRow,
} from '../../src/persistence/postgres/wafPostureRepository.mjs';

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
  const hasInsertTenantColumn = /INSERT\s+INTO\s+waf_/i.test(sql) && /tenant_id/i.test(sql);
  assert.ok(hasTenantPredicate || hasInsertTenantColumn, `expected tenant scope in: ${sql}`);
  assert.ok(params.includes(CTX.tenantId), `expected tenant id param in: ${sql}`);
}

function connectorRowFixture(overrides = {}) {
  return {
    id: 'conn_1',
    tenant_id: CTX.tenantId,
    provider: 'cloudflare',
    name: 'Edge read-only',
    secret_id: null,
    config_json: { read_only: true, zone_ref_hash: 'zh_abc' },
    status: 'disabled',
    last_success_at: null,
    last_error_at: null,
    created_at: new Date(FIXED_NOW),
    updated_at: new Date(FIXED_NOW),
    ...overrides,
  };
}

describe('postgres WAF posture repository', () => {
  it('maps waf asset rows to route-facing shape', () => {
    const mapped = mapWafAssetRow({
      id: 'waf_1',
      tenant_id: CTX.tenantId,
      target_group_id: 'tg_1',
      target_id: null,
      environment_id: null,
      canonical_url: 'https://app.example.com',
      asset_kind: 'web',
      expected_waf_required: true,
      expected_vendor_hint: null,
      business_criticality: 'high',
      traffic_tier: 'edge',
      compliance_tags: ['pci'],
      owner_hint: 'edge-team',
      created_at: new Date(FIXED_NOW),
      updated_at: new Date(FIXED_NOW),
    });
    assert.equal(mapped.id, 'waf_1');
    assert.equal(mapped.canonical_url, 'https://app.example.com');
    assert.deepEqual(mapped.compliance_tags, ['pci']);
    assert.equal(mapped.created_at, FIXED_NOW);
  });

  it('lists waf assets inside tenant context with tenant filter', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/FROM waf_assets/i.test(sql)) {
        assertTenantScoped(sql, params);
        return {
          rows: [
            {
              id: 'waf_1',
              tenant_id: CTX.tenantId,
              target_group_id: 'tg_1',
              target_id: null,
              environment_id: null,
              canonical_url: 'https://app.example.com',
              asset_kind: 'unknown',
              expected_waf_required: true,
              expected_vendor_hint: null,
              business_criticality: 'medium',
              traffic_tier: 'unknown',
              compliance_tags: [],
              owner_hint: null,
              created_at: new Date(FIXED_NOW),
              updated_at: new Date(FIXED_NOW),
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createWafPostureRepository(pool);
    const items = await repo.listWafAssets(CTX);
    assertTenantWrapped(pool.client);
    assert.equal(items.length, 1);
    assert.equal(items[0].id, 'waf_1');
  });

  it('creates waf asset with metadata-only columns', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/INSERT INTO waf_assets/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.doesNotMatch(sql, /payload|credential|secret/i);
        return {
          rows: [
            {
              id: 'waf_new',
              tenant_id: CTX.tenantId,
              target_group_id: 'tg_1',
              target_id: null,
              environment_id: null,
              canonical_url: 'https://new.example.com',
              asset_kind: 'unknown',
              expected_waf_required: true,
              expected_vendor_hint: null,
              business_criticality: 'medium',
              traffic_tier: 'unknown',
              compliance_tags: [],
              owner_hint: null,
              created_at: new Date(FIXED_NOW),
              updated_at: new Date(FIXED_NOW),
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createWafPostureRepository(pool);
    const created = await repo.createWafAsset(CTX, {
      id: 'waf_new',
      target_group_id: 'tg_1',
      canonical_url: 'https://new.example.com',
      created_at: FIXED_NOW,
      updated_at: FIXED_NOW,
    });
    assert.equal(created.id, 'waf_new');
    assert.equal(dataQueries(pool.client).length, 1);
  });

  it('finalize bundle uses tenant-scoped updates and metadata json only', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/UPDATE waf_posture_snapshots/i.test(sql)) {
        assertTenantScoped(sql, params);
      }
      if (/INSERT INTO waf_posture_snapshots/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.match(sql, /source_mix_json/);
        assert.doesNotMatch(sql, /raw_payload|request_body/i);
      }
      if (/INSERT INTO waf_scenario_results/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.match(sql, /evidence_summary_json/);
      }
      if (/UPDATE waf_validation_runs/i.test(sql)) {
        assertTenantScoped(sql, params);
        return {
          rows: [
            {
              id: 'wvr_1',
              tenant_id: CTX.tenantId,
              test_run_id: null,
              waf_asset_id: 'waf_1',
              mode: 'marker',
              status: 'finalized',
              started_at: null,
              finalized_at: new Date(FIXED_NOW),
              safety_profile_json: {},
              summary_json: { posture_status: 'protected' },
              created_at: new Date(FIXED_NOW),
            },
          ],
        };
      }
      if (/UPDATE waf_assets/i.test(sql)) {
        assertTenantScoped(sql, params);
      }
      return { rows: [] };
    });
    const repo = createWafPostureRepository(pool);
    const result = await repo.finalizeWafValidationBundle(CTX, {
      run_id: 'wvr_1',
      waf_asset_id: 'waf_1',
      asset_updated_at: FIXED_NOW,
      snapshot: {
        id: 'snap_1',
        status: 'protected',
        reason_codes: [],
        coverage_required: true,
        risk_score: 0,
        confidence: 0.9,
        source_mix_json: { validation: true },
        created_at: FIXED_NOW,
      },
      scenarios: [
        {
          id: 'scn_1',
          scenario_family: 'marker',
          expected_action: 'block',
          observed_action: 'block',
          passed: true,
          confidence: 1,
          evidence_summary_json: { marker_seen: true },
          created_at: FIXED_NOW,
        },
      ],
      run_updates: {
        status: 'finalized',
        finalized_at: FIXED_NOW,
        summary_json: { posture_status: 'protected' },
      },
    });
    assertTenantWrapped(pool.client);
    assert.equal(result.validation_run.status, 'finalized');
    assert.equal(mapWafPostureSnapshotRow(result.snapshot).status, 'protected');
    assert.equal(mapWafValidationRunRow(result.validation_run).waf_asset_id, 'waf_1');
  });

  it('upsertWafPostureFinding inserts metadata-only finding with tenant scope', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/FROM findings/i.test(sql) && /IS NOT DISTINCT FROM/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.match(sql, /status = 'open'/i);
        return { rows: [] };
      }
      if (/INSERT INTO findings/i.test(sql)) {
        assert.ok(params.includes(CTX.tenantId));
        assert.doesNotMatch(sql, /payload|credential|secret|raw_/i);
        return {
          rows: [
            {
              id: 'fnd_waf_1',
              tenant_id: CTX.tenantId,
              target_group_id: 'tg_1',
              target_id: null,
              test_run_id: 'run_1',
              check_id: 'waf.posture.waf_1',
              title: 'WAF posture unprotected: https://app.example.com',
              severity: 'high',
              status: 'open',
              evidence_ids: ['snap_1', 'scn_1'],
              notes: 'WAF posture finding.',
              remediation_template: 'waf_posture_remediation',
              verdict_id: null,
              last_verdict_id: null,
              assignee: null,
              created_at: new Date(FIXED_NOW),
              updated_at: new Date(FIXED_NOW),
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createWafPostureRepository(pool);
    const result = await repo.upsertWafPostureFinding(CTX, {
      id: 'fnd_waf_1',
      target_group_id: 'tg_1',
      target_id: null,
      test_run_id: 'run_1',
      check_id: 'waf.posture.waf_1',
      title: 'WAF posture unprotected: https://app.example.com',
      severity: 'high',
      notes: 'WAF posture finding.',
      remediation_template: 'waf_posture_remediation',
      evidence_ids: ['snap_1', 'scn_1'],
      created_at: FIXED_NOW,
      updated_at: FIXED_NOW,
    });
    assertTenantWrapped(pool.client);
    assert.equal(result.inserted, true);
    assert.equal(result.finding.check_id, 'waf.posture.waf_1');
    const data = dataQueries(pool.client);
    assert.equal(data.some((q) => /IS NOT DISTINCT FROM/i.test(q.text)), true);
    assert.equal(data.some((q) => /INSERT INTO findings/i.test(q.text)), true);
  });

  it('upsertWafPostureFinding updates open finding when target_id is null', async () => {
    let sawDistinctLookup = false;
    const pool = createRecordingPool((sql, params) => {
      if (/FROM findings/i.test(sql) && /IS NOT DISTINCT FROM/i.test(sql)) {
        sawDistinctLookup = true;
        assert.deepEqual(params[2], null);
        return {
          rows: [
            {
              id: 'fnd_existing',
              tenant_id: CTX.tenantId,
              target_group_id: 'tg_1',
              target_id: null,
              test_run_id: 'run_old',
              check_id: 'waf.posture.waf_1',
              title: 'old title',
              severity: 'medium',
              status: 'open',
              evidence_ids: [],
              notes: null,
              remediation_template: null,
              verdict_id: null,
              last_verdict_id: null,
              assignee: null,
              created_at: new Date('2026-07-01T12:00:00.000Z'),
              updated_at: null,
            },
          ],
        };
      }
      if (/UPDATE findings/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.match(sql, /last_verdict_id = NULL/i);
        return {
          rows: [
            {
              id: 'fnd_existing',
              tenant_id: CTX.tenantId,
              target_group_id: 'tg_1',
              target_id: null,
              test_run_id: 'run_new',
              check_id: 'waf.posture.waf_1',
              title: 'WAF posture underprotected: https://app.example.com',
              severity: 'high',
              status: 'open',
              evidence_ids: ['snap_2'],
              notes: 'updated notes',
              remediation_template: 'waf_posture_remediation',
              verdict_id: null,
              last_verdict_id: null,
              assignee: null,
              created_at: new Date('2026-07-01T12:00:00.000Z'),
              updated_at: new Date(FIXED_NOW),
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createWafPostureRepository(pool);
    const result = await repo.upsertWafPostureFinding(CTX, {
      id: 'fnd_new_should_not_insert',
      target_group_id: 'tg_1',
      target_id: null,
      test_run_id: 'run_new',
      check_id: 'waf.posture.waf_1',
      title: 'WAF posture underprotected: https://app.example.com',
      severity: 'high',
      notes: 'updated notes',
      remediation_template: 'waf_posture_remediation',
      evidence_ids: ['snap_2'],
      updated_at: FIXED_NOW,
      created_at: FIXED_NOW,
    });
    assert.equal(sawDistinctLookup, true);
    assert.equal(result.inserted, false);
    assert.equal(result.finding.id, 'fnd_existing');
    assert.equal(result.finding.test_run_id, 'run_new');
    assert.equal(dataQueries(pool.client).some((q) => /INSERT INTO findings/i.test(q.text)), false);
  });

  it('maps waf drift event rows with before_summary and after_summary', () => {
    const mapped = mapWafDriftEventRow({
      id: 'drf_1',
      tenant_id: CTX.tenantId,
      waf_asset_id: 'waf_1',
      baseline_id: null,
      drift_type: 'marker_failed',
      severity: 'high',
      before_summary_json: { posture_status: 'protected' },
      after_summary_json: { posture_status: 'underprotected' },
      status: 'open',
      finding_id: 'fnd_1',
      created_at: new Date(FIXED_NOW),
      resolved_at: null,
    });
    assert.equal(mapped.drift_type, 'marker_failed');
    assert.deepEqual(mapped.before_summary, { posture_status: 'protected' });
    assert.deepEqual(mapped.after_summary, { posture_status: 'underprotected' });
    assert.equal(mapped.created_at, FIXED_NOW);
  });

  it('lists waf drift events inside tenant context with tenant filter', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/FROM waf_drift_events/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.doesNotMatch(sql, /payload|credential|secret/i);
        return {
          rows: [
            {
              id: 'drf_1',
              tenant_id: CTX.tenantId,
              waf_asset_id: 'waf_1',
              baseline_id: null,
              drift_type: 'marker_failed',
              severity: 'high',
              before_summary_json: { posture_status: 'protected' },
              after_summary_json: { posture_status: 'underprotected' },
              status: 'open',
              finding_id: null,
              created_at: new Date(FIXED_NOW),
              resolved_at: null,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createWafPostureRepository(pool);
    const items = await repo.listWafDriftEvents(CTX);
    assertTenantWrapped(pool.client);
    assert.equal(items.length, 1);
    assert.equal(items[0].before_summary.posture_status, 'protected');
  });

  it('upsertWafDriftEvent updates existing open drift instead of inserting duplicate', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/FROM waf_drift_events/i.test(sql) && /status = 'open'/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.deepEqual(params.slice(1, 3), ['waf_1', 'marker_failed']);
        return {
          rows: [
            {
              id: 'drf_existing',
              tenant_id: CTX.tenantId,
              waf_asset_id: 'waf_1',
              baseline_id: null,
              drift_type: 'marker_failed',
              severity: 'high',
              before_summary_json: { posture_status: 'protected' },
              after_summary_json: { posture_status: 'underprotected' },
              status: 'open',
              finding_id: null,
              created_at: new Date('2026-07-01T12:00:00.000Z'),
              resolved_at: null,
            },
          ],
        };
      }
      if (/UPDATE waf_drift_events/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.match(sql, /after_summary_json/);
        assert.doesNotMatch(sql, /raw_payload|request_body/i);
        return {
          rows: [
            {
              id: 'drf_existing',
              tenant_id: CTX.tenantId,
              waf_asset_id: 'waf_1',
              baseline_id: null,
              drift_type: 'marker_failed',
              severity: 'critical',
              before_summary_json: { posture_status: 'protected' },
              after_summary_json: { posture_status: 'underprotected', waf_detected: true },
              status: 'open',
              finding_id: 'fnd_1',
              created_at: new Date(FIXED_NOW),
              resolved_at: null,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createWafPostureRepository(pool);
    const result = await repo.upsertWafDriftEvent(CTX, {
      id: 'drf_new_should_not_insert',
      waf_asset_id: 'waf_1',
      drift_type: 'marker_failed',
      severity: 'critical',
      before_summary: { posture_status: 'protected' },
      after_summary: { posture_status: 'underprotected', waf_detected: true },
      finding_id: 'fnd_1',
      created_at: FIXED_NOW,
    });
    assertTenantWrapped(pool.client);
    assert.equal(result.inserted, false);
    assert.equal(result.drift_event.id, 'drf_existing');
    assert.equal(result.drift_event.severity, 'critical');
    assert.equal(
      dataQueries(pool.client).some((q) => /INSERT INTO waf_drift_events/i.test(q.text)),
      false,
    );
  });

  it('maps waf connector rows with config field', () => {
    const mapped = mapWafConnectorRow(connectorRowFixture());
    assert.equal(mapped.provider, 'cloudflare');
    assert.deepEqual(mapped.config, { read_only: true, zone_ref_hash: 'zh_abc' });
    assert.equal(mapped.created_at, FIXED_NOW);
  });

  it('lists connectors inside tenant context with tenant filter', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/FROM waf_connectors/i.test(sql)) {
        assertTenantScoped(sql, params);
        return { rows: [connectorRowFixture()] };
      }
      return { rows: [] };
    });
    const repo = createWafPostureRepository(pool);
    const items = await repo.listConnectors(CTX);
    assertTenantWrapped(pool.client);
    assert.equal(items.length, 1);
    assert.equal(items[0].config.zone_ref_hash, 'zh_abc');
  });

  it('creates connector with metadata-only config json', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/INSERT INTO waf_connectors/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.match(sql, /config_json/);
        assert.doesNotMatch(sql, /payload|credential|raw_/i);
        return { rows: [connectorRowFixture({ id: 'conn_new' })] };
      }
      return { rows: [] };
    });
    const repo = createWafPostureRepository(pool);
    const created = await repo.createConnector(CTX, {
      id: 'conn_new',
      provider: 'cloudflare',
      name: 'Edge read-only',
      config_json: { read_only: true },
      status: 'disabled',
      created_at: FIXED_NOW,
      updated_at: FIXED_NOW,
    });
    assert.equal(created.id, 'conn_new');
    assert.equal(created.config.read_only, true);
  });

  it('gets connector by id with tenant scope', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/FROM waf_connectors/i.test(sql) && /WHERE tenant_id/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.deepEqual(params.slice(0, 2), [CTX.tenantId, 'conn_1']);
        return { rows: [connectorRowFixture()] };
      }
      return { rows: [] };
    });
    const repo = createWafPostureRepository(pool);
    const item = await repo.getConnector(CTX, 'conn_1');
    assert.equal(item.id, 'conn_1');
  });

  it('updates connector status inside tenant context', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/UPDATE waf_connectors/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.match(sql, /status =/);
        return {
          rows: [connectorRowFixture({ status: 'active', last_success_at: new Date(FIXED_NOW) })],
        };
      }
      return { rows: [] };
    });
    const repo = createWafPostureRepository(pool);
    const updated = await repo.updateConnectorStatus(CTX, 'conn_1', {
      status: 'active',
      last_success_at: FIXED_NOW,
      updated_at: FIXED_NOW,
    });
    assert.equal(updated.status, 'active');
    assertTenantWrapped(pool.client);
  });

  it('creates connector snapshots with summary json only', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/INSERT INTO waf_connector_snapshots/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.match(sql, /summary_json/);
        assert.doesNotMatch(sql, /raw_payload|request_body/i);
        return {
          rows: [
            {
              id: 'csnap_1',
              tenant_id: CTX.tenantId,
              connector_id: 'conn_1',
              provider: 'cloudflare',
              snapshot_kind: 'waf_policy',
              resource_ref_hash: 'rh_1',
              display_ref: 'zone-a',
              summary_json: { policy_mode: 'block', rule_count: 12 },
              config_hash: 'cfg_hash_1',
              observed_at: new Date(FIXED_NOW),
              created_at: new Date(FIXED_NOW),
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createWafPostureRepository(pool);
    const items = await repo.createConnectorSnapshots(CTX, [
      {
        id: 'csnap_1',
        connector_id: 'conn_1',
        provider: 'cloudflare',
        snapshot_kind: 'waf_policy',
        resource_ref_hash: 'rh_1',
        display_ref: 'zone-a',
        summary_json: { policy_mode: 'block', rule_count: 12 },
        config_hash: 'cfg_hash_1',
        observed_at: FIXED_NOW,
        created_at: FIXED_NOW,
      },
    ]);
    assert.equal(items.length, 1);
    assert.equal(items[0].summary.policy_mode, 'block');
  });

  it('lists connector snapshots for connector id with tenant filter', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/FROM waf_connector_snapshots/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.deepEqual(params, [CTX.tenantId, 'conn_1']);
        return {
          rows: [
            {
              id: 'csnap_1',
              tenant_id: CTX.tenantId,
              connector_id: 'conn_1',
              provider: 'cloudflare',
              snapshot_kind: 'waf_policy',
              resource_ref_hash: 'rh_1',
              display_ref: null,
              summary_json: { rule_count: 3 },
              config_hash: null,
              observed_at: new Date(FIXED_NOW),
              created_at: new Date(FIXED_NOW),
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createWafPostureRepository(pool);
    const items = await repo.listConnectorSnapshots(CTX, 'conn_1');
    assertTenantWrapped(pool.client);
    assert.equal(items[0].summary.rule_count, 3);
  });

  it('patchWafDriftEvent is tenant-scoped and metadata-only', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/UPDATE waf_drift_events/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.doesNotMatch(sql, /payload|credential|secret/i);
        assert.match(sql, /resolved_at = \$4::timestamptz/i);
        return {
          rows: [
            {
              id: 'drf_1',
              tenant_id: CTX.tenantId,
              waf_asset_id: 'waf_1',
              baseline_id: null,
              drift_type: 'marker_failed',
              severity: 'high',
              before_summary_json: {},
              after_summary_json: {},
              status: 'acknowledged',
              finding_id: null,
              created_at: new Date(FIXED_NOW),
              resolved_at: null,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createWafPostureRepository(pool);
    const patched = await repo.patchWafDriftEvent(CTX, 'drf_1', {
      status: 'acknowledged',
      resolved_at: null,
    });
    assertTenantWrapped(pool.client);
    assert.equal(patched.status, 'acknowledged');
  });
});
