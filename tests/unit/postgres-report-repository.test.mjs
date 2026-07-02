import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  createReportRepository,
  mapReportFindingRow,
  mapReportRow,
  mapReportRunRow,
  mapReportVerdictRow,
} from '../../src/persistence/postgres/reportRepository.mjs';

const CTX = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };
const FIXED_NOW = '2026-06-01T12:00:00.000Z';
const REPORT_ID = 'report_abc';
const RUN_ID = 'run_1';

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

function createNoConnectPool() {
  return {
    async connect() {
      throw new Error('pool must not be used for empty run id lists');
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
  assert.doesNotMatch(sql, /FROM reports\s*(?:\n|$)(?!.*WHERE)/s);
}

const reportRecord = {
  id: REPORT_ID,
  tenant_id: CTX.tenantId,
  kind: 'technical',
  title: 'Readiness Summary',
  status: 'ready',
  summary: { readiness_score: 82, open_findings: 1 },
  run_ids: [RUN_ID],
  created_at: FIXED_NOW,
  created_by: CTX.userId,
};

describe('postgres report repository', () => {
  it('maps report, run, verdict, and finding rows with aliases, ISO dates, and default arrays', () => {
    const report = mapReportRow({
      id: REPORT_ID,
      tenant_id: CTX.tenantId,
      kind: 'technical',
      title: 'T',
      status: 'ready',
      summary_json: { readiness_score: 90 },
      run_ids: null,
      created_by: CTX.userId,
      created_at: new Date(FIXED_NOW),
    });
    assert.deepEqual(report.summary, { readiness_score: 90 });
    assert.deepEqual(report.run_ids, []);
    assert.equal(report.created_at, FIXED_NOW);

    const run = mapReportRunRow({
      id: RUN_ID,
      tenant_id: CTX.tenantId,
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      check_id: 'chk_dns',
      vector_family: 'dns',
      safety_class: 'safe',
      status: 'completed',
      summary_json: {},
      created_at: FIXED_NOW,
    });
    assert.equal(run.vector_family, 'dns');
    assert.equal(run.summary, undefined);

    const verdict = mapReportVerdictRow({
      id: 'ver_1',
      tenant_id: CTX.tenantId,
      test_run_id: RUN_ID,
      verdict: 'pass',
      evidence_ids: null,
      placement_confidence_json: { level: 'Low', status: 'not_observed_this_run' },
      created_at: new Date(FIXED_NOW),
    });
    assert.deepEqual(verdict.evidence_ids, []);
    assert.deepEqual(verdict.placement_confidence, {
      level: 'Low',
      status: 'not_observed_this_run',
    });
    assert.equal(verdict.created_at, FIXED_NOW);

    const finding = mapReportFindingRow({
      id: 'find_1',
      tenant_id: CTX.tenantId,
      title: 'Gap',
      severity: 'high',
      status: 'open',
      evidence_ids: ['ev_1'],
      created_at: FIXED_NOW,
      updated_at: null,
    });
    assert.deepEqual(finding.evidence_ids, ['ev_1']);
    assert.equal(finding.updated_at, undefined);
  });

  it('createReport inserts with tenant context and maps summary to summary_json', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('INSERT INTO reports')) {
        assertUsesTenantPredicate(text, params, CTX.tenantId);
        assertNoInterpolatedValue(text, REPORT_ID);
        assert.match(text, /summary_json/);
        assert.match(text, /\$6::jsonb/);
        const summaryParam = params[5];
        assert.equal(typeof summaryParam, 'string');
        assert.deepEqual(JSON.parse(summaryParam), reportRecord.summary);
        return {
          rows: [
            {
              ...reportRecord,
              summary_json: reportRecord.summary,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createReportRepository(pool);
    const row = await repo.createReport(CTX, reportRecord);
    assert.equal(row.id, REPORT_ID);
    assert.deepEqual(row.summary, reportRecord.summary);
    assert.deepEqual(row.run_ids, [RUN_ID]);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('getReport uses tenant and id predicates', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.includes('FROM reports')) {
        assertKeyedTenantIdLookup(text, params, CTX.tenantId, REPORT_ID);
        return {
          rows: [
            {
              ...reportRecord,
              summary_json: reportRecord.summary,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createReportRepository(pool);
    const row = await repo.getReport(CTX, REPORT_ID);
    assert.equal(row.id, REPORT_ID);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('listReports scopes by tenant_id, orders newest first, and bounds limit', async () => {
    const pool = createRecordingPool((text) => {
      if (text.includes('FROM reports')) {
        return {
          rows: [
            {
              ...reportRecord,
              summary_json: reportRecord.summary,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createReportRepository(pool);
    const items = await repo.listReports(CTX, { limit: 9999 });
    assert.equal(items.length, 1);
    assertTenantWrapped(pool.client, CTX.tenantId);
    const [q] = dataQueries(pool.client);
    assertUsesTenantPredicate(q.text, q.params, CTX.tenantId);
    assert.match(q.text, /ORDER BY created_at DESC/);
    assert.equal(q.params[1], 500);
  });

  it('listRunsForReport returns [] for empty run ids without using the pool', async () => {
    const pool = createNoConnectPool();
    const repo = createReportRepository(pool);
    const runs = await repo.listRunsForReport(CTX, []);
    assert.deepEqual(runs, []);
  });

  it('listVerdictsForRunIds returns [] for empty run ids without using the pool', async () => {
    const pool = createNoConnectPool();
    const repo = createReportRepository(pool);
    const verdicts = await repo.listVerdictsForRunIds(CTX, []);
    assert.deepEqual(verdicts, []);
  });

  it('listRunsForReport uses tenant predicate and array parameter for run ids', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.includes('FROM test_runs')) {
        assert.match(text, /tenant_id = \$1/);
        assert.match(text, /id = ANY\(\$2::text\[\]\)/);
        assert.match(text, /ORDER BY array_position\(\$2::text\[\], id\)/);
        assert.deepEqual(params, [CTX.tenantId, [RUN_ID, 'run_2']]);
        assertNoInterpolatedValue(text, RUN_ID);
        assertNoInterpolatedValue(text, 'run_2');
        return {
          rows: [
            {
              id: RUN_ID,
              tenant_id: CTX.tenantId,
              target_group_id: 'tg_1',
              check_id: 'chk_1',
              status: 'completed',
              created_at: FIXED_NOW,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createReportRepository(pool);
    const runs = await repo.listRunsForReport(CTX, [RUN_ID, 'run_2']);
    assert.equal(runs.length, 1);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('listVerdictsForRunIds uses tenant predicate and array parameter for test_run_id', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.includes('FROM verdicts')) {
        assert.match(text, /tenant_id = \$1/);
        assert.match(text, /test_run_id = ANY\(\$2::text\[\]\)/);
        assert.match(text, /ORDER BY array_position\(\$2::text\[\], test_run_id\)/);
        assert.deepEqual(params, [CTX.tenantId, [RUN_ID]]);
        assertNoInterpolatedValue(text, RUN_ID);
        return {
          rows: [
            {
              id: 'ver_1',
              tenant_id: CTX.tenantId,
              test_run_id: RUN_ID,
              verdict: 'pass',
              evidence_ids: [],
              created_at: FIXED_NOW,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createReportRepository(pool);
    const verdicts = await repo.listVerdictsForRunIds(CTX, [RUN_ID]);
    assert.equal(verdicts.length, 1);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('listFindingsForExport scopes by tenant, optional status, and export limit', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.includes('FROM findings')) {
        assert.match(text, /tenant_id = \$1/);
        assert.match(text, /status = \$2/);
        assert.match(text, /ORDER BY created_at DESC/);
        assert.equal(params[0], CTX.tenantId);
        assert.equal(params[1], 'open');
        assert.equal(params[2], 500);
        assertNoInterpolatedValue(text, 'open');
        return {
          rows: [
            {
              id: 'find_1',
              tenant_id: CTX.tenantId,
              title: 'Gap',
              severity: 'medium',
              status: 'open',
              evidence_ids: [],
              created_at: FIXED_NOW,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createReportRepository(pool);
    const findings = await repo.listFindingsForExport(CTX, { status: 'open' });
    assert.equal(findings.length, 1);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });
});