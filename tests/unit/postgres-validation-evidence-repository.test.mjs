import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  createValidationEvidenceRepository,
  mapEventRow,
  mapEvidenceRow,
  mapFindingRow,
  mapTestRunRow,
  mapVerdictRow,
} from '../../src/persistence/postgres/validationEvidenceRepository.mjs';

const CTX = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };
const FIXED_NOW = '2026-06-01T12:00:00.000Z';
const RUN_ID = 'run_abc';
const EVENT_EXT_ID = 'evt_external_1';
const EVIDENCE_ID = 'evidence_1';
const VERDICT_ID = 'verdict_1';
const FINDING_ID = 'finding_1';

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

const testRunRow = {
  id: RUN_ID,
  tenant_id: CTX.tenantId,
  target_group_id: 'tg_1',
  target_id: 'tgt_1',
  check_id: 'chk_1',
  status: 'running',
  awaiting_external_probe: false,
  safety_constraints: { max_events: 10 },
  correlation_json: { nonce_hash: 'nh', window_ms: 120000 },
  summary_json: { ok: true },
  collection_deadline_at: new Date(FIXED_NOW),
  created_at: new Date(FIXED_NOW),
};

describe('postgres validation evidence repository', () => {
  it('maps rows with JSON aliases, ISO dates, and default arrays', () => {
    const run = mapTestRunRow(testRunRow);
    assert.equal(run.collection_deadline_at, FIXED_NOW);
    assert.deepEqual(run.correlation, { nonce_hash: 'nh', window_ms: 120000 });
    assert.deepEqual(run.summary, { ok: true });
    assert.deepEqual(run.safety_constraints, { max_events: 10 });

    const event = mapEventRow({
      id: 'event_1',
      tenant_id: CTX.tenantId,
      event_id: EVENT_EXT_ID,
      timestamp: new Date(FIXED_NOW),
      metadata_json: { probe: 'blocked' },
    });
    assert.equal(event.timestamp, FIXED_NOW);
    assert.deepEqual(event.metadata, { probe: 'blocked' });

    const evidence = mapEvidenceRow({
      id: EVIDENCE_ID,
      tenant_id: CTX.tenantId,
      metadata_json: null,
      created_at: FIXED_NOW,
    });
    assert.deepEqual(evidence.metadata, {});

    const verdict = mapVerdictRow({
      id: VERDICT_ID,
      tenant_id: CTX.tenantId,
      test_run_id: RUN_ID,
      verdict: 'pass',
      evidence_ids: null,
      placement_confidence_json: { level: 'High', status: 'observed_this_run' },
      created_at: FIXED_NOW,
    });
    assert.deepEqual(verdict.evidence_ids, []);
    assert.deepEqual(verdict.placement_confidence, {
      level: 'High',
      status: 'observed_this_run',
    });

    const finding = mapFindingRow({
      id: FINDING_ID,
      tenant_id: CTX.tenantId,
      title: 'T',
      severity: 'high',
      status: 'open',
      evidence_ids: ['ev_1'],
      created_at: FIXED_NOW,
      updated_at: null,
    });
    assert.deepEqual(finding.evidence_ids, ['ev_1']);
    assert.equal(finding.updated_at, null);
  });

  it('listTestRuns and getTestRun use tenant context and predicates', async () => {
    const pool = createRecordingPool((text) => {
      if (text.includes('FROM test_runs')) {
        return { rows: [testRunRow] };
      }
      return { rows: [] };
    });
    const repo = createValidationEvidenceRepository(pool);
    const items = await repo.listTestRuns(CTX);
    assert.equal(items.length, 1);
    assertTenantWrapped(pool.client, CTX.tenantId);
    const listQ = dataQueries(pool.client)[0];
    assertUsesTenantPredicate(listQ.text, listQ.params, CTX.tenantId);

    pool.client.queries.length = 0;
    pool.client.released = false;
    const run = await repo.getTestRun(CTX, RUN_ID);
    assert.equal(run.id, RUN_ID);
    assertTenantWrapped(pool.client, CTX.tenantId);
    const getQ = dataQueries(pool.client)[0];
    assert.match(getQ.text, /WHERE tenant_id = \$1 AND id = \$2/);
    assert.deepEqual(getQ.params, [CTX.tenantId, RUN_ID]);
  });

  it('createTestRun inserts tenant_id column with parameterized values', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('INSERT INTO test_runs')) {
        assertUsesTenantPredicate(text, params, CTX.tenantId);
        assertNoInterpolatedValue(text, RUN_ID);
        return { rows: [testRunRow] };
      }
      return { rows: [] };
    });
    const repo = createValidationEvidenceRepository(pool);
    const row = await repo.createTestRun(CTX, {
      id: RUN_ID,
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      check_id: 'chk_1',
      status: 'running',
      created_at: FIXED_NOW,
    });
    assert.equal(row.id, RUN_ID);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('updateTestRun patches runtime fields with tenant-scoped UPDATE', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('UPDATE test_runs')) {
        assertUsesTenantPredicate(text, params, CTX.tenantId);
        assert.match(text, /status = \$1/);
        assert.match(text, /correlation_json = \$2::jsonb/);
        assertNoInterpolatedValue(text, 'verdicted');
        return {
          rows: [
            {
              ...testRunRow,
              status: 'verdicted',
              correlation_json: { nonce_hash: 'x', window_ms: 1 },
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createValidationEvidenceRepository(pool);
    const row = await repo.updateTestRun(CTX, RUN_ID, {
      status: 'verdicted',
      correlation: { nonce_hash: 'x', window_ms: 1 },
    });
    assert.equal(row.status, 'verdicted');
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('findEventByTenantEventId uses tenant_id and event_id only', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.includes('FROM events')) {
        return {
          rows: [
            {
              id: 'event_1',
              tenant_id: CTX.tenantId,
              event_id: EVENT_EXT_ID,
              timestamp: FIXED_NOW,
              metadata_json: {},
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createValidationEvidenceRepository(pool);
    const event = await repo.findEventByTenantEventId(CTX, EVENT_EXT_ID);
    assert.equal(event.event_id, EVENT_EXT_ID);
    assertTenantWrapped(pool.client, CTX.tenantId);
    const [q] = dataQueries(pool.client);
    assert.match(q.text, /WHERE tenant_id = \$1 AND event_id = \$2/);
    assert.deepEqual(q.params, [CTX.tenantId, EVENT_EXT_ID]);
    assert.doesNotMatch(q.text, /event_id = \$1 AND tenant_id = \$2/);
  });

  it('appendEvent and listRunEvents scope events by tenant and run', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('INSERT INTO events')) {
        assertUsesTenantPredicate(text, params, CTX.tenantId);
        return {
          rows: [
            {
              id: 'event_1',
              tenant_id: CTX.tenantId,
              event_id: EVENT_EXT_ID,
              test_run_id: RUN_ID,
              timestamp: FIXED_NOW,
              metadata_json: {},
            },
          ],
        };
      }
      if (text.includes('FROM events') && text.includes('test_run_id')) {
        return { rows: [] };
      }
      return { rows: [] };
    });
    const repo = createValidationEvidenceRepository(pool);
    await repo.appendEvent(CTX, {
      id: 'event_1',
      event_id: EVENT_EXT_ID,
      test_run_id: RUN_ID,
      timestamp: FIXED_NOW,
    });
    assertTenantWrapped(pool.client, CTX.tenantId);

    pool.client.queries.length = 0;
    pool.client.released = false;
    await repo.listRunEvents(CTX, RUN_ID);
    assertTenantWrapped(pool.client, CTX.tenantId);
    const [q] = dataQueries(pool.client);
    assert.match(q.text, /tenant_id = \$1 AND test_run_id = \$2/);
    assert.match(q.text, /ORDER BY timestamp/);
    assert.match(q.text, /LIMIT \$\d+/);
    assert.deepEqual(q.params, [CTX.tenantId, RUN_ID, 200]);
  });

  it('appendEvidence and getEvidence use tenant-scoped vault access', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('INSERT INTO evidence_vault')) {
        assertUsesTenantPredicate(text, params, CTX.tenantId);
        return {
          rows: [
            {
              id: EVIDENCE_ID,
              tenant_id: CTX.tenantId,
              test_run_id: RUN_ID,
              metadata_json: { label: 'x' },
              created_at: FIXED_NOW,
            },
          ],
        };
      }
      if (text.includes('FROM evidence_vault') && text.includes('AND id')) {
        return {
          rows: [
            {
              id: EVIDENCE_ID,
              tenant_id: CTX.tenantId,
              metadata_json: {},
              created_at: FIXED_NOW,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createValidationEvidenceRepository(pool);
    await repo.appendEvidence(CTX, {
      id: EVIDENCE_ID,
      test_run_id: RUN_ID,
      created_at: FIXED_NOW,
    });
    assertTenantWrapped(pool.client, CTX.tenantId);

    pool.client.queries.length = 0;
    pool.client.released = false;
    await repo.getEvidence(CTX, EVIDENCE_ID);
    assertTenantWrapped(pool.client, CTX.tenantId);
    const [q] = dataQueries(pool.client);
    assert.match(q.text, /WHERE tenant_id = \$1 AND id = \$2/);
  });

  it('createVerdict and getVerdictForRun are tenant-scoped', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('INSERT INTO verdicts')) {
        assertUsesTenantPredicate(text, params, CTX.tenantId);
        return {
          rows: [
            {
              id: VERDICT_ID,
              tenant_id: CTX.tenantId,
              test_run_id: RUN_ID,
              verdict: 'pass',
              evidence_ids: [],
              created_at: FIXED_NOW,
            },
          ],
        };
      }
      if (text.includes('FROM verdicts')) {
        return {
          rows: [
            {
              id: VERDICT_ID,
              tenant_id: CTX.tenantId,
              test_run_id: RUN_ID,
              verdict: 'pass',
              evidence_ids: ['event_1'],
              created_at: FIXED_NOW,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createValidationEvidenceRepository(pool);
    await repo.createVerdict(CTX, {
      id: VERDICT_ID,
      test_run_id: RUN_ID,
      verdict: 'pass',
      created_at: FIXED_NOW,
    });
    assertTenantWrapped(pool.client, CTX.tenantId);

    pool.client.queries.length = 0;
    pool.client.released = false;
    const verdict = await repo.getVerdictForRun(CTX, RUN_ID);
    assert.equal(verdict.verdict, 'pass');
    assertTenantWrapped(pool.client, CTX.tenantId);
    const [q] = dataQueries(pool.client);
    assert.match(q.text, /WHERE tenant_id = \$1 AND test_run_id = \$2/);
  });

  it('findOpenFinding filters by tenant, target tuple, and open status', async () => {
    const pool = createRecordingPool((text) => {
      if (text.includes('FROM findings')) {
        return { rows: [] };
      }
      return { rows: [] };
    });
    const repo = createValidationEvidenceRepository(pool);
    await repo.findOpenFinding(CTX, {
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      check_id: 'chk_1',
    });
    assertTenantWrapped(pool.client, CTX.tenantId);
    const [q] = dataQueries(pool.client);
    assert.match(q.text, /tenant_id = \$1/);
    assert.match(q.text, /target_group_id = \$2/);
    assert.match(q.text, /target_id = \$3/);
    assert.match(q.text, /check_id = \$4/);
    assert.match(q.text, /status = 'open'/);
    assert.deepEqual(q.params, [CTX.tenantId, 'tg_1', 'tgt_1', 'chk_1']);
  });

  it('patchFinding updates only allowed fields with placeholders', async () => {
    const sensitiveNote = 'do-not-interpolate-me';
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('UPDATE findings')) {
        assert.match(text, /status = \$1/);
        assert.match(text, /notes = \$2/);
        assert.match(text, /last_verdict_id = \$3/);
        assert.match(text, /evidence_ids = \$4/);
        assert.match(text, /updated_at = \$5::timestamptz/);
        assertNoInterpolatedValue(text, sensitiveNote);
        assertNoInterpolatedValue(text, 'resolved');
        assertNoInterpolatedValue(text, VERDICT_ID);
        assert.doesNotMatch(text, /SET status = resolved/);
        return {
          rows: [
            {
              id: FINDING_ID,
              tenant_id: CTX.tenantId,
              title: 'F',
              severity: 'medium',
              status: 'resolved',
              evidence_ids: ['ev_2'],
              notes: sensitiveNote,
              last_verdict_id: VERDICT_ID,
              created_at: FIXED_NOW,
              updated_at: FIXED_NOW,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createValidationEvidenceRepository(pool);
    const row = await repo.patchFinding(CTX, FINDING_ID, {
      status: 'resolved',
      notes: sensitiveNote,
      last_verdict_id: VERDICT_ID,
      evidence_ids: ['ev_2'],
      updated_at: FIXED_NOW,
    });
    assert.equal(row.status, 'resolved');
    assertTenantWrapped(pool.client, CTX.tenantId);
    const [q] = dataQueries(pool.client);
    assertUsesTenantPredicate(q.text, q.params, CTX.tenantId);
    assert.ok(q.params.includes(sensitiveNote));
    assert.ok(q.params.includes('resolved'));
  });

  it('createFinding and listFindings use tenant context', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('INSERT INTO findings')) {
        assertUsesTenantPredicate(text, params, CTX.tenantId);
        return {
          rows: [
            {
              id: FINDING_ID,
              tenant_id: CTX.tenantId,
              title: 'Finding',
              severity: 'low',
              status: 'open',
              evidence_ids: [],
              created_at: FIXED_NOW,
              updated_at: null,
            },
          ],
        };
      }
      if (text.includes('FROM findings') && text.includes('ORDER BY')) {
        return { rows: [] };
      }
      return { rows: [] };
    });
    const repo = createValidationEvidenceRepository(pool);
    await repo.createFinding(CTX, {
      id: FINDING_ID,
      title: 'Finding',
      severity: 'low',
      created_at: FIXED_NOW,
    });
    assertTenantWrapped(pool.client, CTX.tenantId);

    pool.client.queries.length = 0;
    pool.client.released = false;
    await repo.listFindings(CTX);
    assertTenantWrapped(pool.client, CTX.tenantId);
    const [q] = dataQueries(pool.client);
    assertUsesTenantPredicate(q.text, q.params, CTX.tenantId);
  });

  it('listFindings applies test_run_id, target, and bounded limit filters', async () => {
    let captured;
    const pool = createRecordingPool((text, params) => {
      if (text.includes('FROM findings') && text.includes('ORDER BY')) {
        captured = { text, params };
        return { rows: [] };
      }
      return { rows: [] };
    });
    const repo = createValidationEvidenceRepository(pool);
    await repo.listFindings(CTX, {
      test_run_id: 'run_1',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      limit: 25,
    });
    assertTenantWrapped(pool.client, CTX.tenantId);
    assert.match(captured.text, /test_run_id = \$\d+/);
    assert.match(captured.text, /target_group_id = \$\d+/);
    assert.match(captured.text, /target_id = \$\d+/);
    assert.match(captured.text, /LIMIT \$\d+/);
    assert.ok(captured.params.includes('run_1'));
    assert.ok(captured.params.includes('tg_1'));
    assert.ok(captured.params.includes('tgt_1'));
    assert.ok(captured.params.includes(25));
  });

  it('listTestRuns applies bounded LIMIT and optional filters with parameterized tenant', async () => {
    const pool = createRecordingPool((text) => {
      if (text.includes('FROM test_runs')) {
        return { rows: [] };
      }
      return { rows: [] };
    });
    const repo = createValidationEvidenceRepository(pool);
    await repo.listTestRuns(CTX, {
      targetGroupId: 'tg_1',
      statuses: ['running', 'verdicted'],
      beforeCreatedAt: FIXED_NOW,
      limit: 9999,
    });
    assertTenantWrapped(pool.client, CTX.tenantId);
    const [q] = dataQueries(pool.client);
    assert.match(q.text, /tenant_id = \$1/);
    assert.match(q.text, /target_group_id = \$2/);
    assert.match(q.text, /status = ANY\(\$3\)/);
    assert.match(q.text, /created_at < \$4::timestamptz/);
    assert.match(q.text, /ORDER BY created_at DESC/);
    assert.match(q.text, /LIMIT \$5/);
    assert.deepEqual(q.params, [CTX.tenantId, 'tg_1', ['running', 'verdicted'], FIXED_NOW, 500]);
    assertUsesTenantPredicate(q.text, q.params, CTX.tenantId);
  });

  it('listRunEvents applies signal type, before timestamp, and bounded LIMIT', async () => {
    const pool = createRecordingPool((text) => {
      if (text.includes('FROM events')) {
        return { rows: [] };
      }
      return { rows: [] };
    });
    const repo = createValidationEvidenceRepository(pool);
    await repo.listRunEvents(CTX, RUN_ID, {
      signalType: 'probe_result',
      beforeTimestamp: FIXED_NOW,
      limit: 50,
    });
    assertTenantWrapped(pool.client, CTX.tenantId);
    const [q] = dataQueries(pool.client);
    assert.match(q.text, /tenant_id = \$1/);
    assert.match(q.text, /test_run_id = \$2/);
    assert.match(q.text, /signal_type = \$3/);
    assert.match(q.text, /timestamp < \$4::timestamptz/);
    assert.match(q.text, /LIMIT \$5/);
    assert.deepEqual(q.params, [CTX.tenantId, RUN_ID, 'probe_result', FIXED_NOW, 50]);
  });

  it('listEvidenceForRun scopes by tenant and run with ORDER BY and LIMIT', async () => {
    const pool = createRecordingPool((text) => {
      if (text.includes('FROM evidence_vault')) {
        return { rows: [] };
      }
      return { rows: [] };
    });
    const repo = createValidationEvidenceRepository(pool);
    await repo.listEvidenceForRun(CTX, RUN_ID, { limit: 25 });
    assertTenantWrapped(pool.client, CTX.tenantId);
    const [q] = dataQueries(pool.client);
    assert.match(q.text, /tenant_id = \$1/);
    assert.match(q.text, /test_run_id = \$2/);
    assert.match(q.text, /ORDER BY created_at DESC/);
    assert.match(q.text, /LIMIT \$3/);
    assert.deepEqual(q.params, [CTX.tenantId, RUN_ID, 25]);
  });

  it('appendEventIdempotent rejects missing event_id', async () => {
    const pool = createRecordingPool(() => ({ rows: [] }));
    const repo = createValidationEvidenceRepository(pool);
    await assert.rejects(
      () =>
        repo.appendEventIdempotent(CTX, {
          id: 'event_1',
          test_run_id: RUN_ID,
          timestamp: FIXED_NOW,
        }),
      /requires record\.event_id/,
    );
    assert.equal(pool.client.queries.length, 0);
  });

  it('appendEventIdempotent uses partial conflict target and parameterized values', async () => {
    const sensitiveMeta = 'secret-probe-token';
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('INSERT INTO events')) {
        assert.match(
          text,
          /ON CONFLICT \(tenant_id, event_id\) WHERE event_id IS NOT NULL/,
        );
        assert.match(text, /DO UPDATE SET/);
        assertNoInterpolatedValue(text, sensitiveMeta);
        assertNoInterpolatedValue(text, EVENT_EXT_ID);
        assert.ok(params.includes(EVENT_EXT_ID));
        assert.ok(
          params.some(
            (p) => typeof p === 'string' && p.includes(sensitiveMeta),
          ),
          'metadata must be passed as a parameterized JSON value',
        );
        return {
          rows: [
            {
              id: 'event_1',
              tenant_id: CTX.tenantId,
              event_id: EVENT_EXT_ID,
              test_run_id: RUN_ID,
              timestamp: FIXED_NOW,
              metadata_json: { token: sensitiveMeta },
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createValidationEvidenceRepository(pool);
    const event = await repo.appendEventIdempotent(CTX, {
      id: 'event_1',
      event_id: EVENT_EXT_ID,
      test_run_id: RUN_ID,
      timestamp: FIXED_NOW,
      metadata: { token: sensitiveMeta },
    });
    assert.equal(event.event_id, EVENT_EXT_ID);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('appendProbeResultEventIdempotent validates required fields and signal_type', async () => {
    const pool = createRecordingPool(() => ({ rows: [] }));
    const repo = createValidationEvidenceRepository(pool);
    const base = {
      id: 'event_probe',
      timestamp: FIXED_NOW,
      nonce_hash: 'nh_1',
    };

    await assert.rejects(
      () => repo.appendProbeResultEventIdempotent(CTX, { ...base, test_run_id: RUN_ID, nonce_hash: '' }),
      /nonce_hash/,
    );
    await assert.rejects(
      () => repo.appendProbeResultEventIdempotent(CTX, { ...base, test_run_id: '', nonce_hash: 'nh_1' }),
      /test_run_id/,
    );
    await assert.rejects(
      () =>
        repo.appendProbeResultEventIdempotent(CTX, {
          ...base,
          test_run_id: RUN_ID,
          signal_type: 'health_ping',
        }),
      /probe_result/,
    );
    assert.equal(pool.client.queries.length, 0);
  });

  it('appendProbeResultEventIdempotent uses probe-result partial conflict and DO UPDATE', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('INSERT INTO events')) {
        assert.match(
          text,
          /ON CONFLICT \(tenant_id, test_run_id, signal_type, nonce_hash\)\s+WHERE signal_type = 'probe_result' AND nonce_hash IS NOT NULL/,
        );
        assert.match(text, /DO UPDATE SET/);
        assert.match(text, /event_id = COALESCE\(EXCLUDED\.event_id, events\.event_id\)/);
        assert.ok(params.includes('probe_result'));
        assert.ok(params.includes('nh_probe'));
        return {
          rows: [
            {
              id: 'event_probe',
              tenant_id: CTX.tenantId,
              test_run_id: RUN_ID,
              signal_type: 'probe_result',
              nonce_hash: 'nh_probe',
              timestamp: FIXED_NOW,
              metadata_json: {},
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createValidationEvidenceRepository(pool);
    const event = await repo.appendProbeResultEventIdempotent(CTX, {
      id: 'event_probe',
      test_run_id: RUN_ID,
      nonce_hash: 'nh_probe',
      timestamp: FIXED_NOW,
    });
    assert.equal(event.signal_type, 'probe_result');
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('createVerdict persists placement_confidence as parameterized JSONB', async () => {
    const placement = { level: 'High', observation_mode: 'canary', status: 'observed_this_run' };
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('INSERT INTO verdicts') && !text.includes('ON CONFLICT')) {
        assert.match(text, /placement_confidence_json/);
        assert.match(text, /\$10::jsonb/);
        assertNoInterpolatedValue(text, 'canary');
        const jsonParam = params[9];
        assert.equal(typeof jsonParam, 'string');
        assert.deepEqual(JSON.parse(jsonParam), placement);
        return {
          rows: [
            {
              id: VERDICT_ID,
              tenant_id: CTX.tenantId,
              test_run_id: RUN_ID,
              verdict: 'pass',
              evidence_ids: [],
              placement_confidence_json: placement,
              created_at: FIXED_NOW,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createValidationEvidenceRepository(pool);
    const verdict = await repo.createVerdict(CTX, {
      id: VERDICT_ID,
      test_run_id: RUN_ID,
      verdict: 'pass',
      placement_confidence: placement,
      created_at: FIXED_NOW,
    });
    assert.deepEqual(verdict.placement_confidence, placement);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('createVerdictIfAbsent upserts with tenant guard and parameterized evidence_ids', async () => {
    const evidenceIds = ['ev_a', 'ev_b'];
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('INSERT INTO verdicts')) {
        assert.match(text, /ON CONFLICT \(test_run_id\)/);
        assert.match(text, /DO UPDATE SET/);
        assert.match(text, /WHERE verdicts\.tenant_id = EXCLUDED\.tenant_id/);
        assert.match(text, /placement_confidence_json = EXCLUDED\.placement_confidence_json/);
        assert.match(text, /\$10::jsonb/);
        assertNoInterpolatedValue(text, evidenceIds[0]);
        assert.deepEqual(params[8], evidenceIds);
        assert.equal(params[9], '{}');
        return {
          rows: [
            {
              id: VERDICT_ID,
              tenant_id: CTX.tenantId,
              test_run_id: RUN_ID,
              verdict: 'fail',
              evidence_ids: evidenceIds,
              created_at: FIXED_NOW,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createValidationEvidenceRepository(pool);
    const verdict = await repo.createVerdictIfAbsent(CTX, {
      id: VERDICT_ID,
      test_run_id: RUN_ID,
      verdict: 'fail',
      evidence_ids: evidenceIds,
      created_at: FIXED_NOW,
    });
    assert.equal(verdict.verdict, 'fail');
    assert.deepEqual(verdict.evidence_ids, evidenceIds);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('upsertOpenFindingFromVerdict uses open-finding partial conflict and updates last_verdict_id', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('INSERT INTO findings')) {
        assert.match(
          text,
          /ON CONFLICT \(tenant_id, target_group_id, target_id, check_id\) WHERE status = 'open'/,
        );
        assert.match(text, /last_verdict_id = EXCLUDED\.last_verdict_id/);
        assert.match(text, /DO UPDATE SET/);
        assert.equal(params[8], 'open');
        assert.ok(params.includes(VERDICT_ID));
        return {
          rows: [
            {
              id: FINDING_ID,
              tenant_id: CTX.tenantId,
              target_group_id: 'tg_1',
              target_id: 'tgt_1',
              check_id: 'chk_1',
              title: 'Open issue',
              severity: 'high',
              status: 'open',
              evidence_ids: ['ev_1'],
              last_verdict_id: VERDICT_ID,
              created_at: FIXED_NOW,
              updated_at: FIXED_NOW,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createValidationEvidenceRepository(pool);
    const finding = await repo.upsertOpenFindingFromVerdict(CTX, {
      id: FINDING_ID,
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      check_id: 'chk_1',
      title: 'Open issue',
      severity: 'high',
      last_verdict_id: VERDICT_ID,
      evidence_ids: ['ev_1'],
      created_at: FIXED_NOW,
    });
    assert.equal(finding.last_verdict_id, VERDICT_ID);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('upsertOpenFindingFromVerdict rejects non-open status before any DB access', async () => {
    const pool = createRecordingPool(() => ({ rows: [] }));
    const repo = createValidationEvidenceRepository(pool);

    await assert.rejects(
      () =>
        repo.upsertOpenFindingFromVerdict(CTX, {
          id: FINDING_ID,
          target_group_id: 'tg_1',
          target_id: 'tgt_1',
          check_id: 'chk_1',
          title: 'Closed issue',
          severity: 'high',
          status: 'resolved',
          created_at: FIXED_NOW,
        }),
      /only accepts open findings/,
    );
    assert.equal(pool.client.queries.length, 0);
  });
});