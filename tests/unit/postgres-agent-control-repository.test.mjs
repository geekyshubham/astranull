import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  createAgentControlRepository,
  mapAgentJobRow,
  mapAgentRow,
} from '../../src/persistence/postgres/agentControlRepository.mjs';

const CTX = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };
const FIXED_NOW = '2026-06-01T12:00:00.000Z';
const AGENT_ID = 'agent_abc';
const JOB_ID = 'job_xyz';

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
  assert.doesNotMatch(sql, /FROM agents\s*(?:\n|$)(?!.*WHERE)/s);
}

const agentRecord = {
  id: AGENT_ID,
  tenant_id: CTX.tenantId,
  name: 'edge-canary',
  hostname: 'host-1',
  fingerprint: 'fp_1',
  target_group_id: 'tg_1',
  environment_id: 'env_demo',
  status: 'online',
  capabilities: ['heartbeat', 'canary'],
  last_heartbeat_at: FIXED_NOW,
  created_at: FIXED_NOW,
  bootstrap_token_id: 'token_1',
  credential_hash: 'chash',
  credential_salt: 'csalt',
};

const agentJobRecord = {
  id: JOB_ID,
  tenant_id: CTX.tenantId,
  agent_id: AGENT_ID,
  test_run_id: 'run_1',
  check_id: 'chk_1',
  target_id: 'tgt_1',
  type: 'observe_window',
  status: 'pending',
  nonce_hash: 'nhash',
  nonce_for_agent: 'nonce_plain',
  created_at: FIXED_NOW,
};

describe('postgres agent control repository', () => {
  it('maps agent and agent job rows with ISO dates, arrays, and json aliases', () => {
    const agent = mapAgentRow({
      id: AGENT_ID,
      tenant_id: CTX.tenantId,
      name: 'A',
      hostname: 'h',
      status: 'online',
      capabilities: null,
      fingerprint: null,
      credential_hash: 'h',
      credential_salt: 's',
      last_heartbeat_at: new Date(FIXED_NOW),
      metadata_json: { zone: 'edge' },
      created_at: FIXED_NOW,
    });
    assert.equal(agent.last_heartbeat_at, FIXED_NOW);
    assert.deepEqual(agent.capabilities, []);
    assert.deepEqual(agent.metadata, { zone: 'edge' });
    assert.equal(agent.credential, undefined);
    assert.equal(agent.agent_credential, undefined);

    const job = mapAgentJobRow({
      id: JOB_ID,
      tenant_id: CTX.tenantId,
      agent_id: AGENT_ID,
      type: 'observe_window',
      status: 'pending',
      payload_json: { window_sec: 30 },
      created_at: new Date(FIXED_NOW),
      acked_at: null,
      observed_at: null,
    });
    assert.equal(job.created_at, FIXED_NOW);
    assert.equal(job.type, 'observe_window');
    assert.deepEqual(job.payload, { window_sec: 30 });
    assert.equal(job.job_type, undefined);
  });

  it('createAgent inserts with tenant context and parameterized values', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('INSERT INTO agents')) {
        assertUsesTenantPredicate(text, params, CTX.tenantId);
        assertNoInterpolatedValue(text, AGENT_ID);
        assertNoInterpolatedValue(text, 'chash');
        return { rows: [{ ...agentRecord, metadata_json: {} }] };
      }
      return { rows: [] };
    });
    const repo = createAgentControlRepository(pool);
    const row = await repo.createAgent(agentRecord);
    assert.equal(row.id, AGENT_ID);
    assert.equal(row.credential_hash, 'chash');
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('listAgents scopes by tenant_id and orders by created_at', async () => {
    const pool = createRecordingPool((text) => {
      if (text.includes('FROM agents')) {
        return { rows: [{ ...agentRecord, metadata_json: {} }] };
      }
      return { rows: [] };
    });
    const repo = createAgentControlRepository(pool);
    const items = await repo.listAgents(CTX);
    assert.equal(items.length, 1);
    assertTenantWrapped(pool.client, CTX.tenantId);
    const [q] = dataQueries(pool.client);
    assertUsesTenantPredicate(q.text, q.params, CTX.tenantId);
    assert.match(q.text, /ORDER BY created_at/);
  });

  it('getAgentById uses tenant and id predicates', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.includes('FROM agents')) {
        assertUsesTenantPredicate(text, params, CTX.tenantId);
        assertNoInterpolatedValue(text, AGENT_ID);
        return { rows: [{ ...agentRecord, metadata_json: {} }] };
      }
      return { rows: [] };
    });
    const repo = createAgentControlRepository(pool);
    const row = await repo.getAgentById(CTX, AGENT_ID);
    assert.equal(row.id, AGENT_ID);
    assertTenantWrapped(pool.client, CTX.tenantId);
    assert.ok(pool.client.queries[2].params.includes(AGENT_ID));
  });

  it('findAgentByAddressedHint uses hint tenant context and keyed lookup', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.includes('FROM agents')) {
        assertKeyedTenantIdLookup(text, params, CTX.tenantId, AGENT_ID);
        return { rows: [{ ...agentRecord, metadata_json: {} }] };
      }
      return { rows: [] };
    });
    const repo = createAgentControlRepository(pool);
    const row = await repo.findAgentByAddressedHint({
      tenantId: CTX.tenantId,
      id: AGENT_ID,
    });
    assert.equal(row.tenant_id, CTX.tenantId);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('updateAgentHeartbeat sets online status and optional version/capabilities', async () => {
    const heartbeatAt = '2026-06-02T08:00:00.000Z';
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('UPDATE agents')) {
        assert.match(text, /status = 'online'/);
        assert.match(text, /last_heartbeat_at = \$1::timestamptz/);
        assert.match(text, /version = \$2/);
        assert.match(text, /capabilities = \$3/);
        assertUsesTenantPredicate(text, params, CTX.tenantId);
        assert.equal(params[0], heartbeatAt);
        assert.equal(params[1], '1.2.3');
        assert.deepEqual(params[2], ['heartbeat']);
        return {
          rows: [
            {
              ...agentRecord,
              version: '1.2.3',
              capabilities: ['heartbeat'],
              last_heartbeat_at: heartbeatAt,
              metadata_json: {},
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createAgentControlRepository(pool);
    const row = await repo.updateAgentHeartbeat(
      { tenantId: CTX.tenantId, id: AGENT_ID },
      { version: '1.2.3', capabilities: ['heartbeat'], last_heartbeat_at: heartbeatAt },
    );
    assert.equal(row.status, 'online');
    assert.equal(row.version, '1.2.3');
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('revokeAgent marks agent revoked with tenant predicate and metadata timestamp', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('UPDATE agents')) {
        assert.match(text, /status = 'revoked'/);
        assert.match(text, /metadata_json = COALESCE\(metadata_json, '\{\}'::jsonb\) \|\| \$1::jsonb/);
        assertUsesTenantPredicate(text, params, CTX.tenantId);
        assert.equal(params[0], JSON.stringify({ revoked_at: FIXED_NOW }));
        assert.equal(params[1], CTX.tenantId);
        assert.equal(params[2], AGENT_ID);
        assertNoInterpolatedValue(text, FIXED_NOW);
        return {
          rows: [
            {
              ...agentRecord,
              status: 'revoked',
              metadata_json: { revoked_at: FIXED_NOW },
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createAgentControlRepository(pool);
    const row = await repo.revokeAgent(CTX, AGENT_ID, FIXED_NOW);
    assert.equal(row.status, 'revoked');
    assert.deepEqual(row.metadata, { revoked_at: FIXED_NOW });
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('createAgentJob inserts using type column not job_type', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('INSERT INTO agent_jobs')) {
        assertUsesTenantPredicate(text, params, CTX.tenantId);
        assert.match(text, /\btype\b/);
        assert.doesNotMatch(text, /\bjob_type\b/);
        assertNoInterpolatedValue(text, JOB_ID);
        assertNoInterpolatedValue(text, 'nonce_plain');
        return { rows: [{ ...agentJobRecord, payload_json: {} }] };
      }
      return { rows: [] };
    });
    const repo = createAgentControlRepository(pool);
    const row = await repo.createAgentJob(agentJobRecord);
    assert.equal(row.type, 'observe_window');
    assert.equal(row.nonce_for_agent, 'nonce_plain');
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('listPendingAgentJobs filters pending jobs for one agent', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.includes('FROM agent_jobs')) {
        assert.match(text, /status = 'pending'/);
        assertUsesTenantPredicate(text, params, CTX.tenantId);
        assert.equal(params[1], AGENT_ID);
        return { rows: [{ ...agentJobRecord, payload_json: {} }] };
      }
      return { rows: [] };
    });
    const repo = createAgentControlRepository(pool);
    const items = await repo.listPendingAgentJobs({
      tenantId: CTX.tenantId,
      agentId: AGENT_ID,
    });
    assert.equal(items.length, 1);
    assertTenantWrapped(pool.client, CTX.tenantId);
    const [q] = dataQueries(pool.client);
    assert.match(q.text, /ORDER BY created_at/);
    assert.doesNotMatch(q.text, /\bjob_type\b/);
  });

  it('ackAgentJob only updates pending jobs', async () => {
    const ackedAt = '2026-06-03T09:00:00.000Z';
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('UPDATE agent_jobs')) {
        assert.match(text, /status = 'acked'/);
        assert.match(text, /AND status = 'pending'/);
        assertUsesTenantPredicate(text, params, CTX.tenantId);
        assert.equal(params[0], ackedAt);
        assert.equal(params[2], AGENT_ID);
        assert.equal(params[3], JOB_ID);
        return {
          rows: [
            {
              ...agentJobRecord,
              status: 'acked',
              acked_at: ackedAt,
              payload_json: {},
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createAgentControlRepository(pool);
    const row = await repo.ackAgentJob(
      { tenantId: CTX.tenantId, agentId: AGENT_ID, jobId: JOB_ID },
      ackedAt,
    );
    assert.equal(row.status, 'acked');
    assert.equal(row.acked_at, ackedAt);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('markAgentJobObserved only updates acked jobs', async () => {
    const observedAt = '2026-06-04T10:00:00.000Z';
    const pool = createRecordingPool((text, params) => {
      if (text.startsWith('UPDATE agent_jobs')) {
        assert.match(text, /status = 'observed'/);
        assert.match(text, /AND status = 'acked'/);
        assertUsesTenantPredicate(text, params, CTX.tenantId);
        assert.equal(params[0], observedAt);
        return {
          rows: [
            {
              ...agentJobRecord,
              status: 'observed',
              acked_at: '2026-06-03T09:00:00.000Z',
              observed_at: observedAt,
              payload_json: {},
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createAgentControlRepository(pool);
    const row = await repo.markAgentJobObserved(
      { tenantId: CTX.tenantId, agentId: AGENT_ID, jobId: JOB_ID },
      observedAt,
    );
    assert.equal(row.status, 'observed');
    assert.equal(row.observed_at, observedAt);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('getAgentJobById filters by tenant, agent, and job id', async () => {
    const pool = createRecordingPool((text, params) => {
      if (text.includes('FROM agent_jobs')) {
        assert.match(text, /WHERE tenant_id = \$1 AND agent_id = \$2 AND id = \$3/);
        assert.deepEqual(params, [CTX.tenantId, AGENT_ID, JOB_ID]);
        return { rows: [{ ...agentJobRecord, payload_json: {} }] };
      }
      return { rows: [] };
    });
    const repo = createAgentControlRepository(pool);
    const row = await repo.getAgentJobById({
      tenantId: CTX.tenantId,
      agentId: AGENT_ID,
      jobId: JOB_ID,
    });
    assert.equal(row.id, JOB_ID);
    assert.equal(row.agent_id, AGENT_ID);
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('returns null when keyed agent or job update misses', async () => {
    const pool = createRecordingPool((text) => {
      if (text.includes('FROM agents') || text.startsWith('UPDATE agent_jobs')) {
        return { rows: [] };
      }
      return { rows: [] };
    });
    const repo = createAgentControlRepository(pool);
    assert.equal(await repo.getAgentById(CTX, 'agent_missing'), null);
    assert.equal(
      await repo.ackAgentJob(
        { tenantId: CTX.tenantId, agentId: AGENT_ID, jobId: 'job_missing' },
        FIXED_NOW,
      ),
      null,
    );
  });

  it('rolls back when a tenant-scoped query fails inside tenant context', async () => {
    const pool = createRecordingPool((text) => {
      if (text.includes('FROM agents')) {
        throw new Error('db read failed');
      }
      return { rows: [] };
    });
    const repo = createAgentControlRepository(pool);
    await assert.rejects(() => repo.getAgentById(CTX, AGENT_ID), /db read failed/);
    assert.ok(pool.client.queries.some((q) => q.text.trim() === 'ROLLBACK'));
    assert.ok(!pool.client.queries.some((q) => q.text.trim() === 'COMMIT'));
    assert.equal(pool.client.released, true);
  });
});
