import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  createProbeJobRepository,
  mapProbeJobRow,
} from '../../src/persistence/postgres/probeJobRepository.mjs';

const CTX = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };
const FIXED_NOW = '2026-06-01T12:00:00.000Z';
const WORKER_ID = 'pw_worker_1';

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

function sampleRow(overrides = {}) {
  return {
    id: 'pjob_1',
    tenant_id: CTX.tenantId,
    test_run_id: 'run_1',
    target_id: 'tgt_1',
    check_id: 'origin.direct_bypass.safe',
    vector_family: 'origin',
    status: 'pending',
    nonce_hash: 'nh_abc',
    nonce_for_worker: 'nonce_plain',
    probe_profile: { kind: 'metadata_marker' },
    constraints_json: { max_requests: 1, timeout_ms: 5000 },
    target_descriptor_json: { id: 'tgt_1', kind: 'ip', value: '203.0.113.1' },
    worker_metadata_json: { check_title: 'Safe' },
    job_signature: 'sig_hex',
    leased_at: null,
    leased_by: null,
    completed_at: null,
    created_at: FIXED_NOW,
    ...overrides,
  };
}

describe('postgres probe job repository', () => {
  it('maps probe job JSON columns to worker-facing shape', () => {
    const job = mapProbeJobRow(sampleRow());
    assert.equal(job.id, 'pjob_1');
    assert.equal(job.nonce, 'nonce_plain');
    assert.equal(job.constraints.max_requests, 1);
    assert.equal(job.target.value, '203.0.113.1');
    assert.equal(job.worker_metadata.check_title, 'Safe');
  });

  it('leases pending jobs with tenant context, bounded limit, and SKIP LOCKED', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (sql.includes('WITH picked AS')) {
        assert.deepEqual(params, [CTX.tenantId, 25, FIXED_NOW, WORKER_ID]);
        return { rows: [sampleRow({ status: 'leased', leased_by: WORKER_ID })] };
      }
      return { rows: [] };
    });
    const repo = createProbeJobRepository(pool);
    const jobs = await repo.leasePendingJobsForWorker(CTX, WORKER_ID, {
      limit: 25,
      leasedAt: FIXED_NOW,
    });
    assert.equal(jobs.length, 1);
    assert.equal(jobs[0].job_signature, 'sig_hex');
    assertTenantWrapped(pool.client, CTX.tenantId);
    const lease = dataQueries(pool.client).find((q) => q.text.includes('WITH picked AS'));
    assert.match(lease.text, /FOR UPDATE SKIP LOCKED/);
    assert.match(lease.text, /LIMIT \$2/);
    assert.ok(!lease.text.includes('ten_demo'));
  });

  it('looks up and updates jobs with parameterized tenant-scoped SQL', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (sql.includes('FROM probe_jobs') && sql.includes('WHERE tenant_id = $1 AND id = $2')) {
        return { rows: [sampleRow()] };
      }
      if (sql.includes("status = 'leased'") && sql.includes("status = 'pending'")) {
        assert.deepEqual(params.slice(0, 4), [CTX.tenantId, 'pjob_1', WORKER_ID, FIXED_NOW]);
        return { rows: [sampleRow({ status: 'leased' })] };
      }
      if (sql.includes("status = 'completed'")) {
        assert.deepEqual(params, [CTX.tenantId, 'pjob_1', FIXED_NOW]);
        return { rows: [sampleRow({ status: 'completed' })] };
      }
      return { rows: [] };
    });
    const repo = createProbeJobRepository(pool);
    const found = await repo.getJobById(CTX, 'pjob_1');
    assert.equal(found.id, 'pjob_1');
    const claimed = await repo.claimPendingJobForWorker(CTX, 'pjob_1', WORKER_ID, FIXED_NOW);
    assert.equal(claimed.status, 'leased');
    const completed = await repo.markJobCompleted(CTX, 'pjob_1', FIXED_NOW);
    assert.equal(completed.status, 'completed');
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('cancelOpenProbeJobsForTestRuns returns empty without querying when run list is empty', async () => {
    const pool = createRecordingPool(() => ({ rows: [] }));
    const repo = createProbeJobRepository(pool);
    const jobs = await repo.cancelOpenProbeJobsForTestRuns(CTX, [], FIXED_NOW);
    assert.deepEqual(jobs, []);
    assert.equal(dataQueries(pool.client).length, 0);
  });

  it('cancelOpenProbeJobsForTestRuns cancels pending and leased jobs for run IDs with tenant-scoped SQL', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (sql.includes("status = 'cancelled'") && sql.includes('ANY($2::text[])')) {
        assert.deepEqual(params, [CTX.tenantId, ['run_1', 'run_2'], FIXED_NOW]);
        assert.match(sql, /tenant_id = \$1/);
        assert.match(sql, /status IN \('pending', 'leased'\)/);
        assert.ok(!sql.includes('ten_demo'));
        return {
          rows: [
            sampleRow({ id: 'pjob_a', status: 'cancelled', test_run_id: 'run_1' }),
            sampleRow({ id: 'pjob_b', status: 'cancelled', test_run_id: 'run_2' }),
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createProbeJobRepository(pool);
    const jobs = await repo.cancelOpenProbeJobsForTestRuns(CTX, ['run_1', 'run_2'], FIXED_NOW);
    assert.equal(jobs.length, 2);
    assert.equal(jobs[0].status, 'cancelled');
    assert.equal(jobs[0].id, 'pjob_a');
    assertTenantWrapped(pool.client, CTX.tenantId);
  });

  it('createProbeJob inserts tenant-scoped row with nonce and signature columns', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (sql.includes('INSERT INTO probe_jobs')) {
        assert.deepEqual(params[0], 'pjob_new');
        assert.equal(params[1], CTX.tenantId);
        assert.equal(params[8], 'nonce_plain');
        return { rows: [sampleRow({ id: 'pjob_new' })] };
      }
      return { rows: [] };
    });
    const repo = createProbeJobRepository(pool);
    const job = await repo.createProbeJob(CTX, {
      id: 'pjob_new',
      test_run_id: 'run_1',
      target_id: 'tgt_1',
      check_id: 'origin.direct_bypass.safe',
      nonce_hash: 'nh_abc',
      nonce: 'nonce_plain',
      job_signature: 'sig_hex',
      created_at: FIXED_NOW,
    });
    assert.equal(job.id, 'pjob_new');
    assertTenantWrapped(pool.client, CTX.tenantId);
    const insert = dataQueries(pool.client).find((q) => q.text.includes('INSERT INTO probe_jobs'));
    assert.ok(insert);
    assert.ok(!insert.text.includes('ten_demo'));
  });
});