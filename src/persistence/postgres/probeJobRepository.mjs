import { withTenantContext } from './tenantContext.mjs';

const PROBE_JOB_COLUMNS = `id, tenant_id, test_run_id, target_id, check_id, vector_family, status,
  nonce_hash, nonce_for_worker, probe_profile, constraints_json, target_descriptor_json,
  worker_metadata_json, job_signature, leased_at, leased_by, completed_at, created_at`;

const PROBE_JOB_COLUMNS_QUALIFIED = PROBE_JOB_COLUMNS.split(',')
  .map((column) => `j.${column.trim()}`)
  .join(', ');

const DEFAULT_LEASE_LIMIT = 50;
const MAX_LEASE_LIMIT = 100;

function toIso(value) {
  if (value == null) return value;
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

function asObject(value) {
  if (value && typeof value === 'object' && !Array.isArray(value)) return value;
  return {};
}

function normalizeLeaseLimit(limit) {
  if (limit === undefined || limit === null) return DEFAULT_LEASE_LIMIT;
  const n = Number(limit);
  if (!Number.isFinite(n) || n < 1) return DEFAULT_LEASE_LIMIT;
  return Math.min(Math.floor(n), MAX_LEASE_LIMIT);
}

/**
 * @param {Record<string, unknown> | null | undefined} row
 */
export function mapProbeJobRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    test_run_id: row.test_run_id,
    target_id: row.target_id ?? undefined,
    check_id: row.check_id,
    vector_family: row.vector_family ?? undefined,
    status: row.status,
    nonce_hash: row.nonce_hash,
    nonce: row.nonce_for_worker ?? undefined,
    probe_profile: asObject(row.probe_profile),
    constraints: asObject(row.constraints_json),
    target: asObject(row.target_descriptor_json),
    worker_metadata: asObject(row.worker_metadata_json),
    job_signature: row.job_signature ?? undefined,
    leased_at: row.leased_at == null ? null : toIso(row.leased_at),
    leased_by: row.leased_by ?? null,
    completed_at: row.completed_at == null ? null : toIso(row.completed_at),
    created_at: toIso(row.created_at),
  };
}

function jobForWorkerResponse(job) {
  const { nonce, ...rest } = job;
  return {
    ...rest,
    nonce,
    job_signature: job.job_signature,
  };
}

/**
 * @param {import('pg').Pool} pool
 */
export function createProbeJobRepository(pool) {
  return {
    async leasePendingJobsForWorker(ctx, workerId, options = {}) {
      const tenantId = ctx.tenantId;
      const limit = normalizeLeaseLimit(options.limit);
      const leasedAt = options.leasedAt ?? new Date().toISOString();

      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `WITH picked AS (
             SELECT id
             FROM probe_jobs
             WHERE tenant_id = $1 AND status = 'pending'
             ORDER BY created_at
             LIMIT $2
             FOR UPDATE SKIP LOCKED
           )
           UPDATE probe_jobs AS j
           SET status = 'leased',
               leased_at = $3::timestamptz,
               leased_by = $4
           FROM picked
           WHERE j.id = picked.id AND j.tenant_id = $1
           RETURNING ${PROBE_JOB_COLUMNS_QUALIFIED}`,
          [tenantId, limit, leasedAt, workerId],
        );
        return rows.map(mapProbeJobRow).map(jobForWorkerResponse);
      });
    },

    async getJobById(ctx, id) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${PROBE_JOB_COLUMNS}
           FROM probe_jobs
           WHERE tenant_id = $1 AND id = $2`,
          [ctx.tenantId, id],
        );
        return mapProbeJobRow(rows[0] ?? null);
      });
    },

    async claimPendingJobForWorker(ctx, id, workerId, leasedAt) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE probe_jobs
           SET status = 'leased',
               leased_at = $4::timestamptz,
               leased_by = $3
           WHERE tenant_id = $1 AND id = $2 AND status = 'pending'
           RETURNING ${PROBE_JOB_COLUMNS}`,
          [ctx.tenantId, id, workerId, leasedAt],
        );
        return mapProbeJobRow(rows[0] ?? null);
      });
    },

    async markJobCompleted(ctx, id, completedAt) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE probe_jobs
           SET status = 'completed',
               completed_at = $3::timestamptz
           WHERE tenant_id = $1 AND id = $2
           RETURNING ${PROBE_JOB_COLUMNS}`,
          [ctx.tenantId, id, completedAt],
        );
        return mapProbeJobRow(rows[0] ?? null);
      });
    },

    async cancelOpenProbeJobsForTestRuns(ctx, testRunIds, cancelledAt) {
      if (!testRunIds?.length) return [];
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE probe_jobs
           SET status = 'cancelled',
               completed_at = $3::timestamptz
           WHERE tenant_id = $1
             AND test_run_id = ANY($2::text[])
             AND status IN ('pending', 'leased')
           RETURNING ${PROBE_JOB_COLUMNS}`,
          [tenantId, testRunIds, cancelledAt],
        );
        return rows.map(mapProbeJobRow);
      });
    },

    async createProbeJob(ctx, record) {
      const tenantId = ctx.tenantId;
      const probeProfile = JSON.stringify(asObject(record.probe_profile));
      const constraintsJson = JSON.stringify(asObject(record.constraints ?? record.constraints_json));
      const targetDescriptorJson = JSON.stringify(asObject(record.target ?? record.target_descriptor_json));
      const workerMetadataJson = JSON.stringify(
        asObject(record.worker_metadata ?? record.worker_metadata_json),
      );

      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO probe_jobs (
             id, tenant_id, test_run_id, target_id, check_id, vector_family, status,
             nonce_hash, nonce_for_worker, probe_profile, constraints_json,
             target_descriptor_json, worker_metadata_json, job_signature, created_at
           )
           VALUES (
             $1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11::jsonb, $12::jsonb, $13::jsonb,
             $14, $15::timestamptz
           )
           RETURNING ${PROBE_JOB_COLUMNS}`,
          [
            record.id,
            tenantId,
            record.test_run_id,
            record.target_id ?? null,
            record.check_id,
            record.vector_family ?? null,
            record.status ?? 'pending',
            record.nonce_hash,
            record.nonce ?? record.nonce_for_worker,
            probeProfile,
            constraintsJson,
            targetDescriptorJson,
            workerMetadataJson,
            record.job_signature ?? null,
            record.created_at,
          ],
        );
        return mapProbeJobRow(rows[0] ?? null);
      });
    },
  };
}