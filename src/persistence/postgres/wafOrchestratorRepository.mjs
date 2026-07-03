import { buildAuditRecord } from '../../audit.mjs';
import { withTenantContext } from './tenantContext.mjs';
import { mapWafDriftEventRow } from './wafPostureRepository.mjs';

const LAST_AUDIT_ROW_SQL = `SELECT id, tenant_id, timestamp, sequence, prev_hash, entry_hash,
                  actor_user_id, actor_role, action, resource_type, resource_id, metadata_json
           FROM audit_logs
           WHERE tenant_id = $1
           ORDER BY sequence DESC
           LIMIT 1`;

const INSERT_AUDIT_SQL = `INSERT INTO audit_logs (
             id, tenant_id, timestamp, sequence, prev_hash, entry_hash,
             actor_user_id, actor_role, action, resource_type, resource_id, metadata_json
           ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb)`;

function auditInsertParams(entry) {
  const metadata = entry.metadata ?? {};
  return [
    entry.id,
    entry.tenant_id,
    entry.timestamp,
    entry.sequence,
    entry.prev_hash ?? null,
    entry.entry_hash,
    entry.actor_user_id ?? null,
    entry.actor_role ?? null,
    entry.action,
    entry.resource_type ?? null,
    entry.resource_id ?? null,
    JSON.stringify(metadata),
  ];
}

function rowToAuditEntry(row) {
  if (!row) return null;
  const { metadata_json: metadataJson, ...rest } = row;
  const timestamp =
    row.timestamp instanceof Date ? row.timestamp.toISOString() : row.timestamp;
  return {
    ...rest,
    timestamp,
    sequence: Number(row.sequence),
    metadata: metadataJson ?? {},
  };
}

async function appendAuditEventInTransaction(client, entry, now) {
  await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [entry.tenant_id]);
  const { rows } = await client.query(LAST_AUDIT_ROW_SQL, [entry.tenant_id]);
  const priorEntry = rowToAuditEntry(rows[0] ?? null);
  const record = buildAuditRecord(entry, priorEntry, now);
  await client.query(INSERT_AUDIT_SQL, auditInsertParams(record));
  return record;
}

const VALIDATION_PLAN_COLUMNS = `id, tenant_id, target_group_id, mode, schedule_interval, custom_cron_expression,
  scenarios_json, max_concurrent, timeout_ms, state, delegated_jobs_json,
  created_at, updated_at, executed_at, cancelled_at, execution_lock_token, execution_lock_expires_at`;

const WAF_BASELINE_COLUMNS = `id, tenant_id, waf_asset_id, state, baseline_json, approved_by, approved_at,
  created_at, updated_at`;

const BASELINE_APPROVAL_COLUMNS = `id, tenant_id, baseline_id, waf_asset_id, approver, approval_notes,
  approved_at, fingerprint_summary_json, created_at`;

const RETEST_REQUEST_COLUMNS = `id, tenant_id, drift_event_id, waf_asset_id, retest_plan_json, requested_by,
  priority, status, verdict, verdict_reason, delegated_jobs_json, created_at, updated_at, completed_at,
  execution_lock_token, execution_lock_expires_at`;

const WAF_DRIFT_EVENT_COLUMNS = `id, tenant_id, waf_asset_id, baseline_id, drift_type, severity,
  before_summary_json, after_summary_json, status, finding_id, created_at, resolved_at`;

function toIso(value) {
  if (value == null) return value;
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

function parseJsonArray(value) {
  if (Array.isArray(value)) return value;
  return [];
}

function parseJsonObject(value) {
  if (value && typeof value === 'object' && !Array.isArray(value)) return value;
  return {};
}

export function mapValidationPlanRow(row) {
  if (!row) return null;
  const scenarios = parseJsonArray(row.scenarios_json);
  const delegatedJobs = parseJsonArray(row.delegated_jobs_json);
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    target_group_id: row.target_group_id,
    mode: row.mode,
    state: row.state,
    scenarios,
    max_concurrent: Number(row.max_concurrent ?? 1),
    timeout_ms: Number(row.timeout_ms ?? 60_000),
    ...(row.schedule_interval ? { schedule_interval: row.schedule_interval } : {}),
    ...(row.custom_cron_expression ? { custom_cron_expression: row.custom_cron_expression } : {}),
    ...(delegatedJobs.length > 0 ? { delegated_jobs: delegatedJobs } : { delegated_jobs: delegatedJobs }),
    created_at: toIso(row.created_at),
    updated_at: toIso(row.updated_at),
    ...(row.executed_at ? { executed_at: toIso(row.executed_at) } : {}),
    ...(row.cancelled_at ? { cancelled_at: toIso(row.cancelled_at) } : {}),
  };
}

export function formatValidationPlanForApi(record) {
  if (!record) return null;
  return {
    id: record.id,
    target_group_id: record.target_group_id,
    mode: record.mode,
    state: record.state,
    scenarios: record.scenarios ?? [],
    max_concurrent: record.max_concurrent,
    timeout_ms: record.timeout_ms,
    ...(record.schedule_interval ? { schedule_interval: record.schedule_interval } : {}),
    ...(record.custom_cron_expression
      ? { custom_cron_expression: record.custom_cron_expression }
      : {}),
    ...(Array.isArray(record.delegated_jobs) ? { delegated_jobs: record.delegated_jobs } : {}),
    created_at: record.created_at,
    ...(record.updated_at ? { updated_at: record.updated_at } : {}),
    ...(record.executed_at ? { executed_at: record.executed_at } : {}),
    ...(record.cancelled_at ? { cancelled_at: record.cancelled_at } : {}),
  };
}

export function mapWafBaselineRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    waf_asset_id: row.waf_asset_id,
    state: row.state,
    baseline_json: parseJsonObject(row.baseline_json),
    approved_by: row.approved_by ?? null,
    approved_at: row.approved_at == null ? null : toIso(row.approved_at),
    created_at: toIso(row.created_at),
    updated_at: toIso(row.updated_at),
  };
}

export function mapBaselineApprovalRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    baseline_id: row.baseline_id,
    waf_asset_id: row.waf_asset_id,
    approver: row.approver,
    approval_notes: row.approval_notes,
    approved_at: toIso(row.approved_at),
    fingerprint_summary: parseJsonObject(row.fingerprint_summary_json),
    created_at: toIso(row.created_at),
  };
}

export function formatRetestRequestForApi(record) {
  if (!record) return null;
  return {
    id: record.id,
    drift_event_id: record.drift_event_id,
    waf_asset_id: record.waf_asset_id,
    retest_plan: record.retest_plan ?? [],
    requested_by: record.requested_by,
    priority: record.priority,
    status: record.status,
    ...(record.verdict ? { verdict: record.verdict } : {}),
    ...(record.verdict_reason ? { verdict_reason: record.verdict_reason } : {}),
    ...(Array.isArray(record.delegated_jobs) && record.delegated_jobs.length > 0
      ? { delegated_jobs: record.delegated_jobs }
      : {}),
    created_at: record.created_at,
    ...(record.updated_at ? { updated_at: record.updated_at } : {}),
    ...(record.completed_at ? { completed_at: record.completed_at } : {}),
  };
}

export function mapRetestRequestRow(row) {
  if (!row) return null;
  const retestPlan = parseJsonArray(row.retest_plan_json);
  const delegatedJobs = parseJsonArray(row.delegated_jobs_json);
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    drift_event_id: row.drift_event_id,
    waf_asset_id: row.waf_asset_id,
    retest_plan: retestPlan,
    requested_by: row.requested_by,
    priority: row.priority,
    status: row.status,
    ...(row.verdict ? { verdict: row.verdict } : {}),
    ...(row.verdict_reason ? { verdict_reason: row.verdict_reason } : {}),
    ...(delegatedJobs.length > 0 ? { delegated_jobs: delegatedJobs } : {}),
    created_at: toIso(row.created_at),
    updated_at: toIso(row.updated_at),
    ...(row.completed_at ? { completed_at: toIso(row.completed_at) } : {}),
  };
}

const PLAN_PATCH_COLUMNS = new Set([
  'state',
  'delegated_jobs',
  'delegated_jobs_json',
  'updated_at',
  'executed_at',
  'cancelled_at',
]);

function normalizeValidationPlanPatch(patch) {
  const normalized = { ...patch };
  if (Object.prototype.hasOwnProperty.call(normalized, 'delegated_jobs')) {
    if (!Object.prototype.hasOwnProperty.call(normalized, 'delegated_jobs_json')) {
      normalized.delegated_jobs_json = normalized.delegated_jobs;
    }
    delete normalized.delegated_jobs;
  }
  return normalized;
}

const RETEST_PATCH_COLUMNS = new Set([
  'status',
  'verdict',
  'verdict_reason',
  'delegated_jobs',
  'delegated_jobs_json',
  'updated_at',
  'completed_at',
]);

function normalizeRetestPatch(patch) {
  const normalized = { ...patch };
  if (Object.prototype.hasOwnProperty.call(normalized, 'delegated_jobs')) {
    if (!Object.prototype.hasOwnProperty.call(normalized, 'delegated_jobs_json')) {
      normalized.delegated_jobs_json = normalized.delegated_jobs;
    }
    delete normalized.delegated_jobs;
  }
  return normalized;
}

function appendValidationPlanPatchSets(normalizedPatch, sets, params, startParamIdx) {
  let paramIdx = startParamIdx;
  for (const [key, value] of Object.entries(normalizedPatch)) {
    if (!PLAN_PATCH_COLUMNS.has(key)) continue;
    if (key === 'delegated_jobs_json') {
      sets.push(`delegated_jobs_json = $${paramIdx}::jsonb`);
      params.push(JSON.stringify(value ?? []));
    } else if (key.endsWith('_at')) {
      sets.push(`${key} = $${paramIdx}::timestamptz`);
      params.push(value);
    } else {
      sets.push(`${key} = $${paramIdx}`);
      params.push(value);
    }
    paramIdx += 1;
  }
  return paramIdx;
}

function appendRetestPatchSets(normalizedPatch, sets, params, startParamIdx) {
  let paramIdx = startParamIdx;
  for (const [key, value] of Object.entries(normalizedPatch)) {
    if (!RETEST_PATCH_COLUMNS.has(key)) continue;
    if (key === 'delegated_jobs_json') {
      sets.push(`delegated_jobs_json = $${paramIdx}::jsonb`);
      params.push(JSON.stringify(value ?? []));
    } else if (key.endsWith('_at')) {
      sets.push(`${key} = $${paramIdx}::timestamptz`);
      params.push(value);
    } else {
      sets.push(`${key} = $${paramIdx}`);
      params.push(value);
    }
    paramIdx += 1;
  }
  return paramIdx;
}

export function createWafOrchestratorRepository(pool) {
  return {
    async listValidationPlans(ctx) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${VALIDATION_PLAN_COLUMNS}
           FROM waf_validation_plans
           WHERE tenant_id = $1
           ORDER BY created_at DESC`,
          [tenantId],
        );
        return rows.map(mapValidationPlanRow);
      });
    },

    async listScheduledValidationPlans(ctx) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${VALIDATION_PLAN_COLUMNS}
           FROM waf_validation_plans
           WHERE tenant_id = $1 AND state = 'scheduled'
           ORDER BY created_at DESC`,
          [tenantId],
        );
        return rows.map(mapValidationPlanRow);
      });
    },

    async listRunnableValidationPlans(ctx) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${VALIDATION_PLAN_COLUMNS}
           FROM waf_validation_plans
           WHERE tenant_id = $1 AND state IN ('scheduled', 'running')
           ORDER BY created_at DESC`,
          [tenantId],
        );
        return rows.map(mapValidationPlanRow);
      });
    },

    async getValidationPlan(ctx, id) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${VALIDATION_PLAN_COLUMNS}
           FROM waf_validation_plans
           WHERE tenant_id = $1 AND id = $2`,
          [tenantId, id],
        );
        return mapValidationPlanRow(rows[0] ?? null);
      });
    },

    async createValidationPlan(ctx, record) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO waf_validation_plans (
             id, tenant_id, target_group_id, mode, schedule_interval, custom_cron_expression,
             scenarios_json, max_concurrent, timeout_ms, state, delegated_jobs_json,
             created_at, updated_at
           )
           VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10, $11::jsonb, $12::timestamptz, $13::timestamptz)
           RETURNING ${VALIDATION_PLAN_COLUMNS}`,
          [
            record.id,
            tenantId,
            record.target_group_id,
            record.mode,
            record.schedule_interval ?? null,
            record.custom_cron_expression ?? null,
            JSON.stringify(record.scenarios ?? []),
            record.max_concurrent,
            record.timeout_ms,
            record.state,
            JSON.stringify(record.delegated_jobs ?? []),
            record.created_at,
            record.updated_at,
          ],
        );
        return mapValidationPlanRow(rows[0]);
      });
    },

    async updateValidationPlan(ctx, id, patch) {
      const tenantId = ctx.tenantId;
      const normalizedPatch = normalizeValidationPlanPatch(patch);
      const sets = [];
      const params = [tenantId, id];
      let paramIdx = 3;

      for (const [key, value] of Object.entries(normalizedPatch)) {
        if (!PLAN_PATCH_COLUMNS.has(key)) continue;
        if (key === 'delegated_jobs_json') {
          sets.push(`delegated_jobs_json = $${paramIdx}::jsonb`);
          params.push(JSON.stringify(value ?? []));
        } else if (key.endsWith('_at')) {
          sets.push(`${key} = $${paramIdx}::timestamptz`);
          params.push(value);
        } else {
          sets.push(`${key} = $${paramIdx}`);
          params.push(value);
        }
        paramIdx += 1;
      }

      if (sets.length === 0) {
        return this.getValidationPlan(ctx, id);
      }

      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE waf_validation_plans
           SET ${sets.join(', ')}
           WHERE tenant_id = $1 AND id = $2
           RETURNING ${VALIDATION_PLAN_COLUMNS}`,
          params,
        );
        return mapValidationPlanRow(rows[0] ?? null);
      });
    },

    async claimValidationPlanExecution(ctx, id, lease) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE waf_validation_plans
           SET execution_lock_token = $3,
               execution_lock_expires_at = $4::timestamptz,
               updated_at = $5::timestamptz
           WHERE tenant_id = $1 AND id = $2
             AND state IN ('draft', 'scheduled', 'running')
             AND (execution_lock_token IS NULL OR execution_lock_expires_at <= $5::timestamptz)
           RETURNING ${VALIDATION_PLAN_COLUMNS}`,
          [tenantId, id, lease.lock_token, lease.lock_expires_at, lease.now],
        );
        return mapValidationPlanRow(rows[0] ?? null);
      });
    },

    async stageValidationPlanDelegation(ctx, id, lockToken, patch) {
      const tenantId = ctx.tenantId;
      const normalizedPatch = normalizeValidationPlanPatch(patch ?? {});
      const sets = [];
      const params = [tenantId, id, lockToken];
      appendValidationPlanPatchSets(normalizedPatch, sets, params, 4);

      if (sets.length === 0) {
        return this.getValidationPlan(ctx, id);
      }

      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE waf_validation_plans
           SET ${sets.join(', ')}
           WHERE tenant_id = $1 AND id = $2 AND execution_lock_token = $3
             AND state IN ('draft', 'scheduled', 'running')
           RETURNING ${VALIDATION_PLAN_COLUMNS}`,
          params,
        );
        return mapValidationPlanRow(rows[0] ?? null);
      });
    },

    async finishValidationPlanExecution(ctx, id, lockToken, patch) {
      const tenantId = ctx.tenantId;
      const normalizedPatch = normalizeValidationPlanPatch(patch ?? {});
      const sets = ['execution_lock_token = NULL', 'execution_lock_expires_at = NULL'];
      const params = [tenantId, id, lockToken];
      appendValidationPlanPatchSets(normalizedPatch, sets, params, 4);

      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE waf_validation_plans
           SET ${sets.join(', ')}
           WHERE tenant_id = $1 AND id = $2 AND execution_lock_token = $3
             AND state IN ('draft', 'scheduled', 'running')
           RETURNING ${VALIDATION_PLAN_COLUMNS}`,
          params,
        );
        return mapValidationPlanRow(rows[0] ?? null);
      });
    },

    async cancelValidationPlanExecution(ctx, id, patch) {
      const tenantId = ctx.tenantId;
      const cancelledAt = patch?.cancelled_at ?? null;
      const updatedAt = patch?.updated_at ?? null;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE waf_validation_plans
           SET state = 'cancelled',
               cancelled_at = $3::timestamptz,
               updated_at = $4::timestamptz,
               execution_lock_token = NULL,
               execution_lock_expires_at = NULL
           WHERE tenant_id = $1 AND id = $2
             AND state IN ('draft', 'scheduled', 'running')
           RETURNING ${VALIDATION_PLAN_COLUMNS}`,
          [tenantId, id, cancelledAt, updatedAt],
        );
        return mapValidationPlanRow(rows[0] ?? null);
      });
    },

    async releaseValidationPlanExecution(ctx, id, lockToken) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE waf_validation_plans
           SET execution_lock_token = NULL,
               execution_lock_expires_at = NULL
           WHERE tenant_id = $1 AND id = $2 AND execution_lock_token = $3
           RETURNING ${VALIDATION_PLAN_COLUMNS}`,
          [tenantId, id, lockToken],
        );
        return mapValidationPlanRow(rows[0] ?? null);
      });
    },

    async getWafBaseline(ctx, id) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${WAF_BASELINE_COLUMNS}
           FROM waf_baselines
           WHERE tenant_id = $1 AND id = $2`,
          [tenantId, id],
        );
        return mapWafBaselineRow(rows[0] ?? null);
      });
    },

    async updateWafBaseline(ctx, id, patch) {
      const tenantId = ctx.tenantId;
      const sets = [];
      const params = [tenantId, id];
      let paramIdx = 3;

      for (const key of ['state', 'approved_by', 'approved_at', 'updated_at']) {
        if (!(key in patch)) continue;
        if (key === 'approved_at' || key === 'updated_at') {
          sets.push(`${key} = $${paramIdx}::timestamptz`);
          params.push(patch[key]);
        } else {
          sets.push(`${key} = $${paramIdx}`);
          params.push(patch[key]);
        }
        paramIdx += 1;
      }

      if (sets.length === 0) {
        return this.getWafBaseline(ctx, id);
      }

      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE waf_baselines
           SET ${sets.join(', ')}
           WHERE tenant_id = $1 AND id = $2
           RETURNING ${WAF_BASELINE_COLUMNS}`,
          params,
        );
        return mapWafBaselineRow(rows[0] ?? null);
      });
    },

    async createBaselineApproval(ctx, record) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO waf_baseline_approvals (
             id, tenant_id, baseline_id, waf_asset_id, approver, approval_notes,
             approved_at, fingerprint_summary_json, created_at
           )
           VALUES ($1, $2, $3, $4, $5, $6, $7::timestamptz, $8::jsonb, $9::timestamptz)
           RETURNING ${BASELINE_APPROVAL_COLUMNS}`,
          [
            record.id,
            tenantId,
            record.baseline_id,
            record.waf_asset_id,
            record.approver,
            record.approval_notes,
            record.approved_at,
            JSON.stringify(record.fingerprint_summary ?? {}),
            record.created_at,
          ],
        );
        return mapBaselineApprovalRow(rows[0]);
      });
    },

    async getWafDriftEvent(ctx, id) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${WAF_DRIFT_EVENT_COLUMNS}
           FROM waf_drift_events
           WHERE tenant_id = $1 AND id = $2`,
          [tenantId, id],
        );
        return mapWafDriftEventRow(rows[0] ?? null);
      });
    },

    async createRetestRequest(ctx, record) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO waf_retest_requests (
             id, tenant_id, drift_event_id, waf_asset_id, retest_plan_json, requested_by,
             priority, status, delegated_jobs_json, created_at, updated_at
           )
           VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, $9::jsonb, $10::timestamptz, $11::timestamptz)
           RETURNING ${RETEST_REQUEST_COLUMNS}`,
          [
            record.id,
            tenantId,
            record.drift_event_id,
            record.waf_asset_id,
            JSON.stringify(record.retest_plan ?? []),
            record.requested_by,
            record.priority,
            record.status ?? 'requested',
            JSON.stringify(record.delegated_jobs ?? []),
            record.created_at,
            record.updated_at,
          ],
        );
        return mapRetestRequestRow(rows[0]);
      });
    },

    async getRetestRequest(ctx, id) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${RETEST_REQUEST_COLUMNS}
           FROM waf_retest_requests
           WHERE tenant_id = $1 AND id = $2`,
          [tenantId, id],
        );
        return mapRetestRequestRow(rows[0] ?? null);
      });
    },

    async listRetestRequests(ctx, filters = {}) {
      const tenantId = ctx.tenantId;
      const driftEventId =
        typeof filters.drift_event_id === 'string' && filters.drift_event_id.trim()
          ? filters.drift_event_id.trim()
          : null;
      const wafAssetId =
        typeof filters.waf_asset_id === 'string' && filters.waf_asset_id.trim()
          ? filters.waf_asset_id.trim()
          : null;
      const status =
        typeof filters.status === 'string' && filters.status.trim()
          ? filters.status.trim()
          : null;
      return withTenantContext(pool, tenantId, async (client) => {
        const params = [tenantId];
        let sql = `SELECT ${RETEST_REQUEST_COLUMNS}
           FROM waf_retest_requests
           WHERE tenant_id = $1`;
        if (driftEventId) {
          params.push(driftEventId);
          sql += ` AND drift_event_id = $${params.length}`;
        }
        if (wafAssetId) {
          params.push(wafAssetId);
          sql += ` AND waf_asset_id = $${params.length}`;
        }
        if (status) {
          params.push(status);
          sql += ` AND status = $${params.length}`;
        }
        sql += ' ORDER BY created_at DESC';
        const { rows } = await client.query(sql, params);
        return rows.map(mapRetestRequestRow);
      });
    },

    async updateRetestRequest(ctx, id, patch) {
      const tenantId = ctx.tenantId;
      const normalizedPatch = normalizeRetestPatch(patch);
      const sets = [];
      const params = [tenantId, id];
      let paramIdx = 3;

      for (const [key, value] of Object.entries(normalizedPatch)) {
        if (!RETEST_PATCH_COLUMNS.has(key)) continue;
        if (key === 'delegated_jobs_json') {
          sets.push(`delegated_jobs_json = $${paramIdx}::jsonb`);
          params.push(JSON.stringify(value ?? []));
        } else if (key.endsWith('_at')) {
          sets.push(`${key} = $${paramIdx}::timestamptz`);
          params.push(value);
        } else {
          sets.push(`${key} = $${paramIdx}`);
          params.push(value);
        }
        paramIdx += 1;
      }

      if (sets.length === 0) {
        return this.getRetestRequest(ctx, id);
      }

      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE waf_retest_requests
           SET ${sets.join(', ')}
           WHERE tenant_id = $1 AND id = $2
           RETURNING ${RETEST_REQUEST_COLUMNS}`,
          params,
        );
        return mapRetestRequestRow(rows[0] ?? null);
      });
    },

    async claimRetestExecution(ctx, id, lease) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE waf_retest_requests
           SET execution_lock_token = $3,
               execution_lock_expires_at = $4::timestamptz,
               updated_at = $5::timestamptz
           WHERE tenant_id = $1 AND id = $2
             AND status IN ('requested', 'running')
             AND (execution_lock_token IS NULL OR execution_lock_expires_at <= $5::timestamptz)
           RETURNING ${RETEST_REQUEST_COLUMNS}`,
          [tenantId, id, lease.lock_token, lease.lock_expires_at, lease.now],
        );
        return mapRetestRequestRow(rows[0] ?? null);
      });
    },

    async stageRetestDelegation(ctx, id, lockToken, patch) {
      const tenantId = ctx.tenantId;
      const normalizedPatch = normalizeRetestPatch(patch ?? {});
      const sets = [];
      const params = [tenantId, id, lockToken];
      appendRetestPatchSets(normalizedPatch, sets, params, 4);

      if (sets.length === 0) {
        return this.getRetestRequest(ctx, id);
      }

      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE waf_retest_requests
           SET ${sets.join(', ')}
           WHERE tenant_id = $1 AND id = $2 AND execution_lock_token = $3
             AND status IN ('requested', 'running')
           RETURNING ${RETEST_REQUEST_COLUMNS}`,
          params,
        );
        return mapRetestRequestRow(rows[0] ?? null);
      });
    },

    async finishRetestExecution(ctx, id, lockToken, patch) {
      const tenantId = ctx.tenantId;
      const normalizedPatch = normalizeRetestPatch(patch ?? {});
      const sets = ['execution_lock_token = NULL', 'execution_lock_expires_at = NULL'];
      const params = [tenantId, id, lockToken];
      appendRetestPatchSets(normalizedPatch, sets, params, 4);

      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE waf_retest_requests
           SET ${sets.join(', ')}
           WHERE tenant_id = $1 AND id = $2 AND execution_lock_token = $3
             AND status IN ('requested', 'running')
           RETURNING ${RETEST_REQUEST_COLUMNS}`,
          params,
        );
        return mapRetestRequestRow(rows[0] ?? null);
      });
    },

    async releaseRetestExecution(ctx, id, lockToken) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE waf_retest_requests
           SET execution_lock_token = NULL,
               execution_lock_expires_at = NULL
           WHERE tenant_id = $1 AND id = $2 AND execution_lock_token = $3
           RETURNING ${RETEST_REQUEST_COLUMNS}`,
          [tenantId, id, lockToken],
        );
        return mapRetestRequestRow(rows[0] ?? null);
      });
    },

    async completeRetestWithDriftAndAudit(ctx, payload) {
      const tenantId = ctx.tenantId;
      const {
        retest_id: retestId,
        retest_patch: retestPatch,
        drift_event_id: driftEventId,
        drift_patch: driftPatch,
        audit_event: auditEvent,
        audit_now: auditNow,
      } = payload ?? {};

      return withTenantContext(pool, tenantId, async (client) => {
        const normalizedRetestPatch = normalizeRetestPatch(retestPatch ?? {});
        const retestSets = [];
        const retestParams = [tenantId, retestId];
        let retestParamIdx = 3;

        for (const [key, value] of Object.entries(normalizedRetestPatch)) {
          if (!RETEST_PATCH_COLUMNS.has(key)) continue;
          if (key === 'delegated_jobs_json') {
            retestSets.push(`delegated_jobs_json = $${retestParamIdx}::jsonb`);
            retestParams.push(JSON.stringify(value ?? []));
          } else if (key.endsWith('_at')) {
            retestSets.push(`${key} = $${retestParamIdx}::timestamptz`);
            retestParams.push(value);
          } else {
            retestSets.push(`${key} = $${retestParamIdx}`);
            retestParams.push(value);
          }
          retestParamIdx += 1;
        }

        if (retestSets.length === 0) {
          throw new Error('completeRetestWithDriftAndAudit requires a non-empty retest_patch.');
        }

        const { rows: retestRows } = await client.query(
          `UPDATE waf_retest_requests
           SET ${retestSets.join(', ')}
           WHERE tenant_id = $1 AND id = $2
           RETURNING ${RETEST_REQUEST_COLUMNS}`,
          retestParams,
        );
        const retestRequest = mapRetestRequestRow(retestRows[0] ?? null);
        if (!retestRequest) {
          throw new Error('Retest request not found for tenant-scoped completion.');
        }

        let driftEvent = null;
        if (driftPatch && driftEventId) {
          const { rows: driftRows } = await client.query(
            `UPDATE waf_drift_events
             SET status = COALESCE($3, status),
                 resolved_at = $4::timestamptz
             WHERE tenant_id = $1 AND id = $2
             RETURNING ${WAF_DRIFT_EVENT_COLUMNS}`,
            [
              tenantId,
              driftEventId,
              driftPatch.status ?? null,
              driftPatch.resolved_at ?? null,
            ],
          );
          driftEvent = mapWafDriftEventRow(driftRows[0] ?? null);
          if (!driftEvent) {
            throw new Error('Drift event not found for tenant-scoped retest completion.');
          }
        }

        const now =
          auditNow instanceof Date
            ? auditNow
            : new Date(auditNow ?? retestPatch?.updated_at ?? Date.now());
        const auditRecord = await appendAuditEventInTransaction(client, auditEvent, now);

        return {
          retest_request: retestRequest,
          drift_event: driftEvent,
          audit_event: auditRecord,
        };
      });
    },
  };
}