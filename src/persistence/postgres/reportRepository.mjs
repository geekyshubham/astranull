import { withTenantContext } from './tenantContext.mjs';

export const DEFAULT_REPORT_LIST_LIMIT = 100;
export const MAX_REPORT_LIST_LIMIT = 500;
export const MAX_FINDINGS_EXPORT_LIMIT = 500;

const REPORT_COLUMNS = `id, tenant_id, kind, title, status, summary_json, run_ids, created_by, created_at`;

const TEST_RUN_EXPORT_COLUMNS = `id, tenant_id, target_group_id, target_id, check_id, vector_family, safety_class,
  status, remediation_template, summary_json, created_at`;

const VERDICT_EXPORT_COLUMNS = `id, tenant_id, test_run_id, target_id, check_id, verdict, confidence, explanation,
  evidence_ids, placement_confidence_json, created_at`;

const FINDING_EXPORT_COLUMNS = `id, tenant_id, target_group_id, target_id, test_run_id, check_id, title, severity,
  status, evidence_ids, notes, remediation_template, verdict_id, last_verdict_id, assignee, created_at, updated_at`;

function toIso(value) {
  if (value == null) return value;
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

function asStringArray(value) {
  return Array.isArray(value) ? value : [];
}

function asObject(value) {
  if (value && typeof value === 'object' && !Array.isArray(value)) return value;
  return {};
}

function normalizeReportListLimit(limit) {
  if (limit === undefined || limit === null) {
    return DEFAULT_REPORT_LIST_LIMIT;
  }
  const n = Number(limit);
  if (!Number.isFinite(n) || n < 1) {
    return DEFAULT_REPORT_LIST_LIMIT;
  }
  return Math.min(Math.floor(n), MAX_REPORT_LIST_LIMIT);
}

function mapReportRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    kind: row.kind,
    title: row.title,
    status: row.status,
    summary: asObject(row.summary_json),
    run_ids: asStringArray(row.run_ids),
    created_by: row.created_by ?? undefined,
    created_at: toIso(row.created_at),
  };
}

function mapReportRunRow(row) {
  if (!row) return null;
  const mapped = {
    id: row.id,
    tenant_id: row.tenant_id,
    target_group_id: row.target_group_id,
    check_id: row.check_id,
    status: row.status,
    created_at: toIso(row.created_at),
  };
  if (row.target_id != null) mapped.target_id = row.target_id;
  if (row.vector_family != null) mapped.vector_family = row.vector_family;
  if (row.safety_class != null) mapped.safety_class = row.safety_class;
  if (row.remediation_template != null) mapped.remediation_template = row.remediation_template;
  const summary = asObject(row.summary_json);
  if (Object.keys(summary).length > 0) mapped.summary = summary;
  return mapped;
}

function mapReportVerdictRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    test_run_id: row.test_run_id,
    target_id: row.target_id ?? undefined,
    check_id: row.check_id ?? undefined,
    verdict: row.verdict,
    confidence: row.confidence ?? undefined,
    explanation: row.explanation ?? undefined,
    evidence_ids: asStringArray(row.evidence_ids),
    placement_confidence: asObject(row.placement_confidence_json),
    created_at: toIso(row.created_at),
  };
}

function mapReportFindingRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    target_group_id: row.target_group_id ?? undefined,
    target_id: row.target_id ?? undefined,
    test_run_id: row.test_run_id ?? undefined,
    check_id: row.check_id ?? undefined,
    title: row.title,
    severity: row.severity,
    status: row.status,
    evidence_ids: asStringArray(row.evidence_ids),
    notes: row.notes ?? undefined,
    remediation_template: row.remediation_template ?? undefined,
    verdict_id: row.verdict_id ?? undefined,
    last_verdict_id: row.last_verdict_id ?? undefined,
    assignee: row.assignee ?? undefined,
    created_at: toIso(row.created_at),
    updated_at: row.updated_at == null ? undefined : toIso(row.updated_at),
  };
}

/**
 * @param {import('pg').Pool} pool
 */
export function createReportRepository(pool) {
  return {
    async createReport(ctx, record) {
      const tenantId = ctx.tenantId;
      const summaryJson = asObject(record.summary ?? record.summary_json);
      const runIds = asStringArray(record.run_ids);

      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO reports (
             id, tenant_id, kind, title, status, summary_json, run_ids, created_by, created_at
           )
           VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9::timestamptz)
           RETURNING ${REPORT_COLUMNS}`,
          [
            record.id,
            tenantId,
            record.kind,
            record.title,
            record.status,
            JSON.stringify(summaryJson),
            runIds,
            record.created_by ?? null,
            record.created_at,
          ],
        );
        return mapReportRow(rows[0]);
      });
    },

    async getReport(ctx, id) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${REPORT_COLUMNS}
           FROM reports
           WHERE tenant_id = $1 AND id = $2`,
          [ctx.tenantId, id],
        );
        return mapReportRow(rows[0] ?? null);
      });
    },

    async listReports(ctx, options = {}) {
      const boundedLimit = normalizeReportListLimit(options.limit);

      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${REPORT_COLUMNS}
           FROM reports
           WHERE tenant_id = $1
           ORDER BY created_at DESC
           LIMIT $2`,
          [ctx.tenantId, boundedLimit],
        );
        return rows.map(mapReportRow);
      });
    },

    async listRunsForReport(ctx, runIds) {
      const ids = asStringArray(runIds);
      if (ids.length === 0) {
        return [];
      }

      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${TEST_RUN_EXPORT_COLUMNS}
           FROM test_runs
           WHERE tenant_id = $1 AND id = ANY($2::text[])
           ORDER BY array_position($2::text[], id)`,
          [ctx.tenantId, ids],
        );
        return rows.map(mapReportRunRow);
      });
    },

    async listVerdictsForRunIds(ctx, runIds) {
      const ids = asStringArray(runIds);
      if (ids.length === 0) {
        return [];
      }

      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${VERDICT_EXPORT_COLUMNS}
           FROM verdicts
           WHERE tenant_id = $1 AND test_run_id = ANY($2::text[])
           ORDER BY array_position($2::text[], test_run_id)`,
          [ctx.tenantId, ids],
        );
        return rows.map(mapReportVerdictRow);
      });
    },

    async listFindingsForExport(ctx, options = {}) {
      const tenantId = ctx.tenantId;
      const status = options.status;

      return withTenantContext(pool, tenantId, async (client) => {
        let sql = `SELECT ${FINDING_EXPORT_COLUMNS}
           FROM findings
           WHERE tenant_id = $1`;
        const params = [tenantId];
        if (status != null && status !== '') {
          sql += ` AND status = $2`;
          params.push(status);
        }
        sql += ` ORDER BY created_at DESC LIMIT $${params.length + 1}`;
        params.push(MAX_FINDINGS_EXPORT_LIMIT);

        const { rows } = await client.query(sql, params);
        return rows.map(mapReportFindingRow);
      });
    },
  };
}

export { mapReportRow, mapReportRunRow, mapReportVerdictRow, mapReportFindingRow };