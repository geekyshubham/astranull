import { buildAuditRecord } from '../../audit.mjs';
import { withTenantContext } from './tenantContext.mjs';

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

/** Matches GET /v1/audit-log dev-store window (`slice(-200)`). */
export const DEFAULT_AUDIT_LIST_LIMIT = 200;
export const MAX_AUDIT_LIST_LIMIT = 500;

function normalizeListLimit(limit) {
  if (limit === undefined || limit === null) {
    return DEFAULT_AUDIT_LIST_LIMIT;
  }
  const n = Number(limit);
  if (!Number.isFinite(n) || n < 1) {
    return DEFAULT_AUDIT_LIST_LIMIT;
  }
  return Math.min(Math.floor(n), MAX_AUDIT_LIST_LIMIT);
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

/**
 * @param {import('pg').Pool} pool
 */
export function createAuditRepository(pool) {
  return {
    /**
     * Newest-window entries in ascending sequence order (matches dev-store list semantics).
     * @param {{ tenantId: string }} ctx
     * @param {{ limit?: number }} [options]
     */
    async listAuditEntries(ctx, options = {}) {
      const tenantId = ctx?.tenantId;
      const boundedLimit = normalizeListLimit(options.limit);

      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT id, tenant_id, timestamp, sequence, prev_hash, entry_hash,
                  actor_user_id, actor_role, action, resource_type, resource_id, metadata_json
           FROM audit_logs
           WHERE tenant_id = $1
           ORDER BY sequence DESC
           LIMIT $2`,
          [tenantId, boundedLimit],
        );
        return rows.reverse().map(rowToAuditEntry);
      });
    },

    /**
     * Persist a fully formed tamper-evident record (e.g. from `audit()` after wiring).
     * @param {Record<string, unknown>} entry
     */
    async appendAuditEntry(entry) {
      const tenantId = entry?.tenant_id;

      return withTenantContext(pool, tenantId, async (client) => {
        await client.query(INSERT_AUDIT_SQL, auditInsertParams(entry));
        return entry;
      });
    },

    /**
     * Redact, chain, and persist a raw audit event under a tenant-scoped advisory lock.
     * @param {Record<string, unknown>} entry
     * @param {{ now?: Date }} [options]
     */
    async appendAuditEvent(entry, options = {}) {
      const tenantId = String(entry?.tenant_id ?? '').trim();
      if (!tenantId) {
        throw new Error('tenant id must be a non-empty string.');
      }

      return withTenantContext(pool, tenantId, async (client) => {
        await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [tenantId]);
        const { rows } = await client.query(LAST_AUDIT_ROW_SQL, [tenantId]);
        const lastRow = rowToAuditEntry(rows[0] ?? null);
        const record = buildAuditRecord(entry, lastRow, options.now);
        await client.query(INSERT_AUDIT_SQL, auditInsertParams(record));
        return record;
      });
    },

    /**
     * Latest chained row for sequence / prev_hash continuation (per-tenant).
     * @param {string} tenantId
     */
    async getLastAuditEntry(tenantId) {
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(LAST_AUDIT_ROW_SQL, [tenantId]);
        return rowToAuditEntry(rows[0] ?? null);
      });
    },
  };
}