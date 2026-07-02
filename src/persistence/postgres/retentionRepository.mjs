import { buildAuditRecord } from '../../audit.mjs';
import { normalizePrivacySettings } from '../../lib/privacySettings.mjs';
import {
  buildMetadataRetentionCutoffs,
  buildRetentionPolicySnapshot,
} from '../../services/privacyRetention.mjs';
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

const RETENTION_COLLECTIONS = Object.freeze([
  { key: 'events', table: 'events', timestampColumn: 'timestamp' },
  { key: 'evidenceVault', table: 'evidence_vault', timestampColumn: 'created_at' },
  { key: 'reports', table: 'reports', timestampColumn: 'created_at' },
  { key: 'notificationEvents', table: 'notification_events', timestampColumn: 'created_at' },
]);

function rowToAuditEntry(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    timestamp: row.timestamp instanceof Date ? row.timestamp.toISOString() : String(row.timestamp),
    sequence: Number(row.sequence),
    prev_hash: row.prev_hash ?? null,
    entry_hash: row.entry_hash,
    actor_user_id: row.actor_user_id ?? null,
    actor_role: row.actor_role ?? null,
    action: row.action,
    resource_type: row.resource_type ?? null,
    resource_id: row.resource_id ?? null,
    metadata: row.metadata_json ?? {},
  };
}

function auditInsertParams(entry) {
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
    JSON.stringify(entry.metadata ?? {}),
  ];
}

function zeroCounts() {
  return {
    events: 0,
    evidenceVault: 0,
    reports: 0,
    notificationEvents: 0,
  };
}

function totalCounts(counts) {
  return counts.events + counts.evidenceVault + counts.reports + counts.notificationEvents;
}

async function countCandidates(client, tenantId, nowIso, privacy) {
  const { metadataCutoffMs, reportCutoffMs } = buildMetadataRetentionCutoffs(privacy, nowIso);
  const cutoffs = {
    events: new Date(metadataCutoffMs).toISOString(),
    evidenceVault: new Date(metadataCutoffMs).toISOString(),
    reports: new Date(reportCutoffMs).toISOString(),
    notificationEvents: new Date(metadataCutoffMs).toISOString(),
  };

  const counts = zeroCounts();
  for (const collection of RETENTION_COLLECTIONS) {
    const cutoffIso = cutoffs[collection.key];
    const { rows } = await client.query(
      `SELECT COUNT(*)::int AS count
       FROM ${collection.table}
       WHERE tenant_id = $1 AND ${collection.timestampColumn} < $2::timestamptz`,
      [tenantId, cutoffIso],
    );
    counts[collection.key] = Number(rows[0]?.count ?? 0);
  }

  return { counts, cutoffs };
}

async function deleteCandidates(client, tenantId, cutoffs) {
  const deleted = zeroCounts();
  for (const collection of RETENTION_COLLECTIONS) {
    const cutoffIso = cutoffs[collection.key];
    const result = await client.query(
      `DELETE FROM ${collection.table}
       WHERE tenant_id = $1 AND ${collection.timestampColumn} < $2::timestamptz`,
      [tenantId, cutoffIso],
    );
    deleted[collection.key] = Number(result.rowCount ?? 0);
  }
  return deleted;
}

async function appendAuditEventInTransaction(client, entry, now) {
  await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [entry.tenant_id]);
  const { rows } = await client.query(LAST_AUDIT_ROW_SQL, [entry.tenant_id]);
  const priorEntry = rowToAuditEntry(rows[0] ?? null);
  const record = buildAuditRecord(entry, priorEntry, now);
  await client.query(INSERT_AUDIT_SQL, auditInsertParams(record));
  return record;
}

/**
 * @param {import('pg').Pool} pool
 */
export function createRetentionRepository(pool) {
  return {
    /**
     * @param {string} tenantId
     * @param {{ userId?: string | null, role?: string | null }} [auditContext]
     * @param {{ dryRun?: boolean, now?: Date }} [options]
     */
    async runMetadataRetention(tenantId, auditContext = {}, options = {}) {
      const normalizedTenantId = String(tenantId ?? '').trim();
      if (!normalizedTenantId) {
        throw new Error('tenant id must be a non-empty string.');
      }

      const now = options.now instanceof Date ? options.now : new Date(options.now ?? Date.now());
      const dryRun = options.dryRun === true;

      return withTenantContext(pool, normalizedTenantId, async (client) => {
        const tenantResult = await client.query(
          `SELECT id, privacy_settings
           FROM tenants
           WHERE id = $1
           FOR UPDATE`,
          [normalizedTenantId],
        );
        const tenantRow = tenantResult.rows[0] ?? null;
        if (!tenantRow) {
          return null;
        }

        const originalPrivacy = tenantRow.privacy_settings ?? {};
        const privacy = normalizePrivacySettings(originalPrivacy);
        if (JSON.stringify(originalPrivacy) !== JSON.stringify(privacy)) {
          await client.query(
            `UPDATE tenants
             SET privacy_settings = $2::jsonb
             WHERE id = $1`,
            [normalizedTenantId, JSON.stringify(privacy)],
          );
        }

        return runMetadataRetentionInTransaction(
          client,
          normalizedTenantId,
          { id: tenantRow.id, privacy_settings: privacy },
          auditContext,
          { dryRun, now },
        );
      });
    },
  };
}

export async function runMetadataRetentionInTransaction(
  client,
  tenantId,
  tenant,
  auditContext = {},
  options = {},
) {
  const normalizedTenantId = String(tenantId ?? '').trim();
  if (!normalizedTenantId) {
    throw new Error('tenant id must be a non-empty string.');
  }

  const now = options.now instanceof Date ? options.now : new Date(options.now ?? Date.now());
  const dryRun = options.dryRun === true;
  const privacy = normalizePrivacySettings(tenant?.privacy_settings ?? {});
  const policySnapshot = buildRetentionPolicySnapshot({
    id: tenant?.id ?? normalizedTenantId,
    privacy_settings: privacy,
  });
  const { counts, cutoffs } = await countCandidates(
    client,
    normalizedTenantId,
    now.toISOString(),
    privacy,
  );

  if (dryRun) {
    return {
      tenant_id: normalizedTenantId,
      dry_run: true,
      deleted: zeroCounts(),
      would_delete: counts,
      blocked_deletions: privacy.evidence_retention.legal_hold ? counts : zeroCounts(),
      metadata_retention_days: privacy.metadata_retention_days,
      evidence_retention: privacy.evidence_retention,
      policy_snapshot: policySnapshot,
      legal_hold: privacy.evidence_retention.legal_hold,
    };
  }

  if (privacy.evidence_retention.legal_hold) {
    if (totalCounts(counts) > 0) {
      await appendAuditEventInTransaction(
        client,
        {
          tenant_id: normalizedTenantId,
          actor_user_id: auditContext.userId ?? null,
          actor_role: auditContext.role ?? 'system',
          action: 'privacy.retention_legal_hold',
          resource_type: 'tenant',
          resource_id: normalizedTenantId,
          metadata: {
            deleted: zeroCounts(),
            blocked_deletions: counts,
            policy_snapshot: policySnapshot,
          },
        },
        now,
      );
    }

    return {
      tenant_id: normalizedTenantId,
      dry_run: false,
      deleted: zeroCounts(),
      would_delete: counts,
      blocked_deletions: counts,
      metadata_retention_days: privacy.metadata_retention_days,
      evidence_retention: privacy.evidence_retention,
      policy_snapshot: policySnapshot,
      legal_hold: true,
    };
  }

  const deleted =
    totalCounts(counts) > 0 ? await deleteCandidates(client, normalizedTenantId, cutoffs) : zeroCounts();
  if (totalCounts(deleted) > 0) {
    await appendAuditEventInTransaction(
      client,
      {
        tenant_id: normalizedTenantId,
        actor_user_id: auditContext.userId ?? null,
        actor_role: auditContext.role ?? 'system',
        action: 'privacy.retention_purged',
        resource_type: 'tenant',
        resource_id: normalizedTenantId,
        metadata: {
          deleted,
          metadata_retention_days: privacy.metadata_retention_days,
          policy_snapshot: policySnapshot,
        },
      },
      now,
    );
  }

  return {
    tenant_id: normalizedTenantId,
    dry_run: false,
    deleted,
    would_delete: counts,
    blocked_deletions: zeroCounts(),
    metadata_retention_days: privacy.metadata_retention_days,
    evidence_retention: privacy.evidence_retention,
    policy_snapshot: policySnapshot,
    legal_hold: false,
  };
}
