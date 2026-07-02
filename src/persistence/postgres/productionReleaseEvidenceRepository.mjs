import { withTenantContext } from './tenantContext.mjs';

const PRODUCTION_RELEASE_EVIDENCE_COLUMNS = `id, tenant_id, kind, release_id, status,
  evidence_json, notes, validation_json, created_at, created_by`;

function toIso(value) {
  if (value == null) return value;
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

export function mapProductionReleaseEvidenceRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    kind: row.kind,
    release_id: row.release_id ?? null,
    status: row.status,
    evidence: row.evidence_json ?? {},
    notes: row.notes ?? null,
    validation: row.validation_json ?? {},
    created_at: toIso(row.created_at),
    created_by: row.created_by ?? null,
  };
}

export function createProductionReleaseEvidenceRepository(pool) {
  return {
    async createProductionReleaseEvidence(ctx, record) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO production_release_evidence (
             id, tenant_id, kind, release_id, status, evidence_json,
             notes, validation_json, created_at, created_by
           )
           VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8::jsonb, $9::timestamptz, $10)
           RETURNING ${PRODUCTION_RELEASE_EVIDENCE_COLUMNS}`,
          [
            record.id,
            tenantId,
            record.kind,
            record.release_id ?? null,
            record.status ?? 'accepted',
            JSON.stringify(record.evidence ?? {}),
            record.notes ?? null,
            JSON.stringify(record.validation ?? {}),
            record.created_at,
            record.created_by ?? null,
          ],
        );
        return mapProductionReleaseEvidenceRow(rows[0]);
      });
    },

    async listProductionReleaseEvidence(ctx) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${PRODUCTION_RELEASE_EVIDENCE_COLUMNS}
           FROM production_release_evidence
           WHERE tenant_id = $1
           ORDER BY created_at ASC`,
          [tenantId],
        );
        return rows.map(mapProductionReleaseEvidenceRow);
      });
    },

    async getProductionReleaseEvidence(ctx, id) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${PRODUCTION_RELEASE_EVIDENCE_COLUMNS}
           FROM production_release_evidence
           WHERE tenant_id = $1 AND id = $2`,
          [tenantId, id],
        );
        return mapProductionReleaseEvidenceRow(rows[0] ?? null);
      });
    },
  };
}
