import { withTenantContext } from './tenantContext.mjs';

const SUPPLY_CHAIN_RISK_COLUMNS = `id, tenant_id, exposure_type, hostname, evidence_summary_json,
  confidence, severity, state, owner_hint, remediation_steps, assessment_metadata_json,
  created_at, updated_at`;

function toIso(value) {
  if (value == null) return value;
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

function parseJsonObject(value) {
  if (value == null) return {};
  if (typeof value === 'string') {
    try {
      return JSON.parse(value);
    } catch {
      return {};
    }
  }
  return value;
}

function buildAssessmentMetadata(risk = {}) {
  const existing = parseJsonObject(risk.assessment_metadata_json);
  return {
    ...existing,
    ...(risk.risk_id ? { risk_id: risk.risk_id } : {}),
    ...(risk.phase ? { phase: risk.phase } : {}),
  };
}

export function mapSupplyChainRiskRow(row) {
  if (!row) return null;
  const assessment = parseJsonObject(row.assessment_metadata_json);
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    risk_id: assessment.risk_id ?? row.id,
    exposure_type: row.exposure_type,
    hostname: row.hostname,
    evidence_summary: parseJsonObject(row.evidence_summary_json),
    confidence: Number(row.confidence ?? 0),
    severity: row.severity ?? 'medium',
    state: row.state ?? 'suspected',
    phase: assessment.phase ?? 'AP0_detect_only',
    owner_hint: row.owner_hint ?? '',
    remediation_steps: row.remediation_steps ?? [],
    assessment_metadata_json: assessment,
    created_at: toIso(row.created_at),
    updated_at: toIso(row.updated_at),
  };
}

export function createSupplyChainRiskRepository(pool) {
  return {
    async listRisks(ctx) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${SUPPLY_CHAIN_RISK_COLUMNS}
           FROM supply_chain_risks
           WHERE tenant_id = $1
           ORDER BY created_at ASC`,
          [tenantId],
        );
        return rows.map(mapSupplyChainRiskRow);
      });
    },

    async getRisk(ctx, id) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${SUPPLY_CHAIN_RISK_COLUMNS}
           FROM supply_chain_risks
           WHERE tenant_id = $1 AND id = $2`,
          [tenantId, id],
        );
        return mapSupplyChainRiskRow(rows[0] ?? null);
      });
    },

    async findRiskByHostnameAndExposure(ctx, hostname, exposureType) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${SUPPLY_CHAIN_RISK_COLUMNS}
           FROM supply_chain_risks
           WHERE tenant_id = $1 AND hostname = $2 AND exposure_type = $3
           LIMIT 1`,
          [tenantId, hostname, exposureType],
        );
        return mapSupplyChainRiskRow(rows[0] ?? null);
      });
    },

    async insertRisk(ctx, risk) {
      const tenantId = ctx.tenantId;
      const assessmentMetadata = buildAssessmentMetadata(risk);
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO supply_chain_risks (
             id, tenant_id, exposure_type, hostname, evidence_summary_json, confidence, severity,
             state, owner_hint, remediation_steps, assessment_metadata_json, created_at, updated_at
           )
           VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, $9, $10, $11::jsonb, $12::timestamptz, $13::timestamptz)
           ON CONFLICT (tenant_id, hostname, exposure_type) DO UPDATE
           SET evidence_summary_json = EXCLUDED.evidence_summary_json,
               confidence = EXCLUDED.confidence,
               severity = EXCLUDED.severity,
               state = EXCLUDED.state,
               owner_hint = EXCLUDED.owner_hint,
               remediation_steps = EXCLUDED.remediation_steps,
               assessment_metadata_json = EXCLUDED.assessment_metadata_json,
               updated_at = EXCLUDED.updated_at
           RETURNING ${SUPPLY_CHAIN_RISK_COLUMNS}`,
          [
            risk.id,
            tenantId,
            risk.exposure_type,
            risk.hostname,
            JSON.stringify(risk.evidence_summary ?? {}),
            risk.confidence ?? 0,
            risk.severity ?? 'medium',
            risk.state ?? 'suspected',
            risk.owner_hint ?? null,
            risk.remediation_steps ?? [],
            JSON.stringify(assessmentMetadata),
            risk.created_at,
            risk.updated_at ?? risk.created_at,
          ],
        );
        return mapSupplyChainRiskRow(rows[0]);
      });
    },

    async updateRiskState(ctx, id, state, extras = {}) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE supply_chain_risks
           SET state = $3,
               owner_hint = COALESCE($4, owner_hint),
               remediation_steps = COALESCE($5, remediation_steps),
               updated_at = $6::timestamptz
           WHERE tenant_id = $1 AND id = $2
           RETURNING ${SUPPLY_CHAIN_RISK_COLUMNS}`,
          [
            tenantId,
            id,
            state,
            extras.owner_hint ?? null,
            extras.remediation_steps ?? null,
            extras.updated_at ?? new Date().toISOString(),
          ],
        );
        return mapSupplyChainRiskRow(rows[0] ?? null);
      });
    },
  };
}