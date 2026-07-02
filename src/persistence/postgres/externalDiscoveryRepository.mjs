import { createHash } from 'node:crypto';
import { withTenantContext } from './tenantContext.mjs';

const DISCOVERY_ENTITY_COLUMNS = `id, tenant_id, entity_type, name, display_name, parent_entity_id,
  root_domains, country, confidence, source, created_at, updated_at`;

const EXTERNAL_CANDIDATE_COLUMNS = `id, tenant_id, entity_id, asset_type, asset_value_hash, display_value,
  source_type, source_ref, confidence, approval_status, approved_target_id, first_seen_at, last_seen_at,
  evidence_summary_json, created_at`;

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

function normalizeHostname(hostname) {
  return String(hostname ?? '').trim().toLowerCase();
}

function hostnameHash(hostname) {
  return createHash('sha256').update(normalizeHostname(hostname), 'utf8').digest('hex');
}

function splitCandidateEvidence(evidenceSummary = {}) {
  const {
    state,
    ownership_status,
    candidate_id,
    scope_hash,
    rejection_reason,
    ...evidence_summary
  } = evidenceSummary;
  return {
    state: state ?? 'candidate',
    ownership_status: ownership_status ?? 'unknown',
    candidate_id: candidate_id ?? null,
    scope_hash: scope_hash ?? null,
    rejection_reason: rejection_reason ?? null,
    evidence_summary,
  };
}

function mergeCandidateEvidence(candidate, evidenceSummary = {}) {
  const split = splitCandidateEvidence(evidenceSummary);
  return {
    state: candidate.state ?? split.state,
    ownership_status: candidate.ownership_status ?? split.ownership_status,
    candidate_id: candidate.candidate_id ?? split.candidate_id,
    scope_hash: candidate.scope_hash ?? split.scope_hash,
    rejection_reason: candidate.rejection_reason ?? split.rejection_reason,
    ...split.evidence_summary,
    ...(candidate.evidence_summary ?? {}),
  };
}

export function mapDiscoveryEntityRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    entity_id: row.id,
    entity_type: row.entity_type,
    name: row.name,
    display_name: row.display_name,
    parent_entity_id: row.parent_entity_id ?? null,
    root_domains: row.root_domains ?? [],
    country: row.country ?? null,
    confidence: Number(row.confidence ?? 0),
    source: row.source,
    created_at: toIso(row.created_at),
    updated_at: toIso(row.updated_at),
  };
}

export function mapExternalCandidateRow(row) {
  if (!row) return null;
  const evidenceSummary = parseJsonObject(row.evidence_summary_json);
  const split = splitCandidateEvidence(evidenceSummary);
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    candidate_id: split.candidate_id ?? row.id,
    hostname: row.display_value,
    entity_id: row.entity_id ?? null,
    source_type: row.source_type,
    source_ref: row.source_ref ?? null,
    confidence: Number(row.confidence ?? 0),
    ownership_status: split.ownership_status,
    approval_status: row.approval_status ?? 'not_requested',
    state: split.state,
    first_seen_at: toIso(row.first_seen_at),
    last_seen_at: toIso(row.last_seen_at),
    evidence_summary: split.evidence_summary,
    scope_hash: split.scope_hash,
    rejection_reason: split.rejection_reason,
    approved_target_id: row.approved_target_id ?? null,
    asset_type: row.asset_type,
    asset_value_hash: row.asset_value_hash,
    created_at: toIso(row.created_at),
    updated_at: split.updated_at ?? null,
  };
}

export function createExternalDiscoveryRepository(pool) {
  return {
    async listEntities(ctx) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${DISCOVERY_ENTITY_COLUMNS}
           FROM discovery_entities
           WHERE tenant_id = $1
           ORDER BY created_at ASC`,
          [tenantId],
        );
        return rows.map(mapDiscoveryEntityRow);
      });
    },

    async insertEntity(ctx, entity) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const id = entity.id ?? entity.entity_id;
        const { rows } = await client.query(
          `INSERT INTO discovery_entities (
             id, tenant_id, entity_type, name, display_name, parent_entity_id, root_domains,
             country, confidence, source, created_at, updated_at
           )
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::timestamptz, $12::timestamptz)
           RETURNING ${DISCOVERY_ENTITY_COLUMNS}`,
          [
            id,
            tenantId,
            entity.entity_type,
            entity.name,
            entity.display_name,
            entity.parent_entity_id ?? null,
            entity.root_domains ?? [],
            entity.country ?? null,
            entity.confidence ?? 0,
            entity.source,
            entity.created_at,
            entity.updated_at ?? entity.created_at,
          ],
        );
        return mapDiscoveryEntityRow(rows[0]);
      });
    },

    async listCandidates(ctx) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${EXTERNAL_CANDIDATE_COLUMNS}
           FROM external_asset_candidates
           WHERE tenant_id = $1
           ORDER BY created_at ASC`,
          [tenantId],
        );
        return rows.map(mapExternalCandidateRow);
      });
    },

    async getCandidate(ctx, id) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${EXTERNAL_CANDIDATE_COLUMNS}
           FROM external_asset_candidates
           WHERE tenant_id = $1 AND id = $2`,
          [tenantId, id],
        );
        return mapExternalCandidateRow(rows[0] ?? null);
      });
    },

    async findCandidateByHostname(ctx, hostname) {
      const tenantId = ctx.tenantId;
      const normalized = normalizeHostname(hostname);
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${EXTERNAL_CANDIDATE_COLUMNS}
           FROM external_asset_candidates
           WHERE tenant_id = $1
             AND asset_type = 'hostname'
             AND lower(display_value) = $2
           LIMIT 1`,
          [tenantId, normalized],
        );
        return mapExternalCandidateRow(rows[0] ?? null);
      });
    },

    async insertCandidate(ctx, candidate) {
      const tenantId = ctx.tenantId;
      const hostname = candidate.hostname ?? candidate.display_value;
      const hash = hostnameHash(hostname);
      const evidenceJson = mergeCandidateEvidence(candidate, candidate.evidence_summary ?? {});

      return withTenantContext(pool, tenantId, async (client) => {
        const { rows: existingRows } = await client.query(
          `SELECT ${EXTERNAL_CANDIDATE_COLUMNS}
           FROM external_asset_candidates
           WHERE tenant_id = $1
             AND asset_type = 'hostname'
             AND asset_value_hash = $2`,
          [tenantId, hash],
        );
        const existing = existingRows[0] ?? null;
        if (existing) {
          const { rows } = await client.query(
            `UPDATE external_asset_candidates
             SET last_seen_at = $3::timestamptz,
                 confidence = $4,
                 evidence_summary_json = $5::jsonb,
                 source_type = COALESCE($6, source_type),
                 source_ref = COALESCE($7, source_ref)
             WHERE tenant_id = $1 AND id = $2
             RETURNING ${EXTERNAL_CANDIDATE_COLUMNS}`,
            [
              tenantId,
              existing.id,
              candidate.last_seen_at ?? candidate.first_seen_at,
              candidate.confidence ?? existing.confidence,
              JSON.stringify(evidenceJson),
              candidate.source_type ?? null,
              candidate.source_ref ?? null,
            ],
          );
          return { candidate: mapExternalCandidateRow(rows[0]), deduplicated: true };
        }

        const { rows } = await client.query(
          `INSERT INTO external_asset_candidates (
             id, tenant_id, entity_id, asset_type, asset_value_hash, display_value, source_type,
             source_ref, confidence, approval_status, first_seen_at, last_seen_at,
             evidence_summary_json, created_at
           )
           VALUES ($1, $2, $3, 'hostname', $4, $5, $6, $7, $8, $9, $10::timestamptz, $11::timestamptz, $12::jsonb, $13::timestamptz)
           RETURNING ${EXTERNAL_CANDIDATE_COLUMNS}`,
          [
            candidate.id,
            tenantId,
            candidate.entity_id ?? null,
            hash,
            normalizeHostname(hostname),
            candidate.source_type,
            candidate.source_ref ?? null,
            candidate.confidence ?? 0,
            candidate.approval_status ?? 'not_requested',
            candidate.first_seen_at,
            candidate.last_seen_at ?? candidate.first_seen_at,
            JSON.stringify(evidenceJson),
            candidate.created_at,
          ],
        );
        return { candidate: mapExternalCandidateRow(rows[0]), deduplicated: false };
      });
    },

    async updateCandidateState(ctx, id, updates) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows: existingRows } = await client.query(
          `SELECT evidence_summary_json, approval_status
           FROM external_asset_candidates
           WHERE tenant_id = $1 AND id = $2`,
          [tenantId, id],
        );
        const existing = existingRows[0];
        if (!existing) return null;

        const evidenceSummary = mergeCandidateEvidence(
          updates,
          parseJsonObject(existing.evidence_summary_json),
        );
        if (updates.updated_at) {
          evidenceSummary.updated_at = updates.updated_at;
        }

        const { rows } = await client.query(
          `UPDATE external_asset_candidates
           SET approval_status = COALESCE($3, approval_status),
               approved_target_id = COALESCE($4, approved_target_id),
               entity_id = COALESCE($5, entity_id),
               confidence = COALESCE($6, confidence),
               last_seen_at = COALESCE($7::timestamptz, last_seen_at),
               evidence_summary_json = $8::jsonb
           WHERE tenant_id = $1 AND id = $2
           RETURNING ${EXTERNAL_CANDIDATE_COLUMNS}`,
          [
            tenantId,
            id,
            updates.approval_status ?? null,
            updates.approved_target_id ?? null,
            updates.entity_id ?? null,
            updates.confidence ?? null,
            updates.last_seen_at ?? null,
            JSON.stringify(evidenceSummary),
          ],
        );
        return mapExternalCandidateRow(rows[0] ?? null);
      });
    },

    async listInboxCandidates(ctx) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${EXTERNAL_CANDIDATE_COLUMNS}
           FROM external_asset_candidates
           WHERE tenant_id = $1
             AND approval_status IN ('not_requested', 'pending')
           ORDER BY confidence DESC, created_at ASC`,
          [tenantId],
        );
        return rows.map(mapExternalCandidateRow);
      });
    },
  };
}