import { withTenantContext } from './tenantContext.mjs';

const TRUST_KEY_COLUMNS = `id, tenant_id, name, public_key_der_base64, fingerprint_sha256, status,
  created_at, created_by, revoked_at`;

const RELEASE_COLUMNS = `id, tenant_id, version, channel, state, manifest_json, signature,
  distribution_json, rollout_json, rollback_json, created_at, created_by, rollback_requested_at`;

const STATUS_COLUMNS = `id, tenant_id, agent_id, release_id, status, action, installed_version, error_code, recorded_at`;

function toIso(value) {
  if (value == null) return value;
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

function asObject(value) {
  if (value && typeof value === 'object' && !Array.isArray(value)) return value;
  return {};
}

/**
 * @param {Record<string, unknown> | null | undefined} row
 */
export function mapTrustKeyRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    name: row.name,
    public_key_der_base64: row.public_key_der_base64,
    fingerprint_sha256: row.fingerprint_sha256,
    status: row.status,
    created_at: toIso(row.created_at),
    created_by: row.created_by ?? undefined,
    revoked_at: row.revoked_at == null ? null : toIso(row.revoked_at),
  };
}

function mapRollbackJson(raw) {
  if (raw == null) return null;
  const rb = asObject(raw);
  if (Object.keys(rb).length === 0) return null;
  return {
    version: rb.version,
    manifest: asObject(rb.manifest),
    signature: rb.signature ?? null,
    distribution: asObject(rb.distribution),
  };
}

/**
 * @param {Record<string, unknown> | null | undefined} row
 */
export function mapReleaseRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    version: row.version,
    channel: row.channel,
    state: row.state,
    manifest: asObject(row.manifest_json),
    signature: row.signature ?? null,
    distribution: asObject(row.distribution_json),
    rollout: asObject(row.rollout_json),
    rollback: mapRollbackJson(row.rollback_json),
    created_at: toIso(row.created_at),
    created_by: row.created_by ?? undefined,
    rollback_requested_at:
      row.rollback_requested_at == null ? null : toIso(row.rollback_requested_at),
  };
}

/**
 * @param {Record<string, unknown> | null | undefined} row
 */
export function mapStatusRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    agent_id: row.agent_id,
    release_id: row.release_id,
    status: row.status,
    action: row.action ?? null,
    installed_version: row.installed_version ?? null,
    error_code: row.error_code ?? null,
    recorded_at: toIso(row.recorded_at),
  };
}

/**
 * @param {import('pg').Pool} pool
 */
export function createAgentUpdateRepository(pool) {
  return {
    async createTrustKey(record) {
      const tenantId = record.tenant_id;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO agent_update_trust_keys (
             id, tenant_id, name, public_key_der_base64, fingerprint_sha256, status,
             created_at, created_by, revoked_at
           )
           VALUES ($1, $2, $3, $4, $5, $6, $7::timestamptz, $8, $9::timestamptz)
           RETURNING ${TRUST_KEY_COLUMNS}`,
          [
            record.id,
            tenantId,
            record.name,
            record.public_key_der_base64,
            record.fingerprint_sha256,
            record.status ?? 'active',
            record.created_at,
            record.created_by ?? null,
            record.revoked_at ?? null,
          ],
        );
        return mapTrustKeyRow(rows[0]);
      });
    },

    async listTrustKeys(ctx) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${TRUST_KEY_COLUMNS}
           FROM agent_update_trust_keys
           WHERE tenant_id = $1
           ORDER BY created_at`,
          [ctx.tenantId],
        );
        return rows.map(mapTrustKeyRow);
      });
    },

    async getTrustKeyById(ctx, id) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${TRUST_KEY_COLUMNS}
           FROM agent_update_trust_keys
           WHERE tenant_id = $1 AND id = $2`,
          [ctx.tenantId, id],
        );
        return mapTrustKeyRow(rows[0] ?? null);
      });
    },

    async getActiveTrustKeyByFingerprint(ctx, fingerprintSha256) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${TRUST_KEY_COLUMNS}
           FROM agent_update_trust_keys
           WHERE tenant_id = $1 AND fingerprint_sha256 = $2 AND status = 'active'
           LIMIT 1`,
          [ctx.tenantId, fingerprintSha256],
        );
        return mapTrustKeyRow(rows[0] ?? null);
      });
    },

    async revokeTrustKey(ctx, id, revokedAt) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE agent_update_trust_keys
           SET status = 'revoked', revoked_at = $3::timestamptz
           WHERE tenant_id = $1 AND id = $2
           RETURNING ${TRUST_KEY_COLUMNS}`,
          [ctx.tenantId, id, revokedAt],
        );
        return mapTrustKeyRow(rows[0] ?? null);
      });
    },

    async createRelease(record) {
      const tenantId = record.tenant_id;
      const rollbackJson = record.rollback == null ? null : JSON.stringify(record.rollback);
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO agent_update_releases (
             id, tenant_id, version, channel, state, manifest_json, signature,
             distribution_json, rollout_json, rollback_json, created_at, created_by, rollback_requested_at
           )
           VALUES (
             $1, $2, $3, $4, $5, $6::jsonb, $7, $8::jsonb, $9::jsonb, $10::jsonb,
             $11::timestamptz, $12, $13::timestamptz
           )
           RETURNING ${RELEASE_COLUMNS}`,
          [
            record.id,
            tenantId,
            record.version,
            record.channel,
            record.state ?? 'active',
            JSON.stringify(record.manifest ?? {}),
            record.signature ?? null,
            JSON.stringify(record.distribution ?? {}),
            JSON.stringify(record.rollout ?? {}),
            rollbackJson,
            record.created_at,
            record.created_by ?? null,
            record.rollback_requested_at ?? null,
          ],
        );
        return mapReleaseRow(rows[0]);
      });
    },

    async listReleases(ctx) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${RELEASE_COLUMNS}
           FROM agent_update_releases
           WHERE tenant_id = $1
           ORDER BY created_at`,
          [ctx.tenantId],
        );
        return rows.map(mapReleaseRow);
      });
    },

    async getReleaseById(ctx, id) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${RELEASE_COLUMNS}
           FROM agent_update_releases
           WHERE tenant_id = $1 AND id = $2`,
          [ctx.tenantId, id],
        );
        return mapReleaseRow(rows[0] ?? null);
      });
    },

    async updateReleaseRollbackRequested(ctx, id, { state, rollback_requested_at }) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE agent_update_releases
           SET state = $3, rollback_requested_at = $4::timestamptz
           WHERE tenant_id = $1 AND id = $2
           RETURNING ${RELEASE_COLUMNS}`,
          [ctx.tenantId, id, state, rollback_requested_at],
        );
        return mapReleaseRow(rows[0] ?? null);
      });
    },

    async appendStatus(record) {
      const tenantId = record.tenant_id;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO agent_update_statuses (
             id, tenant_id, agent_id, release_id, status, action, installed_version, error_code, recorded_at
           )
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::timestamptz)
           RETURNING ${STATUS_COLUMNS}`,
          [
            record.id,
            tenantId,
            record.agent_id,
            record.release_id,
            record.status,
            record.action ?? null,
            record.installed_version ?? null,
            record.error_code ?? null,
            record.recorded_at,
          ],
        );
        return mapStatusRow(rows[0]);
      });
    },

    async getLatestStatusForAgentRelease(ctx, agentId, releaseId) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${STATUS_COLUMNS}
           FROM agent_update_statuses
           WHERE tenant_id = $1 AND agent_id = $2 AND release_id = $3
           ORDER BY recorded_at DESC
           LIMIT 1`,
          [ctx.tenantId, agentId, releaseId],
        );
        return mapStatusRow(rows[0] ?? null);
      });
    },

    async updateAgentVersion(ctx, agentId, version) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE agents
           SET version = $3
           WHERE tenant_id = $1 AND id = $2
           RETURNING id, tenant_id, version`,
          [ctx.tenantId, agentId, version],
        );
        return rows[0] ?? null;
      });
    },
  };
}