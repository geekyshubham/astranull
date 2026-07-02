import { withTenantContext } from './tenantContext.mjs';

const AGENT_COLUMNS = `id, tenant_id, environment_id, target_group_id, bootstrap_token_id, name, hostname,
  status, version, placement_type, capabilities, fingerprint, credential_hash, credential_salt,
  last_heartbeat_at, metadata_json, created_at`;

const AGENT_JOB_COLUMNS = `id, tenant_id, agent_id, test_run_id, check_id, target_id, type, status,
  nonce_hash, nonce_for_agent, payload_json, created_at, acked_at, observed_at`;

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

function mapAgentRow(row) {
  if (!row) return null;
  const mapped = {
    id: row.id,
    tenant_id: row.tenant_id,
    environment_id: row.environment_id ?? undefined,
    target_group_id: row.target_group_id ?? null,
    bootstrap_token_id: row.bootstrap_token_id ?? undefined,
    name: row.name ?? undefined,
    hostname: row.hostname ?? undefined,
    status: row.status,
    version: row.version ?? undefined,
    placement_type: row.placement_type ?? undefined,
    capabilities: asStringArray(row.capabilities),
    fingerprint: row.fingerprint ?? null,
    last_heartbeat_at:
      row.last_heartbeat_at == null ? null : toIso(row.last_heartbeat_at),
    created_at: toIso(row.created_at),
  };
  if (row.credential_hash != null) mapped.credential_hash = row.credential_hash;
  if (row.credential_salt != null) mapped.credential_salt = row.credential_salt;
  const metadata = asObject(row.metadata_json);
  if (Object.keys(metadata).length > 0) mapped.metadata = metadata;
  return mapped;
}

function mapAgentJobRow(row) {
  if (!row) return null;
  const mapped = {
    id: row.id,
    tenant_id: row.tenant_id,
    agent_id: row.agent_id,
    test_run_id: row.test_run_id ?? undefined,
    check_id: row.check_id ?? undefined,
    target_id: row.target_id ?? undefined,
    type: row.type,
    status: row.status,
    nonce_hash: row.nonce_hash ?? undefined,
    nonce_for_agent: row.nonce_for_agent ?? undefined,
    created_at: toIso(row.created_at),
    acked_at: row.acked_at == null ? null : toIso(row.acked_at),
    observed_at: row.observed_at == null ? null : toIso(row.observed_at),
  };
  const payload = asObject(row.payload_json);
  if (Object.keys(payload).length > 0) mapped.payload = payload;
  return mapped;
}

/**
 * @param {import('pg').Pool} pool
 */
export function createAgentControlRepository(pool) {
  return {
    async createAgent(record) {
      const tenantId = record.tenant_id;
      const capabilities = asStringArray(record.capabilities);
      const metadataJson = JSON.stringify(asObject(record.metadata));

      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO agents (
             id, tenant_id, environment_id, target_group_id, bootstrap_token_id, name, hostname,
             status, version, placement_type, capabilities, fingerprint, credential_hash, credential_salt,
             last_heartbeat_at, metadata_json, created_at
           )
           VALUES (
             $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
             $15::timestamptz, $16::jsonb, $17::timestamptz
           )
           RETURNING ${AGENT_COLUMNS}`,
          [
            record.id,
            tenantId,
            record.environment_id ?? null,
            record.target_group_id ?? null,
            record.bootstrap_token_id ?? null,
            record.name ?? null,
            record.hostname ?? null,
            record.status ?? 'pending',
            record.version ?? null,
            record.placement_type ?? null,
            capabilities,
            record.fingerprint ?? null,
            record.credential_hash ?? null,
            record.credential_salt ?? null,
            record.last_heartbeat_at ?? null,
            metadataJson,
            record.created_at,
          ],
        );
        return mapAgentRow(rows[0]);
      });
    },

    async listAgents(ctx) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${AGENT_COLUMNS}
           FROM agents
           WHERE tenant_id = $1
           ORDER BY created_at`,
          [ctx.tenantId],
        );
        return rows.map(mapAgentRow);
      });
    },

    async getAgentById(ctx, id) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${AGENT_COLUMNS}
           FROM agents
           WHERE tenant_id = $1 AND id = $2`,
          [ctx.tenantId, id],
        );
        return mapAgentRow(rows[0] ?? null);
      });
    },

    async findAgentByAddressedHint({ tenantId, id }) {
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${AGENT_COLUMNS}
           FROM agents
           WHERE tenant_id = $1 AND id = $2`,
          [tenantId, id],
        );
        return mapAgentRow(rows[0] ?? null);
      });
    },

    async updateAgentHeartbeat({ tenantId, id }, { version, capabilities, last_heartbeat_at }) {
      return withTenantContext(pool, tenantId, async (client) => {
        const sets = [`status = 'online'`, `last_heartbeat_at = $1::timestamptz`];
        const params = [last_heartbeat_at];
        let paramIndex = 2;

        if (version !== undefined) {
          sets.push(`version = $${paramIndex}`);
          params.push(version);
          paramIndex += 1;
        }
        if (capabilities !== undefined) {
          sets.push(`capabilities = $${paramIndex}`);
          params.push(asStringArray(capabilities));
          paramIndex += 1;
        }

        params.push(tenantId, id);
        const tenantParam = paramIndex;
        const idParam = paramIndex + 1;

        const { rows } = await client.query(
          `UPDATE agents
           SET ${sets.join(', ')}
           WHERE tenant_id = $${tenantParam} AND id = $${idParam}
           RETURNING ${AGENT_COLUMNS}`,
          params,
        );
        return mapAgentRow(rows[0] ?? null);
      });
    },

    async revokeAgent(ctx, id, revokedAt) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE agents
           SET status = 'revoked', metadata_json = COALESCE(metadata_json, '{}'::jsonb) || $1::jsonb
           WHERE tenant_id = $2 AND id = $3
           RETURNING ${AGENT_COLUMNS}`,
          [JSON.stringify({ revoked_at: revokedAt }), ctx.tenantId, id],
        );
        return mapAgentRow(rows[0] ?? null);
      });
    },

    async createAgentJob(record) {
      const tenantId = record.tenant_id;
      const payloadJson = JSON.stringify(asObject(record.payload));

      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO agent_jobs (
             id, tenant_id, agent_id, test_run_id, check_id, target_id, type, status,
             nonce_hash, nonce_for_agent, payload_json, created_at, acked_at, observed_at
           )
           VALUES (
             $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb,
             $12::timestamptz, $13::timestamptz, $14::timestamptz
           )
           RETURNING ${AGENT_JOB_COLUMNS}`,
          [
            record.id,
            tenantId,
            record.agent_id,
            record.test_run_id ?? null,
            record.check_id ?? null,
            record.target_id ?? null,
            record.type ?? 'observe_window',
            record.status ?? 'pending',
            record.nonce_hash ?? null,
            record.nonce_for_agent ?? null,
            payloadJson,
            record.created_at,
            record.acked_at ?? null,
            record.observed_at ?? null,
          ],
        );
        return mapAgentJobRow(rows[0]);
      });
    },

    async listPendingAgentJobs({ tenantId, agentId }) {
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${AGENT_JOB_COLUMNS}
           FROM agent_jobs
           WHERE tenant_id = $1 AND agent_id = $2 AND status = 'pending'
           ORDER BY created_at`,
          [tenantId, agentId],
        );
        return rows.map(mapAgentJobRow);
      });
    },

    async ackAgentJob({ tenantId, agentId, jobId }, ackedAt) {
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE agent_jobs
           SET status = 'acked', acked_at = $1::timestamptz
           WHERE tenant_id = $2 AND agent_id = $3 AND id = $4 AND status = 'pending'
           RETURNING ${AGENT_JOB_COLUMNS}`,
          [ackedAt, tenantId, agentId, jobId],
        );
        return mapAgentJobRow(rows[0] ?? null);
      });
    },

    async markAgentJobObserved({ tenantId, agentId, jobId }, observedAt) {
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE agent_jobs
           SET status = 'observed', observed_at = $1::timestamptz
           WHERE tenant_id = $2 AND agent_id = $3 AND id = $4 AND status = 'acked'
           RETURNING ${AGENT_JOB_COLUMNS}`,
          [observedAt, tenantId, agentId, jobId],
        );
        return mapAgentJobRow(rows[0] ?? null);
      });
    },

    async getAgentJobById({ tenantId, agentId, jobId }) {
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${AGENT_JOB_COLUMNS}
           FROM agent_jobs
           WHERE tenant_id = $1 AND agent_id = $2 AND id = $3`,
          [tenantId, agentId, jobId],
        );
        return mapAgentJobRow(rows[0] ?? null);
      });
    },
  };
}

export { mapAgentRow, mapAgentJobRow };
