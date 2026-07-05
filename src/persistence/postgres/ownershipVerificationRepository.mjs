import { withTenantContext } from './tenantContext.mjs';

const VERIFICATION_COLUMNS = `id, tenant_id, target_group_id, agent_id, declared_fqdn, status,
  challenge_nonce_hash, probe_observed, agent_observed, verified_at, confirmed_by_user_id,
  confirmed_at, probe_job_id, created_at, created_by`;

const OPEN_STATUSES = ['challenge_sent', 'verified'];

function toIso(value) {
  if (value == null) return value;
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

function asObject(value) {
  if (value && typeof value === 'object' && !Array.isArray(value)) return value;
  return null;
}

/**
 * @param {Record<string, unknown> | null | undefined} row
 */
export function mapOwnershipVerificationRow(row) {
  if (!row) return null;
  const mapped = {
    id: row.id,
    tenant_id: row.tenant_id,
    target_group_id: row.target_group_id,
    agent_id: row.agent_id ?? null,
    declared_fqdn: row.declared_fqdn ?? null,
    status: row.status,
    challenge_nonce_hash: row.challenge_nonce_hash ?? null,
    probe_observed: Boolean(row.probe_observed),
    agent_observed: Boolean(row.agent_observed),
    verified_at: row.verified_at == null ? null : toIso(row.verified_at),
    confirmed_by_user_id: row.confirmed_by_user_id ?? null,
    confirmed_at: row.confirmed_at == null ? null : toIso(row.confirmed_at),
    created_at: toIso(row.created_at),
    created_by: row.created_by ?? null,
  };
  if (row.probe_job_id != null) mapped.probe_job_id = row.probe_job_id;
  return mapped;
}

/**
 * @param {import('pg').Pool} pool
 */
export function createOwnershipVerificationRepository(pool) {
  return {
    async insertVerification(ctx, record) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO ownership_verifications (
             id, tenant_id, target_group_id, agent_id, declared_fqdn, status,
             challenge_nonce_hash, probe_observed, agent_observed, verified_at,
             confirmed_by_user_id, confirmed_at, probe_job_id, created_at, created_by
           )
           VALUES (
             $1, $2, $3, $4, $5, $6, $7, $8, $9, $10::timestamptz, $11, $12::timestamptz, $13,
             $14::timestamptz, $15
           )
           RETURNING ${VERIFICATION_COLUMNS}`,
          [
            record.id,
            ctx.tenantId,
            record.target_group_id,
            record.agent_id ?? null,
            record.declared_fqdn ?? null,
            record.status,
            record.challenge_nonce_hash,
            record.probe_observed ?? false,
            record.agent_observed ?? false,
            record.verified_at ?? null,
            record.confirmed_by_user_id ?? null,
            record.confirmed_at ?? null,
            record.probe_job_id ?? null,
            record.created_at,
            record.created_by ?? null,
          ],
        );
        return mapOwnershipVerificationRow(rows[0]);
      });
    },

    async setVerificationProbeJobId(ctx, id, probeJobId) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE ownership_verifications
           SET probe_job_id = $3
           WHERE tenant_id = $1 AND id = $2
           RETURNING ${VERIFICATION_COLUMNS}`,
          [ctx.tenantId, id, probeJobId],
        );
        return mapOwnershipVerificationRow(rows[0] ?? null);
      });
    },

    async findById(ctx, id) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${VERIFICATION_COLUMNS}
           FROM ownership_verifications
           WHERE id = $1 AND tenant_id = $2`,
          [id, ctx.tenantId],
        );
        return mapOwnershipVerificationRow(rows[0] ?? null);
      });
    },

    async findOpenByNonceHash(ctx, nonceHash) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${VERIFICATION_COLUMNS}
           FROM ownership_verifications
           WHERE tenant_id = $1
             AND challenge_nonce_hash = $2
             AND status = ANY($3::text[])`,
          [ctx.tenantId, nonceHash, OPEN_STATUSES],
        );
        return mapOwnershipVerificationRow(rows[0] ?? null);
      });
    },

    async listByTenant(ctx) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${VERIFICATION_COLUMNS}
           FROM ownership_verifications
           WHERE tenant_id = $1
           ORDER BY created_at`,
          [ctx.tenantId],
        );
        return rows.map(mapOwnershipVerificationRow);
      });
    },

    async updateVerificationSignals(ctx, id, patch) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE ownership_verifications
           SET probe_observed = COALESCE($3, probe_observed),
               agent_observed = COALESCE($4, agent_observed),
               status = COALESCE($5, status),
               verified_at = COALESCE($6::timestamptz, verified_at)
           WHERE tenant_id = $1 AND id = $2
           RETURNING ${VERIFICATION_COLUMNS}`,
          [
            ctx.tenantId,
            id,
            patch.probe_observed ?? null,
            patch.agent_observed ?? null,
            patch.status ?? null,
            patch.verified_at ?? null,
          ],
        );
        return mapOwnershipVerificationRow(rows[0] ?? null);
      });
    },

    async updateVerificationConfirmed(ctx, id, { confirmed_by_user_id, confirmed_at }) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE ownership_verifications
           SET confirmed_by_user_id = $3,
               confirmed_at = $4::timestamptz
           WHERE tenant_id = $1 AND id = $2
           RETURNING ${VERIFICATION_COLUMNS}`,
          [ctx.tenantId, id, confirmed_by_user_id, confirmed_at],
        );
        return mapOwnershipVerificationRow(rows[0] ?? null);
      });
    },

    async updateTargetGroupOwnershipStatus(ctx, targetGroupId, ownershipStatus) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        await client.query(
          `UPDATE target_groups
           SET ownership_status = $3
           WHERE tenant_id = $1 AND id = $2 AND archived_at IS NULL`,
          [ctx.tenantId, targetGroupId, ownershipStatus],
        );
      });
    },

    async updateTargetGroupDnsOwnership(ctx, targetGroupId, { dns_ownership, ownership_status }) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const sets = ['dns_ownership = $3::jsonb'];
        const params = [ctx.tenantId, targetGroupId, JSON.stringify(dns_ownership ?? null)];
        if (ownership_status !== undefined) {
          sets.push(`ownership_status = $${params.length + 1}`);
          params.push(ownership_status);
        }
        await client.query(
          `UPDATE target_groups
           SET ${sets.join(', ')}
           WHERE tenant_id = $1 AND id = $2 AND archived_at IS NULL`,
          params,
        );
      });
    },

    async listFqdnTargetValues(ctx, targetGroupId) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT value
           FROM targets
           WHERE tenant_id = $1 AND target_group_id = $2 AND kind = 'fqdn'
           ORDER BY created_at`,
          [ctx.tenantId, targetGroupId],
        );
        return rows.map((row) => String(row.value).trim().toLowerCase());
      });
    },

    async getActiveTargetGroup(ctx, targetGroupId) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT id, tenant_id, validation_mode, ownership_status, dns_ownership, archived_at
           FROM target_groups
           WHERE tenant_id = $1 AND id = $2 AND archived_at IS NULL`,
          [ctx.tenantId, targetGroupId],
        );
        const row = rows[0];
        if (!row) return null;
        return {
          id: row.id,
          tenant_id: row.tenant_id,
          validation_mode: row.validation_mode ?? 'agent_assisted',
          ownership_status: row.ownership_status ?? 'unverified',
          dns_ownership: asObject(row.dns_ownership),
        };
      });
    },
  };
}