import { withTenantContext } from './tenantContext.mjs';

/**
 * @param {import('pg').Pool} pool
 */
export function createKillSwitchRepository(pool) {
  return {
    async isKillSwitchActiveForTenant(ctx) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT active
           FROM soc_kill_switch
           WHERE tenant_id = $1`,
          [ctx.tenantId],
        );
        if (!rows[0]) return false;
        return Boolean(rows[0].active);
      });
    },

    async getKillSwitchRecord(ctx) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT tenant_id, active, reason, updated_at, updated_by
           FROM soc_kill_switch
           WHERE tenant_id = $1`,
          [ctx.tenantId],
        );
        const row = rows[0];
        if (!row) {
          return {
            active: false,
            reason: null,
            updated_at: null,
            updated_by: null,
            tenant_id: ctx.tenantId,
          };
        }
        return {
          active: Boolean(row.active),
          reason: row.reason,
          updated_at: row.updated_at instanceof Date ? row.updated_at.toISOString() : row.updated_at,
          updated_by: row.updated_by,
          tenant_id: row.tenant_id,
        };
      });
    },

    async upsertKillSwitch(ctx, { active, reason, updated_by, updated_at }) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO soc_kill_switch (tenant_id, active, reason, updated_at, updated_by)
           VALUES ($1, $2, $3, $4::timestamptz, $5)
           ON CONFLICT (tenant_id)
           DO UPDATE SET
             active = EXCLUDED.active,
             reason = EXCLUDED.reason,
             updated_at = EXCLUDED.updated_at,
             updated_by = EXCLUDED.updated_by
           RETURNING tenant_id, active, reason, updated_at, updated_by`,
          [ctx.tenantId, active, reason ?? null, updated_at, updated_by ?? null],
        );
        const row = rows[0];
        return {
          active: Boolean(row.active),
          reason: row.reason,
          updated_at: row.updated_at instanceof Date ? row.updated_at.toISOString() : row.updated_at,
          updated_by: row.updated_by,
          tenant_id: row.tenant_id,
        };
      });
    },
  };
}