import { withTenantContext } from './tenantContext.mjs';

const BOOTSTRAP_TOKEN_COLUMNS = `id, tenant_id, name, token_hash, token_salt, environment_id, target_group_id,
  allowed_modes, max_registrations, registrations_used, allowed_cidrs,
  expires_at, revoked_at, created_by, created_at`;

const SERVICE_ACCOUNT_COLUMNS = `id, tenant_id, name, role, scopes, secret_hash, secret_salt,
  expires_at, revoked_at, created_at, created_by, rotated_at, last_used_at`;

function toIso(value) {
  if (value == null) return value;
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

function asStringArray(value) {
  return Array.isArray(value) ? value : [];
}

function mapBootstrapTokenRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    name: row.name ?? undefined,
    token_hash: row.token_hash,
    token_salt: row.token_salt,
    environment_id: row.environment_id ?? undefined,
    target_group_id: row.target_group_id ?? null,
    allowed_modes: asStringArray(row.allowed_modes),
    max_registrations: Number(row.max_registrations),
    registrations_used: Number(row.registrations_used),
    allowed_cidrs: asStringArray(row.allowed_cidrs),
    expires_at: toIso(row.expires_at),
    revoked_at: row.revoked_at == null ? null : toIso(row.revoked_at),
    created_by: row.created_by ?? undefined,
    created_at: toIso(row.created_at),
  };
}

function mapServiceAccountRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    name: row.name,
    role: row.role,
    scopes: asStringArray(row.scopes),
    secret_hash: row.secret_hash,
    secret_salt: row.secret_salt,
    expires_at: row.expires_at == null ? null : toIso(row.expires_at),
    revoked_at: row.revoked_at == null ? null : toIso(row.revoked_at),
    created_at: toIso(row.created_at),
    created_by: row.created_by ?? undefined,
    rotated_at: row.rotated_at == null ? null : toIso(row.rotated_at),
    last_used_at: row.last_used_at == null ? null : toIso(row.last_used_at),
  };
}

/**
 * @param {import('pg').Pool} pool
 */
export function createAuthTokenRepository(pool) {
  return {
    async createBootstrapToken(ctx, record) {
      const tenantId = ctx.tenantId;
      const allowedModes = asStringArray(record.allowed_modes);
      const allowedCidrs = asStringArray(record.allowed_cidrs);

      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO bootstrap_tokens (
             id, tenant_id, name, token_hash, token_salt, environment_id, target_group_id,
             allowed_modes, max_registrations, registrations_used, allowed_cidrs,
             expires_at, revoked_at, created_by, created_at
           )
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::timestamptz, $13::timestamptz, $14, $15::timestamptz)
           RETURNING ${BOOTSTRAP_TOKEN_COLUMNS}`,
          [
            record.id,
            tenantId,
            record.name ?? null,
            record.token_hash,
            record.token_salt,
            record.environment_id ?? null,
            record.target_group_id ?? null,
            allowedModes,
            record.max_registrations ?? 1,
            record.registrations_used ?? 0,
            allowedCidrs,
            record.expires_at,
            record.revoked_at ?? null,
            record.created_by ?? null,
            record.created_at,
          ],
        );
        return mapBootstrapTokenRow(rows[0]);
      });
    },

    async listBootstrapTokens(ctx) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${BOOTSTRAP_TOKEN_COLUMNS}
           FROM bootstrap_tokens
           WHERE tenant_id = $1
           ORDER BY created_at`,
          [ctx.tenantId],
        );
        return rows.map(mapBootstrapTokenRow);
      });
    },

    async getBootstrapTokenById(ctx, id) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${BOOTSTRAP_TOKEN_COLUMNS}
           FROM bootstrap_tokens
           WHERE tenant_id = $1 AND id = $2`,
          [ctx.tenantId, id],
        );
        return mapBootstrapTokenRow(rows[0] ?? null);
      });
    },

    async findBootstrapTokenByAddressedHint({ tenantId, id }) {
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${BOOTSTRAP_TOKEN_COLUMNS}
           FROM bootstrap_tokens
           WHERE tenant_id = $1 AND id = $2`,
          [tenantId, id],
        );
        return mapBootstrapTokenRow(rows[0] ?? null);
      });
    },

    async revokeBootstrapToken(ctx, id, revokedAt) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE bootstrap_tokens
           SET revoked_at = $1::timestamptz
           WHERE tenant_id = $2 AND id = $3
           RETURNING ${BOOTSTRAP_TOKEN_COLUMNS}`,
          [revokedAt, ctx.tenantId, id],
        );
        return mapBootstrapTokenRow(rows[0] ?? null);
      });
    },

    async incrementBootstrapTokenRegistrations({ tenantId, id }) {
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE bootstrap_tokens
           SET registrations_used = registrations_used + 1
           WHERE tenant_id = $1 AND id = $2
           RETURNING ${BOOTSTRAP_TOKEN_COLUMNS}`,
          [tenantId, id],
        );
        return mapBootstrapTokenRow(rows[0] ?? null);
      });
    },

    async consumeBootstrapTokenRegistration({ tenantId, id }, usedAt) {
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE bootstrap_tokens
           SET registrations_used = registrations_used + 1
           WHERE tenant_id = $1 AND id = $2
             AND revoked_at IS NULL
             AND expires_at >= $3::timestamptz
             AND registrations_used < max_registrations
           RETURNING ${BOOTSTRAP_TOKEN_COLUMNS}`,
          [tenantId, id, usedAt],
        );
        return mapBootstrapTokenRow(rows[0] ?? null);
      });
    },

    async createServiceAccount(ctx, record) {
      const tenantId = ctx.tenantId;
      const scopes = asStringArray(record.scopes);

      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO service_accounts (
             id, tenant_id, name, role, scopes, secret_hash, secret_salt,
             expires_at, revoked_at, created_at, created_by, rotated_at, last_used_at
           )
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8::timestamptz, $9::timestamptz, $10::timestamptz, $11, $12::timestamptz, $13::timestamptz)
           RETURNING ${SERVICE_ACCOUNT_COLUMNS}`,
          [
            record.id,
            tenantId,
            record.name,
            record.role,
            scopes,
            record.secret_hash,
            record.secret_salt,
            record.expires_at ?? null,
            record.revoked_at ?? null,
            record.created_at,
            record.created_by ?? null,
            record.rotated_at ?? null,
            record.last_used_at ?? null,
          ],
        );
        return mapServiceAccountRow(rows[0]);
      });
    },

    async listServiceAccounts(ctx) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${SERVICE_ACCOUNT_COLUMNS}
           FROM service_accounts
           WHERE tenant_id = $1
           ORDER BY created_at`,
          [ctx.tenantId],
        );
        return rows.map(mapServiceAccountRow);
      });
    },

    async getServiceAccountById(ctx, id) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${SERVICE_ACCOUNT_COLUMNS}
           FROM service_accounts
           WHERE tenant_id = $1 AND id = $2`,
          [ctx.tenantId, id],
        );
        return mapServiceAccountRow(rows[0] ?? null);
      });
    },

    async findServiceAccountByAddressedHint({ tenantId, id }) {
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${SERVICE_ACCOUNT_COLUMNS}
           FROM service_accounts
           WHERE tenant_id = $1 AND id = $2`,
          [tenantId, id],
        );
        return mapServiceAccountRow(rows[0] ?? null);
      });
    },

    async revokeServiceAccount(ctx, id, revokedAt) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE service_accounts
           SET revoked_at = $1::timestamptz
           WHERE tenant_id = $2 AND id = $3
           RETURNING ${SERVICE_ACCOUNT_COLUMNS}`,
          [revokedAt, ctx.tenantId, id],
        );
        return mapServiceAccountRow(rows[0] ?? null);
      });
    },

    async rotateServiceAccountSecret(ctx, id, { secret_hash, secret_salt, rotated_at }) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE service_accounts
           SET secret_hash = $1, secret_salt = $2, rotated_at = $3::timestamptz, last_used_at = NULL
           WHERE tenant_id = $4 AND id = $5
           RETURNING ${SERVICE_ACCOUNT_COLUMNS}`,
          [secret_hash, secret_salt, rotated_at, ctx.tenantId, id],
        );
        return mapServiceAccountRow(rows[0] ?? null);
      });
    },

    async recordServiceAccountLastUsed({ tenantId, id }, usedAt) {
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE service_accounts
           SET last_used_at = $1::timestamptz
           WHERE tenant_id = $2 AND id = $3
           RETURNING ${SERVICE_ACCOUNT_COLUMNS}`,
          [usedAt, tenantId, id],
        );
        return mapServiceAccountRow(rows[0] ?? null);
      });
    },
  };
}

export { mapBootstrapTokenRow, mapServiceAccountRow };