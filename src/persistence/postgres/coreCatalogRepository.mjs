import { newId } from '../../lib/ids.mjs';
import { normalizePrivacySettings } from '../../lib/privacySettings.mjs';
import { normalizeSafetyPolicy } from '../../lib/safeTestGuards.mjs';
import { runMetadataRetentionInTransaction } from './retentionRepository.mjs';
import { withTenantContext } from './tenantContext.mjs';

function toIso(value) {
  if (value == null) return value;
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

function asObject(value) {
  if (value && typeof value === 'object' && !Array.isArray(value)) return value;
  return {};
}

function mapTenantRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    name: row.name,
    plan: row.plan ?? undefined,
    data_region: row.data_region ?? undefined,
    status: row.status ?? 'active',
    privacy_settings: normalizePrivacySettings(row.privacy_settings),
    created_at: toIso(row.created_at),
  };
}

function mapEnvironmentRow(row) {
  if (!row) return null;
  const settings = asObject(row.settings_json);
  const mapped = {
    id: row.id,
    tenant_id: row.tenant_id,
    name: row.name,
    description: settings.description ?? '',
    status: row.status ?? 'active',
    privacy_settings: normalizePrivacySettings(row.privacy_settings),
    created_at: toIso(row.created_at),
  };
  if (row.timezone) mapped.timezone = row.timezone;
  if (settings.created_by) mapped.created_by = settings.created_by;
  if (settings.updated_at) mapped.updated_at = toIso(settings.updated_at);
  return mapped;
}

function mapTargetGroupRow(row) {
  if (!row) return null;
  const windows = row.safe_test_windows;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    environment_id: row.environment_id,
    name: row.name,
    description: row.description ?? '',
    expected_behavior_default: row.expected_behavior_default ?? undefined,
    timezone: row.timezone ?? 'UTC',
    safe_test_windows: Array.isArray(windows) ? windows : [],
    safety_policy: normalizeSafetyPolicy(row.safety_policy),
    created_at: toIso(row.created_at),
  };
}

function mapTargetRow(row) {
  if (!row) return null;
  const mapped = {
    id: row.id,
    tenant_id: row.tenant_id,
    target_group_id: row.target_group_id,
    kind: row.kind,
    value: row.value,
    expected_behavior: row.expected_behavior ?? undefined,
    created_at: toIso(row.created_at),
  };
  const metadata = asObject(row.metadata_json);
  if (Object.keys(metadata).length > 0) mapped.metadata = metadata;
  return mapped;
}

/**
 * @param {import('pg').Pool} pool
 */
export function createCoreCatalogRepository(pool) {
  return {
    async getCurrentTenant(ctx) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT id, name, plan, data_region, status, privacy_settings, created_at
           FROM tenants
           WHERE id = $1`,
          [ctx.tenantId],
        );
        return mapTenantRow(rows[0] ?? null);
      });
    },

    async patchCurrentTenant(ctx, body, options = {}) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const existing = await client.query(
          `SELECT id, name, plan, data_region, status, privacy_settings, created_at
           FROM tenants
           WHERE id = $1`,
          [ctx.tenantId],
        );
        if (!existing.rows[0]) return null;

        const current = existing.rows[0];
        const sets = [];
        const params = [];
        let n = 1;

        if (body.name) {
          sets.push(`name = $${n++}`);
          params.push(body.name);
        }
        if (body.privacy_settings) {
          const merged = normalizePrivacySettings({
            ...asObject(current.privacy_settings),
            ...body.privacy_settings,
          });
          sets.push(`privacy_settings = $${n++}::jsonb`);
          params.push(JSON.stringify(merged));
        }

        if (sets.length === 0) {
          return mapTenantRow(current);
        }

        params.push(ctx.tenantId);
        const idParam = n++;

        const { rows } = await client.query(
          `UPDATE tenants
           SET ${sets.join(', ')}
           WHERE id = $${idParam}
           RETURNING id, name, plan, data_region, status, privacy_settings, created_at`,
          params,
        );
        const tenantRow = rows[0] ?? null;
        if (!tenantRow) return null;
        if (body.privacy_settings) {
          await runMetadataRetentionInTransaction(
            client,
            ctx.tenantId,
            tenantRow,
            { userId: ctx.userId, role: ctx.role },
            { now: options.now },
          );
        }
        return mapTenantRow(tenantRow);
      });
    },

    async listEnvironments(ctx) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT id, tenant_id, name, status, timezone, privacy_settings, settings_json, created_at
           FROM environments
           WHERE tenant_id = $1 AND status <> $2
           ORDER BY created_at`,
          [ctx.tenantId, 'archived'],
        );
        return rows.map(mapEnvironmentRow);
      });
    },

    async createEnvironment(ctx, body, options = {}) {
      const id = options.id ?? newId('env');
      const now = options.now ?? new Date().toISOString();
      const name = body.name ?? 'Environment';
      const description = body.description ?? '';
      const privacySettings = normalizePrivacySettings(body.privacy_settings);
      const settingsJson = {
        description,
        created_by: ctx.userId,
      };

      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO environments (id, tenant_id, name, status, privacy_settings, settings_json, created_at)
           VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7::timestamptz)
           RETURNING id, tenant_id, name, status, timezone, privacy_settings, settings_json, created_at`,
          [id, ctx.tenantId, name, 'active', JSON.stringify(privacySettings), JSON.stringify(settingsJson), now],
        );
        return mapEnvironmentRow(rows[0]);
      });
    },

    async patchEnvironment(ctx, id, body, options = {}) {
      const now = options.now ?? new Date().toISOString();

      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const existing = await client.query(
          `SELECT id, tenant_id, name, status, timezone, privacy_settings, settings_json, created_at
           FROM environments
           WHERE id = $1 AND tenant_id = $2`,
          [id, ctx.tenantId],
        );
        if (!existing.rows[0]) return null;

        const current = existing.rows[0];
        const settings = { ...asObject(current.settings_json) };
        const sets = [];
        const params = [];
        let n = 1;

        if (body.name) {
          sets.push(`name = $${n++}`);
          params.push(body.name);
        }
        if (body.description !== undefined) {
          settings.description = body.description;
        }
        if (body.status) {
          sets.push(`status = $${n++}`);
          params.push(body.status);
        }
        if (body.privacy_settings) {
          const merged = normalizePrivacySettings({
            ...asObject(current.privacy_settings),
            ...body.privacy_settings,
          });
          sets.push(`privacy_settings = $${n++}::jsonb`);
          params.push(JSON.stringify(merged));
        }

        settings.updated_at = now;
        sets.push(`settings_json = $${n++}::jsonb`);
        params.push(JSON.stringify(settings));

        params.push(id, ctx.tenantId);
        const idParam = n++;
        const tenantParam = n++;

        const { rows } = await client.query(
          `UPDATE environments
           SET ${sets.join(', ')}
           WHERE id = $${idParam} AND tenant_id = $${tenantParam}
           RETURNING id, tenant_id, name, status, timezone, privacy_settings, settings_json, created_at`,
          params,
        );
        return mapEnvironmentRow(rows[0]);
      });
    },

    async listTargetGroups(ctx) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT id, tenant_id, environment_id, name, description, expected_behavior_default,
                  timezone, safe_test_windows, safety_policy, created_at
           FROM target_groups
           WHERE tenant_id = $1
           ORDER BY created_at`,
          [ctx.tenantId],
        );
        return rows.map(mapTargetGroupRow);
      });
    },

    async getTargetGroup(ctx, id) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT id, tenant_id, environment_id, name, description, expected_behavior_default,
                  timezone, safe_test_windows, safety_policy, created_at
           FROM target_groups
           WHERE id = $1 AND tenant_id = $2`,
          [id, ctx.tenantId],
        );
        const group = mapTargetGroupRow(rows[0] ?? null);
        if (!group) return null;

        const targets = await client.query(
          `SELECT id, tenant_id, target_group_id, kind, value, expected_behavior, metadata_json, created_at
           FROM targets
           WHERE target_group_id = $1 AND tenant_id = $2
           ORDER BY created_at`,
          [id, ctx.tenantId],
        );
        return { ...group, targets: targets.rows.map(mapTargetRow) };
      });
    },

    async createTargetGroup(ctx, body, options = {}) {
      const id = options.id ?? newId('tg');
      const now = options.now ?? new Date().toISOString();
      const record = {
        environment_id: body.environment_id ?? 'env_demo',
        name: body.name ?? 'New target group',
        description: body.description ?? '',
        expected_behavior_default: body.expected_behavior_default ?? 'must_block_before_origin',
        timezone: body.timezone ?? 'UTC',
        safe_test_windows: Array.isArray(body.safe_test_windows) ? body.safe_test_windows : [],
        safety_policy: normalizeSafetyPolicy(body.safety_policy),
      };

      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO target_groups (
             id, tenant_id, environment_id, name, description, expected_behavior_default,
             timezone, safe_test_windows, safety_policy, created_at
           )
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9::jsonb, $10::timestamptz)
           RETURNING id, tenant_id, environment_id, name, description, expected_behavior_default,
                     timezone, safe_test_windows, safety_policy, created_at`,
          [
            id,
            ctx.tenantId,
            record.environment_id,
            record.name,
            record.description,
            record.expected_behavior_default,
            record.timezone,
            JSON.stringify(record.safe_test_windows),
            JSON.stringify(record.safety_policy),
            now,
          ],
        );
        return mapTargetGroupRow(rows[0]);
      });
    },

    async addTarget(ctx, groupId, body, options = {}) {
      const id = options.id ?? newId('target');
      const now = options.now ?? new Date().toISOString();

      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const groupResult = await client.query(
          `SELECT id, expected_behavior_default
           FROM target_groups
           WHERE id = $1 AND tenant_id = $2`,
          [groupId, ctx.tenantId],
        );
        const group = groupResult.rows[0];
        if (!group) return null;

        const kind = body.kind ?? 'fqdn';
        const expectedBehavior = body.expected_behavior ?? group.expected_behavior_default;
        const metadata = body.metadata && typeof body.metadata === 'object' ? body.metadata : {};

        const { rows } = await client.query(
          `INSERT INTO targets (id, tenant_id, target_group_id, kind, value, expected_behavior, metadata_json, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::timestamptz)
           RETURNING id, tenant_id, target_group_id, kind, value, expected_behavior, metadata_json, created_at`,
          [
            id,
            ctx.tenantId,
            groupId,
            kind,
            body.value,
            expectedBehavior,
            JSON.stringify(metadata),
            now,
          ],
        );
        return mapTargetRow(rows[0]);
      });
    },
  };
}

export {
  mapTenantRow,
  mapEnvironmentRow,
  mapTargetGroupRow,
  mapTargetRow,
};
