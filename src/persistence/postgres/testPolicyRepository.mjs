import { withTenantContext } from './tenantContext.mjs';

const TEST_POLICY_COLUMNS = `id, tenant_id, target_group_id, check_id, cadence, expected_verdict,
  safe_windows, state, safety_policy_snapshot, archived_at, created_at, updated_at`;

function toIso(value) {
  if (value == null) return value;
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function asObject(value) {
  if (value && typeof value === 'object' && !Array.isArray(value)) return value;
  return {};
}

function mapTestPolicyRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    target_group_id: row.target_group_id,
    check_id: row.check_id,
    cadence: row.cadence,
    expected_verdict: row.expected_verdict,
    safe_windows: asArray(row.safe_windows),
    state: row.state,
    safety_policy_snapshot: asObject(row.safety_policy_snapshot),
    ...(row.archived_at ? { archived_at: toIso(row.archived_at) } : {}),
    created_at: toIso(row.created_at),
    updated_at: toIso(row.updated_at),
  };
}

/**
 * @param {import('pg').Pool} pool
 */
export function createPostgresTestPolicyRepository(pool) {
  return {
    async listTestPolicies(ctx) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${TEST_POLICY_COLUMNS}
           FROM test_policies
           WHERE tenant_id = $1 AND archived_at IS NULL
           ORDER BY created_at`,
          [ctx.tenantId],
        );
        return rows.map(mapTestPolicyRow);
      });
    },

    async getActiveTestPolicy(ctx, id) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${TEST_POLICY_COLUMNS}
           FROM test_policies
           WHERE id = $1 AND tenant_id = $2 AND archived_at IS NULL`,
          [id, ctx.tenantId],
        );
        return mapTestPolicyRow(rows[0] ?? null);
      });
    },

    async createTestPolicy(ctx, record) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO test_policies (
             id, tenant_id, target_group_id, check_id, cadence, expected_verdict,
             safe_windows, state, safety_policy_snapshot, created_at, updated_at
           )
           VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9::jsonb, $10::timestamptz, $11::timestamptz)
           RETURNING ${TEST_POLICY_COLUMNS}`,
          [
            record.id,
            ctx.tenantId,
            record.target_group_id,
            record.check_id,
            record.cadence,
            record.expected_verdict,
            JSON.stringify(asArray(record.safe_windows)),
            record.state ?? 'active',
            JSON.stringify(asObject(record.safety_policy_snapshot)),
            record.created_at,
            record.updated_at,
          ],
        );
        return mapTestPolicyRow(rows[0]);
      });
    },

    async updateTestPolicy(ctx, id, patch) {
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const sets = [];
        const params = [];
        let n = 1;

        if (patch.cadence !== undefined) {
          sets.push(`cadence = $${n++}`);
          params.push(patch.cadence);
        }
        if (patch.expected_verdict !== undefined) {
          sets.push(`expected_verdict = $${n++}`);
          params.push(patch.expected_verdict);
        }
        if (patch.safe_windows !== undefined) {
          sets.push(`safe_windows = $${n++}::jsonb`);
          params.push(JSON.stringify(asArray(patch.safe_windows)));
        }
        if (patch.state !== undefined) {
          sets.push(`state = $${n++}`);
          params.push(patch.state);
        }
        sets.push(`updated_at = $${n++}::timestamptz`);
        params.push(patch.updated_at ?? new Date().toISOString());

        params.push(id, ctx.tenantId);
        const idParam = n++;
        const tenantParam = n++;

        const { rows } = await client.query(
          `UPDATE test_policies
           SET ${sets.join(', ')}
           WHERE id = $${idParam} AND tenant_id = $${tenantParam} AND archived_at IS NULL
           RETURNING ${TEST_POLICY_COLUMNS}`,
          params,
        );
        return mapTestPolicyRow(rows[0] ?? null);
      });
    },

    async archiveTestPolicy(ctx, id, options = {}) {
      const now = options.now ?? new Date().toISOString();
      return withTenantContext(pool, ctx.tenantId, async (client) => {
        const { rows } = await client.query(
          `UPDATE test_policies
           SET state = 'archived', archived_at = $3::timestamptz, updated_at = $3::timestamptz
           WHERE id = $1 AND tenant_id = $2 AND archived_at IS NULL
           RETURNING ${TEST_POLICY_COLUMNS}`,
          [id, ctx.tenantId, now],
        );
        return mapTestPolicyRow(rows[0] ?? null);
      });
    },
  };
}

export { mapTestPolicyRow };
