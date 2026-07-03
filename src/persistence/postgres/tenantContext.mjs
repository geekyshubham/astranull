/**
 * Run callback queries inside a transaction with transaction-local tenant context for RLS.
 *
 * @param {import('pg').Pool} pool
 * @param {string} tenantId
 * @param {(client: import('pg').PoolClient) => Promise<unknown>} callback
 */
/**
 * Run callback with an existing tenant-scoped client or open a new transaction.
 *
 * @param {import('pg').Pool} pool
 * @param {string} tenantId
 * @param {import('pg').PoolClient | undefined} client
 * @param {(client: import('pg').PoolClient) => Promise<unknown>} callback
 */
export async function runWithTenantClient(pool, tenantId, client, callback) {
  if (client) return callback(client);
  return withTenantContext(pool, tenantId, callback);
}

export async function withTenantContext(pool, tenantId, callback) {
  const normalized = String(tenantId ?? '').trim();
  if (!normalized) {
    throw new Error('tenant id must be a non-empty string.');
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`SELECT set_config('app.tenant_id', $1, true)`, [normalized]);
    const result = await callback(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch {
      // preserve original error
    }
    throw err;
  } finally {
    client.release();
  }
}