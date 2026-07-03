#!/usr/bin/env node
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { closePgPool, createPgPool } from '../src/persistence/postgres/pool.mjs';
import { withTenantContext } from '../src/persistence/postgres/tenantContext.mjs';
import { LOCAL_STAGING_DEMO_IDS } from './lib/localStaging.mjs';
import { buildLocalPostgresDatabaseUrl } from './local-postgres-stack.mjs';

/**
 * @param {import('pg').PoolClient} client
 * @param {typeof LOCAL_STAGING_DEMO_IDS} ids
 */
export async function seedLocalStagingTenant(client, ids = LOCAL_STAGING_DEMO_IDS) {
  const existing = await client.query(`SELECT id FROM tenants WHERE id = $1`, [ids.tenantId]);
  if (existing.rows.length > 0) {
    return { seeded: false, tenantId: ids.tenantId };
  }

  await client.query(`INSERT INTO tenants (id, name) VALUES ($1, $2)`, [
    ids.tenantId,
    'Demo Organization',
  ]);
  await client.query(
    `INSERT INTO environments (id, tenant_id, name) VALUES ($1, $2, $3)`,
    [ids.environmentId, ids.tenantId, 'Production Validation'],
  );
  await client.query(
    `INSERT INTO users (id, tenant_id, email, name, role) VALUES ($1, $2, $3, $4, $5)`,
    [ids.adminUserId, ids.tenantId, 'admin@demo.astranull.local', 'Demo Admin', 'admin'],
  );
  await client.query(
    `INSERT INTO users (id, tenant_id, email, name, role) VALUES ($1, $2, $3, $4, $5)`,
    [ids.socUserId, ids.tenantId, 'soc@demo.astranull.local', 'Demo SOC', 'soc'],
  );
  await client.query(
    `INSERT INTO users (id, tenant_id, email, name, role) VALUES ($1, $2, $3, $4, $5)`,
    ['usr_soc2', ids.tenantId, 'soc2@demo.astranull.local', 'Demo SOC 2', 'soc'],
  );
  await client.query(
    `INSERT INTO target_groups (id, tenant_id, environment_id, name, description, expected_behavior_default)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [
      ids.targetGroupId,
      ids.tenantId,
      ids.environmentId,
      'Origin Protection Group',
      'Customer-declared origin targets for bypass validation.',
      'must_block_before_origin',
    ],
  );
  await client.query(
    `INSERT INTO targets (id, tenant_id, target_group_id, kind, value, expected_behavior)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [
      ids.targetId,
      ids.tenantId,
      ids.targetGroupId,
      'fqdn',
      'origin.demo.customer.example',
      'must_block_before_origin',
    ],
  );

  return { seeded: true, tenantId: ids.tenantId };
}

function resolveDatabaseUrl(env = process.env) {
  const explicit = String(env.ASTRANULL_DATABASE_URL ?? '').trim();
  if (explicit) return explicit;

  const host = String(env.ASTRANULL_PG_HOST ?? '127.0.0.1').trim();
  const port = Number(env.ASTRANULL_LOCAL_PG_PORT ?? 54329);
  return buildLocalPostgresDatabaseUrl({ host, port });
}

/**
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} [env]
 */
export async function runSeedLocalStagingTenant(env = process.env) {
  const databaseUrl = resolveDatabaseUrl(env);
  /** @type {import('pg').Pool | undefined} */
  let pool;
  try {
    pool = createPgPool({ ...env, ASTRANULL_DATABASE_URL: databaseUrl });
    const result = await withTenantContext(pool, LOCAL_STAGING_DEMO_IDS.tenantId, async (client) =>
      seedLocalStagingTenant(client),
    );
    return result;
  } finally {
    if (pool) await closePgPool(pool);
  }
}

async function main() {
  try {
    const result = await runSeedLocalStagingTenant(process.env);
    console.log(
      `seed-local-staging-tenant: ${result.seeded ? 'seeded' : 'already_present'} tenant=${result.tenantId}`,
    );
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`seed-local-staging-tenant: failed: ${message}`);
    process.exitCode = 1;
  }
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main();
}