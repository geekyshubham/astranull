#!/usr/bin/env node
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { closePgPool, createPgPool } from '../src/persistence/postgres/pool.mjs';
import {
  assertLatestMigrationApplied,
  getLatestMigrationVersion,
  listMigrationFiles,
  runMigrations,
} from '../src/persistence/postgres/migrations.mjs';
import { withTenantContext } from '../src/persistence/postgres/tenantContext.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '..');
const MIGRATIONS_DIR = path.join(ROOT, 'db', 'migrations');

const RLS_TABLES = ['environments', 'target_groups', 'targets'];
const COMPOSITE_FK_NAMES = [
  'fk_target_groups_environment_tenant',
  'fk_targets_target_group_tenant',
];

const PG_URL_RE = /postgres(?:ql)?:\/\/[^\s'"]+/gi;

/**
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} env
 * @returns {{ action: 'skip' | 'run' | 'fail', message?: string }}
 */
export function resolvePostgresAcceptanceDecision(env) {
  const enabled = env.ASTRANULL_POSTGRES_ACCEPTANCE === '1';
  const required = env.ASTRANULL_REQUIRE_POSTGRES_ACCEPTANCE === '1';

  if (!enabled) {
    if (required) {
      return {
        action: 'fail',
        message:
          'postgres-acceptance: required (ASTRANULL_REQUIRE_POSTGRES_ACCEPTANCE=1) but not enabled; set ASTRANULL_POSTGRES_ACCEPTANCE=1.',
      };
    }
    return {
      action: 'skip',
      message:
        'postgres-acceptance: skipped (set ASTRANULL_POSTGRES_ACCEPTANCE=1 and ASTRANULL_DATABASE_URL to run staging evidence).',
    };
  }

  const databaseUrl = String(env.ASTRANULL_DATABASE_URL ?? '').trim();
  if (!databaseUrl) {
    return {
      action: 'fail',
      message:
        'postgres-acceptance: ASTRANULL_POSTGRES_ACCEPTANCE=1 requires ASTRANULL_DATABASE_URL.',
    };
  }

  return { action: 'run' };
}

/**
 * @param {unknown} message
 */
export function redactAcceptanceErrorMessage(message) {
  let text = message instanceof Error ? message.message : String(message ?? '');
  text = text.replace(PG_URL_RE, '[redacted-database-url]');
  const url = String(process.env.ASTRANULL_DATABASE_URL ?? '').trim();
  if (url && text.includes(url)) {
    text = text.split(url).join('[redacted-database-url]');
  }
  return text;
}

/**
 * @param {string} suffix
 */
export function buildAcceptanceTempIds(suffix) {
  const normalized = String(suffix ?? '').trim() || 'run';
  return {
    tenantId: `ten_accept_${normalized}`,
    environmentId: `env_accept_${normalized}`,
    targetGroupId: `tg_accept_${normalized}`,
    targetId: `tgt_accept_${normalized}`,
  };
}

/** @returns {{ tenantA: boolean, tenantB: boolean }} */
export function createAcceptanceTenantSeedState() {
  return { tenantA: false, tenantB: false };
}

/**
 * @param {{ tenantA: boolean, tenantB: boolean }} seedState
 * @returns {('tenantA' | 'tenantB')[]}
 */
export function acceptanceTenantsNeedingCleanup(seedState) {
  const tenants = [];
  if (seedState.tenantA) {
    tenants.push('tenantA');
  }
  if (seedState.tenantB) {
    tenants.push('tenantB');
  }
  return tenants;
}

/**
 * @param {import('pg').Pool} pool
 */
async function verifyForcedRlsOnTables(pool) {
  const result = await pool.query(
    `SELECT c.relname AS table_name,
            c.relrowsecurity AS row_security,
            c.relforcerowsecurity AS force_row_security
     FROM pg_class c
     JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public'
       AND c.relname = ANY($1::text[])`,
    [RLS_TABLES],
  );
  const byName = new Map(result.rows.map((row) => [row.table_name, row]));
  for (const table of RLS_TABLES) {
    const row = byName.get(table);
    if (!row) {
      throw new Error(`RLS catalog check: table "${table}" not found.`);
    }
    if (!row.row_security || !row.force_row_security) {
      throw new Error(
        `RLS catalog check: "${table}" must have relrowsecurity and relforcerowsecurity enabled.`,
      );
    }
  }
}

/**
 * @param {import('pg').Pool} pool
 */
async function verifyCompositeForeignKeys(pool) {
  const result = await pool.query(
    `SELECT conname
     FROM pg_constraint
     WHERE conname = ANY($1::text[])`,
    [COMPOSITE_FK_NAMES],
  );
  const found = new Set(result.rows.map((row) => row.conname));
  for (const name of COMPOSITE_FK_NAMES) {
    if (!found.has(name)) {
      throw new Error(`Composite FK check: constraint "${name}" not found.`);
    }
  }
}

/**
 * @param {import('pg').PoolClient} client
 * @param {ReturnType<typeof buildAcceptanceTempIds>} ids
 */
async function seedTenantFixture(client, ids) {
  await client.query(`INSERT INTO tenants (id, name) VALUES ($1, $2)`, [
    ids.tenantId,
    'postgres acceptance tenant',
  ]);
  await client.query(
    `INSERT INTO environments (id, tenant_id, name) VALUES ($1, $2, $3)`,
    [ids.environmentId, ids.tenantId, 'acceptance environment'],
  );
  await client.query(
    `INSERT INTO target_groups (id, tenant_id, environment_id, name) VALUES ($1, $2, $3, $4)`,
    [ids.targetGroupId, ids.tenantId, ids.environmentId, 'acceptance target group'],
  );
  await client.query(
    `INSERT INTO targets (id, tenant_id, target_group_id, kind, value) VALUES ($1, $2, $3, $4, $5)`,
    [ids.targetId, ids.tenantId, ids.targetGroupId, 'fqdn', 'acceptance.example'],
  );
}

/**
 * @param {import('pg').PoolClient} client
 * @param {ReturnType<typeof buildAcceptanceTempIds>} ids
 */
async function cleanupTenantFixture(client, ids) {
  try {
    await client.query(`DELETE FROM targets WHERE id = $1`, [ids.targetId]);
    await client.query(`DELETE FROM target_groups WHERE id = $1`, [ids.targetGroupId]);
    await client.query(`DELETE FROM environments WHERE id = $1`, [ids.environmentId]);
    await client.query(`DELETE FROM tenants WHERE id = $1`, [ids.tenantId]);
  } catch {
    // best-effort metadata cleanup
  }
}

/**
 * @param {import('pg').Pool} pool
 */
async function verifyTenantIsolationAndCrossTenantReject(pool) {
  const tenantA = buildAcceptanceTempIds('a');
  const tenantB = buildAcceptanceTempIds('b');
  const seedState = createAcceptanceTenantSeedState();

  try {
    await withTenantContext(pool, tenantA.tenantId, async (client) => {
      await seedTenantFixture(client, tenantA);
    });
    seedState.tenantA = true;

    await withTenantContext(pool, tenantB.tenantId, async (client) => {
      await seedTenantFixture(client, tenantB);
    });
    seedState.tenantB = true;

    await withTenantContext(pool, tenantA.tenantId, async (client) => {
      const own = await client.query(`SELECT id FROM targets WHERE id = $1`, [tenantA.targetId]);
      if (own.rows.length !== 1) {
        throw new Error('Tenant isolation: tenant A cannot read its own target row.');
      }
      const other = await client.query(`SELECT id FROM targets WHERE id = $1`, [tenantB.targetId]);
      if (other.rows.length !== 0) {
        throw new Error('Tenant isolation: tenant A can read tenant B target row.');
      }
    });

    await withTenantContext(pool, tenantB.tenantId, async (client) => {
      const own = await client.query(`SELECT id FROM targets WHERE id = $1`, [tenantB.targetId]);
      if (own.rows.length !== 1) {
        throw new Error('Tenant isolation: tenant B cannot read its own target row.');
      }
      const other = await client.query(`SELECT id FROM targets WHERE id = $1`, [tenantA.targetId]);
      if (other.rows.length !== 0) {
        throw new Error('Tenant isolation: tenant B can read tenant A target row.');
      }
    });

    let crossTenantRejected = false;
    try {
      await withTenantContext(pool, tenantA.tenantId, async (client) => {
        await client.query(
          `INSERT INTO targets (id, tenant_id, target_group_id, kind, value)
           VALUES ($1, $2, $3, $4, $5)`,
          [
            `${tenantA.targetId}_cross`,
            tenantA.tenantId,
            tenantB.targetGroupId,
            'fqdn',
            'cross-tenant.example',
          ],
        );
      });
    } catch {
      crossTenantRejected = true;
    }
    if (!crossTenantRejected) {
      throw new Error(
        'Cross-tenant check: insert with foreign target_group_id was not rejected by composite FK or RLS.',
      );
    }
  } finally {
    for (const key of acceptanceTenantsNeedingCleanup(seedState)) {
      const ids = key === 'tenantA' ? tenantA : tenantB;
      const tenantId = ids.tenantId;
      await withTenantContext(pool, tenantId, async (client) => {
        await cleanupTenantFixture(client, ids);
      });
    }
  }
}

/**
 * @param {import('pg').Pool} pool
 */
async function runAcceptanceChecks(pool) {
  const checks = [];

  const files = listMigrationFiles(MIGRATIONS_DIR);
  const latest = getLatestMigrationVersion(files);
  const { results } = await runMigrations(pool, { migrationsDir: MIGRATIONS_DIR, files });
  await assertLatestMigrationApplied(pool, latest);
  checks.push('migrations');

  await verifyForcedRlsOnTables(pool);
  checks.push('rls_catalog');

  await verifyCompositeForeignKeys(pool);
  checks.push('composite_fk');

  await verifyTenantIsolationAndCrossTenantReject(pool);
  checks.push('tenant_isolation');
  checks.push('cross_tenant_reject');

  return { latest, results, checks };
}

async function main() {
  const decision = resolvePostgresAcceptanceDecision(process.env);
  if (decision.action === 'skip') {
    console.log(decision.message);
    return;
  }
  if (decision.action === 'fail') {
    console.error(decision.message);
    process.exitCode = 1;
    return;
  }

  /** @type {import('pg').Pool | undefined} */
  let pool;
  try {
    pool = createPgPool(process.env);
    const { latest, checks } = await runAcceptanceChecks(pool);
    console.log('postgres-acceptance: ok');
    console.log(`  latest_version: ${latest}`);
    console.log(`  checks: ${checks.join(', ')}`);
  } catch (err) {
    const message = redactAcceptanceErrorMessage(err);
    console.error(`postgres-acceptance: failed: ${message}`);
    process.exitCode = 1;
  } finally {
    if (pool) {
      await closePgPool(pool);
    }
  }
}

const isMain =
  process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
  main();
}