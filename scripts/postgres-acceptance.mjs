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
import { createCoreCatalogRepository } from '../src/persistence/postgres/coreCatalogRepository.mjs';
import { createSupplyChainRiskRepository } from '../src/persistence/postgres/supplyChainRiskRepository.mjs';
import { createWafOrchestratorRepository } from '../src/persistence/postgres/wafOrchestratorRepository.mjs';
import { DELEGATION_STATUS } from '../src/persistence/postgres/wafOrchestratorServiceAdapters.mjs';
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

/** @type {readonly string[]} */
export const DELEGATION_OUTBOX_TABLES = Object.freeze([
  'waf_validation_plans',
  'waf_retest_requests',
]);

/** @type {readonly string[]} */
export const DELEGATION_OUTBOX_STATUS_MARKERS = Object.freeze([
  'pending_start',
  'starting',
  'delegated',
  'failed',
]);

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
    secondaryTargetId: `tgt_accept_${normalized}_2`,
    supplyChainRiskId: `scr_accept_${normalized}`,
    validationPlanId: `wvp_accept_${normalized}`,
  };
}

/**
 * @param {string} tenantId
 * @param {{ userId?: string, role?: string }} [overrides]
 */
export function buildAcceptanceCtx(tenantId, overrides = {}) {
  return {
    tenantId,
    userId: overrides.userId ?? 'usr_accept',
    role: overrides.role ?? 'admin',
    ...overrides,
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
 * @param {import('pg').Pool} pool
 */
export async function verifyWafDelegationOutboxCatalog(pool) {
  const result = await pool.query(
    `SELECT c.relname AS table_name, d.description
     FROM pg_class c
     JOIN pg_namespace n ON n.oid = c.relnamespace
     JOIN pg_attribute a ON a.attrelid = c.oid
       AND a.attname = 'delegated_jobs_json'
       AND NOT a.attisdropped
     LEFT JOIN pg_description d ON d.objoid = c.oid AND d.objsubid = a.attnum
     WHERE n.nspname = 'public'
       AND c.relname = ANY($1::text[])`,
    [DELEGATION_OUTBOX_TABLES],
  );
  const byTable = new Map(result.rows.map((row) => [row.table_name, row.description ?? '']));
  for (const table of DELEGATION_OUTBOX_TABLES) {
    const description = byTable.get(table) ?? '';
    if (!description) {
      throw new Error(
        `WAF delegation outbox catalog: missing column comment on ${table}.delegated_jobs_json.`,
      );
    }
    for (const marker of DELEGATION_OUTBOX_STATUS_MARKERS) {
      if (!description.includes(marker)) {
        throw new Error(
          `WAF delegation outbox catalog: ${table} comment missing status marker "${marker}".`,
        );
      }
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
    if (ids.validationPlanId) {
      await client.query(`DELETE FROM waf_validation_plans WHERE id = $1`, [ids.validationPlanId]);
    }
    if (ids.supplyChainRiskId) {
      await client.query(`DELETE FROM supply_chain_risks WHERE id = $1`, [ids.supplyChainRiskId]);
    }
    if (ids.secondaryTargetId) {
      await client.query(`DELETE FROM targets WHERE id = $1`, [ids.secondaryTargetId]);
    }
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
 * @param {{
 *   ids?: ReturnType<typeof buildAcceptanceTempIds>,
 *   now?: string,
 *   createCoreCatalogRepository?: typeof createCoreCatalogRepository,
 * }} [options]
 */
export async function verifyTargetGroupCrudLifecycle(pool, options = {}) {
  const createRepo = options.createCoreCatalogRepository ?? createCoreCatalogRepository;
  const ids = options.ids ?? buildAcceptanceTempIds('crud');
  const ctx = buildAcceptanceCtx(ids.tenantId);
  const now = options.now ?? new Date().toISOString();
  const repo = createRepo(pool);
  let seeded = false;

  try {
    await withTenantContext(pool, ids.tenantId, async (client) => {
      await seedTenantFixture(client, ids);
    });
    seeded = true;

    const patched = await repo.patchTargetGroup(ctx, ids.targetGroupId, {
      name: 'patched acceptance group',
    });
    if (!patched || patched.name !== 'patched acceptance group') {
      throw new Error('Target group CRUD: patchTargetGroup did not persist name change.');
    }

    const added = await repo.addTarget(
      ctx,
      ids.targetGroupId,
      { kind: 'fqdn', value: 'crud-secondary.example' },
      { id: ids.secondaryTargetId, now },
    );
    if (!added || added.id !== ids.secondaryTargetId) {
      throw new Error('Target group CRUD: addTarget did not persist secondary target.');
    }

    const patchedTarget = await repo.patchTarget(
      ctx,
      ids.targetGroupId,
      ids.secondaryTargetId,
      { value: 'crud-patched.example' },
    );
    if (!patchedTarget || patchedTarget.value !== 'crud-patched.example') {
      throw new Error('Target group CRUD: patchTarget did not persist value change.');
    }

    const deleted = await repo.deleteTarget(ctx, ids.targetGroupId, ids.secondaryTargetId);
    if (!deleted || deleted.deleted !== true) {
      throw new Error('Target group CRUD: deleteTarget did not remove secondary target.');
    }

    const archived = await repo.archiveTargetGroup(ctx, ids.targetGroupId, { now });
    if (!archived || archived.archived !== true) {
      throw new Error('Target group CRUD: archiveTargetGroup did not archive group.');
    }

    const afterArchive = await repo.getTargetGroup(ctx, ids.targetGroupId);
    if (afterArchive !== null) {
      throw new Error('Target group CRUD: archived group still visible via getTargetGroup.');
    }

    const listed = await repo.listTargetGroups(ctx);
    if (listed.some((group) => group.id === ids.targetGroupId)) {
      throw new Error('Target group CRUD: archived group still visible via listTargetGroups.');
    }
  } finally {
    if (seeded) {
      await withTenantContext(pool, ids.tenantId, async (client) => {
        await cleanupTenantFixture(client, ids);
      });
    }
  }
}

/**
 * @param {import('pg').Pool} pool
 * @param {{
 *   ids?: ReturnType<typeof buildAcceptanceTempIds>,
 *   now?: string,
 *   createSupplyChainRiskRepository?: typeof createSupplyChainRiskRepository,
 * }} [options]
 */
export async function verifySupplyChainPhaseAuthorization(pool, options = {}) {
  const createRepo = options.createSupplyChainRiskRepository ?? createSupplyChainRiskRepository;
  const ids = options.ids ?? buildAcceptanceTempIds('phase');
  const ctx = buildAcceptanceCtx(ids.tenantId);
  const now = options.now ?? new Date().toISOString();
  const repo = createRepo(pool);
  let seeded = false;

  const phaseAuthorization = {
    id: 'auth_accept_1',
    target_phase: 'AP2_manual_custody',
    authorization: {
      customer_approval_reference: 'cust-approval-accept',
      customer_signed_at: now,
      custody_ids: ['custody://accept-1'],
      manual_workflow_owner: 'dns-team',
    },
    approved_by_user_id: ctx.userId,
    approved_by_role: ctx.role,
    approved_at: now,
  };

  try {
    await withTenantContext(pool, ids.tenantId, async (client) => {
      await client.query(`INSERT INTO tenants (id, name) VALUES ($1, $2)`, [
        ids.tenantId,
        'postgres acceptance phase tenant',
      ]);
    });
    seeded = true;

    await repo.insertRisk(ctx, {
      id: ids.supplyChainRiskId,
      exposure_type: 'dangling_cname',
      hostname: 'acceptance-phase.example',
      evidence_summary: { data_source: 'acceptance_harness' },
      confidence: 0.9,
      severity: 'high',
      state: 'remediation_pending',
      phase: 'AP1_ticket_workflow',
      phase_authorizations: [],
      created_at: now,
      updated_at: now,
    });

    const updated = await repo.updateRiskPhase(ctx, ids.supplyChainRiskId, {
      phase: 'AP2_manual_custody',
      state: 'customer_custody',
      phase_authorizations: [phaseAuthorization],
      updated_at: now,
    });
    if (!updated || updated.phase !== 'AP2_manual_custody') {
      throw new Error('Supply chain phase authorization: phase transition not persisted.');
    }
    if (!Array.isArray(updated.phase_authorizations) || updated.phase_authorizations.length !== 1) {
      throw new Error('Supply chain phase authorization: authorization entry not persisted.');
    }
    if (updated.phase_authorizations[0].target_phase !== 'AP2_manual_custody') {
      throw new Error('Supply chain phase authorization: target_phase mismatch.');
    }

    const loaded = await repo.getRisk(ctx, ids.supplyChainRiskId);
    if (!loaded || loaded.phase_authorizations.length !== 1) {
      throw new Error(
        'Supply chain phase authorization: getRisk did not round-trip authorization metadata.',
      );
    }
  } finally {
    if (seeded) {
      await withTenantContext(pool, ids.tenantId, async (client) => {
        await cleanupTenantFixture(client, ids);
      });
    }
  }
}

/**
 * @param {import('pg').Pool} pool
 * @param {{
 *   ids?: ReturnType<typeof buildAcceptanceTempIds>,
 *   now?: string,
 *   lockToken?: string,
 *   createWafOrchestratorRepository?: typeof createWafOrchestratorRepository,
 * }} [options]
 */
export async function verifyWafDelegationOutboxPersistence(pool, options = {}) {
  const createRepo = options.createWafOrchestratorRepository ?? createWafOrchestratorRepository;
  const ids = options.ids ?? buildAcceptanceTempIds('outbox');
  const ctx = buildAcceptanceCtx(ids.tenantId);
  const now = options.now ?? new Date().toISOString();
  const lockToken = options.lockToken ?? 'lock_accept_outbox';
  const repo = createRepo(pool);
  let seeded = false;

  const delegatedJob = {
    status: DELEGATION_STATUS.PENDING_START,
    reservation_id: 'res_accept_1',
    scenario: 'marker',
    waf_asset_id: 'waf_accept_1',
    check_id: 'waf.marker_rule.safe',
  };

  try {
    await withTenantContext(pool, ids.tenantId, async (client) => {
      await seedTenantFixture(client, ids);
    });
    seeded = true;

    await repo.createValidationPlan(ctx, {
      id: ids.validationPlanId,
      target_group_id: ids.targetGroupId,
      mode: 'manual',
      scenarios: ['marker'],
      max_concurrent: 1,
      timeout_ms: 60_000,
      state: 'scheduled',
      delegated_jobs: [],
      created_at: now,
      updated_at: now,
    });

    const claimed = await repo.claimValidationPlanExecution(ctx, ids.validationPlanId, {
      lock_token: lockToken,
      lock_expires_at: new Date(Date.parse(now) + 120_000).toISOString(),
      now,
    });
    if (!claimed || claimed.id !== ids.validationPlanId) {
      throw new Error('WAF delegation outbox: claimValidationPlanExecution did not acquire lease.');
    }

    const staged = await repo.stageValidationPlanDelegation(ctx, ids.validationPlanId, lockToken, {
      delegated_jobs: [delegatedJob],
      updated_at: now,
    });
    if (!staged || !Array.isArray(staged.delegated_jobs) || staged.delegated_jobs.length !== 1) {
      throw new Error(
        'WAF delegation outbox: stageValidationPlanDelegation did not persist delegated_jobs.',
      );
    }
    if (staged.delegated_jobs[0].status !== DELEGATION_STATUS.PENDING_START) {
      throw new Error('WAF delegation outbox: staged job missing pending_start status.');
    }

    const loaded = await repo.getValidationPlan(ctx, ids.validationPlanId);
    if (
      !loaded?.delegated_jobs?.[0]
      || loaded.delegated_jobs[0].status !== DELEGATION_STATUS.PENDING_START
    ) {
      throw new Error(
        'WAF delegation outbox: getValidationPlan did not round-trip delegated_jobs_json.',
      );
    }
  } finally {
    if (seeded) {
      await withTenantContext(pool, ids.tenantId, async (client) => {
        await cleanupTenantFixture(client, ids);
      });
    }
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
 * @param {{
 *   migrationsDir?: string,
 *   verifyTargetGroupCrudLifecycle?: typeof verifyTargetGroupCrudLifecycle,
 *   verifySupplyChainPhaseAuthorization?: typeof verifySupplyChainPhaseAuthorization,
 *   verifyWafDelegationOutboxCatalog?: typeof verifyWafDelegationOutboxCatalog,
 *   verifyWafDelegationOutboxPersistence?: typeof verifyWafDelegationOutboxPersistence,
 * }} [options]
 */
export async function runAcceptanceChecks(pool, options = {}) {
  const checks = [];
  const migrationsDir = options.migrationsDir ?? MIGRATIONS_DIR;
  const verifyCrud = options.verifyTargetGroupCrudLifecycle ?? verifyTargetGroupCrudLifecycle;
  const verifyPhaseAuth =
    options.verifySupplyChainPhaseAuthorization ?? verifySupplyChainPhaseAuthorization;
  const verifyOutboxCatalog = options.verifyWafDelegationOutboxCatalog ?? verifyWafDelegationOutboxCatalog;
  const verifyOutboxPersistence =
    options.verifyWafDelegationOutboxPersistence ?? verifyWafDelegationOutboxPersistence;

  const files = listMigrationFiles(migrationsDir);
  const latest = getLatestMigrationVersion(files);
  const { results } = await runMigrations(pool, { migrationsDir, files });
  await assertLatestMigrationApplied(pool, latest);
  checks.push('migrations');

  await verifyForcedRlsOnTables(pool);
  checks.push('rls_catalog');

  await verifyCompositeForeignKeys(pool);
  checks.push('composite_fk');

  await verifyTenantIsolationAndCrossTenantReject(pool);
  checks.push('tenant_isolation');
  checks.push('cross_tenant_reject');

  await verifyCrud(pool, options);
  checks.push('target_group_crud');

  await verifyPhaseAuth(pool, options);
  checks.push('supply_chain_phase_authorization');

  await verifyOutboxCatalog(pool);
  checks.push('waf_delegation_outbox_catalog');

  await verifyOutboxPersistence(pool, options);
  checks.push('waf_delegation_outbox_persistence');

  return { latest, results, checks };
}

/**
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} env
 * @param {{
 *   createPgPool?: typeof createPgPool,
 *   closePgPool?: typeof closePgPool,
 *   runAcceptanceChecks?: typeof runAcceptanceChecks,
 * }} [options]
 * @returns {Promise<{ outcome: 'skip' | 'ok', message?: string, latest?: string, checks?: string[] }>}
 */
export async function runPostgresAcceptance(env, options = {}) {
  const decision = resolvePostgresAcceptanceDecision(env);
  if (decision.action === 'skip') {
    return { outcome: 'skip', message: decision.message };
  }
  if (decision.action === 'fail') {
    throw new Error(decision.message);
  }

  const createPoolFn = options.createPgPool ?? createPgPool;
  const closePoolFn = options.closePgPool ?? closePgPool;
  const runChecksFn = options.runAcceptanceChecks ?? runAcceptanceChecks;

  /** @type {import('pg').Pool | undefined} */
  let pool;
  try {
    pool = createPoolFn(env);
    const { latest, checks } = await runChecksFn(pool, options);
    return { outcome: 'ok', latest, checks };
  } finally {
    if (pool) {
      await closePoolFn(pool);
    }
  }
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

  try {
    const result = await runPostgresAcceptance(process.env);
    console.log('postgres-acceptance: ok');
    console.log(`  latest_version: ${result.latest}`);
    console.log(`  checks: ${result.checks?.join(', ')}`);
  } catch (err) {
    const message = redactAcceptanceErrorMessage(err);
    console.error(`postgres-acceptance: failed: ${message}`);
    process.exitCode = 1;
  }
}

const isMain =
  process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
  main();
}