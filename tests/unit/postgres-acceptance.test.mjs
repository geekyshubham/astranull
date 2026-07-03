import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { DELEGATION_STATUS } from '../../src/persistence/postgres/wafOrchestratorServiceAdapters.mjs';
import {
  DELEGATION_OUTBOX_STATUS_MARKERS,
  DELEGATION_OUTBOX_TABLES,
  acceptanceTenantsNeedingCleanup,
  buildAcceptanceCtx,
  buildAcceptanceTempIds,
  createAcceptanceTenantSeedState,
  redactAcceptanceErrorMessage,
  resolvePostgresAcceptanceDecision,
  runPostgresAcceptance,
  verifySupplyChainPhaseAuthorization,
  verifyTargetGroupCrudLifecycle,
  verifyWafDelegationOutboxCatalog,
  verifyWafDelegationOutboxPersistence,
} from '../../scripts/postgres-acceptance.mjs';

describe('postgres acceptance gating', () => {
  it('skips when acceptance flag is not set', () => {
    const decision = resolvePostgresAcceptanceDecision({});
    assert.equal(decision.action, 'skip');
    assert.match(decision.message ?? '', /skipped/i);
  });

  it('fails when required but acceptance flag is missing', () => {
    const decision = resolvePostgresAcceptanceDecision({
      ASTRANULL_REQUIRE_POSTGRES_ACCEPTANCE: '1',
    });
    assert.equal(decision.action, 'fail');
    assert.match(decision.message ?? '', /required/i);
  });

  it('fails when enabled without database URL', () => {
    const decision = resolvePostgresAcceptanceDecision({
      ASTRANULL_POSTGRES_ACCEPTANCE: '1',
    });
    assert.equal(decision.action, 'fail');
    assert.match(decision.message ?? '', /ASTRANULL_DATABASE_URL/i);
  });

  it('runs when enabled with database URL', () => {
    const decision = resolvePostgresAcceptanceDecision({
      ASTRANULL_POSTGRES_ACCEPTANCE: '1',
      ASTRANULL_DATABASE_URL: 'postgresql://localhost/astranull',
    });
    assert.equal(decision.action, 'run');
  });

  it('does not treat non-1 acceptance values as enabled', () => {
    const decision = resolvePostgresAcceptanceDecision({
      ASTRANULL_POSTGRES_ACCEPTANCE: 'true',
      ASTRANULL_DATABASE_URL: 'postgresql://localhost/astranull',
    });
    assert.equal(decision.action, 'skip');
  });
});

describe('postgres acceptance helpers', () => {
  it('redacts database URLs from error messages', () => {
    const redacted = redactAcceptanceErrorMessage(
      'connect failed: postgresql://user:secret@db.example:5432/astranull',
    );
    assert.doesNotMatch(redacted, /postgresql:\/\//);
    assert.match(redacted, /\[redacted-database-url\]/);
  });

  it('builds deterministic temporary ids from suffix', () => {
    assert.deepEqual(buildAcceptanceTempIds('staging42'), {
      tenantId: 'ten_accept_staging42',
      environmentId: 'env_accept_staging42',
      targetGroupId: 'tg_accept_staging42',
      targetId: 'tgt_accept_staging42',
      secondaryTargetId: 'tgt_accept_staging42_2',
      supplyChainRiskId: 'scr_accept_staging42',
      validationPlanId: 'wvp_accept_staging42',
    });
    assert.deepEqual(buildAcceptanceTempIds('  '), {
      tenantId: 'ten_accept_run',
      environmentId: 'env_accept_run',
      targetGroupId: 'tg_accept_run',
      targetId: 'tgt_accept_run',
      secondaryTargetId: 'tgt_accept_run_2',
      supplyChainRiskId: 'scr_accept_run',
      validationPlanId: 'wvp_accept_run',
    });
  });

  it('builds acceptance ctx with stable defaults', () => {
    assert.deepEqual(buildAcceptanceCtx('ten_demo'), {
      tenantId: 'ten_demo',
      userId: 'usr_accept',
      role: 'admin',
    });
    assert.deepEqual(buildAcceptanceCtx('ten_demo', { userId: 'usr_x', role: 'engineer' }), {
      tenantId: 'ten_demo',
      userId: 'usr_x',
      role: 'engineer',
    });
  });

  it('starts tenant seed state with no fixtures marked seeded', () => {
    assert.deepEqual(createAcceptanceTenantSeedState(), {
      tenantA: false,
      tenantB: false,
    });
    assert.deepEqual(acceptanceTenantsNeedingCleanup(createAcceptanceTenantSeedState()), []);
  });

  it('plans cleanup only for tenants that finished seeding', () => {
    const onlyA = { tenantA: true, tenantB: false };
    assert.deepEqual(acceptanceTenantsNeedingCleanup(onlyA), ['tenantA']);

    const both = { tenantA: true, tenantB: true };
    assert.deepEqual(acceptanceTenantsNeedingCleanup(both), ['tenantA', 'tenantB']);

    const onlyB = { tenantA: false, tenantB: true };
    assert.deepEqual(acceptanceTenantsNeedingCleanup(onlyB), ['tenantB']);
  });

  it('redacts database URLs from Error objects', () => {
    const err = new Error('pool failed: postgresql://user:secret@db.example:5432/astranull');
    const redacted = redactAcceptanceErrorMessage(err);
    assert.doesNotMatch(redacted, /postgresql:\/\//);
    assert.match(redacted, /\[redacted-database-url\]/);
  });
});

describe('postgres acceptance scenario helpers', () => {
  it('verifies target group CRUD lifecycle with injected repository', async () => {
    const ids = buildAcceptanceTempIds('crud_mock');
    const ctx = buildAcceptanceCtx(ids.tenantId);
    const now = '2026-07-03T12:00:00.000Z';
    const state = {
      seeded: false,
      cleaned: false,
      archived: false,
      targets: new Set([ids.targetId]),
      name: 'acceptance target group',
    };

    const repo = {
      async patchTargetGroup(callCtx, groupId, body) {
        assert.equal(callCtx.tenantId, ctx.tenantId);
        assert.equal(groupId, ids.targetGroupId);
        state.name = body.name;
        return { id: groupId, name: state.name };
      },
      async addTarget(callCtx, groupId, body, options = {}) {
        assert.equal(callCtx.tenantId, ctx.tenantId);
        state.targets.add(options.id);
        return { id: options.id, value: body.value };
      },
      async patchTarget(callCtx, groupId, targetId, body) {
        return { id: targetId, value: body.value };
      },
      async deleteTarget(callCtx, groupId, targetId) {
        state.targets.delete(targetId);
        return { deleted: true, id: targetId };
      },
      async archiveTargetGroup() {
        state.archived = true;
        return { archived: true, id: ids.targetGroupId };
      },
      async getTargetGroup() {
        return state.archived ? null : { id: ids.targetGroupId, targets: [] };
      },
      async listTargetGroups() {
        return state.archived ? [] : [{ id: ids.targetGroupId, name: state.name }];
      },
    };

    const pool = {
      async connect() {
        return {
          async query(text) {
            if (text.trim() === 'BEGIN') state.seeded = true;
            if (text.trim() === 'COMMIT' && state.seeded && !state.cleaned) state.cleaned = true;
            return { rows: [] };
          },
          release() {},
        };
      },
    };

    await verifyTargetGroupCrudLifecycle(pool, {
      ids,
      now,
      createCoreCatalogRepository: () => repo,
    });

    assert.equal(state.name, 'patched acceptance group');
    assert.equal(state.archived, true);
    assert.equal(state.cleaned, true);
    assert.ok(!state.targets.has(ids.secondaryTargetId));
  });

  it('verifies supply chain phase authorization with injected repository', async () => {
    const ids = buildAcceptanceTempIds('phase_mock');
    const ctx = buildAcceptanceCtx(ids.tenantId);
    const now = '2026-07-03T12:00:00.000Z';
    const store = {
      phase: 'AP1_ticket_workflow',
      phase_authorizations: [],
      cleaned: false,
    };

    const repo = {
      async insertRisk(callCtx, risk) {
        assert.equal(callCtx.tenantId, ctx.tenantId);
        store.phase = risk.phase;
        return risk;
      },
      async updateRiskPhase(callCtx, riskId, update) {
        assert.equal(callCtx.tenantId, ctx.tenantId);
        assert.equal(riskId, ids.supplyChainRiskId);
        store.phase = update.phase;
        store.phase_authorizations = update.phase_authorizations;
        return {
          id: riskId,
          phase: store.phase,
          phase_authorizations: store.phase_authorizations,
        };
      },
      async getRisk(callCtx, riskId) {
        assert.equal(callCtx.tenantId, ctx.tenantId);
        return {
          id: riskId,
          phase: store.phase,
          phase_authorizations: store.phase_authorizations,
        };
      },
    };

    const pool = {
      async connect() {
        return {
          async query(text) {
            if (text.trim() === 'COMMIT') store.cleaned = true;
            return { rows: [] };
          },
          release() {},
        };
      },
    };

    await verifySupplyChainPhaseAuthorization(pool, {
      ids,
      now,
      createSupplyChainRiskRepository: () => repo,
    });

    assert.equal(store.phase, 'AP2_manual_custody');
    assert.equal(store.phase_authorizations.length, 1);
    assert.equal(store.phase_authorizations[0].target_phase, 'AP2_manual_custody');
    assert.equal(store.cleaned, true);
  });

  it('verifies WAF delegation outbox catalog comments', async () => {
    const pool = {
      async query(_sql, params) {
        assert.deepEqual(params[0], DELEGATION_OUTBOX_TABLES);
        return {
          rows: DELEGATION_OUTBOX_TABLES.map((table) => ({
            table_name: table,
            description: DELEGATION_OUTBOX_STATUS_MARKERS.join(' '),
          })),
        };
      },
    };
    await verifyWafDelegationOutboxCatalog(pool);
  });

  it('rejects WAF delegation outbox catalog when status markers are missing', async () => {
    const pool = {
      async query() {
        return {
          rows: [{ table_name: 'waf_validation_plans', description: 'pending_start only' }],
        };
      },
    };
    await assert.rejects(
      () => verifyWafDelegationOutboxCatalog(pool),
      /missing status marker "starting"/,
    );
  });

  it('verifies WAF delegation outbox persistence with injected repository', async () => {
    const ids = buildAcceptanceTempIds('outbox_mock');
    const ctx = buildAcceptanceCtx(ids.tenantId);
    const now = '2026-07-03T12:00:00.000Z';
    const lockToken = 'lock_mock';
    const store = {
      delegated_jobs: [],
      cleaned: false,
    };

    const repo = {
      async createValidationPlan(callCtx, record) {
        assert.equal(callCtx.tenantId, ctx.tenantId);
        return record;
      },
      async claimValidationPlanExecution(callCtx, planId) {
        assert.equal(callCtx.tenantId, ctx.tenantId);
        assert.equal(planId, ids.validationPlanId);
        return { id: planId };
      },
      async stageValidationPlanDelegation(callCtx, planId, token, patch) {
        assert.equal(callCtx.tenantId, ctx.tenantId);
        assert.equal(planId, ids.validationPlanId);
        assert.equal(token, lockToken);
        store.delegated_jobs = patch.delegated_jobs;
        return { id: planId, delegated_jobs: store.delegated_jobs };
      },
      async getValidationPlan(callCtx, planId) {
        assert.equal(callCtx.tenantId, ctx.tenantId);
        return { id: planId, delegated_jobs: store.delegated_jobs };
      },
    };

    const pool = {
      async connect() {
        return {
          async query(text) {
            if (text.trim() === 'COMMIT') store.cleaned = true;
            return { rows: [] };
          },
          release() {},
        };
      },
    };

    await verifyWafDelegationOutboxPersistence(pool, {
      ids,
      now,
      lockToken,
      createWafOrchestratorRepository: () => repo,
    });

    assert.equal(store.delegated_jobs.length, 1);
    assert.equal(store.delegated_jobs[0].status, DELEGATION_STATUS.PENDING_START);
    assert.equal(store.cleaned, true);
  });
});

describe('postgres acceptance execution', () => {
  it('returns skip outcome when not enabled', async () => {
    const result = await runPostgresAcceptance({});
    assert.equal(result.outcome, 'skip');
    assert.match(result.message ?? '', /skipped/i);
  });

  it('runs injected acceptance checks and closes the pool', async () => {
    let closed = false;
    const result = await runPostgresAcceptance(
      {
        ASTRANULL_POSTGRES_ACCEPTANCE: '1',
        ASTRANULL_DATABASE_URL: 'postgresql://localhost/astranull',
      },
      {
        createPgPool: () => ({ id: 'pool-1' }),
        closePgPool: async () => {
          closed = true;
        },
        runAcceptanceChecks: async () => ({
          latest: '0013_waf_delegation_outbox',
          results: [],
          checks: ['migrations', 'target_group_crud'],
        }),
      },
    );
    assert.equal(result.outcome, 'ok');
    assert.equal(result.latest, '0013_waf_delegation_outbox');
    assert.deepEqual(result.checks, ['migrations', 'target_group_crud']);
    assert.equal(closed, true);
  });

  it('fails when required but not enabled via runPostgresAcceptance', async () => {
    await assert.rejects(
      () =>
        runPostgresAcceptance({
          ASTRANULL_REQUIRE_POSTGRES_ACCEPTANCE: '1',
        }),
      /required/i,
    );
  });
});