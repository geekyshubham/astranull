/**
 * Portal hydrator performance budgets (docs/ux/17 §8, doc 16 §6).
 */
import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { createAgentControlRepository } from '../../src/persistence/postgres/agentControlRepository.mjs';
import { createCoreCatalogRepository } from '../../src/persistence/postgres/coreCatalogRepository.mjs';
import { createHighScaleRepository } from '../../src/persistence/postgres/highScaleRepository.mjs';
import { createKillSwitchRepository } from '../../src/persistence/postgres/killSwitchRepository.mjs';
import { createPortalRevampRepository } from '../../src/persistence/postgres/portalRevampRepository.mjs';
import { createPostgresStateServices } from '../../src/persistence/postgres/stateServiceAdapters.mjs';
import { createPostgresCatalogServices } from '../../src/persistence/postgres/serviceAdapters.mjs';
import { createValidationEvidenceRepository } from '../../src/persistence/postgres/validationEvidenceRepository.mjs';
import { createPostgresPortalRevampServices } from '../../src/persistence/postgres/portalRevampServiceAdapters.mjs';
import { withTenantContext } from '../../src/persistence/postgres/tenantContext.mjs';
import * as state from '../../src/services/state.mjs';
import * as targetGroups from '../../src/services/targetGroups.mjs';
import * as targetDetail from '../../src/services/targetDetail.mjs';
import * as findings from '../../src/services/findings.mjs';
import * as wafPosture from '../../src/services/wafPosture.mjs';
import * as highScale from '../../src/services/highScale.mjs';

import {
  resolvePostgresHarnessAvailability,
  withEphemeralPostgres,
} from '../helpers/pg-harness.mjs';
import {
  isPortalScaleEnabled,
  PORTAL_SCALE_PROFILE,
  portalScaleIds,
  portalScalePostgresProfile,
  portalScaleStatus,
  seedPortalScale,
  seedPortalScalePostgres,
} from '../fixtures/portal-scale/seed.mjs';

const ITERATIONS = Number(process.env.ASTRANULL_PORTAL_PERF_ITERATIONS ?? 40);
const WARMUP = 5;

const PERF_BUDGETS = [
  { id: 'FT-PERF-01', key: 'state', budgetMs: 200 },
  { id: 'FT-PERF-02', key: 'targetGroup', budgetMs: 180 },
  { id: 'FT-PERF-03', key: 'targetDetail', budgetMs: 250 },
  { id: 'FT-PERF-04', key: 'findingEvidence', budgetMs: 120 },
  { id: 'FT-PERF-05', key: 'wafSummary', budgetMs: 40 },
  { id: 'FT-PERF-06', key: 'highScaleList', budgetMs: 150 },
  { id: 'FT-PERF-07', key: 'findingsList', budgetMs: 200 },
];

function p95(samples) {
  const sorted = [...samples].sort((a, b) => a - b);
  const idx = Math.ceil(sorted.length * 0.95) - 1;
  return sorted[Math.max(0, idx)];
}

/** Indexes from migration 0032_targets_indexes_for_hydrator.sql */
const HYDRATOR_INDEXES = Object.freeze({
  targetsByGroup: 'targets_by_group_kind',
  targetsByTenant: 'targets_by_tenant',
  findingsByTarget: 'findings_by_target',
  testRunsByTarget: 'test_runs_by_target',
});

const PG_PERF_BUDGETS = Object.freeze([
  { id: 'FT-PERF-PG-01', method: 'getState', arg: null, budgetMs: 200 },
  { id: 'FT-PERF-PG-02', method: 'getTargetGroup', arg: 'targetGroupId', budgetMs: 180 },
  { id: 'FT-PERF-PG-03', method: 'getTargetDetail', arg: 'targetId', budgetMs: 250 },
]);

/**
 * @param {string} plan
 * @param {string} indexName
 * @param {string} label
 */
function assertPlanUsesIndex(plan, indexName, label) {
  assert.ok(
    plan.includes(indexName),
    `${label}: expected index "${indexName}" in plan:\n${plan}`,
  );
  assert.ok(
    !/Seq Scan on (?:targets|findings|test_runs)\b/.test(plan),
    `${label}: sequential scan on hot hydrator table:\n${plan}`,
  );
}

/**
 * @param {import('pg').PoolClient} client
 * @param {string} sql
 * @param {unknown[]} params
 */
async function explainHydratorQuery(client, sql, params) {
  await client.query('SET LOCAL enable_seqscan = off');
  const { rows } = await client.query(`EXPLAIN (FORMAT TEXT) ${sql}`, params);
  return rows.map((row) => row['QUERY PLAN']).join('\n');
}

/**
 * @param {import('pg').Pool} pool
 */
function buildPostgresHydratorServices(pool) {
  const repositories = {
    coreCatalog: createCoreCatalogRepository(pool),
    agentControl: createAgentControlRepository(pool),
    validationEvidence: createValidationEvidenceRepository(pool),
    highScale: createHighScaleRepository(pool),
    killSwitch: createKillSwitchRepository(pool),
  };
  const portalRevamp = createPortalRevampRepository(pool);
  const catalogServices = createPostgresCatalogServices(repositories);
  const portalServices = createPostgresPortalRevampServices({ repositories: { portalRevamp } });
  const stateServices = createPostgresStateServices(repositories);
  return {
    getState: stateServices.getState.bind(stateServices),
    getTargetGroup: catalogServices.targetGroups.getTargetGroup.bind(catalogServices.targetGroups),
    getTargetDetail: portalServices.targetDetail.getTargetDetail.bind(portalServices.targetDetail),
  };
}

const ctx = { tenantId: portalScaleIds().tenantId, userId: 'usr_owner', role: 'owner' };
let baseUrl;
let server;
let scaleIds;

const runners = {
  async state() {
    return state.getState(ctx);
  },
  async targetGroup() {
    return targetGroups.getTargetGroup(ctx, scaleIds.targetGroupId);
  },
  async targetDetail() {
    return targetDetail.getTargetDetail(ctx, scaleIds.targetId);
  },
  async findingEvidence() {
    return findings.getEvidenceBundle(ctx, scaleIds.findingId);
  },
  async wafSummary() {
    return wafPosture.getCoverageSummary(ctx);
  },
  async highScaleList() {
    return highScale.listHighScaleRequests(ctx, { scope: 'my-tenant' });
  },
  async findingsList() {
    return findings.listFindings(ctx, { limit: 50, offset: 0 });
  },
};

before(() => {
  const status = portalScaleStatus();
  if (!status.ready) return;

  const seeded = seedPortalScale();
  scaleIds = seeded.ids;

  server = createServer({
    services: {
      state,
      targetGroups,
      targetDetail,
      findings: {
        listFindings: findings.listFindings,
        getFinding: findings.getFinding,
        patchFinding: findings.patchFinding,
        getEvidenceBundle: findings.getEvidenceBundle,
      },
      wafPosture,
      highScale,
    },
  });
  server.listen(0);
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(() => {
  if (server) server.close();
});

describe('portal hydrator performance (FT-PERF-01..07)', () => {
  const scaleStatus = portalScaleStatus();

  for (const spec of PERF_BUDGETS) {
    it(
      `${spec.id} ${spec.key} p95 ≤ ${spec.budgetMs} ms`,
      { skip: scaleStatus.ready ? false : scaleStatus.reason },
      async () => {
        const run = runners[spec.key];
        assert.equal(typeof run, 'function');

        for (let i = 0; i < WARMUP; i += 1) {
          await run();
        }

        const samples = [];
        for (let i = 0; i < ITERATIONS; i += 1) {
          const start = performance.now();
          await run();
          samples.push(performance.now() - start);
        }

        const measured = p95(samples);
        console.log(`${spec.id} measured p95 ${measured.toFixed(2)}ms (budget ${spec.budgetMs}ms)`);
        assert.ok(
          measured <= spec.budgetMs,
          `${spec.id} p95 ${measured.toFixed(2)}ms exceeds ${spec.budgetMs}ms budget`,
        );
      },
    );
  }

  it('documents skip gate when scale fixture is unavailable', () => {
    const status = portalScaleStatus();
    if (!status.ready) {
      console.log(`portal-hydrator-perf: skipped — ${status.reason}`);
      assert.ok(status.reason);
      return;
    }
    assert.equal(status.profile.targetGroups, PORTAL_SCALE_PROFILE.targetGroups);
    assert.equal(status.profile.findings, PORTAL_SCALE_PROFILE.findings);
  });
});

const describePortalScalePostgres = isPortalScaleEnabled() ? describe : describe.skip;

describePortalScalePostgres('portal hydrator performance — postgres (doc 16 §6)', () => {
  const pgIds = portalScaleIds();
  const pgCtx = { tenantId: pgIds.tenantId, userId: 'usr_owner', role: 'owner' };

  function activePgProfile() {
    return portalScalePostgresProfile();
  }

  it('documents Postgres scale profile per doc 16 §6', () => {
    const pgProfile = activePgProfile();
    assert.equal(pgProfile.targetGroups, PORTAL_SCALE_PROFILE.targetGroups);
    assert.equal(pgProfile.findings, PORTAL_SCALE_PROFILE.findings);
    assert.equal(pgProfile.targets, PORTAL_SCALE_PROFILE.targets);
    console.log(
      `portal-hydrator-perf postgres: ${pgProfile.targetGroups} groups / `
      + `${pgProfile.findings} findings / ${pgProfile.targets} targets / ${pgProfile.agents} agents`,
    );
  });

  for (const spec of PG_PERF_BUDGETS) {
    it(`${spec.id} postgres ${spec.method} p95 ≤ ${spec.budgetMs} ms`, async (t) => {
      const availability = await resolvePostgresHarnessAvailability(process.env);
      if (!availability.available) {
        t.skip(availability.reason);
        return;
      }

      await withEphemeralPostgres(async (pool) => {
        const pgProfile = activePgProfile();
        await seedPortalScalePostgres(pool, { profile: pgProfile });
        const services = buildPostgresHydratorServices(pool);
        const run = services[spec.method];
        assert.equal(typeof run, 'function');
        const invoke = spec.arg
          ? () => run(pgCtx, pgIds[spec.arg])
          : () => run(pgCtx);

        for (let i = 0; i < WARMUP; i += 1) {
          const result = await invoke();
          assert.ok(result && !result.error, `warmup ${spec.method} failed: ${result?.error ?? 'null'}`);
        }

        const samples = [];
        for (let i = 0; i < ITERATIONS; i += 1) {
          const start = performance.now();
          const result = await invoke();
          samples.push(performance.now() - start);
          assert.ok(result && !result.error, `${spec.method} failed: ${result?.error ?? 'null'}`);
        }

        const measured = p95(samples);
        console.log(
          `${spec.id} postgres measured p95 ${measured.toFixed(2)}ms (budget ${spec.budgetMs}ms)`,
        );
        assert.ok(
          measured <= spec.budgetMs,
          `${spec.id} postgres p95 ${measured.toFixed(2)}ms exceeds ${spec.budgetMs}ms budget`,
        );
      });
    });
  }

  it('FT-PERF-PG-04 EXPLAIN hydrator queries use 0032 indexes', async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (!availability.available) {
      t.skip(availability.reason);
      return;
    }

    await withEphemeralPostgres(async (pool) => {
      const pgProfile = activePgProfile();
      await seedPortalScalePostgres(pool, { profile: pgProfile });

      await withTenantContext(pool, pgIds.tenantId, async (client) => {
        const targetsByGroupPlan = await explainHydratorQuery(
          client,
          `SELECT id, tenant_id, target_group_id, kind, value, expected_behavior, metadata_json, created_at
           FROM targets
           WHERE target_group_id = $1 AND tenant_id = $2
           ORDER BY created_at`,
          [pgIds.targetGroupId, pgIds.tenantId],
        );
        assertPlanUsesIndex(
          targetsByGroupPlan,
          HYDRATOR_INDEXES.targetsByGroup,
          'getTargetGroup targets list',
        );

        const targetDetailPlan = await explainHydratorQuery(
          client,
          `SELECT * FROM targets WHERE tenant_id = $1 AND id = $2`,
          [pgIds.tenantId, pgIds.targetId],
        );
        assert.ok(
          targetDetailPlan.includes('Index') || targetDetailPlan.includes('targets_pkey'),
          `getTargetDetail target lookup should use an index:\n${targetDetailPlan}`,
        );

        const findingsPlan = await explainHydratorQuery(
          client,
          `SELECT id, severity, title, status, created_at
           FROM findings WHERE tenant_id = $1 AND target_id = $2
           ORDER BY created_at DESC`,
          [pgIds.tenantId, pgIds.targetId],
        );
        assertPlanUsesIndex(
          findingsPlan,
          HYDRATOR_INDEXES.findingsByTarget,
          'getTargetDetail findings list',
        );

        const runsPlan = await explainHydratorQuery(
          client,
          `SELECT id, check_id, status, started_at, created_at
           FROM test_runs WHERE tenant_id = $1 AND target_id = $2
           ORDER BY COALESCE(started_at, created_at) DESC LIMIT $3`,
          [pgIds.tenantId, pgIds.targetId, 5],
        );
        assertPlanUsesIndex(
          runsPlan,
          HYDRATOR_INDEXES.testRunsByTarget,
          'getTargetDetail recent runs',
        );
      });
    });
  });

  it('documents skip gate when Postgres harness is unavailable', async (t) => {
    const availability = await resolvePostgresHarnessAvailability(process.env);
    if (availability.available) {
      assert.ok(availability.env?.ASTRANULL_DATABASE_URL);
      return;
    }
    console.log(`portal-hydrator-perf postgres: skipped — ${availability.reason}`);
    assert.ok(availability.reason);
    t.skip(availability.reason);
  });
});