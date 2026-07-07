/**
 * Scale fixture for portal hydrator perf tests (docs/ux/17 §8, doc 16 §6).
 * Enable via ASTRANULL_PORTAL_SCALE=1 — always materializes the full 10k-group profile.
 */
import { computeHighScaleStatus } from '../../../src/lib/statePayload.mjs';
import { resetStoreForTests } from '../../../src/store.mjs';
import { withTenantContext } from '../../../src/persistence/postgres/tenantContext.mjs';
import { PORTAL_BASELINE_IDS, buildPortalBaselineStore } from '../portal-baseline/seed.mjs';

const PG_SEED_CHUNK = 500;

export const PORTAL_SCALE_PROFILE = Object.freeze({
  targetGroups: 10_000,
  findings: 100_000,
  targets: 5_000,
  agents: 500,
});

export const PORTAL_SCALE_FAST_PROFILE = Object.freeze({
  targetGroups: 200,
  findings: 2_000,
  targets: 500,
  agents: 50,
});

export function isPortalScaleEnabled(env = process.env) {
  return String(env.ASTRANULL_PORTAL_SCALE ?? '').trim() === '1';
}

export function isPortalScaleFast(env = process.env) {
  return String(env.ASTRANULL_PORTAL_SCALE_FAST ?? '').trim() === '1';
}

/**
 * @returns {{ ready: boolean, reason?: string, profile: typeof PORTAL_SCALE_PROFILE }}
 */
export function portalScaleStatus(env = process.env) {
  if (!isPortalScaleEnabled(env)) {
    return {
      ready: false,
      reason: 'Set ASTRANULL_PORTAL_SCALE=1 to materialize the scale fixture.',
      profile: PORTAL_SCALE_PROFILE,
    };
  }
  return { ready: true, profile: PORTAL_SCALE_PROFILE };
}

/**
 * @returns {{ tenantId: string, targetGroupId: string, targetId: string, findingId: string }}
 */
export function portalScaleIds() {
  return {
    tenantId: 'ten_portal_scale',
    targetGroupId: 'tg_scale_0',
    targetId: 'tgt_scale_0_0',
    findingId: 'fnd_scale_0',
  };
}

/**
 * Materialize scale dataset into the dev-json store for perf harness runs.
 */
export function seedPortalScale(env = process.env) {
  const status = portalScaleStatus(env);
  if (!status.ready) {
    throw new Error(status.reason);
  }

  const profile = status.profile;
  const ids = portalScaleIds();
  const baseline = buildPortalBaselineStore();
  const frozenAt = PORTAL_BASELINE_IDS.frozenAt;

  const targetGroups = [];
  const targets = [];
  const findings = [];
  const agents = [];
  const testRuns = [];

  for (let g = 0; g < profile.targetGroups; g += 1) {
    targetGroups.push({
      id: `tg_scale_${g}`,
      tenant_id: ids.tenantId,
      environment_id: PORTAL_BASELINE_IDS.environmentId,
      name: `scale-group-${g}`,
      criticality: 'medium',
      created_at: frozenAt,
    });
  }

  let targetCount = 0;
  for (let g = 0; g < profile.targetGroups && targetCount < profile.targets; g += 1) {
    const perGroup = Math.min(1, profile.targets - targetCount);
    for (let t = 0; t < perGroup; t += 1) {
      const targetId = `tgt_scale_${g}_${t}`;
      targets.push({
        id: targetId,
        tenant_id: ids.tenantId,
        target_group_id: `tg_scale_${g}`,
        kind: 'fqdn',
        value: `host-${g}-${t}.scale.test`,
        expected_behavior: 'cloud_baseline',
        created_at: frozenAt,
      });
      targetCount += 1;
    }
  }

  for (let f = 0; f < profile.findings; f += 1) {
    const groupIdx = f % profile.targetGroups;
    const targetIdx = targets[f % targets.length]?.id ?? ids.targetId;
    findings.push({
      id: `fnd_scale_${f}`,
      tenant_id: ids.tenantId,
      target_group_id: `tg_scale_${groupIdx}`,
      target_id: targetIdx,
      severity: 's3',
      title: `Scale finding ${f}`,
      state: f % 3 === 0 ? 'open' : 'closed',
      opened_at: frozenAt,
      owner_group: 'edge-sre',
      check_id: 'chk_l7_rate',
    });
  }

  for (let a = 0; a < profile.agents; a += 1) {
    agents.push({
      id: `agt_scale_${a}`,
      tenant_id: ids.tenantId,
      name: `scale-agent-${a}`,
      status: 'online',
      version: '1.0.0',
      last_heartbeat_at: frozenAt,
      capabilities: ['packet_metadata'],
    });
  }

  for (let r = 0; r < Math.min(500, profile.findings / 20); r += 1) {
    testRuns.push({
      id: `run_scale_${r}`,
      tenant_id: ids.tenantId,
      target_group_id: ids.targetGroupId,
      target_id: ids.targetId,
      state: 'finalized',
      verdict: 'pass',
      started_at: frozenAt,
      finalized_at: frozenAt,
    });
  }

  const openFindings = findings.filter((row) => String(row.state ?? row.status ?? 'open') === 'open').length;
  const recentRuns = testRuns.slice(-5).map((run) => ({
    id: run.id,
    target_group_id: run.target_group_id,
    target_id: run.target_id,
    verdict: run.verdict,
    started_at: run.started_at,
  }));
  const stateRollups = {
    [ids.tenantId]: {
      readiness: {
        score: 58,
        factors: [
          { key: 'coverage', label: 'Validation coverage', score: 18, detail: 'Scale fixture rollup.' },
          { key: 'agent_placement', label: 'Agent placement & health', score: 15, detail: 'Scale fixture rollup.' },
          { key: 'verdicts', label: 'Open findings impact', score: 10, detail: 'Scale fixture rollup.' },
          { key: 'evidence_freshness', label: 'Evidence freshness', score: 10, detail: 'Scale fixture rollup.' },
          { key: 'soc_readiness', label: 'SOC governance posture', score: 5, detail: 'Scale fixture rollup.' },
        ],
        updated_at: frozenAt,
      },
      target_groups: profile.targetGroups,
      agents_online: profile.agents,
      open_findings: openFindings,
      high_scale_requests: 0,
      high_scale_status: computeHighScaleStatus({
        highScaleWired: true,
        highScaleRequests: [],
        killSwitch: null,
        requestCount: 0,
      }),
      recent_runs: recentRuns,
    },
  };

  resetStoreForTests({
    ...baseline,
    tenants: [{ id: ids.tenantId, name: 'Portal Scale Tenant' }, ...baseline.tenants],
    targetGroups: [...targetGroups, ...baseline.targetGroups],
    targets: [...targets, ...baseline.targets],
    findings: [...findings, ...baseline.findings],
    agents: [...agents, ...baseline.agents],
    testRuns: [...testRuns, ...baseline.testRuns],
    wafCoverageSummaries: {
      [ids.tenantId]: {
        assets_total: 12,
        protected: 9,
        underprotected: 3,
        unknown: 0,
        coverage_pct: 75,
        by_vendor: { cloudflare: { assets: 7, protected: 6 } },
        connectors_active: 2,
        connectors_degraded: 0,
        connectors_disabled: 1,
        refreshed_at: frozenAt,
      },
    },
    stateRollups,
  });

  return { ids, profile };
}

/**
 * Resolve the Postgres perf profile (doc 16 §6: 10k groups / 100k findings).
 *
 * @param {{ fast?: boolean }} [options] Pass fast:true only for explicit local smoke runs.
 */
export function portalScalePostgresProfile(options = {}) {
  if (options.fast === true) return PORTAL_SCALE_FAST_PROFILE;
  return PORTAL_SCALE_PROFILE;
}

/**
 * @param {unknown[][]} rows
 * @param {number} width
 */
function chunkRows(rows, width) {
  const chunks = [];
  for (let i = 0; i < rows.length; i += width) {
    chunks.push(rows.slice(i, i + width));
  }
  return chunks;
}

/**
 * @param {import('pg').PoolClient} client
 * @param {string} table
 * @param {string[]} columns
 * @param {unknown[][]} rows
 */
async function insertRows(client, table, columns, rows) {
  if (!rows.length) return;
  const width = columns.length;
  for (const chunk of chunkRows(rows, PG_SEED_CHUNK)) {
    const values = [];
    const params = [];
    let param = 1;
    for (const row of chunk) {
      const placeholders = row.map(() => `$${param++}`);
      values.push(`(${placeholders.join(', ')})`);
      params.push(...row);
    }
    await client.query(
      `INSERT INTO ${table} (${columns.join(', ')}) VALUES ${values.join(', ')}`,
      params,
    );
  }
}

/**
 * Seed tenant-scoped scale rows into Postgres for hydrator perf / EXPLAIN tests (doc 16 §6).
 *
 * @param {import('pg').Pool} pool
 * @param {{ profile?: typeof PORTAL_SCALE_FAST_PROFILE, fast?: boolean }} [options]
 */
export async function seedPortalScalePostgres(pool, options = {}) {
  const profile = options.profile ?? portalScalePostgresProfile(options);
  const ids = portalScaleIds();
  const frozenAt = PORTAL_BASELINE_IDS.frozenAt;

  await withTenantContext(pool, ids.tenantId, async (client) => {
    const openFindings = Math.floor(profile.findings / 3);
    const dashboardRollup = {
      readiness: {
        score: 58,
        factors: [
          { key: 'coverage', label: 'Validation coverage', score: 18, detail: 'Scale fixture rollup.' },
          { key: 'agent_placement', label: 'Agent placement & health', score: 15, detail: 'Scale fixture rollup.' },
          { key: 'verdicts', label: 'Open findings impact', score: 10, detail: 'Scale fixture rollup.' },
          { key: 'evidence_freshness', label: 'Evidence freshness', score: 10, detail: 'Scale fixture rollup.' },
          { key: 'soc_readiness', label: 'SOC governance posture', score: 5, detail: 'Scale fixture rollup.' },
        ],
        updated_at: frozenAt,
      },
      target_groups: profile.targetGroups,
      agents_online: profile.agents,
      open_findings: openFindings,
      high_scale_requests: 0,
      high_scale_status: computeHighScaleStatus({
        highScaleWired: true,
        highScaleRequests: [],
        killSwitch: null,
        requestCount: 0,
      }),
      recent_runs: [],
    };
    await client.query(
      `INSERT INTO tenants (id, name, dashboard_rollup) VALUES ($1, $2, $3::jsonb)`,
      [ids.tenantId, 'Portal Scale Tenant', JSON.stringify(dashboardRollup)],
    );
    await client.query(
      `INSERT INTO environments (id, tenant_id, name) VALUES ($1, $2, $3)`,
      [PORTAL_BASELINE_IDS.environmentId, ids.tenantId, 'scale environment'],
    );

    const targetGroupRows = [];
    for (let g = 0; g < profile.targetGroups; g += 1) {
      targetGroupRows.push([
        `tg_scale_${g}`,
        ids.tenantId,
        PORTAL_BASELINE_IDS.environmentId,
        `scale-group-${g}`,
        frozenAt,
      ]);
    }
    await insertRows(
      client,
      'target_groups',
      ['id', 'tenant_id', 'environment_id', 'name', 'created_at'],
      targetGroupRows,
    );

    const targetRows = [];
    let targetCount = 0;
    for (let g = 0; g < profile.targetGroups && targetCount < profile.targets; g += 1) {
      const perGroup = Math.min(1, profile.targets - targetCount);
      for (let t = 0; t < perGroup; t += 1) {
        targetRows.push([
          `tgt_scale_${g}_${t}`,
          ids.tenantId,
          `tg_scale_${g}`,
          'fqdn',
          `host-${g}-${t}.scale.test`,
          frozenAt,
        ]);
        targetCount += 1;
      }
    }
    await insertRows(
      client,
      'targets',
      ['id', 'tenant_id', 'target_group_id', 'kind', 'value', 'created_at'],
      targetRows,
    );

    const findingRows = [];
    for (let f = 0; f < profile.findings; f += 1) {
      const groupIdx = f % profile.targetGroups;
      const targetId = targetRows[f % targetRows.length]?.[0] ?? ids.targetId;
      findingRows.push([
        `fnd_scale_${f}`,
        ids.tenantId,
        `tg_scale_${groupIdx}`,
        targetId,
        `chk_scale_${f}`,
        `Scale finding ${f}`,
        's3',
        f % 3 === 0 ? 'open' : 'closed',
        frozenAt,
      ]);
    }
    await insertRows(
      client,
      'findings',
      [
        'id',
        'tenant_id',
        'target_group_id',
        'target_id',
        'check_id',
        'title',
        'severity',
        'status',
        'created_at',
      ],
      findingRows,
    );

    const runCount = Math.min(500, Math.floor(profile.findings / 20));
    const testRunRows = [];
    for (let r = 0; r < runCount; r += 1) {
      testRunRows.push([
        `run_scale_${r}`,
        ids.tenantId,
        ids.targetGroupId,
        ids.targetId,
        'chk_l7_rate',
        'finalized',
        frozenAt,
        frozenAt,
      ]);
    }
    await insertRows(
      client,
      'test_runs',
      [
        'id',
        'tenant_id',
        'target_group_id',
        'target_id',
        'check_id',
        'status',
        'started_at',
        'created_at',
      ],
      testRunRows,
    );

    await client.query('ANALYZE target_groups');
    await client.query('ANALYZE targets');
    await client.query('ANALYZE findings');
    await client.query('ANALYZE test_runs');
  });

  return { ids, profile };
}