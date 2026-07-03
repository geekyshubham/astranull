import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  createWafOrchestratorRepository,
  formatValidationPlanForApi,
  mapRetestRequestRow,
  mapValidationPlanRow,
} from '../../src/persistence/postgres/wafOrchestratorRepository.mjs';
import {
  DELEGATION_STATUS,
  WAF_ORCHESTRATOR_REPOSITORY_METHODS,
  createPostgresWafOrchestratorServices,
} from '../../src/persistence/postgres/wafOrchestratorServiceAdapters.mjs';

const CTX = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };
const FIXED_NOW = '2026-07-02T12:00:00.000Z';

function createRecordingPool(handler) {
  const client = {
    queries: [],
    released: false,
    async query(text, params) {
      this.queries.push({ text, params });
      return handler(text, params, this.queries);
    },
    release() {
      this.released = true;
    },
  };
  return {
    client,
    async connect() {
      return client;
    },
  };
}

function businessQueries(client) {
  return client.queries.filter((q) => {
    const t = q.text.trim();
    return (
      t !== 'BEGIN' &&
      t !== 'COMMIT' &&
      t !== 'ROLLBACK' &&
      !t.startsWith("SELECT set_config('app.tenant_id'")
    );
  });
}

function assertTenantWrapped(client) {
  assert.equal(client.queries[0].text.trim(), 'BEGIN');
  assert.equal(client.queries[1].text.trim(), "SELECT set_config('app.tenant_id', $1, true)");
  assert.deepEqual(client.queries[1].params, [CTX.tenantId]);
  assert.equal(client.queries.at(-1).text.trim(), 'COMMIT');
  assert.equal(client.released, true);
}

function assertTenantScoped(sql, params) {
  const hasTenantPredicate = /tenant_id\s*=\s*\$\d+/i.test(sql);
  const hasInsertTenantColumn = /INSERT\s+INTO\s+waf_/i.test(sql) && /tenant_id/i.test(sql);
  assert.ok(hasTenantPredicate || hasInsertTenantColumn, `expected tenant scope in: ${sql}`);
  assert.ok(params.includes(CTX.tenantId), `expected tenant id param in: ${sql}`);
}

const validationPlanRow = {
  id: 'plan_1',
  tenant_id: CTX.tenantId,
  target_group_id: 'tg_1',
  mode: 'scheduled',
  schedule_interval: 'daily',
  custom_cron_expression: null,
  scenarios_json: ['marker'],
  max_concurrent: 1,
  timeout_ms: 60_000,
  state: 'scheduled',
  delegated_jobs_json: [],
  created_at: new Date(FIXED_NOW),
  updated_at: new Date(FIXED_NOW),
  executed_at: null,
  cancelled_at: null,
};

describe('postgres WAF orchestrator repository', () => {
  it('maps validation plan rows to route-facing shape', () => {
    const mapped = mapValidationPlanRow({
      id: 'plan_1',
      tenant_id: CTX.tenantId,
      target_group_id: 'tg_1',
      mode: 'manual',
      schedule_interval: null,
      custom_cron_expression: null,
      scenarios_json: ['marker', 'fingerprint'],
      max_concurrent: 2,
      timeout_ms: 60_000,
      state: 'draft',
      delegated_jobs_json: [],
      created_at: new Date(FIXED_NOW),
      updated_at: new Date(FIXED_NOW),
      executed_at: null,
      cancelled_at: null,
      execution_lock_token: 'secret_lock',
      execution_lock_expires_at: new Date(FIXED_NOW),
    });
    assert.equal(mapped.id, 'plan_1');
    assert.deepEqual(mapped.scenarios, ['marker', 'fingerprint']);
    assert.ok(!('execution_lock_token' in mapped));
    assert.ok(!('execution_lock_expires_at' in mapped));
    const api = formatValidationPlanForApi(mapped);
    assert.equal(api.target_group_id, 'tg_1');
    assert.ok(!('execution_lock_token' in api));
  });

  it('lists retest requests with optional drift_event_id filter', async () => {
    const retestRow = {
      id: 'rt_1',
      tenant_id: CTX.tenantId,
      drift_event_id: 'drift_1',
      waf_asset_id: 'waf_1',
      retest_plan_json: ['marker'],
      requested_by: 'operator',
      priority: 'normal',
      status: 'requested',
      verdict: null,
      verdict_reason: null,
      delegated_jobs_json: [],
      created_at: new Date(FIXED_NOW),
      updated_at: new Date(FIXED_NOW),
      completed_at: null,
      execution_lock_token: null,
      execution_lock_expires_at: null,
    };
    const pool = createRecordingPool((sql, params) => {
      if (/FROM waf_retest_requests/i.test(sql)) {
        assertTenantScoped(sql, params);
        if (params.length === 2) {
          assert.match(sql, /drift_event_id = \$2/i);
          assert.equal(params[1], 'drift_1');
        } else {
          assert.match(sql, /ORDER BY created_at DESC/i);
        }
        return { rows: [retestRow] };
      }
      return { rows: [] };
    });
    const repo = createWafOrchestratorRepository(pool);
    const all = await repo.listRetestRequests(CTX);
    assert.equal(all.length, 1);
    assert.equal(all[0].id, 'rt_1');
    assert.deepEqual(all[0].retest_plan, ['marker']);
    assertTenantWrapped(pool.client);

    pool.client.queries = [];
    pool.client.released = false;
    const filtered = await repo.listRetestRequests(CTX, { drift_event_id: 'drift_1' });
    assert.equal(filtered.length, 1);
    assert.equal(filtered[0].drift_event_id, 'drift_1');
    assertTenantWrapped(pool.client);

    pool.client.queries = [];
    pool.client.released = false;
    const statusFiltered = await repo.listRetestRequests(CTX, {
      waf_asset_id: 'waf_1',
      status: 'requested',
    });
    assert.equal(statusFiltered.length, 1);
    const statusQuery = pool.client.queries.find((q) =>
      /waf_asset_id = \$2/i.test(q.text) && /status = \$3/i.test(q.text),
    );
    assert.ok(statusQuery);
    assert.deepEqual(statusQuery.params.slice(1), ['waf_1', 'requested']);
    assertTenantWrapped(pool.client);
  });

  it('lists validation plans inside tenant context', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/FROM waf_validation_plans/i.test(sql)) {
        assertTenantScoped(sql, params);
        return { rows: [validationPlanRow] };
      }
      return { rows: [] };
    });
    const repo = createWafOrchestratorRepository(pool);
    const plans = await repo.listValidationPlans(CTX);
    assert.equal(plans.length, 1);
    assert.equal(plans[0].state, 'scheduled');
    assertTenantWrapped(pool.client);
  });

  it('lists runnable validation plans with scheduled and running state filter', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/FROM waf_validation_plans/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.match(sql, /state IN \('scheduled', 'running'\)/i);
        return {
          rows: [
            validationPlanRow,
            {
              ...validationPlanRow,
              id: 'plan_running',
              state: 'running',
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createWafOrchestratorRepository(pool);
    const plans = await repo.listRunnableValidationPlans(CTX);
    assert.equal(plans.length, 2);
    assert.equal(plans[1].state, 'running');
    assertTenantWrapped(pool.client);
  });

  it('lists scheduled validation plans with tenant context and scheduled state filter', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/FROM waf_validation_plans/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.match(sql, /state\s*=\s*'scheduled'/i);
        return { rows: [validationPlanRow] };
      }
      return { rows: [] };
    });
    const repo = createWafOrchestratorRepository(pool);
    const plans = await repo.listScheduledValidationPlans(CTX);
    assert.equal(plans.length, 1);
    assert.equal(plans[0].mode, 'scheduled');
    assert.deepEqual(plans[0].scenarios, ['marker']);
    assertTenantWrapped(pool.client);
  });

  it('gets validation plan by id with tenant scope and mapped row', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/FROM waf_validation_plans/i.test(sql) && /AND id = \$2/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.equal(params[1], 'plan_1');
        return { rows: [validationPlanRow] };
      }
      return { rows: [] };
    });
    const repo = createWafOrchestratorRepository(pool);
    const plan = await repo.getValidationPlan(CTX, 'plan_1');
    assert.equal(plan.id, 'plan_1');
    assert.equal(plan.target_group_id, 'tg_1');
    assert.deepEqual(plan.scenarios, ['marker']);
    assertTenantWrapped(pool.client);
  });

  it('creates validation plan with tenant id on insert', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/INSERT INTO waf_validation_plans/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.equal(params[1], CTX.tenantId);
        return {
          rows: [
            {
              id: 'plan_new',
              tenant_id: CTX.tenantId,
              target_group_id: 'tg_1',
              mode: 'manual',
              schedule_interval: null,
              custom_cron_expression: null,
              scenarios_json: ['marker'],
              max_concurrent: 1,
              timeout_ms: 60_000,
              state: 'draft',
              delegated_jobs_json: [],
              created_at: new Date(FIXED_NOW),
              updated_at: new Date(FIXED_NOW),
              executed_at: null,
              cancelled_at: null,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createWafOrchestratorRepository(pool);
    const created = await repo.createValidationPlan(CTX, {
      id: 'plan_new',
      target_group_id: 'tg_1',
      mode: 'manual',
      scenarios: ['marker'],
      max_concurrent: 1,
      timeout_ms: 60_000,
      state: 'draft',
      created_at: FIXED_NOW,
      updated_at: FIXED_NOW,
    });
    assert.equal(created.id, 'plan_new');
    assertTenantWrapped(pool.client);
  });

  it('updates validation plan delegated_jobs into delegated_jobs_json column', async () => {
    const delegatedJobs = [{ job_id: 'job_1', kind: 'marker' }];
    const pool = createRecordingPool((sql, params) => {
      if (/UPDATE waf_validation_plans/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.match(sql, /delegated_jobs_json\s*=\s*\$\d+::jsonb/i);
        assert.ok(!/delegated_jobs\s*=/i.test(sql));
        const jsonParam = params.find((p) => p === JSON.stringify(delegatedJobs));
        assert.ok(jsonParam, 'expected JSON-stringified delegated jobs param');
        return {
          rows: [
            {
              ...validationPlanRow,
              delegated_jobs_json: delegatedJobs,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createWafOrchestratorRepository(pool);
    const updated = await repo.updateValidationPlan(CTX, 'plan_1', {
      delegated_jobs: delegatedJobs,
    });
    assert.deepEqual(updated.delegated_jobs, delegatedJobs);
    assertTenantWrapped(pool.client);
  });

  it('maps retest request rows with retest_plan array', () => {
    const mapped = mapRetestRequestRow({
      id: 'rt_1',
      tenant_id: CTX.tenantId,
      drift_event_id: 'drift_1',
      waf_asset_id: 'waf_1',
      retest_plan_json: ['marker'],
      requested_by: 'usr_1',
      priority: 'high',
      status: 'requested',
      verdict: null,
      verdict_reason: null,
      delegated_jobs_json: [],
      created_at: new Date(FIXED_NOW),
      updated_at: new Date(FIXED_NOW),
      completed_at: null,
    });
    assert.deepEqual(mapped.retest_plan, ['marker']);
    assert.equal(mapped.priority, 'high');
  });

  it('gets and updates WAF baseline inside tenant context', async () => {
    const baselineRow = {
      id: 'bl_1',
      tenant_id: CTX.tenantId,
      waf_asset_id: 'waf_1',
      state: 'draft',
      baseline_json: { rules: 1 },
      approved_by: null,
      approved_at: null,
      created_at: new Date(FIXED_NOW),
      updated_at: new Date(FIXED_NOW),
    };
    const pool = createRecordingPool((sql, params) => {
      if (/FROM waf_baselines/i.test(sql)) {
        assertTenantScoped(sql, params);
        return { rows: [baselineRow] };
      }
      if (/UPDATE waf_baselines/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.match(sql, /state\s*=\s*\$\d+/i);
        return { rows: [{ ...baselineRow, state: 'approved' }] };
      }
      return { rows: [] };
    });
    const repo = createWafOrchestratorRepository(pool);
    const baseline = await repo.getWafBaseline(CTX, 'bl_1');
    assert.equal(baseline.waf_asset_id, 'waf_1');
    assert.deepEqual(baseline.baseline_json, { rules: 1 });
    assertTenantWrapped(pool.client);

    pool.client.queries.length = 0;
    pool.client.released = false;
    const updated = await repo.updateWafBaseline(CTX, 'bl_1', { state: 'approved' });
    assert.equal(updated.state, 'approved');
    assertTenantWrapped(pool.client);
  });

  it('creates baseline approval with tenant scope and mapped fingerprint summary', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/INSERT INTO waf_baseline_approvals/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.equal(params[1], CTX.tenantId);
        return {
          rows: [
            {
              id: 'appr_1',
              tenant_id: CTX.tenantId,
              baseline_id: 'bl_1',
              waf_asset_id: 'waf_1',
              approver: 'usr_admin',
              approval_notes: 'ok',
              approved_at: new Date(FIXED_NOW),
              fingerprint_summary_json: { hash: 'abc' },
              created_at: new Date(FIXED_NOW),
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createWafOrchestratorRepository(pool);
    const approval = await repo.createBaselineApproval(CTX, {
      id: 'appr_1',
      baseline_id: 'bl_1',
      waf_asset_id: 'waf_1',
      approver: 'usr_admin',
      approval_notes: 'ok',
      approved_at: FIXED_NOW,
      fingerprint_summary: { hash: 'abc' },
      created_at: FIXED_NOW,
    });
    assert.equal(approval.baseline_id, 'bl_1');
    assert.deepEqual(approval.fingerprint_summary, { hash: 'abc' });
    assertTenantWrapped(pool.client);
  });

  it('gets WAF drift event with tenant scope and route-facing summaries', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/FROM waf_drift_events/i.test(sql)) {
        assertTenantScoped(sql, params);
        return {
          rows: [
            {
              id: 'drift_1',
              tenant_id: CTX.tenantId,
              waf_asset_id: 'waf_1',
              baseline_id: 'bl_1',
              drift_type: 'rule_change',
              severity: 'high',
              before_summary_json: { rules: 1 },
              after_summary_json: { rules: 2 },
              status: 'open',
              finding_id: 'find_1',
              created_at: new Date(FIXED_NOW),
              resolved_at: null,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createWafOrchestratorRepository(pool);
    const drift = await repo.getWafDriftEvent(CTX, 'drift_1');
    assert.equal(drift.drift_type, 'rule_change');
    assert.deepEqual(drift.before_summary, { rules: 1 });
    assert.deepEqual(drift.after_summary, { rules: 2 });
    assertTenantWrapped(pool.client);
  });

  it('updates retest request delegated_jobs into delegated_jobs_json column', async () => {
    const delegatedJobs = [
      {
        test_run_id: 'run_rt_1',
        probe_job_id: 'pjob_rt_1',
        scenario: 'marker',
        waf_asset_id: 'waf_1',
        check_id: 'waf.marker_rule.safe',
      },
    ];
    const retestRow = {
      id: 'rt_1',
      tenant_id: CTX.tenantId,
      drift_event_id: 'drift_1',
      waf_asset_id: 'waf_1',
      retest_plan_json: ['marker', 'fingerprint'],
      requested_by: 'usr_1',
      priority: 'high',
      status: 'running',
      verdict: null,
      verdict_reason: null,
      delegated_jobs_json: delegatedJobs,
      created_at: new Date(FIXED_NOW),
      updated_at: new Date(FIXED_NOW),
      completed_at: null,
    };
    const pool = createRecordingPool((sql, params) => {
      if (/UPDATE waf_retest_requests/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.match(sql, /delegated_jobs_json\s*=\s*\$\d+::jsonb/i);
        assert.ok(!/delegated_jobs\s*=/i.test(sql));
        const jsonParam = params.find((p) => p === JSON.stringify(delegatedJobs));
        assert.ok(jsonParam, 'expected JSON-stringified delegated jobs param');
        return { rows: [retestRow] };
      }
      return { rows: [] };
    });
    const repo = createWafOrchestratorRepository(pool);
    const updated = await repo.updateRetestRequest(CTX, 'rt_1', {
      delegated_jobs: delegatedJobs,
    });
    assert.deepEqual(updated.delegated_jobs, delegatedJobs);
    assertTenantWrapped(pool.client);
  });

  it('creates, gets, and updates retest requests inside tenant context', async () => {
    const retestRow = {
      id: 'rt_1',
      tenant_id: CTX.tenantId,
      drift_event_id: 'drift_1',
      waf_asset_id: 'waf_1',
      retest_plan_json: ['marker'],
      requested_by: 'usr_1',
      priority: 'high',
      status: 'requested',
      verdict: null,
      verdict_reason: null,
      delegated_jobs_json: [],
      created_at: new Date(FIXED_NOW),
      updated_at: new Date(FIXED_NOW),
      completed_at: null,
    };
    const pool = createRecordingPool((sql, params) => {
      if (/INSERT INTO waf_retest_requests/i.test(sql)) {
        assertTenantScoped(sql, params);
        return { rows: [retestRow] };
      }
      if (/FROM waf_retest_requests/i.test(sql) && /AND id = \$2/i.test(sql)) {
        assertTenantScoped(sql, params);
        return { rows: [retestRow] };
      }
      if (/UPDATE waf_retest_requests/i.test(sql)) {
        assertTenantScoped(sql, params);
        return {
          rows: [
            {
              ...retestRow,
              status: 'completed',
              verdict: 'pass',
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createWafOrchestratorRepository(pool);

    const created = await repo.createRetestRequest(CTX, {
      id: 'rt_1',
      drift_event_id: 'drift_1',
      waf_asset_id: 'waf_1',
      retest_plan: ['marker'],
      requested_by: 'usr_1',
      priority: 'high',
      status: 'requested',
      created_at: FIXED_NOW,
      updated_at: FIXED_NOW,
    });
    assert.deepEqual(created.retest_plan, ['marker']);
    assertTenantWrapped(pool.client);

    pool.client.queries.length = 0;
    pool.client.released = false;
    const fetched = await repo.getRetestRequest(CTX, 'rt_1');
    assert.equal(fetched.status, 'requested');
    assertTenantWrapped(pool.client);

    pool.client.queries.length = 0;
    pool.client.released = false;
    const updated = await repo.updateRetestRequest(CTX, 'rt_1', {
      status: 'completed',
      verdict: 'pass',
    });
    assert.equal(updated.verdict, 'pass');
    assertTenantWrapped(pool.client);
  });

  it('claimValidationPlanExecution is tenant-scoped and requires missing or expired lock', async () => {
    const lease = {
      lock_token: 'lease_plan_1',
      lock_expires_at: '2026-07-02T13:00:00.000Z',
      now: FIXED_NOW,
    };
    const pool = createRecordingPool((sql, params) => {
      if (/UPDATE waf_validation_plans/i.test(sql) && /execution_lock_token/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.match(sql, /execution_lock_token IS NULL OR execution_lock_expires_at <=/i);
        assert.match(sql, /state IN \('draft', 'scheduled', 'running'\)/i);
        assert.equal(params[2], lease.lock_token);
        assert.equal(params[3], lease.lock_expires_at);
        assert.equal(params[4], lease.now);
        return { rows: [validationPlanRow] };
      }
      return { rows: [] };
    });
    const repo = createWafOrchestratorRepository(pool);
    const claimed = await repo.claimValidationPlanExecution(CTX, 'plan_1', lease);
    assert.equal(claimed.id, 'plan_1');
    assertTenantWrapped(pool.client);
  });

  it('claimValidationPlanExecution returns null when no row is claimed', async () => {
    const pool = createRecordingPool((sql) => {
      if (/UPDATE waf_validation_plans/i.test(sql) && /execution_lock_token/i.test(sql)) {
        return { rows: [] };
      }
      return { rows: [] };
    });
    const repo = createWafOrchestratorRepository(pool);
    const claimed = await repo.claimValidationPlanExecution(CTX, 'plan_missing', {
      lock_token: 't1',
      lock_expires_at: FIXED_NOW,
      now: FIXED_NOW,
    });
    assert.equal(claimed, null);
    assertTenantWrapped(pool.client);
  });

  it('stageValidationPlanDelegation updates delegated_jobs while retaining execution lease', async () => {
    const delegatedJobs = [
      {
        status: 'pending_start',
        reservation_id: 'res_1',
        scenario: 'marker',
        waf_asset_id: 'waf_1',
        check_id: 'waf.marker_rule.safe',
        reserved_at: FIXED_NOW,
      },
    ];
    const pool = createRecordingPool((sql, params) => {
      if (
        /UPDATE waf_validation_plans/i.test(sql) &&
        /execution_lock_token = \$3/i.test(sql) &&
        !/execution_lock_token = NULL/i.test(sql)
      ) {
        assertTenantScoped(sql, params);
        assert.equal(params[2], 'lease_plan_stage');
        assert.match(sql, /delegated_jobs_json\s*=\s*\$\d+::jsonb/i);
        assert.ok(params.includes(JSON.stringify(delegatedJobs)));
        return {
          rows: [
            {
              ...validationPlanRow,
              state: 'running',
              delegated_jobs_json: delegatedJobs,
              execution_lock_token: 'lease_plan_stage',
              execution_lock_expires_at: new Date(FIXED_NOW),
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createWafOrchestratorRepository(pool);
    const staged = await repo.stageValidationPlanDelegation(CTX, 'plan_1', 'lease_plan_stage', {
      delegated_jobs: delegatedJobs,
      updated_at: FIXED_NOW,
    });
    assert.equal(staged.state, 'running');
    assert.deepEqual(staged.delegated_jobs, delegatedJobs);
    assert.ok(!('execution_lock_token' in staged));
    assertTenantWrapped(pool.client);
  });

  it('stageValidationPlanDelegation returns null when lock token does not match', async () => {
    const pool = createRecordingPool((sql) => {
      if (/UPDATE waf_validation_plans/i.test(sql) && /execution_lock_token = \$3/i.test(sql)) {
        return { rows: [] };
      }
      return { rows: [] };
    });
    const repo = createWafOrchestratorRepository(pool);
    const staged = await repo.stageValidationPlanDelegation(CTX, 'plan_1', 'wrong_token', {
      delegated_jobs: [],
      updated_at: FIXED_NOW,
    });
    assert.equal(staged, null);
    assertTenantWrapped(pool.client);
  });

  it('stageRetestDelegation updates delegated_jobs while retaining execution lease', async () => {
    const delegatedJobs = [
      {
        status: 'starting',
        reservation_id: 'res_rt_1',
        test_run_id: 'run_rt_1',
        probe_job_id: 'pjob_rt_1',
        scenario: 'marker',
        waf_asset_id: 'waf_1',
        check_id: 'waf.marker_rule.safe',
        started_at: FIXED_NOW,
      },
    ];
    const retestRow = {
      id: 'rt_stage',
      tenant_id: CTX.tenantId,
      drift_event_id: 'drift_1',
      waf_asset_id: 'waf_1',
      retest_plan_json: ['marker'],
      requested_by: 'usr_1',
      priority: 'high',
      status: 'running',
      verdict: null,
      verdict_reason: null,
      delegated_jobs_json: delegatedJobs,
      created_at: new Date(FIXED_NOW),
      updated_at: new Date(FIXED_NOW),
      completed_at: null,
    };
    const pool = createRecordingPool((sql, params) => {
      if (
        /UPDATE waf_retest_requests/i.test(sql) &&
        /execution_lock_token = \$3/i.test(sql) &&
        !/execution_lock_token = NULL/i.test(sql)
      ) {
        assertTenantScoped(sql, params);
        assert.equal(params[2], 'lease_rt_stage');
        assert.match(sql, /status IN \('requested', 'running'\)/i);
        return { rows: [retestRow] };
      }
      return { rows: [] };
    });
    const repo = createWafOrchestratorRepository(pool);
    const staged = await repo.stageRetestDelegation(CTX, 'rt_stage', 'lease_rt_stage', {
      delegated_jobs: delegatedJobs,
      updated_at: FIXED_NOW,
    });
    assert.equal(staged.status, 'running');
    assert.deepEqual(staged.delegated_jobs, delegatedJobs);
    assert.ok(!('execution_lock_token' in staged));
    assertTenantWrapped(pool.client);
  });

  it('finishValidationPlanExecution clears lock, requires token, and normalizes delegated_jobs', async () => {
    const delegatedJobs = [{ job_id: 'job_finish', kind: 'marker' }];
    const pool = createRecordingPool((sql, params) => {
      if (
        /UPDATE waf_validation_plans/i.test(sql) &&
        /execution_lock_token = NULL/i.test(sql) &&
        /execution_lock_token = \$3/i.test(sql)
      ) {
        assertTenantScoped(sql, params);
        assert.equal(params[2], 'lease_plan_finish');
        assert.match(sql, /state IN \('draft', 'scheduled', 'running'\)/i);
        assert.match(sql, /delegated_jobs_json\s*=\s*\$\d+::jsonb/i);
        assert.ok(!/delegated_jobs\s*=/i.test(sql));
        assert.ok(params.includes(JSON.stringify(delegatedJobs)));
        return {
          rows: [
            {
              ...validationPlanRow,
              state: 'running',
              delegated_jobs_json: delegatedJobs,
              execution_lock_token: null,
              execution_lock_expires_at: null,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createWafOrchestratorRepository(pool);
    const finished = await repo.finishValidationPlanExecution(CTX, 'plan_1', 'lease_plan_finish', {
      state: 'running',
      delegated_jobs: delegatedJobs,
      updated_at: FIXED_NOW,
    });
    assert.equal(finished.state, 'running');
    assert.deepEqual(finished.delegated_jobs, delegatedJobs);
    assert.ok(!('execution_lock_token' in finished));
    assertTenantWrapped(pool.client);
  });

  it('finishValidationPlanExecution returns null when lock token does not match', async () => {
    const pool = createRecordingPool((sql) => {
      if (/UPDATE waf_validation_plans/i.test(sql) && /execution_lock_token = \$3/i.test(sql)) {
        return { rows: [] };
      }
      return { rows: [] };
    });
    const repo = createWafOrchestratorRepository(pool);
    const finished = await repo.finishValidationPlanExecution(CTX, 'plan_1', 'wrong_token', {
      state: 'running',
    });
    assert.equal(finished, null);
    assertTenantWrapped(pool.client);
  });

  it('cancelValidationPlanExecution is tenant-scoped, cancels, clears locks, and gates lifecycle state', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (
        /UPDATE waf_validation_plans/i.test(sql) &&
        /state = 'cancelled'/i.test(sql) &&
        /execution_lock_token = NULL/i.test(sql)
      ) {
        assertTenantScoped(sql, params);
        assert.match(sql, /state IN \('draft', 'scheduled', 'running'\)/i);
        assert.match(sql, /execution_lock_expires_at = NULL/i);
        assert.equal(params[1], 'plan_cancel');
        assert.equal(params[2], FIXED_NOW);
        assert.equal(params[3], FIXED_NOW);
        return {
          rows: [
            {
              ...validationPlanRow,
              id: 'plan_cancel',
              state: 'cancelled',
              cancelled_at: new Date(FIXED_NOW),
              updated_at: new Date(FIXED_NOW),
              execution_lock_token: null,
              execution_lock_expires_at: null,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createWafOrchestratorRepository(pool);
    const cancelled = await repo.cancelValidationPlanExecution(CTX, 'plan_cancel', {
      cancelled_at: FIXED_NOW,
      updated_at: FIXED_NOW,
    });
    assert.equal(cancelled.state, 'cancelled');
    assert.equal(cancelled.cancelled_at, FIXED_NOW);
    assert.equal(cancelled.updated_at, FIXED_NOW);
    assert.ok(!('execution_lock_token' in cancelled));
    assert.ok(!('execution_lock_expires_at' in cancelled));
    assertTenantWrapped(pool.client);
  });

  it('cancelValidationPlanExecution returns null when no row matches lifecycle gate', async () => {
    const pool = createRecordingPool((sql) => {
      if (/UPDATE waf_validation_plans/i.test(sql) && /state = 'cancelled'/i.test(sql)) {
        return { rows: [] };
      }
      return { rows: [] };
    });
    const repo = createWafOrchestratorRepository(pool);
    const cancelled = await repo.cancelValidationPlanExecution(CTX, 'plan_done', {
      cancelled_at: FIXED_NOW,
      updated_at: FIXED_NOW,
    });
    assert.equal(cancelled, null);
    assertTenantWrapped(pool.client);
  });

  it('releaseValidationPlanExecution clears lock columns and requires matching token', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (
        /UPDATE waf_validation_plans/i.test(sql) &&
        /execution_lock_token = NULL/i.test(sql) &&
        /execution_lock_token = \$3/i.test(sql)
      ) {
        assertTenantScoped(sql, params);
        assert.equal(params[2], 'lease_plan_release');
        assert.ok(!/SET[\s\S]*delegated_jobs_json\s*=/i.test(sql));
        return {
          rows: [
            {
              ...validationPlanRow,
              execution_lock_token: null,
              execution_lock_expires_at: null,
            },
          ],
        };
      }
      return { rows: [] };
    });
    const repo = createWafOrchestratorRepository(pool);
    const released = await repo.releaseValidationPlanExecution(CTX, 'plan_1', 'lease_plan_release');
    assert.equal(released.id, 'plan_1');
    assert.ok(!('execution_lock_token' in released));
    assertTenantWrapped(pool.client);
  });

  it('releaseValidationPlanExecution returns null when lock token does not match', async () => {
    const pool = createRecordingPool((sql) => {
      if (/UPDATE waf_validation_plans/i.test(sql) && /execution_lock_token = \$3/i.test(sql)) {
        return { rows: [] };
      }
      return { rows: [] };
    });
    const repo = createWafOrchestratorRepository(pool);
    const released = await repo.releaseValidationPlanExecution(CTX, 'plan_1', 'stale_token');
    assert.equal(released, null);
    assertTenantWrapped(pool.client);
  });

  it('claimRetestExecution is tenant-scoped and requires missing or expired lock', async () => {
    const retestRow = {
      id: 'rt_claim',
      tenant_id: CTX.tenantId,
      drift_event_id: 'drift_1',
      waf_asset_id: 'waf_1',
      retest_plan_json: ['marker'],
      requested_by: 'usr_1',
      priority: 'high',
      status: 'requested',
      verdict: null,
      verdict_reason: null,
      delegated_jobs_json: [],
      created_at: new Date(FIXED_NOW),
      updated_at: new Date(FIXED_NOW),
      completed_at: null,
    };
    const lease = {
      lock_token: 'lease_rt_1',
      lock_expires_at: '2026-07-02T13:00:00.000Z',
      now: FIXED_NOW,
    };
    const pool = createRecordingPool((sql, params) => {
      if (/UPDATE waf_retest_requests/i.test(sql) && /execution_lock_token/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.match(sql, /execution_lock_token IS NULL OR execution_lock_expires_at <=/i);
        assert.match(sql, /status IN \('requested', 'running'\)/i);
        return { rows: [retestRow] };
      }
      return { rows: [] };
    });
    const repo = createWafOrchestratorRepository(pool);
    const claimed = await repo.claimRetestExecution(CTX, 'rt_claim', lease);
    assert.equal(claimed.id, 'rt_claim');
    assert.ok(!('execution_lock_token' in claimed));
    assertTenantWrapped(pool.client);
  });

  it('claimRetestExecution returns null on conflict or missing row', async () => {
    const pool = createRecordingPool((sql) => {
      if (/UPDATE waf_retest_requests/i.test(sql) && /execution_lock_token/i.test(sql)) {
        return { rows: [] };
      }
      return { rows: [] };
    });
    const repo = createWafOrchestratorRepository(pool);
    const claimed = await repo.claimRetestExecution(CTX, 'rt_missing', {
      lock_token: 't2',
      lock_expires_at: FIXED_NOW,
      now: FIXED_NOW,
    });
    assert.equal(claimed, null);
    assertTenantWrapped(pool.client);
  });

  it('finishRetestExecution clears lock, requires token, and normalizes delegated_jobs', async () => {
    const delegatedJobs = [
      {
        test_run_id: 'run_finish',
        probe_job_id: 'pjob_finish',
        scenario: 'marker',
        waf_asset_id: 'waf_1',
        check_id: 'waf.marker_rule.safe',
      },
    ];
    const retestRow = {
      id: 'rt_finish',
      tenant_id: CTX.tenantId,
      drift_event_id: 'drift_1',
      waf_asset_id: 'waf_1',
      retest_plan_json: ['marker'],
      requested_by: 'usr_1',
      priority: 'high',
      status: 'running',
      verdict: null,
      verdict_reason: null,
      delegated_jobs_json: delegatedJobs,
      created_at: new Date(FIXED_NOW),
      updated_at: new Date(FIXED_NOW),
      completed_at: null,
    };
    const pool = createRecordingPool((sql, params) => {
      if (
        /UPDATE waf_retest_requests/i.test(sql) &&
        /execution_lock_token = NULL/i.test(sql) &&
        /execution_lock_token = \$3/i.test(sql)
      ) {
        assertTenantScoped(sql, params);
        assert.match(sql, /status IN \('requested', 'running'\)/i);
        assert.match(sql, /delegated_jobs_json\s*=\s*\$\d+::jsonb/i);
        return { rows: [retestRow] };
      }
      return { rows: [] };
    });
    const repo = createWafOrchestratorRepository(pool);
    const finished = await repo.finishRetestExecution(CTX, 'rt_finish', 'lease_rt_finish', {
      status: 'running',
      delegated_jobs: delegatedJobs,
      updated_at: FIXED_NOW,
    });
    assert.equal(finished.status, 'running');
    assert.deepEqual(finished.delegated_jobs, delegatedJobs);
    assert.ok(!('execution_lock_token' in finished));
    assertTenantWrapped(pool.client);
  });

  it('finishRetestExecution returns null when lock token does not match', async () => {
    const pool = createRecordingPool((sql) => {
      if (/UPDATE waf_retest_requests/i.test(sql) && /execution_lock_token = \$3/i.test(sql)) {
        return { rows: [] };
      }
      return { rows: [] };
    });
    const repo = createWafOrchestratorRepository(pool);
    const finished = await repo.finishRetestExecution(CTX, 'rt_1', 'bad_token', { status: 'running' });
    assert.equal(finished, null);
    assertTenantWrapped(pool.client);
  });

  it('releaseRetestExecution clears lock columns and requires matching token', async () => {
    const retestRow = {
      id: 'rt_release',
      tenant_id: CTX.tenantId,
      drift_event_id: 'drift_1',
      waf_asset_id: 'waf_1',
      retest_plan_json: ['marker'],
      requested_by: 'usr_1',
      priority: 'high',
      status: 'running',
      verdict: null,
      verdict_reason: null,
      delegated_jobs_json: [],
      created_at: new Date(FIXED_NOW),
      updated_at: new Date(FIXED_NOW),
      completed_at: null,
    };
    const pool = createRecordingPool((sql, params) => {
      if (
        /UPDATE waf_retest_requests/i.test(sql) &&
        /execution_lock_token = NULL/i.test(sql) &&
        /execution_lock_token = \$3/i.test(sql)
      ) {
        assertTenantScoped(sql, params);
        assert.equal(params[2], 'lease_rt_release');
        return { rows: [retestRow] };
      }
      return { rows: [] };
    });
    const repo = createWafOrchestratorRepository(pool);
    const released = await repo.releaseRetestExecution(CTX, 'rt_release', 'lease_rt_release');
    assert.equal(released.id, 'rt_release');
    assert.ok(!('execution_lock_token' in released));
    assertTenantWrapped(pool.client);
  });

  it('releaseRetestExecution returns null when lock token does not match', async () => {
    const pool = createRecordingPool((sql) => {
      if (/UPDATE waf_retest_requests/i.test(sql) && /execution_lock_token = \$3/i.test(sql)) {
        return { rows: [] };
      }
      return { rows: [] };
    });
    const repo = createWafOrchestratorRepository(pool);
    const released = await repo.releaseRetestExecution(CTX, 'rt_1', 'wrong');
    assert.equal(released, null);
    assertTenantWrapped(pool.client);
  });

  it('rolls back and releases client when a tenant-scoped query fails', async () => {
    const pool = createRecordingPool((sql) => {
      if (/FROM waf_validation_plans/i.test(sql)) {
        throw new Error('plan read failed');
      }
      return { rows: [] };
    });
    const repo = createWafOrchestratorRepository(pool);
    await assert.rejects(() => repo.getValidationPlan(CTX, 'plan_1'), /plan read failed/);
    assert.ok(pool.client.queries.some((q) => q.text.trim() === 'ROLLBACK'));
    assert.ok(!pool.client.queries.some((q) => q.text.trim() === 'COMMIT'));
    assert.equal(pool.client.released, true);
    assert.equal(businessQueries(pool.client).length, 1);
  });

  it('completeRetestWithDriftAndAudit updates retest, drift, and audit in one tenant transaction', async () => {
    const delegatedJobs = [
      {
        test_run_id: 'run_close_1',
        probe_job_id: 'pjob_close_1',
        scenario: 'marker',
        waf_asset_id: 'waf_1',
        check_id: 'waf.marker_rule.safe',
      },
    ];
    const retestRow = {
      id: 'rt_1',
      tenant_id: CTX.tenantId,
      drift_event_id: 'drift_1',
      waf_asset_id: 'waf_1',
      retest_plan_json: ['marker'],
      requested_by: 'usr_1',
      priority: 'high',
      status: 'completed',
      verdict: 'resolved',
      verdict_reason: 'all_pass',
      delegated_jobs_json: delegatedJobs,
      created_at: new Date(FIXED_NOW),
      updated_at: new Date(FIXED_NOW),
      completed_at: new Date(FIXED_NOW),
    };
    const driftRow = {
      id: 'drift_1',
      tenant_id: CTX.tenantId,
      waf_asset_id: 'waf_1',
      baseline_id: 'bl_1',
      drift_type: 'rule_change',
      severity: 'high',
      before_summary_json: { rules: 1 },
      after_summary_json: { rules: 2 },
      status: 'resolved',
      finding_id: 'find_1',
      created_at: new Date(FIXED_NOW),
      resolved_at: new Date(FIXED_NOW),
    };
    const pool = createRecordingPool((sql, params) => {
      if (/UPDATE waf_retest_requests/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.match(sql, /delegated_jobs_json\s*=\s*\$\d+::jsonb/i);
        return { rows: [retestRow] };
      }
      if (/UPDATE waf_drift_events/i.test(sql)) {
        assertTenantScoped(sql, params);
        assert.match(sql, /status\s*=/i);
        return { rows: [driftRow] };
      }
      if (/pg_advisory_xact_lock/i.test(sql)) {
        return { rows: [] };
      }
      if (/FROM audit_logs/i.test(sql) && /ORDER BY sequence DESC/i.test(sql)) {
        return { rows: [] };
      }
      if (/INSERT INTO audit_logs/i.test(sql)) {
        assert.equal(params[8], 'waf.retest.completed');
        return { rows: [] };
      }
      return { rows: [] };
    });
    const repo = createWafOrchestratorRepository(pool);
    const payload = {
      retest_id: 'rt_1',
      retest_patch: {
        status: 'completed',
        verdict: 'resolved',
        verdict_reason: 'all_pass',
        delegated_jobs: delegatedJobs,
        completed_at: FIXED_NOW,
        updated_at: FIXED_NOW,
      },
      drift_event_id: 'drift_1',
      drift_patch: { status: 'resolved', resolved_at: FIXED_NOW },
      audit_event: {
        tenant_id: CTX.tenantId,
        actor_user_id: CTX.userId,
        actor_role: CTX.role,
        action: 'waf.retest.completed',
        resource_type: 'waf_retest_request',
        resource_id: 'rt_1',
        metadata: { drift_event_id: 'drift_1', verdict: 'resolved' },
      },
    };
    const result = await repo.completeRetestWithDriftAndAudit(CTX, payload);
    assert.equal(result.retest_request.id, 'rt_1');
    assert.equal(result.retest_request.status, 'completed');
    assert.equal(result.retest_request.verdict, 'resolved');
    assert.deepEqual(result.retest_request.delegated_jobs, delegatedJobs);
    assert.equal(result.drift_event.status, 'resolved');
    assert.equal(result.audit_event.action, 'waf.retest.completed');
    const biz = businessQueries(pool.client);
    assert.equal(biz.length, 5);
    assert.ok(biz.some((q) => /UPDATE waf_retest_requests/i.test(q.text)));
    assert.ok(biz.some((q) => /UPDATE waf_drift_events/i.test(q.text)));
    assert.ok(biz.some((q) => /INSERT INTO audit_logs/i.test(q.text)));
    assertTenantWrapped(pool.client);
  });

  it('completeRetestWithDriftAndAudit rolls back when drift update matches no row', async () => {
    const pool = createRecordingPool((sql) => {
      if (/UPDATE waf_retest_requests/i.test(sql)) {
        return {
          rows: [
            {
              id: 'rt_1',
              tenant_id: CTX.tenantId,
              drift_event_id: 'drift_missing',
              waf_asset_id: 'waf_1',
              retest_plan_json: [],
              requested_by: 'usr_1',
              priority: 'high',
              status: 'completed',
              verdict: 'resolved',
              verdict_reason: null,
              delegated_jobs_json: [],
              created_at: new Date(FIXED_NOW),
              updated_at: new Date(FIXED_NOW),
              completed_at: new Date(FIXED_NOW),
            },
          ],
        };
      }
      if (/UPDATE waf_drift_events/i.test(sql)) {
        return { rows: [] };
      }
      return { rows: [] };
    });
    const repo = createWafOrchestratorRepository(pool);
    await assert.rejects(
      () =>
        repo.completeRetestWithDriftAndAudit(CTX, {
          retest_id: 'rt_1',
          retest_patch: { status: 'completed', verdict: 'resolved', updated_at: FIXED_NOW },
          drift_event_id: 'drift_missing',
          drift_patch: { status: 'resolved' },
          audit_event: {
            tenant_id: CTX.tenantId,
            action: 'waf.retest.completed',
            resource_type: 'waf_retest_request',
            resource_id: 'rt_1',
          },
        }),
      /Drift event not found for tenant-scoped retest completion/,
    );
    assert.ok(pool.client.queries.some((q) => q.text.trim() === 'ROLLBACK'));
    assert.ok(!pool.client.queries.some((q) => q.text.trim() === 'COMMIT'));
    assert.equal(pool.client.released, true);
    assert.ok(!pool.client.queries.some((q) => /INSERT INTO audit_logs/i.test(q.text)));
  });

  it('completeRetestWithDriftAndAudit rolls back when drift update fails', async () => {
    const pool = createRecordingPool((sql) => {
      if (/UPDATE waf_retest_requests/i.test(sql)) {
        return {
          rows: [
            {
              id: 'rt_1',
              tenant_id: CTX.tenantId,
              drift_event_id: 'drift_1',
              waf_asset_id: 'waf_1',
              retest_plan_json: [],
              requested_by: 'usr_1',
              priority: 'high',
              status: 'completed',
              verdict: 'resolved',
              verdict_reason: null,
              delegated_jobs_json: [],
              created_at: new Date(FIXED_NOW),
              updated_at: new Date(FIXED_NOW),
              completed_at: new Date(FIXED_NOW),
            },
          ],
        };
      }
      if (/UPDATE waf_drift_events/i.test(sql)) {
        throw new Error('drift update failed');
      }
      return { rows: [] };
    });
    const repo = createWafOrchestratorRepository(pool);
    await assert.rejects(
      () =>
        repo.completeRetestWithDriftAndAudit(CTX, {
          retest_id: 'rt_1',
          retest_patch: { status: 'completed', verdict: 'resolved', updated_at: FIXED_NOW },
          drift_event_id: 'drift_1',
          drift_patch: { status: 'resolved' },
          audit_event: {
            tenant_id: CTX.tenantId,
            action: 'waf.retest.completed',
            resource_type: 'waf_retest_request',
            resource_id: 'rt_1',
          },
        }),
      /drift update failed/,
    );
    assert.ok(pool.client.queries.some((q) => q.text.trim() === 'ROLLBACK'));
    assert.ok(!pool.client.queries.some((q) => q.text.trim() === 'COMMIT'));
    assert.equal(pool.client.released, true);
  });

  it('persists pending_start before startTestRun during executeValidationPlan', async () => {
    const ctx = { tenantId: 'ten_outbox', userId: 'usr_waf', role: 'admin' };
    const fixed = new Date('2026-07-03T12:00:00.000Z');
    const callOrder = [];
    const wafOrchestrator = {};
    for (const method of WAF_ORCHESTRATOR_REPOSITORY_METHODS) {
      wafOrchestrator[method] = async () => null;
    }
    wafOrchestrator.getValidationPlan = async () => ({
      id: 'plan_outbox',
      target_group_id: 'tg_1',
      mode: 'manual',
      state: 'scheduled',
      scenarios: ['marker'],
      max_concurrent: 1,
      timeout_ms: 60_000,
      delegated_jobs: [],
      created_at: fixed.toISOString(),
      updated_at: fixed.toISOString(),
    });
    wafOrchestrator.claimValidationPlanExecution = async () => wafOrchestrator.getValidationPlan();
    wafOrchestrator.stageValidationPlanDelegation = async (_ctx, _id, _lockToken, patch) => {
      callOrder.push('stage');
      const hasPending = (patch.delegated_jobs ?? []).some(
        (job) => job.status === DELEGATION_STATUS.PENDING_START,
      );
      if (hasPending) {
        assert.equal(callOrder.includes('startTestRun'), false);
      }
      return {
        id: 'plan_outbox',
        delegated_jobs: patch.delegated_jobs,
        updated_at: patch.updated_at,
      };
    };
    wafOrchestrator.finishValidationPlanExecution = async (_ctx, _id, _lockToken, patch) => ({
      id: 'plan_outbox',
      target_group_id: 'tg_1',
      mode: 'manual',
      state: patch.state,
      scenarios: ['marker'],
      max_concurrent: 1,
      timeout_ms: 60_000,
      delegated_jobs: patch.delegated_jobs,
      executed_at: patch.executed_at,
      updated_at: patch.updated_at,
    });

    const repositories = {
      wafOrchestrator,
      wafPosture: {
        listWafAssets: async () => [
          { id: 'waf_asset_1', target_group_id: 'tg_1', target_id: 'tgt_1' },
        ],
        patchWafDriftEvent: async () => ({}),
      },
      coreCatalog: {
        getTargetGroup: async () => ({
          id: 'tg_1',
          targets: [{ id: 'tgt_1', kind: 'fqdn', value: 'edge.example' }],
        }),
      },
      audit: { appendAuditEvent: async (event) => event },
    };

    const svc = createPostgresWafOrchestratorServices(repositories, {
      now: () => fixed,
      newId: (prefix) => `${prefix}_test_1`,
      testRuns: {
        startTestRun: async () => {
          callOrder.push('startTestRun');
          assert.ok(callOrder.includes('stage'));
          return { run: { id: 'run_outbox_1' }, probe_job: { id: 'pjob_outbox_1' } };
        },
      },
    });

    const result = await svc.executeValidationPlan(ctx, 'plan_outbox', { probeMode: 'signed-worker' });
    assert.equal(result.error, undefined);
    assert.equal(result.validation_plan.state, 'completed');
    assert.equal(result.delegated_jobs[0].status, DELEGATION_STATUS.DELEGATED);
    assert.ok(callOrder.indexOf('stage') < callOrder.indexOf('startTestRun'));
    assert.ok(callOrder.filter((entry) => entry === 'stage').length >= 2);
  });

  it('stages pending_start, starting, and delegated progression from workingDelegatedJobs', async () => {
    const ctx = { tenantId: 'ten_outbox', userId: 'usr_waf', role: 'admin' };
    const fixed = new Date('2026-07-03T12:00:00.000Z');
    const stageSnapshots = [];
    const wafOrchestrator = {};
    for (const method of WAF_ORCHESTRATOR_REPOSITORY_METHODS) {
      wafOrchestrator[method] = async () => null;
    }
    wafOrchestrator.getValidationPlan = async () => ({
      id: 'plan_outbox',
      target_group_id: 'tg_1',
      mode: 'manual',
      state: 'running',
      scenarios: ['marker', 'fingerprint'],
      max_concurrent: 2,
      timeout_ms: 60_000,
      delegated_jobs: [
        {
          status: DELEGATION_STATUS.DELEGATED,
          reservation_id: 'res_existing',
          test_run_id: 'run_existing',
          probe_job_id: 'pjob_existing',
          scenario: 'marker',
          waf_asset_id: 'waf_asset_1',
          check_id: 'waf.marker_rule.safe',
        },
      ],
      executed_at: fixed.toISOString(),
      created_at: fixed.toISOString(),
      updated_at: fixed.toISOString(),
    });
    wafOrchestrator.claimValidationPlanExecution = async () => wafOrchestrator.getValidationPlan();
    wafOrchestrator.stageValidationPlanDelegation = async (_ctx, _id, _lockToken, patch) => {
      stageSnapshots.push((patch.delegated_jobs ?? []).map((job) => job.status));
      return {
        id: 'plan_outbox',
        delegated_jobs: patch.delegated_jobs,
        updated_at: patch.updated_at,
      };
    };
    wafOrchestrator.finishValidationPlanExecution = async (_ctx, _id, _lockToken, patch) => ({
      id: 'plan_outbox',
      target_group_id: 'tg_1',
      mode: 'manual',
      state: patch.state,
      scenarios: ['marker', 'fingerprint'],
      max_concurrent: 2,
      timeout_ms: 60_000,
      delegated_jobs: patch.delegated_jobs,
      executed_at: patch.executed_at,
      updated_at: patch.updated_at,
    });

    const repositories = {
      wafOrchestrator,
      wafPosture: {
        listWafAssets: async () => [
          { id: 'waf_asset_1', target_group_id: 'tg_1', target_id: 'tgt_1' },
        ],
        patchWafDriftEvent: async () => ({}),
      },
      coreCatalog: {
        getTargetGroup: async () => ({
          id: 'tg_1',
          targets: [{ id: 'tgt_1', kind: 'fqdn', value: 'edge.example' }],
        }),
      },
      audit: { appendAuditEvent: async (event) => event },
    };

    const svc = createPostgresWafOrchestratorServices(repositories, {
      now: () => fixed,
      newId: (prefix) => `${prefix}_progression`,
      testRuns: {
        startTestRun: async () => ({
          run: { id: 'run_fingerprint_1' },
          probe_job: { id: 'pjob_fingerprint_1' },
        }),
      },
    });

    const result = await svc.executeValidationPlan(ctx, 'plan_outbox', { probeMode: 'signed-worker' });
    assert.equal(result.error, undefined);
    assert.equal(stageSnapshots.length, 2);
    assert.deepEqual(stageSnapshots[0], [
      DELEGATION_STATUS.DELEGATED,
      DELEGATION_STATUS.PENDING_START,
    ]);
    assert.deepEqual(stageSnapshots[1], [
      DELEGATION_STATUS.DELEGATED,
      DELEGATION_STATUS.STARTING,
    ]);
    assert.equal(result.delegated_jobs.length, 2);
    assert.equal(result.delegated_jobs[0].status, DELEGATION_STATUS.DELEGATED);
    assert.equal(result.delegated_jobs[1].status, DELEGATION_STATUS.DELEGATED);
    assert.equal(result.delegated_jobs[1].test_run_id, 'run_fingerprint_1');
  });

  it('persists failed delegation from workingDelegatedJobs after pending_start is staged', async () => {
    const ctx = { tenantId: 'ten_outbox', userId: 'usr_waf', role: 'admin' };
    const fixed = new Date('2026-07-03T12:00:00.000Z');
    const stageSnapshots = [];
    const wafOrchestrator = {};
    for (const method of WAF_ORCHESTRATOR_REPOSITORY_METHODS) {
      wafOrchestrator[method] = async () => null;
    }
    wafOrchestrator.getValidationPlan = async () => ({
      id: 'plan_outbox',
      target_group_id: 'tg_1',
      mode: 'manual',
      state: 'running',
      scenarios: ['marker', 'fingerprint'],
      max_concurrent: 2,
      timeout_ms: 60_000,
      delegated_jobs: [
        {
          status: DELEGATION_STATUS.DELEGATED,
          reservation_id: 'res_existing',
          test_run_id: 'run_existing',
          probe_job_id: 'pjob_existing',
          scenario: 'marker',
          waf_asset_id: 'waf_asset_1',
          check_id: 'waf.marker_rule.safe',
        },
      ],
      executed_at: fixed.toISOString(),
      created_at: fixed.toISOString(),
      updated_at: fixed.toISOString(),
    });
    wafOrchestrator.claimValidationPlanExecution = async () => wafOrchestrator.getValidationPlan();
    wafOrchestrator.stageValidationPlanDelegation = async (_ctx, _id, _lockToken, patch) => {
      stageSnapshots.push(patch.delegated_jobs ?? []);
      return {
        id: 'plan_outbox',
        delegated_jobs: patch.delegated_jobs,
        updated_at: patch.updated_at,
      };
    };
    wafOrchestrator.releaseValidationPlanExecution = async () => true;

    const repositories = {
      wafOrchestrator,
      wafPosture: {
        listWafAssets: async () => [
          { id: 'waf_asset_1', target_group_id: 'tg_1', target_id: 'tgt_1' },
        ],
        patchWafDriftEvent: async () => ({}),
      },
      coreCatalog: {
        getTargetGroup: async () => ({
          id: 'tg_1',
          targets: [{ id: 'tgt_1', kind: 'fqdn', value: 'edge.example' }],
        }),
      },
      audit: { appendAuditEvent: async (event) => event },
    };

    const svc = createPostgresWafOrchestratorServices(repositories, {
      now: () => fixed,
      newId: (prefix) => `${prefix}_failure`,
      testRuns: {
        startTestRun: async () => ({ error: 'concurrent_run_blocked', status: 409 }),
      },
    });

    const result = await svc.executeValidationPlan(ctx, 'plan_outbox', { probeMode: 'signed-worker' });
    assert.equal(result.error, 'concurrent_run_blocked');
    assert.equal(result.status, 409);
    assert.equal(stageSnapshots.length, 2);
    assert.equal(stageSnapshots[0].length, 2);
    assert.equal(stageSnapshots[0][0].status, DELEGATION_STATUS.DELEGATED);
    assert.equal(stageSnapshots[0][1].status, DELEGATION_STATUS.PENDING_START);
    assert.equal(stageSnapshots[1].length, 2);
    assert.equal(stageSnapshots[1][0].status, DELEGATION_STATUS.DELEGATED);
    assert.equal(stageSnapshots[1][1].status, DELEGATION_STATUS.FAILED);
    assert.equal(stageSnapshots[1][1].failure_reason, 'concurrent_run_blocked');
    assert.equal(stageSnapshots[1][1].scenario, 'fingerprint');
  });

  it('completeRetestWithDriftAndAudit rolls back when audit insert fails', async () => {
    const pool = createRecordingPool((sql) => {
      if (/UPDATE waf_retest_requests/i.test(sql)) {
        return {
          rows: [
            {
              id: 'rt_1',
              tenant_id: CTX.tenantId,
              drift_event_id: 'drift_1',
              waf_asset_id: 'waf_1',
              retest_plan_json: [],
              requested_by: 'usr_1',
              priority: 'high',
              status: 'completed',
              verdict: 'resolved',
              verdict_reason: null,
              delegated_jobs_json: [],
              created_at: new Date(FIXED_NOW),
              updated_at: new Date(FIXED_NOW),
              completed_at: new Date(FIXED_NOW),
            },
          ],
        };
      }
      if (/UPDATE waf_drift_events/i.test(sql)) {
        return {
          rows: [
            {
              id: 'drift_1',
              tenant_id: CTX.tenantId,
              waf_asset_id: 'waf_1',
              baseline_id: 'bl_1',
              drift_type: 'rule_change',
              severity: 'high',
              before_summary_json: {},
              after_summary_json: {},
              status: 'resolved',
              finding_id: null,
              created_at: new Date(FIXED_NOW),
              resolved_at: new Date(FIXED_NOW),
            },
          ],
        };
      }
      if (/pg_advisory_xact_lock/i.test(sql) || /FROM audit_logs/i.test(sql)) {
        return { rows: [] };
      }
      if (/INSERT INTO audit_logs/i.test(sql)) {
        throw new Error('audit insert failed');
      }
      return { rows: [] };
    });
    const repo = createWafOrchestratorRepository(pool);
    await assert.rejects(
      () =>
        repo.completeRetestWithDriftAndAudit(CTX, {
          retest_id: 'rt_1',
          retest_patch: { status: 'completed', verdict: 'resolved', updated_at: FIXED_NOW },
          drift_event_id: 'drift_1',
          drift_patch: { status: 'resolved' },
          audit_event: {
            tenant_id: CTX.tenantId,
            action: 'waf.retest.completed',
            resource_type: 'waf_retest_request',
            resource_id: 'rt_1',
          },
        }),
      /audit insert failed/,
    );
    assert.ok(pool.client.queries.some((q) => q.text.trim() === 'ROLLBACK'));
    assert.ok(!pool.client.queries.some((q) => q.text.trim() === 'COMMIT'));
    assert.equal(pool.client.released, true);
  });
});