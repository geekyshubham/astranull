import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it } from 'node:test';
import { loadRuntimeConfig } from '../../src/config.mjs';
import {
  computeRetestVerdict,
  createBaselineApproval,
  createRetestRequest,
  createValidationPlan,
  validateOrchestratorPlan,
} from '../../src/contracts/wafOrchestrator.mjs';
import {
  approveBaseline,
  cancelValidationPlan,
  createValidationPlan as createValidationPlanService,
  executeValidationPlan,
  getScheduledPlans,
  listValidationPlans,
  orchestratorDelegationSurface,
  requestRetest,
} from '../../src/services/wafOrchestrator.mjs';
import { getStore, resetStoreForTests } from '../../src/store.mjs';

const envSnapshot = { ...process.env };
const ctx = { tenantId: 'ten_demo', userId: 'usr_demo', role: 'engineer' };
const WORKER_SECRET = 'probe-worker-secret-at-least-32-chars!!';

function restoreEnv() {
  for (const key of Object.keys(process.env)) {
    if (!(key in envSnapshot)) delete process.env[key];
  }
  Object.assign(process.env, envSnapshot);
}

function wafEnabledEnv() {
  process.env.ASTRANULL_NO_PERSIST = '1';
  process.env.ASTRANULL_WAF_POSTURE_ENABLED = '1';
  process.env.ASTRANULL_PROBE_MODE = 'signed-worker';
  process.env.ASTRANULL_PROBE_WORKER_SECRET = WORKER_SECRET;
}

function seedStore() {
  resetStoreForTests({
    tenants: [{ id: 'ten_demo', name: 'Demo' }],
    environments: [{ id: 'env_demo', tenant_id: 'ten_demo', name: 'Prod' }],
    targetGroups: [
      {
        id: 'tg_1',
        tenant_id: 'ten_demo',
        environment_id: 'env_demo',
        name: 'TG',
        expected_behavior_default: 'must_block_before_origin',
      },
    ],
    targets: [
      {
        id: 'tgt_1',
        tenant_id: 'ten_demo',
        target_group_id: 'tg_1',
        kind: 'fqdn',
        value: 'app.example.com',
        expected_behavior: 'must_block_before_origin',
      },
    ],
    wafAssets: [
      {
        id: 'waf_1',
        tenant_id: 'ten_demo',
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
        canonical_url: 'https://app.example.com',
        status: 'protected',
        expected_waf_required: true,
      },
    ],
    wafBaselines: [
      {
        id: 'baseline_1',
        tenant_id: 'ten_demo',
        waf_asset_id: 'waf_1',
        state: 'proposed',
        baseline_json: { expected_status: 'protected' },
        created_at: new Date().toISOString(),
      },
    ],
    wafDriftEvents: [
      {
        id: 'drift_1',
        tenant_id: 'ten_demo',
        waf_asset_id: 'waf_1',
        drift_type: 'marker_failed',
        severity: 'high',
        before_summary_json: { status: 'protected' },
        after_summary_json: { status: 'underprotected' },
        status: 'open',
        created_at: new Date().toISOString(),
      },
    ],
    wafValidationPlans: [],
    wafBaselineApprovals: [],
    wafRetestRequests: [],
    testRuns: [],
    probeJobs: [],
    auditLog: [],
  });
}

function basePlanFields(overrides = {}) {
  return {
    tenant_id: 'ten_demo',
    target_group_id: 'tg_1',
    mode: 'manual',
    scenarios: ['marker'],
    max_concurrent: 2,
    timeout_ms: 60_000,
    ...overrides,
  };
}

describe('WAF orchestrator contracts', () => {
  it('validates plan constraints for max concurrent and timeout', () => {
    const valid = validateOrchestratorPlan(basePlanFields());
    assert.equal(valid.max_concurrent, 2);
    assert.equal(valid.timeout_ms, 60_000);

    assert.throws(
      () => validateOrchestratorPlan(basePlanFields({ max_concurrent: 11 })),
      /max_concurrent must be an integer between 1 and 10/,
    );
    assert.throws(
      () => validateOrchestratorPlan(basePlanFields({ timeout_ms: 300_001 })),
      /timeout_ms must be an integer between 1000 and 300000/,
    );
  });

  it('rejects non-safe and attack-pattern scenarios', () => {
    assert.throws(
      () => validateOrchestratorPlan(basePlanFields({ scenarios: ['protocol_evasion_marker'] })),
      /not an approved safe scenario ID|requires SOC workflow/,
    );
    assert.throws(
      () => validateOrchestratorPlan(basePlanFields({ scenarios: ['ddos_flood_attack'] })),
      /prohibited attack\/exploit patterns/,
    );
    assert.throws(
      () => createValidationPlan(basePlanFields({ scenarios: ['exploit_payload'] })),
      /prohibited attack\/exploit patterns/,
    );
  });

  it('computes retest verdicts for resolved, persistent, and inconclusive cases', () => {
    const drift = {
      drift_type: 'marker_failed',
      before_summary_json: { status: 'protected' },
      after_summary_json: { status: 'underprotected' },
    };

    const resolved = computeRetestVerdict(
      {
        results: [
          {
            passed: true,
            observed_action: 'block',
            evidence_summary: { blocked: true, marker_result: 'blocked' },
          },
        ],
        validation_passed: true,
        posture_status: 'protected',
      },
      drift,
    );
    assert.equal(resolved.verdict, 'resolved');
    assert.equal(resolved.reason, 'posture_restored');

    const persistent = computeRetestVerdict(
      {
        results: [
          {
            passed: false,
            observed_action: 'allow',
            evidence_summary: { blocked: false, marker_result: 'allowed' },
          },
        ],
        validation_failed: true,
        posture_status: 'underprotected',
      },
      drift,
    );
    assert.equal(persistent.verdict, 'persistent');
    assert.equal(persistent.reason, 'drift_confirmed');

    const inconclusive = computeRetestVerdict({ results: [] }, drift);
    assert.equal(inconclusive.verdict, 'inconclusive');
    assert.equal(inconclusive.reason, 'insufficient_evidence');
  });

  it('normalizes baseline approval and retest request shapes', () => {
    const approval = createBaselineApproval({
      baseline_id: 'baseline_1',
      approver: 'sec-lead',
      approval_notes: 'Approved protected marker baseline.',
      fingerprint_summary: { block_page_fingerprint_hash: 'sha256:abc' },
    });
    assert.equal(approval.approver, 'sec-lead');
    assert.equal(approval.fingerprint_summary.block_page_fingerprint_hash, 'sha256:abc');

    const retest = createRetestRequest({
      drift_event_id: 'drift_1',
      retest_plan: ['marker'],
      requested_by: 'usr_demo',
      priority: 'high',
    });
    assert.deepEqual(retest.retest_plan, ['marker']);
    assert.equal(retest.priority, 'high');
  });
});

describe('WAF orchestrator service', () => {
  beforeEach(() => {
    restoreEnv();
    wafEnabledEnv();
    seedStore();
  });

  afterEach(restoreEnv);

  it('creates validation plans and enforces safe scenario constraints', () => {
    const created = createValidationPlanService(ctx, {
      target_group_id: 'tg_1',
      mode: 'scheduled',
      schedule_interval: 'daily',
      scenarios: ['marker', 'fingerprint'],
      max_concurrent: 3,
      timeout_ms: 90_000,
    });
    assert.ok(created.validation_plan);
    assert.equal(created.validation_plan.state, 'scheduled');
    assert.equal(created.validation_plan.scenarios.length, 2);

    const rejected = createValidationPlanService(ctx, {
      target_group_id: 'tg_1',
      scenarios: ['amplification_attack'],
      max_concurrent: 1,
    });
    assert.equal(rejected.error, 'unsafe_orchestrator_plan');

    const audit = getStore().auditLog.find((e) => e.action === 'waf.validation_plan.created');
    assert.ok(audit);
    assert.equal(audit.metadata.target_group_id, 'tg_1');
  });

  it('returns only scheduled-state plans from getScheduledPlans', () => {
    createValidationPlanService(ctx, {
      target_group_id: 'tg_1',
      mode: 'manual',
      scenarios: ['marker'],
    });
    createValidationPlanService(ctx, {
      target_group_id: 'tg_1',
      mode: 'scheduled',
      schedule_interval: 'weekly',
      scenarios: ['marker'],
    });

    const scheduled = getScheduledPlans(ctx);
    assert.equal(scheduled.plans.length, 1);
    assert.equal(scheduled.plans[0].state, 'scheduled');
    assert.equal(scheduled.plans[0].schedule_interval, 'weekly');

    const all = listValidationPlans(ctx);
    assert.equal(all.plans.length, 2);
  });

  it('approves baselines and records approver in audit log', () => {
    const result = approveBaseline(ctx, 'baseline_1', {
      approver: 'sec-lead',
      approval_notes: 'Customer confirmed marker baseline.',
      fingerprint_summary: { waf_product_hint: 'cloudflare' },
    });
    assert.equal(result.baseline.state, 'active');
    assert.equal(result.baseline.approved_by, 'sec-lead');

    const audit = getStore().auditLog.find((e) => e.action === 'waf.baseline.approved');
    assert.ok(audit);
    assert.equal(audit.metadata.approver, 'sec-lead');
    assert.equal(audit.resource_id, 'baseline_1');
  });

  it('cancels plans, updates state, and audits cancellation', () => {
    const created = createValidationPlanService(ctx, {
      target_group_id: 'tg_1',
      mode: 'scheduled',
      schedule_interval: 'daily',
      scenarios: ['marker'],
    });
    const planId = created.validation_plan.id;

    const cancelled = cancelValidationPlan(ctx, planId);
    assert.equal(cancelled.validation_plan.state, 'cancelled');
    assert.ok(cancelled.validation_plan.cancelled_at);

    const audit = getStore().auditLog.find((e) => e.action === 'waf.validation_plan.cancelled');
    assert.ok(audit);
    assert.equal(audit.resource_id, planId);
    assert.equal(audit.metadata.previous_state, 'scheduled');
  });

  it('delegates validation execution to probe coordinator without direct traffic generation', () => {
    const surface = orchestratorDelegationSurface();
    assert.equal(surface.uses_probe_coordinator, true);
    assert.equal(surface.avoids_direct_traffic_stub, true);

    const created = createValidationPlanService(ctx, {
      target_group_id: 'tg_1',
      scenarios: ['marker', 'fingerprint'],
      max_concurrent: 2,
      timeout_ms: 45_000,
    });
    const runtimeConfig = loadRuntimeConfig();
    const beforeJobs = getStore().probeJobs.length;

    const executed = executeValidationPlan(ctx, created.validation_plan.id, runtimeConfig);
    assert.equal(executed.validation_plan.state, 'completed');
    assert.equal(executed.delegated_jobs.length, 2);
    assert.equal(getStore().probeJobs.length, beforeJobs + 2);

    const audit = getStore().auditLog.find((e) => e.action === 'waf.validation_plan.executed');
    assert.ok(audit);
    assert.equal(audit.metadata.delegated_job_count, 2);
    assert.ok(Array.isArray(audit.metadata.probe_job_ids));
  });

  it('returns waf_feature_disabled when feature flag is off', () => {
    delete process.env.ASTRANULL_WAF_POSTURE_ENABLED;

    assert.deepEqual(listValidationPlans(ctx), {
      error: 'waf_feature_disabled',
      status: 404,
    });
    assert.deepEqual(
      createValidationPlanService(ctx, { target_group_id: 'tg_1', scenarios: ['marker'] }),
      { error: 'waf_feature_disabled', status: 404 },
    );
    assert.deepEqual(getScheduledPlans(ctx), { error: 'waf_feature_disabled', status: 404 });
  });

  it('creates retest requests with audit metadata', () => {
    const requested = requestRetest(ctx, 'drift_1', {
      retest_plan: ['marker'],
      requested_by: 'usr_demo',
      priority: 'urgent',
    });
    assert.equal(requested.retest_request.status, 'requested');
    assert.deepEqual(requested.retest_request.retest_plan, ['marker']);

    const drift = getStore().wafDriftEvents.find((e) => e.id === 'drift_1');
    assert.equal(drift.status, 'retest_pending');

    const audit = getStore().auditLog.find((e) => e.action === 'waf.retest.requested');
    assert.ok(audit);
    assert.equal(audit.metadata.requested_by, 'usr_demo');
    assert.equal(audit.metadata.priority, 'urgent');
  });
});