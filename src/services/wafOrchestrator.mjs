import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { audit } from '../audit.mjs';
import { loadRuntimeConfig } from '../config.mjs';
import { getCheckById, WAF_SAFE_CHECK_IDS } from '../contracts/checks.mjs';
import {
  createBaselineApproval,
  createRetestRequest,
  createValidationPlan as normalizeValidationPlan,
  computeRetestVerdict,
  validateOrchestratorPlan,
} from '../contracts/wafOrchestrator.mjs';
import { newId } from '../lib/ids.mjs';
import {
  buildOrchestratorWorkQueue,
  buildRetestResultsFromDelegatedRuns,
  DELEGATION_STATUS,
  filterPendingWorkItems,
  reconcileStaleDelegations,
  upsertDelegationJobByReservation,
} from '../persistence/postgres/wafOrchestratorServiceAdapters.mjs';
import { getStore, persistStore } from '../store.mjs';
import { cancelTestRun, getTestRun, startTestRun } from './testRuns.mjs';

const SCENARIO_TO_CHECK = Object.freeze({
  marker: 'waf.marker_rule.safe',
  fingerprint: 'waf.fingerprint.safe',
  sqli_marker: 'waf.marker_rule.safe',
  xss_marker: 'waf.marker_rule.safe',
  rce_marker: 'waf.marker_rule.safe',
  path_traversal_marker: 'waf.marker_rule.safe',
  rate_limit_marker: 'waf.low_rate_limit.safe',
  origin_bypass: 'waf.origin_bypass.safe',
});

const CANCELLABLE_STATES = new Set(['draft', 'scheduled', 'running']);
const BASELINE_APPROVABLE_STATES = new Set(['proposed', 'draft']);
const WAF_SAFE_CHECK_ID_SET = new Set(WAF_SAFE_CHECK_IDS);

function wafFeatureDisabled() {
  const { featureFlags } = loadRuntimeConfig();
  return featureFlags.wafPostureEnabled !== true;
}

function featureDisabledResponse() {
  return { error: 'waf_feature_disabled', status: 404 };
}

function contractError(err, fallbackStatus = 400) {
  return {
    error: err.code ?? 'invalid_request',
    status: fallbackStatus,
    message: err.message,
  };
}

function ensureStoreShape() {
  const store = getStore();
  const keys = [
    'wafValidationPlans',
    'wafBaselineApprovals',
    'wafRetestRequests',
    'wafBaselines',
    'wafAssets',
    'wafDriftEvents',
    'testRuns',
    'probeJobs',
  ];
  for (const key of keys) {
    if (!Array.isArray(store[key])) store[key] = [];
  }
  return store;
}

function findPlan(ctx, planId) {
  ensureStoreShape();
  return (
    getStore().wafValidationPlans.find(
      (p) => p.id === planId && p.tenant_id === ctx.tenantId,
    ) ?? null
  );
}

function findBaseline(ctx, baselineId) {
  ensureStoreShape();
  return (
    getStore().wafBaselines.find(
      (b) => b.id === baselineId && b.tenant_id === ctx.tenantId,
    ) ?? null
  );
}

function findDriftEvent(ctx, driftEventId) {
  ensureStoreShape();
  return (
    getStore().wafDriftEvents.find(
      (e) => e.id === driftEventId && e.tenant_id === ctx.tenantId,
    ) ?? null
  );
}

function findRetestRequest(ctx, retestId) {
  ensureStoreShape();
  return (
    getStore().wafRetestRequests.find(
      (r) => r.id === retestId && r.tenant_id === ctx.tenantId,
    ) ?? null
  );
}

function targetGroupExists(ctx, targetGroupId) {
  return getStore().targetGroups.some(
    (g) => g.id === targetGroupId && g.tenant_id === ctx.tenantId,
  );
}

function assetsForTargetGroup(ctx, targetGroupId) {
  ensureStoreShape();
  return getStore().wafAssets.filter(
    (a) => a.tenant_id === ctx.tenantId && a.target_group_id === targetGroupId,
  );
}

function targetsForTargetGroup(ctx, targetGroupId) {
  return getStore().targets.filter(
    (t) => t.tenant_id === ctx.tenantId && t.target_group_id === targetGroupId,
  );
}

export function formatRetestRequest(record) {
  if (!record) return null;
  return {
    id: record.id,
    drift_event_id: record.drift_event_id,
    waf_asset_id: record.waf_asset_id,
    retest_plan: record.retest_plan ?? [],
    requested_by: record.requested_by,
    priority: record.priority,
    status: record.status,
    ...(record.verdict ? { verdict: record.verdict } : {}),
    ...(record.verdict_reason ? { verdict_reason: record.verdict_reason } : {}),
    ...(Array.isArray(record.delegated_jobs) && record.delegated_jobs.length > 0
      ? { delegated_jobs: record.delegated_jobs }
      : {}),
    created_at: record.created_at,
    ...(record.updated_at ? { updated_at: record.updated_at } : {}),
    ...(record.completed_at ? { completed_at: record.completed_at } : {}),
  };
}

function formatValidationPlan(record) {
  return {
    id: record.id,
    target_group_id: record.target_group_id,
    mode: record.mode,
    state: record.state,
    scenarios: record.scenarios ?? [],
    max_concurrent: record.max_concurrent,
    timeout_ms: record.timeout_ms,
    ...(record.schedule_interval ? { schedule_interval: record.schedule_interval } : {}),
    ...(record.custom_cron_expression
      ? { custom_cron_expression: record.custom_cron_expression }
      : {}),
    ...(Array.isArray(record.delegated_jobs) ? { delegated_jobs: record.delegated_jobs } : {}),
    created_at: record.created_at,
    ...(record.updated_at ? { updated_at: record.updated_at } : {}),
    ...(record.executed_at ? { executed_at: record.executed_at } : {}),
    ...(record.cancelled_at ? { cancelled_at: record.cancelled_at } : {}),
  };
}

function scenarioCheckId(scenarioId) {
  return SCENARIO_TO_CHECK[scenarioId] ?? null;
}

function validateWorkItemPreflight({ asset, scenario }, targets) {
  const checkId = scenarioCheckId(scenario);
  const check = checkId ? getCheckById(checkId) : null;
  if (!check || !WAF_SAFE_CHECK_ID_SET.has(check.check_id)) {
    return {
      error: 'validation_plan_execution_failed',
      status: 422,
      message: 'Scenario does not map to an allowed safe WAF check.',
    };
  }

  const targetId = asset.target_id;
  if (!targetId || !targets.some((t) => t.id === targetId)) {
    return {
      error: 'validation_plan_execution_failed',
      status: 422,
      message:
        'WAF asset must declare a target_id that matches a target in the plan target group.',
    };
  }

  return { check };
}

function preflightWorkItems(pendingItems, targets) {
  for (const item of pendingItems) {
    const preflight = validateWorkItemPreflight(item, targets);
    if (preflight.error) {
      return preflight;
    }
  }
  return null;
}

function delegateOneWorkItemViaStartTestRun(
  ctx,
  { asset, scenario, targetGroupId, timeoutMs },
  runtimeConfig,
) {
  const targets = targetsForTargetGroup(ctx, targetGroupId);
  const preflight = validateWorkItemPreflight({ asset, scenario }, targets);
  if (preflight.error) {
    return preflight;
  }

  const { check } = preflight;
  const startResult = startTestRun(
    ctx,
    {
      check_id: check.check_id,
      target_group_id: targetGroupId,
      target_id: asset.target_id,
      probe_profile: {
        scenario_family: scenario,
        timeout_ms: Math.min(
          timeoutMs,
          Number(check.probe_profile?.timeout_ms ?? timeoutMs),
        ),
      },
      waf_orchestration: true,
    },
    runtimeConfig,
  );

  if (startResult?.error) {
    return startResult;
  }

  const testRunId = startResult.run?.id;
  const probeJobId = startResult.probe_job?.id;
  if (!testRunId || !probeJobId) {
    return {
      error: 'validation_plan_execution_failed',
      status: 422,
      message: 'Delegated test run did not return probe job identifiers.',
    };
  }

  return {
    delegated: {
      test_run_id: testRunId,
      probe_job_id: probeJobId,
      scenario,
      waf_asset_id: asset.id,
      check_id: check.check_id,
    },
  };
}

export function listValidationPlans(ctx) {
  if (wafFeatureDisabled()) return featureDisabledResponse();
  ensureStoreShape();
  const plans = getStore()
    .wafValidationPlans.filter((p) => p.tenant_id === ctx.tenantId)
    .map((p) => formatValidationPlan(p));
  return { plans };
}

function normalizeListFilter(value) {
  return typeof value === 'string' && value.trim() ? value.trim() : null;
}

export function listRetests(ctx, filters = {}) {
  if (wafFeatureDisabled()) return featureDisabledResponse();
  ensureStoreShape();
  const driftEventId = normalizeListFilter(filters.drift_event_id);
  const wafAssetId = normalizeListFilter(filters.waf_asset_id);
  const status = normalizeListFilter(filters.status);
  let items = getStore().wafRetestRequests.filter((r) => r.tenant_id === ctx.tenantId);
  if (driftEventId) {
    items = items.filter((r) => r.drift_event_id === driftEventId);
  }
  if (wafAssetId) {
    items = items.filter((r) => r.waf_asset_id === wafAssetId);
  }
  if (status) {
    items = items.filter((r) => r.status === status);
  }
  items.sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
  return { items: items.map((r) => formatRetestRequest(r)) };
}

export function createValidationPlan(ctx, body = {}) {
  if (wafFeatureDisabled()) return featureDisabledResponse();
  ensureStoreShape();
  try {
    const normalized = normalizeValidationPlan({
      ...body,
      tenant_id: ctx.tenantId,
    });
    if (!targetGroupExists(ctx, normalized.target_group_id)) {
      return {
        error: 'target_group_not_found',
        status: 404,
        message: 'Target group not found for tenant.',
      };
    }

    const id = newId('id');
    const now = new Date().toISOString();
    const record = {
      id,
      ...normalized,
      delegated_jobs: [],
      created_at: now,
      updated_at: now,
    };
    getStore().wafValidationPlans.push(record);

    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'waf.validation_plan.created',
      resource_type: 'waf_validation_plan',
      resource_id: id,
      metadata: {
        target_group_id: record.target_group_id,
        mode: record.mode,
        scenarios: record.scenarios,
        state: record.state,
      },
    });
    persistStore();
    return { validation_plan: formatValidationPlan(record) };
  } catch (err) {
    return contractError(err);
  }
}

export function executeValidationPlan(ctx, planId, runtimeConfig = loadRuntimeConfig()) {
  if (wafFeatureDisabled()) return featureDisabledResponse();
  ensureStoreShape();

  const plan = findPlan(ctx, planId);
  if (!plan) {
    return { error: 'validation_plan_not_found', status: 404 };
  }
  if (plan.state === 'completed') {
    return { error: 'validation_plan_already_completed', status: 409 };
  }
  if (plan.state === 'cancelled') {
    return { error: 'validation_plan_cancelled', status: 409 };
  }

  try {
    validateOrchestratorPlan(plan);
  } catch (err) {
    return contractError(err);
  }

  if (runtimeConfig.probeMode !== 'signed-worker') {
    return {
      error: 'waf_orchestrator_signed_worker_required',
      status: 422,
      message:
        'WAF orchestration requires signed probe-worker mode (runtimeConfig.probeMode === "signed-worker").',
    };
  }

  const targets = targetsForTargetGroup(ctx, plan.target_group_id);
  if (targets.length === 0) {
    return {
      error: 'validation_plan_execution_failed',
      status: 422,
      message: 'Target group has no declared targets for WAF orchestration.',
    };
  }

  const assets = assetsForTargetGroup(ctx, plan.target_group_id);
  const workQueue = buildOrchestratorWorkQueue(assets, plan.scenarios);
  if (workQueue.length === 0) {
    return {
      error: 'validation_plan_execution_failed',
      status: 422,
      message: 'No WAF assets or probe jobs could be delegated for this plan.',
    };
  }
  if (workQueue.length > plan.max_concurrent) {
    return {
      error: 'waf_orchestration_batch_too_large',
      status: 422,
      message: `Plan would delegate ${workQueue.length} jobs, exceeding max_concurrent of ${plan.max_concurrent}.`,
    };
  }

  const planPreflightError = preflightWorkItems(workQueue, targets);
  if (planPreflightError) {
    return planPreflightError;
  }

  const now = new Date().toISOString();
  if (plan.state === 'draft' || plan.state === 'scheduled') {
    plan.state = 'running';
  }

  let workingDelegatedJobs = Array.isArray(plan.delegated_jobs) ? [...plan.delegated_jobs] : [];
  const reconciliation = reconcileStaleDelegations(workingDelegatedJobs, now);
  if (reconciliation.reconciled_count > 0) {
    for (const runId of reconciliation.runs_to_cancel) {
      cancelTestRun(ctx, runId);
    }
    workingDelegatedJobs = reconciliation.delegated_jobs;
  }

  const pendingItems = filterPendingWorkItems(workQueue, workingDelegatedJobs);
  if (pendingItems.length === 0) {
    plan.delegated_jobs = workingDelegatedJobs;
    plan.state = 'completed';
    plan.executed_at = plan.executed_at ?? now;
    plan.updated_at = now;
    persistStore();
    return {
      validation_plan: formatValidationPlan(plan),
      delegated_jobs: workingDelegatedJobs,
    };
  }

  const item = pendingItems[0];
  const checkId = scenarioCheckId(item.scenario);
  const reservationId = newId('res');
  const pendingJob = {
    status: DELEGATION_STATUS.PENDING_START,
    reservation_id: reservationId,
    scenario: item.scenario,
    waf_asset_id: item.asset.id,
    check_id: checkId,
    reserved_at: now,
  };
  workingDelegatedJobs = upsertDelegationJobByReservation(
    workingDelegatedJobs,
    reservationId,
    pendingJob,
  );
  plan.delegated_jobs = workingDelegatedJobs;
  plan.updated_at = now;
  persistStore();

  const delegation = delegateOneWorkItemViaStartTestRun(
    ctx,
    {
      asset: item.asset,
      scenario: item.scenario,
      targetGroupId: plan.target_group_id,
      timeoutMs: plan.timeout_ms,
    },
    runtimeConfig,
  );

  if (delegation.error) {
    const failedJob = {
      ...pendingJob,
      status: DELEGATION_STATUS.FAILED,
      failed_at: now,
      failure_reason: delegation.error,
    };
    workingDelegatedJobs = upsertDelegationJobByReservation(
      workingDelegatedJobs,
      reservationId,
      failedJob,
    );
    plan.delegated_jobs = workingDelegatedJobs;
    plan.updated_at = now;
    persistStore();
    return {
      error: delegation.error,
      status: delegation.status ?? 422,
      ...(delegation.message ? { message: delegation.message } : {}),
      ...(delegation.missing ? { missing: delegation.missing } : {}),
    };
  }

  const delegatedJob = {
    status: DELEGATION_STATUS.DELEGATED,
    reservation_id: reservationId,
    test_run_id: delegation.delegated.test_run_id,
    probe_job_id: delegation.delegated.probe_job_id,
    scenario: delegation.delegated.scenario,
    waf_asset_id: delegation.delegated.waf_asset_id,
    check_id: delegation.delegated.check_id,
    delegated_at: now,
  };
  workingDelegatedJobs = upsertDelegationJobByReservation(
    workingDelegatedJobs,
    reservationId,
    delegatedJob,
  );

  const pendingAfter = filterPendingWorkItems(workQueue, workingDelegatedJobs);
  const allDelegated = pendingAfter.length === 0;

  plan.delegated_jobs = workingDelegatedJobs;
  plan.state = allDelegated ? 'completed' : 'running';
  if (allDelegated || !plan.executed_at) {
    plan.executed_at = now;
  }
  plan.updated_at = now;

  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'waf.validation_plan.executed',
    resource_type: 'waf_validation_plan',
    resource_id: plan.id,
    metadata: {
      target_group_id: plan.target_group_id,
      delegated_job_count: workingDelegatedJobs.length,
      new_delegated_job_count: 1,
      test_run_ids: workingDelegatedJobs.map((j) => j.test_run_id).filter(Boolean),
      probe_job_ids: workingDelegatedJobs.map((j) => j.probe_job_id).filter(Boolean),
      plan_state: plan.state,
    },
  });
  persistStore();

  return {
    validation_plan: formatValidationPlan(plan),
    delegated_jobs: workingDelegatedJobs,
    ...(allDelegated ? {} : { continuation_required: true }),
  };
}

export function cancelValidationPlan(ctx, planId) {
  if (wafFeatureDisabled()) return featureDisabledResponse();
  ensureStoreShape();

  const plan = findPlan(ctx, planId);
  if (!plan) {
    return { error: 'validation_plan_not_found', status: 404 };
  }
  if (!CANCELLABLE_STATES.has(plan.state)) {
    return {
      error: 'validation_plan_not_cancellable',
      status: 409,
      message: `Plan in state ${plan.state} cannot be cancelled.`,
    };
  }

  const previousState = plan.state;
  const now = new Date().toISOString();
  plan.state = 'cancelled';
  plan.cancelled_at = now;
  plan.updated_at = now;

  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'waf.validation_plan.cancelled',
    resource_type: 'waf_validation_plan',
    resource_id: plan.id,
    metadata: {
      target_group_id: plan.target_group_id,
      previous_state: previousState,
    },
  });
  persistStore();

  return { validation_plan: formatValidationPlan(plan) };
}

export function approveBaseline(ctx, baselineId, body = {}) {
  if (wafFeatureDisabled()) return featureDisabledResponse();
  ensureStoreShape();

  const baseline = findBaseline(ctx, baselineId);
  if (!baseline) {
    return { error: 'waf_baseline_not_found', status: 404 };
  }
  if (!BASELINE_APPROVABLE_STATES.has(baseline.state)) {
    return {
      error: 'waf_baseline_not_approvable',
      status: 409,
      message: `Baseline in state ${baseline.state} cannot be approved.`,
    };
  }

  try {
    const approval = createBaselineApproval({
      baseline_id: baselineId,
      ...body,
    });
    const approvalId = newId('id');
    const now = new Date().toISOString();
    const record = {
      id: approvalId,
      tenant_id: ctx.tenantId,
      waf_asset_id: baseline.waf_asset_id,
      ...approval,
      created_at: now,
    };
    getStore().wafBaselineApprovals.push(record);

    baseline.state = 'active';
    baseline.approved_by = approval.approver;
    baseline.approved_at = approval.approved_at;
    baseline.updated_at = now;

    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'waf.baseline.approved',
      resource_type: 'waf_baseline',
      resource_id: baselineId,
      metadata: {
        approver: approval.approver,
        waf_asset_id: baseline.waf_asset_id,
        fingerprint_summary: approval.fingerprint_summary,
      },
    });
    persistStore();

    return {
      baseline: {
        id: baseline.id,
        waf_asset_id: baseline.waf_asset_id,
        state: baseline.state,
        approved_by: baseline.approved_by,
        approved_at: baseline.approved_at,
      },
      approval: record,
    };
  } catch (err) {
    return contractError(err);
  }
}

export function requestRetest(ctx, driftEventId, body = {}) {
  if (wafFeatureDisabled()) return featureDisabledResponse();
  ensureStoreShape();

  const driftEvent = findDriftEvent(ctx, driftEventId);
  if (!driftEvent) {
    return { error: 'waf_drift_event_not_found', status: 404 };
  }

  try {
    const normalized = createRetestRequest({
      drift_event_id: driftEventId,
      ...body,
    });
    const id = newId('id');
    const now = new Date().toISOString();
    const record = {
      id,
      tenant_id: ctx.tenantId,
      waf_asset_id: driftEvent.waf_asset_id,
      status: 'requested',
      ...normalized,
      created_at: now,
      updated_at: now,
    };
    getStore().wafRetestRequests.push(record);

    if (driftEvent.status === 'open' || driftEvent.status === 'acknowledged') {
      driftEvent.status = 'retest_pending';
      driftEvent.updated_at = now;
    }

    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'waf.retest.requested',
      resource_type: 'waf_retest_request',
      resource_id: id,
      metadata: {
        drift_event_id: driftEventId,
        retest_plan: normalized.retest_plan,
        priority: normalized.priority,
        requested_by: normalized.requested_by,
      },
    });
    persistStore();

    return { retest_request: record };
  } catch (err) {
    return contractError(err);
  }
}

function delegatedScenarioKeys(delegatedJobs = []) {
  return new Set(
    (delegatedJobs ?? [])
      .filter((job) => job?.scenario && (job.test_run_id || job.status === DELEGATION_STATUS.FAILED))
      .map((job) => job.scenario),
  );
}

function pendingRetestScenarios(retestPlan, delegatedJobs = []) {
  const blocked = delegatedScenarioKeys(delegatedJobs);
  return (retestPlan ?? []).filter((scenario) => !blocked.has(scenario));
}

export function executeRetest(ctx, retestId, _body = {}, runtimeConfig = loadRuntimeConfig()) {
  if (wafFeatureDisabled()) return featureDisabledResponse();
  ensureStoreShape();

  const retest = findRetestRequest(ctx, retestId);
  if (!retest) {
    return { error: 'waf_retest_not_found', status: 404 };
  }
  if (retest.status === 'completed') {
    return { error: 'waf_retest_already_completed', status: 409 };
  }
  if (retest.status === 'delegated') {
    return { error: 'waf_retest_already_delegated', status: 409 };
  }

  const driftEvent = findDriftEvent(ctx, retest.drift_event_id);
  if (!driftEvent) {
    return { error: 'waf_drift_event_not_found', status: 404 };
  }

  const asset = getStore().wafAssets.find(
    (a) => a.id === driftEvent.waf_asset_id && a.tenant_id === ctx.tenantId,
  );
  if (!asset) {
    return { error: 'waf_asset_not_found', status: 404 };
  }

  const retestPlan = retest.retest_plan ?? [];
  if (retestPlan.length === 0) {
    return {
      error: 'validation_plan_execution_failed',
      status: 422,
      message: 'Retest plan has no scenarios to delegate.',
    };
  }

  const now = new Date().toISOString();
  let workingDelegatedJobs = Array.isArray(retest.delegated_jobs) ? [...retest.delegated_jobs] : [];
  const reconciliation = reconcileStaleDelegations(workingDelegatedJobs, now);
  if (reconciliation.reconciled_count > 0) {
    for (const runId of reconciliation.runs_to_cancel) {
      cancelTestRun(ctx, runId);
    }
    workingDelegatedJobs = reconciliation.delegated_jobs;
  }

  const pendingScenarios = pendingRetestScenarios(retestPlan, workingDelegatedJobs);
  if (pendingScenarios.length === 0) {
    retest.status = 'delegated';
    retest.delegated_jobs = workingDelegatedJobs;
    retest.updated_at = now;
    persistStore();
    return {
      retest_request: formatRetestRequest(retest),
      delegated_jobs: workingDelegatedJobs,
    };
  }

  const scenario = pendingScenarios[0];
  const checkId = scenarioCheckId(scenario);
  const reservationId = newId('res');
  const pendingJob = {
    status: DELEGATION_STATUS.PENDING_START,
    reservation_id: reservationId,
    scenario,
    waf_asset_id: asset.id,
    check_id: checkId,
    reserved_at: now,
  };
  workingDelegatedJobs = upsertDelegationJobByReservation(
    workingDelegatedJobs,
    reservationId,
    pendingJob,
  );
  retest.status = 'running';
  retest.delegated_jobs = workingDelegatedJobs;
  retest.updated_at = now;
  persistStore();

  if (runtimeConfig.probeMode !== 'signed-worker') {
    return {
      error: 'waf_orchestrator_signed_worker_required',
      status: 422,
      message:
        'WAF orchestration requires signed probe-worker mode (runtimeConfig.probeMode === "signed-worker").',
    };
  }

  const delegation = delegateOneWorkItemViaStartTestRun(
    ctx,
    {
      asset,
      scenario,
      targetGroupId: asset.target_group_id,
      timeoutMs: 60_000,
    },
    runtimeConfig,
  );

  if (delegation.error) {
    const failedJob = {
      ...pendingJob,
      status: DELEGATION_STATUS.FAILED,
      failed_at: now,
      failure_reason: delegation.error,
    };
    workingDelegatedJobs = upsertDelegationJobByReservation(
      workingDelegatedJobs,
      reservationId,
      failedJob,
    );
    retest.delegated_jobs = workingDelegatedJobs;
    retest.updated_at = now;
    persistStore();
    return {
      error: delegation.error,
      status: delegation.status ?? 422,
      ...(delegation.message ? { message: delegation.message } : {}),
      ...(delegation.missing ? { missing: delegation.missing } : {}),
    };
  }

  const delegatedJob = {
    status: DELEGATION_STATUS.DELEGATED,
    reservation_id: reservationId,
    test_run_id: delegation.delegated.test_run_id,
    probe_job_id: delegation.delegated.probe_job_id,
    scenario: delegation.delegated.scenario,
    waf_asset_id: delegation.delegated.waf_asset_id,
    check_id: delegation.delegated.check_id,
    delegated_at: now,
  };
  workingDelegatedJobs = upsertDelegationJobByReservation(
    workingDelegatedJobs,
    reservationId,
    delegatedJob,
  );

  const allDelegated = pendingRetestScenarios(retestPlan, workingDelegatedJobs).length === 0;
  retest.status = allDelegated ? 'delegated' : 'running';
  retest.delegated_jobs = workingDelegatedJobs;
  retest.updated_at = now;

  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'waf.retest.delegated',
    resource_type: 'waf_retest_request',
    resource_id: retest.id,
    metadata: {
      drift_event_id: retest.drift_event_id,
      delegated_job_count: workingDelegatedJobs.length,
      new_delegated_job_count: 1,
      test_run_ids: workingDelegatedJobs.map((j) => j.test_run_id).filter(Boolean),
      probe_job_ids: workingDelegatedJobs.map((j) => j.probe_job_id).filter(Boolean),
      retest_status: retest.status,
    },
  });
  persistStore();

  return {
    retest_request: formatRetestRequest(retest),
    delegated_jobs: workingDelegatedJobs,
    ...(allDelegated ? {} : { continuation_required: true }),
  };
}

export function completeRetest(ctx, retestId) {
  if (wafFeatureDisabled()) return featureDisabledResponse();
  ensureStoreShape();

  const retest = findRetestRequest(ctx, retestId);
  if (!retest) {
    return { error: 'waf_retest_not_found', status: 404 };
  }
  if (retest.status === 'completed') {
    return { error: 'waf_retest_already_completed', status: 409 };
  }
  if (retest.status !== 'delegated') {
    return {
      error: 'waf_retest_closure_not_ready',
      status: 422,
      message: 'Retest must finish delegation before evidence-backed closure.',
    };
  }

  const delegatedJobs = Array.isArray(retest.delegated_jobs) ? retest.delegated_jobs : [];
  if (delegatedJobs.length === 0) {
    return {
      error: 'waf_retest_closure_not_ready',
      status: 422,
      message: 'Retest has no delegated jobs to close against.',
    };
  }

  const driftEvent = findDriftEvent(ctx, retest.drift_event_id);
  if (!driftEvent) {
    return { error: 'waf_drift_event_not_found', status: 404 };
  }

  const runsById = {};
  for (const job of delegatedJobs) {
    const run = getTestRun(ctx, job.test_run_id);
    if (!run) {
      return {
        error: 'waf_retest_closure_not_ready',
        status: 422,
        message: 'Delegated test run evidence is not available yet.',
      };
    }
    runsById[job.test_run_id] = run;
  }

  const retestResults = buildRetestResultsFromDelegatedRuns(delegatedJobs, runsById);
  if (!retestResults) {
    return {
      error: 'waf_retest_closure_not_ready',
      status: 422,
      message: 'Delegated test runs are not finalized with verdict evidence yet.',
    };
  }

  const verdict = computeRetestVerdict(retestResults, driftEvent);
  const now = new Date().toISOString();

  retest.status = 'completed';
  retest.verdict = verdict.verdict;
  retest.verdict_reason = verdict.reason;
  retest.delegated_jobs = delegatedJobs;
  retest.completed_at = now;
  retest.updated_at = now;

  if (verdict.verdict === 'resolved') {
    driftEvent.status = 'resolved';
    driftEvent.resolved_at = now;
    driftEvent.updated_at = now;
  } else if (verdict.verdict === 'persistent') {
    driftEvent.status = 'open';
    driftEvent.updated_at = now;
  }

  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'waf.retest.completed',
    resource_type: 'waf_retest_request',
    resource_id: retest.id,
    metadata: {
      drift_event_id: retest.drift_event_id,
      verdict: verdict.verdict,
      verdict_reason: verdict.reason,
      delegated_job_count: delegatedJobs.length,
      test_run_ids: delegatedJobs.map((j) => j.test_run_id),
      probe_job_ids: delegatedJobs.map((j) => j.probe_job_id),
    },
  });
  persistStore();

  return {
    retest_request: formatRetestRequest(retest),
    verdict,
    delegated_jobs: delegatedJobs,
  };
}

export function getScheduledPlans(ctx) {
  if (wafFeatureDisabled()) return featureDisabledResponse();
  ensureStoreShape();
  const plans = getStore()
    .wafValidationPlans.filter(
      (p) => p.tenant_id === ctx.tenantId && p.state === 'scheduled',
    )
    .map((p) => formatValidationPlan(p));
  return { plans };
}

/** Test hook: confirms orchestrator delegates via probe coordinator only. */
export function orchestratorDelegationSurface() {
  const selfPath = fileURLToPath(import.meta.url);
  const source = readFileSync(selfPath, 'utf8');
  return {
    uses_start_test_run_safe_path: /from\s+['"]\.\/testRuns\.mjs['"]/.test(source)
      && /startTestRun\s*\(/.test(source),
    avoids_direct_probe_job_creation:
      !/createProbeJob\s*\(/.test(source),
    avoids_direct_traffic_stub:
      !/from\s+['"].*probeStub/.test(source)
      && !/simulateProbeResult\s*\(/.test(source),
  };
}