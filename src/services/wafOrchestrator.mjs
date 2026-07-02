import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { audit } from '../audit.mjs';
import { loadRuntimeConfig } from '../config.mjs';
import { getCheckById } from '../contracts/checks.mjs';
import {
  createBaselineApproval,
  createRetestRequest,
  createValidationPlan as normalizeValidationPlan,
  computeRetestVerdict,
  validateOrchestratorPlan,
} from '../contracts/wafOrchestrator.mjs';
import { newId } from '../lib/ids.mjs';
import { getStore, persistStore } from '../store.mjs';
import { createProbeJob } from './probeCoordinator.mjs';

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

function delegateScenariosToProbeCoordinator(ctx, {
  targetGroupId,
  scenarios,
  maxConcurrent,
  timeoutMs,
  wafAssetId = null,
}, runtimeConfig) {
  const assets = wafAssetId
    ? assetsForTargetGroup(ctx, targetGroupId).filter((a) => a.id === wafAssetId)
    : assetsForTargetGroup(ctx, targetGroupId);
  const targets = targetsForTargetGroup(ctx, targetGroupId);
  if (assets.length === 0 || targets.length === 0) {
    return [];
  }

  const delegated = [];
  const scenarioBatch = scenarios.slice(0, maxConcurrent);

  for (const asset of assets) {
    const target =
      targets.find((t) => asset.target_id && t.id === asset.target_id) ?? targets[0];
    if (!target) continue;

    for (const scenario of scenarioBatch) {
      const checkId = scenarioCheckId(scenario);
      const check = checkId ? getCheckById(checkId) : null;
      if (!check) continue;

      const runId = newId('run');
      const now = new Date().toISOString();
      const run = {
        id: runId,
        tenant_id: ctx.tenantId,
        target_group_id: targetGroupId,
        target_id: target.id,
        check_id: check.check_id,
        vector_family: check.vector_family,
        safety_class: check.safety_class ?? check.risk_class,
        safety_constraints: check.safety_constraints ?? {},
        status: 'running',
        created_at: now,
        created_by: ctx.userId,
        correlation: { nonce_hash: null, window_ms: 120_000 },
        waf_orchestration: true,
      };
      getStore().testRuns.push(run);

      const probeProfile = {
        ...(check.probe_profile ?? {}),
        scenario_family: scenario,
        timeout_ms: Math.min(
          timeoutMs,
          Number(check.probe_profile?.timeout_ms ?? timeoutMs),
        ),
      };

      const job = createProbeJob(ctx, run, check, target, probeProfile, runtimeConfig);
      run.correlation.nonce_hash = job.nonce_hash;
      run.awaiting_external_probe = true;

      delegated.push({
        test_run_id: runId,
        probe_job_id: job.id,
        scenario,
        waf_asset_id: asset.id,
        check_id: check.check_id,
      });
    }
  }

  return delegated;
}

export function listValidationPlans(ctx) {
  if (wafFeatureDisabled()) return featureDisabledResponse();
  ensureStoreShape();
  const plans = getStore()
    .wafValidationPlans.filter((p) => p.tenant_id === ctx.tenantId)
    .map((p) => formatValidationPlan(p));
  return { plans };
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

  const now = new Date().toISOString();
  plan.state = 'running';
  plan.updated_at = now;

  const delegatedJobs = delegateScenariosToProbeCoordinator(
    ctx,
    {
      targetGroupId: plan.target_group_id,
      scenarios: plan.scenarios,
      maxConcurrent: plan.max_concurrent,
      timeoutMs: plan.timeout_ms,
    },
    runtimeConfig,
  );

  if (delegatedJobs.length === 0) {
    plan.state = 'failed';
    plan.updated_at = now;
    persistStore();
    return {
      error: 'validation_plan_execution_failed',
      status: 422,
      message: 'No WAF assets or probe jobs could be delegated for this plan.',
    };
  }

  plan.delegated_jobs = delegatedJobs;
  plan.state = 'completed';
  plan.executed_at = now;
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
      delegated_job_count: delegatedJobs.length,
      probe_job_ids: delegatedJobs.map((j) => j.probe_job_id),
    },
  });
  persistStore();

  return {
    validation_plan: formatValidationPlan(plan),
    delegated_jobs: delegatedJobs,
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

function buildRetestResults(body, delegatedJobs) {
  if (Array.isArray(body.results) && body.results.length > 0) {
    return {
      results: body.results,
      validation_passed: body.validation_passed === true,
      validation_failed: body.validation_failed === true,
      posture_status: typeof body.posture_status === 'string' ? body.posture_status : undefined,
      waf_detected: body.waf_detected === true,
      origin_bypass_confirmed: body.origin_bypass_confirmed === true,
    };
  }

  return {
    results: delegatedJobs.map((job) => ({
      scenario_family: job.scenario,
      passed: null,
      observed_action: 'inconclusive',
      evidence_summary: {
        probe_job_id: job.probe_job_id,
        test_run_id: job.test_run_id,
        scenario_id: job.scenario,
      },
    })),
    validation_passed: false,
    validation_failed: false,
    posture_status: 'unknown',
    waf_detected: false,
    origin_bypass_confirmed: false,
  };
}

export function executeRetest(ctx, retestId, body = {}, runtimeConfig = loadRuntimeConfig()) {
  if (wafFeatureDisabled()) return featureDisabledResponse();
  ensureStoreShape();

  const retest = findRetestRequest(ctx, retestId);
  if (!retest) {
    return { error: 'waf_retest_not_found', status: 404 };
  }
  if (retest.status === 'completed') {
    return { error: 'waf_retest_already_completed', status: 409 };
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

  const delegatedJobs = delegateScenariosToProbeCoordinator(
    ctx,
    {
      targetGroupId: asset.target_group_id,
      scenarios: retest.retest_plan,
      maxConcurrent: retest.retest_plan.length,
      timeoutMs: 60_000,
      wafAssetId: asset.id,
    },
    runtimeConfig,
  );

  const retestResults = buildRetestResults(body, delegatedJobs);

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
    },
  });
  persistStore();

  return {
    retest_request: retest,
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
    uses_probe_coordinator: /from\s+['"]\.\/probeCoordinator\.mjs['"]/.test(source),
    avoids_direct_traffic_stub:
      !/from\s+['"].*probeStub/.test(source)
      && !/simulateProbeResult\s*\(/.test(source),
  };
}