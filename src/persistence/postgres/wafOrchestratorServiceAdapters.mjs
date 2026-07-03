import { getCheckById, WAF_SAFE_CHECK_IDS } from '../../contracts/checks.mjs';
import {
  computeRetestVerdict,
  createBaselineApproval,
  createRetestRequest,
  createValidationPlan as normalizeValidationPlan,
  validateOrchestratorPlan,
} from '../../contracts/wafOrchestrator.mjs';
import { newId } from '../../lib/ids.mjs';
import { redactObject } from '../../lib/redact.mjs';
import {
  formatRetestRequestForApi,
  formatValidationPlanForApi,
} from './wafOrchestratorRepository.mjs';

export const WAF_ORCHESTRATOR_REPOSITORY_METHODS = Object.freeze([
  'listValidationPlans',
  'listScheduledValidationPlans',
  'listRunnableValidationPlans',
  'getValidationPlan',
  'createValidationPlan',
  'updateValidationPlan',
  'getWafBaseline',
  'updateWafBaseline',
  'createBaselineApproval',
  'getWafDriftEvent',
  'createRetestRequest',
  'getRetestRequest',
  'listRetestRequests',
  'updateRetestRequest',
  'completeRetestWithDriftAndAudit',
  'cancelValidationPlanExecution',
  'claimValidationPlanExecution',
  'stageValidationPlanDelegation',
  'finishValidationPlanExecution',
  'releaseValidationPlanExecution',
  'claimRetestExecution',
  'stageRetestDelegation',
  'finishRetestExecution',
  'releaseRetestExecution',
]);

export const POSTGRES_WAF_ORCHESTRATOR_SERVICE_METHODS = Object.freeze([
  'listValidationPlans',
  'createValidationPlan',
  'getScheduledPlans',
  'getRunnablePlans',
  'cancelValidationPlan',
  'approveBaseline',
  'requestRetest',
  'listRetests',
  'executeValidationPlan',
  'executeRetest',
  'completeRetest',
]);

const CANCELLABLE_STATES = new Set(['draft', 'scheduled', 'running']);
const BASELINE_APPROVABLE_STATES = new Set(['proposed', 'draft']);

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

const WAF_SAFE_CHECK_ID_SET = new Set(WAF_SAFE_CHECK_IDS);

const EXECUTION_LEASE_SAFETY_BUFFER_MS = 30_000;
const DEFAULT_VALIDATION_PLAN_LEASE_BASE_MS = 60_000;
const DEFAULT_RETEST_LEASE_MS = 90_000;

export const DELEGATION_STATUS = Object.freeze({
  PENDING_START: 'pending_start',
  STARTING: 'starting',
  DELEGATED: 'delegated',
  FAILED: 'failed',
});

const STALE_DELEGATION_STATUSES = new Set([
  DELEGATION_STATUS.PENDING_START,
  DELEGATION_STATUS.STARTING,
]);

function computeExecutionLeaseMs({ timeoutMs, optionsLeaseMs, kind = 'validation_plan' }) {
  const hasTimeout = timeoutMs != null && Number(timeoutMs) > 0;
  let minimumMs;
  if (kind === 'retest') {
    minimumMs = hasTimeout
      ? Number(timeoutMs) + EXECUTION_LEASE_SAFETY_BUFFER_MS
      : DEFAULT_RETEST_LEASE_MS;
  } else {
    minimumMs = hasTimeout
      ? Number(timeoutMs) + EXECUTION_LEASE_SAFETY_BUFFER_MS
      : DEFAULT_VALIDATION_PLAN_LEASE_BASE_MS + EXECUTION_LEASE_SAFETY_BUFFER_MS;
  }
  const configured = optionsLeaseMs;
  if (configured != null && Number(configured) > minimumMs) {
    return Number(configured);
  }
  return minimumMs;
}

function scenarioCheckId(scenarioId) {
  return SCENARIO_TO_CHECK[scenarioId] ?? null;
}

function workItemKey(assetId, scenario) {
  return `${assetId}::${scenario}`;
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

export function resolveDelegationStatus(job) {
  if (job?.status) return job.status;
  if (job?.test_run_id) return DELEGATION_STATUS.DELEGATED;
  return null;
}

export function buildOrchestratorWorkQueue(assets, scenarios) {
  const workQueue = [];
  for (const asset of assets) {
    for (const scenario of scenarios ?? []) {
      workQueue.push({ asset, scenario });
    }
  }
  return workQueue;
}

export function filterPendingWorkItems(workQueue, delegatedJobs = []) {
  const blockingKeys = new Set(
    (delegatedJobs ?? [])
      .filter(isBlockingDelegationJob)
      .map((job) => workItemKey(job.waf_asset_id, job.scenario)),
  );
  return workQueue.filter(
    ({ asset, scenario }) => !blockingKeys.has(workItemKey(asset.id, scenario)),
  );
}

export function isBlockingDelegationJob(job) {
  const status = resolveDelegationStatus(job);
  if (status === DELEGATION_STATUS.FAILED) return false;
  if (status === DELEGATION_STATUS.PENDING_START || status === DELEGATION_STATUS.STARTING) {
    return true;
  }
  return status === DELEGATION_STATUS.DELEGATED || Boolean(job?.test_run_id);
}

function buildPendingDelegationJob({ asset, scenario, checkId, reservationId, now }) {
  return {
    status: DELEGATION_STATUS.PENDING_START,
    reservation_id: reservationId,
    scenario,
    waf_asset_id: asset.id,
    check_id: checkId,
    reserved_at: now,
  };
}

function buildStartingDelegationJob(pendingJob, startResult, now) {
  return {
    ...pendingJob,
    status: DELEGATION_STATUS.STARTING,
    test_run_id: startResult.run.id,
    probe_job_id: startResult.probe_job.id,
    started_at: now,
  };
}

function buildFailedDelegationJob(job, now, failureReason) {
  return {
    ...job,
    status: DELEGATION_STATUS.FAILED,
    failed_at: now,
    failure_reason: failureReason,
  };
}

function buildDelegatedJob(startResult, scenario, assetId, checkId, extras = {}) {
  return {
    status: DELEGATION_STATUS.DELEGATED,
    ...(extras.reservationId ? { reservation_id: extras.reservationId } : {}),
    test_run_id: startResult.run.id,
    probe_job_id: startResult.probe_job.id,
    scenario,
    waf_asset_id: assetId,
    check_id: checkId,
    ...(extras.now ? { delegated_at: extras.now } : {}),
  };
}

export function upsertDelegationJobByReservation(delegatedJobs, reservationId, nextJob) {
  const index = delegatedJobs.findIndex((job) => job.reservation_id === reservationId);
  if (index === -1) {
    return [...delegatedJobs, nextJob];
  }
  const updated = [...delegatedJobs];
  updated[index] = nextJob;
  return updated;
}

export function reconcileStaleDelegations(delegatedJobs, nowIso) {
  let reconciledCount = 0;
  const runsToCancel = [];
  const delegated_jobs = (delegatedJobs ?? []).map((job) => {
    const status = resolveDelegationStatus(job);
    if (!STALE_DELEGATION_STATUSES.has(status)) {
      return job;
    }
    reconciledCount += 1;
    if (job.test_run_id) {
      runsToCancel.push(job.test_run_id);
    }
    return buildFailedDelegationJob(job, nowIso, 'stale_delegation_reconciled');
  });
  return {
    delegated_jobs,
    runs_to_cancel: runsToCancel,
    reconciled_count: reconciledCount,
  };
}

async function cancelDelegatedRuns(cancelTestRunFn, ctx, delegatedJobsOrRunIds) {
  const runIds = (delegatedJobsOrRunIds ?? []).map((entry) =>
    typeof entry === 'string' ? entry : entry.test_run_id,
  );
  await cancelStartedRuns(cancelTestRunFn, ctx, runIds);
}

function isTerminalTestRun(run) {
  return run?.status === 'completed' || run?.status === 'verdicted';
}

function delegatedRunEvidenceMatchesJob(job, run) {
  if (run?.id != null && job.test_run_id != null && run.id !== job.test_run_id) {
    return false;
  }
  if (run?.check_id != null && job.check_id != null && run.check_id !== job.check_id) {
    return false;
  }
  const runProbeJobId = run?.probe_job_id ?? run?.probe_job?.id;
  if (runProbeJobId != null && job.probe_job_id != null && runProbeJobId !== job.probe_job_id) {
    return false;
  }
  return true;
}

function scenarioPassedFromVerdict(verdictValue) {
  if (
    verdictValue === 'pass'
    || verdictValue === 'protected'
    || verdictValue === 'allowed_as_expected'
  ) {
    return true;
  }
  if (
    verdictValue === 'fail'
    || verdictValue === 'bypassable'
    || verdictValue === 'penetrated'
  ) {
    return false;
  }
  return null;
}

function mapRunToRetestScenarioResult(job, run) {
  const verdictRecord = run?.verdict;
  if (!verdictRecord || typeof verdictRecord.verdict !== 'string') {
    return null;
  }
  const verdictValue = verdictRecord.verdict;
  const passed = scenarioPassedFromVerdict(verdictValue);
  let observed_action = 'inconclusive';
  if (passed === true) observed_action = 'block';
  else if (passed === false) observed_action = 'allow';

  return {
    scenario_family: job.scenario,
    passed,
    observed_action,
    evidence_summary: {
      test_run_id: job.test_run_id,
      probe_job_id: job.probe_job_id,
      scenario_id: job.scenario,
      verdict: verdictValue,
    },
  };
}

export function buildRetestResultsFromDelegatedRuns(delegatedJobs, runsById) {
  const results = [];
  for (const job of delegatedJobs) {
    const status = resolveDelegationStatus(job);
    if (
      status === DELEGATION_STATUS.FAILED
      || status === DELEGATION_STATUS.PENDING_START
      || status === DELEGATION_STATUS.STARTING
      || !job.test_run_id
    ) {
      return null;
    }
    const run = runsById[job.test_run_id];
    if (!run || !delegatedRunEvidenceMatchesJob(job, run) || !isTerminalTestRun(run)) {
      return null;
    }
    const mapped = mapRunToRetestScenarioResult(job, run);
    if (!mapped) {
      return null;
    }
    results.push(mapped);
  }

  const validation_passed = results.length > 0 && results.every((entry) => entry.passed === true);
  const validation_failed = results.some((entry) => entry.passed === false);
  const posture_status = validation_passed
    ? 'protected'
    : validation_failed
      ? 'underprotected'
      : 'unknown';

  return {
    results,
    validation_passed,
    validation_failed,
    posture_status,
    waf_detected: validation_passed,
    origin_bypass_confirmed: results.some(
      (entry) => entry.scenario_family === 'origin_bypass' && entry.passed === false,
    ),
  };
}

async function cancelStartedRuns(cancelTestRunFn, ctx, runIds) {
  if (typeof cancelTestRunFn !== 'function') return;
  for (const runId of runIds) {
    try {
      await cancelTestRunFn(ctx, runId);
    } catch {
      // Best-effort compensating cancellation after delegation failure.
    }
  }
}

async function persistDelegationStage(stageDelegationFn, delegatedJobs, nowIso) {
  if (typeof stageDelegationFn !== 'function') {
    return {
      error: 'validation_plan_execution_failed',
      status: 422,
      message: 'Delegation outbox staging is not available for this persistence slice.',
    };
  }
  const staged = await stageDelegationFn(delegatedJobs, nowIso);
  if (!staged) {
    return {
      error: 'validation_plan_execution_failed',
      status: 422,
      message: 'Delegation outbox reservation lost execution lease before persistence.',
    };
  }
  return { staged };
}

async function delegatePendingWorkItems({
  ctx,
  pendingItems,
  targetGroupId,
  targets,
  existingDelegatedJobs,
  startTestRunFn,
  cancelTestRunFn,
  runtimeConfig,
  stageDelegationFn,
  newIdFn,
  nowFn,
}) {
  const itemsToDelegate = pendingItems.slice(0, 1);
  const preflightError = preflightWorkItems(itemsToDelegate, targets);
  if (preflightError) {
    return preflightError;
  }

  const newDelegatedJobs = [];
  const startedRunIds = [];
  let workingDelegatedJobs = [...(existingDelegatedJobs ?? [])];

  for (const { asset, scenario } of itemsToDelegate) {
    const { check } = validateWorkItemPreflight({ asset, scenario }, targets);
    const targetId = asset.target_id;
    const now = nowFn().toISOString();
    const reservationId = newIdFn('res');
    const pendingJob = buildPendingDelegationJob({
      asset,
      scenario,
      checkId: check.check_id,
      reservationId,
      now,
    });

    const pendingStage = await persistDelegationStage(
      stageDelegationFn,
      [...workingDelegatedJobs, pendingJob],
      now,
    );
    if (pendingStage.error) {
      await cancelStartedRuns(cancelTestRunFn, ctx, startedRunIds);
      return pendingStage;
    }
    workingDelegatedJobs = pendingStage.staged.delegated_jobs ?? [...workingDelegatedJobs, pendingJob];

    const startResult = await startTestRunFn(
      ctx,
      {
        check_id: check.check_id,
        target_group_id: targetGroupId,
        target_id: targetId,
        probe_profile: { scenario_family: scenario },
        waf_orchestration: true,
      },
      runtimeConfig,
    );

    if (startResult?.error) {
      const failedJob = buildFailedDelegationJob(pendingJob, now, startResult.error);
      workingDelegatedJobs = upsertDelegationJobByReservation(
        workingDelegatedJobs,
        reservationId,
        failedJob,
      );
      await persistDelegationStage(stageDelegationFn, workingDelegatedJobs, now);
      await cancelStartedRuns(cancelTestRunFn, ctx, startedRunIds);
      return {
        error: startResult.error,
        status: startResult.status ?? 422,
        ...(startResult.message ? { message: startResult.message } : {}),
        ...(startResult.missing ? { missing: startResult.missing } : {}),
      };
    }

    const testRunId = startResult.run?.id;
    const probeJobId = startResult.probe_job?.id;
    if (!testRunId || !probeJobId) {
      const runsToCancel = testRunId ? [...startedRunIds, testRunId] : startedRunIds;
      const failedJob = buildFailedDelegationJob(pendingJob, now, 'missing_probe_job_identifiers');
      workingDelegatedJobs = upsertDelegationJobByReservation(
        workingDelegatedJobs,
        reservationId,
        failedJob,
      );
      await persistDelegationStage(stageDelegationFn, workingDelegatedJobs, now);
      await cancelStartedRuns(cancelTestRunFn, ctx, runsToCancel);
      return {
        error: 'validation_plan_execution_failed',
        status: 422,
        message: 'Delegated test run did not return probe job identifiers.',
      };
    }

    const startingJob = buildStartingDelegationJob(
      pendingJob,
      { run: { id: testRunId }, probe_job: { id: probeJobId } },
      now,
    );
    workingDelegatedJobs = upsertDelegationJobByReservation(
      workingDelegatedJobs,
      reservationId,
      startingJob,
    );
    const startingStage = await persistDelegationStage(
      stageDelegationFn,
      workingDelegatedJobs,
      now,
    );
    if (startingStage.error) {
      await cancelStartedRuns(cancelTestRunFn, ctx, [...startedRunIds, testRunId]);
      return startingStage;
    }
    workingDelegatedJobs = startingStage.staged.delegated_jobs ?? workingDelegatedJobs;

    startedRunIds.push(testRunId);
    const delegatedJob = buildDelegatedJob(
      { run: { id: testRunId }, probe_job: { id: probeJobId } },
      scenario,
      asset.id,
      check.check_id,
      { reservationId, now },
    );
    newDelegatedJobs.push(delegatedJob);
    workingDelegatedJobs = upsertDelegationJobByReservation(
      workingDelegatedJobs,
      reservationId,
      delegatedJob,
    );
  }

  return {
    delegated_jobs: workingDelegatedJobs,
    new_delegated_jobs: newDelegatedJobs,
    started_run_ids: startedRunIds,
  };
}

function assertWafOrchestratorRepositories(repositories) {
  const wafOrchestrator = repositories?.wafOrchestrator;
  if (!wafOrchestrator || typeof wafOrchestrator !== 'object') {
    throw new Error('Postgres WAF orchestrator service adapter requires repositories.wafOrchestrator.');
  }
  for (const method of WAF_ORCHESTRATOR_REPOSITORY_METHODS) {
    if (typeof wafOrchestrator[method] !== 'function') {
      throw new Error(`Postgres WAF orchestrator service adapter requires wafOrchestrator.${method}().`);
    }
  }

  const coreCatalog = repositories?.coreCatalog;
  if (!coreCatalog || typeof coreCatalog.getTargetGroup !== 'function') {
    throw new Error('Postgres WAF orchestrator service adapter requires coreCatalog.getTargetGroup().');
  }

  const wafPosture = repositories?.wafPosture;
  if (
    !wafPosture ||
    typeof wafPosture.patchWafDriftEvent !== 'function' ||
    typeof wafPosture.listWafAssets !== 'function'
  ) {
    throw new Error(
      'Postgres WAF orchestrator service adapter requires wafPosture.patchWafDriftEvent() and wafPosture.listWafAssets().',
    );
  }

  const audit = repositories?.audit;
  if (!audit || typeof audit.appendAuditEvent !== 'function') {
    throw new Error('Postgres WAF orchestrator service adapter requires audit.appendAuditEvent().');
  }
}

function contractError(err, fallbackStatus = 400) {
  return {
    error: err.code ?? 'invalid_request',
    status: fallbackStatus,
    message: err.message,
  };
}

export function createPostgresWafOrchestratorServices(repositories, options = {}) {
  assertWafOrchestratorRepositories(repositories);
  const orchRepo = repositories.wafOrchestrator;
  const wafPostureRepo = repositories.wafPosture;
  const coreCatalog = repositories.coreCatalog;
  const auditRepo = repositories.audit;
  const nowFn = options.now ?? (() => new Date());
  const newIdFn = options.newId ?? newId;
  const startTestRunFn = options.testRuns?.startTestRun;
  const cancelTestRunFn = options.testRuns?.cancelTestRun;
  const getTestRunFn = options.testRuns?.getTestRun;

  return {
    async listValidationPlans(ctx) {
      const plans = await orchRepo.listValidationPlans(ctx);
      return { plans: plans.map((p) => formatValidationPlanForApi(p)) };
    },

    async createValidationPlan(ctx, body = {}) {
      try {
        const normalized = normalizeValidationPlan({
          ...body,
          tenant_id: ctx.tenantId,
        });
        const targetGroup = await coreCatalog.getTargetGroup(ctx, normalized.target_group_id);
        if (!targetGroup) {
          return {
            error: 'target_group_not_found',
            status: 404,
            message: 'Target group not found for tenant.',
          };
        }

        const id = newIdFn('id');
        const now = nowFn().toISOString();
        const record = await orchRepo.createValidationPlan(ctx, {
          id,
          ...normalized,
          delegated_jobs: [],
          created_at: now,
          updated_at: now,
        });

        await auditRepo.appendAuditEvent({
          tenant_id: ctx.tenantId,
          actor_user_id: ctx.userId,
          actor_role: ctx.role,
          action: 'waf.validation_plan.created',
          resource_type: 'waf_validation_plan',
          resource_id: id,
          metadata: redactObject({
            target_group_id: record.target_group_id,
            mode: record.mode,
            scenarios: record.scenarios,
            state: record.state,
          }),
        });

        return { validation_plan: formatValidationPlanForApi(record) };
      } catch (err) {
        return contractError(err);
      }
    },

    async getScheduledPlans(ctx) {
      const plans = await orchRepo.listScheduledValidationPlans(ctx);
      return { plans: plans.map((p) => formatValidationPlanForApi(p)) };
    },

    async listRetests(ctx, filters = {}) {
      const items = await orchRepo.listRetestRequests(ctx, filters);
      return { items: items.map((item) => formatRetestRequestForApi(item)) };
    },

    async getRunnablePlans(ctx) {
      const plans = await orchRepo.listRunnableValidationPlans(ctx);
      return { plans: plans.map((p) => formatValidationPlanForApi(p)) };
    },

    async cancelValidationPlan(ctx, planId) {
      const plan = await orchRepo.getValidationPlan(ctx, planId);
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
      const now = nowFn().toISOString();
      const updated = await orchRepo.cancelValidationPlanExecution(ctx, planId, {
        cancelled_at: now,
        updated_at: now,
      });
      if (!updated) {
        return {
          error: 'validation_plan_not_cancellable',
          status: 409,
          message: 'Validation plan could not be cancelled; execution lease or plan state changed.',
        };
      }

      const delegatedJobs = Array.isArray(updated.delegated_jobs)
        ? updated.delegated_jobs
        : Array.isArray(plan.delegated_jobs)
          ? plan.delegated_jobs
          : [];
      await cancelDelegatedRuns(cancelTestRunFn, ctx, delegatedJobs);

      await auditRepo.appendAuditEvent({
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId,
        actor_role: ctx.role,
        action: 'waf.validation_plan.cancelled',
        resource_type: 'waf_validation_plan',
        resource_id: planId,
        metadata: redactObject({
          target_group_id: plan.target_group_id,
          previous_state: previousState,
          ...(delegatedJobs.length > 0
            ? { cancelled_run_ids: delegatedJobs.map((job) => job.test_run_id) }
            : {}),
        }),
      });

      return { validation_plan: formatValidationPlanForApi(updated) };
    },

    async approveBaseline(ctx, baselineId, body = {}) {
      const baseline = await orchRepo.getWafBaseline(ctx, baselineId);
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
        const approvalId = newIdFn('id');
        const now = nowFn().toISOString();
        const approvalRow = await orchRepo.createBaselineApproval(ctx, {
          id: approvalId,
          baseline_id: baselineId,
          waf_asset_id: baseline.waf_asset_id,
          approver: approval.approver,
          approval_notes: approval.approval_notes,
          approved_at: approval.approved_at,
          fingerprint_summary: approval.fingerprint_summary,
          created_at: now,
        });

        const updatedBaseline = await orchRepo.updateWafBaseline(ctx, baselineId, {
          state: 'active',
          approved_by: approval.approver,
          approved_at: approval.approved_at,
          updated_at: now,
        });

        await auditRepo.appendAuditEvent({
          tenant_id: ctx.tenantId,
          actor_user_id: ctx.userId,
          actor_role: ctx.role,
          action: 'waf.baseline.approved',
          resource_type: 'waf_baseline',
          resource_id: baselineId,
          metadata: redactObject({
            approver: approval.approver,
            waf_asset_id: baseline.waf_asset_id,
            fingerprint_summary: approval.fingerprint_summary,
          }),
        });

        return {
          baseline: {
            id: updatedBaseline.id,
            waf_asset_id: updatedBaseline.waf_asset_id,
            state: updatedBaseline.state,
            approved_by: updatedBaseline.approved_by,
            approved_at: updatedBaseline.approved_at,
          },
          approval: approvalRow,
        };
      } catch (err) {
        return contractError(err);
      }
    },

    async requestRetest(ctx, driftEventId, body = {}) {
      const driftEvent = await orchRepo.getWafDriftEvent(ctx, driftEventId);
      if (!driftEvent) {
        return { error: 'waf_drift_event_not_found', status: 404 };
      }

      try {
        const normalized = createRetestRequest({
          drift_event_id: driftEventId,
          ...body,
        });
        const id = newIdFn('id');
        const now = nowFn().toISOString();
        const record = await orchRepo.createRetestRequest(ctx, {
          id,
          drift_event_id: driftEventId,
          waf_asset_id: driftEvent.waf_asset_id,
          retest_plan: normalized.retest_plan,
          requested_by: normalized.requested_by,
          priority: normalized.priority,
          status: 'requested',
          created_at: now,
          updated_at: now,
        });

        if (driftEvent.status === 'open' || driftEvent.status === 'acknowledged') {
          await wafPostureRepo.patchWafDriftEvent(ctx, driftEventId, {
            status: 'retest_pending',
          });
        }

        await auditRepo.appendAuditEvent({
          tenant_id: ctx.tenantId,
          actor_user_id: ctx.userId,
          actor_role: ctx.role,
          action: 'waf.retest.requested',
          resource_type: 'waf_retest_request',
          resource_id: id,
          metadata: redactObject({
            drift_event_id: driftEventId,
            retest_plan: normalized.retest_plan,
            priority: normalized.priority,
            requested_by: normalized.requested_by,
          }),
        });

        return { retest_request: record };
      } catch (err) {
        return contractError(err);
      }
    },

    async executeValidationPlan(ctx, planId, runtimeConfig = {}) {
      const plan = await orchRepo.getValidationPlan(ctx, planId);
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

      if (typeof startTestRunFn !== 'function') {
        return {
          error: 'waf_orchestrator_execution_not_ready',
          status: 422,
          message:
            'Signed probe-worker delegation for WAF orchestration is not available in Postgres mode for this release slice.',
        };
      }

      if (runtimeConfig.probeMode !== 'signed-worker') {
        return {
          error: 'waf_orchestrator_signed_worker_required',
          status: 422,
          message:
            'Postgres WAF orchestration requires signed probe-worker mode (runtimeConfig.probeMode === "signed-worker").',
        };
      }

      const targetGroup = await coreCatalog.getTargetGroup(ctx, plan.target_group_id);
      const targets = targetGroup?.targets ?? [];
      if (!targetGroup || targets.length === 0) {
        return {
          error: 'validation_plan_execution_failed',
          status: 422,
          message: 'Target group has no declared targets for WAF orchestration.',
        };
      }

      const allAssets = await wafPostureRepo.listWafAssets(ctx);
      const assets = (allAssets ?? []).filter(
        (a) => a.target_group_id === plan.target_group_id,
      );
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

      const lockToken = newIdFn('lock');
      const claimNow = nowFn();
      const leaseMs = computeExecutionLeaseMs({
        timeoutMs: plan.timeout_ms,
        optionsLeaseMs: options.executionLeaseMs,
        kind: 'validation_plan',
      });
      const lockExpiresAt = new Date(claimNow.getTime() + leaseMs).toISOString();
      const claimedPlan = await orchRepo.claimValidationPlanExecution(ctx, planId, {
        lock_token: lockToken,
        lock_expires_at: lockExpiresAt,
        now: claimNow.toISOString(),
      });
      if (!claimedPlan) {
        const refreshedPlan = await orchRepo.getValidationPlan(ctx, planId);
        if (!refreshedPlan) {
          return { error: 'validation_plan_not_found', status: 404 };
        }
        if (refreshedPlan.state === 'cancelled') {
          return { error: 'validation_plan_cancelled', status: 409 };
        }
        if (refreshedPlan.state === 'completed') {
          return { error: 'validation_plan_already_completed', status: 409 };
        }
        return {
          error: 'waf_orchestrator_execution_in_progress',
          status: 409,
          message:
            'Another WAF validation plan execution holds an active lease; retry after the current executor finishes.',
        };
      }

      let workingDelegatedJobs = Array.isArray(claimedPlan.delegated_jobs)
        ? claimedPlan.delegated_jobs
        : [];
      const reconcileNow = nowFn().toISOString();
      const reconciliation = reconcileStaleDelegations(workingDelegatedJobs, reconcileNow);
      if (reconciliation.reconciled_count > 0) {
        if (reconciliation.runs_to_cancel.length > 0) {
          await cancelStartedRuns(cancelTestRunFn, ctx, reconciliation.runs_to_cancel);
        }
        const reconciledStage = await orchRepo.stageValidationPlanDelegation(ctx, planId, lockToken, {
          delegated_jobs: reconciliation.delegated_jobs,
          updated_at: reconcileNow,
        });
        if (!reconciledStage) {
          try {
            await orchRepo.releaseValidationPlanExecution(ctx, planId, lockToken);
          } catch {
            // Best-effort lease cleanup after stale delegation reconciliation failure.
          }
          return {
            error: 'validation_plan_execution_failed',
            status: 422,
            message:
              'Stale delegation outbox reconciliation lost execution lease before persistence.',
          };
        }
        workingDelegatedJobs = reconciledStage.delegated_jobs ?? reconciliation.delegated_jobs;
      }

      const pendingItems = filterPendingWorkItems(workQueue, workingDelegatedJobs);

      if (pendingItems.length === 0) {
        const now = nowFn().toISOString();
        const updated = await orchRepo.finishValidationPlanExecution(ctx, planId, lockToken, {
          state: 'completed',
          delegated_jobs: workingDelegatedJobs,
          executed_at: claimedPlan.executed_at ?? now,
          updated_at: now,
        });
        if (!updated) {
          return {
            error: 'validation_plan_execution_failed',
            status: 422,
            message:
              'Validation plan completion lost execution lease before persistence could finish.',
          };
        }
        return {
          validation_plan: formatValidationPlanForApi(updated),
          delegated_jobs: workingDelegatedJobs,
        };
      }

      const delegation = await delegatePendingWorkItems({
        ctx,
        pendingItems,
        targetGroupId: plan.target_group_id,
        targets,
        existingDelegatedJobs: workingDelegatedJobs,
        startTestRunFn,
        cancelTestRunFn,
        runtimeConfig,
        stageDelegationFn: async (delegatedJobs, updatedAt) =>
          orchRepo.stageValidationPlanDelegation(ctx, planId, lockToken, {
            delegated_jobs: delegatedJobs,
            updated_at: updatedAt,
          }),
        newIdFn,
        nowFn,
      });
      if (delegation.error) {
        try {
          await orchRepo.releaseValidationPlanExecution(ctx, planId, lockToken);
        } catch {
          // Best-effort lease cleanup after delegation failure.
        }
        return delegation;
      }

      const delegatedJobs = delegation.delegated_jobs;
      const pendingAfter = filterPendingWorkItems(workQueue, delegatedJobs);
      const allDelegated = pendingAfter.length === 0;
      const now = nowFn().toISOString();

      let updated;
      try {
        updated = await orchRepo.finishValidationPlanExecution(ctx, planId, lockToken, {
          state: allDelegated ? 'completed' : 'running',
          delegated_jobs: delegatedJobs,
          ...(allDelegated || !claimedPlan.executed_at ? { executed_at: now } : {}),
          updated_at: now,
        });
      } catch (_persistErr) {
        await cancelDelegatedRuns(cancelTestRunFn, ctx, delegation.started_run_ids);
        try {
          await orchRepo.releaseValidationPlanExecution(ctx, planId, lockToken);
        } catch {
          // Best-effort lease cleanup after finish persistence failure.
        }
        return {
          error: 'validation_plan_execution_failed',
          status: 422,
          message:
            'Delegated probe job started but validation plan execution lease persistence failed.',
        };
      }

      if (!updated) {
        await cancelDelegatedRuns(cancelTestRunFn, ctx, delegation.started_run_ids);
        try {
          await orchRepo.releaseValidationPlanExecution(ctx, planId, lockToken);
        } catch {
          // Best-effort lease cleanup after a lost finish token.
        }
        return {
          error: 'validation_plan_execution_failed',
          status: 422,
          message:
            'Delegated probe job started but validation plan execution lease was lost before persistence.',
        };
      }

      if (delegation.new_delegated_jobs.length > 0) {
        await auditRepo.appendAuditEvent({
          tenant_id: ctx.tenantId,
          actor_user_id: ctx.userId,
          actor_role: ctx.role,
          action: 'waf.validation_plan.executed',
          resource_type: 'waf_validation_plan',
          resource_id: planId,
          metadata: redactObject({
            target_group_id: plan.target_group_id,
            delegated_job_count: delegatedJobs.length,
            new_delegated_job_count: delegation.new_delegated_jobs.length,
            test_run_ids: delegatedJobs.map((j) => j.test_run_id),
            probe_job_ids: delegatedJobs.map((j) => j.probe_job_id),
            plan_state: updated.state,
          }),
        });
      }

      return {
        validation_plan: formatValidationPlanForApi(updated),
        delegated_jobs: delegatedJobs,
        ...(allDelegated ? {} : { continuation_required: true }),
      };
    },

    async executeRetest(ctx, retestId, _body = {}, runtimeConfig = {}) {
      const retest = await orchRepo.getRetestRequest(ctx, retestId);
      if (!retest) {
        return { error: 'waf_retest_not_found', status: 404 };
      }
      if (retest.status === 'completed') {
        return { error: 'waf_retest_already_completed', status: 409 };
      }
      if (retest.status === 'delegated') {
        return { error: 'waf_retest_already_delegated', status: 409 };
      }

      const driftEvent = await orchRepo.getWafDriftEvent(ctx, retest.drift_event_id);
      if (!driftEvent) {
        return { error: 'waf_drift_event_not_found', status: 404 };
      }

      if (typeof startTestRunFn !== 'function') {
        return {
          error: 'waf_orchestrator_execution_not_ready',
          status: 422,
          message:
            'Signed probe-worker delegation for WAF orchestration is not available in Postgres mode for this release slice.',
        };
      }

      if (runtimeConfig.probeMode !== 'signed-worker') {
        return {
          error: 'waf_orchestrator_signed_worker_required',
          status: 422,
          message:
            'Postgres WAF orchestration requires signed probe-worker mode (runtimeConfig.probeMode === "signed-worker").',
        };
      }

      const allAssets = await wafPostureRepo.listWafAssets(ctx);
      const asset = (allAssets ?? []).find((a) => a.id === driftEvent.waf_asset_id);
      if (!asset) {
        return { error: 'waf_asset_not_found', status: 404 };
      }

      const targetGroup = await coreCatalog.getTargetGroup(ctx, asset.target_group_id);
      const targets = targetGroup?.targets ?? [];
      if (!targetGroup || targets.length === 0) {
        return {
          error: 'validation_plan_execution_failed',
          status: 422,
          message: 'Target group has no declared targets for WAF retest execution.',
        };
      }

      const retestPlan = retest.retest_plan ?? [];
      if (retestPlan.length === 0) {
        return {
          error: 'validation_plan_execution_failed',
          status: 422,
          message: 'Retest plan has no scenarios to delegate.',
        };
      }

      const workQueue = retestPlan.map((scenario) => ({ asset, scenario }));

      const retestPreflightError = preflightWorkItems(workQueue, targets);
      if (retestPreflightError) {
        return retestPreflightError;
      }

      const lockToken = newIdFn('lock');
      const claimNow = nowFn();
      const leaseMs = computeExecutionLeaseMs({
        timeoutMs: retest.timeout_ms,
        optionsLeaseMs: options.executionLeaseMs,
        kind: 'retest',
      });
      const lockExpiresAt = new Date(claimNow.getTime() + leaseMs).toISOString();
      const claimedRetest = await orchRepo.claimRetestExecution(ctx, retestId, {
        lock_token: lockToken,
        lock_expires_at: lockExpiresAt,
        now: claimNow.toISOString(),
      });
      if (!claimedRetest) {
        const refreshedRetest = await orchRepo.getRetestRequest(ctx, retestId);
        if (!refreshedRetest) {
          return { error: 'waf_retest_not_found', status: 404 };
        }
        if (refreshedRetest.status === 'completed') {
          return { error: 'waf_retest_already_completed', status: 409 };
        }
        if (refreshedRetest.status === 'delegated') {
          return { error: 'waf_retest_already_delegated', status: 409 };
        }
        return {
          error: 'waf_orchestrator_execution_in_progress',
          status: 409,
          message:
            'Another WAF retest execution holds an active lease; retry after the current executor finishes.',
        };
      }

      let workingDelegatedJobs = Array.isArray(claimedRetest.delegated_jobs)
        ? claimedRetest.delegated_jobs
        : [];
      const reconcileNow = nowFn().toISOString();
      const reconciliation = reconcileStaleDelegations(workingDelegatedJobs, reconcileNow);
      if (reconciliation.reconciled_count > 0) {
        if (reconciliation.runs_to_cancel.length > 0) {
          await cancelStartedRuns(cancelTestRunFn, ctx, reconciliation.runs_to_cancel);
        }
        const reconciledStage = await orchRepo.stageRetestDelegation(ctx, retestId, lockToken, {
          delegated_jobs: reconciliation.delegated_jobs,
          updated_at: reconcileNow,
        });
        if (!reconciledStage) {
          try {
            await orchRepo.releaseRetestExecution(ctx, retestId, lockToken);
          } catch {
            // Best-effort lease cleanup after stale delegation reconciliation failure.
          }
          return {
            error: 'validation_plan_execution_failed',
            status: 422,
            message:
              'Stale delegation outbox reconciliation lost execution lease before persistence.',
          };
        }
        workingDelegatedJobs = reconciledStage.delegated_jobs ?? reconciliation.delegated_jobs;
      }

      const pendingItems = filterPendingWorkItems(workQueue, workingDelegatedJobs);

      if (pendingItems.length === 0) {
        const now = nowFn().toISOString();
        const updatedRetest = await orchRepo.finishRetestExecution(ctx, retestId, lockToken, {
          status: 'delegated',
          delegated_jobs: workingDelegatedJobs,
          updated_at: now,
        });
        if (!updatedRetest) {
          return {
            error: 'validation_plan_execution_failed',
            status: 422,
            message: 'Retest delegation lost execution lease before persistence could finish.',
          };
        }
        return {
          retest_request: updatedRetest,
          delegated_jobs: workingDelegatedJobs,
        };
      }

      const delegation = await delegatePendingWorkItems({
        ctx,
        pendingItems,
        targetGroupId: asset.target_group_id,
        targets,
        existingDelegatedJobs: workingDelegatedJobs,
        startTestRunFn,
        cancelTestRunFn,
        runtimeConfig,
        stageDelegationFn: async (delegatedJobs, updatedAt) =>
          orchRepo.stageRetestDelegation(ctx, retestId, lockToken, {
            delegated_jobs: delegatedJobs,
            updated_at: updatedAt,
          }),
        newIdFn,
        nowFn,
      });
      if (delegation.error) {
        try {
          await orchRepo.releaseRetestExecution(ctx, retestId, lockToken);
        } catch {
          // Best-effort lease cleanup after delegation failure.
        }
        return delegation;
      }

      const delegatedJobs = delegation.delegated_jobs;
      const pendingAfter = filterPendingWorkItems(workQueue, delegatedJobs);
      const allDelegated = pendingAfter.length === 0;
      const now = nowFn().toISOString();

      let updatedRetest;
      try {
        updatedRetest = await orchRepo.finishRetestExecution(ctx, retestId, lockToken, {
          status: allDelegated ? 'delegated' : 'running',
          delegated_jobs: delegatedJobs,
          updated_at: now,
        });
      } catch (_persistErr) {
        await cancelDelegatedRuns(cancelTestRunFn, ctx, delegation.started_run_ids);
        try {
          await orchRepo.releaseRetestExecution(ctx, retestId, lockToken);
        } catch {
          // Best-effort lease cleanup after finish persistence failure.
        }
        return {
          error: 'validation_plan_execution_failed',
          status: 422,
          message: 'Delegated probe job started but retest execution lease persistence failed.',
        };
      }

      if (!updatedRetest) {
        await cancelDelegatedRuns(cancelTestRunFn, ctx, delegation.started_run_ids);
        try {
          await orchRepo.releaseRetestExecution(ctx, retestId, lockToken);
        } catch {
          // Best-effort lease cleanup after a lost finish token.
        }
        return {
          error: 'validation_plan_execution_failed',
          status: 422,
          message: 'Delegated probe job started but retest execution lease was lost before persistence.',
        };
      }

      if (delegation.new_delegated_jobs.length > 0) {
        await auditRepo.appendAuditEvent({
          tenant_id: ctx.tenantId,
          actor_user_id: ctx.userId,
          actor_role: ctx.role,
          action: 'waf.retest.delegated',
          resource_type: 'waf_retest_request',
          resource_id: retestId,
          metadata: redactObject({
            drift_event_id: retest.drift_event_id,
            delegated_job_count: delegatedJobs.length,
            new_delegated_job_count: delegation.new_delegated_jobs.length,
            test_run_ids: delegatedJobs.map((j) => j.test_run_id),
            probe_job_ids: delegatedJobs.map((j) => j.probe_job_id),
            retest_status: updatedRetest.status,
          }),
        });
      }

      return {
        retest_request: updatedRetest,
        delegated_jobs: delegatedJobs,
        ...(allDelegated ? {} : { continuation_required: true }),
      };
    },

    async completeRetest(ctx, retestId) {
      const retest = await orchRepo.getRetestRequest(ctx, retestId);
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

      if (typeof getTestRunFn !== 'function') {
        return {
          error: 'waf_retest_closure_not_ready',
          status: 422,
          message: 'Evidence-backed retest closure is not available in Postgres mode for this slice.',
        };
      }

      const driftEvent = await orchRepo.getWafDriftEvent(ctx, retest.drift_event_id);
      if (!driftEvent) {
        return { error: 'waf_drift_event_not_found', status: 404 };
      }

      /** @type {Record<string, unknown>} */
      const runsById = {};
      for (const job of delegatedJobs) {
        const run = await getTestRunFn(ctx, job.test_run_id);
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
      const now = nowFn().toISOString();
      const driftPatch =
        verdict.verdict === 'resolved'
          ? { status: 'resolved', resolved_at: now }
          : verdict.verdict === 'persistent'
            ? { status: 'open' }
            : null;

      const completion = await orchRepo.completeRetestWithDriftAndAudit(ctx, {
        retest_id: retestId,
        retest_patch: {
          status: 'completed',
          verdict: verdict.verdict,
          verdict_reason: verdict.reason,
          delegated_jobs: delegatedJobs,
          completed_at: now,
          updated_at: now,
        },
        drift_event_id: retest.drift_event_id,
        drift_patch: driftPatch,
        audit_event: {
          tenant_id: ctx.tenantId,
          actor_user_id: ctx.userId,
          actor_role: ctx.role,
          action: 'waf.retest.completed',
          resource_type: 'waf_retest_request',
          resource_id: retestId,
          metadata: redactObject({
            drift_event_id: retest.drift_event_id,
            verdict: verdict.verdict,
            verdict_reason: verdict.reason,
            delegated_job_count: delegatedJobs.length,
            test_run_ids: delegatedJobs.map((j) => j.test_run_id),
            probe_job_ids: delegatedJobs.map((j) => j.probe_job_id),
          }),
        },
        audit_now: nowFn(),
      });

      const updatedRetest = completion.retest_request;

      return {
        retest_request: updatedRetest,
        verdict,
        delegated_jobs: delegatedJobs,
      };
    },
  };
}
