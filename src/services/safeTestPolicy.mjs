import { getStore } from '../store.mjs';
import {
  DEFAULT_MAX_RUNS_PER_HOUR,
  DEFAULT_MIN_SECONDS_BETWEEN_RUNS,
  countCustomerRunnableRunsLastHour as countRunsLastHourFromRuns,
  effectiveSafetyConstraints,
  isWithinSafeTestWindow,
  lastRunForTargetGroup as lastRunForTargetGroupFromRuns,
  normalizeSafetyPolicy,
  wouldExceedEventCap as wouldExceedEventCapFromCount,
} from '../lib/safeTestGuards.mjs';

export {
  DEFAULT_MAX_RUNS_PER_HOUR,
  DEFAULT_MIN_SECONDS_BETWEEN_RUNS,
  effectiveSafetyConstraints,
  isWithinSafeTestWindow,
  normalizeSafetyPolicy,
};

export function countCustomerRunnableRunsLastHour(tenantId, now = Date.now()) {
  return countRunsLastHourFromRuns(getStore().testRuns, tenantId, now);
}

export function lastRunForTargetGroup(tenantId, targetGroupId) {
  return lastRunForTargetGroupFromRuns(getStore().testRuns, tenantId, targetGroupId);
}

export function countEventsForRun(runId) {
  return getStore().events.filter((e) => e.test_run_id === runId).length;
}

export function wouldExceedEventCap(run, additional = 1) {
  return wouldExceedEventCapFromCount(run, countEventsForRun(run.id), additional);
}