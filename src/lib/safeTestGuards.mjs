import { getCheckById, isCustomerRunnable } from '../contracts/checks.mjs';

export const DEFAULT_MAX_RUNS_PER_HOUR = 60;
export const DEFAULT_MIN_SECONDS_BETWEEN_RUNS = 0;

export function normalizeSafetyPolicy(policy = {}) {
  return {
    max_runs_per_hour: policy.max_runs_per_hour ?? DEFAULT_MAX_RUNS_PER_HOUR,
    min_seconds_between_runs: policy.min_seconds_between_runs ?? DEFAULT_MIN_SECONDS_BETWEEN_RUNS,
  };
}

export function effectiveSafetyConstraints(check, group) {
  const policy = normalizeSafetyPolicy(group?.safety_policy);
  return {
    ...(check.safety_constraints ?? {}),
    max_runs_per_hour: policy.max_runs_per_hour,
    min_seconds_between_runs: policy.min_seconds_between_runs,
  };
}

export function isWithinSafeTestWindow(group, now = Date.now()) {
  const windows = group?.safe_test_windows ?? [];
  if (!windows.length) return true;
  return windows.some((w) => {
    const start = new Date(w.start_at).getTime();
    const end = new Date(w.end_at).getTime();
    if (Number.isNaN(start) || Number.isNaN(end)) return false;
    return now >= start && now <= end;
  });
}

export function countCustomerRunnableRunsLastHour(runs, tenantId, now = Date.now()) {
  const hourAgo = now - 3_600_000;
  return runs.filter((r) => {
    if (r.tenant_id !== tenantId) return false;
    const created = new Date(r.created_at).getTime();
    if (created < hourAgo) return false;
    const check = getCheckById(r.check_id);
    return isCustomerRunnable(check);
  }).length;
}

export function lastRunForTargetGroup(runs, tenantId, targetGroupId) {
  const sorted = runs
    .filter((r) => r.tenant_id === tenantId && r.target_group_id === targetGroupId)
    .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
  return sorted[0] ?? null;
}

export function wouldExceedEventCap(run, eventCount, additional = 1) {
  const max = run.safety_constraints?.max_events;
  if (max == null) return false;
  return eventCount + additional > max;
}