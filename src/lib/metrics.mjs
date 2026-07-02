import { getStore } from '../store.mjs';

const COUNTERS = {
  http_requests_total: 0,
  api_errors_total: 0,
  test_runs_started_total: 0,
  events_ingested_total: 0,
  high_scale_transitions_total: 0,
  api_rate_limited_total: 0,
};

export function incMetric(name, delta = 1) {
  COUNTERS[name] = (COUNTERS[name] ?? 0) + delta;
}

export function metricsSnapshot() {
  return { ...COUNTERS };
}

export function metricsPlaintext() {
  return Object.entries(COUNTERS)
    .map(([k, v]) => `${k} ${v}`)
    .join('\n');
}

/**
 * Postgres-mode observability summary from tenant state (no dev JSON store reads).
 * @param {object} state
 */
export function observabilityFromState(state) {
  return {
    service: 'astranull',
    persistence: 'postgres',
    tenant_id: state.tenant_id,
    counters: metricsSnapshot(),
    target_groups: state.target_groups ?? 0,
    agents_online: state.agents_online ?? 0,
    test_runs_recent: Array.isArray(state.recent_runs) ? state.recent_runs.length : 0,
    open_findings: state.open_findings ?? 0,
    high_scale_requests: state.high_scale_requests ?? 0,
    note: 'Metadata-only observability; no packet payloads.',
  };
}

export function observabilityJson() {
  const store = getStore();
  return {
    service: 'astranull',
    counters: metricsSnapshot(),
    tenants: store.tenants.length,
    environments: store.environments.length,
    agents: store.agents.length,
    test_runs: store.testRuns.length,
    evidence_records: (store.evidenceVault ?? []).length,
    notifications: (store.notificationEvents ?? []).length,
    note: 'Metadata-only observability; no packet payloads.',
  };
}