/**
 * Shared GET /v1/state response builder for dev-json and Postgres parity.
 */

const HS_TERMINAL_STATES = new Set(['closed', 'rejected']);
const HS_ACTIVE_STATES = new Set(['scheduled', 'running']);

/**
 * Derive tenant high-scale program status from wired service data (not a static default).
 *
 * @param {{
 *   highScaleWired?: boolean,
 *   highScaleRequests?: unknown[],
 *   killSwitch?: { active?: boolean } | null,
 *   rollupStatus?: unknown,
 *   requestCount?: number | null,
 * }} input
 */
export function computeHighScaleStatus({
  highScaleWired = false,
  highScaleRequests = [],
  killSwitch = null,
  rollupStatus = null,
  requestCount = null,
} = {}) {
  if (typeof rollupStatus === 'string' && rollupStatus.trim()) {
    return rollupStatus.trim();
  }
  if (!highScaleWired) {
    return 'postgres_high_scale_not_wired';
  }
  if (killSwitch?.active === true) {
    return 'degraded';
  }

  const requests = Array.isArray(highScaleRequests) ? highScaleRequests : [];
  const open = requests.filter((row) => !HS_TERMINAL_STATES.has(String(row?.state ?? '')));
  if (open.some((row) => HS_ACTIVE_STATES.has(String(row?.state ?? '')))) {
    return 'active';
  }
  if (open.length > 0) {
    return 'pending';
  }

  const count = Number(requestCount ?? 0);
  if (Number.isFinite(count) && count > 0) {
    return 'pending';
  }
  return 'available';
}

/** @deprecated Use computeHighScaleStatus — kept for existing unit imports. */
export function deriveHighScaleStatus({ rollup, highScaleWired = false, highScaleRequests = [], killSwitch = null }) {
  return computeHighScaleStatus({
    highScaleWired,
    highScaleRequests,
    killSwitch,
    rollupStatus: rollup?.high_scale_status,
    requestCount: rollup?.high_scale_requests,
  });
}

/**
 * @param {{ rollup?: Record<string, unknown> | null, computed?: { high_scale_status?: string } | null }} input
 */
export function resolveHighScaleStatus({ rollup, computed }) {
  if (typeof rollup?.high_scale_status === 'string' && rollup.high_scale_status.trim()) {
    return rollup.high_scale_status;
  }
  if (typeof computed?.high_scale_status === 'string' && computed.high_scale_status.trim()) {
    return computed.high_scale_status;
  }
  return 'available';
}

/**
 * @param {{
 *   tenantId: string,
 *   rollup?: Record<string, unknown> | null,
 *   computed: {
 *     readiness: unknown,
 *     target_groups: number,
 *     agents_online: number,
 *     recent_runs: unknown[],
 *     open_findings: number,
 *     high_scale_requests: number,
 *   },
 *   killSwitch: unknown,
 *   highScaleWired?: boolean,
 *   highScaleRequests?: unknown[],
 * }} input
 */
export function buildGetStatePayload({
  tenantId,
  rollup,
  computed,
  killSwitch,
  highScaleWired = false,
  highScaleRequests = [],
}) {
  const hasRollupReadiness = rollup?.readiness && typeof rollup.readiness === 'object';
  const requestCount = Number(rollup?.high_scale_requests ?? computed.high_scale_requests);
  const highScaleStatus = computeHighScaleStatus({
    highScaleWired,
    highScaleRequests,
    killSwitch,
    rollupStatus: rollup?.high_scale_status,
    requestCount,
  });
  return {
    tenant_id: tenantId,
    readiness: hasRollupReadiness ? rollup.readiness : computed.readiness,
    target_groups: Number(rollup?.target_groups ?? computed.target_groups),
    agents_online: Number(rollup?.agents_online ?? computed.agents_online),
    recent_runs: Array.isArray(rollup?.recent_runs) ? rollup.recent_runs : computed.recent_runs,
    open_findings: Number(rollup?.open_findings ?? computed.open_findings),
    high_scale_requests: requestCount,
    high_scale_status: resolveHighScaleStatus({
      rollup,
      computed: { high_scale_status: highScaleStatus },
    }),
    kill_switch: killSwitch,
  };
}