/**
 * Resolve explicit tenant scope for scheduled/multi-tenant background jobs.
 * Cross-tenant enumeration (e.g. SELECT DISTINCT tenant_id) is forbidden under RLS.
 */

/**
 * @param {{ tenantIds?: string[], tenant_ids?: string[] }} ctx
 * @param {{ label?: string }} [options]
 * @returns {{ tenantIds: string[] } | { error: string, status: number, message: string }}
 */
export function resolveScheduledTenantIds(ctx = {}, options = {}) {
  const raw = ctx.tenantIds ?? ctx.tenant_ids ?? null;
  if (!Array.isArray(raw) || raw.length === 0) {
    const label = options.label ?? 'Scheduled job';
    return {
      error: 'tenant_scope_required',
      status: 400,
      message:
        `${label} requires an explicit tenant_ids list from the operator runner `
        + '(--tenant-id, --tenant-ids-file). Cross-tenant enumeration is not permitted under RLS.',
    };
  }

  const tenantIds = [...new Set(
    raw.map((id) => String(id ?? '').trim()).filter(Boolean),
  )];
  if (tenantIds.length === 0) {
    return {
      error: 'tenant_scope_required',
      status: 400,
      message: 'tenant_ids must contain at least one non-empty tenant id.',
    };
  }

  return { tenantIds };
}

/**
 * @param {string[] | null | undefined} tenantIds
 * @param {'postgres' | 'dev-json'} persistenceMode
 * @param {string} runnerName
 */
export function assertRunnerTenantScope(tenantIds, persistenceMode, runnerName) {
  if (persistenceMode !== 'postgres') return null;
  const scope = resolveScheduledTenantIds(
    { tenantIds: tenantIds ?? [] },
    { label: runnerName },
  );
  if ('error' in scope) {
    return { ok: false, message: `${runnerName}: ${scope.message}` };
  }
  return { ok: true, tenantIds: scope.tenantIds };
}