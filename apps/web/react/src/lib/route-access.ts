import type { RouteId } from './types';

const STAFF_SOC_ROLES = new Set(['soc_analyst', 'soc_lead', 'admin']);

/**
 * Permission keys used by route gates — keep aligned with `src/contracts/roles.mjs` PERMISSIONS.
 * Node tests import `route-access.mjs`, which delegates to `roleHasPermission` from roles.mjs.
 */
const ROUTE_BACKEND_PERMISSIONS: Record<string, readonly string[]> = {
  'notification:read': ['owner', 'admin', 'engineer', 'soc', 'auditor'],
  'audit:read': ['owner', 'admin', 'soc', 'auditor'],
  'soc:high_scale': ['soc'],
};

/** Customer portal routes gated by backend RBAC keys in `src/contracts/roles.mjs`. */
const ROUTE_PERMISSION: Partial<Record<RouteId, string>> = {
  notifications: 'notification:read',
  audit: 'audit:read',
};

const STAFF_ONLY_ROUTES = new Set<RouteId>(['admin', 'tenant-detail']);
const STAFF_SOC_ROUTES = new Set<RouteId>(['internal-soc', 'queue-detail']);

export type RouteAccessContext = {
  principal?: string;
  staffRole?: string;
};

function roleHasPermission(role: string, permission: string): boolean {
  const allowed = ROUTE_BACKEND_PERMISSIONS[permission];
  if (!allowed) return false;
  return allowed.includes(role);
}

export function canAccessRoute(
  role: string | undefined,
  routeId: RouteId,
  context: RouteAccessContext = {}
): boolean {
  const normalizedRole = String(role ?? '').trim().toLowerCase();
  const principal = String(context.principal ?? 'customer').trim().toLowerCase();
  const staffRole = String(context.staffRole ?? '').trim().toLowerCase();

  if (STAFF_ONLY_ROUTES.has(routeId)) {
    return principal === 'staff';
  }

  if (STAFF_SOC_ROUTES.has(routeId)) {
    return principal === 'staff' && STAFF_SOC_ROLES.has(staffRole);
  }

  const permission = ROUTE_PERMISSION[routeId];
  if (!permission) {
    return true;
  }

  return roleHasPermission(normalizedRole, permission);
}