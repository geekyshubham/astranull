import { roleHasPermission } from '../../../../../src/contracts/roles.mjs';

/** Align with isStaffSocRole in api.ts — operational SOC staff only. */
const STAFF_SOC_ROLES = new Set(['soc_analyst', 'soc_lead']);

/** Customer portal routes gated by backend RBAC keys in `src/contracts/roles.mjs`. */
const ROUTE_PERMISSION = Object.freeze({
  notifications: 'notification:read',
  audit: 'audit:read',
  reports: 'report:read',
  'release-evidence': 'release_evidence:read',
});

const STAFF_ONLY_ROUTES = new Set(['admin', 'tenant-detail']);
/** Staff-only SOC execution console. queue-detail is shared for customer pack completion. */
const STAFF_SOC_ROUTES = new Set(['internal-soc']);

/**
 * @param {string | undefined} role
 * @param {string} routeId
 * @param {{ principal?: string; staffRole?: string }} [context]
 */
export function canAccessRoute(role, routeId, context = {}) {
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