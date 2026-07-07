import { PORTAL_BASELINE_IDS } from '../fixtures/portal-baseline/seed.mjs';

/** Baseline entity IDs for detail-route hash query params (`route-params.ts`). */
export const PORTAL_DETAIL_ENTITY_IDS = Object.freeze({
  'target-group-detail': PORTAL_BASELINE_IDS.targetGroupId,
  'target-detail': PORTAL_BASELINE_IDS.targetId,
  'agent-detail': PORTAL_BASELINE_IDS.agentId,
  'run-detail': 'run_checkout_1',
  'finding-detail': PORTAL_BASELINE_IDS.findingId,
  'report-detail': 'rpt_checkout_baseline',
  'tenant-detail': PORTAL_BASELINE_IDS.tenantId,
  'queue-detail': 'hsr_checkout_scheduled',
});

/** Customer-visible sidebar routes from `navigation.ts` NAV_ITEMS (excludes staff). */
export const NAV_ROUTE_IDS = Object.freeze([
  'dashboard',
  'environments',
  'target-groups',
  'agents',
  'checks',
  'test-policies',
  'runs',
  'findings',
  'reports',
  'integrations',
  'notifications',
  'audit',
  'settings',
  'support',
  'subscription',
]);

/** Staff sidebar routes from `navigation.ts` NAV_ITEMS. */
export const STAFF_NAV_ROUTE_IDS = Object.freeze([
  'admin',
  'internal-soc',
]);

/** Deep-link detail routes from `navigation.ts` DETAIL_ROUTE_ITEMS. */
export const DETAIL_ROUTE_IDS = Object.freeze([
  'target-group-detail',
  'target-detail',
  'agent-detail',
  'run-detail',
  'finding-detail',
  'report-detail',
  'tenant-detail',
  'queue-detail',
]);

/** Public routes from docs/ux/14 §3.2. */
export const PUBLIC_ROUTE_ENTRIES = Object.freeze([
  { routeId: 'landing', pathname: '/' },
  { routeId: 'login', pathname: '/login' },
  { routeId: 'signup', pathname: '/signup' },
  { routeId: 'signup-status', pathname: '/signup-status' },
  { routeId: 'staff-login', pathname: '/internal/admin/login' },
]);

/**
 * FT-A11Y-01 route matrix: 25 app routes (NAV_ITEMS + DETAIL_ROUTE_ITEMS) + 5 public routes.
 * @typedef {'public' | 'customer' | 'staff-admin' | 'staff-soc'} PortalRouteSurface
 * @typedef {{ routeId: string, surface: PortalRouteSurface, pathname?: string }} PortalRouteScan
 */

/** @type {readonly PortalRouteScan[]} */
export const ROUTES_TO_SCAN = Object.freeze([
  ...PUBLIC_ROUTE_ENTRIES.map((entry) => ({
    routeId: entry.routeId,
    surface: 'public',
    pathname: entry.pathname,
  })),
  ...NAV_ROUTE_IDS.map((routeId) => ({
    routeId,
    surface: 'customer',
  })),
  ...STAFF_NAV_ROUTE_IDS.map((routeId) => ({
    routeId,
    surface: routeId === 'internal-soc' ? 'staff-soc' : 'staff-admin',
  })),
  ...DETAIL_ROUTE_IDS.map((routeId) => ({
    routeId,
    surface: routeId === 'tenant-detail'
      ? 'staff-admin'
      : routeId === 'queue-detail'
        ? 'staff-soc'
        : 'customer',
  })),
]);