/**
 * Portal revamp RBAC integration tests (docs/ux/17 §7).
 */
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { roleHasPermission } from '../../src/contracts/roles.mjs';
import { canAccessRoute } from '../../apps/web/react/src/lib/route-access.mjs';

/** 25 surviving portal RouteId values (docs/ux/14 §3). */
const PORTAL_ROUTES = Object.freeze([
  'dashboard',
  'environments',
  'target-groups',
  'target-group-detail',
  'target-detail',
  'agents',
  'agent-detail',
  'checks',
  'test-policies',
  'runs',
  'run-detail',
  'findings',
  'finding-detail',
  'reports',
  'report-detail',
  'integrations',
  'notifications',
  'audit',
  'settings',
  'support',
  'subscription',
  'admin',
  'tenant-detail',
  'internal-soc',
  'queue-detail',
]);

/** Fifteen customer + two staff sidebar entries from navigation.ts NAV_ITEMS. */
const SIDEBAR_ROUTE_IDS = Object.freeze([
  'dashboard',
  'environments',
  'target-groups',
  'agents',
  'checks',
  'test-policies',
  'runs',
  'findings',
  'integrations',
  'reports',
  'settings',
  'support',
  'notifications',
  'audit',
  'subscription',
  'admin',
  'internal-soc',
]);

const STAFF_ONLY_ROUTES = new Set(['admin', 'tenant-detail']);
const STAFF_SOC_ROUTES = new Set(['internal-soc', 'queue-detail']);
const PERMISSION_GATED_ROUTES = Object.freeze({
  notifications: 'notification:read',
  audit: 'audit:read',
});

const CUSTOMER_ROLES = ['owner', 'engineer', 'viewer', 'auditor', 'admin', 'soc'];
const STAFF_SOC_ROLES = ['soc_analyst', 'soc_lead', 'admin'];

function expectedCustomerAccess(role, routeId) {
  if (STAFF_ONLY_ROUTES.has(routeId) || STAFF_SOC_ROUTES.has(routeId)) {
    return false;
  }
  const permission = PERMISSION_GATED_ROUTES[routeId];
  if (permission) {
    return roleHasPermission(role, permission);
  }
  return true;
}

function filterSidebar(role, principal, staffRole) {
  return SIDEBAR_ROUTE_IDS.filter((routeId) =>
    canAccessRoute(role, routeId, { principal, staffRole }),
  );
}

describe('portal RBAC matrix (FT-RBAC-01..03)', () => {
  it('FT-RBAC-01 customer route-access matches roles.mjs permission gates', () => {
    for (const role of CUSTOMER_ROLES) {
      for (const routeId of PORTAL_ROUTES) {
        const allowed = canAccessRoute(role, routeId, { principal: 'customer' });
        const expected = expectedCustomerAccess(role, routeId);
        assert.equal(
          allowed,
          expected,
          `role=${role} route=${routeId} expected=${expected} got=${allowed}`,
        );
      }
    }
  });

  it('FT-RBAC-02 staff-only surfaces are absent from every non-staff sidebar', () => {
    for (const role of CUSTOMER_ROLES) {
      const visible = filterSidebar(role, 'customer');
      for (const routeId of STAFF_ONLY_ROUTES) {
        assert.equal(
          visible.includes(routeId),
          false,
          `customer role=${role} must not see staff route ${routeId}`,
        );
      }
      assert.equal(visible.includes('internal-soc'), false);
    }
  });

  it('FT-RBAC-03 SOC console requires staff principal with SOC staff role', () => {
    for (const role of CUSTOMER_ROLES) {
      assert.equal(
        canAccessRoute(role, 'internal-soc', { principal: 'customer' }),
        false,
        `customer principal must not access internal-soc (role=${role})`,
      );
    }

    assert.equal(
      canAccessRoute('admin', 'internal-soc', { principal: 'staff', staffRole: 'support_engineer' }),
      false,
    );

    for (const staffRole of STAFF_SOC_ROLES) {
      assert.equal(
        canAccessRoute('admin', 'internal-soc', { principal: 'staff', staffRole }),
        true,
        `staff SOC role ${staffRole} must access internal-soc`,
      );
      assert.equal(
        canAccessRoute('admin', 'queue-detail', { principal: 'staff', staffRole }),
        true,
        `staff SOC role ${staffRole} must access queue-detail`,
      );
    }
  });
});