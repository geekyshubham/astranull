import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  isStaffRole,
  staffRoleHasPermission,
  STAFF_ROLES,
} from '../../src/contracts/staffRoles.mjs';
import {
  isInternalAdminApiRoute,
  isInternalAdminPageRoute,
  isInternalAdminRoute,
  isPublicApiRoute,
} from '../../src/lib/staffAuth.mjs';

describe('staff roles and route boundaries', () => {
  it('defines staff roles separate from customer roles', () => {
    assert.ok(STAFF_ROLES.includes('internal_admin'));
    assert.ok(!STAFF_ROLES.includes('owner'));
    assert.equal(isStaffRole('internal_admin'), true);
    assert.equal(isStaffRole('admin'), false);
  });

  it('gates staff permissions by role', () => {
    assert.equal(staffRoleHasPermission('internal_admin', 'staff:signup:decide'), true);
    assert.equal(staffRoleHasPermission('support_engineer', 'staff:signup:decide'), false);
    assert.equal(staffRoleHasPermission('billing_ops', 'staff:subscription:write'), true);
  });

  it('classifies public and internal admin routes', () => {
    assert.equal(isPublicApiRoute('/v1/signup-requests', 'POST'), true);
    assert.equal(isPublicApiRoute('/v1/public/site-config', 'GET'), true);
    assert.equal(isPublicApiRoute('/v1/tenants/current', 'GET'), false);
    assert.equal(isInternalAdminRoute('/internal/admin/tenants'), true);
    assert.equal(isInternalAdminRoute('/internal/soc/kill-switch'), false);
    assert.equal(isInternalAdminPageRoute('/internal/admin', 'GET'), true);
    assert.equal(isInternalAdminApiRoute('/internal/admin', 'GET'), false);
    assert.equal(isInternalAdminApiRoute('/internal/admin/tenants', 'GET'), true);
  });
});