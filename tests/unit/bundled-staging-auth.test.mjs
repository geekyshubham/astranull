import assert from 'node:assert/strict';
import test from 'node:test';
import { loginBundledStagingPrincipal } from '../../src/services/bundledStagingAuth.mjs';

test('bundled staging customer login mints access token', () => {
  const result = loginBundledStagingPrincipal(
    { principal: 'customer', tenant_id: 'ten_demo', user_id: 'usr_admin', role: 'admin' },
    { bundledStagingOidc: true },
  );
  assert.equal(result.error, undefined);
  assert.match(result.access_token, /^eyJ/);
  assert.equal(result.principal, 'customer');
  assert.equal(result.role, 'admin');
});

test('bundled staging staff login mints access token', () => {
  const result = loginBundledStagingPrincipal(
    { principal: 'staff', staff_id: 'staff_admin', staff_role: 'internal_admin' },
    { bundledStagingOidc: true },
  );
  assert.equal(result.error, undefined);
  assert.match(result.access_token, /^eyJ/);
  assert.equal(result.principal, 'staff');
  assert.equal(result.staff_role, 'internal_admin');
});

test('bundled staging login refused when fixture disabled', () => {
  const result = loginBundledStagingPrincipal(
    { principal: 'customer' },
    { bundledStagingOidc: false },
  );
  assert.equal(result.error, 'login_disabled');
  assert.equal(result.status, 403);
});