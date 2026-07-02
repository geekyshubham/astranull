import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { roleHasPermission } from '../../src/contracts/roles.mjs';
import { requirePermission } from '../../src/rbac.mjs';
import { freshStore } from '../helpers/reset.mjs';
import { getStore } from '../../src/store.mjs';

describe('RBAC', () => {
  it('denies viewer WAF mutation permissions while allowing read', () => {
    assert.equal(roleHasPermission('viewer', 'waf:read'), true);
    assert.equal(roleHasPermission('viewer', 'discovery:read'), true);
    assert.equal(roleHasPermission('viewer', 'cve_pipeline:read'), true);
    assert.equal(roleHasPermission('viewer', 'waf:write'), false);
    assert.equal(roleHasPermission('viewer', 'waf:run'), false);
    assert.equal(roleHasPermission('viewer', 'waf:connector_write'), false);
    assert.equal(roleHasPermission('viewer', 'discovery:write'), false);
    assert.equal(roleHasPermission('viewer', 'discovery:approve'), false);
  });

  it('allows engineer safe WAF run and denies connector write', () => {
    assert.equal(roleHasPermission('engineer', 'waf:run'), true);
    assert.equal(roleHasPermission('engineer', 'waf:write'), true);
    assert.equal(roleHasPermission('engineer', 'waf:connector_read'), true);
    assert.equal(roleHasPermission('engineer', 'waf:connector_write'), false);
    assert.equal(roleHasPermission('auditor', 'waf:connector_read'), true);
    assert.equal(roleHasPermission('auditor', 'waf:write'), false);
  });

  it('denies engineer SOC high-scale permission and audits', () => {
    freshStore();
    const ctx = { tenantId: 'ten_demo', userId: 'eng1', role: 'engineer' };
    const gate = requirePermission(ctx, 'soc:high_scale', { resource_type: 'high_scale' });
    assert.equal(gate.ok, false);
    assert.equal(gate.status, 403);
    const denied = getStore().auditLog.find((a) => a.action === 'rbac.denied');
    assert.ok(denied);
  });
});