import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { buildPortalDemoStore, PORTAL_DEMO_IDS } from '../fixtures/portal-demo/seed.mjs';

describe('portal demo seed fixture', () => {
  it('fills every major portal surface for ten_demo', () => {
    const store = buildPortalDemoStore();
    const tenantId = PORTAL_DEMO_IDS.tenantId;

    assert.ok(store.tenants.some((row) => row.id === tenantId));
    assert.ok(store.environments.filter((row) => row.tenant_id === tenantId).length >= 2);
    assert.ok(store.targetGroups.filter((row) => row.tenant_id === tenantId).length >= 1);
    assert.ok(store.targets.filter((row) => row.tenant_id === tenantId).length >= 5);
    assert.ok(store.agents.filter((row) => row.tenant_id === tenantId).length >= 1);
    assert.ok(store.testRuns.filter((row) => row.tenant_id === tenantId).length >= 3);
    assert.ok(store.findings.filter((row) => row.tenant_id === tenantId).length >= 2);
    assert.ok(store.reports.filter((row) => row.tenant_id === tenantId).length >= 2);
    assert.ok(store.notificationRules.filter((row) => row.tenant_id === tenantId).length >= 2);
    assert.ok(store.notificationEvents.filter((row) => row.tenant_id === tenantId).length >= 2);
    assert.ok(store.auditLog.filter((row) => row.tenant_id === tenantId).length >= 4);
    assert.ok(store.tenantSubscriptions.some((row) => row.tenant_id === tenantId));
    assert.ok(store.signupRequests.length >= 2);
    assert.ok(store.highScaleRequests.filter((row) => row.tenant_id === tenantId).length >= 3);
    assert.ok(store.productionReleaseEvidence.filter((row) => row.tenant_id === tenantId).length >= 2);
    assert.ok(store.wafConnectors.filter((row) => row.tenant_id === tenantId).length >= 1);
    assert.ok(store.bootstrapTokens.filter((row) => row.tenant_id === tenantId).length >= 1);
    assert.ok(store.reports.some((row) => row.id === PORTAL_DEMO_IDS.reportId));
  });
});