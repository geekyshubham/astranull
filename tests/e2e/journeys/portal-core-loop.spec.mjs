import { expect, test } from '@playwright/test';
import { applyPortalBaselineReadinessBoost } from '../../fixtures/portal-baseline/readiness.mjs';
import { PORTAL_BASELINE_IDS } from '../../fixtures/portal-baseline/seed.mjs';
import {
  fetchPortalReadinessScore,
  getPortalPlaywrightBaseUrl,
  portalOwnerHeaders,
  startPortalPlaywrightServer,
  stopPortalPlaywrightServer,
} from '../../helpers/portal-playwright-server.mjs';
import {
  gotoPortalRoute,
  injectPortalDevHeadersSession,
} from '../../helpers/portal-playwright-session.mjs';

test.describe('portal core loop (Playwright)', () => {
  test.beforeAll(async () => {
    await startPortalPlaywrightServer({ mutate: applyPortalBaselineReadinessBoost });
  });

  test.afterAll(async () => {
    await stopPortalPlaywrightServer();
  });
  test('dashboard renders readiness score from GET /v1/state', async ({ page }) => {
    const baseUrl = getPortalPlaywrightBaseUrl();
    const apiScore = await fetchPortalReadinessScore(baseUrl);

    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'dashboard', baseUrl);

    await expect(page.getByText('Readiness score', { exact: true })).toBeVisible();
    await expect(page.getByText(String(apiScore), { exact: true }).first()).toBeVisible();
  });

  test('target-groups lists baseline seed group name', async ({ page }) => {
    const baseUrl = getPortalPlaywrightBaseUrl();
    const groupsRes = await fetch(`${baseUrl}/v1/target-groups`, { headers: portalOwnerHeaders() });
    expect(groupsRes.ok).toBeTruthy();
    const groupsJson = await groupsRes.json();
    const seededGroup = (groupsJson.items ?? []).find((item) => item.id === PORTAL_BASELINE_IDS.targetGroupId);
    expect(seededGroup?.name).toBe('edge-checkout');

    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'target-groups', baseUrl);

    await expect(page.getByText('Declared target groups')).toBeVisible();
    await expect(page.getByRole('cell', { name: 'edge-checkout' })).toBeVisible();
  });
});