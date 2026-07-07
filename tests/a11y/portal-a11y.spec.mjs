import { expect, test } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { applyPortalBaselineReadinessBoost } from '../fixtures/portal-baseline/readiness.mjs';
import {
  getPortalPlaywrightBaseUrl,
  startPortalPlaywrightServer,
  stopPortalPlaywrightServer,
} from '../helpers/portal-playwright-server.mjs';
import {
  gotoPortalRoute,
  gotoPublicPortalRoute,
  injectPortalSessionForSurface,
} from '../helpers/portal-playwright-session.mjs';
import { ROUTES_TO_SCAN } from '../helpers/portal-routes.mjs';

const AXE_TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/**
 * @param {import('@axe-core/playwright').AxeResults} results
 */
function formatBlockingViolations(results) {
  return results.violations
    .filter((violation) => violation.impact === 'critical' || violation.impact === 'serious')
    .map((violation) => `${violation.id} (${violation.impact}): ${violation.help}`)
    .join('\n');
}

/**
 * @param {import('@playwright/test').Page} page
 */
async function assertNoCriticalOrSeriousViolations(page) {
  const results = await new AxeBuilder({ page })
    .withTags(AXE_TAGS)
    .analyze();

  const blocking = results.violations.filter((violation) => (
    violation.impact === 'critical' || violation.impact === 'serious'
  ));

  expect(
    blocking,
    formatBlockingViolations(results),
  ).toEqual([]);
}

test.describe('portal accessibility (FT-A11Y-01)', () => {
  test.beforeAll(async () => {
    await startPortalPlaywrightServer({ mutate: applyPortalBaselineReadinessBoost });
  });

  test.afterAll(async () => {
    await stopPortalPlaywrightServer();
  });

  test.describe.parallel('axe-core route scans', () => {
    for (const routeEntry of ROUTES_TO_SCAN) {
      const label = routeEntry.pathname ?? routeEntry.routeId;

      test(`${label} has no critical or serious axe violations`, async ({ page }) => {
        const baseUrl = getPortalPlaywrightBaseUrl();
        await injectPortalSessionForSurface(page, routeEntry.surface);

        if (routeEntry.surface === 'public') {
          await gotoPublicPortalRoute(page, routeEntry.pathname, baseUrl);
        } else {
          await gotoPortalRoute(page, routeEntry.routeId, baseUrl);
        }

        await assertNoCriticalOrSeriousViolations(page);
      });
    }
  });
});