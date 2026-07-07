import { PORTAL_BASELINE_IDS } from '../fixtures/portal-baseline/seed.mjs';
import { PORTAL_DETAIL_ENTITY_IDS } from './portal-routes.mjs';

export const PORTAL_SESSION = Object.freeze({
  mode: 'dev-headers',
  principal: 'customer',
  tenant_id: PORTAL_BASELINE_IDS.tenantId,
  user_id: 'usr_owner',
  role: 'owner',
});

export const PORTAL_STAFF_SESSION = Object.freeze({
  mode: 'dev-headers',
  principal: 'staff',
  staff_id: 'staff_admin',
  staff_role: 'internal_admin',
  role: 'internal_admin',
});

export const PORTAL_STAFF_SOC_SESSION = Object.freeze({
  mode: 'dev-headers',
  principal: 'staff',
  staff_id: 'staff_soc',
  staff_role: 'soc_analyst',
  role: 'soc_analyst',
});

const STAFF_ADMIN_ROUTE_IDS = new Set(['admin', 'tenant-detail']);
const STAFF_SOC_ROUTE_IDS = new Set(['internal-soc', 'queue-detail']);

/**
 * Inject dev-headers portal session before navigation (matches demoHeaders / pp-06 pattern).
 * @param {import('@playwright/test').Page} page
 * @param {Record<string, unknown>} [session]
 */
export async function injectPortalDevHeadersSession(page, session = PORTAL_SESSION) {
  await page.addInitScript((value) => {
    sessionStorage.setItem('astranull.portal.session.v1', JSON.stringify(value));
  }, session);
}

/**
 * Clear any persisted portal session (public routes).
 * @param {import('@playwright/test').Page} page
 */
export async function clearPortalSession(page) {
  await page.addInitScript(() => {
    sessionStorage.removeItem('astranull.portal.session.v1');
  });
}

/**
 * @param {string} routeId
 * @param {Record<string, string>} [entityIds]
 */
export function buildPortalRouteHash(routeId, entityIds = PORTAL_DETAIL_ENTITY_IDS) {
  const entityId = entityIds[routeId];
  if (entityId) {
    return `${routeId}?id=${encodeURIComponent(entityId)}`;
  }
  return routeId;
}

/**
 * @param {string} routeId
 * @param {string} baseUrl
 * @param {{ entityIds?: Record<string, string> }} [options]
 */
export function resolvePortalRouteUrl(routeId, baseUrl, options = {}) {
  const hash = buildPortalRouteHash(routeId, options.entityIds);

  if (STAFF_ADMIN_ROUTE_IDS.has(routeId)) {
    return `${baseUrl}/internal/admin#${hash}`;
  }
  if (routeId === 'internal-soc') {
    return `${baseUrl}/internal/soc`;
  }
  if (routeId === 'queue-detail') {
    return `${baseUrl}/internal/soc#${hash}`;
  }
  return `${baseUrl}/app#${hash}`;
}

/**
 * @param {import('@playwright/test').Page} page
 * @param {string} routeId
 * @param {string} baseUrl
 * @param {{ entityIds?: Record<string, string> }} [options]
 */
export async function gotoPortalRoute(page, routeId, baseUrl, options = {}) {
  const url = resolvePortalRouteUrl(routeId, baseUrl, options);
  await page.goto(url, { waitUntil: 'networkidle', timeout: 60_000 });
}

/**
 * @param {import('@playwright/test').Page} page
 * @param {string} pathname
 * @param {string} baseUrl
 */
export async function gotoPublicPortalRoute(page, pathname, baseUrl) {
  await page.goto(`${baseUrl}${pathname}`, { waitUntil: 'networkidle', timeout: 60_000 });
}

/**
 * @param {import('@playwright/test').Page} page
 * @param {'public' | 'customer' | 'staff-admin' | 'staff-soc'} surface
 */
export async function injectPortalSessionForSurface(page, surface) {
  if (surface === 'public') {
    await clearPortalSession(page);
    return;
  }
  if (surface === 'staff-admin') {
    await injectPortalDevHeadersSession(page, PORTAL_STAFF_SESSION);
    return;
  }
  if (surface === 'staff-soc') {
    await injectPortalDevHeadersSession(page, PORTAL_STAFF_SOC_SESSION);
    return;
  }
  await injectPortalDevHeadersSession(page, PORTAL_SESSION);
}