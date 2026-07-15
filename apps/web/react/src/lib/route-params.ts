function routeQueryParams() {
  const hash = window.location.hash.replace(/^#/, '');
  const queryInHash = hash.includes('?') ? hash.slice(hash.indexOf('?') + 1) : '';
  return new URLSearchParams(queryInHash || window.location.search);
}

export function getRouteEntityId(fallback = '') {
  const params = routeQueryParams();
  return params.get('id') ?? params.get('entity_id') ?? fallback;
}

/** Optional tenant scope for staff SOC cross-tenant detail links. */
export function getRouteTenantId(fallback = '') {
  const params = routeQueryParams();
  return params.get('tenant') ?? params.get('tenant_id') ?? fallback;
}

export function buildDetailHref(route: string, id: string, extras: { tenantId?: string } = {}) {
  const encoded = encodeURIComponent(id);
  const tenant = String(extras.tenantId ?? '').trim();
  const tenantQs = tenant ? `&tenant=${encodeURIComponent(tenant)}` : '';
  return `${window.location.pathname}${window.location.search}#${route}?id=${encoded}${tenantQs}`;
}