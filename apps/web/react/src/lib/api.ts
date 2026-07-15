import type { DataItem, PortalConfig, PortalData, RouteId, Session } from './types';
import { asArray } from './utils';

const SESSION_KEY = 'astranull.portal.session.v1';

export type PortalSessionGate = {
  config: PortalConfig;
  session: Session | null;
  redirectToLogin: boolean;
  loginUrl?: string;
  errorMessage?: string;
};

export function isOidcJwtMode(config: Pick<PortalConfig, 'authMode'>) {
  return config.authMode === 'oidc-jwt';
}

export function isExternalAuthUrl(url: string) {
  const trimmed = url.trim();
  return /^https?:\/\//i.test(trimmed);
}

/** Derive portal auth surface from the browser pathname. */
export function portalSurface(pathname: string): 'customer' | 'staff' {
  const path = pathname.replace(/\/+$/, '') || '/';
  if (path === '/internal/admin' || path.startsWith('/internal/admin/')) {
    return 'staff';
  }
  if (path === '/internal/soc' || path.startsWith('/internal/soc/')) {
    return 'staff';
  }
  return 'customer';
}

/** When oidc-jwt is active without bundled staging, redirect to a configured enterprise IdP URL. */
export function resolveOidcLoginRedirect(
  config: PortalConfig,
  surface: 'customer' | 'staff' = 'customer'
): string | null {
  if (!isOidcJwtMode(config) || config.bundledLoginEnabled) return null;
  const loginUrl = surface === 'staff' ? config.staffLoginPath : config.loginUrl;
  return isExternalAuthUrl(loginUrl) ? loginUrl : null;
}

export function sessionFromLoginResponse(loginResponse: Record<string, unknown>): Session {
  const expiresIn = Number(loginResponse.expires_in ?? 3600);
  return {
    mode: 'oidc',
    access_token: String(loginResponse.access_token ?? ''),
    principal: String(loginResponse.principal ?? 'customer'),
    tenant_id: loginResponse.tenant_id != null ? String(loginResponse.tenant_id) : undefined,
    user_id: loginResponse.user_id != null ? String(loginResponse.user_id) : undefined,
    role: loginResponse.role != null ? String(loginResponse.role) : undefined,
    staff_id: loginResponse.staff_id != null ? String(loginResponse.staff_id) : undefined,
    staff_role: loginResponse.staff_role != null ? String(loginResponse.staff_role) : undefined,
    expires_at: Date.now() + expiresIn * 1000
  };
}

export function loadSession(): Session | null {
  try {
    const raw = sessionStorage.getItem(SESSION_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Session;
    if (!parsed || typeof parsed !== 'object') return null;
    if (parsed.expires_at && Date.now() > Number(parsed.expires_at)) {
      sessionStorage.removeItem(SESSION_KEY);
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

export function saveSession(session: Session) {
  sessionStorage.setItem(SESSION_KEY, JSON.stringify(session));
}

export function clearSession() {
  sessionStorage.removeItem(SESSION_KEY);
}

export function sessionIdentity(session: Session | null | undefined) {
  if (!session) return '';
  return JSON.stringify({
    tenant_id: session.tenant_id ?? '',
    user_id: session.user_id ?? '',
    principal: session.principal ?? '',
    staff_id: session.staff_id ?? '',
    role: session.role ?? '',
    staff_role: session.staff_role ?? ''
  });
}

export async function fetchPortalConfig(): Promise<PortalConfig> {
  const [readyRes, siteRes] = await Promise.all([
    fetch('/ready').catch(() => null),
    fetch('/v1/public/site-config').catch(() => null)
  ]);
  const ready = readyRes?.ok ? await readyRes.json().catch(() => ({})) : {};
  const siteConfig = siteRes?.ok ? await siteRes.json().catch(() => ({})) : {};
  const authMode = String(ready.auth_mode ?? siteConfig.auth_mode ?? 'dev-headers');
  return {
    authMode,
    siteConfig,
    bundledLoginEnabled: siteConfig.bundled_staging_login_enabled === true,
    loginUrl: String(siteConfig.login_url ?? '/login'),
    portalPath: String(siteConfig.customer_portal_path ?? '/app'),
    staffLoginPath: '/internal/admin/login'
  };
}

export async function ensurePortalSession(surface: 'customer' | 'staff' = 'customer'): Promise<PortalSessionGate> {
  const config = await fetchPortalConfig();
  const session = loadSession();

  if (config.authMode === 'dev-headers') {
    if (!session) {
      const bootstrap = surface === 'staff'
        ? {
          mode: 'dev-headers',
          principal: 'staff',
          staff_id: 'staff_admin',
          staff_role: 'internal_admin'
        }
        : {
          mode: 'dev-headers',
          principal: 'customer',
          tenant_id: 'ten_demo',
          user_id: 'usr_admin',
          role: 'admin'
        };
      saveSession(bootstrap);
      return { config, session: bootstrap, redirectToLogin: false };
    }
    return { config, session, redirectToLogin: false };
  }

  const loginPath = surface === 'staff'
    ? (session?.staff_login_path ?? config.staffLoginPath)
    : config.loginUrl;
  const hasToken = Boolean(String(session?.access_token ?? '').trim());
  const principalOk = surface === 'staff'
    ? session?.principal === 'staff'
    : session?.principal !== 'staff';

  if (!hasToken || !principalOk) {
    const idpRedirect = resolveOidcLoginRedirect(config, surface);
    if (idpRedirect) {
      return { config, session: null, redirectToLogin: true, loginUrl: idpRedirect };
    }
    if (config.bundledLoginEnabled) {
      return { config, session: null, redirectToLogin: true, loginUrl: loginPath };
    }
    return {
      config,
      session: null,
      redirectToLogin: true,
      loginUrl: loginPath,
      errorMessage: 'Sign in is required. Configure enterprise SSO or enable bundled staging login for this environment.'
    };
  }

  return { config, session, redirectToLogin: false };
}

/** Operational staff SOC roles — must match route-access STAFF_SOC_ROLES. */
export const STAFF_SOC_ROLES = new Set(['soc_analyst', 'soc_lead']);

export function isStaffSocRole(session: Session) {
  return STAFF_SOC_ROLES.has(String(session.staff_role ?? '').trim().toLowerCase());
}

export function buildApiHeaders(config: PortalConfig, session: Session) {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    accept: 'application/json'
  };
  if (config.authMode === 'dev-headers') {
    if (session.principal === 'staff') {
      headers['x-principal-type'] = 'staff';
      headers['x-staff-id'] = String(session.staff_id ?? session.user_id ?? 'staff_dev');
      headers['x-staff-role'] = String(session.staff_role ?? session.role ?? 'support_engineer');
      return headers;
    }
    headers['x-tenant-id'] = String(session.tenant_id ?? 'ten_demo');
    headers['x-user-id'] = String(session.user_id ?? 'usr_admin');
    headers['x-role'] = String(session.role ?? 'admin');
    return headers;
  }
  const token = String(session.access_token ?? '').trim();
  if (token) headers.authorization = `Bearer ${token}`;
  return headers;
}

/**
 * Staff SOC surface impersonates tenant SOC role for governed execution routes.
 * - dev-headers: rewrite to tenant + x-role:soc (never silent ten_demo for staff without tenant).
 * - oidc-jwt: staff cannot spoof SOC claims; require an explicit tenant SOC path (throws).
 */
export function buildSocCustomerHeaders(
  config: PortalConfig,
  session: Session,
  tenantId?: string
) {
  const resolvedTenant = String(tenantId ?? session.tenant_id ?? '').trim();
  const headers = buildApiHeaders(config, session);
  if (config.authMode === 'dev-headers') {
    if (session.principal === 'staff' && !resolvedTenant) {
      throw new Error(
        'Select an execution tenant before running staff SOC actions. Cross-tenant Open links pass ?tenant=…, or set a tenant on the SOC console.'
      );
    }
    const tenant = resolvedTenant || 'ten_demo';
    delete headers['x-principal-type'];
    delete headers['x-staff-id'];
    delete headers['x-staff-role'];
    headers['x-tenant-id'] = tenant;
    headers['x-user-id'] = String(session.staff_id ?? session.user_id ?? 'staff_soc');
    headers['x-role'] = 'soc';
    return headers;
  }
  if (session.principal === 'staff') {
    throw new Error(
      'Staff SOC tenant impersonation is not available in oidc-jwt mode. Use a tenant SOC session or local dev-headers for governed execution.'
    );
  }
  return headers;
}

function friendlyHttpError(path: string, status: number, payload: unknown): string {
  if (status === 429) {
    return 'Too many requests right now. Wait a moment and try again.';
  }
  if (status === 503) {
    return 'Service is temporarily unavailable. Try again shortly.';
  }
  if (status === 404) {
    return 'That record was not found, or you do not have access to it.';
  }
  if (payload && typeof payload === 'object') {
    const msg = (payload as { message?: unknown }).message;
    if (typeof msg === 'string' && msg.trim()) return msg.trim();
    const err = (payload as { error?: unknown }).error;
    if (typeof err === 'string' && err.trim()) {
      if (err === 'rate_limited') return 'Too many requests right now. Wait a moment and try again.';
      if (err === 'not_found') return 'That record was not found, or you do not have access to it.';
      // snake_case API codes → readable words
      if (/^[a-z][a-z0-9_]+$/.test(err)) return err.replace(/_/g, ' ');
      return err.trim();
    }
  }
  if (status >= 500) return 'Something went wrong on the server. Try again.';
  return `Request failed (${status}).`;
}

async function getJson(path: string, headers: Record<string, string>) {
  const response = await fetch(path, { headers });
  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    const error = new Error(friendlyHttpError(path, response.status, payload)) as Error & {
      status?: number;
      payload?: unknown;
    };
    error.status = response.status;
    error.payload = payload;
    throw error;
  }
  return response.json();
}

async function requestWithHeaders(
  path: string,
  headers: Record<string, string>,
  options: { method?: string; body?: unknown } = {}
) {
  const response = await fetch(path, {
    method: options.method ?? 'GET',
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body)
  });
  const payload = await response.json().catch(() => null);
  if (!response.ok) {
    const error = new Error(friendlyHttpError(path, response.status, payload)) as Error & {
      status?: number;
      payload?: unknown;
    };
    error.status = response.status;
    error.payload = payload;
    throw error;
  }
  return payload;
}

export async function requestJson(
  config: PortalConfig,
  session: Session,
  path: string,
  options: { method?: string; body?: unknown } = {}
) {
  return requestWithHeaders(path, buildApiHeaders(config, session), options);
}

export async function requestSocJson(
  config: PortalConfig,
  session: Session,
  path: string,
  options: { method?: string; body?: unknown; tenantId?: string } = {}
) {
  return requestWithHeaders(path, buildSocCustomerHeaders(config, session, options.tenantId), options);
}

async function getJsonOptional(
  path: string,
  headers: Record<string, string>,
  fallback: unknown,
  errors?: string[]
) {
  try {
    return await getJson(path, headers);
  } catch (err) {
    const status = (err as { status?: number } | null)?.status;
    // Treat missing records as empty; surface auth/server/network failures.
    if (errors && status !== 404) {
      const message = err instanceof Error ? err.message : `Request failed for ${path}`;
      if (!errors.includes(message)) errors.push(message);
    }
    return fallback;
  }
}

function asObject(value: unknown) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

export type FetchPortalDataOptions = {
  route?: RouteId;
};

export async function fetchPortalData(
  config: PortalConfig,
  session: Session,
  options: FetchPortalDataOptions = {}
): Promise<PortalData> {
  const headers = buildApiHeaders(config, session);
  const isStaffSession = session.principal === 'staff';
  const wantsStaffSocHydrate =
    isStaffSession && isStaffSocRole(session) && (options.route === 'internal-soc' || options.route === 'queue-detail');
  const hydrateErrors: string[] = [];
  let useStaffSocTenantHeaders = wantsStaffSocHydrate;
  let tenantHeaders: Record<string, string> = headers;
  if (wantsStaffSocHydrate) {
    try {
      tenantHeaders = buildSocCustomerHeaders(config, session);
    } catch (err) {
      useStaffSocTenantHeaders = false;
      hydrateErrors.push(err instanceof Error ? err.message : 'Staff SOC needs an execution tenant.');
    }
  }
  // Staff customer-API calls only when impersonating (SOC headers). Otherwise skip /v1/* hydrate.
  // When SOC impersonating, ALL customer /v1 hydrate calls must use tenantHeaders — not raw staff headers.
  const customerHeaders = useStaffSocTenantHeaders
    ? tenantHeaders
    : isStaffSession
      ? null
      : headers;
  const opt = (path: string, h: Record<string, string> | null, fallback: unknown, track = false) => {
    if (!h) return Promise.resolve(fallback);
    return getJsonOptional(path, h, fallback, track ? hydrateErrors : undefined);
  };
  const deploymentFeatures = await opt('/v1/tenant/deployment-features', customerHeaders, null, true);
  const connectorsEnabled =
    deploymentFeatures !== null &&
    typeof deploymentFeatures === 'object' &&
    (deploymentFeatures as { connectors?: unknown }).connectors === true;
  const wafEnabled =
    deploymentFeatures !== null &&
    typeof deploymentFeatures === 'object' &&
    (deploymentFeatures as { waf_posture?: unknown }).waf_posture === true;
  const discoveryEnabled =
    deploymentFeatures !== null &&
    typeof deploymentFeatures === 'object' &&
    (deploymentFeatures as { external_discovery?: unknown }).external_discovery === true;
  const [
    state,
    tenant,
    targetGroups,
    agents,
    checks,
    testPolicies,
    runs,
    findings,
    evidence,
    highScale,
    reports,
    notificationsPayload,
    releaseEvidence,
    releaseAttestationPayload,
    audit,
    connectors,
    secrets,
    bootstrapTokens,
    serviceAccounts,
    wafAssets,
    wafCoverage,
    wafCoverageSummary,
    wafRiskRoadmap,
    wafValidations,
    wafDriftEvents,
    wafExceptions,
    wafValidationPlans,
    wafRetests,
    wafActionItems,
    cvePipeline,
    supplyChainRisks,
    discoveryEntities,
    discoveryCandidates,
    discoveryInbox,
    discoverySummary,
    subscriptionSummary,
    internalOverview,
    internalSignupRequests,
    internalTenants,
    internalApprovalRequests,
    internalAudit
  ] = await Promise.all([
    opt('/v1/state', useStaffSocTenantHeaders ? tenantHeaders : customerHeaders, null, true),
    opt('/v1/tenants/current', customerHeaders, null, true),
    opt('/v1/target-groups', customerHeaders, { items: [] }, true),
    opt('/v1/agents', customerHeaders, { items: [] }, true),
    opt('/v1/checks', customerHeaders, { items: [] }),
    opt('/v1/test-policies', customerHeaders, { items: [] }),
    opt('/v1/test-runs', customerHeaders, { items: [] }, true),
    opt('/v1/findings', useStaffSocTenantHeaders ? tenantHeaders : customerHeaders, { items: [] }, true),
    opt('/v1/evidence', customerHeaders, { items: [] }),
    opt('/v1/high-scale-requests', useStaffSocTenantHeaders ? tenantHeaders : customerHeaders, { items: [] }, true),
    opt('/v1/reports', customerHeaders, { items: [] }, true),
    opt('/v1/notifications', customerHeaders, { rules: [], events: [] }),
    opt('/v1/production-release-evidence', customerHeaders, { items: [] }),
    opt('/v1/production-release-evidence/attestation', customerHeaders, null),
    opt('/v1/audit-log', customerHeaders, { items: [] }),
    connectorsEnabled ? opt('/v1/connectors', customerHeaders, { items: [] }) : Promise.resolve({ items: [] }),
    opt('/v1/secrets', customerHeaders, { items: [] }),
    opt('/v1/bootstrap-tokens', customerHeaders, { items: [] }),
    opt('/v1/service-accounts', customerHeaders, { items: [] }),
    wafEnabled ? opt('/v1/waf/assets', customerHeaders, { items: [] }) : Promise.resolve({ items: [] }),
    wafEnabled ? opt('/v1/waf/coverage', customerHeaders, null) : Promise.resolve(null),
    wafEnabled ? opt('/v1/waf/coverage/summary', customerHeaders, null) : Promise.resolve(null),
    wafEnabled ? opt('/v1/waf/coverage/risk-roadmap', customerHeaders, null) : Promise.resolve(null),
    wafEnabled ? opt('/v1/waf/validations', customerHeaders, { items: [] }) : Promise.resolve({ items: [] }),
    wafEnabled ? opt('/v1/waf/drift-events', customerHeaders, { items: [] }) : Promise.resolve({ items: [] }),
    wafEnabled ? opt('/v1/waf/exceptions', customerHeaders, { items: [] }) : Promise.resolve({ items: [] }),
    wafEnabled ? opt('/v1/waf/validation-plans', customerHeaders, { items: [] }) : Promise.resolve({ items: [] }),
    wafEnabled ? opt('/v1/waf/retests', customerHeaders, { items: [] }) : Promise.resolve({ items: [] }),
    wafEnabled ? opt('/v1/waf/action-items', customerHeaders, { items: [] }) : Promise.resolve({ items: [] }),
    wafEnabled ? opt('/v1/waf/cve-pipeline', customerHeaders, { items: [] }) : Promise.resolve({ items: [] }),
    wafEnabled ? opt('/v1/waf/supply-chain/risks', customerHeaders, { items: [] }) : Promise.resolve({ items: [] }),
    discoveryEnabled ? opt('/v1/discovery/entities', customerHeaders, { items: [] }) : Promise.resolve({ items: [] }),
    discoveryEnabled ? opt('/v1/discovery/candidates', customerHeaders, { items: [] }) : Promise.resolve({ items: [] }),
    discoveryEnabled ? opt('/v1/discovery/inbox', customerHeaders, { items: [] }) : Promise.resolve({ items: [] }),
    discoveryEnabled ? opt('/v1/discovery/reports/summary', customerHeaders, null) : Promise.resolve(null),
    isStaffSession ? Promise.resolve(null) : opt('/v1/subscription/current', customerHeaders, null),
    isStaffSession ? getJsonOptional('/internal/admin/overview', headers, null, hydrateErrors) : Promise.resolve(null),
    isStaffSession ? getJsonOptional('/internal/admin/signup-requests', headers, { items: [] }, hydrateErrors) : Promise.resolve({ items: [] }),
    isStaffSession ? getJsonOptional('/internal/admin/tenants', headers, { items: [] }, hydrateErrors) : Promise.resolve({ items: [] }),
    isStaffSession ? getJsonOptional('/internal/admin/approval-requests', headers, { items: [] }, hydrateErrors) : Promise.resolve({ items: [] }),
    isStaffSession ? getJsonOptional('/internal/admin/audit-log?limit=20', headers, { items: [] }, hydrateErrors) : Promise.resolve({ items: [] })
  ]);

  return {
    state,
    tenant: asObject(tenant),
    targetGroups: asArray(targetGroups),
    targetGroupsMeta: asObject((targetGroups as { meta?: unknown })?.meta),
    agents: asArray(agents),
    checks: asArray(checks),
    testPolicies: asArray(testPolicies),
    runs: asArray(runs),
    findings: asArray(findings),
    evidence: asArray(evidence),
    highScale: asArray(highScale),
    reports: asArray(reports),
    notificationRules: Array.isArray((notificationsPayload as { rules?: unknown })?.rules)
      ? (notificationsPayload as { rules: DataItem[] }).rules
      : [],
    notificationEvents: Array.isArray((notificationsPayload as { events?: unknown })?.events)
      ? (notificationsPayload as { events: DataItem[] }).events
      : [],
    releaseEvidence: asArray(releaseEvidence),
    releaseAttestation: asObject(
      (releaseAttestationPayload as { attestation?: unknown } | null)?.attestation
        ?? releaseAttestationPayload
    ),
    audit: asArray(audit),
    connectors: asArray(connectors),
    secrets: asArray(secrets),
    bootstrapTokens: asArray(bootstrapTokens),
    serviceAccounts: asArray(serviceAccounts),
    wafAssets: asArray(wafAssets),
    wafCoverage: asObject(wafCoverage),
    wafCoverageSummary: asObject(wafCoverageSummary),
    wafRiskRoadmap: asObject(wafRiskRoadmap),
    wafValidations: asArray(wafValidations),
    wafDriftEvents: asArray(wafDriftEvents),
    wafExceptions: asArray(wafExceptions),
    wafValidationPlans: asArray(wafValidationPlans),
    wafRetests: asArray(wafRetests),
    wafActionItems: asArray(wafActionItems),
    cvePipeline: asArray(cvePipeline),
    supplyChainRisks: asArray(supplyChainRisks),
    discoveryEntities: asArray(discoveryEntities),
    discoveryCandidates: asArray(discoveryCandidates),
    discoveryInbox: asArray(discoveryInbox),
    discoverySummary: asObject(discoverySummary),
    subscriptionSummary: asObject(subscriptionSummary),
    internalOverview: asObject(internalOverview),
    internalSignupRequests: asArray(internalSignupRequests),
    internalTenants: asArray(internalTenants),
    internalApprovalRequests: asArray(internalApprovalRequests),
    internalAudit: asArray(internalAudit),
    deploymentFeatures,
    loaded: true,
    error: hydrateErrors.length > 0
      ? (hydrateErrors.length === 1
        ? hydrateErrors[0]
        : `${hydrateErrors[0]} (+${hydrateErrors.length - 1} more load issues)`)
      : null
  };
}

export const EMPTY_PORTAL_DATA: PortalData = {
  state: null,
  tenant: null,
  targetGroups: [],
  targetGroupsMeta: null,
  agents: [],
  checks: [],
  testPolicies: [],
  runs: [],
  findings: [],
  evidence: [],
  highScale: [],
  reports: [],
  notificationRules: [],
  notificationEvents: [],
  releaseEvidence: [],
  releaseAttestation: null,
  audit: [],
  connectors: [],
  secrets: [],
  bootstrapTokens: [],
  serviceAccounts: [],
  wafAssets: [],
  wafCoverage: null,
  wafCoverageSummary: null,
  wafRiskRoadmap: null,
  wafValidations: [],
  wafDriftEvents: [],
  wafExceptions: [],
  wafValidationPlans: [],
  wafRetests: [],
  wafActionItems: [],
  cvePipeline: [],
  supplyChainRisks: [],
  discoveryEntities: [],
  discoveryCandidates: [],
  discoveryInbox: [],
  discoverySummary: null,
  subscriptionSummary: null,
  internalOverview: null,
  internalSignupRequests: [],
  internalTenants: [],
  internalApprovalRequests: [],
  internalAudit: [],
  deploymentFeatures: null,
  loaded: false,
  error: null
};
