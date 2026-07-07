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

export function ensureDevSession(config: PortalConfig, current: Session | null): Session {
  if (current) return current;
  if (config.authMode !== 'dev-headers') return {};
  const session = {
    mode: 'dev-headers',
    principal: 'customer',
    tenant_id: 'ten_demo',
    user_id: 'usr_admin',
    role: 'admin'
  };
  saveSession(session);
  return session;
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

const STAFF_SOC_ROLES = new Set(['soc_analyst', 'soc_lead']);

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

/** Staff SOC surface impersonates tenant SOC role for governed execution routes in dev-headers mode. */
export function buildSocCustomerHeaders(config: PortalConfig, session: Session, tenantId = 'ten_demo') {
  const headers = buildApiHeaders(config, session);
  if (config.authMode === 'dev-headers') {
    delete headers['x-principal-type'];
    delete headers['x-staff-id'];
    delete headers['x-staff-role'];
    headers['x-tenant-id'] = tenantId;
    headers['x-user-id'] = String(session.staff_id ?? session.user_id ?? 'staff_soc');
    headers['x-role'] = 'soc';
  }
  return headers;
}

async function getJson(path: string, headers: Record<string, string>) {
  const response = await fetch(path, { headers });
  if (!response.ok) throw new Error(`${path} returned ${response.status}`);
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
    const message =
      payload && typeof payload === 'object' && 'message' in payload
        ? String((payload as { message?: unknown }).message)
        : `${path} returned ${response.status}`;
    const error = new Error(message) as Error & { status?: number; payload?: unknown };
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

async function getJsonOptional(path: string, headers: Record<string, string>, fallback: unknown) {
  try {
    return await getJson(path, headers);
  } catch {
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
  const useStaffSocTenantHeaders =
    isStaffSession && isStaffSocRole(session) && options.route === 'internal-soc';
  const tenantHeaders = useStaffSocTenantHeaders ? buildSocCustomerHeaders(config, session) : headers;
  const deploymentFeatures = await getJsonOptional('/v1/tenant/deployment-features', headers, null);
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
    getJsonOptional('/v1/state', tenantHeaders, null),
    getJsonOptional('/v1/tenants/current', headers, null),
    getJsonOptional('/v1/target-groups', headers, { items: [] }),
    getJsonOptional('/v1/agents', headers, { items: [] }),
    getJsonOptional('/v1/checks', headers, { items: [] }),
    getJsonOptional('/v1/test-policies', headers, { items: [] }),
    getJsonOptional('/v1/test-runs', headers, { items: [] }),
    getJsonOptional('/v1/findings', tenantHeaders, { items: [] }),
    getJsonOptional('/v1/evidence', headers, { items: [] }),
    getJsonOptional('/v1/high-scale-requests', tenantHeaders, { items: [] }),
    getJsonOptional('/v1/reports', headers, { items: [] }),
    getJsonOptional('/v1/notifications', headers, { rules: [], events: [] }),
    getJsonOptional('/v1/production-release-evidence', headers, { items: [] }),
    getJsonOptional('/v1/production-release-evidence/attestation', headers, null),
    getJsonOptional('/v1/audit-log', headers, { items: [] }),
    connectorsEnabled ? getJsonOptional('/v1/connectors', headers, { items: [] }) : Promise.resolve({ items: [] }),
    getJsonOptional('/v1/secrets', headers, { items: [] }),
    getJsonOptional('/v1/bootstrap-tokens', headers, { items: [] }),
    getJsonOptional('/v1/service-accounts', headers, { items: [] }),
    wafEnabled ? getJsonOptional('/v1/waf/assets', headers, { items: [] }) : Promise.resolve({ items: [] }),
    wafEnabled ? getJsonOptional('/v1/waf/coverage', headers, null) : Promise.resolve(null),
    wafEnabled ? getJsonOptional('/v1/waf/coverage/summary', headers, null) : Promise.resolve(null),
    wafEnabled ? getJsonOptional('/v1/waf/coverage/risk-roadmap', headers, null) : Promise.resolve(null),
    wafEnabled ? getJsonOptional('/v1/waf/validations', headers, { items: [] }) : Promise.resolve({ items: [] }),
    wafEnabled ? getJsonOptional('/v1/waf/drift-events', headers, { items: [] }) : Promise.resolve({ items: [] }),
    wafEnabled ? getJsonOptional('/v1/waf/exceptions', headers, { items: [] }) : Promise.resolve({ items: [] }),
    wafEnabled ? getJsonOptional('/v1/waf/validation-plans', headers, { items: [] }) : Promise.resolve({ items: [] }),
    wafEnabled ? getJsonOptional('/v1/waf/retests', headers, { items: [] }) : Promise.resolve({ items: [] }),
    wafEnabled ? getJsonOptional('/v1/waf/action-items', headers, { items: [] }) : Promise.resolve({ items: [] }),
    wafEnabled ? getJsonOptional('/v1/waf/cve-pipeline', headers, { items: [] }) : Promise.resolve({ items: [] }),
    wafEnabled ? getJsonOptional('/v1/waf/supply-chain/risks', headers, { items: [] }) : Promise.resolve({ items: [] }),
    discoveryEnabled ? getJsonOptional('/v1/discovery/entities', headers, { items: [] }) : Promise.resolve({ items: [] }),
    discoveryEnabled ? getJsonOptional('/v1/discovery/candidates', headers, { items: [] }) : Promise.resolve({ items: [] }),
    discoveryEnabled ? getJsonOptional('/v1/discovery/inbox', headers, { items: [] }) : Promise.resolve({ items: [] }),
    discoveryEnabled ? getJsonOptional('/v1/discovery/reports/summary', headers, null) : Promise.resolve(null),
    isStaffSession ? Promise.resolve(null) : getJsonOptional('/v1/subscription/current', headers, null),
    isStaffSession ? getJsonOptional('/internal/admin/overview', headers, null) : Promise.resolve(null),
    isStaffSession ? getJsonOptional('/internal/admin/signup-requests', headers, { items: [] }) : Promise.resolve({ items: [] }),
    isStaffSession ? getJsonOptional('/internal/admin/tenants', headers, { items: [] }) : Promise.resolve({ items: [] }),
    isStaffSession ? getJsonOptional('/internal/admin/approval-requests', headers, { items: [] }) : Promise.resolve({ items: [] }),
    isStaffSession ? getJsonOptional('/internal/admin/audit-log?limit=20', headers, { items: [] }) : Promise.resolve({ items: [] })
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
    error: null
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
