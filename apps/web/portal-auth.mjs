const SESSION_KEY = 'astranull.portal.session.v1';

/**
 * @returns {Promise<{
 *   authMode: string,
 *   siteConfig: Record<string, unknown>,
 *   bundledLoginEnabled: boolean,
 *   loginUrl: string,
 *   portalPath: string,
 *   staffLoginPath: string,
 * }>}
 */
export async function fetchPortalConfig() {
  const [readyRes, siteRes] = await Promise.all([
    fetch('/ready').catch(() => null),
    fetch('/v1/public/site-config').catch(() => null),
  ]);
  const ready = readyRes?.ok ? await readyRes.json().catch(() => ({})) : {};
  const siteConfig = siteRes?.ok ? await siteRes.json().catch(() => ({})) : {};
  const authMode = ready.auth_mode ?? siteConfig.auth_mode ?? 'dev-headers';
  return {
    authMode,
    siteConfig,
    bundledLoginEnabled: siteConfig.bundled_staging_login_enabled === true,
    loginUrl: String(siteConfig.login_url ?? '/login'),
    portalPath: String(siteConfig.customer_portal_path ?? '/app'),
    staffLoginPath: String(siteConfig.staff_login_path ?? '/internal/admin/login'),
  };
}

export function loadSession() {
  try {
    const raw = sessionStorage.getItem(SESSION_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
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

/**
 * @param {Record<string, unknown>} session
 */
export function saveSession(session) {
  sessionStorage.setItem(SESSION_KEY, JSON.stringify(session));
}

export function clearSession() {
  sessionStorage.removeItem(SESSION_KEY);
}

/**
 * @param {ReturnType<typeof fetchPortalConfig> extends Promise<infer T> ? T : never} config
 * @param {Record<string, unknown> | null} session
 */
export function buildApiHeaders(config, session) {
  const headers = { 'Content-Type': 'application/json' };
  if (config.authMode === 'dev-headers') {
    headers['x-tenant-id'] = String(session?.tenant_id ?? 'ten_demo');
    headers['x-user-id'] = String(session?.user_id ?? 'usr_admin');
    headers['x-role'] = String(session?.role ?? 'admin');
    return headers;
  }
  const token = String(session?.access_token ?? '').trim();
  if (token) headers.authorization = `Bearer ${token}`;
  return headers;
}

/**
 * @param {ReturnType<typeof fetchPortalConfig> extends Promise<infer T> ? T : never} config
 * @param {Record<string, unknown> | null} session
 */
export function buildStaffApiHeaders(config, session) {
  const headers = { 'Content-Type': 'application/json' };
  if (config.authMode === 'dev-headers') {
    headers['x-principal-type'] = 'staff';
    headers['x-staff-id'] = String(session?.staff_id ?? 'staff_admin');
    headers['x-staff-role'] = String(session?.staff_role ?? 'internal_admin');
    return headers;
  }
  const token = String(session?.access_token ?? '').trim();
  if (token) headers.authorization = `Bearer ${token}`;
  return headers;
}

/**
 * @param {'customer' | 'staff'} surface
 */
export async function ensurePortalSession(surface = 'customer') {
  const config = await fetchPortalConfig();
  let session = loadSession();

  if (config.authMode === 'dev-headers') {
    if (!session) {
      session = surface === 'staff'
        ? {
          mode: 'dev-headers',
          principal: 'staff',
          staff_id: 'staff_admin',
          staff_role: 'internal_admin',
        }
        : {
          mode: 'dev-headers',
          principal: 'customer',
          tenant_id: 'ten_demo',
          user_id: 'usr_admin',
          role: 'admin',
        };
      saveSession(session);
    }
    return { config, session, redirectToLogin: false };
  }

  const loginPath = surface === 'staff' ? config.staffLoginPath : config.loginUrl;
  const hasToken = Boolean(session?.access_token);
  const principalOk = surface === 'staff'
    ? session?.principal === 'staff'
    : session?.principal !== 'staff';

  if (!hasToken || !principalOk) {
    if (config.bundledLoginEnabled) {
      return { config, session: null, redirectToLogin: true, loginUrl: loginPath };
    }
    return {
      config,
      session: null,
      redirectToLogin: true,
      loginUrl: loginPath,
      errorMessage: 'Sign in is required. Configure enterprise SSO or enable bundled staging login for this environment.',
    };
  }

  return { config, session, redirectToLogin: false };
}

/**
 * @param {Record<string, unknown>} loginResponse
 */
export function sessionFromLoginResponse(loginResponse) {
  const expiresIn = Number(loginResponse.expires_in ?? 3600);
  return {
    mode: 'oidc',
    access_token: loginResponse.access_token,
    principal: loginResponse.principal ?? 'customer',
    tenant_id: loginResponse.tenant_id ?? null,
    user_id: loginResponse.user_id ?? loginResponse.staff_id ?? null,
    role: loginResponse.role ?? null,
    staff_id: loginResponse.staff_id ?? null,
    staff_role: loginResponse.staff_role ?? null,
    expires_at: Date.now() + expiresIn * 1000,
  };
}