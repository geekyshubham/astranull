import { loadRuntimeConfig } from '../config.mjs';
import { STAFF_ROLES } from '../contracts/staffRoles.mjs';
import { verifyOidcStaffBearerToken } from './oidc.mjs';
import { verifySignedSessionToken } from '../context.mjs';

function staffSurfacePaths(runtimeConfig = loadRuntimeConfig()) {
  const internalAdmin = String(runtimeConfig.internalAdminPath ?? '/internal/admin').trim() || '/internal/admin';
  const staffLogin = String(runtimeConfig.staffLoginPath ?? '/internal/admin/login').trim() || '/internal/admin/login';
  return { internalAdmin, staffLogin };
}

export function isInternalAdminRoute(pathname, runtimeConfig) {
  const { internalAdmin } = staffSurfacePaths(runtimeConfig);
  return pathname === internalAdmin || pathname.startsWith(`${internalAdmin}/`);
}

export function isInternalAdminApiRoute(pathname, method, runtimeConfig) {
  if (!isInternalAdminRoute(pathname, runtimeConfig)) return false;
  if (isInternalAdminPageRoute(pathname, method, runtimeConfig)) return false;
  return true;
}

export function isInternalAdminPageRoute(pathname, method, runtimeConfig) {
  if (method !== 'GET') return false;
  const { internalAdmin, staffLogin } = staffSurfacePaths(runtimeConfig);
  if (pathname === staffLogin) return true;
  return pathname === internalAdmin || pathname === `${internalAdmin}/`;
}

export function isPublicApiRoute(pathname, method) {
  if (method === 'POST' && pathname === '/v1/signup-requests') return true;
  if (method === 'POST' && pathname === '/v1/auth/bundled-staging-login') return true;
  if (method === 'GET' && pathname === '/v1/public/site-config') return true;
  if (method === 'GET' && /^\/v1\/signup-requests\/[^/]+$/.test(pathname)) return true;
  return false;
}

function bearerToken(headers) {
  const auth = headers.authorization;
  if (!auth || typeof auth !== 'string') return null;
  const m = auth.match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : null;
}

function staffContextFromDevHeaders(headers) {
  const principalType = String(headers['x-principal-type'] ?? 'customer').trim().toLowerCase();
  if (principalType !== 'staff') return null;
  let staffRole = String(headers['x-staff-role'] ?? '').trim().toLowerCase();
  if (!STAFF_ROLES.includes(staffRole)) staffRole = 'support_engineer';
  const staffId = String(headers['x-staff-id'] ?? 'staff_dev').trim() || 'staff_dev';
  return {
    principalType: 'staff',
    staffId,
    staffRole,
    userId: staffId,
    role: staffRole,
    tenantId: null,
  };
}

/**
 * Resolve staff principal for /internal/admin routes.
 */
export async function resolveStaffAuth(headers, runtimeConfig) {
  if (runtimeConfig.authMode === 'dev-headers') {
    const ctx = staffContextFromDevHeaders(headers);
    if (!ctx) {
      return {
        ok: false,
        status: 403,
        body: { error: 'staff_forbidden', message: 'Staff principal required.' },
      };
    }
    return { ok: true, ctx };
  }

  const token = bearerToken(headers);
  if (!token) {
    return {
      ok: false,
      status: 401,
      body: { error: 'unauthorized', message: 'Missing staff session token.' },
    };
  }

  if (runtimeConfig.authMode === 'oidc-jwt') {
    const verified = await verifyOidcStaffBearerToken(token, runtimeConfig.oidc);
    if (verified.error) {
      return {
        ok: false,
        status: verified.error === 'invalid_staff_role' ? 403 : 401,
        body: {
          error: verified.error === 'invalid_staff_role' ? 'staff_forbidden' : 'unauthorized',
          message: 'Missing or invalid staff session token.',
        },
      };
    }
    return { ok: true, ctx: verified };
  }

  const verified = verifySignedSessionToken(token, runtimeConfig.sessionSecret);
  if (verified.error) {
    return {
      ok: false,
      status: 401,
      body: { error: 'unauthorized', message: 'Missing or invalid staff session token.' },
    };
  }
  if (!STAFF_ROLES.includes(verified.role)) {
    return {
      ok: false,
      status: 403,
      body: { error: 'staff_forbidden', message: 'Customer principal cannot access internal management.' },
    };
  }
  return {
    ok: true,
    ctx: {
      principalType: 'staff',
      staffId: verified.userId,
      staffRole: verified.role,
      userId: verified.userId,
      role: verified.role,
      tenantId: null,
    },
  };
}

export function denyCustomerOnInternalAdmin(customerCtx) {
  if (!customerCtx?.tenantId && customerCtx?.principalType === 'staff') return false;
  if (customerCtx?.principalType === 'staff') return false;
  return true;
}