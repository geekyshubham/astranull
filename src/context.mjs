import { createHmac, timingSafeEqual } from 'node:crypto';
import { ROLES } from './contracts/roles.mjs';
import { verifyOidcBearerToken } from './lib/oidc.mjs';
import { authenticateProbeWorker } from './services/probeCoordinator.mjs';
import {
  auditServiceAccountAuthFailure,
  authenticateServiceAccountBearer,
} from './services/serviceAccounts.mjs';

const DEMO_TENANT = 'ten_demo';
const DEMO_USER = 'usr_admin';
const DEMO_ROLE = 'admin';
const SESSION_VERSION = 'asn1';

export function authContextFromHeaders(headers) {
  // Staff principal headers must not silently become customer admin@ten_demo.
  // Staff SOC impersonation strips x-principal-type and sets tenant + soc role instead.
  const principalType = String(headers['x-principal-type'] ?? '').trim().toLowerCase();
  if (principalType === 'staff') {
    return {
      error: 'staff_tenant_context_required',
      message: 'Staff sessions must use tenant impersonation headers for customer API routes.',
    };
  }
  const tenantId = headers['x-tenant-id'] ?? DEMO_TENANT;
  const userId = headers['x-user-id'] ?? DEMO_USER;
  let role = (headers['x-role'] ?? DEMO_ROLE).toLowerCase();
  if (!ROLES.includes(role)) role = 'viewer';
  return { tenantId, userId, role };
}

function safeEqualUtf8(a, b) {
  if (!a || !b) return false;
  const ba = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (ba.length !== bb.length) return false;
  return timingSafeEqual(ba, bb);
}

function sessionSignature(secret, version, payloadB64) {
  return createHmac('sha256', secret).update(`${version}.${payloadB64}`, 'utf8').digest('base64url');
}

/**
 * Mint HMAC-signed session tokens for tests and operators — not a production IdP.
 */
export function mintSignedSessionToken(
  { tenantId, userId, role, exp },
  secret,
) {
  if (!secret || secret.length < 32) {
    throw new Error('mintSignedSessionToken requires a session secret of at least 32 characters');
  }
  const normalizedRole = String(role).toLowerCase();
  if (!ROLES.includes(normalizedRole)) {
    throw new Error(`mintSignedSessionToken: invalid role "${role}"`);
  }
  const payload = {
    tenantId,
    userId,
    role: normalizedRole,
    exp: exp ?? Math.floor(Date.now() / 1000) + 3600,
  };
  const payloadB64 = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const sig = sessionSignature(secret, SESSION_VERSION, payloadB64);
  return `${SESSION_VERSION}.${payloadB64}.${sig}`;
}

export function verifySignedSessionToken(token, secret) {
  if (!token || typeof token !== 'string') return { error: 'invalid_token' };
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== SESSION_VERSION) return { error: 'invalid_token' };
  const [version, payloadB64, sig] = parts;
  const expected = sessionSignature(secret, version, payloadB64);
  if (!safeEqualUtf8(sig, expected)) return { error: 'invalid_token' };
  let payload;
  try {
    payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
  } catch {
    return { error: 'invalid_token' };
  }
  if (!payload?.tenantId || !payload?.userId || !payload?.role || payload.exp == null) {
    return { error: 'invalid_token' };
  }
  if (Number(payload.exp) * 1000 < Date.now()) return { error: 'expired' };
  const role = String(payload.role).toLowerCase();
  if (!ROLES.includes(role)) return { error: 'invalid_role' };
  return { tenantId: payload.tenantId, userId: payload.userId, role };
}

export function isProbeWorkerRoute(pathname, method) {
  if (method === 'GET' && pathname === '/internal/probe/jobs') return true;
  if (method === 'POST' && /^\/internal\/probe\/jobs\/[^/]+\/result$/.test(pathname)) return true;
  return false;
}

export function isAgentBootstrapOrCredentialRoute(pathname, method) {
  if (method === 'POST' && pathname === '/v1/agents/register') return true;
  if (method === 'POST' && /^\/v1\/agents\/[^/]+\/heartbeat$/.test(pathname)) return true;
  if (method === 'GET' && /^\/v1\/agents\/[^/]+\/jobs$/.test(pathname)) return true;
  if (method === 'POST' && /^\/v1\/agents\/[^/]+\/jobs\/[^/]+\/ack$/.test(pathname)) return true;
  if (method === 'POST' && /^\/v1\/agents\/[^/]+\/observations$/.test(pathname)) return true;
  if (method === 'GET' && /^\/v1\/agents\/[^/]+\/update$/.test(pathname)) return true;
  if (method === 'POST' && /^\/v1\/agents\/[^/]+\/update-status$/.test(pathname)) return true;
  return false;
}

function bearerSessionToken(headers) {
  const auth = headers.authorization;
  if (!auth || typeof auth !== 'string') return null;
  const m = auth.match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : null;
}

/**
 * Resolve human API auth for /v1 and /internal routes (not health/metrics/static).
 * Agent bootstrap/credential routes skip human session requirements.
 */
export async function resolveHumanApiAuth(headers, pathname, method, runtimeConfig, options = {}) {
  const serviceAccountsSvc = options.services?.serviceAccounts;
  const authenticateServiceAccountBearerFn =
    serviceAccountsSvc?.authenticateServiceAccountBearer ?? authenticateServiceAccountBearer;
  const auditServiceAccountAuthFailureFn =
    serviceAccountsSvc?.auditServiceAccountAuthFailure ?? auditServiceAccountAuthFailure;

  if (isAgentBootstrapOrCredentialRoute(pathname, method)) {
    return { ok: true, ctx: null, skipped: true };
  }

  if (isProbeWorkerRoute(pathname, method)) {
    const auth = authenticateProbeWorker(
      headers,
      method,
      pathname,
      options.bodyText ?? '',
      runtimeConfig,
    );
    if (!auth.ok) {
      return { ok: false, status: auth.status, body: auth.body };
    }
    return {
      ok: true,
      ctx: {
        ...auth.workerCtx,
        tenantId: auth.workerCtx.tenantId,
        role: 'probe_worker',
      },
      probeWorker: true,
    };
  }

  const token = bearerSessionToken(headers);
  if (token?.startsWith('svc_')) {
    const svc = await authenticateServiceAccountBearerFn(token);
    if (svc.error) {
      if (svc.error === 'invalid_token') {
        await auditServiceAccountAuthFailureFn(token);
      }
      return {
        ok: false,
        status: 401,
        body: { error: 'unauthorized', message: 'Missing or invalid service account token.' },
      };
    }
    return { ok: true, ctx: svc };
  }

  if (runtimeConfig.authMode === 'dev-headers') {
    const ctx = authContextFromHeaders(headers);
    if (ctx?.error) {
      return {
        ok: false,
        status: 401,
        body: { error: ctx.error, message: ctx.message ?? 'Unauthorized.' },
      };
    }
    return { ok: true, ctx };
  }

  if (!token) {
    return {
      ok: false,
      status: 401,
      body: { error: 'unauthorized', message: 'Missing or invalid session token.' },
    };
  }

  if (runtimeConfig.authMode === 'oidc-jwt') {
    const verified = await verifyOidcBearerToken(token, runtimeConfig.oidc);
    if (verified.error) {
      return {
        ok: false,
        status: 401,
        body: { error: 'unauthorized', message: 'Missing or invalid session token.' },
      };
    }
    return { ok: true, ctx: verified };
  }

  const verified = verifySignedSessionToken(token, runtimeConfig.sessionSecret);
  if (verified.error) {
    return {
      ok: false,
      status: 401,
      body: { error: 'unauthorized', message: 'Missing or invalid session token.' },
    };
  }

  return { ok: true, ctx: verified };
}