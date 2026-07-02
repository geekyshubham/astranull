import { createPublicKey, verify } from 'node:crypto';
import { ROLES } from '../contracts/roles.mjs';

const CLOCK_TOLERANCE_SEC = 60;

/** @type {Map<string, { keys: object[], fetchedAt: number }>} */
const jwksCache = new Map();

export function clearJwksCache() {
  jwksCache.clear();
}

function base64UrlDecode(segment) {
  const padded = segment + '='.repeat((4 - (segment.length % 4)) % 4);
  return Buffer.from(padded.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

function parseCompactJwt(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    const header = JSON.parse(base64UrlDecode(parts[0]).toString('utf8'));
    const payload = JSON.parse(base64UrlDecode(parts[1]).toString('utf8'));
    return {
      header,
      payload,
      signingInput: `${parts[0]}.${parts[1]}`,
      signature: base64UrlDecode(parts[2]),
    };
  } catch {
    return null;
  }
}

async function loadJwksKeys(jwksUrl, cacheTtlMs, fetchTimeoutMs) {
  const now = Date.now();
  const cached = jwksCache.get(jwksUrl);
  if (cached && now - cached.fetchedAt < cacheTtlMs) {
    return cached.keys;
  }
  const timeoutMs = fetchTimeoutMs ?? 5000;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let res;
  try {
    res = await fetch(jwksUrl, { signal: controller.signal, redirect: 'manual' });
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
  if (!res.ok) {
    return null;
  }
  let body;
  try {
    body = await res.json();
  } catch {
    return null;
  }
  const keys = Array.isArray(body?.keys) ? body.keys : [];
  jwksCache.set(jwksUrl, { keys, fetchedAt: now });
  return keys;
}

function audienceMatches(audClaim, expectedAudience) {
  if (audClaim == null) return false;
  if (Array.isArray(audClaim)) {
    return audClaim.some((a) => String(a) === expectedAudience);
  }
  return String(audClaim) === expectedAudience;
}

function pickRole(roleClaim) {
  const candidates = Array.isArray(roleClaim) ? roleClaim : [roleClaim];
  for (const raw of candidates) {
    if (raw == null || raw === '') continue;
    const role = String(raw).toLowerCase();
    if (ROLES.includes(role)) return role;
  }
  return null;
}

function claimString(payload, claimName) {
  const value = payload[claimName];
  if (value == null || value === '') return null;
  if (typeof value === 'object') return null;
  return String(value);
}

function claimHasAcceptedMfaValue(value, acceptedValues) {
  const accepted = new Set((acceptedValues ?? []).map((v) => String(v).toLowerCase()));
  const candidates = Array.isArray(value) ? value : [value];
  return candidates.some((candidate) => {
    if (candidate == null || candidate === '') return false;
    if (typeof candidate === 'object') return false;
    return accepted.has(String(candidate).toLowerCase());
  });
}

/** @param {unknown} value */
function readJwtNumericDate(value) {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return null;
  }
  return value;
}

/** @param {object | null | undefined} jwk */
function isRs256SigningRsaJwk(jwk) {
  if (!jwk || jwk.kty !== 'RSA') return false;
  if (jwk.use != null && jwk.use !== 'sig') return false;
  if (jwk.alg != null && jwk.alg !== 'RS256') return false;
  return true;
}

/**
 * Verify RS256 OIDC bearer JWT against JWKS and return human auth ctx or { error }.
 * @param {string} token
 * @param {import('../config.mjs').OidcRuntimeConfig} oidc
 */
export async function verifyOidcBearerToken(token, oidc) {
  const parsed = parseCompactJwt(token);
  if (!parsed) return { error: 'invalid_token' };

  const { header, payload, signingInput, signature } = parsed;
  if (header.alg !== 'RS256') return { error: 'invalid_token' };

  const kid = header.kid;
  if (!kid || typeof kid !== 'string') return { error: 'invalid_token' };

  const keys = await loadJwksKeys(
    oidc.jwksUrl,
    oidc.jwksCacheTtlMs,
    oidc.jwksFetchTimeoutMs,
  );
  if (!keys) return { error: 'invalid_token' };

  const jwk = keys.find((k) => k && k.kid === kid && isRs256SigningRsaJwk(k));
  if (!jwk) return { error: 'invalid_token' };

  let publicKey;
  try {
    publicKey = createPublicKey({ key: jwk, format: 'jwk' });
  } catch {
    return { error: 'invalid_token' };
  }

  const sigOk = verify(
    'RSA-SHA256',
    Buffer.from(signingInput, 'utf8'),
    publicKey,
    signature,
  );
  if (!sigOk) return { error: 'invalid_token' };

  if (payload.iss !== oidc.issuer) return { error: 'invalid_token' };
  if (!audienceMatches(payload.aud, oidc.audience)) return { error: 'invalid_token' };

  const nowSec = Math.floor(Date.now() / 1000);
  const expSec = readJwtNumericDate(payload.exp);
  if (expSec == null) {
    return payload.exp == null ? { error: 'expired' } : { error: 'invalid_token' };
  }
  if (expSec + CLOCK_TOLERANCE_SEC < nowSec) {
    return { error: 'expired' };
  }
  if (payload.nbf != null) {
    const nbfSec = readJwtNumericDate(payload.nbf);
    if (nbfSec == null) return { error: 'invalid_token' };
    if (nbfSec - CLOCK_TOLERANCE_SEC > nowSec) {
      return { error: 'invalid_token' };
    }
  }

  if (
    oidc.requireMfa
    && !claimHasAcceptedMfaValue(payload[oidc.mfaClaim], oidc.mfaValues)
  ) {
    return { error: 'mfa_required' };
  }

  const tenantId = claimString(payload, oidc.tenantClaim);
  const userId = claimString(payload, oidc.userClaim);
  if (!tenantId || !userId) return { error: 'invalid_token' };

  const role = pickRole(payload[oidc.roleClaim]);
  if (!role) return { error: 'invalid_role' };

  return { tenantId, userId, role };
}
