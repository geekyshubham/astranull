import { createPrivateKey, createSign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_FIXTURE_PATH = path.resolve(__dirname, '../../ops/staging/bundled-oidc-fixture.json');

let cachedFixture = null;

function loadFixture(env = process.env) {
  if (cachedFixture) return cachedFixture;
  const fixturePath = String(env.ASTRANULL_BUNDLED_STAGING_OIDC_FIXTURE ?? DEFAULT_FIXTURE_PATH).trim();
  cachedFixture = JSON.parse(readFileSync(fixturePath, 'utf8'));
  return cachedFixture;
}

/**
 * @param {NodeJS.ProcessEnv} [env]
 */
export function isBundledStagingOidcEnabled(env = process.env) {
  return env.ASTRANULL_BUNDLED_STAGING_OIDC === '1';
}

/**
 * @param {NodeJS.ProcessEnv} [env]
 */
export function resolvePublicBaseUrl(env = process.env) {
  const explicit = String(
    env.ASTRANULL_PUBLIC_BASE_URL ?? env.ASTRANULL_HOSTED_STAGING_BASE_URL ?? '',
  ).trim().replace(/\/$/, '');
  if (explicit) return explicit;
  const railwayStatic = String(env.RAILWAY_STATIC_URL ?? env.RAILWAY_SERVICE_CONTROL_PLANE_URL ?? '').trim().replace(/\/$/, '');
  if (railwayStatic) return railwayStatic;
  const railwayDomain = String(env.RAILWAY_PUBLIC_DOMAIN ?? '').trim();
  if (railwayDomain) return `https://${railwayDomain.replace(/^https?:\/\//, '')}`;
  const port = String(env.PORT ?? '3000').trim();
  const nodeEnv = String(env.NODE_ENV ?? 'development');
  if (nodeEnv === 'production') {
    throw new Error(
      'ASTRANULL_PUBLIC_BASE_URL or Railway public domain is required for bundled staging OIDC in production.',
    );
  }
  return `http://127.0.0.1:${port}`;
}

/**
 * @param {NodeJS.ProcessEnv} [env]
 */
export function resolveBundledStagingOidcIssuer(env = process.env) {
  const explicit = String(env.ASTRANULL_OIDC_ISSUER ?? '').trim();
  if (explicit) return explicit;
  const fixture = loadFixture(env);
  return `${resolvePublicBaseUrl(env)}${fixture.issuer_suffix}`;
}

/**
 * @param {NodeJS.ProcessEnv} [env]
 */
export function resolveBundledStagingOidcAudience(env = process.env) {
  return String(env.ASTRANULL_OIDC_AUDIENCE ?? loadFixture(env).audience).trim();
}

/**
 * @param {NodeJS.ProcessEnv} [env]
 */
export function resolveBundledStagingOidcJwksUrl(env = process.env) {
  const explicit = String(env.ASTRANULL_OIDC_JWKS_URL ?? '').trim();
  if (explicit) return explicit;
  return `${resolvePublicBaseUrl(env)}/.well-known/jwks.json`;
}

/**
 * @param {NodeJS.ProcessEnv} [env]
 */
export function getBundledStagingJwksDocument(env = process.env) {
  const fixture = loadFixture(env);
  return { keys: [fixture.public_jwk] };
}

function base64UrlJson(obj) {
  return Buffer.from(JSON.stringify(obj), 'utf8').toString('base64url');
}

/**
 * @param {{
 *   role: string,
 *   tenantId?: string,
 *   userId?: string,
 *   exp?: number,
 *   extraClaims?: Record<string, unknown>,
 *   roleClaimKey?: string,
 *   tenantClaimKey?: string,
 *   userClaimKey?: string,
 * }} params
 * @param {NodeJS.ProcessEnv} [env]
 */
export function mintBundledStagingOidcJwt(params, env = process.env) {
  const fixture = loadFixture(env);
  const privateKey = createPrivateKey(fixture.private_key_pem);
  const header = { alg: 'RS256', typ: 'JWT', kid: fixture.kid };
  const roleClaimKey = params.roleClaimKey ?? 'role';
  const tenantClaimKey = params.tenantClaimKey ?? 'tenant_id';
  const userClaimKey = params.userClaimKey ?? 'sub';
  const payload = {
    iss: resolveBundledStagingOidcIssuer(env),
    aud: resolveBundledStagingOidcAudience(env),
    exp: params.exp ?? Math.floor(Date.now() / 1000) + 3600,
    amr: ['mfa', 'otp'],
    ...(params.extraClaims ?? {}),
  };
  payload[userClaimKey] = params.userId ?? 'usr_oidc_hosted';
  payload[tenantClaimKey] = params.tenantId ?? 'ten_demo';
  payload[roleClaimKey] = params.role;
  const signingInput = `${base64UrlJson(header)}.${base64UrlJson(payload)}`;
  const sig = createSign('RSA-SHA256').update(signingInput, 'utf8').sign(privateKey);
  return `${signingInput}.${sig.toString('base64url')}`;
}

/**
 * Apply bundled staging OIDC defaults to env for startup when enabled.
 * @param {NodeJS.ProcessEnv} env
 */
export function applyBundledStagingOidcEnvDefaults(env) {
  if (!isBundledStagingOidcEnabled(env)) return;
  if (!String(env.ASTRANULL_AUTH_MODE ?? '').trim()) {
    env.ASTRANULL_AUTH_MODE = 'oidc-jwt';
  }
  if (!String(env.ASTRANULL_OIDC_ISSUER ?? '').trim()) {
    env.ASTRANULL_OIDC_ISSUER = resolveBundledStagingOidcIssuer(env);
  }
  if (!String(env.ASTRANULL_OIDC_AUDIENCE ?? '').trim()) {
    env.ASTRANULL_OIDC_AUDIENCE = resolveBundledStagingOidcAudience(env);
  }
  if (!String(env.ASTRANULL_OIDC_JWKS_URL ?? '').trim()) {
    env.ASTRANULL_OIDC_JWKS_URL = resolveBundledStagingOidcJwksUrl(env);
  }
  if (!String(env.ASTRANULL_DEPLOYMENT_PROFILE ?? '').trim()) {
    env.ASTRANULL_DEPLOYMENT_PROFILE = 'hosted-staging';
  }
}