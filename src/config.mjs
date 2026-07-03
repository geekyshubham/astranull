import { applyBundledStagingOidcEnvDefaults } from './lib/bundledStagingOidc.mjs';
import { isHostedStagingDeployment, resolveDeploymentProfile } from './lib/deploymentProfile.mjs';
import { loadSecretEncryptionKey } from './lib/secrets.mjs';

export const AUTH_MODES = ['dev-headers', 'signed-session', 'oidc-jwt'];

const DEFAULT_OIDC_TENANT_CLAIM = 'tenant_id';
const DEFAULT_OIDC_ROLE_CLAIM = 'role';
const DEFAULT_OIDC_USER_CLAIM = 'sub';
const DEFAULT_OIDC_MFA_CLAIM = 'amr';
const DEFAULT_OIDC_MFA_VALUES = [
  'mfa',
  'otp',
  'webauthn',
  'fido',
  'fido2',
  'phishing_resistant',
];
const DEFAULT_OIDC_JWKS_CACHE_TTL_MS = 300_000;
const MIN_OIDC_JWKS_CACHE_TTL_MS = 60_000;
const MAX_OIDC_JWKS_CACHE_TTL_MS = 3_600_000;
const DEFAULT_OIDC_JWKS_FETCH_TIMEOUT_MS = 5_000;
const MIN_OIDC_JWKS_FETCH_TIMEOUT_MS = 1_000;
const MAX_OIDC_JWKS_FETCH_TIMEOUT_MS = 30_000;

export const PERSISTENCE_MODES = ['memory', 'dev-json', 'postgres'];

export const PROBE_MODES = ['simulation', 'signed-worker'];
export const HIGH_SCALE_ADAPTER_MODES = ['disabled', 'dry-run', 'governed-adapter'];
export const AGENT_IDENTITY_MODES = ['bearer', 'gateway-mtls'];

const MIN_SESSION_SECRET_LENGTH = 32;
const MIN_PROBE_WORKER_SECRET_LENGTH = 32;
const DEFAULT_MAX_JSON_BODY_BYTES = 65536;
const MAX_MAX_JSON_BODY_BYTES = 1_048_576;
const DEFAULT_SHUTDOWN_GRACE_MS = 30_000;
const MAX_SHUTDOWN_GRACE_MS = 300_000;
const DEFAULT_RATE_LIMIT_WINDOW_MS = 60_000;
const MIN_RATE_LIMIT_WINDOW_MS = 1_000;
const MAX_RATE_LIMIT_WINDOW_MS = 3_600_000;
const DEFAULT_RATE_LIMIT_MAX_REQUESTS = 600;
const MIN_RATE_LIMIT_MAX_REQUESTS = 1;
const MAX_RATE_LIMIT_MAX_REQUESTS = 100_000;

function parsePositiveInt(raw, name, { min = 1, max, fallback }) {
  if (raw === undefined || raw === null || String(raw).trim() === '') {
    return fallback;
  }
  const n = Number(raw);
  if (!Number.isInteger(n) || n < min || n > max) {
    throw new Error(
      `${name} must be an integer between ${min} and ${max} (got "${raw}").`,
    );
  }
  return n;
}

function parseOptionalBoolean(raw, name, fallback) {
  if (raw === undefined || raw === null || String(raw).trim() === '') {
    return fallback;
  }
  const value = String(raw).trim();
  if (value === '1') return true;
  if (value === '0') return false;
  throw new Error(`${name} must be 1 or 0 (got "${raw}").`);
}

function parseCommaSeparatedList(raw, fallback, name) {
  const source = raw === undefined || raw === null || String(raw).trim() === ''
    ? fallback
    : String(raw).split(',');
  const values = source
    .map((value) => String(value).trim().toLowerCase())
    .filter(Boolean);
  if (values.length === 0) {
    throw new Error(`${name} must include at least one non-empty value.`);
  }
  return [...new Set(values)];
}

function parseTenantBooleanMap(raw, name) {
  if (raw === undefined || raw === null || String(raw).trim() === '') {
    return {};
  }
  let parsed;
  try {
    parsed = JSON.parse(String(raw));
  } catch {
    throw new Error(`${name} must be valid JSON object mapping tenant_id to 0/1 or boolean.`);
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(`${name} must be a JSON object mapping tenant_id to 0/1 or boolean.`);
  }
  /** @type {Record<string, boolean>} */
  const out = {};
  for (const [tenantId, value] of Object.entries(parsed)) {
    const key = String(tenantId ?? '').trim();
    if (!key) {
      throw new Error(`${name} keys must be non-empty tenant ids.`);
    }
    if (value === true || value === 1 || value === '1') {
      out[key] = true;
      continue;
    }
    if (value === false || value === 0 || value === '0') {
      out[key] = false;
      continue;
    }
    throw new Error(`${name} value for tenant "${key}" must be boolean or 0/1.`);
  }
  return out;
}

export function isConnectorsEnabledForTenant(runtimeConfig, tenantId) {
  const tenantKey = String(tenantId ?? '').trim();
  const tenantOverrides = runtimeConfig.featureFlags?.connectorsEnabledTenants ?? {};
  if (tenantKey && Object.prototype.hasOwnProperty.call(tenantOverrides, tenantKey)) {
    return tenantOverrides[tenantKey] === true;
  }
  return runtimeConfig.featureFlags?.connectorsEnabledDefault === true;
}

function parseOidcRoleMap(raw, name) {
  if (raw === undefined || raw === null || String(raw).trim() === '') {
    return {};
  }
  const entries = String(raw).split(',');
  /** @type {Record<string, string>} */
  const roleMap = {};
  for (const entry of entries) {
    const trimmed = entry.trim();
    if (!trimmed) continue;
    const separator = trimmed.indexOf(':');
    if (separator <= 0 || separator === trimmed.length - 1) {
      throw new Error(
        `${name} entries must use idp_role:platform_role format (got "${entry}").`,
      );
    }
    const idpRole = trimmed.slice(0, separator).trim().toLowerCase();
    const platformRole = trimmed.slice(separator + 1).trim().toLowerCase();
    if (!idpRole || !platformRole) {
      throw new Error(
        `${name} entries must use idp_role:platform_role format (got "${entry}").`,
      );
    }
    roleMap[idpRole] = platformRole;
  }
  if (Object.keys(roleMap).length === 0) {
    throw new Error(`${name} must include at least one idp_role:platform_role entry.`);
  }
  return roleMap;
}

function assertOidcJwksUrl(jwksUrl, nodeEnv) {
  let parsed;
  try {
    parsed = new URL(jwksUrl);
  } catch {
    throw new Error('ASTRANULL_OIDC_JWKS_URL must be a valid URL.');
  }
  if (nodeEnv === 'production' && parsed.protocol !== 'https:') {
    throw new Error(
      'ASTRANULL_OIDC_JWKS_URL must use HTTPS when NODE_ENV=production.',
    );
  }
}

export function resolvePersistenceMode(env = process.env) {
  const nodeEnv = env.NODE_ENV ?? 'development';
  const explicit = env.ASTRANULL_PERSISTENCE_MODE?.trim();

  if (explicit) {
    if (!PERSISTENCE_MODES.includes(explicit)) {
      throw new Error(
        `Invalid ASTRANULL_PERSISTENCE_MODE "${explicit}". Allowed: ${PERSISTENCE_MODES.join(', ')}.`,
      );
    }
    return explicit;
  }

  if (env.ASTRANULL_NO_PERSIST === '1') {
    if (nodeEnv === 'production') {
      throw new Error(
        'Refusing to start: ASTRANULL_NO_PERSIST=1 and memory persistence are not permitted when NODE_ENV=production.',
      );
    }
    return 'memory';
  }

  return nodeEnv === 'production' ? 'postgres' : 'dev-json';
}

export function resolveProbeMode(env = process.env) {
  const nodeEnv = env.NODE_ENV ?? 'development';
  const explicit = env.ASTRANULL_PROBE_MODE?.trim();
  if (explicit) {
    if (!PROBE_MODES.includes(explicit)) {
      throw new Error(
        `Invalid ASTRANULL_PROBE_MODE "${explicit}". Allowed: ${PROBE_MODES.join(', ')}.`,
      );
    }
    if (nodeEnv === 'production' && explicit === 'simulation') {
      throw new Error(
        'Refusing to start: ASTRANULL_PROBE_MODE=simulation is not permitted when NODE_ENV=production. Use signed-worker with external probe workers.',
      );
    }
    return explicit;
  }
  return nodeEnv === 'production' ? 'signed-worker' : 'simulation';
}

export function resolveHighScaleAdapterMode(env = process.env) {
  const explicit = env.ASTRANULL_HIGH_SCALE_ADAPTER_MODE?.trim();
  const nodeEnv = env.NODE_ENV ?? 'development';
  const mode = explicit || (nodeEnv === 'production' ? 'governed-adapter' : 'dry-run');
  if (!HIGH_SCALE_ADAPTER_MODES.includes(mode)) {
    throw new Error(
      `Invalid ASTRANULL_HIGH_SCALE_ADAPTER_MODE "${mode}". Allowed: ${HIGH_SCALE_ADAPTER_MODES.join(', ')}.`,
    );
  }
  if (nodeEnv === 'production' && mode === 'dry-run') {
    throw new Error(
      'Refusing to start: ASTRANULL_HIGH_SCALE_ADAPTER_MODE=dry-run is not permitted when NODE_ENV=production. Use governed-adapter or disabled.',
    );
  }
  return mode;
}

export function resolveAgentIdentityMode(env = process.env) {
  const explicit = env.ASTRANULL_AGENT_IDENTITY_MODE?.trim();
  const nodeEnv = env.NODE_ENV ?? 'development';
  const mode = explicit || (nodeEnv === 'production' ? 'gateway-mtls' : 'bearer');
  if (!AGENT_IDENTITY_MODES.includes(mode)) {
    throw new Error(
      `Invalid ASTRANULL_AGENT_IDENTITY_MODE "${mode}". Allowed: ${AGENT_IDENTITY_MODES.join(', ')}.`,
    );
  }
  if (nodeEnv === 'production' && mode === 'bearer' && !isHostedStagingDeployment(env)) {
    throw new Error(
      'Refusing to start: ASTRANULL_AGENT_IDENTITY_MODE=bearer is not permitted when NODE_ENV=production. Use gateway-mtls.',
    );
  }
  return mode;
}

export function resolveAuthMode(env = process.env) {
  const explicit = env.ASTRANULL_AUTH_MODE?.trim();
  if (explicit) {
    if (!AUTH_MODES.includes(explicit)) {
      throw new Error(
        `Invalid ASTRANULL_AUTH_MODE "${explicit}". Allowed: ${AUTH_MODES.join(', ')}.`,
      );
    }
    return explicit;
  }
  const nodeEnv = env.NODE_ENV ?? 'development';
  return nodeEnv === 'production' ? 'oidc-jwt' : 'dev-headers';
}

function assertProductionPersistence(env, persistenceMode) {
  const nodeEnv = env.NODE_ENV ?? 'development';
  if (nodeEnv !== 'production') return;

  if (persistenceMode === 'memory' || persistenceMode === 'dev-json') {
    throw new Error(
      `Refusing to start: persistence mode "${persistenceMode}" is not permitted when NODE_ENV=production. Use postgres with ASTRANULL_DATABASE_URL.`,
    );
  }

  if (persistenceMode === 'postgres') {
    const databaseUrl = (env.ASTRANULL_DATABASE_URL ?? '').trim();
    if (!databaseUrl) {
      throw new Error(
        'Refusing to start: ASTRANULL_DATABASE_URL must be set when NODE_ENV=production and persistence mode is postgres.',
      );
    }
  }
}

export function loadRuntimeConfig(env = process.env) {
  applyBundledStagingOidcEnvDefaults(env);
  const nodeEnv = env.NODE_ENV ?? 'development';
  const deploymentProfile = resolveDeploymentProfile(env);
  const authMode = resolveAuthMode(env);

  if (
    nodeEnv === 'production'
    && (authMode === 'dev-headers' || authMode === 'signed-session')
  ) {
    throw new Error(
      'Refusing to start: ASTRANULL_AUTH_MODE must be oidc-jwt when NODE_ENV=production. dev-headers and signed-session are not permitted.',
    );
  }

  if (nodeEnv === 'production' && env.ASTRANULL_RATE_LIMIT_DISABLED === '1') {
    throw new Error(
      'Refusing to start: ASTRANULL_RATE_LIMIT_DISABLED=1 is not permitted when NODE_ENV=production.',
    );
  }

  let sessionSecret = null;
  if (authMode === 'signed-session') {
    sessionSecret = env.ASTRANULL_SESSION_SECRET ?? '';
    if (sessionSecret.length < MIN_SESSION_SECRET_LENGTH) {
      throw new Error(
        `ASTRANULL_SESSION_SECRET must be at least ${MIN_SESSION_SECRET_LENGTH} characters when auth mode is signed-session.`,
      );
    }
  }

  /** @type {null | OidcRuntimeConfig} */
  let oidc = null;
  if (authMode === 'oidc-jwt') {
    const issuer = (env.ASTRANULL_OIDC_ISSUER ?? '').trim();
    const audience = (env.ASTRANULL_OIDC_AUDIENCE ?? '').trim();
    const jwksUrl = (env.ASTRANULL_OIDC_JWKS_URL ?? '').trim();
    if (!issuer) {
      throw new Error('ASTRANULL_OIDC_ISSUER must be set when auth mode is oidc-jwt.');
    }
    if (!audience) {
      throw new Error('ASTRANULL_OIDC_AUDIENCE must be set when auth mode is oidc-jwt.');
    }
    if (!jwksUrl) {
      throw new Error('ASTRANULL_OIDC_JWKS_URL must be set when auth mode is oidc-jwt.');
    }
    assertOidcJwksUrl(jwksUrl, nodeEnv);
    const tenantClaim = (env.ASTRANULL_OIDC_TENANT_CLAIM ?? DEFAULT_OIDC_TENANT_CLAIM).trim()
      || DEFAULT_OIDC_TENANT_CLAIM;
    const roleClaim = (env.ASTRANULL_OIDC_ROLE_CLAIM ?? DEFAULT_OIDC_ROLE_CLAIM).trim()
      || DEFAULT_OIDC_ROLE_CLAIM;
    const userClaim = (env.ASTRANULL_OIDC_USER_CLAIM ?? DEFAULT_OIDC_USER_CLAIM).trim()
      || DEFAULT_OIDC_USER_CLAIM;
    const requireMfa = parseOptionalBoolean(
      env.ASTRANULL_OIDC_REQUIRE_MFA,
      'ASTRANULL_OIDC_REQUIRE_MFA',
      nodeEnv === 'production',
    );
    const mfaClaim = (env.ASTRANULL_OIDC_MFA_CLAIM ?? DEFAULT_OIDC_MFA_CLAIM).trim()
      || DEFAULT_OIDC_MFA_CLAIM;
    const mfaValues = parseCommaSeparatedList(
      env.ASTRANULL_OIDC_MFA_VALUES,
      DEFAULT_OIDC_MFA_VALUES,
      'ASTRANULL_OIDC_MFA_VALUES',
    );
    const jwksCacheTtlMs = parsePositiveInt(
      env.ASTRANULL_OIDC_JWKS_CACHE_TTL_MS,
      'ASTRANULL_OIDC_JWKS_CACHE_TTL_MS',
      {
        min: MIN_OIDC_JWKS_CACHE_TTL_MS,
        max: MAX_OIDC_JWKS_CACHE_TTL_MS,
        fallback: DEFAULT_OIDC_JWKS_CACHE_TTL_MS,
      },
    );
    const jwksFetchTimeoutMs = parsePositiveInt(
      env.ASTRANULL_OIDC_JWKS_FETCH_TIMEOUT_MS,
      'ASTRANULL_OIDC_JWKS_FETCH_TIMEOUT_MS',
      {
        min: MIN_OIDC_JWKS_FETCH_TIMEOUT_MS,
        max: MAX_OIDC_JWKS_FETCH_TIMEOUT_MS,
        fallback: DEFAULT_OIDC_JWKS_FETCH_TIMEOUT_MS,
      },
    );
    const rolePrefix = (env.ASTRANULL_OIDC_ROLE_PREFIX ?? '').trim();
    const roleMap = parseOidcRoleMap(env.ASTRANULL_OIDC_ROLE_MAP, 'ASTRANULL_OIDC_ROLE_MAP');
    oidc = {
      issuer,
      audience,
      jwksUrl,
      tenantClaim,
      roleClaim,
      userClaim,
      requireMfa,
      mfaClaim,
      mfaValues,
      jwksCacheTtlMs,
      jwksFetchTimeoutMs,
      rolePrefix: rolePrefix || null,
      roleMap,
      requireExplicitRoleMap: nodeEnv === 'production' && !isHostedStagingDeployment(env),
    };
  }

  const secretEncryptionKey = loadSecretEncryptionKey(env, {
    required: nodeEnv === 'production',
  });
  const secretEncryptionConfigured = Boolean(secretEncryptionKey);

  const maxJsonBodyBytes = parsePositiveInt(env.ASTRANULL_MAX_JSON_BODY_BYTES, 'ASTRANULL_MAX_JSON_BODY_BYTES', {
    min: 1,
    max: MAX_MAX_JSON_BODY_BYTES,
    fallback: DEFAULT_MAX_JSON_BODY_BYTES,
  });
  const shutdownGraceMs = parsePositiveInt(env.ASTRANULL_SHUTDOWN_GRACE_MS, 'ASTRANULL_SHUTDOWN_GRACE_MS', {
    min: 100,
    max: MAX_SHUTDOWN_GRACE_MS,
    fallback: DEFAULT_SHUTDOWN_GRACE_MS,
  });

  const persistenceMode = resolvePersistenceMode(env);
  assertProductionPersistence(env, persistenceMode);

  const databaseUrlConfigured =
    persistenceMode === 'postgres' && Boolean((env.ASTRANULL_DATABASE_URL ?? '').trim());

  const probeMode = resolveProbeMode(env);
  let probeWorkerSecret = null;
  if (probeMode === 'signed-worker') {
    probeWorkerSecret = env.ASTRANULL_PROBE_WORKER_SECRET ?? '';
    if (probeWorkerSecret.length < MIN_PROBE_WORKER_SECRET_LENGTH) {
      throw new Error(
        `ASTRANULL_PROBE_WORKER_SECRET must be at least ${MIN_PROBE_WORKER_SECRET_LENGTH} characters when probe mode is signed-worker.`,
      );
    }
  }

  const highScaleAdapterMode = resolveHighScaleAdapterMode(env);
  const agentIdentityMode = resolveAgentIdentityMode(env);

  const rateLimitDisabled = env.ASTRANULL_RATE_LIMIT_DISABLED === '1';
  const rateLimitTrustProxyHeaders = env.ASTRANULL_TRUST_PROXY_HEADERS === '1';

  const rateLimitWindowMs = parsePositiveInt(
    env.ASTRANULL_RATE_LIMIT_WINDOW_MS,
    'ASTRANULL_RATE_LIMIT_WINDOW_MS',
    {
      min: MIN_RATE_LIMIT_WINDOW_MS,
      max: MAX_RATE_LIMIT_WINDOW_MS,
      fallback: DEFAULT_RATE_LIMIT_WINDOW_MS,
    },
  );
  const rateLimitMaxRequests = parsePositiveInt(
    env.ASTRANULL_RATE_LIMIT_MAX_REQUESTS,
    'ASTRANULL_RATE_LIMIT_MAX_REQUESTS',
    {
      min: MIN_RATE_LIMIT_MAX_REQUESTS,
      max: MAX_RATE_LIMIT_MAX_REQUESTS,
      fallback: DEFAULT_RATE_LIMIT_MAX_REQUESTS,
    },
  );

  const wafPostureEnabled = parseOptionalBoolean(
    env.ASTRANULL_WAF_POSTURE_ENABLED,
    'ASTRANULL_WAF_POSTURE_ENABLED',
    false,
  );
  const externalDiscoveryEnabled = parseOptionalBoolean(
    env.ASTRANULL_EXTERNAL_DISCOVERY_ENABLED,
    'ASTRANULL_EXTERNAL_DISCOVERY_ENABLED',
    false,
  );
  const connectorsEnabledDefault = parseOptionalBoolean(
    env.ASTRANULL_CONNECTORS_ENABLED,
    'ASTRANULL_CONNECTORS_ENABLED',
    false,
  );
  const connectorsEnabledTenants = parseTenantBooleanMap(
    env.ASTRANULL_CONNECTORS_ENABLED_TENANTS,
    'ASTRANULL_CONNECTORS_ENABLED_TENANTS',
  );

  const bundledStagingOidc = env.ASTRANULL_BUNDLED_STAGING_OIDC === '1';
  const publicLoginUrl = (
    env.ASTRANULL_PUBLIC_LOGIN_URL
    ?? (bundledStagingOidc ? '/login' : '/app')
  ).trim() || (bundledStagingOidc ? '/login' : '/app');
  const publicSignupEnabled = env.ASTRANULL_PUBLIC_SIGNUP_ENABLED !== '0';
  const staffLoginPath = (
    String(env.ASTRANULL_STAFF_LOGIN_PATH ?? '/internal/admin/login').trim() || '/internal/admin/login'
  );
  const internalAdminPath = (
    String(env.ASTRANULL_INTERNAL_ADMIN_PATH ?? '/internal/admin').trim() || '/internal/admin'
  );

  return {
    authMode,
    sessionSecret,
    oidc,
    deploymentProfile,
    bundledStagingOidc,
    publicSite: {
      loginUrl: publicLoginUrl,
      signupEnabled: publicSignupEnabled,
    },
    staffLoginPath,
    internalAdminPath,
    nodeEnv,
    maxJsonBodyBytes,
    shutdownGraceMs,
    persistenceMode,
    databaseUrlConfigured,
    probeMode,
    probeWorkerSecret,
    probeWorkerSecretConfigured: probeMode === 'signed-worker' && Boolean(probeWorkerSecret),
    highScaleAdapterMode,
    agentIdentityMode,
    rateLimit: {
      windowMs: rateLimitWindowMs,
      maxRequests: rateLimitMaxRequests,
      disabled: rateLimitDisabled,
      trustProxyHeaders: rateLimitTrustProxyHeaders,
    },
    secretEncryptionKey,
    secretEncryptionConfigured,
    featureFlags: {
      wafPostureEnabled,
      externalDiscoveryEnabled,
      connectorsEnabledDefault,
      connectorsEnabledTenants,
    },
  };
}
