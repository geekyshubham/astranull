#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadRuntimeConfig, resolveAuthMode } from '../src/config.mjs';
import { redactDatabaseUrlInMessage } from '../src/lib/pgErrorRedact.mjs';
import { redactObject } from '../src/lib/redact.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DEFAULT_OUT = 'output/oidc-prod-auth-preflight.json';

const DEV_SESSION_SECRET = 'preflight-negative-session-secret-32-chars!!';
const PROBE_SECRET = 'preflight-probe-worker-secret-32-chars!!';
const ENC_KEY_PLACEHOLDER = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';

export function parseArgs(argv = []) {
  const opts = {
    out: DEFAULT_OUT,
    help: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = () => {
      i += 1;
      if (i >= argv.length) throw new Error(`Missing value for ${arg}`);
      return argv[i];
    };
    if (arg === '--out') opts.out = next();
    else if (arg === '--help' || arg === '-h') opts.help = true;
    else throw new Error(`Unknown argument: ${arg}`);
  }
  return opts;
}

export function redactUrlForEvidence(raw) {
  if (raw === undefined || raw === null || raw === '') return null;
  const value = String(raw);
  try {
    const parsed = new URL(value);
    if (parsed.username || parsed.password) {
      parsed.username = '';
      parsed.password = '';
    }
    if (parsed.search) {
      parsed.search = '?[REDACTED]';
    }
    return parsed.toString();
  } catch {
    return '[REDACTED_INVALID_URL]';
  }
}

function redactDetail(message, env) {
  const text = typeof message === 'string' ? message : String(message);
  return redactDatabaseUrlInMessage(redactObject(text), env);
}

function pushCheck(checks, env, { id, ok, detail, required = true }) {
  checks.push({
    id,
    ok: Boolean(ok),
    required,
    detail: typeof detail === 'string' ? redactDetail(detail, env) : detail,
  });
}

export function verifyJwksFetchRedirectPolicyOffline(rootDir = ROOT) {
  const text = readFileSync(path.join(rootDir, 'src/lib/oidc.mjs'), 'utf8');
  const ok = /fetch\s*\(\s*jwksUrl[\s\S]*?redirect:\s*['"]manual['"]/m.test(text);
  return {
    ok,
    detail: ok
      ? 'JWKS verification uses fetch redirect=manual (redirects not followed).'
      : 'Could not confirm JWKS redirect=manual policy in src/lib/oidc.mjs.',
  };
}

function productionProbeEnv(overrides = {}) {
  return {
    NODE_ENV: 'production',
    ASTRANULL_AUTH_MODE: 'oidc-jwt',
    ASTRANULL_OIDC_ISSUER: 'https://idp.example/oauth2/default',
    ASTRANULL_OIDC_AUDIENCE: 'astranull-api',
    ASTRANULL_OIDC_JWKS_URL: 'https://idp.example/oauth2/default/v1/keys',
    ASTRANULL_SECRET_ENCRYPTION_KEY: ENC_KEY_PLACEHOLDER,
    ASTRANULL_DATABASE_URL: 'postgresql://preflight:secret@db.example:5432/astranull',
    ASTRANULL_PROBE_WORKER_SECRET: PROBE_SECRET,
    ...overrides,
  };
}

function probeStartupRefused(env) {
  try {
    loadRuntimeConfig(env);
    return { ok: false, detail: 'Expected startup refusal but loadRuntimeConfig succeeded.' };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { ok: true, detail: redactDatabaseUrlInMessage(message, env) };
  }
}

export function evaluateOidcProdAuthPreflight(env = process.env, options = {}) {
  const rootDir = options.rootDir ?? ROOT;
  const checks = [];
  const nodeEnv = env.NODE_ENV ?? 'development';

  pushCheck(checks, env, {
    id: 'node_env_production',
    ok: nodeEnv === 'production',
    detail: nodeEnv === 'production'
      ? 'NODE_ENV=production.'
      : `NODE_ENV must be production for prod-auth preflight (got "${nodeEnv}").`,
  });

  let authMode = null;
  let authModeError = null;
  try {
    authMode = resolveAuthMode(env);
  } catch (err) {
    authModeError = err instanceof Error ? err.message : String(err);
  }

  pushCheck(checks, env, {
    id: 'auth_mode_oidc_jwt',
    ok: authMode === 'oidc-jwt',
    detail: authModeError
      ?? (authMode === 'oidc-jwt'
        ? 'ASTRANULL_AUTH_MODE resolves to oidc-jwt.'
        : `ASTRANULL_AUTH_MODE must be oidc-jwt in production (resolved "${authMode ?? 'unknown'}").`),
  });

  const issuer = (env.ASTRANULL_OIDC_ISSUER ?? '').trim();
  const audience = (env.ASTRANULL_OIDC_AUDIENCE ?? '').trim();
  const jwksUrl = (env.ASTRANULL_OIDC_JWKS_URL ?? '').trim();

  pushCheck(checks, env, {
    id: 'oidc_issuer_configured',
    ok: Boolean(issuer),
    detail: issuer ? 'ASTRANULL_OIDC_ISSUER is set.' : 'ASTRANULL_OIDC_ISSUER must be set for oidc-jwt.',
  });

  pushCheck(checks, env, {
    id: 'oidc_audience_configured',
    ok: Boolean(audience),
    detail: audience
      ? 'ASTRANULL_OIDC_AUDIENCE is set.'
      : 'ASTRANULL_OIDC_AUDIENCE must be set for oidc-jwt.',
  });

  let jwksHttps = false;
  let jwksDetail = 'ASTRANULL_OIDC_JWKS_URL must be set for oidc-jwt.';
  if (jwksUrl) {
    try {
      const parsed = new URL(jwksUrl);
      jwksHttps = nodeEnv !== 'production' || parsed.protocol === 'https:';
      jwksDetail = jwksHttps
        ? 'ASTRANULL_OIDC_JWKS_URL uses HTTPS in production.'
        : 'ASTRANULL_OIDC_JWKS_URL must use HTTPS when NODE_ENV=production.';
    } catch {
      jwksDetail = 'ASTRANULL_OIDC_JWKS_URL must be a valid URL.';
    }
  }
  pushCheck(checks, env, {
    id: 'oidc_jwks_https',
    ok: Boolean(jwksUrl) && jwksHttps,
    detail: jwksDetail,
  });

  const redirectPolicy = verifyJwksFetchRedirectPolicyOffline(rootDir);
  pushCheck(checks, env, {
    id: 'jwks_redirect_policy_manual',
    ok: redirectPolicy.ok,
    detail: redirectPolicy.detail,
  });

  let runtimeConfig = null;
  let runtimeError = null;
  try {
    runtimeConfig = loadRuntimeConfig(env);
  } catch (err) {
    runtimeError = err instanceof Error ? err.message : String(err);
  }

  pushCheck(checks, env, {
    id: 'production_runtime_config_loads',
    ok: Boolean(runtimeConfig),
    detail: runtimeError
      ? redactDatabaseUrlInMessage(runtimeError, env)
      : 'loadRuntimeConfig succeeded under production posture.',
  });

  const requireMfa = runtimeConfig?.oidc?.requireMfa;
  pushCheck(checks, env, {
    id: 'oidc_mfa_enforced',
    ok: requireMfa === true,
    detail: requireMfa === true
      ? 'OIDC MFA claim enforcement is enabled (production default).'
      : 'OIDC MFA must be enforced in production (do not set ASTRANULL_OIDC_REQUIRE_MFA=0).',
  });

  const negativeDevHeaders = probeStartupRefused(
    productionProbeEnv({ ASTRANULL_AUTH_MODE: 'dev-headers' }),
  );
  pushCheck(checks, env, {
    id: 'negative_dev_headers_refused',
    ok: negativeDevHeaders.ok,
    detail: negativeDevHeaders.detail,
  });

  const negativeSignedSession = probeStartupRefused(
    productionProbeEnv({
      ASTRANULL_AUTH_MODE: 'signed-session',
      ASTRANULL_SESSION_SECRET: DEV_SESSION_SECRET,
    }),
  );
  pushCheck(checks, env, {
    id: 'negative_signed_session_refused',
    ok: negativeSignedSession.ok,
    detail: negativeSignedSession.detail,
  });

  const negativeHttpJwks = probeStartupRefused(
    productionProbeEnv({ ASTRANULL_OIDC_JWKS_URL: 'http://idp.example/jwks' }),
  );
  pushCheck(checks, env, {
    id: 'negative_http_jwks_refused',
    ok: negativeHttpJwks.ok,
    detail: negativeHttpJwks.detail,
  });

  const requiredFailed = checks.filter((check) => check.required && !check.ok);
  const ok = requiredFailed.length === 0;

  const authPosture = runtimeConfig?.oidc
    ? {
      auth_mode: runtimeConfig.authMode,
      oidc: {
        issuer_redacted: redactUrlForEvidence(runtimeConfig.oidc.issuer),
        audience: runtimeConfig.oidc.audience,
        jwks_url_redacted: redactUrlForEvidence(runtimeConfig.oidc.jwksUrl),
        tenant_claim: runtimeConfig.oidc.tenantClaim,
        role_claim: runtimeConfig.oidc.roleClaim,
        user_claim: runtimeConfig.oidc.userClaim,
        require_mfa: runtimeConfig.oidc.requireMfa,
        mfa_claim: runtimeConfig.oidc.mfaClaim,
        mfa_values: runtimeConfig.oidc.mfaValues,
        jwks_cache_ttl_ms: runtimeConfig.oidc.jwksCacheTtlMs,
        jwks_fetch_timeout_ms: runtimeConfig.oidc.jwksFetchTimeoutMs,
      },
      jwks_redirect_policy: 'manual',
    }
    : {
      auth_mode: authMode,
      oidc: {
        issuer_redacted: redactUrlForEvidence(issuer),
        audience: audience || null,
        jwks_url_redacted: redactUrlForEvidence(jwksUrl),
      },
      jwks_redirect_policy: 'manual',
    };

  return {
    ok,
    checks,
    auth_posture: redactObject(authPosture),
  };
}

export function createOidcProdAuthPreflightManifest(input = {}) {
  const evaluation = input.evaluation ?? evaluateOidcProdAuthPreflight(input.env ?? process.env, input);
  return {
    schema_version: 1,
    artifact_type: 'oidc_production_auth_preflight',
    mode: 'offline',
    created_at: input.createdAt ?? new Date().toISOString(),
    node_env: (input.env ?? process.env).NODE_ENV ?? 'development',
    ok: evaluation.ok,
    checks: evaluation.checks,
    auth_posture: evaluation.auth_posture,
    caveats: [
      'Offline metadata-only preflight; does not fetch JWKS or contact a live IdP.',
      'Passing checks prove config refusal of dev-header/signed-session and unsafe JWKS posture only.',
      'Production signoff still requires real IdP tenant/role mapping, staging login flow, and header-only negative API tests.',
    ],
  };
}

export async function main(argv = process.argv.slice(2)) {
  const opts = parseArgs(argv);
  if (opts.help) {
    console.log(
      'Usage: node scripts/oidc-prod-auth-preflight.mjs [--out file]',
    );
    console.log('');
    console.log('Evaluates NODE_ENV=production OIDC auth posture from process.env.');
    console.log('Pure offline: no JWKS fetch or IdP contact. Writes metadata-only JSON.');
    return 0;
  }

  const manifest = createOidcProdAuthPreflightManifest({ env: process.env });
  mkdirSync(path.dirname(opts.out), { recursive: true });
  writeFileSync(opts.out, `${JSON.stringify(manifest, null, 2)}\n`);

  const failed = manifest.checks.filter((check) => check.required && !check.ok).length;
  console.log(
    `oidc-prod-auth-preflight: ${manifest.ok ? 'ok' : 'failed'} (${manifest.checks.length} check(s), ${failed} failed) wrote ${opts.out}`,
  );
  return manifest.ok ? 0 : 1;
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(`oidc-prod-auth-preflight: ${err.message}`);
      process.exit(1);
    },
  );
}