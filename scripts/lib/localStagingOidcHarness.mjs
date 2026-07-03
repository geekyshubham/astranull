import http from 'node:http';
import { createSign, generateKeyPairSync } from 'node:crypto';
import { loadRuntimeConfig } from '../../src/config.mjs';
import { verifyOidcBearerToken } from '../../src/lib/oidc.mjs';
import { createServer } from '../../src/server.mjs';
import { freshStore } from '../../tests/helpers/reset.mjs';

const ISSUER = 'https://idp.local-staging.astranull.test';
const AUDIENCE = 'astranull-local-staging';
const KID = 'local-staging-rsa-1';

const { privateKey, publicKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
});

const publicJwk = publicKey.export({ format: 'jwk' });
publicJwk.kid = KID;
publicJwk.alg = 'RS256';
publicJwk.use = 'sig';

function base64UrlJson(obj) {
  return Buffer.from(JSON.stringify(obj), 'utf8').toString('base64url');
}

export function mintLocalStagingOidcJwt({
  role,
  tenantId = 'ten_demo',
  userId = 'usr_oidc_local',
  exp,
  extraClaims = {},
  roleClaimKey = 'role',
  tenantClaimKey = 'tenant_id',
  userClaimKey = 'sub',
}) {
  const header = { alg: 'RS256', typ: 'JWT', kid: KID };
  const payload = {
    iss: ISSUER,
    aud: AUDIENCE,
    exp: exp ?? Math.floor(Date.now() / 1000) + 3600,
    amr: ['mfa', 'otp'],
    ...extraClaims,
  };
  payload[userClaimKey] = userId;
  payload[tenantClaimKey] = tenantId;
  payload[roleClaimKey] = role;
  const headerB64 = base64UrlJson(header);
  const payloadB64 = base64UrlJson(payload);
  const signingInput = `${headerB64}.${payloadB64}`;
  const sig = createSign('RSA-SHA256').update(signingInput, 'utf8').sign(privateKey);
  return `${signingInput}.${sig.toString('base64url')}`;
}

async function startJwksServer() {
  const server = http.createServer((req, res) => {
    if (req.url === '/jwks' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ keys: [publicJwk] }));
      return;
    }
    res.writeHead(404);
    res.end();
  });
  await new Promise((resolve) => {
    server.listen(0, '127.0.0.1', resolve);
  });
  const { port } = server.address();
  return { server, jwksUrl: `http://127.0.0.1:${port}/jwks` };
}

async function startOidcAppServer(jwksUrl) {
  process.env.ASTRANULL_AUTH_MODE = 'oidc-jwt';
  process.env.ASTRANULL_OIDC_ISSUER = ISSUER;
  process.env.ASTRANULL_OIDC_AUDIENCE = AUDIENCE;
  process.env.ASTRANULL_OIDC_JWKS_URL = jwksUrl;
  process.env.ASTRANULL_OIDC_REQUIRE_MFA = '1';
  delete process.env.NODE_ENV;
  freshStore();
  const appServer = createServer();
  appServer.listen(0);
  const { port } = appServer.address();
  return { appServer, baseUrl: `http://127.0.0.1:${port}` };
}

async function requestJson(baseUrl, method, pathname, options = {}) {
  const response = await fetch(new URL(pathname, baseUrl), {
    method,
    headers: options.headers ?? {},
    body: options.body,
  });
  const text = await response.text();
  let json = null;
  if (text) {
    try {
      json = JSON.parse(text);
    } catch {
      json = { raw: text };
    }
  }
  return { status: response.status, json };
}

/**
 * Execute local OIDC/JWKS fixture login proof without persisting tokens in evidence.
 */
export async function runLocalStagingOidcLoginProof() {
  const checks = [];
  const { server: jwksServer, jwksUrl } = await startJwksServer();
  let appServer;
  try {
    ({ appServer } = await startOidcAppServer(jwksUrl));
    const baseUrl = `http://127.0.0.1:${appServer.address().port}`;

    const token = mintLocalStagingOidcJwt({ role: 'engineer', userId: 'usr_eng_local' });
    const ok = await requestJson(baseUrl, 'GET', '/v1/tenants/current', {
      headers: { Authorization: `Bearer ${token}`, accept: 'application/json' },
    });
    if (ok.status !== 200 || ok.json?.id !== 'ten_demo') {
      throw new Error(`OIDC bearer login expected 200 tenant current (got ${ok.status})`);
    }
    checks.push('oidc_bearer_login');

    const headerBypass = await requestJson(baseUrl, 'GET', '/v1/tenants/current', {
      headers: {
        accept: 'application/json',
        'x-tenant-id': 'ten_demo',
        'x-user-id': 'usr_eng_local',
        'x-role': 'engineer',
      },
    });
    if (headerBypass.status !== 401) {
      throw new Error(`header-only bypass expected 401 (got ${headerBypass.status})`);
    }
    checks.push('header_only_negative');

    const socToken = mintLocalStagingOidcJwt({ role: 'soc', userId: 'usr_soc_local' });
    const socOk = await requestJson(baseUrl, 'GET', '/v1/state', {
      headers: { Authorization: `Bearer ${socToken}`, accept: 'application/json' },
    });
    if (socOk.status !== 200) {
      throw new Error(`SOC OIDC role mapping expected 200 (got ${socOk.status})`);
    }
    checks.push('soc_role_mapping');

    const noMfa = mintLocalStagingOidcJwt({
      role: 'engineer',
      userId: 'usr_no_mfa',
      extraClaims: { amr: ['pwd'] },
    });
    const runtime = loadRuntimeConfig(process.env);
    const mfaVerify = await verifyOidcBearerToken(noMfa, runtime.oidc);
    if (mfaVerify.error !== 'mfa_required') {
      throw new Error(`MFA enforcement expected mfa_required (got ${mfaVerify.error ?? 'ok'})`);
    }
    const mfaDenied = await requestJson(baseUrl, 'GET', '/v1/tenants/current', {
      headers: { Authorization: `Bearer ${noMfa}`, accept: 'application/json' },
    });
    if (mfaDenied.status !== 401 || mfaDenied.json?.error !== 'unauthorized') {
      throw new Error(`MFA HTTP denial expected 401 unauthorized (got ${mfaDenied.status})`);
    }
    checks.push('mfa_enforcement');
  } finally {
    appServer?.close();
    jwksServer?.close();
  }

  return {
    checks,
    evidence_uri: 'evidence://local-staging/oidc-jwks-fixture/login-proof',
  };
}