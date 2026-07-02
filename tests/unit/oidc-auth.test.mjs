import assert from 'node:assert/strict';
import {
  createSign,
  generateKeyPairSync,
} from 'node:crypto';
import { afterEach, describe, it } from 'node:test';
import { clearJwksCache, verifyOidcBearerToken } from '../../src/lib/oidc.mjs';
import http from 'node:http';

const ISSUER = 'https://idp.test.example';
const AUDIENCE = 'astranull-api';
const KID = 'test-rsa-1';

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

function signRs256Jwt(payload, headerExtra = {}) {
  const header = { alg: 'RS256', typ: 'JWT', kid: KID, ...headerExtra };
  const headerB64 = base64UrlJson(header);
  const payloadB64 = base64UrlJson(payload);
  const signingInput = `${headerB64}.${payloadB64}`;
  const sig = createSign('RSA-SHA256').update(signingInput, 'utf8').sign(privateKey);
  return `${signingInput}.${sig.toString('base64url')}`;
}

function defaultOidcConfig(jwksUrl) {
  return {
    issuer: ISSUER,
    audience: AUDIENCE,
    jwksUrl,
    tenantClaim: 'tenant_id',
    roleClaim: 'role',
    userClaim: 'sub',
    requireMfa: false,
    mfaClaim: 'amr',
    mfaValues: ['mfa', 'otp', 'webauthn', 'fido', 'fido2', 'phishing_resistant'],
    jwksCacheTtlMs: 300_000,
  };
}

function startJwksServer(keys) {
  const server = http.createServer((req, res) => {
    if (req.url === '/jwks' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ keys }));
      return;
    }
    res.writeHead(404);
    res.end();
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ server, jwksUrl: `http://127.0.0.1:${port}/jwks` });
    });
  });
}

function startHangingJwksServer() {
  const server = http.createServer(() => {
    // Intentionally never respond so JWKS fetch can time out.
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ server, jwksUrl: `http://127.0.0.1:${port}/jwks` });
    });
  });
}

afterEach(() => {
  clearJwksCache();
});

describe('OIDC bearer JWT verification', () => {
  it('verifies a valid RS256 token and maps claims', async () => {
    const { server, jwksUrl } = await startJwksServer([publicJwk]);
    try {
      const token = signRs256Jwt({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'usr_oidc_1',
        tenant_id: 'ten_oidc',
        role: 'engineer',
        exp: Math.floor(Date.now() / 1000) + 3600,
      });
      const ctx = await verifyOidcBearerToken(token, defaultOidcConfig(jwksUrl));
      assert.equal(ctx.tenantId, 'ten_oidc');
      assert.equal(ctx.userId, 'usr_oidc_1');
      assert.equal(ctx.role, 'engineer');
    } finally {
      server.close();
    }
  });

  it('accepts audience as an array', async () => {
    const { server, jwksUrl } = await startJwksServer([publicJwk]);
    try {
      const token = signRs256Jwt({
        iss: ISSUER,
        aud: ['other', AUDIENCE],
        sub: 'usr_1',
        tenant_id: 'ten_a',
        role: 'viewer',
        exp: Math.floor(Date.now() / 1000) + 3600,
      });
      const ctx = await verifyOidcBearerToken(token, defaultOidcConfig(jwksUrl));
      assert.equal(ctx.role, 'viewer');
    } finally {
      server.close();
    }
  });

  it('picks the first valid role from an array claim', async () => {
    const { server, jwksUrl } = await startJwksServer([publicJwk]);
    try {
      const token = signRs256Jwt({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'usr_1',
        tenant_id: 'ten_a',
        role: ['unknown', 'admin'],
        exp: Math.floor(Date.now() / 1000) + 3600,
      });
      const ctx = await verifyOidcBearerToken(token, defaultOidcConfig(jwksUrl));
      assert.equal(ctx.role, 'admin');
    } finally {
      server.close();
    }
  });

  it('rejects tokens without accepted MFA evidence when MFA is required', async () => {
    const { server, jwksUrl } = await startJwksServer([publicJwk]);
    try {
      const cfg = { ...defaultOidcConfig(jwksUrl), requireMfa: true };
      const token = signRs256Jwt({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'usr_1',
        tenant_id: 'ten_a',
        role: 'viewer',
        exp: Math.floor(Date.now() / 1000) + 3600,
      });
      assert.equal((await verifyOidcBearerToken(token, cfg)).error, 'mfa_required');

      const passwordOnly = signRs256Jwt({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'usr_1',
        tenant_id: 'ten_a',
        role: 'viewer',
        amr: ['pwd'],
        exp: Math.floor(Date.now() / 1000) + 3600,
      });
      assert.equal((await verifyOidcBearerToken(passwordOnly, cfg)).error, 'mfa_required');
    } finally {
      server.close();
    }
  });

  it('accepts scalar and array MFA claim evidence when configured', async () => {
    const { server, jwksUrl } = await startJwksServer([publicJwk]);
    try {
      const cfg = { ...defaultOidcConfig(jwksUrl), requireMfa: true };
      const arrayMfa = signRs256Jwt({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'usr_array',
        tenant_id: 'ten_a',
        role: 'viewer',
        amr: ['pwd', 'mfa'],
        exp: Math.floor(Date.now() / 1000) + 3600,
      });
      assert.equal((await verifyOidcBearerToken(arrayMfa, cfg)).userId, 'usr_array');

      const scalarMfa = signRs256Jwt({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'usr_scalar',
        tenant_id: 'ten_a',
        role: 'engineer',
        amr: 'webauthn',
        exp: Math.floor(Date.now() / 1000) + 3600,
      });
      assert.equal((await verifyOidcBearerToken(scalarMfa, cfg)).userId, 'usr_scalar');
    } finally {
      server.close();
    }
  });

  it('supports custom MFA claim names and accepted values', async () => {
    const { server, jwksUrl } = await startJwksServer([publicJwk]);
    try {
      const cfg = {
        ...defaultOidcConfig(jwksUrl),
        requireMfa: true,
        mfaClaim: 'acr',
        mfaValues: ['urn:example:assurance:mfa'],
      };
      const token = signRs256Jwt({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'usr_acr',
        tenant_id: 'ten_a',
        role: 'admin',
        acr: 'URN:EXAMPLE:ASSURANCE:MFA',
        exp: Math.floor(Date.now() / 1000) + 3600,
      });
      assert.equal((await verifyOidcBearerToken(token, cfg)).role, 'admin');
    } finally {
      server.close();
    }
  });

  it('rejects HS256 alg', async () => {
    const { server, jwksUrl } = await startJwksServer([publicJwk]);
    try {
      const token = signRs256Jwt(
        {
          iss: ISSUER,
          aud: AUDIENCE,
          sub: 'usr_1',
          tenant_id: 'ten_a',
          role: 'viewer',
          exp: Math.floor(Date.now() / 1000) + 3600,
        },
        { alg: 'HS256' },
      );
      assert.equal((await verifyOidcBearerToken(token, defaultOidcConfig(jwksUrl))).error, 'invalid_token');
    } finally {
      server.close();
    }
  });

  it('rejects none alg', async () => {
    const { server, jwksUrl } = await startJwksServer([publicJwk]);
    try {
      const token = signRs256Jwt(
        {
          iss: ISSUER,
          aud: AUDIENCE,
          sub: 'usr_1',
          tenant_id: 'ten_a',
          role: 'viewer',
          exp: Math.floor(Date.now() / 1000) + 3600,
        },
        { alg: 'none' },
      );
      assert.equal((await verifyOidcBearerToken(token, defaultOidcConfig(jwksUrl))).error, 'invalid_token');
    } finally {
      server.close();
    }
  });

  it('rejects wrong issuer', async () => {
    const { server, jwksUrl } = await startJwksServer([publicJwk]);
    try {
      const token = signRs256Jwt({
        iss: 'https://evil.example',
        aud: AUDIENCE,
        sub: 'usr_1',
        tenant_id: 'ten_a',
        role: 'viewer',
        exp: Math.floor(Date.now() / 1000) + 3600,
      });
      assert.equal((await verifyOidcBearerToken(token, defaultOidcConfig(jwksUrl))).error, 'invalid_token');
    } finally {
      server.close();
    }
  });

  it('rejects wrong audience', async () => {
    const { server, jwksUrl } = await startJwksServer([publicJwk]);
    try {
      const token = signRs256Jwt({
        iss: ISSUER,
        aud: 'wrong-aud',
        sub: 'usr_1',
        tenant_id: 'ten_a',
        role: 'viewer',
        exp: Math.floor(Date.now() / 1000) + 3600,
      });
      assert.equal((await verifyOidcBearerToken(token, defaultOidcConfig(jwksUrl))).error, 'invalid_token');
    } finally {
      server.close();
    }
  });

  it('rejects non-numeric exp', async () => {
    const { server, jwksUrl } = await startJwksServer([publicJwk]);
    try {
      const token = signRs256Jwt({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'usr_1',
        tenant_id: 'ten_a',
        role: 'viewer',
        exp: 'not-a-number',
      });
      assert.equal((await verifyOidcBearerToken(token, defaultOidcConfig(jwksUrl))).error, 'invalid_token');
    } finally {
      server.close();
    }
  });

  it('rejects numeric-string exp', async () => {
    const { server, jwksUrl } = await startJwksServer([publicJwk]);
    try {
      const token = signRs256Jwt({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'usr_1',
        tenant_id: 'ten_a',
        role: 'viewer',
        exp: String(Math.floor(Date.now() / 1000) + 3600),
      });
      assert.equal((await verifyOidcBearerToken(token, defaultOidcConfig(jwksUrl))).error, 'invalid_token');
    } finally {
      server.close();
    }
  });

  it('rejects non-numeric nbf', async () => {
    const { server, jwksUrl } = await startJwksServer([publicJwk]);
    try {
      const token = signRs256Jwt({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'usr_1',
        tenant_id: 'ten_a',
        role: 'viewer',
        nbf: 'later',
        exp: Math.floor(Date.now() / 1000) + 3600,
      });
      assert.equal((await verifyOidcBearerToken(token, defaultOidcConfig(jwksUrl))).error, 'invalid_token');
    } finally {
      server.close();
    }
  });

  it('rejects future nbf beyond tolerance', async () => {
    const { server, jwksUrl } = await startJwksServer([publicJwk]);
    try {
      const token = signRs256Jwt({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'usr_1',
        tenant_id: 'ten_a',
        role: 'viewer',
        nbf: Math.floor(Date.now() / 1000) + 3600,
        exp: Math.floor(Date.now() / 1000) + 7200,
      });
      assert.equal((await verifyOidcBearerToken(token, defaultOidcConfig(jwksUrl))).error, 'invalid_token');
    } finally {
      server.close();
    }
  });

  it('rejects non-RSA JWKS key', async () => {
    const ecJwk = { kid: KID, kty: 'EC', crv: 'P-256', x: 'x', y: 'y', alg: 'RS256', use: 'sig' };
    const { server, jwksUrl } = await startJwksServer([ecJwk]);
    try {
      const token = signRs256Jwt({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'usr_1',
        tenant_id: 'ten_a',
        role: 'viewer',
        exp: Math.floor(Date.now() / 1000) + 3600,
      });
      assert.equal((await verifyOidcBearerToken(token, defaultOidcConfig(jwksUrl))).error, 'invalid_token');
    } finally {
      server.close();
    }
  });

  it('rejects JWKS key with wrong use', async () => {
    const { server, jwksUrl } = await startJwksServer([{ ...publicJwk, use: 'enc' }]);
    try {
      const token = signRs256Jwt({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'usr_1',
        tenant_id: 'ten_a',
        role: 'viewer',
        exp: Math.floor(Date.now() / 1000) + 3600,
      });
      assert.equal((await verifyOidcBearerToken(token, defaultOidcConfig(jwksUrl))).error, 'invalid_token');
    } finally {
      server.close();
    }
  });

  it('rejects JWKS key with wrong alg', async () => {
    const { server, jwksUrl } = await startJwksServer([{ ...publicJwk, alg: 'RS384' }]);
    try {
      const token = signRs256Jwt({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'usr_1',
        tenant_id: 'ten_a',
        role: 'viewer',
        exp: Math.floor(Date.now() / 1000) + 3600,
      });
      assert.equal((await verifyOidcBearerToken(token, defaultOidcConfig(jwksUrl))).error, 'invalid_token');
    } finally {
      server.close();
    }
  });

  it('rejects expired tokens', async () => {
    const { server, jwksUrl } = await startJwksServer([publicJwk]);
    try {
      const token = signRs256Jwt({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'usr_1',
        tenant_id: 'ten_a',
        role: 'viewer',
        exp: Math.floor(Date.now() / 1000) - 120,
      });
      assert.equal((await verifyOidcBearerToken(token, defaultOidcConfig(jwksUrl))).error, 'expired');
    } finally {
      server.close();
    }
  });

  it('rejects unknown kid', async () => {
    const { server, jwksUrl } = await startJwksServer([{ ...publicJwk, kid: 'other-kid' }]);
    try {
      const token = signRs256Jwt({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'usr_1',
        tenant_id: 'ten_a',
        role: 'viewer',
        exp: Math.floor(Date.now() / 1000) + 3600,
      });
      assert.equal((await verifyOidcBearerToken(token, defaultOidcConfig(jwksUrl))).error, 'invalid_token');
    } finally {
      server.close();
    }
  });

  it('rejects unknown role', async () => {
    const { server, jwksUrl } = await startJwksServer([publicJwk]);
    try {
      const token = signRs256Jwt({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'usr_1',
        tenant_id: 'ten_a',
        role: 'superuser',
        exp: Math.floor(Date.now() / 1000) + 3600,
      });
      assert.equal((await verifyOidcBearerToken(token, defaultOidcConfig(jwksUrl))).error, 'invalid_role');
    } finally {
      server.close();
    }
  });

  it('returns invalid_token when JWKS endpoint redirects and does not follow', async () => {
    let redirectTargetHits = 0;
    const { server, jwksUrl } = await new Promise((resolve) => {
      const server = http.createServer((req, res) => {
        if (req.url === '/jwks' && req.method === 'GET') {
          res.writeHead(302, { Location: '/jwks-redirected' });
          res.end();
          return;
        }
        if (req.url === '/jwks-redirected' && req.method === 'GET') {
          redirectTargetHits += 1;
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ keys: [publicJwk] }));
          return;
        }
        res.writeHead(404);
        res.end();
      });
      server.listen(0, '127.0.0.1', () => {
        const { port } = server.address();
        resolve({ server, jwksUrl: `http://127.0.0.1:${port}/jwks` });
      });
    });
    try {
      const token = signRs256Jwt({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'usr_1',
        tenant_id: 'ten_a',
        role: 'viewer',
        exp: Math.floor(Date.now() / 1000) + 3600,
      });
      const result = await verifyOidcBearerToken(token, defaultOidcConfig(jwksUrl));
      assert.equal(result.error, 'invalid_token');
      assert.equal(redirectTargetHits, 0);
    } finally {
      server.close();
    }
  });

  it('returns invalid_token when JWKS fetch times out', async () => {
    const { server, jwksUrl } = await startHangingJwksServer();
    try {
      const token = signRs256Jwt({
        iss: ISSUER,
        aud: AUDIENCE,
        sub: 'usr_1',
        tenant_id: 'ten_a',
        role: 'viewer',
        exp: Math.floor(Date.now() / 1000) + 3600,
      });
      const cfg = { ...defaultOidcConfig(jwksUrl), jwksFetchTimeoutMs: 50 };
      const result = await verifyOidcBearerToken(token, cfg);
      assert.equal(result.error, 'invalid_token');
    } finally {
      server.close();
    }
  });
});
