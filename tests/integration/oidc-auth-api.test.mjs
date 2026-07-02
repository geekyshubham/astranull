import assert from 'node:assert/strict';
import http from 'node:http';
import { createSign, generateKeyPairSync } from 'node:crypto';
import { after, before, describe, it } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { request } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';

const ISSUER = 'https://idp.integration.test';
const AUDIENCE = 'astranull-integration';
const KID = 'integration-rsa-1';

const { privateKey, publicKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
});

const publicJwk = publicKey.export({ format: 'jwk' });
publicJwk.kid = KID;
publicJwk.alg = 'RS256';
publicJwk.use = 'sig';

const envSnapshot = { ...process.env };

let jwksServer;
let jwksUrl;
let appServer;
let baseUrl;

function base64UrlJson(obj) {
  return Buffer.from(JSON.stringify(obj), 'utf8').toString('base64url');
}

function mintOidcJwt({ role, tenantId = 'ten_demo', userId = 'usr_oidc', exp }) {
  const header = { alg: 'RS256', typ: 'JWT', kid: KID };
  const payload = {
    iss: ISSUER,
    aud: AUDIENCE,
    sub: userId,
    tenant_id: tenantId,
    role,
    exp: exp ?? Math.floor(Date.now() / 1000) + 3600,
  };
  const headerB64 = base64UrlJson(header);
  const payloadB64 = base64UrlJson(payload);
  const signingInput = `${headerB64}.${payloadB64}`;
  const sig = createSign('RSA-SHA256').update(signingInput, 'utf8').sign(privateKey);
  return `${signingInput}.${sig.toString('base64url')}`;
}

function restoreEnv() {
  for (const key of Object.keys(process.env)) {
    if (!(key in envSnapshot)) delete process.env[key];
  }
  Object.assign(process.env, envSnapshot);
}

before(async () => {
  jwksServer = http.createServer((req, res) => {
    if (req.url === '/jwks' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ keys: [publicJwk] }));
      return;
    }
    res.writeHead(404);
    res.end();
  });
  await new Promise((resolve) => {
    jwksServer.listen(0, '127.0.0.1', resolve);
  });
  const { port: jwksPort } = jwksServer.address();
  jwksUrl = `http://127.0.0.1:${jwksPort}/jwks`;

  freshStore();
  process.env.ASTRANULL_AUTH_MODE = 'oidc-jwt';
  process.env.ASTRANULL_OIDC_ISSUER = ISSUER;
  process.env.ASTRANULL_OIDC_AUDIENCE = AUDIENCE;
  process.env.ASTRANULL_OIDC_JWKS_URL = jwksUrl;
  delete process.env.NODE_ENV;

  appServer = createServer();
  appServer.listen(0);
  const { port } = appServer.address();
  baseUrl = `http://127.0.0.1:${port}`;
});

after(() => {
  appServer?.close();
  jwksServer?.close();
  restoreEnv();
});

describe('oidc-jwt API boundary', () => {
  it('returns tenant current with a valid OIDC bearer token', async () => {
    const token = mintOidcJwt({ role: 'engineer', userId: 'usr_eng' });
    const res = await request(baseUrl, 'GET', '/v1/tenants/current', {
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(res.status, 200);
    assert.equal(res.json.id, 'ten_demo');
  });

  it('ignores spoofed x-role when JWT role is viewer', async () => {
    const token = mintOidcJwt({ role: 'viewer', userId: 'usr_view' });
    const res = await request(baseUrl, 'POST', '/v1/bootstrap-tokens', {
      headers: {
        Authorization: `Bearer ${token}`,
        'x-role': 'admin',
        'x-tenant-id': 'ten_demo',
      },
      body: { name: 'should-fail', max_registrations: 1 },
    });
    assert.equal(res.status, 403);
    assert.equal(res.json.error, 'forbidden');
  });
});