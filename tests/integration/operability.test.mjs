import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { demoHeaders, request } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';

let baseUrl;
let server;

before(() => {
  freshStore();
  server = createServer({
    env: {
      ...process.env,
      ASTRANULL_MAX_JSON_BODY_BYTES: '128',
      ASTRANULL_NO_PERSIST: '1',
    },
  });
  server.listen(0);
  const { port } = server.address();
  baseUrl = `http://127.0.0.1:${port}`;
});

after(() => server.close());

describe('API rate limiting', () => {
  let rateBaseUrl;
  let rateServer;

  before(() => {
    freshStore();
    rateServer = createServer({
      env: {
        ...process.env,
        ASTRANULL_NO_PERSIST: '1',
        ASTRANULL_RATE_LIMIT_MAX_REQUESTS: '2',
        ASTRANULL_RATE_LIMIT_WINDOW_MS: '60000',
      },
    });
    rateServer.listen(0);
    const { port } = rateServer.address();
    rateBaseUrl = `http://127.0.0.1:${port}`;
  });

  after(() => rateServer.close());

  it('returns 429 on third API request from the same client with Retry-After', async () => {
    const path = '/v1/environments';
    const headers = demoHeaders('viewer');
    assert.equal((await request(rateBaseUrl, 'GET', path, { headers })).status, 200);
    assert.equal((await request(rateBaseUrl, 'GET', path, { headers })).status, 200);
    const res = await fetch(`${rateBaseUrl}${path}`, { method: 'GET', headers });
    const json = await res.json();
    assert.equal(res.status, 429);
    assert.equal(json.error, 'rate_limited');
    assert.ok(res.headers.get('retry-after'));
  });

  it('GET /health stays 200 after API limit is exceeded', async () => {
    const path = '/v1/environments';
    const headers = demoHeaders('viewer');
    await request(rateBaseUrl, 'GET', path, { headers });
    await request(rateBaseUrl, 'GET', path, { headers });
    await request(rateBaseUrl, 'GET', path, { headers });
    const health = await request(rateBaseUrl, 'GET', '/health');
    assert.equal(health.status, 200);
    assert.equal(health.json.status, 'ok');
  });
});

describe('control-plane operability', () => {
  it('GET /health returns liveness with service astranull', async () => {
    const res = await request(baseUrl, 'GET', '/health');
    assert.equal(res.status, 200);
    assert.equal(res.json.status, 'ok');
    assert.equal(res.json.service, 'astranull');
  });

  it('GET /ready returns readiness metadata', async () => {
    const res = await request(baseUrl, 'GET', '/ready');
    assert.equal(res.status, 200);
    assert.equal(res.json.status, 'ready');
    assert.equal(res.json.service, 'astranull');
    assert.equal(res.json.auth_mode, 'dev-headers');
    assert.equal(res.json.persistence, 'memory');
    assert.ok(res.json.timestamp);
    assert.equal(res.json.database_url, undefined);
    assert.equal(res.json.databaseUrl, undefined);
    assert.equal(res.json.session_secret, undefined);
  });

  it('returns 400 invalid_json for malformed JSON body', async () => {
    const res = await request(baseUrl, 'POST', '/v1/environments', {
      headers: demoHeaders('admin'),
      rawBody: '{not-json',
    });
    assert.equal(res.status, 400);
    assert.equal(res.json.error, 'invalid_json');
  });

  it('returns 413 payload_too_large for oversized JSON body', async () => {
    const res = await request(baseUrl, 'POST', '/v1/environments', {
      headers: demoHeaders('admin'),
      rawBody: `{"name":"${'x'.repeat(200)}"}`,
    });
    assert.equal(res.status, 413);
    assert.equal(res.json.error, 'payload_too_large');
  });
});