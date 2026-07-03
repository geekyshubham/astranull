import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { isConnectorsEnabledForTenant, loadRuntimeConfig } from '../../src/config.mjs';
import { createServer } from '../../src/server.mjs';
import { demoHeaders, request } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';

const envSnapshot = { ...process.env };

function restoreEnv() {
  for (const key of Object.keys(process.env)) {
    if (!(key in envSnapshot)) delete process.env[key];
  }
  Object.assign(process.env, envSnapshot);
}

function wafEnabledEnv(extra = {}) {
  return {
    ...process.env,
    ASTRANULL_NO_PERSIST: '1',
    ASTRANULL_WAF_POSTURE_ENABLED: '1',
    ...extra,
  };
}

function startServer(env) {
  const runtimeConfig = loadRuntimeConfig(env);
  const server = createServer({ runtimeConfig, env });
  server.listen(0);
  const { port } = server.address();
  return { server, baseUrl: `http://127.0.0.1:${port}`, runtimeConfig };
}

describe('connector feature flag runtime config', () => {
  after(() => {
    restoreEnv();
  });

  it('defaults connectors off and supports per-tenant overrides', () => {
    const env = {
      NODE_ENV: 'test',
      ASTRANULL_NO_PERSIST: '1',
      ASTRANULL_CONNECTORS_ENABLED: '0',
      ASTRANULL_CONNECTORS_ENABLED_TENANTS: JSON.stringify({ ten_demo: true, ten_other: false }),
    };
    const cfg = loadRuntimeConfig(env);
    assert.equal(isConnectorsEnabledForTenant(cfg, 'ten_demo'), true);
    assert.equal(isConnectorsEnabledForTenant(cfg, 'ten_other'), false);
    assert.equal(isConnectorsEnabledForTenant(cfg, 'ten_missing'), false);

    env.ASTRANULL_CONNECTORS_ENABLED = '1';
    const globalOn = loadRuntimeConfig(env);
    assert.equal(isConnectorsEnabledForTenant(globalOn, 'ten_missing'), true);
    assert.equal(isConnectorsEnabledForTenant(globalOn, 'ten_other'), false);
  });
});

describe('connector API feature flag', () => {
  let server;
  let baseUrl;

  before(() => {
    freshStore();
    ({ server, baseUrl } = startServer(wafEnabledEnv({
      ASTRANULL_CONNECTORS_ENABLED: '0',
      ASTRANULL_CONNECTORS_ENABLED_TENANTS: JSON.stringify({ ten_demo: true }),
    })));
  });

  after(() => {
    server?.close();
    restoreEnv();
  });

  it('returns connector_feature_disabled when tenant override is off', async () => {
    const res = await request(baseUrl, 'GET', '/v1/connectors', {
      headers: demoHeaders('admin', 'ten_other'),
    });
    assert.equal(res.status, 404);
    assert.equal(res.json.error, 'connector_feature_disabled');
  });

  it('allows connector routes when tenant override is on', async () => {
    const res = await request(baseUrl, 'GET', '/v1/connectors', {
      headers: demoHeaders('admin', 'ten_demo'),
    });
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.json.items));
  });
});