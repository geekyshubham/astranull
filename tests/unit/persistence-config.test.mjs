import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';
import {
  isConnectorsEnabledForTenant,
  loadRuntimeConfig,
  resolveAgentIdentityMode,
  resolveHighScaleAdapterMode,
  resolvePersistenceMode,
  resolveProbeMode,
} from '../../src/config.mjs';

const TEST_ENC_KEY = 'a'.repeat(64);

function setProductionOidcEnv() {
  process.env.ASTRANULL_AUTH_MODE = 'oidc-jwt';
  process.env.ASTRANULL_OIDC_ISSUER = 'https://idp.example';
  process.env.ASTRANULL_OIDC_AUDIENCE = 'astranull-api';
  process.env.ASTRANULL_OIDC_JWKS_URL = 'https://idp.example/jwks';
}
const envSnapshot = { ...process.env };

function restoreEnv() {
  for (const key of Object.keys(process.env)) {
    if (!(key in envSnapshot)) delete process.env[key];
  }
  Object.assign(process.env, envSnapshot);
}

afterEach(() => {
  restoreEnv();
});

describe('production persistence fail-closed', () => {
  it('defaults to dev-json outside production', () => {
    process.env.NODE_ENV = 'test';
    delete process.env.ASTRANULL_PERSISTENCE_MODE;
    delete process.env.ASTRANULL_NO_PERSIST;
    assert.equal(resolvePersistenceMode(), 'dev-json');
  });

  it('defaults to postgres in production', () => {
    process.env.NODE_ENV = 'production';
    delete process.env.ASTRANULL_PERSISTENCE_MODE;
    delete process.env.ASTRANULL_NO_PERSIST;
    assert.equal(resolvePersistenceMode(), 'postgres');
  });

  it('refuses dev-json and memory in production', () => {
    process.env.NODE_ENV = 'production';
    setProductionOidcEnv();
    process.env.ASTRANULL_SECRET_ENCRYPTION_KEY = TEST_ENC_KEY;
    process.env.ASTRANULL_PERSISTENCE_MODE = 'dev-json';
    assert.throws(() => loadRuntimeConfig(), /not permitted when NODE_ENV=production/);

    process.env.ASTRANULL_PERSISTENCE_MODE = 'memory';
    assert.throws(() => loadRuntimeConfig(), /not permitted when NODE_ENV=production/);
  });

  it('requires ASTRANULL_DATABASE_URL for postgres in production', () => {
    process.env.NODE_ENV = 'production';
    setProductionOidcEnv();
    process.env.ASTRANULL_SECRET_ENCRYPTION_KEY = TEST_ENC_KEY;
    process.env.ASTRANULL_PERSISTENCE_MODE = 'postgres';
    delete process.env.ASTRANULL_DATABASE_URL;
    assert.throws(() => loadRuntimeConfig(), /ASTRANULL_DATABASE_URL/);
  });

  it('allows postgres persistence when production requirements are satisfied', () => {
    process.env.NODE_ENV = 'production';
    setProductionOidcEnv();
    process.env.ASTRANULL_SECRET_ENCRYPTION_KEY = TEST_ENC_KEY;
    process.env.ASTRANULL_PROBE_MODE = 'signed-worker';
    process.env.ASTRANULL_PROBE_WORKER_SECRET = 'p'.repeat(32);
    process.env.ASTRANULL_PERSISTENCE_MODE = 'postgres';
    process.env.ASTRANULL_DATABASE_URL = 'postgres://user:pass@localhost/astranull';
    const cfg = loadRuntimeConfig();
    assert.equal(cfg.persistenceMode, 'postgres');
    assert.equal(cfg.databaseUrlConfigured, true);
    assert.equal(cfg.highScaleAdapterMode, 'governed-adapter');
    assert.equal(cfg.agentIdentityMode, 'gateway-mtls');

    process.env.NODE_ENV = 'test';
    process.env.ASTRANULL_NO_PERSIST = '1';
    delete process.env.ASTRANULL_PROBE_MODE;
    delete process.env.ASTRANULL_PROBE_WORKER_SECRET;
    process.env.ASTRANULL_PERSISTENCE_MODE = 'postgres';
    const testCfg = loadRuntimeConfig();
    assert.equal(testCfg.persistenceMode, 'postgres');
  });

  it('allows ASTRANULL_NO_PERSIST=1 only outside production', () => {
    process.env.NODE_ENV = 'test';
    process.env.ASTRANULL_NO_PERSIST = '1';
    assert.equal(resolvePersistenceMode(), 'memory');

    process.env.NODE_ENV = 'production';
    setProductionOidcEnv();
    assert.throws(() => resolvePersistenceMode(), /ASTRANULL_NO_PERSIST/);
  });

  it('defaults probes and high-scale adapters to production-safe modes', () => {
    process.env.NODE_ENV = 'production';
    delete process.env.ASTRANULL_PROBE_MODE;
    delete process.env.ASTRANULL_HIGH_SCALE_ADAPTER_MODE;
    assert.equal(resolveProbeMode(), 'signed-worker');
    assert.equal(resolveHighScaleAdapterMode(), 'governed-adapter');
    assert.equal(resolveAgentIdentityMode(), 'gateway-mtls');

    process.env.NODE_ENV = 'test';
    assert.equal(resolveProbeMode(), 'simulation');
    assert.equal(resolveHighScaleAdapterMode(), 'dry-run');
    assert.equal(resolveAgentIdentityMode(), 'bearer');
  });

  it('requires signed probe worker credentials for production default probes', () => {
    process.env.NODE_ENV = 'production';
    setProductionOidcEnv();
    process.env.ASTRANULL_SECRET_ENCRYPTION_KEY = TEST_ENC_KEY;
    process.env.ASTRANULL_PERSISTENCE_MODE = 'postgres';
    process.env.ASTRANULL_DATABASE_URL = 'postgres://user:pass@localhost/astranull';
    delete process.env.ASTRANULL_PROBE_MODE;
    delete process.env.ASTRANULL_PROBE_WORKER_SECRET;
    assert.throws(() => loadRuntimeConfig(), /ASTRANULL_PROBE_WORKER_SECRET/);
  });

  it('rejects explicit probe simulation in production', () => {
    process.env.NODE_ENV = 'production';
    process.env.ASTRANULL_PROBE_MODE = 'simulation';
    assert.throws(
      () => resolveProbeMode(),
      /ASTRANULL_PROBE_MODE=simulation is not permitted when NODE_ENV=production/,
    );

    setProductionOidcEnv();
    process.env.ASTRANULL_SECRET_ENCRYPTION_KEY = TEST_ENC_KEY;
    process.env.ASTRANULL_PERSISTENCE_MODE = 'postgres';
    process.env.ASTRANULL_DATABASE_URL = 'postgres://user:pass@localhost/astranull';
    assert.throws(
      () => loadRuntimeConfig(),
      /ASTRANULL_PROBE_MODE=simulation is not permitted when NODE_ENV=production/,
    );
  });

  it('allows probe simulation outside production', () => {
    process.env.NODE_ENV = 'test';
    process.env.ASTRANULL_PROBE_MODE = 'simulation';
    assert.equal(resolveProbeMode(), 'simulation');
    delete process.env.ASTRANULL_PROBE_MODE;
    assert.equal(resolveProbeMode(), 'simulation');
  });

  it('rejects unsafe or unknown high-scale adapter modes', () => {
    process.env.NODE_ENV = 'test';
    process.env.ASTRANULL_HIGH_SCALE_ADAPTER_MODE = 'dry-run';
    assert.equal(resolveHighScaleAdapterMode(), 'dry-run');

    process.env.ASTRANULL_HIGH_SCALE_ADAPTER_MODE = 'disabled';
    assert.equal(resolveHighScaleAdapterMode(), 'disabled');

    process.env.ASTRANULL_HIGH_SCALE_ADAPTER_MODE = 'bogus';
    assert.throws(() => resolveHighScaleAdapterMode(), /Invalid ASTRANULL_HIGH_SCALE_ADAPTER_MODE/);

    process.env.NODE_ENV = 'production';
    process.env.ASTRANULL_HIGH_SCALE_ADAPTER_MODE = 'dry-run';
    assert.throws(() => resolveHighScaleAdapterMode(), /dry-run is not permitted/);
  });

  it('parses per-tenant connector feature flags from runtime config', () => {
    process.env.NODE_ENV = 'test';
    process.env.ASTRANULL_NO_PERSIST = '1';
    process.env.ASTRANULL_CONNECTORS_ENABLED = '0';
    process.env.ASTRANULL_CONNECTORS_ENABLED_TENANTS = JSON.stringify({
      ten_demo: true,
      ten_other: false,
    });
    const cfg = loadRuntimeConfig();
    assert.equal(cfg.featureFlags.connectorsEnabledDefault, false);
    assert.deepEqual(cfg.featureFlags.connectorsEnabledTenants, {
      ten_demo: true,
      ten_other: false,
    });
    assert.equal(isConnectorsEnabledForTenant(cfg, 'ten_demo'), true);
    assert.equal(isConnectorsEnabledForTenant(cfg, 'ten_other'), false);
    assert.equal(isConnectorsEnabledForTenant(cfg, 'ten_missing'), false);

    process.env.ASTRANULL_CONNECTORS_ENABLED_TENANTS = '{bad json';
    assert.throws(() => loadRuntimeConfig(), /ASTRANULL_CONNECTORS_ENABLED_TENANTS/);
  });

  it('rejects bearer-only agent identity in production', () => {
    process.env.NODE_ENV = 'test';
    process.env.ASTRANULL_AGENT_IDENTITY_MODE = 'bearer';
    assert.equal(resolveAgentIdentityMode(), 'bearer');

    process.env.ASTRANULL_AGENT_IDENTITY_MODE = 'bogus';
    assert.throws(() => resolveAgentIdentityMode(), /Invalid ASTRANULL_AGENT_IDENTITY_MODE/);

    process.env.NODE_ENV = 'production';
    process.env.ASTRANULL_AGENT_IDENTITY_MODE = 'bearer';
    assert.throws(() => resolveAgentIdentityMode(), /bearer is not permitted/);
  });
});
