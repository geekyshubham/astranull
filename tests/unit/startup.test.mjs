import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';
import { EventEmitter } from 'node:events';
import { loadRuntimeConfig } from '../../src/config.mjs';
import { startControlPlane, redactStartupErrorMessage } from '../../src/startup.mjs';

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

function fakeHttpServer() {
  const server = new EventEmitter();
  server.close = (cb) => {
    setImmediate(() => cb?.());
  };
  return server;
}

describe('startControlPlane startup seam', () => {
  it('does not create Postgres runtime in dev-json mode', async () => {
    process.env.NODE_ENV = 'test';
    process.env.ASTRANULL_NO_PERSIST = '1';
    delete process.env.ASTRANULL_PERSISTENCE_MODE;

    let postgresCalled = false;
    const server = fakeHttpServer();
    const app = await startControlPlane({
      env: process.env,
      createPostgresRuntime: async () => {
        postgresCalled = true;
        throw new Error('should not run');
      },
      createServer: () => server,
    });

    assert.equal(postgresCalled, false);
    assert.equal(app.persistenceRuntime, null);
    assert.equal(app.runtimeConfig.persistenceMode, 'memory');
    await app.close();
  });

  it('creates Postgres runtime, injects services, and close shuts down runtime', async () => {
    const injected = { tenants: { getCurrentTenant: async () => ({ id: 'ten_x' }) } };
    let runtimeCloseCalls = 0;
    const fakeRuntime = {
      services: injected,
      health: async () => ({ ok: true }),
      close: async () => {
        runtimeCloseCalls += 1;
      },
    };
    const server = fakeHttpServer();
    let serverOptions;
    const app = await startControlPlane({
      env: {
        ...process.env,
        NODE_ENV: 'test',
        ASTRANULL_PERSISTENCE_MODE: 'postgres',
        ASTRANULL_DATABASE_URL: 'postgres://user:secret@db.example/astranull',
      },
      runtimeConfig: {
        ...loadRuntimeConfig({
          ...process.env,
          NODE_ENV: 'test',
          ASTRANULL_NO_PERSIST: '1',
          ASTRANULL_PERSISTENCE_MODE: 'dev-json',
        }),
        persistenceMode: 'postgres',
        databaseUrlConfigured: true,
      },
      createPostgresRuntime: async () => fakeRuntime,
      createServer: (opts) => {
        serverOptions = opts;
        return server;
      },
    });

    assert.equal(app.persistenceRuntime, fakeRuntime);
    assert.equal(serverOptions.services.tenants, injected.tenants);
    assert.equal(typeof serverOptions.runtimeHealth, 'function');
    await app.close();
    assert.equal(runtimeCloseCalls, 1);
  });

  it('redacts database URLs in startup error messages', () => {
    const env = {
      ASTRANULL_DATABASE_URL: 'postgres://user:secret@db.example/astranull',
    };
    const text = redactStartupErrorMessage(
      new Error(`connect failed to ${env.ASTRANULL_DATABASE_URL}`),
      env,
    );
    assert.ok(!text.includes('secret@db'));
    assert.ok(text.includes('[redacted-database-url]'));
  });

  it('closes Postgres runtime when createServer fails after runtime init', async () => {
    let closeCalls = 0;
    await assert.rejects(
      () =>
        startControlPlane({
          env: process.env,
          runtimeConfig: {
            persistenceMode: 'postgres',
            authMode: 'dev-headers',
            shutdownGraceMs: 1000,
          },
          createPostgresRuntime: async () => ({
            services: { tenants: {} },
            health: async () => ({}),
            close: async () => {
              closeCalls += 1;
            },
          }),
          createServer: () => {
            throw new Error('server build failed');
          },
        }),
      /server build failed/,
    );
    assert.equal(closeCalls, 1);
  });
});
