import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';
import { closePgPool, createPgPool, pingPostgres, resolvePgPoolConfig } from '../../src/persistence/postgres/pool.mjs';

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

describe('postgres pool', () => {
  it('resolvePgPoolConfig uses bounded env overrides', () => {
    process.env.ASTRANULL_DATABASE_URL = 'postgresql://localhost/testdb';
    process.env.ASTRANULL_PG_POOL_MAX = '5';
    process.env.ASTRANULL_PG_IDLE_TIMEOUT_MS = '2000';
    process.env.ASTRANULL_PG_CONNECTION_TIMEOUT_MS = '3000';
    const config = resolvePgPoolConfig();
    assert.equal(config.max, 5);
    assert.equal(config.idleTimeoutMillis, 2000);
    assert.equal(config.connectionTimeoutMillis, 3000);
    assert.equal(config.connectionString, 'postgresql://localhost/testdb');
  });

  it('rejects invalid pool max without exposing database URL', () => {
    process.env.ASTRANULL_DATABASE_URL = 'postgresql://secret:secret@host/db';
    process.env.ASTRANULL_PG_POOL_MAX = '9999';
    assert.throws(() => resolvePgPoolConfig(), (err) => {
      assert.match(err.message, /ASTRANULL_PG_POOL_MAX must be an integer/);
      assert.doesNotMatch(err.message, /secret@host/);
      return true;
    });
  });

  it('requires database URL', () => {
    delete process.env.ASTRANULL_DATABASE_URL;
    assert.throws(() => resolvePgPoolConfig(), /ASTRANULL_DATABASE_URL must be set/);
  });

  it('pingPostgres uses SELECT 1 and releases client', async () => {
    const released = [];
    const pool = {
      async connect() {
        return {
          async query(text) {
            assert.equal(text, 'SELECT 1 AS ok');
            return { rows: [{ ok: 1 }] };
          },
          release() {
            released.push(true);
          },
        };
      },
    };
    const result = await pingPostgres(pool);
    assert.deepEqual(result, { ok: true });
    assert.equal(released.length, 1);
  });

  it('closePgPool ends pool when present', async () => {
    let ended = false;
    await closePgPool({ end: async () => { ended = true; } });
    assert.equal(ended, true);
    await closePgPool(null);
  });

  it('createPgPool accepts explicit config object', () => {
    const pool = createPgPool({ connectionString: 'postgresql://localhost/x' });
    assert.ok(pool);
    assert.equal(typeof pool.end, 'function');
    pool.end().catch(() => {});
  });
});