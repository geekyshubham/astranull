import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  buildLocalPostgresDatabaseUrl,
  buildLocalPostgresEnv,
  DEFAULT_LOCAL_PG_PORT,
  parseLocalPostgresStackArgs,
} from '../../scripts/local-postgres-stack.mjs';

describe('local postgres stack helpers', () => {
  it('builds the default local database URL for the non-superuser app role', () => {
    const url = buildLocalPostgresDatabaseUrl();
    assert.match(url, new RegExp(`127\\.0\\.0\\.1:${DEFAULT_LOCAL_PG_PORT}/astranull$`));
    assert.match(url, /^postgresql:\/\/astranull_app:/);
  });

  it('builds verification env with acceptance and runtime smoke flags', () => {
    const env = buildLocalPostgresEnv();
    assert.equal(env.ASTRANULL_PERSISTENCE_MODE, 'postgres');
    assert.equal(env.ASTRANULL_POSTGRES_ACCEPTANCE, '1');
    assert.equal(env.ASTRANULL_POSTGRES_RUNTIME_SMOKE, '1');
    assert.match(String(env.ASTRANULL_DATABASE_URL), /127\.0\.0\.1/);
  });

  it('parses stack commands and port override', () => {
    assert.deepEqual(parseLocalPostgresStackArgs(['verify', '--port', '55432']), {
      command: 'verify',
      port: 55432,
      timeoutMs: 60_000,
      help: false,
    });
  });

  it('rejects unknown commands', () => {
    assert.throws(
      () => parseLocalPostgresStackArgs(['bootstrap']),
      /Unknown command: bootstrap/,
    );
  });
});