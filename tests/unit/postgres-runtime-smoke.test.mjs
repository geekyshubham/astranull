import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  POSTGRES_RUNTIME_SMOKE_SERVICE_FAMILIES,
  redactRuntimeSmokeErrorMessage,
  resolvePostgresRuntimeSmokeDecision,
  runPostgresRuntimeSmoke,
  verifyRuntimeSmokeServiceFamilies,
} from '../../scripts/postgres-runtime-smoke.mjs';

function buildFakeRuntime({ healthResult, healthError } = {}) {
  const services = {};
  for (const { keys } of POSTGRES_RUNTIME_SMOKE_SERVICE_FAMILIES) {
    for (const key of keys) {
      services[key] = key === 'audit' ? { appendAuditEvent: () => {}, listAuditEntries: () => {} } : {};
    }
  }

  const state = { closeCalls: 0 };
  const runtime = {
    services,
    health: async () => {
      if (healthError) {
        throw healthError;
      }
      return healthResult ?? { ok: true, persistence: 'postgres', latestMigration: '0007' };
    },
    close: async () => {
      state.closeCalls += 1;
    },
  };
  return { runtime, state };
}

describe('postgres runtime smoke gating', () => {
  it('skips when runtime smoke flag is not set', () => {
    const decision = resolvePostgresRuntimeSmokeDecision({});
    assert.equal(decision.action, 'skip');
    assert.match(decision.message ?? '', /skipped/i);
  });

  it('fails when required but runtime smoke flag is missing', () => {
    const decision = resolvePostgresRuntimeSmokeDecision({
      ASTRANULL_REQUIRE_POSTGRES_RUNTIME_SMOKE: '1',
    });
    assert.equal(decision.action, 'fail');
    assert.match(decision.message ?? '', /required/i);
  });

  it('fails when enabled without database URL', () => {
    const decision = resolvePostgresRuntimeSmokeDecision({
      ASTRANULL_POSTGRES_RUNTIME_SMOKE: '1',
    });
    assert.equal(decision.action, 'fail');
    assert.match(decision.message ?? '', /ASTRANULL_DATABASE_URL/i);
  });

  it('runs when enabled with database URL', () => {
    const decision = resolvePostgresRuntimeSmokeDecision({
      ASTRANULL_POSTGRES_RUNTIME_SMOKE: '1',
      ASTRANULL_DATABASE_URL: 'postgresql://localhost/astranull',
    });
    assert.equal(decision.action, 'run');
  });
});

describe('postgres runtime smoke execution', () => {
  it('returns skip outcome when not enabled', async () => {
    const result = await runPostgresRuntimeSmoke({});
    assert.equal(result.outcome, 'skip');
    assert.match(result.message ?? '', /skipped/i);
  });

  it('succeeds with injected fake runtime and verifies service families', async () => {
    const { runtime, state } = buildFakeRuntime();
    const result = await runPostgresRuntimeSmoke(
      {
        ASTRANULL_POSTGRES_RUNTIME_SMOKE: '1',
        ASTRANULL_DATABASE_URL: 'postgresql://localhost/astranull',
      },
      {
        createPostgresRuntime: async () => runtime,
      },
    );
    assert.equal(result.outcome, 'ok');
    assert.deepEqual(
      result.families,
      POSTGRES_RUNTIME_SMOKE_SERVICE_FAMILIES.map((entry) => entry.family),
    );
    assert.equal(state.closeCalls, 1);
  });

  it('closes runtime when health check fails', async () => {
    const { runtime, state } = buildFakeRuntime({
      healthError: new Error('health ping failed'),
    });
    await assert.rejects(
      () =>
        runPostgresRuntimeSmoke(
          {
            ASTRANULL_POSTGRES_RUNTIME_SMOKE: '1',
            ASTRANULL_DATABASE_URL: 'postgresql://localhost/astranull',
          },
          {
            createPostgresRuntime: async () => runtime,
          },
        ),
      /health ping failed/,
    );
    assert.equal(state.closeCalls, 1);
  });

  it('rejects missing service family wiring', () => {
    const services = {};
    for (const { keys } of POSTGRES_RUNTIME_SMOKE_SERVICE_FAMILIES) {
      for (const key of keys) {
        services[key] = {};
      }
    }
    delete services.testRuns;
    assert.throws(
      () => verifyRuntimeSmokeServiceFamilies(services),
      /runtime\.services\.testRuns/,
    );
  });

  it('rejects missing wafPosture service wiring', () => {
    const services = {};
    for (const { keys } of POSTGRES_RUNTIME_SMOKE_SERVICE_FAMILIES) {
      for (const key of keys) {
        services[key] = {};
      }
    }
    delete services.wafPosture;
    assert.throws(
      () => verifyRuntimeSmokeServiceFamilies(services),
      /runtime\.services\.wafPosture/,
    );
  });
});

describe('postgres runtime smoke redaction', () => {
  it('redacts database URLs from error messages', () => {
    const env = {
      ASTRANULL_DATABASE_URL: 'postgresql://user:secret@db.example:5432/astranull',
    };
    const redacted = redactRuntimeSmokeErrorMessage(
      'connect failed: postgresql://user:secret@db.example:5432/astranull',
      env,
    );
    assert.doesNotMatch(redacted, /postgresql:\/\//);
    assert.match(redacted, /\[redacted-database-url\]/);
  });
});