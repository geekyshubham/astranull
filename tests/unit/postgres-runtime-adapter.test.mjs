import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';
import {
  POSTGRES_RUNTIME_REPOSITORY_KEYS,
  createPostgresRuntime,
  getDefaultPostgresMigrationsDir,
} from '../../src/persistence/postgres/runtime.mjs';
import {
  AGENT_CONTROL_REPOSITORY_METHODS,
  VALIDATION_AGENT_CONTROL_REPOSITORY_METHODS,
  AUTH_TOKEN_REPOSITORY_METHODS,
  CORE_CATALOG_TARGET_GROUP_SERVICE_METHODS,
  CORE_CATALOG_TENANT_SERVICE_METHODS,
  POSTGRES_AGENT_AUTH_SERVICE_METHODS,
  POSTGRES_AGENT_SERVICE_METHODS,
  POSTGRES_AUTH_TOKEN_SERVICE_METHODS,
  POSTGRES_SERVICE_ACCOUNT_SERVICE_METHODS,
  POSTGRES_VALIDATION_EVIDENCE_SERVICE_METHODS,
  POSTGRES_VALIDATION_FINDINGS_SERVICE_METHODS,
  POSTGRES_SECRET_VAULT_SERVICE_METHODS,
  POSTGRES_VALIDATION_TEST_RUNS_SERVICE_METHODS,
  POSTGRES_REPORT_SERVICE_METHODS,
  POSTGRES_NOTIFICATION_SERVICE_METHODS,
  NOTIFICATION_REPOSITORY_METHODS,
  AGENT_UPDATE_REPOSITORY_METHODS,
  POSTGRES_AGENT_UPDATE_SERVICE_METHODS,
  POSTGRES_PROBE_JOB_SERVICE_METHODS,
  PROBE_JOB_REPOSITORY_METHODS,
  POSTGRES_STATE_SERVICE_METHODS,
  POSTGRES_HIGH_SCALE_SERVICE_METHODS,
  HIGH_SCALE_REPOSITORY_METHODS,
  PRODUCTION_RELEASE_EVIDENCE_REPOSITORY_METHODS,
  POSTGRES_PRODUCTION_RELEASE_EVIDENCE_SERVICE_METHODS,
  POSTGRES_RETENTION_SERVICE_METHODS,
  WAF_POSTURE_REPOSITORY_METHODS,
  POSTGRES_WAF_POSTURE_SERVICE_METHODS,
  REPORT_AUDIT_REPOSITORY_METHODS,
  REPORT_REPOSITORY_METHODS,
  SECRET_VAULT_REPOSITORY_METHODS,
  SERVICE_ACCOUNT_REPOSITORY_METHODS,
  VALIDATION_EVIDENCE_REPOSITORY_METHODS,
} from '../../src/persistence/postgres/serviceAdapters.mjs';
import { POSTGRES_EVENTS_SERVICE_METHODS } from '../../src/persistence/postgres/validationServiceAdapters.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '../..');
const RUNTIME_SOURCE = readFileSync(
  path.join(ROOT, 'src/persistence/postgres/runtime.mjs'),
  'utf8',
);

function createFakePool() {
  return { id: 'pool-1', endCalls: 0, async end() { this.endCalls += 1; } };
}

function createHarness(overrides = {}) {
  const pool = createFakePool();
  const calls = [];
  const files = [{ version: '0001_test' }];
  const latest = '0001_test';

  const coreCatalogCalls = [];
  const repositoryFactories = {};
  for (const key of POSTGRES_RUNTIME_REPOSITORY_KEYS) {
    repositoryFactories[key] = (receivedPool) => {
      calls.push({ type: 'repo', key, pool: receivedPool });
      if (key === 'coreCatalog') {
        const repo = {};
        for (const method of [
          ...CORE_CATALOG_TENANT_SERVICE_METHODS,
          ...CORE_CATALOG_TARGET_GROUP_SERVICE_METHODS,
        ]) {
          repo[method] = async (...args) => {
            coreCatalogCalls.push({ method, args });
            return { method };
          };
        }
        return repo;
      }
      if (key === 'authTokens') {
        const repo = {};
        for (const method of [
          ...AUTH_TOKEN_REPOSITORY_METHODS,
          ...SERVICE_ACCOUNT_REPOSITORY_METHODS,
        ]) {
          repo[method] = async () => null;
        }
        return repo;
      }
      if (key === 'audit') {
        const repo = {};
        for (const method of [...REPORT_AUDIT_REPOSITORY_METHODS, 'listAuditEntries']) {
          repo[method] = async () => null;
        }
        return repo;
      }
      if (key === 'reports') {
        const repo = {};
        for (const method of REPORT_REPOSITORY_METHODS) {
          repo[method] = async () => null;
        }
        return repo;
      }
      if (key === 'agentControl') {
        const repo = {};
        for (const method of [
          ...new Set([
            ...AGENT_CONTROL_REPOSITORY_METHODS,
            ...VALIDATION_AGENT_CONTROL_REPOSITORY_METHODS,
          ]),
        ]) {
          repo[method] = async () => null;
        }
        return repo;
      }
      if (key === 'validationEvidence') {
        const repo = {};
        for (const method of VALIDATION_EVIDENCE_REPOSITORY_METHODS) {
          repo[method] = async () => null;
        }
        repo.appendProbeResultEventIdempotent = async () => null;
        return repo;
      }
      if (key === 'secretVault') {
        const repo = {};
        for (const method of SECRET_VAULT_REPOSITORY_METHODS) {
          repo[method] = async () => null;
        }
        return repo;
      }
      if (key === 'notifications') {
        const repo = {};
        for (const method of NOTIFICATION_REPOSITORY_METHODS) {
          repo[method] = async () => null;
        }
        return repo;
      }
      if (key === 'agentUpdates') {
        const repo = {};
        for (const method of AGENT_UPDATE_REPOSITORY_METHODS) {
          repo[method] = async () => null;
        }
        return repo;
      }
      if (key === 'probeJobs') {
        const repo = {};
        for (const method of PROBE_JOB_REPOSITORY_METHODS) {
          repo[method] = async () => null;
        }
        return repo;
      }
      if (key === 'killSwitch') {
        return {
          isKillSwitchActiveForTenant: async () => false,
          getKillSwitchRecord: async () => ({ active: false }),
          upsertKillSwitch: async () => ({ active: false }),
        };
      }
      if (key === 'highScale') {
        const repo = {};
        for (const method of HIGH_SCALE_REPOSITORY_METHODS) {
          repo[method] = async () => null;
        }
        return repo;
      }
      if (key === 'productionReleaseEvidence') {
        const repo = {};
        for (const method of PRODUCTION_RELEASE_EVIDENCE_REPOSITORY_METHODS) {
          repo[method] = async () => null;
        }
        return repo;
      }
      if (key === 'retention') {
        return {
          runMetadataRetention: async () => null,
        };
      }
      if (key === 'wafPosture') {
        const repo = {};
        for (const method of WAF_POSTURE_REPOSITORY_METHODS) {
          repo[method] = async () => null;
        }
        return repo;
      }
      return { key };
    };
  }

  const deps = {
    createPool: () => {
      calls.push({ type: 'createPool' });
      return pool;
    },
    closePool: async (p) => {
      calls.push({ type: 'closePool', pool: p });
      await p.end();
    },
    ping: async (p) => {
      calls.push({ type: 'ping', pool: p });
    },
    listMigrationFiles: (dir) => {
      calls.push({ type: 'listMigrationFiles', dir });
      return files;
    },
    getLatestMigrationVersion: (listed) => {
      calls.push({ type: 'getLatestMigrationVersion', listed });
      return latest;
    },
    assertLatestMigrationApplied: async (p, version) => {
      calls.push({ type: 'assertLatestMigrationApplied', pool: p, version });
    },
    runMigrations: async (p, opts) => {
      calls.push({ type: 'runMigrations', pool: p, opts });
      return { results: [] };
    },
    repositoryFactories,
    ...overrides,
  };

  return { pool, calls, files, latest, deps, coreCatalogCalls };
}

describe('postgres runtime adapter', () => {
  it('exposes stable repository keys and default migrations dir', () => {
    assert.deepEqual(POSTGRES_RUNTIME_REPOSITORY_KEYS, [
      'coreCatalog',
      'audit',
      'authTokens',
      'agentControl',
      'validationEvidence',
      'reports',
      'secretVault',
      'notifications',
      'agentUpdates',
      'probeJobs',
      'killSwitch',
      'highScale',
      'productionReleaseEvidence',
      'retention',
      'wafPosture',
    ]);
    assert.equal(getDefaultPostgresMigrationsDir(), path.join(ROOT, 'db', 'migrations'));
  });

  it('creates one pool, pings before latest assertion, and does not migrate by default', async () => {
    const { pool, calls, deps } = createHarness();
    const runtime = await createPostgresRuntime({}, deps);

    assert.equal(calls.filter((c) => c.type === 'createPool').length, 1);
    assert.deepEqual(
      calls
        .filter((c) => ['ping', 'assertLatestMigrationApplied', 'runMigrations'].includes(c.type))
        .map((c) => c.type),
      ['ping', 'assertLatestMigrationApplied'],
    );
    assert.equal(calls.some((c) => c.type === 'runMigrations'), false);

    for (const call of calls.filter((c) => c.type === 'repo')) {
      assert.equal(call.pool, pool);
    }

    assert.equal(runtime.latestMigration, '0001_test');
    assert.equal(Object.keys(runtime.repositories).length, POSTGRES_RUNTIME_REPOSITORY_KEYS.length);
    assert.ok(runtime.services?.tenants);
    assert.ok(runtime.services?.targetGroups);
    assert.ok(runtime.services?.tokens);
    assert.ok(runtime.services?.serviceAccounts);
    assert.ok(runtime.services?.agents);
    assert.ok(runtime.services?.agentAuth);
    assert.equal(typeof runtime.services.audit?.appendAuditEvent, 'function');
    assert.equal(typeof runtime.services.audit?.listAuditEntries, 'function');
    for (const method of CORE_CATALOG_TENANT_SERVICE_METHODS) {
      assert.equal(typeof runtime.services.tenants[method], 'function', method);
    }
    for (const method of CORE_CATALOG_TARGET_GROUP_SERVICE_METHODS) {
      assert.equal(typeof runtime.services.targetGroups[method], 'function', method);
    }
    for (const method of POSTGRES_AUTH_TOKEN_SERVICE_METHODS) {
      assert.equal(typeof runtime.services.tokens[method], 'function', method);
    }
    for (const method of POSTGRES_SERVICE_ACCOUNT_SERVICE_METHODS) {
      assert.equal(typeof runtime.services.serviceAccounts[method], 'function', method);
    }
    for (const method of POSTGRES_AGENT_SERVICE_METHODS) {
      assert.equal(typeof runtime.services.agents[method], 'function', method);
    }
    for (const method of POSTGRES_AGENT_AUTH_SERVICE_METHODS) {
      assert.equal(typeof runtime.services.agentAuth[method], 'function', method);
    }
    assert.ok(runtime.services.testRuns);
    assert.ok(runtime.services.evidence);
    assert.ok(runtime.services.findings);
    assert.ok(runtime.services.events);
    for (const method of POSTGRES_EVENTS_SERVICE_METHODS) {
      assert.equal(typeof runtime.services.events[method], 'function', method);
    }
    for (const method of POSTGRES_VALIDATION_TEST_RUNS_SERVICE_METHODS) {
      assert.equal(typeof runtime.services.testRuns[method], 'function', method);
    }
    for (const method of POSTGRES_VALIDATION_EVIDENCE_SERVICE_METHODS) {
      assert.equal(typeof runtime.services.evidence[method], 'function', method);
    }
    for (const method of POSTGRES_VALIDATION_FINDINGS_SERVICE_METHODS) {
      assert.equal(typeof runtime.services.findings[method], 'function', method);
    }
    assert.ok(runtime.services.secretVault);
    for (const method of POSTGRES_SECRET_VAULT_SERVICE_METHODS) {
      assert.equal(typeof runtime.services.secretVault[method], 'function', method);
    }
    assert.ok(runtime.services.reports);
    for (const method of POSTGRES_REPORT_SERVICE_METHODS) {
      assert.equal(typeof runtime.services.reports[method], 'function', method);
    }
    assert.ok(runtime.services.notifications);
    for (const method of POSTGRES_NOTIFICATION_SERVICE_METHODS) {
      assert.equal(typeof runtime.services.notifications[method], 'function', method);
    }
    assert.ok(runtime.services.agentUpdates);
    for (const method of POSTGRES_AGENT_UPDATE_SERVICE_METHODS) {
      assert.equal(typeof runtime.services.agentUpdates[method], 'function', method);
    }
    assert.ok(runtime.services.state);
    for (const method of POSTGRES_STATE_SERVICE_METHODS) {
      assert.equal(typeof runtime.services.state[method], 'function', method);
    }
    assert.ok(runtime.services.probeJobs);
    for (const method of POSTGRES_PROBE_JOB_SERVICE_METHODS) {
      assert.equal(typeof runtime.services.probeJobs[method], 'function', method);
    }
    assert.ok(runtime.services.highScale);
    for (const method of POSTGRES_HIGH_SCALE_SERVICE_METHODS) {
      assert.equal(typeof runtime.services.highScale[method], 'function', method);
    }
    assert.ok(runtime.services.productionReleaseEvidence);
    for (const method of POSTGRES_PRODUCTION_RELEASE_EVIDENCE_SERVICE_METHODS) {
      assert.equal(typeof runtime.services.productionReleaseEvidence[method], 'function', method);
    }
    assert.ok(runtime.services.retention);
    for (const method of POSTGRES_RETENTION_SERVICE_METHODS) {
      assert.equal(typeof runtime.services.retention[method], 'function', method);
    }
    assert.ok(runtime.services.wafPosture);
    for (const method of POSTGRES_WAF_POSTURE_SERVICE_METHODS) {
      assert.equal(typeof runtime.services.wafPosture[method], 'function', method);
    }
    await runtime.close();
  });

  it('services forward tenant catalog calls to the coreCatalog repository', async () => {
    const { deps, coreCatalogCalls } = createHarness();
    const runtime = await createPostgresRuntime({}, deps);
    const ctx = { tenantId: 'ten_demo', userId: 'usr_1', role: 'admin' };

    await runtime.services.tenants.getCurrentTenant(ctx);
    await runtime.services.targetGroups.listTargetGroups(ctx);

    assert.deepEqual(coreCatalogCalls, [
      { method: 'getCurrentTenant', args: [ctx] },
      { method: 'listTargetGroups', args: [ctx] },
    ]);
    await runtime.close();
  });

  it('applies migrations when autoMigrate is enabled before latest assertion', async () => {
    const { calls, deps } = createHarness({ autoMigrate: true });
    await createPostgresRuntime({}, deps);

    assert.deepEqual(
      calls
        .filter((c) => ['ping', 'runMigrations', 'assertLatestMigrationApplied'].includes(c.type))
        .map((c) => c.type),
      ['ping', 'runMigrations', 'assertLatestMigrationApplied'],
    );
  });

  it('applies migrations when ASTRANULL_POSTGRES_AUTO_MIGRATE=1', async () => {
    const { calls, deps } = createHarness();
    await createPostgresRuntime({ ASTRANULL_POSTGRES_AUTO_MIGRATE: '1' }, deps);
    assert.ok(calls.some((c) => c.type === 'runMigrations'));
  });

  it('health pings, asserts latest migration, and returns safe metadata', async () => {
    const { calls, deps } = createHarness();
    const runtime = await createPostgresRuntime({}, deps);
    calls.length = 0;

    const health = await runtime.health();
    assert.deepEqual(health, { ok: true, persistence: 'postgres', latestMigration: '0001_test' });
    assert.deepEqual(
      calls.map((c) => c.type),
      ['ping', 'assertLatestMigrationApplied'],
    );
    await runtime.close();
  });

  it('closes pool and rethrows when ping fails during initialization', async () => {
    const { pool, deps } = createHarness({
      ping: async () => {
        throw new Error('ping failed');
      },
    });
    await assert.rejects(() => createPostgresRuntime({}, deps), /ping failed/);
    assert.equal(pool.endCalls, 1);
  });

  it('rethrows ping failure when cleanup close fails', async () => {
    let closeAttempts = 0;
    const { deps } = createHarness({
      ping: async () => {
        throw new Error('ping failed');
      },
      closePool: async () => {
        closeAttempts += 1;
        throw new Error('close failed');
      },
    });
    await assert.rejects(async () => createPostgresRuntime({}, deps), (err) => {
      assert.match(err.message, /ping failed/);
      assert.doesNotMatch(err.message, /close failed/);
      assert.match(err.cleanup_error?.message ?? '', /close failed/);
      return true;
    });
    assert.equal(closeAttempts, 1);
  });

  it('closes pool when repository factory fails', async () => {
    const { pool, deps } = createHarness({
      repositoryFactories: {
        coreCatalog: () => {
          throw new Error('repo build failed');
        },
      },
    });
    await assert.rejects(() => createPostgresRuntime({}, deps), /repo build failed/);
    assert.equal(pool.endCalls, 1);
  });

  it('rethrows repository factory failure when cleanup close fails', async () => {
    let closeAttempts = 0;
    const { deps } = createHarness({
      repositoryFactories: {
        coreCatalog: () => {
          throw new Error('repo build failed');
        },
      },
      closePool: async () => {
        closeAttempts += 1;
        throw new Error('close failed');
      },
    });
    await assert.rejects(async () => createPostgresRuntime({}, deps), (err) => {
      assert.match(err.message, /repo build failed/);
      assert.doesNotMatch(err.message, /close failed/);
      assert.match(err.cleanup_error?.message ?? '', /close failed/);
      return true;
    });
    assert.equal(closeAttempts, 1);
  });

  it('close is idempotent and closes the pool once', async () => {
    const { pool, deps } = createHarness();
    const runtime = await createPostgresRuntime({}, deps);
    await runtime.close();
    await runtime.close();
    assert.equal(pool.endCalls, 1);
  });

  it('does not reference dev-json memory store symbols or createServer in runtime source', () => {
    assert.equal(/\bgetStore\b/.test(RUNTIME_SOURCE), false);
    assert.equal(/\bpersistStore\b/.test(RUNTIME_SOURCE), false);
    assert.equal(/\bseedIfEmpty\b/.test(RUNTIME_SOURCE), false);
    assert.equal(/\bcreateServer\b/.test(RUNTIME_SOURCE), false);
  });

  it('wires high-scale services with notification service option', () => {
    assert.match(
      RUNTIME_SOURCE,
      /createPostgresHighScaleServices\(\s*repositories,\s*\{[\s\S]*?notifications:\s*notificationServices[\s\S]*?\}\s*\)/,
    );
  });
});
