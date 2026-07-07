import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';
import {
  assertLatestMigrationApplied,
  getLatestMigrationVersion,
  listMigrationFiles,
  migrationVersionFromFilename,
  migrationRequiresOutsideTransaction,
  MIGRATION_ADVISORY_LOCK_KEY,
  runMigrations,
} from '../../src/persistence/postgres/migrations.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '../..');
const MIGRATIONS_DIR = path.join(ROOT, 'db', 'migrations');

function createFakeClient({
  applied = new Set(),
  failOnQuery = null,
  schemaMigrationsTableExists = null,
  invalidIndexes = new Set(),
  validIndexes = new Set(),
  onQuery = null,
} = {}) {
  const queries = [];
  let inTransaction = false;
  let tableExists = schemaMigrationsTableExists ?? applied.size > 0;
  return {
    queries,
    async query(text, params) {
      queries.push({ text, params });
      if (onQuery) onQuery({ text, params, queries, applied, invalidIndexes, validIndexes });
      if (failOnQuery && failOnQuery(text)) {
        throw new Error('migration sql failed');
      }
      const normalized = String(text).trim();
      if (normalized === 'BEGIN') {
        inTransaction = true;
        return { rows: [] };
      }
      if (normalized === 'COMMIT') {
        inTransaction = false;
        return { rows: [] };
      }
      if (normalized === 'ROLLBACK') {
        inTransaction = false;
        return { rows: [] };
      }
      if (/to_regclass\('schema_migrations'\)/.test(text)) {
        return { rows: [{ table_name: tableExists ? 'schema_migrations' : null }] };
      }
      if (/pg_advisory_lock\(\$1\)/.test(text) && !/pg_advisory_xact_lock/.test(text)) {
        return { rows: [{ locked: true }] };
      }
      if (/pg_advisory_unlock\(\$1\)/.test(text)) {
        return { rows: [{ unlocked: true }] };
      }
      if (/SELECT version FROM schema_migrations/.test(text)) {
        if (!tableExists) {
          const err = new Error('relation "schema_migrations" does not exist');
          err.code = '42P01';
          throw err;
        }
        return { rows: [...applied].map((version) => ({ version })) };
      }
      if (/i\.indisvalid = false/.test(text)) {
        const indexName = params?.[0];
        return {
          rows: invalidIndexes.has(indexName)
            ? [{ schema_name: 'public', index_name: indexName }]
            : [],
        };
      }
      if (/DROP INDEX CONCURRENTLY IF EXISTS/.test(text)) {
        for (const indexName of [...invalidIndexes]) {
          if (text.includes(indexName)) invalidIndexes.delete(indexName);
        }
        return { rows: [] };
      }
      if (/CREATE\s+(?:UNIQUE\s+)?INDEX\s+CONCURRENTLY/i.test(text)) {
        const match = String(text).match(
          /CREATE\s+(?:UNIQUE\s+)?INDEX\s+CONCURRENTLY\s+(?:IF\s+NOT\s+EXISTS\s+)?("?[\w$]+"?)/i,
        );
        if (match) validIndexes.add(match[1].replace(/^"|"$/g, ''));
      }
      if (/i\.indisvalid = true/.test(text)) {
        const indexName = params?.[0];
        return { rows: validIndexes.has(indexName) ? [{ index_name: indexName }] : [] };
      }
      if (/CREATE TABLE schema_migrations/.test(text)) {
        tableExists = true;
      }
      if (/INSERT INTO schema_migrations/.test(text) && params?.[0]) {
        applied.add(params[0]);
      }
      return { rows: [] };
    },
    release() {},
    get inTransaction() {
      return inTransaction;
    },
    get schemaMigrationsTableExists() {
      return tableExists;
    },
  };
}

function createFakePool(appliedSet, { schemaMigrationsTableExists = null } = {}) {
  const tableExists =
    schemaMigrationsTableExists ?? (appliedSet.size > 0 ? true : false);
  const client = createFakeClient({
    applied: appliedSet,
    schemaMigrationsTableExists: tableExists,
  });
  let connectCount = 0;
  return {
    client,
    connectCount: () => connectCount,
    async query(text) {
      if (/to_regclass\('schema_migrations'\)/.test(text)) {
        return { rows: [{ table_name: tableExists ? 'schema_migrations' : null }] };
      }
      if (/SELECT version FROM schema_migrations/.test(text)) {
        if (!tableExists) {
          const err = new Error('relation "schema_migrations" does not exist');
          err.code = '42P01';
          throw err;
        }
        return { rows: [...appliedSet].map((version) => ({ version })) };
      }
      throw new Error(`unexpected pool query: ${text}`);
    },
    async connect() {
      connectCount += 1;
      return client;
    },
  };
}

function queryIndex(client, predicate) {
  return client.queries.findIndex((q) => predicate(q.text, q.params));
}

describe('postgres migrations', () => {
  it('lists migration files sorted and includes baseline', () => {
    const files = listMigrationFiles(MIGRATIONS_DIR);
    assert.ok(files.length >= 1);
    assert.equal(files[0].version, '0001_core_validation_loop');
    const versions = files.map((f) => f.version);
    const sorted = [...versions].sort();
    assert.deepEqual(versions, sorted);
  });

  it('lists production ledger migration after core validation loop', () => {
    const files = listMigrationFiles(MIGRATIONS_DIR);
    const versions = files.map((f) => f.version);
    assert.ok(versions.includes('0001_core_validation_loop'));
    assert.ok(versions.includes('0002_production_ledgers'));
    assert.equal(versions.indexOf('0002_production_ledgers'), versions.indexOf('0001_core_validation_loop') + 1);
  });

  it('lists runtime shape parity migration after production ledgers', () => {
    const files = listMigrationFiles(MIGRATIONS_DIR);
    const versions = files.map((f) => f.version);
    assert.ok(versions.includes('0003_runtime_shape_parity'));
    assert.equal(
      versions.indexOf('0003_runtime_shape_parity'),
      versions.indexOf('0002_production_ledgers') + 1,
    );
  });

  it('lists validation ledger indexes migration after runtime shape parity', () => {
    const files = listMigrationFiles(MIGRATIONS_DIR);
    const versions = files.map((f) => f.version);
    assert.ok(versions.includes('0004_validation_ledger_indexes'));
    assert.equal(
      versions.indexOf('0004_validation_ledger_indexes'),
      versions.indexOf('0003_runtime_shape_parity') + 1,
    );
  });

  it('lists verdict placement confidence migration after validation ledger indexes', () => {
    const files = listMigrationFiles(MIGRATIONS_DIR);
    const versions = files.map((f) => f.version);
    assert.ok(versions.includes('0005_verdict_placement_confidence'));
    assert.equal(
      versions.indexOf('0005_verdict_placement_confidence'),
      versions.indexOf('0004_validation_ledger_indexes') + 1,
    );
  });

  it('lists notification rule triggers migration after verdict placement confidence', () => {
    const files = listMigrationFiles(MIGRATIONS_DIR);
    const versions = files.map((f) => f.version);
    assert.ok(versions.includes('0006_notification_rule_triggers'));
    assert.equal(
      versions.indexOf('0006_notification_rule_triggers'),
      versions.indexOf('0005_verdict_placement_confidence') + 1,
    );
  });

  it('derives version from filename', () => {
    assert.equal(migrationVersionFromFilename('0001_core_validation_loop.sql'), '0001_core_validation_loop');
  });

  it('skips already-applied migration under advisory lock and single transaction', async () => {
    const applied = new Set(['0001_core_validation_loop']);
    const pool = createFakePool(applied, { schemaMigrationsTableExists: true });
    const files = listMigrationFiles(MIGRATIONS_DIR);
    const { results } = await runMigrations(pool, { migrationsDir: MIGRATIONS_DIR, files });
    assert.equal(results.length, files.length);
    assert.equal(results[0].status, 'skipped');
    assert.equal(pool.connectCount(), 1);

    const lockIdx = queryIndex(pool.client, (t) => /pg_advisory_xact_lock/.test(t));
    const regclassIdx = queryIndex(pool.client, (t) => /to_regclass/.test(t));
    const appliedIdx = queryIndex(pool.client, (t) => /SELECT version FROM schema_migrations/.test(t));
    const ddlIdx = queryIndex(pool.client, (t) => /CREATE TABLE tenants/.test(t));
    assert.ok(lockIdx >= 0, 'expected advisory lock');
    assert.ok(regclassIdx > lockIdx, 'to_regclass must follow lock');
    assert.ok(appliedIdx > regclassIdx, 'applied lookup must follow to_regclass');
    assert.equal(ddlIdx, -1, 'skipped run must not execute migration DDL');
    assert.equal(pool.client.queries.at(-1)?.text.trim(), 'COMMIT');
  });

  it('applies unapplied migration in a transaction and records version', async () => {
    const applied = new Set();
    const client = createFakeClient({ applied, schemaMigrationsTableExists: false });
    let connectCount = 0;
    const pool = {
      async query(text) {
        throw new Error(`unexpected pool query: ${text}`);
      },
      async connect() {
        connectCount += 1;
        return client;
      },
    };
    const files = [
      {
        name: '0099_test.sql',
        version: '0099_test',
        path: '/tmp/0099_test.sql',
        sql: 'CREATE TABLE schema_migrations (version TEXT PRIMARY KEY);\nCREATE TABLE demo(id int);',
      },
    ];
    const { results } = await runMigrations(pool, { migrationsDir: MIGRATIONS_DIR, files });
    assert.equal(results[0].status, 'applied');
    assert.ok(applied.has('0099_test'));
    assert.equal(connectCount, 1);

    const lockIdx = queryIndex(client, (t) => /pg_advisory_xact_lock/.test(t));
    const regclassIdx = queryIndex(client, (t) => /to_regclass/.test(t));
    const versionSelectIdx = queryIndex(client, (t) => /SELECT version FROM schema_migrations/.test(t));
    const ddlIdx = queryIndex(client, (t) => /CREATE TABLE demo/.test(t));
    assert.ok(lockIdx >= 0);
    assert.ok(regclassIdx > lockIdx);
    assert.equal(versionSelectIdx, -1, 'must not SELECT versions when table is absent');
    assert.ok(ddlIdx > regclassIdx, 'DDL must run after to_regclass lookup');

    assert.deepEqual(client.queries[lockIdx].params, [MIGRATION_ADVISORY_LOCK_KEY]);
    assert.deepEqual(
      client.queries.map((q) => q.text.trim()),
      [
        'BEGIN',
        'SELECT pg_advisory_xact_lock($1)',
        "SELECT to_regclass('schema_migrations') AS table_name",
        'CREATE TABLE schema_migrations (version TEXT PRIMARY KEY);\nCREATE TABLE demo(id int);',
        'INSERT INTO schema_migrations (version) VALUES ($1) ON CONFLICT (version) DO NOTHING',
        'COMMIT',
      ],
    );
  });

  it('first-run empty database uses to_regclass and applies baseline without aborting transaction', async () => {
    const applied = new Set();
    const client = createFakeClient({ applied, schemaMigrationsTableExists: false });
    const pool = {
      async query(text) {
        throw new Error(`unexpected pool query: ${text}`);
      },
      async connect() {
        return client;
      },
    };
    const files = listMigrationFiles(MIGRATIONS_DIR).slice(0, 1);
    const { results } = await runMigrations(pool, { migrationsDir: MIGRATIONS_DIR, files });
    assert.equal(results.length, 1);
    assert.equal(results[0].status, 'applied');
    assert.ok(applied.has('0001_core_validation_loop'));
    assert.ok(client.schemaMigrationsTableExists);

    const texts = client.queries.map((q) => q.text.trim());
    assert.equal(texts[0], 'BEGIN');
    assert.match(texts[1], /pg_advisory_xact_lock/);
    assert.match(texts[2], /to_regclass\('schema_migrations'\)/);
    const versionSelectBeforeBaseline = client.queries.findIndex(
      (q, idx) =>
        /SELECT version FROM schema_migrations/.test(q.text) &&
        idx < client.queries.findIndex((qq) => /CREATE TABLE schema_migrations/.test(qq.text)),
    );
    assert.equal(versionSelectBeforeBaseline, -1, 'must not query versions before baseline creates table');
    assert.ok(texts.some((t) => /CREATE TABLE schema_migrations/.test(t)), 'baseline DDL must run');
    assert.ok(
      texts.some((t) => /INSERT INTO schema_migrations \(version\) VALUES \(\$1\)/.test(t)),
      'runner must record applied version',
    );
    assert.equal(texts.at(-1), 'COMMIT');
    assert.ok(client.queries.every((q) => q.text.trim() !== 'ROLLBACK'));
  });

  it('detects migrations that require outside-transaction execution', () => {
    assert.equal(
      migrationRequiresOutsideTransaction('CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_demo ON demo(id);'),
      true,
    );
    assert.equal(migrationRequiresOutsideTransaction('CREATE INDEX IF NOT EXISTS idx_demo ON demo(id);'), false);
  });

  it('applies CREATE INDEX CONCURRENTLY migration outside an open transaction', async () => {
    const applied = new Set(['0001_core_validation_loop']);
    const client = createFakeClient({ applied, schemaMigrationsTableExists: true });
    const pool = {
      async query(text) {
        throw new Error(`unexpected pool query: ${text}`);
      },
      async connect() {
        return client;
      },
    };
    const concurrentSql = [
      'ALTER TABLE demo ADD COLUMN IF NOT EXISTS created_at timestamptz;',
      'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_demo ON demo(id);',
    ].join('\n');
    const files = [
      {
        name: '0097_concurrent.sql',
        version: '0097_concurrent',
        path: '/tmp/0097_concurrent.sql',
        sql: concurrentSql,
      },
    ];
    const { results } = await runMigrations(pool, { migrationsDir: MIGRATIONS_DIR, files });
    assert.equal(results[0].status, 'applied');
    assert.ok(applied.has('0097_concurrent'));

    const ddlIdx = queryIndex(client, (t) => /CREATE INDEX CONCURRENTLY/.test(t));
    assert.ok(ddlIdx >= 0, 'expected concurrent index DDL');
    const alterIdx = queryIndex(client, (t) => /ALTER TABLE demo ADD COLUMN/.test(t));
    assert.ok(alterIdx >= 0, 'expected non-concurrent DDL statement to execute separately');
    assert.ok(alterIdx < ddlIdx, 'expected split statements to preserve migration order');
    assert.notEqual(alterIdx, ddlIdx, 'outside-transaction migration must split semicolon statements');
    const commitBeforeDdl = client.queries
      .slice(0, ddlIdx)
      .some((q) => q.text.trim() === 'COMMIT');
    assert.ok(commitBeforeDdl, 'must COMMIT before concurrent index DDL');
    const beginAfterDdl = client.queries
      .slice(ddlIdx)
      .some((q) => q.text.trim() === 'BEGIN');
    assert.ok(beginAfterDdl, 'must BEGIN a new transaction after concurrent migration');
    const ddlBetweenBeginCommit = (() => {
      let openBegin = null;
      for (const q of client.queries) {
        const t = q.text.trim();
        if (t === 'BEGIN') openBegin = client.queries.indexOf(q);
        if (t === 'COMMIT' && openBegin != null) openBegin = null;
        if (/CREATE INDEX CONCURRENTLY/.test(q.text) && openBegin != null) return true;
      }
      return false;
    })();
    assert.equal(ddlBetweenBeginCommit, false, 'concurrent DDL must not run between BEGIN and COMMIT');
    assert.ok(
      client.queries.some((q) => /pg_advisory_lock\(\$1\)/.test(q.text) && !/xact/.test(q.text)),
      'expected session advisory lock around concurrent migration',
    );
    assert.ok(
      client.queries.some((q) => /i\.indisvalid = false/.test(q.text)),
      'expected invalid index catalog check before concurrent create',
    );
    assert.ok(
      client.queries.some((q) => /i\.indisvalid = true/.test(q.text)),
      'expected valid index catalog check after concurrent create',
    );
  });

  it('drops invalid matching concurrent indexes before rebuilding', async () => {
    const applied = new Set(['0001_core_validation_loop']);
    const invalidIndexes = new Set(['idx_demo']);
    const client = createFakeClient({
      applied,
      schemaMigrationsTableExists: true,
      invalidIndexes,
    });
    const pool = {
      async query(text) {
        throw new Error(`unexpected pool query: ${text}`);
      },
      async connect() {
        return client;
      },
    };
    const files = [{
      name: '0097_concurrent.sql',
      version: '0097_concurrent',
      path: '/tmp/0097_concurrent.sql',
      sql: 'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_demo ON demo(id);',
    }];

    await runMigrations(pool, { migrationsDir: MIGRATIONS_DIR, files });

    const dropIdx = queryIndex(client, (t) => /DROP INDEX CONCURRENTLY IF EXISTS "public"\."idx_demo"/.test(t));
    const createIdx = queryIndex(client, (t) => /CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_demo/.test(t));
    assert.ok(dropIdx >= 0, 'expected invalid index to be dropped');
    assert.ok(createIdx > dropIdx, 'expected rebuild after invalid drop');
    assert.equal(invalidIndexes.has('idx_demo'), false);
  });

  it('skips outside-transaction migration when another migrator records it under the session lock', async () => {
    const applied = new Set(['0001_core_validation_loop']);
    const client = createFakeClient({
      applied,
      schemaMigrationsTableExists: true,
      onQuery: ({ text }) => {
        if (/pg_advisory_lock\(\$1\)/.test(text) && !/xact/.test(text)) {
          applied.add('0097_concurrent');
        }
      },
    });
    const pool = {
      async query(text) {
        throw new Error(`unexpected pool query: ${text}`);
      },
      async connect() {
        return client;
      },
    };
    const files = [{
      name: '0097_concurrent.sql',
      version: '0097_concurrent',
      path: '/tmp/0097_concurrent.sql',
      sql: 'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_demo ON demo(id);',
    }];

    const { results } = await runMigrations(pool, { migrationsDir: MIGRATIONS_DIR, files });

    assert.equal(results[0].status, 'skipped');
    assert.equal(client.queries.some((q) => /CREATE INDEX CONCURRENTLY/.test(q.text)), false);
  });

  it('refreshes applied migrations after reacquiring the transaction lock', async () => {
    const applied = new Set(['0001_core_validation_loop']);
    let xactLockCount = 0;
    const client = createFakeClient({
      applied,
      schemaMigrationsTableExists: true,
      onQuery: ({ text }) => {
        if (/pg_advisory_xact_lock/.test(text)) {
          xactLockCount += 1;
          if (xactLockCount === 2) applied.add('0098_later');
        }
      },
    });
    const pool = {
      async query(text) {
        throw new Error(`unexpected pool query: ${text}`);
      },
      async connect() {
        return client;
      },
    };
    const files = [
      {
        name: '0097_concurrent.sql',
        version: '0097_concurrent',
        path: '/tmp/0097_concurrent.sql',
        sql: 'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_demo ON demo(id);',
      },
      {
        name: '0098_later.sql',
        version: '0098_later',
        path: '/tmp/0098_later.sql',
        sql: 'CREATE TABLE later(id int);',
      },
    ];

    const { results } = await runMigrations(pool, { migrationsDir: MIGRATIONS_DIR, files });

    assert.deepEqual(results.map((r) => [r.version, r.status]), [
      ['0097_concurrent', 'applied'],
      ['0098_later', 'skipped'],
    ]);
    assert.equal(client.queries.some((q) => /CREATE TABLE later/.test(q.text)), false);
  });

  it('rolls back on migration failure', async () => {
    const applied = new Set();
    const client = createFakeClient({
      applied,
      schemaMigrationsTableExists: false,
      failOnQuery: (text) => /CREATE TABLE broken/.test(text),
    });
    const pool = {
      async query(text) {
        throw new Error(`unexpected pool query: ${text}`);
      },
      async connect() {
        return client;
      },
    };
    const files = [
      {
        name: '0098_broken.sql',
        version: '0098_broken',
        path: '/tmp/0098_broken.sql',
        sql: 'CREATE TABLE broken(id int);',
      },
    ];
    await assert.rejects(
      () => runMigrations(pool, { migrationsDir: MIGRATIONS_DIR, files }),
      /migration sql failed/,
    );
    assert.ok(!applied.has('0098_broken'));
    assert.ok(client.queries.some((q) => q.text.trim() === 'ROLLBACK'));
    assert.ok(!client.queries.some((q) => q.text.trim() === 'COMMIT'));
  });

  it('assertLatestMigrationApplied fails when latest is missing', async () => {
    const pool = createFakePool(new Set(), { schemaMigrationsTableExists: false });
    await assert.rejects(
      () => assertLatestMigrationApplied(pool, '0001_core_validation_loop'),
      /not recorded in schema_migrations/,
    );
  });

  it('lists production release evidence migration after notification rule triggers', () => {
    const files = listMigrationFiles(MIGRATIONS_DIR);
    const versions = files.map((f) => f.version);
    assert.ok(versions.includes('0007_production_release_evidence'));
    assert.equal(
      versions.indexOf('0007_production_release_evidence'),
      versions.indexOf('0006_notification_rule_triggers') + 1,
    );
  });

  it('lists WAF posture migration after production release evidence', () => {
    const files = listMigrationFiles(MIGRATIONS_DIR);
    const versions = files.map((f) => f.version);
    assert.ok(versions.includes('0008_waf_posture'));
    assert.equal(
      versions.indexOf('0008_waf_posture'),
      versions.indexOf('0007_production_release_evidence') + 1,
    );
  });

  it('lists wave1 extensions migration after WAF posture', () => {
    const files = listMigrationFiles(MIGRATIONS_DIR);
    const versions = files.map((f) => f.version);
    assert.ok(versions.includes('0009_wave1_extensions'));
    assert.equal(
      versions.indexOf('0009_wave1_extensions'),
      versions.indexOf('0008_waf_posture') + 1,
    );
  });

  it('lists WAF add-on postgres parity migration after wave1 extensions', () => {
    const files = listMigrationFiles(MIGRATIONS_DIR);
    const versions = files.map((f) => f.version);
    assert.ok(versions.includes('0010_waf_addon_postgres_parity'));
    assert.equal(
      versions.indexOf('0010_waf_addon_postgres_parity'),
      versions.indexOf('0009_wave1_extensions') + 1,
    );
  });

  it('lists WAF orchestrator migration after WAF add-on postgres parity', () => {
    const files = listMigrationFiles(MIGRATIONS_DIR);
    const versions = files.map((f) => f.version);
    assert.ok(versions.includes('0011_waf_orchestrator'));
    assert.equal(
      versions.indexOf('0011_waf_orchestrator'),
      versions.indexOf('0010_waf_addon_postgres_parity') + 1,
    );
  });

  it('lists WAF orchestrator execution leases migration after WAF orchestrator', () => {
    const files = listMigrationFiles(MIGRATIONS_DIR);
    const versions = files.map((f) => f.version);
    assert.ok(versions.includes('0012_waf_orchestrator_execution_leases'));
    assert.equal(
      versions.indexOf('0012_waf_orchestrator_execution_leases'),
      versions.indexOf('0011_waf_orchestrator') + 1,
    );
  });

  it('getLatestMigrationVersion returns last sorted file', () => {
    const files = listMigrationFiles(MIGRATIONS_DIR);
    const latest = getLatestMigrationVersion(files);
    assert.equal(latest, '0037_test_policies');
    assert.equal(latest, files[files.length - 1].version);
  });

  it('lists test policies migration after signup queue events public RLS', () => {
    const files = listMigrationFiles(MIGRATIONS_DIR);
    const versions = files.map((f) => f.version);
    assert.ok(versions.includes('0037_test_policies'));
    assert.equal(
      versions.indexOf('0037_test_policies'),
      versions.indexOf('0036_signup_queue_events_public_rls') + 1,
    );
  });

  it('0037 migration creates test_policies with tenant RLS and isolation policy', () => {
    const sql = fs.readFileSync(
      path.join(MIGRATIONS_DIR, '0037_test_policies.sql'),
      'utf8',
    );
    assert.match(sql, /CREATE TABLE IF NOT EXISTS test_policies/);
    assert.match(sql, /ALTER TABLE test_policies ENABLE ROW LEVEL SECURITY/);
    assert.match(sql, /ALTER TABLE test_policies FORCE ROW LEVEL SECURITY/);
    assert.match(sql, /test_policies_tenant_isolation/);
    assert.match(sql, /current_setting\('app\.tenant_id', true\)/);
  });

  it('0010 migration adds notification delivery attempt retry columns', () => {
    const sql = fs.readFileSync(
      path.join(MIGRATIONS_DIR, '0010_waf_addon_postgres_parity.sql'),
      'utf8',
    );
    assert.match(sql, /ALTER TABLE notification_delivery_attempts ADD COLUMN IF NOT EXISTS attempt_number INT/);
    assert.match(sql, /ALTER TABLE notification_delivery_attempts ADD COLUMN IF NOT EXISTS next_retry_at TIMESTAMPTZ/);
    assert.match(sql, /ALTER TABLE notification_delivery_attempts ADD COLUMN IF NOT EXISTS exhausted BOOLEAN/);
  });

  it('0011 migration adds WAF orchestrator tables with tenant RLS', () => {
    const sql = fs.readFileSync(
      path.join(MIGRATIONS_DIR, '0011_waf_orchestrator.sql'),
      'utf8',
    );
    assert.match(sql, /CREATE TABLE IF NOT EXISTS waf_validation_plans/);
    assert.match(sql, /CREATE TABLE IF NOT EXISTS waf_baseline_approvals/);
    assert.match(sql, /CREATE TABLE IF NOT EXISTS waf_retest_requests/);
    assert.match(sql, /ALTER TABLE waf_baselines ADD COLUMN IF NOT EXISTS updated_at/);
    assert.match(sql, /tenant_isolation_waf_validation_plans/);
    assert.match(sql, /fk_waf_retest_requests_drift_event_tenant/);
  });

  it('0022 migration adds durable WAF exceptions with tenant RLS and composite FK', () => {
    const sql = fs.readFileSync(
      path.join(MIGRATIONS_DIR, '0022_waf_exceptions.sql'),
      'utf8',
    );
    assert.match(sql, /CREATE TABLE IF NOT EXISTS waf_exceptions/);
    assert.match(sql, /waf_exceptions_tenant_id_id_key/);
    assert.match(sql, /fk_waf_exceptions_waf_asset_tenant/);
    assert.match(sql, /ALTER TABLE waf_exceptions ENABLE ROW LEVEL SECURITY/);
    assert.match(sql, /ALTER TABLE waf_exceptions FORCE ROW LEVEL SECURITY/);
    assert.match(sql, /tenant_isolation_waf_exceptions/);
    assert.match(sql, /idx_waf_exceptions_tenant_expires/);
    assert.match(sql, /idx_waf_exceptions_tenant_asset/);
  });

  it('0012 migration adds execution lease columns and partial lock indexes', () => {
    const sql = fs.readFileSync(
      path.join(MIGRATIONS_DIR, '0012_waf_orchestrator_execution_leases.sql'),
      'utf8',
    );
    assert.match(sql, /ALTER TABLE waf_validation_plans ADD COLUMN IF NOT EXISTS execution_lock_token TEXT/);
    assert.match(sql, /ALTER TABLE waf_validation_plans ADD COLUMN IF NOT EXISTS execution_lock_expires_at TIMESTAMPTZ/);
    assert.match(sql, /ALTER TABLE waf_retest_requests ADD COLUMN IF NOT EXISTS execution_lock_token TEXT/);
    assert.match(sql, /ALTER TABLE waf_retest_requests ADD COLUMN IF NOT EXISTS execution_lock_expires_at TIMESTAMPTZ/);
    assert.match(sql, /CREATE INDEX IF NOT EXISTS idx_waf_validation_plans_execution_lock/);
    assert.match(sql, /CREATE INDEX IF NOT EXISTS idx_waf_retest_requests_execution_lock/);
    assert.match(sql, /WHERE execution_lock_token IS NOT NULL/);
  });
});
