import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';
import {
  assertLatestMigrationApplied,
  getLatestMigrationVersion,
  listMigrationFiles,
  migrationVersionFromFilename,
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
} = {}) {
  const queries = [];
  let inTransaction = false;
  let tableExists = schemaMigrationsTableExists ?? applied.size > 0;
  return {
    queries,
    async query(text, params) {
      queries.push({ text, params });
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
      if (/SELECT version FROM schema_migrations/.test(text)) {
        if (!tableExists) {
          const err = new Error('relation "schema_migrations" does not exist');
          err.code = '42P01';
          throw err;
        }
        return { rows: [...applied].map((version) => ({ version })) };
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

  it('getLatestMigrationVersion returns last sorted file', () => {
    const files = listMigrationFiles(MIGRATIONS_DIR);
    const latest = getLatestMigrationVersion(files);
    assert.equal(latest, '0009_wave1_extensions');
    assert.equal(latest, files[files.length - 1].version);
  });
});
