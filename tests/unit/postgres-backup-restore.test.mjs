import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import {
  ARTIFACT_TYPE,
  MANIFEST_VERSION,
  backupPostgres,
  collectManifestForbiddenFields,
  decryptBackupPayload,
  encryptBackupPayload,
  parsePostgresBackupCliArgs,
  resolveDatabaseUrl,
  resolvePostgresBackupConfig,
  sha256Hex,
  validatePostgresBackupManifestFields,
} from '../../scripts/postgres-backup.mjs';
import {
  createPostgresRestoreDrillManifest,
  parsePostgresRestoreDrillArgs,
  resolvePostgresRestoreDrillConfig,
  runPostgresRestoreDrill,
  validatePostgresRestoreDrillEvidence,
  verifyEncryptedPostgresBackup,
} from '../../scripts/postgres-restore-drill.mjs';

const TEST_KEY_HEX = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const PG_CUSTOM_DUMP = Buffer.concat([
  Buffer.from('PGDMP', 'ascii'),
  Buffer.from([1, 0, 0, 0]),
  Buffer.from('test-dump-body'),
]);

const VALID_DRILL = {
  drill_id: 'pg_dr_2026_07_03_staging_restore',
  environment: 'staging',
  started_at: '2026-07-03T00:00:00.000Z',
  completed_at: '2026-07-03T01:00:00.000Z',
  backup_manifest: {
    manifest_uri: 'evidence://postgres/backup-manifest/staging-2026-07-03',
    sha256: 'a'.repeat(64),
    backup_reference: 's3://backups/staging/postgres-2026-07-03.dump.enc',
  },
  restore_target: {
    cluster_reference: 'db-cluster/staging/astranull-restore-clone',
    database_reference: 'postgres/staging/astranull',
    restore_mode: 'non_production_clone',
  },
  verification: {
    signoff_reference: 'signoff://ops/postgres-restore-verification',
    checks: [
      {
        check_id: 'tenant_rls_smoke',
        status: 'passed',
        evidence_uri: 'evidence://postgres/checks/tenant-rls',
      },
      {
        check_id: 'migration_head',
        status: 'passed',
        evidence_uri: 'evidence://postgres/checks/migration-head',
      },
    ],
  },
  operator_signoff: {
    operator: 'db-oncall',
    role: 'database-operator',
    signed_at: '2026-07-03T01:00:00.000Z',
    signoff_reference: 'signoff://ops/postgres-drill',
  },
};

const tempDirs = [];

function tempDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-pg-backup-'));
  tempDirs.push(dir);
  return dir;
}

function writeJson(file, value) {
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function testEnv(overrides = {}) {
  return {
    DATABASE_URL: 'postgresql://backup:secret@db.example:5432/astranull',
    ASTRANULL_BACKUP_ENCRYPTION_KEY: TEST_KEY_HEX,
    ...overrides,
  };
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop(), { recursive: true, force: true });
  }
});

describe('postgres backup config', () => {
  it('parses CLI arguments', () => {
    const parsed = parsePostgresBackupCliArgs([
      'node',
      'script.mjs',
      '--out',
      '/tmp/backups',
      '--label',
      'nightly',
    ]);
    assert.equal(parsed.out, '/tmp/backups');
    assert.equal(parsed.label, 'nightly');
  });

  it('fails closed without DATABASE_URL', () => {
    const resolved = resolveDatabaseUrl({});
    assert.equal(resolved.ok, false);
    assert.match(resolved.message ?? '', /DATABASE_URL/);
  });

  it('accepts ASTRANULL_DATABASE_URL', () => {
    const resolved = resolveDatabaseUrl({
      ASTRANULL_DATABASE_URL: 'postgresql://localhost/astranull',
    });
    assert.equal(resolved.ok, true);
    assert.equal(resolved.databaseUrl, 'postgresql://localhost/astranull');
  });

  it('fails closed without backup encryption key', () => {
    const config = resolvePostgresBackupConfig(
      { DATABASE_URL: 'postgresql://localhost/astranull' },
      { out: '/tmp/out', label: null },
    );
    assert.equal(config.ok, false);
    assert.match(config.message ?? '', /ASTRANULL_BACKUP_ENCRYPTION_KEY/);
  });
});

describe('postgres backup manifest safety', () => {
  it('rejects forbidden secret-like manifest fields', () => {
    const manifest = {
      version: MANIFEST_VERSION,
      artifact_type: ARTIFACT_TYPE,
      created_at: '2026-07-03T12:00:00.000Z',
      backup_file: 'postgres-2026-07-03.dump.enc',
      sha256: sha256Hex(Buffer.from('x')),
      plaintext_sha256: sha256Hex(PG_CUSTOM_DUMP),
      bytes: 10,
      label: null,
      database_reference: { host: 'db.example', port: 5432, database: 'astranull' },
      dump_format: 'pg_custom',
      encryption: {
        algorithm: 'AES-256-GCM',
        key_reference: 'env:ASTRANULL_BACKUP_ENCRYPTION_KEY',
        envelope_version: 1,
      },
      database_url: 'postgresql://secret@db.example/astranull',
    };
    const forbidden = collectManifestForbiddenFields(manifest);
    assert.ok(forbidden.includes('database_url'));
    assert.throws(() => validatePostgresBackupManifestFields(manifest), /forbidden fields/);
  });
});

describe('postgres backup and restore drill', () => {
  it('creates encrypted backup with metadata-only manifest', () => {
    const root = tempDir();
    const fixedNow = new Date('2026-07-03T12:00:00.000Z');
    const key = Buffer.from(TEST_KEY_HEX, 'hex');

    const { backupPath, manifestPath, manifest } = backupPostgres({
      databaseUrl: 'postgresql://backup:secret@db.example:5432/astranull',
      encryptionKey: key,
      out: path.join(root, 'backups'),
      label: 'drill',
      now: fixedNow,
      dumpFn: () => PG_CUSTOM_DUMP,
    });

    assert.ok(existsSync(backupPath));
    assert.ok(existsSync(manifestPath));

    const manifestText = readFileSync(manifestPath, 'utf8');
    assert.doesNotMatch(manifestText, /secret/);
    assert.doesNotMatch(manifestText, /postgresql:\/\//);

    const backupBytes = readFileSync(backupPath);
    assert.equal(manifest.version, MANIFEST_VERSION);
    assert.equal(manifest.artifact_type, ARTIFACT_TYPE);
    assert.equal(manifest.backup_file, path.basename(backupPath));
    assert.equal(manifest.sha256, sha256Hex(backupBytes));
    assert.equal(manifest.plaintext_sha256, sha256Hex(PG_CUSTOM_DUMP));
    assert.equal(manifest.label, 'drill');
    assert.deepEqual(manifest.database_reference, {
      host: 'db.example',
      port: 5432,
      database: 'astranull',
    });
    validatePostgresBackupManifestFields(manifest);
  });

  it('verifies encrypted backup for restore drill', () => {
    const root = tempDir();
    const key = Buffer.from(TEST_KEY_HEX, 'hex');
    const { manifestPath } = backupPostgres({
      databaseUrl: 'postgresql://backup:secret@db.example:5432/astranull',
      encryptionKey: key,
      out: path.join(root, 'backups'),
      label: null,
      dumpFn: () => PG_CUSTOM_DUMP,
    });

    const verification = verifyEncryptedPostgresBackup({
      manifestPath,
      encryptionKey: key,
    });

    assert.equal(verification.status, 'verified');
    assert.equal(verification.plaintext_sha256, sha256Hex(PG_CUSTOM_DUMP));
    assert.equal(verification.database_reference.database, 'astranull');
  });

  it('rejects checksum mismatch during restore drill verification', () => {
    const root = tempDir();
    const key = Buffer.from(TEST_KEY_HEX, 'hex');
    const { backupPath, manifestPath } = backupPostgres({
      databaseUrl: 'postgresql://backup:secret@db.example:5432/astranull',
      encryptionKey: key,
      out: path.join(root, 'backups'),
      label: null,
      dumpFn: () => PG_CUSTOM_DUMP,
    });

    const tampered = '{"tampered":true}\n';
    writeFileSync(backupPath, tampered, 'utf8');
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
    manifest.bytes = Buffer.byteLength(tampered, 'utf8');
    writeFileSync(manifestPath, JSON.stringify(manifest), 'utf8');

    assert.throws(
      () =>
        verifyEncryptedPostgresBackup({
          manifestPath,
          encryptionKey: key,
        }),
      (err) => err && err.code === 'CHECKSUM_MISMATCH',
    );
  });

  it('round-trips encryption envelope with matching AAD', () => {
    const key = Buffer.from(TEST_KEY_HEX, 'hex');
    const aad = {
      artifact_type: ARTIFACT_TYPE,
      backup_file: 'postgres-test.dump.enc',
      created_at: '2026-07-03T12:00:00.000Z',
      database_reference: { host: 'db.example', port: 5432, database: 'astranull' },
    };
    const envelope = encryptBackupPayload(PG_CUSTOM_DUMP, key, aad);
    const plaintext = decryptBackupPayload(envelope, key, aad);
    assert.equal(plaintext.toString('hex'), PG_CUSTOM_DUMP.toString('hex'));
  });
});

describe('postgres restore drill evidence', () => {
  it('parses CLI arguments', () => {
    assert.deepEqual(
      parsePostgresRestoreDrillArgs(['--manifest', 'backup.manifest.json', '--input', 'drill.json']),
      {
        manifest: 'backup.manifest.json',
        backup: null,
        input: 'drill.json',
        out: 'output/postgres-restore-drill-manifest.json',
        dryRun: false,
        validateOnly: false,
        help: false,
      },
    );
    assert.throws(() => parsePostgresRestoreDrillArgs([]), /--manifest is required/);
  });

  it('fails closed without DATABASE_URL for restore drill', () => {
    const config = resolvePostgresRestoreDrillConfig(
      { ASTRANULL_BACKUP_ENCRYPTION_KEY: TEST_KEY_HEX },
      { manifest: '/tmp/manifest.json', backup: null, input: null, dryRun: true },
    );
    assert.equal(config.ok, false);
    assert.match(config.message ?? '', /DATABASE_URL/);
  });

  it('accepts valid metadata-only drill evidence', () => {
    const result = validatePostgresRestoreDrillEvidence(VALID_DRILL);
    assert.equal(result.ok, true);
    assert.deepEqual(result.missing_fields, []);
    assert.deepEqual(result.forbidden_fields, []);
    assert.equal(result.missing_signoff, false);
  });

  it('rejects drill evidence containing database URLs', () => {
    const result = validatePostgresRestoreDrillEvidence({
      ...VALID_DRILL,
      notes: 'connected using postgresql://user:secret@db.example:5432/astranull',
    });
    assert.equal(result.ok, false);
    assert.ok(result.forbidden_fields.some((field) => field.includes('database_url_pattern')));
  });

  it('runs end-to-end restore drill with evidence manifest output', async () => {
    const root = tempDir();
    const key = Buffer.from(TEST_KEY_HEX, 'hex');
    const { manifestPath } = backupPostgres({
      databaseUrl: 'postgresql://backup:secret@db.example:5432/astranull',
      encryptionKey: key,
      out: path.join(root, 'backups'),
      label: 'drill',
      dumpFn: () => PG_CUSTOM_DUMP,
    });

    const drillPath = path.join(root, 'drill.json');
    writeJson(drillPath, VALID_DRILL);
    const outPath = path.join(root, 'output', 'postgres-restore-drill-manifest.json');

    const result = await runPostgresRestoreDrill({
      env: testEnv(),
      manifest: manifestPath,
      backup: null,
      input: drillPath,
      out: outPath,
      dryRun: true,
      validateOnly: false,
    });

    assert.equal(result.ok, true);
    assert.equal(result.drillValidation?.ok, true);
    assert.ok(existsSync(outPath));

    const written = JSON.parse(readFileSync(outPath, 'utf8'));
    assert.equal(written.artifact_type, 'postgres_restore_drill_manifest');
    assert.equal(written.verification.status, 'verified');
    assert.equal(written.drill_validation.ok, true);
    assert.doesNotMatch(readFileSync(outPath, 'utf8'), /postgresql:\/\//);
  });

  it('creates metadata-only restore drill manifest helper output', () => {
    const manifest = createPostgresRestoreDrillManifest({
      verification: {
        status: 'verified',
        manifestPath: '/tmp/backup.manifest.json',
        backupPath: '/tmp/backup.dump.enc',
        sha256: 'b'.repeat(64),
        plaintext_sha256: 'c'.repeat(64),
        plaintext_bytes: 128,
        database_reference: { host: 'db.example', port: 5432, database: 'astranull' },
        encryption_algorithm: 'AES-256-GCM',
      },
      drillValidation: {
        ok: true,
        missing_fields: [],
        forbidden_fields: [],
        missing_signoff: false,
      },
      drillEvidence: VALID_DRILL,
    });

    const serialized = JSON.stringify(manifest);
    assert.doesNotMatch(serialized, /postgresql:\/\//);
    assert.equal(manifest.drill_summary.drill_id, VALID_DRILL.drill_id);
  });
});