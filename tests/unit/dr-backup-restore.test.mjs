import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import {
  MANIFEST_VERSION,
  backupDevStore,
  sha256Hex,
} from '../../scripts/backup-dev-store.mjs';
import { restoreDevStore } from '../../scripts/restore-dev-store.mjs';

const SAMPLE_STORE = {
  tenants: [{ id: 'ten_demo', name: 'Demo' }],
  environments: [],
  users: [],
  targetGroups: [],
  targets: [],
  bootstrapTokens: [],
  agents: [],
  agentJobs: [],
  testRuns: [],
  events: [],
  verdicts: [],
  findings: [],
  reports: [],
  highScaleRequests: [],
  readiness: {},
  auditLog: [],
  checkCatalog: [],
  serviceAccounts: [],
  encryptedSecrets: [],
};

describe('dr backup and restore (developer validation)', () => {
  /** @type {string[]} */
  const tmpDirs = [];

  afterEach(() => {
    for (const dir of tmpDirs) {
      rmSync(dir, { recursive: true, force: true });
    }
    tmpDirs.length = 0;
  });

  function tempRoot() {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-dr-'));
    tmpDirs.push(dir);
    return dir;
  }

  it('backup writes manifest with matching sha256 and bytes', () => {
    const root = tempRoot();
    const source = path.join(root, 'store.json');
    const payload = JSON.stringify(SAMPLE_STORE);
    writeFileSync(source, payload, 'utf8');
    const fixedNow = new Date('2026-07-01T15:04:05.000Z');

    const { backupPath, manifestPath, manifest } = backupDevStore({
      source,
      out: path.join(root, 'backups'),
      label: 'pre-migrate',
      now: fixedNow,
    });

    assert.ok(existsSync(backupPath));
    assert.ok(existsSync(manifestPath));

    const backupBytes = readFileSync(backupPath);
    assert.equal(manifest.version, MANIFEST_VERSION);
    assert.equal(manifest.created_at, fixedNow.toISOString());
    assert.equal(manifest.source, source);
    assert.equal(manifest.backup_file, path.basename(backupPath));
    assert.equal(manifest.sha256, sha256Hex(backupBytes));
    assert.equal(manifest.bytes, backupBytes.length);
    assert.equal(manifest.label, 'pre-migrate');
    assert.equal(backupBytes.toString('utf8'), payload);
  });

  it('restore dry-run verifies checksum and does not write dest', () => {
    const root = tempRoot();
    const source = path.join(root, 'store.json');
    writeFileSync(source, JSON.stringify(SAMPLE_STORE), 'utf8');
    const { manifestPath } = backupDevStore({
      source,
      out: path.join(root, 'backups'),
      label: null,
      now: new Date('2026-07-01T16:00:00.000Z'),
    });
    const dest = path.join(root, 'restored.json');
    assert.ok(!existsSync(dest));

    const result = restoreDevStore({
      manifest: manifestPath,
      backup: null,
      dest,
      dryRun: true,
      yes: false,
    });

    assert.equal(result.status, 'dry-run');
    assert.equal(result.wrote, false);
    assert.ok(!existsSync(dest));
  });

  it('restore refuses write without --yes', () => {
    const root = tempRoot();
    const source = path.join(root, 'store.json');
    writeFileSync(source, JSON.stringify(SAMPLE_STORE), 'utf8');
    const { manifestPath } = backupDevStore({
      source,
      out: path.join(root, 'backups'),
      label: null,
    });
    const dest = path.join(root, 'restored.json');

    assert.throws(
      () =>
        restoreDevStore({
          manifest: manifestPath,
          backup: null,
          dest,
          dryRun: false,
          yes: false,
        }),
      (err) => err && err.code === 'CONFIRMATION_REQUIRED',
    );
    assert.ok(!existsSync(dest));
  });

  it('restore with --yes writes exact backup bytes to dest', () => {
    const root = tempRoot();
    const source = path.join(root, 'store.json');
    const payload = JSON.stringify({ ...SAMPLE_STORE, tenants: [{ id: 'ten_x', name: 'X' }] });
    writeFileSync(source, payload, 'utf8');
    const { manifestPath } = backupDevStore({
      source,
      out: path.join(root, 'backups'),
      label: null,
    });
    const dest = path.join(root, 'out', 'astranull-dev.json');

    const result = restoreDevStore({
      manifest: manifestPath,
      backup: null,
      dest,
      dryRun: false,
      yes: true,
    });

    assert.equal(result.status, 'restored');
    assert.equal(result.wrote, true);
    assert.equal(readFileSync(dest, 'utf8'), payload);
  });

  it('restore rejects manifest backup_file with path traversal', () => {
    const root = tempRoot();
    const source = path.join(root, 'store.json');
    writeFileSync(source, JSON.stringify(SAMPLE_STORE), 'utf8');
    const { backupPath, manifestPath } = backupDevStore({
      source,
      out: path.join(root, 'backups'),
      label: null,
    });
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
    manifest.backup_file = '../store.json';
    writeFileSync(manifestPath, JSON.stringify(manifest), 'utf8');

    assert.throws(
      () =>
        restoreDevStore({
          manifest: manifestPath,
          backup: backupPath,
          dest: path.join(root, 'dest.json'),
          dryRun: true,
          yes: false,
        }),
      /backup_file must be a simple filename/,
    );
  });

  it('restore rejects manifest with invalid sha256 format', () => {
    const root = tempRoot();
    const source = path.join(root, 'store.json');
    writeFileSync(source, JSON.stringify(SAMPLE_STORE), 'utf8');
    const { backupPath, manifestPath } = backupDevStore({
      source,
      out: path.join(root, 'backups'),
      label: null,
    });
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
    manifest.sha256 = 'not-a-valid-digest';
    writeFileSync(manifestPath, JSON.stringify(manifest), 'utf8');

    assert.throws(
      () =>
        restoreDevStore({
          manifest: manifestPath,
          backup: backupPath,
          dest: path.join(root, 'dest.json'),
          dryRun: true,
          yes: false,
        }),
      /sha256 must be a 64-character hex digest/,
    );
  });

  it('restore rejects manifest bytes that do not match backup length', () => {
    const root = tempRoot();
    const source = path.join(root, 'store.json');
    writeFileSync(source, JSON.stringify(SAMPLE_STORE), 'utf8');
    const { backupPath, manifestPath } = backupDevStore({
      source,
      out: path.join(root, 'backups'),
      label: null,
    });
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
    manifest.bytes = manifest.bytes + 1;
    writeFileSync(manifestPath, JSON.stringify(manifest), 'utf8');

    assert.throws(
      () =>
        restoreDevStore({
          manifest: manifestPath,
          backup: backupPath,
          dest: path.join(root, 'dest.json'),
          dryRun: true,
          yes: false,
        }),
      /does not match backup length/,
    );
  });

  it('restore rejects manifest bytes that are not a nonnegative integer', () => {
    const root = tempRoot();
    const source = path.join(root, 'store.json');
    writeFileSync(source, JSON.stringify(SAMPLE_STORE), 'utf8');
    const { backupPath, manifestPath } = backupDevStore({
      source,
      out: path.join(root, 'backups'),
      label: null,
    });
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
    manifest.bytes = -1;
    writeFileSync(manifestPath, JSON.stringify(manifest), 'utf8');

    assert.throws(
      () =>
        restoreDevStore({
          manifest: manifestPath,
          backup: backupPath,
          dest: path.join(root, 'dest.json'),
          dryRun: true,
          yes: false,
        }),
      /bytes must be a nonnegative integer/,
    );
  });

  it('restore refuses checksum mismatch', () => {
    const root = tempRoot();
    const source = path.join(root, 'store.json');
    writeFileSync(source, JSON.stringify(SAMPLE_STORE), 'utf8');
    const { backupPath, manifestPath } = backupDevStore({
      source,
      out: path.join(root, 'backups'),
      label: null,
    });
    const tampered = '{"tampered":true}';
    writeFileSync(backupPath, tampered, 'utf8');
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
    manifest.bytes = Buffer.byteLength(tampered, 'utf8');
    writeFileSync(manifestPath, JSON.stringify(manifest), 'utf8');

    assert.throws(
      () =>
        restoreDevStore({
          manifest: manifestPath,
          backup: backupPath,
          dest: path.join(root, 'dest.json'),
          dryRun: false,
          yes: true,
        }),
      (err) => err && err.code === 'CHECKSUM_MISMATCH',
    );
  });
});