import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import {
  buildRetentionRunnerSummary,
  parseRetentionRunnerArgs,
  parseTenantIdsFromJson,
  redactRetentionRunnerJsonValue,
  redactRetentionRunnerMessage,
  resolveRetentionRunnerConfig,
  runPostgresMetadataRetention,
  runRetentionRunner,
  toMetadataOnlyTenantResult,
} from '../../scripts/postgres-retention-runner.mjs';

const tempDirs = [];

function tempDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-retention-runner-'));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop(), { recursive: true, force: true });
  }
});

describe('postgres retention runner args', () => {
  it('parses single-tenant dry-run with output path', () => {
    assert.deepEqual(
      parseRetentionRunnerArgs([
        'node',
        'script.mjs',
        '--tenant-id',
        'ten_demo',
        '--dry-run',
        '--out',
        'summary.json',
      ]),
      {
        tenantId: 'ten_demo',
        tenantIdsFile: null,
        dryRun: true,
        out: 'summary.json',
        help: false,
      },
    );
  });

  it('parses tenant ids file and enforce mode', () => {
    assert.deepEqual(
      parseRetentionRunnerArgs(['node', 'script.mjs', '--tenant-ids-file', 'tenants.json']),
      {
        tenantId: null,
        tenantIdsFile: 'tenants.json',
        dryRun: false,
        out: null,
        help: false,
      },
    );
  });

  it('rejects unknown arguments', () => {
    assert.throws(
      () => parseRetentionRunnerArgs(['node', 'script.mjs', '--all-tenants']),
      /unknown argument/i,
    );
  });
});

describe('postgres retention runner config', () => {
  it('refuses to run without database URL', () => {
    const config = resolveRetentionRunnerConfig({}, { tenantId: 'ten_demo' });
    assert.equal(config.ok, false);
    assert.match(config.message ?? '', /ASTRANULL_DATABASE_URL/i);
  });

  it('requires explicit tenant scope', () => {
    const config = resolveRetentionRunnerConfig(
      { ASTRANULL_DATABASE_URL: 'postgresql://localhost/astranull' },
      {},
    );
    assert.equal(config.ok, false);
    assert.match(config.message ?? '', /tenant-id|tenant-ids-file/i);
  });

  it('rejects combining single tenant and file', () => {
    const config = resolveRetentionRunnerConfig(
      { ASTRANULL_DATABASE_URL: 'postgresql://localhost/astranull' },
      { tenantId: 'ten_a', tenantIdsFile: 'tenants.json' },
    );
    assert.equal(config.ok, false);
    assert.match(config.message ?? '', /not both/i);
  });

  it('parses tenant list from JSON file', () => {
    const dir = tempDir();
    const filePath = path.join(dir, 'tenants.json');
    writeFileSync(filePath, JSON.stringify({ tenant_ids: ['ten_a', 'ten_b'] }));

    const config = resolveRetentionRunnerConfig(
      { ASTRANULL_DATABASE_URL: 'postgresql://localhost/astranull' },
      { tenantIdsFile: filePath },
    );
    assert.equal(config.ok, true);
    assert.deepEqual(config.tenantIds, ['ten_a', 'ten_b']);
  });
});

describe('postgres retention runner tenant list parsing', () => {
  it('accepts JSON arrays and tenant_ids objects', () => {
    assert.deepEqual(parseTenantIdsFromJson(['ten_a', ' ten_b ']), ['ten_a', 'ten_b']);
    assert.deepEqual(parseTenantIdsFromJson({ tenant_ids: ['ten_c'] }), ['ten_c']);
  });

  it('rejects empty tenant lists', () => {
    assert.throws(() => parseTenantIdsFromJson([]), /must not be empty/i);
  });
});

describe('postgres retention runner execution', () => {
  it('dry-run calls preview and enforce calls enforce', async () => {
    const calls = [];
    const previewResult = {
      tenant_id: 'ten_demo',
      dry_run: true,
      deleted: { events: 0, evidenceVault: 0, reports: 0, notificationEvents: 0 },
      would_delete: { events: 2, evidenceVault: 0, reports: 0, notificationEvents: 0 },
      blocked_deletions: { events: 0, evidenceVault: 0, reports: 0, notificationEvents: 0 },
      metadata_retention_days: 90,
      evidence_retention: { legal_hold: false },
      policy_snapshot: { tenant_id: 'ten_demo', protected_collections: ['auditLog'] },
      legal_hold: false,
    };
    const enforceResult = { ...previewResult, dry_run: false, deleted: previewResult.would_delete };

    const createPostgresRuntimeFn = async () => ({
      services: {
        retention: {
          async previewMetadataRetentionForTenant(ctx, tenantId) {
            calls.push({ method: 'preview', ctx, tenantId });
            return previewResult;
          },
          async enforceMetadataRetentionForTenant(ctx, tenantId) {
            calls.push({ method: 'enforce', ctx, tenantId });
            return enforceResult;
          },
        },
      },
      close: async () => {
        calls.push({ method: 'close' });
      },
    });

    await runPostgresMetadataRetention({
      env: { ASTRANULL_DATABASE_URL: 'postgresql://localhost/astranull' },
      tenantIds: ['ten_demo'],
      dryRun: true,
      createPostgresRuntimeFn,
    });
    await runPostgresMetadataRetention({
      env: { ASTRANULL_DATABASE_URL: 'postgresql://localhost/astranull' },
      tenantIds: ['ten_demo'],
      dryRun: false,
      createPostgresRuntimeFn,
    });

    assert.deepEqual(calls[0], {
      method: 'preview',
      ctx: { userId: 'postgres-retention-runner', role: 'system', tenantId: 'ten_demo' },
      tenantId: 'ten_demo',
    });
    assert.deepEqual(calls[1], { method: 'close' });
    assert.deepEqual(calls[2], {
      method: 'enforce',
      ctx: { userId: 'postgres-retention-runner', role: 'system', tenantId: 'ten_demo' },
      tenantId: 'ten_demo',
    });
    assert.deepEqual(calls[3], { method: 'close' });
  });

  it('closes runtime when retention fails', async () => {
    const calls = [];
    const createPostgresRuntimeFn = async () => ({
      services: {
        retention: {
          async previewMetadataRetentionForTenant() {
            throw new Error('retention failed');
          },
          async enforceMetadataRetentionForTenant() {
            throw new Error('retention failed');
          },
        },
      },
      close: async () => {
        calls.push('close');
      },
    });

    const results = await runPostgresMetadataRetention({
      env: { ASTRANULL_DATABASE_URL: 'postgresql://localhost/astranull' },
      tenantIds: ['ten_demo'],
      dryRun: true,
      createPostgresRuntimeFn,
    });

    assert.equal(calls.length, 1);
    assert.equal(calls[0], 'close');
    assert.equal(results.length, 1);
    assert.match(String(results[0].error ?? ''), /retention failed/);
  });
});

describe('postgres retention runner output', () => {
  it('summary and written JSON are metadata-only and redact database URLs', async () => {
    const dir = tempDir();
    const outPath = path.join(dir, 'nested', 'summary.json');
    const secretUrl = 'postgresql://user:secret@db.example:5432/astranull';
    const createPostgresRuntimeFn = async () => ({
      services: {
        retention: {
          async previewMetadataRetentionForTenant() {
            return {
              tenant_id: 'ten_demo',
              dry_run: true,
              deleted: { events: 0, evidenceVault: 0, reports: 0, notificationEvents: 0 },
              would_delete: { events: 1, evidenceVault: 0, reports: 0, notificationEvents: 0 },
              blocked_deletions: { events: 0, evidenceVault: 0, reports: 0, notificationEvents: 0 },
              metadata_retention_days: 90,
              evidence_retention: { legal_hold: false },
              policy_snapshot: { tenant_id: 'ten_demo' },
              legal_hold: false,
              note: secretUrl,
            };
          },
          async enforceMetadataRetentionForTenant() {
            throw new Error(`failed for ${secretUrl}`);
          },
        },
      },
      close: async () => {},
    });

    const { summary, exitCode } = await runRetentionRunner(
      { ASTRANULL_DATABASE_URL: secretUrl },
      { dryRun: true, tenantIds: ['ten_demo'], out: outPath },
      { createPostgresRuntimeFn },
    );

    assert.equal(exitCode, 0);
    assert.equal(summary.artifact_type, 'postgres_metadata_retention_run');
    assert.equal(summary.tenants[0].tenant_id, 'ten_demo');
    assert.equal(summary.tenants[0].note, undefined);
    assert.doesNotMatch(JSON.stringify(summary), /postgresql:\/\//);

    const written = readFileSync(outPath, 'utf8');
    assert.doesNotMatch(written, /postgresql:\/\//);
    assert.match(written, /postgres_metadata_retention_run/);
  });

  it('redacts database URLs in error messages', () => {
    const env = { ASTRANULL_DATABASE_URL: 'postgresql://user:secret@db.example:5432/astranull' };
    const redacted = redactRetentionRunnerMessage(
      'connect failed: postgresql://user:secret@db.example:5432/astranull',
      env,
    );
    assert.doesNotMatch(redacted, /postgresql:\/\//);
    assert.match(redacted, /\[redacted-database-url\]/);

    const json = redactRetentionRunnerJsonValue(
      { error: 'postgresql://user:secret@db.example:5432/astranull' },
      env,
    );
    assert.doesNotMatch(JSON.stringify(json), /postgresql:\/\//);
  });

  it('metadata-only tenant rows exclude unexpected fields', () => {
    const row = toMetadataOnlyTenantResult({
      tenant_id: 'ten_demo',
      dry_run: true,
      deleted: { events: 0, evidenceVault: 0, reports: 0, notificationEvents: 0 },
      would_delete: { events: 1, evidenceVault: 0, reports: 0, notificationEvents: 0 },
      blocked_deletions: { events: 0, evidenceVault: 0, reports: 0, notificationEvents: 0 },
      metadata_retention_days: 90,
      evidence_retention: { legal_hold: false },
      policy_snapshot: { tenant_id: 'ten_demo' },
      legal_hold: false,
      raw_packet: 'must-not-appear',
      authorization_doc: 'secret',
    });
    assert.equal(row.raw_packet, undefined);
    assert.equal(row.authorization_doc, undefined);
    assert.equal(row.tenant_id, 'ten_demo');

    const summary = buildRetentionRunnerSummary({
      dryRun: true,
      tenantResults: [row],
      startedAt: '2026-07-02T00:00:00.000Z',
      finishedAt: '2026-07-02T00:00:00.000Z',
    });
    assert.equal(summary.tenant_count, 1);
    assert.match(JSON.stringify(summary), /policy_snapshot/);
    assert.doesNotMatch(JSON.stringify(summary), /raw_packet|authorization_doc/);
  });
});