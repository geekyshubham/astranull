import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import {
  buildNotificationRetryRunnerSummary,
  parseNotificationRetryRunnerArgs,
  parseTenantIdsFromJson,
  redactNotificationRetryRunnerMessage,
  resolveNotificationRetryRunnerConfig,
  runNotificationRetryRunner,
  toMetadataOnlyTenantRetryResult,
} from '../../scripts/notification-retry-runner.mjs';

const tempDirs = [];

function tempDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-notification-retry-runner-'));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop(), { recursive: true, force: true });
  }
});

describe('notification retry runner args', () => {
  it('parses defaults when only argv0/argv1 are present', () => {
    assert.deepEqual(parseNotificationRetryRunnerArgs(['node', 'notification-retry-runner.mjs']), {
      tenantId: null,
      tenantIdsFile: null,
      asOf: null,
      dryRun: false,
      out: null,
      help: false,
    });
  });

  it('parses explicit tenant, as-of, dry-run, out, and help', () => {
    assert.deepEqual(
      parseNotificationRetryRunnerArgs([
        'node',
        'notification-retry-runner.mjs',
        '--tenant-id',
        'ten_alpha',
        '--as-of',
        '2026-06-01T12:00:00.000Z',
        '--dry-run',
        '--out',
        '/tmp/summary.json',
        '--help',
      ]),
      {
        tenantId: 'ten_alpha',
        tenantIdsFile: null,
        asOf: '2026-06-01T12:00:00.000Z',
        dryRun: true,
        out: '/tmp/summary.json',
        help: true,
      },
    );
  });

  it('parses -h as help', () => {
    assert.equal(
      parseNotificationRetryRunnerArgs(['node', 'script.mjs', '-h']).help,
      true,
    );
  });

  it('parses --tenant-ids-file', () => {
    assert.deepEqual(
      parseNotificationRetryRunnerArgs([
        'node',
        'script.mjs',
        '--tenant-ids-file',
        'tenants.json',
      ]).tenantIdsFile,
      'tenants.json',
    );
  });

  it('rejects --tenant-id without a value', () => {
    assert.throws(
      () => parseNotificationRetryRunnerArgs(['node', 'script.mjs', '--tenant-id']),
      /--tenant-id requires a value/,
    );
  });

  it('rejects unknown arguments', () => {
    assert.throws(
      () => parseNotificationRetryRunnerArgs(['node', 'script.mjs', '--bogus']),
      /unknown argument/,
    );
  });
});

describe('notification retry runner tenant id file parsing', () => {
  it('accepts a JSON array of tenant ids', () => {
    assert.deepEqual(parseTenantIdsFromJson(['ten_a', ' ten_b ']), ['ten_a', 'ten_b']);
  });

  it('accepts { tenant_ids: [] } object form', () => {
    assert.deepEqual(parseTenantIdsFromJson({ tenant_ids: ['ten_x', 'ten_y'] }), ['ten_x', 'ten_y']);
  });

  it('parses JSON strings', () => {
    assert.deepEqual(parseTenantIdsFromJson('["ten_z"]'), ['ten_z']);
  });

  it('rejects empty tenant lists', () => {
    assert.throws(
      () => parseTenantIdsFromJson([]),
      /must not be empty/,
    );
    assert.throws(
      () => parseTenantIdsFromJson({ tenant_ids: ['', '   '] }),
      /must not be empty/,
    );
  });

  it('rejects malformed tenant id payloads', () => {
    assert.throws(
      () => parseTenantIdsFromJson({ tenants: ['ten_a'] }),
      /JSON array or/,
    );
    assert.throws(
      () => parseTenantIdsFromJson('not-json'),
      /JSON/,
    );
  });
});

describe('notification retry runner config validation', () => {
  const baseEnv = { ASTRANULL_DATABASE_URL: 'postgresql://user:secret@db.example.invalid/astranull' };

  it('requires ASTRANULL_DATABASE_URL', () => {
    const config = resolveNotificationRetryRunnerConfig(
      {},
      parseNotificationRetryRunnerArgs(['node', 'script.mjs', '--tenant-id', 'ten_a']),
    );
    assert.equal(config.ok, false);
    assert.match(config.message ?? '', /ASTRANULL_DATABASE_URL/);
  });

  it('requires explicit tenant scope', () => {
    const config = resolveNotificationRetryRunnerConfig(
      baseEnv,
      parseNotificationRetryRunnerArgs(['node', 'script.mjs']),
    );
    assert.equal(config.ok, false);
    assert.match(config.message ?? '', /tenant-id|tenant-ids-file/);
  });

  it('rejects both --tenant-id and --tenant-ids-file', () => {
    const config = resolveNotificationRetryRunnerConfig(
      baseEnv,
      parseNotificationRetryRunnerArgs([
        'node',
        'script.mjs',
        '--tenant-id',
        'ten_a',
        '--tenant-ids-file',
        'ids.json',
      ]),
    );
    assert.equal(config.ok, false);
    assert.match(config.message ?? '', /not both/);
  });

  it('rejects invalid --as-of timestamps', () => {
    const config = resolveNotificationRetryRunnerConfig(
      baseEnv,
      parseNotificationRetryRunnerArgs([
        'node',
        'script.mjs',
        '--tenant-id',
        'ten_a',
        '--as-of',
        'not-a-date',
      ]),
    );
    assert.equal(config.ok, false);
    assert.match(config.message ?? '', /valid ISO timestamp/);
  });

  it('resolves tenant ids from file via injectable reader', () => {
    const config = resolveNotificationRetryRunnerConfig(
      baseEnv,
      parseNotificationRetryRunnerArgs([
        'node',
        'script.mjs',
        '--tenant-ids-file',
        '/ignored/path.json',
      ]),
      {
        readTenantIdsFile: () => JSON.stringify({ tenant_ids: ['ten_file_a', 'ten_file_b'] }),
      },
    );
    assert.equal(config.ok, true);
    assert.deepEqual(config.tenantIds, ['ten_file_a', 'ten_file_b']);
    assert.equal(config.dryRun, false);
  });

  it('wraps tenant file parse errors', () => {
    const config = resolveNotificationRetryRunnerConfig(
      baseEnv,
      parseNotificationRetryRunnerArgs([
        'node',
        'script.mjs',
        '--tenant-ids-file',
        'bad.json',
      ]),
      { readTenantIdsFile: () => '{' },
    );
    assert.equal(config.ok, false);
    assert.ok(config.message);
  });
});

describe('notification retry runner metadata-only summary', () => {
  const sensitiveProcessed = [
    {
      event_id: 'nevt_1',
      status: 'provider_retry_scheduled',
      destination: 'https://hooks.example.invalid/secret-path',
      payload: { token: 'ast_abcdefghijklmnop' },
      body: 'raw webhook body',
    },
  ];

  it('tenant result helper keeps allowed fields and drops secrets at top level', () => {
    const redacted = toMetadataOnlyTenantRetryResult({
      tenant_id: 'ten_demo',
      dry_run: true,
      as_of: '2026-06-01T12:00:00.000Z',
      delivery_mode: 'metadata_only',
      due_count: 1,
      scheduled_not_due_count: 0,
      network_sends_performed: 0,
      processed: sensitiveProcessed,
      destination: 'https://user:pass@hooks.example.invalid/h',
      database_url: 'postgresql://user:pass@db.example.invalid/db',
      credentials: { api_key: 'sk-test' },
    });

    const blob = JSON.stringify(redacted);
    assert.equal(redacted.tenant_id, 'ten_demo');
    assert.equal(redacted.due_count, 1);
    assert.ok(!('destination' in redacted));
    assert.ok(!('database_url' in redacted));
    assert.ok(!('credentials' in redacted));
    assert.ok(!blob.includes('postgresql://'));
    assert.ok(!blob.includes('sk-test'));
    assert.equal(redacted.processed.length, 1);
    assert.equal(redacted.processed[0].event_id, 'nevt_1');
    assert.ok(!('destination' in redacted.processed[0]));
    assert.ok(!('payload' in redacted.processed[0]));
  });

  it('summary JSON excludes destinations, payloads, tokens, and database URLs', () => {
    const summary = buildNotificationRetryRunnerSummary({
      dryRun: false,
      asOf: '2026-06-01T12:00:00.000Z',
      deliveryMode: 'metadata_only',
      startedAt: '2026-06-01T12:00:01.000Z',
      finishedAt: '2026-06-01T12:00:02.000Z',
      tenantResults: [
        {
          tenant_id: 'ten_demo',
          dry_run: false,
          as_of: '2026-06-01T12:00:00.000Z',
          delivery_mode: 'metadata_only',
          due_count: 1,
          scheduled_not_due_count: 0,
          network_sends_performed: 0,
          processed: sensitiveProcessed,
          webhook_destination: 'https://hooks.example.invalid/x',
          metadata: { token: 'ast_abcdefghijklmnop' },
        },
      ],
    });

    const blob = JSON.stringify(summary);
    assert.equal(summary.artifact_type, 'notification_retry_runtime_run');
    assert.equal(summary.tenant_count, 1);
    assert.ok(summary.caveats.some((c) => /metadata-only/i.test(c)));
    assert.ok(!blob.includes('hooks.example.invalid'));
    assert.ok(!blob.includes('ast_abcdefghijklmnop'));
    assert.ok(!blob.includes('postgresql://'));
    assert.ok(!blob.includes('raw webhook body'));
  });

  it('redacts database URLs from error messages', () => {
    const env = { ASTRANULL_DATABASE_URL: 'postgresql://user:secret@db.example.invalid/astranull' };
    const message = redactNotificationRetryRunnerMessage(
      new Error('connect failed postgresql://user:secret@db.example.invalid/astranull'),
      env,
    );
    assert.ok(!String(message).includes('postgresql://user:secret'));
  });
});

describe('notification retry runner execution (mocked postgres)', () => {
  it('writes metadata-only summary without connecting to postgres', async () => {
    const dir = tempDir();
    const outPath = path.join(dir, 'nested', 'summary.json');
    const env = {
      ASTRANULL_DATABASE_URL: 'postgresql://runner:secret@db.example.invalid/astranull',
      ASTRANULL_NOTIFICATION_DELIVERY_MODE: 'metadata_only',
    };

    const { summary, exitCode } = await runNotificationRetryRunner(
      env,
      {
        dryRun: true,
        tenantIds: ['ten_mock'],
        asOf: '2026-06-01T12:00:00.000Z',
        out: outPath,
        deliveryMode: 'metadata_only',
      },
      {
        createPostgresRuntimeFn: async () => ({
          services: {
            notifications: {
              processDueNotificationRetries: async () => ({
                tenant_id: 'ten_mock',
                dry_run: true,
                as_of: '2026-06-01T12:00:00.000Z',
                delivery_mode: 'metadata_only',
                due_count: 0,
                scheduled_not_due_count: 0,
                network_sends_performed: 0,
                processed: [],
                destination: 'https://hooks.example.invalid/should-not-appear',
              }),
            },
          },
          close: async () => {},
        }),
      },
    );

    assert.equal(exitCode, 0);
    assert.equal(summary.tenant_count, 1);
    const written = readFileSync(outPath, 'utf8');
    assert.ok(!written.includes('hooks.example.invalid'));
    assert.ok(!written.includes('postgresql://'));
    assert.ok(written.includes('"artifact_type": "notification_retry_runtime_run"'));
  });

  it('returns exit code 1 when a tenant run records an error', async () => {
    const env = { ASTRANULL_DATABASE_URL: 'postgresql://runner:secret@db.example.invalid/astranull' };
    const { exitCode } = await runNotificationRetryRunner(
      env,
      {
        dryRun: false,
        tenantIds: ['ten_fail'],
        asOf: '2026-06-01T12:00:00.000Z',
        out: null,
        deliveryMode: 'metadata_only',
      },
      {
        createPostgresRuntimeFn: async () => ({
          services: {
            notifications: {
              processDueNotificationRetries: async () => {
                throw new Error('tenant processing failed');
              },
            },
          },
          close: async () => {},
        }),
      },
    );

    assert.equal(exitCode, 1);
  });
});