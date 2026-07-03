import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import {
  DEFAULT_NOTIFICATION_RETRY_INTERVAL_MS,
  MAX_NOTIFICATION_RETRY_INTERVAL_MS,
  MIN_NOTIFICATION_RETRY_INTERVAL_MS,
  buildNotificationRetrySchedulerTickSummary,

  parseNotificationRetrySchedulerArgs,
  redactNotificationRetrySchedulerMessage,
  resolveNotificationRetryIntervalMs,
  resolveNotificationRetrySchedulerConfig,
  resolveTenantIdsFromNotificationStore,
  runDevJsonNotificationRetryTick,
  runNotificationRetryScheduler,
  runNotificationRetrySchedulerTick,
} from '../../scripts/notification-retry-scheduler.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';

const tempDirs = [];
const envSnapshot = { ...process.env };

function restoreEnv() {
  for (const key of Object.keys(process.env)) {
    if (!(key in envSnapshot)) delete process.env[key];
  }
  Object.assign(process.env, envSnapshot);
}

function tempDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-notification-retry-scheduler-'));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  restoreEnv();
  freshStore();
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop(), { recursive: true, force: true });
  }
});

describe('notification retry scheduler args', () => {
  it('parses defaults when only argv0/argv1 are present', () => {
    assert.deepEqual(parseNotificationRetrySchedulerArgs(['node', 'notification-retry-scheduler.mjs']), {
      tenantId: null,
      tenantIdsFile: null,
      allTenants: false,
      intervalMs: null,
      once: false,
      dryRun: false,
      out: null,
      help: false,
    });
  });

  it('parses tenant scope, interval, once, dry-run, out, and help', () => {
    assert.deepEqual(
      parseNotificationRetrySchedulerArgs([
        'node',
        'notification-retry-scheduler.mjs',
        '--tenant-id',
        'ten_alpha',
        '--interval-ms',
        '15000',
        '--once',
        '--dry-run',
        '--out',
        '/tmp/summary.json',
        '--help',
      ]),
      {
        tenantId: 'ten_alpha',
        tenantIdsFile: null,
        allTenants: false,
        intervalMs: 15000,
        once: true,
        dryRun: true,
        out: '/tmp/summary.json',
        help: true,
      },
    );
  });

  it('rejects unknown arguments and missing values', () => {
    assert.throws(
      () => parseNotificationRetrySchedulerArgs(['node', 'script.mjs', '--tenant-id']),
      /--tenant-id requires a value/,
    );
    assert.throws(
      () => parseNotificationRetrySchedulerArgs(['node', 'script.mjs', '--interval-ms', 'nope']),
      /--interval-ms must be a positive integer/,
    );
    assert.throws(
      () => parseNotificationRetrySchedulerArgs(['node', 'script.mjs', '--bogus']),
      /unknown argument/,
    );
  });
});

describe('notification retry scheduler interval resolution', () => {
  it('defaults to 60s and clamps to bounded min/max', () => {
    assert.equal(resolveNotificationRetryIntervalMs(undefined), DEFAULT_NOTIFICATION_RETRY_INTERVAL_MS);
    assert.equal(resolveNotificationRetryIntervalMs(1000), MIN_NOTIFICATION_RETRY_INTERVAL_MS);
    assert.equal(resolveNotificationRetryIntervalMs(999999), MAX_NOTIFICATION_RETRY_INTERVAL_MS);
    assert.equal(resolveNotificationRetryIntervalMs('45000'), 45_000);
  });
});

describe('notification retry scheduler config', () => {
  const postgresEnv = {
    ASTRANULL_DATABASE_URL: 'postgresql://user:secret@db.example.invalid/astranull',
  };

  it('rejects both --tenant-id and --tenant-ids-file', () => {
    const config = resolveNotificationRetrySchedulerConfig(
      postgresEnv,
      parseNotificationRetrySchedulerArgs([
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

  it('resolves dev-json mode without database URL and defaults to all tenants', () => {
    const config = resolveNotificationRetrySchedulerConfig(
      {},
      parseNotificationRetrySchedulerArgs(['node', 'script.mjs']),
    );
    assert.equal(config.ok, true);
    assert.equal(config.persistenceMode, 'dev-json');
    assert.equal(config.allTenants, true);
    assert.equal(config.deliveryMode, 'metadata_only');
    assert.equal(config.intervalMs, DEFAULT_NOTIFICATION_RETRY_INTERVAL_MS);
  });

  it('requires explicit tenant scope in postgres mode', () => {
    const config = resolveNotificationRetrySchedulerConfig(
      postgresEnv,
      parseNotificationRetrySchedulerArgs(['node', 'script.mjs']),
    );
    assert.equal(config.ok, false);
    assert.match(config.message ?? '', /explicit tenant scope/i);
  });

  it('resolves postgres mode and explicit tenant scope', () => {
    const config = resolveNotificationRetrySchedulerConfig(
      {
        ...postgresEnv,
        ASTRANULL_NOTIFICATION_RETRY_INTERVAL_MS: '12000',
        ASTRANULL_NOTIFICATION_DELIVERY_MODE: 'webhook',
      },
      parseNotificationRetrySchedulerArgs(['node', 'script.mjs', '--tenant-id', 'ten_a']),
    );
    assert.equal(config.ok, true);
    assert.equal(config.persistenceMode, 'postgres');
    assert.deepEqual(config.tenantIds, ['ten_a']);
    assert.equal(config.allTenants, false);
    assert.equal(config.deliveryMode, 'webhook');
    assert.equal(config.intervalMs, 12_000);
  });

  it('honors --interval-ms over env default', () => {
    const config = resolveNotificationRetrySchedulerConfig(
      { ASTRANULL_NOTIFICATION_RETRY_INTERVAL_MS: '90000' },
      parseNotificationRetrySchedulerArgs(['node', 'script.mjs', '--interval-ms', '20000']),
    );
    assert.equal(config.ok, true);
    assert.equal(config.intervalMs, 20_000);
  });
});

describe('notification retry scheduler tenant discovery', () => {
  it('discovers tenant ids from notification events and rules in dev-json store', () => {
    const store = getStore();
    store.notificationEvents = [{ tenant_id: 'ten_a' }, { tenant_id: 'ten_b' }];
    store.notificationRules = [{ tenant_id: 'ten_b' }, { tenant_id: 'ten_c' }];

    assert.deepEqual(resolveTenantIdsFromNotificationStore([], store), ['ten_a', 'ten_b', 'ten_c']);
    assert.deepEqual(resolveTenantIdsFromNotificationStore(['ten_explicit'], store), ['ten_explicit']);
  });
});

describe('notification retry scheduler metadata-only summary', () => {
  it('tick summary excludes destinations, payloads, tokens, and database URLs', () => {
    const summary = buildNotificationRetrySchedulerTickSummary({
      dryRun: false,
      asOf: '2026-06-01T12:00:00.000Z',
      deliveryMode: 'metadata_only',
      intervalMs: 60_000,
      persistenceMode: 'dev-json',
      tickNumber: 2,
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
          processed: [
            {
              event_id: 'nevt_1',
              status: 'provider_retry_scheduled',
              destination: 'https://hooks.example.invalid/secret-path',
              payload: { token: 'ast_abcdefghijklmnop' },
            },
          ],
          webhook_destination: 'https://hooks.example.invalid/x',
        },
      ],
    });

    const blob = JSON.stringify(summary);
    assert.equal(summary.artifact_type, 'notification_retry_scheduler_tick');
    assert.equal(summary.persistence_mode, 'dev-json');
    assert.equal(summary.tick_number, 2);
    assert.equal(summary.interval_ms, 60_000);
    assert.ok(summary.caveats.some((c) => /--once/i.test(c)));
    assert.ok(!blob.includes('hooks.example.invalid'));
    assert.ok(!blob.includes('ast_abcdefghijklmnop'));
    assert.ok(!blob.includes('postgresql://'));
  });

  it('redacts database URLs from scheduler error messages', () => {
    const env = { ASTRANULL_DATABASE_URL: 'postgresql://user:secret@db.example.invalid/astranull' };
    const message = redactNotificationRetrySchedulerMessage(
      new Error('connect failed postgresql://user:secret@db.example.invalid/astranull'),
      env,
    );
    assert.ok(!String(message).includes('postgresql://user:secret'));
  });
});

describe('notification retry scheduler execution (mocked)', () => {
  it('processes dev-json due retries in a single tick without outbound sends by default', async () => {
    const store = getStore();
    store.notificationRules = [
      {
        id: 'nrule_1',
        tenant_id: 'ten_demo',
        channel: 'webhook',
        destination: 'https://hooks.example.invalid/path',
        triggers: ['report.ready'],
        enabled: true,
      },
    ];
    store.notificationEvents = [
      {
        id: 'nevt_1',
        tenant_id: 'ten_demo',
        trigger: 'report.ready',
        subject: '[REDACTED]',
        metadata: {},
        created_at: '2026-06-01T10:00:00.000Z',
        delivery_attempts: [
          {
            id: 'natt_1',
            rule_id: 'nrule_1',
            channel: 'webhook',
            destination_preview: 'webhook://hooks.example.invalid/…',
            status: 'provider_retry_scheduled',
            attempt_number: 1,
            max_attempts: 3,
            next_retry_at: '2026-01-01T00:00:00.000Z',
            provider_error: 'webhook_http_error',
          },
        ],
      },
    ];

    const tenantResults = await runDevJsonNotificationRetryTick({
      tenantIds: ['ten_demo'],
      dryRun: false,
      asOf: '2026-06-01T12:00:00.000Z',
    });

    assert.equal(tenantResults.length, 1);
    assert.equal(tenantResults[0].due_count, 1);
    assert.equal(tenantResults[0].network_sends_performed, 0);
    assert.equal(tenantResults[0].processed[0].status, 'provider_retry_scheduled');
    assert.equal(store.notificationEvents[0].delivery_attempts.length, 2);
  });

  it('writes metadata-only tick summary for mocked postgres runtime', async () => {
    const dir = tempDir();
    const outPath = path.join(dir, 'tick.json');
    const env = {
      ASTRANULL_DATABASE_URL: 'postgresql://scheduler:secret@db.example.invalid/astranull',
      ASTRANULL_NOTIFICATION_DELIVERY_MODE: 'metadata_only',
    };

    const { summary, exitCode } = await runNotificationRetrySchedulerTick(
      env,
      {
        dryRun: true,
        tenantIds: ['ten_mock'],
        allTenants: false,
        out: outPath,
        intervalMs: 30_000,
        persistenceMode: 'postgres',
        deliveryMode: 'metadata_only',
        tickNumber: 1,
      },
      {
        createPostgresRuntimeFn: async () => ({
          pool: {
            query: async () => ({ rows: [] }),
          },
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
    assert.equal(summary.artifact_type, 'notification_retry_scheduler_tick');
    const written = readFileSync(outPath, 'utf8');
    assert.ok(!written.includes('hooks.example.invalid'));
    assert.ok(!written.includes('postgresql://'));
  });

  it('runs two ticks in loop mode then stops via shouldContinue', async () => {
    const sleeps = [];
    let ticks = 0;
    const env = {
      ASTRANULL_DATABASE_URL: 'postgresql://scheduler:secret@db.example.invalid/astranull',
    };

    const { tickCount, exitCode } = await runNotificationRetryScheduler(
      env,
      {
        dryRun: true,
        tenantIds: ['ten_loop'],
        allTenants: false,
        out: null,
        once: false,
        intervalMs: 1000,
        persistenceMode: 'postgres',
        deliveryMode: 'metadata_only',
      },
      {
        sleepFn: async (ms) => {
          sleeps.push(ms);
        },
        shouldContinue: () => {
          ticks += 1;
          return ticks < 2;
        },
        createPostgresRuntimeFn: async () => {
          const runtime = {
            pool: { query: async () => ({ rows: [] }) },
            services: {
              notifications: {
                processDueNotificationRetries: async () => ({
                  tenant_id: 'ten_loop',
                  dry_run: true,
                  as_of: '2026-06-01T12:00:00.000Z',
                  delivery_mode: 'metadata_only',
                  due_count: 0,
                  scheduled_not_due_count: 0,
                  network_sends_performed: 0,
                  processed: [],
                }),
              },
            },
            close: async () => {},
          };
          return runtime;
        },
      },
    );

    assert.equal(tickCount, 2);
    assert.equal(exitCode, 0);
    assert.deepEqual(sleeps, [1000]);
  });

  it('returns exit code 1 when a tenant tick records an error', async () => {
    const env = {
      ASTRANULL_DATABASE_URL: 'postgresql://scheduler:secret@db.example.invalid/astranull',
    };

    const { exitCode } = await runNotificationRetrySchedulerTick(
      env,
      {
        dryRun: false,
        tenantIds: ['ten_fail'],
        allTenants: false,
        out: null,
        intervalMs: 60_000,
        persistenceMode: 'postgres',
        deliveryMode: 'metadata_only',
      },
      {
        createPostgresRuntimeFn: async () => ({
          pool: { query: async () => ({ rows: [] }) },
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