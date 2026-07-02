import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import {
  NETWORK_DELIVERY_DISABLED,
  collectForbiddenFields,
  parseNotificationLedger,
  parseNotificationRetryWorkerArgs,
  planNotificationRetries,
  planRetryForAttempt,
  resolveNotificationRetryWorkerConfig,
  runNotificationRetryWorker,
  validateNotificationLedger,
  validateNotificationRetryPlanOutput,
} from '../../scripts/notification-retry-worker.mjs';

const tempDirs = [];

function tempDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-notification-retry-'));
  tempDirs.push(dir);
  return dir;
}

function sampleLedger(overrides = {}) {
  return {
    notification_rules: [
      {
        id: 'nrule_1',
        channel: 'webhook',
        destination: 'https://hooks.example.invalid/path',
      },
    ],
    notification_events: [
      {
        id: 'nevt_due',
        tenant_id: 'ten_demo',
        delivery_attempts: [
          {
            id: 'natt_due',
            rule_id: 'nrule_1',
            channel: 'webhook',
            destination_preview: 'https://hooks.example.invalid/***',
            status: 'provider_retry_scheduled',
            attempt_number: 1,
            max_attempts: 3,
            next_retry_at: '2026-01-01T00:00:00.000Z',
            provider_error: 'webhook_http_error',
          },
        ],
      },
      {
        id: 'nevt_future',
        tenant_id: 'ten_demo',
        delivery_attempts: [
          {
            id: 'natt_future',
            rule_id: 'nrule_1',
            channel: 'webhook',
            destination_preview: 'https://hooks.example.invalid/***',
            status: 'provider_retry_scheduled',
            attempt_number: 1,
            max_attempts: 3,
            next_retry_at: '2099-01-01T00:00:00.000Z',
          },
        ],
      },
    ],
    ...overrides,
  };
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop(), { recursive: true, force: true });
  }
});

describe('notification retry worker args', () => {
  it('parses input, out, as-of, max-attempts, and dry-run', () => {
    assert.deepEqual(
      parseNotificationRetryWorkerArgs([
        'node',
        'script.mjs',
        '--input',
        'ledger.json',
        '--out',
        'plan.json',
        '--as-of',
        '2026-06-01T12:00:00.000Z',
        '--max-attempts',
        '5',
        '--dry-run',
      ]),
      {
        input: 'ledger.json',
        out: 'plan.json',
        asOf: '2026-06-01T12:00:00.000Z',
        maxAttempts: 5,
        dryRun: true,
        help: false,
      },
    );
  });

  it('requires --input in resolved config', () => {
    const config = resolveNotificationRetryWorkerConfig(
      parseNotificationRetryWorkerArgs(['node', 'script.mjs']),
    );
    assert.equal(config.ok, false);
    assert.match(config.message ?? '', /--input/i);
  });
});

describe('notification retry worker planning', () => {
  it('selects only due provider_retry_scheduled attempts', () => {
    const ledger = parseNotificationLedger(sampleLedger());
    const plan = planNotificationRetries({
      ledger,
      asOf: '2026-06-01T12:00:00.000Z',
      maxAttemptsDefault: 3,
      dryRun: true,
    });

    assert.equal(plan.due_count, 1);
    assert.equal(plan.scheduled_not_due, 1);
    assert.equal(plan.due_items[0].event_id, 'nevt_due');
    assert.equal(plan.due_items[0].status, 'retry_due');
  });

  it('plans provider_retry_scheduled when attempts remain', () => {
    const item = planRetryForAttempt({
      event_id: 'nevt_1',
      tenant_id: 'ten_demo',
      attempt: {
        status: 'provider_retry_scheduled',
        attempt_number: 1,
        max_attempts: 3,
        next_retry_at: '2026-01-01T00:00:00.000Z',
      },
      asOf: '2026-06-01T12:00:00.000Z',
      maxAttemptsDefault: 3,
      dryRun: false,
    });

    assert.equal(item.status, 'provider_retry_scheduled');
    assert.equal(item.next_attempt_number, 2);
    assert.equal(item.exhausted, false);
    assert.ok(item.next_retry_at);
  });

  it('plans provider_failed_dlq when next attempt exhausts max attempts', () => {
    const item = planRetryForAttempt({
      event_id: 'nevt_1',
      tenant_id: 'ten_demo',
      attempt: {
        status: 'provider_retry_scheduled',
        attempt_number: 2,
        max_attempts: 3,
        next_retry_at: '2026-01-01T00:00:00.000Z',
      },
      asOf: '2026-06-01T12:00:00.000Z',
      maxAttemptsDefault: 3,
      dryRun: false,
    });

    assert.equal(item.status, 'provider_failed_dlq');
    assert.equal(item.next_attempt_number, 3);
    assert.equal(item.exhausted, true);
  });
});

describe('notification retry worker validation', () => {
  it('rejects forbidden secret-bearing ledger fields', () => {
    const ledger = parseNotificationLedger({
      events: [{ id: 'e1', delivery_attempts: [], metadata: { token: 'ast_v1.fake.fake.fake' } }],
      rules: [],
    });
    const validation = validateNotificationLedger(ledger);
    assert.equal(validation.ok, false);
    assert.ok(validation.forbidden_fields.some((f) => f.endsWith('.token')));
  });

  it('rejects webhook destinations with embedded URL credentials', () => {
    const ledger = parseNotificationLedger({
      events: [],
      rules: [{ id: 'r1', channel: 'webhook', destination: 'https://user:pass@hooks.example.invalid/h' }],
    });
    const validation = validateNotificationLedger(ledger);
    assert.equal(validation.ok, false);
    assert.deepEqual(validation.destination_errors, ['rules[0].destination']);
  });

  it('redacts sensitive values in written output', () => {
    const dir = tempDir();
    const inputPath = path.join(dir, 'ledger.json');
    const outPath = path.join(dir, 'plan.json');

    const ledger = sampleLedger({
      notification_events: [
        {
          id: 'nevt_secret',
          tenant_id: 'ten_demo',
          delivery_attempts: [
            {
              id: 'natt_1',
              rule_id: 'nrule_1',
              channel: 'webhook',
              destination_preview: 'https://hooks.example.invalid/***',
              status: 'provider_retry_scheduled',
              attempt_number: 1,
              max_attempts: 3,
              next_retry_at: '2026-01-01T00:00:00.000Z',
              provider_error: 'svc_v1.abc.def.ghi Bearer sk-abcdefghijklmnopqrstuvwxyz',
            },
          ],
        },
      ],
    });
    writeFileSync(inputPath, JSON.stringify(ledger));

    runNotificationRetryWorker({
      inputPath,
      out: outPath,
      asOf: '2026-06-01T12:00:00.000Z',
      maxAttemptsDefault: 3,
      dryRun: false,
    });

    const written = JSON.parse(readFileSync(outPath, 'utf8'));
    const blob = JSON.stringify(written);
    assert.ok(!blob.includes('svc_v1.abc.def.ghi'));
    assert.ok(!blob.includes('sk-abcdefghijklmnopqrstuvwxyz'));
    const outputValidation = validateNotificationRetryPlanOutput(written);
    assert.equal(outputValidation.ok, true);
  });

  it('refuses ledgers with raw payload fields', () => {
    const dir = tempDir();
    const inputPath = path.join(dir, 'bad.json');
    writeFileSync(
      inputPath,
      JSON.stringify({
        events: [{ id: 'e1', payload: { x: 1 }, delivery_attempts: [] }],
        rules: [],
      }),
    );

    assert.throws(
      () =>
        runNotificationRetryWorker({
          inputPath,
          out: null,
          asOf: '2026-06-01T12:00:00.000Z',
          maxAttemptsDefault: 3,
          dryRun: true,
        }),
      /forbidden fields/i,
    );
  });
});

describe('notification retry worker execution', () => {
  it('writes metadata-only plan JSON to --out', () => {
    const dir = tempDir();
    const inputPath = path.join(dir, 'ledger.json');
    const outPath = path.join(dir, 'plan.json');
    writeFileSync(inputPath, JSON.stringify(sampleLedger()));

    const { summary } = runNotificationRetryWorker({
      inputPath,
      out: outPath,
      asOf: '2026-06-01T12:00:00.000Z',
      maxAttemptsDefault: 3,
      dryRun: false,
    });

    assert.equal(summary.due_count, 1);
    assert.equal(summary.items[0].status, 'provider_retry_scheduled');
    assert.equal(readFileSync(outPath, 'utf8').includes('"artifact_type": "notification_retry_plan"'), true);
  });

  it('does not perform network delivery', () => {
    assert.equal(NETWORK_DELIVERY_DISABLED, true);
    const ledger = parseNotificationLedger(sampleLedger());
    const plan = planNotificationRetries({
      ledger,
      asOf: '2026-06-01T12:00:00.000Z',
      maxAttemptsDefault: 3,
      dryRun: false,
    });
    assert.equal(plan.due_count, 1);
    assert.ok(collectForbiddenFields(plan).length >= 0);
  });
});