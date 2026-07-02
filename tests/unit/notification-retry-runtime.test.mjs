import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';
import {
  NOTIFICATION_REPOSITORY_METHODS,
  createPostgresNotificationServices,
} from '../../src/persistence/postgres/notificationServiceAdapters.mjs';
import {
  buildMetadataOnlyRetryDeliveryAttempt,
  buildWebhookRetryDeliveryAttempt,
  collectDueNotificationRetries,
  processDueNotificationRetryBatch,
} from '../../src/lib/notificationRetry.mjs';
import { WEBHOOK_DELIVERY_MODE } from '../../src/lib/notificationDelivery.mjs';
import {
  createNotificationRule,
  emitNotification,
} from '../../src/services/notifications.mjs';
import { processDueNotificationRetries } from '../../src/services/notificationRetry.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';

const demoCtx = { tenantId: 'ten_demo', userId: 'usr_1', role: 'admin' };
const AS_OF = '2026-06-01T12:00:00.000Z';

afterEach(() => {
  freshStore();
});

function sampleDueEvent(overrides = {}) {
  return {
    id: 'nevt_1',
    tenant_id: 'ten_demo',
    trigger: 'report.ready',
    subject: '[REDACTED]',
    metadata: { token: '[REDACTED]' },
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
        next_retry_at: '2026-06-01T11:00:00.000Z',
        provider_error: 'webhook_http_error',
      },
    ],
    ...overrides,
  };
}

describe('notification retry runtime library', () => {
  it('collects only due latest attempts per rule', () => {
    const events = [
      sampleDueEvent(),
      {
        id: 'nevt_future',
        delivery_attempts: [
          {
            id: 'natt_future',
            rule_id: 'nrule_1',
            channel: 'webhook',
            status: 'provider_retry_scheduled',
            attempt_number: 1,
            max_attempts: 3,
            next_retry_at: '2099-01-01T00:00:00.000Z',
          },
        ],
      },
      {
        id: 'nevt_superseded',
        delivery_attempts: [
          {
            id: 'natt_old',
            rule_id: 'nrule_1',
            channel: 'webhook',
            status: 'provider_retry_scheduled',
            attempt_number: 1,
            max_attempts: 3,
            next_retry_at: '2020-01-01T00:00:00.000Z',
          },
          {
            id: 'natt_new',
            rule_id: 'nrule_1',
            channel: 'webhook',
            status: 'delivered_provider',
            attempt_number: 2,
            max_attempts: 3,
          },
        ],
      },
    ];

    const collected = collectDueNotificationRetries(events, AS_OF);
    assert.equal(collected.due_count, 1);
    assert.equal(collected.scheduled_not_due, 1);
    assert.equal(collected.due_items[0].event.id, 'nevt_1');
  });

  it('metadata-only retry schedules next attempt or DLQ at max attempts', () => {
    const scheduled = buildMetadataOnlyRetryDeliveryAttempt({
      attempt: { rule_id: 'nrule_1', channel: 'webhook', attempt_number: 1, max_attempts: 3 },
      now: AS_OF,
      newAttemptId: 'natt_2',
    });
    assert.equal(scheduled.status, 'provider_retry_scheduled');
    assert.equal(scheduled.attempt_number, 2);
    assert.ok(scheduled.next_retry_at);

    const dlq = buildMetadataOnlyRetryDeliveryAttempt({
      attempt: { rule_id: 'nrule_1', channel: 'webhook', attempt_number: 2, max_attempts: 3 },
      now: AS_OF,
      newAttemptId: 'natt_3',
    });
    assert.equal(dlq.status, 'provider_failed_dlq');
    assert.equal(dlq.exhausted, true);
  });

  it('webhook retry uses redacted body and injected sender', async () => {
    const sent = [];
    const record = await buildWebhookRetryDeliveryAttempt({
      attempt: {
        rule_id: 'nrule_1',
        channel: 'webhook',
        attempt_number: 1,
        max_attempts: 3,
      },
      event: {
        id: 'nevt_1',
        trigger: 'report.ready',
        subject: '[REDACTED]',
        metadata: { token: '[REDACTED]' },
        created_at: '2026-06-01T10:00:00.000Z',
      },
      rule: {
        id: 'nrule_1',
        channel: 'webhook',
        destination: 'https://hooks.example.invalid/retry',
      },
      now: AS_OF,
      newAttemptId: 'natt_retry',
      webhookSender: async (destination, body) => {
        sent.push({ destination, body });
        return { ok: true, status: 202 };
      },
    });

    assert.equal(sent.length, 1);
    assert.equal(sent[0].body.metadata.token, '[REDACTED]');
    assert.equal(record.status, 'delivered_provider');
    assert.equal(record.attempt_number, 2);
  });

  it('default delivery mode batch performs no network sends', async () => {
    const fetchCalls = [];
    const batch = await processDueNotificationRetryBatch({
      deliveryMode: 'metadata_only',
      events: [sampleDueEvent()],
      rules: [
        { id: 'nrule_1', channel: 'webhook', destination: 'https://hooks.example.invalid/x' },
      ],
      asOf: AS_OF,
      fetchFn: async () => {
        fetchCalls.push(1);
        return { ok: true, status: 200 };
      },
    });

    assert.equal(batch.network_sends_performed, 0);
    assert.equal(batch.processed.length, 1);
    assert.equal(batch.processed[0].status, 'provider_retry_scheduled');
    assert.equal(fetchCalls.length, 0);
  });
});

describe('dev notification retry service', () => {
  it('persists metadata-only retry attempts and audits without destinations', async () => {
    freshStore();
    createNotificationRule(demoCtx, {
      channel: 'webhook',
      destination: 'https://hooks.example.invalid/fail',
      triggers: ['report.ready'],
    });

    await emitNotification(
      demoCtx,
      { trigger: 'report.ready', subject: 'secret ast_abcdefghijklmnop', metadata: { token: 'ast_abcdefghijklmnop' } },
      {
        deliveryMode: WEBHOOK_DELIVERY_MODE,
        webhookSender: async () => ({ ok: false, error: 'webhook_http_error', status: 503 }),
      },
    );

    const eventBefore = getStore().notificationEvents[0];
    eventBefore.delivery_attempts[0].next_retry_at = '2026-06-01T11:00:00.000Z';

    const result = await processDueNotificationRetries(demoCtx, {
      asOf: AS_OF,
      deliveryMode: 'metadata_only',
      now: AS_OF,
      newId: () => 'natt_retry_2',
    });

    assert.equal(result.network_sends_performed, 0);
    assert.equal(result.processed.length, 1);
    const eventAfter = getStore().notificationEvents[0];
    assert.equal(eventAfter.delivery_attempts.length, 2);
    assert.equal(eventAfter.delivery_attempts[1].status, 'provider_retry_scheduled');
    assert.equal(eventAfter.delivery_attempts[1].attempt_number, 2);

    const audits = getStore().auditLog.filter((a) => a.action === 'notification.delivery_attempt_recorded');
    const blob = JSON.stringify(audits);
    assert.ok(!blob.includes('hooks.example.invalid'));
    assert.ok(!blob.includes('ast_abcdefghijklmnop'));
  });

  it('dry-run does not append attempts', async () => {
    freshStore();
    getStore().notificationEvents.push(sampleDueEvent());

    const result = await processDueNotificationRetries(demoCtx, {
      asOf: AS_OF,
      dryRun: true,
      deliveryMode: 'metadata_only',
    });

    assert.equal(result.processed[0].status, 'retry_due');
    assert.equal(getStore().notificationEvents[0].delivery_attempts.length, 1);
  });
});

describe('postgres notification retry service adapter', () => {
  it('exposes processDueNotificationRetries on the service surface', () => {
    assert.ok(
      createPostgresNotificationServices({
        notifications: Object.fromEntries(
          NOTIFICATION_REPOSITORY_METHODS.map((method) => [method, async () => []]),
        ),
        audit: { appendAuditEvent: async () => {} },
      }).processDueNotificationRetries,
    );
  });

  it('appends retry attempts and audits in apply mode', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'usr_1', role: 'admin' };
    const rule = {
      id: 'nrule_1',
      channel: 'webhook',
      destination: 'https://hooks.example.invalid/x',
      triggers: ['report.ready'],
      enabled: true,
    };
    const appendCalls = [];
    const auditEvents = [];

    const notifications = createPostgresNotificationServices(
      {
        notifications: {
          listNotificationRules: async () => [rule],
          listNotificationEvents: async () => [
            {
              id: 'nevt_1',
              tenant_id: ctx.tenantId,
              trigger: 'report.ready',
              subject: '[REDACTED]',
              metadata: {},
              created_at: '2026-06-01T10:00:00.000Z',
              delivery_attempts: [
                {
                  id: 'natt_1',
                  rule_id: 'nrule_1',
                  channel: 'webhook',
                  status: 'provider_retry_scheduled',
                  attempt_number: 2,
                  max_attempts: 3,
                  next_retry_at: '2026-06-01T11:00:00.000Z',
                },
              ],
            },
          ],
          createNotificationRule: async () => rule,
          appendNotificationEvent: async () => ({}),
          appendDeliveryAttempts: async (_c, eventId, attempts) => {
            appendCalls.push({ eventId, attempts });
            return attempts;
          },
        },
        audit: {
          appendAuditEvent: async (entry) => {
            auditEvents.push(entry);
            return entry;
          },
        },
      },
      { newId: () => 'natt_pg_retry', deliveryMode: 'metadata_only' },
    );

    const result = await notifications.processDueNotificationRetries(ctx, {
      asOf: AS_OF,
      now: AS_OF,
    });

    assert.equal(result.due_count, 1);
    assert.equal(result.processed[0].status, 'provider_failed_dlq');
    assert.equal(appendCalls.length, 1);
    assert.equal(appendCalls[0].attempts[0].id, 'natt_pg_retry');
    assert.ok(auditEvents.some((a) => a.metadata?.retry === true));
  });
});