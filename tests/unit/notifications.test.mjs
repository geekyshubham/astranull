import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { createServer } from '../../src/server.mjs';
import {
  createNotificationRule,
  emitNotification,
  listNotifications,
} from '../../src/services/notifications.mjs';
import { getStore } from '../../src/store.mjs';
import { demoHeaders, request } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';

const demoCtx = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };
const otherCtx = { tenantId: 'ten_other', userId: 'usr_other', role: 'admin' };

describe('notifications', () => {
  it('normalizes a valid webhook rule and ignores provider secret fields', () => {
    freshStore();
    const rule = createNotificationRule(demoCtx, {
      channel: 'WEBHOOK',
      destination: 'https://hooks.example.invalid/path',
      triggers: ['high_scale.state_change', 'finding.high_severity'],
      slack_signing_secret: 'shhh',
      api_key: 'key_material',
    });
    assert.equal(rule.channel, 'webhook');
    assert.deepEqual(rule.triggers, ['high_scale.state_change', 'finding.high_severity']);
    assert.equal(rule.destination, 'https://hooks.example.invalid/path');
    assert.equal(rule.slack_signing_secret, undefined);
    assert.equal(rule.api_key, undefined);
  });

  it('rejects invalid channel and trigger with 400-style errors', () => {
    freshStore();
    const badChannel = createNotificationRule(demoCtx, { channel: 'sms', destination: 'x' });
    assert.equal(badChannel.status, 400);
    assert.equal(badChannel.error, 'invalid_channel');

    const badTrigger = createNotificationRule(demoCtx, {
      channel: 'webhook',
      destination: 'https://x.invalid/h',
      triggers: ['finding.high_severity', 'not.a.real.trigger'],
    });
    assert.equal(badTrigger.status, 400);
    assert.equal(badTrigger.error, 'invalid_trigger');
  });

  it('validates webhook destinations for https and dev-only http hosts', () => {
    freshStore();
    const httpsOk = createNotificationRule(demoCtx, {
      channel: 'webhook',
      destination: 'https://siem.example.com/hook',
      triggers: ['report.ready'],
    });
    assert.ok(httpsOk.id);

    const localOk = createNotificationRule(demoCtx, {
      channel: 'webhook',
      destination: 'http://127.0.0.1:9999/hook',
      triggers: ['report.ready'],
    });
    assert.ok(localOk.id);

    const unsafeHttp = createNotificationRule(demoCtx, {
      channel: 'webhook',
      destination: 'http://public.example.com/hook',
      triggers: ['report.ready'],
    });
    assert.equal(unsafeHttp.status, 400);
    assert.equal(unsafeHttp.error, 'invalid_webhook_destination');
  });

  it('records redacted events, delivery attempts, and safe audits on emit', async () => {
    freshStore();
    createNotificationRule(demoCtx, {
      channel: 'in_app',
      triggers: ['agent.offline'],
    });
    createNotificationRule(demoCtx, {
      channel: 'webhook',
      destination: 'https://hooks.example.invalid/ast_abcdefghijklmnop',
      triggers: ['agent.offline'],
    });
    createNotificationRule(demoCtx, {
      channel: 'email',
      destination: 'alerts@customer.example',
      triggers: ['agent.offline'],
    });

    const event = await emitNotification(demoCtx, {
      trigger: 'agent.offline',
      subject: 'Agent down ast_abcdefghijklmnop',
      metadata: { token: 'ast_abcdefghijklmnop', agent_id: 'ag_1' },
    });

    assert.equal(event.metadata.token, '[REDACTED]');
    assert.match(event.subject, /\[REDACTED\]/);
    assert.equal(event.delivery_attempts.length, 3);

    const inApp = event.delivery_attempts.find((a) => a.channel === 'in_app');
    assert.equal(inApp.status, 'delivered_in_app');
    assert.ok(inApp.attempted_at);

    const webhook = event.delivery_attempts.find((a) => a.channel === 'webhook');
    assert.equal(webhook.status, 'queued_provider_not_configured');
    assert.equal(webhook.attempted_at, null);
    assert.ok(webhook.destination_preview.includes('example.invalid'));
    assert.ok(!webhook.destination_preview.includes('ast_'));

    const email = event.delivery_attempts.find((a) => a.channel === 'email');
    assert.equal(email.status, 'queued_provider_not_configured');

    const audits = getStore().auditLog.filter((a) => a.action.startsWith('notification.'));
    const emitted = audits.filter((a) => a.action === 'notification.event_emitted');
    assert.equal(emitted.length, 1);
    const attempts = audits.filter((a) => a.action === 'notification.delivery_attempt_recorded');
    assert.equal(attempts.length, 3);

    const auditBlob = JSON.stringify(audits);
    assert.ok(!auditBlob.includes('ast_abcdefghijklmnop'));
    assert.ok(!auditBlob.includes('alerts@customer.example'));
  });

  it('does not send webhooks in default delivery mode', async () => {
    freshStore();
    let senderCalls = 0;
    createNotificationRule(demoCtx, {
      channel: 'webhook',
      destination: 'https://hooks.example.invalid/no-send',
      triggers: ['report.ready'],
    });

    const event = await emitNotification(
      demoCtx,
      { trigger: 'report.ready', subject: 'Report', metadata: {} },
      {
        deliveryMode: 'metadata_only',
        webhookSender: () => {
          senderCalls += 1;
          return { ok: true };
        },
      },
    );

    assert.equal(senderCalls, 0);
    assert.equal(event.delivery_attempts[0].status, 'queued_provider_not_configured');
  });

  it('delivers webhooks when delivery mode is enabled and sender succeeds', async () => {
    freshStore();
    const sent = [];
    createNotificationRule(demoCtx, {
      channel: 'webhook',
      destination: 'https://hooks.example.invalid/ok',
      triggers: ['report.ready'],
    });

    const event = await emitNotification(
      demoCtx,
      {
        trigger: 'report.ready',
        subject: 'Ready ast_secretvalue',
        metadata: { token: 'ast_secretvalue' },
      },
      {
        deliveryMode: 'webhook',
        webhookSender: async (destination, body) => {
          sent.push({ destination, body });
          return { ok: true, status: 202 };
        },
      },
    );

    assert.equal(sent.length, 1);
    assert.equal(sent[0].body.event_id, event.id);
    assert.equal(sent[0].body.metadata.token, '[REDACTED]');
    assert.equal(event.delivery_attempts[0].status, 'delivered_provider');
    assert.equal(event.delivery_attempts[0].attempt_number, 1);
    assert.equal(event.delivery_attempts[0].max_attempts, 3);

    const audits = getStore().auditLog.filter((a) => a.action.startsWith('notification.'));
    const blob = JSON.stringify(audits);
    assert.ok(!blob.includes('hooks.example.invalid/ok'));
    assert.ok(!blob.includes('ast_secretvalue'));
  });

  it('records retry metadata when webhook delivery fails', async () => {
    freshStore();
    createNotificationRule(demoCtx, {
      channel: 'webhook',
      destination: 'https://hooks.example.invalid/fail',
      triggers: ['report.ready'],
    });

    const event = await emitNotification(
      demoCtx,
      { trigger: 'report.ready', subject: 'Report', metadata: {} },
      {
        deliveryMode: 'webhook',
        webhookSender: async () => ({ ok: false, error: 'webhook_http_error', status: 503 }),
      },
    );

    const attempt = event.delivery_attempts[0];
    assert.equal(attempt.status, 'provider_retry_scheduled');
    assert.equal(attempt.attempt_number, 1);
    assert.equal(attempt.max_attempts, 3);
    assert.ok(attempt.next_retry_at);
    assert.equal(attempt.exhausted, false);
  });

  it('scopes listNotifications to the requesting tenant', async () => {
    freshStore();
    getStore().tenants.push({ id: 'ten_other', name: 'Other' });

    createNotificationRule(demoCtx, {
      channel: 'slack',
      destination: '#demo-alerts',
      triggers: ['safe_test.completed'],
    });
    createNotificationRule(otherCtx, {
      channel: 'slack',
      destination: '#other-alerts',
      triggers: ['safe_test.completed'],
    });

    await emitNotification(demoCtx, {
      trigger: 'safe_test.completed',
      subject: 'demo run',
      metadata: { run_id: 'run_demo' },
    });
    await emitNotification(otherCtx, {
      trigger: 'safe_test.completed',
      subject: 'other run',
      metadata: { run_id: 'run_other' },
    });

    const listed = listNotifications(demoCtx);
    assert.equal(listed.rules.length, 1);
    assert.equal(listed.rules[0].destination, undefined);
    assert.equal(listed.rules[0].destination_preview, 'slack:#demo-alerts');
    assert.ok(listed.events.every((e) => e.tenant_id === 'ten_demo'));
    assert.equal(listed.events.length, 1);
  });
});

describe('POST /v1/notifications', () => {
  let baseUrl;
  let server;

  before(() => {
    freshStore();
    process.env.ASTRANULL_NO_PERSIST = '1';
    server = createServer();
    server.listen(0);
    const { port } = server.address();
    baseUrl = `http://127.0.0.1:${port}`;
  });

  after(() => {
    server?.close();
    delete process.env.ASTRANULL_NO_PERSIST;
  });

  it('returns HTTP 400 for invalid notification rules', async () => {
    const res = await request(baseUrl, 'POST', '/v1/notifications', {
      headers: demoHeaders('admin'),
      body: { channel: 'sms', destination: 'x' },
    });
    assert.equal(res.status, 400);
    assert.equal(res.json.error, 'invalid_channel');
  });

  it('returns destination previews, not raw destinations, after creating rules over HTTP', async () => {
    freshStore();
    const res = await request(baseUrl, 'POST', '/v1/notifications', {
      headers: demoHeaders('admin'),
      body: {
        channel: 'webhook',
        destination: 'https://hooks.example.invalid/secret-path',
        triggers: ['report.ready'],
      },
    });
    assert.equal(res.status, 201);
    assert.equal(res.json.destination, undefined);
    assert.equal(res.json.destination_preview, 'webhook://hooks.example.invalid…');
    assert.equal(JSON.stringify(res.json).includes('secret-path'), false);
  });

  it('processes due retries through HTTP as metadata-only and omits delivery records', async () => {
    freshStore();
    const denied = await request(baseUrl, 'POST', '/v1/notifications/retries/process', {
      headers: demoHeaders('viewer'),
      body: { dry_run: true },
    });
    assert.equal(denied.status, 403);
    assert.equal(denied.json.permission, 'notification:write');

    createNotificationRule(demoCtx, {
      channel: 'webhook',
      destination: 'https://hooks.example.invalid/ast_v1.secret',
      triggers: ['report.ready'],
    });
    const event = await emitNotification(demoCtx, {
      trigger: 'report.ready',
      subject: 'Report ready',
      metadata: { report_id: 'rpt_1' },
    });
    event.delivery_attempts[0] = {
      ...event.delivery_attempts[0],
      status: 'provider_retry_scheduled',
      reason: 'webhook_http_error',
      provider_error: 'webhook_http_error',
      attempt_number: 1,
      max_attempts: 2,
      next_retry_at: '2026-07-03T00:00:00.000Z',
    };

    const processed = await request(baseUrl, 'POST', '/v1/notifications/retries/process', {
      headers: demoHeaders('admin'),
      body: { as_of: '2026-07-03T00:01:00.000Z' },
    });
    assert.equal(processed.status, 200);
    assert.equal(processed.json.due_count, 1);
    assert.equal(processed.json.processed.length, 1);
    assert.equal(processed.json.processed[0].status, 'provider_failed_dlq');
    assert.equal(JSON.stringify(processed.json).includes('delivery_record'), false);
    assert.equal(JSON.stringify(processed.json).includes('ast_v1.secret'), false);

    const listed = await request(baseUrl, 'GET', '/v1/notifications', {
      headers: demoHeaders('admin'),
    });
    const attempts = listed.json.events[0].delivery_attempts;
    assert.equal(attempts.at(-1).status, 'provider_failed_dlq');
    assert.equal(attempts.at(-1).exhausted, true);
  });

  it('redrives DLQ attempts through HTTP as metadata-only and omits delivery records', async () => {
    freshStore();
    const denied = await request(baseUrl, 'POST', '/v1/notifications/dlq/redrive', {
      headers: demoHeaders('viewer'),
      body: { attempt_ids: ['natt_dlq'] },
    });
    assert.equal(denied.status, 403);
    assert.equal(denied.json.permission, 'notification:write');

    createNotificationRule(demoCtx, {
      channel: 'webhook',
      destination: 'https://hooks.example.invalid/ast_v1.secret',
      triggers: ['report.ready'],
    });
    const event = await emitNotification(demoCtx, {
      trigger: 'report.ready',
      subject: 'Report ready',
      metadata: { report_id: 'rpt_1' },
    });
    event.delivery_attempts[0] = {
      ...event.delivery_attempts[0],
      id: 'natt_dlq',
      status: 'provider_failed_dlq',
      reason: 'webhook_http_error',
      provider_error: 'webhook_http_error',
      attempt_number: 3,
      max_attempts: 3,
      exhausted: true,
    };

    const redriven = await request(baseUrl, 'POST', '/v1/notifications/dlq/redrive', {
      headers: demoHeaders('admin'),
      body: { attempt_ids: ['natt_dlq'] },
    });
    assert.equal(redriven.status, 200);
    assert.equal(redriven.json.requeued_count, 1);
    assert.equal(redriven.json.skipped_count, 0);
    assert.equal(redriven.json.still_dlq_count, 0);
    assert.equal(redriven.json.processed[0].status, 'provider_retry_scheduled');
    assert.equal(JSON.stringify(redriven.json).includes('delivery_record'), false);
    assert.equal(JSON.stringify(redriven.json).includes('ast_v1.secret'), false);

    const listed = await request(baseUrl, 'GET', '/v1/notifications', {
      headers: demoHeaders('admin'),
    });
    const attempts = listed.json.events[0].delivery_attempts;
    assert.equal(attempts.at(-1).status, 'provider_retry_scheduled');
    assert.equal(attempts.at(-1).attempt_number, 1);

    const audits = getStore().auditLog.filter((a) => a.action === 'notification.dlq_redrive');
    assert.equal(audits.length, 1);
    assert.equal(audits[0].metadata.requeued_count, 1);
  });
});
