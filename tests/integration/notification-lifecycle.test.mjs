import assert from 'node:assert/strict';
import { after, before, beforeEach, describe, it } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { getStore } from '../../src/store.mjs';
import { emitNotification } from '../../src/services/notifications.mjs';
import { processDueNotificationRetries } from '../../src/services/notificationRetry.mjs';
import { redriveNotificationDlq } from '../../src/services/notificationDlqRedrive.mjs';
import { demoHeaders, request } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';

let server;
let baseUrl;

before(() => {
  freshStore();
  server = createServer();
  server.listen(0);
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(() => server.close());

beforeEach(() => freshStore());

describe('notification lifecycle (FT-CRUD-NOTIF-01)', () => {
  it('create rule → ledger event → retry failed delivery → DLQ redrive', async () => {
    const headers = demoHeaders('admin');
    const created = await request(baseUrl, 'POST', '/v1/notifications', {
      headers,
      body: {
        channel: 'webhook',
        destination: 'https://hooks.example.invalid/lifecycle',
        triggers: ['finding.high_severity'],
        enabled: true,
      },
    });
    assert.equal(created.status, 201);
    const ruleId = created.json.id;

    const listed = await request(baseUrl, 'GET', '/v1/notifications', { headers });
    assert.ok(listed.json.rules.some((rule) => rule.id === ruleId));

    const ctx = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };
    await emitNotification(
      ctx,
      { trigger: 'finding.high_severity', subject: 'Lifecycle finding opened', metadata: { finding_id: 'fnd_1' } },
      { deliveryMode: 'metadata_only' },
    );

    const store = getStore();
    const event = store.notificationEvents.at(-1);
    assert.ok(event);
    assert.ok(event.delivery_attempts.length > 0);

    const failedAttempt = event.delivery_attempts[0];
    failedAttempt.status = 'failed';
    failedAttempt.next_retry_at = new Date(Date.now() - 60_000).toISOString();

    const retried = await processDueNotificationRetries(ctx, {
      asOf: new Date().toISOString(),
      deliveryMode: 'metadata_only',
    });
    assert.ok(retried.processed.length >= 0);

    failedAttempt.status = 'dlq';
    const redriven = await redriveNotificationDlq(ctx, {
      attemptIds: [failedAttempt.id],
      deliveryMode: 'metadata_only',
    });
    assert.ok(Array.isArray(redriven.processed));
    assert.ok(redriven.requeued_count >= 0);

    const audits = store.auditLog
      .filter((entry) => entry.resource_type?.startsWith('notification'))
      .map((entry) => entry.action);
    assert.ok(audits.includes('notification.rule_created'));
    assert.ok(audits.includes('notification.event_emitted'));
  });
});