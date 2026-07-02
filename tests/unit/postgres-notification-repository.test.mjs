import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  createNotificationRepository,
  mapDeliveryAttemptRow,
  mapNotificationRuleRow,
} from '../../src/persistence/postgres/notificationRepository.mjs';

const CTX = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };
const FIXED_NOW = '2026-06-01T12:00:00.000Z';

function createRecordingPool(handler) {
  const client = {
    queries: [],
    released: false,
    async query(text, params) {
      this.queries.push({ text, params });
      return handler(text, params, this.queries);
    },
    release() {
      this.released = true;
    },
  };
  return {
    client,
    async connect() {
      return client;
    },
  };
}

function dataQueries(client) {
  return client.queries.filter((q) => {
    const t = q.text.trim();
    return t !== 'BEGIN' && t !== 'COMMIT' && t !== 'ROLLBACK' && !t.startsWith("SELECT set_config('app.tenant_id'");
  });
}

function assertTenantWrapped(client, tenantId) {
  assert.equal(client.queries[0].text.trim(), 'BEGIN');
  assert.equal(client.queries[1].text.trim(), "SELECT set_config('app.tenant_id', $1, true)");
  assert.deepEqual(client.queries[1].params, [tenantId]);
  assert.equal(client.queries.at(-1).text.trim(), 'COMMIT');
  assert.equal(client.released, true);
}

describe('postgres notification repository', () => {
  it('maps notification rule rows with triggers_json array', () => {
    const mapped = mapNotificationRuleRow({
      id: 'nrule_1',
      tenant_id: CTX.tenantId,
      channel: 'webhook',
      destination: 'https://hooks.example.invalid/x',
      trigger: 'finding.high_severity',
      triggers_json: ['finding.high_severity', 'agent.offline'],
      enabled: true,
      created_at: new Date(FIXED_NOW),
    });
    assert.deepEqual(mapped.triggers, ['finding.high_severity', 'agent.offline']);
    assert.equal(mapped.created_at, FIXED_NOW);
  });

  it('falls back to legacy trigger column when triggers_json is empty', () => {
    const mapped = mapNotificationRuleRow({
      id: 'nrule_2',
      tenant_id: CTX.tenantId,
      channel: 'in_app',
      destination: '',
      trigger: 'report.ready',
      triggers_json: [],
      enabled: true,
      created_at: FIXED_NOW,
    });
    assert.deepEqual(mapped.triggers, ['report.ready']);
  });

  it('maps delivery attempt rows with ISO timestamps', () => {
    const mapped = mapDeliveryAttemptRow({
      id: 'natt_1',
      rule_id: 'nrule_1',
      channel: 'email',
      destination_preview: 'email:a…@example.com',
      status: 'queued_provider_not_configured',
      reason: 'outbound_provider_not_configured_safe_by_default',
      created_at: new Date(FIXED_NOW),
      attempted_at: null,
    });
    assert.equal(mapped.attempted_at, null);
    assert.equal(mapped.created_at, FIXED_NOW);
  });

  it('createNotificationRule uses parameterized SQL and triggers_json', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/INSERT INTO notification_rules/i.test(sql)) {
        assert.match(sql, /triggers_json/i);
        assert.ok(params.includes(CTX.tenantId));
        const triggersParam = params.find(
          (p) => typeof p === 'string' && p.includes('finding.high_severity'),
        );
        assert.ok(triggersParam);
        return {
          rows: [
            {
              id: 'nrule_new',
              tenant_id: CTX.tenantId,
              channel: 'in_app',
              destination: '',
              trigger: 'finding.high_severity',
              triggers_json: ['finding.high_severity', 'agent.offline'],
              enabled: true,
              created_at: FIXED_NOW,
            },
          ],
        };
      }
      return { rows: [] };
    });

    const repo = createNotificationRepository(pool);
    const created = await repo.createNotificationRule(CTX, {
      id: 'nrule_new',
      channel: 'in_app',
      destination: '',
      triggers: ['finding.high_severity', 'agent.offline'],
      enabled: true,
      created_at: FIXED_NOW,
    });

    assertTenantWrapped(pool.client, CTX.tenantId);
    assert.equal(dataQueries(pool.client).length, 1);
    assert.deepEqual(created.triggers, ['finding.high_severity', 'agent.offline']);
  });

  it('listNotificationEvents loads delivery attempts for tenant-scoped events', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/FROM notification_events/i.test(sql)) {
        assert.ok(params.includes(CTX.tenantId));
        return {
          rows: [
            {
              id: 'nevt_1',
              tenant_id: CTX.tenantId,
              rule_id: null,
              trigger: 'finding.high_severity',
              subject: 'Finding opened',
              metadata_json: { severity: 'high' },
              delivery_status: 'metadata_only',
              created_at: FIXED_NOW,
            },
          ],
        };
      }
      if (/FROM notification_delivery_attempts/i.test(sql)) {
        assert.ok(params.includes(CTX.tenantId));
        assert.ok(params.some((p) => Array.isArray(p) && p.includes('nevt_1')));
        return {
          rows: [
            {
              id: 'natt_nevt_1_nrule_1',
              tenant_id: CTX.tenantId,
              notification_event_id: 'nevt_1',
              rule_id: 'nrule_1',
              channel: 'in_app',
              destination_preview: 'in_app:feed',
              status: 'delivered_in_app',
              reason: 'recorded_in_tenant_in_app_feed',
              created_at: FIXED_NOW,
              attempted_at: FIXED_NOW,
            },
          ],
        };
      }
      return { rows: [] };
    });

    const repo = createNotificationRepository(pool);
    const events = await repo.listNotificationEvents(CTX, { limit: 50 });
    assertTenantWrapped(pool.client, CTX.tenantId);
    assert.equal(dataQueries(pool.client).length, 2);
    assert.equal(events.length, 1);
    assert.deepEqual(events[0].metadata, { severity: 'high' });
    assert.equal(events[0].delivery_attempts.length, 1);
    assert.equal(events[0].delivery_attempts[0].status, 'delivered_in_app');
  });

  it('appendNotificationEvent stores redacted metadata_json with parameterized SQL', async () => {
    const pool = createRecordingPool((sql, params) => {
      if (/INSERT INTO notification_events/i.test(sql)) {
        assert.match(sql, /metadata_json/i);
        assert.ok(params.includes(JSON.stringify({ token: '[REDACTED]' })));
        return {
          rows: [
            {
              id: 'nevt_meta',
              tenant_id: CTX.tenantId,
              rule_id: null,
              trigger: 'agent.offline',
              subject: 'Agent [REDACTED]',
              metadata_json: { token: '[REDACTED]' },
              delivery_status: 'metadata_only',
              created_at: FIXED_NOW,
            },
          ],
        };
      }
      return { rows: [] };
    });

    const repo = createNotificationRepository(pool);
    const event = await repo.appendNotificationEvent(CTX, {
      id: 'nevt_meta',
      trigger: 'agent.offline',
      subject: 'Agent [REDACTED]',
      metadata: { token: '[REDACTED]' },
      delivery_status: 'metadata_only',
      created_at: FIXED_NOW,
    });

    assertTenantWrapped(pool.client, CTX.tenantId);
    assert.deepEqual(event.metadata, { token: '[REDACTED]' });
  });
});
