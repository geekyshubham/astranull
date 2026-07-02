import { withTenantContext } from './tenantContext.mjs';

const RULE_COLUMNS = `id, tenant_id, channel, destination, trigger, triggers_json, enabled, created_at`;

function toIso(value) {
  if (value == null) return value;
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

function parseTriggersJson(row) {
  const raw = row.triggers_json;
  if (Array.isArray(raw) && raw.length > 0) {
    return raw.map((t) => String(t));
  }
  if (typeof raw === 'string') {
    try {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed) && parsed.length > 0) {
        return parsed.map((t) => String(t));
      }
    } catch {
      /* fall through */
    }
  }
  if (row.trigger && String(row.trigger).trim()) {
    return [String(row.trigger).trim()];
  }
  return [];
}

/**
 * @param {Record<string, unknown> | null | undefined} row
 */
export function mapNotificationRuleRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    channel: row.channel,
    destination: row.destination ?? '',
    triggers: parseTriggersJson(row),
    enabled: row.enabled !== false,
    created_at: toIso(row.created_at),
  };
}

/**
 * @param {Record<string, unknown> | null | undefined} row
 */
export function mapDeliveryAttemptRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    rule_id: row.rule_id,
    channel: row.channel,
    destination_preview: row.destination_preview ?? '',
    status: row.status,
    reason: row.reason ?? null,
    created_at: toIso(row.created_at),
    attempted_at: row.attempted_at ? toIso(row.attempted_at) : null,
  };
}

/**
 * @param {Record<string, unknown> | null | undefined} row
 * @param {import('./notificationRepository.mjs').mapDeliveryAttemptRow[]} attempts
 */
export function mapNotificationEventRow(row, attempts = []) {
  if (!row) return null;
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    trigger: row.trigger,
    subject: row.subject ?? '',
    metadata: row.metadata_json && typeof row.metadata_json === 'object' ? row.metadata_json : {},
    delivery_attempts: attempts,
    created_at: toIso(row.created_at),
  };
}

/**
 * @param {import('pg').Pool} pool
 */
export function createNotificationRepository(pool) {
  return {
    /**
     * @param {{ tenantId: string }} ctx
     */
    async listNotificationRules(ctx) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `SELECT ${RULE_COLUMNS}
           FROM notification_rules
           WHERE tenant_id = $1
           ORDER BY created_at ASC`,
          [tenantId],
        );
        return rows.map(mapNotificationRuleRow);
      });
    },

    /**
     * @param {{ tenantId: string }} ctx
     * @param {{ limit?: number }} [options]
     */
    async listNotificationEvents(ctx, options = {}) {
      const tenantId = ctx.tenantId;
      const limit = Math.min(Math.max(Number(options.limit) || 100, 1), 500);
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows: eventRows } = await client.query(
          `SELECT id, tenant_id, rule_id, trigger, subject, metadata_json, delivery_status, created_at
           FROM notification_events
           WHERE tenant_id = $1
           ORDER BY created_at DESC
           LIMIT $2`,
          [tenantId, limit],
        );
        if (eventRows.length === 0) return [];

        const eventIds = eventRows.map((r) => r.id);
        const { rows: attemptRows } = await client.query(
          `SELECT id, tenant_id, notification_event_id, rule_id, channel, destination_preview,
                  status, reason, created_at, attempted_at
           FROM notification_delivery_attempts
           WHERE tenant_id = $1 AND notification_event_id = ANY($2::text[])
           ORDER BY created_at ASC`,
          [tenantId, eventIds],
        );

        const attemptsByEvent = new Map();
        for (const row of attemptRows) {
          const eventId = row.notification_event_id;
          if (!attemptsByEvent.has(eventId)) attemptsByEvent.set(eventId, []);
          attemptsByEvent.get(eventId).push(mapDeliveryAttemptRow(row));
        }

        const events = eventRows.map((row) =>
          mapNotificationEventRow(row, attemptsByEvent.get(row.id) ?? []),
        );
        return events.reverse();
      });
    },

    /**
     * @param {{ tenantId: string }} ctx
     * @param {Record<string, unknown>} record
     */
    async createNotificationRule(ctx, record) {
      const tenantId = ctx.tenantId;
      const triggers = Array.isArray(record.triggers) ? record.triggers : [];
      const legacyTrigger = triggers[0] ?? null;

      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO notification_rules (
             id, tenant_id, channel, destination, trigger, triggers_json, enabled, created_at
           )
           VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8::timestamptz)
           RETURNING ${RULE_COLUMNS}`,
          [
            record.id,
            tenantId,
            record.channel,
            record.destination ?? '',
            legacyTrigger,
            JSON.stringify(triggers),
            record.enabled !== false,
            record.created_at,
          ],
        );
        return mapNotificationRuleRow(rows[0]);
      });
    },

    /**
     * @param {{ tenantId: string }} ctx
     * @param {Record<string, unknown>} event
     */
    async appendNotificationEvent(ctx, event) {
      const tenantId = ctx.tenantId;
      return withTenantContext(pool, tenantId, async (client) => {
        const { rows } = await client.query(
          `INSERT INTO notification_events (
             id, tenant_id, rule_id, trigger, subject, metadata_json, delivery_status, created_at
           )
           VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8::timestamptz)
           RETURNING id, tenant_id, rule_id, trigger, subject, metadata_json, delivery_status, created_at`,
          [
            event.id,
            tenantId,
            event.rule_id ?? null,
            event.trigger,
            event.subject,
            JSON.stringify(event.metadata ?? {}),
            event.delivery_status ?? 'metadata_only',
            event.created_at,
          ],
        );
        return mapNotificationEventRow(rows[0], []);
      });
    },

    /**
     * @param {{ tenantId: string }} ctx
     * @param {string} notificationEventId
     * @param {Record<string, unknown>[]} attempts
     */
    async appendDeliveryAttempts(ctx, notificationEventId, attempts) {
      const tenantId = ctx.tenantId;
      if (!attempts.length) return [];

      return withTenantContext(pool, tenantId, async (client) => {
        const inserted = [];
        for (const attempt of attempts) {
          const { rows } = await client.query(
            `INSERT INTO notification_delivery_attempts (
               id, tenant_id, notification_event_id, rule_id, channel, destination_preview,
               status, reason, created_at, attempted_at
             )
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::timestamptz, $10::timestamptz)
             RETURNING id, tenant_id, notification_event_id, rule_id, channel, destination_preview,
                       status, reason, created_at, attempted_at`,
            [
              attempt.id,
              tenantId,
              notificationEventId,
              attempt.rule_id,
              attempt.channel,
              attempt.destination_preview,
              attempt.status,
              attempt.reason ?? null,
              attempt.created_at,
              attempt.attempted_at ?? null,
            ],
          );
          inserted.push(mapDeliveryAttemptRow(rows[0]));
        }
        return inserted;
      });
    },
  };
}
