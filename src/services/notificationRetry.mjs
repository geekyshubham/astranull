import { audit } from '../audit.mjs';
import { newId } from '../lib/ids.mjs';
import { resolveNotificationDeliveryMode } from '../lib/notificationDelivery.mjs';
import { processDueNotificationRetryBatch } from '../lib/notificationRetry.mjs';
import { getStore, persistStore } from '../store.mjs';

function ensure() {
  const store = getStore();
  if (!store.notificationRules) store.notificationRules = [];
  if (!store.notificationEvents) store.notificationEvents = [];
  return store;
}

/**
 * @param {{ tenantId: string, userId?: string | null, role?: string | null }} ctx
 * @param {{
 *   asOf?: string,
 *   dryRun?: boolean,
 *   deliveryMode?: string,
 *   now?: string,
 *   webhookSender?: (destination: string, body: Record<string, unknown>) => unknown,
 *   fetchFn?: typeof fetch,
 *   emailDeliverer?: (envelope: { from: string, to: string, subject: string, html_body: string }) => unknown,
 *   slackDeliverer?: (payload: Record<string, unknown>, destination: string) => unknown,
 *   teamsDeliverer?: (payload: Record<string, unknown>, destination: string) => unknown,
 *   newId?: typeof newId,
 * }} [options]
 */
export async function processDueNotificationRetries(ctx, options = {}) {
  const store = ensure();
  const asOf = options.asOf ?? new Date().toISOString();
  const deliveryMode = resolveNotificationDeliveryMode(options);
  const newIdFn = options.newId ?? newId;

  const events = store.notificationEvents.filter((event) => event.tenant_id === ctx.tenantId);
  const rules = store.notificationRules.filter((rule) => rule.tenant_id === ctx.tenantId);

  const batch = await processDueNotificationRetryBatch({
    deliveryMode,
    events,
    rules,
    asOf,
    now: options.now ?? asOf,
    dryRun: options.dryRun === true,
    newAttemptId: (_eventId, _ruleId, _attemptNumber) => newIdFn('id'),
    webhookSender: options.webhookSender,
    fetchFn: options.fetchFn,
    emailDeliverer: options.emailDeliverer,
    slackDeliverer: options.slackDeliverer,
    teamsDeliverer: options.teamsDeliverer,
  });

  if (!batch.dry_run) {
    for (const item of batch.processed) {
      const record = item.delivery_record;
      if (!record || typeof record !== 'object') continue;
      const eventId = item.event_id;
      const event = store.notificationEvents.find((e) => e.id === eventId && e.tenant_id === ctx.tenantId);
      if (!event) continue;
      if (!Array.isArray(event.delivery_attempts)) event.delivery_attempts = [];
      const { delivery_record: _drop, ...safeItem } = item;
      event.delivery_attempts.push(record);

      audit({
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId ?? null,
        actor_role: ctx.role ?? null,
        action: 'notification.delivery_attempt_recorded',
        resource_type: 'notification_delivery_attempt',
        resource_id: record.id,
        metadata: {
          event_id: event.id,
          rule_id: record.rule_id,
          channel: record.channel,
          status: record.status,
          retry: true,
        },
      });
    }
    if (batch.processed.length > 0) {
      persistStore();
    }
  }

  return {
    tenant_id: ctx.tenantId,
    ...batch,
    processed: batch.processed.map(({ delivery_record: _drop, ...safe }) => safe),
  };
}