import { audit } from '../audit.mjs';
import { newId } from '../lib/ids.mjs';
import {
  processNotificationDlqRedriveBatch,
  resolveDlqRedriveDeliveryMode,
} from '../lib/notificationDlqRedrive.mjs';
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
 *   attemptIds?: string[],
 *   ruleId?: string,
 *   dryRun?: boolean,
 *   forceMetadataOnly?: boolean,
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
export async function redriveNotificationDlq(ctx, options = {}) {
  const store = ensure();
  const deliveryMode = resolveDlqRedriveDeliveryMode({
    forceMetadataOnly: options.forceMetadataOnly,
    deliveryMode: options.deliveryMode,
  });
  const newIdFn = options.newId ?? newId;
  const now = options.now ?? new Date().toISOString();

  const events = store.notificationEvents.filter((event) => event.tenant_id === ctx.tenantId);
  const rules = store.notificationRules.filter((rule) => rule.tenant_id === ctx.tenantId);

  const batch = await processNotificationDlqRedriveBatch({
    deliveryMode,
    events,
    rules,
    attemptIds: options.attemptIds,
    ruleId: options.ruleId,
    dryRun: options.dryRun === true,
    now,
    newAttemptId: (_eventId, _ruleId, _attemptId) => newIdFn('id'),
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
          dlq_redrive: true,
        },
      });
    }

    if (batch.processed.some((item) => item.delivery_record)) {
      persistStore();
    }
  }

  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId ?? null,
    actor_role: ctx.role ?? null,
    action: 'notification.dlq_redrive',
    resource_type: 'notification_dlq',
    resource_id: ctx.tenantId,
    metadata: {
      dry_run: batch.dry_run,
      delivery_mode: batch.delivery_mode,
      requeued_count: batch.requeued_count,
      skipped_count: batch.skipped_count,
      still_dlq_count: batch.still_dlq_count,
      processed_count: batch.processed.length,
      rule_id: options.ruleId ?? null,
      attempt_ids_count: Array.isArray(options.attemptIds) ? options.attemptIds.length : 0,
    },
  });

  return {
    tenant_id: ctx.tenantId,
    ...batch,
    processed: batch.processed.map(({ delivery_record: _drop, ...safe }) => safe),
  };
}