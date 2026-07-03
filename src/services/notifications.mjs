import { audit } from '../audit.mjs';
import { newId } from '../lib/ids.mjs';
import { redactString } from '../lib/redact.mjs';
import {
  finalizeNotificationDeliveryAttempts,
  resolveNotificationDeliveryMode,
} from '../lib/notificationDelivery.mjs';
import {
  buildNotificationDeliveryAttempt,
  buildRedactedNotificationEventPayload,
  DEV_NOTIFICATION_DELIVERY_NOTE,
  formatNotificationRuleForRead,
  normalizeNotificationRuleInput,
} from '../lib/notifications.mjs';
import { getStore, persistStore } from '../store.mjs';

function ensure() {
  const store = getStore();
  if (!store.notificationRules) store.notificationRules = [];
  if (!store.notificationEvents) store.notificationEvents = [];
  return store;
}

export { destinationPreview } from '../lib/notifications.mjs';

export function listNotifications(ctx) {
  const store = ensure();
  return {
    rules: store.notificationRules
      .filter((r) => r.tenant_id === ctx.tenantId)
      .map((r) => formatNotificationRuleForRead(r)),
    events: store.notificationEvents.filter((e) => e.tenant_id === ctx.tenantId).slice(-100),
  };
}

export function createNotificationRule(ctx, body) {
  const normalized = normalizeNotificationRuleInput(body);
  if (!normalized.ok) return normalized;

  const store = ensure();
  const rule = {
    id: newId('nrule'),
    tenant_id: ctx.tenantId,
    channel: normalized.channel,
    destination: normalized.destination,
    triggers: normalized.triggers,
    enabled: normalized.enabled,
    created_at: new Date().toISOString(),
    created_by: ctx.userId,
    delivery_note: DEV_NOTIFICATION_DELIVERY_NOTE,
  };
  store.notificationRules.push(rule);
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'notification.rule_created',
    resource_type: 'notification_rule',
    resource_id: rule.id,
    metadata: { channel: rule.channel, trigger_count: rule.triggers.length },
  });
  persistStore();
  return rule;
}

export async function emitNotification(ctx, { trigger, subject, metadata = {} }, options = {}) {
  const store = ensure();
  const now = new Date().toISOString();
  const rules = store.notificationRules.filter(
    (r) => r.tenant_id === ctx.tenantId && r.enabled && r.triggers.includes(trigger),
  );

  const eventId = newId('nevt');
  const redacted = buildRedactedNotificationEventPayload(subject, metadata);
  const initialAttempts = rules.map((rule) => buildNotificationDeliveryAttempt(eventId, rule, now));
  const delivery_attempts = await finalizeNotificationDeliveryAttempts({
    deliveryMode: resolveNotificationDeliveryMode(options),
    attempts: initialAttempts,
    rules,
    event: {
      id: eventId,
      trigger,
      subject: redacted.subject,
      metadata: redacted.metadata,
      created_at: now,
    },
    now,
    webhookSender: options.webhookSender,
    fetchFn: options.fetchFn,
  });

  const event = {
    id: eventId,
    tenant_id: ctx.tenantId,
    trigger,
    subject: redacted.subject,
    metadata: redacted.metadata,
    delivery_attempts,
    created_at: now,
  };
  store.notificationEvents.push(event);

  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId ?? null,
    actor_role: ctx.role ?? null,
    action: 'notification.event_emitted',
    resource_type: 'notification_event',
    resource_id: event.id,
    metadata: {
      trigger: event.trigger,
      subject_preview: redactString(String(subject ?? '')).slice(0, 80),
      attempt_count: delivery_attempts.length,
    },
  });

  for (const attempt of delivery_attempts) {
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId ?? null,
      actor_role: ctx.role ?? null,
      action: 'notification.delivery_attempt_recorded',
      resource_type: 'notification_delivery_attempt',
      resource_id: attempt.id,
      metadata: {
        event_id: event.id,
        rule_id: attempt.rule_id,
        channel: attempt.channel,
        status: attempt.status,
      },
    });
  }

  persistStore();
  return event;
}
