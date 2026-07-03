import { newId } from '../../lib/ids.mjs';
import { redactString } from '../../lib/redact.mjs';
import {
  finalizeNotificationDeliveryAttempts,
  resolveNotificationDeliveryMode,
} from '../../lib/notificationDelivery.mjs';
import { processDueNotificationRetryBatch } from '../../lib/notificationRetry.mjs';
import {
  processNotificationDlqRedriveBatch,
  resolveDlqRedriveDeliveryMode,
} from '../../lib/notificationDlqRedrive.mjs';
import {
  buildNotificationDeliveryAttempt,
  buildRedactedNotificationEventPayload,
  formatNotificationRuleForRead,
  normalizeNotificationRuleInput,
  POSTGRES_NOTIFICATION_DELIVERY_NOTE,
} from '../../lib/notifications.mjs';

/** @type {readonly string[]} */
export const NOTIFICATION_REPOSITORY_METHODS = Object.freeze([
  'listNotificationRules',
  'listNotificationEvents',
  'createNotificationRule',
  'appendNotificationEvent',
  'appendDeliveryAttempts',
]);

/** @type {readonly string[]} */
export const POSTGRES_NOTIFICATION_SERVICE_METHODS = Object.freeze([
  'listNotifications',
  'createNotificationRule',
  'emitNotification',
  'processDueNotificationRetries',
  'redriveNotificationDlq',
]);

function assertNotificationRepositories(repositories) {
  const notifications = repositories?.notifications;
  if (!notifications || typeof notifications !== 'object') {
    throw new Error('Postgres notification service adapter requires repositories.notifications.');
  }
  for (const method of NOTIFICATION_REPOSITORY_METHODS) {
    if (typeof notifications[method] !== 'function') {
      throw new Error(`Postgres notification service adapter requires notifications.${method}().`);
    }
  }

  const audit = repositories?.audit;
  if (!audit || typeof audit !== 'object') {
    throw new Error('Postgres notification service adapter requires repositories.audit.');
  }
  if (typeof audit.appendAuditEvent !== 'function') {
    throw new Error('Postgres notification service adapter requires audit.appendAuditEvent().');
  }
}

/**
 * @param {{
 *   notifications?: Record<string, unknown>,
 *   audit?: { appendAuditEvent?: (...args: unknown[]) => unknown },
 * }} repositories
 * @param {{
 *   now?: () => Date,
 *   newId?: typeof newId,
 *   deliveryMode?: string,
 *   webhookSender?: (destination: string, body: Record<string, unknown>) => unknown,
 *   fetchFn?: typeof fetch,
 * }} [options]
 */
export function createPostgresNotificationServices(repositories, options = {}) {
  assertNotificationRepositories(repositories);
  const notificationRepo = repositories.notifications;
  const auditRepo = repositories.audit;
  const nowFn = options.now ?? (() => new Date());
  const newIdFn = options.newId ?? newId;

  return {
    async listNotifications(ctx) {
      const [rules, events] = await Promise.all([
        notificationRepo.listNotificationRules(ctx),
        notificationRepo.listNotificationEvents(ctx, { limit: 100 }),
      ]);
      return { rules: rules.map((rule) => formatNotificationRuleForRead(rule)), events };
    },

    async createNotificationRule(ctx, body) {
      const normalized = normalizeNotificationRuleInput(body);
      if (!normalized.ok) return normalized;

      const now = nowFn().toISOString();
      const id = newIdFn('nrule');
      const persisted = await notificationRepo.createNotificationRule(ctx, {
        id,
        channel: normalized.channel,
        destination: normalized.destination,
        triggers: normalized.triggers,
        enabled: normalized.enabled,
        created_at: now,
      });

      await auditRepo.appendAuditEvent({
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId,
        actor_role: ctx.role,
        action: 'notification.rule_created',
        resource_type: 'notification_rule',
        resource_id: persisted.id,
        metadata: {
          channel: persisted.channel,
          trigger_count: persisted.triggers.length,
        },
      });

      return {
        ...persisted,
        created_by: ctx.userId,
        delivery_note: POSTGRES_NOTIFICATION_DELIVERY_NOTE,
      };
    },

    async emitNotification(ctx, { trigger, subject, metadata = {} }) {
      const now = nowFn().toISOString();
      const rules = (await notificationRepo.listNotificationRules(ctx)).filter(
        (r) => r.enabled && r.triggers.includes(trigger),
      );

      const eventId = newIdFn('nevt');
      const redacted = buildRedactedNotificationEventPayload(subject, metadata);
      const initialAttempts = rules.map((rule) =>
        buildNotificationDeliveryAttempt(eventId, rule, now),
      );
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

      const eventRow = await notificationRepo.appendNotificationEvent(ctx, {
        id: eventId,
        trigger,
        subject: redacted.subject,
        metadata: redacted.metadata,
        delivery_status: 'metadata_only',
        created_at: now,
      });

      const persistedAttempts = await notificationRepo.appendDeliveryAttempts(
        ctx,
        eventId,
        delivery_attempts,
      );

      const event = {
        ...eventRow,
        metadata: redacted.metadata,
        delivery_attempts: persistedAttempts,
      };

      await auditRepo.appendAuditEvent({
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
        await auditRepo.appendAuditEvent({
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

      return event;
    },

    async processDueNotificationRetries(ctx, options = {}) {
      const asOf = options.asOf ?? nowFn().toISOString();
      const deliveryMode = resolveNotificationDeliveryMode(options);

      const [rules, events] = await Promise.all([
        notificationRepo.listNotificationRules(ctx),
        notificationRepo.listNotificationEvents(ctx, { limit: 500 }),
      ]);

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
        const attemptsByEvent = new Map();
        for (const item of batch.processed) {
          const record = item.delivery_record;
          if (!record || typeof record !== 'object') continue;
          const eventId = String(item.event_id ?? '');
          if (!eventId) continue;
          if (!attemptsByEvent.has(eventId)) attemptsByEvent.set(eventId, []);
          attemptsByEvent.get(eventId).push(record);

          await auditRepo.appendAuditEvent({
            tenant_id: ctx.tenantId,
            actor_user_id: ctx.userId ?? null,
            actor_role: ctx.role ?? null,
            action: 'notification.delivery_attempt_recorded',
            resource_type: 'notification_delivery_attempt',
            resource_id: record.id,
            metadata: {
              event_id: eventId,
              rule_id: record.rule_id,
              channel: record.channel,
              status: record.status,
              retry: true,
            },
          });
        }

        for (const [eventId, attempts] of attemptsByEvent.entries()) {
          await notificationRepo.appendDeliveryAttempts(ctx, eventId, attempts);
        }
      }

      return {
        tenant_id: ctx.tenantId,
        ...batch,
        processed: batch.processed.map(({ delivery_record: _drop, ...safe }) => safe),
      };
    },

    async redriveNotificationDlq(ctx, options = {}) {
      const deliveryMode = resolveDlqRedriveDeliveryMode({
        forceMetadataOnly: options.forceMetadataOnly,
        deliveryMode: options.deliveryMode,
      });
      const now = options.now ?? nowFn().toISOString();

      const [rules, events] = await Promise.all([
        notificationRepo.listNotificationRules(ctx),
        notificationRepo.listNotificationEvents(ctx, { limit: 500 }),
      ]);

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
        const attemptsByEvent = new Map();
        for (const item of batch.processed) {
          const record = item.delivery_record;
          if (!record || typeof record !== 'object') continue;
          const eventId = String(item.event_id ?? '');
          if (!eventId) continue;
          if (!attemptsByEvent.has(eventId)) attemptsByEvent.set(eventId, []);
          attemptsByEvent.get(eventId).push(record);

          await auditRepo.appendAuditEvent({
            tenant_id: ctx.tenantId,
            actor_user_id: ctx.userId ?? null,
            actor_role: ctx.role ?? null,
            action: 'notification.delivery_attempt_recorded',
            resource_type: 'notification_delivery_attempt',
            resource_id: record.id,
            metadata: {
              event_id: eventId,
              rule_id: record.rule_id,
              channel: record.channel,
              status: record.status,
              dlq_redrive: true,
            },
          });
        }

        for (const [eventId, attempts] of attemptsByEvent.entries()) {
          await notificationRepo.appendDeliveryAttempts(ctx, eventId, attempts);
        }
      }

      await auditRepo.appendAuditEvent({
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
    },
  };
}
