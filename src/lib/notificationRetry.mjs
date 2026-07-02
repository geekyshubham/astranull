import {
  WEBHOOK_DELIVERY_MODE,
  WEBHOOK_MAX_ATTEMPTS,
  buildWebhookNotificationBody,
  encodeWebhookPayload,
  sendWebhookNotification,
} from './notificationDelivery.mjs';
import { destinationPreview } from './notifications.mjs';

export const NOTIFICATION_RETRY_BACKOFF_MS = 60_000;

function addMs(iso, ms) {
  return new Date(new Date(iso).getTime() + ms).toISOString();
}

/**
 * @param {Record<string, unknown>} attempt
 * @param {number} asOfMs
 */
export function isNotificationRetryDue(attempt, asOfMs) {
  if (attempt.status !== 'provider_retry_scheduled') return false;
  const nextRetryAt = attempt.next_retry_at;
  if (typeof nextRetryAt !== 'string') return false;
  const dueMs = new Date(nextRetryAt).getTime();
  return Number.isFinite(dueMs) && dueMs <= asOfMs;
}

/**
 * Latest delivery attempt per rule_id on an event (array order wins).
 *
 * @param {{ delivery_attempts?: Array<Record<string, unknown>> }} event
 */
export function latestDeliveryAttemptsByRule(event) {
  const attempts = Array.isArray(event.delivery_attempts) ? event.delivery_attempts : [];
  /** @type {Map<string, Record<string, unknown>>} */
  const latestByRule = new Map();
  for (const attempt of attempts) {
    if (!attempt || typeof attempt !== 'object') continue;
    const ruleId = attempt.rule_id;
    if (typeof ruleId !== 'string' || !ruleId) continue;
    latestByRule.set(ruleId, attempt);
  }
  return latestByRule;
}

/**
 * @param {Array<Record<string, unknown>>} events
 * @param {string} asOf
 */
export function collectDueNotificationRetries(events, asOf) {
  const asOfMs = new Date(asOf).getTime();
  if (!Number.isFinite(asOfMs)) {
    throw new Error('notification retry: invalid as-of timestamp.');
  }

  /** @type {{ event: Record<string, unknown>, attempt: Record<string, unknown> }[]} */
  const due_items = [];
  let scheduled_not_due = 0;

  for (const event of events) {
    if (!event || typeof event !== 'object') continue;
    for (const attempt of latestDeliveryAttemptsByRule(event).values()) {
      if (attempt.status !== 'provider_retry_scheduled') continue;
      if (!isNotificationRetryDue(attempt, asOfMs)) {
        scheduled_not_due += 1;
        continue;
      }
      due_items.push({ event, attempt });
    }
  }

  return {
    due_items,
    scheduled_not_due,
    due_count: due_items.length,
  };
}

/**
 * Metadata-only retry progression (no outbound provider I/O).
 *
 * @param {{
 *   attempt: Record<string, unknown>,
 *   now: string,
 *   newAttemptId: string,
 * }} input
 */
export function buildMetadataOnlyRetryDeliveryAttempt(input) {
  const attemptNumber = Number(input.attempt.attempt_number ?? 1) + 1;
  const maxAttempts = Number(input.attempt.max_attempts ?? WEBHOOK_MAX_ATTEMPTS);

  const base = {
    id: input.newAttemptId,
    rule_id: input.attempt.rule_id,
    channel: input.attempt.channel,
    destination_preview: input.attempt.destination_preview,
    created_at: input.now,
    attempted_at: input.now,
    attempt_number: attemptNumber,
    max_attempts: maxAttempts,
  };

  if (attemptNumber >= maxAttempts) {
    return {
      ...base,
      status: 'provider_failed_dlq',
      reason: input.attempt.provider_error ?? 'retry_exhausted_metadata_only',
      provider_error: input.attempt.provider_error ?? 'retry_exhausted_metadata_only',
      exhausted: true,
    };
  }

  return {
    ...base,
    status: 'provider_retry_scheduled',
    reason: input.attempt.provider_error ?? 'retry_planned_metadata_only',
    provider_error: input.attempt.provider_error ?? 'retry_planned_metadata_only',
    next_retry_at: addMs(input.now, NOTIFICATION_RETRY_BACKOFF_MS),
    exhausted: false,
  };
}

/**
 * @param {{
 *   attempt: Record<string, unknown>,
 *   event: { id: string, trigger: string, subject: string, metadata: Record<string, unknown>, created_at: string },
 *   rule: { id: string, channel: string, destination: string },
 *   now: string,
 *   newAttemptId: string,
 *   webhookSender?: (destination: string, body: Record<string, unknown>) => Promise<{ ok: boolean, error?: string, status?: number }> | { ok: boolean, error?: string, status?: number },
 *   fetchFn?: typeof fetch,
 * }} input
 */
export async function buildWebhookRetryDeliveryAttempt(input) {
  const attemptNumber = Number(input.attempt.attempt_number ?? 1) + 1;
  const maxAttempts = Number(input.attempt.max_attempts ?? WEBHOOK_MAX_ATTEMPTS);

  const base = {
    id: input.newAttemptId,
    rule_id: input.attempt.rule_id,
    channel: input.attempt.channel,
    destination_preview:
      input.attempt.destination_preview ??
      destinationPreview(input.rule.channel, input.rule.destination),
    created_at: input.now,
    attempted_at: input.now,
    attempt_number: attemptNumber,
    max_attempts: maxAttempts,
  };

  if (input.attempt.channel !== 'webhook' || !input.rule?.destination) {
    return {
      ...base,
      status: 'provider_failed_dlq',
      reason: 'retry_channel_not_supported',
      provider_error: 'retry_channel_not_supported',
      exhausted: true,
    };
  }

  const body = buildWebhookNotificationBody({
    event_id: input.event.id,
    rule_id: input.attempt.rule_id,
    trigger: input.event.trigger,
    subject: input.event.subject,
    metadata: input.event.metadata,
    created_at: input.event.created_at,
  });
  const encoded = encodeWebhookPayload(body);
  if (!encoded.ok) {
    return {
      ...base,
      status: 'provider_failed_dlq',
      reason: encoded.error,
      provider_error: encoded.error,
      exhausted: true,
    };
  }

  let sendResult;
  if (typeof input.webhookSender === 'function') {
    sendResult = await input.webhookSender(input.rule.destination, body);
  } else {
    sendResult = await sendWebhookNotification(input.rule.destination, encoded.json, {
      fetchFn: input.fetchFn,
    });
  }

  if (sendResult?.ok) {
    return {
      ...base,
      status: 'delivered_provider',
      reason: 'webhook_delivered',
      provider_status: sendResult.status ?? null,
    };
  }

  const retryable = attemptNumber < maxAttempts;
  const providerError = sendResult?.error ?? 'webhook_send_failed';
  if (retryable) {
    return {
      ...base,
      status: 'provider_retry_scheduled',
      reason: providerError,
      provider_error: providerError,
      next_retry_at: addMs(input.now, NOTIFICATION_RETRY_BACKOFF_MS),
      exhausted: false,
    };
  }

  return {
    ...base,
    status: 'provider_failed_dlq',
    reason: providerError,
    provider_error: providerError,
    exhausted: true,
  };
}

/**
 * @param {{
 *   deliveryMode: string,
 *   event: Record<string, unknown>,
 *   attempt: Record<string, unknown>,
 *   rulesById: Map<string, { id: string, channel: string, destination: string }>,
 *   now: string,
 *   newAttemptId: string,
 *   webhookSender?: (destination: string, body: Record<string, unknown>) => unknown,
 *   fetchFn?: typeof fetch,
 * }} input
 */
export async function buildRetryDeliveryAttempt(input) {
  const rule = input.rulesById.get(String(input.attempt.rule_id ?? ''));
  const eventPayload = {
    id: String(input.event.id ?? ''),
    trigger: String(input.event.trigger ?? ''),
    subject:
      typeof input.event.subject === 'string' ? input.event.subject : String(input.event.subject ?? ''),
    metadata:
      input.event.metadata && typeof input.event.metadata === 'object' && !Array.isArray(input.event.metadata)
        ? input.event.metadata
        : {},
    created_at: String(input.event.created_at ?? input.now),
  };

  if (input.deliveryMode !== WEBHOOK_DELIVERY_MODE) {
    return buildMetadataOnlyRetryDeliveryAttempt({
      attempt: input.attempt,
      now: input.now,
      newAttemptId: input.newAttemptId,
    });
  }

  return buildWebhookRetryDeliveryAttempt({
    attempt: input.attempt,
    event: eventPayload,
    rule: rule ?? { id: String(input.attempt.rule_id ?? ''), channel: 'webhook', destination: '' },
    now: input.now,
    newAttemptId: input.newAttemptId,
    webhookSender: input.webhookSender,
    fetchFn: input.fetchFn,
  });
}

/**
 * @param {{
 *   deliveryMode: string,
 *   events: Array<Record<string, unknown>>,
 *   rules: Array<{ id: string, channel: string, destination: string }>,
 *   asOf: string,
 *   now?: string,
 *   dryRun?: boolean,
 *   newAttemptId?: (eventId: string, ruleId: string, attemptNumber: number) => string,
 *   webhookSender?: (destination: string, body: Record<string, unknown>) => unknown,
 *   fetchFn?: typeof fetch,
 * }} input
 */
export async function processDueNotificationRetryBatch(input) {
  const now = input.now ?? input.asOf;
  const dryRun = input.dryRun === true;
  const collected = collectDueNotificationRetries(input.events, input.asOf);
  const rulesById = new Map(input.rules.map((rule) => [rule.id, rule]));

  const newAttemptId =
    input.newAttemptId ??
    ((eventId, ruleId, attemptNumber) => `nretry_${eventId}_${ruleId}_${attemptNumber}`);

  /** @type {Record<string, unknown>[]} */
  const processed = [];
  let network_sends_performed = 0;

  for (const { event, attempt } of collected.due_items) {
    const nextAttemptNumber = Number(attempt.attempt_number ?? 1) + 1;
    if (dryRun) {
      processed.push({
        event_id: event.id ?? null,
        attempt_id: attempt.id ?? null,
        rule_id: attempt.rule_id ?? null,
        channel: attempt.channel ?? null,
        status: 'retry_due',
        prior_status: attempt.status ?? null,
        prior_attempt_number: attempt.attempt_number ?? 1,
        next_attempt_number: nextAttemptNumber,
        dry_run: true,
      });
      continue;
    }

    const record = await buildRetryDeliveryAttempt({
      deliveryMode: input.deliveryMode,
      event,
      attempt,
      rulesById,
      now,
      newAttemptId: newAttemptId(String(event.id ?? ''), String(attempt.rule_id ?? ''), nextAttemptNumber),
      webhookSender: input.webhookSender,
      fetchFn: input.fetchFn,
    });

    if (input.deliveryMode === WEBHOOK_DELIVERY_MODE && attempt.channel === 'webhook') {
      network_sends_performed += 1;
    }

    processed.push({
      event_id: event.id ?? null,
      attempt_id: record.id,
      rule_id: record.rule_id ?? null,
      channel: record.channel ?? null,
      status: record.status,
      prior_status: attempt.status ?? null,
      prior_attempt_id: attempt.id ?? null,
      attempt_number: record.attempt_number ?? null,
      max_attempts: record.max_attempts ?? null,
      next_retry_at: record.next_retry_at ?? null,
      exhausted: record.exhausted ?? null,
      dry_run: false,
      delivery_record: record,
    });
  }

  return {
    as_of: input.asOf,
    delivery_mode: input.deliveryMode,
    dry_run: dryRun,
    due_count: collected.due_count,
    scheduled_not_due_count: collected.scheduled_not_due,
    processed,
    network_sends_performed: dryRun ? 0 : network_sends_performed,
  };
}