import {
  WEBHOOK_MAX_ATTEMPTS,
  finalizeNotificationDeliveryAttempts,
  parseNotificationDeliveryModes,
} from './notificationDelivery.mjs';
import { latestDeliveryAttemptsByRule, NOTIFICATION_RETRY_BACKOFF_MS } from './notificationRetry.mjs';

/**
 * @param {{ forceMetadataOnly?: boolean }} [options]
 */
export function resolveDlqRedriveDeliveryMode(options = {}) {
  if (options.forceMetadataOnly !== false) {
    return 'metadata_only';
  }
  if (process.env.NODE_ENV === 'test') {
    return 'metadata_only';
  }
  const raw = process.env.ASTRANULL_NOTIFICATION_DELIVERY_MODE ?? 'metadata_only';
  const modes = parseNotificationDeliveryModes(raw);
  if (modes.has('metadata_only') && modes.size === 1) {
    return 'metadata_only';
  }
  return [...modes].sort().join(',');
}

/**
 * @param {Array<Record<string, unknown>>} events
 * @param {{ attemptIds?: string[], ruleId?: string }} [filters]
 */
export function collectDlqNotificationAttempts(events, filters = {}) {
  const attemptIdSet =
    Array.isArray(filters.attemptIds) && filters.attemptIds.length > 0
      ? new Set(filters.attemptIds.map((id) => String(id)))
      : null;
  const ruleId = filters.ruleId ? String(filters.ruleId) : null;

  /** @type {{ event: Record<string, unknown>, attempt: Record<string, unknown> }[]} */
  const candidates = [];
  const seenAttemptIds = new Set();

  for (const event of events) {
    if (!event || typeof event !== 'object') continue;
    for (const attempt of latestDeliveryAttemptsByRule(event).values()) {
      if (attempt.status !== 'provider_failed_dlq') continue;
      const attemptId = String(attempt.id ?? '');
      if (!attemptId) continue;
      seenAttemptIds.add(attemptId);

      if (ruleId && String(attempt.rule_id ?? '') !== ruleId) continue;
      if (attemptIdSet && !attemptIdSet.has(attemptId)) continue;

      candidates.push({ event, attempt });
    }
  }

  let skipped_count = 0;
  if (attemptIdSet) {
    for (const requestedId of attemptIdSet) {
      if (!seenAttemptIds.has(requestedId)) {
        skipped_count += 1;
      }
    }
  }

  return {
    candidates,
    skipped_count,
    candidate_count: candidates.length,
  };
}

/**
 * @param {{
 *   attempt: Record<string, unknown>,
 *   now: string,
 *   newAttemptId: string,
 * }} input
 */
export function buildMetadataOnlyDlqRedriveAttempt(input) {
  const maxAttempts = Number(input.attempt.max_attempts ?? WEBHOOK_MAX_ATTEMPTS);
  return {
    id: input.newAttemptId,
    rule_id: input.attempt.rule_id,
    channel: input.attempt.channel,
    destination_preview: input.attempt.destination_preview,
    status: 'provider_retry_scheduled',
    reason: 'dlq_redrive_metadata_only',
    provider_error: input.attempt.provider_error ?? 'dlq_redrive_metadata_only',
    created_at: input.now,
    attempted_at: input.now,
    attempt_number: 1,
    max_attempts: maxAttempts,
    next_retry_at: input.now,
    exhausted: false,
  };
}

/**
 * @param {{
 *   attempt: Record<string, unknown>,
 *   event: Record<string, unknown>,
 *   rule: { id: string, channel: string, destination: string },
 *   now: string,
 *   newAttemptId: string,
 *   deliveryMode: string,
 *   webhookSender?: (destination: string, body: Record<string, unknown>) => unknown,
 *   fetchFn?: typeof fetch,
 *   emailDeliverer?: (envelope: { from: string, to: string, subject: string, html_body: string }) => unknown,
 *   slackDeliverer?: (payload: Record<string, unknown>, destination: string) => unknown,
 *   teamsDeliverer?: (payload: Record<string, unknown>, destination: string) => unknown,
 * }} input
 */
export async function buildDlqRedriveDeliveryAttempt(input) {
  const modes = parseNotificationDeliveryModes(input.deliveryMode);
  if (modes.has('metadata_only') && modes.size === 1) {
    return buildMetadataOnlyDlqRedriveAttempt({
      attempt: input.attempt,
      now: input.now,
      newAttemptId: input.newAttemptId,
    });
  }

  const seed = {
    id: input.newAttemptId,
    rule_id: input.attempt.rule_id,
    channel: input.attempt.channel,
    destination_preview: input.attempt.destination_preview,
    status: 'queued_provider_not_configured',
    reason: 'dlq_redrive',
    created_at: input.now,
    attempted_at: null,
    attempt_number: 1,
    max_attempts: Number(input.attempt.max_attempts ?? WEBHOOK_MAX_ATTEMPTS),
  };

  const eventPayload = {
    id: String(input.event.id ?? ''),
    trigger: String(input.event.trigger ?? ''),
    subject:
      typeof input.event.subject === 'string'
        ? input.event.subject
        : String(input.event.subject ?? ''),
    metadata:
      input.event.metadata && typeof input.event.metadata === 'object' && !Array.isArray(input.event.metadata)
        ? input.event.metadata
        : {},
    created_at: String(input.event.created_at ?? input.now),
  };

  const [record] = await finalizeNotificationDeliveryAttempts({
    deliveryMode: input.deliveryMode,
    attempts: [seed],
    rules: [input.rule],
    event: eventPayload,
    now: input.now,
    webhookSender: input.webhookSender,
    fetchFn: input.fetchFn,
    emailDeliverer: input.emailDeliverer,
    slackDeliverer: input.slackDeliverer,
    teamsDeliverer: input.teamsDeliverer,
  });

  if (record.status === 'provider_retry_scheduled' && !record.next_retry_at) {
    return {
      ...record,
      next_retry_at: new Date(new Date(input.now).getTime() + NOTIFICATION_RETRY_BACKOFF_MS).toISOString(),
    };
  }

  return record;
}

/**
 * @param {Array<Record<string, unknown>>} events
 */
export function countStillDlqAttempts(events) {
  let count = 0;
  for (const event of events) {
    if (!event || typeof event !== 'object') continue;
    for (const attempt of latestDeliveryAttemptsByRule(event).values()) {
      if (attempt.status === 'provider_failed_dlq') count += 1;
    }
  }
  return count;
}

/**
 * @param {{
 *   deliveryMode: string,
 *   events: Array<Record<string, unknown>>,
 *   rules: Array<{ id: string, channel: string, destination: string }>,
 *   attemptIds?: string[],
 *   ruleId?: string,
 *   dryRun?: boolean,
 *   now?: string,
 *   newAttemptId?: (eventId: string, ruleId: string, attemptId: string) => string,
 *   webhookSender?: (destination: string, body: Record<string, unknown>) => unknown,
 *   fetchFn?: typeof fetch,
 *   emailDeliverer?: (envelope: { from: string, to: string, subject: string, html_body: string }) => unknown,
 *   slackDeliverer?: (payload: Record<string, unknown>, destination: string) => unknown,
 *   teamsDeliverer?: (payload: Record<string, unknown>, destination: string) => unknown,
 * }} input
 */
export async function processNotificationDlqRedriveBatch(input) {
  const now = input.now ?? new Date().toISOString();
  const dryRun = input.dryRun === true;
  const collected = collectDlqNotificationAttempts(input.events, {
    attemptIds: input.attemptIds,
    ruleId: input.ruleId,
  });
  const rulesById = new Map(input.rules.map((rule) => [rule.id, rule]));
  const adapterModeActive = !(
    parseNotificationDeliveryModes(input.deliveryMode).has('metadata_only')
    && parseNotificationDeliveryModes(input.deliveryMode).size === 1
  );

  const newAttemptId =
    input.newAttemptId ??
    ((eventId, ruleId, attemptId) => `ndlq_${eventId}_${ruleId}_${attemptId}`);

  /** @type {Record<string, unknown>[]} */
  const processed = [];
  let skipped_count = collected.skipped_count;
  let network_sends_performed = 0;

  for (const { event, attempt } of collected.candidates) {
    const channel = String(attempt.channel ?? '');
    if (channel === 'in_app') {
      skipped_count += 1;
      continue;
    }

    const rule = rulesById.get(String(attempt.rule_id ?? ''));
    if (!rule) {
      skipped_count += 1;
      continue;
    }

    if (dryRun) {
      processed.push({
        event_id: event.id ?? null,
        prior_attempt_id: attempt.id ?? null,
        rule_id: attempt.rule_id ?? null,
        channel,
        status: 'redrive_planned',
        dry_run: true,
      });
      continue;
    }

    const record = await buildDlqRedriveDeliveryAttempt({
      attempt,
      event,
      rule,
      now,
      newAttemptId: newAttemptId(
        String(event.id ?? ''),
        String(attempt.rule_id ?? ''),
        String(attempt.id ?? ''),
      ),
      deliveryMode: input.deliveryMode,
      webhookSender: input.webhookSender,
      fetchFn: input.fetchFn,
      emailDeliverer: input.emailDeliverer,
      slackDeliverer: input.slackDeliverer,
      teamsDeliverer: input.teamsDeliverer,
    });

    if (
      adapterModeActive
      && (record.status === 'delivered_provider' || record.status === 'provider_retry_scheduled')
    ) {
      network_sends_performed += 1;
    }

    processed.push({
      event_id: event.id ?? null,
      prior_attempt_id: attempt.id ?? null,
      attempt_id: record.id,
      rule_id: record.rule_id ?? null,
      channel: record.channel ?? null,
      status: record.status,
      attempt_number: record.attempt_number ?? null,
      max_attempts: record.max_attempts ?? null,
      next_retry_at: record.next_retry_at ?? null,
      exhausted: record.exhausted ?? null,
      dry_run: false,
      delivery_record: record,
    });
  }

  const requeued_count = dryRun
    ? processed.length
    : processed.filter((item) => item.status !== 'provider_failed_dlq').length;

  const projectedEvents = dryRun
    ? input.events
    : applyDlqRedriveRecords(input.events, processed);

  return {
    delivery_mode: input.deliveryMode,
    dry_run: dryRun,
    requeued_count,
    skipped_count,
    still_dlq_count: countStillDlqAttempts(projectedEvents),
    processed,
    network_sends_performed: dryRun ? 0 : network_sends_performed,
  };
}

/**
 * @param {Array<Record<string, unknown>>} events
 * @param {Array<Record<string, unknown>>} processed
 */
export function applyDlqRedriveRecords(events, processed) {
  const byEventId = new Map();
  for (const item of processed) {
    const record = item.delivery_record;
    if (!record || typeof record !== 'object') continue;
    const eventId = String(item.event_id ?? '');
    if (!eventId) continue;
    if (!byEventId.has(eventId)) byEventId.set(eventId, []);
    byEventId.get(eventId).push(record);
  }

  return events.map((event) => {
    const eventId = String(event.id ?? '');
    const additions = byEventId.get(eventId);
    if (!additions?.length) return event;
    const attempts = Array.isArray(event.delivery_attempts) ? [...event.delivery_attempts] : [];
    attempts.push(...additions);
    return { ...event, delivery_attempts: attempts };
  });
}