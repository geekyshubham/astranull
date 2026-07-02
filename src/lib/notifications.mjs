import { redactObject, redactString } from './redact.mjs';

export const ALLOWED_CHANNELS = new Set(['in_app', 'webhook', 'email', 'slack', 'teams']);

export const ALLOWED_TRIGGERS = new Set([
  'finding.high_severity',
  'agent.offline',
  'safe_test.completed',
  'high_scale.state_change',
  'report.ready',
  'bootstrap_token.created',
  'bootstrap_token.revoked',
]);

export const DEFAULT_TRIGGERS = ['finding.high_severity', 'high_scale.state_change'];

export const POSTGRES_NOTIFICATION_DELIVERY_NOTE =
  'Postgres stores delivery metadata only — no Slack/email/Teams/webhook send.';

export const DEV_NOTIFICATION_DELIVERY_NOTE =
  'Developer validation stores delivery metadata only — no Slack/email/Teams/webhook send.';

function normalizeChannel(raw) {
  if (typeof raw !== 'string') return null;
  const channel = raw.trim().toLowerCase();
  return ALLOWED_CHANNELS.has(channel) ? channel : null;
}

function normalizeTriggers(raw) {
  if (raw === undefined || raw === null) return [...DEFAULT_TRIGGERS];
  const list = Array.isArray(raw) ? raw : [raw];
  if (list.length === 0) return null;
  const out = [];
  for (const item of list) {
    if (typeof item !== 'string' || !item.trim()) return null;
    const trigger = item.trim();
    if (!ALLOWED_TRIGGERS.has(trigger)) return null;
    if (!out.includes(trigger)) out.push(trigger);
  }
  return out;
}

function isAllowedWebhookDestination(destination) {
  let url;
  try {
    url = new URL(destination);
  } catch {
    return false;
  }
  if (url.protocol === 'https:') return true;
  if (url.protocol !== 'http:') return false;
  const host = url.hostname.toLowerCase();
  if (host === '127.0.0.1' || host === 'localhost') return true;
  if (host.endsWith('.invalid')) return true;
  return false;
}

function validateDestination(channel, destination) {
  if (channel === 'in_app') return { ok: true, destination: '' };
  if (typeof destination !== 'string' || !destination.trim()) {
    return { error: 'missing_destination', status: 400 };
  }
  const normalized = destination.trim();
  if (channel === 'webhook' && !isAllowedWebhookDestination(normalized)) {
    return { error: 'invalid_webhook_destination', status: 400 };
  }
  return { ok: true, destination: normalized };
}

/**
 * @param {Record<string, unknown> | null | undefined} body
 */
export function normalizeNotificationRuleInput(body) {
  const channel = normalizeChannel(body?.channel ?? 'webhook');
  if (!channel) {
    return { error: 'invalid_channel', status: 400 };
  }

  const triggers = normalizeTriggers(body?.triggers);
  if (!triggers) {
    return { error: 'invalid_trigger', status: 400 };
  }

  const destCheck = validateDestination(channel, body?.destination);
  if (!destCheck.ok) return destCheck;

  return {
    ok: true,
    channel,
    destination: destCheck.destination,
    triggers,
    enabled: body?.enabled !== false,
  };
}

export function destinationPreview(channel, destination) {
  const redacted = redactString(String(destination ?? ''));
  if (channel === 'webhook') {
    try {
      const u = new URL(destination);
      const pathHint = u.pathname && u.pathname !== '/' ? '…' : '';
      return `webhook://${u.hostname}${pathHint}`;
    } catch {
      return `webhook:${redacted.slice(0, 40)}`;
    }
  }
  if (channel === 'email') {
    const at = redacted.indexOf('@');
    if (at > 0) return `email:${redacted[0]}…@${redacted.slice(at + 1)}`;
    return `email:${redacted.slice(0, 24)}`;
  }
  if (channel === 'in_app') return 'in_app:feed';
  return `${channel}:${redacted.slice(0, 32)}`;
}

function deliveryStatusForChannel(channel) {
  if (channel === 'in_app') {
    return {
      status: 'delivered_in_app',
      reason: 'recorded_in_tenant_in_app_feed',
      attempted: true,
    };
  }
  return {
    status: 'queued_provider_not_configured',
    reason: 'outbound_provider_not_configured_safe_by_default',
    attempted: false,
  };
}

/**
 * @param {string} eventId
 * @param {{ id: string, channel: string, destination: string }} rule
 * @param {string} now
 */
export function buildNotificationDeliveryAttempt(eventId, rule, now) {
  const { status, reason, attempted } = deliveryStatusForChannel(rule.channel);
  return {
    id: `natt_${eventId}_${rule.id}`,
    rule_id: rule.id,
    channel: rule.channel,
    destination_preview: destinationPreview(rule.channel, rule.destination),
    status,
    reason,
    created_at: now,
    attempted_at: attempted ? now : null,
  };
}

/**
 * @param {string} subject
 * @param {Record<string, unknown>} [metadata]
 */
export function buildRedactedNotificationEventPayload(subject, metadata = {}) {
  return {
    subject: redactString(subject),
    metadata: redactObject(metadata),
  };
}