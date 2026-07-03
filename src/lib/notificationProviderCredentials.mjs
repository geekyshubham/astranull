import { createHash } from 'node:crypto';
import { rejectWebhookDestinationWithCredentials } from './notificationDelivery.mjs';
import { ALLOWED_CHANNELS } from './notifications.mjs';

export const NOTIFICATION_PROVIDER_SECRET_PURPOSE = 'notification_provider';

export const PROVIDER_CREDENTIAL_CHANNELS = Object.freeze(
  ['webhook', 'email', 'slack', 'teams'].filter((channel) => ALLOWED_CHANNELS.has(channel)),
);

function hasValue(value) {
  if (value === null || value === undefined) return false;
  if (typeof value === 'string' && value.trim() === '') return false;
  return true;
}

function normalizeChannel(raw) {
  if (!hasValue(raw)) return null;
  const channel = String(raw).trim().toLowerCase();
  return PROVIDER_CREDENTIAL_CHANNELS.includes(channel) ? channel : null;
}

function normalizeProviderId(raw, channel) {
  if (!hasValue(raw)) return channel;
  const providerId = String(raw).trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9._-]{0,63}$/.test(providerId)) return null;
  return providerId;
}

export function hashWebhookUrl(rawUrl) {
  const normalized = String(rawUrl ?? '').trim();
  if (!normalized) return null;
  return createHash('sha256').update(normalized, 'utf8').digest('hex');
}

function validateWebhookUrl(rawUrl) {
  if (!hasValue(rawUrl)) {
    return { error: 'missing_webhook_url', status: 400, message: 'webhook_url is required for webhook credentials.' };
  }
  const normalized = String(rawUrl).trim();
  let parsed;
  try {
    parsed = new URL(normalized);
  } catch {
    return { error: 'invalid_webhook_url', status: 400, message: 'webhook_url must be a valid URL.' };
  }
  if (parsed.protocol !== 'https:') {
    const host = parsed.hostname.toLowerCase();
    const devOnly = parsed.protocol === 'http:'
      && (host === '127.0.0.1' || host === 'localhost' || host.endsWith('.invalid'));
    if (!devOnly) {
      return {
        error: 'invalid_webhook_url',
        status: 400,
        message: 'webhook_url must use https:// or a dev-only http host.',
      };
    }
  }
  const credentialCheck = rejectWebhookDestinationWithCredentials(normalized);
  if (!credentialCheck.ok) {
    return {
      error: credentialCheck.error,
      status: 400,
      message: 'webhook_url must not embed credentials.',
    };
  }
  return { ok: true, webhook_url_hash: hashWebhookUrl(normalized) };
}

/**
 * @param {Record<string, unknown> | null | undefined} body
 */
export function normalizeNotificationProviderCredentialInput(body) {
  const channel = normalizeChannel(body?.channel);
  if (!channel) {
    return { error: 'invalid_channel', status: 400, message: 'channel must be webhook, email, slack, or teams.' };
  }

  const providerId = normalizeProviderId(body?.provider_id, channel);
  if (!providerId) {
    return {
      error: 'invalid_provider_id',
      status: 400,
      message: 'provider_id must be a short lowercase identifier.',
    };
  }

  const plaintext = body?.plaintext;
  if (!hasValue(plaintext)) {
    return { error: 'invalid_request', status: 400, message: 'plaintext is required.' };
  }

  let webhookUrlHash = null;
  if (channel === 'webhook') {
    const webhookCheck = validateWebhookUrl(body?.webhook_url);
    if (!webhookCheck.ok) return webhookCheck;
    webhookUrlHash = webhookCheck.webhook_url_hash;
  }

  const credentialId = hasValue(body?.credential_id) ? String(body.credential_id).trim() : null;

  return {
    ok: true,
    channel,
    provider_id: providerId,
    plaintext: String(plaintext),
    webhook_url_hash: webhookUrlHash,
    credential_id: credentialId,
  };
}

export function providerCredentialMetadata(channel, providerId, webhookUrlHash) {
  return {
    channel,
    provider_id: providerId,
    ...(webhookUrlHash ? { webhook_url_hash: webhookUrlHash } : {}),
  };
}

export function matchesProviderCredentialBinding(secretRecord, channel, providerId) {
  if (!secretRecord || secretRecord.purpose !== NOTIFICATION_PROVIDER_SECRET_PURPOSE) return false;
  const metadata = secretRecord.metadata ?? {};
  return metadata.channel === channel && metadata.provider_id === providerId;
}

export function formatNotificationProviderCredential(secretRecord) {
  const metadata = secretRecord.metadata ?? {};
  return {
    id: secretRecord.id,
    channel: metadata.channel ?? null,
    provider_id: metadata.provider_id ?? null,
    webhook_url_hash: metadata.webhook_url_hash ?? null,
    encrypted_secret_ref: secretRecord.id,
    rotation: secretRecord.rotation ?? 0,
    created_at: secretRecord.created_at,
    updated_at: secretRecord.updated_at,
    created_by: secretRecord.created_by ?? null,
  };
}