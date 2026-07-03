import { assertNoRawWafEvidence } from '../contracts/wafPosture.mjs';
import { sleep } from './connectorProviders/common.mjs';
import { redactObject, redactString } from './redact.mjs';
import {
  encodeProviderPayload,
  rejectProviderDestinationWithCredentials,
  sendProviderHttpsPost,
  WEBHOOK_MAX_ATTEMPTS,
  WEBHOOK_TIMEOUT_MS,
} from './notificationDelivery.mjs';

export const DEFAULT_REMEDIATION_DELIVERY_MODE = 'metadata_only';
export const REMEDIATION_DELIVERY_TIMEOUT_MS = WEBHOOK_TIMEOUT_MS;
export const REMEDIATION_MAX_ATTEMPTS = WEBHOOK_MAX_ATTEMPTS;
export const REMEDIATION_BASE_BACKOFF_MS = 250;

export const REMEDIATION_DELIVERABLE_CHANNELS = Object.freeze([
  'jira',
  'servicenow',
  'slack',
  'webhook',
  'siem',
]);

const VALID_DELIVERY_MODES = new Set([
  ...REMEDIATION_DELIVERABLE_CHANNELS,
  'all',
  'metadata_only',
]);

const DESTINATION_ENV_KEYS = Object.freeze({
  jira: 'ASTRANULL_REMEDIATION_JIRA_URL',
  servicenow: 'ASTRANULL_REMEDIATION_SERVICENOW_URL',
  slack: 'ASTRANULL_REMEDIATION_SLACK_URL',
  webhook: 'ASTRANULL_REMEDIATION_WEBHOOK_URL',
  siem: 'ASTRANULL_REMEDIATION_SIEM_URL',
});

/**
 * @param {string | undefined | null} raw
 * @returns {Set<string>}
 */
export function parseRemediationDeliveryModes(raw) {
  const modes = new Set();
  const str = String(raw ?? '').trim().toLowerCase();
  if (!str || str === DEFAULT_REMEDIATION_DELIVERY_MODE) {
    modes.add('metadata_only');
    return modes;
  }

  for (const part of str.split(',').map((segment) => segment.trim()).filter(Boolean)) {
    if (!VALID_DELIVERY_MODES.has(part)) continue;
    if (part === 'all') {
      for (const channel of REMEDIATION_DELIVERABLE_CHANNELS) modes.add(channel);
      continue;
    }
    if (part === 'metadata_only') continue;
    modes.add(part);
  }

  if (modes.size === 0) modes.add('metadata_only');
  return modes;
}

/**
 * @param {Set<string>} modes
 * @param {string} channel
 */
export function isRemediationDeliveryActive(modes, channel) {
  if (modes.has('metadata_only') && modes.size === 1) return false;
  return modes.has(channel);
}

/**
 * @param {{ deliveryMode?: string }} [options]
 */
export function resolveRemediationDeliveryMode(options = {}) {
  const raw =
    options.deliveryMode
    ?? process.env.ASTRANULL_REMEDIATION_DELIVERY_MODE
    ?? DEFAULT_REMEDIATION_DELIVERY_MODE;
  const modes = parseRemediationDeliveryModes(raw);
  if (modes.has('metadata_only') && modes.size === 1) return DEFAULT_REMEDIATION_DELIVERY_MODE;
  return [...modes].sort().join(',');
}

/**
 * @param {string | undefined | null} raw
 * @returns {string | null}
 */
export function normalizeRemediationDeliverChannel(raw) {
  const channel = String(raw ?? '').trim().toLowerCase();
  if (channel === 'splunk_hec' || channel === 'sentinel') return 'siem';
  if (REMEDIATION_DELIVERABLE_CHANNELS.includes(channel)) return channel;
  return null;
}

/**
 * @param {{ siemProvider?: string }} [options]
 */
export function resolveSiemConnectorType(options = {}) {
  const raw = options.siemProvider ?? process.env.ASTRANULL_REMEDIATION_SIEM_PROVIDER ?? 'splunk_hec';
  const provider = String(raw).trim().toLowerCase();
  return provider === 'sentinel' ? 'sentinel' : 'splunk_hec';
}

/**
 * @param {string} channel
 * @param {{ siemProvider?: string }} [options]
 */
export function resolveRemediationConnectorType(channel, options = {}) {
  if (channel === 'siem') return resolveSiemConnectorType(options);
  return channel;
}

/**
 * @param {string} channel
 * @param {{ destination?: string }} [options]
 */
export function resolveRemediationDestination(channel, options = {}) {
  if (typeof options.destination === 'string' && options.destination.trim()) {
    return options.destination.trim();
  }
  const envKey = DESTINATION_ENV_KEYS[channel];
  if (!envKey) return '';
  return String(process.env[envKey] ?? '').trim();
}

/**
 * @param {string} channel
 * @param {string} destination
 */
export function remediationDestinationPreview(channel, destination) {
  const redacted = redactString(String(destination ?? ''));
  if (channel === 'webhook' || channel === 'slack' || channel === 'siem' || channel === 'jira' || channel === 'servicenow') {
    try {
      const u = new URL(destination);
      const pathHint = u.pathname && u.pathname !== '/' ? '…' : '';
      return `${channel}://${u.hostname}${pathHint}`;
    } catch {
      return `${channel}:${redacted.slice(0, 40)}`;
    }
  }
  return `${channel}:${redacted.slice(0, 32)}`;
}

/**
 * @param {string} connectorType
 * @param {Record<string, unknown>} payload
 */
export function extractRemediationOutboundBody(connectorType, payload) {
  switch (connectorType) {
    case 'splunk_hec':
      return payload.event && typeof payload.event === 'object'
        ? { event: payload.event }
        : payload;
    case 'sentinel':
      return Array.isArray(payload.records)
        ? { records: payload.records }
        : payload;
    case 'slack':
      return {
        ...(typeof payload.text === 'string' ? { text: payload.text } : {}),
        ...(Array.isArray(payload.blocks) ? { blocks: payload.blocks } : {}),
      };
    default:
      return payload;
  }
}

function isRetryableRemediationSendError(sendResult) {
  if (!sendResult || sendResult.ok) return false;
  if (sendResult.transport === 'rejected_precheck') return false;

  const status = Number(sendResult.status ?? 0);
  if (status === 429 || status >= 500) return true;

  const error = String(sendResult.error ?? '').toLowerCase();
  if (error === 'provider_redirect_not_allowed') return false;
  if (error.includes('abort') || error.includes('timeout')) return true;

  return sendResult.transport === 'http' && !status;
}

/**
 * @param {string} destination
 * @param {string} json
 * @param {{
 *   fetchFn?: typeof fetch,
 *   timeoutMs?: number,
 *   baseBackoffMs?: number,
 *   sleepFn?: (ms: number) => Promise<void>,
 * }} [options]
 */
async function sendRemediationWithBoundedRetry(destination, json, options = {}) {
  const max_attempts = REMEDIATION_MAX_ATTEMPTS;
  const baseBackoffMs = Number(options.baseBackoffMs ?? REMEDIATION_BASE_BACKOFF_MS);
  const sleepFn = options.sleepFn ?? sleep;
  let lastResult = null;

  for (let attempt_number = 1; attempt_number <= max_attempts; attempt_number += 1) {
    const sendResult = await sendProviderHttpsPost(destination, json, options);
    if (sendResult?.ok) {
      return {
        sendResult,
        attempt_number,
        max_attempts,
        exhausted: false,
      };
    }

    lastResult = sendResult;
    const retryable = isRetryableRemediationSendError(sendResult);
    if (!retryable || attempt_number >= max_attempts) {
      return {
        sendResult: lastResult,
        attempt_number,
        max_attempts,
        exhausted: true,
      };
    }

    const delayMs = baseBackoffMs * (2 ** (attempt_number - 1));
    await sleepFn(delayMs);
  }

  return {
    sendResult: lastResult,
    attempt_number: max_attempts,
    max_attempts,
    exhausted: true,
  };
}

function mapRemediationSendResult(sendOutcome, deliveredReason) {
  const { sendResult, attempt_number, max_attempts, exhausted } = sendOutcome;

  if (sendResult?.ok) {
    return {
      status: 'delivered_provider',
      reason: deliveredReason,
      attempt_number,
      max_attempts,
      provider_status: sendResult.status ?? null,
      exhausted: false,
    };
  }

  const providerError = sendResult?.error ?? 'provider_send_failed';
  return {
    status: 'provider_failed_dlq',
    reason: providerError,
    attempt_number,
    max_attempts,
    provider_error: providerError,
    exhausted,
  };
}

/**
 * @param {{
 *   channel: string,
 *   connectorType: string,
 *   payload: Record<string, unknown>,
 *   dryRun?: boolean,
 *   deliveryMode?: string,
 *   fetchFn?: typeof fetch,
 *   destination?: string,
 *   baseBackoffMs?: number,
 *   sleepFn?: (ms: number) => Promise<void>,
 * }} input
 */
export async function executeRemediationDelivery(input) {
  const {
    channel,
    connectorType,
    payload,
    dryRun = true,
    deliveryMode,
    fetchFn,
    destination: destinationOverride,
    baseBackoffMs,
    sleepFn,
  } = input;

  assertNoRawWafEvidence(payload);

  const destination = resolveRemediationDestination(channel, { destination: destinationOverride });
  const destination_preview = destination
    ? remediationDestinationPreview(channel, destination)
    : null;

  const outboundBody = extractRemediationOutboundBody(connectorType, payload);
  assertNoRawWafEvidence(outboundBody);
  const encoded = encodeProviderPayload(outboundBody);
  if (!encoded.ok) {
    return {
      channel,
      connector: connectorType,
      status: 'provider_failed_dlq',
      reason: encoded.error,
      dry_run: dryRun,
      destination_preview,
      payload_byte_length: encoded.byteLength ?? null,
      exhausted: true,
    };
  }

  if (dryRun) {
    return {
      channel,
      connector: connectorType,
      status: 'metadata_only',
      reason: 'dry_run_payload_preview',
      dry_run: true,
      destination_preview,
      payload: redactObject(outboundBody),
      payload_byte_length: encoded.byteLength,
    };
  }

  const modes = parseRemediationDeliveryModes(
    deliveryMode ?? process.env.ASTRANULL_REMEDIATION_DELIVERY_MODE,
  );
  if (!isRemediationDeliveryActive(modes, channel)) {
    return {
      channel,
      connector: connectorType,
      status: 'queued_provider_not_configured',
      reason: 'remediation_delivery_mode_metadata_only',
      dry_run: false,
      destination_preview,
      payload_byte_length: encoded.byteLength,
    };
  }

  if (!destination) {
    return {
      channel,
      connector: connectorType,
      status: 'queued_provider_not_configured',
      reason: `remediation_${channel}_url_not_configured`,
      dry_run: false,
      destination_preview: null,
      payload_byte_length: encoded.byteLength,
    };
  }

  const destCheck = rejectProviderDestinationWithCredentials(destination);
  if (!destCheck.ok) {
    return {
      channel,
      connector: connectorType,
      status: 'provider_failed_dlq',
      reason: destCheck.error,
      dry_run: false,
      destination_preview,
      payload_byte_length: encoded.byteLength,
      exhausted: true,
    };
  }

  const sendOutcome = await sendRemediationWithBoundedRetry(destination, encoded.json, {
    fetchFn,
    timeoutMs: REMEDIATION_DELIVERY_TIMEOUT_MS,
    baseBackoffMs,
    sleepFn,
  });
  const mapped = mapRemediationSendResult(sendOutcome, `${channel}_delivered`);
  return {
    channel,
    connector: connectorType,
    status: mapped.status,
    reason: mapped.reason,
    dry_run: false,
    destination_preview,
    payload_byte_length: encoded.byteLength,
    attempt_number: mapped.attempt_number,
    max_attempts: mapped.max_attempts,
    provider_status: mapped.provider_status ?? null,
    ...(mapped.provider_error ? { provider_error: mapped.provider_error } : {}),
    ...(mapped.exhausted != null ? { exhausted: mapped.exhausted } : {}),
  };
}