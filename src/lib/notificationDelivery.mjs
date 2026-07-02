import net from 'node:net';
import tls from 'node:tls';
import { collectForbiddenEvidenceFields } from './redact.mjs';

const DEFAULT_DELIVERY_MODE = 'metadata_only';
export const WEBHOOK_DELIVERY_MODE = 'webhook';

export const WEBHOOK_MAX_ATTEMPTS = 3;
export const WEBHOOK_TIMEOUT_MS = 10_000;
export const WEBHOOK_MAX_PAYLOAD_BYTES = 32_768;
export const PROVIDER_MAX_PAYLOAD_BYTES = 65_536;

export const SMTP_CONNECT_TIMEOUT_MS = 10_000;
export const SMTP_TOTAL_TIMEOUT_MS = 10_000;

const VALID_DELIVERY_MODES = new Set([
  'webhook',
  'email',
  'slack',
  'teams',
  'all',
  'metadata_only',
]);

/**
 * @param {string | undefined | null} raw
 * @returns {Set<string>}
 */
export function parseNotificationDeliveryModes(raw) {
  const modes = new Set();
  const str = String(raw ?? '').trim().toLowerCase();
  if (!str || str === DEFAULT_DELIVERY_MODE) {
    modes.add('metadata_only');
    return modes;
  }

  for (const part of str.split(',').map((segment) => segment.trim()).filter(Boolean)) {
    if (!VALID_DELIVERY_MODES.has(part)) continue;
    if (part === 'all') {
      modes.add('webhook');
      modes.add('email');
      modes.add('slack');
      modes.add('teams');
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
export function isDeliveryChannelActive(modes, channel) {
  if (modes.has('metadata_only') && modes.size === 1) return false;
  return modes.has(channel);
}

/**
 * @param {{ deliveryMode?: string }} [options]
 */
export function resolveNotificationDeliveryMode(options = {}) {
  const raw =
    options.deliveryMode ?? process.env.ASTRANULL_NOTIFICATION_DELIVERY_MODE ?? DEFAULT_DELIVERY_MODE;
  const modes = parseNotificationDeliveryModes(raw);
  if (modes.has('metadata_only') && modes.size === 1) return DEFAULT_DELIVERY_MODE;
  return [...modes].sort().join(',');
}

function isAllowedHttpsDestination(destination) {
  let url;
  try {
    url = new URL(destination);
  } catch {
    return false;
  }
  if (url.username || url.password) return false;
  if (url.protocol === 'https:') return true;
  if (url.protocol !== 'http:') return false;
  const host = url.hostname.toLowerCase();
  if (host === '127.0.0.1' || host === 'localhost') return true;
  if (host.endsWith('.invalid')) return true;
  return false;
}

/**
 * @param {string} destination
 */
export function rejectWebhookDestinationWithCredentials(destination) {
  try {
    const url = new URL(destination);
    if (url.username || url.password) {
      return { ok: false, error: 'webhook_url_credentials_not_allowed' };
    }
    if (!isAllowedHttpsDestination(destination)) {
      return { ok: false, error: 'invalid_webhook_destination' };
    }
    return { ok: true };
  } catch {
    return { ok: false, error: 'invalid_webhook_destination' };
  }
}

/**
 * @param {string} destination
 */
export function rejectProviderDestinationWithCredentials(destination) {
  return rejectWebhookDestinationWithCredentials(destination);
}

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * @param {Record<string, unknown>} metadata
 */
function formatMetadataSummary(metadata) {
  const entries = Object.entries(metadata ?? {});
  if (entries.length === 0) return 'No additional metadata';
  return entries
    .map(([key, value]) => {
      const rendered =
        typeof value === 'string' ? value : JSON.stringify(value ?? null);
      return `${key}: ${rendered}`;
    })
    .join('\n');
}

/**
 * @param {{
 *   trigger: string,
 *   subject: string,
 *   metadata: Record<string, unknown>,
 *   created_at: string,
 * }} event
 * @param {{ destination: string }} rule
 */
export function buildEmailPayload(event, rule) {
  const from = process.env.ASTRANULL_SMTP_FROM?.trim() || 'noreply@astranull.local';
  const to = rule.destination;
  const subject = `[AstraNull] ${event.subject}`;
  const metadataSummary = formatMetadataSummary(event.metadata);
  const html_body = `<!DOCTYPE html>
<html><body>
<table border="1" cellpadding="6" cellspacing="0">
<tr><th>Trigger</th><td>${escapeHtml(event.trigger)}</td></tr>
<tr><th>Subject</th><td>${escapeHtml(event.subject)}</td></tr>
<tr><th>Metadata</th><td><pre>${escapeHtml(metadataSummary)}</pre></td></tr>
<tr><th>Timestamp</th><td>${escapeHtml(event.created_at)}</td></tr>
</table>
</body></html>`;

  return { from, to, subject, html_body };
}

/**
 * @param {{
 *   trigger: string,
 *   subject: string,
 *   metadata: Record<string, unknown>,
 *   created_at: string,
 * }} event
 * @param {{ destination: string }} rule
 */
export function buildSlackPayload(event, rule) {
  void rule;
  const metadataSummary = formatMetadataSummary(event.metadata);
  return {
    blocks: [
      {
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: `*${event.trigger}*\n${event.subject}`,
        },
      },
      {
        type: 'context',
        elements: [
          {
            type: 'mrkdwn',
            text: `Recorded at ${event.created_at}`,
          },
        ],
      },
      {
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: metadataSummary,
        },
      },
    ],
  };
}

/**
 * @param {{
 *   trigger: string,
 *   subject: string,
 *   metadata: Record<string, unknown>,
 *   created_at: string,
 * }} event
 * @param {{ destination: string }} rule
 */
export function buildTeamsPayload(event, rule) {
  void rule;
  const metadataSummary = formatMetadataSummary(event.metadata);
  return {
    type: 'message',
    attachments: [
      {
        contentType: 'application/vnd.microsoft.card.adaptive',
        content: {
          $schema: 'http://adaptivecards.io/schemas/adaptive-card.json',
          type: 'AdaptiveCard',
          version: '1.4',
          body: [
            {
              type: 'TextBlock',
              text: event.trigger,
              weight: 'Bolder',
              size: 'Medium',
            },
            {
              type: 'TextBlock',
              text: event.subject,
              wrap: true,
            },
            {
              type: 'TextBlock',
              text: metadataSummary,
              wrap: true,
            },
            {
              type: 'TextBlock',
              text: event.created_at,
              isSubtle: true,
            },
          ],
          actions: [
            {
              type: 'Action.OpenUrl',
              title: 'View notification',
              url: 'https://app.astranull.local/notifications',
            },
          ],
        },
      },
    ],
  };
}

/**
 * @param {Record<string, unknown>} body
 * @param {number} [maxBytes]
 */
export function encodeProviderPayload(body, maxBytes = PROVIDER_MAX_PAYLOAD_BYTES) {
  const json = JSON.stringify(body);
  const bytes = Buffer.byteLength(json, 'utf8');
  if (bytes > maxBytes) {
    return { ok: false, error: 'provider_payload_too_large', byteLength: bytes };
  }
  return { ok: true, json, byteLength: bytes };
}

/**
 * @param {Record<string, unknown>} body
 */
export function encodeWebhookPayload(body) {
  return encodeProviderPayload(body, WEBHOOK_MAX_PAYLOAD_BYTES);
}

/**
 * @param {string} destination
 * @param {string} json
 * @param {{ fetchFn?: typeof fetch, timeoutMs?: number, maxPayloadBytes?: number }} [options]
 */
export async function sendProviderHttpsPost(destination, json, options = {}) {
  const destCheck = rejectProviderDestinationWithCredentials(destination);
  if (!destCheck.ok) {
    return { ok: false, error: destCheck.error, transport: 'rejected_precheck' };
  }

  const fetchFn = options.fetchFn ?? fetch;
  const timeoutMs = options.timeoutMs ?? WEBHOOK_TIMEOUT_MS;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetchFn(destination, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: json,
      redirect: 'manual',
      signal: controller.signal,
    });
    if (res.status >= 300 && res.status < 400) {
      return { ok: false, error: 'provider_redirect_not_allowed', status: res.status, transport: 'http' };
    }
    if (!res.ok) {
      return {
        ok: false,
        error: 'provider_http_error',
        status: res.status,
        transport: 'http',
      };
    }
    return { ok: true, status: res.status, transport: 'http' };
  } catch (err) {
    const message = err instanceof Error ? err.message : 'provider_send_failed';
    return { ok: false, error: message, transport: 'http' };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * @param {string} destination
 * @param {string} json
 * @param {{ fetchFn?: typeof fetch, timeoutMs?: number }} [options]
 */
export async function sendWebhookNotification(destination, json, options = {}) {
  const destCheck = rejectWebhookDestinationWithCredentials(destination);
  if (!destCheck.ok) {
    return { ok: false, error: destCheck.error, transport: 'rejected_precheck' };
  }

  const fetchFn = options.fetchFn ?? fetch;
  const timeoutMs = options.timeoutMs ?? WEBHOOK_TIMEOUT_MS;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetchFn(destination, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: json,
      redirect: 'manual',
      signal: controller.signal,
    });
    if (res.status >= 300 && res.status < 400) {
      return { ok: false, error: 'webhook_redirect_not_allowed', status: res.status, transport: 'http' };
    }
    if (!res.ok) {
      return {
        ok: false,
        error: 'webhook_http_error',
        status: res.status,
        transport: 'http',
      };
    }
    return { ok: true, status: res.status, transport: 'http' };
  } catch (err) {
    const message = err instanceof Error ? err.message : 'webhook_send_failed';
    return { ok: false, error: message, transport: 'http' };
  } finally {
    clearTimeout(timer);
  }
}

function createSmtpLineReader(socket) {
  let buffer = '';
  /** @type {string[]} */
  const queue = [];
  /** @type {((line: string) => void) | null} */
  let waiter = null;

  socket.on('data', (chunk) => {
    buffer += chunk.toString('utf8');
    let idx = buffer.indexOf('\n');
    while (idx !== -1) {
      const line = buffer.slice(0, idx).replace(/\r$/, '');
      buffer = buffer.slice(idx + 1);
      if (waiter) {
        const resolve = waiter;
        waiter = null;
        resolve(line);
      } else {
        queue.push(line);
      }
      idx = buffer.indexOf('\n');
    }
  });

  return {
    readLine() {
      return new Promise((resolve, reject) => {
        if (queue.length > 0) {
          resolve(queue.shift());
          return;
        }
        const onError = (err) => {
          waiter = null;
          reject(err);
        };
        const onClose = () => {
          waiter = null;
          reject(new Error('smtp_connection_closed'));
        };
        waiter = (line) => {
          socket.off('error', onError);
          socket.off('close', onClose);
          resolve(line);
        };
        socket.once('error', onError);
        socket.once('close', onClose);
      });
    },
  };
}

async function readSmtpResponse(reader) {
  const lines = [];
  let line = await reader.readLine();
  lines.push(line);
  let code = Number.parseInt(line.slice(0, 3), 10);
  while (line.length > 3 && line[3] === '-') {
    line = await reader.readLine();
    lines.push(line);
    code = Number.parseInt(line.slice(0, 3), 10);
  }
  if (!Number.isFinite(code)) throw new Error('smtp_invalid_response');
  return { code, text: lines.join('\n') };
}

async function expectSmtpResponse(reader, expectedCodes) {
  const response = await readSmtpResponse(reader);
  if (!expectedCodes.includes(response.code)) {
    throw new Error(`smtp_unexpected_response_${response.code}`);
  }
  return response;
}

function smtpWrite(socket, command) {
  socket.write(`${command}\r\n`);
}

/**
 * @param {{ from: string, to: string, subject: string, html_body: string }} envelope
 * @param {{
 *   smtpHost?: string,
 *   smtpPort?: number,
 *   smtpStartTls?: boolean,
 *   connect?: typeof net.connect,
 *   secureConnect?: typeof tls.connect,
 * }} [options]
 */
export async function deliverEmail(envelope, options = {}) {
  const host = options.smtpHost ?? process.env.ASTRANULL_SMTP_HOST;
  if (!host || !String(host).trim()) {
    return {
      status: 'queued_provider_not_configured',
      reason: 'smtp_host_not_configured',
    };
  }

  const port = Number(options.smtpPort ?? process.env.ASTRANULL_SMTP_PORT ?? 587);
  const startTls =
    options.smtpStartTls ??
    (process.env.ASTRANULL_SMTP_STARTTLS === undefined
      ? true
      : process.env.ASTRANULL_SMTP_STARTTLS !== 'false');
  const connectFn = options.connect ?? net.connect;
  const secureConnectFn = options.secureConnect ?? tls.connect;

  let socket;

  try {
    socket = await new Promise((resolve, reject) => {
      const connectTimer = setTimeout(() => reject(new Error('smtp_connect_timeout')), SMTP_CONNECT_TIMEOUT_MS);
      const rawSocket = connectFn({ host, port }, () => {
        clearTimeout(connectTimer);
        resolve(rawSocket);
      });
      rawSocket.once('error', (err) => {
        clearTimeout(connectTimer);
        reject(err);
      });
    });

    const deadline = setTimeout(() => socket.destroy(new Error('smtp_total_timeout')), SMTP_TOTAL_TIMEOUT_MS);

    let reader = createSmtpLineReader(socket);
    await expectSmtpResponse(reader, [220]);

    smtpWrite(socket, 'EHLO astranull.local');
    const ehlo = await expectSmtpResponse(reader, [250]);

    if (startTls && ehlo.text.toUpperCase().includes('STARTTLS')) {
      smtpWrite(socket, 'STARTTLS');
      await expectSmtpResponse(reader, [220]);
      socket.removeAllListeners('data');
      socket = await new Promise((resolve, reject) => {
        const tlsSocket = secureConnectFn({ socket, servername: host }, () => resolve(tlsSocket));
        tlsSocket.once('error', reject);
      });
      reader = createSmtpLineReader(socket);
      smtpWrite(socket, 'EHLO astranull.local');
      await expectSmtpResponse(reader, [250]);
    }

    await runSmtpMailTransaction(reader, socket, envelope);

    clearTimeout(deadline);
    smtpWrite(socket, 'QUIT');
    socket.end();

    return {
      status: 'delivered_provider',
      reason: 'email_delivered',
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : 'smtp_send_failed';
    socket?.destroy?.();
    const attempt_number = 1;
    const max_attempts = WEBHOOK_MAX_ATTEMPTS;
    if (attempt_number < max_attempts) {
      return {
        status: 'provider_retry_scheduled',
        reason: message,
        attempt_number,
        max_attempts,
        provider_error: message,
        exhausted: false,
      };
    }
    return {
      status: 'provider_failed_dlq',
      reason: message,
      attempt_number,
      max_attempts,
      provider_error: message,
      exhausted: true,
    };
  }
}

async function runSmtpMailTransaction(reader, socket, envelope) {
  smtpWrite(socket, `MAIL FROM:<${envelope.from}>`);
  await expectSmtpResponse(reader, [250]);
  smtpWrite(socket, `RCPT TO:<${envelope.to}>`);
  await expectSmtpResponse(reader, [250, 251]);
  smtpWrite(socket, 'DATA');
  await expectSmtpResponse(reader, [354]);
  const message = [
    `From: ${envelope.from}`,
    `To: ${envelope.to}`,
    `Subject: ${envelope.subject}`,
    'MIME-Version: 1.0',
    'Content-Type: text/html; charset=utf-8',
    '',
    envelope.html_body,
    '.',
  ].join('\r\n');
  smtpWrite(socket, message);
  await expectSmtpResponse(reader, [250]);
}

/**
 * @param {Record<string, unknown>} payload
 * @param {string} destination
 * @param {{ fetchFn?: typeof fetch, timeoutMs?: number }} [options]
 */
export async function deliverSlack(payload, destination, options = {}) {
  const encoded = encodeProviderPayload(payload);
  if (!encoded.ok) {
    return {
      status: 'provider_failed_dlq',
      reason: encoded.error,
      provider_error: encoded.error,
      exhausted: true,
    };
  }

  const sendResult = await sendProviderHttpsPost(destination, encoded.json, options);
  return mapProviderSendResult(sendResult, 'slack_delivered');
}

/**
 * @param {Record<string, unknown>} payload
 * @param {string} destination
 * @param {{ fetchFn?: typeof fetch, timeoutMs?: number }} [options]
 */
export async function deliverTeams(payload, destination, options = {}) {
  const encoded = encodeProviderPayload(payload);
  if (!encoded.ok) {
    return {
      status: 'provider_failed_dlq',
      reason: encoded.error,
      provider_error: encoded.error,
      exhausted: true,
    };
  }

  const sendResult = await sendProviderHttpsPost(destination, encoded.json, options);
  return mapProviderSendResult(sendResult, 'teams_delivered');
}

function mapProviderSendResult(sendResult, deliveredReason) {
  const attempt_number = 1;
  const max_attempts = WEBHOOK_MAX_ATTEMPTS;

  if (sendResult?.ok) {
    return {
      status: 'delivered_provider',
      reason: deliveredReason,
      attempt_number,
      max_attempts,
      provider_status: sendResult.status ?? null,
    };
  }

  const providerError = sendResult?.error ?? 'provider_send_failed';
  if (attempt_number < max_attempts) {
    return {
      status: 'provider_retry_scheduled',
      reason: providerError,
      attempt_number,
      max_attempts,
      provider_error: providerError,
      exhausted: false,
    };
  }

  return {
    status: 'provider_failed_dlq',
    reason: providerError,
    attempt_number,
    max_attempts,
    provider_error: providerError,
    exhausted: true,
  };
}

function addMs(iso, ms) {
  return new Date(new Date(iso).getTime() + ms).toISOString();
}

function applyProviderResult(attempt, result, now) {
  if (result.status === 'queued_provider_not_configured') {
    return attempt;
  }

  const attempt_number = result.attempt_number ?? 1;
  const max_attempts = result.max_attempts ?? WEBHOOK_MAX_ATTEMPTS;
  const base = {
    ...attempt,
    attempted_at: now,
    attempt_number,
    max_attempts,
  };

  if (result.status === 'delivered_provider') {
    return {
      ...base,
      status: 'delivered_provider',
      reason: result.reason,
      provider_status: result.provider_status ?? null,
    };
  }

  if (result.status === 'provider_retry_scheduled') {
    return {
      ...base,
      status: 'provider_retry_scheduled',
      reason: result.reason,
      next_retry_at: addMs(now, 60_000),
      provider_error: result.provider_error ?? result.reason,
      exhausted: false,
    };
  }

  return {
    ...base,
    status: 'provider_failed_dlq',
    reason: result.reason,
    provider_error: result.provider_error ?? result.reason,
    exhausted: true,
  };
}

/**
 * @param {{
 *   event_id: string,
 *   rule_id: string,
 *   trigger: string,
 *   subject: string,
 *   metadata: Record<string, unknown>,
 *   created_at: string,
 * }} fields
 */
export function buildWebhookNotificationBody(fields) {
  return {
    event_id: fields.event_id,
    rule_id: fields.rule_id,
    trigger: fields.trigger,
    subject: fields.subject,
    metadata: fields.metadata,
    created_at: fields.created_at,
  };
}

async function finalizeWebhookAttempt(attempt, rule, event, now, input) {
  const attempt_number = 1;
  const max_attempts = WEBHOOK_MAX_ATTEMPTS;
  const body = buildWebhookNotificationBody({
    event_id: event.id,
    rule_id: attempt.rule_id,
    trigger: event.trigger,
    subject: event.subject,
    metadata: event.metadata,
    created_at: event.created_at,
  });
  const encoded = encodeWebhookPayload(body);
  if (!encoded.ok) {
    return {
      ...attempt,
      status: 'provider_failed_dlq',
      reason: encoded.error,
      attempted_at: now,
      attempt_number,
      max_attempts,
      provider_error: encoded.error,
      exhausted: true,
    };
  }

  let sendResult;
  if (typeof input.webhookSender === 'function') {
    sendResult = await input.webhookSender(rule.destination, body);
  } else {
    sendResult = await sendWebhookNotification(rule.destination, encoded.json, {
      fetchFn: input.fetchFn,
    });
  }

  if (sendResult?.ok) {
    return {
      ...attempt,
      status: 'delivered_provider',
      reason: 'webhook_delivered',
      attempted_at: now,
      attempt_number,
      max_attempts,
      provider_status: sendResult.status ?? null,
    };
  }

  const retryable = attempt_number < max_attempts;
  if (retryable) {
    return {
      ...attempt,
      status: 'provider_retry_scheduled',
      reason: sendResult?.error ?? 'webhook_send_failed',
      attempted_at: now,
      attempt_number,
      max_attempts,
      next_retry_at: addMs(now, 60_000),
      provider_error: sendResult?.error ?? 'webhook_send_failed',
      exhausted: false,
    };
  }

  return {
    ...attempt,
    status: 'provider_failed_dlq',
    reason: sendResult?.error ?? 'webhook_send_failed',
    attempted_at: now,
    attempt_number,
    max_attempts,
    provider_error: sendResult?.error ?? 'webhook_send_failed',
    exhausted: true,
  };
}

/**
 * @param {{
 *   deliveryMode: string,
 *   attempts: Array<Record<string, unknown>>,
 *   rules: Array<{ id: string, channel: string, destination: string }>,
 *   event: { id: string, trigger: string, subject: string, metadata: Record<string, unknown>, created_at: string },
 *   now: string,
 *   webhookSender?: (destination: string, body: Record<string, unknown>) => Promise<{ ok: boolean, error?: string, status?: number }> | { ok: boolean, error?: string, status?: number },
 *   fetchFn?: typeof fetch,
 *   emailDeliverer?: (envelope: { from: string, to: string, subject: string, html_body: string }) => Promise<Record<string, unknown>> | Record<string, unknown>,
 *   slackDeliverer?: (payload: Record<string, unknown>, destination: string) => Promise<Record<string, unknown>> | Record<string, unknown>,
 *   teamsDeliverer?: (payload: Record<string, unknown>, destination: string) => Promise<Record<string, unknown>> | Record<string, unknown>,
 * }} input
 */
export async function finalizeNotificationDeliveryAttempts(input) {
  const { attempts, rules, event, now } = input;
  const modes = parseNotificationDeliveryModes(input.deliveryMode);
  const rulesById = new Map(rules.map((r) => [r.id, r]));
  const out = [];

  for (const attempt of attempts) {
    const rule = rulesById.get(attempt.rule_id);
    const channel = attempt.channel;

    if (channel === 'webhook' && isDeliveryChannelActive(modes, 'webhook')) {
      if (!rule?.destination) {
        out.push(attempt);
        continue;
      }
      out.push(await finalizeWebhookAttempt(attempt, rule, event, now, input));
      continue;
    }

    if (channel === 'email' && isDeliveryChannelActive(modes, 'email')) {
      if (!rule?.destination) {
        out.push(attempt);
        continue;
      }
      const envelope = buildEmailPayload(event, rule);
      const deliverer = input.emailDeliverer ?? deliverEmail;
      const result = await deliverer(envelope);
      out.push(applyProviderResult(attempt, result, now));
      continue;
    }

    if (channel === 'slack' && isDeliveryChannelActive(modes, 'slack')) {
      if (!rule?.destination) {
        out.push(attempt);
        continue;
      }
      const payload = buildSlackPayload(event, rule);
      const deliverer = input.slackDeliverer ?? ((body, destination) => deliverSlack(body, destination, { fetchFn: input.fetchFn }));
      const result = await deliverer(payload, rule.destination);
      out.push(applyProviderResult(attempt, result, now));
      continue;
    }

    if (channel === 'teams' && isDeliveryChannelActive(modes, 'teams')) {
      if (!rule?.destination) {
        out.push(attempt);
        continue;
      }
      const payload = buildTeamsPayload(event, rule);
      const deliverer = input.teamsDeliverer ?? ((body, destination) => deliverTeams(body, destination, { fetchFn: input.fetchFn }));
      const result = await deliverer(payload, rule.destination);
      out.push(applyProviderResult(attempt, result, now));
      continue;
    }

    out.push(attempt);
  }

  return out;
}