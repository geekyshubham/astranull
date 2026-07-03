import {
  CONNECTOR_POLL_BASE_BACKOFF_MS,
  CONNECTOR_POLL_MAX_ATTEMPTS,
  sleep,
} from './common.mjs';

function isRetryableProviderError(err) {
  const status = Number(err?.status ?? err?.http_status ?? 0);
  if (status === 429 || status >= 500) return true;
  const code = String(err?.code ?? '').toLowerCase();
  return code === 'network_error' || code === 'provider_timeout' || code === 'rate_limited';
}

/**
 * Bounded retry with exponential backoff for read-only provider polls.
 *
 * @param {(attempt: number) => Promise<unknown>} fn
 * @param {{ maxAttempts?: number, baseBackoffMs?: number }} [options]
 */
export async function withConnectorPollRetry(fn, options = {}) {
  const maxAttempts = Number(options.maxAttempts ?? CONNECTOR_POLL_MAX_ATTEMPTS);
  const baseBackoffMs = Number(options.baseBackoffMs ?? CONNECTOR_POLL_BASE_BACKOFF_MS);
  let lastError = null;

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      const result = await fn(attempt);
      return { result, attempts: attempt };
    } catch (err) {
      lastError = err;
      if (attempt >= maxAttempts || !isRetryableProviderError(err)) {
        break;
      }
      const delayMs = baseBackoffMs * (2 ** (attempt - 1));
      await sleep(delayMs);
    }
  }

  const wrapped = lastError instanceof Error ? lastError : new Error(String(lastError ?? 'provider_poll_failed'));
  if (!(wrapped instanceof Error)) {
    throw wrapped;
  }
  wrapped.attempts = maxAttempts;
  throw wrapped;
}