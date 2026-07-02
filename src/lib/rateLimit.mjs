/**
 * In-process fixed-window rate limiter (no external deps).
 */

export function deriveClientKey(req, { trustProxyHeaders = false } = {}) {
  if (trustProxyHeaders) {
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded) {
      const first = String(forwarded).split(',')[0].trim();
      if (first) return `ip:${first}`;
    }
    const realIp = req.headers['x-real-ip'];
    if (realIp) {
      const trimmed = String(realIp).trim();
      if (trimmed) return `ip:${trimmed}`;
    }
  }
  const addr = req.socket?.remoteAddress ?? 'unknown';
  return `ip:${addr}`;
}

export function createFixedWindowRateLimiter({ windowMs, maxRequests, now = () => Date.now() }) {
  if (!Number.isInteger(windowMs) || windowMs < 1) {
    throw new Error('createFixedWindowRateLimiter requires a positive integer windowMs');
  }
  if (!Number.isInteger(maxRequests) || maxRequests < 1) {
    throw new Error('createFixedWindowRateLimiter requires a positive integer maxRequests');
  }

  /** @type {Map<string, { windowIndex: number, count: number }>} */
  const buckets = new Map();

  function check(key) {
    const t = now();
    const windowIndex = Math.floor(t / windowMs);
    for (const [k, b] of buckets) {
      if (b.windowIndex < windowIndex) {
        buckets.delete(k);
      }
    }
    let bucket = buckets.get(key);
    if (!bucket || bucket.windowIndex !== windowIndex) {
      bucket = { windowIndex, count: 0 };
      buckets.set(key, bucket);
    }
    bucket.count += 1;
    const allowed = bucket.count <= maxRequests;
    const windowEndMs = (windowIndex + 1) * windowMs;
    const retryAfterSeconds = Math.max(1, Math.ceil((windowEndMs - t) / 1000));
    return {
      allowed,
      retryAfterSeconds,
      remaining: Math.max(0, maxRequests - bucket.count),
    };
  }

  return {
    check,
    bucketCount: () => buckets.size,
  };
}