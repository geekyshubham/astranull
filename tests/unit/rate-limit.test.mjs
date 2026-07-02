import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createFixedWindowRateLimiter, deriveClientKey } from '../../src/lib/rateLimit.mjs';

describe('deriveClientKey', () => {
  it('ignores spoofed X-Forwarded-For by default and uses socket remoteAddress', () => {
    const key = deriveClientKey({
      headers: { 'x-forwarded-for': '203.0.113.1, 198.51.100.2' },
      socket: { remoteAddress: '127.0.0.1' },
    });
    assert.equal(key, 'ip:127.0.0.1');
  });

  it('ignores X-Real-IP by default', () => {
    const key = deriveClientKey({
      headers: { 'x-real-ip': '203.0.113.9' },
      socket: { remoteAddress: '10.0.0.5' },
    });
    assert.equal(key, 'ip:10.0.0.5');
  });

  it('uses the first X-Forwarded-For hop when trustProxyHeaders is true', () => {
    const key = deriveClientKey(
      {
        headers: { 'x-forwarded-for': '203.0.113.1, 198.51.100.2' },
        socket: { remoteAddress: '127.0.0.1' },
      },
      { trustProxyHeaders: true },
    );
    assert.equal(key, 'ip:203.0.113.1');
  });

  it('falls back to socket remoteAddress when trustProxyHeaders is true but headers absent', () => {
    const key = deriveClientKey(
      {
        headers: {},
        socket: { remoteAddress: '::1' },
      },
      { trustProxyHeaders: true },
    );
    assert.equal(key, 'ip:::1');
  });
});

describe('fixed-window rate limiter', () => {
  it('allows requests up to max then blocks until window resets', () => {
    let clock = 1_000_000;
    const limiter = createFixedWindowRateLimiter({
      windowMs: 10_000,
      maxRequests: 2,
      now: () => clock,
    });

    assert.equal(limiter.check('client-a').allowed, true);
    assert.equal(limiter.check('client-a').allowed, true);
    const blocked = limiter.check('client-a');
    assert.equal(blocked.allowed, false);
    assert.ok(blocked.retryAfterSeconds >= 1);

    clock += 10_000;
    assert.equal(limiter.check('client-a').allowed, true);
  });

  it('tracks separate keys independently', () => {
    const limiter = createFixedWindowRateLimiter({
      windowMs: 60_000,
      maxRequests: 1,
      now: () => 0,
    });
    assert.equal(limiter.check('client-a').allowed, true);
    assert.equal(limiter.check('client-a').allowed, false);
    assert.equal(limiter.check('client-b').allowed, true);
  });

  it('prunes stale buckets when the window advances', () => {
    let clock = 0;
    const limiter = createFixedWindowRateLimiter({
      windowMs: 1_000,
      maxRequests: 1,
      now: () => clock,
    });

    for (let i = 0; i < 25; i++) {
      limiter.check(`client-${i}`);
    }
    assert.equal(limiter.bucketCount(), 25);

    clock = 1_000;
    limiter.check('client-new');
    assert.equal(limiter.bucketCount(), 1);
  });
});