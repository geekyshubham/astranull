import assert from 'node:assert/strict';
import test from 'node:test';
import {
  discoverRailwayBaseUrl,
  normalizeHostedBaseUrl,
  parseHostedStagingStackArgs,
} from '../../scripts/hosted-staging-stack.mjs';

test('normalizeHostedBaseUrl strips quotes and trailing slashes', () => {
  assert.equal(
    normalizeHostedBaseUrl('https://control-plane-production-3404.up.railway.app"'),
    'https://control-plane-production-3404.up.railway.app',
  );
  assert.equal(
    normalizeHostedBaseUrl('control-plane-production-3404.up.railway.app/'),
    'https://control-plane-production-3404.up.railway.app',
  );
});

test('parseHostedStagingStackArgs honors --base-url', () => {
  const opts = parseHostedStagingStackArgs(['smoke', '--base-url', 'https://staging.example.test/']);
  assert.equal(opts.command, 'smoke');
  assert.equal(opts.baseUrl, 'https://staging.example.test/');
});

test('discoverRailwayBaseUrl returns sanitized https URL when railway CLI is available', () => {
  const discovered = discoverRailwayBaseUrl();
  if (!discovered) return;
  assert.match(discovered, /^https:\/\/[^\s"']+$/);
  assert.doesNotMatch(discovered, /["']$/);
});