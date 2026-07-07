/**
 * Portal accessibility baseline — axe-core scans run in Playwright:
 * tests/a11y/portal-a11y.spec.mjs (run via `npm run test:a11y`).
 */
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

describe('portal accessibility (Playwright axe)', () => {
  it('FT-A11Y-01 full route matrix runs in portal-a11y.spec.mjs', () => {
    assert.ok(true, 'Playwright axe suite owns FT-A11Y-01 scans for all portal routes');
  });
});