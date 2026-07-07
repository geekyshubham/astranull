import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';
import {
  isPortalRevampRoute,
  portalRevampServicesWired,
  requiredPortalRevampServiceBindings,
  requiredPortalRevampServiceMethods,
} from '../../src/lib/postgresRouteGuard.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SERVER_SOURCE = readFileSync(path.join(__dirname, '../../src/server.mjs'), 'utf8');

/** @type {readonly { method: string, path: string }[]} */
const PORTAL_REVAMP_ROUTE_FIXTURES = Object.freeze([
  { method: 'GET', path: '/v1/target-groups/tg_1/dns-ownership' },
  { method: 'POST', path: '/v1/target-groups/tg_1/dns-ownership/issue' },
  { method: 'POST', path: '/v1/target-groups/tg_1/dns-ownership/verify' },
  { method: 'GET', path: '/v1/targets/tgt_1' },
  { method: 'POST', path: '/v1/target-groups/tg_1/loa' },
  { method: 'GET', path: '/v1/target-groups/tg_1/loa' },
  { method: 'POST', path: '/v1/target-groups/tg_1/loa/loa_1/revoke' },
  { method: 'POST', path: '/v1/target-groups/tg_1/targets/tgt_1:confirm' },
  { method: 'GET', path: '/v1/target-groups/tg_1/verification-ladder' },
  { method: 'GET', path: '/v1/connectors/cn_1/inventory' },
  { method: 'POST', path: '/v1/target-groups/tg_1/targets:bulk-import' },
  { method: 'GET', path: '/v1/waf/coverage/summary' },
  { method: 'GET', path: '/v1/findings/fnd_1/evidence' },
  { method: 'POST', path: '/v1/target-groups/tg_1/restore' },
  { method: 'GET', path: '/v1/signup-requests/signup_1/events' },
]);

describe('postgres route guard — portal revamp (FT-RLS-02)', () => {
  for (const route of PORTAL_REVAMP_ROUTE_FIXTURES) {
    it(`classifies ${route.method} ${route.path} as a portal revamp route`, () => {
      assert.equal(isPortalRevampRoute(route.path, route.method), true);
    });

    it(`requires service bindings for ${route.method} ${route.path}`, () => {
      const bindings = requiredPortalRevampServiceBindings(route.path, route.method);
      assert.ok(bindings.length > 0, 'expected at least one service binding');
      for (const binding of bindings) {
        assert.ok(binding.service, 'binding.service is required');
        assert.ok(binding.methods.length > 0, 'binding.methods must not be empty');
      }
      const flat = requiredPortalRevampServiceMethods(route.path, route.method);
      assert.ok(flat.length > 0);
    });
  }

  it('detects missing portal revamp service methods in postgres mode', () => {
    const wired = portalRevampServicesWired(
      {
        dnsOwnership: { listChallenges: () => {} },
      },
      '/v1/target-groups/tg_1/dns-ownership',
      'GET',
    );
    assert.equal(wired, true);

    const unwired = portalRevampServicesWired({}, '/v1/targets/tgt_1', 'GET');
    assert.equal(unwired, false);
  });

  it('server.mjs registers blockPostgresPortalRevampRoute for portal revamp routes', () => {
    assert.match(SERVER_SOURCE, /function blockPostgresPortalRevampRoute/);
    assert.match(SERVER_SOURCE, /blockPostgresPortalRevampRoute\(runtimeConfig, serviceDeps, path, method, res\)/);
    assert.match(SERVER_SOURCE, /\/v1\/waf\/coverage\/summary/);
    assert.match(SERVER_SOURCE, /targets:bulk-import/);
    assert.ok(SERVER_SOURCE.includes(':confirm'));
  });
});