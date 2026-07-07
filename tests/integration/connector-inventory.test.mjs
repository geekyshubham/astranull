import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { after, before, describe, it } from 'node:test';
import { loadRuntimeConfig } from '../../src/config.mjs';
import { createServer } from '../../src/server.mjs';
import { mapProviderInventory, listProviderInventoryMappers } from '../../src/lib/connectorInventory.mjs';
import { getStore } from '../../src/store.mjs';
import { demoHeaders, request } from '../helpers/http.mjs';
import { seedPortalBaseline, PORTAL_BASELINE_IDS } from '../fixtures/portal-baseline/seed.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.join(__dirname, '..', 'fixtures', 'connector-responses');

let baseUrl;
let server;

function wafEnabledEnv(extra = {}) {
  return {
    ...process.env,
    ASTRANULL_NO_PERSIST: '1',
    ASTRANULL_WAF_POSTURE_ENABLED: '1',
    ASTRANULL_CONNECTORS_ENABLED: '1',
    ...extra,
  };
}

before(() => {
  seedPortalBaseline();
  const runtimeConfig = loadRuntimeConfig(wafEnabledEnv());
  server = createServer({ runtimeConfig, env: wafEnabledEnv() });
  server.listen(0);
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(() => server.close());

function ownerHeaders() {
  return demoHeaders('owner', PORTAL_BASELINE_IDS.tenantId, 'usr_owner');
}

describe('connector inventory (FT-CI-01..05)', () => {
  it('FT-CI-01 inventory returns items and never leaks credentials', async () => {
    const res = await request(
      baseUrl,
      'GET',
      `/v1/connectors/${PORTAL_BASELINE_IDS.connectorId}/inventory`,
      { headers: ownerHeaders() },
    );
    assert.equal(res.status, 200);
    assert.ok(res.json.items.length > 0);
    assert.ok(res.json.discovered_at);
    const body = JSON.stringify(res.json);
    assert.equal(/api[_-]?token/i.test(body), false);
    assert.equal(/sk_live_/i.test(body), false);
  });

  it('FT-CI-02 cursor pagination is disjoint and complete for 500 items', async () => {
    const seen = new Set();
    let cursor;
    for (let page = 0; page < 20; page += 1) {
      const path = cursor
        ? `/v1/connectors/${PORTAL_BASELINE_IDS.connectorId}/inventory?limit=50&cursor=${cursor}`
        : `/v1/connectors/${PORTAL_BASELINE_IDS.connectorId}/inventory?limit=50`;
      const res = await request(baseUrl, 'GET', path, { headers: ownerHeaders() });
      assert.equal(res.status, 200);
      for (const item of res.json.items) {
        assert.ok(!seen.has(item.value));
        seen.add(item.value);
      }
      cursor = res.json.next_cursor;
      if (!cursor) break;
    }
    assert.equal(seen.size, 500);
  });

  it('FT-CI-03 bulk import sets verify_state by kind', async () => {
    const res = await request(
      baseUrl,
      'POST',
      `/v1/target-groups/${PORTAL_BASELINE_IDS.targetGroupId}/targets:bulk-import`,
      {
        headers: ownerHeaders(),
        body: {
          source: 'cloudflare',
          items: [
            { kind: 'fqdn', value: 'imported-zone.baseline.test' },
            { kind: 'ip', value: '203.0.113.44' },
          ],
        },
      },
    );
    assert.equal(res.status, 201);
    assert.equal(res.json.imported.length, 2);
    const fqdn = res.json.imported.find((t) => t.kind === 'fqdn');
    const ip = res.json.imported.find((t) => t.kind === 'ip');
    assert.equal(fqdn.verify_state, 'pending');
    assert.equal(ip.verify_state, 'awaiting_heartbeat');
  });

  it('FT-CI-04 re-import is idempotent via skipped[]', async () => {
    const body = {
      source: 'cloudflare',
      items: [{ kind: 'fqdn', value: 'dup-zone.baseline.test' }],
    };
    const first = await request(
      baseUrl,
      'POST',
      `/v1/target-groups/${PORTAL_BASELINE_IDS.targetGroupId}/targets:bulk-import`,
      { headers: ownerHeaders(), body },
    );
    assert.equal(first.status, 201);
    const second = await request(
      baseUrl,
      'POST',
      `/v1/target-groups/${PORTAL_BASELINE_IDS.targetGroupId}/targets:bulk-import`,
      { headers: ownerHeaders(), body },
    );
    assert.equal(second.status, 201);
    assert.equal(second.json.imported.length, 0);
    assert.equal(second.json.skipped[0].reason, 'already_imported');
  });

  it('FT-CI-05 per-provider adapter maps fixture shapes', () => {
    for (const provider of listProviderInventoryMappers()) {
      const fixtureName = provider === 'aws_waf' ? 'aws' : provider;
      const fixturePath = path.join(FIXTURES, `${fixtureName}.json`);
      const raw = JSON.parse(readFileSync(fixturePath, 'utf8'));
      const items = mapProviderInventory(provider, raw);
      assert.ok(items.length > 0, `${provider} should map items`);
      assert.ok(items.every((item) => item.kind && item.value));
    }
  });
});