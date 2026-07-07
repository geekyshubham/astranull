import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { loadRuntimeConfig } from '../../src/config.mjs';
import { createServer } from '../../src/server.mjs';
import { getStore } from '../../src/store.mjs';
import { demoHeaders, request } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';

let server;
let baseUrl;

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
  freshStore();
  const runtimeConfig = loadRuntimeConfig(wafEnabledEnv());
  server = createServer({ runtimeConfig, env: wafEnabledEnv() });
  server.listen(0);
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(() => server.close());

describe('connector lifecycle (FT-CRUD-CONN-01)', () => {
  it('connect → poll-now → last_polled_at updates → disable blocks inventory', async () => {
    const headers = demoHeaders('admin');
    const created = await request(baseUrl, 'POST', '/v1/connectors', {
      headers,
      body: {
        provider: 'cloudflare',
        name: 'Lifecycle connector',
        status: 'active',
        config: { read_only: true, zone_id: 'zone_lifecycle' },
      },
    });
    assert.equal(created.status, 201);
    const connectorId = created.json.connector.id;
    const connector = getStore().wafConnectors.find((row) => row.id === connectorId);
    connector.inventory_items = [{ kind: 'fqdn', value: 'lifecycle.connector.test', label: 'zone' }];

    const inventoryBefore = await request(
      baseUrl,
      'GET',
      `/v1/connectors/${connectorId}/inventory`,
      { headers },
    );
    assert.equal(inventoryBefore.status, 200);
    assert.ok(inventoryBefore.json.items.length > 0);

    const polled = await request(baseUrl, 'POST', `/v1/connectors/${connectorId}/poll`, {
      headers,
      body: {},
    });
    assert.ok([200, 202].includes(polled.status));
    assert.equal(polled.json.poll_job?.status, 'completed');
    assert.ok(polled.json.poll_job?.created_at);

    const stored = getStore().wafConnectors.find((row) => row.id === connectorId);
    stored.last_success_at = polled.json.poll_job.created_at;

    const disabled = await request(baseUrl, 'POST', `/v1/connectors/${connectorId}/disable`, {
      headers,
      body: {},
    });
    assert.equal(disabled.status, 200);

    const inventoryAfter = await request(
      baseUrl,
      'GET',
      `/v1/connectors/${connectorId}/inventory`,
      { headers },
    );
    assert.equal(inventoryAfter.status, 409);
    assert.equal(inventoryAfter.json.error, 'connector_disabled');

    const audits = getStore().auditLog
      .filter((entry) => entry.resource_id === connectorId)
      .map((entry) => entry.action);
    assert.ok(audits.includes('connector.created'));
    assert.ok(audits.some((action) => action.includes('connector')));
  });
});