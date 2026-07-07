import assert from 'node:assert/strict';
import { after, before, beforeEach, describe, it } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { getStore } from '../../src/store.mjs';
import { demoHeaders, request } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';

let server;
let baseUrl;

before(() => {
  freshStore();
  server = createServer();
  server.listen(0);
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(() => {
  server?.close();
});

beforeEach(() => {
  freshStore();
});

describe('test policy lifecycle (FT-CRUD-POL-01)', () => {
  it('create → list → patch cadence → delete retains run snapshot', async () => {
    const headers = demoHeaders('engineer');
    const secondGroup = await request(baseUrl, 'POST', '/v1/target-groups', {
      headers,
      body: { name: 'Policy scope B', environment_id: 'env_demo' },
    });
    assert.equal(secondGroup.status, 201);

    const created = await request(baseUrl, 'POST', '/v1/test-policies', {
      headers,
      body: {
        target_group_id: 'tg_1',
        check_id: 'dns.authoritative_response.safe',
        cadence: 'weekly',
      },
    });
    assert.equal(created.status, 201);
    const policyId = created.json.id;

    const listed = await request(baseUrl, 'GET', '/v1/test-policies', { headers });
    assert.ok(listed.json.items.some((policy) => policy.id === policyId));

    const patched = await request(baseUrl, 'PATCH', `/v1/test-policies/${policyId}`, {
      headers,
      body: { cadence: 'daily' },
    });
    assert.equal(patched.status, 200);
    assert.equal(patched.json.cadence, 'daily');

    const policySnapshot = getStore().testPolicies.find((policy) => policy.id === policyId);
    assert.ok(policySnapshot?.safety_policy_snapshot);

    const run = await request(baseUrl, 'POST', '/v1/test-runs', {
      headers,
      body: {
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
        check_id: 'dns.authoritative_response.safe',
      },
    });
    assert.equal(run.status, 201);

    const archived = await request(baseUrl, 'DELETE', `/v1/test-policies/${policyId}`, { headers });
    assert.equal(archived.status, 200);

    const afterDelete = await request(baseUrl, 'GET', '/v1/test-policies', { headers });
    assert.equal(afterDelete.json.items.some((policy) => policy.id === policyId), false);

    const storedRun = getStore().testRuns.find((r) => r.id === run.json.run.id);
    assert.ok(storedRun);
    assert.ok(policySnapshot.safety_policy_snapshot);

    const audits = getStore().auditLog
      .filter((entry) => entry.resource_id === policyId)
      .map((entry) => entry.action);
    assert.ok(audits.includes('test_policy.created'));
    assert.ok(audits.includes('test_policy.updated'));
    assert.ok(audits.includes('test_policy.archived'));
  });
});