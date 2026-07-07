import assert from 'node:assert/strict';
import { after, beforeEach, before, describe, it } from 'node:test';
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
  const { port } = server.address();
  baseUrl = `http://127.0.0.1:${port}`;
});

after(() => {
  server?.close();
});

beforeEach(() => {
  freshStore();
});

describe('target group lifecycle (FT-CRUD-TG-01)', () => {
  it('create → list → patch → archive → archived list → restore with audit trail', async () => {
    const headers = demoHeaders('engineer');
    const created = await request(baseUrl, 'POST', '/v1/target-groups', {
      headers,
      body: { name: 'Lifecycle group', environment_id: 'env_demo' },
    });
    assert.equal(created.status, 201);
    const groupId = created.json.id;

    const listed = await request(baseUrl, 'GET', '/v1/target-groups', { headers });
    assert.ok(listed.json.items.some((g) => g.id === groupId));

    const patched = await request(baseUrl, 'PATCH', `/v1/target-groups/${groupId}`, {
      headers,
      body: { description: 'critical checkout scope' },
    });
    assert.equal(patched.status, 200);
    assert.equal(patched.json.description, 'critical checkout scope');

    const archived = await request(baseUrl, 'DELETE', `/v1/target-groups/${groupId}`, { headers });
    assert.equal(archived.status, 200);
    const stored = getStore().targetGroups.find((g) => g.id === groupId);
    assert.ok(stored.deleted_at);
    assert.equal(stored.deleted_by, 'usr_admin');

    const active = await request(baseUrl, 'GET', '/v1/target-groups', { headers });
    assert.equal(active.json.items.some((g) => g.id === groupId), false);

    const archivedList = await request(baseUrl, 'GET', '/v1/target-groups?archived=true', {
      headers,
    });
    assert.ok(archivedList.json.items.some((g) => g.id === groupId));

    const restored = await request(baseUrl, 'POST', `/v1/target-groups/${groupId}/restore`, {
      headers,
    });
    assert.equal(restored.status, 200);

    const activeAgain = await request(baseUrl, 'GET', '/v1/target-groups', { headers });
    assert.ok(activeAgain.json.items.some((g) => g.id === groupId));

    const actions = getStore().auditLog
      .filter((entry) => entry.resource_id === groupId)
      .map((entry) => entry.action);
    assert.ok(actions.includes('target_group.created'));
    assert.ok(actions.includes('target_group.updated'));
    assert.ok(actions.includes('target_group.archived'));
    assert.ok(actions.includes('target_group.restored'));
  });
});