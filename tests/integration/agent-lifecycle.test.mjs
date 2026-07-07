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

describe('agent lifecycle (FT-CRUD-AGT-01)', () => {
  it('enroll → heartbeat → agent_verified → revoke blocks run binding', async () => {
    const headers = demoHeaders('engineer');
    const token = await request(baseUrl, 'POST', '/v1/bootstrap-tokens', {
      headers,
      body: { name: 'Lifecycle token', target_group_id: 'tg_1', environment_id: 'env_demo' },
    });
    assert.equal(token.status, 201);
    const secret = token.json.secret;

    const enrolled = await request(baseUrl, 'POST', '/v1/agents/register', {
      headers: { ...headers, 'x-tenant-id': 'ten_demo' },
      body: {
        bootstrap_token: secret,
        hostname: 'agent-lifecycle',
        fingerprint: 'fp-lifecycle',
      },
    });
    assert.equal(enrolled.status, 201);
    const agentId = enrolled.json.agent.id;
    const credential = enrolled.json.agent_credential;

    const heartbeat = await request(baseUrl, 'POST', `/v1/agents/${agentId}/heartbeat`, {
      headers: {
        'x-agent-credential': credential,
        'Content-Type': 'application/json',
      },
      body: { version: '1.0.0' },
    });
    assert.equal(heartbeat.status, 200);
    assert.equal(heartbeat.json.agent.status, 'online');

    const store = getStore();
    if (!Array.isArray(store.targetVerifications)) store.targetVerifications = [];
    store.targetVerifications.push({
      id: 'tv_agent_lifecycle',
      tenant_id: 'ten_demo',
      target_id: 'tgt_1',
      state: 'agent_verified',
      source_kind: 'agent_heartbeat',
      source_ref: { agent_id: agentId },
      transitioned_at: new Date().toISOString(),
      transitioned_by: 'system',
      audit_entry_id: 'aud_agent_lifecycle',
    });
    const target = store.targets.find((t) => t.id === 'tgt_1');
    if (target) target.verify_state = 'agent_verified';

    const runBefore = await request(baseUrl, 'POST', '/v1/test-runs', {
      headers,
      body: {
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
        check_id: 'dns.authoritative_response.safe',
      },
    });
    assert.equal(runBefore.status, 201);
    const jobsBefore = getStore().agentJobs.filter((job) => job.agent_id === agentId);
    assert.ok(jobsBefore.length > 0);

    const revoked = await request(baseUrl, 'POST', `/v1/agents/${agentId}/revoke`, {
      headers: demoHeaders('admin'),
    });
    assert.equal(revoked.status, 200);
    assert.equal(revoked.json.agent.status, 'revoked');

    const cancelled = await request(baseUrl, 'POST', `/v1/test-runs/${runBefore.json.run.id}/cancel`, {
      headers,
      body: { reason: 'lifecycle cleanup' },
    });
    assert.equal(cancelled.status, 200);

    const runAfter = await request(baseUrl, 'POST', '/v1/test-runs', {
      headers,
      body: {
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
        check_id: 'dns.authoritative_response.safe',
      },
    });
    assert.equal(runAfter.status, 201);
    const jobsAfter = getStore().agentJobs.filter(
      (job) => job.agent_id === agentId && job.test_run_id === runAfter.json.run.id,
    );
    assert.equal(jobsAfter.length, 0);

    const audits = getStore().auditLog
      .filter((entry) => entry.resource_id === agentId)
      .map((entry) => entry.action);
    assert.ok(audits.includes('agent.registered'));
    assert.ok(audits.includes('agent.heartbeat'));
    assert.ok(audits.includes('agent.revoked'));
  });
});