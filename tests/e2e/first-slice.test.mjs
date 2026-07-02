import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { agentHeaders, demoHeaders, request } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';

let baseUrl;
let server;

before(() => {
  process.env.ASTRANULL_NO_PERSIST = '1';
  freshStore();
  server = createServer();
  server.listen(0);
  const { port } = server.address();
  baseUrl = `http://127.0.0.1:${port}`;
});

after(() => server.close());

describe('e2e first slice', () => {
  it('completes validation loop and state reflects evidence', async () => {
    const admin = demoHeaders('admin');
    const tokenRes = await request(baseUrl, 'POST', '/v1/bootstrap-tokens', {
      headers: admin,
      body: { name: 'e2e', target_group_id: 'tg_1', max_registrations: 1 },
    });
    const secret = tokenRes.json.secret;

    const reg = await request(baseUrl, 'POST', '/v1/agents/register', {
      headers: demoHeaders('engineer'),
      body: { bootstrap_token: secret, hostname: 'e2e-host' },
    });
    const agentId = reg.json.agent.id;
    const agentCredential = reg.json.agent_credential;

    await request(baseUrl, 'POST', `/v1/agents/${agentId}/heartbeat`, {
      headers: agentHeaders(agentCredential),
      body: { version: '0.1.0' },
    });

    const runRes = await request(baseUrl, 'POST', '/v1/test-runs', {
      headers: demoHeaders('engineer'),
      body: {
        check_id: 'origin.direct_bypass.safe',
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
      },
    });
    const runId = runRes.json.run.id;
    const nonce_hash = runRes.json.run.correlation.nonce_hash;

    const jobs = await request(baseUrl, 'GET', `/v1/agents/${agentId}/jobs`, {
      headers: agentHeaders(agentCredential),
    });
    const jobId = jobs.json.jobs[0].id;
    await request(baseUrl, 'POST', `/v1/agents/${agentId}/jobs/${jobId}/ack`, {
      headers: agentHeaders(agentCredential),
    });

    await request(baseUrl, 'POST', `/v1/agents/${agentId}/observations`, {
      headers: agentHeaders(agentCredential),
      body: { agent_job_id: jobId, test_run_id: runId, target_id: 'tgt_1', nonce_hash },
    });

    const state = await request(baseUrl, 'GET', '/v1/state', { headers: admin });
    assert.equal(state.status, 200);
    assert.ok(state.json.readiness.score >= 0);
    assert.ok(state.json.open_findings >= 1);
    assert.ok(state.json.recent_runs.some((r) => r.id === runId));

    const events = await request(baseUrl, 'GET', `/v1/test-runs/${runId}/events`, {
      headers: admin,
    });
    assert.ok(events.json.items.some((e) => e.signal_type === 'probe_result'));
    assert.ok(events.json.items.some((e) => e.signal_type === 'agent_observation'));
  });
});