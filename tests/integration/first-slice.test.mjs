import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { agentHeaders, demoHeaders, request } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';
import { getStore } from '../../src/store.mjs';
import { createBootstrapToken } from '../../src/services/tokens.mjs';

let baseUrl;
let server;

before(() => {
  freshStore();
  server = createServer();
  server.listen(0);
  const { port } = server.address();
  baseUrl = `http://127.0.0.1:${port}`;
});

after(() => {
  server.close();
});

describe('integration first validation slice', () => {
  it('runs safe validation loop to bypassable finding and report', async () => {
    const h = demoHeaders('engineer');
    const tg = await request(baseUrl, 'POST', '/v1/target-groups', {
      headers: h,
      body: { name: 'Slice TG', environment_id: 'env_demo' },
    });
    assert.equal(tg.status, 201);
    const tgId = tg.json.id;

    const tgt = await request(baseUrl, 'POST', `/v1/target-groups/${tgId}/targets`, {
      headers: h,
      body: { value: 'slice.example.com', kind: 'fqdn' },
    });
    assert.equal(tgt.status, 201);

    const ctx = { tenantId: 'ten_demo', userId: 'u1', role: 'admin' };
    const { secret } = createBootstrapToken(ctx, {
      target_group_id: tgId,
      max_registrations: 1,
    });

    const reg = await request(baseUrl, 'POST', '/v1/agents/register', {
      headers: demoHeaders('engineer'),
      body: {
        bootstrap_token: secret,
        hostname: 'slice-host',
        name: 'slice-agent',
        capabilities: ['canary', 'heartbeat'],
      },
    });
    assert.equal(reg.status, 201);
    const agentId = reg.json.agent.id;
    const agentCredential = reg.json.agent_credential;

    const hb = await request(baseUrl, 'POST', `/v1/agents/${agentId}/heartbeat`, {
      headers: agentHeaders(agentCredential),
      body: { version: '0.2.0-production-readiness' },
    });
    assert.equal(hb.status, 200);

    const run = await request(baseUrl, 'POST', '/v1/test-runs', {
      headers: h,
      body: {
        check_id: 'origin.direct_bypass.safe',
        target_group_id: tgId,
        target_id: tgt.json.id,
      },
    });
    assert.equal(run.status, 201);
    const runId = run.json.run.id;
    const nonce_hash = run.json.run.correlation.nonce_hash;

    const jobs = await request(baseUrl, 'GET', `/v1/agents/${agentId}/jobs`, {
      headers: agentHeaders(agentCredential),
    });
    assert.equal(jobs.status, 200);
    assert.ok(jobs.json.jobs.length >= 1);
    const jobId = jobs.json.jobs[0].id;
    await request(baseUrl, 'POST', `/v1/agents/${agentId}/jobs/${jobId}/ack`, {
      headers: agentHeaders(agentCredential),
    });

    const obs = await request(baseUrl, 'POST', `/v1/agents/${agentId}/observations`, {
      headers: agentHeaders(agentCredential),
      body: {
        agent_job_id: jobId,
        test_run_id: runId,
        target_id: tgt.json.id,
        nonce_hash,
        metadata: { mode: 'canary_observation' },
      },
    });
    assert.equal(obs.status, 201);

    const detail = await request(baseUrl, 'GET', `/v1/test-runs/${runId}`, { headers: h });
    assert.equal(detail.json.verdict.verdict, 'bypassable');
    assert.ok(detail.json.verdict.placement_confidence);
    assert.equal(detail.json.verdict.placement_confidence.level, 'High');
    assert.equal(detail.json.verdict.placement_confidence.status, 'observed_this_run');
    assert.equal(detail.json.verdict.placement_confidence.agent_id, agentId);

    const findings = await request(baseUrl, 'GET', '/v1/findings', { headers: h });
    assert.ok(findings.json.items.length >= 1);

    const report = await request(baseUrl, 'POST', '/v1/reports', {
      headers: demoHeaders('admin'),
      body: { kind: 'technical' },
    });
    assert.equal(report.status, 201);
    assert.ok(report.json.summary.readiness_score >= 0);

    const reportExport = await request(
      baseUrl,
      'GET',
      `/v1/reports/${report.json.id}/export?format=json`,
      { headers: demoHeaders('admin') },
    );
    assert.equal(reportExport.status, 200);
    const exportVerdict = (reportExport.json.payload?.verdicts ?? []).find(
      (v) => v.test_run_id === runId,
    );
    assert.ok(exportVerdict?.placement_confidence);
    assert.equal(exportVerdict.placement_confidence.level, 'High');

    const audit = await request(baseUrl, 'GET', '/v1/audit-log', { headers: demoHeaders('admin') });
    assert.ok(audit.json.items.some((a) => a.action === 'test_run.started'));
  });

  it('rejects cross-tenant observation injection', async () => {
    const h = demoHeaders('engineer');
    const listedAgents = await request(baseUrl, 'GET', '/v1/agents', { headers: h });
    const agentId = listedAgents.json.items[0]?.id;
    assert.ok(agentId);
    const runs = await request(baseUrl, 'GET', '/v1/test-runs', { headers: h });
    const runId = runs.json.items[0]?.id;
    const ctx = { tenantId: 'ten_demo', userId: 'u1', role: 'admin' };
    const tgId = getStore().targetGroups.find((g) => g.name === 'Slice TG')?.id ?? 'tg_1';
    const { secret } = createBootstrapToken(ctx, { max_registrations: 1, target_group_id: tgId });
    const agentFromReg = await request(baseUrl, 'POST', '/v1/agents/register', {
      headers: demoHeaders('engineer'),
      body: { bootstrap_token: secret, hostname: 'cross-tenant-agent' },
    });
    assert.equal(agentFromReg.status, 201);

    const res = await request(baseUrl, 'POST', `/v1/agents/${agentFromReg.json.agent.id}/observations`, {
      headers: agentHeaders(agentFromReg.json.agent_credential),
      body: {
        tenant_id: 'ten_other',
        test_run_id: runId,
        nonce_hash: 'sha256:deadbeef',
      },
    });
    assert.equal(res.status, 403);
  });

  it('blocks concurrent runs on one target group', async () => {
    const h = demoHeaders('engineer');
    const tgId = getStore().targetGroups.find((g) => g.name === 'Slice TG').id;
    const tgtId = getStore().targets.find((t) => t.target_group_id === tgId).id;
    const first = await request(baseUrl, 'POST', '/v1/test-runs', {
      headers: h,
      body: {
        check_id: 'l3.forbidden_tcp_port.safe',
        target_group_id: tgId,
        target_id: tgtId,
      },
    });
    assert.equal(first.status, 201);
    const second = await request(baseUrl, 'POST', '/v1/test-runs', {
      headers: h,
      body: {
        check_id: 'l3.forbidden_tcp_port.safe',
        target_group_id: tgId,
        target_id: tgtId,
      },
    });
    assert.equal(second.status, 409);
  });

  it('rejects token replay after max registrations', async () => {
    const ctx = { tenantId: 'ten_demo', userId: 'u1', role: 'admin' };
    const { secret } = createBootstrapToken(ctx, { max_registrations: 1, target_group_id: 'tg_1' });
    const ok = await request(baseUrl, 'POST', '/v1/agents/register', {
      headers: demoHeaders('engineer'),
      body: { bootstrap_token: secret, hostname: 'replay-a' },
    });
    assert.equal(ok.status, 201);
    const bad = await request(baseUrl, 'POST', '/v1/agents/register', {
      headers: demoHeaders('engineer'),
      body: { bootstrap_token: secret, hostname: 'replay-b' },
    });
    assert.equal(bad.status, 401);
    const audited = getStore().auditLog.some((a) => a.action === 'bootstrap_token.replay_rejected');
    assert.ok(audited);
  });
});