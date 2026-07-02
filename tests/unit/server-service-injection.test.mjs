import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { demoHeaders, request } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';

const FAKE_TENANT = { id: 'ten_demo', name: 'Fake Tenant' };

function makeFakeTenants(handlers = {}) {
  const calls = [];
  const tenants = {
    async getCurrentTenant(ctx) {
      calls.push({ fn: 'getCurrentTenant', ctx });
      if (handlers.getCurrentTenant) return handlers.getCurrentTenant(ctx);
      return FAKE_TENANT;
    },
    async patchCurrentTenant(ctx, body) {
      calls.push({ fn: 'patchCurrentTenant', ctx, body });
      if (handlers.patchCurrentTenant) return handlers.patchCurrentTenant(ctx, body);
      return { ...FAKE_TENANT, ...body };
    },
    async listEnvironments(ctx) {
      calls.push({ fn: 'listEnvironments', ctx });
      return handlers.listEnvironments?.(ctx) ?? [{ id: 'env_fake', name: 'Fake Env' }];
    },
    async createEnvironment(ctx, body) {
      calls.push({ fn: 'createEnvironment', ctx, body });
      return handlers.createEnvironment?.(ctx, body) ?? {
        id: 'env_new',
        tenant_id: ctx.tenantId,
        name: body.name,
      };
    },
    async patchEnvironment(ctx, id, body) {
      calls.push({ fn: 'patchEnvironment', ctx, id, body });
      if (handlers.patchEnvironment) return handlers.patchEnvironment(ctx, id, body);
      return { id, name: body.name ?? 'patched' };
    },
  };
  return { tenants, calls };
}

function makeFakeTargetGroups(handlers = {}) {
  const calls = [];
  const targetGroups = {
    async listTargetGroups(ctx) {
      calls.push({ fn: 'listTargetGroups', ctx });
      return handlers.listTargetGroups?.(ctx) ?? [{ id: 'tg_fake', name: 'Fake TG' }];
    },
    async createTargetGroup(ctx, body) {
      calls.push({ fn: 'createTargetGroup', ctx, body });
      return handlers.createTargetGroup?.(ctx, body) ?? { id: 'tg_new', ...body };
    },
    async getTargetGroup(ctx, id) {
      calls.push({ fn: 'getTargetGroup', ctx, id });
      if (handlers.getTargetGroup) return handlers.getTargetGroup(ctx, id);
      return { id, name: 'Fake TG', targets: [] };
    },
    async addTarget(ctx, groupId, body) {
      calls.push({ fn: 'addTarget', ctx, groupId, body });
      if (handlers.addTarget) return handlers.addTarget(ctx, groupId, body);
      return { id: 'tgt_new', target_group_id: groupId, ...body };
    },
  };
  return { targetGroups, calls };
}

function listenServer(services) {
  const server = createServer({
    env: {
      ...process.env,
      NODE_ENV: 'test',
      ASTRANULL_AUTH_MODE: 'dev-headers',
      ASTRANULL_NO_PERSIST: '1',
    },
    services,
  });
  server.listen(0);
  const { port } = server.address();
  return { server, baseUrl: `http://127.0.0.1:${port}` };
}

describe('createServer service injection — tenant and target-group routes', () => {
  let baseUrl;
  let server;
  let tenantCalls;
  let tgCalls;

  before(() => {
    freshStore();
    const fakeTenants = makeFakeTenants();
    const fakeTargetGroups = makeFakeTargetGroups();
    tenantCalls = fakeTenants.calls;
    tgCalls = fakeTargetGroups.calls;
    ({ server, baseUrl } = listenServer({
      tenants: fakeTenants.tenants,
      targetGroups: fakeTargetGroups.targetGroups,
    }));
  });

  after(() => server.close());

  it('GET /v1/tenants/current uses injected tenant service and auth ctx', async () => {
    const headers = demoHeaders('admin', 'ten_demo', 'usr_admin');
    const res = await request(baseUrl, 'GET', '/v1/tenants/current', { headers });
    assert.equal(res.status, 200);
    assert.deepEqual(res.json, FAKE_TENANT);
    const call = tenantCalls.find((c) => c.fn === 'getCurrentTenant');
    assert.ok(call);
    assert.equal(call.ctx.tenantId, 'ten_demo');
    assert.equal(call.ctx.userId, 'usr_admin');
    assert.equal(call.ctx.role, 'admin');
  });

  it('PATCH /v1/tenants/current forwards parsed body to injected tenant service', async () => {
    const headers = demoHeaders('admin');
    const body = { name: 'Renamed' };
    const res = await request(baseUrl, 'PATCH', '/v1/tenants/current', { headers, body });
    assert.equal(res.status, 200);
    assert.equal(res.json.name, 'Renamed');
    const call = tenantCalls.find((c) => c.fn === 'patchCurrentTenant' && c.body.name === 'Renamed');
    assert.ok(call);
    assert.equal(call.ctx.tenantId, 'ten_demo');
  });

  it('GET and POST /v1/environments use injected tenant service', async () => {
    const readHeaders = demoHeaders('viewer');
    const listRes = await request(baseUrl, 'GET', '/v1/environments', { headers: readHeaders });
    assert.equal(listRes.status, 200);
    assert.deepEqual(listRes.json.items, [{ id: 'env_fake', name: 'Fake Env' }]);
    assert.ok(tenantCalls.some((c) => c.fn === 'listEnvironments'));

    const writeHeaders = demoHeaders('admin');
    const createRes = await request(baseUrl, 'POST', '/v1/environments', {
      headers: writeHeaders,
      body: { name: 'Staging' },
    });
    assert.equal(createRes.status, 201);
    assert.equal(createRes.json.name, 'Staging');
    const createCall = tenantCalls.find((c) => c.fn === 'createEnvironment' && c.body.name === 'Staging');
    assert.ok(createCall);
  });

  it('target-group list/create/detail/add-target routes use injected target-group service', async () => {
    const readHeaders = demoHeaders('viewer');
    const listRes = await request(baseUrl, 'GET', '/v1/target-groups', { headers: readHeaders });
    assert.equal(listRes.status, 200);
    assert.deepEqual(listRes.json.items, [{ id: 'tg_fake', name: 'Fake TG' }]);

    const writeHeaders = demoHeaders('admin');
    const createRes = await request(baseUrl, 'POST', '/v1/target-groups', {
      headers: writeHeaders,
      body: { name: 'Edge' },
    });
    assert.equal(createRes.status, 201);
    assert.equal(createRes.json.name, 'Edge');

    const detailRes = await request(baseUrl, 'GET', '/v1/target-groups/tg_99', { headers: readHeaders });
    assert.equal(detailRes.status, 200);
    assert.equal(detailRes.json.id, 'tg_99');

    const addRes = await request(baseUrl, 'POST', '/v1/target-groups/tg_99/targets', {
      headers: writeHeaders,
      body: { kind: 'fqdn', value: 'api.example.test' },
    });
    assert.equal(addRes.status, 201);
    assert.equal(addRes.json.value, 'api.example.test');
    assert.ok(tgCalls.some((c) => c.fn === 'addTarget' && c.groupId === 'tg_99'));
  });
});

describe('createServer service injection — not_found from fakes', () => {
  let baseUrl;
  let server;

  after(() => server?.close());

  it('maps null tenant/target-group service results to HTTP 404', async () => {
    freshStore();
    const fakeTenants = makeFakeTenants({
      getCurrentTenant: async () => null,
      patchCurrentTenant: async () => null,
      patchEnvironment: async () => null,
    });
    const fakeTargetGroups = makeFakeTargetGroups({
      getTargetGroup: async () => null,
      addTarget: async () => null,
    });
    ({ server, baseUrl } = listenServer({
      tenants: fakeTenants.tenants,
      targetGroups: fakeTargetGroups.targetGroups,
    }));

    const headers = demoHeaders('admin');
    assert.equal((await request(baseUrl, 'GET', '/v1/tenants/current', { headers })).status, 404);
    assert.equal((await request(baseUrl, 'PATCH', '/v1/tenants/current', { headers, body: { name: 'x' } })).status, 404);
    assert.equal(
      (await request(baseUrl, 'PATCH', '/v1/environments/env_missing', { headers, body: { name: 'x' } })).status,
      404,
    );
    assert.equal((await request(baseUrl, 'GET', '/v1/target-groups/tg_missing', { headers })).status, 404);
    assert.equal(
      (
        await request(baseUrl, 'POST', '/v1/target-groups/tg_missing/targets', {
          headers,
          body: { value: 'x.test' },
        })
      ).status,
      404,
    );
  });
});

const FAKE_AGENT = { id: 'agt_fake', tenant_id: 'ten_demo', status: 'online' };

function makeFakeTokens(handlers = {}) {
  const calls = [];
  const tokens = {
    async createBootstrapToken(ctx, body) {
      calls.push({ fn: 'createBootstrapToken', ctx, body });
      if (handlers.createBootstrapToken) return handlers.createBootstrapToken(ctx, body);
      return {
        token: {
          id: 'bt_fake',
          name: body.name,
          token_hash: 'hash',
          token_salt: 'salt',
        },
        secret: 'ast_fake_secret',
      };
    },
    async listBootstrapTokens(ctx) {
      calls.push({ fn: 'listBootstrapTokens', ctx });
      return handlers.listBootstrapTokens?.(ctx) ?? [{ id: 'bt_fake', name: 'Install' }];
    },
    async revokeBootstrapToken(ctx, id) {
      calls.push({ fn: 'revokeBootstrapToken', ctx, id });
      if (handlers.revokeBootstrapToken) return handlers.revokeBootstrapToken(ctx, id);
      return { id, status: 'revoked' };
    },
  };
  return { tokens, calls };
}

function makeFakeServiceAccounts(handlers = {}) {
  const calls = [];
  const serviceAccounts = {
    async createServiceAccount(ctx, body) {
      calls.push({ fn: 'createServiceAccount', ctx, body });
      if (handlers.createServiceAccount) return handlers.createServiceAccount(ctx, body);
      return {
        account: {
          id: 'sa_fake',
          name: body.name,
          secret_hash: 'hash',
          secret_salt: 'salt',
        },
        secret: 'svc_fake_secret',
      };
    },
    async listServiceAccounts(ctx) {
      calls.push({ fn: 'listServiceAccounts', ctx });
      return handlers.listServiceAccounts?.(ctx) ?? [{ id: 'sa_fake', name: 'CI' }];
    },
    async revokeServiceAccount(ctx, id) {
      calls.push({ fn: 'revokeServiceAccount', ctx, id });
      if (handlers.revokeServiceAccount) return handlers.revokeServiceAccount(ctx, id);
      return { id, status: 'revoked' };
    },
    async rotateServiceAccount(ctx, id) {
      calls.push({ fn: 'rotateServiceAccount', ctx, id });
      if (handlers.rotateServiceAccount) return handlers.rotateServiceAccount(ctx, id);
      return {
        account: { id, secret_hash: 'hash2', secret_salt: 'salt2' },
        secret: 'svc_rotated',
      };
    },
    async authenticateServiceAccountBearer(token) {
      calls.push({ fn: 'authenticateServiceAccountBearer', token });
      if (handlers.authenticateServiceAccountBearer) {
        return handlers.authenticateServiceAccountBearer(token);
      }
      if (token === 'svc_injected_ok') {
        return { tenantId: 'ten_demo', userId: 'sa_fake', role: 'viewer', serviceAccountId: 'sa_fake' };
      }
      return { error: 'invalid_token' };
    },
    async auditServiceAccountAuthFailure(token) {
      calls.push({ fn: 'auditServiceAccountAuthFailure', token });
      handlers.auditServiceAccountAuthFailure?.(token);
    },
  };
  return { serviceAccounts, calls };
}

function makeFakeAgents(handlers = {}) {
  const calls = [];
  const agents = {
    async registerAgent(body, tenantId) {
      calls.push({ fn: 'registerAgent', body, tenantId });
      if (handlers.registerAgent) return handlers.registerAgent(body, tenantId);
      return { agent: { id: 'agt_new', tenant_id: 'ten_demo' }, credential: 'agc_new' };
    },
    async listAgents(ctx) {
      calls.push({ fn: 'listAgents', ctx });
      return handlers.listAgents?.(ctx) ?? [FAKE_AGENT];
    },
    async revokeAgent(ctx, id) {
      calls.push({ fn: 'revokeAgent', ctx, id });
      if (handlers.revokeAgent) return handlers.revokeAgent(ctx, id);
      return { agent: { ...FAKE_AGENT, id, status: 'revoked' } };
    },
    async heartbeatAgent(agent, body) {
      calls.push({ fn: 'heartbeatAgent', agent, body });
      return handlers.heartbeatAgent?.(agent, body) ?? { agent };
    },
    async pollJobs(agent, timeoutMs) {
      calls.push({ fn: 'pollJobs', agent, timeoutMs });
      return handlers.pollJobs?.(agent, timeoutMs) ?? { jobs: [{ id: 'job_fake' }] };
    },
    async ackJob(agent, jobId) {
      calls.push({ fn: 'ackJob', agent, jobId });
      if (handlers.ackJob) return handlers.ackJob(agent, jobId);
      return { id: jobId, status: 'acked' };
    },
  };
  return { agents, calls };
}

function makeFakeAgentAuth(handlers = {}) {
  const calls = [];
  const agentAuth = {
    async requireAgentAuth(headers, agentId) {
      calls.push({ fn: 'requireAgentAuth', agentId, headers });
      if (handlers.requireAgentAuth) return handlers.requireAgentAuth(headers, agentId);
      if (agentId === FAKE_AGENT.id) {
        return { agent: FAKE_AGENT, credential: 'agc_injected' };
      }
      return { error: 'unauthorized', status: 401 };
    },
  };
  return { agentAuth, calls };
}

describe('createServer service injection — tokens, service accounts, agents', () => {
  let baseUrl;
  let server;
  let tokenCalls;
  let saCalls;
  let agentCalls;
  let agentAuthCalls;

  before(() => {
    freshStore();
    const fakeTenants = makeFakeTenants();
    const fakeTargetGroups = makeFakeTargetGroups();
    const fakeTokens = makeFakeTokens();
    const fakeServiceAccounts = makeFakeServiceAccounts();
    const fakeAgents = makeFakeAgents();
    const fakeAgentAuth = makeFakeAgentAuth();
    tokenCalls = fakeTokens.calls;
    saCalls = fakeServiceAccounts.calls;
    agentCalls = fakeAgents.calls;
    agentAuthCalls = fakeAgentAuth.calls;
    ({ server, baseUrl } = listenServer({
      tenants: fakeTenants.tenants,
      targetGroups: fakeTargetGroups.targetGroups,
      tokens: fakeTokens.tokens,
      serviceAccounts: fakeServiceAccounts.serviceAccounts,
      agents: fakeAgents.agents,
      agentAuth: fakeAgentAuth.agentAuth,
    }));
  });

  after(() => server.close());

  it('bootstrap-token routes use injected tokens service and redact hash/salt', async () => {
    const headers = demoHeaders('admin');
    const createRes = await request(baseUrl, 'POST', '/v1/bootstrap-tokens', {
      headers,
      body: { name: 'edge-install', max_registrations: 2 },
    });
    assert.equal(createRes.status, 201);
    assert.equal(createRes.json.secret, 'ast_fake_secret');
    assert.equal(createRes.json.token_hash, undefined);
    assert.equal(createRes.json.token_salt, undefined);
    const createCall = tokenCalls.find((c) => c.fn === 'createBootstrapToken');
    assert.equal(createCall.body.name, 'edge-install');
    assert.equal(createCall.ctx.tenantId, 'ten_demo');

    const listRes = await request(baseUrl, 'GET', '/v1/bootstrap-tokens', { headers: demoHeaders('admin') });
    assert.equal(listRes.status, 200);
    assert.deepEqual(listRes.json.items, [{ id: 'bt_fake', name: 'Install' }]);

    const revokeRes = await request(baseUrl, 'POST', '/v1/bootstrap-tokens/bt_9/revoke', { headers });
    assert.equal(revokeRes.status, 200);
    assert.equal(revokeRes.json.id, 'bt_9');
    assert.ok(tokenCalls.some((c) => c.fn === 'revokeBootstrapToken' && c.id === 'bt_9'));
  });

  it('service-account management routes use injected serviceAccounts and redact hash/salt', async () => {
    const headers = demoHeaders('admin');
    const createRes = await request(baseUrl, 'POST', '/v1/service-accounts', {
      headers,
      body: { name: 'ci-bot', role: 'viewer' },
    });
    assert.equal(createRes.status, 201);
    assert.equal(createRes.json.secret, 'svc_fake_secret');
    assert.equal(createRes.json.secret_hash, undefined);
    assert.equal(createRes.json.secret_salt, undefined);

    const listRes = await request(baseUrl, 'GET', '/v1/service-accounts', { headers: demoHeaders('admin') });
    assert.equal(listRes.status, 200);
    assert.deepEqual(listRes.json.items, [{ id: 'sa_fake', name: 'CI' }]);

    const revokeRes = await request(baseUrl, 'POST', '/v1/service-accounts/sa_9/revoke', { headers });
    assert.equal(revokeRes.status, 200);
    assert.equal(revokeRes.json.id, 'sa_9');

    const rotateRes = await request(baseUrl, 'POST', '/v1/service-accounts/sa_9/rotate', { headers });
    assert.equal(rotateRes.status, 200);
    assert.equal(rotateRes.json.secret, 'svc_rotated');
    assert.equal(rotateRes.json.secret_hash, undefined);
  });

  it('resolveHumanApiAuth uses injected service-account bearer auth and audits invalid tokens', async () => {
    const okRes = await request(baseUrl, 'GET', '/v1/target-groups', {
      headers: { Authorization: 'Bearer svc_injected_ok' },
    });
    assert.equal(okRes.status, 200);
    assert.deepEqual(okRes.json.items, [{ id: 'tg_fake', name: 'Fake TG' }]);
    assert.ok(saCalls.some((c) => c.fn === 'authenticateServiceAccountBearer' && c.token === 'svc_injected_ok'));

    const badRes = await request(baseUrl, 'GET', '/v1/target-groups', {
      headers: { Authorization: 'Bearer svc_injected_bad' },
    });
    assert.equal(badRes.status, 401);
    assert.ok(saCalls.some((c) => c.fn === 'auditServiceAccountAuthFailure' && c.token === 'svc_injected_bad'));
  });

  it('agent register/list and credential routes use injected agents and agentAuth', async () => {
    const regRes = await request(baseUrl, 'POST', '/v1/agents/register', {
      body: { bootstrap_token: 'ast_x', hostname: 'host-a' },
    });
    assert.equal(regRes.status, 201);
    assert.equal(regRes.json.agent.id, 'agt_new');
    const regCall = agentCalls.find((c) => c.fn === 'registerAgent');
    assert.equal(regCall.body.hostname, 'host-a');

    const listRes = await request(baseUrl, 'GET', '/v1/agents', { headers: demoHeaders('viewer') });
    assert.equal(listRes.status, 200);
    assert.deepEqual(listRes.json.items, [FAKE_AGENT]);

    const revokeRes = await request(baseUrl, 'POST', `/v1/agents/${FAKE_AGENT.id}/revoke`, {
      headers: demoHeaders('admin'),
    });
    assert.equal(revokeRes.status, 200);
    assert.equal(revokeRes.json.agent.status, 'revoked');
    assert.ok(agentCalls.some((c) => c.fn === 'revokeAgent' && c.id === FAKE_AGENT.id));

    const hbRes = await request(baseUrl, 'POST', `/v1/agents/${FAKE_AGENT.id}/heartbeat`, {
      headers: { Authorization: 'Bearer agc_injected' },
      body: { version: '1.0.0' },
    });
    assert.equal(hbRes.status, 200);
    assert.ok(agentAuthCalls.some((c) => c.fn === 'requireAgentAuth' && c.agentId === FAKE_AGENT.id));
    const hbCall = agentCalls.find((c) => c.fn === 'heartbeatAgent');
    assert.equal(hbCall.agent.id, FAKE_AGENT.id);
    assert.equal(hbCall.body.version, '1.0.0');

    const jobsRes = await request(baseUrl, 'GET', `/v1/agents/${FAKE_AGENT.id}/jobs`, {
      headers: { Authorization: 'Bearer agc_injected' },
    });
    assert.equal(jobsRes.status, 200);
    assert.deepEqual(jobsRes.json.jobs, [{ id: 'job_fake' }]);
    const pollCall = agentCalls.find((c) => c.fn === 'pollJobs');
    assert.equal(pollCall.timeoutMs, 3000);

    const ackRes = await request(baseUrl, 'POST', `/v1/agents/${FAKE_AGENT.id}/jobs/job_1/ack`, {
      headers: { Authorization: 'Bearer agc_injected' },
    });
    assert.equal(ackRes.status, 200);
    assert.equal(ackRes.json.job.id, 'job_1');
    assert.ok(agentCalls.some((c) => c.fn === 'ackJob' && c.jobId === 'job_1'));
  });
});

function makeFakeValidationServices(handlers = {}) {
  const calls = [];
  const testRuns = {
    async listChecks() {
      calls.push({ group: 'testRuns', fn: 'listChecks' });
      return handlers.listChecks?.() ?? [{ check_id: 'chk_fake' }];
    },
    async listTestRuns(ctx) {
      calls.push({ group: 'testRuns', fn: 'listTestRuns', ctx });
      return handlers.listTestRuns?.(ctx) ?? [{ id: 'run_fake' }];
    },
    async getTestRun(ctx, id) {
      calls.push({ group: 'testRuns', fn: 'getTestRun', ctx, id });
      if (handlers.getTestRun) return handlers.getTestRun(ctx, id);
      return { id, verdict: null };
    },
    async getRunEvents(ctx, id) {
      calls.push({ group: 'testRuns', fn: 'getRunEvents', ctx, id });
      if (handlers.getRunEvents) return handlers.getRunEvents(ctx, id);
      return [{ id: 'evt_fake' }];
    },
    async startTestRun(ctx, body, runtimeConfig) {
      calls.push({ group: 'testRuns', fn: 'startTestRun', ctx, body, runtimeConfig });
      return handlers.startTestRun?.(ctx, body, runtimeConfig) ?? { id: 'run_new' };
    },
    async finalizeTestRun(ctx, id) {
      calls.push({ group: 'testRuns', fn: 'finalizeTestRun', ctx, id });
      return handlers.finalizeTestRun?.(ctx, id) ?? { run: { id }, verdict: null };
    },
    async cancelTestRun(ctx, id) {
      calls.push({ group: 'testRuns', fn: 'cancelTestRun', ctx, id });
      return handlers.cancelTestRun?.(ctx, id) ?? { run: { id, status: 'cancelled' } };
    },
    async ingestObservation(ctx, agentId, body) {
      calls.push({ group: 'testRuns', fn: 'ingestObservation', ctx, agentId, body });
      return handlers.ingestObservation?.(ctx, agentId, body) ?? { event_id: 'evt_obs' };
    },
    async maybeFinalizeRunAfterProbeIngest(runId) {
      calls.push({ group: 'testRuns', fn: 'maybeFinalizeRunAfterProbeIngest', runId });
      return handlers.maybeFinalizeRunAfterProbeIngest?.(runId) ?? null;
    },
  };
  const evidence = {
    async listEvidence(ctx) {
      calls.push({ group: 'evidence', fn: 'listEvidence', ctx });
      return handlers.listEvidence?.(ctx) ?? [{ id: 'ev_fake' }];
    },
    async getEvidence(ctx, id) {
      calls.push({ group: 'evidence', fn: 'getEvidence', ctx, id });
      if (handlers.getEvidence) return handlers.getEvidence(ctx, id);
      return { id };
    },
  };
  const findings = {
    async listFindings(ctx) {
      calls.push({ group: 'findings', fn: 'listFindings', ctx });
      return handlers.listFindings?.(ctx) ?? [{ id: 'find_fake' }];
    },
    async getFinding(ctx, id) {
      calls.push({ group: 'findings', fn: 'getFinding', ctx, id });
      if (handlers.getFinding) return handlers.getFinding(ctx, id);
      return { id, status: 'open' };
    },
    async patchFinding(ctx, id, body) {
      calls.push({ group: 'findings', fn: 'patchFinding', ctx, id, body });
      if (handlers.patchFinding) return handlers.patchFinding(ctx, id, body);
      return { id, ...body };
    },
  };
  const reports = {
    async createReport(ctx, body) {
      calls.push({ group: 'reports', fn: 'createReport', ctx, body });
      return handlers.createReport?.(ctx, body) ?? { id: 'rpt_fake' };
    },
    async getReport(ctx, id) {
      calls.push({ group: 'reports', fn: 'getReport', ctx, id });
      if (handlers.getReport) return handlers.getReport(ctx, id);
      return { id };
    },
    async exportReport(ctx, id, format) {
      calls.push({ group: 'reports', fn: 'exportReport', ctx, id, format });
      if (handlers.exportReport) return handlers.exportReport(ctx, id, format);
      return { content: '{}', format };
    },
    async exportFinding(ctx, id) {
      calls.push({ group: 'reports', fn: 'exportFinding', ctx, id });
      if (handlers.exportFinding) return handlers.exportFinding(ctx, id);
      return { finding_id: id };
    },
  };
  return { testRuns, evidence, findings, reports, calls };
}

describe('createServer service injection — validation, evidence, findings, reports', () => {
  let baseUrl;
  let server;
  let validationCalls;

  before(() => {
    freshStore();
    const fakeTenants = makeFakeTenants();
    const fakeValidation = makeFakeValidationServices();
    validationCalls = fakeValidation.calls;
    ({ server, baseUrl } = listenServer({
      tenants: fakeTenants.tenants,
      testRuns: fakeValidation.testRuns,
      evidence: fakeValidation.evidence,
      findings: fakeValidation.findings,
      reports: fakeValidation.reports,
    }));
  });

  after(() => server.close());

  it('evidence and test-run read routes use injected async services', async () => {
    const headers = demoHeaders('viewer');
    const evList = await request(baseUrl, 'GET', '/v1/evidence', { headers });
    assert.equal(evList.status, 200);
    assert.deepEqual(evList.json.items, [{ id: 'ev_fake' }]);

    const evGet = await request(baseUrl, 'GET', '/v1/evidence/ev_9', { headers });
    assert.equal(evGet.status, 200);
    assert.equal(evGet.json.id, 'ev_9');

    const checks = await request(baseUrl, 'GET', '/v1/checks', { headers });
    assert.equal(checks.status, 200);
    assert.deepEqual(checks.json.items, [{ check_id: 'chk_fake' }]);

    const runs = await request(baseUrl, 'GET', '/v1/test-runs', { headers });
    assert.equal(runs.status, 200);
    assert.deepEqual(runs.json.items, [{ id: 'run_fake' }]);

    const run = await request(baseUrl, 'GET', '/v1/test-runs/run_9', { headers });
    assert.equal(run.status, 200);
    assert.equal(run.json.id, 'run_9');

    const events = await request(baseUrl, 'GET', '/v1/test-runs/run_9/events', { headers });
    assert.equal(events.status, 200);
    assert.deepEqual(events.json.items, [{ id: 'evt_fake' }]);

    assert.ok(validationCalls.some((c) => c.group === 'evidence' && c.fn === 'listEvidence'));
    assert.ok(validationCalls.some((c) => c.group === 'testRuns' && c.fn === 'getTestRun' && c.id === 'run_9'));
  });

  it('findings and report routes use injected async services', async () => {
    const readHeaders = demoHeaders('viewer');
    const listRes = await request(baseUrl, 'GET', '/v1/findings', { headers: readHeaders });
    assert.equal(listRes.status, 200);
    assert.deepEqual(listRes.json.items, [{ id: 'find_fake' }]);

    const getRes = await request(baseUrl, 'GET', '/v1/findings/find_9', { headers: readHeaders });
    assert.equal(getRes.status, 200);
    assert.equal(getRes.json.id, 'find_9');

    const writeHeaders = demoHeaders('admin');
    const patchRes = await request(baseUrl, 'PATCH', '/v1/findings/find_9', {
      headers: writeHeaders,
      body: { status: 'closed' },
    });
    assert.equal(patchRes.status, 200);
    assert.equal(patchRes.json.status, 'closed');

    const createRpt = await request(baseUrl, 'POST', '/v1/reports', {
      headers: writeHeaders,
      body: { test_run_id: 'run_1' },
    });
    assert.equal(createRpt.status, 201);
    assert.equal(createRpt.json.id, 'rpt_fake');

    const getRpt = await request(baseUrl, 'GET', '/v1/reports/rpt_9', { headers: writeHeaders });
    assert.equal(getRpt.status, 200);
    assert.equal(getRpt.json.id, 'rpt_9');

    const exportFinding = await request(baseUrl, 'POST', '/v1/findings/find_9/export', {
      headers: readHeaders,
    });
    assert.equal(exportFinding.status, 200);
    assert.equal(exportFinding.json.finding_id, 'find_9');
  });
});

describe('createServer service injection — validation not_found and orchestration errors', () => {
  let baseUrl;
  let server;

  after(() => server?.close());

  it('maps null validation service results to HTTP 404 and preserves orchestration status', async () => {
    freshStore();
    const fakeValidation = makeFakeValidationServices({
      getEvidence: async () => null,
      getTestRun: async () => null,
      getRunEvents: async () => null,
      getFinding: async () => null,
      patchFinding: async () => null,
      getReport: async () => null,
      exportReport: async () => null,
      exportFinding: async () => null,
      startTestRun: async () => ({
        error: 'postgres_validation_orchestration_not_wired',
        status: 503,
      }),
    });
    ({ server, baseUrl } = listenServer({
      tenants: makeFakeTenants().tenants,
      testRuns: fakeValidation.testRuns,
      evidence: fakeValidation.evidence,
      findings: fakeValidation.findings,
      reports: fakeValidation.reports,
    }));

    const headers = demoHeaders('admin');
    assert.equal((await request(baseUrl, 'GET', '/v1/evidence/ev_missing', { headers })).status, 404);
    assert.equal((await request(baseUrl, 'GET', '/v1/test-runs/run_missing', { headers })).status, 404);
    assert.equal(
      (await request(baseUrl, 'GET', '/v1/test-runs/run_missing/events', { headers })).status,
      404,
    );
    assert.equal((await request(baseUrl, 'GET', '/v1/findings/find_missing', { headers })).status, 404);
    assert.equal(
      (
        await request(baseUrl, 'PATCH', '/v1/findings/find_missing', {
          headers,
          body: { status: 'closed' },
        })
      ).status,
      404,
    );

    const startRes = await request(baseUrl, 'POST', '/v1/test-runs', {
      headers,
      body: { target_group_id: 'tg_1', check_id: 'chk_1' },
    });
    assert.equal(startRes.status, 503);
    assert.equal(startRes.json.error, 'postgres_validation_orchestration_not_wired');
  });
});
