import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { afterEach, describe, it } from 'node:test';
import { isHighScaleRoute, isPostgresUnwiredRoute } from '../../src/lib/postgresRouteGuard.mjs';
import { probeWorkerAuthHeaders } from '../../src/services/probeCoordinator.mjs';
import { createServer } from '../../src/server.mjs';
import { getStore, resetStoreForTests } from '../../src/store.mjs';
import { demoHeaders, request } from '../helpers/http.mjs';

const PROBE_WORKER_SECRET = 'postgres-probe-worker-secret-32chars!!';

const TEST_ENC_KEY_B64 = randomBytes(32).toString('base64');

function postgresRuntimeConfig(overrides = {}) {
  return {
    authMode: 'dev-headers',
    sessionSecret: null,
    oidc: null,
    nodeEnv: 'test',
    maxJsonBodyBytes: 65536,
    shutdownGraceMs: 30_000,
    persistenceMode: 'postgres',
    databaseUrlConfigured: true,
    probeMode: 'simulation',
    probeWorkerSecret: null,
    probeWorkerSecretConfigured: false,
    rateLimit: {
      windowMs: 60_000,
      maxRequests: 600,
      disabled: false,
      trustProxyHeaders: false,
    },
    secretEncryptionKey: null,
    secretEncryptionConfigured: false,
    ...overrides,
  };
}

function listenPostgresServer(services, runtimeHealth, runtimeConfigOverrides = {}) {
  const server = createServer({
    env: { ...process.env, ASTRANULL_NO_PERSIST: '1' },
    runtimeConfig: postgresRuntimeConfig(runtimeConfigOverrides),
    services,
    runtimeHealth,
  });
  server.listen(0);
  const { port } = server.address();
  return { server, baseUrl: `http://127.0.0.1:${port}` };
}

describe('createServer postgres mode — dev store seeding', () => {
  it('does not seed the dev JSON store', () => {
    process.env.ASTRANULL_NO_PERSIST = '1';
    resetStoreForTests({ tenants: [], environments: [], users: [], auditLog: [] });
    createServer({
      runtimeConfig: postgresRuntimeConfig(),
      services: {
        tenants: { getCurrentTenant: async () => null },
      },
    });
    assert.equal(getStore().tenants.length, 0);
  });
});

describe('createServer postgres mode — route wiring', () => {
  let server;
  let baseUrl;

  afterEach(() => {
    server?.close();
    server = undefined;
  });

  it('returns postgres_route_not_wired for high-scale when service is missing after auth', async () => {
    const fakeTenants = {
      async getCurrentTenant() {
        return { id: 'ten_demo', name: 'Demo' };
      },
    };
    ({ server, baseUrl } = listenPostgresServer({
      tenants: fakeTenants,
    }));

    const headers = demoHeaders('admin');
    const wired = await request(baseUrl, 'GET', '/v1/tenants/current', { headers });
    assert.equal(wired.status, 200);
    assert.equal(wired.json.id, 'ten_demo');

    const unwired = await request(baseUrl, 'GET', '/v1/high-scale-requests', { headers });
    assert.equal(unwired.status, 503);
    assert.equal(unwired.json.error, 'postgres_route_not_wired');
  });

  it('lists high-scale requests via injected highScale service without dev store', async () => {
    let listCalls = 0;
    ({ server, baseUrl } = listenPostgresServer({
      tenants: { getCurrentTenant: async () => ({ id: 'ten_demo' }) },
      highScale: {
        async listHighScaleRequests(ctx) {
          listCalls += 1;
          assert.equal(ctx.tenantId, 'ten_demo');
          return [{ id: 'hs_pg_1', state: 'submitted' }];
        },
      },
    }));

    const headers = demoHeaders('admin');
    const res = await request(baseUrl, 'GET', '/v1/high-scale-requests', { headers });
    assert.equal(res.status, 200);
    assert.equal(res.json.items.length, 1);
    assert.equal(res.json.items[0].id, 'hs_pg_1');
    assert.equal(listCalls, 1);
    assert.equal((getStore().highScaleRequests ?? []).length, 0);
  });

  it('denies missing tenant:read before GET /v1/state wiring check', async () => {
    let stateCalls = 0;
    ({ server, baseUrl } = listenPostgresServer({
      tenants: { getCurrentTenant: async () => ({ id: 'ten_demo' }) },
      state: {
        async getState() {
          stateCalls += 1;
          return { readiness: { score: 99, factors: [] } };
        },
      },
      serviceAccounts: {
        async authenticateServiceAccountBearer(token) {
          if (token === 'svc_no_tenant_read') {
            return {
              tenantId: 'ten_demo',
              userId: 'sa_1',
              role: 'engineer',
              scopes: ['target_group:read'],
              serviceAccountId: 'sa_1',
            };
          }
          return { error: 'invalid_token' };
        },
        async auditServiceAccountAuthFailure() {},
      },
      audit: { appendAuditEvent: async () => {} },
    }));

    const forbidden = await request(baseUrl, 'GET', '/v1/state', {
      headers: { Authorization: 'Bearer svc_no_tenant_read' },
    });
    assert.equal(forbidden.status, 403);
    assert.equal(forbidden.json.permission, 'tenant:read');
    assert.equal(stateCalls, 0);
  });

  it('returns postgres_route_not_wired for GET /v1/state when state service is missing', async () => {
    ({ server, baseUrl } = listenPostgresServer({
      tenants: { getCurrentTenant: async () => ({ id: 'ten_demo' }) },
    }));

    const headers = demoHeaders('admin');
    const unwired = await request(baseUrl, 'GET', '/v1/state', { headers });
    assert.equal(unwired.status, 503);
    assert.equal(unwired.json.error, 'postgres_route_not_wired');
  });

  it('returns postgres_route_not_wired for GET /v1/observability when state service is missing', async () => {
    ({ server, baseUrl } = listenPostgresServer({
      tenants: { getCurrentTenant: async () => ({ id: 'ten_demo' }) },
    }));

    const headers = demoHeaders('admin');
    const unwired = await request(baseUrl, 'GET', '/v1/observability', { headers });
    assert.equal(unwired.status, 503);
    assert.equal(unwired.json.error, 'postgres_route_not_wired');
  });

  it('handles GET /v1/observability via injected state.getState without dev store', async () => {
    let stateCalls = 0;
    resetStoreForTests({
      tenants: Array.from({ length: 50 }, (_, i) => ({ id: `ten_dev_${i}` })),
      environments: Array.from({ length: 40 }, (_, i) => ({ id: `env_dev_${i}` })),
      agents: Array.from({ length: 30 }, (_, i) => ({ id: `agt_dev_${i}` })),
      testRuns: Array.from({ length: 25 }, (_, i) => ({ id: `run_dev_${i}` })),
    });
    const stateSvc = {
      async getState(ctx) {
        stateCalls += 1;
        assert.equal(ctx.tenantId, 'ten_demo');
        return {
          tenant_id: ctx.tenantId,
          readiness: { score: 88, factors: [], updated_at: '2026-06-01T00:00:00.000Z' },
          target_groups: 7,
          agents_online: 2,
          recent_runs: [{ id: 'run_pg_1' }, { id: 'run_pg_2' }],
          open_findings: 4,
          high_scale_requests: 3,
          high_scale_status: 'available',
          kill_switch: {
            tenant_id: ctx.tenantId,
            active: false,
            reason: null,
            updated_at: null,
            updated_by: null,
          },
        };
      },
    };
    ({ server, baseUrl } = listenPostgresServer({
      tenants: { getCurrentTenant: async () => ({ id: 'ten_demo' }) },
      state: stateSvc,
    }));

    const headers = demoHeaders('admin');
    const res = await request(baseUrl, 'GET', '/v1/observability', { headers });
    assert.equal(res.status, 200);
    assert.equal(res.json.persistence, 'postgres');
    assert.equal(res.json.tenant_id, 'ten_demo');
    assert.equal(res.json.target_groups, 7);
    assert.equal(res.json.agents_online, 2);
    assert.equal(res.json.test_runs_recent, 2);
    assert.equal(res.json.open_findings, 4);
    assert.equal(res.json.high_scale_requests, 3);
    assert.equal(typeof res.json.counters, 'object');
    assert.equal(res.json.counters.http_requests_total >= 1, true);
    assert.equal('tenants' in res.json, false);
    assert.equal(stateCalls, 1);
    assert.equal(getStore().tenants.length, 50);
    assert.equal(getStore().agents.length, 30);
  });

  it('handles GET /v1/state via injected state.getState without dev store', async () => {
    let stateCalls = 0;
    resetStoreForTests({
      tenants: [],
      targetGroups: [{ id: 'tg_dev', tenant_id: 'ten_demo' }],
      testRuns: [{ id: 'run_dev', tenant_id: 'ten_demo' }],
    });
    const stateSvc = {
      async getState(ctx) {
        stateCalls += 1;
        assert.equal(ctx.tenantId, 'ten_demo');
        return {
          tenant_id: ctx.tenantId,
          readiness: { score: 42, factors: [], updated_at: '2026-06-01T00:00:00.000Z' },
          target_groups: 3,
          agents_online: 2,
          recent_runs: [{ id: 'run_pg' }],
          open_findings: 1,
          high_scale_requests: 1,
          high_scale_status: 'available',
          kill_switch: {
            tenant_id: ctx.tenantId,
            active: false,
            reason: null,
            updated_at: null,
            updated_by: null,
          },
        };
      },
    };
    ({ server, baseUrl } = listenPostgresServer({
      tenants: { getCurrentTenant: async () => ({ id: 'ten_demo' }) },
      state: stateSvc,
    }));

    const headers = demoHeaders('admin');
    const res = await request(baseUrl, 'GET', '/v1/state', { headers });
    assert.equal(res.status, 200);
    assert.equal(res.json.target_groups, 3);
    assert.equal(res.json.readiness.score, 42);
    assert.equal(stateCalls, 1);
    assert.equal(getStore().targetGroups.length, 1);
    assert.equal(getStore().testRuns.length, 1);
  });

  it('returns postgres_route_not_wired for GET /v1/audit-log when listAuditEntries is missing', async () => {
    const auditEvents = [];
    ({ server, baseUrl } = listenPostgresServer({
      tenants: { getCurrentTenant: async () => ({ id: 'ten_demo' }) },
      audit: {
        async appendAuditEvent(entry) {
          auditEvents.push(entry);
          return entry;
        },
      },
    }));

    const headers = demoHeaders('admin');
    const unwired = await request(baseUrl, 'GET', '/v1/audit-log', { headers });
    assert.equal(unwired.status, 503);
    assert.equal(unwired.json.error, 'postgres_route_not_wired');

    const forbidden = await request(baseUrl, 'GET', '/v1/audit-log', {
      headers: demoHeaders('viewer'),
    });
    assert.equal(forbidden.status, 403);
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(auditEvents.length, 1);
    assert.equal(auditEvents[0].action, 'rbac.denied');
  });

  it('lists audit entries via injected listAuditEntries without dev store', async () => {
    const pgItems = [
      { id: 'aud_1', tenant_id: 'ten_demo', action: 'tenant.updated', sequence: 1 },
    ];
    let listCalls = 0;
    resetStoreForTests({
      tenants: [],
      auditLog: [{ id: 'aud_dev', tenant_id: 'ten_demo', action: 'dev.only' }],
    });
    ({ server, baseUrl } = listenPostgresServer({
      tenants: { getCurrentTenant: async () => ({ id: 'ten_demo' }) },
      audit: {
        async listAuditEntries(ctx, options) {
          listCalls += 1;
          assert.equal(ctx.tenantId, 'ten_demo');
          assert.deepEqual(options, { limit: 200 });
          return pgItems;
        },
      },
    }));

    const headers = demoHeaders('admin');
    const res = await request(baseUrl, 'GET', '/v1/audit-log', { headers });
    assert.equal(res.status, 200);
    assert.deepEqual(res.json.items, pgItems);
    assert.equal(listCalls, 1);
    assert.equal(getStore().auditLog.length, 1);
  });

  it('returns postgres_route_not_wired for /v1/secrets when secretVault service is missing', async () => {
    ({ server, baseUrl } = listenPostgresServer({
      tenants: { getCurrentTenant: async () => ({ id: 'ten_demo' }) },
    }));

    const headers = demoHeaders('admin');
    const listRes = await request(baseUrl, 'GET', '/v1/secrets', { headers });
    assert.equal(listRes.status, 503);
    assert.equal(listRes.json.error, 'postgres_route_not_wired');

    const viewerList = await request(baseUrl, 'GET', '/v1/secrets', {
      headers: demoHeaders('viewer'),
    });
    assert.equal(viewerList.status, 403);
  });

  it('returns postgres_route_not_wired for report routes when reports service is missing', async () => {
    ({ server, baseUrl } = listenPostgresServer({
      tenants: { getCurrentTenant: async () => ({ id: 'ten_demo' }) },
    }));

    const headers = demoHeaders('admin');
    const createRes = await request(baseUrl, 'POST', '/v1/reports', {
      headers,
      body: { title: 'R' },
    });
    assert.equal(createRes.status, 503);
    assert.equal(createRes.json.error, 'postgres_route_not_wired');

    const viewerCreate = await request(baseUrl, 'POST', '/v1/reports', {
      headers: demoHeaders('viewer'),
      body: { title: 'R' },
    });
    assert.equal(viewerCreate.status, 403);
  });

  it('handles report routes via injected reports service without dev store', async () => {
    const auditEvents = [];
    const reports = {
      async createReport(ctx, body) {
        return {
          id: 'report_pg_1',
          tenant_id: ctx.tenantId,
          title: body.title ?? 'R',
          status: 'ready',
        };
      },
      async getReport(ctx, id) {
        return id === 'report_pg_1' ? { id, tenant_id: ctx.tenantId, title: 'R' } : null;
      },
      async exportReport(ctx, id, format) {
        if (id !== 'report_pg_1') return null;
        const payload = { report_id: id, title: 'R' };
        const custody = { schema_version: 'astranull.custody.v1', content_sha256: 'abc' };
        if (format === 'markdown') {
          return { format: 'markdown', content: '# R', payload, custody };
        }
        return { format: 'json', payload, custody };
      },
      async exportFinding(ctx, id) {
        if (id !== 'find_pg_1') return null;
        return { finding_id: id, custody: { content_sha256: 'def' } };
      },
    };

    resetStoreForTests({ tenants: [], reports: [] });
    ({ server, baseUrl } = listenPostgresServer({
      tenants: { getCurrentTenant: async () => ({ id: 'ten_demo' }) },
      reports,
      audit: { appendAuditEvent: async (e) => auditEvents.push(e) },
    }));

    const headers = demoHeaders('admin');
    const created = await request(baseUrl, 'POST', '/v1/reports', {
      headers,
      body: { title: 'Postgres report' },
    });
    assert.equal(created.status, 201);
    assert.equal(created.json.id, 'report_pg_1');
    assert.equal(getStore().reports.length, 0);

    const fetched = await request(baseUrl, 'GET', '/v1/reports/report_pg_1', { headers });
    assert.equal(fetched.status, 200);

    const exported = await request(baseUrl, 'GET', '/v1/reports/report_pg_1/export?format=json', {
      headers,
    });
    assert.equal(exported.status, 200);
    assert.equal(exported.json.payload.report_id, 'report_pg_1');

    const findingExport = await request(baseUrl, 'POST', '/v1/findings/find_pg_1/export', { headers });
    assert.equal(findingExport.status, 200);
    assert.equal(findingExport.json.finding_id, 'find_pg_1');
    assert.equal(auditEvents.length, 0);
  });

  it('handles secret vault routes via injected secretVault without dev store', async () => {
    const secrets = new Map();
    const auditEvents = [];
    const secretVault = {
      async storeEncryptedSecret(ctx, body) {
        const id = `secret_${secrets.size + 1}`;
        const record = {
          id,
          tenant_id: ctx.tenantId,
          purpose: body.purpose,
          name: body.name,
          metadata: body.metadata ?? {},
          rotation: 0,
          envelope: { version: 1, algorithm: 'AES-256-GCM', iv: 'iv' },
          created_at: '2026-06-01T00:00:00.000Z',
          updated_at: '2026-06-01T00:00:00.000Z',
        };
        secrets.set(id, record);
        return { secret: { ...record, envelope: { version: 1, algorithm: 'AES-256-GCM', iv: 'iv' } } };
      },
      async listEncryptedSecrets(ctx) {
        return [...secrets.values()].filter((s) => s.tenant_id === ctx.tenantId);
      },
      async rotateEncryptedSecret(ctx, id, body) {
        const record = secrets.get(id);
        if (!record || record.tenant_id !== ctx.tenantId) return null;
        record.rotation = (record.rotation ?? 0) + 1;
        record.updated_at = '2026-06-02T00:00:00.000Z';
        if (body.metadata) record.metadata = body.metadata;
        return { ...record };
      },
    };

    resetStoreForTests({ tenants: [], encryptedSecrets: [] });
    ({ server, baseUrl } = listenPostgresServer(
      {
        tenants: { getCurrentTenant: async () => ({ id: 'ten_demo' }) },
        secretVault,
        audit: { appendAuditEvent: async (entry) => auditEvents.push(entry) },
      },
      undefined,
      { secretEncryptionKey: Buffer.from(TEST_ENC_KEY_B64, 'base64'), secretEncryptionConfigured: true },
    ));

    const headers = demoHeaders('admin');
    const created = await request(baseUrl, 'POST', '/v1/secrets', {
      headers,
      body: { purpose: 'webhook', name: 'outbound', plaintext: 'whsec_test' },
    });
    assert.equal(created.status, 201);
    assert.equal(created.json.secret.purpose, 'webhook');
    assert.equal(getStore().encryptedSecrets.length, 0);

    const listed = await request(baseUrl, 'GET', '/v1/secrets', { headers });
    assert.equal(listed.status, 200);
    assert.equal(listed.json.items.length, 1);

    const rotated = await request(
      baseUrl,
      'POST',
      `/v1/secrets/${created.json.secret.id}/rotate`,
      { headers, body: { plaintext: 'whsec_rotated' } },
    );
    assert.equal(rotated.status, 200);
    assert.equal(rotated.json.rotation, 1);
    assert.equal(auditEvents.length, 0);
  });

  it('returns postgres_route_not_wired for POST /v1/events when events service is missing', async () => {
    ({ server, baseUrl } = listenPostgresServer({
      tenants: { getCurrentTenant: async () => ({ id: 'ten_demo' }) },
    }));

    const headers = demoHeaders('admin');
    const unwired = await request(baseUrl, 'POST', '/v1/events', {
      headers,
      body: { event_id: 'ext_unwired' },
    });
    assert.equal(unwired.status, 503);
    assert.equal(unwired.json.error, 'postgres_route_not_wired');

    const forbidden = await request(baseUrl, 'POST', '/v1/events', {
      headers: demoHeaders('viewer'),
      body: { event_id: 'ext_unwired' },
    });
    assert.equal(forbidden.status, 403);
  });

  it('returns postgres_route_not_wired for notification routes when notifications service is missing', async () => {
    ({ server, baseUrl } = listenPostgresServer({
      tenants: { getCurrentTenant: async () => ({ id: 'ten_demo' }) },
    }));

    const headers = demoHeaders('admin');
    const listRes = await request(baseUrl, 'GET', '/v1/notifications', { headers });
    assert.equal(listRes.status, 503);
    assert.equal(listRes.json.error, 'postgres_route_not_wired');

    const createRes = await request(baseUrl, 'POST', '/v1/notifications', {
      headers,
      body: { channel: 'in_app', triggers: ['finding.high_severity'] },
    });
    assert.equal(createRes.status, 503);
    assert.equal(createRes.json.error, 'postgres_route_not_wired');
  });

  it('denies viewer before notification route wiring check', async () => {
    ({ server, baseUrl } = listenPostgresServer({
      tenants: { getCurrentTenant: async () => ({ id: 'ten_demo' }) },
    }));

    const forbidden = await request(baseUrl, 'GET', '/v1/notifications', {
      headers: demoHeaders('viewer'),
    });
    assert.equal(forbidden.status, 403);
  });

  it('handles GET/POST /v1/notifications via injected notifications service without dev store', async () => {
    let listCalls = 0;
    let createCalls = 0;
    const notifications = {
      async listNotifications(ctx) {
        listCalls += 1;
        assert.equal(ctx.tenantId, 'ten_demo');
        return { rules: [{ id: 'nrule_pg', triggers: ['finding.high_severity'] }], events: [] };
      },
      async createNotificationRule(ctx, body) {
        createCalls += 1;
        assert.equal(ctx.tenantId, 'ten_demo');
        assert.equal(body.channel, 'in_app');
        return {
          id: 'nrule_new',
          tenant_id: ctx.tenantId,
          channel: 'in_app',
          destination: '',
          triggers: body.triggers ?? ['finding.high_severity'],
          enabled: true,
          created_at: '2026-06-01T00:00:00.000Z',
        };
      },
    };

    resetStoreForTests({ tenants: [], notificationRules: [{ id: 'nrule_dev', tenant_id: 'ten_demo' }] });
    ({ server, baseUrl } = listenPostgresServer({
      tenants: { getCurrentTenant: async () => ({ id: 'ten_demo' }) },
      notifications,
    }));

    const headers = demoHeaders('admin');
    const listed = await request(baseUrl, 'GET', '/v1/notifications', { headers });
    assert.equal(listed.status, 200);
    assert.equal(listed.json.rules[0].id, 'nrule_pg');
    assert.equal(listCalls, 1);
    assert.equal(getStore().notificationRules.length, 1);

    const created = await request(baseUrl, 'POST', '/v1/notifications', {
      headers,
      body: { channel: 'in_app', triggers: ['agent.offline'] },
    });
    assert.equal(created.status, 201);
    assert.equal(created.json.id, 'nrule_new');
    assert.equal(createCalls, 1);
    assert.equal(getStore().notificationRules.length, 1);
  });

  it('returns postgres_route_not_wired for agent update routes when agentUpdates service is missing', async () => {
    ({ server, baseUrl } = listenPostgresServer({
      tenants: { getCurrentTenant: async () => ({ id: 'ten_demo' }) },
    }));

    const headers = demoHeaders('admin');
    const listReleases = await request(baseUrl, 'GET', '/v1/agent-updates', { headers });
    assert.equal(listReleases.status, 503);
    assert.equal(listReleases.json.error, 'postgres_route_not_wired');

    const listKeys = await request(baseUrl, 'GET', '/v1/agent-update-trust-keys', { headers });
    assert.equal(listKeys.status, 503);

    const createKey = await request(baseUrl, 'POST', '/v1/agent-update-trust-keys', {
      headers,
      body: { name: 'k', public_key_der_base64: 'QUJD' },
    });
    assert.equal(createKey.status, 503);

    const rollback = await request(baseUrl, 'POST', '/v1/agent-updates/aup_missing/rollback', { headers });
    assert.equal(rollback.status, 503);
  });

  it('denies viewer before agent update route wiring check', async () => {
    ({ server, baseUrl } = listenPostgresServer({
      tenants: { getCurrentTenant: async () => ({ id: 'ten_demo' }) },
    }));

    const forbidden = await request(baseUrl, 'GET', '/v1/agent-updates', {
      headers: demoHeaders('viewer'),
    });
    assert.equal(forbidden.status, 403);

    const forbiddenWrite = await request(baseUrl, 'POST', '/v1/agent-updates', {
      headers: demoHeaders('viewer'),
      body: { version: '2.0.0' },
    });
    assert.equal(forbiddenWrite.status, 403);
  });

  it('handles representative agent update routes via injected agentUpdates without dev store', async () => {
    let trustCreateCalls = 0;
    let pollCalls = 0;
    let statusCalls = 0;
    let rollbackCalls = 0;
    const agentUpdates = {
      async createAgentUpdateTrustKey(ctx, body) {
        trustCreateCalls += 1;
        assert.equal(ctx.tenantId, 'ten_demo');
        assert.ok(body.public_key_der_base64);
        return { trust_key: { id: 'aup_key_pg', name: 'k', fingerprint_sha256: 'fp', status: 'active' } };
      },
      async listAgentUpdateTrustKeys(ctx) {
        assert.equal(ctx.tenantId, 'ten_demo');
        return [{ id: 'aup_key_pg', name: 'k', fingerprint_sha256: 'fp', status: 'active' }];
      },
      async revokeAgentUpdateTrustKey() {
        return { trust_key: { id: 'aup_key_pg', status: 'revoked' } };
      },
      async createAgentUpdateRelease(ctx) {
        assert.equal(ctx.tenantId, 'ten_demo');
        return { release: { id: 'aup_rel_pg', version: '2.0.0', state: 'active' } };
      },
      async listAgentUpdateReleases(ctx) {
        assert.equal(ctx.tenantId, 'ten_demo');
        return [{ id: 'aup_rel_pg', version: '2.0.0', state: 'active' }];
      },
      async requestAgentUpdateRollback(ctx, releaseId) {
        rollbackCalls += 1;
        assert.equal(ctx.tenantId, 'ten_demo');
        assert.equal(releaseId, 'aup_rel_pg');
        return { release: { id: releaseId, state: 'rollback_requested' } };
      },
      async pollAgentUpdate(agent) {
        pollCalls += 1;
        assert.equal(agent.id, 'agt_pg');
        return { update: null };
      },
      async recordAgentUpdateStatus(agent, body) {
        statusCalls += 1;
        assert.equal(agent.id, 'agt_pg');
        assert.equal(body.status, 'applied');
        return { status: { id: 'aup_st_pg', status: 'applied' } };
      },
    };

    resetStoreForTests({
      tenants: [],
      agentUpdateReleases: [{ id: 'aup_dev', tenant_id: 'ten_demo' }],
      agentUpdateTrustKeys: [{ id: 'aup_dev_key', tenant_id: 'ten_demo' }],
    });
    ({ server, baseUrl } = listenPostgresServer({
      tenants: { getCurrentTenant: async () => ({ id: 'ten_demo' }) },
      agentUpdates,
      agentAuth: {
        async requireAgentAuth(_headers, agentId) {
          return { agent: { id: agentId, tenant_id: 'ten_demo', version: '1.0.0' } };
        },
      },
    }));

    const headers = demoHeaders('admin');
    const listed = await request(baseUrl, 'GET', '/v1/agent-updates', { headers });
    assert.equal(listed.status, 200);
    assert.equal(listed.json.items[0].id, 'aup_rel_pg');
    assert.equal(getStore().agentUpdateReleases.length, 1);

    const keys = await request(baseUrl, 'GET', '/v1/agent-update-trust-keys', { headers });
    assert.equal(keys.status, 200);
    assert.equal(keys.json.items[0].id, 'aup_key_pg');

    const rollback = await request(baseUrl, 'POST', '/v1/agent-updates/aup_rel_pg/rollback', { headers });
    assert.equal(rollback.status, 200);
    assert.equal(rollbackCalls, 1);

    const poll = await request(baseUrl, 'GET', '/v1/agents/agt_pg/update', {
      headers: { Authorization: 'Bearer agc_test' },
    });
    assert.equal(poll.status, 200);
    assert.equal(pollCalls, 1);

    const status = await request(baseUrl, 'POST', '/v1/agents/agt_pg/update-status', {
      headers: { Authorization: 'Bearer agc_test' },
      body: { release_id: 'aup_rel_pg', status: 'applied', installed_version: '2.0.0' },
    });
    assert.equal(status.status, 201);
    assert.equal(statusCalls, 1);
    assert.equal(trustCreateCalls, 0);
  });

  it('handles POST /v1/events via injected events service without dev store', async () => {
    let ingestCalls = 0;
    const events = {
      async ingestEvent(ctx, body) {
        ingestCalls += 1;
        assert.equal(ctx.tenantId, 'ten_demo');
        assert.equal(body.event_id, 'ext_pg_1');
        return {
          event: {
            id: 'event_pg_1',
            event_id: body.event_id,
            tenant_id: ctx.tenantId,
            signal_type: 'generic',
          },
        };
      },
    };

    resetStoreForTests({ tenants: [], events: [], ingestedEventIds: {} });
    ({ server, baseUrl } = listenPostgresServer({
      tenants: { getCurrentTenant: async () => ({ id: 'ten_demo' }) },
      events,
    }));

    const headers = demoHeaders('admin');
    const created = await request(baseUrl, 'POST', '/v1/events', {
      headers,
      body: { event_id: 'ext_pg_1', signal_type: 'generic' },
    });
    assert.equal(created.status, 201);
    assert.equal(created.json.event.id, 'event_pg_1');
    assert.equal(ingestCalls, 1);
    assert.equal(getStore().events.length, 0);
  });

  it('returns postgres_route_not_wired for production release evidence when service is missing', async () => {
    ({ server, baseUrl } = listenPostgresServer({
      tenants: { getCurrentTenant: async () => ({ id: 'ten_demo' }) },
    }));

    const headers = demoHeaders('admin');
    const unwired = await request(baseUrl, 'GET', '/v1/production-release-evidence', { headers });
    assert.equal(unwired.status, 503);
    assert.equal(unwired.json.error, 'postgres_route_not_wired');
  });

  it('handles production release evidence routes via injected service without dev store', async () => {
    resetStoreForTests({ productionReleaseEvidence: [{ id: 'evd_dev_only', tenant_id: 'ten_demo' }] });
    const calls = [];
    const evidenceRecord = {
      id: 'evd_pg_1',
      tenant_id: 'ten_demo',
      kind: 'third_party_security_review',
      release_id: 'rel_pg',
      status: 'accepted',
      evidence: { review_report_uri: 'evidence://report' },
      validation: { ok: true },
      created_at: '2026-07-02T00:00:00.000Z',
      created_by: 'usr_admin',
    };
    ({ server, baseUrl } = listenPostgresServer({
      tenants: { getCurrentTenant: async () => ({ id: 'ten_demo' }) },
      productionReleaseEvidence: {
        async recordProductionReleaseEvidence(ctx, body) {
          calls.push({ method: 'record', ctx, body });
          return evidenceRecord;
        },
        async listProductionReleaseEvidence(ctx) {
          calls.push({ method: 'list', ctx });
          return [evidenceRecord];
        },
        async getProductionReleaseEvidence(ctx, id) {
          calls.push({ method: 'get', ctx, id });
          return id === evidenceRecord.id ? evidenceRecord : null;
        },
        async getProductionReleaseEvidenceAttestation(ctx) {
          calls.push({ method: 'attestation', ctx });
          return {
            attestation: {
              production_ready: false,
              release_id: 'rel_pg',
              signoff_status: 'inventory_incomplete',
            },
            records: [
              {
                id: evidenceRecord.id,
                kind: evidenceRecord.kind,
                status: evidenceRecord.status,
                release_id: evidenceRecord.release_id,
                created_at: evidenceRecord.created_at,
                validation: evidenceRecord.validation,
              },
            ],
          };
        },
      },
    }));

    const headers = demoHeaders('admin');
    const created = await request(baseUrl, 'POST', '/v1/production-release-evidence', {
      headers,
      body: {
        kind: 'third_party_security_review',
        release_id: 'rel_pg',
        evidence: { review_report_uri: 'evidence://report' },
      },
    });
    assert.equal(created.status, 201);
    assert.equal(created.json.evidence.id, 'evd_pg_1');

    const listed = await request(baseUrl, 'GET', '/v1/production-release-evidence', { headers });
    assert.equal(listed.status, 200);
    assert.equal(listed.json.items[0].id, 'evd_pg_1');

    const fetched = await request(baseUrl, 'GET', '/v1/production-release-evidence/evd_pg_1', {
      headers,
    });
    assert.equal(fetched.status, 200);
    assert.equal(fetched.json.id, 'evd_pg_1');

    const attestation = await request(baseUrl, 'GET', '/v1/production-release-evidence/attestation', {
      headers,
    });
    assert.equal(attestation.status, 200);
    assert.equal(attestation.json.attestation.production_ready, false);
    assert.equal(attestation.json.records[0].id, 'evd_pg_1');
    assert.equal('evidence' in attestation.json.records[0], false);

    assert.deepEqual(calls.map((c) => c.method), ['record', 'list', 'get', 'attestation']);
    assert.equal(calls[0].ctx.tenantId, 'ten_demo');
    assert.equal(calls[2].id, 'evd_pg_1');
    assert.equal(calls[3].ctx.tenantId, 'ten_demo');
    assert.equal(getStore().productionReleaseEvidence.length, 1);
    assert.equal(getStore().productionReleaseEvidence[0].id, 'evd_dev_only');
  });

  it('returns postgres_route_not_wired for WAF routes when wafPosture service is missing', async () => {
    ({ server, baseUrl } = listenPostgresServer(
      { tenants: { getCurrentTenant: async () => ({ id: 'ten_demo' }) } },
      undefined,
      {
        featureFlags: { wafPostureEnabled: true, externalDiscoveryEnabled: false },
      },
    ));

    const headers = demoHeaders('admin');
    const unwired = await request(baseUrl, 'GET', '/v1/waf/assets', { headers });
    assert.equal(unwired.status, 503);
    assert.equal(unwired.json.error, 'postgres_route_not_wired');
  });

  it('handles GET /v1/waf/assets via injected wafPosture service without dev store', async () => {
    resetStoreForTests({ wafAssets: [{ id: 'waf_dev_only', tenant_id: 'ten_demo' }] });
    const calls = [];
    const wafItems = [{ id: 'waf_pg_1', tenant_id: 'ten_demo', status: 'unknown' }];
    ({ server, baseUrl } = listenPostgresServer(
      {
        tenants: { getCurrentTenant: async () => ({ id: 'ten_demo' }) },
        wafPosture: {
          async listWafAssets(ctx) {
            calls.push({ method: 'listWafAssets', ctx });
            return wafItems;
          },
        },
      },
      undefined,
      {
        featureFlags: { wafPostureEnabled: true, externalDiscoveryEnabled: false },
      },
    ));

    const headers = demoHeaders('admin');
    const listed = await request(baseUrl, 'GET', '/v1/waf/assets', { headers });
    assert.equal(listed.status, 200);
    assert.deepEqual(listed.json.items, wafItems);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].method, 'listWafAssets');
    assert.equal(calls[0].ctx.tenantId, 'ten_demo');
    assert.equal(getStore().wafAssets.length, 1);
    assert.equal(getStore().wafAssets[0].id, 'waf_dev_only');
  });

  it('handles connector snapshot routes via injected wafPosture service without dev store', async () => {
    resetStoreForTests({ wafConnectorSnapshots: [{ id: 'snap_dev_only', tenant_id: 'ten_demo' }] });
    const calls = [];
    const snapshots = [
      {
        id: 'snap_pg_1',
        connector_id: 'conn_pg_1',
        snapshot_kind: 'waf_policy',
        summary: { policy_mode: 'block' },
      },
    ];
    ({ server, baseUrl } = listenPostgresServer(
      {
        tenants: { getCurrentTenant: async () => ({ id: 'ten_demo' }) },
        wafPosture: {
          async listConnectorSnapshots(ctx, id) {
            calls.push({ method: 'listConnectorSnapshots', ctx, id });
            return snapshots;
          },
        },
      },
      undefined,
      {
        featureFlags: { wafPostureEnabled: true, externalDiscoveryEnabled: false },
      },
    ));

    const headers = demoHeaders('admin');
    const listed = await request(baseUrl, 'GET', '/v1/connectors/conn_pg_1/snapshots', { headers });
    assert.equal(listed.status, 200);
    assert.deepEqual(listed.json.items, snapshots);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].id, 'conn_pg_1');
    assert.equal(calls[0].ctx.tenantId, 'ten_demo');
    assert.equal(getStore().wafConnectorSnapshots.length, 1);
    assert.equal(getStore().wafConnectorSnapshots[0].id, 'snap_dev_only');
  });
});

describe('createServer postgres mode — probe worker routes', () => {
  let server;
  let baseUrl;

  afterEach(() => {
    server?.close();
    server = undefined;
  });

  it('does not treat probe worker routes as generic unwired routes', () => {
    assert.equal(isPostgresUnwiredRoute('/internal/probe/jobs', 'GET'), false);
    assert.equal(
      isPostgresUnwiredRoute('/internal/probe/jobs/pjob_1/result', 'POST'),
      false,
    );
    assert.equal(isHighScaleRoute('/v1/high-scale-requests', 'GET'), true);
    assert.equal(isPostgresUnwiredRoute('/v1/high-scale-requests', 'GET'), false);
  });

  function signedProbeHeaders(method, path, bodyText = '', tenantId = 'ten_demo') {
    return probeWorkerAuthHeaders(
      'pw_pg_test',
      { method, path, bodyText, tenantId },
      PROBE_WORKER_SECRET,
    );
  }

  it('returns postgres_route_not_wired when probeJobs service is missing after worker auth', async () => {
    ({ server, baseUrl } = listenPostgresServer(
      { tenants: { getCurrentTenant: async () => ({ id: 'ten_demo' }) } },
      undefined,
      {
        probeMode: 'signed-worker',
        probeWorkerSecret: PROBE_WORKER_SECRET,
        probeWorkerSecretConfigured: true,
      },
    ));

    const headers = signedProbeHeaders('GET', '/internal/probe/jobs');
    const res = await request(baseUrl, 'GET', '/internal/probe/jobs', { headers });
    assert.equal(res.status, 503);
    assert.equal(res.json.error, 'postgres_route_not_wired');
  });

  it('rejects probe worker requests without x-probe-tenant-id in postgres mode', async () => {
    ({ server, baseUrl } = listenPostgresServer(
      {
        probeJobs: {
          listPendingProbeJobsForWorker: async () => [],
          ingestProbeResult: async () => ({}),
        },
      },
      undefined,
      {
        probeMode: 'signed-worker',
        probeWorkerSecret: PROBE_WORKER_SECRET,
        probeWorkerSecretConfigured: true,
      },
    ));

    const headers = probeWorkerAuthHeaders(
      'pw_pg_test',
      { method: 'GET', path: '/internal/probe/jobs', bodyText: '' },
      PROBE_WORKER_SECRET,
    );
    const res = await request(baseUrl, 'GET', '/internal/probe/jobs', { headers });
    assert.equal(res.status, 401);
    assert.match(res.json.message, /x-probe-tenant-id/);
  });

  it('calls injected probeJobs service without using dev store', async () => {
    resetStoreForTests({
      probeJobs: [{ id: 'pjob_dev_only', status: 'pending', tenant_id: 'ten_demo' }],
    });
    let listCalls = 0;
    ({ server, baseUrl } = listenPostgresServer(
      {
        probeJobs: {
          async listPendingProbeJobsForWorker(ctx) {
            listCalls += 1;
            assert.equal(ctx.tenantId, 'ten_demo');
            assert.equal(ctx.workerId, 'pw_pg_test');
            return [{ id: 'pjob_pg', status: 'leased' }];
          },
          async ingestProbeResult() {
            return { error: 'not_used' };
          },
        },
        testRuns: { maybeFinalizeRunAfterProbeIngest: async () => null },
      },
      undefined,
      {
        probeMode: 'signed-worker',
        probeWorkerSecret: PROBE_WORKER_SECRET,
        probeWorkerSecretConfigured: true,
      },
    ));

    const headers = signedProbeHeaders('GET', '/internal/probe/jobs');
    const res = await request(baseUrl, 'GET', '/internal/probe/jobs', { headers });
    assert.equal(res.status, 200);
    assert.equal(res.json.jobs.length, 1);
    assert.equal(res.json.jobs[0].id, 'pjob_pg');
    assert.equal(listCalls, 1);
    assert.equal(getStore().probeJobs[0].status, 'pending');
  });

  it('passes tenant context to maybeFinalizeRunAfterProbeIngest after probe result ingest', async () => {
    const finalizeCalls = [];
    ({ server, baseUrl } = listenPostgresServer(
      {
        probeJobs: {
          listPendingProbeJobsForWorker: async () => [],
          async ingestProbeResult() {
            return { run_id: 'run_1', tenant_id: 'ten_demo' };
          },
        },
        testRuns: {
          async maybeFinalizeRunAfterProbeIngest(ctxOrRunId, runId) {
            finalizeCalls.push({ ctxOrRunId, runId });
            return null;
          },
        },
      },
      undefined,
      {
        probeMode: 'signed-worker',
        probeWorkerSecret: PROBE_WORKER_SECRET,
        probeWorkerSecretConfigured: true,
      },
    ));

    const path = '/internal/probe/jobs/pjob_1/result';
    const body = { external_result: 'blocked' };
    const headers = signedProbeHeaders('POST', path, JSON.stringify(body));
    const res = await request(baseUrl, 'POST', path, { headers, body });
    assert.equal(res.status, 201);
    assert.equal(finalizeCalls.length, 1);
    assert.equal(finalizeCalls[0].runId, 'run_1');
    assert.equal(finalizeCalls[0].ctxOrRunId.tenantId, 'ten_demo');
    assert.equal(finalizeCalls[0].ctxOrRunId.role, 'probe_worker');
  });
});

describe('createServer postgres mode — readiness', () => {
  let server;
  let baseUrl;

  afterEach(() => {
    server?.close();
    server = undefined;
  });

  it('uses runtimeHealth for /ready when persistence is postgres', async () => {
    let healthCalls = 0;
    const runtimeHealth = async () => {
      healthCalls += 1;
      return { ok: true, persistence: 'postgres' };
    };
    ({ server, baseUrl } = listenPostgresServer(
      { tenants: { getCurrentTenant: async () => ({ id: 'ten_demo' }) } },
      runtimeHealth,
    ));

    const ready = await request(baseUrl, 'GET', '/ready');
    assert.equal(ready.status, 200);
    assert.equal(ready.json.persistence, 'postgres');
    assert.equal(healthCalls, 1);
  });
});
