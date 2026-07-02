import assert from 'node:assert/strict';
import { after, afterEach, before, describe, it } from 'node:test';
import { loadRuntimeConfig } from '../../src/config.mjs';
import { createServer } from '../../src/server.mjs';
import { getStore } from '../../src/store.mjs';
import { demoHeaders, request } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';

const envSnapshot = { ...process.env };

function restoreEnv() {
  for (const key of Object.keys(process.env)) {
    if (!(key in envSnapshot)) delete process.env[key];
  }
  Object.assign(process.env, envSnapshot);
}

function discoveryEnabledEnv() {
  return {
    ...process.env,
    ASTRANULL_NO_PERSIST: '1',
    ASTRANULL_EXTERNAL_DISCOVERY_ENABLED: '1',
  };
}

function applyDiscoveryEnv() {
  Object.assign(process.env, discoveryEnabledEnv());
}

function startServer(env = discoveryEnabledEnv()) {
  const runtimeConfig = loadRuntimeConfig(env);
  const server = createServer({ runtimeConfig, env });
  server.listen(0);
  const { port } = server.address();
  return { server, baseUrl: `http://127.0.0.1:${port}` };
}

function sampleEntityBody(overrides = {}) {
  return {
    entity_id: 'ent_acme',
    entity_type: 'parent_organization',
    name: 'Acme Corp',
    display_name: 'Acme',
    root_domains: ['example.com'],
    country: 'US',
    confidence: 0.9,
    source: 'customer_import',
    ...overrides,
  };
}

function sampleCandidateBody(overrides = {}) {
  return {
    candidate_id: 'cand_api',
    hostname: 'api.example.com',
    source_type: 'dns',
    source_ref: 'dns_ref_1',
    confidence: 0.8,
    ownership_status: 'unknown',
    approval_status: 'not_requested',
    first_seen_at: '2026-07-02T00:00:00.000Z',
    last_seen_at: '2026-07-02T12:00:00.000Z',
    evidence_summary: {
      source_kind: 'dns',
      dns_record_type: 'CNAME',
      root_domain_match: true,
    },
    state: 'candidate',
    ...overrides,
  };
}

async function createEntity(baseUrl, headers, overrides = {}) {
  const res = await request(baseUrl, 'POST', '/v1/discovery/entities', {
    headers,
    body: sampleEntityBody(overrides),
  });
  assert.equal(res.status, 201);
  return res.json.entity;
}

async function createCandidate(baseUrl, headers, overrides = {}) {
  const res = await request(baseUrl, 'POST', '/v1/discovery/candidates', {
    headers,
    body: sampleCandidateBody(overrides),
  });
  assert.equal(res.status, 201);
  return res.json.candidate;
}

function seedOtherTenant() {
  const store = getStore();
  store.tenants.push({ id: 'ten_other', name: 'Other' });
}

describe('external discovery API feature flag', () => {
  let server;
  let baseUrl;

  before(() => {
    freshStore();
    const env = { ...process.env, ASTRANULL_NO_PERSIST: '1' };
    delete env.ASTRANULL_EXTERNAL_DISCOVERY_ENABLED;
    ({ server, baseUrl } = startServer(env));
  });

  after(() => {
    server?.close();
    restoreEnv();
  });

  it('returns discovery_feature_disabled when flag is off', async () => {
    const res = await request(baseUrl, 'GET', '/v1/discovery/entities', {
      headers: demoHeaders('admin'),
    });
    assert.equal(res.status, 404);
    assert.equal(res.json.error, 'discovery_feature_disabled');
  });
});

describe('external discovery API', () => {
  let server;
  let baseUrl;

  before(() => {
    freshStore();
    applyDiscoveryEnv();
    ({ server, baseUrl } = startServer());
  });

  after(() => {
    server?.close();
    restoreEnv();
  });

  afterEach(() => {
    freshStore();
    applyDiscoveryEnv();
  });

  it('creates and lists discovery entities scoped to tenant', async () => {
    const engineer = demoHeaders('engineer');
    const entity = await createEntity(baseUrl, engineer);
    assert.equal(entity.entity_id, 'ent_acme');
    assert.equal(entity.entity_type, 'parent_organization');

    const list = await request(baseUrl, 'GET', '/v1/discovery/entities', { headers: engineer });
    assert.equal(list.status, 200);
    assert.equal(list.json.items.length, 1);
    assert.equal(list.json.items[0].id, entity.id);

    seedOtherTenant();
    await createEntity(baseUrl, demoHeaders('engineer', 'ten_other', 'usr_other'), {
      entity_id: 'ent_other',
      name: 'Other Corp',
      display_name: 'Other',
      root_domains: ['other.example'],
    });

    const scoped = await request(baseUrl, 'GET', '/v1/discovery/entities', { headers: engineer });
    assert.equal(scoped.status, 200);
    assert.equal(scoped.json.items.length, 1);
    assert.equal(scoped.json.items[0].entity_id, 'ent_acme');
  });

  it('creates candidates and lists them', async () => {
    const engineer = demoHeaders('engineer');
    const candidate = await createCandidate(baseUrl, engineer);
    assert.equal(candidate.hostname, 'api.example.com');
    assert.equal(candidate.state, 'candidate');

    const list = await request(baseUrl, 'GET', '/v1/discovery/candidates', { headers: engineer });
    assert.equal(list.status, 200);
    assert.equal(list.json.items.length, 1);
    assert.equal(list.json.items[0].id, candidate.id);
  });

  it('returns only inbox-eligible candidates', async () => {
    const engineer = demoHeaders('engineer');
    const inboxCandidate = await createCandidate(baseUrl, engineer, { state: 'candidate' });
    await createCandidate(baseUrl, engineer, {
      candidate_id: 'cand_review',
      hostname: 'review.example.com',
      state: 'needs_review',
    });
    await createCandidate(baseUrl, engineer, {
      candidate_id: 'cand_approved',
      hostname: 'approved.example.com',
      state: 'approved_target',
      approval_status: 'approved',
    });

    const inbox = await request(baseUrl, 'GET', '/v1/discovery/inbox', { headers: engineer });
    assert.equal(inbox.status, 200);
    assert.equal(inbox.json.count, 2);
    assert.equal(inbox.json.items.length, 2);
    const ids = inbox.json.items.map((c) => c.id);
    assert.ok(ids.includes(inboxCandidate.id));
    assert.ok(!ids.some((id) => {
      const item = inbox.json.items.find((c) => c.id === id);
      return item?.state === 'approved_target';
    }));
  });

  it('approves and rejects candidates with state transitions', async () => {
    const engineer = demoHeaders('engineer');
    const candidate = await createCandidate(baseUrl, engineer);

    const approved = await request(
      baseUrl,
      'POST',
      `/v1/discovery/candidates/${candidate.id}/approve`,
      { headers: engineer, body: {} },
    );
    assert.equal(approved.status, 200);
    assert.equal(approved.json.candidate.state, 'approved_target');
    assert.equal(approved.json.candidate.approval_status, 'approved');
    assert.ok(approved.json.candidate.scope_hash);

    const rejectCandidate = await createCandidate(baseUrl, engineer, {
      candidate_id: 'cand_reject',
      hostname: 'reject.example.com',
    });
    const rejected = await request(
      baseUrl,
      'POST',
      `/v1/discovery/candidates/${rejectCandidate.id}/reject`,
      { headers: engineer, body: { reason: 'out_of_scope' } },
    );
    assert.equal(rejected.status, 200);
    assert.equal(rejected.json.candidate.state, 'rejected');
    assert.equal(rejected.json.candidate.approval_status, 'rejected');
    assert.equal(rejected.json.candidate.rejection_reason, 'out_of_scope');
  });

  it('rejects forbidden raw content fields on candidate create', async () => {
    const engineer = demoHeaders('engineer');
    const before = getStore().discoveryCandidates?.length ?? 0;

    const res = await request(baseUrl, 'POST', '/v1/discovery/candidates', {
      headers: engineer,
      body: sampleCandidateBody({ raw_page_body: 'must-not-store' }),
    });
    assert.equal(res.status, 400);
    assert.equal(res.json.error, 'unsafe_discovery_candidate');
    assert.equal(getStore().discoveryCandidates?.length ?? 0, before);
  });

  it('enforces RBAC on write operations', async () => {
    const engineer = demoHeaders('engineer');
    const candidate = await createCandidate(baseUrl, engineer);
    const viewer = demoHeaders('viewer', 'ten_demo', 'usr_viewer');

    const list = await request(baseUrl, 'GET', '/v1/discovery/inbox', { headers: viewer });
    assert.equal(list.status, 200);

    const create = await request(baseUrl, 'POST', '/v1/discovery/entities', {
      headers: viewer,
      body: sampleEntityBody({ entity_id: 'ent_denied' }),
    });
    assert.equal(create.status, 403);
    assert.equal(create.json.permission, 'discovery:write');

    const approve = await request(
      baseUrl,
      'POST',
      `/v1/discovery/candidates/${candidate.id}/approve`,
      { headers: viewer, body: {} },
    );
    assert.equal(approve.status, 403);
    assert.equal(approve.json.permission, 'discovery:write');
  });
});