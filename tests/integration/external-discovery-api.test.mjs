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
    const admin = demoHeaders('admin');
    const candidate = await createCandidate(baseUrl, engineer);

    const approved = await request(
      baseUrl,
      'POST',
      `/v1/discovery/candidates/${candidate.id}/approve`,
      { headers: admin, body: {} },
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
      { headers: admin, body: { reason: 'out_of_scope' } },
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

  it('ingests passive discovery source records into inbox pending approval', async () => {
    const engineer = demoHeaders('engineer');
    const beforeTargets = getStore().targets.length;

    const ingest = await request(baseUrl, 'POST', '/v1/discovery/sources/ingest', {
      headers: engineer,
      body: {
        source: 'passive_dns',
        records: [
          {
            hostname: 'passive.example.com',
            source_type: 'passive_dns',
            confidence: 0.43,
            observed_at: '2026-07-03T10:00:00.000Z',
          },
          {
            hostname: 'ct.example.com',
            source_type: 'passive_dns',
            confidence: 0.5,
            observed_at: '2026-07-03T11:00:00.000Z',
          },
        ],
      },
    });
    assert.equal(ingest.status, 200);
    assert.equal(ingest.json.source, 'passive_dns');
    assert.equal(ingest.json.created, 2);
    assert.equal(ingest.json.updated, 0);
    assert.equal(ingest.json.candidates.length, 2);
    assert.equal(ingest.json.candidates[0].approval_status, 'pending');
    assert.equal(ingest.json.candidates[0].state, 'candidate');

    const ctIngest = await request(baseUrl, 'POST', '/v1/discovery/sources/ingest', {
      headers: engineer,
      body: {
        source: 'certificate_transparency',
        records: [
          {
            hostname: 'tls.example.com',
            source_type: 'certificate_transparency',
            confidence: 0.68,
            observed_at: '2026-07-03T12:00:00.000Z',
          },
        ],
      },
    });
    assert.equal(ctIngest.status, 200);
    assert.equal(ctIngest.json.candidates[0].source_type, 'ct_log');

    const inbox = await request(baseUrl, 'GET', '/v1/discovery/inbox', { headers: engineer });
    assert.equal(inbox.status, 200);
    assert.equal(inbox.json.count, 3);

    const auditEntry = getStore().auditLog.findLast((entry) => entry.action === 'discovery.source_ingested');
    assert.ok(auditEntry);
    assert.equal(auditEntry.metadata.source, 'certificate_transparency');
    assert.equal(getStore().targets.length, beforeTargets);
  });

  it('rejects unsafe passive source payloads at ingest', async () => {
    const engineer = demoHeaders('engineer');
    const before = getStore().discoveryCandidates?.length ?? 0;

    const res = await request(baseUrl, 'POST', '/v1/discovery/sources/ingest', {
      headers: engineer,
      body: {
        source: 'certificate_transparency',
        records: [
          {
            hostname: 'unsafe.example.com',
            source_type: 'certificate_transparency',
            confidence: 0.5,
            observed_at: '2026-07-03T12:00:00.000Z',
            raw_log: 'must-not-store',
          },
        ],
      },
    });
    assert.equal(res.status, 400);
    assert.equal(res.json.error, 'unsafe_discovery_source_record');
    assert.equal(getStore().discoveryCandidates?.length ?? 0, before);
  });

  it('imports approved candidate into target group with linked WAF asset', async () => {
    const engineer = demoHeaders('engineer');
    const admin = demoHeaders('admin');
    const candidate = await createCandidate(baseUrl, engineer, {
      candidate_id: 'cand_import',
      hostname: 'import.example.com',
    });
    const approved = await request(
      baseUrl,
      'POST',
      `/v1/discovery/candidates/${candidate.id}/approve`,
      { headers: admin, body: {} },
    );
    assert.equal(approved.status, 200);
    assert.equal(approved.json.candidate.state, 'approved_target');

    const beforeTargets = getStore().targets.length;
    const beforeWafAssets = getStore().wafAssets?.length ?? 0;

    const imported = await request(
      baseUrl,
      'POST',
      `/v1/discovery/candidates/${candidate.id}/import`,
      {
        headers: admin,
        body: {
          target_group_id: 'tg_1',
          environment_id: 'env_demo',
          create_waf_asset: true,
        },
      },
    );
    assert.equal(imported.status, 200);
    assert.equal(imported.json.target.kind, 'fqdn');
    assert.equal(imported.json.target.value, 'import.example.com');
    assert.equal(imported.json.target.target_group_id, 'tg_1');
    assert.ok(imported.json.waf_asset);
    assert.equal(imported.json.waf_asset.target_id, imported.json.target.id);
    assert.equal(imported.json.candidate.approved_target_id, imported.json.target.id);
    assert.equal(imported.json.candidate.approval_status, 'approved');

    assert.equal(getStore().targets.length, beforeTargets + 1);
    assert.equal(getStore().wafAssets.length, beforeWafAssets + 1);

    const auditEntry = getStore().auditLog.findLast(
      (entry) => entry.action === 'discovery.candidate_imported',
    );
    assert.ok(auditEntry);
    assert.equal(auditEntry.metadata.target_group_id, 'tg_1');
    assert.equal(auditEntry.metadata.hostname, 'import.example.com');

    const duplicate = await request(
      baseUrl,
      'POST',
      `/v1/discovery/candidates/${candidate.id}/import`,
      { headers: admin, body: { target_group_id: 'tg_1' } },
    );
    assert.equal(duplicate.status, 409);
    assert.equal(duplicate.json.error, 'discovery_candidate_already_imported');
  });

  it('rejects import for unapproved candidates', async () => {
    const engineer = demoHeaders('engineer');
    const admin = demoHeaders('admin');
    const candidate = await createCandidate(baseUrl, engineer, {
      candidate_id: 'cand_import_denied',
      hostname: 'pending.example.com',
    });

    const imported = await request(
      baseUrl,
      'POST',
      `/v1/discovery/candidates/${candidate.id}/import`,
      { headers: admin, body: { target_group_id: 'tg_1' } },
    );
    assert.equal(imported.status, 403);
    assert.equal(imported.json.error, 'discovery_candidate_not_approved');
  });

  it('returns metadata-only discovery report summary scoped to tenant', async () => {
    const engineer = demoHeaders('engineer');
    const admin = demoHeaders('admin');
    await createCandidate(baseUrl, engineer, {
      candidate_id: 'cand_report_dns',
      hostname: 'report-dns.example.com',
      source_type: 'dns',
      confidence: 0.82,
      approval_status: 'not_requested',
    });
    await createCandidate(baseUrl, engineer, {
      candidate_id: 'cand_report_ct',
      hostname: 'report-ct.example.com',
      source_type: 'ct_log',
      confidence: 0.67,
      approval_status: 'pending',
    });
    await createCandidate(baseUrl, engineer, {
      candidate_id: 'cand_report_passive',
      hostname: 'report-passive.example.com',
      source_type: 'passive_dns',
      confidence: 0.35,
      approval_status: 'pending',
    });
    const approved = await createCandidate(baseUrl, engineer, {
      candidate_id: 'cand_report_approved',
      hostname: 'report-approved.example.com',
      source_type: 'connector',
      confidence: 0.91,
      approval_status: 'not_requested',
      state: 'candidate',
    });
    await request(baseUrl, 'POST', `/v1/discovery/candidates/${approved.id}/approve`, {
      headers: admin,
      body: {},
    });
    await createCandidate(baseUrl, engineer, {
      candidate_id: 'cand_report_rejected',
      hostname: 'report-rejected.example.com',
      source_type: 'registry',
      confidence: 0.18,
      approval_status: 'not_requested',
    });
    const rejectCandidate = await createCandidate(baseUrl, engineer, {
      candidate_id: 'cand_report_reject_flow',
      hostname: 'report-reject-flow.example.com',
      source_type: 'page_link',
      confidence: 0.55,
      approval_status: 'not_requested',
    });
    await request(baseUrl, 'POST', `/v1/discovery/candidates/${rejectCandidate.id}/reject`, {
      headers: admin,
      body: { reason: 'out_of_scope' },
    });

    seedOtherTenant();
    await createCandidate(baseUrl, demoHeaders('engineer', 'ten_other', 'usr_other'), {
      candidate_id: 'cand_other_report',
      hostname: 'other-report.example.com',
      source_type: 'dns',
      confidence: 0.99,
      approval_status: 'approved',
    });

    const res = await request(baseUrl, 'GET', '/v1/discovery/reports/summary', {
      headers: engineer,
    });
    assert.equal(res.status, 200);
    assert.ok(res.json.summary);
    assert.equal(res.json.summary.total_candidates, 6);
    assert.equal(res.json.summary.candidate_sources.dns, 1);
    assert.equal(res.json.summary.candidate_sources.ct_log, 1);
    assert.equal(res.json.summary.candidate_sources.passive_dns, 1);
    assert.equal(res.json.summary.candidate_sources.connector, 1);
    assert.equal(res.json.summary.candidate_sources.registry, 1);
    assert.equal(res.json.summary.candidate_sources.page_link, 1);
    assert.equal(res.json.summary.approval_states.pending, 2);
    assert.equal(res.json.summary.approval_states.approved, 1);
    assert.equal(res.json.summary.approval_states.rejected, 1);
    assert.equal(res.json.summary.confidence_histogram['0.0-0.2'], 1);
    assert.equal(res.json.summary.confidence_histogram['0.2-0.4'], 1);
    assert.equal(res.json.summary.confidence_histogram['0.4-0.6'], 1);
    assert.equal(res.json.summary.confidence_histogram['0.6-0.8'], 1);
    assert.equal(res.json.summary.confidence_histogram['0.8-1.0'], 2);
    assert.ok(res.json.summary.generated_at);

    const payload = JSON.stringify(res.json);
    assert.ok(!payload.includes('report-dns.example.com'));
    assert.ok(!payload.includes('dns_ref_1'));
    assert.ok(!payload.includes('raw_log'));
    assert.ok(!payload.includes('dns_zone_file'));
    assert.ok(!payload.includes('dns_record_type'));
  });

  it('allows discovery:read viewers to fetch discovery report summary', async () => {
    const engineer = demoHeaders('engineer');
    await createCandidate(baseUrl, engineer, {
      candidate_id: 'cand_viewer_report',
      hostname: 'viewer-report.example.com',
      source_type: 'dns',
      confidence: 0.5,
    });
    const viewer = demoHeaders('viewer', 'ten_demo', 'usr_viewer');
    const res = await request(baseUrl, 'GET', '/v1/discovery/reports/summary', { headers: viewer });
    assert.equal(res.status, 200);
    assert.equal(res.json.summary.total_candidates, 1);
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
    assert.equal(approve.json.permission, 'discovery:approve');

    const reject = await request(
      baseUrl,
      'POST',
      `/v1/discovery/candidates/${candidate.id}/reject`,
      { headers: engineer, body: { reason: 'needs_owner_approval' } },
    );
    assert.equal(reject.status, 403);
    assert.equal(reject.json.permission, 'discovery:approve');

    const importAttempt = await request(
      baseUrl,
      'POST',
      `/v1/discovery/candidates/${candidate.id}/import`,
      { headers: viewer, body: { target_group_id: 'tg_1' } },
    );
    assert.equal(importAttempt.status, 403);
    assert.equal(importAttempt.json.permission, 'discovery:approve');
  });
});
