import assert from 'node:assert/strict';
import { createServer as createHttpServer } from 'node:http';
import { createServer as createNetServer } from 'node:net';
import { after, before, describe, it } from 'node:test';
import { loadRuntimeConfig } from '../../src/config.mjs';
import {
  MAX_PROBE_PROFILE_REQUESTS,
  MAX_PROBE_PROFILE_TIMEOUT_MS,
  WAF_SAFE_CHECK_IDS,
  buildProbeProfile,
  getCheckById,
} from '../../src/contracts/checks.mjs';
import { createServer } from '../../src/server.mjs';
import {
  authenticateProbeWorker,
  probeWorkerAuthHeaders,
  signProbeJob,
  verifyProbeJobSignature,
} from '../../src/services/probeCoordinator.mjs';
import { startTestRun } from '../../src/services/testRuns.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';
import {
  WORKER_VERSION,
  fetchHttpHeadWithSafeRedirects,
  parseWorkerConfig,
  pollAndProcessOnce,
  probeDns,
  probeHttpHead,
  probeTcpConnect,
  processJob,
  redactSecrets,
  sanitizeProbeMetadata,
  workerSigningPath,
} from '../../workers/probe-worker.mjs';

const WORKER_SECRET = 'probe-worker-secret-at-least-32-chars!!';
const PROBE_WORKER_ENV = {
  ASTRANULL_PROBE_WORKER_SECRET: WORKER_SECRET,
  ASTRANULL_PROBE_TENANT_ID: 'ten_demo',
};
const pollCtx = { tenantId: 'ten_demo', userId: 'u1', role: 'engineer' };

function completeActiveRuns() {
  for (const run of getStore().testRuns) {
    if (['running', 'collecting', 'planned'].includes(run.status)) {
      run.status = 'verdicted';
      run.completed_at = new Date().toISOString();
    }
  }
}

function baseJob(overrides = {}) {
  const target = {
    id: 'tgt_1',
    kind: 'fqdn',
    value: 'origin.test',
    expected_behavior: 'must_block_before_origin',
    ...(overrides.target ?? {}),
  };
  const checkId = overrides.check_id ?? 'path.protected_canary.safe';
  const check = getCheckById(checkId) ?? getCheckById('path.protected_canary.safe');
  const job = {
    id: 'pjob_test',
    tenant_id: 'ten_demo',
    test_run_id: 'run_test',
    check_id: check.check_id,
    vector_family: check.vector_family,
    nonce_hash: 'abc123hash',
    nonce: 'nonce-plaintext',
    probe_profile: check.probe_profile,
    constraints: {
      max_requests: check.probe_profile.max_requests,
      timeout_ms: check.probe_profile.timeout_ms,
    },
    target,
    job_signature: null,
    ...overrides,
  };
  if (overrides.probe_profile) job.probe_profile = overrides.probe_profile;
  if (overrides.constraints) job.constraints = { ...job.constraints, ...overrides.constraints };
  job.job_signature = signProbeJob(job, WORKER_SECRET);
  return job;
}

function runtimeSignedWorker() {
  return loadRuntimeConfig({
    NODE_ENV: 'test',
    ASTRANULL_NO_PERSIST: '1',
    ASTRANULL_PROBE_MODE: 'signed-worker',
    ASTRANULL_PROBE_WORKER_SECRET: WORKER_SECRET,
  });
}

describe('probe worker config', () => {
  it('requires a secret of at least 32 characters', () => {
    assert.throws(
      () => parseWorkerConfig([], { ASTRANULL_PROBE_WORKER_SECRET: 'short', ASTRANULL_PROBE_TENANT_ID: 'ten_demo' }),
      /≥32/,
    );
  });

  it('requires tenant id at boot', () => {
    assert.throws(
      () => parseWorkerConfig(['--secret', WORKER_SECRET], {}),
      /tenant id is required/i,
    );
  });

  it('bounds poll interval', () => {
    const cfg = parseWorkerConfig(['--poll-interval-ms', '50'], PROBE_WORKER_ENV);
    assert.equal(cfg.pollIntervalMs, 1000);
    const cfgMax = parseWorkerConfig(['--poll-interval-ms', '999999'], PROBE_WORKER_ENV);
    assert.equal(cfgMax.pollIntervalMs, 60_000);
  });

  it('redacts secrets in error text', () => {
    const msg = redactSecrets(`failed: ${WORKER_SECRET}`, WORKER_SECRET);
    assert.equal(msg.includes(WORKER_SECRET), false);
    assert.match(msg, /\[redacted\]/);
  });
});

describe('probe worker request signing', () => {
  it('signs root-mounted route paths without duplicating slashes from API URL', () => {
    assert.equal(workerSigningPath('http://localhost:3000', '/internal/probe/jobs'), '/internal/probe/jobs');
    assert.equal(
      workerSigningPath('http://localhost:3000', '/internal/probe/jobs/pjob_1/result'),
      '/internal/probe/jobs/pjob_1/result',
    );
  });

  it('authenticates signed poll headers with control plane verifier', () => {
    const runtime = runtimeSignedWorker();
    const bodyText = '';
    const headers = probeWorkerAuthHeaders(
      'worker-cli',
      { method: 'GET', path: '/internal/probe/jobs', bodyText, tenantId: 'ten_demo' },
      WORKER_SECRET,
    );
    const auth = authenticateProbeWorker(
      headers,
      'GET',
      '/internal/probe/jobs',
      bodyText,
      runtime,
    );
    assert.equal(auth.ok, true);
    assert.equal(auth.workerCtx.tenantId, 'ten_demo');
    assert.equal(auth.workerCtx.workerId, 'worker-cli');
  });

  it('includes and signs x-probe-tenant-id when tenantId is configured', () => {
    const runtime = runtimeSignedWorker();
    const bodyText = '';
    const headers = probeWorkerAuthHeaders(
      'worker-cli',
      { method: 'GET', path: '/internal/probe/jobs', bodyText, tenantId: 'ten_demo' },
      WORKER_SECRET,
    );
    assert.equal(headers['x-probe-tenant-id'], 'ten_demo');
    const auth = authenticateProbeWorker(
      headers,
      'GET',
      '/internal/probe/jobs',
      bodyText,
      runtime,
    );
    assert.equal(auth.ok, true);

    const tampered = { ...headers, 'x-probe-tenant-id': 'ten_evil' };
    const bad = authenticateProbeWorker(
      tampered,
      'GET',
      '/internal/probe/jobs',
      bodyText,
      runtime,
    );
    assert.equal(bad.ok, false);
  });

  it('parseWorkerConfig accepts tenant id from flag and env', () => {
    const fromFlag = parseWorkerConfig(
      ['--secret', WORKER_SECRET, '--tenant-id', 'ten_flag'],
      {},
    );
    assert.equal(fromFlag.tenantId, 'ten_flag');
    const fromEnv = parseWorkerConfig(['--secret', WORKER_SECRET], {
      ASTRANULL_PROBE_TENANT_ID: 'ten_env',
    });
    assert.equal(fromEnv.tenantId, 'ten_env');
  });
});

describe('WAF safe probe profiles', () => {
  it('buildProbeProfile preserves allowlisted WAF metadata keys', () => {
    const profile = buildProbeProfile({
      kind: 'http_head',
      max_requests: 2,
      scenario_family: 'marker',
      marker_type: 'header',
      expected_action: 'block',
      nonce_hash_only: true,
      collect: ['status_code', 'waf_product_hint', 'not_allowed'],
    });
    assert.equal(profile.scenario_family, 'marker');
    assert.equal(profile.marker_type, 'header');
    assert.equal(profile.expected_action, 'block');
    assert.equal(profile.nonce_hash_only, true);
    assert.deepEqual(profile.collect, ['status_code', 'waf_product_hint']);
  });

  it('WAF catalog profiles stay within signed worker caps', () => {
    for (const checkId of WAF_SAFE_CHECK_IDS) {
      const check = getCheckById(checkId);
      const profile = check.probe_profile;
      assert.ok(profile.max_requests <= MAX_PROBE_PROFILE_REQUESTS, checkId);
      assert.ok(profile.timeout_ms <= MAX_PROBE_PROFILE_TIMEOUT_MS, checkId);
      const job = baseJob({ check_id: checkId });
      assert.equal(verifyProbeJobSignature(job, WORKER_SECRET), true);
      job.probe_profile = { ...job.probe_profile, max_requests: MAX_PROBE_PROFILE_REQUESTS + 1 };
      assert.equal(verifyProbeJobSignature(job, WORKER_SECRET), false);
    }
  });
});

describe('probe job signature verification', () => {
  it('accepts a valid signed job', () => {
    const job = baseJob();
    assert.equal(verifyProbeJobSignature(job, WORKER_SECRET), true);
  });

  it('rejects tampered target', () => {
    const job = baseJob();
    job.target = { ...job.target, value: 'evil.example' };
    assert.equal(verifyProbeJobSignature(job, WORKER_SECRET), false);
  });

  it('rejects tampered constraints', () => {
    const job = baseJob();
    job.constraints = { ...job.constraints, max_requests: 99 };
    assert.equal(verifyProbeJobSignature(job, WORKER_SECRET), false);
  });

  it('rejects tampered probe_profile', () => {
    const job = baseJob();
    job.probe_profile = { ...job.probe_profile, max_requests: 99 };
    assert.equal(verifyProbeJobSignature(job, WORKER_SECRET), false);
  });

  it('accepts signed job after postgres-style JSON key reordering', () => {
    const job = baseJob();
    const signature = signProbeJob(job, WORKER_SECRET);
    const reordered = {
      ...job,
      job_signature: signature,
      probe_profile: {
        kind: job.probe_profile.kind,
        marker: job.probe_profile.marker,
        max_requests: job.probe_profile.max_requests,
        method: job.probe_profile.method,
        timeout_ms: job.probe_profile.timeout_ms,
      },
      constraints: {
        max_concurrent_runs_per_target_group: job.constraints.max_concurrent_runs_per_target_group,
        max_duration_seconds: job.constraints.max_duration_seconds,
        max_events: job.constraints.max_events,
        max_requests: job.constraints.max_requests,
        timeout_ms: job.constraints.timeout_ms,
      },
      target: {
        expected_behavior: job.target.expected_behavior,
        id: job.target.id,
        kind: job.target.kind,
        value: job.target.value,
      },
    };
    assert.equal(verifyProbeJobSignature(reordered, WORKER_SECRET), true);
  });

  it('processJob returns invalid_job_signature without executing probe', async () => {
    const job = baseJob();
    job.target = { ...job.target, value: 'tampered.example' };
    const config = parseWorkerConfig([], PROBE_WORKER_ENV);
    const body = await processJob(config, job);
    assert.equal(body.external_result, 'error');
    assert.equal(body.metadata.error_class, 'invalid_job_signature');
    assert.equal(body.safety_attestation.requests_sent, 0);
  });
});

describe('probe worker metadata sanitizer', () => {
  it('removes disallowed raw fields recursively and keeps scalar probe metadata', () => {
    const out = sanitizeProbeMetadata({
      probe_kind: 'http_head',
      status_code: 204,
      duration_ms: 12,
      headers: { 'set-cookie': 'secret' },
      body: 'response',
      nested: { raw_packet: 'deadbeef', error_class: 'timeout', log_line: 'full trace' },
      final_host: 'origin.test',
    });
    assert.equal(out.probe_kind, 'http_head');
    assert.equal(out.status_code, 204);
    assert.equal(out.final_host, 'origin.test');
    assert.equal(out.headers, undefined);
    assert.equal(out.body, undefined);
    assert.equal(out.nested.error_class, 'timeout');
    assert.equal(out.nested.raw_packet, undefined);
    assert.equal(out.nested.log_line, undefined);
  });

  it('processJob never posts disallowed metadata keys from probe outcomes', async () => {
    const server = createHttpServer((req, res) => {
      res.statusCode = 200;
      res.setHeader('x-leak', 'should-not-appear');
      res.end('body');
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address();
    const job = baseJob({
      target: { kind: 'url', value: `http://127.0.0.1:${port}/` },
    });
    const config = parseWorkerConfig([], PROBE_WORKER_ENV);
    const body = await processJob(config, job);
    assert.equal(body.metadata.headers, undefined);
    assert.equal(body.metadata.body, undefined);
    assert.equal(body.metadata.probe_kind, 'http_head');
    assert.equal(body.metadata.profile_kind, 'http_head');
    await new Promise((resolve) => server.close(resolve));
  });
});

describe('probe worker DNS helper', () => {
  it('clears the race timeout after a successful lookup', async () => {
    const job = baseJob({
      vector_family: 'dns',
      check_id: 'dns.authoritative_response.safe',
      target: { kind: 'fqdn', value: 'localhost' },
      constraints: { max_requests: 1, timeout_ms: 60_000 },
    });
    const outcome = await probeDns(job, {
      lookupFn: async () => ({ address: '127.0.0.1', family: 4 }),
    });
    assert.equal(outcome.external_result, 'connected');
    assert.equal(outcome.metadata.probe_kind, 'dns_resolve');
    assert.equal(outcome.metadata.profile_kind, 'dns_resolve');
  });
});

describe('probe worker HTTP HEAD execution', () => {
  it('sends one HEAD with nonce header and metadata-only attestation', async () => {
    const server = createHttpServer((req, res) => {
      assert.equal(req.method, 'HEAD');
      assert.equal(req.headers['x-astranull-nonce'], 'nonce-plaintext');
      assert.equal(req.headers['x-astranull-marker'], 'astranull-safe-marker');
      res.statusCode = 204;
      res.end();
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address();

    const job = baseJob({
      target: { kind: 'url', value: `http://127.0.0.1:${port}/health` },
    });
    const outcome = await probeHttpHead(job);
    assert.equal(outcome.requests_sent, 1);
    assert.equal(outcome.external_result, 'connected');
    assert.equal(outcome.metadata.status_code, 204);
    assert.equal(outcome.metadata.probe_kind, 'http_head');
    assert.equal(outcome.metadata.profile_kind, 'http_head');
    assert.equal('body' in outcome.metadata, false);
    assert.equal('headers' in outcome.metadata, false);

    await new Promise((resolve) => server.close(resolve));
  });

  it('does not follow same-host redirects beyond the signed request cap', async () => {
    let requests = 0;
    const server = createHttpServer((req, res) => {
      requests += 1;
      assert.equal(req.method, 'HEAD');
      assert.equal(req.url, '/start');
      assert.equal(req.headers['x-astranull-nonce'], 'nonce-plaintext');
      res.statusCode = 302;
      res.setHeader('location', '/next');
      res.end();
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address();

    try {
      const job = baseJob({
        constraints: { max_requests: 1, timeout_ms: 1000 },
        target: { kind: 'url', value: `http://127.0.0.1:${port}/start` },
      });
      const outcome = await probeHttpHead(job);
      assert.equal(requests, 1);
      assert.equal(outcome.requests_sent, 1);
      assert.equal(outcome.external_result, 'error');
      assert.equal(outcome.metadata.error_class, 'unsafe_redirect');
      assert.equal(outcome.metadata.redirect_reason, 'request_cap_exhausted');
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  it('does not leak nonce or marker headers to cross-host redirects', async () => {
    let originRequests = 0;
    let redirectedRequests = 0;
    const redirected = createHttpServer((req, res) => {
      redirectedRequests += 1;
      assert.equal(req.headers['x-astranull-nonce'], undefined);
      assert.equal(req.headers['x-astranull-marker'], undefined);
      res.statusCode = 204;
      res.end();
    });
    await new Promise((resolve) => redirected.listen(0, '127.0.0.1', resolve));
    const redirectedPort = redirected.address().port;
    const origin = createHttpServer((req, res) => {
      originRequests += 1;
      assert.equal(req.headers['x-astranull-nonce'], 'nonce-plaintext');
      assert.equal(req.headers['x-astranull-marker'], 'astranull-safe-marker');
      res.statusCode = 302;
      res.setHeader('location', `http://127.0.0.1:${redirectedPort}/next`);
      res.end();
    });
    await new Promise((resolve) => origin.listen(0, '127.0.0.1', resolve));
    const originPort = origin.address().port;

    try {
      const job = baseJob({
        target: { kind: 'url', value: `http://127.0.0.1:${originPort}/start` },
      });
      const outcome = await probeHttpHead(job);
      assert.equal(originRequests, 1);
      assert.equal(redirectedRequests, 0);
      assert.equal(outcome.requests_sent, 1);
      assert.equal(outcome.external_result, 'error');
      assert.equal(outcome.metadata.error_class, 'unsafe_redirect');
      assert.equal(outcome.metadata.redirect_reason, 'host_mismatch');
    } finally {
      await new Promise((resolve) => origin.close(resolve));
      await new Promise((resolve) => redirected.close(resolve));
    }
  });

  it('maps abort to timeout without raw response fields', async () => {
    const job = baseJob({
      constraints: { max_requests: 1, timeout_ms: 50 },
      target: { kind: 'url', value: 'http://127.0.0.1:1/unreachable' },
    });
    const outcome = await probeHttpHead(job);
    assert.ok(['timeout', 'blocked', 'error'].includes(outcome.external_result));
    assert.equal(outcome.requests_sent, 1);
    assert.equal(outcome.metadata.raw_packet, undefined);
    assert.equal(outcome.metadata.headers, undefined);
  });
});

describe('probe worker TCP helper', () => {
  it('connects when target value is host-only and port is set separately', async () => {
    const server = createNetServer((socket) => socket.end());
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address();

    const job = baseJob({
      vector_family: 'l3_l4',
      check_id: 'l3.forbidden_tcp_port.safe',
      target: { kind: 'fqdn', value: '127.0.0.1', port },
    });
    const outcome = await probeTcpConnect(job);
    assert.equal(outcome.requests_sent, 1);
    assert.equal(outcome.external_result, 'connected');
    assert.equal(outcome.metadata.target_port, port);

    await new Promise((resolve) => server.close(resolve));
  });

  it('connects to a local TCP listener once', async () => {
    const server = createNetServer((socket) => socket.end());
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address();

    const job = baseJob({
      vector_family: 'l3_l4',
      check_id: 'l3.forbidden_tcp_port.safe',
      target: { kind: 'fqdn', value: `127.0.0.1:${port}` },
    });
    const outcome = await probeTcpConnect(job);
    assert.equal(outcome.requests_sent, 1);
    assert.equal(outcome.external_result, 'connected');
    assert.equal(outcome.metadata.probe_kind, 'tcp_connect');
    assert.equal(outcome.metadata.profile_kind, 'tcp_connect');

    await new Promise((resolve) => server.close(resolve));
  });
});

describe('probe worker poll integration', () => {
  let probeTargetServer;
  let apiServer;
  let baseUrl;

  before(async () => {
    freshStore();
    probeTargetServer = createHttpServer((req, res) => {
      if (req.method === 'HEAD') {
        res.statusCode = 204;
        res.end();
        return;
      }
      res.statusCode = 405;
      res.end();
    });
    await new Promise((resolve) => probeTargetServer.listen(0, '127.0.0.1', resolve));
    const probePort = probeTargetServer.address().port;
    const tgt = getStore().targets.find((t) => t.id === 'tgt_1');
    tgt.kind = 'url';
    tgt.value = `http://127.0.0.1:${probePort}/health`;

    apiServer = createServer({
      env: {
        NODE_ENV: 'test',
        ASTRANULL_NO_PERSIST: '1',
        ASTRANULL_PROBE_MODE: 'signed-worker',
        ASTRANULL_PROBE_WORKER_SECRET: WORKER_SECRET,
        ASTRANULL_AUTH_MODE: 'dev-headers',
      },
    });
    apiServer.listen(0);
    const { port } = apiServer.address();
    baseUrl = `http://127.0.0.1:${port}`;
  });

  after(async () => {
    await Promise.all([
      new Promise((resolve) => probeTargetServer.close(resolve)),
      new Promise((resolve) => apiServer.close(resolve)),
    ]);
  });

  it('pollAndProcessOnce leases a signed job, probes locally, and completes ingestion', async () => {
    completeActiveRuns();
    const started = startTestRun(
      pollCtx,
      {
        check_id: 'path.protected_canary.safe',
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
      },
      runtimeSignedWorker(),
    );
    assert.ok(started.probe_job?.job_signature);

    const config = parseWorkerConfig(
      ['--worker-id', 'worker-integration', '--tenant-id', 'ten_demo'],
      {
        ASTRANULL_PROBE_WORKER_SECRET: WORKER_SECRET,
        ASTRANULL_API_URL: baseUrl,
      },
    );
    const results = await pollAndProcessOnce(config);
    assert.equal(results.length, 1);
    assert.equal(results[0].job_id, started.probe_job.id);
    assert.equal(results[0].external_result, 'connected');

    const job = getStore().probeJobs.find((j) => j.id === started.probe_job.id);
    assert.equal(job.status, 'completed');
    assert.equal(job.leased_by, 'worker-integration');

    const run = getStore().testRuns.find((r) => r.id === started.run.id);
    assert.equal(run.probe_external_result, 'connected');
    assert.equal(run.awaiting_external_probe, false);
    assert.equal(run.status, 'collecting');

    const probeEvent = getStore().events.find(
      (e) => e.test_run_id === run.id && e.signal_type === 'probe_result',
    );
    assert.ok(probeEvent);
    assert.equal(probeEvent.metadata.external_result, 'connected');
    assert.equal(probeEvent.metadata.safety_attestation.requests_sent, 1);
  });
});

describe('executeProbeForJob routing', () => {
  const CAPABILITY_ROUTING_CASES = [
    { kind: 'origin_leak_scan', check_id: 'origin.leak_scan.safe', vector_family: 'origin' },
    { kind: 'host_sni_bypass', check_id: 'origin.direct_reachability.safe', vector_family: 'origin', target: { kind: 'fqdn', value: 'edge.test', metadata: { direct_origin_ip: '198.51.100.7' } }, probe_profile: { kind: 'host_sni_bypass', protected_host: 'edge.test', max_requests: 1, timeout_ms: 500 } },
    { kind: 'host_sni_bypass', check_id: 'origin.direct_bypass.safe', vector_family: 'origin', target: { kind: 'fqdn', value: 'edge.test', metadata: { direct_origin_ip: '198.51.100.7' } }, probe_profile: { kind: 'host_sni_bypass', protected_host: 'edge.test', max_requests: 1, timeout_ms: 500 } },
    { kind: 'host_sni_bypass', check_id: 'origin.host_sni_bypass.safe', vector_family: 'origin', target: { kind: 'url', value: 'http://198.51.100.7/' }, probe_profile: { kind: 'host_sni_bypass', protected_host: 'edge.test', direct_ip: '198.51.100.7', max_requests: 1, timeout_ms: 500 } },
    { kind: 'host_sni_bypass', check_id: 'waf.origin_bypass.safe', vector_family: 'waf', target: { kind: 'fqdn', value: 'edge.test', metadata: { direct_origin_ip: '198.51.100.7' } }, probe_profile: { kind: 'host_sni_bypass', protected_host: 'edge.test', max_requests: 1, timeout_ms: 500 } },
    { kind: 'port_scan_bounded', check_id: 'l3.firewall_exposure_scan.safe', vector_family: 'l3_l4' },
    { kind: 'rate_limit_sequence', check_id: 'l7.low_rate_rate_limit.safe', vector_family: 'l7' },
    { kind: 'waf_enforcement_probe', check_id: 'waf.enforcement.safe', vector_family: 'waf' },
    { kind: 'outside_in_waf_scan', check_id: 'waf.fingerprint.safe', vector_family: 'waf' },
    { kind: 'dnssec_posture', check_id: 'dns.dnssec_expensive_query.safe', vector_family: 'dns' },
    { kind: 'dns_open_recursion', check_id: 'dns.open_recursion_behavior.safe', vector_family: 'dns' },
    { kind: 'dns_failover_posture', check_id: 'dns.secondary_failover.safe', vector_family: 'dns' },
    { kind: 'dns_axfr_leak', check_id: 'dns.zone_transfer_exposure.safe', vector_family: 'dns' },
    { kind: 'tls_audit', check_id: 'tls.full_audit.safe', vector_family: 'tls' },
    { kind: 'cache_abuse_probe', check_id: 'l7.cache_busting.safe', vector_family: 'l7' },
    { kind: 'api_surface_scan', check_id: 'l7.api_surface_scan.safe', vector_family: 'l7' },
    { kind: 'cors_posture_probe', check_id: 'l7.cors_posture.safe', vector_family: 'l7' },
    { kind: 'bot_challenge_probe', check_id: 'l7.bot_challenge_marker.safe', vector_family: 'l7' },
    { kind: 'graphql_posture_probe', check_id: 'l7.graphql_complexity.safe', vector_family: 'l7' },
  ];

  for (const routeCase of CAPABILITY_ROUTING_CASES) {
    it(`routes ${routeCase.kind} via executeProbeForJob`, async () => {
      const { executeProbeForJob } = await import('../../workers/probe-worker.mjs');
      const check = getCheckById(routeCase.check_id);
      const job = baseJob({
        check_id: routeCase.check_id,
        vector_family: routeCase.vector_family,
        probe_profile: routeCase.probe_profile ?? check.probe_profile,
        target: routeCase.target ?? { kind: 'fqdn', value: 'nonexistent.invalid' },
        constraints: {
          timeout_ms: 500,
          max_requests: check.probe_profile.max_requests,
        },
      });
      const outcome = await executeProbeForJob(job, {
        signedJobVerified: true,
        fetchFn: async () => ({ status: 403, headers: { get: () => null } }),
        resolve4Fn: async () => [],
        resolve6Fn: async () => [],
        resolveNsFn: async () => ['ns1.invalid'],
        connectFn: () => {
          const handlers = {};
          const socket = {
            on: (event, fn) => { handlers[event] = fn; },
            once: (event, fn) => { handlers[event] = fn; },
            destroy: () => {},
            write: () => {},
            end: () => {},
            setTimeout: () => {},
          };
          queueMicrotask(() => {
            handlers.error?.(Object.assign(new Error('refused'), { code: 'ECONNREFUSED' }));
          });
          return socket;
        },
        resolveFn: async () => [],
        resolve4ExternalFn: async () => { throw new Error('refused'); },
      });
      assert.equal(outcome.metadata.probe_kind, routeCase.kind);
      assert.notEqual(outcome.metadata.error_class, 'unsupported_check');
      assert.notEqual(outcome.metadata.error_class, 'live_probe_requires_signed_worker');
    });
  }

  it('routes Host/SNI bypass with declared URL port and path preserved', async () => {
    const { executeProbeForJob } = await import('../../workers/probe-worker.mjs');
    const check = getCheckById('origin.direct_bypass.safe');
    let captured = null;
    const job = baseJob({
      check_id: check.check_id,
      vector_family: check.vector_family,
      probe_profile: check.probe_profile,
      target: {
        kind: 'url',
        value: 'https://edge.test:8443/health?probe=1',
        metadata: { direct_origin_ip: '198.51.100.7' },
      },
      constraints: { timeout_ms: 500, max_requests: 1 },
    });
    const outcome = await executeProbeForJob(job, {
      signedJobVerified: true,
      fetchFn: async (url, init) => {
        captured = { url, init };
        return { status: 200, headers: { get: () => null } };
      },
    });
    assert.equal(captured.url, 'http://198.51.100.7:8443/health?probe=1');
    assert.equal(captured.init.headers.Host, 'edge.test:8443');
    assert.equal(outcome.metadata.probe_kind, 'host_sni_bypass');
    assert.equal(outcome.external_result, 'connected');
  });

  it('routes udp_probe profile kind to bounded UDP datagram probe', async () => {
    const { executeProbeForJob } = await import('../../workers/probe-worker.mjs');
    const job = baseJob({
      check_id: 'l3.forbidden_udp_port.safe',
      probe_profile: { kind: 'udp_probe', max_requests: 1, timeout_ms: 1000 },
      target: { kind: 'fqdn', value: 'origin.test', port: 9999 },
    });
    const outcome = await executeProbeForJob(job);
    assert.ok(['connected', 'blocked', 'timeout', 'error'].includes(outcome.external_result));
    assert.equal(outcome.metadata.probe_kind, 'udp_probe');
  });

  it('executeProbeForJob handles ownership_challenge', async () => {
    const { executeProbeForJob } = await import('../../workers/probe-worker.mjs');
    const job = baseJob({
      probe_profile: {
        kind: 'ownership_challenge',
        marker: 'astranull-ownership-challenge',
        max_requests: 1,
        timeout_ms: 2000,
      },
      target: { kind: 'fqdn', value: 'example.test' },
      vector_family: 'ownership',
      nonce_hash: 'sha256:abc',
    });
    const outcome = await executeProbeForJob(job);
    assert.equal(outcome.metadata.probe_kind, 'ownership_challenge');
    assert.notEqual(outcome.metadata.error_class, 'unsupported_check');
    assert.ok(['connected', 'blocked', 'timeout', 'error'].includes(outcome.external_result));
  });

  it('routes alert_webhook_ping when webhook URL is missing', async () => {
    const { executeProbeForJob } = await import('../../workers/probe-worker.mjs');
    const job = baseJob({
      check_id: 'ops.alert_workflow_marker.safe',
      vector_family: 'operations',
      probe_profile: { kind: 'alert_webhook_ping', max_requests: 1, timeout_ms: 1000 },
      target: { kind: 'canary', value: 'canary' },
    });
    const outcome = await executeProbeForJob(job);
    assert.equal(outcome.external_result, 'error');
    assert.equal(outcome.metadata.error_class, 'missing_webhook_url');
  });

  it('routes tls_session profile kind to bounded TLS probe', async () => {
    const { executeProbeForJob } = await import('../../workers/probe-worker.mjs');
    const job = baseJob({
      check_id: 'tls.idle_connection_timeout.safe',
      vector_family: 'tls',
      probe_profile: { kind: 'tls_session', max_requests: 1, timeout_ms: 50 },
      target: { kind: 'fqdn', value: '127.0.0.1:9' },
      constraints: { timeout_ms: 50, max_requests: 1 },
    });
    const outcome = await executeProbeForJob(job);
    assert.equal(outcome.metadata.probe_kind, 'tls_session');
    assert.ok(['connected', 'blocked', 'timeout', 'error'].includes(outcome.external_result));
  });

  it('routes http2_settings profile kind to bounded HTTP/2 SETTINGS probe', async () => {
    const { executeProbeForJob } = await import('../../workers/probe-worker.mjs');
    const job = baseJob({
      check_id: 'protocol.http2_stream_concurrency.safe',
      vector_family: 'protocol',
      probe_profile: { kind: 'http2_settings', max_requests: 1, timeout_ms: 50 },
      target: { kind: 'fqdn', value: '127.0.0.1:9' },
      constraints: { timeout_ms: 50, max_requests: 1 },
    });
    const outcome = await executeProbeForJob(job);
    assert.equal(outcome.metadata.probe_kind, 'http2_settings');
    assert.ok(['connected', 'blocked', 'timeout', 'error'].includes(outcome.external_result));
  });

  it('uses worker version constant in processJob attestation', async () => {
    const server = createHttpServer((req, res) => {
      res.statusCode = 200;
      res.end();
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address();
    const job = baseJob({
      target: { kind: 'url', value: `http://127.0.0.1:${port}/` },
    });
    const config = parseWorkerConfig([], PROBE_WORKER_ENV);
    const body = await processJob(config, job);
    assert.equal(body.safety_attestation.worker_version, WORKER_VERSION);
    assert.ok(body.safety_attestation.requests_sent <= job.constraints.max_requests);
    assert.ok(body.safety_attestation.duration_ms <= job.constraints.timeout_ms);
    await new Promise((resolve) => server.close(resolve));
  });
});
