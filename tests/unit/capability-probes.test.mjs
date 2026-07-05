import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  probeApiSurfaceScan,
  probeAxfrLeak,
  probeBotChallenge,
  probeCacheAbuse,
  probeCorsPosture,
  probeDnsFailoverPosture,
  probeDnssecPosture,
  probeGraphqlPosture,
  probeHostSniBypass,
  probeOpenRecursion,
  probeOriginLeakScan,
  probePortScanBounded,
  probeRateLimitSequence,
  probeTlsAudit,
  probeWafEnforcement,
  executeCapabilityProbe,
} from '../../src/lib/capabilityProbes.mjs';
import { getCheckById } from '../../src/contracts/checks.mjs';

function job(overrides = {}) {
  return {
    constraints: { timeout_ms: 1000, max_requests: 14 },
    probe_profile: { kind: 'origin_leak_scan' },
    target: { kind: 'fqdn', value: 'shop.example.test' },
    ...overrides,
  };
}

describe('capability probes P0/P1', () => {
  it('origin leak scan reports leak signals from subdomain divergence', async () => {
    const outcome = await probeOriginLeakScan(job(), {
      resolve4Fn: async (host) => {
        if (host === 'shop.example.test') return ['203.0.113.10'];
        if (host === 'origin.shop.example.test') return ['198.51.100.5'];
        return [];
      },
      resolve6Fn: async () => ['2001:db8::1'],
      fetchFn: async () => ({ status: 200, headers: { get: () => null } }),
    });
    assert.equal(outcome.external_result, 'connected');
    assert.ok(outcome.metadata.leak_signals.includes('ipv6_present'));
    assert.ok(outcome.metadata.leak_signals.some((s) => s.startsWith('subdomain_origin_divergence:')));
  });

  it('host/SNI bypass detects direct IP reachability via injectable fetchFn', async () => {
    const outcome = await probeHostSniBypass(
      job({
        probe_profile: {
          kind: 'host_sni_bypass',
          protected_host: 'edge.example.test',
          direct_ip: '198.51.100.7',
        },
      }),
      {
        fetchFn: async () => ({ status: 200, headers: { get: () => null } }),
      },
    );
    assert.equal(outcome.external_result, 'connected');
    assert.equal(outcome.metadata.bypass_signal, true);
  });

  it('host/SNI bypass uses HTTPS with TLS SNI when no fetchFn is injected', async () => {
    let captured = null;
    const outcome = await probeHostSniBypass(
      job({
        probe_profile: {
          kind: 'host_sni_bypass',
          protected_host: 'edge.example.test',
          direct_ip: '198.51.100.7',
        },
      }),
      {
        httpsRequestFn: (opts, cb) => {
          captured = opts;
          return {
            on() { return this; },
            end() {
              cb({ statusCode: 200, headers: {}, resume() {} });
            },
          };
        },
      },
    );
    assert.equal(captured.host, '198.51.100.7');
    assert.equal(captured.servername, 'edge.example.test');
    assert.equal(outcome.metadata.bypass_signal, true);
  });

  it('port scan bounded reports risky admin ports', async () => {
    const outcome = await probePortScanBounded(
      job({
        target: { value: '10.0.0.5' },
        probe_profile: { kind: 'port_scan_bounded', ports: [22, 443, 9999] },
      }),
      {
        connectFn: ({ port }, cb) => {
          const socket = {
            once(event, handler) {
              if (event === 'connect') setImmediate(() => handler());
            },
            end() {},
            destroy() {},
          };
          if (port === 22) return socket;
          const errSocket = {
            once(event, handler) {
              if (event === 'error') setImmediate(() => handler({ code: 'ECONNREFUSED' }));
            },
            destroy() {},
          };
          return errSocket;
        },
      },
    );
    assert.equal(outcome.external_result, 'connected');
    assert.deepEqual(outcome.metadata.open_ports, [22]);
    assert.deepEqual(outcome.metadata.risky_admin_ports_open, [22]);
  });

  it('rate limit sequence detects throttling', async () => {
    let n = 0;
    const outcome = await probeRateLimitSequence(
      job({
        target: { value: 'https://login.example.test/signin' },
        probe_profile: { kind: 'rate_limit_sequence', max_requests: 3 },
      }),
      {
        fetchFn: async () => {
          n += 1;
          return { status: n >= 2 ? 429 : 200, headers: { get: () => null } };
        },
      },
    );
    assert.equal(outcome.metadata.throttled, true);
    assert.equal(outcome.external_result, 'blocked');
  });

  it('waf enforcement flags monitor-only leak', async () => {
    const outcome = await probeWafEnforcement(
      job({
        target: { value: 'https://app.example.test' },
        probe_profile: { kind: 'waf_enforcement_probe', marker: 'test-marker' },
      }),
      {
        fetchFn: async () => ({ status: 200, headers: { get: () => null } }),
      },
    );
    assert.equal(outcome.metadata.monitor_only_leak, true);
    assert.equal(outcome.external_result, 'connected');
  });

  it('dnssec posture reports missing DNSSEC', async () => {
    const outcome = await probeDnssecPosture(job({
      probe_profile: { kind: 'dnssec_posture' },
    }), {
      resolveFn: async () => {
        throw new Error('ENODATA');
      },
    });
    assert.equal(outcome.metadata.dnssec_missing, true);
    assert.equal(outcome.external_result, 'connected');
  });

  it('axfr leak probe treats REFUSED rcode as blocked', async () => {
    const refusedHeader = Buffer.alloc(12);
    refusedHeader.writeUInt16BE(0, 0);
    refusedHeader[3] = 0x05;
    refusedHeader.writeUInt16BE(0, 6);

    const outcome = await probeAxfrLeak(job({
      probe_profile: { kind: 'dns_axfr_leak', zone: 'example.test' },
    }), {
      resolveNsFn: async () => ['ns1.example.test'],
      connectFn: () => ({
        once(event, handler) {
          if (event === 'connect') setImmediate(() => handler());
          if (event === 'data') setImmediate(() => handler(refusedHeader));
        },
        write() {},
        destroy() {},
      }),
    });
    assert.equal(outcome.external_result, 'blocked');
    assert.equal(outcome.metadata.axfr_refused, true);
    assert.notEqual(outcome.metadata.axfr_leak, true);
  });

  it('tls audit reports weak protocol issues', async () => {
    const outcome = await probeTlsAudit(job({
      probe_profile: { kind: 'tls_audit' },
    }), {
      connectFn: () => ({
        once(event, handler) {
          if (event === 'secureConnect') handler();
        },
        getProtocol: () => 'TLSv1.1',
        getCipher: () => ({ name: 'RC4-SHA' }),
        authorized: false,
        getPeerCertificate: () => ({ valid_to: 'Jan 1 2020', issuer: { O: 'Test CA' }, subject: { CN: 'shop.example.test' } }),
        end() {},
      }),
    });
    assert.ok(outcome.metadata.tls_issues.includes('weak_tls_protocol'));
    assert.equal(outcome.external_result, 'connected');
  });

  it('cache abuse probe detects cache key weakness including bust variant', async () => {
    const outcome = await probeCacheAbuse(job({
      target: { value: 'https://cdn.example.test/asset' },
      probe_profile: { kind: 'cache_abuse_probe' },
    }), {
      fetchFn: async () => ({
        status: 200,
        headers: {
          get: (name) => {
            if (name === 'cache-control') return 'public, max-age=3600';
            if (name === 'x-cache') return 'HIT';
            return null;
          },
        },
      }),
    });
    assert.equal(outcome.metadata.cache_key_weakness, true);
    assert.equal(outcome.metadata.observations[1].x_cache, 'HIT');
  });

  it('open recursion probe detects open resolver', async () => {
    const outcome = await probeOpenRecursion(job({
      probe_profile: { kind: 'dns_open_recursion', resolver_host: '8.8.8.8' },
    }), {
      resolve4ExternalFn: async () => ['93.184.216.34'],
    });
    assert.equal(outcome.metadata.open_recursion_detected, true);
    assert.equal(outcome.external_result, 'connected');
  });

  it('dns failover posture flags weak secondary NS coverage', async () => {
    const outcome = await probeDnsFailoverPosture(job({
      probe_profile: { kind: 'dns_failover_posture', secondary_nameservers: ['ns2.example.test'] },
    }), {
      resolveNsFn: async () => ['ns1.example.test'],
      resolve4Fn: async (host) => (host === 'ns2.example.test' ? [] : ['203.0.113.1']),
    });
    assert.equal(outcome.metadata.weak_failover, true);
    assert.equal(outcome.external_result, 'connected');
  });

  it('api surface scan finds exposed swagger path', async () => {
    const outcome = await probeApiSurfaceScan(job({
      target: { value: 'https://api.example.test' },
      probe_profile: { kind: 'api_surface_scan', paths: ['/swagger.json', '/missing'] },
    }), {
      fetchFn: async (url) => ({
        status: String(url).endsWith('/swagger.json') ? 200 : 404,
        headers: { get: () => null },
      }),
    });
    assert.equal(outcome.metadata.exposure_count, 1);
    assert.equal(outcome.external_result, 'connected');
  });

  it('cors posture flags wildcard ACAO', async () => {
    const outcome = await probeCorsPosture(job({
      target: { value: 'https://api.example.test' },
      probe_profile: { kind: 'cors_posture_probe' },
    }), {
      fetchFn: async () => ({
        status: 204,
        headers: { get: (n) => (n === 'access-control-allow-origin' ? '*' : null) },
      }),
    });
    assert.equal(outcome.metadata.weak_cors, true);
  });

  it('bot challenge probe flags missing challenge', async () => {
    const outcome = await probeBotChallenge(job({
      target: { value: 'https://app.example.test' },
      probe_profile: { kind: 'bot_challenge_probe' },
    }), {
      fetchFn: async () => ({ status: 200, headers: { get: () => null } }),
    });
    assert.equal(outcome.metadata.bot_challenge_missing, true);
  });

  it('graphql posture flags exposed endpoint without limits', async () => {
    const outcome = await probeGraphqlPosture(job({
      target: { value: 'https://api.example.test' },
      probe_profile: { kind: 'graphql_posture_probe', graphql_path: '/graphql' },
    }), {
      fetchFn: async () => ({ status: 200, headers: { get: () => null } }),
    });
    assert.equal(outcome.metadata.graphql_exposed, true);
    assert.equal(outcome.external_result, 'connected');
  });

  it('executeCapabilityProbe dispatches by profile kind', async () => {
    const outcome = await executeCapabilityProbe(job({
      probe_profile: { kind: 'bot_challenge_probe' },
      target: { value: 'https://app.example.test' },
    }), {
      fetchFn: async () => ({ status: 403, headers: { get: () => 'challenge' } }),
    });
    assert.equal(outcome.metadata.probe_kind, 'bot_challenge_probe');
    assert.equal(outcome.external_result, 'blocked');
  });

  it('catalog includes full P0/P1 capability checks with live probe kinds', () => {
    const ids = [
      'origin.leak_scan.safe',
      'l3.firewall_exposure_scan.safe',
      'waf.enforcement.safe',
      'tls.full_audit.safe',
      'l7.api_surface_scan.safe',
      'l7.cors_posture.safe',
    ];
    for (const id of ids) {
      const check = getCheckById(id);
      assert.ok(check, `missing ${id}`);
      assert.notEqual(check.probe_profile.kind, 'metadata_marker', `${id} still metadata_marker`);
    }
    assert.equal(getCheckById('origin.host_sni_bypass.safe').probe_profile.kind, 'host_sni_bypass');
    assert.equal(getCheckById('l7.login_abuse_flow.safe').probe_profile.kind, 'rate_limit_sequence');
    assert.equal(getCheckById('dns.zone_transfer_exposure.safe').probe_profile.kind, 'dns_axfr_leak');
    assert.equal(getCheckById('dns.secondary_failover.safe').probe_profile.kind, 'dns_failover_posture');
    assert.equal(getCheckById('l7.bot_challenge_marker.safe').probe_profile.kind, 'bot_challenge_probe');
  });
});