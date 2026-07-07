import assert from 'node:assert/strict';
import net from 'node:net';
import { describe, it } from 'node:test';
import { isLiveCapabilityProbeAuthorized } from '../../src/lib/capabilityProbeAuth.mjs';
import {
  buildAxfrDnsMessage,
  encodeDnsQName,
  frameDnsTcpMessage,
} from '../../src/lib/dnsTcpWire.mjs';
import {
  BOUNDED_SUBDOMAIN_PREFIXES,
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
  probeOutsideInWafScan,
  executeCapabilityProbe,
} from '../../src/lib/capabilityProbes.mjs';
import { getCheckById } from '../../src/contracts/checks.mjs';

function job(overrides = {}) {
  return {
    constraints: { timeout_ms: 1000, max_requests: 15 },
    probe_profile: { kind: 'origin_leak_scan' },
    target: { kind: 'fqdn', value: 'shop.example.test' },
    ...overrides,
  };
}

describe('capability probes P0/P1', () => {
  it('origin leak scan stops at constraints max_requests budget', async () => {
    const outcome = await probeOriginLeakScan(job({
      constraints: { max_requests: 4, timeout_ms: 1000 },
    }), {
      resolve4Fn: async () => [],
      resolve6Fn: async () => [],
      fetchFn: async () => ({ status: 404, headers: { get: () => null } }),
    });
    assert.equal(outcome.requests_sent, 4);
    assert.equal(outcome.metadata.subdomains_scanned.length, 1);
    assert.ok(outcome.metadata.subdomains_scanned.length < BOUNDED_SUBDOMAIN_PREFIXES.length);
  });

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
    assert.equal(outcome.metadata.leak_signals.includes('ipv6_present'), false);
    assert.ok(outcome.metadata.leak_signals.some((s) => s.startsWith('subdomain_origin_divergence:')));
  });

  it('origin leak scan does not flag normal dual-stack DNS as a leak', async () => {
    const outcome = await probeOriginLeakScan(job(), {
      resolve4Fn: async (host) => (host === 'shop.example.test' ? ['203.0.113.10'] : []),
      resolve6Fn: async () => ['2001:db8::1'],
      fetchFn: async () => ({ status: 200, headers: { get: () => null } }),
    });
    assert.equal(outcome.external_result, 'blocked');
    assert.deepEqual(outcome.metadata.leak_signals, []);
    assert.deepEqual(outcome.metadata.ipv6_addrs, ['2001:db8::1']);
  });

  it('origin leak scan does not flag subdomains that resolve to the apex edge IP', async () => {
    const outcome = await probeOriginLeakScan(job({
      constraints: { max_requests: 4, timeout_ms: 1000 },
    }), {
      resolve4Fn: async (host) => {
        if (host === 'shop.example.test') return ['203.0.113.10'];
        if (host === 'www.shop.example.test') return ['203.0.113.10'];
        return [];
      },
      resolve6Fn: async () => [],
      fetchFn: async () => ({ status: 200, headers: { get: () => null } }),
    });
    assert.equal(outcome.external_result, 'blocked');
    assert.deepEqual(outcome.metadata.leak_signals, []);
    assert.equal(outcome.metadata.subdomains_scanned.length, 1);
  });

  it('origin leak scan default budget covers the full bounded prefix list', async () => {
    const outcome = await probeOriginLeakScan(job(), {
      resolve4Fn: async () => [],
      resolve6Fn: async () => [],
      fetchFn: async () => ({ status: 404, headers: { get: () => null } }),
    });
    assert.equal(outcome.requests_sent, 15);
    assert.equal(outcome.metadata.subdomains_scanned.length, BOUNDED_SUBDOMAIN_PREFIXES.length);
  });

  it('host/SNI bypass derives direct IP and URL from declared http target', async () => {
    const outcome = await probeHostSniBypass(
      job({
        target: { kind: 'url', value: 'http://198.51.100.7:8080/health' },
        probe_profile: { kind: 'host_sni_bypass', protected_host: 'edge.example.test' },
      }),
      {
        fetchFn: async (url, init) => {
          assert.equal(url, 'http://198.51.100.7:8080/health');
          assert.equal(init.headers.Host, 'edge.example.test');
          return { status: 200, headers: { get: () => null } };
        },
      },
    );
    assert.equal(outcome.metadata.bypass_signal, true);
    assert.equal(outcome.metadata.direct_ip, '198.51.100.7');
  });

  it('host/SNI bypass reports missing direct IP before live probing', async () => {
    const outcome = await probeHostSniBypass(
      job({
        target: { kind: 'fqdn', value: 'edge.example.test' },
        probe_profile: { kind: 'host_sni_bypass', protected_host: 'edge.example.test' },
      }),
      {
        fetchFn: async () => {
          throw new Error('should not execute without direct IP');
        },
      },
    );
    assert.equal(outcome.external_result, 'error');
    assert.equal(outcome.metadata.error_class, 'missing_direct_ip_or_host');
    assert.equal(outcome.requests_sent, 0);
  });

  it('host/SNI bypass preserves URL port and path when direct IP comes from metadata', async () => {
    let captured = null;
    const outcome = await probeHostSniBypass(
      job({
        target: {
          kind: 'url',
          value: 'https://edge.example.test:8443/health?probe=1',
          metadata: { direct_origin_ip: '198.51.100.7' },
        },
        probe_profile: { kind: 'host_sni_bypass' },
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
    assert.equal(captured.port, 8443);
    assert.equal(captured.path, '/health?probe=1');
    assert.equal(captured.headers.Host, 'edge.example.test:8443');
    assert.equal(outcome.metadata.bypass_signal, true);
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

  it('port scan respects max_requests from probe profile', async () => {
    const probedPorts = [];
    const outcome = await probePortScanBounded(
      job({
        constraints: { timeout_ms: 1000 },
        target: { value: '10.0.0.5' },
        probe_profile: {
          kind: 'port_scan_bounded',
          max_requests: 3,
          ports: [22, 443, 80, 8080, 9999],
        },
      }),
      {
        connectFn: ({ port }, cb) => {
          probedPorts.push(port);
          const socket = {
            once(event, handler) {
              if (event === 'error') setImmediate(() => handler({ code: 'ECONNREFUSED' }));
            },
            destroy() {},
          };
          return socket;
        },
      },
    );
    assert.deepEqual(probedPorts, [22, 443, 80]);
    assert.equal(outcome.requests_sent, 3);
  });

  it('port scan preserves IPv6 literal IP targets', async () => {
    let resolved = false;
    const probed = [];
    const outcome = await probePortScanBounded(
      job({
        constraints: { timeout_ms: 1000, max_requests: 1 },
        target: { kind: 'ip', value: '2001:db8::1' },
        probe_profile: { kind: 'port_scan_bounded', ports: [443] },
      }),
      {
        resolve4Fn: async () => {
          resolved = true;
          return [];
        },
        connectFn: ({ host, port }) => {
          probed.push({ host, port });
          return {
            once(event, handler) {
              if (event === 'error') setImmediate(() => handler({ code: 'ECONNREFUSED' }));
            },
            destroy() {},
          };
        },
      },
    );
    assert.equal(resolved, false);
    assert.deepEqual(probed, [{ host: '2001:db8::1', port: 443 }]);
    assert.equal(outcome.requests_sent, 1);
  });

  it('port scan uses the full port budget for FQDN targets', async () => {
    const probedPorts = [];
    const outcome = await probePortScanBounded(
      job({
        constraints: { timeout_ms: 1000, max_requests: 15 },
        target: { kind: 'fqdn', value: 'scan.example.test' },
        probe_profile: { kind: 'port_scan_bounded', max_requests: 15 },
      }),
      {
        resolve4Fn: async () => ['203.0.113.55'],
        connectFn: ({ port }) => {
          probedPorts.push(port);
          return {
            once(event, handler) {
              if (event === 'error') setImmediate(() => handler({ code: 'ECONNREFUSED' }));
            },
            destroy() {},
          };
        },
      },
    );
    assert.equal(probedPorts.length, 15);
    assert.equal(probedPorts.at(-1), 8443);
    assert.equal(outcome.requests_sent, 15);
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

  it('probeAxfrLeak accumulates split TCP response chunks before parsing', async () => {
    const refusedDns = Buffer.alloc(12);
    refusedDns[3] = 0x05;
    const refusedFramed = frameDnsTcpMessage(refusedDns);
    const chunk1 = refusedFramed.subarray(0, 4);
    const chunk2 = refusedFramed.subarray(4);
    let receivedQuery = null;

    const server = net.createServer((socket) => {
      socket.on('data', (buf) => {
        receivedQuery = buf;
        socket.write(chunk1, () => socket.write(chunk2));
      });
      socket.on('error', () => {});
    });

    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const { port } = server.address();

    try {
      const outcome = await probeAxfrLeak(job({
        probe_profile: { kind: 'dns_axfr_leak', zone: 'example.test' },
      }), {
        signedJobVerified: true,
        resolveNsFn: async () => ['127.0.0.1'],
        connectFn: (opts) => net.connect({ ...opts, port }),
      });

      assert.ok(receivedQuery);
      assert.equal(receivedQuery.readUInt16BE(0), receivedQuery.length - 2);
      assert.equal(outcome.external_result, 'blocked');
      assert.equal(outcome.metadata.axfr_refused, true);
      assert.equal(outcome.metadata.rcode, 5);
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  it('axfr leak probe counts resolve-only when no nameservers', async () => {
    const outcome = await probeAxfrLeak(job({
      probe_profile: { kind: 'dns_axfr_leak', zone: 'missing.test' },
    }), {
      resolveNsFn: async () => [],
    });
    assert.equal(outcome.metadata.axfr_refused, true);
    assert.equal(outcome.metadata.reason, 'no_nameservers');
    assert.equal(outcome.requests_sent, 1);
  });

  it('axfr leak probe sends TCP-framed query and treats REFUSED rcode as blocked', async () => {
    let written = null;
    const refusedDns = Buffer.alloc(12);
    refusedDns[3] = 0x05;
    const refusedFramed = frameDnsTcpMessage(refusedDns);

    const outcome = await probeAxfrLeak(job({
      probe_profile: { kind: 'dns_axfr_leak', zone: 'example.test' },
    }), {
      resolveNsFn: async () => ['ns1.example.test'],
      connectFn: () => ({
        once(event, handler) {
          if (event === 'connect') setImmediate(() => handler());
        },
        on(event, handler) {
          if (event === 'data') setImmediate(() => handler(refusedFramed));
        },
        write(buf) {
          written = buf;
        },
        destroy() {},
      }),
    });

    assert.ok(written);
    assert.equal(written.readUInt16BE(0), written.length - 2);
    const inner = written.subarray(2);
    assert.equal(inner.readUInt16BE(encodeDnsQName('example.test').length + 12), 252);
    assert.equal(outcome.external_result, 'blocked');
    assert.equal(outcome.metadata.axfr_refused, true);
    assert.notEqual(outcome.metadata.axfr_leak, true);
    assert.equal(outcome.requests_sent, 2);
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

  it('executeCapabilityProbe blocks unsigned live probes without injectable deps', async () => {
    const outcome = await executeCapabilityProbe(job({
      probe_profile: {
        kind: 'host_sni_bypass',
        protected_host: 'edge.example.test',
        direct_ip: '198.51.100.7',
      },
    }));
    assert.equal(outcome.metadata.probe_kind, 'host_sni_bypass');
    assert.equal(outcome.metadata.error_class, 'live_probe_requires_signed_worker');
    assert.equal(outcome.external_result, 'blocked');
    assert.equal(outcome.requests_sent, 0);
  });

  it('isLiveCapabilityProbeAuthorized accepts signed worker verification context', () => {
    assert.equal(isLiveCapabilityProbeAuthorized(job(), { signedJobVerified: true }), true);
    assert.equal(isLiveCapabilityProbeAuthorized(job(), {}), false);
    assert.equal(
      isLiveCapabilityProbeAuthorized(job(), { fetchFn: async () => ({ status: 200, headers: { get: () => null } }) }),
      true,
    );
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
    assert.equal(getCheckById('origin.direct_bypass.safe').probe_profile.kind, 'host_sni_bypass');
    assert.equal(getCheckById('waf.marker_rule.safe').probe_profile.kind, 'waf_enforcement_probe');
    assert.equal(getCheckById('waf.origin_bypass.safe').probe_profile.kind, 'host_sni_bypass');
    assert.equal(getCheckById('tls.profile_exposure.safe').probe_profile.kind, 'tls_audit');
    assert.equal(getCheckById('l7.api_quota_exhaustion.safe').probe_profile.kind, 'rate_limit_sequence');
    assert.equal(getCheckById('protocol.http2_readiness.safe').probe_profile.kind, 'http2_settings');
  });
});
