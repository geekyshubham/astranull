import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  parseNetworkEndpoint,
  probeAlertWebhookPing,
  probeHttp2Settings,
  probeQuicReachability,
  probeTlsSession,
  probeUdpDatagram,
  probeWebsocketUpgradePosture,
  resolveAlertWebhookUrl,
} from '../../src/lib/safeNetworkProbes.mjs';

function baseJob(overrides = {}) {
  return {
    id: 'pjob_1',
    check_id: 'l3.forbidden_udp_port.safe',
    vector_family: 'l3_l4',
    nonce_hash: 'abc123hashvalue',
    nonce: 'nonce-plain',
    constraints: { timeout_ms: 1000, max_requests: 1 },
    probe_profile: { kind: 'udp_probe', max_requests: 1, timeout_ms: 1000 },
    target: { id: 'tgt_1', kind: 'fqdn', value: 'origin.test', port: 9999 },
    ...overrides,
  };
}

describe('safe network probes', () => {
  it('parses host:port and host+port target descriptors', () => {
    assert.deepEqual(parseNetworkEndpoint(baseJob()), { host: 'origin.test', port: 9999 });
    assert.deepEqual(
      parseNetworkEndpoint(baseJob({ target: { value: '10.0.0.5:53' } })),
      { host: '10.0.0.5', port: 53 },
    );
    assert.equal(parseNetworkEndpoint(baseJob({ target: { value: 'no-port' } })), null);
  });

  it('resolves alert webhook URL from target metadata', () => {
    const job = baseJob({
      probe_profile: { kind: 'alert_webhook_ping' },
      target: {
        value: 'canary',
        metadata: { alert_webhook_url: 'https://hooks.example.test/alerts' },
      },
    });
    assert.equal(resolveAlertWebhookUrl(job), 'https://hooks.example.test/alerts');
  });

  it('probeUdpDatagram reports blocked when lookup fails', async () => {
    const outcome = await probeUdpDatagram(baseJob(), {
      lookupFn: async () => {
        throw Object.assign(new Error('not found'), { code: 'ENOTFOUND' });
      },
    });
    assert.equal(outcome.external_result, 'blocked');
    assert.equal(outcome.metadata.probe_kind, 'udp_probe');
    assert.equal(outcome.requests_sent, 1);
  });

  it('probeUdpDatagram reports connected after single datagram send', async () => {
    const outcome = await probeUdpDatagram(baseJob(), {
      lookupFn: async () => [{ address: '127.0.0.1', family: 4 }],
      createSocket: () => ({
        send(_payload, _port, _host, cb) {
          cb(null);
        },
        close() {},
      }),
    });
    assert.equal(outcome.external_result, 'connected');
    assert.equal(outcome.metadata.datagram_bytes > 0, true);
  });

  it('probeQuicReachability collects Alt-Svc and UDP send metadata', async () => {
    const outcome = await probeQuicReachability(
      baseJob({
        probe_profile: { kind: 'quic_reachability', max_requests: 2, timeout_ms: 1000 },
        target: { kind: 'fqdn', value: 'edge.example.test' },
      }),
      {
        fetchFn: async () => ({
          status: 200,
          headers: {
            get(name) {
              if (name === 'alt-svc') return 'h3=":443"; ma=86400, quic=":443"; v="46,43"';
              return null;
            },
          },
        }),
        lookupFn: async () => [{ address: '127.0.0.1', family: 4 }],
        createSocket: () => ({
          send(_payload, _port, _host, cb) {
            cb(null);
          },
          close() {},
        }),
      },
    );
    assert.equal(outcome.external_result, 'connected');
    assert.equal(outcome.metadata.alt_svc_present, true);
    assert.equal(outcome.metadata.quic_port, 443);
    assert.equal(outcome.requests_sent, 2);
  });

  it('probeAlertWebhookPing requires webhook URL', async () => {
    const outcome = await probeAlertWebhookPing(
      baseJob({
        probe_profile: { kind: 'alert_webhook_ping', marker: 'test-marker' },
        target: { value: 'canary' },
      }),
    );
    assert.equal(outcome.external_result, 'error');
    assert.equal(outcome.metadata.error_class, 'missing_webhook_url');
  });

  it('probeAlertWebhookPing treats HTTP 2xx as connected', async () => {
    const outcome = await probeAlertWebhookPing(
      baseJob({
        probe_profile: { kind: 'alert_webhook_ping', marker: 'test-marker' },
        target: {
          value: 'canary',
          metadata: { alert_webhook_url: 'https://hooks.example.test/ping' },
        },
      }),
      {
        fetchFn: async () => ({ status: 204 }),
      },
    );
    assert.equal(outcome.external_result, 'connected');
    assert.equal(outcome.metadata.alert_delivery_ok, true);
    assert.equal(outcome.metadata.response_status, 204);
  });

  it('probeTlsSession reports connected after secureConnect', async () => {
    const outcome = await probeTlsSession(
      baseJob({
        probe_profile: { kind: 'tls_session', max_requests: 1, timeout_ms: 1000 },
        vector_family: 'tls',
        target: { kind: 'fqdn', value: 'edge.example.test' },
      }),
      {
        connectFn: () => {
          const handlers = {};
          const socket = {
            once(event, fn) {
              handlers[event] = fn;
            },
            getProtocol: () => 'TLSv1.3',
            getCipher: () => ({ name: 'TLS_AES_128_GCM_SHA256' }),
            authorized: true,
            end() {},
            destroy() {},
          };
          queueMicrotask(() => handlers.secureConnect?.());
          return socket;
        },
      },
    );
    assert.equal(outcome.external_result, 'connected');
    assert.equal(outcome.metadata.tls_protocol, 'TLSv1.3');
    assert.equal(outcome.metadata.cipher, 'TLS_AES_128_GCM_SHA256');
    assert.equal(outcome.metadata.authorized, true);
    assert.equal(outcome.requests_sent, 1);
  });

  it('probeTlsSession reports blocked on connect refusal', async () => {
    const outcome = await probeTlsSession(
      baseJob({
        probe_profile: { kind: 'tls_session', max_requests: 1, timeout_ms: 1000 },
        target: { kind: 'fqdn', value: 'edge.example.test' },
      }),
      {
        connectFn: () => {
          const handlers = {};
          const socket = {
            once(event, fn) {
              handlers[event] = fn;
            },
            end() {},
            destroy() {},
          };
          queueMicrotask(() => {
            handlers.error?.(Object.assign(new Error('refused'), { code: 'ECONNREFUSED' }));
          });
          return socket;
        },
      },
    );
    assert.equal(outcome.external_result, 'blocked');
    assert.equal(outcome.metadata.error_class, 'ECONNREFUSED');
  });

  it('probeTlsSession reports timeout when secureConnect never fires', async () => {
    const outcome = await probeTlsSession(
      baseJob({
        constraints: { timeout_ms: 50, max_requests: 1 },
        probe_profile: { kind: 'tls_session', max_requests: 1, timeout_ms: 50 },
        target: { kind: 'fqdn', value: 'edge.example.test' },
      }),
      {
        connectFn: () => ({
          once() {},
          end() {},
          destroy() {},
        }),
      },
    );
    assert.equal(outcome.external_result, 'timeout');
    assert.equal(outcome.metadata.error_class, 'timeout');
  });

  it('probeHttp2Settings reports connected after remoteSettings', async () => {
    const outcome = await probeHttp2Settings(
      baseJob({
        probe_profile: { kind: 'http2_settings', max_requests: 1, timeout_ms: 1000 },
        vector_family: 'protocol',
        target: { kind: 'fqdn', value: 'edge.example.test' },
      }),
      {
        connectFn: () => {
          const handlers = {};
          const session = {
            once(event, fn) {
              handlers[event] = fn;
            },
            close() {},
            destroy() {},
          };
          queueMicrotask(() => {
            handlers.remoteSettings?.({
              maxConcurrentStreams: 128,
              enablePush: false,
            });
          });
          return session;
        },
      },
    );
    assert.equal(outcome.external_result, 'connected');
    assert.equal(outcome.metadata.max_concurrent_streams, 128);
    assert.equal(outcome.metadata.enable_push, false);
    assert.equal(outcome.requests_sent, 1);
  });

  it('probeHttp2Settings reports blocked on session error', async () => {
    const outcome = await probeHttp2Settings(
      baseJob({
        probe_profile: { kind: 'http2_settings', max_requests: 1, timeout_ms: 1000 },
        target: { kind: 'url', value: 'https://edge.example.test/' },
      }),
      {
        connectFn: () => {
          const handlers = {};
          const session = {
            once(event, fn) {
              handlers[event] = fn;
            },
            close() {},
            destroy() {},
          };
          queueMicrotask(() => {
            handlers.error?.(Object.assign(new Error('unreachable'), { code: 'EHOSTUNREACH' }));
          });
          return session;
        },
      },
    );
    assert.equal(outcome.external_result, 'blocked');
    assert.equal(outcome.metadata.error_class, 'EHOSTUNREACH');
  });

  it('probeWebsocketUpgradePosture requires HTTP-capable target', async () => {
    const outcome = await probeWebsocketUpgradePosture(
      baseJob({
        probe_profile: { kind: 'websocket_upgrade_posture', max_requests: 1, timeout_ms: 1000 },
        vector_family: 'protocol',
        target: { kind: 'fqdn', value: '' },
      }),
    );
    assert.equal(outcome.external_result, 'error');
    assert.equal(outcome.metadata.error_class, 'unsupported_target');
    assert.equal(outcome.requests_sent, 0);
  });

  it('probeWebsocketUpgradePosture sends bounded upgrade headers and classifies 101', async () => {
    let captured = null;
    const outcome = await probeWebsocketUpgradePosture(
      baseJob({
        probe_profile: { kind: 'websocket_upgrade_posture', max_requests: 1, timeout_ms: 1000, marker: 'ws-marker' },
        vector_family: 'protocol',
        target: { kind: 'fqdn', value: 'ws.example.test' },
        nonce: 'nonce-ws',
      }),
      {
        fetchFn: async (url, options) => {
          captured = { url, options };
          return {
            status: 101,
            headers: {
              get(name) {
                if (name === 'upgrade') return 'websocket';
                if (name === 'connection') return 'Upgrade';
                return null;
              },
            },
          };
        },
      },
    );
    assert.equal(outcome.external_result, 'connected');
    assert.equal(outcome.metadata.upgrade_accepted, true);
    assert.equal(outcome.metadata.status_code, 101);
    assert.equal(outcome.requests_sent, 1);
    assert.equal(captured.url, 'https://ws.example.test/');
    assert.equal(captured.options.method, 'GET');
    assert.equal(captured.options.headers.Connection, 'Upgrade');
    assert.equal(captured.options.headers.Upgrade, 'websocket');
    assert.equal(captured.options.headers['Sec-WebSocket-Version'], '13');
    assert.ok(typeof captured.options.headers['Sec-WebSocket-Key'] === 'string');
    assert.equal(captured.options.headers['x-astranull-marker'], 'ws-marker');
    assert.equal(captured.options.headers['x-astranull-nonce'], 'nonce-ws');
  });

  it('probeWebsocketUpgradePosture classifies 403 as upgrade denied', async () => {
    const outcome = await probeWebsocketUpgradePosture(
      baseJob({
        probe_profile: { kind: 'websocket_upgrade_posture', max_requests: 1, timeout_ms: 1000 },
        vector_family: 'protocol',
        target: { kind: 'url', value: 'https://ws.example.test/socket' },
      }),
      {
        fetchFn: async () => ({
          status: 403,
          headers: { get: () => null },
        }),
      },
    );
    assert.equal(outcome.external_result, 'blocked');
    assert.equal(outcome.metadata.upgrade_denied, true);
    assert.equal(outcome.metadata.status_code, 403);
  });

  it('probeWebsocketUpgradePosture classifies 426 as upgrade required', async () => {
    const outcome = await probeWebsocketUpgradePosture(
      baseJob({
        probe_profile: { kind: 'websocket_upgrade_posture', max_requests: 1, timeout_ms: 1000 },
        vector_family: 'protocol',
        target: { kind: 'fqdn', value: 'ws.example.test' },
      }),
      {
        fetchFn: async () => ({
          status: 426,
          headers: { get: () => null },
        }),
      },
    );
    assert.equal(outcome.external_result, 'blocked');
    assert.equal(outcome.metadata.upgrade_required, true);
    assert.equal(outcome.metadata.status_code, 426);
  });

  it('probeWebsocketUpgradePosture reports timeout on abort', async () => {
    const outcome = await probeWebsocketUpgradePosture(
      baseJob({
        constraints: { timeout_ms: 50, max_requests: 1 },
        probe_profile: { kind: 'websocket_upgrade_posture', max_requests: 1, timeout_ms: 50 },
        vector_family: 'protocol',
        target: { kind: 'fqdn', value: 'ws.example.test' },
      }),
      {
        fetchFn: async (_url, options) => new Promise((_resolve, reject) => {
          options.signal?.addEventListener('abort', () => {
            reject(Object.assign(new Error('aborted'), { name: 'AbortError' }));
          });
        }),
      },
    );
    assert.equal(outcome.external_result, 'timeout');
    assert.equal(outcome.metadata.error_class, 'timeout');
    assert.equal(outcome.requests_sent, 1);
  });

  it('probeWebsocketUpgradePosture reports blocked on DNS failure', async () => {
    const outcome = await probeWebsocketUpgradePosture(
      baseJob({
        probe_profile: { kind: 'websocket_upgrade_posture', max_requests: 1, timeout_ms: 1000 },
        vector_family: 'protocol',
        target: { kind: 'fqdn', value: 'ws.example.test' },
      }),
      {
        fetchFn: async () => {
          throw Object.assign(new Error('not found'), { code: 'ENOTFOUND' });
        },
      },
    );
    assert.equal(outcome.external_result, 'blocked');
    assert.equal(outcome.metadata.error_class, 'ENOTFOUND');
    assert.equal(outcome.requests_sent, 1);
  });
});