import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { getCheckById } from '../../src/contracts/checks.mjs';
import {
  BENIGN_CLASS_MARKERS,
  EVASION_VARIANT_MARKERS,
  buildOutsideInPostureReport,
  buildOutsideInScanPlan,
  detectGenericWafPresence,
  runOutsideInWafScan,
} from '../../src/lib/outsideInWafScanner.mjs';
import {
  executeCapabilityProbe,
  probeOutsideInWafScan,
} from '../../src/lib/capabilityProbes.mjs';

function mockResponse(status, headers = {}) {
  const normalized = Object.fromEntries(
    Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]),
  );
  return {
    status,
    headers: {
      get: (name) => normalized[String(name).toLowerCase()] ?? null,
      forEach: (fn) => {
        for (const [name, value] of Object.entries(normalized)) {
          fn(value, name);
        }
      },
    },
    async text() {
      return normalized.__body ?? '';
    },
  };
}

describe('outside-in WAF scanner', () => {
  it('waf.fingerprint.safe maps to outside_in_waf_scan with 10-request budget', () => {
    const check = getCheckById('waf.fingerprint.safe');
    assert.equal(check.probe_profile.kind, 'outside_in_waf_scan');
    assert.equal(check.probe_profile.max_requests, 10);
    assert.equal(check.probe_profile.require_agent_for_protected, true);
  });

  it('buildOutsideInScanPlan prioritizes evasion phases within budget', () => {
    const plan = buildOutsideInScanPlan(6, { hasDirectIp: false });
    assert.deepEqual(plan.map((entry) => entry.phase), [
      'baseline',
      'combined_marker',
      'path_traversal_marker',
      'sqli_marker',
      'sqli_encoded_marker',
      'sqli_case_marker',
    ]);
    const fullPlan = buildOutsideInScanPlan(10, { hasDirectIp: false });
    assert.ok(fullPlan.some((entry) => entry.phase === 'multipart_confusion'));
  });

  it('detects generic WAF via status drift between baseline and marker probe', () => {
    const baseline = { status_code: 200, server_header: 'nginx', connection_dropped: false };
    const attack = { status_code: 403, server_header: 'nginx', connection_dropped: false };
    const result = detectGenericWafPresence({ baseline, attack, noUserAgent: baseline });
    assert.equal(result.detected, true);
    assert.ok(result.reasons.includes('status_code_drift'));
  });

  it('fingerprints Cloudflare but requires agent for Protected label', async () => {
    const baseUrl = 'https://shop.example.test/';
    const outcome = await runOutsideInWafScan({
      url: baseUrl,
      budget: 10,
      timeoutMs: 1000,
      fetchFn: async (url, init) => {
        const isBaseline = url === baseUrl && init?.headers?.['User-Agent'] && init?.method !== 'POST';
        if (!isBaseline) {
          return mockResponse(403, {
            server: 'cloudflare',
            'cf-ray': 'abc123',
            'set-cookie': '__cf_bm=1; Path=/',
            __body: 'Attention Required! | Cloudflare',
          });
        }
        return mockResponse(200, {
          server: 'cloudflare',
          'cf-ray': 'abc123',
          'set-cookie': '__cf_bm=1; Path=/',
        });
      },
    });

    assert.equal(outcome.waf_detected, true);
    assert.equal(outcome.detected_vendor, 'cloudflare');
    assert.equal(outcome.posture_label, 'Detected, not validated');
    assert.equal(outcome.probe_validation_passed, true);
    assert.equal(outcome.validation_passed, false);
    assert.ok(outcome.marker_probes.some((probe) => probe.family === 'sqli_encoded_marker'));
  });

  it('reports Protected only when agent corroboration is present', async () => {
    const baseUrl = 'https://shop.example.test/';
    const outcome = await runOutsideInWafScan({
      url: baseUrl,
      budget: 8,
      timeoutMs: 1000,
      agentCorroborated: true,
      fetchFn: async (url, init) => {
        const isBaseline = url === baseUrl && init?.headers?.['User-Agent'] && init?.method !== 'POST';
        if (!isBaseline) {
          return mockResponse(403, { server: 'cloudflare', 'cf-ray': '1', __body: 'Cloudflare' });
        }
        return mockResponse(200, { server: 'cloudflare', 'cf-ray': '1' });
      },
    });
    assert.equal(outcome.posture_label, 'Protected');
    assert.equal(outcome.validation_passed, true);
    assert.equal(outcome.agent_corroborated, true);
  });

  it('flags evasion bypass when plain markers blocked but encoded allowed', async () => {
    const baseUrl = 'https://edge.example.test/';
    const outcome = await runOutsideInWafScan({
      url: baseUrl,
      budget: 10,
      timeoutMs: 1000,
      fetchFn: async (url, init) => {
        const isBaseline = url === baseUrl && init?.headers?.['User-Agent'];
        if (isBaseline) return mockResponse(200, { server: 'nginx' });
        if (url.includes('%25') || url.includes(EVASION_VARIANT_MARKERS.sqli_encoded)) {
          return mockResponse(200, { server: 'nginx' });
        }
        if (init?.method === 'POST') return mockResponse(200, { server: 'nginx' });
        return mockResponse(403, { server: 'nginx', __body: 'blocked' });
      },
    });
    assert.equal(outcome.evasion_bypass_suspected, true);
    assert.equal(outcome.posture_label, 'Underprotected');
    assert.equal(outcome.validation_failed, true);
  });

  it('runs content-type and multipart confusion POST probes within scan plan', async () => {
    const methods = [];
    const contentTypes = [];
    const outcome = await runOutsideInWafScan({
      url: 'https://api.example.test/',
      budget: 10,
      timeoutMs: 1000,
      fetchFn: async (_url, init) => {
        methods.push(init?.method ?? 'GET');
        contentTypes.push(init?.headers?.['Content-Type'] ?? null);
        return mockResponse(403, { server: 'waf', __body: 'blocked' });
      },
    });
    assert.ok(methods.includes('POST'));
    const contentTypeProbe = outcome.marker_probes.find((probe) => probe.family === 'content_type_confusion');
    assert.ok(contentTypeProbe);
    assert.equal(contentTypeProbe.blocked, true);
    const multipartProbe = outcome.marker_probes.find((probe) => probe.family === 'multipart_confusion');
    assert.ok(multipartProbe);
    assert.equal(multipartProbe.blocked, true);
    assert.ok(contentTypes.some((value) => String(value).includes('multipart/form-data')));
  });

  it('flags content-type confusion gap when POST marker is allowed through', async () => {
    const outcome = await runOutsideInWafScan({
      url: 'https://api.example.test/',
      budget: 10,
      timeoutMs: 1000,
      fetchFn: async (_url, init) => {
        if (init?.method === 'POST') return mockResponse(200, { server: 'nginx' });
        return mockResponse(403, { server: 'nginx', __body: 'blocked' });
      },
    });
    assert.equal(outcome.evasion_bypass_suspected, true);
    assert.ok(outcome.marker_probes.find((probe) => probe.family === 'content_type_confusion')?.allowed);
  });

  it('reports underprotected when markers reach origin with 200', async () => {
    const outcome = await runOutsideInWafScan({
      url: 'https://app.example.test/',
      budget: 8,
      timeoutMs: 1000,
      fetchFn: async () => mockResponse(200, { server: 'nginx' }),
    });

    assert.equal(outcome.waf_detected, false);
    assert.equal(outcome.posture_label, 'Underprotected');
    assert.equal(outcome.validation_failed, true);
  });

  it('reports bypass risk when declared origin is reachable', async () => {
    const outcome = await runOutsideInWafScan({
      url: 'https://edge.example.test/',
      budget: 10,
      timeoutMs: 1000,
      directIp: '198.51.100.7',
      hostname: 'edge.example.test',
      fetchFn: async (url, init) => {
        if (url === 'https://edge.example.test/' && init?.headers?.['User-Agent']) {
          return mockResponse(200, { server: 'cloudflare', 'cf-ray': '1' });
        }
        return mockResponse(403, { server: 'cloudflare', 'cf-ray': '1', __body: 'blocked' });
      },
      originBypassFn: async () => ({
        res: mockResponse(200, { server: 'origin-nginx' }),
        error: null,
      }),
    });

    assert.equal(outcome.origin_bypass_confirmed, true);
    assert.equal(outcome.posture_label, 'Bypass Risk');
  });

  it('probeOutsideInWafScan applies bound agent corroboration after scan', async () => {
    const outcome = await probeOutsideInWafScan({
      check_id: 'waf.fingerprint.safe',
      nonce_hash: 'sha256:agent-proof',
      constraints: { max_requests: 10, timeout_ms: 1000 },
      probe_profile: { kind: 'outside_in_waf_scan' },
      target: { kind: 'url', value: 'https://edge.example.test/' },
    }, {
      agentObservations: [{
        nonce_hash: 'sha256:agent-proof',
        metadata: { waf_marker: true, observed_action: 'block', waf_blocked: true },
      }],
      fetchFn: async (url, init) => {
        const isBaseline = url === 'https://edge.example.test/' && init?.headers?.['User-Agent'] && init?.method !== 'POST';
        if (!isBaseline) {
          return mockResponse(403, { server: 'cloudflare', 'cf-ray': '1', __body: 'Cloudflare' });
        }
        return mockResponse(200, { server: 'cloudflare', 'cf-ray': '1' });
      },
    });

    assert.equal(outcome.metadata.agent_corroborated, true);
    assert.equal(outcome.metadata.posture_label, 'Protected');
  });

  it('probeOutsideInWafScan integrates with capability probe dispatch', async () => {
    const outcome = await probeOutsideInWafScan({
      check_id: 'waf.fingerprint.safe',
      constraints: { max_requests: 10, timeout_ms: 1000 },
      probe_profile: { kind: 'outside_in_waf_scan' },
      target: { kind: 'url', value: 'https://edge.example.test/' },
    }, {
      fetchFn: async (url) => {
        const blocked = url.includes('OR') || url.includes('%');
        return mockResponse(blocked ? 403 : 200, {
          server: 'cloudflare',
          'cf-ray': 'xyz',
          __body: blocked ? 'Cloudflare block page' : '',
        });
      },
    });

    assert.equal(outcome.metadata.probe_kind, 'outside_in_waf_scan');
    assert.equal(outcome.metadata.waf_fingerprint_detected, true);
    assert.ok(outcome.requests_sent >= 5);
    assert.ok(outcome.metadata.waf_fingerprint_catalog_version);
    assert.equal(outcome.metadata.agent_corroboration_required, true);
  });

  it('executeCapabilityProbe routes outside_in_waf_scan kind', async () => {
    const outcome = await executeCapabilityProbe({
      constraints: { max_requests: 8, timeout_ms: 1000 },
      probe_profile: { kind: 'outside_in_waf_scan' },
      target: { kind: 'url', value: 'https://edge.example.test/' },
    }, {
      fetchFn: async () => mockResponse(403, { server: 'akamai', 'x-akamai-request-id': '1', __body: 'Access Denied' }),
    });
    assert.equal(outcome.metadata.probe_kind, 'outside_in_waf_scan');
    assert.equal(outcome.metadata.detected_vendor, 'akamai');
  });

  it('buildOutsideInPostureReport maps validation failures to underprotected', () => {
    const report = buildOutsideInPostureReport({
      wafDetected: true,
      markerResults: [
        { family: 'sqli_marker', variant: 'plain', blocked: false, challenged: false, allowed: true },
      ],
      originBypassConfirmed: false,
    });
    assert.equal(report.posture_status, 'underprotected');
    assert.equal(report.posture_label, 'Underprotected');
    assert.equal(report.validation_failed, true);
  });

  it('exports benign and evasion marker constants', () => {
    assert.ok(BENIGN_CLASS_MARKERS.sqli.includes('OR'));
    assert.ok(EVASION_VARIANT_MARKERS.sqli_comment.includes('/**/'));
  });
});