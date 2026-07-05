/**
 * Full P0/P1 capability probes — bounded, metadata-only results, no flooding.
 */

import dns from 'node:dns/promises';
import { Resolver } from 'node:dns/promises';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';

export const BOUNDED_SUBDOMAIN_PREFIXES = Object.freeze([
  'www', 'api', 'admin', 'dev', 'staging', 'test', 'old', 'legacy', 'direct', 'origin', 'cdn', 'internal',
]);

export const RISKY_ADMIN_PORTS = Object.freeze([
  21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 5432, 6379, 8080, 8443,
]);

export const API_DOC_PATHS = Object.freeze([
  '/swagger.json',
  '/openapi.json',
  '/api-docs',
  '/v3/api-docs',
  '/graphql',
  '/.well-known/openapi',
]);

const WEAK_TLS_PROTOCOLS = new Set(['TLSv1', 'TLSv1.1', 'SSLv3']);

function withKind(job, kind, metadata) {
  return { profile_kind: kind, probe_kind: kind, ...metadata };
}

function apexDomain(job) {
  const raw = String(job.target?.value ?? '').trim().replace(/^https?:\/\//i, '').split('/')[0].split(':')[0];
  return raw || null;
}

function baseUrlForHost(host, https = true) {
  return `${https ? 'https' : 'http'}://${host}/`;
}

function httpsHeadWithSni(directIp, hostname, { headers = {}, timeoutMs = 5000 }, deps = {}) {
  const requestFn = deps.httpsRequestFn ?? https.request;
  return new Promise((resolve) => {
    const req = requestFn(
      {
        host: directIp,
        servername: hostname,
        path: '/',
        method: 'HEAD',
        headers: { Host: hostname, ...headers },
        timeout: timeoutMs,
        rejectUnauthorized: false,
      },
      (res) => {
        res.resume();
        resolve({
          res: {
            status: res.statusCode ?? 0,
            headers: { get: (name) => res.headers[String(name).toLowerCase()] ?? null },
          },
          error: null,
        });
      },
    );
    req.on('timeout', () => {
      req.destroy();
      resolve({ res: null, error: Object.assign(new Error('timeout'), { name: 'AbortError' }) });
    });
    req.on('error', (err) => resolve({ res: null, error: err }));
    req.end();
  });
}

async function boundedFetch(url, options = {}, deps = {}) {
  const fetchFn = deps.fetchFn ?? fetch;
  const timeoutMs = options.timeoutMs ?? 5000;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchFn(url, { ...options.fetchOptions, signal: controller.signal });
    return { res, error: null };
  } catch (err) {
    return { res: null, error: err };
  } finally {
    clearTimeout(timer);
  }
}

function classifyFetchError(err) {
  const name = err?.name ?? '';
  const code = err?.code ?? '';
  if (name === 'AbortError') return 'timeout';
  if (code === 'ECONNREFUSED' || code === 'ENOTFOUND' || code === 'EHOSTUNREACH') return 'blocked';
  return 'error';
}

async function resolve4(host, deps) {
  const fn = deps.resolve4Fn ?? dns.resolve4;
  try {
    return await fn(host);
  } catch {
    return [];
  }
}

async function resolve6(host, deps) {
  const fn = deps.resolve6Fn ?? dns.resolve6;
  try {
    return await fn(host);
  } catch {
    return [];
  }
}

async function resolveNs(zone, deps) {
  const fn = deps.resolveNsFn ?? dns.resolveNs;
  try {
    return await fn(zone);
  } catch {
    return [];
  }
}

function tcpConnectProbe(host, port, timeoutMs, connectFn = net.connect) {
  return new Promise((resolve) => {
    let settled = false;
    const socket = connectFn({ host, port, timeout: timeoutMs });
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve('timeout');
    }, timeoutMs);
    socket.once('connect', () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.end();
      resolve('open');
    });
    socket.once('error', (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      const code = err?.code ?? '';
      if (code === 'ECONNREFUSED') resolve('closed');
      else if (code === 'ETIMEOUT') resolve('timeout');
      else resolve('filtered');
    });
  });
}

/**
 * P0 — Origin leak: DNS A/AAAA, bounded subdomains, IPv6 vs edge path signals.
 */
export async function probeOriginLeakScan(job, deps = {}) {
  const kind = 'origin_leak_scan';
  const domain = apexDomain(job);
  if (!domain) {
    return { external_result: 'error', metadata: withKind(job, kind, { error_class: 'unsupported_target' }), requests_sent: 0, duration_ms: 0 };
  }

  const started = Date.now();
  let requestsSent = 0;
  const leak_signals = [];
  const subdomains_scanned = [];
  const origin_ips = new Set();
  const ipv6_addrs = new Set();

  const apex4 = await resolve4(domain, deps);
  requestsSent += 1;
  apex4.forEach((ip) => origin_ips.add(ip));

  const apex6 = await resolve6(domain, deps);
  requestsSent += 1;
  apex6.forEach((ip) => ipv6_addrs.add(ip));
  if (apex6.length > 0 && apex4.length === 0) {
    leak_signals.push('ipv6_only_dns');
  }
  if (apex6.length > 0) {
    leak_signals.push('ipv6_present');
  }

  let edge_ip = null;
  const edgeProbe = await boundedFetch(baseUrlForHost(domain), {
    timeoutMs: job.constraints?.timeout_ms ?? 5000,
    fetchOptions: { method: 'HEAD', redirect: 'manual' },
  }, deps);
  requestsSent += 1;
  if (edgeProbe.res) {
    edge_ip = edgeProbe.res.headers.get('x-backend-ip') ?? null;
  }

  for (const prefix of BOUNDED_SUBDOMAIN_PREFIXES) {
    if (requestsSent >= (job.constraints?.max_requests ?? 14)) break;
    const host = `${prefix}.${domain}`;
    subdomains_scanned.push(host);
    const ips = await resolve4(host, deps);
    requestsSent += 1;
    if (ips.length > 0) {
      leak_signals.push(`subdomain_resolves:${prefix}`);
      ips.forEach((ip) => origin_ips.add(ip));
      const unique = [...new Set(ips)];
      if (apex4.length && unique.some((ip) => !apex4.includes(ip))) {
        leak_signals.push(`subdomain_origin_divergence:${prefix}`);
      }
    }
  }

  const directIps = [...origin_ips];
  if (directIps.length && edge_ip && directIps.includes(edge_ip) === false) {
    leak_signals.push('dns_points_not_edge');
  }
  if (directIps.length && !edgeProbe.res) {
    leak_signals.push('dns_only_no_edge_http');
  }

  const durationMs = Date.now() - started;
  const external = leak_signals.length > 0 ? 'connected' : 'blocked';
  return {
    external_result: external,
    metadata: withKind(job, kind, {
      duration_ms: durationMs,
      apex_domain: domain,
      origin_ips: directIps.slice(0, 8),
      ipv6_addrs: [...ipv6_addrs].slice(0, 8),
      subdomains_scanned,
      leak_signals,
      leak_count: leak_signals.length,
    }),
    requests_sent: requestsSent,
    duration_ms: durationMs,
  };
}

/**
 * P0 — CDN/WAF bypass: HTTPS to direct IP with TLS SNI + Host of protected hostname.
 * Injectable deps.fetchFn uses HTTP+Host for bounded test/verification consumers.
 */
export async function probeHostSniBypass(job, deps = {}) {
  const kind = 'host_sni_bypass';
  const hostname = job.probe_profile?.protected_host ?? apexDomain(job);
  const directIp = job.probe_profile?.direct_ip ?? job.target?.metadata?.direct_origin_ip;
  if (!hostname || !directIp) {
    return { external_result: 'error', metadata: withKind(job, kind, { error_class: 'missing_direct_ip_or_host' }), requests_sent: 0, duration_ms: 0 };
  }

  const started = Date.now();
  const timeoutMs = job.constraints?.timeout_ms ?? 5000;
  const headers = {
    Host: hostname,
    ...(job.nonce ? { 'x-astranull-nonce': job.nonce } : {}),
    ...(job.probe_profile?.marker ? { 'x-astranull-marker': String(job.probe_profile.marker) } : {}),
  };
  const hasInjectedFetch = typeof deps.fetchFn === 'function';
  const useHttps = !hasInjectedFetch && job.probe_profile?.use_https !== false;
  const { res, error } = useHttps
    ? await httpsHeadWithSni(directIp, hostname, { headers, timeoutMs }, deps)
    : await boundedFetch(`http://${directIp}/`, {
      timeoutMs,
      fetchOptions: { method: 'HEAD', headers, redirect: 'manual' },
    }, deps);

  const durationMs = Date.now() - started;
  if (error) {
    return {
      external_result: classifyFetchError(error),
      metadata: withKind(job, kind, { error_class: error.code ?? error.name, protected_host: hostname, direct_ip: directIp, duration_ms: durationMs }),
      requests_sent: 1,
      duration_ms: durationMs,
    };
  }
  const bypassed = res.status >= 200 && res.status < 500;
  return {
    external_result: bypassed ? 'connected' : 'blocked',
    metadata: withKind(job, kind, {
      status_code: res.status,
      protected_host: hostname,
      direct_ip: directIp,
      bypass_signal: bypassed,
      duration_ms: durationMs,
    }),
    requests_sent: 1,
    duration_ms: durationMs,
  };
}

/**
 * P0 — Firewall exposure: bounded risky-port scan (one connect per port).
 */
export async function probePortScanBounded(job, deps = {}) {
  const kind = 'port_scan_bounded';
  const host = job.probe_profile?.scan_host ?? apexDomain(job) ?? job.target?.value;
  if (!host) {
    return { external_result: 'error', metadata: withKind(job, kind, { error_class: 'unsupported_target' }), requests_sent: 0, duration_ms: 0 };
  }

  const ports = (job.probe_profile?.ports ?? RISKY_ADMIN_PORTS).slice(0, 15);
  const timeoutMs = Math.min(3000, job.constraints?.timeout_ms ?? 3000);
  const started = Date.now();
  const open_ports = [];
  const filtered_ports = [];
  let requestsSent = 0;

  let resolvedHost = host;
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    const ips = await resolve4(host, deps);
    requestsSent += 1;
    resolvedHost = ips[0] ?? host;
  }

  for (const port of ports) {
    const state = await tcpConnectProbe(resolvedHost, port, timeoutMs, deps.connectFn);
    requestsSent += 1;
    if (state === 'open') open_ports.push(port);
    else if (state === 'filtered' || state === 'timeout') filtered_ports.push(port);
  }

  const durationMs = Date.now() - started;
  const risky_open = open_ports.filter((p) => [22, 23, 3389, 5432, 6379, 445].includes(p));
  return {
    external_result: open_ports.length ? 'connected' : 'blocked',
    metadata: withKind(job, kind, {
      duration_ms: durationMs,
      scan_host: resolvedHost,
      open_ports,
      filtered_ports,
      risky_admin_ports_open: risky_open,
      exposure_count: open_ports.length,
    }),
    requests_sent: requestsSent,
    duration_ms: durationMs,
  };
}

/**
 * P0 — Rate-limit: rapid bounded HEAD sequence on abuse-sensitive path.
 */
export async function probeRateLimitSequence(job, deps = {}) {
  const kind = 'rate_limit_sequence';
  const url = job.target?.value?.startsWith('http') ? job.target.value : baseUrlForHost(apexDomain(job) ?? '');
  if (!url) {
    return { external_result: 'error', metadata: withKind(job, kind, { error_class: 'unsupported_target' }), requests_sent: 0, duration_ms: 0 };
  }

  const maxSeq = Math.min(5, job.probe_profile?.max_requests ?? 5);
  const started = Date.now();
  const statuses = [];
  let throttled = false;

  for (let i = 0; i < maxSeq; i += 1) {
    const { res, error } = await boundedFetch(url, {
      timeoutMs: job.constraints?.timeout_ms ?? 5000,
      fetchOptions: {
        method: 'HEAD',
        redirect: 'manual',
        headers: {
          ...(job.probe_profile?.marker ? { 'x-astranull-marker': String(job.probe_profile.marker) } : {}),
        },
      },
    }, deps);
    if (error) {
      statuses.push(classifyFetchError(error));
      continue;
    }
    statuses.push(res.status);
    if (res.status === 429 || res.status === 403 || res.status === 503) throttled = true;
  }

  const durationMs = Date.now() - started;
  return {
    external_result: throttled ? 'blocked' : 'connected',
    metadata: withKind(job, kind, {
      duration_ms: durationMs,
      status_sequence: statuses,
      throttled,
      rate_limit_enforced: throttled,
    }),
    requests_sent: statuses.length,
    duration_ms: durationMs,
  };
}

/**
 * P0 — WAF enforcement: marker must be blocked or challenged.
 */
export async function probeWafEnforcement(job, deps = {}) {
  const kind = 'waf_enforcement_probe';
  const url = job.target?.value?.startsWith('http') ? job.target.value : baseUrlForHost(apexDomain(job) ?? '');
  if (!url) {
    return { external_result: 'error', metadata: withKind(job, kind, { error_class: 'unsupported_target' }), requests_sent: 0, duration_ms: 0 };
  }

  const marker = job.probe_profile?.marker ?? 'astranull-waf-marker';
  const started = Date.now();
  const { res, error } = await boundedFetch(url, {
    timeoutMs: job.constraints?.timeout_ms ?? 5000,
    fetchOptions: {
      method: 'HEAD',
      redirect: 'manual',
      headers: {
        'x-astranull-marker': marker,
        ...(job.nonce ? { 'x-astranull-nonce': job.nonce } : {}),
      },
    },
  }, deps);

  const durationMs = Date.now() - started;
  if (error) {
    return {
      external_result: classifyFetchError(error),
      metadata: withKind(job, kind, { error_class: error.code ?? error.name, duration_ms: durationMs }),
      requests_sent: 1,
      duration_ms: durationMs,
    };
  }

  const challenged = res.status === 403 || res.status === 401 || res.status === 429;
  const mitigated = Boolean(res.headers.get('cf-mitigated') ?? res.headers.get('x-waf-block'));
  const enforced = challenged || mitigated;
  const monitor_only = res.status >= 200 && res.status < 300 && !enforced;

  return {
    external_result: enforced ? 'blocked' : 'connected',
    metadata: withKind(job, kind, {
      status_code: res.status,
      waf_enforced: enforced,
      monitor_only_leak: monitor_only,
      duration_ms: durationMs,
    }),
    requests_sent: 1,
    duration_ms: durationMs,
  };
}

/**
 * P1 — DNSSEC posture via DNSKEY/DS presence.
 */
export async function probeDnssecPosture(job, deps = {}) {
  const kind = 'dnssec_posture';
  const zone = apexDomain(job);
  if (!zone) {
    return { external_result: 'error', metadata: withKind(job, kind, { error_class: 'unsupported_target' }), requests_sent: 0, duration_ms: 0 };
  }

  const resolveFn = deps.resolveFn ?? dns.resolve;
  const started = Date.now();
  let dnskey_count = 0;
  let ds_count = 0;
  let requestsSent = 0;

  try {
    const keys = await resolveFn(zone, 'DNSKEY');
    dnskey_count = keys?.length ?? 0;
    requestsSent += 1;
  } catch {
    requestsSent += 1;
  }

  try {
    const ds = await resolveFn(zone, 'DS');
    ds_count = ds?.length ?? 0;
    requestsSent += 1;
  } catch {
    requestsSent += 1;
  }

  const durationMs = Date.now() - started;
  const dnssec_configured = dnskey_count > 0 || ds_count > 0;
  return {
    external_result: dnssec_configured ? 'blocked' : 'connected',
    metadata: withKind(job, kind, {
      duration_ms: durationMs,
      dnskey_count,
      ds_count,
      dnssec_configured,
      dnssec_missing: !dnssec_configured,
    }),
    requests_sent: requestsSent,
    duration_ms: durationMs,
  };
}

function buildAxfrQuery(zone) {
  const labels = zone.split('.').filter(Boolean);
  const qname = Buffer.alloc(labels.reduce((n, l) => n + l.length + 1, 1));
  let offset = 0;
  for (const label of labels) {
    qname[offset] = label.length;
    offset += 1;
    qname.write(label, offset, 'ascii');
    offset += label.length;
  }
  const header = Buffer.alloc(12);
  header.writeUInt16BE(0x1234, 0);
  header.writeUInt16BE(0x0100, 2);
  header.writeUInt16BE(1, 4);
  const question = Buffer.alloc(qname.length + 5);
  qname.copy(question, 0);
  question.writeUInt16BE(252, qname.length);
  question.writeUInt16BE(1, qname.length + 2);
  return Buffer.concat([header, question]);
}

/**
 * P1 — AXFR leak: single TCP-53 AXFR attempt against first NS.
 */
export async function probeAxfrLeak(job, deps = {}) {
  const kind = 'dns_axfr_leak';
  const zone = job.probe_profile?.zone ?? apexDomain(job);
  if (!zone) {
    return { external_result: 'error', metadata: withKind(job, kind, { error_class: 'unsupported_target' }), requests_sent: 0, duration_ms: 0 };
  }

  const started = Date.now();
  const nameservers = await resolveNs(zone, deps);
  if (!nameservers.length) {
    return {
      external_result: 'blocked',
      metadata: withKind(job, kind, { axfr_refused: true, reason: 'no_nameservers', zone }),
      requests_sent: 1,
      duration_ms: Date.now() - started,
    };
  }

  const nsHost = nameservers[0];
  const connectFn = deps.connectFn ?? net.connect;
  const timeoutMs = job.constraints?.timeout_ms ?? 5000;

  const outcome = await new Promise((resolve) => {
    let settled = false;
    const socket = connectFn({ host: nsHost, port: 53, timeout: timeoutMs });
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({ axfr_refused: true, reason: 'timeout' });
    }, timeoutMs);

    socket.once('connect', () => {
      socket.write(buildAxfrQuery(zone));
    });
    socket.once('data', (chunk) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      const rcode = (chunk[3] ?? 0) & 0x0f;
      const answerCount = chunk.length >= 8 ? chunk.readUInt16BE(6) : 0;
      if (rcode === 0 && answerCount > 0) {
        resolve({ axfr_leak: true, rcode, answer_count: answerCount });
      } else {
        resolve({ axfr_refused: true, rcode, answer_count: answerCount });
      }
    });
    socket.once('error', (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ axfr_refused: true, reason: err.code ?? 'error' });
    });
  });

  const durationMs = Date.now() - started;
  const leaked = outcome.axfr_leak === true;
  return {
    external_result: leaked ? 'connected' : 'blocked',
    metadata: withKind(job, kind, { duration_ms: durationMs, zone, nameserver: nsHost, ...outcome }),
    requests_sent: 1,
    duration_ms: durationMs,
  };
}

/**
 * P1 — TLS audit: protocol, cipher, cert expiry, authorization.
 */
export async function probeTlsAudit(job, deps = {}) {
  const kind = 'tls_audit';
  const host = apexDomain(job);
  if (!host) {
    return { external_result: 'error', metadata: withKind(job, kind, { error_class: 'unsupported_target' }), requests_sent: 0, duration_ms: 0 };
  }

  const connectFn = deps.connectFn ?? tls.connect;
  const timeoutMs = job.constraints?.timeout_ms ?? 5000;
  const started = Date.now();

  try {
    const session = await new Promise((resolve, reject) => {
      let settled = false;
      const socket = connectFn({
        host,
        port: 443,
        servername: host,
        rejectUnauthorized: false,
      });
      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        socket.destroy();
        reject(Object.assign(new Error('timeout'), { code: 'ETIMEOUT' }));
      }, timeoutMs);
      socket.once('secureConnect', () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        const cert = socket.getPeerCertificate();
        resolve({
          tls_protocol: socket.getProtocol(),
          cipher: socket.getCipher()?.name ?? null,
          authorized: socket.authorized,
          valid_to: cert?.valid_to ?? null,
          issuer: cert?.issuer?.O ?? null,
          subject: cert?.subject?.CN ?? null,
          days_to_expiry: cert?.valid_to ? Math.floor((new Date(cert.valid_to) - Date.now()) / 86400000) : null,
        });
        socket.end();
      });
      socket.once('error', (err) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        reject(err);
      });
    });

    const durationMs = Date.now() - started;
    const weak_tls = WEAK_TLS_PROTOCOLS.has(session.tls_protocol);
    const cert_expired = session.days_to_expiry != null && session.days_to_expiry < 0;
    const issues = [];
    if (weak_tls) issues.push('weak_tls_protocol');
    if (cert_expired) issues.push('cert_expired');
    if (!session.authorized) issues.push('unauthorized_chain');

    return {
      external_result: issues.length ? 'connected' : 'blocked',
      metadata: withKind(job, kind, { duration_ms: durationMs, ...session, tls_issues: issues }),
      requests_sent: 1,
      duration_ms: durationMs,
    };
  } catch (err) {
    const durationMs = Date.now() - started;
    return {
      external_result: classifyFetchError(err),
      metadata: withKind(job, kind, { error_class: err.code ?? err.name, duration_ms: durationMs }),
      requests_sent: 1,
      duration_ms: durationMs,
    };
  }
}

/**
 * P1 — Cache/CDN abuse: cache-bust + vary probe.
 */
export async function probeCacheAbuse(job, deps = {}) {
  const kind = 'cache_abuse_probe';
  const base = job.target?.value?.startsWith('http') ? job.target.value : baseUrlForHost(apexDomain(job) ?? '');
  if (!base) {
    return { external_result: 'error', metadata: withKind(job, kind, { error_class: 'unsupported_target' }), requests_sent: 0, duration_ms: 0 };
  }

  const started = Date.now();
  const observations = [];
  const urls = [
    base,
    `${base}${base.includes('?') ? '&' : '?'}cb=${Date.now()}`,
    base,
  ];

  for (const url of urls) {
    const { res } = await boundedFetch(url, {
      timeoutMs: job.constraints?.timeout_ms ?? 5000,
      fetchOptions: {
        method: 'HEAD',
        redirect: 'manual',
        headers: { 'x-astranull-cache-probe': '1' },
      },
    }, deps);
    if (res) {
      observations.push({
        cache_control: res.headers.get('cache-control'),
        age: res.headers.get('age'),
        x_cache: res.headers.get('x-cache') ?? res.headers.get('cf-cache-status'),
        status: res.status,
      });
    }
  }

  const durationMs = Date.now() - started;
  const sensitive_cached = observations.some((o) => o.cache_control?.includes('public') && !o.cache_control?.includes('no-store'));
  const cache_key_weakness = observations.length >= 3
    && observations[0].x_cache != null
    && observations[0].x_cache === observations[1].x_cache
    && observations[0].x_cache === observations[2].x_cache;

  return {
    external_result: sensitive_cached || cache_key_weakness ? 'connected' : 'blocked',
    metadata: withKind(job, kind, {
      duration_ms: durationMs,
      observations,
      sensitive_cached,
      cache_key_weakness,
    }),
    requests_sent: observations.length,
    duration_ms: durationMs,
  };
}

/**
 * P1 — API surface scan: common doc paths.
 */
export async function probeApiSurfaceScan(job, deps = {}) {
  const kind = 'api_surface_scan';
  const origin = job.target?.value?.startsWith('http')
    ? new URL(job.target.value).origin
    : baseUrlForHost(apexDomain(job) ?? '').replace(/\/$/, '');

  if (!origin) {
    return { external_result: 'error', metadata: withKind(job, kind, { error_class: 'unsupported_target' }), requests_sent: 0, duration_ms: 0 };
  }

  const paths = (job.probe_profile?.paths ?? API_DOC_PATHS).slice(0, 6);
  const started = Date.now();
  const exposed_paths = [];

  for (const path of paths) {
    const { res } = await boundedFetch(`${origin}${path}`, {
      timeoutMs: job.constraints?.timeout_ms ?? 5000,
      fetchOptions: { method: 'HEAD', redirect: 'manual' },
    }, deps);
    if (res && res.status >= 200 && res.status < 400) {
      exposed_paths.push({ path, status: res.status });
    }
  }

  const durationMs = Date.now() - started;
  return {
    external_result: exposed_paths.length ? 'connected' : 'blocked',
    metadata: withKind(job, kind, { duration_ms: durationMs, exposed_paths, exposure_count: exposed_paths.length }),
    requests_sent: paths.length,
    duration_ms: durationMs,
  };
}

/**
 * P1 — CORS posture: OPTIONS preflight with foreign Origin.
 */
export async function probeCorsPosture(job, deps = {}) {
  const kind = 'cors_posture_probe';
  const url = job.target?.value?.startsWith('http') ? job.target.value : baseUrlForHost(apexDomain(job) ?? '');
  if (!url) {
    return { external_result: 'error', metadata: withKind(job, kind, { error_class: 'unsupported_target' }), requests_sent: 0, duration_ms: 0 };
  }

  const started = Date.now();
  const { res, error } = await boundedFetch(url, {
    timeoutMs: job.constraints?.timeout_ms ?? 5000,
    fetchOptions: {
      method: 'OPTIONS',
      redirect: 'manual',
      headers: {
        Origin: 'https://probe.invalid.astranull',
        'Access-Control-Request-Method': 'GET',
      },
    },
  }, deps);

  const durationMs = Date.now() - started;
  if (error) {
    return {
      external_result: classifyFetchError(error),
      metadata: withKind(job, kind, { error_class: error.code ?? error.name, duration_ms: durationMs }),
      requests_sent: 1,
      duration_ms: durationMs,
    };
  }

  const acao = res.headers.get('access-control-allow-origin');
  const weak_cors = acao === '*' || acao === 'https://probe.invalid.astranull';
  return {
    external_result: weak_cors ? 'connected' : 'blocked',
    metadata: withKind(job, kind, {
      status_code: res.status,
      access_control_allow_origin: acao,
      weak_cors,
      duration_ms: durationMs,
    }),
    requests_sent: 1,
    duration_ms: durationMs,
  };
}

/**
 * P1 — Bot/challenge: cookie-less scripted client.
 */
export async function probeBotChallenge(job, deps = {}) {
  const kind = 'bot_challenge_probe';
  const url = job.target?.value?.startsWith('http') ? job.target.value : baseUrlForHost(apexDomain(job) ?? '');
  if (!url) {
    return { external_result: 'error', metadata: withKind(job, kind, { error_class: 'unsupported_target' }), requests_sent: 0, duration_ms: 0 };
  }

  const started = Date.now();
  const { res, error } = await boundedFetch(url, {
    timeoutMs: job.constraints?.timeout_ms ?? 5000,
    fetchOptions: {
      method: 'HEAD',
      redirect: 'manual',
      headers: {
        'User-Agent': 'AstraNullBotProbe/1.0 (+https://astranull.invalid/bot-probe)',
        Accept: '*/*',
      },
    },
  }, deps);

  const durationMs = Date.now() - started;
  if (error) {
    return {
      external_result: classifyFetchError(error),
      metadata: withKind(job, kind, { error_class: error.code ?? error.name, duration_ms: durationMs }),
      requests_sent: 1,
      duration_ms: durationMs,
    };
  }

  const challenged = res.status === 403 || res.status === 401 || res.status === 429 || res.status === 302;
  const challenge_header = res.headers.get('cf-mitigated') ?? res.headers.get('x-bot-challenge') ?? null;
  const no_challenge = res.status >= 200 && res.status < 300 && !challenge_header;

  return {
    external_result: challenged ? 'blocked' : 'connected',
    metadata: withKind(job, kind, {
      status_code: res.status,
      challenge_header,
      bot_challenge_missing: no_challenge,
      duration_ms: durationMs,
    }),
    requests_sent: 1,
    duration_ms: durationMs,
  };
}

/**
 * P1 — GraphQL posture: endpoint reachability + complexity signal headers.
 */
export async function probeGraphqlPosture(job, deps = {}) {
  const kind = 'graphql_posture_probe';
  const path = job.probe_profile?.graphql_path ?? '/graphql';
  const origin = job.target?.value?.startsWith('http')
    ? new URL(job.target.value).origin
    : baseUrlForHost(apexDomain(job) ?? '').replace(/\/$/, '');

  if (!origin) {
    return { external_result: 'error', metadata: withKind(job, kind, { error_class: 'unsupported_target' }), requests_sent: 0, duration_ms: 0 };
  }

  const started = Date.now();
  const { res, error } = await boundedFetch(`${origin}${path}`, {
    timeoutMs: job.constraints?.timeout_ms ?? 5000,
    fetchOptions: {
      method: 'HEAD',
      redirect: 'manual',
      headers: { Accept: 'application/json' },
    },
  }, deps);

  const durationMs = Date.now() - started;
  if (error) {
    return {
      external_result: classifyFetchError(error),
      metadata: withKind(job, kind, { error_class: error.code ?? error.name, duration_ms: durationMs }),
      requests_sent: 1,
      duration_ms: durationMs,
    };
  }

  const exposed = res.status >= 200 && res.status < 400;
  const complexity_limits_advertised = Boolean(
    res.headers.get('x-graphql-complexity-limit') ?? res.headers.get('x-rate-limit-limit'),
  );

  return {
    external_result: exposed && !complexity_limits_advertised ? 'connected' : 'blocked',
    metadata: withKind(job, kind, {
      status_code: res.status,
      graphql_exposed: exposed,
      complexity_limits_advertised,
      duration_ms: durationMs,
    }),
    requests_sent: 1,
    duration_ms: durationMs,
  };
}

/**
 * P1 — Open resolver: single external lookup via declared resolver.
 */
export async function probeOpenRecursion(job, deps = {}) {
  const kind = 'dns_open_recursion';
  const resolverHost = job.probe_profile?.resolver_host ?? apexDomain(job);
  if (!resolverHost) {
    return {
      external_result: 'error',
      metadata: withKind(job, kind, { error_class: 'unsupported_target' }),
      requests_sent: 0,
      duration_ms: 0,
    };
  }

  const started = Date.now();
  const queryName = job.probe_profile?.recursion_test_name ?? 'example.com';
  const resolveExternal = deps.resolve4ExternalFn ?? (async (resolver, name) => {
    const resolverClient = new Resolver();
    resolverClient.setServers([resolver]);
    return resolverClient.resolve4(name);
  });

  let open_recursion = false;
  try {
    await resolveExternal(resolverHost, queryName);
    open_recursion = true;
  } catch {
    open_recursion = false;
  }

  const durationMs = Date.now() - started;
  return {
    external_result: open_recursion ? 'connected' : 'blocked',
    metadata: withKind(job, kind, {
      duration_ms: durationMs,
      resolver_host: resolverHost,
      recursion_test_name: queryName,
      open_recursion_detected: open_recursion,
    }),
    requests_sent: 1,
    duration_ms: durationMs,
  };
}

/**
 * P1 — Secondary DNS failover posture: NS count and declared secondary reachability.
 */
export async function probeDnsFailoverPosture(job, deps = {}) {
  const kind = 'dns_failover_posture';
  const zone = apexDomain(job);
  if (!zone) {
    return {
      external_result: 'error',
      metadata: withKind(job, kind, { error_class: 'unsupported_target' }),
      requests_sent: 0,
      duration_ms: 0,
    };
  }

  const started = Date.now();
  const nameservers = await resolveNs(zone, deps);
  const declaredSecondary = (job.probe_profile?.secondary_nameservers ?? []).slice(0, 2);
  const secondary_results = [];

  for (const ns of declaredSecondary) {
    const addrs = await resolve4(ns, deps);
    secondary_results.push({ nameserver: ns, reachable: addrs.length > 0, addresses: addrs.slice(0, 2) });
  }

  const weak_failover = nameservers.length < 2
    || (declaredSecondary.length > 0 && secondary_results.some((r) => !r.reachable));
  const durationMs = Date.now() - started;

  return {
    external_result: weak_failover ? 'connected' : 'blocked',
    metadata: withKind(job, kind, {
      duration_ms: durationMs,
      zone,
      nameserver_count: nameservers.length,
      nameservers: nameservers.slice(0, 4),
      secondary_results,
      weak_failover,
    }),
    requests_sent: 1 + secondary_results.length,
    duration_ms: durationMs,
  };
}

export const CAPABILITY_PROBE_DISPATCH = Object.freeze({
  origin_leak_scan: probeOriginLeakScan,
  host_sni_bypass: probeHostSniBypass,
  port_scan_bounded: probePortScanBounded,
  rate_limit_sequence: probeRateLimitSequence,
  waf_enforcement_probe: probeWafEnforcement,
  dnssec_posture: probeDnssecPosture,
  dns_open_recursion: probeOpenRecursion,
  dns_failover_posture: probeDnsFailoverPosture,
  dns_axfr_leak: probeAxfrLeak,
  tls_audit: probeTlsAudit,
  cache_abuse_probe: probeCacheAbuse,
  api_surface_scan: probeApiSurfaceScan,
  cors_posture_probe: probeCorsPosture,
  bot_challenge_probe: probeBotChallenge,
  graphql_posture_probe: probeGraphqlPosture,
});

export async function executeCapabilityProbe(job, deps = {}) {
  const kind = job.probe_profile?.kind;
  const fn = CAPABILITY_PROBE_DISPATCH[kind];
  if (!fn) return null;
  return fn(job, deps);
}