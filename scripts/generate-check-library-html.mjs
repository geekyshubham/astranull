#!/usr/bin/env node
/**
 * Generate docs/check-library.html from src/contracts/checks.mjs CHECK_CATALOG.
 */
import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { CHECK_CATALOG } from '../src/contracts/checks.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(__dirname, '..', 'docs', 'check-library.html');

const GLOSSARY = {
  'Probe worker': 'AstraNull-signed outside process that runs bounded network probes against customer-declared targets (not in your app process).',
  Agent: 'Customer-deployed outbound observer (heartbeat, packet, mirror, log-tail, or canary). Correlates inside traffic with outside probes — not required for every check.',
  'default_expected_behavior': 'Per-check pass criteria from the catalog (e.g. must_block_before_origin). Verdict correlation uses this, not customer-declared target fields.',
  'probe_profile.kind': 'The bounded probe technique used (HTTP HEAD, TCP connect, DNS lookup, etc.).',
  'external_result': 'Probe outcome: blocked, timeout, connected, or allowed.',
  'agent_observation': 'Metadata that the agent saw matching probe traffic at the observation point.',
  'metadata_marker': 'Catalog-only simulation in dev/CI; production signed-worker may still dispatch a minimal stub unless a live probe kind is set.',
  'soc_gated': 'Not runnable from customer UI — requires SOC approval, authorization pack, and governed execution.',
  nonce_hash: 'Correlation token linking probe job to agent observation without sending raw payloads.',
  'direct_origin_ip': 'Customer-declared origin IP used for Host/SNI bypass probes (no automatic origin hunting).',
};

const PROBE_KINDS = {
  http_head: 'Single bounded HTTP HEAD with optional harmless marker header.',
  tcp_connect: 'One TCP connect attempt to declared host:port.',
  dns_resolve: 'Single DNS lookup for declared name.',
  metadata_marker: 'No live network I/O — records declared intent only (deferred checks).',
  udp_probe: 'One labeled UDP datagram (no amplification).',
  quic_reachability: 'HTTPS Alt-Svc read plus one UDP/443 datagram.',
  alert_webhook_ping: 'One POST to declared alert webhook; expects HTTP 2xx.',
  ops_readiness: 'Validates runbook/kill-switch evidence metadata (no traffic to customer edge).',
  ownership_challenge: 'Bounded HEAD with challenge nonce for ownership verification.',
  tls_session: 'One TLS handshake; collects protocol/cipher/cert metadata.',
  http2_settings: 'Reads HTTP/2 SETTINGS frame limits (no reset flood).',
  origin_leak_scan: 'Bounded prefix DNS scan on declared apex (fixed label list, not internet-wide).',
  host_sni_bypass: 'HEAD to declared direct IP using protected hostname as Host/SNI.',
  port_scan_bounded: 'TCP connect to capped port list on declared host.',
  rate_limit_sequence: 'Up to 5 spaced HEAD requests to observe 429/challenge.',
  waf_enforcement_probe: 'Harmless marker request; blocked/challenged = WAF enforcing.',
  dnssec_posture: 'DNSKEY/DS lookups for DNSSEC signals.',
  dns_open_recursion: 'Single recursion test via declared resolver.',
  dns_failover_posture: 'NS count and secondary NS reachability.',
  dns_axfr_leak: 'One TCP-53 AXFR attempt; leak if zone transfers when unauthorized.',
  tls_audit: 'Full TLS handshake audit (version, cipher, cert expiry).',
  cache_abuse_probe: 'Bounded cache-bust HEAD sequence.',
  api_surface_scan: 'HEAD on declared/common API doc paths.',
  cors_posture_probe: 'OPTIONS with foreign Origin; weak ACAO = finding.',
  bot_challenge_probe: 'Cookie-less client; expects bot challenge or block.',
  graphql_posture_probe: 'Bounded GraphQL endpoint posture (no deep queries).',
  websocket_upgrade_posture: 'Single WebSocket upgrade request; classifies 101/403/426.',
  outside_in_waf_scan: 'Up to 10 bounded probes: WAF fingerprint, benign markers, evasion variants, origin bypass.',
};

const FAMILY_LABELS = {
  origin: 'Origin & bypass',
  l3_l4: 'L3/L4 network',
  path: 'Protected path / canary',
  dns: 'DNS',
  l7: 'L7 / API / HTTP',
  waf: 'WAF posture',
  tls: 'TLS & connections',
  protocol: 'Modern protocols',
  operations: 'Operations readiness',
  high_scale: 'High-scale (SOC only)',
};

function esc(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function detectSummary(check) {
  const kind = check.probe_profile?.kind ?? 'none';
  const maxReq = check.probe_profile?.max_requests ?? 1;
  const parts = [PROBE_KINDS[kind] ?? `Probe kind: ${kind}`];
  if (kind !== 'metadata_marker' && kind !== 'ops_readiness' && maxReq > 0) {
    parts.push(`Max ${maxReq} request(s), timeout ≤ ${check.probe_profile?.timeout_ms ?? 5000}ms.`);
  }
  if ((check.evidence_required ?? []).includes('agent_observation')) {
    parts.push('Correlates outside probe with agent observation when agent-assisted.');
  } else {
    parts.push('Verdict primarily from outside probe metadata.');
  }
  return parts.join(' ');
}

function whatWeDetect(check) {
  const id = check.check_id;
  const hints = {
    'origin.leak_scan.safe': 'Leaked origin IPs, stale subdomains, IPv6-only DNS paths that bypass CDN.',
    'waf.fingerprint.safe': 'WAF vendor fingerprint, benign SQLi/XSS/path markers blocked or not, evasion bypass, posture label.',
    'dns.zone_transfer_exposure.safe': 'Unauthorized AXFR (full zone download) on declared zone.',
    'l7.cors_posture.safe': 'Overly permissive CORS (wildcard ACAO on preflight).',
    'protocol.grpc_reflection_stream.safe': 'Declared gRPC reflection policy only (live probe deferred).',
  };
  if (hints[id]) return hints[id];
  return check.verdict_logic || check.description;
}

const safe = CHECK_CATALOG.filter((c) => c.safety_class === 'safe');
const soc = CHECK_CATALOG.filter((c) => c.safety_class === 'soc_gated');

const byFamily = new Map();
for (const c of safe) {
  const f = c.vector_family ?? 'other';
  if (!byFamily.has(f)) byFamily.set(f, []);
  byFamily.get(f).push(c);
}

const familyOrder = ['origin', 'l3_l4', 'path', 'dns', 'waf', 'l7', 'tls', 'protocol', 'operations'];

function renderCheckCard(c) {
  const agents = (c.required_agent_modes ?? []).join(', ') || 'none';
  const setup = (c.required_customer_setup ?? []).map((s) => `<li>${esc(s)}</li>`).join('');
  const evidence = (c.evidence_required ?? []).map(esc).join(', ');
  const stops = (c.stop_conditions ?? []).map(esc).join(', ');
  return `
    <article class="check" id="${esc(c.check_id)}">
      <header>
        <h3>${esc(c.name)}</h3>
        <code class="check-id">${esc(c.check_id)}</code>
        <span class="badge ${esc(c.safety_class)}">${esc(c.safety_class)}</span>
      </header>
      <p class="desc">${esc(c.description)}</p>
      <dl>
        <dt>What we detect</dt>
        <dd>${esc(whatWeDetect(c))}</dd>
        <dt>How we detect</dt>
        <dd>${esc(detectSummary(c))}</dd>
        <dt>Probe kind</dt>
        <dd><code>${esc(c.probe_profile?.kind ?? 'none')}</code></dd>
        <dt>Default expected behavior</dt>
        <dd><code>${esc(c.default_expected_behavior ?? '—')}</code></dd>
        <dt>Targets</dt>
        <dd>${esc((c.supported_targets ?? []).join(', '))}</dd>
        <dt>Agent modes</dt>
        <dd>${esc(agents)}</dd>
        <dt>Evidence required</dt>
        <dd>${esc(evidence)}</dd>
        <dt>Stop conditions</dt>
        <dd>${esc(stops)}</dd>
      </dl>
      ${setup ? `<details><summary>Customer setup required</summary><ul>${setup}</ul></details>` : ''}
    </article>`;
}

const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>AstraNull Check Library</title>
  <style>
    :root {
      --bg: #0f1419;
      --surface: #1a2332;
      --text: #e7ecf3;
      --muted: #9aa8bc;
      --accent: #5b9fd4;
      --safe: #3d8f6e;
      --soc: #c47a3a;
      --border: #2a3548;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.55;
    }
    header.page {
      padding: 2rem 1.5rem 1rem;
      border-bottom: 1px solid var(--border);
      background: var(--surface);
    }
    header.page h1 { margin: 0 0 0.5rem; font-size: 1.75rem; }
    header.page p { margin: 0; color: var(--muted); max-width: 72ch; }
    nav.toc {
      padding: 1rem 1.5rem;
      background: var(--surface);
      border-bottom: 1px solid var(--border);
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem 1rem;
      font-size: 0.9rem;
    }
    nav.toc a { color: var(--accent); text-decoration: none; }
    nav.toc a:hover { text-decoration: underline; }
    main { padding: 1.5rem; max-width: 1100px; margin: 0 auto; }
    section { margin-bottom: 2.5rem; }
    h2 { font-size: 1.35rem; border-bottom: 1px solid var(--border); padding-bottom: 0.35rem; }
    h3 { margin: 0; font-size: 1.1rem; }
    .glossary, .probe-table { width: 100%; border-collapse: collapse; font-size: 0.92rem; }
    .glossary th, .glossary td, .probe-table th, .probe-table td {
      border: 1px solid var(--border);
      padding: 0.5rem 0.65rem;
      text-align: left;
      vertical-align: top;
    }
    .glossary th, .probe-table th { background: var(--surface); }
    .flow {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1rem 1.25rem;
      font-size: 0.95rem;
    }
    .flow ol { margin: 0.5rem 0 0; padding-left: 1.25rem; }
    .checks { display: grid; gap: 1rem; }
    .check {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1rem 1.25rem;
    }
    .check header { display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem 0.75rem; margin-bottom: 0.5rem; }
    .check-id { font-size: 0.8rem; color: var(--muted); }
    .badge {
      font-size: 0.7rem;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      padding: 0.15rem 0.45rem;
      border-radius: 4px;
      font-weight: 600;
    }
    .badge.safe { background: rgba(61,143,110,0.25); color: #8fd4b3; }
    .badge.soc_gated { background: rgba(196,122,58,0.25); color: #f0b07a; }
    .desc { color: var(--muted); margin: 0 0 0.75rem; }
    dl { margin: 0; display: grid; grid-template-columns: 9rem 1fr; gap: 0.35rem 0.75rem; font-size: 0.9rem; }
    dt { color: var(--muted); font-weight: 500; }
    dd { margin: 0; }
    details { margin-top: 0.75rem; font-size: 0.88rem; }
    details summary { cursor: pointer; color: var(--accent); }
    details ul { margin: 0.35rem 0 0; padding-left: 1.25rem; color: var(--muted); }
    footer { padding: 2rem 1.5rem; color: var(--muted); font-size: 0.85rem; border-top: 1px solid var(--border); }
    code { font-size: 0.85em; background: rgba(0,0,0,0.25); padding: 0.1em 0.35em; border-radius: 3px; }
  </style>
</head>
<body>
  <header class="page">
    <h1>AstraNull Check Library</h1>
    <p>Reference for every check in <code>CHECK_CATALOG</code> (${CHECK_CATALOG.length} entries).
    Safe checks are customer-runnable with bounded probes. SOC-gated checks require authorization and SOC execution.
    Generated from the repo catalog — re-run <code>node scripts/generate-check-library-html.mjs</code> after catalog changes.</p>
  </header>
  <nav class="toc">
    <a href="#how-it-works">How it works</a>
    <a href="#glossary">Glossary</a>
    <a href="#probe-kinds">Probe kinds</a>
    ${familyOrder.map((f) => `<a href="#family-${f}">${esc(FAMILY_LABELS[f] ?? f)}</a>`).join('')}
    <a href="#soc-gated">SOC-gated</a>
  </nav>
  <main>
    <section id="how-it-works">
      <h2>How a check runs</h2>
      <div class="flow">
        <ol>
          <li><strong>Declare</strong> target group + target (FQDN/IP/URL).</li>
          <li><strong>Start test run</strong> — planner picks check, creates signed probe job(s).</li>
          <li><strong>Probe worker</strong> executes bounded probe (<code>probe_profile</code>) against declared target only.</li>
          <li><strong>Agent</strong> (if deployed &amp; required) uploads metadata observation when local signal matches.</li>
          <li><strong>Correlation</strong> compares <code>external_result</code> + observation vs the check&apos;s <code>default_expected_behavior</code> → verdict + finding.</li>
        </ol>
      </div>
    </section>
    <section id="glossary">
      <h2>Glossary</h2>
      <table class="glossary">
        <thead><tr><th>Term</th><th>Meaning</th></tr></thead>
        <tbody>
          ${Object.entries(GLOSSARY).map(([k, v]) => `<tr><td><strong>${esc(k)}</strong></td><td>${esc(v)}</td></tr>`).join('')}
        </tbody>
      </table>
      <h3 style="margin-top:1.5rem">Expected behavior values</h3>
      <table class="glossary">
        <tbody>
          <tr><td><code>must_block_before_origin</code></td><td>Attack-ish probe should be stopped at edge/WAF — must not reach your app.</td></tr>
          <tr><td><code>must_reach_canary</code></td><td>Traffic should reach your opt-in canary on the protected path (positive test).</td></tr>
          <tr><td><code>must_allow_baseline_health</code></td><td>Legitimate health probe should succeed (declared; correlation partial).</td></tr>
          <tr><td><code>must_challenge_or_rate_limit</code></td><td>Suspicious probe should get challenge or 429 (declared; correlation partial).</td></tr>
          <tr><td><code>must_not_expose_direct_ip</code></td><td>Origin IP should not answer when only CDN hostname is public (declared; correlation partial).</td></tr>
        </tbody>
      </table>
    </section>
    <section id="probe-kinds">
      <h2>Probe kinds (how detection works)</h2>
      <table class="probe-table">
        <thead><tr><th>Kind</th><th>What it does</th></tr></thead>
        <tbody>
          ${Object.entries(PROBE_KINDS).map(([k, v]) => `<tr><td><code>${esc(k)}</code></td><td>${esc(v)}</td></tr>`).join('')}
        </tbody>
      </table>
    </section>
    ${familyOrder.map((f) => {
      const checks = byFamily.get(f) ?? [];
      if (checks.length === 0) return '';
      return `
    <section id="family-${f}">
      <h2>${esc(FAMILY_LABELS[f] ?? f)} <span style="color:var(--muted);font-weight:400">(${checks.length})</span></h2>
      <div class="checks">${checks.map(renderCheckCard).join('')}</div>
    </section>`;
    }).join('')}
    <section id="soc-gated">
      <h2>SOC-gated &amp; high-scale <span style="color:var(--muted);font-weight:400">(${soc.length})</span></h2>
      <p style="color:var(--muted)">Not runnable from customer test-runs API. Customer may <em>request</em>; SOC approves, schedules, and executes via governed adapter. No unmanaged attack traffic in-repo.</p>
      <div class="checks">${soc.map(renderCheckCard).join('')}</div>
    </section>
  </main>
  <footer>
    AstraNull · Check catalog v${esc(safe[0]?.version ?? '1.0.0')} · ${safe.length} safe + ${soc.length} SOC-gated · ${new Date().toISOString().slice(0, 10)}
  </footer>
</body>
</html>`;

writeFileSync(OUT, html, 'utf8');
console.log(`check-library: wrote ${OUT} (${CHECK_CATALOG.length} checks)`);