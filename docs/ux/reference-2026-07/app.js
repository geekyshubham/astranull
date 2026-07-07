/* ════════════════════════════════════════════════════════════════════
 * AstraNull portal · router, RBAC, interactions
 * Event-delegated so it survives the refresh-skeleton cycle.
 * ════════════════════════════════════════════════════════════════════ */
(function () {
  'use strict';
  var reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var STORE = 'astranull.portal.v1';

  /* ───────── reveal + gauge ───────── */
  function revealIn(scope) {
    var nodes = Array.prototype.slice.call((scope || document).querySelectorAll('[data-reveal]:not(.is-in)'));
    if (!nodes.length) return;
    if (reduce || !('IntersectionObserver' in window)) { nodes.forEach(function (n) { n.classList.add('is-in'); }); return; }
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (!e.isIntersecting) return;
        var el = e.target, idx = nodes.indexOf(el);
        setTimeout(function () { el.classList.add('is-in'); }, Math.max(0, idx) * 60);
        io.unobserve(el);
      });
    }, { threshold: 0.12, rootMargin: '0px 0px -6% 0px' });
    nodes.forEach(function (n) { io.observe(n); });
  }
  function drawGauges(scope) {
    Array.prototype.slice.call((scope || document).querySelectorAll('.gauge')).forEach(function (g) {
      if (g.dataset.drawn) return; g.dataset.drawn = '1';
      if (reduce) g.classList.add('is-in'); else setTimeout(function () { g.classList.add('is-in'); }, 300);
    });
  }

  /* ───────── toast ───────── */
  var toastStack;
  function toast(title, detail, kind) {
    if (!toastStack) { toastStack = document.createElement('div'); toastStack.className = 'toast-stack'; document.body.appendChild(toastStack); }
    var t = document.createElement('div'); t.className = 'toast' + (kind ? ' is-' + kind : ''); t.setAttribute('role', 'status');
    var inner = '<span class="t-dot"></span><div class="toast-body"><strong></strong></div>' +
      '<button type="button" class="toast-close" aria-label="Dismiss notification">' +
      '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M6 6l12 12M18 6L6 18" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>' +
      '</button>';
    t.innerHTML = inner;
    t.querySelector('strong').textContent = title;
    if (detail) { var s = document.createElement('span'); s.textContent = detail; t.querySelector('.toast-body').appendChild(s); }
    toastStack.appendChild(t);
    var dismissed = false;
    function dismiss() {
      if (dismissed) return; dismissed = true;
      t.style.transition = 'opacity .2s, transform .2s';
      t.style.opacity = '0'; t.style.transform = 'translateY(6px)';
      setTimeout(function () { t.remove(); }, 220);
    }
    var autoTimer = setTimeout(dismiss, 3400);
    // Pause auto-dismiss while the user is hovering or focus is inside the toast (WCAG 2.2.1)
    function pause() { if (autoTimer) { clearTimeout(autoTimer); autoTimer = null; } }
    function resume() { if (!autoTimer && !dismissed) autoTimer = setTimeout(dismiss, 3400); }
    t.addEventListener('mouseenter', pause);
    t.addEventListener('mouseleave', resume);
    t.addEventListener('focusin', pause);
    t.addEventListener('focusout', resume);
    t.querySelector('.toast-close').addEventListener('click', function (e) { e.stopPropagation(); dismiss(); });
  }

  /* ───────── routing ───────── */
  var GROUP_LABELS = { overview: 'Overview', scope: 'Declared scope', validation: 'Validation', posture: 'Posture', governance: 'Governance', staff: 'Staff' };
  var DETAIL_ROUTES = {
    'agent-detail':        { group: 'scope',      parent: 'agents',         label: 'Agent detail',                 store: 'agents' },
    'environment-detail':  { group: 'scope',      parent: 'environments',   label: 'Environment detail',           store: 'environments' },
    'target-group-detail': { group: 'scope',      parent: 'target-groups',  label: 'Target group detail',          store: 'targetGroups' },
    'target-detail':       { group: 'scope',      parent: 'target-groups',  label: 'Target detail',                store: 'targets' },
    'tenant-detail':       { group: 'staff',      parent: 'admin',          label: 'Tenant detail',                store: 'tenants' },
    'report-detail':       { group: 'governance', parent: 'reports',        label: 'Report detail',                store: 'reports' },
    'run-detail':          { group: 'validation', parent: 'runs',           label: 'Run detail',                   store: 'runs' },
    'check-detail':        { group: 'validation', parent: 'checks',         label: 'Check detail',                 store: 'checks' },
    'policy-detail':       { group: 'validation', parent: 'test-policies',  label: 'Policy detail',                store: 'policies' },
    'finding-detail':      { group: 'validation', parent: 'findings',       label: 'Finding detail',               store: 'findings' },
    'queue-detail':        { group: 'staff',      parent: 'internal-soc',   label: 'Queue item detail',            store: 'queueItems' }
  };
  var ENTITIES = {
    agents: {
      agt_edge_01: { id: 'agt_edge_01', hostname: 'edge-01.acme', env: 'env_prod', version: 'v1.4.2', heartbeat: '12s', placement: 'declared', status: 'Healthy', statusClass: 'badge--success', observations: '847', lastRun: 'run_8f3c' },
      agt_edge_02: { id: 'agt_edge_02', hostname: 'edge-02.acme', env: 'env_prod', version: 'v1.4.2', heartbeat: '18s', placement: 'declared', status: 'Healthy', statusClass: 'badge--success', observations: '612', lastRun: 'run_5b09' },
      agt_edge_03: { id: 'agt_edge_03', hostname: 'edge-03.acme', env: 'env_prod', version: 'v1.4.1', heartbeat: '29s', placement: 'diagnostic', status: 'Update due', statusClass: 'badge--warn', observations: '531', lastRun: 'run_6d14' },
      agt_stage_01: { id: 'agt_stage_01', hostname: 'stage-01.acme', env: 'env_staging', version: 'v1.4.2', heartbeat: '22s', placement: 'declared', status: 'Healthy', statusClass: 'badge--success', observations: '204', lastRun: 'run_7a21' }
    },
    environments: {
      env_prod: { id: 'env_prod', name: 'Production edge', region: 'us-east-1', groups: '6', agents: '3', findings: '4', status: 'Validated', statusClass: 'badge--success', lastValidation: '2h ago' },
      env_staging: { id: 'env_staging', name: 'Staging', region: 'eu-west-2', groups: '3', agents: '2', findings: '1', status: 'Validated', statusClass: 'badge--success', lastValidation: '5h ago' },
      env_dr: { id: 'env_dr', name: 'Failover', region: 'apac', groups: '2', agents: '1', findings: '2', status: 'Review', statusClass: 'badge--warn', lastValidation: '1d ago' },
      env_internal: { id: 'env_internal', name: 'Internal apps', region: 'us-east-1', groups: '4', agents: '0', findings: '0', status: 'No agent', statusClass: 'badge--muted', lastValidation: '-' }
    },
    targetGroups: {
      tg_checkout: { id: 'tg_checkout', name: 'edge-checkout', env: 'env_prod', criticality: 'Critical', criticalityClass: 'badge--accent', targets: '12', verdict: 'Gap', verdictClass: 'badge--danger', owner: 'edge-sre', lastRun: 'run_8f3c' },
      tg_media: { id: 'tg_media', name: 'media-origin', env: 'env_prod', criticality: 'Critical', criticalityClass: 'badge--accent', targets: '8', verdict: 'Review', verdictClass: 'badge--warn', owner: 'edge-sre', lastRun: 'run_6d14' },
      tg_api: { id: 'tg_api', name: 'api-public', env: 'env_prod', criticality: 'High', criticalityClass: 'badge--muted', targets: '6', verdict: 'Pass', verdictClass: 'badge--success', owner: 'platform', lastRun: 'run_5b09' },
      tg_dns: { id: 'tg_dns', name: 'dns-zone-root', env: 'env_prod', criticality: 'High', criticalityClass: 'badge--muted', targets: '4', verdict: 'Review', verdictClass: 'badge--warn', owner: 'platform', lastRun: 'run_4c77' },
      tg_stage: { id: 'tg_stage', name: 'staging-edge', env: 'env_staging', criticality: 'Medium', criticalityClass: 'badge--muted', targets: '5', verdict: 'Pass', verdictClass: 'badge--success', owner: 'qa', lastRun: 'run_7a21' },
      tg_fail: { id: 'tg_fail', name: 'failover-edge', env: 'env_dr', criticality: 'Critical', criticalityClass: 'badge--accent', targets: '3', verdict: 'None', verdictClass: 'badge--muted', owner: 'sre', lastRun: '-' }
    },
    targets: {
      tgt_checkout_1: {
        id: 'tgt_checkout_1', targetGroup: 'edge-checkout', targetGroupId: 'tg_checkout', env: 'env_prod',
        kind: 'fqdn', value: 'checkout.acme.com', expected: 'block_at_edge',
        verification: 'agent_verified', verificationClass: 'is-verified',
        verificationTitle: 'probe + agent correlated on agt_edge_01 · Jul 4',
        ownershipMethod: 'DNS TXT + agent callback', ownershipStatus: 'verified',
        dnsRecord: '_astranull-challenge.checkout.acme.com', dnsValue: 'astranull=8f3c-9e2a-4c1b-7d20',
        dnsStatus: 'resolved', dnsStatusClass: 'badge--success', dnsCheckedTs: 'Jul 4 · 09:12 UTC',
        agentBinding: 'agt_edge_01', agentBindingTs: '12s ago',
        loaState: 'signed', loaClass: 'badge--success',
        loaCustody: 'sha256:9f2a…c41e', loaSignedBy: 'Priya Menon · Head of Platform',
        loaSignedAt: '2026-07-04 09:14 UTC',
        testWindow: 'daily 04:00 · 04:00-04:30 UTC',
        eligibility: 'eligible', eligibilityClass: 'badge--success',
        eligibilityReason: 'ownership verified, LOA signed, in scope of test window',
        wafAssetId: 'waf_edge_checkout', wafVendor: 'cloudflare',
        wafPosture: 'protected', wafPostureClass: 'badge--success',
        wafDrift: '-', wafDriftClass: 'badge--muted',
        wafValidation: 'finalized', wafValidationClass: 'badge--success',
        wafConnector: 'healthy', wafConnectorClass: 'badge--success',
        wafFingerprint: 'passed', wafMarkerRules: '4/4 blocked',
        wafOriginBypass: 'not confirmed',
        wafNotes: 'Cloudflare-fronted checkout host. Fingerprint check finalized. Marker rules pass. Origin bypass not observed on the last bounded probe.',
        checks: [
          { id: 'chk_l7_rate', family: 'l7-api', bound: '50 RPS', lastRun: 'run_8f3c', lastRunTs: '2h ago', verdict: 'Gap', verdictClass: 'badge--danger', method: 'bounded 50 RPS · agent-corroborated' },
          { id: 'chk_origin_bypass', family: 'origin-bypass', bound: '50 RPS', lastRun: 'run_5b09', lastRunTs: '2d ago', verdict: 'Pass', verdictClass: 'badge--success', method: 'metadata-only · bounded 50 RPS' },
          { id: 'chk_l3_l4', family: 'l3-l4', bound: 'metadata', lastRun: 'run_5b09', lastRunTs: '2d ago', verdict: 'Pass', verdictClass: 'badge--success', method: 'metadata-only · single probe' }
        ],
        runs: [
          { id: 'run_8f3c', policy: 'pol_edge_daily', started: '2h ago', verdict: 'Gap', verdictClass: 'badge--danger', agent: 'agt_edge_01', duration: '2m 14s' },
          { id: 'run_7a21', policy: 'pol_edge_daily', started: '1d ago', verdict: 'Pass', verdictClass: 'badge--success', agent: 'agt_edge_01', duration: '2m 02s' },
          { id: 'run_5b09', policy: 'pol_edge_daily', started: '2d ago', verdict: 'Pass', verdictClass: 'badge--success', agent: 'agt_edge_02', duration: '2m 09s' }
        ],
        findingIds: ['fnd_l7_8f3c', 'fnd_bgp_9a12', 'fnd_l7_2c93', 'fnd_bgp_5a08', 'fnd_hdr_7b56']
      },
      tgt_checkout_2: {
        id: 'tgt_checkout_2', targetGroup: 'edge-checkout', targetGroupId: 'tg_checkout', env: 'env_prod',
        kind: 'fqdn', value: 'pay.acme.com', expected: 'block_at_edge',
        verification: 'agent_verified', verificationClass: 'is-verified',
        verificationTitle: 'probe + agent correlated on agt_edge_01 · Jul 4',
        ownershipMethod: 'DNS TXT + agent callback', ownershipStatus: 'verified',
        dnsRecord: '_astranull-challenge.pay.acme.com', dnsValue: 'astranull=b7c3-2d40-9a1e-6f88',
        dnsStatus: 'resolved', dnsStatusClass: 'badge--success', dnsCheckedTs: 'Jul 4 · 09:12 UTC',
        agentBinding: 'agt_edge_01', agentBindingTs: '18s ago',
        loaState: 'signed', loaClass: 'badge--success',
        loaCustody: 'sha256:9f2a…c41e', loaSignedBy: 'Priya Menon · Head of Platform',
        loaSignedAt: '2026-07-04 09:14 UTC',
        testWindow: 'daily 04:00 · 04:00-04:30 UTC',
        eligibility: 'eligible', eligibilityClass: 'badge--success',
        eligibilityReason: 'ownership verified, LOA signed, in scope of test window',
        wafAssetId: 'waf_edge_checkout', wafVendor: 'cloudflare',
        wafPosture: 'protected', wafPostureClass: 'badge--success',
        wafDrift: '-', wafDriftClass: 'badge--muted',
        wafValidation: 'finalized', wafValidationClass: 'badge--success',
        wafConnector: 'healthy', wafConnectorClass: 'badge--success',
        wafFingerprint: 'passed', wafMarkerRules: '4/4 blocked',
        wafOriginBypass: 'not confirmed',
        wafNotes: 'Payment origin behind the same Cloudflare pool as checkout. Marker rules validated. No drift observed.',
        checks: [
          { id: 'chk_l7_rate', family: 'l7-api', bound: '50 RPS', lastRun: 'run_7a21', lastRunTs: '1d ago', verdict: 'Pass', verdictClass: 'badge--success', method: 'bounded 50 RPS · agent-corroborated' },
          { id: 'chk_origin_bypass', family: 'origin-bypass', bound: '50 RPS', lastRun: 'run_7a21', lastRunTs: '1d ago', verdict: 'Pass', verdictClass: 'badge--success', method: 'metadata-only · bounded 50 RPS' },
          { id: 'chk_l3_l4', family: 'l3-l4', bound: 'metadata', lastRun: 'run_7a21', lastRunTs: '1d ago', verdict: 'Pass', verdictClass: 'badge--success', method: 'metadata-only · single probe' }
        ],
        runs: [
          { id: 'run_7a21', policy: 'pol_edge_daily', started: '1d ago', verdict: 'Pass', verdictClass: 'badge--success', agent: 'agt_edge_01', duration: '2m 02s' },
          { id: 'run_5b09', policy: 'pol_edge_daily', started: '2d ago', verdict: 'Pass', verdictClass: 'badge--success', agent: 'agt_edge_02', duration: '2m 09s' }
        ],
        findingIds: ['fnd_waf_8b47']
      },
      tgt_checkout_3: {
        id: 'tgt_checkout_3', targetGroup: 'edge-checkout', targetGroupId: 'tg_checkout', env: 'env_prod',
        kind: 'tcp', value: '203.0.113.10:443', expected: 'absorb_at_origin',
        verification: 'pending_agent', verificationClass: 'is-partial',
        verificationTitle: 'DNS not applicable · awaiting agent heartbeat from this IP',
        ownershipMethod: 'Agent callback (IP)', ownershipStatus: 'awaiting',
        dnsRecord: 'n/a for IP target', dnsValue: 'n/a', dnsStatus: 'not applicable', dnsStatusClass: 'badge--muted', dnsCheckedTs: '-',
        agentBinding: 'not yet bound', agentBindingTs: '-',
        loaState: 'signed', loaClass: 'badge--success',
        loaCustody: 'sha256:9f2a…c41e', loaSignedBy: 'Priya Menon · Head of Platform',
        loaSignedAt: '2026-07-04 09:14 UTC',
        testWindow: 'daily 04:00 · 04:00-04:30 UTC',
        eligibility: 'not eligible', eligibilityClass: 'badge--warn',
        eligibilityReason: 'agent binding required for IP targets. Install an agent on the origin instance and wait for the outbound heartbeat.',
        wafAssetId: '', wafVendor: '',
        checks: [
          { id: 'chk_l3_l4', family: 'l3-l4', bound: 'metadata', lastRun: 'run_6d14', lastRunTs: '1d ago', verdict: 'Review', verdictClass: 'badge--warn', method: 'metadata-only · single probe' }
        ],
        runs: [
          { id: 'run_6d14', policy: 'pol_edge_daily', started: '1d ago', verdict: 'Review', verdictClass: 'badge--warn', agent: 'agt_edge_03', duration: '1m 48s' }
        ],
        findingIds: []
      },
      tgt_checkout_4: {
        id: 'tgt_checkout_4', targetGroup: 'edge-checkout', targetGroupId: 'tg_checkout', env: 'env_prod',
        kind: 'fqdn', value: 'cdn-checkout.acme.com', expected: 'rate_shape',
        verification: 'dns_verified', verificationClass: 'is-dns',
        verificationTitle: '_astranull-challenge TXT resolved · Jul 4',
        ownershipMethod: 'DNS TXT (agent binding optional)', ownershipStatus: 'dns verified',
        dnsRecord: '_astranull-challenge.cdn-checkout.acme.com', dnsValue: 'astranull=1e07-4a29-b7c5-0d3f',
        dnsStatus: 'resolved', dnsStatusClass: 'badge--success', dnsCheckedTs: 'Jul 4 · 09:12 UTC',
        agentBinding: 'not required (external only)', agentBindingTs: '-',
        loaState: 'signed', loaClass: 'badge--success',
        loaCustody: 'sha256:9f2a…c41e', loaSignedBy: 'Priya Menon · Head of Platform',
        loaSignedAt: '2026-07-04 09:14 UTC',
        testWindow: 'daily 04:00 · 04:00-04:30 UTC',
        eligibility: 'eligible', eligibilityClass: 'badge--success',
        eligibilityReason: 'DNS ownership proven, LOA signed, external-only validation allowed',
        wafAssetId: 'waf_edge_checkout', wafVendor: 'cloudflare',
        wafPosture: 'protected', wafPostureClass: 'badge--success',
        wafDrift: '-', wafDriftClass: 'badge--muted',
        wafValidation: 'finalized', wafValidationClass: 'badge--success',
        wafConnector: 'healthy', wafConnectorClass: 'badge--success',
        wafFingerprint: 'passed', wafMarkerRules: '3/3 rate-shaped',
        wafOriginBypass: 'not applicable',
        wafNotes: 'CDN-fronted static origin. Rate-shape expected; rate-limit marker rules validated.',
        checks: [
          { id: 'chk_l7_rate', family: 'l7-api', bound: '50 RPS', lastRun: 'run_7a21', lastRunTs: '1d ago', verdict: 'Pass', verdictClass: 'badge--success', method: 'bounded 50 RPS · rate-shape expected' }
        ],
        runs: [
          { id: 'run_7a21', policy: 'pol_edge_daily', started: '1d ago', verdict: 'Pass', verdictClass: 'badge--success', agent: 'agt_edge_01', duration: '2m 02s' }
        ],
        findingIds: []
      },
      tgt_checkout_5: {
        id: 'tgt_checkout_5', targetGroup: 'edge-checkout', targetGroupId: 'tg_checkout', env: 'env_prod',
        kind: 'fqdn', value: 'legacy-api.acme.com', expected: 'block_at_edge',
        verification: 'unverified', verificationClass: 'is-unverified',
        verificationTitle: 'No TXT record resolved · no agent has bound this target',
        ownershipMethod: 'DNS TXT + agent callback', ownershipStatus: 'unverified',
        dnsRecord: '_astranull-challenge.legacy-api.acme.com', dnsValue: 'astranull=44b1-9c02-e5f7-a218',
        dnsStatus: 'pending', dnsStatusClass: 'badge--warn', dnsCheckedTs: 'never resolved',
        agentBinding: 'not yet bound', agentBindingTs: '-',
        loaState: 'signed', loaClass: 'badge--success',
        loaCustody: 'sha256:9f2a…c41e', loaSignedBy: 'Priya Menon · Head of Platform',
        loaSignedAt: '2026-07-04 09:14 UTC',
        testWindow: 'daily 04:00 · 04:00-04:30 UTC',
        eligibility: 'not eligible', eligibilityClass: 'badge--danger',
        eligibilityReason: 'ownership not proven. Publish the DNS TXT record or bind an agent, then re-verify. Group LOA already covers this target once ownership is proven.',
        wafAssetId: '', wafVendor: '',
        checks: [],
        runs: [],
        findingIds: []
      }
    },
    runs: {
      run_8f3c: { id: 'run_8f3c', targetGroup: 'edge-checkout', checks: '4', verdict: 'Gap', verdictClass: 'badge--danger', duration: '2m 14s', agent: 'agt_edge_01', started: '2h ago', probe: 'probe-eu-west-2', boundRps: '50 RPS', originMs: '47 ms', scrubberBypassed: 'true', policy: 'pol_edge_daily' },
      run_7a21: { id: 'run_7a21', targetGroup: 'edge-checkout', checks: '4', verdict: 'Pass', verdictClass: 'badge--success', duration: '2m 02s', agent: 'agt_edge_01', started: '1d ago', probe: 'probe-eu-west-2', boundRps: '50 RPS', originMs: '-', scrubberBypassed: 'false', policy: 'pol_edge_daily' },
      run_6d14: { id: 'run_6d14', targetGroup: 'media-origin', checks: '3', verdict: 'Review', verdictClass: 'badge--warn', duration: '1m 48s', agent: 'agt_edge_03', started: '1d ago', probe: 'probe-us-east-1', boundRps: '50 RPS', originMs: '-', scrubberBypassed: 'partial', policy: 'pol_media_weekly' },
      run_5b09: { id: 'run_5b09', targetGroup: 'api-public', checks: '4', verdict: 'Pass', verdictClass: 'badge--success', duration: '2m 09s', agent: 'agt_edge_02', started: '2d ago', probe: 'probe-eu-west-2', boundRps: '50 RPS', originMs: '-', scrubberBypassed: 'false', policy: 'pol_edge_daily' }
    },
    checks: {
      chk_origin_bypass: { id: 'chk_origin_bypass', family: 'origin-bypass', mode: 'safe', modeClass: 'badge--success', bound: '50 RPS', verdict: 'Pass', verdictClass: 'badge--success', description: 'Detects whether a bounded probe can reach the origin while the scrubber tier is declared active.', method: 'metadata-only · bounded 50 RPS · single probe', lastRun: 'run_5b09' },
      chk_l3_l4: { id: 'chk_l3_l4', family: 'l3-l4', mode: 'safe', modeClass: 'badge--success', bound: 'metadata', verdict: 'Pass', verdictClass: 'badge--success', description: 'Correlates edge ACL posture with observed L3/L4 protection headers.', method: 'metadata-only · single probe', lastRun: 'run_5b09' },
      chk_dns_shadow: { id: 'chk_dns_shadow', family: 'dns', mode: 'safe', modeClass: 'badge--success', bound: 'metadata', verdict: 'Review', verdictClass: 'badge--warn', description: 'Enumerates declared DNS records vs. authoritative zone for shadow subdomain risk.', method: 'zone-diff · passive DNS', lastRun: 'run_6d14' },
      chk_l7_rate: { id: 'chk_l7_rate', family: 'l7-api', mode: 'safe', modeClass: 'badge--success', bound: '50 RPS', verdict: 'Gap', verdictClass: 'badge--danger', description: 'Sends a bounded 50 RPS probe against declared API endpoints and correlates against agent observation.', method: 'bounded 50 RPS · agent-corroborated', lastRun: 'run_8f3c' },
      scn_high_volume: { id: 'scn_high_volume', family: 'high-scale', mode: 'SOC-gated', modeClass: 'badge--accent', bound: '≥40k RPS', verdict: 'request', verdictClass: 'badge--muted', description: 'High-scale scenario. Requires SOC approval and a complete authorization pack.', method: 'partner_adapter or provider_fire_drill', lastRun: '-' }
    },
    policies: {
      pol_edge_daily: { id: 'pol_edge_daily', targets: 'edge-checkout, api-public', cadence: 'daily 04:00', window: '04:00–04:30', expected: 'Pass', expectedClass: 'badge--success', gated: 'false', owner: 'edge-sre', description: 'Daily bounded probe against edge-fronted business services during the declared safe window.' },
      pol_dns_weekly: { id: 'pol_dns_weekly', targets: 'dns-zone-root', cadence: 'weekly', window: 'Sun 02:00', expected: 'Review', expectedClass: 'badge--warn', gated: 'false', owner: 'platform', description: 'Weekly zone-diff review for shadow subdomains. Metadata-only.' },
      pol_highscale_q: { id: 'pol_highscale_q', targets: 'media-origin', cadence: 'quarterly', window: 'SOC-scheduled', expected: 'SOC-gated', expectedClass: 'badge--accent', gated: 'true', owner: 'sre', description: 'Governed quarterly high-scale rehearsal. Not customer-executable. SOC schedules.' }
    },
    findings: {
      fnd_l7_8f3c: { id: 'fnd_l7_8f3c', title: 'Origin exposed under bounded load', check: 'chk_l7_rate', severity: 'S2', severityClass: 'badge--danger', verdict: 'Gap', verdictClass: 'badge--danger', targetGroup: 'edge-checkout', owner: 'edge-sre', state: 'open', stateClass: 'badge--warn', run: 'run_8f3c', opened: '2026-07-04 14:32', openedTs: 1751639520000, sla: '2d 4h remaining', slaHours: 52, description: 'A bounded 50 RPS probe reached the origin at 47 ms while the scrubber tier was bypassed; agent agt_edge_01 independently observed the direct-to-origin path.', remAction: 'origin_restrict', remOwner: 'edge-sre', remState: 'remediation_pending', remStateClass: 'badge--warn', remSla: '2d 4h remaining', remDescription: 'Restrict origin ingress to the scrubber egress ranges so the direct-to-origin path is closed.', remSteps: 'Update origin firewall ACL to allow only scrubber egress CIDRs.|Remove /24 public allow on the checkout origin group.|Rerun chk_l7_rate at 50 RPS to confirm the direct path is closed.' },
      fnd_dns_6d14: { id: 'fnd_dns_6d14', title: 'DNS shadow subdomain reachable', check: 'chk_dns_shadow', severity: 'S3', severityClass: 'badge--warn', verdict: 'Review', verdictClass: 'badge--warn', targetGroup: 'dns-zone-root', owner: 'platform', state: 'open', stateClass: 'badge--warn', run: 'run_6d14', opened: '2026-07-03 09:11', openedTs: 1751533860000, sla: '5d 6h remaining', slaHours: 126, description: 'A zone-diff surfaced an authoritative record that is not declared in the customer inventory.', remAction: 'declare_or_retire', remOwner: 'platform', remState: 'remediation_pending', remStateClass: 'badge--warn', remSla: '5d 6h remaining', remDescription: 'Reconcile the undeclared authoritative record. Declare it into scope or retire it from the zone.', remSteps: 'Confirm ownership of the shadow subdomain with the responsible team.|Add to declared inventory OR delete the record with a 300s TTL.|Rerun chk_dns_shadow to close.' },
      fnd_waf_5b09: { id: 'fnd_waf_5b09', title: 'WAF rule exception too broad', check: 'waf-bypass', severity: 'S3', severityClass: 'badge--warn', verdict: 'Review', verdictClass: 'badge--warn', targetGroup: 'media-origin', owner: 'edge-sre', state: 'open', stateClass: 'badge--warn', run: 'run_5b09', opened: '2026-07-02 16:48', openedTs: 1751474880000, sla: '4d 12h remaining', slaHours: 108, description: 'A declared WAF exception matches a wildcard path segment; the fingerprint check finalized but drift is present.', remAction: 'tighten_waf_exception', remOwner: 'edge-sre', remState: 'remediation_pending', remStateClass: 'badge--warn', remSla: '4d 12h remaining', remDescription: 'Narrow the WAF exception match so it does not wildcard-match unrelated paths.', remSteps: 'Change the exception match from prefix wildcard to exact path.|Add a scoped test rule; run chk_waf_fingerprint in dry-run.|Promote to enforce after 24h clean window.' },
      fnd_org_4c77: { id: 'fnd_org_4c77', title: 'Origin IP on cloud baseline', check: 'chk_origin_bypass', severity: 'S2', severityClass: 'badge--danger', verdict: 'Gap', verdictClass: 'badge--danger', targetGroup: 'api-public', owner: 'unassigned', state: 'open', stateClass: 'badge--warn', run: 'run_4c77', opened: '2026-07-01 11:04', openedTs: 1751367840000, sla: 'overdue', slaHours: -8, description: 'A bounded probe reached the origin on the vendor cloud baseline range while the API declares scrubber-only ingress.', remAction: 'origin_restrict_or_replace', remOwner: 'platform', remState: 'remediation_pending', remStateClass: 'badge--danger', remSla: 'overdue', remDescription: 'Take the API origin off the vendor cloud baseline range OR restrict ingress so the baseline range cannot reach it.', remSteps: 'Move the origin to a customer-owned range OR add scrubber-only ingress ACL.|Rotate the origin cert if the IP changed.|Rerun chk_origin_bypass to close.' },
      fnd_bgp_9a12: { id: 'fnd_bgp_9a12', title: 'BGP route leak on secondary transit', check: 'chk_bgp_leak', severity: 'S1', severityClass: 'badge--danger', verdict: 'Gap', verdictClass: 'badge--danger', targetGroup: 'edge-checkout', owner: 'network', state: 'open', stateClass: 'badge--warn', run: 'run_9a12', opened: '2026-07-05 03:22', openedTs: 1751685720000, sla: '18h remaining', slaHours: 18, description: 'A secondary transit briefly announced a shorter path for the checkout prefix; scrubber egress ACL held but the advertisement is uncorrected.', remAction: 'withdraw_leaked_advertisement', remOwner: 'network', remState: 'remediation_pending', remStateClass: 'badge--danger', remSla: '18h remaining', remDescription: 'Withdraw the leaked advertisement on the secondary transit and add an inbound filter to prevent recurrence.', remSteps: 'Coordinate with the secondary transit NOC to withdraw the prefix.|Add an inbound AS-path filter on the primary transit session.|Rerun chk_bgp_leak once the RIB clears.' },
      fnd_tls_2e45: { id: 'fnd_tls_2e45', title: 'TLS session tickets not rotated', check: 'chk_tls_rotate', severity: 'S4', severityClass: 'badge--muted', verdict: 'Info', verdictClass: 'badge--muted', targetGroup: 'api-public', owner: 'platform', state: 'open', stateClass: 'badge--warn', run: 'run_2e45', opened: '2026-06-30 08:15', openedTs: 1751271300000, sla: '9d 2h remaining', slaHours: 218, description: 'STEK rotation last observed 14 days ago; policy target is 7 days. Informational, no exposure.', remAction: 'enable_stek_rotation', remOwner: 'platform', remState: 'remediation_pending', remStateClass: 'badge--muted', remSla: '9d 2h remaining', remDescription: 'Rotate TLS session tickets on a 7-day cadence per policy.', remSteps: 'Enable automated STEK rotation with a 7-day interval.|Verify rotation via chk_tls_rotate on the next cycle.|Document the rotation window in the runbook.' },
      fnd_rate_7c81: { id: 'fnd_rate_7c81', title: 'Rate-limit disabled on /health endpoint', check: 'chk_l7_rate', severity: 'S3', severityClass: 'badge--warn', verdict: 'Review', verdictClass: 'badge--warn', targetGroup: 'api-public', owner: 'edge-sre', state: 'accepted', stateClass: 'badge--muted', run: 'run_7c81', opened: '2026-06-28 12:00', openedTs: 1751097600000, closed: '2026-06-29 10:04', closedTs: 1751191440000, sla: 'accepted risk', slaHours: 0, description: 'Owner accepted the risk of an unrated /health endpoint for load-balancer probes. Documented exception with quarterly review.', remAction: 'rate_limit_documented', remOwner: 'edge-sre', remState: 'accepted_risk', remStateClass: 'badge--muted', remSla: '-', remDescription: 'Owner accepted the unrated /health endpoint under a documented exception; quarterly review scheduled.', remSteps: 'Owner declaration on file; custody digest sealed.|Quarterly review scheduled at 2026-09-28.|No action required until review.' },
      fnd_hdr_3d92: { id: 'fnd_hdr_3d92', title: 'Missing HSTS on marketing subdomain', check: 'chk_headers', severity: 'S4', severityClass: 'badge--muted', verdict: 'Info', verdictClass: 'badge--muted', targetGroup: 'marketing-web', owner: 'platform', state: 'closed', stateClass: 'badge--success', run: 'run_3d92', opened: '2026-06-24 15:41', openedTs: 1750779660000, closed: '2026-06-27 09:12', closedTs: 1751022720000, sla: 'closed in 2d 17h', slaHours: 0, description: 'HSTS was added to the marketing subdomain and re-verified with chk_headers on 06-27.', remAction: 'hsts_enabled', remOwner: 'platform', remState: 'resolved', remStateClass: 'badge--success', remSla: 'closed in 2d 17h', remDescription: 'HSTS added to the marketing subdomain and re-verified with chk_headers on 06-27.', remSteps: 'HSTS header enabled on origin.|CDN cache purged.|chk_headers re-run · pass.' },
      fnd_dns_1f08: { id: 'fnd_dns_1f08', title: 'CAA record missing for apex', check: 'chk_dns_caa', severity: 'S3', severityClass: 'badge--warn', verdict: 'Review', verdictClass: 'badge--warn', targetGroup: 'dns-zone-root', owner: 'platform', state: 'closed', stateClass: 'badge--success', run: 'run_1f08', opened: '2026-06-20 11:22', openedTs: 1750418520000, closed: '2026-06-22 14:03', closedTs: 1750604580000, sla: 'closed in 2d 3h', slaHours: 0, description: 'CAA record set for the apex and one wildcard delegation. Re-verified on 06-22.', remAction: 'caa_added', remOwner: 'platform', remState: 'resolved', remStateClass: 'badge--success', remSla: 'closed in 2d 3h', remDescription: 'CAA record set for the apex and one wildcard delegation. Re-verified on 06-22.', remSteps: 'CAA record added at apex with issuer allowlist.|Wildcard delegation covered.|chk_dns_caa re-run · pass.' },
      fnd_waf_8b47: { id: 'fnd_waf_8b47', title: 'WAF managed-rule set out of date', check: 'chk_waf_fingerprint', severity: 'S3', severityClass: 'badge--warn', verdict: 'Review', verdictClass: 'badge--warn', targetGroup: 'edge-checkout', owner: 'edge-sre', state: 'closed', stateClass: 'badge--success', run: 'run_8b47', opened: '2026-06-18 07:03', openedTs: 1750230180000, closed: '2026-06-20 18:52', closedTs: 1750450320000, sla: 'closed in 2d 12h', slaHours: 0, description: 'Managed rule set upgraded to v2026.06 and fingerprint re-baselined.', remAction: 'ruleset_upgraded', remOwner: 'edge-sre', remState: 'resolved', remStateClass: 'badge--success', remSla: 'closed in 2d 12h', remDescription: 'Managed rule set upgraded to v2026.06 and fingerprint re-baselined.', remSteps: 'Managed ruleset upgraded to v2026.06 via connector.|Fingerprint re-baselined on the edge pool.|chk_waf_fingerprint re-run · pass.' },
      fnd_l7_2c93: { id: 'fnd_l7_2c93', title: 'Backend timeout below scrubber advisory', check: 'chk_l7_timeout', severity: 'S2', severityClass: 'badge--danger', verdict: 'Gap', verdictClass: 'badge--danger', targetGroup: 'edge-checkout', owner: 'edge-sre', state: 'closed', stateClass: 'badge--success', run: 'run_2c93', opened: '2026-06-15 20:11', openedTs: 1749989460000, closed: '2026-06-16 09:22', closedTs: 1750037520000, sla: 'closed in 13h', slaHours: 0, description: 'Backend timeout raised from 4s to 12s per scrubber advisory. Retested with bounded probe.', remAction: 'backend_timeout_raised', remOwner: 'edge-sre', remState: 'resolved', remStateClass: 'badge--success', remSla: 'closed in 13h', remDescription: 'Backend timeout raised from 4s to 12s per scrubber advisory. Retested with bounded probe.', remSteps: 'Origin backend_read_timeout raised 4s → 12s.|Load balancer idle timeout aligned.|chk_l7_timeout re-run · pass.' },
      fnd_org_6e15: { id: 'fnd_org_6e15', title: 'Origin health endpoint public', check: 'chk_origin_bypass', severity: 'S3', severityClass: 'badge--warn', verdict: 'Review', verdictClass: 'badge--warn', targetGroup: 'media-origin', owner: 'platform', state: 'closed', stateClass: 'badge--success', run: 'run_6e15', opened: '2026-06-12 13:44', openedTs: 1749727440000, closed: '2026-06-13 08:10', closedTs: 1749795000000, sla: 'closed in 18h', slaHours: 0, description: 'Health endpoint moved behind an internal ACL; verified via agent agt_media_02.', remAction: 'health_endpoint_gated', remOwner: 'platform', remState: 'resolved', remStateClass: 'badge--success', remSla: 'closed in 18h', remDescription: 'Health endpoint moved behind an internal ACL; verified via agent agt_media_02.', remSteps: '/health moved to internal-only ACL.|Public path removed at edge.|Agent agt_media_02 confirmed reachability change.' },
      fnd_dns_9d31: { id: 'fnd_dns_9d31', title: 'NS record pointed to decommissioned resolver', check: 'chk_dns_shadow', severity: 'S2', severityClass: 'badge--danger', verdict: 'Gap', verdictClass: 'badge--danger', targetGroup: 'dns-zone-root', owner: 'platform', state: 'closed', stateClass: 'badge--success', run: 'run_9d31', opened: '2026-06-08 05:29', openedTs: 1749360540000, closed: '2026-06-08 18:47', closedTs: 1749408420000, sla: 'closed in 13h', slaHours: 0, description: 'NS record updated within same day; downstream caches flushed after TTL window.', remAction: 'ns_record_updated', remOwner: 'platform', remState: 'resolved', remStateClass: 'badge--success', remSla: 'closed in 13h', remDescription: 'NS record updated within same day; downstream caches flushed after TTL window.', remSteps: 'Zone NS updated to the current resolver pair.|Registrar glue updated.|TTL 300s · downstream caches confirmed.' },
      fnd_rate_4f22: { id: 'fnd_rate_4f22', title: 'Login endpoint rate-limit too permissive', check: 'chk_l7_rate', severity: 'S3', severityClass: 'badge--warn', verdict: 'Review', verdictClass: 'badge--warn', targetGroup: 'api-public', owner: 'edge-sre', state: 'accepted', stateClass: 'badge--muted', run: 'run_4f22', opened: '2026-06-04 10:12', openedTs: 1749032520000, closed: '2026-06-05 15:00', closedTs: 1749139200000, sla: 'accepted risk', slaHours: 0, description: 'Rate-limit tuning left as-is pending product decision on lockout UX. Reviewed quarterly.', remAction: 'rate_limit_accepted', remOwner: 'edge-sre', remState: 'accepted_risk', remStateClass: 'badge--muted', remSla: '-', remDescription: 'Rate-limit tuning left as-is pending product decision on lockout UX. Reviewed quarterly.', remSteps: 'Product owner accepted current rate-limit floor.|Quarterly review scheduled 2026-09-04.|Rerun chk_l7_rate on the next cycle.' },
      fnd_bgp_5a08: { id: 'fnd_bgp_5a08', title: 'RPKI validation misconfigured on primary transit', check: 'chk_bgp_rpki', severity: 'S1', severityClass: 'badge--danger', verdict: 'Gap', verdictClass: 'badge--danger', targetGroup: 'edge-checkout', owner: 'network', state: 'closed', stateClass: 'badge--success', run: 'run_5a08', opened: '2026-06-01 22:03', openedTs: 1748815380000, closed: '2026-06-02 11:16', closedTs: 1748863020000, sla: 'closed in 13h', slaHours: 0, description: 'RPKI ROV enabled on the primary transit session; verified via BGP monitor.', remAction: 'rpki_rov_enabled', remOwner: 'network', remState: 'resolved', remStateClass: 'badge--success', remSla: 'closed in 13h', remDescription: 'RPKI ROV enabled on the primary transit session; verified via BGP monitor.', remSteps: 'RPKI ROV enabled on primary transit peer.|ROAs published for owned prefixes.|BGP monitor confirms invalids dropped.' },
      fnd_hdr_7b56: { id: 'fnd_hdr_7b56', title: 'CSP report-only on payment origin', check: 'chk_headers', severity: 'S3', severityClass: 'badge--warn', verdict: 'Review', verdictClass: 'badge--warn', targetGroup: 'edge-checkout', owner: 'platform', state: 'closed', stateClass: 'badge--success', run: 'run_7b56', opened: '2026-05-28 14:44', openedTs: 1748443440000, closed: '2026-05-30 09:00', closedTs: 1748595600000, sla: 'closed in 1d 18h', slaHours: 0, description: 'CSP moved to enforce mode; report-only violations dropped to zero over 48h.', remAction: 'csp_enforced', remOwner: 'platform', remState: 'resolved', remStateClass: 'badge--success', remSla: 'closed in 1d 18h', remDescription: 'CSP moved to enforce mode; report-only violations dropped to zero over 48h.', remSteps: 'CSP moved from report-only to enforce.|Violation endpoint tail 48h clean.|chk_headers re-run · pass.' },
      fnd_waf_2d18: { id: 'fnd_waf_2d18', title: 'Bot management ruleset in learning mode', check: 'chk_waf_fingerprint', severity: 'S4', severityClass: 'badge--muted', verdict: 'Info', verdictClass: 'badge--muted', targetGroup: 'marketing-web', owner: 'edge-sre', state: 'accepted', stateClass: 'badge--muted', run: 'run_2d18', opened: '2026-05-22 08:00', openedTs: 1747900800000, closed: '2026-05-23 12:30', closedTs: 1748003400000, sla: 'accepted risk', slaHours: 0, description: 'Learning mode retained for the marketing site during campaign; risk documented until next quarter.', remAction: 'learning_mode_accepted', remOwner: 'edge-sre', remState: 'accepted_risk', remStateClass: 'badge--muted', remSla: '-', remDescription: 'Learning mode retained for the marketing site during campaign; risk documented until next quarter.', remSteps: 'Campaign owner declaration on file.|Learning mode retained until 2026-08-22.|Auto-promotion to enforce queued for next quarter.' }
    },
    artifacts: {
      art_probe_8f3c:   { id: 'art_probe_8f3c',   kind: 'probe-result',      run: 'run_8f3c', sha256: '9f2a…c41e', sealed: '2026-07-04 14:32', size: '4.1 KB',  finding: 'fnd_l7_8f3c', description: 'Outside probe result. Metadata-only.' },
      art_agent_8f3c:   { id: 'art_agent_8f3c',   kind: 'agent-observation', run: 'run_8f3c', sha256: '4c1b…e7a9', sealed: '2026-07-04 14:32', size: '3.7 KB',  finding: 'fnd_l7_8f3c', description: 'Inside agent observation. Correlated with the probe.' },
      art_verdict_8f3c: { id: 'art_verdict_8f3c', kind: 'verdict',           run: 'run_8f3c', sha256: 'b8d0…3f12', sealed: '2026-07-04 14:32', size: '2.2 KB',  finding: 'fnd_l7_8f3c', description: 'Verdict artifact · evidence-backed conclusion.' },
      art_bundle_8f3c:  { id: 'art_bundle_8f3c',  kind: 'evidence-bundle',   run: 'run_8f3c', sha256: '11a7…9d4c', sealed: '2026-07-04 14:33', size: '10.0 KB', finding: 'fnd_l7_8f3c', description: 'Sealed bundle of probe + agent + verdict for auditor export.' }
    },
    wafAssets: {
      waf_edge_checkout: { id: 'waf_edge_checkout', vendor: 'cloudflare', posture: 'protected',       postureClass: 'badge--success', drift: '-',                             validation: 'finalized', connector: 'healthy',  connectorClass: 'badge--success', targetGroup: 'edge-checkout', description: 'Declared WAF pool fronting the checkout target group. Fingerprint check finalized on the last run.' },
      waf_edge_media:    { id: 'waf_edge_media',    vendor: 'akamai',     posture: 'underprotected', postureClass: 'badge--warn',    drift: 'origin_bypass_confirmed',      validation: 'finalized', connector: 'degraded', connectorClass: 'badge--warn',    targetGroup: 'media-origin',  description: 'Drift observed: origin reached under bounded probe. Fingerprint validation ok, coverage not.' },
      waf_edge_api:      { id: 'waf_edge_api',      vendor: 'cloudflare', posture: 'underprotected', postureClass: 'badge--warn',    drift: 'policy_exception_active',      validation: 'finalized', connector: 'healthy',  connectorClass: 'badge--success', targetGroup: 'api-public',    description: 'A broad rate-limit exception is in force. Not a WAF outage · a declared policy carve-out.' },
      waf_edge_dns:      { id: 'waf_edge_dns',      vendor: 'aws',        posture: 'protected',       postureClass: 'badge--success', drift: '-',                             validation: 'finalized', connector: 'healthy',  connectorClass: 'badge--success', targetGroup: 'dns-zone-root', description: 'Route53 + Shield Advanced. Coverage finalized; no drift.' },
      waf_edge_internal: { id: 'waf_edge_internal', vendor: 'generic',    posture: 'unprotected',     postureClass: 'badge--danger',  drift: 'waf_fingerprint_lost',         validation: 'failed',    connector: 'unknown',  connectorClass: 'badge--muted',   targetGroup: 'internal',      description: 'Fingerprint check failed · asset may be behind an unmanaged edge or is fronting nothing.' },
      waf_edge_failover: { id: 'waf_edge_failover', vendor: 'fortinet',   posture: 'excluded',        postureClass: 'badge--muted',   drift: 'customer-declared',            validation: 'planned',   connector: 'disabled', connectorClass: 'badge--muted',   targetGroup: 'failover-edge', description: 'Excluded by customer declaration · not audited by AstraNull until re-enabled.' }
    },
    queueItems: {
      hsr_9c2a: { id: 'hsr_9c2a', adapter: 'partner_adapter',     telemetry: 'healthy · 0 runs',    state: 'soc_review',   stateClass: 'badge--warn',    action: 'Awaiting pack acceptance', drillFresh: 'no',  observerOncall: 'yes', description: 'Waiting on pack acceptance before SOC approval. Adapter healthy.' },
      hsr_8d11: { id: 'hsr_8d11', adapter: 'provider_fire_drill', telemetry: 'healthy · armed',     state: 'scheduled',    stateClass: 'badge--accent',  action: 'Execute at window',        drillFresh: 'yes', observerOncall: 'yes', description: 'Scheduled and armed. Kill switch drill fresh; observer on-call.' },
      hsr_7f04: { id: 'hsr_7f04', adapter: 'internal_lab',        telemetry: 'idle',                state: 'submitted',    stateClass: 'badge--muted',   action: 'Awaiting pack',            drillFresh: 'no',  observerOncall: 'no',  description: 'Idle. Nothing to execute until pack is filed and approved.' }
    },
    reports: {
      rpt_4a8c: { id: 'rpt_4a8c', title: 'Executive readiness · 2026 Q2', kind: 'executive',   status: 'ready',   statusClass: 'badge--success', format: 'html',     period: '2026 Q2',  readiness: 78, openFindings: 4, generated: '2d ago',  generated_at: '2026-07-04 09:12', custodySha: '4a8c…7e21', schema: 'report.v1', artifactId: 'art_rpt_4a8c', description: 'Executive summary of tenant readiness posture for the quarter. Readiness score, open findings, and coverage by surface.' },
      rpt_3b21: { id: 'rpt_3b21', title: 'Audit trail export · Jun 2026', kind: 'audit',       status: 'ready',   statusClass: 'badge--success', format: 'json',     period: 'Jun 2026', readiness: 0,  openFindings: 0, generated: '1w ago',  generated_at: '2026-06-29 16:40', custodySha: '3b21…0a55', schema: 'report.v1', artifactId: 'art_rpt_3b21', description: 'Append-only audit trail export with custody-chain digests for the period. Suitable for external auditor hand-off.' },
      rpt_2c77: { id: 'rpt_2c77', title: 'SOC 2 evidence bundle · H1 2026', kind: 'soc2',       status: 'review',  statusClass: 'badge--warn',    format: 'markdown', period: 'H1 2026',  readiness: 0,  openFindings: 0, generated: '2w ago',  generated_at: '2026-06-22 11:05', custodySha: '2c77…9d3a', schema: 'report.v1', artifactId: 'art_rpt_2c77', description: 'SOC 2 Type II evidence bundle. Marked review · two attestation kinds still in gap state pending operator sign-off.' },
      rpt_9f02: { id: 'rpt_9f02', title: 'Technical findings digest · Jul 2026', kind: 'technical', status: 'ready', statusClass: 'badge--success', format: 'json',   period: 'Jul 2026', readiness: 0,  openFindings: 4, generated: '3w ago',  generated_at: '2026-06-15 08:30', custodySha: '9f02…1b7e', schema: 'report.v1', artifactId: 'art_rpt_9f02', description: 'Per-finding technical digest with probe + agent correlation metadata. Custody-sealed at generation.' },
      rpt_1e6b: { id: 'rpt_1e6b', title: 'Board readiness brief · Q2 2026', kind: 'board',      status: 'draft',   statusClass: 'badge--muted',   format: 'html',     period: '2026 Q2',  readiness: 0,  openFindings: 0, generated: '4w ago',  generated_at: '2026-06-08 14:00', custodySha: '1e6b…c4d2', schema: 'report.v1', artifactId: 'art_rpt_1e6b', description: 'Board brief draft. Not yet custody-sealed · pending review sign-off before delivery.' }
    },
    tenants: {
      ten_demo:      { id: 'ten_demo',      name: 'acme-prod',   lifecycle: 'active',       lifecycleClass: 'badge--success', plan: 'professional', region: 'us',   agents: '4', groups: '6', findings: '4', ownerUsers: '3', mrr: '$4,800', createdAt: '2025-11-02', lastActive: '2m ago',  lifecycleNote: 'Healthy tenant. Safe-check volume normal; no open SOC escalations.' },
      ten_northwind: { id: 'ten_northwind', name: 'Northwind',   lifecycle: 'provisioning', lifecycleClass: 'badge--warn',    plan: 'professional', region: 'eu',   agents: '0', groups: '0', findings: '0', ownerUsers: '1', mrr: '-',      createdAt: '2026-07-03', lastActive: '1h ago',  lifecycleNote: 'Sign-up approved; first agent enrollment pending. Setup progress tracked on the Agents page.' },
      ten_orbital:   { id: 'ten_orbital',   name: 'Orbital',     lifecycle: 'suspended',    lifecycleClass: 'badge--danger',   plan: 'starter',      region: 'apac', agents: '1', groups: '2', findings: '0', ownerUsers: '2', mrr: '$640',    createdAt: '2026-02-18', lastActive: '9d ago',  lifecycleNote: 'Suspended for non-payment. Evidence retained for the audit window; no data purged.' },
      ten_vela:      { id: 'ten_vela',      name: 'Vela Labs',   lifecycle: 'active',       lifecycleClass: 'badge--success',  plan: 'enterprise',   region: 'us',   agents: '9', groups: '14', findings: '2', ownerUsers: '5', mrr: '$18,500', createdAt: '2025-08-21', lastActive: '5m ago',  lifecycleNote: 'Enterprise tenant. High-scale rehearsal cadence quarterly; kill-switch drill current.' },
      ten_harbor:    { id: 'ten_harbor',    name: 'Harbor Edge', lifecycle: 'active',       lifecycleClass: 'badge--success',  plan: 'professional', region: 'uk',   agents: '3', groups: '5', findings: '1', ownerUsers: '2', mrr: '$4,800', createdAt: '2026-01-12', lastActive: '1d ago',  lifecycleNote: 'Active tenant. One aging S3 finding under remediation review.' }
    }
  };
  var DETAIL_DEFAULTS = {
    'agent-detail':        'agt_edge_01',
    'environment-detail':  'env_prod',
    'target-group-detail': 'tg_checkout',
    'target-detail':       'tgt_checkout_1',
    'run-detail':          'run_8f3c',
    'check-detail':        'chk_l7_rate',
    'policy-detail':       'pol_edge_daily',
    'finding-detail':      'fnd_l7_8f3c',
    'queue-detail':        'hsr_9c2a',
    'report-detail':       'rpt_4a8c',
    'tenant-detail':       'ten_demo'
  };

  function navEl(id) { return document.querySelector('.nav-item[data-route="' + id + '"]'); }

  function populateDetail(route, entityId) {
    var meta = DETAIL_ROUTES[route];
    if (!meta) return;
    var data = (ENTITIES[meta.store] || {})[entityId];
    if (!data) return;
    var screen = document.getElementById('screen-' + route);
    if (!screen) return;
    screen.setAttribute('data-active-entity', entityId);
    screen.querySelectorAll('[data-detail]').forEach(function (node) {
      var key = node.getAttribute('data-detail');
      var val = data[key];
      if (val == null) return;
      var kind = node.getAttribute('data-detail-kind');
      if (kind === 'badge') {
        node.className = 'badge ' + (data[key + 'Class'] || 'badge--muted');
        node.textContent = val;
      } else if (kind === 'steps') {
        // Pipe-separated steps → ordered list <li> items with mono step number
        var parts = String(val).split('|').map(function (s) { return s.trim(); }).filter(Boolean);
        node.innerHTML = '';
        parts.forEach(function (step, i) {
          var li = document.createElement('li');
          li.className = 'rem-step';
          var num = document.createElement('span');
          num.className = 'rem-step-num';
          num.textContent = String(i + 1).padStart(2, '0');
          var txt = document.createElement('span');
          txt.className = 'rem-step-text';
          txt.textContent = step;
          li.appendChild(num);
          li.appendChild(txt);
          node.appendChild(li);
        });
      } else {
        node.textContent = val;
      }
    });
  }

  function populateTargetDetail(entityId) {
    var data = (ENTITIES.targets || {})[entityId];
    if (!data) return;
    var screen = document.getElementById('screen-target-detail');
    if (!screen) return;
    screen.setAttribute('data-active-entity', entityId);

    function q(td) { return screen.querySelector('[data-td="' + td + '"]'); }
    function setText(td, val) { var n = q(td); if (n && val != null) n.textContent = val; }
    function setBadge(td, val, cls) { var n = q(td); if (n && val != null) { n.className = 'badge ' + (cls || 'badge--muted'); n.textContent = val; } }
    function setAttr(td, attr, val) { var n = q(td); if (n && val != null) n.setAttribute(attr, val); }

    // Page header
    setText('value', data.value);
    setText('kind', data.kind);
    setText('expected', data.expected);
    setText('tgName', data.targetGroup);
    setAttr('tgLink', 'data-entity', data.targetGroupId);

    // Verify chip
    var chipEl = q('verifyChip');
    if (chipEl) {
      chipEl.classList.remove('is-verified', 'is-partial', 'is-dns', 'is-unverified');
      if (data.verificationClass) chipEl.classList.add(data.verificationClass);
      if (data.verificationTitle) chipEl.setAttribute('title', data.verificationTitle);
    }
    setText('verifyLabel', data.verification);

    // Eligibility
    setBadge('eligibilityChip', data.eligibility, data.eligibilityClass);
    setBadge('eligibilityChip2', data.eligibility, data.eligibilityClass);
    setText('eligibilityReason', data.eligibilityReason);

    // Ownership panel
    setText('ownershipMethod', data.ownershipMethod);
    setText('ownershipMethod2', data.ownershipMethod);
    setBadge('ownershipStatusChip', data.ownershipStatus, data.dnsStatusClass);
    setText('dnsRecord', data.dnsRecord);
    setText('dnsValue', data.dnsValue);
    setBadge('dnsStatusChip', data.dnsStatus, data.dnsStatusClass);
    setText('dnsCheckedTs', data.dnsCheckedTs);
    setText('agentBinding', data.agentBinding);
    setText('agentBindingTs', data.agentBindingTs);
    setBadge('loaChip', data.loaState, data.loaClass);
    setText('loaCustody', data.loaCustody);
    setText('loaSignedBy', data.loaSignedBy);
    setText('loaSignedAt', data.loaSignedAt);
    setText('testWindow', data.testWindow);

    // WAF panel + raw context code block
    var wafPanel = screen.querySelector('#target-waf-panel');
    if (wafPanel) {
      if (data.wafAssetId) {
        wafPanel.style.display = '';
        setText('wafVendor', data.wafVendor);
        setText('wafAssetId', data.wafAssetId);
        setBadge('wafPostureChip', data.wafPosture, data.wafPostureClass);
        setText('wafDrift', data.wafDrift);
        setBadge('wafValidationChip', data.wafValidation, data.wafValidationClass);
        setBadge('wafConnectorChip', data.wafConnector, data.wafConnectorClass);
        setText('wafFingerprint', data.wafFingerprint);
        setText('wafMarkerRules', data.wafMarkerRules);
        setText('wafOriginBypass', data.wafOriginBypass);
        setText('wafNotes', data.wafNotes);
        var codeEl = q('wafCode');
        if (codeEl) {
          codeEl.innerHTML =
            '<span class="c-key">asset_id</span>: <span class="c-str">' + escapeHtml(data.wafAssetId) + '</span>\n' +
            '<span class="c-key">vendor</span>: <span class="c-str">' + escapeHtml(data.wafVendor) + '</span>\n' +
            '<span class="c-key">target_group</span>: <span class="c-str">' + escapeHtml(data.targetGroup) + '</span>\n' +
            '<span class="c-key">target</span>: <span class="c-str">' + escapeHtml(data.value) + '</span>\n' +
            '<span class="c-key">posture</span>: <span class="c-str">' + escapeHtml(data.wafPosture) + '</span>\n' +
            '<span class="c-key">drift_reason</span>: <span class="c-str">' + escapeHtml(data.wafDrift || '-') + '</span>\n' +
            '<span class="c-key">validation</span>: <span class="c-str">' + escapeHtml(data.wafValidation) + '</span>\n' +
            '<span class="c-key">connector</span>: <span class="c-str">' + escapeHtml(data.wafConnector) + '</span>';
        }
      } else {
        wafPanel.style.display = 'none';
      }
    }

    // Checks table
    var checksBody = q('checksTbody');
    if (checksBody) {
      if (!data.checks || !data.checks.length) {
        checksBody.innerHTML = '<tr><td class="muted" colspan="5">No checks recorded yet.</td></tr>';
      } else {
        checksBody.innerHTML = data.checks.map(function (c) {
          return '<tr data-route="check-detail" data-entity="' + escapeHtml(c.id) + '" role="link" tabindex="0" style="cursor:pointer">' +
            '<td class="mono">' + escapeHtml(c.id) + '</td>' +
            '<td class="mono">' + escapeHtml(c.family) + '</td>' +
            '<td class="mono">' + escapeHtml(c.bound) + '</td>' +
            '<td class="mono">' + escapeHtml(c.lastRun) + ' <span class="meta">' + escapeHtml(c.lastRunTs) + '</span></td>' +
            '<td><span class="badge ' + escapeHtml(c.verdictClass || 'badge--muted') + '">' + escapeHtml(c.verdict) + '</span></td>' +
            '</tr>';
        }).join('');
      }
    }

    // Runs table
    var runsBody = q('runsTbody');
    if (runsBody) {
      if (!data.runs || !data.runs.length) {
        runsBody.innerHTML = '<tr><td class="muted" colspan="6">No runs against this target yet.</td></tr>';
      } else {
        runsBody.innerHTML = data.runs.map(function (r) {
          return '<tr data-route="run-detail" data-entity="' + escapeHtml(r.id) + '" role="link" tabindex="0" style="cursor:pointer">' +
            '<td class="mono">' + escapeHtml(r.id) + '</td>' +
            '<td class="mono">' + escapeHtml(r.policy) + '</td>' +
            '<td><span class="badge ' + escapeHtml(r.verdictClass || 'badge--muted') + '">' + escapeHtml(r.verdict) + '</span></td>' +
            '<td class="mono">' + escapeHtml(r.agent) + '</td>' +
            '<td class="mono">' + escapeHtml(r.duration) + '</td>' +
            '<td class="muted">' + escapeHtml(r.started) + '</td>' +
            '</tr>';
        }).join('');
      }
    }

    // Findings table (looked up from ENTITIES.findings by findingIds)
    var findingsBody = q('findingsTbody');
    if (findingsBody) {
      var fs = (data.findingIds || []).map(function (fid) { return ENTITIES.findings[fid]; }).filter(Boolean);
      if (!fs.length) {
        findingsBody.innerHTML = '<tr><td class="muted" colspan="7">No findings on this target.</td></tr>';
      } else {
        findingsBody.innerHTML = fs.map(function (f) {
          return '<tr data-route="finding-detail" data-entity="' + escapeHtml(f.id) + '" role="link" tabindex="0" style="cursor:pointer">' +
            '<td><span class="badge ' + escapeHtml(f.severityClass) + '">' + escapeHtml(f.severity) + '</span></td>' +
            '<td class="mono">' + escapeHtml(f.id) + '</td>' +
            '<td>' + escapeHtml(f.title) + '</td>' +
            '<td class="mono">' + escapeHtml(f.check) + '</td>' +
            '<td><span class="badge ' + escapeHtml(f.stateClass) + '">' + escapeHtml(f.state) + '</span></td>' +
            '<td class="muted">' + escapeHtml(f.opened) + '</td>' +
            '<td class="mono">' + escapeHtml(f.sla) + '</td>' +
            '</tr>';
        }).join('');
      }
    }

    // Sub-labels
    setText('checksSub', ((data.checks || []).length) + ' checks bound to this target');
    setText('runsSub', ((data.runs || []).length) + ' recent runs · this target only');
    setText('findingsSub', ((data.findingIds || []).length) + ' related · open + closed + accepted');

    // Run-bounded-checks button · disable when ineligible
    var runBtn = q('runBtn');
    if (runBtn) {
      if (data.eligibility && data.eligibility.indexOf('not') === 0) {
        runBtn.setAttribute('disabled', 'disabled');
        runBtn.setAttribute('title', 'Verify ownership + eligibility before running probes against this target.');
        runBtn.setAttribute('aria-disabled', 'true');
        runBtn.classList.add('is-locked');
      } else {
        runBtn.removeAttribute('disabled');
        runBtn.removeAttribute('aria-disabled');
        runBtn.removeAttribute('title');
        runBtn.classList.remove('is-locked');
      }
    }
  }

  // ─── Affected-targets hydrator ──────────────────────────────────
  // Reverse-lookup: given a finding id, list every target whose
  // findingIds contains it. Renders into #finding-affected-tbody.
  function populateFindingAffectedTargets(findingId) {
    var tbody = document.getElementById('finding-affected-tbody');
    if (!tbody) return;
    var targets = ENTITIES.targets || {};
    var affected = [];
    Object.keys(targets).forEach(function (tid) {
      var t = targets[tid];
      if (t && Array.isArray(t.findingIds) && t.findingIds.indexOf(findingId) !== -1) {
        affected.push(t);
      }
    });
    // Update the panel-sub count
    var countEl = document.querySelector('#screen-finding-detail [data-detail="affectedCount"]');
    if (countEl) countEl.textContent = String(affected.length);
    if (!affected.length) {
      tbody.innerHTML = '<tr><td colspan="6" class="muted" style="padding:20px;text-align:center;">No specific target rows link to this finding. It may apply at the target-group level (zone-wide, edge-wide) rather than to a single declared target.</td></tr>';
      return;
    }
    // Derive per-target last verdict for THIS finding's check by scanning
    // the target's runs for the finding's run id (fall back to first run).
    var finding = (ENTITIES.findings || {})[findingId] || {};
    var findingRun = finding.run;
    var rows = affected.map(function (t) {
      var run = null;
      if (Array.isArray(t.runs)) {
        for (var i = 0; i < t.runs.length; i++) {
          if (t.runs[i].id === findingRun) { run = t.runs[i]; break; }
        }
        if (!run && t.runs.length) run = t.runs[0];
      }
      var verdict = run ? run.verdict : (finding.verdict || '-');
      var verdictClass = run ? run.verdictClass : (finding.verdictClass || 'badge--muted');
      var verdictWhen = run ? run.started : '-';
      var verifyLabel = (t.verification || 'unverified').replace(/_/g, ' ');
      return (
        '<tr role="link" tabindex="0" data-route="target-detail" data-entity="' + t.id + '">' +
        '<td class="mono">' + t.id + '</td>' +
        '<td class="mono">' + (t.kind || '-') + '</td>' +
        '<td class="mono">' + (t.value || '-') + '</td>' +
        '<td><span class="verify-chip ' + (t.verificationClass || 'is-unverified') + '" title="' + (t.verificationTitle || '') + '">' + verifyLabel + '</span></td>' +
        '<td><span class="badge ' + (t.eligibilityClass || 'badge--muted') + '">' + (t.eligibility || '-') + '</span></td>' +
        '<td><span class="badge ' + verdictClass + '">' + verdict + '</span><span class="muted mono" style="font-size:11px;margin-left:8px;">' + verdictWhen + '</span></td>' +
        '</tr>'
      );
    });
    tbody.innerHTML = rows.join('');
  }

  function navigate(id, entityId) {
    var el = navEl(id);
    var detail = DETAIL_ROUTES[id];
    var target = document.getElementById('screen-' + id);
    if (!target && !el) return;
    if (el) {
      if (el.classList.contains('is-locked')) { toast('On the roadmap', '“' + (el.dataset.label || id) + '” ships in a later phase · ask to build it next.', 'info'); return; }
      if (el.classList.contains('is-gated')) { toast('Permission required', 'Switch role or ask an admin. Your current role cannot open ' + (el.dataset.label || id) + '.', 'warn'); return; }
    }
    document.querySelectorAll('.screen').forEach(function (s) { s.classList.remove('is-active'); });
    if (target) {
      target.classList.add('is-active');
      if (detail) populateDetail(id, entityId || DETAIL_DEFAULTS[id]);
      if (id === 'target-detail') populateTargetDetail(entityId || DETAIL_DEFAULTS['target-detail']);
      if (id === 'finding-detail') populateFindingAffectedTargets(entityId || DETAIL_DEFAULTS['finding-detail']);
      drawGauges(target);
      revealIn(target);
      if (id === 'findings') { findingsWire(); findingsRender(); }
    }
    document.querySelectorAll('.nav-item').forEach(function (n) { n.classList.remove('is-active'); });
    if (el) el.classList.add('is-active');
    else if (detail) { var parentNav = navEl(detail.parent); if (parentNav) parentNav.classList.add('is-active'); }
    var crumb = document.getElementById('crumbs');
    if (crumb) {
      if (detail) {
        var parentEl = navEl(detail.parent);
        var parentLabel = parentEl ? parentEl.dataset.label : detail.parent;
        var activeId = entityId || DETAIL_DEFAULTS[id] || detail.label;
        crumb.innerHTML = '<span>' + GROUP_LABELS[detail.group] + '</span><span class="sep">›</span><button type="button" class="crumb-link" data-route="' + detail.parent + '">' + parentLabel + '</button><span class="sep">›</span><b class="mono">' + activeId + '</b>';
      } else if (el) {
        crumb.innerHTML = '<span>' + GROUP_LABELS[el.dataset.group] + '</span><span class="sep">›</span><b>' + el.dataset.label + '</b>';
      }
    }
    try { var s = JSON.parse(localStorage.getItem(STORE) || '{}'); s.route = id; if (entityId) s.entity = entityId; localStorage.setItem(STORE, JSON.stringify(s)); } catch (e) {}
    var main = document.querySelector('.main'); if (main) main.scrollTop = 0;
    window.scrollTo(0, 0);
    closeSidebar();
  }

  function enterPortal() {
    document.body.classList.add('is-portal');
    var saved = 'dashboard';
    var entity;
    try {
      var st = JSON.parse(localStorage.getItem(STORE) || '{}');
      saved = st.route || 'dashboard';
      entity = st.entity;
    } catch (e) {}
    if (DETAIL_ROUTES[saved]) {
      navigate(saved, entity);
    } else {
      var el = navEl(saved);
      var first = (el && !el.classList.contains('is-locked') && !el.classList.contains('is-gated')) ? saved : 'dashboard';
      navigate(first);
    }
    toast('Signed in', 'Tenant acme-prod · role ' + currentRole() + '.', 'info');
  }
  function exitPortal() { document.body.classList.remove('is-portal'); window.scrollTo(0, 0); }

  /* ───────── auth funnel ───────── */
  var AUTH_SCREENS = ['login', 'signup', 'signup-status', 'staff-login'];
  function showAuthScreen(id) {
    if (AUTH_SCREENS.indexOf(id) === -1) id = 'login';
    AUTH_SCREENS.forEach(function (s) {
      var el = document.getElementById('auth-' + s);
      if (el) el.hidden = s !== id;
    });
    try { var st = JSON.parse(localStorage.getItem(STORE) || '{}'); st.auth = id; localStorage.setItem(STORE, JSON.stringify(st)); } catch (e) {}
  }
  function enterAuth(id) {
    document.body.classList.remove('is-portal');
    document.body.classList.add('is-auth');
    showAuthScreen(id);
    window.scrollTo(0, 0);
  }
  function exitAuth() {
    document.body.classList.remove('is-auth');
    window.scrollTo(0, 0);
  }
  function enterPortalFromAuth() {
    document.body.classList.remove('is-auth');
    var roleSel = document.getElementById('auth-role');
    if (roleSel && roleSel.value) setRole(roleSel.value);
    enterPortal();
  }
  function enterStaffFromAuth() {
    document.body.classList.remove('is-auth');
    var staffSel = document.getElementById('staff-role');
    var staffRole = staffSel ? staffSel.value : 'internal_admin';
    // SOC roles land on the SOC execution console; others on the admin console.
    var landing = (staffRole === 'soc_analyst' || staffRole === 'soc_lead') ? 'internal-soc' : 'admin';
    enterPortal();
    navigate(landing);
    toast('Staff signed in', 'Staff role ' + staffRole + ' · routed to ' + (landing === 'internal-soc' ? 'SOC console' : 'Admin console') + '.', 'info');
  }

  /* ───────── RBAC ───────── */
  var ROLES = {
    admin:    { label: 'Admin',    write: true,  soc: true  },
    engineer: { label: 'Engineer', write: true,  soc: false },
    soc:      { label: 'SOC',      write: false, soc: true  },
    viewer:   { label: 'Viewer',   write: false, soc: false },
    auditor:  { label: 'Auditor',  write: false, soc: false }
  };
  function currentRole() { try { return JSON.parse(localStorage.getItem(STORE) || '{}').role || 'admin'; } catch (e) { return 'admin'; } }

  function setRole(role) {
    var r = ROLES[role]; if (!r) return;
    try { var s = JSON.parse(localStorage.getItem(STORE) || '{}'); s.role = role; localStorage.setItem(STORE, JSON.stringify(s)); } catch (e) {}
    document.querySelectorAll('.nav-item[data-roles]').forEach(function (n) {
      var allowed = (n.dataset.roles || '').split(/\s+/);
      n.classList.toggle('is-gated', allowed.indexOf(role) === -1);
    });
    document.querySelectorAll('[data-needs]').forEach(function (b) {
      var need = b.dataset.needs;
      var disabled = (need === 'write' && !r.write) || (need === 'soc' && !r.soc);
      if (disabled) b.setAttribute('disabled', ''); else b.removeAttribute('disabled');
      b.setAttribute('aria-disabled', disabled ? 'true' : 'false');
    });
    var sel = document.getElementById('role-select'); if (sel) sel.value = role;
    var cur = document.querySelector('.nav-item.is-active');
    if (cur && cur.classList.contains('is-gated')) navigate('dashboard');
  }

  /* ───────── sidebar (mobile + collapse) ───────── */
  function openSidebar() { var sb = document.querySelector('.sidebar'); var sc = document.querySelector('.scrim'); if (sb) sb.classList.add('is-open'); if (sc) sc.classList.add('is-open'); }
  function closeSidebar() { var sb = document.querySelector('.sidebar'); var sc = document.querySelector('.scrim'); if (sb) sb.classList.remove('is-open'); if (sc) sc.classList.remove('is-open'); }
  function setSidebarCollapsed(collapsed) {
    var sb = document.getElementById('sidebar');
    var btn = document.querySelector('[data-sidebar-collapse]');
    if (!sb) return;
    sb.classList.toggle('is-collapsed', collapsed);
    if (btn) {
      btn.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
      btn.setAttribute('aria-label', collapsed ? 'Expand navigation' : 'Collapse navigation');
    }
    document.querySelectorAll('.nav-item[data-label]').forEach(function (item) {
      if (collapsed) item.setAttribute('title', item.getAttribute('data-label'));
      else item.removeAttribute('title');
    });
  }
  function toggleSidebarCollapse() { var sb = document.getElementById('sidebar'); if (sb) setSidebarCollapsed(!sb.classList.contains('is-collapsed')); }

  /* ───────── modal ───────── */
  var lastFocus = null;
  function openModal(id) {
    var m = document.getElementById(id); if (!m) return;
    lastFocus = document.activeElement;
    m.classList.add('is-open'); m.setAttribute('aria-hidden', 'false');
    var f = m.querySelector('input, select, textarea, button'); if (f) setTimeout(function () { f.focus(); }, 40);
    document.addEventListener('keydown', trapKey);
  }
  function closeModal(m) {
    m = m || document.querySelector('.modal-overlay.is-open'); if (!m) return;
    m.classList.remove('is-open'); m.setAttribute('aria-hidden', 'true');
    document.removeEventListener('keydown', trapKey);
    if (lastFocus && lastFocus.focus) try { lastFocus.focus(); } catch (e) {}
  }
  function trapKey(e) {
    if (e.key === 'Escape') { closeModal(); return; }
    if (e.key !== 'Tab') return;
    var m = document.querySelector('.modal-overlay.is-open'); if (!m) return;
    var f = Array.prototype.slice.call(m.querySelectorAll('input, select, textarea, button, a[href]')).filter(function (el) { return el.offsetParent !== null && !el.disabled; });
    if (!f.length) return;
    var first = f[0], last = f[f.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  }

  /* ───────── custody + download ───────── */
  function shaMock(n) { var s = '', hex = '0123456789abcdef'; for (var i = 0; i < n; i++) s += hex[Math.floor(Math.random() * 16)]; return s; }
  function sortKeys(o) {
    if (Array.isArray(o)) return o.map(sortKeys);
    if (o && typeof o === 'object') return Object.keys(o).sort().reduce(function (a, k) { a[k] = sortKeys(o[k]); return a; }, {});
    return o;
  }
  function custodyManifest(bundle) {
    return { digest_kind: 'json-key-sorted-v1', digest_sha256: shaMock(64), sealed_at: new Date().toISOString(), artifacts: Object.keys(bundle).length };
  }
  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) { navigator.clipboard.writeText(text).catch(function () {}); return; }
    var t = document.createElement('textarea'); t.value = text; document.body.appendChild(t); t.select(); try { document.execCommand('copy'); } catch (e) {} t.remove();
  }
  function downloadJson(filename, obj) {
    var blob = new Blob([JSON.stringify(obj, null, 2)], { type: 'application/json' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a'); a.href = url; a.download = filename; document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1500);
  }

  /* ───────── tabs ───────── */
  function handleTab(tab) {
    var group = tab.closest('.tabs'); if (!group) return;
    var g = group.getAttribute('data-tabgroup'); if (!g) return;
    var name = tab.getAttribute('data-tab');
    group.querySelectorAll('.tab').forEach(function (t) {
      var on = t === tab;
      t.classList.toggle('is-active', on);
      if (t.hasAttribute('role') && t.getAttribute('role') === 'tab') t.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    var scope = group.parentNode;
    scope.querySelectorAll('.tab-pane[data-tabgroup="' + g + '"]').forEach(function (p) { p.classList.toggle('is-active', p.getAttribute('data-tab') === name); });
    if (group.hasAttribute('data-persist')) {
      try { localStorage.setItem('astranull-tabs-' + g, name); } catch (_) {}
    }
  }

  function restorePersistedTabs() {
    document.querySelectorAll('.tabs[data-persist]').forEach(function (group) {
      var g = group.getAttribute('data-tabgroup'); if (!g) return;
      var saved = null;
      try { saved = localStorage.getItem('astranull-tabs-' + g); } catch (_) {}
      if (!saved) return;
      var t = group.querySelector('.tab[data-tab="' + saved + '"]');
      if (t) handleTab(t);
    });
  }

  /* ───────── findings ───────── */
  var FINDINGS_STATE = {
    status: 'open',
    severity: 'all',
    owner: 'all',
    targetGroup: 'all',
    search: '',
    sort: 'severity',
    page: 1,
    pageSize: 12
  };
  var FINDINGS_WIRED = false;

  function findingsAll() {
    var f = (ENTITIES && ENTITIES.findings) || {};
    var out = [];
    for (var k in f) if (Object.prototype.hasOwnProperty.call(f, k)) out.push(f[k]);
    return out;
  }
  function findingsStatusCounts() {
    var all = findingsAll();
    var counts = { open: 0, closed: 0, accepted: 0, all: all.length };
    all.forEach(function (x) { if (counts[x.state] != null) counts[x.state]++; });
    return counts;
  }
  function findingsUnique(items, key) {
    var seen = {}, out = [];
    items.forEach(function (x) {
      var v = x[key]; if (!v || seen[v]) return;
      seen[v] = true; out.push(v);
    });
    out.sort();
    return out;
  }
  var SEV_RANK = { S1: 4, S2: 3, S3: 2, S4: 1 };
  function findingsFiltered() {
    var items = findingsAll();
    var s = FINDINGS_STATE;
    if (s.status !== 'all') items = items.filter(function (x) { return x.state === s.status; });
    if (s.severity !== 'all') items = items.filter(function (x) { return x.severity === s.severity; });
    if (s.owner !== 'all') items = items.filter(function (x) { return x.owner === s.owner; });
    if (s.targetGroup !== 'all') items = items.filter(function (x) { return x.targetGroup === s.targetGroup; });
    if (s.search) {
      var q = s.search.toLowerCase();
      items = items.filter(function (x) {
        return (x.title || '').toLowerCase().indexOf(q) !== -1
          || (x.check || '').toLowerCase().indexOf(q) !== -1
          || (x.id || '').toLowerCase().indexOf(q) !== -1
          || (x.targetGroup || '').toLowerCase().indexOf(q) !== -1
          || (x.owner || '').toLowerCase().indexOf(q) !== -1;
      });
    }
    items.sort(function (a, b) {
      switch (s.sort) {
        case 'opened-desc': return (b.openedTs || 0) - (a.openedTs || 0);
        case 'opened-asc': return (a.openedTs || 0) - (b.openedTs || 0);
        case 'sla': return (a.slaHours || 0) - (b.slaHours || 0);
        case 'title': return (a.title || '').localeCompare(b.title || '');
        case 'severity':
        default: {
          var d = (SEV_RANK[b.severity] || 0) - (SEV_RANK[a.severity] || 0);
          if (d !== 0) return d;
          return (b.openedTs || 0) - (a.openedTs || 0);
        }
      }
    });
    return items;
  }
  function findingSlaClass(f) {
    if (f.state !== 'open') return '';
    if (f.slaHours == null) return '';
    if (f.slaHours < 0) return 'is-danger';
    if (f.slaHours <= 24) return 'is-warn';
    return '';
  }
  function findingCardHtml(f) {
    var sev = (f.severity || '') + ' · ' + (f.verdict || '');
    var slaTxt = f.sla || '';
    var slaCls = findingSlaClass(f);
    var stateLabel = (f.state || '').toUpperCase();
    var facets = [];
    facets.push('<span>' + escapeHtml(f.targetGroup || '-') + '</span>');
    facets.push('<span class="fc-sep">·</span><span><span class="fc-key">owner:</span> ' + escapeHtml(f.owner || '-') + '</span>');
    facets.push('<span class="fc-sep">·</span><span><span class="fc-key">check:</span> ' + escapeHtml(f.check || '-') + '</span>');
    if (f.state === 'open' && f.opened) {
      facets.push('<span class="fc-sep">·</span><span><span class="fc-key">opened:</span> ' + escapeHtml(f.opened) + '</span>');
      if (slaTxt) facets.push('<span class="fc-sep">·</span><span class="fc-sla ' + slaCls + '">' + escapeHtml(slaTxt) + '</span>');
    } else if (f.closed) {
      facets.push('<span class="fc-sep">·</span><span>' + escapeHtml(slaTxt || 'closed') + '</span>');
    }
    return '<div class="finding-card" data-route="finding-detail" data-entity="' + escapeAttr(f.id) + '" role="link" tabindex="0" aria-label="Open finding ' + escapeAttr(f.id) + '">' +
      '<div class="fc-body">' +
        '<div class="fc-top">' +
          '<span class="badge ' + escapeAttr(f.severityClass || 'badge--muted') + '">' + escapeHtml(sev) + '</span>' +
          '<span class="fc-meta">' + escapeHtml(f.id) + '</span>' +
        '</div>' +
        '<div class="fc-headline"><h4>' + escapeHtml(f.title || 'Untitled') + '</h4>' +
          '<span class="fc-state">' + escapeHtml(stateLabel) + '</span>' +
        '</div>' +
        '<div class="fc-facets">' + facets.join('') + '</div>' +
      '</div>' +
    '</div>';
  }
  function escapeHtml(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function escapeAttr(s) { return escapeHtml(s); }

  function findingsPopulateSelects() {
    var all = findingsAll();
    var owners = findingsUnique(all, 'owner');
    var groups = findingsUnique(all, 'targetGroup');
    var ownerSel = document.getElementById('findings-owner');
    var groupSel = document.getElementById('findings-target');
    if (ownerSel && ownerSel.options.length <= 1) {
      owners.forEach(function (o) { var opt = document.createElement('option'); opt.value = o; opt.textContent = o; ownerSel.appendChild(opt); });
    }
    if (groupSel && groupSel.options.length <= 1) {
      groups.forEach(function (g) { var opt = document.createElement('option'); opt.value = g; opt.textContent = g; groupSel.appendChild(opt); });
    }
  }
  function findingsRender() {
    var list = document.getElementById('findings-list');
    var empty = document.getElementById('findings-empty');
    if (!list) return;
    var items = findingsFiltered();
    var s = FINDINGS_STATE;
    var total = items.length;
    var pages = Math.max(1, Math.ceil(total / s.pageSize));
    if (s.page > pages) s.page = pages;
    if (s.page < 1) s.page = 1;
    var start = (s.page - 1) * s.pageSize;
    var end = Math.min(start + s.pageSize, total);
    var page = items.slice(start, end);

    if (total === 0) {
      list.innerHTML = '';
      list.hidden = true;
      if (empty) empty.hidden = false;
    } else {
      if (empty) empty.hidden = true;
      list.hidden = false;
      list.innerHTML = page.map(findingCardHtml).join('');
    }

    var sub = document.getElementById('findings-count-sub');
    if (sub) {
      var label = s.status === 'open' ? 'open' : s.status === 'closed' ? 'closed' : s.status === 'accepted' ? 'accepted' : 'total';
      sub.textContent = total + ' ' + label + ' finding' + (total === 1 ? '' : 's') + ' · click a card to open the correlated verdict';
    }

    var range = document.getElementById('findings-range');
    if (range) range.textContent = total === 0 ? '0-0' : (start + 1) + '-' + end;
    var totalEl = document.getElementById('findings-total');
    if (totalEl) totalEl.textContent = String(total);
    var pageEl = document.getElementById('findings-page');
    if (pageEl) pageEl.textContent = String(s.page);
    var pagesEl = document.getElementById('findings-pages');
    if (pagesEl) pagesEl.textContent = String(pages);

    var prev = document.getElementById('findings-prev');
    var next = document.getElementById('findings-next');
    if (prev) { prev.disabled = s.page <= 1; prev.setAttribute('aria-disabled', String(s.page <= 1)); }
    if (next) { next.disabled = s.page >= pages; next.setAttribute('aria-disabled', String(s.page >= pages)); }

    var counts = findingsStatusCounts();
    Object.keys(counts).forEach(function (k) {
      var el = document.querySelector('[data-status-count="' + k + '"]');
      if (el) el.textContent = String(counts[k]);
    });
    document.querySelectorAll('.ft-tab[data-findings-status]').forEach(function (b) {
      var on = b.getAttribute('data-findings-status') === s.status;
      b.classList.toggle('is-active', on);
      b.setAttribute('aria-selected', String(on));
    });
  }
  function findingsSetStatus(v) { FINDINGS_STATE.status = v; FINDINGS_STATE.page = 1; findingsRender(); }
  function findingsWire() {
    if (FINDINGS_WIRED) return;
    var root = document.getElementById('screen-findings');
    if (!root) return;
    findingsPopulateSelects();

    root.addEventListener('click', function (e) {
      var t = e.target.closest('.ft-tab[data-findings-status]');
      if (t) { e.preventDefault(); findingsSetStatus(t.getAttribute('data-findings-status')); return; }
      if (e.target.id === 'findings-reset' || e.target.id === 'findings-empty-reset') {
        e.preventDefault();
        FINDINGS_STATE.severity = 'all'; FINDINGS_STATE.owner = 'all'; FINDINGS_STATE.targetGroup = 'all';
        FINDINGS_STATE.search = ''; FINDINGS_STATE.sort = 'severity'; FINDINGS_STATE.status = 'open'; FINDINGS_STATE.page = 1;
        var ids = ['findings-severity', 'findings-owner', 'findings-target', 'findings-sort'];
        ids.forEach(function (id) { var el = document.getElementById(id); if (el) el.value = el.options[0].value; });
        var srch = document.getElementById('findings-search'); if (srch) srch.value = '';
        var srt = document.getElementById('findings-sort'); if (srt) srt.value = 'severity';
        findingsRender();
        return;
      }
      if (e.target.id === 'findings-prev') { e.preventDefault(); if (FINDINGS_STATE.page > 1) { FINDINGS_STATE.page--; findingsRender(); } return; }
      if (e.target.id === 'findings-next') { e.preventDefault(); FINDINGS_STATE.page++; findingsRender(); return; }
    });

    var wire = function (id, key, isPage) {
      var el = document.getElementById(id); if (!el) return;
      el.addEventListener('change', function () {
        FINDINGS_STATE[key] = isPage ? parseInt(el.value, 10) || 12 : el.value;
        FINDINGS_STATE.page = 1;
        findingsRender();
      });
    };
    wire('findings-severity', 'severity');
    wire('findings-owner', 'owner');
    wire('findings-target', 'targetGroup');
    wire('findings-sort', 'sort');
    wire('findings-page-size', 'pageSize', true);
    var search = document.getElementById('findings-search');
    if (search) {
      var t;
      search.addEventListener('input', function () {
        clearTimeout(t);
        t = setTimeout(function () { FINDINGS_STATE.search = search.value.trim(); FINDINGS_STATE.page = 1; findingsRender(); }, 140);
      });
    }
    FINDINGS_WIRED = true;
  }

  function exportFindingEvidence() {
    var active = document.getElementById('screen-finding-detail');
    var id = (active && active.getAttribute('data-active-entity')) || 'fnd_l7_8f3c';
    var finding = ((ENTITIES.findings || {})[id]) || { id: id, check: 'chk_l7_rate', verdict: 'Gap', severity: 'S2', owner: 'edge-sre', state: 'open', run: 'run_8f3c' };
    var bundle = {
      finding: { id: finding.id, check: finding.check, verdict: (finding.verdict || '').toLowerCase(), severity: finding.severity, owner: finding.owner, state: finding.state },
      probe_result: { probe: 'probe-eu-west-2', bound_rps: 50, origin_ms: 47, scrubber_bypassed: true, ts: '2026-07-04T14:32:01Z' },
      agent_observation: { agent: 'agt_edge_01', direct_to_origin: true, waf_pool_bypassed: true, heartbeat: 'healthy' },
      verdict: { state: (finding.verdict || 'gap').toLowerCase(), correlated_from: ['probe_result', 'agent_observation'] }
    };
    downloadJson(id + '-evidence-bundle.json', { bundle: bundle, custody: custodyManifest(bundle) });
  }

  /* ───────── refresh ───────── */
  function refreshCurrent(btn) {
    var screen = document.querySelector('.screen.is-active'); if (!screen) return;
    var panes = Array.prototype.slice.call(screen.querySelectorAll('.panel-body'));
    var originals = panes.map(function (p) { return p.innerHTML; });
    panes.forEach(function (p) {
      p.innerHTML = '<div class="empty" style="padding:34px;text-align:left"><div class="skeleton sk-row" style="width:40%"></div><div class="skeleton sk-row" style="width:85%"></div><div class="skeleton sk-row" style="width:70%"></div><div class="skeleton sk-row" style="width:60%"></div></div>';
    });
    btn.setAttribute('aria-busy', 'true');
    setTimeout(function () {
      panes.forEach(function (p, i) { p.innerHTML = originals[i]; });
      btn.removeAttribute('aria-busy');
      toast('Refreshed', 'Latest tenant data loaded.', 'info');
    }, 650);
  }

  /* ───────── delegated actions ───────── */
  function handleAction(btn) {
    if (btn.getAttribute('aria-disabled') === 'true' || btn.disabled) { toast('Permission required', 'Your role cannot perform this action.', 'warn'); return; }
    var a = btn.getAttribute('data-action');
    switch (a) {
      case 'refresh': refreshCurrent(btn); break;
      case 'hb-refresh': {
        // Per-agent heartbeat refresh on the agent-detail view. Nudges the
        // "last heartbeat" KPI + hb-value cell, and briefly flashes the
        // trailing hb-dot so the user sees the poll happen.
        var hbLast = document.querySelector('#screen-agent-detail [data-detail="heartbeat"]');
        var hbCell = document.querySelector('#screen-agent-detail .hb-cell:nth-child(2) .hb-value');
        var nowDot = document.querySelector('#screen-agent-detail .hb-dot.is-now');
        if (hbLast) hbLast.textContent = '2s ago';
        if (hbCell) hbCell.textContent = '2s ago';
        if (nowDot) {
          nowDot.setAttribute('title', '2s ago');
          nowDot.animate([{ transform: 'scaleY(1)' }, { transform: 'scaleY(1.35)' }, { transform: 'scaleY(1)' }], { duration: 480, easing: 'cubic-bezier(0.2, 0, 0, 1)' });
        }
        toast('Heartbeat refreshed', 'Latest ping observed 2s ago · cadence stable.');
        break;
      }
      case 'token-generate': {
        var secret = 'ast_live_' + shaMock(28);
        var row = document.getElementById('agent-secret-row');
        row.querySelector('.secret').textContent = secret;
        row.classList.remove('is-hidden');
        document.getElementById('agent-secret-reveal').textContent = 'Hide';
        toast('Bootstrap token created', 'One-time secret shown · copied to clipboard, won\'t be shown again.', 'info');
        copyText(secret);
        break;
      }
      case 'token-reveal': {
        var r = document.getElementById('agent-secret-row');
        r.classList.toggle('is-hidden');
        btn.textContent = r.classList.contains('is-hidden') ? 'Reveal' : 'Hide';
        break;
      }
      case 'token-copy': {
        var s = document.getElementById('agent-secret-row').querySelector('.secret').textContent;
        if (s && s.indexOf('•') === -1) { copyText(s); toast('Copied', 'Bootstrap token copied.'); }
        else toast('Nothing to copy', 'Generate or reveal the token first.', 'warn');
        break;
      }
      case 'token-revoke': {
        if (!confirm('Revoke this bootstrap token? Agents booted with it will no longer authenticate.')) break;
        var rr = document.getElementById('agent-secret-row');
        rr.classList.add('is-hidden'); rr.querySelector('.secret').textContent = '••••••••••• revoked';
        toast('Token revoked', 'Outstanding sessions fail heartbeat within 60s.', 'warn');
        break;
      }
      case 'finding-assign': toast('Assigned', 'Finding → edge-sre. Verdict trail + audit log updated.', 'info'); break;
      case 'finding-accept': toast('Risk accepted', 'Accepted-risk recorded under custody. SLA paused.', 'warn'); break;
      case 'finding-close': toast('Finding closed', 'Closed · evidence retained for audit window.', 'info'); break;
      case 'finding-retest': toast('Retest queued', 'Scheduled for the next safe window.', 'info'); break;
      case 'finding-export': exportFindingEvidence(); toast('Evidence exported', 'fnd_l7_8f3c-evidence-bundle.json · custody manifest attached.', 'info'); break;
      case 'evidence-export': {
        var id = btn.getAttribute('data-artifact');
        var art = { artifact_id: id, kind: 'verdict', run: 'run_8f3c', sha256: shaMock(64), sealed_at: new Date().toISOString() };
        downloadJson(id + '.json', { artifact: art, custody: custodyManifest(art) });
        toast('Artifact exported', id + ' · custody manifest attached.', 'info');
        break;
      }
      case 'evidence-verify': toast('Chain verified', 'Custody chain intact · digests match · 3 artifacts.', 'info'); break;
      case 'run-safe': toast('Safe run queued', 'Bounded, metadata-only. Results land in Test Runs.', 'info'); break;
      case 'soc-request': toast('SOC-gated request submitted', 'Routed to the SOC queue · approval-gated, not self-service. Watch the SOC-gated queue for state changes.', 'info'); break;
      case 'soc-complete-pack': toast('Authorization pack update', 'Missing artifacts routed to the tenant owner for completion.', 'info'); break;
      case 'remediation-deliver': toast('Marked delivered', 'State → resolved · delivery evidence sealed under custody.', 'info'); break;
      case 'report-generate': {
        var kind = document.getElementById('report-kind');
        var fmt = document.getElementById('report-format');
        var k = kind ? kind.value : 'executive';
        var f = fmt ? fmt.value : 'json';
        if (f === 'pdf') { toast('Unsupported format', 'PDF returns unsupported_format · use HTML-to-PDF in your review toolchain.', 'warn'); break; }
        var rpt = { report: { kind: k, format: f, period: new Date().toISOString().slice(0, 7) }, custody: custodyManifest({ kind: k }) };
        downloadJson('rpt_' + k + '.' + f, rpt);
        toast('Report generated', k + ' · ' + f + ' · custody manifest attached. Draft lands in Recent reports.', 'info');
        break;
      }
      case 'report-export': {
        var rid = btn.getAttribute('data-report');
        var rfmt = btn.getAttribute('data-format') || 'json';
        var rep = (ENTITIES.reports || {})[rid] || { id: rid, kind: 'executive', title: rid };
        var bundle = { report: { id: rid, kind: rep.kind, title: rep.title, format: rfmt }, custody: custodyManifest({ id: rid }) };
        downloadJson(rid + '.' + rfmt, bundle);
        toast('Report exported', rid + ' · ' + rfmt + ' · custody manifest attached.', 'info');
        break;
      }
      case 'report-copy': {
        var cid = btn.getAttribute('data-report');
        var crep = (ENTITIES.reports || {})[cid];
        if (crep) { copyText(JSON.stringify({ report: { id: cid, custody_sha256: crep.custodySha } }, null, 2)); toast('Custody digest copied', cid + ' · ' + crep.custodySha); }
        break;
      }
      case 'tenant-suspend': toast('Tenant suspended', 'Lifecycle → suspended · evidence retained for the audit window.', 'warn'); break;
      case 'tenant-reactivate': toast('Tenant reactivated', 'Lifecycle → active · safe checks resumed under prior scope.', 'info'); break;
      case 'tenant-approve': toast('Sign-up approved', 'Tenant provisioning · first agent enrollment unlocked.', 'info'); break;
      case 'approval-grant': toast('Approval granted', 'Request advanced to the next lifecycle state · custody recorded.', 'info'); break;
      case 'approval-reject': toast('Approval rejected', 'Request closed · retained under custody, not advanced.', 'warn'); break;
      case 'kill-arm': {
        if (!confirm('Arm the kill switch? Governed high-scale execution halts and the 7-step validated sequence runs with custody at each step.')) break;
        toast('Kill switch armed', 'Sequence complete · adapter stop path invoked · audit timeline recorded.', 'warn');
        break;
      }
      case 'soc-approve': toast('SOC approval granted', 'Request → approved · scheduled for the declared safe window.', 'info'); break;
      case 'soc-execute': {
        if (!confirm('Execute this governed run now? Adapter traffic generation begins at the declared bound.')) break;
        toast('Execution started', 'Adapter armed · telemetry live · stop criteria monitored.', 'warn');
        break;
      }
      case 'connector-add': toast('Connector draft saved', 'Secret stored as a vault reference · never rendered or logged. Validate to activate.', 'info'); break;
      case 'connector-snapshot': toast('Snapshot queued', 'Cloud inventory snapshot scheduled · metadata-only, no credentials invoked.', 'info'); break;
      case 'connector-disable': toast('Connector disabled', 'Telemetry paused · vault reference retained for re-enable.', 'warn'); break;
      case 'notif-rule': toast('Rule created', 'Metadata-only delivery rule recorded · external delivery remains opt-in.', 'info'); break;
      case 'notif-retry': toast('Retry queued', 'Attempt re-queued · provider retry schedule updated.', 'info'); break;
      case 'notif-redrive': toast('DLQ redriving', 'Dead-letter attempts requeued for delivery.', 'warn'); break;
      case 'settings-save': toast('Profile saved', 'Tenant profile updated · change ledgered to the audit log.', 'info'); break;
      case 'sso-toggle': toast('SSO enforcement toggled', 'OIDC enforcement updated · role mapping re-derived from IdP claims on next login.', 'info'); break;
      case 'safe-toggle': toast('Safe default toggled', 'Safe-by-default policy updated for this tenant.', 'info'); break;
      case 'support-open': toast('Request opened', 'Tracked support ticket created · your account engineer is notified.', 'info'); break;
      case 'agent-placement':
        toast('Placement test started', 'Bounded protected-path canary queued · evidence recorded on completion.', 'info');
        break;
      case 'signup-submit': {
        var form = document.getElementById('form-signup');
        var d = form ? new FormData(form) : null;
        var org = d ? String(d.get('organization_name') || 'your organization').trim() : 'your organization';
        var reqId = 'sgn_' + shaMock(8);
        var formWrap = document.getElementById('form-signup');
        var success = document.getElementById('signup-success');
        var idNode = document.getElementById('signup-request-id');
        if (formWrap) formWrap.hidden = true;
        if (success) success.hidden = false;
        if (idNode) idNode.textContent = reqId;
        toast('Request submitted', reqId + ' · ' + org + ' · reviewed within 2 business days.', 'info');
        break;
      }
      case 'signup-status-lookup': {
        var sf = document.getElementById('form-signup-status');
        var sd = sf ? new FormData(sf) : null;
        var typed = sd ? String(sd.get('request_id') || '').trim() : '';
        var sid = typed || ('sgn_' + shaMock(8));
        var res = document.getElementById('signup-status-result');
        var idEl = document.getElementById('status-id');
        var orgEl = document.getElementById('status-org');
        if (idEl) idEl.textContent = sid;
        if (orgEl) orgEl.textContent = 'Northwind Inc.';
        if (res) res.hidden = false;
        toast('Status found', sid + ' · under review · operations validating organization details.', 'info');
        break;
      }
      case 'tg-picker-toggle': {
        var tgPicker = btn.closest('[data-tg-picker]');
        if (!tgPicker) break;
        var tgOpen = btn.getAttribute('aria-expanded') === 'true';
        var tgMenu = tgPicker.querySelector('.tg-picker-menu');
        btn.setAttribute('aria-expanded', tgOpen ? 'false' : 'true');
        if (tgMenu) { if (tgOpen) tgMenu.setAttribute('hidden', ''); else tgMenu.removeAttribute('hidden'); }
        break;
      }
      case 'tg-picker-check': {
        // Checkbox row toggled inside the picker menu. The <label> wraps
        // the checkbox so the click flips the state natively; we just
        // need to re-render the pill display in the trigger.
        var tgPickerC = btn.closest('[data-tg-picker]');
        if (tgPickerC) updateTgPickerValues(tgPickerC);
        break;
      }
      case 'tg-pill-remove': {
        var tgVal = btn.getAttribute('data-tg-value');
        var tgPickerR = btn.closest('[data-tg-picker]');
        if (!tgPickerR || !tgVal) break;
        var tgCheckbox = tgPickerR.querySelector('input[type="checkbox"][value="' + tgVal + '"]');
        if (tgCheckbox) tgCheckbox.checked = false;
        updateTgPickerValues(tgPickerR);
        break;
      }
    }
  }

  function updateTgPickerValues(picker) {
    var values = picker.querySelector('[data-tg-values]');
    if (!values) return;
    var checked = picker.querySelectorAll('input[type="checkbox"]:checked');
    if (checked.length === 0) {
      values.innerHTML = '<span class="tg-picker-placeholder">Select one or more target groups…</span>';
      return;
    }
    var parts = [];
    for (var i = 0; i < checked.length; i++) {
      var v = checked[i].value;
      parts.push(
        '<span class="tg-pill">' + v +
        '<button type="button" class="tg-pill-close" data-action="tg-pill-remove" data-tg-value="' + v + '" aria-label="Remove ' + v + '">' +
        '<svg width="10" height="10" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M6 6l12 12M18 6L6 18" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/></svg>' +
        '</button></span>'
      );
    }
    values.innerHTML = parts.join('');
  }

  function closeTgPickersExcept(target) {
    var pickers = document.querySelectorAll('[data-tg-picker]');
    for (var i = 0; i < pickers.length; i++) {
      var p = pickers[i];
      if (target && p.contains(target)) continue;
      var trg = p.querySelector('.tg-picker-trigger');
      var menu = p.querySelector('.tg-picker-menu');
      if (trg) trg.setAttribute('aria-expanded', 'false');
      if (menu) menu.setAttribute('hidden', '');
    }
  }

  function onClick(e) {
    var el;
    // Close any open target-group pickers when clicking outside them.
    // Skip when the click landed on the trigger itself; the tg-picker-toggle
    // action handler owns that path.
    if (!e.target.closest('[data-tg-picker]')) closeTgPickersExcept(null);
    if ((el = e.target.closest('.tab')) && el.closest('.tabs')) { handleTab(el); return; }
    if ((el = e.target.closest('[data-action]'))) { e.preventDefault(); handleAction(el); return; }
    if ((el = e.target.closest('[data-route]'))) { e.preventDefault(); navigate(el.getAttribute('data-route'), el.getAttribute('data-entity')); return; }
    if ((el = e.target.closest('[data-enter-portal]'))) { e.preventDefault(); enterPortal(); return; }
    if ((el = e.target.closest('[data-exit-portal]'))) { e.preventDefault(); exitPortal(); return; }
    if ((el = e.target.closest('[data-enter-auth]'))) { e.preventDefault(); enterAuth(el.getAttribute('data-enter-auth')); return; }
    if ((el = e.target.closest('[data-exit-auth]'))) { e.preventDefault(); exitAuth(); return; }
    if ((el = e.target.closest('[data-auth-submit]'))) { e.preventDefault(); enterPortalFromAuth(); return; }
    if ((el = e.target.closest('[data-auth-submit-staff]'))) { e.preventDefault(); enterStaffFromAuth(); return; }
    if ((el = e.target.closest('[data-burger]'))) { openSidebar(); return; }
    if ((el = e.target.closest('[data-sidebar-collapse]'))) { toggleSidebarCollapse(); return; }
    if ((el = e.target.closest('.scrim'))) { closeSidebar(); return; }
    if ((el = e.target.closest('[data-open-modal]'))) { e.preventDefault(); openModal(el.getAttribute('data-open-modal')); return; }
    if ((el = e.target.closest('[data-close-modal]'))) { e.preventDefault(); closeModal(); return; }
    if ((el = e.target.closest('.modal-overlay')) && e.target === el) { closeModal(el); return; }

    /* ── verification + LOA + integrations ── */
    if ((el = e.target.closest('[data-action="dns-issue-challenge"]'))) {
      e.preventDefault();
      dnsIssueChallenge();
      return;
    }
    if ((el = e.target.closest('[data-action="dns-refresh"]'))) {
      e.preventDefault();
      dnsRefreshCheck(el);
      return;
    }
    if ((el = e.target.closest('[data-action="copy-dns-name"]'))) {
      e.preventDefault();
      copyById('dns-record-name', 'TXT record name');
      return;
    }
    if ((el = e.target.closest('[data-action="copy-dns-value"]'))) {
      e.preventDefault();
      copyById('dns-record-value', 'TXT record value');
      return;
    }
    if ((el = e.target.closest('[data-action="target-verify"]'))) {
      e.preventDefault();
      targetVerify(el);
      return;
    }
    if ((el = e.target.closest('[data-action="connect-provider"]'))) {
      e.preventDefault();
      var provider = el.getAttribute('data-provider') || 'provider';
      openInventory(provider);
      return;
    }
    if ((el = e.target.closest('[data-action="run-target-locked"]'))) {
      e.preventDefault();
      toast('Verify first', 'This target is unverified. Complete DNS TXT verification or bind an agent before running a test.', 'warn');
      return;
    }
    if ((el = e.target.closest('[data-inv-filter]'))) {
      e.preventDefault();
      inventoryFilter(el.getAttribute('data-inv-filter'));
      return;
    }
    if ((el = e.target.closest('[data-action="inventory-refresh"]'))) {
      e.preventDefault();
      inventoryRefresh(el);
      return;
    }
    if ((el = e.target.closest('[data-action="inventory-import"]'))) {
      e.preventDefault();
      inventoryImport();
      return;
    }
    if ((el = e.target.closest('[data-action="provider-docs"]'))) {
      e.preventDefault();
      var docsProvider = el.getAttribute('data-provider') || 'provider';
      toast('Scope for ' + docsProvider, 'Open the credential-setup runbook for this provider.', 'info');
      return;
    }
    if ((el = e.target.closest('[data-action="loa-open-template"]'))) {
      e.preventDefault();
      openModal('modal-loa');
      return;
    }
    if ((el = e.target.closest('[data-action="loa-download"]'))) {
      e.preventDefault();
      toast('LOA download', 'PDF export queued. Signed copy will land in the evidence vault under the target group.', 'info');
      return;
    }
    if (
      (el = e.target.closest('[data-action="deploy-copy-container"], [data-action="deploy-download-dockerfile"], [data-action="deploy-download-helm"], [data-action="deploy-download-k8s"], [data-action="deploy-download-deb"], [data-action="deploy-download-deb-arm"], [data-action="deploy-download-rpm"], [data-action="deploy-download-rpm-arm"], [data-action="deploy-download-tarball"], [data-action="deploy-download-manifest"], [data-action="deploy-download-pubkey"], [data-action="deploy-view-cosign"], [data-action="deploy-view-values"], [data-action="download-sbom"], [data-action="download-provenance"]'))
    ) {
      e.preventDefault();
      var label = el.textContent.trim().replace(/\s+/g, ' ');
      toast('Signed artifact', label + ' · pinned by sha256 · cosign-verifiable.', 'info');
      return;
    }
  }

  /* ───────── DNS ownership challenge ───────── */
  function dnsIssueChallenge() {
    var domainInput = document.getElementById('onb-domain');
    var domain = (domainInput && domainInput.value ? domainInput.value.trim() : '').toLowerCase();
    if (!domain) { toast('Domain required', 'Enter a domain before issuing a challenge.', 'warn'); return; }
    var recordName = document.getElementById('dns-record-name');
    var recordValue = document.getElementById('dns-record-value');
    var card = document.getElementById('dns-challenge-card');
    var chip = document.getElementById('dns-status-chip');
    var lastChecked = document.getElementById('dns-last-checked');
    if (recordName) recordName.textContent = '_astranull-challenge.' + domain;
    if (recordValue) recordValue.textContent = 'dnstxt_' + Math.random().toString(36).slice(2, 6) + '_v1.' + Math.random().toString(36).slice(2, 26);
    if (card) card.setAttribute('data-state', 'pending');
    if (chip) { chip.className = 'verify-chip is-pending'; chip.innerHTML = '<span class="vc-dot" aria-hidden="true"></span>pending'; }
    if (lastChecked) lastChecked.textContent = 'Last checked: not yet';
    toast('DNS challenge issued', 'Publish the TXT record at your DNS provider, then click Check now.', 'info');
  }

  function dnsRefreshCheck(btn) {
    var card = document.getElementById('dns-challenge-card');
    var chip = document.getElementById('dns-status-chip');
    var lastChecked = document.getElementById('dns-last-checked');
    if (!card || !chip) return;
    if (btn && btn.disabled) return;
    if (btn) { btn.disabled = true; btn.setAttribute('aria-busy', 'true'); }
    if (chip) { chip.className = 'verify-chip is-checking'; chip.innerHTML = '<span class="vc-dot" aria-hidden="true"></span>checking…'; }
    setTimeout(function () {
      var stamp = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      chip.className = 'verify-chip is-verified';
      chip.innerHTML = '<span class="vc-dot" aria-hidden="true"></span>dns_verified';
      card.setAttribute('data-state', 'verified');
      if (lastChecked) lastChecked.textContent = 'Last checked: ' + stamp + ' · TXT resolved';
      if (btn) { btn.disabled = false; btn.removeAttribute('aria-busy'); }
      toast('DNS verified', 'The TXT record resolved. Target ownership is now dns_verified.', 'info');
    }, 1500);
  }

  function copyById(id, label) {
    var node = document.getElementById(id);
    if (!node) return;
    var text = node.textContent;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () {
        toast('Copied', label + ' copied to clipboard.', 'info');
      }, function () { toast('Copy failed', 'Select the text manually.', 'warn'); });
    } else {
      toast('Copy failed', 'Clipboard access is unavailable in this preview.', 'warn');
    }
  }

  /* ───────── per-target verify action ───────── */
  function targetVerify(btn) {
    var row = btn.closest('tr[data-target]');
    if (!row) return;
    var chip = row.querySelector('.verify-chip');
    btn.disabled = true; btn.textContent = 'Verifying…';
    if (chip) { chip.className = 'verify-chip is-checking'; chip.innerHTML = '<span class="vc-dot" aria-hidden="true"></span>checking…'; }
    setTimeout(function () {
      if (chip) { chip.className = 'verify-chip is-verified'; chip.innerHTML = '<span class="vc-dot" aria-hidden="true"></span>agent_verified'; chip.title = 'probe + agent correlated · just now'; }
      row.classList.remove('is-unverified');
      var locked = row.querySelector('[data-action="run-target-locked"]');
      if (locked) {
        locked.disabled = false;
        locked.removeAttribute('aria-disabled');
        locked.classList.remove('is-locked');
        locked.setAttribute('data-action', 'run-target');
        locked.setAttribute('title', 'Run a bounded safe check against this target');
        locked.innerHTML = 'Run test';
      }
      btn.remove();
      toast('Target verified', 'Probe result correlated with agent observation on the same nonce.', 'info');
    }, 1500);
  }

  /* ───────── Provider inventory picker ───────── */
  var INVENTORY_CATALOG = {
    cloudflare: {
      name: 'Cloudflare',
      eyebrow: 'Cloudflare',
      account: 'acme-prod (id: 3f2a9c4b)',
      scope: 'Zone:Read · DNS:Read',
      note: 'Read-only pull scoped to Zone:Read. AstraNull never edits Cloudflare records.',
      typeLabel: 'zone',
      rows: [
        { name: 'checkout.acme.com', type: 'zone', providerStatus: 'active', records: 42, imported: true, importedAs: 'tgt_checkout_1' },
        { name: 'pay.acme.com', type: 'zone', providerStatus: 'active', records: 18, imported: true, importedAs: 'tgt_checkout_2' },
        { name: 'cdn-checkout.acme.com', type: 'zone', providerStatus: 'active', records: 7, imported: true, importedAs: 'tgt_checkout_4' },
        { name: 'api.acme.com', type: 'zone', providerStatus: 'active', records: 12, imported: false },
        { name: 'www.acme.com', type: 'zone', providerStatus: 'active', records: 24, imported: false },
        { name: 'shop.acme.com', type: 'zone', providerStatus: 'active', records: 9, imported: false },
        { name: 'assets.acme.com', type: 'zone', providerStatus: 'active', records: 6, imported: false },
        { name: 'staging.acme.com', type: 'zone', providerStatus: 'active', records: 15, imported: false }
      ]
    },
    route53: {
      name: 'Route 53',
      eyebrow: 'AWS Route 53',
      account: '918273645510 · role AstraNullReader',
      scope: 'sts:AssumeRole · route53:List*',
      note: 'Read-only STS role. Lists hosted zones and record sets in this account.',
      typeLabel: 'hosted zone',
      rows: [
        { name: 'acme.com', type: 'hosted zone', providerStatus: 'public', records: 68, imported: false },
        { name: 'internal.acme.com', type: 'hosted zone', providerStatus: 'private', records: 34, imported: false },
        { name: 'events.acme.com', type: 'hosted zone', providerStatus: 'public', records: 11, imported: false },
        { name: 'ops.acme.io', type: 'hosted zone', providerStatus: 'public', records: 5, imported: false }
      ]
    },
    godaddy: {
      name: 'GoDaddy',
      eyebrow: 'GoDaddy',
      account: 'acme-billing (customer 4a12b)',
      scope: 'Production API key · domains:read',
      note: 'GoDaddy API returns registered domains. DNS records are fetched per selection on import.',
      typeLabel: 'domain',
      rows: [
        { name: 'acme-labs.io', type: 'domain', providerStatus: 'registered', records: 4, imported: false },
        { name: 'acme-status.com', type: 'domain', providerStatus: 'registered', records: 2, imported: false },
        { name: 'try-acme.co', type: 'domain', providerStatus: 'registered', records: 3, imported: false }
      ]
    },
    namecheap: {
      name: 'Namecheap',
      eyebrow: 'Namecheap',
      account: 'acme-ops · whitelist 203.0.113.42',
      scope: 'API user · namecheap.domains.getList',
      note: 'Namecheap requires a whitelisted source IP. Records fetched read-only per selection.',
      typeLabel: 'domain',
      rows: [
        { name: 'acme-inc.dev', type: 'domain', providerStatus: 'registered', records: 6, imported: false },
        { name: 'acme-inc.app', type: 'domain', providerStatus: 'registered', records: 4, imported: false }
      ]
    },
    aws: {
      name: 'AWS · EC2 & ELB',
      eyebrow: 'AWS EC2 · ELB',
      account: '918273645510 · role AstraNullReader',
      scope: 'ec2:Describe* · elasticloadbalancing:Describe*',
      note: 'Pulls Elastic IPs, ALB / NLB DNS names, and instance public IPs. Rows import as tcp targets bound to an agent.',
      typeLabel: 'resource',
      rows: [
        { name: '203.0.113.10', type: 'elastic-ip', providerStatus: 'associated · edge-01', records: 0, imported: true, importedAs: 'tgt_checkout_3' },
        { name: 'checkout-alb-1234.us-east-1.elb.amazonaws.com', type: 'alb', providerStatus: 'active · 3 targets', records: 1, imported: false },
        { name: 'media-nlb-9877.us-east-1.elb.amazonaws.com', type: 'nlb', providerStatus: 'active · 2 listeners', records: 1, imported: false },
        { name: '198.51.100.42', type: 'elastic-ip', providerStatus: 'associated · edge-02', records: 0, imported: false },
        { name: '198.51.100.87', type: 'elastic-ip', providerStatus: 'unassociated', records: 0, imported: false }
      ]
    },
    gcp: {
      name: 'GCP · Compute & GCLB',
      eyebrow: 'GCP Compute · GCLB',
      account: 'acme-prod · sa astranull-reader@acme-prod.iam',
      scope: 'roles/compute.viewer',
      note: 'Lists external IPs and forwarding rules across regions. Records import as tcp targets.',
      typeLabel: 'resource',
      rows: [
        { name: '34.120.15.42', type: 'external-ip', providerStatus: 'global · gclb', records: 0, imported: false },
        { name: '35.190.44.7', type: 'external-ip', providerStatus: 'regional · us-central1', records: 0, imported: false },
        { name: 'checkout-fr-eu (forwarding rule)', type: 'forwarding-rule', providerStatus: 'active', records: 1, imported: false }
      ]
    },
    azure: {
      name: 'Azure · Public IPs',
      eyebrow: 'Azure · Public IPs · Front Door',
      account: 'acme-prod · sp astranull-reader',
      scope: 'Reader on subscription',
      note: 'Lists public IP resources and Front Door frontends. Records import as tcp / fqdn targets.',
      typeLabel: 'resource',
      rows: [
        { name: 'pip-edge-01', type: 'public-ip', providerStatus: '20.55.7.101 · standard', records: 0, imported: false },
        { name: 'pip-edge-02', type: 'public-ip', providerStatus: '20.55.7.102 · standard', records: 0, imported: false },
        { name: 'acme-fd (front door)', type: 'front-door', providerStatus: '2 frontends', records: 2, imported: false }
      ]
    }
  };

  var inventoryState = { provider: null, filter: 'all', search: '', selected: {} };

  function openInventory(provider) {
    var payload = INVENTORY_CATALOG[provider];
    if (!payload) { toast('Provider not wired', 'Demo inventory for ' + provider + ' is not seeded.', 'warn'); return; }
    inventoryState.provider = provider;
    inventoryState.filter = 'all';
    inventoryState.search = '';
    inventoryState.selected = {};
    var name = document.getElementById('inv-provider-name');
    var eyebrow = document.getElementById('inv-provider-eyebrow');
    var account = document.getElementById('inv-account');
    var scope = document.getElementById('inv-scope');
    var note = document.getElementById('inv-provider-note');
    var stamp = document.getElementById('inv-discovered-at');
    if (name) name.textContent = payload.name;
    if (eyebrow) eyebrow.textContent = payload.eyebrow;
    if (account) account.textContent = payload.account;
    if (scope) scope.textContent = payload.scope;
    if (note) note.textContent = payload.note;
    if (stamp) stamp.textContent = 'just now';
    var searchInput = document.getElementById('inv-search');
    if (searchInput) { searchInput.value = ''; searchInput.oninput = function () { inventoryState.search = searchInput.value.trim().toLowerCase(); inventoryRender(); }; }
    var selectAll = document.getElementById('inv-select-all');
    if (selectAll) { selectAll.checked = false; selectAll.onchange = function () { inventoryToggleAll(selectAll.checked); }; }
    var filterChips = document.querySelectorAll('[data-inv-filter]');
    for (var i = 0; i < filterChips.length; i++) {
      var chip = filterChips[i];
      chip.classList.toggle('is-active', chip.getAttribute('data-inv-filter') === 'all');
    }
    inventoryRender();
    openModal('modal-inventory');
  }

  function inventoryRows() {
    var payload = INVENTORY_CATALOG[inventoryState.provider];
    if (!payload) return [];
    var rows = payload.rows.slice();
    if (inventoryState.filter === 'importable') rows = rows.filter(function (r) { return !r.imported; });
    if (inventoryState.filter === 'imported') rows = rows.filter(function (r) { return r.imported; });
    if (inventoryState.search) {
      var q = inventoryState.search;
      rows = rows.filter(function (r) { return (r.name || '').toLowerCase().indexOf(q) !== -1; });
    }
    return rows;
  }

  function inventoryRender() {
    var tbody = document.getElementById('inv-tbody');
    var emptyNote = document.getElementById('inv-empty-note');
    if (!tbody) return;
    var rows = inventoryRows();
    if (!rows.length) {
      tbody.innerHTML = '<tr><td colspan="6" class="muted" style="padding:24px 16px;text-align:center">No inventory matched this filter.</td></tr>';
      if (emptyNote) emptyNote.hidden = false;
      inventoryUpdateCount();
      return;
    }
    if (emptyNote) emptyNote.hidden = true;
    var html = '';
    for (var i = 0; i < rows.length; i++) {
      var r = rows[i];
      var checked = !!inventoryState.selected[r.name];
      var statusCell = r.imported
        ? '<span class="verify-chip is-verified"><span class="vc-dot" aria-hidden="true"></span>imported</span> <span class="mono muted" style="font-size:var(--text-xs)">' + esc(r.importedAs || '') + '</span>'
        : '<span class="verify-chip is-pending"><span class="vc-dot" aria-hidden="true"></span>importable</span>';
      var checkboxCell = r.imported
        ? '<span class="inv-check is-disabled" aria-hidden="true"><input type="checkbox" disabled></span>'
        : '<label class="inv-check"><input type="checkbox" data-inv-row="' + esc(r.name) + '"' + (checked ? ' checked' : '') + ' aria-label="Select ' + esc(r.name) + '"><span aria-hidden="true"></span></label>';
      html += '<tr class="' + (r.imported ? 'is-already-imported' : '') + '">' +
        '<td class="inv-check-cell">' + checkboxCell + '</td>' +
        '<td><span class="mono">' + esc(r.name) + '</span></td>' +
        '<td class="mono">' + esc(r.type) + '</td>' +
        '<td class="muted">' + esc(r.providerStatus) + '</td>' +
        '<td class="num mono">' + (r.records || 0) + '</td>' +
        '<td>' + statusCell + '</td>' +
      '</tr>';
    }
    tbody.innerHTML = html;
    var boxes = tbody.querySelectorAll('input[data-inv-row]');
    for (var j = 0; j < boxes.length; j++) {
      boxes[j].onchange = function () {
        var key = this.getAttribute('data-inv-row');
        if (this.checked) inventoryState.selected[key] = true;
        else delete inventoryState.selected[key];
        inventoryUpdateCount();
      };
    }
    inventoryUpdateCount();
  }

  function inventoryFilter(f) {
    inventoryState.filter = f;
    var filterChips = document.querySelectorAll('[data-inv-filter]');
    for (var i = 0; i < filterChips.length; i++) {
      filterChips[i].classList.toggle('is-active', filterChips[i].getAttribute('data-inv-filter') === f);
    }
    inventoryRender();
  }

  function inventoryToggleAll(checked) {
    var rows = inventoryRows();
    for (var i = 0; i < rows.length; i++) {
      if (rows[i].imported) continue;
      if (checked) inventoryState.selected[rows[i].name] = true;
      else delete inventoryState.selected[rows[i].name];
    }
    inventoryRender();
  }

  function inventoryUpdateCount() {
    var count = Object.keys(inventoryState.selected).length;
    var counter = document.getElementById('inv-count');
    var importBtn = document.getElementById('inv-import-btn');
    var btnCount = document.getElementById('inv-btn-count');
    if (counter) counter.textContent = count + ' selected';
    if (importBtn) {
      importBtn.disabled = count === 0;
      if (count === 0) importBtn.setAttribute('aria-disabled', 'true');
      else importBtn.removeAttribute('aria-disabled');
    }
    if (btnCount) {
      btnCount.textContent = String(count);
      btnCount.hidden = count === 0;
    }
  }

  function inventoryRefresh(btn) {
    if (!btn) return;
    var original = btn.innerHTML;
    btn.disabled = true;
    btn.setAttribute('aria-busy', 'true');
    var svg = btn.querySelector('svg');
    if (svg) svg.style.animation = 'vc-blink 0.9s ease-in-out infinite';
    setTimeout(function () {
      btn.disabled = false;
      btn.removeAttribute('aria-busy');
      if (svg) svg.style.animation = '';
      var stamp = document.getElementById('inv-discovered-at');
      if (stamp) stamp.textContent = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      inventoryRender();
      toast('Inventory refreshed', 'Latest inventory pulled from the provider.', 'info');
    }, 900);
  }

  function inventoryImport() {
    var count = Object.keys(inventoryState.selected).length;
    if (!count) return;
    var payload = INVENTORY_CATALOG[inventoryState.provider];
    if (!payload) return;
    var picks = payload.rows.filter(function (r) { return inventoryState.selected[r.name]; });
    var tbody = document.querySelector('.tg-targets-table tbody');
    if (tbody) {
      var frag = '';
      var seq = document.querySelectorAll('.tg-targets-table tbody tr').length;
      for (var i = 0; i < picks.length; i++) {
        var r = picks[i];
        seq += 1;
        var kind = (r.type === 'zone' || r.type === 'hosted zone' || r.type === 'domain' || r.type === 'front-door') ? 'fqdn' :
                   (r.type === 'alb' || r.type === 'nlb' || r.type === 'forwarding-rule') ? 'fqdn' :
                   'tcp';
        var chipClass = kind === 'fqdn' ? 'is-pending' : 'is-partial';
        var chipLabel = kind === 'fqdn' ? 'dns_pending' : 'awaiting_heartbeat';
        var chipTitle = kind === 'fqdn'
          ? 'Imported from ' + payload.name + ' · TXT challenge queued'
          : 'Imported from ' + payload.name + ' · awaiting agent heartbeat from this IP';
        frag +=
          '<tr data-target="tgt_import_' + seq + '" class="is-pending is-new">' +
            '<td class="mono">' + kind + '</td>' +
            '<td class="muted">' + esc(r.name) + '</td>' +
            '<td class="mono">' + (kind === 'fqdn' ? 'block_at_edge' : 'absorb_at_origin') + '</td>' +
            '<td><span class="verify-chip ' + chipClass + '" title="' + esc(chipTitle) + '"><span class="vc-dot" aria-hidden="true"></span>' + chipLabel + '</span></td>' +
            '<td class="muted">-</td>' +
            '<td class="row-end row-end-actions">' +
              '<button type="button" class="btn btn-ghost btn-sm" data-action="target-verify" data-target-id="tgt_import_' + seq + '">Verify</button>' +
              '<button type="button" class="btn btn-ghost btn-sm is-locked" data-action="run-target-locked" disabled aria-disabled="true" title="Verify to enable testing">' +
                '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" aria-hidden="true" style="margin-right:6px;vertical-align:-1px"><rect x="5" y="11" width="14" height="9" rx="2" stroke="currentColor" stroke-width="1.6"/><path d="M8 11V8a4 4 0 0 1 8 0v3" stroke="currentColor" stroke-width="1.6"/></svg>' +
                'Run test' +
              '</button>' +
            '</td>' +
          '</tr>';
      }
      tbody.insertAdjacentHTML('beforeend', frag);
    }
    closeModal(document.getElementById('modal-inventory'));
    toast('Imported ' + count + ' from ' + payload.name, 'Added as pending verification. Complete DNS TXT or agent binding to enable probes.', 'info');
  }

  /* ───────── LOA sign ───────── */
  window.__signLoa = function (form) {
    var attest = document.getElementById('loa-attest-check');
    var name = document.getElementById('loa-signer-name');
    var title = document.getElementById('loa-signer-title');
    var date = document.getElementById('loa-signer-date');
    if (!attest || !attest.checked) { toast('Attestation required', 'Tick the attestation before signing.', 'warn'); return; }
    if (!name || !name.value.trim() || !title || !title.value.trim() || !date || !date.value) {
      toast('Signer required', 'Fill signer name, title, and date.', 'warn'); return;
    }
    var digest = 'sha256:' + Math.random().toString(16).slice(2, 10) + '…' + Math.random().toString(16).slice(2, 6);
    closeModal(document.getElementById('modal-loa'));
    var chip = document.getElementById('tg-loa-chip');
    if (chip) { chip.className = 'badge badge--success'; chip.textContent = 'Signed'; }
    var callout = document.getElementById('tg-loa-callout');
    if (callout) {
      callout.setAttribute('data-loa-state', 'signed');
      callout.querySelector('.callout-title').textContent = 'Letter of Authorization on file';
      callout.querySelector('.callout-desc').innerHTML = 'Signed by <strong>' + esc(name.value.trim()) + '</strong> · ' + esc(title.value.trim()) + ' · ' + esc(date.value) + '. Custody digest <span class="mono">' + digest + '</span>.';
      var actionsBox = callout.querySelector('.callout-actions');
      if (actionsBox) actionsBox.innerHTML = '<button type="button" class="btn btn-ghost btn-sm" data-open-modal="modal-loa">View LOA</button>';
    }
    toast('LOA signed', 'Recorded to the authorization custody ledger. Runs are now unlocked for verified targets.', 'info');
  };

  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  /* ───────── init ───────── */
  function init() {
    document.addEventListener('click', onClick);
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') { closeSidebar(); return; }
      if (e.key !== 'Enter' && e.key !== ' ') return;
      var target = e.target;
      if (target && target.closest('button, a, input, select, textarea')) return;
      var el = target.closest('tr[data-route], [data-route][role="link"]');
      if (!el) return;
      e.preventDefault();
      navigate(el.getAttribute('data-route'), el.getAttribute('data-entity'));
    });

    var role = currentRole();
    setRole(role);

    var sel = document.getElementById('role-select');
    if (sel) sel.addEventListener('change', function () { setRole(sel.value); });

    var form = document.getElementById('form-tg');
    if (form) form.addEventListener('submit', function (e) {
      e.preventDefault();
      var d = new FormData(form);
      closeModal(document.getElementById('modal-tg'));
      toast('Target group created', (d.get('name') || 'New group') + ' · declared scope only · safe-by-default.', 'info');
      form.reset();
    });

    revealIn(document);
    drawGauges(document);
    restorePersistedTabs();
    findingsWire();
    findingsRender();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
