/**
 * Outside-in WAF scanner — bounded metadata-only edge validation.
 * Detects WAF presence, fingerprints vendor/product, validates benign class markers
 * (including safe evasion variants), content-type confusion, optional origin bypass,
 * and emits a posture summary. Protected requires agent corroboration by default.
 */

import { createHash } from 'node:crypto';
import { classifyWafPosture } from '../contracts/wafPosture.mjs';
import { classifyWafProductFromSignals } from './wafProductCatalog.mjs';

const MAX_BODY_READ_BYTES = 8192;
const BLOCK_STATUSES = new Set([401, 403, 406, 429, 503]);
const CHALLENGE_HEADERS = ['cf-mitigated', 'x-waf-block', 'x-bot-challenge', 'x-sucuri-block'];

export const BENIGN_CLASS_MARKERS = Object.freeze({
  xss: '<astranull-xss-probe/>',
  sqli: "astranull' OR '1'='0",
  path_traversal: '../../astranull-probe',
});

/** Safe evasion-class variants — single-request probes, not reusable attack tooling. */
export const EVASION_VARIANT_MARKERS = Object.freeze({
  sqli_encoded: encodeURIComponent(encodeURIComponent(BENIGN_CLASS_MARKERS.sqli)),
  sqli_case: "AsTrAnUlL' oR '1'='0",
  sqli_comment: "astranull' O/**/R '1'='0",
  xss_encoded: encodeURIComponent(BENIGN_CLASS_MARKERS.xss),
  path_encoded: encodeURIComponent(BENIGN_CLASS_MARKERS.path_traversal),
});

export const OUTSIDE_IN_SCAN_PHASES = Object.freeze([
  'baseline',
  'combined_marker',
  'path_traversal_marker',
  'sqli_marker',
  'xss_marker',
  'sqli_encoded_marker',
  'sqli_case_marker',
  'sqli_comment_marker',
  'xss_encoded_marker',
  'no_user_agent',
  'content_type_confusion',
  'origin_bypass',
]);

export const OUTSIDE_IN_SCAN_DEFAULT_BUDGET = 10;

const DEFAULT_BROWSER_HEADERS = Object.freeze({
  Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'User-Agent': 'Mozilla/5.0 (compatible; AstraNullOutsideIn/1.0; +https://astranull.invalid/probe)',
  'Accept-Language': 'en-US,en;q=0.5',
  DNT: '1',
});

const BLOCK_PAGE_SIGNATURE_RULES = Object.freeze([
  { id: 'block_sig_cloudflare_generic_v1', pattern: /cloudflare|cf-ray/i },
  { id: 'block_sig_akamai_generic_v1', pattern: /akamai|reference\s+#\d+\.\w+\.\d+\.\d+\.\d+/i },
  { id: 'block_sig_incapsula_generic_v1', pattern: /incapsula|imperva|visid_incap/i },
  { id: 'block_sig_aws_waf_v1', pattern: /request blocked|aws.?waf|x-amz-cf-id/i },
  { id: 'block_sig_modsecurity_v1', pattern: /mod.?security|modsecurity/i },
  { id: 'block_sig_sucuri_v1', pattern: /sucuri|cloudproxy@sucuri/i },
  { id: 'block_sig_f5_asm_v1', pattern: /the requested url was rejected|support id|f5/i },
  { id: 'block_sig_barracuda_v1', pattern: /barracuda/i },
  { id: 'block_sig_fortiweb_v1', pattern: /fortiweb|fortigate/i },
  { id: 'block_sig_azure_waf_v1', pattern: /azure|front door|application gateway/i },
  { id: 'block_sig_fastly_v1', pattern: /fastly error|fastly-ssl/i },
  { id: 'block_sig_radware_v1', pattern: /radware|appwall/i },
  { id: 'block_sig_paloalto_v1', pattern: /palo alto|prisma/i },
  { id: 'block_sig_generic_waf_v1', pattern: /access denied|request rejected|security policy|web application firewall/i },
]);

function randomParamName() {
  return `p${createHash('sha256').update(String(Date.now())).digest('hex').slice(0, 8)}`;
}

function hashBodySnippet(text) {
  const snippet = String(text ?? '').slice(0, MAX_BODY_READ_BYTES);
  if (!snippet) return null;
  return createHash('sha256').update(snippet).digest('hex').slice(0, 32);
}

function headerNamesFromResponse(res) {
  if (!res?.headers) return [];
  const names = [];
  if (typeof res.headers.forEach === 'function') {
    res.headers.forEach((_value, name) => names.push(String(name).toLowerCase()));
    return [...new Set(names)].sort();
  }
  if (typeof res.headers === 'object') {
    return [...new Set(Object.keys(res.headers).map((k) => String(k).toLowerCase()))].sort();
  }
  return [];
}

function headerValue(res, name) {
  if (!res?.headers?.get) return null;
  return res.headers.get(name);
}

function cookieNamesFromResponse(res) {
  const raw = headerValue(res, 'set-cookie');
  if (!raw) return [];
  return [...new Set(
    String(raw)
      .split(/,(?=[^;]+?=)/)
      .map((part) => part.split('=')[0]?.trim())
      .filter(Boolean)
      .map((name) => name.toLowerCase()),
  )].sort();
}

function matchBlockPageSignature(bodyText) {
  const text = String(bodyText ?? '').slice(0, MAX_BODY_READ_BYTES);
  if (!text) return null;
  for (const rule of BLOCK_PAGE_SIGNATURE_RULES) {
    if (rule.pattern.test(text)) return rule.id;
  }
  return null;
}

function responseSnapshot(res, bodyText = '') {
  if (!res) {
    return {
      status_code: 0,
      status_code_class: 'error',
      header_names: [],
      cookie_names: [],
      server_header: null,
      block_page_signature_id: null,
      block_page_fingerprint_hash: null,
      connection_dropped: true,
    };
  }
  const status = res.status ?? 0;
  return {
    status_code: status,
    status_code_class: status >= 500 ? '5xx' : status >= 400 ? '4xx' : status >= 300 ? '3xx' : '2xx',
    header_names: headerNamesFromResponse(res),
    cookie_names: cookieNamesFromResponse(res),
    server_header: headerValue(res, 'server'),
    block_page_signature_id: matchBlockPageSignature(bodyText),
    block_page_fingerprint_hash: hashBodySnippet(bodyText),
    connection_dropped: false,
  };
}

export function isBlockedOrChallenged(snapshot, baseline = null) {
  if (!snapshot || snapshot.connection_dropped) return { blocked: true, challenged: false, allowed: false };
  const status = snapshot.status_code;
  if (BLOCK_STATUSES.has(status)) {
    return { blocked: true, challenged: status === 403 || status === 401, allowed: false };
  }
  if (status >= 300 && status < 400) {
    return { blocked: true, challenged: true, allowed: false };
  }
  for (const name of CHALLENGE_HEADERS) {
    if (snapshot.header_names.includes(name)) {
      return { blocked: true, challenged: true, allowed: false };
    }
  }
  if (snapshot.block_page_signature_id) {
    return { blocked: true, challenged: false, allowed: false };
  }
  if (baseline && baseline.status_code !== status) {
    const baselineOk = baseline.status_code >= 200 && baseline.status_code < 400;
    const probeOk = status >= 200 && status < 400;
    if (baselineOk !== probeOk || (baseline.server_header && snapshot.server_header
      && baseline.server_header !== snapshot.server_header)) {
      return { blocked: true, challenged: false, allowed: false };
    }
  }
  if (status >= 200 && status < 300) {
    return { blocked: false, challenged: false, allowed: true };
  }
  return { blocked: false, challenged: false, allowed: false };
}

export function detectGenericWafPresence({ baseline, attack, noUserAgent } = {}) {
  const reasons = [];
  if (!baseline || baseline.connection_dropped) {
    return { detected: true, reason: 'connection_dropped_on_baseline', reasons: ['connection_dropped_on_baseline'] };
  }
  if (attack?.connection_dropped) {
    return { detected: true, reason: 'connection_dropped_on_marker', reasons: ['connection_dropped_on_marker'] };
  }
  if (attack && baseline.status_code !== attack.status_code) reasons.push('status_code_drift');
  if (attack && baseline.server_header && attack.server_header
    && baseline.server_header !== attack.server_header) {
    reasons.push('server_header_drift');
  }
  if (noUserAgent && baseline.status_code !== noUserAgent.status_code) reasons.push('no_user_agent_drift');
  if (attack?.block_page_signature_id) reasons.push('block_page_signature');
  return { detected: reasons.length > 0, reason: reasons[0] ?? null, reasons };
}

function recordMarkerResult(markerResults, entry) {
  const existing = markerResults.find((row) => row.family === entry.family && row.variant === entry.variant);
  if (existing) Object.assign(existing, entry);
  else markerResults.push(entry);
}

function detectEvasionBypass(markerResults) {
  const plainFamilies = ['sqli_marker', 'xss_marker', 'path_traversal_marker'];
  const evasionFamilies = [
    'sqli_encoded_marker',
    'sqli_case_marker',
    'sqli_comment_marker',
    'xss_encoded_marker',
    'content_type_confusion',
  ];
  const plainRows = markerResults.filter((row) => plainFamilies.includes(row.family));
  const plainBlocked = plainRows.length > 0 && plainRows.every((row) => row.blocked);
  const evasionAllowed = markerResults
    .filter((row) => evasionFamilies.includes(row.family))
    .some((row) => row.allowed);
  return plainBlocked && evasionAllowed;
}

/**
 * @param {object} input
 * @param {boolean} [input.agentCorroborated=false]
 * @param {boolean} [input.requireAgentForProtected=true]
 */
export function buildOutsideInPostureReport({
  wafDetected = false,
  genericWafDetected = false,
  markerResults = [],
  originBypassConfirmed = false,
  wafRequired = true,
  vendorClassification = null,
  agentCorroborated = false,
  requireAgentForProtected = true,
  evasionBypassSuspected = false,
} = {}) {
  const anyMarkerAllowed = markerResults.some((m) => m.allowed === true);
  const anyMarkerBlocked = markerResults.some((m) => m.blocked === true);
  const probeValidationPassed = markerResults.length > 0 && anyMarkerBlocked && !anyMarkerAllowed;
  const validationFailed = markerResults.length > 0 && (anyMarkerAllowed || evasionBypassSuspected);

  let validationPassed = probeValidationPassed && !evasionBypassSuspected;
  if (requireAgentForProtected && validationPassed && !agentCorroborated) {
    validationPassed = false;
  }

  const posture = classifyWafPosture({
    wafDetected: wafDetected || genericWafDetected,
    validationPassed,
    validationFailed,
    originBypassConfirmed,
    wafRequired,
  });

  const reason_codes = [...posture.reason_codes];
  if (evasionBypassSuspected && !reason_codes.includes('scenario_category_failed')) {
    reason_codes.push('scenario_category_failed');
  }
  if (probeValidationPassed && requireAgentForProtected && !agentCorroborated
    && !reason_codes.includes('insufficient_validation_evidence')) {
    reason_codes.push('insufficient_validation_evidence');
  }

  let posture_label = 'Unknown';
  let posture_status = posture.status;

  if (originBypassConfirmed) {
    posture_label = 'Bypass Risk';
    posture_status = 'underprotected';
  } else if (validationFailed) {
    posture_label = 'Underprotected';
    posture_status = 'underprotected';
  } else if (validationPassed && agentCorroborated) {
    posture_label = 'Protected';
    posture_status = 'protected';
  } else if (probeValidationPassed && (wafDetected || genericWafDetected) && !agentCorroborated) {
    posture_label = 'Detected, not validated';
    posture_status = 'unknown';
  } else if (posture.status === 'unprotected') {
    posture_label = 'Unprotected';
  } else if (posture.status === 'excluded') {
    posture_label = 'Excluded';
  } else if (posture.status === 'underprotected') {
    posture_label = 'Underprotected';
  }

  const best = vendorClassification?.best ?? null;
  return {
    posture_status,
    posture_label,
    reason_codes: [...new Set(reason_codes)],
    waf_detected: wafDetected || genericWafDetected || Boolean(best),
    waf_fingerprint_detected: Boolean(best) || wafDetected || genericWafDetected,
    generic_waf_detected: genericWafDetected,
    detected_vendor: best?.vendor ?? null,
    detected_product: best?.product ?? null,
    waf_product_hint: best ? `${best.vendor}/${best.product}` : null,
    waf_confidence: best?.confidence ?? (genericWafDetected ? 0.45 : 0),
    validation_passed: validationPassed,
    validation_failed: validationFailed,
    probe_validation_passed: probeValidationPassed,
    agent_corroborated: agentCorroborated,
    agent_corroboration_required: requireAgentForProtected,
    evasion_bypass_suspected: evasionBypassSuspected,
    dom_xss_validation: 'agent_required',
    origin_bypass_confirmed: originBypassConfirmed,
    marker_summary: {
      probes_sent: markerResults.length,
      blocked_count: markerResults.filter((m) => m.blocked).length,
      allowed_count: markerResults.filter((m) => m.allowed).length,
      challenged_count: markerResults.filter((m) => m.challenged).length,
      evasion_probes_sent: markerResults.filter((m) => String(m.variant ?? '') !== 'plain').length,
    },
  };
}

function buildUrl(baseUrl, { pathSuffix = '', params = {}, rawParams = {} } = {}) {
  const url = new URL(baseUrl);
  if (pathSuffix) {
    const joined = `${url.pathname.replace(/\/$/, '')}/${pathSuffix}`.replace(/\/+/g, '/');
    url.pathname = joined.startsWith('/') ? joined : `/${joined}`;
  }
  for (const [key, value] of Object.entries(params)) {
    url.searchParams.set(key, value);
  }
  let href = url.href;
  for (const [key, value] of Object.entries(rawParams)) {
    const sep = href.includes('?') ? '&' : '?';
    href = `${href}${sep}${key}=${value}`;
  }
  return href;
}

async function boundedRequest(url, { method = 'GET', headers = {}, body = null }, timeoutMs, deps) {
  const fetchFn = deps.fetchFn ?? fetch;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchFn(url, {
      method,
      headers,
      body,
      redirect: 'manual',
      signal: controller.signal,
    });
    let bodyText = '';
    if (res && typeof res.text === 'function') {
      const full = await res.text();
      bodyText = String(full).slice(0, MAX_BODY_READ_BYTES);
    }
    return { res, bodyText, error: null };
  } catch (err) {
    return { res: null, bodyText: '', error: err };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Priority-ordered scan phases for a given request budget.
 * @param {number} budget
 * @param {{ hasDirectIp?: boolean }} options
 */
export function buildOutsideInScanPlan(budget, { hasDirectIp = false } = {}) {
  const ordered = [
    { phase: 'baseline', method: 'GET' },
    { phase: 'combined_marker', method: 'GET' },
    { phase: 'path_traversal_marker', method: 'GET' },
    { phase: 'sqli_marker', method: 'GET' },
    { phase: 'sqli_encoded_marker', method: 'GET' },
    { phase: 'sqli_case_marker', method: 'GET' },
    { phase: 'sqli_comment_marker', method: 'GET' },
    { phase: 'content_type_confusion', method: 'POST' },
    { phase: 'xss_marker', method: 'GET' },
    { phase: 'xss_encoded_marker', method: 'GET' },
    { phase: 'no_user_agent', method: 'GET' },
  ];
  if (hasDirectIp) ordered.push({ phase: 'origin_bypass', method: 'HEAD' });

  if (hasDirectIp && budget >= 10) {
    const reserve = ordered.filter((entry) => entry.phase !== 'no_user_agent' && entry.phase !== 'origin_bypass');
    const picked = reserve.slice(0, budget - 1);
    picked.push(ordered.find((entry) => entry.phase === 'origin_bypass'));
    return picked.filter(Boolean);
  }

  return ordered.slice(0, budget);
}

/**
 * @param {{
 *   url: string,
 *   hostname?: string,
 *   directIp?: string,
 *   budget?: number,
 *   timeoutMs?: number,
 *   wafRequired?: boolean,
 *   customerVendorHint?: string,
 *   agentCorroborated?: boolean,
 *   requireAgentForProtected?: boolean,
 *   fetchFn?: typeof fetch,
 *   originBypassFn?: (args: object) => Promise<{ res: object|null, error: Error|null }>,
 * }} options
 */
export async function runOutsideInWafScan(options = {}) {
  const url = String(options.url ?? '').trim();
  if (!url) {
    return { error_class: 'unsupported_target', requests_sent: 0, phases: [] };
  }

  const budget = Number.isInteger(options.budget) && options.budget > 0
    ? options.budget
    : OUTSIDE_IN_SCAN_DEFAULT_BUDGET;
  const timeoutMs = Number.isInteger(options.timeoutMs) && options.timeoutMs > 0 ? options.timeoutMs : 5000;
  const deps = { fetchFn: options.fetchFn };
  const started = Date.now();
  let requestsSent = 0;
  const phaseLog = [];
  const markerResults = [];

  const directIp = options.directIp ?? null;
  const hostname = options.hostname ?? (() => {
    try { return new URL(url).hostname; } catch { return null; }
  })();
  const plan = buildOutsideInScanPlan(budget, { hasDirectIp: Boolean(directIp && hostname) });
  const plannedPhases = new Set(plan.map((entry) => entry.phase));

  async function runGetPhase(phase, requestUrl, headers) {
    if (requestsSent >= budget) return null;
    requestsSent += 1;
    const { res, bodyText, error } = await boundedRequest(requestUrl, { method: 'GET', headers }, timeoutMs, deps);
    const snapshot = error
      ? { ...responseSnapshot(null), error_class: error.name ?? error.code ?? 'probe_failed' }
      : responseSnapshot(res, bodyText);
    phaseLog.push({ phase, status_code: snapshot.status_code });
    return snapshot;
  }

  let baseline = null;
  let combined = null;
  let sqli = null;
  let xss = null;
  let pathTraversal = null;
  let noUserAgent = null;

  if (plannedPhases.has('baseline')) {
    baseline = await runGetPhase('baseline', url, { ...DEFAULT_BROWSER_HEADERS });
    if (!baseline) return { error_class: 'request_budget_exhausted', requests_sent: requestsSent, phases: phaseLog };
  }

  if (plannedPhases.has('combined_marker')) {
    const combinedParams = {
      [randomParamName()]: BENIGN_CLASS_MARKERS.xss,
      [randomParamName()]: BENIGN_CLASS_MARKERS.sqli,
      [randomParamName()]: BENIGN_CLASS_MARKERS.path_traversal,
    };
    combined = await runGetPhase('combined_marker', buildUrl(url, { params: combinedParams }), { ...DEFAULT_BROWSER_HEADERS });
    if (combined) {
      const evalResult = isBlockedOrChallenged(combined, baseline);
      recordMarkerResult(markerResults, { family: 'sqli_marker', variant: 'plain', ...evalResult, status_code: combined.status_code });
      recordMarkerResult(markerResults, { family: 'xss_marker', variant: 'plain', ...evalResult, status_code: combined.status_code });
    }
  }

  if (plannedPhases.has('path_traversal_marker')) {
    pathTraversal = await runGetPhase(
      'path_traversal_marker',
      buildUrl(url, { pathSuffix: BENIGN_CLASS_MARKERS.path_traversal }),
      { ...DEFAULT_BROWSER_HEADERS },
    );
    if (pathTraversal) {
      recordMarkerResult(markerResults, {
        family: 'path_traversal_marker',
        variant: 'plain',
        ...isBlockedOrChallenged(pathTraversal, baseline),
        status_code: pathTraversal.status_code,
      });
    }
  }

  if (plannedPhases.has('sqli_marker')) {
    sqli = await runGetPhase(
      'sqli_marker',
      buildUrl(url, { params: { [randomParamName()]: BENIGN_CLASS_MARKERS.sqli } }),
      { ...DEFAULT_BROWSER_HEADERS },
    );
    if (sqli) {
      recordMarkerResult(markerResults, {
        family: 'sqli_marker',
        variant: 'plain',
        ...isBlockedOrChallenged(sqli, baseline),
        status_code: sqli.status_code,
      });
    }
  }

  if (plannedPhases.has('sqli_encoded_marker')) {
    const snap = await runGetPhase(
      'sqli_encoded_marker',
      buildUrl(url, { rawParams: { [randomParamName()]: EVASION_VARIANT_MARKERS.sqli_encoded } }),
      { ...DEFAULT_BROWSER_HEADERS },
    );
    if (snap) {
      recordMarkerResult(markerResults, {
        family: 'sqli_encoded_marker',
        variant: 'double_url_encoded',
        ...isBlockedOrChallenged(snap, baseline),
        status_code: snap.status_code,
      });
    }
  }

  if (plannedPhases.has('sqli_case_marker')) {
    const snap = await runGetPhase(
      'sqli_case_marker',
      buildUrl(url, { params: { [randomParamName()]: EVASION_VARIANT_MARKERS.sqli_case } }),
      { ...DEFAULT_BROWSER_HEADERS },
    );
    if (snap) {
      recordMarkerResult(markerResults, {
        family: 'sqli_case_marker',
        variant: 'case_mixed',
        ...isBlockedOrChallenged(snap, baseline),
        status_code: snap.status_code,
      });
    }
  }

  if (plannedPhases.has('sqli_comment_marker')) {
    const snap = await runGetPhase(
      'sqli_comment_marker',
      buildUrl(url, { params: { [randomParamName()]: EVASION_VARIANT_MARKERS.sqli_comment } }),
      { ...DEFAULT_BROWSER_HEADERS },
    );
    if (snap) {
      recordMarkerResult(markerResults, {
        family: 'sqli_comment_marker',
        variant: 'comment_insertion',
        ...isBlockedOrChallenged(snap, baseline),
        status_code: snap.status_code,
      });
    }
  }

  if (plannedPhases.has('xss_marker')) {
    xss = await runGetPhase(
      'xss_marker',
      buildUrl(url, { params: { [randomParamName()]: BENIGN_CLASS_MARKERS.xss } }),
      { ...DEFAULT_BROWSER_HEADERS },
    );
    if (xss) {
      recordMarkerResult(markerResults, {
        family: 'xss_marker',
        variant: 'plain',
        ...isBlockedOrChallenged(xss, baseline),
        status_code: xss.status_code,
      });
    }
  }

  if (plannedPhases.has('xss_encoded_marker')) {
    const snap = await runGetPhase(
      'xss_encoded_marker',
      buildUrl(url, { rawParams: { [randomParamName()]: EVASION_VARIANT_MARKERS.xss_encoded } }),
      { ...DEFAULT_BROWSER_HEADERS },
    );
    if (snap) {
      recordMarkerResult(markerResults, {
        family: 'xss_encoded_marker',
        variant: 'url_encoded',
        ...isBlockedOrChallenged(snap, baseline),
        status_code: snap.status_code,
      });
    }
  }

  if (plannedPhases.has('no_user_agent')) {
    const noUaHeaders = { ...DEFAULT_BROWSER_HEADERS };
    delete noUaHeaders['User-Agent'];
    noUserAgent = await runGetPhase('no_user_agent', url, noUaHeaders);
  }

  if (plannedPhases.has('content_type_confusion') && requestsSent < budget) {
    requestsSent += 1;
    const formBody = `${randomParamName()}=${encodeURIComponent(BENIGN_CLASS_MARKERS.sqli)}`;
    const { res, bodyText, error } = await boundedRequest(url, {
      method: 'POST',
      headers: {
        ...DEFAULT_BROWSER_HEADERS,
        'Content-Type': 'application/json',
        'Content-Length': String(formBody.length),
      },
      body: formBody,
    }, timeoutMs, deps);
    const snapshot = error
      ? { ...responseSnapshot(null), error_class: error.name ?? error.code ?? 'probe_failed' }
      : responseSnapshot(res, bodyText);
    phaseLog.push({ phase: 'content_type_confusion', status_code: snapshot.status_code });
    const contentTypeEval = snapshot.status_code >= 200 && snapshot.status_code < 300
      ? { blocked: false, challenged: false, allowed: true }
      : isBlockedOrChallenged(snapshot, baseline);
    recordMarkerResult(markerResults, {
      family: 'content_type_confusion',
      variant: 'json_header_form_body',
      ...contentTypeEval,
      status_code: snapshot.status_code,
    });
  }

  let originBypassConfirmed = false;
  let originBypassStatus = null;
  if (plannedPhases.has('origin_bypass') && directIp && hostname
    && requestsSent < budget && typeof options.originBypassFn === 'function') {
    requestsSent += 1;
    const { res, error } = await options.originBypassFn({ directIp, hostname, timeoutMs, deps });
    originBypassStatus = error ? 0 : (res?.status ?? 0);
    originBypassConfirmed = !error && originBypassStatus >= 200 && originBypassStatus < 400;
    phaseLog.push({ phase: 'origin_bypass', status_code: originBypassStatus, bypass_signal: originBypassConfirmed });
  }

  const attackSnapshot = combined ?? sqli ?? xss ?? pathTraversal ?? baseline;
  const generic = detectGenericWafPresence({ baseline, attack: attackSnapshot, noUserAgent });
  const signalSource = attackSnapshot?.header_names?.length >= baseline?.header_names?.length
    ? attackSnapshot
    : baseline;
  const vendorClassification = classifyWafProductFromSignals({
    header_names: [...new Set([...(baseline?.header_names ?? []), ...(signalSource?.header_names ?? [])])],
    cookie_names: [...new Set([...(baseline?.cookie_names ?? []), ...(signalSource?.cookie_names ?? [])])],
    block_page_signature_id: attackSnapshot?.block_page_signature_id ?? baseline?.block_page_signature_id ?? null,
    customer_vendor_hint: options.customerVendorHint ?? null,
    waf_present: generic.detected || Boolean(attackSnapshot?.block_page_signature_id),
  });

  const wafDetected = Boolean(vendorClassification.best) || generic.detected;
  const evasionBypassSuspected = detectEvasionBypass(markerResults);
  const posture = buildOutsideInPostureReport({
    wafDetected,
    genericWafDetected: generic.detected,
    markerResults,
    originBypassConfirmed,
    wafRequired: options.wafRequired !== false,
    vendorClassification,
    agentCorroborated: options.agentCorroborated === true,
    requireAgentForProtected: options.requireAgentForProtected !== false,
    evasionBypassSuspected,
  });

  const durationMs = Date.now() - started;
  const external_result = originBypassConfirmed || posture.validation_failed
    ? 'connected'
    : posture.validation_passed || (wafDetected && posture.probe_validation_passed)
      ? 'blocked'
      : wafDetected
        ? 'blocked'
        : 'connected';

  return {
    duration_ms: durationMs,
    requests_sent: requestsSent,
    phases: phaseLog,
    scan_plan: plan.map((entry) => entry.phase),
    baseline_status_code: baseline?.status_code ?? 0,
    header_names: signalSource?.header_names ?? baseline?.header_names ?? [],
    cookie_names: signalSource?.cookie_names ?? baseline?.cookie_names ?? [],
    block_page_signature_id: attackSnapshot?.block_page_signature_id ?? null,
    block_page_fingerprint_hash: attackSnapshot?.block_page_fingerprint_hash ?? null,
    generic_waf_reasons: generic.reasons,
    marker_probes: markerResults,
    origin_bypass_confirmed: originBypassConfirmed,
    origin_bypass_status_code: originBypassStatus,
    vendor_candidates: (vendorClassification.candidates ?? []).slice(0, 3),
    ...posture,
    external_result,
  };
}