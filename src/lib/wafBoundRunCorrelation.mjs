export const EXTERNAL_WAF_PASS = new Set([
  'blocked',
  'challenge',
  'challenged',
  'rate_limited',
  'filtered',
]);
export const EXTERNAL_WAF_FAIL = new Set([
  'allowed',
  'reached_origin',
  'delivered',
  'connected',
]);

function normalizeExternalResult(value) {
  return String(value ?? '').trim().toLowerCase();
}

function hasWafFingerprintHint(metadata) {
  const md = metadata ?? {};
  return Boolean(
    md.waf_fingerprint_detected === true
    || (typeof md.block_page_fingerprint_hash === 'string' && md.block_page_fingerprint_hash.trim())
    || (typeof md.waf_product_hint === 'string' && md.waf_product_hint.trim())
    || (typeof md.detected_vendor === 'string' && md.detected_vendor.trim()),
  );
}

function isWafMarkerAgentMetadata(metadata) {
  const md = metadata ?? {};
  if (md.waf_marker === true || md.waf_validation_marker === true) return true;
  if (typeof md.marker_type === 'string' && md.marker_type.trim()) return true;
  if (md.scenario_family === 'marker') return true;
  if (md.canary_observation === true && (md.waf_marker === true || md.waf_validation_marker === true)) {
    return true;
  }
  return false;
}

/**
 * Derive WAF validation signals from metadata-only probe/agent events correlated by nonce_hash.
 *
 * @param {{ probes: Array<{ id: string, nonce_hash?: string|null, metadata?: object }>, agents: Array<{ nonce_hash?: string|null, metadata?: object }> }} input
 */
export function deriveWafSignalsFromBoundEvents({ probes = [], agents = [] }) {
  const agentsByNonce = new Map();
  for (const agentEvent of agents) {
    if (!agentEvent.nonce_hash) continue;
    const bucket = agentsByNonce.get(agentEvent.nonce_hash) ?? [];
    bucket.push(agentEvent);
    agentsByNonce.set(agentEvent.nonce_hash, bucket);
  }

  let wafDetected = false;
  let anyPass = false;
  let validationFailed = false;
  let originBypassConfirmed = false;
  let hasExternalProbeEvidence = false;
  const scenarioResults = [];

  for (const probe of probes) {
    if (hasWafFingerprintHint(probe.metadata)) {
      wafDetected = true;
    }

    const external = normalizeExternalResult(probe.metadata?.external_result);
    if (!external) continue;
    hasExternalProbeEvidence = true;

    const nonce = probe.nonce_hash ?? null;
    const matchingAgents = nonce ? (agentsByNonce.get(nonce) ?? []) : [];
    const wafMarkerAgents = matchingAgents.filter((a) => isWafMarkerAgentMetadata(a.metadata));

    let passed = null;
    let observed_action = 'inconclusive';
    if (EXTERNAL_WAF_FAIL.has(external)) {
      validationFailed = true;
      passed = false;
      observed_action = 'allow';
      if (external === 'reached_origin' || external === 'delivered') {
        originBypassConfirmed = true;
      }
    } else if (EXTERNAL_WAF_PASS.has(external)) {
      wafDetected = true;
      if (wafMarkerAgents.length > 0) {
        validationFailed = true;
        passed = false;
        observed_action = 'allow';
      } else if (nonce && hasWafFingerprintHint(probe.metadata)) {
        anyPass = true;
        passed = true;
        observed_action = 'block';
      } else {
        passed = null;
        observed_action = 'inconclusive';
      }
    }

    const agentObservedBlock = wafMarkerAgents.some(
      (agent) => agent.metadata?.observed_action === 'block'
        || agent.metadata?.waf_blocked === true,
    );

    const evidence_summary = {
      request_id: probe.id,
      nonce_hash: nonce ?? undefined,
      marker_result: external,
      blocked: EXTERNAL_WAF_PASS.has(external),
      observed_at_agent: agentObservedBlock || wafMarkerAgents.length > 0,
      test_run_id: probe.metadata?.test_run_id ?? undefined,
      probe_job_id: probe.metadata?.probe_job_id ?? probe.id,
    };

    scenarioResults.push({
      scenario_family: 'marker',
      expected_action: 'block',
      observed_action,
      passed,
      confidence: passed === true ? 0.85 : passed === false ? 0.8 : 0,
      evidence_summary,
    });
  }

  const validationPassed = hasExternalProbeEvidence && anyPass && !validationFailed;

  return {
    wafDetected,
    validationPassed,
    validationFailed,
    originBypassConfirmed,
    scenarioResults,
    source_external: hasExternalProbeEvidence,
    source_agent: agents.length > 0,
  };
}

export function booleanFieldExplicit(body, snake, camel) {
  return Object.prototype.hasOwnProperty.call(body, snake)
    || Object.prototype.hasOwnProperty.call(body, camel);
}