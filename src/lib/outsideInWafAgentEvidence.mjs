import { buildOutsideInPostureReport } from './outsideInWafScanner.mjs';

const XSS_PROBE_MARKER_FRAGMENT = 'astranull-xss-probe';

function normalizeNonceHash(value) {
  if (value == null || value === '') return null;
  const s = String(value).trim();
  if (!s) return null;
  if (s.startsWith('sha256:')) return s;
  if (/^[a-f0-9]{64}$/i.test(s)) return `sha256:${s.toLowerCase()}`;
  return s;
}

export function isOutsideInWafAgentObservation(metadata) {
  const md = metadata ?? {};
  if (md.waf_marker === true || md.waf_validation_marker === true) return true;
  if (md.dom_xss_probe === true) return true;
  if (md.scenario_family === 'fingerprint' || md.scenario_family === 'marker') return true;
  if (typeof md.observation_type === 'string' && /waf|marker|xss/i.test(md.observation_type)) return true;
  return false;
}

/**
 * @param {{
 *   agents?: Array<{ nonce_hash?: string|null, metadata?: object }>,
 *   nonceHash?: string|null,
 *   probeValidationPassed?: boolean,
 * }} input
 */
export function resolveOutsideInAgentCorroboration({
  agents = [],
  nonceHash = null,
  probeValidationPassed = false,
} = {}) {
  if (!probeValidationPassed) return false;
  const nonce = normalizeNonceHash(nonceHash);
  if (!nonce) return false;

  const matching = agents.filter((agent) => normalizeNonceHash(agent.nonce_hash) === nonce);
  const wafObservations = matching.filter((agent) => isOutsideInWafAgentObservation(agent.metadata));
  if (wafObservations.length === 0) return false;

  const markerLeak = wafObservations.some((agent) => {
    const md = agent.metadata ?? {};
    if (md.observed_action === 'allow') return true;
    if (md.marker_reached_origin === true && md.waf_blocked !== true && md.observed_action !== 'block') {
      return true;
    }
    if (md.observation_type === 'waf_marker_seen' && md.waf_blocked !== true && md.observed_action !== 'block') {
      return true;
    }
    return false;
  });
  if (markerLeak) return false;

  return wafObservations.some((agent) => {
    const md = agent.metadata ?? {};
    return md.observed_action === 'block'
      || md.waf_blocked === true
      || md.observation_type === 'waf_marker_blocked'
      || md.marker_reached_origin === false;
  });
}

/**
 * @param {{
 *   agents?: Array<{ nonce_hash?: string|null, metadata?: object }>,
 *   nonceHash?: string|null,
 * }} input
 */
export function resolveDomXssValidation({ agents = [], nonceHash = null } = {}) {
  const nonce = normalizeNonceHash(nonceHash);
  if (!nonce) return 'agent_required';

  const matching = agents.filter((agent) => normalizeNonceHash(agent.nonce_hash) === nonce);
  const domObservations = matching.filter((agent) => {
    const md = agent.metadata ?? {};
    return md.dom_xss_probe === true
      || md.observation_type === 'dom_xss_canary'
      || (md.scenario_family === 'xss_marker' && md.waf_marker === true);
  });
  if (domObservations.length === 0) return 'agent_required';

  if (domObservations.some((agent) => agent.metadata?.dom_xss_reflection_observed === true)) {
    return 'reflection_observed';
  }

  if (domObservations.some((agent) => agent.metadata?.dom_xss_blocked === true
    || agent.metadata?.waf_blocked === true
    || agent.metadata?.observed_action === 'block')) {
    return 'agent_corroborated_blocked';
  }

  if (domObservations.some((agent) => agent.metadata?.marker_reached_origin === true
    || agent.metadata?.observation_type === 'waf_marker_seen')) {
    return 'marker_reached_origin';
  }

  return 'agent_observed_no_reflection';
}

/**
 * Recompute outside-in posture labels when agent evidence arrives after probe execution.
 *
 * @param {Record<string, unknown>} metadata
 * @param {{
 *   agents?: Array<{ nonce_hash?: string|null, metadata?: object }>,
 *   nonceHash?: string|null,
 * }} context
 */
export function enrichOutsideInWafProbeMetadata(metadata, { agents = [], nonceHash = null } = {}) {
  if (!metadata || metadata.probe_kind !== 'outside_in_waf_scan') return metadata;

  const agentCorroborated = resolveOutsideInAgentCorroboration({
    agents,
    nonceHash,
    probeValidationPassed: metadata.probe_validation_passed === true,
  }) || metadata.agent_corroborated === true;

  const domXssValidation = resolveDomXssValidation({ agents, nonceHash });

  if (agentCorroborated === metadata.agent_corroborated
    && domXssValidation === metadata.dom_xss_validation) {
    return metadata;
  }

  const posture = buildOutsideInPostureReport({
    wafDetected: metadata.waf_detected === true,
    genericWafDetected: metadata.generic_waf_detected === true,
    markerResults: Array.isArray(metadata.marker_probes) ? metadata.marker_probes : [],
    originBypassConfirmed: metadata.origin_bypass_confirmed === true,
    wafRequired: metadata.waf_required !== false,
    vendorClassification: (metadata.detected_vendor || metadata.detected_product)
      ? {
        best: {
          vendor: metadata.detected_vendor ?? null,
          product: metadata.detected_product ?? null,
          confidence: Number(metadata.waf_confidence) || 0.45,
        },
      }
      : null,
    agentCorroborated,
    requireAgentForProtected: metadata.agent_corroboration_required !== false,
    evasionBypassSuspected: metadata.evasion_bypass_suspected === true,
    domXssValidation,
  });

  return {
    ...metadata,
    ...posture,
  };
}

export { XSS_PROBE_MARKER_FRAGMENT };