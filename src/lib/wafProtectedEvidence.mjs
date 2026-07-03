import { EXTERNAL_WAF_PASS } from './wafBoundRunCorrelation.mjs';

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
 * @param {{ probes?: object[], agents?: object[] }} input
 */
export function buildWafEvidenceCorroboration({ probes = [], agents = [] } = {}) {
  const probesById = new Map();
  const probesByNonce = new Map();
  const agentsByNonce = new Map();

  for (const probe of probes) {
    if (probe?.id) {
      probesById.set(String(probe.id), probe);
    }
    if (probe?.nonce_hash) {
      const bucket = probesByNonce.get(probe.nonce_hash) ?? [];
      bucket.push(probe);
      probesByNonce.set(probe.nonce_hash, bucket);
    }
  }

  for (const agent of agents) {
    if (!agent?.nonce_hash) continue;
    const bucket = agentsByNonce.get(agent.nonce_hash) ?? [];
    bucket.push(agent);
    agentsByNonce.set(agent.nonce_hash, bucket);
  }

  return { probesById, probesByNonce, agentsByNonce };
}

/**
 * @param {object} scenario
 * @param {ReturnType<typeof buildWafEvidenceCorroboration>} corroboration
 */
export function corroborateProtectedScenarioEvidence(scenario, corroboration) {
  if (!scenario || scenario.passed !== true) return false;

  const evidence = scenario.evidence_summary_json ?? scenario.evidence_summary ?? {};
  const nonceHash = typeof evidence.nonce_hash === 'string' ? evidence.nonce_hash.trim() : '';
  if (!nonceHash) return false;

  const matchingProbes = corroboration.probesByNonce.get(nonceHash) ?? [];
  const matchingAgents = corroboration.agentsByNonce.get(nonceHash) ?? [];

  const verifiedProbePass = matchingProbes.some((probe) => {
    const external = normalizeExternalResult(probe.metadata?.external_result);
    if (!EXTERNAL_WAF_PASS.has(external)) return false;
    if (!hasWafFingerprintHint(probe.metadata)) return false;
    if (evidence.request_id) {
      const linkedProbe = corroboration.probesById.get(String(evidence.request_id));
      if (!linkedProbe || linkedProbe.nonce_hash !== nonceHash) return false;
    }
    if (evidence.test_run_id && probe.metadata?.test_run_id
      && String(probe.metadata.test_run_id) !== String(evidence.test_run_id)) {
      return false;
    }
    if (evidence.probe_job_id && probe.metadata?.probe_job_id
      && String(probe.metadata.probe_job_id) !== String(evidence.probe_job_id)
      && String(probe.id) !== String(evidence.probe_job_id)) {
      return false;
    }
    return true;
  });

  if (verifiedProbePass) {
    const wafMarkerAgents = matchingAgents.filter((agent) => isWafMarkerAgentMetadata(agent.metadata));
    if (wafMarkerAgents.length > 0) {
      const markerLeak = wafMarkerAgents.some(
        (agent) => agent.metadata?.observed_action !== 'block' && agent.metadata?.waf_blocked !== true,
      );
      if (markerLeak) return false;
    }
    return true;
  }

  return false;
}

/**
 * @param {object[]} normalizedScenarios
 * @param {ReturnType<typeof buildWafEvidenceCorroboration>} corroboration
 */
export function scenarioSetSupportsProtectedClaim(normalizedScenarios, corroboration) {
  return normalizedScenarios.some(
    (scenario) => corroborateProtectedScenarioEvidence(scenario, corroboration),
  );
}

/**
 * @param {{
 *   validationPassed: boolean,
 *   normalizedScenarios: object[],
 *   corroboration: ReturnType<typeof buildWafEvidenceCorroboration>,
 * }} input
 */
export function protectedFinalizeEvidenceRequired({
  validationPassed,
  normalizedScenarios,
  corroboration,
}) {
  if (!validationPassed) return null;
  if (scenarioSetSupportsProtectedClaim(normalizedScenarios, corroboration)) return null;
  return {
    error: 'waf_validation_evidence_required',
    status: 400,
  };
}

/**
 * Remove client-asserted agent observation flags; corroboration derives these from stored events.
 *
 * @param {Record<string, unknown>} evidenceSummary
 */
export function stripClientAssertedAgentEvidence(evidenceSummary = {}) {
  if (!evidenceSummary || typeof evidenceSummary !== 'object' || Array.isArray(evidenceSummary)) {
    return evidenceSummary;
  }
  const { observed_at_agent: _ignored, ...rest } = evidenceSummary;
  return rest;
}

const FINALIZE_CORROBORATION_EVENT_LIMIT = 500;

/**
 * @param {object[]} events
 * @param {string | null | undefined} testRunId
 * @param {object[]} normalizedScenarios
 */
export function buildCorroborationFromEvents(events, testRunId, normalizedScenarios = []) {
  const nonces = new Set(
    normalizedScenarios
      .map((scenario) => scenario.evidence_summary_json?.nonce_hash)
      .filter((nonce) => typeof nonce === 'string' && nonce.trim())
      .map((nonce) => nonce.trim()),
  );

  let scoped = Array.isArray(events) ? events : [];
  if (testRunId) {
    scoped = scoped.filter((event) => event.test_run_id === testRunId);
  } else if (nonces.size > 0) {
    scoped = scoped.filter((event) => event.nonce_hash && nonces.has(event.nonce_hash));
  } else {
    scoped = [];
  }

  return buildWafEvidenceCorroboration({
    probes: scoped.filter((event) => event.signal_type === 'probe_result'),
    agents: scoped.filter((event) => event.signal_type === 'agent_observation'),
  });
}

/**
 * @param {object} validationEvidence
 * @param {{ tenantId: string }} ctx
 * @param {string | null | undefined} testRunId
 * @param {object[]} normalizedScenarios
 */
export async function buildCorroborationFromValidationEvidence(
  validationEvidence,
  ctx,
  testRunId,
  normalizedScenarios = [],
) {
  if (!testRunId || typeof validationEvidence?.listRunEvents !== 'function') {
    return buildWafEvidenceCorroboration({ probes: [], agents: [] });
  }

  const [probes, agents] = await Promise.all([
    validationEvidence.listRunEvents(ctx, testRunId, {
      signalType: 'probe_result',
      limit: FINALIZE_CORROBORATION_EVENT_LIMIT,
    }),
    validationEvidence.listRunEvents(ctx, testRunId, {
      signalType: 'agent_observation',
      limit: FINALIZE_CORROBORATION_EVENT_LIMIT,
    }),
  ]);

  const events = [
    ...(Array.isArray(probes) ? probes : []),
    ...(Array.isArray(agents) ? agents : []),
  ];
  return buildCorroborationFromEvents(events, testRunId, normalizedScenarios);
}
