/**
 * Correlation truth table — evidence-backed verdicts (metadata-only developer validation).
 */

export function correlateVerdict({
  externalResult,
  agentObserved,
  expectedBehavior,
  agentOnline,
  agentBound,
}) {
  if (!agentOnline || !agentBound) {
    return {
      verdict: 'inconclusive',
      confidence: 'low',
      explanation:
        'Agent is offline or not bound to the target group; internal observation evidence is unavailable.',
      createsFinding: false,
    };
  }

  const blocked = externalResult === 'blocked' || externalResult === 'timeout';
  const connected = externalResult === 'connected' || externalResult === 'allowed';

  if (expectedBehavior === 'must_block_before_origin') {
    if (blocked && !agentObserved) {
      return {
        verdict: 'protected',
        confidence: 'medium',
        explanation:
          'Simulated external probe was blocked or timed out and the agent did not observe traffic — consistent with protection.',
        createsFinding: false,
      };
    }
    if (connected && agentObserved) {
      return {
        verdict: 'bypassable',
        confidence: 'high',
        explanation:
          'Simulated external probe reached the target path and the agent observed matching traffic — bypass risk.',
        createsFinding: true,
        severity: 'high',
      };
    }
    if (blocked && agentObserved) {
      return {
        verdict: 'penetrated',
        confidence: 'high',
        explanation:
          'External response indicated block/timeout but the agent observed traffic — possible penetration with silent drop downstream.',
        createsFinding: true,
        severity: 'high',
      };
    }
    if (connected && !agentObserved) {
      return {
        verdict: 'misplaced_agent',
        confidence: 'low',
        explanation:
          'External probe succeeded but no agent observation — inconclusive placement or downstream block.',
        createsFinding: false,
      };
    }
  }

  if (expectedBehavior === 'must_reach_canary') {
    if (connected && agentObserved) {
      return {
        verdict: 'allowed_as_expected',
        confidence: 'high',
        explanation: 'Protected-path canary traffic reached the observation point as expected.',
        createsFinding: false,
      };
    }
    if (blocked && !agentObserved) {
      return {
        verdict: 'inconclusive',
        confidence: 'low',
        explanation: 'Canary path did not complete — protected path or canary may be unreachable.',
        createsFinding: false,
      };
    }
  }

  return {
    verdict: 'inconclusive',
    confidence: 'low',
    explanation: 'Insufficient correlated evidence for a definitive verdict.',
    createsFinding: false,
  };
}

export function correlateExternalOnlyVerdict({ externalResult, expectedBehavior }) {
  const blocked = externalResult === 'blocked' || externalResult === 'timeout';
  const connected = externalResult === 'connected' || externalResult === 'allowed';

  if (expectedBehavior === 'must_block_before_origin') {
    if (blocked) {
      return {
        verdict: 'edge_protected',
        confidence: 'external_only',
        placement: 'unverified',
        explanation:
          'External-only probe was blocked at the edge; origin reachability not proven without an agent.',
        createsFinding: false,
        strengthen_hint: 'deploy_agent',
      };
    }
    if (connected) {
      return {
        verdict: 'edge_exposed',
        confidence: 'external_only',
        placement: 'unverified',
        explanation:
          'External-only probe reached the declared path; deploy an agent to confirm whether traffic reached origin.',
        createsFinding: true,
        severity: 'medium',
        strengthen_hint: 'deploy_agent',
      };
    }
  }

  return {
    verdict: 'inconclusive',
    confidence: 'external_only',
    placement: 'unverified',
    explanation: 'Insufficient external-only evidence.',
    createsFinding: false,
    strengthen_hint: 'deploy_agent',
  };
}

export function withinCorrelationWindow(probeTs, obsTs, windowMs = 120_000) {
  const a = new Date(probeTs).getTime();
  const b = new Date(obsTs).getTime();
  return Math.abs(b - a) <= windowMs;
}