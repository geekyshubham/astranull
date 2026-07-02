/** Metadata-only verdict / finding explanation panels (no raw packets, logs, or bodies). */

function esc(text) {
  return String(text ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

export function verdictExplanationEventItems(eventsPayload) {
  return eventsPayload?.items || eventsPayload || [];
}

export function verdictExplanationMetaMode(event) {
  const meta = event?.metadata || {};
  for (const key of ['observation_mode', 'mode', 'source', 'interface', 'log_source']) {
    if (meta[key] != null && meta[key] !== '') return String(meta[key]);
  }
  return event?.signal_type || 'event';
}

export function summarizeExternalProbeEvidence(probeEvents) {
  if (!probeEvents.length) {
    return 'No probe_result events recorded for this run yet; external probe evidence is missing or limited.';
  }
  return probeEvents
    .map((e) => {
      const parts = [];
      if (e.timestamp) parts.push(esc(e.timestamp));
      if (e.source) parts.push(`source ${esc(e.source)}`);
      const meta = e.metadata || {};
      const externalResult = e.external_result ?? meta.external_result;
      if (externalResult) parts.push(`external_result ${esc(externalResult)}`);
      if (meta.probe_profile_kind) parts.push(`profile ${esc(meta.probe_profile_kind)}`);
      if (meta.simulation) parts.push(esc(meta.simulation));
      if (meta.note) parts.push(esc(meta.note));
      return parts.length ? parts.join(' · ') : esc(e.signal_type || 'probe_result');
    })
    .join('; ');
}

export function summarizeInternalAgentEvidence(obsEvents, noObsEvents) {
  const lines = [];
  if (obsEvents.length) {
    obsEvents.forEach((e) => {
      const parts = [];
      if (e.timestamp) parts.push(esc(e.timestamp));
      if (e.agent_id) parts.push(`agent ${esc(e.agent_id)}`);
      if (e.source) parts.push(`source ${esc(e.source)}`);
      if (e.nonce_hash) parts.push('nonce correlated');
      const meta = e.metadata || {};
      if (meta.reason) parts.push(esc(meta.reason));
      lines.push(parts.length ? parts.join(' · ') : 'agent_observation recorded');
    });
  } else {
    lines.push('No agent_observation events in this run timeline.');
  }
  if (noObsEvents.length) {
    noObsEvents.forEach((e) => {
      const reason = e.metadata?.reason ? esc(e.metadata.reason) : 'no observation within bounded window';
      lines.push(`agent_no_observation · ${reason}`);
    });
  }
  return lines.join('; ');
}

export function summarizeObservationMode(events) {
  const agentSignals = events.filter(
    (e) => e.signal_type === 'agent_observation' || e.signal_type === 'agent_no_observation',
  );
  const pool = agentSignals.length ? agentSignals : events;
  if (!pool.length) return 'Observation mode cannot be determined — no agent or probe events yet.';
  const modes = [...new Set(pool.map((e) => verdictExplanationMetaMode(e)))];
  return modes.map((m) => esc(m)).join(', ');
}

export function formatPlacementConfidenceFromVerdict(pc) {
  if (!pc || typeof pc !== 'object') return null;
  const parts = [];
  if (pc.level) parts.push(`${pc.level}`);
  if (pc.observation_mode) parts.push(`mode ${pc.observation_mode}`);
  if (pc.reason) parts.push(pc.reason);
  if (pc.agent_id) parts.push(`agent ${pc.agent_id}`);
  return parts.map((p) => esc(String(p))).join(' · ');
}

export function summarizePlacementConfidence(matchingObs, noObsEvents, verdictPlacement) {
  const fromBackend = formatPlacementConfidenceFromVerdict(verdictPlacement);
  if (fromBackend) return fromBackend;
  if (matchingObs.length) {
    return 'Placement confidence is supported by job-bound agent observation correlated to this run.';
  }
  if (noObsEvents.length) {
    return 'Placement confidence is limited: bounded window ended with agent_no_observation and no matching observation.';
  }
  return 'Placement confidence cannot be proven from run events yet.';
}

export function renderVerdictExplanationItem(label, valueHtml) {
  return `<div class="verdict-explanation-item">
    <span class="verdict-explanation-label">${esc(label)}</span>
    <span class="verdict-explanation-value">${valueHtml}</span>
  </div>`;
}

/**
 * @param {object} detail — test run detail including optional `verdict` and `correlation`
 * @param {object|object[]} eventsPayload — run events (`{ items }` or array)
 * @param {{ heading?: string, remediationTemplate?: string }} [options]
 */
export function renderVerdictExplanation(detail, eventsPayload, options = {}) {
  const heading = options.heading ?? 'Why this verdict?';
  if (!detail?.verdict) {
    return `<section class="verdict-explanation verdict-explanation--pending">
      <h4>${esc(heading)}</h4>
      <p class="muted">Verdict evidence is still pending for this run.</p>
    </section>`;
  }
  const items = verdictExplanationEventItems(eventsPayload);
  const probeEvents = items.filter((e) => e.signal_type === 'probe_result');
  const obsEvents = items.filter((e) => e.signal_type === 'agent_observation');
  const noObsEvents = items.filter((e) => e.signal_type === 'agent_no_observation');
  const nonceHash = detail.correlation?.nonce_hash;
  const matchingObs = nonceHash
    ? obsEvents.filter((e) => e.nonce_hash === nonceHash)
    : obsEvents;

  const v = detail.verdict;
  const externalHtml = summarizeExternalProbeEvidence(probeEvents);
  const internalHtml = summarizeInternalAgentEvidence(obsEvents, noObsEvents);
  const modeHtml = summarizeObservationMode(items);
  const placementHtml = summarizePlacementConfidence(matchingObs, noObsEvents, v.placement_confidence);
  const conclusionHtml = `${esc(v.verdict || '—')} · confidence ${esc(v.confidence || '—')}. ${esc(v.explanation || '')}`;
  const remediationRef = options.remediationTemplate ?? detail.remediation_template;
  const remediationHtml = remediationRef
    ? esc(remediationRef)
    : '<span class="muted">No remediation template recorded for this run.</span>';

  const grid = [
    renderVerdictExplanationItem('External probe evidence', externalHtml),
    renderVerdictExplanationItem('Internal agent evidence', internalHtml),
    renderVerdictExplanationItem('Observation mode', modeHtml),
    renderVerdictExplanationItem('Placement confidence', placementHtml),
    renderVerdictExplanationItem('Conclusion', conclusionHtml),
    renderVerdictExplanationItem('Remediation', remediationHtml),
  ].join('');

  return `<section class="verdict-explanation">
    <h4>${esc(heading)}</h4>
    <div class="verdict-explanation-grid">${grid}</div>
  </section>`;
}

/** Prefer finding remediation and run verdict/correlation for the explanation grid. */
export function buildFindingVerdictExplanationDetail(finding, runDetail) {
  const detail = runDetail ? { ...runDetail } : {};
  if (finding?.remediation_template) {
    detail.remediation_template = finding.remediation_template;
  }
  return detail;
}

export function renderFindingVerdictExplanation(finding, runDetail, eventsPayload) {
  if (!finding?.test_run_id) {
    const parts = [
      '<section class="verdict-explanation verdict-explanation--pending">',
      '<h4>Why this finding?</h4>',
      '<p class="muted">This finding has no linked test run; probe and agent evidence cannot be loaded.</p>',
    ];
    if (finding?.notes) {
      parts.push(renderVerdictExplanationItem('Conclusion', esc(finding.notes)));
    }
    if (finding?.remediation_template) {
      parts.push(renderVerdictExplanationItem('Remediation', esc(finding.remediation_template)));
    }
    parts.push('</section>');
    return parts.join('');
  }
  const detail = buildFindingVerdictExplanationDetail(finding, runDetail);
  return renderVerdictExplanation(detail, eventsPayload, {
    heading: 'Why this finding?',
    remediationTemplate: finding.remediation_template ?? detail.remediation_template,
  });
}