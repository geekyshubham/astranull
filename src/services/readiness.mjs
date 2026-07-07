import { getStore } from '../store.mjs';
import { REQUIRED_ARTIFACT_TYPES } from './highScale.mjs';
import {
  computePlacementDiagnostics,
  placementScoreFromDiagnostics,
  publicPlacementDiagnosticsPayload,
  summarizePlacementDiagnostics,
} from './placement.mjs';
import { activeTargetGroupsForTenant } from './targetGroups.mjs';

/** Evidence older than this window earns no freshness credit. */
export const RECENT_EVIDENCE_WINDOW_DAYS = 30;
export const RECENT_EVIDENCE_WINDOW_MS = RECENT_EVIDENCE_WINDOW_DAYS * 24 * 60 * 60 * 1000;

export const WEIGHT_COVERAGE = 40;
export const WEIGHT_AGENT_PLACEMENT = 25;
export const WEIGHT_VERDICTS = 25;
export const WEIGHT_EVIDENCE_FRESHNESS = 15;
export const WEIGHT_SOC_GOVERNANCE = 10;

const RUN_EVIDENCE_TIMESTAMP_FIELDS = [
  'verdict_at',
  'completed_at',
  'updated_at',
  'created_at',
];

const GOVERNED_HS_STATES = new Set(['scheduled', 'running', 'stopped', 'closed']);

const SOC_KILL_SWITCH_ACTIONS = new Set(['soc.kill_switch.activated', 'soc.kill_switch.cleared']);

function parseTs(value) {
  if (!value) return null;
  const ms = new Date(value).getTime();
  return Number.isFinite(ms) ? ms : null;
}

function isRecentMs(ms, nowMs = Date.now()) {
  if (ms == null || !Number.isFinite(ms)) return false;
  if (ms > nowMs) return false;
  return nowMs - ms <= RECENT_EVIDENCE_WINDOW_MS;
}

function isRecentTimestamp(value, nowMs = Date.now()) {
  return isRecentMs(parseTs(value), nowMs);
}

function runStatusEligible(run) {
  return run.status === 'completed' || run.status === 'verdicted';
}

function verdictForRun(store, runId) {
  return store.verdicts.find((v) => v.test_run_id === runId) ?? null;
}

function eventsForRun(store, runId) {
  return store.events.filter((e) => e.test_run_id === runId);
}

function vaultForRun(store, runId) {
  return (store.evidenceVault ?? []).filter((e) => e.test_run_id === runId);
}

function runHasEvidenceBacking(store, run) {
  if (verdictForRun(store, run.id)) return true;
  if (eventsForRun(store, run.id).length > 0) return true;
  if (vaultForRun(store, run.id).length > 0) return true;
  return false;
}

function collectEvidenceTimestamps(store, run) {
  const stamps = [];
  for (const field of RUN_EVIDENCE_TIMESTAMP_FIELDS) {
    const ms = parseTs(run[field]);
    if (ms != null) stamps.push(ms);
  }
  const verdict = verdictForRun(store, run.id);
  if (verdict) {
    const vMs = parseTs(verdict.created_at);
    if (vMs != null) stamps.push(vMs);
  }
  for (const ev of eventsForRun(store, run.id)) {
    const eMs = parseTs(ev.timestamp ?? ev.created_at);
    if (eMs != null) stamps.push(eMs);
  }
  for (const rec of vaultForRun(store, run.id)) {
    const rMs = parseTs(rec.created_at);
    if (rMs != null) stamps.push(rMs);
  }
  return stamps;
}

function evidenceFreshnessForRun(store, run, nowMs) {
  if (!runStatusEligible(run) || !runHasEvidenceBacking(store, run)) {
    return { recent: false, stale: false, backed: false };
  }
  const stamps = collectEvidenceTimestamps(store, run);
  if (stamps.length === 0) {
    return { recent: false, stale: false, backed: true };
  }
  const hasRecent = stamps.some((ms) => isRecentMs(ms, nowMs));
  const hasStaleOnly = !hasRecent;
  return { recent: hasRecent, stale: hasStaleOnly, backed: true };
}

function acceptedArtifacts(req) {
  return (req.artifacts ?? []).filter((a) => a.status === 'accepted');
}

function authorizationPackComplete(req) {
  const types = new Set(acceptedArtifacts(req).map((a) => a.type));
  for (const t of REQUIRED_ARTIFACT_TYPES) {
    if (!types.has(t)) return false;
  }
  if (req.provider_context?.requires_provider_approval) {
    if (!types.has('provider_approval')) return false;
  }
  return true;
}

function distinctSocApprovalCount(req) {
  return new Set((req.soc_approvals ?? []).map((a) => a.user_id)).size;
}

function hasAgentObservationEvidence(store, tenantId) {
  return store.events.some(
    (e) =>
      e.tenant_id === tenantId &&
      (e.signal_type === 'agent_observation' || e.signal_type === 'agent_no_observation'),
  );
}

function killSwitchEvidenceForTenant(store, tenantId) {
  const ks = store.socKillSwitch ?? {};
  const ksTenant = ks.tenant_id ?? null;
  const tenantScoped =
    ksTenant === tenantId ||
    (ks.tenants && typeof ks.tenants === 'object' && ks.tenants[tenantId]);
  if (tenantScoped && parseTs(ks.updated_at) != null) {
    return { kind: 'kill_switch_state', detail: 'Kill switch state recorded for tenant.' };
  }
  const auditHit = (store.auditLog ?? []).find(
    (a) => a.tenant_id === tenantId && SOC_KILL_SWITCH_ACTIONS.has(a.action),
  );
  if (auditHit) {
    return { kind: 'kill_switch_audit', detail: 'Kill switch audit trail recorded for tenant.' };
  }
  return null;
}

function highScaleGovernanceEvidence(store, tenantId) {
  const requests = store.highScaleRequests.filter((h) => h.tenant_id === tenantId);
  const hits = [];

  for (const req of requests) {
    const packOk = authorizationPackComplete(req);
    const approvals = distinctSocApprovalCount(req);
    if (packOk && approvals >= 2) {
      hits.push({
        requestId: req.id,
        kind: 'approved_pack',
        detail: `Request ${req.id}: authorization pack accepted with ${approvals} SOC approver(s).`,
      });
    }
    if (GOVERNED_HS_STATES.has(req.state) && (req.audit_trail?.length ?? 0) > 0) {
      hits.push({
        requestId: req.id,
        kind: 'governed_lifecycle',
        detail: `Request ${req.id}: governed lifecycle state "${req.state}" with audit trail.`,
      });
    }
  }

  return hits;
}

function pendingHighScaleGates(store, tenantId) {
  const pending = store.highScaleRequests.filter(
    (h) => h.tenant_id === tenantId && !['closed', 'rejected'].includes(h.state),
  );
  const gates = [];
  for (const req of pending) {
    const missing = [];
    if (!authorizationPackComplete(req)) {
      const have = new Set(acceptedArtifacts(req).map((a) => a.type));
      const need = REQUIRED_ARTIFACT_TYPES.filter((t) => !have.has(t));
      if (need.length) missing.push(`missing accepted artifacts: ${need.join(', ')}`);
    }
    const approvals = distinctSocApprovalCount(req);
    if (approvals < 2) {
      missing.push(`SOC approvals ${approvals}/2`);
    }
    if (missing.length) {
      gates.push({ requestId: req.id, state: req.state, missing });
    }
  }
  return gates;
}

function scoreSocGovernance(store, tenantId) {
  const kill = killSwitchEvidenceForTenant(store, tenantId);
  const hsHits = highScaleGovernanceEvidence(store, tenantId);
  const pendingGates = pendingHighScaleGates(store, tenantId);

  const hasEvidence = Boolean(kill) || hsHits.length > 0;
  if (!hasEvidence) {
    let detail = 'No high-scale governance evidence recorded yet.';
    if (pendingGates.length) {
      const parts = pendingGates.map(
        (g) => `${g.requestId} (${g.state}): ${g.missing.join('; ')}`,
      );
      detail = `Pending high-scale workflow — gates remain: ${parts.join(' | ')}.`;
    }
    return { score: 0, detail };
  }

  let score = WEIGHT_SOC_GOVERNANCE;
  const detailParts = [];
  if (kill) detailParts.push(kill.detail);
  for (const h of hsHits) detailParts.push(h.detail);
  if (pendingGates.length) {
    const parts = pendingGates.map(
      (g) => `${g.requestId}: ${g.missing.join('; ')}`,
    );
    detailParts.push(`Other request(s) still pending gates: ${parts.join(' | ')}.`);
  }

  return {
    score,
    detail: detailParts.join(' '),
  };
}

export function computeReadiness(tenantId) {
  const store = getStore();
  const rollup = store.stateRollups?.[tenantId];
  if (rollup?.readiness && typeof rollup.readiness === 'object') {
    return rollup.readiness;
  }
  const nowMs = Date.now();
  const groups = activeTargetGroupsForTenant(tenantId);
  const agents = store.agents.filter((a) => a.tenant_id === tenantId && a.status !== 'revoked');
  const onlineAgents = agents.filter((a) => a.status === 'online');
  const runs = store.testRuns.filter((r) => r.tenant_id === tenantId);
  const findings = store.findings.filter((f) => f.tenant_id === tenantId && f.status === 'open');
  const verdicts = store.verdicts.filter((v) => v.tenant_id === tenantId);

  const factors = [];

  const declaredGroupIds = new Set(groups.map((g) => g.id));
  const coveredGroupIds = new Set();
  let staleBackedRuns = 0;
  let recentBackedRuns = 0;

  for (const run of runs) {
    const freshness = evidenceFreshnessForRun(store, run, nowMs);
    if (!freshness.backed) continue;
    if (
      freshness.recent &&
      run.target_group_id &&
      declaredGroupIds.has(run.target_group_id)
    ) {
      coveredGroupIds.add(run.target_group_id);
      recentBackedRuns += 1;
    } else if (freshness.stale) {
      staleBackedRuns += 1;
    }
  }

  const totalGroups = groups.length;
  const coveredCount = coveredGroupIds.size;
  const coverageRatio = totalGroups ? coveredCount / totalGroups : 0;
  const coverageScore = Math.round(Math.min(WEIGHT_COVERAGE, coverageRatio * WEIGHT_COVERAGE));

  let coverageDetail;
  if (!totalGroups) {
    coverageDetail = 'No declared target groups.';
  } else if (coveredCount === 0) {
    if (staleBackedRuns > 0) {
      coverageDetail = `0 of ${totalGroups} target group(s) covered by recent evidence-backed validations; stale evidence exists on ${staleBackedRuns} run(s).`;
    } else {
      coverageDetail = `0 of ${totalGroups} target group(s) have evidence-backed validations in the last ${RECENT_EVIDENCE_WINDOW_DAYS} days.`;
    }
  } else {
    const missing = totalGroups - coveredCount;
    coverageDetail = `${coveredCount} of ${totalGroups} target group(s) have recent evidence-backed validations.`;
    if (missing > 0) {
      coverageDetail += ` ${missing} group(s) lack recent validation evidence.`;
    }
  }

  factors.push({
    key: 'coverage',
    label: 'Validation coverage',
    score: coverageScore,
    detail: coverageDetail,
  });

  const pathObservation = hasAgentObservationEvidence(store, tenantId);
  const placementDiagnostics = computePlacementDiagnostics(tenantId, nowMs);
  const placementSummary = summarizePlacementDiagnostics(placementDiagnostics);
  let placementScore = 0;
  let placementDetail;
  if (!agents.length) {
    placementDetail = 'No agents registered; internal path observation cannot be evidenced.';
    if (totalGroups > 0) {
      placementDetail += ` ${placementSummary.summary}`;
    }
  } else if (!onlineAgents.length) {
    placementScore = 0;
    placementDetail = `0 online of ${agents.length} registered agent(s); agents are not reporting healthy.`;
    if (!pathObservation) {
      placementDetail += ' No agent observation evidence recorded yet.';
    }
    if (totalGroups > 0) {
      placementDetail += ` ${placementSummary.summary}`;
    }
  } else if (totalGroups > 0) {
    const diagScore = placementScoreFromDiagnostics(placementDiagnostics, WEIGHT_AGENT_PLACEMENT);
    placementScore = diagScore ?? 0;
    placementDetail = `${onlineAgents.length} online of ${agents.length} registered agent(s). ${placementSummary.summary}`;
    if (placementSummary.unbound_online_agent_count > 0 && placementSummary.proven === 0) {
      placementDetail +=
        ' Unbound online agents do not prove placement for declared target groups.';
    } else if (!pathObservation && placementSummary.proven === 0) {
      placementDetail +=
        ' Online agents registered; path coverage is not yet proven by agent observation evidence.';
    }
  } else {
    placementScore = Math.round(
      Math.min(WEIGHT_AGENT_PLACEMENT, (onlineAgents.length / agents.length) * WEIGHT_AGENT_PLACEMENT),
    );
    placementDetail = `${onlineAgents.length} online of ${agents.length} registered agent(s).`;
    if (pathObservation) {
      placementDetail += ' Agent observation evidence exists for validation runs.';
    } else {
      placementDetail +=
        ' Online agents registered; path coverage is not yet proven by agent observation evidence.';
    }
  }

  factors.push({
    key: 'agent_placement',
    label: 'Agent placement & health',
    score: placementScore,
    detail: placementDetail,
    placement_diagnostics: publicPlacementDiagnosticsPayload(placementDiagnostics),
  });

  const recentVerdicts = verdicts.filter((v) => isRecentTimestamp(v.created_at, nowMs));
  const staleVerdicts = verdicts.filter((v) => {
    const ms = parseTs(v.created_at);
    return ms != null && ms <= nowMs && nowMs - ms > RECENT_EVIDENCE_WINDOW_MS;
  });

  let verdictScore = 0;
  let verdictDetail;
  if (verdicts.length === 0) {
    verdictDetail =
      'No verdict evidence recorded; absence of findings is not proof of readiness until verdict evidence exists.';
  } else if (recentVerdicts.length === 0) {
    verdictDetail = `${findings.length} open finding(s); ${verdicts.length} verdict(s) recorded (0 recent`;
    if (staleVerdicts.length) verdictDetail += `, ${staleVerdicts.length} stale`;
    verdictDetail +=
      '). Stale or missing recent verdict evidence does not support full posture credit.';
  } else {
    const penalty = Math.min(WEIGHT_VERDICTS, findings.length * 10);
    verdictScore = Math.max(0, WEIGHT_VERDICTS - penalty);
    verdictDetail = `${findings.length} open finding(s); ${verdicts.length} verdict(s) recorded (${recentVerdicts.length} recent`;
    if (staleVerdicts.length) verdictDetail += `, ${staleVerdicts.length} stale`;
    verdictDetail += ').';
  }

  factors.push({
    key: 'verdicts',
    label: 'Open findings impact',
    score: Math.round(verdictScore),
    detail: verdictDetail,
  });

  let freshnessScore = 0;
  let freshnessDetail;
  if (recentBackedRuns > 0 || coveredCount > 0) {
    freshnessScore = WEIGHT_EVIDENCE_FRESHNESS;
    freshnessDetail = `Recent evidence-backed validation within ${RECENT_EVIDENCE_WINDOW_DAYS} days (${recentBackedRuns} run(s), ${coveredCount} target group(s)).`;
  } else if (staleBackedRuns > 0) {
    freshnessScore = 0;
    freshnessDetail = `Evidence exists but is stale (older than ${RECENT_EVIDENCE_WINDOW_DAYS} days); no freshness credit awarded.`;
  } else {
    freshnessScore = 0;
    freshnessDetail = 'No evidence-backed validations yet.';
  }

  factors.push({
    key: 'evidence_freshness',
    label: 'Evidence freshness',
    score: freshnessScore,
    detail: freshnessDetail,
  });

  const soc = scoreSocGovernance(store, tenantId);
  factors.push({
    key: 'soc_readiness',
    label: 'SOC governance posture',
    score: soc.score,
    detail: soc.detail,
  });

  const score = Math.min(100, Math.round(factors.reduce((s, f) => s + f.score, 0)));
  const result = { score, factors, updated_at: new Date().toISOString() };
  store.readiness[tenantId] = result;
  return result;
}
