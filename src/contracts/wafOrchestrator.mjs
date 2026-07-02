import { assertNoRawWafEvidence, WAF_SCENARIO_FAMILIES } from './wafPosture.mjs';

export const ORCHESTRATION_MODES = Object.freeze([
  'manual',
  'scheduled',
  'on_demand',
  'post_change',
]);

export const SCHEDULE_INTERVALS = Object.freeze([
  'daily',
  'weekly',
  'monthly',
  'custom_cron',
]);

export const VALIDATION_PLAN_STATES = Object.freeze([
  'draft',
  'scheduled',
  'running',
  'completed',
  'failed',
  'cancelled',
]);

export const SAFE_SCENARIO_IDS = Object.freeze([
  'marker',
  'fingerprint',
  'sqli_marker',
  'xss_marker',
  'rce_marker',
  'path_traversal_marker',
  'rate_limit_marker',
  'origin_bypass',
]);

export const RETEST_PRIORITIES = Object.freeze(['low', 'normal', 'high', 'urgent']);

export const RETEST_VERDICTS = Object.freeze(['resolved', 'persistent', 'inconclusive']);

const SAFE_SCENARIO_SET = new Set(SAFE_SCENARIO_IDS);
const ORCHESTRATION_MODE_SET = new Set(ORCHESTRATION_MODES);
const SCHEDULE_INTERVAL_SET = new Set(SCHEDULE_INTERVALS);

const DEFAULT_TIMEOUT_MS = 60_000;
const MAX_TIMEOUT_MS = 300_000;
const MAX_CONCURRENT = 10;

const ATTACK_SCENARIO_TOKENS = [
  'attack',
  'exploit',
  'amplification',
  'flood',
  'ddos',
  'smuggling',
  'shell_exec',
  'cmd_injection',
  'payload_delivery',
  ['traffic', 'generator'].join('_'),
];

const ATTACK_PATTERN_RE = new RegExp(
  `(?:^|[_-])(${ATTACK_SCENARIO_TOKENS.join('|')})(?:$|[_-])`,
  'i',
);

const PROHIBITED_ORCHESTRATION_FIELDS = new Set([
  'raw_payload',
  'payload',
  'attack_profile',
  'amplification',
  'exploit_code',
  'exploit_payload',
  ['traffic', 'generator'].join('_'),
  'soc_gated',
  'prohibited',
]);

function contractError(message, code = 'invalid_request') {
  const err = new Error(message);
  err.code = code;
  throw err;
}

function rejectProhibitedFields(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return;
  for (const key of Object.keys(input)) {
    const normalized = String(key)
      .replace(/([a-z])([A-Z])/g, '$1_$2')
      .replace(/[^A-Za-z0-9]+/g, '_')
      .toLowerCase();
    if (PROHIBITED_ORCHESTRATION_FIELDS.has(normalized)) {
      contractError(`Field ${key} is not permitted in WAF orchestration requests.`, 'unsafe_orchestrator_plan');
    }
  }
}

function normalizeScenarios(raw) {
  if (!Array.isArray(raw) || raw.length === 0) {
    contractError('scenarios must be a non-empty array of safe scenario IDs.', 'unsafe_orchestrator_plan');
  }
  const scenarios = [...new Set(raw.map((s) => String(s).trim()).filter(Boolean))];
  if (scenarios.length === 0) {
    contractError('scenarios must include at least one safe scenario ID.', 'unsafe_orchestrator_plan');
  }
  return scenarios;
}

export function assertSafeScenarioId(scenarioId) {
  const id = String(scenarioId ?? '').trim();
  if (!id) {
    contractError('Scenario ID must be a non-empty string.', 'unsafe_orchestrator_plan');
  }
  if (ATTACK_PATTERN_RE.test(id)) {
    contractError(
      `Scenario ${id} matches prohibited attack/exploit patterns.`,
      'unsafe_orchestrator_plan',
    );
  }
  if (!SAFE_SCENARIO_SET.has(id)) {
    if (WAF_SCENARIO_FAMILIES.includes(id) && id === 'protocol_evasion_marker') {
      contractError(
        `Scenario ${id} requires SOC workflow and cannot be orchestrated.`,
        'unsafe_orchestrator_plan',
      );
    }
    contractError(`Scenario ${id} is not an approved safe scenario ID.`, 'unsafe_orchestrator_plan');
  }
  return id;
}

export function validateOrchestratorPlan(plan) {
  if (plan === null || plan === undefined || typeof plan !== 'object' || Array.isArray(plan)) {
    contractError('Validation plan must be a plain object.', 'invalid_orchestrator_plan');
  }
  assertNoRawWafEvidence(plan);
  rejectProhibitedFields(plan);

  const maxConcurrent = Number(plan.max_concurrent ?? 1);
  if (!Number.isInteger(maxConcurrent) || maxConcurrent < 1 || maxConcurrent > MAX_CONCURRENT) {
    contractError(
      `max_concurrent must be an integer between 1 and ${MAX_CONCURRENT}.`,
      'unsafe_orchestrator_plan',
    );
  }

  const timeoutMs = Number(plan.timeout_ms ?? DEFAULT_TIMEOUT_MS);
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > MAX_TIMEOUT_MS) {
    contractError(
      `timeout_ms must be an integer between 1000 and ${MAX_TIMEOUT_MS}.`,
      'unsafe_orchestrator_plan',
    );
  }

  const scenarios = normalizeScenarios(plan.scenarios);
  for (const scenario of scenarios) {
    assertSafeScenarioId(scenario);
  }

  return {
    max_concurrent: maxConcurrent,
    timeout_ms: timeoutMs,
    scenarios,
  };
}

export function createValidationPlan(fields = {}) {
  if (fields === null || fields === undefined || typeof fields !== 'object' || Array.isArray(fields)) {
    contractError('Validation plan fields must be a plain object.', 'invalid_orchestrator_plan');
  }
  assertNoRawWafEvidence(fields);
  rejectProhibitedFields(fields);

  const tenant_id = typeof fields.tenant_id === 'string' ? fields.tenant_id.trim() : '';
  if (!tenant_id) {
    contractError('tenant_id is required.', 'invalid_orchestrator_plan');
  }

  const target_group_id =
    typeof fields.target_group_id === 'string' ? fields.target_group_id.trim() : '';
  if (!target_group_id) {
    contractError('target_group_id is required.', 'invalid_orchestrator_plan');
  }

  const mode = String(fields.mode ?? 'manual').trim();
  if (!ORCHESTRATION_MODE_SET.has(mode)) {
    contractError(
      `mode must be one of: ${ORCHESTRATION_MODES.join(', ')}.`,
      'invalid_orchestrator_plan',
    );
  }

  let schedule_interval = null;
  let custom_cron_expression = null;
  if (mode === 'scheduled') {
    schedule_interval = String(fields.schedule_interval ?? '').trim();
    if (!SCHEDULE_INTERVAL_SET.has(schedule_interval)) {
      contractError(
        `schedule_interval must be one of: ${SCHEDULE_INTERVALS.join(', ')} when mode is scheduled.`,
        'invalid_orchestrator_plan',
      );
    }
    if (schedule_interval === 'custom_cron') {
      custom_cron_expression =
        typeof fields.custom_cron_expression === 'string'
          ? fields.custom_cron_expression.trim()
          : '';
      if (!custom_cron_expression) {
        contractError(
          'custom_cron_expression is required when schedule_interval is custom_cron.',
          'invalid_orchestrator_plan',
        );
      }
    }
  }

  const validated = validateOrchestratorPlan(fields);

  const initialState =
    mode === 'scheduled' ? 'scheduled' : 'draft';

  return {
    tenant_id,
    target_group_id,
    mode,
    schedule_interval,
    ...(custom_cron_expression ? { custom_cron_expression } : {}),
    scenarios: validated.scenarios,
    max_concurrent: validated.max_concurrent,
    timeout_ms: validated.timeout_ms,
    state: initialState,
  };
}

export function createBaselineApproval(fields = {}) {
  if (fields === null || fields === undefined || typeof fields !== 'object' || Array.isArray(fields)) {
    contractError('Baseline approval fields must be a plain object.', 'invalid_baseline_approval');
  }
  assertNoRawWafEvidence(fields);
  rejectProhibitedFields(fields);

  const baseline_id = typeof fields.baseline_id === 'string' ? fields.baseline_id.trim() : '';
  if (!baseline_id) {
    contractError('baseline_id is required.', 'invalid_baseline_approval');
  }

  const approver = typeof fields.approver === 'string' ? fields.approver.trim() : '';
  if (!approver) {
    contractError('approver is required.', 'invalid_baseline_approval');
  }

  const approval_notes =
    typeof fields.approval_notes === 'string' ? fields.approval_notes.trim() : '';
  if (!approval_notes) {
    contractError('approval_notes is required.', 'invalid_baseline_approval');
  }

  const approved_at =
    typeof fields.approved_at === 'string' && fields.approved_at.trim()
      ? fields.approved_at.trim()
      : new Date().toISOString();

  const fingerprintRaw =
    fields.fingerprint_summary && typeof fields.fingerprint_summary === 'object'
    && !Array.isArray(fields.fingerprint_summary)
      ? fields.fingerprint_summary
      : {};
  assertNoRawWafEvidence(fingerprintRaw);

  const fingerprint_summary = {};
  for (const [key, value] of Object.entries(fingerprintRaw)) {
    const normalized = String(key)
      .replace(/([a-z])([A-Z])/g, '$1_$2')
      .replace(/[^A-Za-z0-9]+/g, '_')
      .toLowerCase();
    if (typeof value === 'string' && value.trim()) {
      fingerprint_summary[normalized] = value.trim();
    } else if (typeof value === 'number' || typeof value === 'boolean') {
      fingerprint_summary[normalized] = value;
    }
  }

  return {
    baseline_id,
    approver,
    approval_notes,
    approved_at,
    fingerprint_summary,
  };
}

export function createRetestRequest(fields = {}) {
  if (fields === null || fields === undefined || typeof fields !== 'object' || Array.isArray(fields)) {
    contractError('Retest request fields must be a plain object.', 'invalid_retest_request');
  }
  assertNoRawWafEvidence(fields);
  rejectProhibitedFields(fields);

  const drift_event_id =
    typeof fields.drift_event_id === 'string' ? fields.drift_event_id.trim() : '';
  if (!drift_event_id) {
    contractError('drift_event_id is required.', 'invalid_retest_request');
  }

  const retest_plan = normalizeScenarios(fields.retest_plan ?? fields.scenarios);
  for (const scenario of retest_plan) {
    assertSafeScenarioId(scenario);
  }

  const requested_by =
    typeof fields.requested_by === 'string' ? fields.requested_by.trim() : '';
  if (!requested_by) {
    contractError('requested_by is required.', 'invalid_retest_request');
  }

  const priority = String(fields.priority ?? 'normal').trim().toLowerCase();
  if (!RETEST_PRIORITIES.includes(priority)) {
    contractError(
      `priority must be one of: ${RETEST_PRIORITIES.join(', ')}.`,
      'invalid_retest_request',
    );
  }

  return {
    drift_event_id,
    retest_plan,
    requested_by,
    priority,
  };
}

export function computeRetestVerdict(retestResults, originalDrift = {}) {
  const results = Array.isArray(retestResults?.results) ? retestResults.results : [];
  const hasScenarioEvidence = results.some(
    (entry) =>
      entry?.evidence_summary
      && typeof entry.evidence_summary === 'object'
      && Object.keys(entry.evidence_summary).length > 0,
  );
  const hasSignal =
    retestResults?.validation_passed === true
    || retestResults?.validation_failed === true
    || typeof retestResults?.posture_status === 'string'
    || hasScenarioEvidence;

  if (!hasSignal || results.length === 0) {
    return { verdict: 'inconclusive', reason: 'insufficient_evidence' };
  }

  const beforeStatus =
    originalDrift?.before_summary_json?.status
    ?? originalDrift?.before_summary?.status
    ?? null;
  const driftType = originalDrift?.drift_type ?? null;

  const postureStatus = String(retestResults?.posture_status ?? '').trim();
  const validationPassed = retestResults?.validation_passed === true;
  const validationFailed = retestResults?.validation_failed === true;
  const originBypassConfirmed = retestResults?.origin_bypass_confirmed === true;
  const wafDetected = retestResults?.waf_detected === true;

  const markerRestored = results.some(
    (entry) => entry?.passed === true && ['block', 'challenge', 'rate_limit'].includes(entry?.observed_action),
  );

  if (validationPassed || postureStatus === 'protected') {
    if (beforeStatus === 'protected' || markerRestored) {
      return { verdict: 'resolved', reason: 'posture_restored' };
    }
  }

  if (driftType === 'fingerprint_lost' && wafDetected && validationPassed) {
    return { verdict: 'resolved', reason: 'posture_restored' };
  }

  if (driftType === 'origin_bypass_new' && !originBypassConfirmed && validationPassed) {
    return { verdict: 'resolved', reason: 'posture_restored' };
  }

  if (
    validationFailed
    || postureStatus === 'underprotected'
    || postureStatus === 'unprotected'
    || originBypassConfirmed
  ) {
    return { verdict: 'persistent', reason: 'drift_confirmed' };
  }

  const anyFailedScenario = results.some((entry) => entry?.passed === false);
  if (anyFailedScenario) {
    return { verdict: 'persistent', reason: 'drift_confirmed' };
  }

  return { verdict: 'inconclusive', reason: 'insufficient_evidence' };
}