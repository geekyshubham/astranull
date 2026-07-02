export const KILL_SWITCH_REQUIRED_STEPS = Object.freeze([
  {
    step_id: 'activate_tenant_kill_switch',
    required_fields: Object.freeze(['evidence_uri', 'validated_at', 'operator', 'tenant_id']),
  },
  {
    step_id: 'block_new_safe_runs',
    required_fields: Object.freeze(['evidence_uri', 'validated_at', 'operator', 'blocked_run_reference']),
  },
  {
    step_id: 'cancel_active_safe_runs',
    required_fields: Object.freeze(['evidence_uri', 'validated_at', 'operator', 'cancelled_run_ids']),
  },
  {
    step_id: 'probe_fleet_stops_leasing',
    required_fields: Object.freeze(['evidence_uri', 'validated_at', 'operator', 'worker_pool_reference']),
  },
  {
    step_id: 'adapter_stop_path_invoked',
    required_fields: Object.freeze(['evidence_uri', 'validated_at', 'operator', 'adapter_stop_reference']),
  },
  {
    step_id: 'audit_timeline_recorded',
    required_fields: Object.freeze(['evidence_uri', 'validated_at', 'operator', 'audit_event_ids']),
  },
  {
    step_id: 'clear_and_resume_guarded',
    required_fields: Object.freeze(['evidence_uri', 'validated_at', 'operator', 'resume_decision_reference']),
  },
]);

export const KILL_SWITCH_REQUIRED_STEP_IDS = Object.freeze(
  KILL_SWITCH_REQUIRED_STEPS.map((step) => step.step_id),
);

const STEP_BY_ID = Object.freeze(
  Object.fromEntries(KILL_SWITCH_REQUIRED_STEPS.map((step) => [step.step_id, step])),
);

const FORBIDDEN_KEYS = new Set([
  'authorization',
  'body',
  'credential',
  'headers',
  'packet',
  'packet_payload',
  'password',
  'payload',
  'raw_body',
  'raw_headers',
  'raw_log',
  'raw_packet',
  'secret',
  'token',
]);

function normalizeKey(key) {
  return key
    .replace(/([a-z])([A-Z])/g, '$1_$2')
    .replace(/[^A-Za-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase();
}

function hasValue(value) {
  if (value === null || value === undefined) return false;
  if (typeof value === 'string' && value.trim() === '') return false;
  if (Array.isArray(value) && value.length === 0) return false;
  return true;
}

function collectForbiddenFields(value, path = '') {
  if (value === null || value === undefined || typeof value !== 'object') return [];
  const findings = [];
  if (Array.isArray(value)) {
    value.forEach((entry, index) => {
      findings.push(...collectForbiddenFields(entry, `${path}[${index}]`));
    });
    return findings;
  }
  for (const [key, nested] of Object.entries(value)) {
    const keyPath = path ? `${path}.${key}` : key;
    const normalized = normalizeKey(key);
    if (FORBIDDEN_KEYS.has(normalized) || normalized.startsWith('raw_')) {
      findings.push(keyPath);
    }
    findings.push(...collectForbiddenFields(nested, keyPath));
  }
  return findings;
}

export function validateKillSwitchExerciseEvidence(evidence) {
  const steps = Array.isArray(evidence?.steps) ? evidence.steps : [];
  const seen = new Set();
  const invalid_steps = [];
  const missing_fields = [];
  const forbidden_fields = collectForbiddenFields(evidence);

  for (const step of steps) {
    const stepId = step?.step_id;
    if (!stepId || typeof stepId !== 'string') {
      invalid_steps.push({ step_id: stepId ?? null, reason: 'missing_step_id' });
      continue;
    }
    const baseline = STEP_BY_ID[stepId];
    if (!baseline) {
      invalid_steps.push({ step_id: stepId, reason: 'unknown_step' });
      continue;
    }
    seen.add(stepId);
    const missing = baseline.required_fields.filter((field) => !hasValue(step[field]));
    if (missing.length > 0) {
      missing_fields.push({ step_id: stepId, fields: missing });
    }
  }

  const missing_steps = KILL_SWITCH_REQUIRED_STEP_IDS.filter((stepId) => !seen.has(stepId));

  return {
    ok:
      missing_steps.length === 0
      && invalid_steps.length === 0
      && missing_fields.length === 0
      && forbidden_fields.length === 0,
    missing_steps,
    invalid_steps,
    missing_fields,
    forbidden_fields,
  };
}
