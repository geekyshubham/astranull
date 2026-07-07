/**
 * Lightweight JSON-shape validators for portal revamp contract tests (docs/ux/16 §4).
 */

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function matchesPrimitive(value, type) {
  if (type === 'string') return typeof value === 'string';
  if (type === 'number') return typeof value === 'number' && !Number.isNaN(value);
  if (type === 'boolean') return typeof value === 'boolean';
  if (type === 'null') return value === null;
  if (type === 'object') return isObject(value);
  if (type === 'array') return Array.isArray(value);
  return false;
}

function shapeEntries(shape) {
  return Object.entries(shape).map(([key, childShape]) => {
    const optional = key.endsWith('?');
    return [optional ? key.slice(0, -1) : key, childShape, optional];
  });
}

function assertShape(value, shape, path = '$', issues = []) {
  if (typeof shape === 'string') {
    if (!matchesPrimitive(value, shape)) issues.push(`${path}: expected ${shape}`);
    return issues;
  }

  if (Array.isArray(shape)) {
    if (shape.length === 0) {
      if (!Array.isArray(value)) issues.push(`${path}: expected array`);
      return issues;
    }
    if (shape.every((entry) => typeof entry === 'string')) {
      if (!shape.some((type) => matchesPrimitive(value, type))) {
        issues.push(`${path}: expected one of ${shape.join('|')}`);
      }
      return issues;
    }
    if (!Array.isArray(value)) {
      issues.push(`${path}: expected array`);
      return issues;
    }
    if (shape.length === 1) {
      for (let i = 0; i < value.length; i += 1) {
        assertShape(value[i], shape[0], `${path}[${i}]`, issues);
      }
      return issues;
    }
    assertShape(value, shape[0], path, issues);
    return issues;
  }

  if (!isObject(shape)) {
    issues.push(`${path}: invalid schema node`);
    return issues;
  }

  if (!isObject(value)) {
    issues.push(`${path}: expected object`);
    return issues;
  }

  const entries = shapeEntries(shape);
  const allowed = new Set(entries.map(([key]) => key));
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) issues.push(`${path}.${key}: undocumented field`);
  }

  for (const [key, childShape, optional] of entries) {
    if (!(key in value)) {
      if (!optional) issues.push(`${path}.${key}: missing required field`);
      continue;
    }
    assertShape(value[key], childShape, `${path}.${key}`, issues);
  }

  return issues;
}

export function validateShape(value, shape) {
  const issues = assertShape(value, shape);
  return { ok: issues.length === 0, issues };
}

export const TARGET_DETAIL_SHAPE = {
  target: {
    id: 'string',
    tenant_id: 'string',
    target_group_id: 'string',
    kind: 'string',
    value: 'string',
    expected_behavior: 'string',
    agent_binding: { agent_id: 'string', bound_at: 'string' },
    created_at: 'string',
    eligibility: 'string',
    eligibility_reason: 'null',
  },
  verification: {
    state: 'string',
    source_kind: 'string',
    source_ref: ['object', 'null'],
    history: [{ state: 'string', transitioned_at: 'string', 'source_ref?': ['object', 'null'] }],
  },
  waf_posture: ['object', 'null'],
  checks_applied: [{ check_id: 'string', cadence: 'string', last_verdict: 'string', last_ran_at: 'string' }],
  runs_recent: [{ run_id: 'string', policy_id: 'string', verdict: 'string', started_at: 'string', agent_id: 'string' }],
  findings: [{ id: 'string', severity: 'string', title: 'string', state: 'string', opened_at: 'string', owner_group: 'string' }],
  loa: ['object', 'null'],
  counts: { runs_total: 'number', findings_open: 'number', findings_closed: 'number' },
  'meta?': {
    runs_empty_reason: ['string', 'null'],
    findings_empty_reason: ['string', 'null'],
    checks_empty_reason: ['string', 'null'],
    waf_empty_reason: ['string', 'null'],
  },
  'findings_next_cursor?': 'string',
};

export const EVIDENCE_SHAPE = {
  finding: { id: 'string', title: 'string', run_id: 'string' },
  bundle: {
    id: 'string',
    sha256: 'string',
    sealed_at: 'string',
    size_bytes: 'number',
    custody_schema_version: 'string',
  },
  artifacts: [{ id: 'string', kind: 'string', run_id: 'string', sha256: 'string', sealed_at: 'string', size_bytes: 'number' }],
  custody_chain: [{ step: 'number', kind: 'string', sha256: 'string', at: 'string' }],
  verify_url: 'string',
};

export const WAF_SUMMARY_SHAPE = {
  assets_total: 'number',
  protected: 'number',
  underprotected: 'number',
  unknown: 'number',
  coverage_pct: 'number',
  by_vendor: 'object',
  connectors_active: 'number',
  connectors_degraded: 'number',
  connectors_disabled: 'number',
  refreshed_at: 'string',
};

export const VERIFICATION_LADDER_SHAPE = {
  steps: [{ id: 'string', label: 'string', done: 'boolean', count: 'number', total: 'number' }],
};

export const LIST_ENVELOPE_SHAPE = {
  items: 'array',
  count: 'number',
  meta: ['object', 'null'],
};

export function validateListEnvelope(value, { requireEmptyReason = false } = {}) {
  const result = validateShape(value, LIST_ENVELOPE_SHAPE);
  if (!result.ok) return result;
  if (!Array.isArray(value.items)) {
    return { ok: false, issues: ['$.items: expected array'] };
  }
  if (requireEmptyReason) {
    const reason = value?.meta?.empty_reason;
    if (typeof reason !== 'string' || reason.trim().length === 0) {
      return { ok: false, issues: ['$.meta.empty_reason: required non-empty string for empty lists'] };
    }
  }
  return { ok: true, issues: [] };
}