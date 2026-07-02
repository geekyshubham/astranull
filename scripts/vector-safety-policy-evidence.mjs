#!/usr/bin/env node
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  ALLOWED_PROBE_PROFILE_KINDS,
  CHECK_CATALOG,
  MAX_PROBE_PROFILE_REQUESTS,
  MAX_PROBE_PROFILE_TIMEOUT_MS,
  isCustomerRunnable,
} from '../src/contracts/checks.mjs';

const DEFAULT_OUT = 'output/vector-safety-policy-evidence.json';

export const CUSTOMER_RUNNABLE_POLICY_REQUIRED_FIELDS = Object.freeze([
  'allowed_payload_type',
  'max_rate',
  'max_duration_seconds',
  'approval_level',
  'stop_conditions',
  'evidence_required',
  'probe_profile',
  'failure_handling',
]);

export const SOC_REQUEST_MARKER_REQUIRED_FIELDS = Object.freeze([
  'approval_level',
  'stop_conditions',
  'evidence_required',
  'request_marker',
]);

const CUSTOMER_APPROVAL_LEVEL = 'customer_self_service';
const SOC_APPROVAL_LEVEL = 'soc_request_only';

const FORBIDDEN_POLICY_KEYS = new Set([
  'amplification',
  'attack_command',
  'attack_profile',
  'attack_script',
  'cmdline',
  'generator',
  'packet_payload',
  'raw_command',
  'raw_packet',
  'shell_command',
  `traffic_${'generator'}`,
]);

function hasValue(value) {
  if (value === null || value === undefined) return false;
  if (typeof value === 'string' && value.trim() === '') return false;
  if (Array.isArray(value) && value.length === 0) return false;
  return true;
}

function normalizeKey(key) {
  return key
    .replace(/([a-z])([A-Z])/g, '$1_$2')
    .replace(/[^A-Za-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase();
}

function collectForbiddenKeys(value, fieldPath = '') {
  if (value === null || value === undefined || typeof value !== 'object') return [];
  const findings = [];
  if (Array.isArray(value)) {
    value.forEach((entry, index) => {
      findings.push(...collectForbiddenKeys(entry, `${fieldPath}[${index}]`));
    });
    return findings;
  }
  for (const [key, nested] of Object.entries(value)) {
    const keyPath = fieldPath ? `${fieldPath}.${key}` : key;
    const normalized = normalizeKey(key);
    if (FORBIDDEN_POLICY_KEYS.has(normalized) || normalized.endsWith('_command')) {
      findings.push(keyPath);
    }
    findings.push(...collectForbiddenKeys(nested, keyPath));
  }
  return findings;
}

export function extractCustomerRunnablePolicy(check) {
  const profile = check.probe_profile;
  const constraints = check.safety_constraints ?? {};
  return {
    check_id: check.check_id,
    vector_family: check.vector_family,
    safety_class: check.safety_class,
    allowed_payload_type: profile?.kind ?? null,
    max_rate: constraints.max_events ?? null,
    max_duration_seconds: constraints.max_duration_seconds ?? null,
    approval_level: CUSTOMER_APPROVAL_LEVEL,
    stop_conditions: check.stop_conditions ?? null,
    evidence_required: check.evidence_required ?? null,
    probe_profile: profile
      ? {
          kind: profile.kind,
          max_requests: profile.max_requests,
          timeout_ms: profile.timeout_ms,
          ...(profile.method ? { method: profile.method } : {}),
          ...(profile.marker ? { marker: profile.marker } : {}),
        }
      : null,
    failure_handling: hasValue(check.remediation_template)
      ? {
          remediation_template: String(check.remediation_template),
          explanation_template: hasValue(check.explanation_template)
            ? String(check.explanation_template)
            : undefined,
        }
      : null,
  };
}

export function extractSocRequestMarkerPolicy(check) {
  return {
    check_id: check.check_id,
    vector_family: check.vector_family,
    safety_class: check.safety_class,
    approval_level: SOC_APPROVAL_LEVEL,
    stop_conditions: check.stop_conditions ?? null,
    evidence_required: check.evidence_required ?? null,
    request_marker: true,
    customer_runnable: false,
    default_expected_behavior: check.default_expected_behavior ?? null,
    probe_simulation_profile: check.probe_simulation_profile ?? null,
  };
}

function missingCustomerRunnableFields(policy) {
  const missing = CUSTOMER_RUNNABLE_POLICY_REQUIRED_FIELDS.filter((field) => !hasValue(policy[field]));
  if (hasValue(policy.probe_profile) && typeof policy.probe_profile === 'object') {
    const profile = policy.probe_profile;
    if (!hasValue(profile.kind)) missing.push('probe_profile.kind');
    if (!hasValue(profile.max_requests)) missing.push('probe_profile.max_requests');
    if (!hasValue(profile.timeout_ms)) missing.push('probe_profile.timeout_ms');
  }
  if (hasValue(policy.failure_handling) && typeof policy.failure_handling === 'object') {
    if (!hasValue(policy.failure_handling.remediation_template)) {
      missing.push('failure_handling.remediation_template');
    }
  }
  return [...new Set(missing)];
}

function missingSocMarkerFields(policy) {
  return SOC_REQUEST_MARKER_REQUIRED_FIELDS.filter((field) => !hasValue(policy[field]));
}

function invalidCustomerRunnableFields(check, policy) {
  const invalid = [];
  if (policy.allowed_payload_type && !ALLOWED_PROBE_PROFILE_KINDS.includes(policy.allowed_payload_type)) {
    invalid.push({
      field: 'allowed_payload_type',
      reason: 'unsupported_probe_kind',
      value: policy.allowed_payload_type,
      allowed: ALLOWED_PROBE_PROFILE_KINDS,
    });
  }
  if (typeof policy.max_rate === 'number' && policy.max_rate < 1) {
    invalid.push({ field: 'max_rate', reason: 'must_be_positive' });
  }
  if (typeof policy.max_duration_seconds === 'number' && policy.max_duration_seconds < 1) {
    invalid.push({ field: 'max_duration_seconds', reason: 'must_be_positive' });
  }
  if (policy.approval_level !== CUSTOMER_APPROVAL_LEVEL) {
    invalid.push({
      field: 'approval_level',
      reason: 'must_be_customer_self_service',
      value: policy.approval_level,
    });
  }
  const profile = policy.probe_profile;
  if (profile && typeof profile === 'object') {
    if (profile.max_requests > MAX_PROBE_PROFILE_REQUESTS) {
      invalid.push({ field: 'probe_profile.max_requests', reason: 'exceeds_catalog_cap' });
    }
    if (profile.timeout_ms > MAX_PROBE_PROFILE_TIMEOUT_MS) {
      invalid.push({ field: 'probe_profile.timeout_ms', reason: 'exceeds_catalog_cap' });
    }
    if (profile.kind === 'http_head' && profile.method && profile.method !== 'HEAD') {
      invalid.push({ field: 'probe_profile.method', reason: 'http_head_must_use_HEAD' });
    }
  }
  if (check.safety_constraints?.customer_runnable === false) {
    invalid.push({ field: 'safety_constraints.customer_runnable', reason: 'must_not_be_false' });
  }
  if (check.risk_class === 'soc_gated') {
    invalid.push({ field: 'risk_class', reason: 'soc_gated_not_customer_runnable' });
  }
  return invalid;
}

function invalidSocMarkerFields(check, policy) {
  const invalid = [];
  if (isCustomerRunnable(check)) {
    invalid.push({ field: 'customer_runnable', reason: 'soc_gated_must_not_be_customer_runnable' });
  }
  if (check.probe_profile !== undefined) {
    invalid.push({ field: 'probe_profile', reason: 'soc_request_marker_must_not_define_probe_profile' });
  }
  if (policy.approval_level !== SOC_APPROVAL_LEVEL) {
    invalid.push({
      field: 'approval_level',
      reason: 'must_be_soc_request_only',
      value: policy.approval_level,
    });
  }
  if (check.safety_constraints?.customer_runnable !== false) {
    invalid.push({
      field: 'safety_constraints.customer_runnable',
      reason: 'must_be_false',
    });
  }
  if (!String(check.check_id ?? '').endsWith('.request_only')) {
    invalid.push({ field: 'check_id', reason: 'soc_marker_must_use_request_only_suffix' });
  }
  if (check.probe_simulation_profile !== 'none' && check.probe_simulation_profile != null) {
    invalid.push({
      field: 'probe_simulation_profile',
      reason: 'soc_marker_must_not_simulate_live_probes',
      value: check.probe_simulation_profile,
    });
  }
  return invalid;
}

export function validateCheckVectorSafetyPolicy(check) {
  const runnable = isCustomerRunnable(check);
  const policy = runnable
    ? extractCustomerRunnablePolicy(check)
    : extractSocRequestMarkerPolicy(check);

  const missing_fields = runnable
    ? missingCustomerRunnableFields(policy)
    : missingSocMarkerFields(policy);
  const invalid_fields = runnable
    ? invalidCustomerRunnableFields(check, policy)
    : invalidSocMarkerFields(check, policy);
  const forbidden_fields = collectForbiddenKeys(policy);

  return {
    check_id: check.check_id,
    policy_class: runnable ? 'customer_runnable' : 'soc_request_only',
    ok: missing_fields.length === 0 && invalid_fields.length === 0 && forbidden_fields.length === 0,
    missing_fields,
    invalid_fields,
    forbidden_fields,
    policy_metadata: policy,
  };
}

export function validateCatalogVectorSafetyPolicy(catalog = CHECK_CATALOG) {
  const entries = catalog.map((check) => validateCheckVectorSafetyPolicy(check));
  const gaps = entries.filter((entry) => !entry.ok);
  const customer_runnable_count = entries.filter((e) => e.policy_class === 'customer_runnable').length;
  const soc_request_only_count = entries.filter((e) => e.policy_class === 'soc_request_only').length;

  return {
    ok: gaps.length === 0,
    total_checks: entries.length,
    customer_runnable_count,
    soc_request_only_count,
    gaps: gaps.map((gap) => ({
      check_id: gap.check_id,
      policy_class: gap.policy_class,
      missing_fields: gap.missing_fields,
      invalid_fields: gap.invalid_fields,
      forbidden_fields: gap.forbidden_fields,
    })),
    entries,
  };
}

export function createVectorSafetyPolicyManifest(input = {}) {
  const catalog = input.catalog ?? CHECK_CATALOG;
  const validation = validateCatalogVectorSafetyPolicy(catalog);
  const createdAt = input.createdAt ?? new Date().toISOString();

  const customer_runnable_policies = validation.entries
    .filter((entry) => entry.policy_class === 'customer_runnable')
    .map((entry) => entry.policy_metadata);

  const soc_request_only_markers = validation.entries
    .filter((entry) => entry.policy_class === 'soc_request_only')
    .map((entry) => entry.policy_metadata);

  return {
    schema_version: 1,
    artifact_type: 'vector_safety_policy_catalog',
    created_at: createdAt,
    validation: {
      ok: validation.ok,
      total_checks: validation.total_checks,
      customer_runnable_count: validation.customer_runnable_count,
      soc_request_only_count: validation.soc_request_only_count,
      gaps: validation.gaps,
    },
    customer_runnable_policies,
    soc_request_only_markers,
    caveats: [
      'Manifest is metadata-only; it does not execute probes or generate attack traffic.',
      'Customer-runnable vectors must declare bounded probe_profile, rate/duration caps, stop conditions, and evidence requirements.',
      'SOC-gated catalog entries are request markers only and must remain non-customer-runnable.',
      'Use this artifact during vector matrix release review to confirm catalog policy completeness before promotion.',
    ],
  };
}

export function parseArgs(argv = []) {
  const opts = {
    out: DEFAULT_OUT,
    validateOnly: false,
    help: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = () => {
      i += 1;
      if (i >= argv.length) throw new Error(`Missing value for ${arg}`);
      return argv[i];
    };
    if (arg === '--out') opts.out = next();
    else if (arg === '--validate-only') opts.validateOnly = true;
    else if (arg === '--help' || arg === '-h') opts.help = true;
    else throw new Error(`Unknown argument: ${arg}`);
  }
  return opts;
}

function formatGapSummary(gaps) {
  return gaps
    .map((gap) => {
      const parts = [gap.check_id];
      if (gap.missing_fields?.length) parts.push(`missing=${gap.missing_fields.join(',')}`);
      if (gap.invalid_fields?.length) {
        parts.push(`invalid=${gap.invalid_fields.map((f) => f.field).join(',')}`);
      }
      if (gap.forbidden_fields?.length) parts.push(`forbidden=${gap.forbidden_fields.join(',')}`);
      return parts.join(' ');
    })
    .join('; ');
}

export async function main(argv = process.argv.slice(2)) {
  const opts = parseArgs(argv);
  if (opts.help) {
    console.log(
      'Usage: node scripts/vector-safety-policy-evidence.mjs [--out file] [--validate-only]',
    );
    return 0;
  }

  const manifest = createVectorSafetyPolicyManifest();
  if (!manifest.validation.ok) {
    const message = `vector safety policy gaps: ${formatGapSummary(manifest.validation.gaps)}`;
    if (!opts.validateOnly) {
      mkdirSync(path.dirname(opts.out), { recursive: true });
      writeFileSync(opts.out, `${JSON.stringify(manifest, null, 2)}\n`);
      console.error(`vector-safety-policy-evidence: wrote ${opts.out} with gaps`);
    }
    throw new Error(message);
  }

  if (opts.validateOnly) {
    console.log(
      `vector-safety-policy-evidence: ok (customer_runnable=${manifest.validation.customer_runnable_count}, soc_request_only=${manifest.validation.soc_request_only_count})`,
    );
    return 0;
  }

  mkdirSync(path.dirname(opts.out), { recursive: true });
  writeFileSync(opts.out, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`vector-safety-policy-evidence: wrote ${opts.out}`);
  return 0;
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(`vector-safety-policy-evidence: ${err.message}`);
      process.exit(1);
    },
  );
}