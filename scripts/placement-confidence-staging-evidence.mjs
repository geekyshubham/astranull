#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateProductionReleaseEvidence } from '../src/contracts/productionReleaseEvidence.mjs';
import { redactObject, redactString } from '../src/lib/redact.mjs';

const DEFAULT_OUT = 'output/placement-confidence-staging-evidence.json';
const PRODUCTION_RELEASE_EVIDENCE_KIND = 'placement_confidence_staging';

export const PLACEMENT_CONFIDENCE_STAGING_REQUIRED_SCENARIOS = Object.freeze([
  'strong_agent_observation',
  'misplaced_agent_detection',
  'external_only_inconclusive',
  'canary_path_observation',
]);

export const PLACEMENT_CONFIDENCE_SCENARIO_REQUIRED_FIELDS = Object.freeze([
  'scenario_id',
  'status',
  'target_group_reference',
  'run_reference',
  'verdict_reference',
  'confidence_label',
  'evidence_uri',
  'owner',
  'completed_at',
]);

export const PLACEMENT_CONFIDENCE_TOP_LEVEL_REQUIRED_FIELDS = Object.freeze([
  'environment',
  'evidence_uri',
  'signoff',
  'evidence_correlation_summary',
  'scenarios',
]);

const SIGNOFF_REQUIRED_FIELDS = Object.freeze(['owner', 'signed_at', 'signoff_reference']);

const CORRELATION_SUMMARY_REQUIRED_FIELDS = Object.freeze([
  'probe_evidence_count',
  'agent_evidence_count',
  'correlated_pairs',
  'gaps',
]);

const ALLOWED_SCENARIO_STATUS = new Set(['passed', 'failed', 'invalid', 'not_run']);

const FORBIDDEN_KEYS = new Set([
  'api_key',
  'apikey',
  'attachment',
  'attachments',
  'authorization',
  'body',
  'connection_string',
  'credential',
  'credentials',
  'customer_payload',
  'database_url',
  'headers',
  'ip_inventory',
  'ip_list',
  'log',
  'log_lines',
  'logs',
  'packet',
  'packet_capture',
  'packet_payload',
  'password',
  'payload',
  'pcap',
  'raw_body',
  'raw_headers',
  'raw_log',
  'raw_packet',
  'screenshot',
  'screenshot_data',
  'screenshots',
  'secret',
  'target_ip_inventory',
  'target_ips',
  'token',
]);

const PG_URL_RE = /postgres(?:ql)?:\/\/[^\s'"]+/gi;
const IPV4_CSV_RE = /\b(?:\d{1,3}\.){3}\d{1,3}(?:\s*,\s*(?:\d{1,3}\.){3}\d{1,3}){2,}/;

const SECRET_IN_STRING_PATTERNS = [
  { pattern: /ast_v1\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){2}/, reason: 'token_pattern' },
  { pattern: /agc_v1\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){2}/, reason: 'token_pattern' },
  { pattern: /svc_v1\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){2}/, reason: 'token_pattern' },
];

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

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function collectForbiddenFields(value, fieldPath = '') {
  if (value === null || value === undefined || typeof value !== 'object') return [];
  const findings = [];
  if (Array.isArray(value)) {
    value.forEach((entry, index) => {
      findings.push(...collectForbiddenFields(entry, `${fieldPath}[${index}]`));
    });
    return findings;
  }
  for (const [key, nested] of Object.entries(value)) {
    const keyPath = fieldPath ? `${fieldPath}.${key}` : key;
    const normalized = normalizeKey(key);
    if (FORBIDDEN_KEYS.has(normalized) || normalized.startsWith('raw_')) {
      findings.push(keyPath);
    }
    findings.push(...collectForbiddenFields(nested, keyPath));
  }
  return findings;
}

function collectForbiddenStringPatterns(value, fieldPath = '') {
  if (value === null || value === undefined) return [];
  if (typeof value === 'string') {
    const findings = [];
    if (PG_URL_RE.test(value)) {
      PG_URL_RE.lastIndex = 0;
      findings.push(`${fieldPath}:database_url_pattern`);
    }
    if (IPV4_CSV_RE.test(value)) {
      findings.push(`${fieldPath}:target_ip_inventory_pattern`);
    }
    for (const { pattern, reason } of SECRET_IN_STRING_PATTERNS) {
      if (pattern.test(value)) {
        pattern.lastIndex = 0;
        findings.push(`${fieldPath}:${reason}`);
      }
    }
    return findings;
  }
  if (Array.isArray(value)) {
    return value.flatMap((entry, index) =>
      collectForbiddenStringPatterns(entry, `${fieldPath}[${index}]`),
    );
  }
  if (typeof value === 'object') {
    return Object.entries(value).flatMap(([key, nested]) =>
      collectForbiddenStringPatterns(nested, fieldPath ? `${fieldPath}.${key}` : key),
    );
  }
  return [];
}

function missingNestedFields(object, requiredFields, prefix) {
  if (!isObject(object)) {
    return requiredFields.map((field) => `${prefix}.${field}`);
  }
  return requiredFields
    .filter((field) => !hasValue(object[field]))
    .map((field) => `${prefix}.${field}`);
}

function validateScenarioEntry(scenario, index) {
  const prefix = `scenarios[${index}]`;
  const missing_fields = [];
  const invalid_fields = [];

  if (!isObject(scenario)) {
    return {
      missing_fields: [prefix],
      invalid_fields: [{ field: prefix, reason: 'invalid_scenario_object' }],
      scenario_id: null,
      status: null,
    };
  }

  const scenarioId = hasValue(scenario.scenario_id) ? String(scenario.scenario_id).trim() : null;
  const status = hasValue(scenario.status) ? String(scenario.status).trim().toLowerCase() : null;

  for (const field of PLACEMENT_CONFIDENCE_SCENARIO_REQUIRED_FIELDS) {
    if (!hasValue(scenario[field])) {
      missing_fields.push(`${prefix}.${field}`);
    }
  }

  if (status && !ALLOWED_SCENARIO_STATUS.has(status)) {
    invalid_fields.push({
      field: `${prefix}.status`,
      reason: 'invalid_scenario_status',
      allowed: [...ALLOWED_SCENARIO_STATUS],
    });
  }

  return { missing_fields, invalid_fields, scenario_id: scenarioId, status };
}

function summarizeCorrelationFromScenarios(scenarios) {
  const passed = scenarios.filter((s) => String(s?.status ?? '').toLowerCase() === 'passed');
  return {
    probe_evidence_count: passed.length,
    agent_evidence_count: passed.filter((s) => s.scenario_id !== 'external_only_inconclusive').length,
    correlated_pairs: passed.filter((s) =>
      ['strong_agent_observation', 'canary_path_observation'].includes(s.scenario_id),
    ).length,
    gaps: scenarios
      .filter((s) => String(s?.status ?? '').toLowerCase() !== 'passed')
      .map((s) => s.scenario_id)
      .filter(Boolean),
  };
}

function sanitizeScenarioSummary(scenario) {
  if (!isObject(scenario)) return null;
  return {
    scenario_id: scenario.scenario_id ?? null,
    status: scenario.status ?? null,
    target_group_reference: scenario.target_group_reference != null
      ? redactString(String(scenario.target_group_reference))
      : null,
    run_reference: scenario.run_reference != null ? redactString(String(scenario.run_reference)) : null,
    verdict_reference: scenario.verdict_reference != null
      ? redactString(String(scenario.verdict_reference))
      : null,
    confidence_label: scenario.confidence_label ?? null,
    evidence_uri: scenario.evidence_uri != null ? redactString(String(scenario.evidence_uri)) : null,
    owner: scenario.owner != null ? redactString(String(scenario.owner)) : null,
    completed_at: scenario.completed_at ?? null,
  };
}

/**
 * @param {unknown} input
 */
export function validatePlacementConfidenceStagingEvidence(input) {
  const forbidden_fields = [
    ...new Set([
      ...collectForbiddenFields(input),
      ...collectForbiddenStringPatterns(input),
    ]),
  ].sort();

  const missing_fields = PLACEMENT_CONFIDENCE_TOP_LEVEL_REQUIRED_FIELDS.filter(
    (field) => !hasValue(input?.[field]),
  );

  missing_fields.push(...missingNestedFields(input?.signoff, SIGNOFF_REQUIRED_FIELDS, 'signoff'));
  const correlationSummary = input?.evidence_correlation_summary;
  if (!isObject(correlationSummary)) {
    missing_fields.push('evidence_correlation_summary');
  } else {
    for (const field of CORRELATION_SUMMARY_REQUIRED_FIELDS) {
      if (field === 'gaps') {
        if (!Array.isArray(correlationSummary.gaps)) {
          missing_fields.push('evidence_correlation_summary.gaps');
        }
        continue;
      }
      if (!hasValue(correlationSummary[field]) && correlationSummary[field] !== 0) {
        missing_fields.push(`evidence_correlation_summary.${field}`);
      }
    }
  }

  const invalid_fields = [];
  const scenarios = Array.isArray(input?.scenarios) ? input.scenarios : [];
  const scenarioResults = scenarios.map((scenario, index) => validateScenarioEntry(scenario, index));

  for (const result of scenarioResults) {
    missing_fields.push(...result.missing_fields);
    invalid_fields.push(...result.invalid_fields);
  }

  const scenariosById = new Map();
  for (const result of scenarioResults) {
    if (!result.scenario_id) continue;
    if (scenariosById.has(result.scenario_id)) {
      invalid_fields.push({
        field: `scenarios.${result.scenario_id}`,
        reason: 'duplicate_scenario_id',
      });
    }
    scenariosById.set(result.scenario_id, result);
  }

  const missing_scenarios = PLACEMENT_CONFIDENCE_STAGING_REQUIRED_SCENARIOS.filter(
    (scenarioId) => !scenariosById.has(scenarioId),
  ).map((scenarioId) => `missing_scenario:${scenarioId}`);

  const failed_scenarios = PLACEMENT_CONFIDENCE_STAGING_REQUIRED_SCENARIOS.filter((scenarioId) => {
    const entry = scenariosById.get(scenarioId);
    return entry && entry.status !== 'passed';
  }).map((scenarioId) => `failed_scenario:${scenarioId}`);

  const uniqueMissing = [...new Set(missing_fields)].sort();
  const uniqueInvalid = [...new Set(invalid_fields.map((entry) => entry.field))].sort();

  const ok =
    forbidden_fields.length === 0
    && uniqueMissing.length === 0
    && uniqueInvalid.length === 0
    && missing_scenarios.length === 0
    && failed_scenarios.length === 0;

  return {
    ok,
    missing_fields: uniqueMissing,
    invalid_fields,
    forbidden_fields,
    missing_scenarios,
    failed_scenarios,
    scenario_count: scenarios.length,
  };
}

function fieldSummary(fields) {
  return fields.length > 0 ? fields.join(', ') : 'none';
}

export function assertValidPlacementConfidenceStagingEvidence(input) {
  const validation = validatePlacementConfidenceStagingEvidence(input);
  if (validation.forbidden_fields.length > 0) {
    throw new Error(`Forbidden field(s): ${fieldSummary(validation.forbidden_fields)}`);
  }
  if (validation.missing_scenarios.length > 0) {
    throw new Error(`Missing required scenario(s): ${fieldSummary(validation.missing_scenarios)}`);
  }
  if (validation.failed_scenarios.length > 0) {
    throw new Error(`Failed or invalid scenario(s): ${fieldSummary(validation.failed_scenarios)}`);
  }
  if (validation.missing_fields.length > 0) {
    throw new Error(`Missing field(s): ${fieldSummary(validation.missing_fields)}`);
  }
  if (validation.invalid_fields.length > 0) {
    throw new Error(
      `Invalid field(s): ${validation.invalid_fields.map((entry) => entry.field).join(', ')}`,
    );
  }
  return validation;
}

export function buildPlacementConfidenceStagingReleaseEvidence(input = {}, options = {}) {
  const redacted = redactObject(input);
  const scenarios = Array.isArray(redacted.scenarios) ? redacted.scenarios : [];
  const correlation =
    isObject(redacted.evidence_correlation_summary) && hasValue(redacted.evidence_correlation_summary)
      ? redacted.evidence_correlation_summary
      : summarizeCorrelationFromScenarios(scenarios);

  return {
    schema_version: 1,
    artifact_type: 'placement_confidence_staging_evidence',
    created_at: options.createdAt ?? redacted.created_at ?? new Date().toISOString(),
    release_id: options.releaseId ?? redacted.release_id ?? null,
    environment: redacted.environment ?? null,
    scenarios: scenarios.map((scenario) => ({
      scenario_id: scenario.scenario_id ?? null,
      status: scenario.status ?? null,
      target_group_reference: scenario.target_group_reference ?? null,
      run_reference: scenario.run_reference ?? null,
      verdict_reference: scenario.verdict_reference ?? null,
      confidence_label: scenario.confidence_label ?? null,
      evidence_uri: scenario.evidence_uri ?? null,
      owner: scenario.owner ?? null,
      completed_at: scenario.completed_at ?? null,
    })),
    evidence_correlation_summary: {
      probe_evidence_count: correlation.probe_evidence_count ?? null,
      agent_evidence_count: correlation.agent_evidence_count ?? null,
      correlated_pairs: correlation.correlated_pairs ?? null,
      gaps: Array.isArray(correlation.gaps) ? correlation.gaps : [],
    },
    signoff: redacted.signoff
      ? {
          owner: redacted.signoff.owner ?? null,
          signed_at: redacted.signoff.signed_at ?? null,
          signoff_reference: redacted.signoff.signoff_reference ?? null,
        }
      : null,
    evidence_uri: redacted.evidence_uri ?? null,
  };
}

export function validatePlacementConfidenceStagingReleaseContract(releaseEvidence) {
  return validateProductionReleaseEvidence(PRODUCTION_RELEASE_EVIDENCE_KIND, releaseEvidence);
}

export function createPlacementConfidenceStagingEvidenceManifest(input = {}) {
  const evidence = input.evidence ?? {};
  const validation = validatePlacementConfidenceStagingEvidence(evidence);
  const releaseEvidence = buildPlacementConfidenceStagingReleaseEvidence(evidence, {
    releaseId: input.releaseId,
    createdAt: input.createdAt,
  });
  const contractValidation = validatePlacementConfidenceStagingReleaseContract(releaseEvidence);

  const manifest = {
    schema_version: 1,
    artifact_type: 'placement_confidence_staging_validator_manifest',
    created_at: input.createdAt ?? new Date().toISOString(),
    release_id: releaseEvidence.release_id,
    validation: {
      ok: validation.ok && contractValidation.ok,
      missing_fields: validation.missing_fields,
      invalid_fields: validation.invalid_fields,
      forbidden_fields: validation.forbidden_fields,
      missing_scenarios: validation.missing_scenarios,
      failed_scenarios: validation.failed_scenarios,
      contract: {
        ok: contractValidation.ok,
        invalid_kind: contractValidation.invalid_kind,
        missing_fields: contractValidation.missing_fields,
        forbidden_fields: contractValidation.forbidden_fields,
      },
    },
    production_release_evidence: {
      kind: PRODUCTION_RELEASE_EVIDENCE_KIND,
      evidence: releaseEvidence,
    },
    scenarios: (Array.isArray(evidence.scenarios) ? evidence.scenarios : []).map(sanitizeScenarioSummary),
    required_scenarios: [...PLACEMENT_CONFIDENCE_STAGING_REQUIRED_SCENARIOS],
    caveats: [
      'Metadata-only placement confidence staging proof; no raw packets, logs, bodies, headers, payloads, IP inventories, credentials, tokens, database URLs, or screenshots.',
      'Scenarios must demonstrate probe-to-agent correlation, misplaced-agent detection, external-only inconclusive paths, and canary placement observation using references only.',
      'Passing validation does not replace live staging execution, verdict explanation UI review, or detection signoff.',
    ],
  };

  return manifest;
}

export function parseArgs(argv = []) {
  const opts = {
    input: null,
    out: DEFAULT_OUT,
    releaseId: null,
    validateOnly: false,
    help: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = () => {
      i += 1;
      if (i >= argv.length) throw new Error('placement-confidence-staging-evidence: missing value for argument');
      return argv[i];
    };
    if (arg === '--input') opts.input = next();
    else if (arg === '--out') opts.out = next();
    else if (arg === '--release-id') opts.releaseId = next();
    else if (arg === '--validate-only') opts.validateOnly = true;
    else if (arg === '--help' || arg === '-h') opts.help = true;
    else throw new Error(`placement-confidence-staging-evidence: unknown argument ${arg}`);
  }
  if (!opts.help && !opts.input) {
    throw new Error('placement-confidence-staging-evidence: --input is required');
  }
  return opts;
}

function readInputJson(inputPath) {
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(inputPath, 'utf8'));
  } catch {
    throw new Error(`placement-confidence-staging-evidence: input is not valid JSON: ${inputPath}`);
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('placement-confidence-staging-evidence: input must be a JSON object');
  }
  if (parsed.evidence && typeof parsed.evidence === 'object' && !Array.isArray(parsed.evidence)) {
    return parsed.evidence;
  }
  return parsed;
}

export async function main(argv = process.argv.slice(2)) {
  const opts = parseArgs(argv);
  if (opts.help) {
    console.log(
      'Usage: node scripts/placement-confidence-staging-evidence.mjs --input evidence.json '
      + '[--out output/placement-confidence-staging-evidence.json] [--release-id rel] [--validate-only]',
    );
    return 0;
  }

  const evidence = readInputJson(opts.input);
  if (opts.releaseId && !hasValue(evidence.release_id)) {
    evidence.release_id = opts.releaseId;
  }

  const validation = validatePlacementConfidenceStagingEvidence(evidence);
  const manifest = createPlacementConfidenceStagingEvidenceManifest({
    evidence,
    releaseId: opts.releaseId ?? evidence.release_id,
    createdAt: hasValue(evidence.created_at) ? String(evidence.created_at) : undefined,
  });

  if (opts.validateOnly) {
    console.log(
      `placement-confidence-staging-evidence: ${validation.ok && manifest.validation.contract.ok ? 'ok' : 'failed'} `
      + `(scenarios=${validation.scenario_count}, release_id=${manifest.release_id ?? 'none'})`,
    );
    return validation.ok && manifest.validation.contract.ok ? 0 : 1;
  }

  mkdirSync(path.dirname(path.resolve(opts.out)), { recursive: true });
  writeFileSync(opts.out, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`placement-confidence-staging-evidence: wrote ${opts.out}`);
  return validation.ok && manifest.validation.contract.ok ? 0 : 1;
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(err instanceof Error ? err.message : String(err));
      process.exit(1);
    },
  );
}