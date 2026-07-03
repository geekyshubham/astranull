#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateProductionReleaseEvidence } from '../src/contracts/productionReleaseEvidence.mjs';
import { redactObject, redactString } from '../src/lib/redact.mjs';

const DEFAULT_OUT = 'output/staging-e2e-matrix-evidence.json';
const EVIDENCE_KIND = 'staging_e2e_matrix';

export const REQUIRED_SCENARIOS = Object.freeze([
  'oidc_login',
  'signed_agent_registration',
  'signed_probe_worker',
  'safe_validation_loop',
  'verdict_explanation',
  'report_export_custody',
  'soc_high_scale_governance',
]);

export const SCENARIO_REQUIRED_FIELDS = Object.freeze([
  'status',
  'evidence_uri',
  'owner',
  'completed_at',
]);

export const SIGNOFF_REQUIRED_FIELDS = Object.freeze([
  'owner',
  'signed_at',
  'signoff_reference',
]);

export const TOP_LEVEL_REQUIRED_FIELDS = Object.freeze([
  'environment',
  'scenarios',
  'signoff',
  'evidence_uri',
]);

const ALLOWED_SCENARIO_STATUS = new Set(['passed', 'failed', 'skipped', 'not_run']);
const LOCAL_STAGING_ENVIRONMENT = 'local-staging';

const FORBIDDEN_KEYS = new Set([
  'api_key',
  'apikey',
  'attachment',
  'attachments',
  'authorization',
  'body',
  'browser_log',
  'browser_logs',
  'connection_string',
  'console_log',
  'console_logs',
  'credential',
  'credentials',
  'database_url',
  'dom_snapshot',
  'har',
  'har_file',
  'headers',
  'html_blob',
  'image_blob',
  'ip_inventory',
  'ip_list',
  'log',
  'log_blob',
  'logs',
  'network_log',
  'packet',
  'packet_capture',
  'packet_payload',
  'page_source',
  'password',
  'payload',
  'pcap',
  'png_data',
  'raw_body',
  'raw_dump',
  'raw_headers',
  'raw_log',
  'raw_logs',
  'raw_packet',
  'request',
  'response',
  'screenshot',
  'screenshot_data',
  'screenshots',
  'secret',
  'target_ip_inventory',
  'target_ips',
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

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export function collectForbiddenFields(value, fieldPath = '') {
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

function normalizeScenarioId(scenario) {
  const raw = scenario?.scenario_id ?? scenario?.id ?? scenario?.scenario;
  if (!hasValue(raw)) return null;
  return String(raw).trim().toLowerCase();
}

function normalizeScenarioStatus(status) {
  if (!hasValue(status)) return null;
  return String(status).trim().toLowerCase();
}

function normalizeEnvironment(value) {
  if (!hasValue(value)) return null;
  return String(value).trim().toLowerCase();
}

function isLocalStagingMatrix(evidence) {
  return normalizeEnvironment(evidence?.environment) === LOCAL_STAGING_ENVIRONMENT;
}

function scenarioIndexById(scenarios) {
  const map = new Map();
  if (!Array.isArray(scenarios)) return map;
  scenarios.forEach((entry, index) => {
    const id = normalizeScenarioId(entry);
    if (!id) return;
    if (!map.has(id)) map.set(id, { entry, index });
  });
  return map;
}

function computeOverallStatus({ missingScenarios, failedScenarios, scenarioFieldGaps, missingFields }) {
  if (failedScenarios.length > 0) return 'failed';
  if (
    missingScenarios.length > 0
    || scenarioFieldGaps.length > 0
    || missingFields.length > 0
  ) {
    return 'incomplete';
  }
  return 'passed';
}

/**
 * @param {Record<string, unknown>} evidence
 * @param {{ releaseId?: string | null }} [options]
 */
function resolveReleaseId(evidence, options = {}) {
  if (hasValue(evidence?.release_id)) return String(evidence.release_id);
  if (hasValue(options.releaseId)) return String(options.releaseId);
  return null;
}

export function validateStagingE2eMatrixEvidence(evidence, options = {}) {
  const releaseId = resolveReleaseId(evidence, options);
  const missing_fields = [];

  if (!hasValue(releaseId)) missing_fields.push('release_id');
  for (const field of TOP_LEVEL_REQUIRED_FIELDS) {
    if (!hasValue(evidence?.[field])) missing_fields.push(field);
  }

  if (isObject(evidence?.signoff)) {
    for (const field of SIGNOFF_REQUIRED_FIELDS) {
      if (!hasValue(evidence.signoff[field])) {
        missing_fields.push(`signoff.${field}`);
      }
    }
  } else if (hasValue(evidence?.signoff)) {
    missing_fields.push('signoff');
  }

  const scenarios = Array.isArray(evidence?.scenarios) ? evidence.scenarios : [];
  const byId = scenarioIndexById(scenarios);
  const missing_scenarios = REQUIRED_SCENARIOS.filter((id) => !byId.has(id));

  const failed_scenarios = [];
  const scenario_field_gaps = [];
  const invalid_scenario_status = [];
  const localStagingMatrix = isLocalStagingMatrix(evidence);

  for (const scenarioId of REQUIRED_SCENARIOS) {
    const row = byId.get(scenarioId);
    if (!row) continue;
    const scenario = row.entry;
    for (const field of SCENARIO_REQUIRED_FIELDS) {
      if (!hasValue(scenario[field])) {
        scenario_field_gaps.push(`${scenarioId}.${field}`);
      }
    }
    const status = normalizeScenarioStatus(scenario.status);
    if (status && !ALLOWED_SCENARIO_STATUS.has(status)) {
      invalid_scenario_status.push(scenarioId);
    } else if (status !== 'passed' && !(localStagingMatrix && ['not_run', 'skipped'].includes(status))) {
      failed_scenarios.push(scenarioId);
    } else if (localStagingMatrix && ['not_run', 'skipped'].includes(status)) {
      scenario_field_gaps.push(`${scenarioId}.status`);
    }
  }

  if (invalid_scenario_status.length > 0) {
    for (const scenarioId of invalid_scenario_status) {
      scenario_field_gaps.push(`${scenarioId}.status`);
    }
  }

  const forbidden_fields = [...new Set(collectForbiddenFields(evidence))].sort();

  const validation_gaps = [
    ...missing_scenarios.map((id) => `missing_scenario:${id}`),
    ...failed_scenarios.map((id) => `failed_scenario:${id}`),
    ...scenario_field_gaps,
  ].sort();

  const uniqueMissing = [...new Set(missing_fields)].sort();
  const overall_status = computeOverallStatus({
    missingScenarios: missing_scenarios,
    failedScenarios: failed_scenarios,
    scenarioFieldGaps: scenario_field_gaps,
    missingFields: uniqueMissing,
  });

  const ok =
    uniqueMissing.length === 0
    && forbidden_fields.length === 0
    && missing_scenarios.length === 0
    && failed_scenarios.length === 0
    && scenario_field_gaps.length === 0
    && overall_status === 'passed';

  return {
    ok,
    release_id: hasValue(releaseId) ? String(releaseId) : null,
    overall_status,
    missing_fields: uniqueMissing,
    forbidden_fields,
    missing_scenarios,
    failed_scenarios,
    scenario_field_gaps: [...new Set(scenario_field_gaps)].sort(),
    validation_gaps,
  };
}

function sanitizeScenario(entry) {
  const scenario_id = normalizeScenarioId(entry);
  return redactObject({
    scenario_id,
    status: normalizeScenarioStatus(entry?.status),
    evidence_uri: hasValue(entry?.evidence_uri) ? String(entry.evidence_uri) : null,
    owner: hasValue(entry?.owner) ? String(entry.owner) : null,
    completed_at: hasValue(entry?.completed_at) ? String(entry.completed_at) : null,
    ...(hasValue(entry?.notes) ? { notes: redactString(String(entry.notes)) } : {}),
  });
}

/**
 * @param {Record<string, unknown>} evidence
 * @param {{ releaseId?: string | null, createdAt?: string }} [options]
 */
export function buildStagingE2eMatrixProductionEvidence(evidence, options = {}) {
  const releaseId = resolveReleaseId(evidence, options);
  const scenarios = Array.isArray(evidence?.scenarios) ? evidence.scenarios : [];
  const byId = scenarioIndexById(scenarios);
  const orderedScenarios = REQUIRED_SCENARIOS
    .filter((id) => byId.has(id))
    .map((id) => sanitizeScenario(byId.get(id).entry));

  const validation = validateStagingE2eMatrixEvidence(evidence, { releaseId });

  const signoff = isObject(evidence?.signoff)
    ? redactObject({
      owner: evidence.signoff.owner ?? null,
      signed_at: evidence.signoff.signed_at ?? null,
      signoff_reference: evidence.signoff.signoff_reference ?? null,
    })
    : null;

  return redactObject({
    schema_version: 1,
    artifact_type: 'staging_e2e_matrix_evidence',
    created_at: options.createdAt ?? evidence?.created_at ?? new Date().toISOString(),
    release_id: hasValue(releaseId) ? String(releaseId) : null,
    environment: hasValue(evidence?.environment) ? String(evidence.environment) : null,
    scenarios: orderedScenarios,
    overall_status: validation.overall_status,
    signoff,
    evidence_uri: hasValue(evidence?.evidence_uri) ? String(evidence.evidence_uri) : null,
  });
}

/**
 * @param {{ evidence: Record<string, unknown>, validation: ReturnType<typeof validateStagingE2eMatrixEvidence>, releaseId?: string | null, createdAt?: string }} input
 */
export function createStagingE2eMatrixArtifact(input) {
  const { evidence, validation, releaseId, createdAt } = input;
  const productionEvidence = buildStagingE2eMatrixProductionEvidence(evidence, {
    releaseId: releaseId ?? validation.release_id,
    createdAt,
  });
  const contractValidation = validateProductionReleaseEvidence(EVIDENCE_KIND, productionEvidence);

  return {
    schema_version: 1,
    artifact_type: 'staging_e2e_matrix_evidence',
    created_at: productionEvidence.created_at,
    validation: {
      ok: validation.ok && contractValidation.ok,
      missing_fields: validation.missing_fields,
      forbidden_fields: validation.forbidden_fields,
      missing_scenarios: validation.missing_scenarios,
      failed_scenarios: validation.failed_scenarios,
      scenario_field_gaps: validation.scenario_field_gaps,
      validation_gaps: validation.validation_gaps,
      contract: {
        ok: contractValidation.ok,
        missing_fields: contractValidation.missing_fields,
        forbidden_fields: contractValidation.forbidden_fields,
      },
    },
    release_id: productionEvidence.release_id,
    environment: productionEvidence.environment,
    overall_status: productionEvidence.overall_status,
    scenarios: productionEvidence.scenarios,
    signoff: productionEvidence.signoff,
    evidence_uri: productionEvidence.evidence_uri,
    production_release_evidence: {
      kind: EVIDENCE_KIND,
      evidence: productionEvidence,
    },
    caveats: [
      'Metadata-only staging E2E matrix summary; no browser logs, HAR, screenshots, request/response bodies, tokens, credentials, or target IP inventories.',
      'This validator does not execute staging flows or call external services; operators supply captured scenario metadata and custody URIs.',
      'Production promotion still requires immutable custody of linked evidence_uri artifacts and SOC/legal signoff where applicable.',
    ],
  };
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
      if (i >= argv.length) throw new Error(`Missing value for ${arg}`);
      return argv[i];
    };
    if (arg === '--input') opts.input = next();
    else if (arg === '--out') opts.out = next();
    else if (arg === '--release-id') opts.releaseId = next();
    else if (arg === '--validate-only') opts.validateOnly = true;
    else if (arg === '--help' || arg === '-h') opts.help = true;
    else throw new Error(`Unknown argument: ${arg}`);
  }
  if (!opts.help && !opts.input) throw new Error('--input is required');
  return opts;
}

function readEvidence(inputPath) {
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(inputPath, 'utf8'));
  } catch {
    throw new Error(`staging-e2e-matrix-evidence: input is not valid JSON: ${inputPath}`);
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('staging-e2e-matrix-evidence: input must be a JSON object');
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
      'Usage: node scripts/staging-e2e-matrix-evidence.mjs --input evidence.json [--out file] [--release-id rel] [--validate-only]',
    );
    return 0;
  }

  const evidence = readEvidence(opts.input);
  const validation = validateStagingE2eMatrixEvidence(evidence, { releaseId: opts.releaseId });
  const artifact = createStagingE2eMatrixArtifact({
    evidence,
    validation,
    releaseId: opts.releaseId,
  });

  if (opts.validateOnly) {
    console.log(
      `staging-e2e-matrix-evidence: ${artifact.validation.ok ? 'ok' : 'failed'} (overall_status=${artifact.overall_status}, scenarios=${artifact.scenarios.length})`,
    );
    return artifact.validation.ok || isLocalStagingMatrix(evidence) ? 0 : 1;
  }

  mkdirSync(path.dirname(path.resolve(opts.out)), { recursive: true });
  writeFileSync(opts.out, `${JSON.stringify(artifact, null, 2)}\n`);
  console.log(`staging-e2e-matrix-evidence: wrote ${opts.out} (overall_status=${artifact.overall_status})`);
  return artifact.validation.ok || isLocalStagingMatrix(evidence) ? 0 : 1;
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(`staging-e2e-matrix-evidence: ${err.message}`);
      process.exit(1);
    },
  );
}
