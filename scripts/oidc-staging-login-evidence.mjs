#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ROLES } from '../src/contracts/roles.mjs';
import { loadRuntimeConfig, resolveAuthMode } from '../src/config.mjs';
import { redactObject, redactString } from '../src/lib/redact.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DEFAULT_OUT = 'output/oidc-staging-login-evidence.json';

export const OIDC_STAGING_LOGIN_REQUIRED_SCENARIOS = Object.freeze([
  'admin_role_login',
  'engineer_role_login',
  'viewer_role_login',
  'soc_role_login',
  'tenant_claim_mapping',
  'mfa_login',
  'header_only_negative',
  'invalid_token_rejected',
]);

export const OIDC_STAGING_LOGIN_SCENARIO_REQUIRED_FIELDS = Object.freeze([
  'scenario_id',
  'status',
  'evidence_uri',
  'owner',
  'completed_at',
  'api_probe_reference',
]);

export const OIDC_STAGING_LOGIN_TOP_LEVEL_REQUIRED_FIELDS = Object.freeze([
  'environment',
  'evidence_uri',
  'signoff',
  'claim_mapping_summary',
  'scenarios',
]);

const SIGNOFF_REQUIRED_FIELDS = Object.freeze(['owner', 'signed_at', 'signoff_reference']);

const CLAIM_MAPPING_REQUIRED_FIELDS = Object.freeze([
  'tenant_claim',
  'role_claim',
  'user_claim',
  'mapped_roles',
]);

const ALLOWED_SCENARIO_STATUS = new Set(['passed', 'failed', 'skipped', 'not_run']);

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

const JWT_RE = /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/;
const PG_URL_RE = /postgres(?:ql)?:\/\/[^\s'"]+/gi;

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

export function collectForbiddenStringPatterns(value, fieldPath = '') {
  if (value === null || value === undefined) return [];
  if (typeof value === 'string') {
    const findings = [];
    if (JWT_RE.test(value)) {
      findings.push(`${fieldPath}:jwt_pattern`);
    }
    if (PG_URL_RE.test(value)) {
      PG_URL_RE.lastIndex = 0;
      findings.push(`${fieldPath}:database_url_pattern`);
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

  for (const field of OIDC_STAGING_LOGIN_SCENARIO_REQUIRED_FIELDS) {
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

  if (scenario.mapped_role != null) {
    const mappedRole = String(scenario.mapped_role).trim().toLowerCase();
    if (!ROLES.includes(mappedRole)) {
      invalid_fields.push({
        field: `${prefix}.mapped_role`,
        reason: 'invalid_mapped_role',
        allowed: ROLES,
      });
    }
  }

  return { missing_fields, invalid_fields, scenario_id: scenarioId, status };
}

export function redactUrlForEvidence(raw) {
  if (raw === undefined || raw === null || raw === '') return null;
  const value = String(raw);
  try {
    const parsed = new URL(value);
    if (parsed.username || parsed.password) {
      parsed.username = '';
      parsed.password = '';
    }
    if (parsed.search) {
      parsed.search = '?[REDACTED]';
    }
    return parsed.toString();
  } catch {
    return '[REDACTED_INVALID_URL]';
  }
}

export function summarizeClaimMappingFromEnv(env = process.env) {
  let authMode = null;
  let runtimeConfig = null;
  let runtimeError = null;

  try {
    authMode = resolveAuthMode(env);
    runtimeConfig = loadRuntimeConfig(env);
  } catch (err) {
    runtimeError = err instanceof Error ? err.message : String(err);
  }

  const oidc = runtimeConfig?.oidc;
  const roleMapKeys = oidc?.roleMap ? Object.keys(oidc.roleMap) : [];

  return {
    auth_mode: authMode,
    runtime_load_error: runtimeError ? redactString(runtimeError) : null,
    tenant_claim: oidc?.tenantClaim ?? null,
    role_claim: oidc?.roleClaim ?? null,
    user_claim: oidc?.userClaim ?? null,
    role_prefix: oidc?.rolePrefix ?? null,
    role_map_entry_count: roleMapKeys.length,
    role_map_keys: roleMapKeys.map((key) => redactString(key)),
    require_mfa: oidc?.requireMfa ?? null,
    mfa_claim: oidc?.mfaClaim ?? null,
    mapped_roles: [...ROLES],
    issuer_redacted: oidc?.issuer ? redactUrlForEvidence(oidc.issuer) : null,
    audience: oidc?.audience ?? null,
    jwks_url_redacted: oidc?.jwksUrl ? redactUrlForEvidence(oidc.jwksUrl) : null,
  };
}

export function evaluateOidcStagingLoginOffline(env = process.env) {
  const checks = [];
  const claimMapping = summarizeClaimMappingFromEnv(env);

  checks.push({
    id: 'auth_mode_oidc_jwt',
    ok: claimMapping.auth_mode === 'oidc-jwt',
    detail: claimMapping.auth_mode === 'oidc-jwt'
      ? 'ASTRANULL_AUTH_MODE resolves to oidc-jwt.'
      : `Expected oidc-jwt for staging login evidence (got "${claimMapping.auth_mode ?? 'unknown'}").`,
  });

  checks.push({
    id: 'runtime_config_loads',
    ok: !claimMapping.runtime_load_error,
    detail: claimMapping.runtime_load_error
      ?? 'loadRuntimeConfig succeeded for staging login posture.',
  });

  checks.push({
    id: 'tenant_claim_configured',
    ok: Boolean(claimMapping.tenant_claim),
    detail: claimMapping.tenant_claim
      ? `Tenant claim configured (${claimMapping.tenant_claim}).`
      : 'Tenant claim must be configured for staging login mapping.',
  });

  checks.push({
    id: 'role_claim_configured',
    ok: Boolean(claimMapping.role_claim),
    detail: claimMapping.role_claim
      ? `Role claim configured (${claimMapping.role_claim}).`
      : 'Role claim must be configured for staging login mapping.',
  });

  checks.push({
    id: 'user_claim_configured',
    ok: Boolean(claimMapping.user_claim),
    detail: claimMapping.user_claim
      ? `User claim configured (${claimMapping.user_claim}).`
      : 'User claim must be configured for staging login mapping.',
  });

  const requiredFailed = checks.filter((check) => !check.ok);
  return {
    ok: requiredFailed.length === 0,
    checks,
    claim_mapping_summary: redactObject(claimMapping),
  };
}

/**
 * @param {unknown} input
 */
export function validateOidcStagingLoginEvidence(input) {
  const forbidden_fields = [
    ...new Set([
      ...collectForbiddenFields(input),
      ...collectForbiddenStringPatterns(input),
    ]),
  ].sort();

  const missing_fields = OIDC_STAGING_LOGIN_TOP_LEVEL_REQUIRED_FIELDS.filter(
    (field) => !hasValue(input?.[field]),
  );

  missing_fields.push(...missingNestedFields(input?.signoff, SIGNOFF_REQUIRED_FIELDS, 'signoff'));
  missing_fields.push(
    ...missingNestedFields(input?.claim_mapping_summary, CLAIM_MAPPING_REQUIRED_FIELDS, 'claim_mapping_summary'),
  );

  const claimSummary = input?.claim_mapping_summary;
  if (isObject(claimSummary) && !Array.isArray(claimSummary.mapped_roles)) {
    missing_fields.push('claim_mapping_summary.mapped_roles');
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

  const missing_scenarios = OIDC_STAGING_LOGIN_REQUIRED_SCENARIOS.filter(
    (scenarioId) => !scenariosById.has(scenarioId),
  ).map((scenarioId) => `missing_scenario:${scenarioId}`);

  const failed_scenarios = OIDC_STAGING_LOGIN_REQUIRED_SCENARIOS.filter((scenarioId) => {
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
    overall_status: ok ? 'passed' : failed_scenarios.length > 0 ? 'failed' : 'incomplete',
  };
}

function sanitizeScenarioSummary(scenario) {
  if (!isObject(scenario)) return null;
  return {
    scenario_id: scenario.scenario_id ?? null,
    status: scenario.status ?? null,
    mapped_role: scenario.mapped_role ?? null,
    mapped_tenant_reference: scenario.mapped_tenant_reference != null
      ? redactString(String(scenario.mapped_tenant_reference))
      : null,
    api_probe_reference: scenario.api_probe_reference != null
      ? redactString(String(scenario.api_probe_reference))
      : null,
    evidence_uri: scenario.evidence_uri != null ? redactString(String(scenario.evidence_uri)) : null,
    owner: scenario.owner != null ? redactString(String(scenario.owner)) : null,
    completed_at: scenario.completed_at ?? null,
  };
}

export function createOidcStagingLoginEvidenceManifest(input = {}) {
  const evidence = input.evidence ?? {};
  const validation = validateOidcStagingLoginEvidence(evidence);
  const offline = input.offline ?? evaluateOidcStagingLoginOffline(input.env ?? process.env);

  return {
    schema_version: 1,
    artifact_type: 'oidc_staging_login_evidence',
    mode: 'metadata_only',
    created_at: input.createdAt ?? new Date().toISOString(),
    release_id: evidence.release_id ?? input.releaseId ?? null,
    environment: evidence.environment ?? null,
    overall_status: validation.overall_status,
    validation,
    offline_claim_mapping: offline,
    claim_mapping_summary: redactObject(
      evidence.claim_mapping_summary ?? offline.claim_mapping_summary,
    ),
    signoff: evidence.signoff
      ? {
          owner: evidence.signoff.owner ?? null,
          signed_at: evidence.signoff.signed_at ?? null,
          signoff_reference: evidence.signoff.signoff_reference ?? null,
        }
      : null,
    scenarios: (Array.isArray(evidence.scenarios) ? evidence.scenarios : []).map(sanitizeScenarioSummary),
    required_scenarios: [...OIDC_STAGING_LOGIN_REQUIRED_SCENARIOS],
    evidence_uri: evidence.evidence_uri ?? null,
    caveats: [
      'Metadata-only staging OIDC login matrix; does not contact a live IdP or capture browser sessions.',
      'Scenarios must reference API probe custody URIs only — no JWTs, headers, bodies, screenshots, or credentials.',
      'Passing validation does not replace live staging SSO login, MFA/conditional-access review, or security signoff.',
    ],
  };
}

export function parseArgs(argv = []) {
  const opts = {
    input: null,
    out: DEFAULT_OUT,
    releaseId: null,
    validateOnly: false,
    offlineOnly: false,
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
    else if (arg === '--offline-only') opts.offlineOnly = true;
    else if (arg === '--help' || arg === '-h') opts.help = true;
    else throw new Error(`Unknown argument: ${arg}`);
  }
  if (!opts.help && !opts.offlineOnly && !opts.input) {
    throw new Error('--input is required unless --offline-only is set');
  }
  return opts;
}

function readInputJson(inputPath) {
  return JSON.parse(readFileSync(inputPath, 'utf8'));
}

export async function main(argv = process.argv.slice(2)) {
  const opts = parseArgs(argv);
  if (opts.help) {
    console.log('Usage: node scripts/oidc-staging-login-evidence.mjs [--input file] [--out file]');
    console.log('');
    console.log('Validates metadata-only staging OIDC login matrix evidence.');
    console.log('Use --offline-only to emit claim-mapping posture from process.env without input.');
    return 0;
  }

  const evidence = opts.offlineOnly
    ? {
        release_id: opts.releaseId,
        environment: 'staging',
        evidence_uri: 'evidence://oidc/staging-login/offline',
        claim_mapping_summary: evaluateOidcStagingLoginOffline(process.env).claim_mapping_summary,
        signoff: {
          owner: 'security-oncall',
          signed_at: new Date().toISOString(),
          signoff_reference: 'signoff://oidc/staging-login/offline',
        },
        scenarios: OIDC_STAGING_LOGIN_REQUIRED_SCENARIOS.map((scenarioId) => ({
          scenario_id: scenarioId,
          status: 'not_run',
          evidence_uri: `evidence://oidc/staging-login/${scenarioId}`,
          owner: 'security-oncall',
          completed_at: new Date().toISOString(),
          api_probe_reference: `probe://oidc/staging-login/${scenarioId}`,
        })),
      }
    : readInputJson(opts.input);

  const manifest = createOidcStagingLoginEvidenceManifest({
    evidence,
    releaseId: opts.releaseId,
    env: process.env,
  });

  if (!opts.validateOnly) {
    mkdirSync(path.dirname(opts.out), { recursive: true });
    writeFileSync(opts.out, `${JSON.stringify(manifest, null, 2)}\n`);
  }

  const failedChecks = manifest.validation.missing_scenarios.length
    + manifest.validation.failed_scenarios.length
    + manifest.validation.forbidden_fields.length;
  console.log(
    `oidc-staging-login-evidence: ${manifest.validation.ok ? 'ok' : 'failed'} `
    + `(${manifest.validation.scenario_count} scenario(s), ${failedChecks} gap(s))`
    + `${opts.validateOnly ? ' validate-only' : ` wrote ${opts.out}`}`,
  );
  return manifest.validation.ok ? 0 : 1;
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(`oidc-staging-login-evidence: ${err.message}`);
      process.exit(1);
    },
  );
}