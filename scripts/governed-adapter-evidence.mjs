#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { GOVERNED_ADAPTER_TYPES } from '../src/contracts/governedExecutionAdapter.mjs';
import { redactObject } from '../src/lib/redact.mjs';

const DEFAULT_OUT = 'output/governed-adapter-evidence.json';

export const GOVERNED_ADAPTER_EVIDENCE_REQUIRED_FIELDS = Object.freeze([
  'adapter_id',
  'adapter_type',
  'authorization_pack_id',
  'scheduled_window',
  'soc_approvers',
  'provider_approval_reference',
  'kill_switch_hook',
  'telemetry_metadata',
  'dry_run_status',
  'stop_close_evidence',
]);

const SCHEDULED_WINDOW_REQUIRED_FIELDS = Object.freeze(['start_at', 'end_at']);

const DRY_RUN_STATUS_REQUIRED_FIELDS = Object.freeze(['mode', 'traffic_generated', 'validated_at']);

const STOP_CLOSE_REQUIRED_FIELDS = Object.freeze(['stop_reference', 'close_reference']);

const UNAPPROVED_EXECUTION_STATES = new Set([
  'live_traffic',
  'traffic_active',
  'production_execution',
  'attack_running',
  'traffic_generation_enabled',
]);

const FORBIDDEN_EVIDENCE_KEYS = new Set([
  'amplification',
  'api_key',
  'apikey',
  'attack_command',
  'attack_profile',
  'attack_script',
  'authorization',
  'body',
  'cmdline',
  'command_line',
  'credential',
  'credentials',
  'generator',
  'headers',
  'ip_inventory',
  'ip_list',
  'packet',
  'packet_payload',
  'password',
  'payload',
  'raw_command',
  'raw_headers',
  'raw_log',
  'raw_packet',
  'secret',
  'shell_command',
  'target_inventory',
  'target_ips',
  `traffic_${'generator'}`,
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
    if (
      FORBIDDEN_EVIDENCE_KEYS.has(normalized)
      || normalized.startsWith('raw_')
      || normalized.endsWith('_command')
    ) {
      findings.push(keyPath);
    }
    findings.push(...collectForbiddenFields(nested, keyPath));
  }
  return findings;
}

function missingNestedFields(object, requiredFields, prefix) {
  if (!hasValue(object) || typeof object !== 'object' || Array.isArray(object)) {
    return requiredFields.map((field) => `${prefix}.${field}`);
  }
  return requiredFields
    .filter((field) => !hasValue(object[field]))
    .map((field) => `${prefix}.${field}`);
}

export function parseArgs(argv = []) {
  const opts = {
    input: null,
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
    if (arg === '--input') opts.input = next();
    else if (arg === '--out') opts.out = next();
    else if (arg === '--validate-only') opts.validateOnly = true;
    else if (arg === '--help' || arg === '-h') opts.help = true;
    else throw new Error(`Unknown argument: ${arg}`);
  }
  if (!opts.help && !opts.input) throw new Error('--input is required');
  return opts;
}

export function validateGovernedAdapterReadinessEvidence(evidence) {
  const missing_fields = GOVERNED_ADAPTER_EVIDENCE_REQUIRED_FIELDS.filter(
    (field) => !hasValue(evidence?.[field]),
  );
  missing_fields.push(
    ...missingNestedFields(evidence?.scheduled_window, SCHEDULED_WINDOW_REQUIRED_FIELDS, 'scheduled_window'),
    ...missingNestedFields(evidence?.dry_run_status, DRY_RUN_STATUS_REQUIRED_FIELDS, 'dry_run_status'),
    ...missingNestedFields(evidence?.stop_close_evidence, STOP_CLOSE_REQUIRED_FIELDS, 'stop_close_evidence'),
  );

  const invalid_fields = [];
  const forbidden_fields = collectForbiddenFields(evidence);

  if (
    hasValue(evidence?.adapter_type)
    && !GOVERNED_ADAPTER_TYPES.includes(evidence.adapter_type)
  ) {
    invalid_fields.push({
      field: 'adapter_type',
      reason: 'unsupported_adapter_type',
      allowed: GOVERNED_ADAPTER_TYPES,
    });
  }

  const dryRun = evidence?.dry_run_status;
  if (hasValue(dryRun) && typeof dryRun === 'object' && !Array.isArray(dryRun)) {
    if (dryRun.mode !== 'dry_run') {
      invalid_fields.push({
        field: 'dry_run_status.mode',
        reason: 'must_be_dry_run',
        allowed: ['dry_run'],
      });
    }
    if (dryRun.traffic_generated === true) {
      invalid_fields.push({
        field: 'dry_run_status.traffic_generated',
        reason: 'traffic_must_not_be_generated',
      });
    }
  }

  const executionState = evidence?.high_scale_execution_state;
  if (hasValue(executionState) && UNAPPROVED_EXECUTION_STATES.has(String(executionState))) {
    invalid_fields.push({
      field: 'high_scale_execution_state',
      reason: 'unapproved_execution_state',
      value: executionState,
    });
  }

  if (evidence?.traffic_generation_enabled === true || evidence?.live_traffic_started === true) {
    invalid_fields.push({
      field: evidence?.traffic_generation_enabled === true
        ? 'traffic_generation_enabled'
        : 'live_traffic_started',
      reason: 'unapproved_high_scale_execution',
    });
  }

  const uniqueMissing = [...new Set(missing_fields)];

  return {
    ok:
      uniqueMissing.length === 0
      && invalid_fields.length === 0
      && forbidden_fields.length === 0,
    missing_fields: uniqueMissing,
    invalid_fields,
    forbidden_fields,
  };
}

export function createGovernedAdapterEvidenceManifest(input = {}) {
  const evidence = input.evidence ?? null;
  const validation = validateGovernedAdapterReadinessEvidence(evidence);
  if (!validation.ok) {
    const err = new Error('governed adapter evidence validation failed');
    err.validation = validation;
    throw err;
  }

  const redactedEvidence = redactObject(evidence);
  return {
    schema_version: 1,
    artifact_type: 'governed_adapter_readiness',
    created_at: input.createdAt ?? new Date().toISOString(),
    adapter_id: evidence.adapter_id,
    adapter_type: evidence.adapter_type,
    authorization_pack_id: evidence.authorization_pack_id,
    dry_run_mode: true,
    validation: {
      ok: true,
      missing_fields: [],
      invalid_fields: [],
      forbidden_fields: [],
    },
    evidence: redactedEvidence,
    caveats: [
      'Manifest records metadata-only governed adapter readiness evidence.',
      'Governed integration adapters coordinate approved provider paths; they are not attack scripts or traffic generators.',
      'Production promotion still requires connected partner/provider adapter signoff, staging start/stop/kill-switch proof, and SOC/security review.',
    ],
  };
}

function parseInputJson(inputPath) {
  return JSON.parse(readFileSync(inputPath, 'utf8'));
}

function formatValidationError(validation) {
  const parts = [];
  if (validation.missing_fields.length > 0) {
    parts.push(`missing field(s): ${validation.missing_fields.join(', ')}`);
  }
  if (validation.invalid_fields.length > 0) {
    parts.push(`invalid field(s): ${validation.invalid_fields.map((f) => f.field).join(', ')}`);
  }
  if (validation.forbidden_fields.length > 0) {
    parts.push(`forbidden field(s): ${validation.forbidden_fields.join(', ')}`);
  }
  return parts.join('; ');
}

export async function main(argv = process.argv.slice(2)) {
  const opts = parseArgs(argv);
  if (opts.help) {
    console.log(
      'Usage: node scripts/governed-adapter-evidence.mjs --input evidence.json [--out file] [--validate-only]',
    );
    return 0;
  }

  const evidence = parseInputJson(opts.input);
  const validation = validateGovernedAdapterReadinessEvidence(evidence);
  if (!validation.ok) {
    throw new Error(formatValidationError(validation));
  }

  if (opts.validateOnly) {
    console.log(
      `governed-adapter-evidence: ok (adapter_id=${evidence.adapter_id}, dry_run_mode=true)`,
    );
    return 0;
  }

  const manifest = createGovernedAdapterEvidenceManifest({ evidence });
  mkdirSync(path.dirname(opts.out), { recursive: true });
  writeFileSync(opts.out, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`governed-adapter-evidence: wrote ${opts.out}`);
  return 0;
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(`governed-adapter-evidence: ${err.message}`);
      process.exit(1);
    },
  );
}