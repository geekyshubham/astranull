#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateKillSwitchExerciseEvidence } from '../src/contracts/killSwitchValidation.mjs';
import { redactObject, redactString } from '../src/lib/redact.mjs';

const DEFAULT_OUT = 'output/kill-switch-drill-evidence.json';
const DEFAULT_MAX_LATENCY_MS = 120_000;

const DRILL_REQUIRED_FIELDS = Object.freeze([
  'drill_id',
  'tenant_id',
  'activation_at',
  'stop_signal_at',
  'affected_request_ids',
  'cancelled_safe_run_ids',
  'soc_actors',
  'audit_event_ids',
  'closeout',
]);

const CLOSEOUT_REQUIRED_FIELDS = Object.freeze([
  'signoff_by',
  'signoff_role',
  'signed_at',
  'signoff_reference',
]);

const SOC_ACTOR_REQUIRED_FIELDS = Object.freeze(['actor_id', 'role']);

const FORBIDDEN_KEYS = new Set([
  'api_key',
  'apikey',
  'authorization',
  'aws_secret',
  'azure_credential',
  'body',
  'credential',
  'credentials',
  'gcp_credential',
  'headers',
  'packet',
  'packet_capture',
  'packet_payload',
  'password',
  'payload',
  'pcap',
  'provider_credential',
  'provider_credentials',
  'raw_body',
  'raw_headers',
  'raw_log',
  'raw_packet',
  'raw_traffic',
  'secret',
  'token',
  'traffic',
  'traffic_capture',
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
      FORBIDDEN_KEYS.has(normalized)
      || normalized.startsWith('raw_')
      || normalized.endsWith('_credential')
      || normalized.endsWith('_secret')
    ) {
      findings.push(keyPath);
    }
    findings.push(...collectForbiddenFields(nested, keyPath));
  }
  return findings;
}

function parseIsoMs(value, fieldName) {
  const ms = Date.parse(value);
  if (!Number.isFinite(ms)) {
    throw new Error(`Invalid ISO timestamp for ${fieldName}: ${value}`);
  }
  return ms;
}

function fieldSummary(fields) {
  return fields.length > 0 ? fields.join(', ') : 'none';
}

export function parseArgs(argv = []) {
  const opts = {
    input: null,
    out: DEFAULT_OUT,
    maxLatencyMs: DEFAULT_MAX_LATENCY_MS,
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
    else if (arg === '--max-latency-ms') {
      const parsed = Number(next());
      if (!Number.isFinite(parsed) || parsed <= 0) {
        throw new Error('--max-latency-ms must be a positive number');
      }
      opts.maxLatencyMs = parsed;
    } else if (arg === '--validate-only') opts.validateOnly = true;
    else if (arg === '--help' || arg === '-h') opts.help = true;
    else throw new Error(`Unknown argument: ${arg}`);
  }
  if (!opts.help && !opts.input) throw new Error('--input is required');
  return opts;
}

function parseInputJson(inputPath) {
  const parsed = JSON.parse(readFileSync(inputPath, 'utf8'));
  if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
    if (parsed.transcript && typeof parsed.transcript === 'object') return parsed.transcript;
    return parsed;
  }
  throw new Error('Input must be a drill transcript object or { transcript: { ... } }.');
}

export function computeResponseLatencyMs(transcript) {
  const activationMs = parseIsoMs(transcript.activation_at, 'activation_at');
  const stopMs = parseIsoMs(transcript.stop_signal_at, 'stop_signal_at');
  const latency = stopMs - activationMs;
  if (latency < 0) {
    throw new Error('stop_signal_at must be on or after activation_at');
  }
  return latency;
}

export function validateDrillTranscript(transcript, options = {}) {
  const maxLatencyMs = options.maxLatencyMs ?? DEFAULT_MAX_LATENCY_MS;
  const missing_fields = DRILL_REQUIRED_FIELDS.filter((field) => !hasValue(transcript?.[field]));
  const forbidden_fields = [...new Set(collectForbiddenFields(transcript))].sort();

  const closeout = transcript?.closeout;
  const missing_closeout_fields = CLOSEOUT_REQUIRED_FIELDS.filter(
    (field) => !hasValue(closeout?.[field]),
  );
  if (missing_closeout_fields.length > 0) {
    missing_fields.push(...missing_closeout_fields.map((field) => `closeout.${field}`));
  }

  const socActors = Array.isArray(transcript?.soc_actors) ? transcript.soc_actors : [];
  const invalid_soc_actors = [];
  socActors.forEach((actor, index) => {
    const missing = SOC_ACTOR_REQUIRED_FIELDS.filter((field) => !hasValue(actor?.[field]));
    if (missing.length > 0) {
      invalid_soc_actors.push({ index, fields: missing });
    }
  });

  const auditIds = transcript?.audit_event_ids;
  if (!hasValue(auditIds)) {
    if (!missing_fields.includes('audit_event_ids')) missing_fields.push('audit_event_ids');
  }

  let exercise_validation = null;
  if (transcript?.exercise != null) {
    exercise_validation = validateKillSwitchExerciseEvidence(transcript.exercise);
  }

  let response_latency_ms = null;
  let latency_exceeded = false;
  const structuralOk =
    missing_fields.length === 0
    && forbidden_fields.length === 0
    && invalid_soc_actors.length === 0
    && (!exercise_validation || exercise_validation.ok);

  if (structuralOk) {
    response_latency_ms = computeResponseLatencyMs(transcript);
    latency_exceeded = response_latency_ms > maxLatencyMs;
  }

  const ok = structuralOk && !latency_exceeded;

  return {
    ok,
    missing_fields,
    forbidden_fields,
    invalid_soc_actors,
    exercise_validation,
    response_latency_ms,
    max_latency_ms: maxLatencyMs,
    latency_exceeded,
  };
}

export function validateAndPrepareDrillTranscript(transcript, options = {}) {
  const validation = validateDrillTranscript(transcript, options);
  if (validation.forbidden_fields.length > 0) {
    throw new Error(
      `Drill transcript contains forbidden field(s): ${fieldSummary(validation.forbidden_fields)}`,
    );
  }
  if (validation.missing_fields.length > 0) {
    throw new Error(
      `Drill transcript missing required field(s): ${fieldSummary(validation.missing_fields)}`,
    );
  }
  if (validation.invalid_soc_actors.length > 0) {
    const detail = validation.invalid_soc_actors
      .map((entry) => `soc_actors[${entry.index}]: ${entry.fields.join(', ')}`)
      .join('; ');
    throw new Error(`Drill transcript has invalid SOC actor entries: ${detail}`);
  }
  if (validation.exercise_validation && !validation.exercise_validation.ok) {
    const ex = validation.exercise_validation;
    const parts = [];
    if (ex.missing_steps?.length) parts.push(`missing_steps=${ex.missing_steps.join(',')}`);
    if (ex.missing_fields?.length) parts.push('missing_exercise_fields');
    if (ex.forbidden_fields?.length) parts.push(`forbidden=${ex.forbidden_fields.join(',')}`);
    throw new Error(`Kill switch exercise evidence invalid: ${parts.join('; ') || 'validation failed'}`);
  }
  if (validation.latency_exceeded) {
    throw new Error(
      `Kill switch response latency ${validation.response_latency_ms}ms exceeds max ${validation.max_latency_ms}ms`,
    );
  }
  return {
    transcript: redactObject(transcript),
    validation,
    ...(transcript.notes ? { notes: redactString(String(transcript.notes)) } : {}),
  };
}

export function createKillSwitchDrillEvidenceManifest(input = {}) {
  const transcript = input.transcript;
  if (!transcript || typeof transcript !== 'object') {
    throw new Error('Drill transcript object is required.');
  }
  const prepared = validateAndPrepareDrillTranscript(transcript, {
    maxLatencyMs: input.maxLatencyMs,
  });
  return {
    schema_version: 1,
    artifact_type: 'kill_switch_drill_evidence',
    created_at: input.createdAt ?? new Date().toISOString(),
    drill_id: prepared.transcript.drill_id ?? null,
    tenant_id: prepared.transcript.tenant_id ?? null,
    response_latency_ms: prepared.validation.response_latency_ms,
    max_latency_ms: prepared.validation.max_latency_ms,
    latency_ok: true,
    validation: {
      ok: true,
      audit_event_count: Array.isArray(prepared.transcript.audit_event_ids)
        ? prepared.transcript.audit_event_ids.length
        : 0,
      affected_request_count: Array.isArray(prepared.transcript.affected_request_ids)
        ? prepared.transcript.affected_request_ids.length
        : 0,
      cancelled_safe_run_count: Array.isArray(prepared.transcript.cancelled_safe_run_ids)
        ? prepared.transcript.cancelled_safe_run_ids.length
        : 0,
      soc_actor_count: Array.isArray(prepared.transcript.soc_actors)
        ? prepared.transcript.soc_actors.length
        : 0,
      exercise_validated: Boolean(prepared.validation.exercise_validation?.ok),
    },
    transcript: prepared.transcript,
    ...(prepared.notes ? { notes: prepared.notes } : {}),
    caveats: [
      'Manifest records metadata-only kill-switch drill evidence for SOC production readiness review.',
      'Staging execution still requires live probe-fleet stop proof, governed adapter stop-path proof, and SOC/security signoff.',
    ],
  };
}

export async function main(argv = process.argv.slice(2)) {
  const opts = parseArgs(argv);
  if (opts.help) {
    console.log(
      'Usage: node scripts/kill-switch-drill-evidence.mjs --input drill.json [--out file] [--max-latency-ms ms] [--validate-only]',
    );
    return 0;
  }

  const transcript = parseInputJson(opts.input);
  const manifest = createKillSwitchDrillEvidenceManifest({
    transcript,
    maxLatencyMs: opts.maxLatencyMs,
  });

  if (opts.validateOnly) {
    console.log(
      `kill-switch-drill-evidence: ok (drill_id=${manifest.drill_id ?? 'none'}, latency_ms=${manifest.response_latency_ms})`,
    );
    return 0;
  }

  mkdirSync(path.dirname(opts.out), { recursive: true });
  writeFileSync(opts.out, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`kill-switch-drill-evidence: wrote ${opts.out}`);
  return 0;
}

const isCli = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isCli) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(`kill-switch-drill-evidence: ${err.message}`);
      process.exit(1);
    },
  );
}