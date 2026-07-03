import { redactObject } from './redact.mjs';

const DEFAULT_MAX_REQUESTS = 1;
const DEFAULT_TIMEOUT_CAP_MS = 5000;

export const RAW_PACKET_FIELD_DENYLIST = new Set([
  'packet_payload',
  'raw_packet',
  'raw_packets',
  'packets',
  'packet_data',
  'raw_payload',
  'payload',
  'body',
  'headers',
  'request_body',
  'request_headers',
  'authorization',
  'cookie',
  'raw_log',
  'log_line',
]);
const RAW_PACKET_FIELD_COMPACT_DENYLIST = new Set(
  [...RAW_PACKET_FIELD_DENYLIST].map((key) => key.replace(/_/g, '')),
);

export const ALLOWED_EXTERNAL_RESULTS = new Set(['blocked', 'connected', 'timeout', 'error']);

const ALLOWED_ATTESTATION_META_KEYS = new Set(['worker_version', 'region', 'completed_at']);

export const PROBE_EVENT_RESERVED_METADATA_KEYS = new Set([
  'external_result',
  'probe_worker_id',
  'safety_attestation',
]);

function objectContainsRawPacketFields(value) {
  const normalizeKey = (key) => String(key)
    .trim()
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2')
    .replace(/([a-z])([A-Z])/g, '$1_$2')
    .replace(/[^a-zA-Z0-9]+/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase();
  const scan = (node) => {
    if (node == null) return false;
    if (Array.isArray(node)) {
      for (const item of node) {
        if (scan(item)) return true;
      }
      return false;
    }
    if (typeof node !== 'object') return false;
    for (const key of Object.keys(node)) {
      const normalized = normalizeKey(key);
      const compact = normalized.replace(/_/g, '');
      if (
        RAW_PACKET_FIELD_DENYLIST.has(normalized)
        || RAW_PACKET_FIELD_COMPACT_DENYLIST.has(compact)
        || normalized.startsWith('raw_')
        || compact.startsWith('raw')
      ) {
        return true;
      }
      if (scan(node[key])) return true;
    }
    return false;
  };
  return scan(value);
}

export function bodyContainsRawPacketFields(body) {
  if (!body || typeof body !== 'object') return false;
  return objectContainsRawPacketFields(body);
}

function sanitizeSafetyAttestation(attestation) {
  const out = {
    requests_sent: attestation.requests_sent,
    duration_ms: attestation.duration_ms,
  };
  for (const key of ALLOWED_ATTESTATION_META_KEYS) {
    if (attestation[key] != null) out[key] = attestation[key];
  }
  return out;
}

export function validateSafetyAttestation(body, constraints) {
  const attestation = body?.safety_attestation ?? body?.execution_summary;
  if (attestation == null) {
    return {
      ok: false,
      error: 'missing_safety_attestation',
      status: 400,
      message: 'Probe results must include safety_attestation (or execution_summary).',
    };
  }
  if (typeof attestation !== 'object' || Array.isArray(attestation)) {
    return {
      ok: false,
      error: 'invalid_safety_attestation',
      status: 400,
      message: 'safety_attestation must be an object with requests_sent and duration_ms.',
    };
  }
  if (bodyContainsRawPacketFields(attestation)) {
    return {
      ok: false,
      error: 'invalid_safety_attestation',
      status: 400,
      message: 'safety_attestation must not contain raw packet or payload fields.',
    };
  }
  const { requests_sent: requestsSent, duration_ms: durationMs } = attestation;
  if (!Number.isInteger(requestsSent) || requestsSent < 0) {
    return {
      ok: false,
      error: 'invalid_safety_attestation',
      status: 400,
      message: 'safety_attestation.requests_sent must be a non-negative integer.',
    };
  }
  if (!Number.isInteger(durationMs) || durationMs < 0) {
    return {
      ok: false,
      error: 'invalid_safety_attestation',
      status: 400,
      message: 'safety_attestation.duration_ms must be a non-negative integer.',
    };
  }
  const maxRequests = constraints.max_requests ?? DEFAULT_MAX_REQUESTS;
  const timeoutMs = constraints.timeout_ms ?? DEFAULT_TIMEOUT_CAP_MS;
  if (requestsSent > maxRequests || durationMs > timeoutMs) {
    return {
      ok: false,
      error: 'safety_attestation_exceeded',
      status: 422,
      message: 'safety_attestation exceeds signed job constraints.',
    };
  }
  return { ok: true, sanitized: sanitizeSafetyAttestation(attestation) };
}

export function sanitizeWorkerProbeMetadata(metadata) {
  if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) {
    return {};
  }
  const stripped = {};
  for (const [key, val] of Object.entries(metadata)) {
    if (!PROBE_EVENT_RESERVED_METADATA_KEYS.has(key)) {
      stripped[key] = val;
    }
  }
  return redactObject(stripped);
}

export function validateProbeResultBody(body, constraints) {
  if (bodyContainsRawPacketFields(body)) {
    return {
      error: 'raw_packet_rejected',
      status: 400,
      message: 'Raw packet or payload fields are not accepted.',
    };
  }

  const externalResult = body?.external_result;
  if (!externalResult || !ALLOWED_EXTERNAL_RESULTS.has(externalResult)) {
    return {
      error: 'invalid_external_result',
      status: 400,
      message: 'external_result must be one of: blocked, connected, timeout, error.',
    };
  }

  const attestationResult = validateSafetyAttestation(body, constraints ?? {});
  if (!attestationResult.ok) {
    return {
      error: attestationResult.error,
      status: attestationResult.status,
      message: attestationResult.message,
    };
  }

  return {
    ok: true,
    externalResult,
    safetyAttestation: attestationResult.sanitized,
    workerMetadata: sanitizeWorkerProbeMetadata(body.metadata),
  };
}
