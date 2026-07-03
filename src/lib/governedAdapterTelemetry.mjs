import { GOVERNED_ADAPTER_TYPES } from '../contracts/governedExecutionAdapter.mjs';
import {
  TELEMETRY_CATEGORIES,
  TELEMETRY_LIVE_STATUSES,
  parseObservedAt,
  telemetryObjectContainsForbiddenKeys,
} from './highScalePolicy.mjs';
import { redactObject, redactString } from './redact.mjs';

export const GOVERNED_ADAPTER_TELEMETRY_MAX_SNAPSHOTS = 50;

export const GOVERNED_ADAPTER_INGEST_REQUIRED_FIELDS = Object.freeze(['adapter_id', 'snapshots']);

const FORBIDDEN_INGEST_KEYS = new Set([
  'amplification',
  'api_key',
  'apikey',
  'attack_command',
  'attack_profile',
  'attack_script',
  'authorization',
  'body',
  'cookie',
  'request_body',
  'request_headers',
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
const FORBIDDEN_INGEST_COMPACT_KEYS = new Set(
  [...FORBIDDEN_INGEST_KEYS].map((key) => key.replace(/_/g, '')),
);

function normalizeKey(key) {
  return String(key)
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2')
    .replace(/([a-z])([A-Z])/g, '$1_$2')
    .replace(/[^A-Za-z0-9]+/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase();
}

function hasValue(value) {
  if (value === null || value === undefined) return false;
  if (typeof value === 'string' && value.trim() === '') return false;
  if (Array.isArray(value) && value.length === 0) return false;
  return true;
}

/**
 * @param {unknown} value
 * @param {string} [path]
 * @returns {boolean}
 */
export function governedAdapterIngestContainsForbiddenKeys(value, path = '') {
  if (value === null || value === undefined || typeof value !== 'object') return false;
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      if (governedAdapterIngestContainsForbiddenKeys(value[index], `${path}[${index}]`)) {
        return true;
      }
    }
    return false;
  }
  for (const [key, nested] of Object.entries(value)) {
    const keyPath = path ? `${path}.${key}` : key;
    const normalized = normalizeKey(key);
    const compact = normalized.replace(/_/g, '');
    if (
      FORBIDDEN_INGEST_KEYS.has(normalized)
      || FORBIDDEN_INGEST_COMPACT_KEYS.has(compact)
      || normalized.startsWith('raw_')
      || compact.startsWith('raw')
      || normalized.endsWith('_command')
      || compact.endsWith('command')
    ) {
      return true;
    }
    if (governedAdapterIngestContainsForbiddenKeys(nested, keyPath)) return true;
  }
  return false;
}

/**
 * @param {{ adapter_id?: string, adapter_type?: string, provider_key?: string, provider_run_id?: string }} context
 * @returns {string}
 */
export function buildGovernedAdapterTelemetrySource(context) {
  const adapterId = redactString(String(context.adapter_id ?? '').trim());
  const parts = ['governed-adapter', adapterId];
  if (hasValue(context.provider_key)) {
    parts.push(redactString(String(context.provider_key).trim()));
  }
  return parts.filter(Boolean).join(':');
}

/**
 * Provider-neutral envelope validation for governed adapter telemetry ingestion.
 *
 * @param {Record<string, unknown> | null | undefined} body
 * @returns {{ ok: true, adapter_id: string, adapter_type: string | null, provider_key: string | null, provider_run_id: string | null, snapshots: unknown[] } | { ok: false, error: string, status: number, [key: string]: unknown }}
 */
export function validateGovernedAdapterIngestEnvelope(body) {
  if (body == null || typeof body !== 'object' || Array.isArray(body)) {
    return { ok: false, error: 'invalid_ingest_body', status: 400 };
  }

  const missing_fields = GOVERNED_ADAPTER_INGEST_REQUIRED_FIELDS.filter((field) => !hasValue(body[field]));
  if (missing_fields.length > 0) {
    return { ok: false, error: 'missing_ingest_fields', status: 400, missing_fields };
  }

  if (!Array.isArray(body.snapshots)) {
    return { ok: false, error: 'invalid_snapshots', status: 400 };
  }

  if (body.snapshots.length === 0) {
    return { ok: false, error: 'empty_snapshots', status: 400 };
  }

  if (body.snapshots.length > GOVERNED_ADAPTER_TELEMETRY_MAX_SNAPSHOTS) {
    return {
      ok: false,
      error: 'too_many_snapshots',
      status: 400,
      max_snapshots: GOVERNED_ADAPTER_TELEMETRY_MAX_SNAPSHOTS,
    };
  }

  const { snapshots: _snapshots, ...envelopeWithoutSnapshots } = body;
  if (governedAdapterIngestContainsForbiddenKeys(envelopeWithoutSnapshots)) {
    return { ok: false, error: 'forbidden_ingest_fields', status: 400 };
  }

  const adapter_id = String(body.adapter_id).trim();
  if (!adapter_id) {
    return { ok: false, error: 'invalid_adapter_id', status: 400 };
  }

  let adapter_type = null;
  if (hasValue(body.adapter_type)) {
    adapter_type = String(body.adapter_type).trim();
    if (!GOVERNED_ADAPTER_TYPES.includes(adapter_type)) {
      return {
        ok: false,
        error: 'invalid_adapter_type',
        status: 400,
        allowed: GOVERNED_ADAPTER_TYPES,
      };
    }
  }

  const provider_key =
    body.provider_key != null && body.provider_key !== ''
      ? redactString(String(body.provider_key).trim())
      : null;
  const provider_run_id =
    body.provider_run_id != null && body.provider_run_id !== ''
      ? redactString(String(body.provider_run_id).trim())
      : null;

  return {
    ok: true,
    adapter_id,
    adapter_type,
    provider_key,
    provider_run_id,
    snapshots: body.snapshots,
  };
}

/**
 * @param {Record<string, unknown>} snapshot
 * @param {{ adapter_id: string, adapter_type: string | null, provider_key: string | null, provider_run_id: string | null, ingestion_id: string }} context
 * @returns {{ ok: true, category: string, live_status: string | null, observed_at: string, source: string, metrics: Record<string, unknown> | null } | { ok: false, error: string, status: number, [key: string]: unknown }}
 */
export function normalizeGovernedAdapterTelemetrySnapshot(snapshot, context) {
  if (snapshot == null || typeof snapshot !== 'object' || Array.isArray(snapshot)) {
    return { ok: false, error: 'invalid_snapshot', status: 400 };
  }

  if (snapshot.metrics != null && telemetryObjectContainsForbiddenKeys(snapshot.metrics)) {
    return { ok: false, error: 'forbidden_telemetry_fields', status: 400 };
  }

  const { metrics: _metrics, ...snapshotWithoutMetrics } = snapshot;
  if (governedAdapterIngestContainsForbiddenKeys(snapshotWithoutMetrics)) {
    return { ok: false, error: 'forbidden_ingest_fields', status: 400 };
  }

  const category = snapshot.category != null ? String(snapshot.category).trim() : '';
  if (!TELEMETRY_CATEGORIES.has(category)) {
    return { ok: false, error: 'invalid_category', status: 400 };
  }

  let live_status = null;
  if (snapshot.live_status != null && snapshot.live_status !== '') {
    live_status = String(snapshot.live_status).trim();
    if (!TELEMETRY_LIVE_STATUSES.has(live_status)) {
      return { ok: false, error: 'invalid_live_status', status: 400 };
    }
  }

  const observed = parseObservedAt(snapshot.observed_at);
  if (!observed.ok) return observed;

  const snapshotMetrics =
    snapshot.metrics != null && typeof snapshot.metrics === 'object' && !Array.isArray(snapshot.metrics)
      ? redactObject(snapshot.metrics)
      : null;

  const provenance = {
    adapter_id: context.adapter_id,
    ingestion_id: context.ingestion_id,
  };
  if (context.adapter_type) provenance.adapter_type = context.adapter_type;
  if (context.provider_key) provenance.provider_key = context.provider_key;
  if (context.provider_run_id) provenance.provider_run_id = context.provider_run_id;

  const metrics =
    snapshotMetrics != null
      ? { ...snapshotMetrics, adapter_provenance: provenance }
      : { adapter_provenance: provenance };

  return {
    ok: true,
    category,
    live_status,
    observed_at: observed.value,
    source: buildGovernedAdapterTelemetrySource(context),
    metrics,
  };
}

/**
 * Normalize a governed adapter ingest envelope into metadata-only telemetry record inputs.
 *
 * @param {Record<string, unknown> | null | undefined} body
 * @param {{ ingestion_id: string }} options
 * @returns {{ ok: true, adapter_id: string, adapter_type: string | null, provider_key: string | null, provider_run_id: string | null, ingestion_id: string, records: Array<{ category: string, live_status: string | null, observed_at: string, source: string, metrics: Record<string, unknown> | null }> } | { ok: false, error: string, status: number, [key: string]: unknown }}
 */
export function normalizeGovernedAdapterTelemetryIngest(body, options) {
  const envelope = validateGovernedAdapterIngestEnvelope(body);
  if (!envelope.ok) return envelope;

  const context = {
    adapter_id: envelope.adapter_id,
    adapter_type: envelope.adapter_type,
    provider_key: envelope.provider_key,
    provider_run_id: envelope.provider_run_id,
    ingestion_id: options.ingestion_id,
  };

  const records = [];
  for (let index = 0; index < envelope.snapshots.length; index += 1) {
    const normalized = normalizeGovernedAdapterTelemetrySnapshot(
      /** @type {Record<string, unknown>} */ (envelope.snapshots[index]),
      context,
    );
    if (!normalized.ok) {
      return { ...normalized, snapshot_index: index };
    }
    records.push({
      category: normalized.category,
      live_status: normalized.live_status,
      observed_at: normalized.observed_at,
      source: normalized.source,
      metrics: normalized.metrics,
    });
  }

  return {
    ok: true,
    adapter_id: envelope.adapter_id,
    adapter_type: envelope.adapter_type,
    provider_key: envelope.provider_key,
    provider_run_id: envelope.provider_run_id,
    ingestion_id: options.ingestion_id,
    records,
  };
}
