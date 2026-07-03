import { TELEMETRY_ACTIVE_STATES } from './highScalePolicy.mjs';
import { validateGovernedAdapterIngestEnvelope } from './governedAdapterTelemetry.mjs';

/**
 * @typedef {{
 *   high_scale_request_id: string,
 *   body: Record<string, unknown>,
 * }} GovernedAdapterTelemetryIngestEntry
 */

/**
 * @param {unknown} raw
 * @returns {GovernedAdapterTelemetryIngestEntry[]}
 */
export function parseGovernedAdapterTelemetryIngestManifest(raw) {
  let payload = raw;
  if (typeof raw === 'string') {
    payload = JSON.parse(raw);
  }
  if (payload == null || typeof payload !== 'object') {
    throw new Error('governed-adapter-telemetry-ingest: manifest must be a JSON object.');
  }

  /** @type {GovernedAdapterTelemetryIngestEntry[]} */
  const entries = [];
  if (Array.isArray(payload)) {
    for (const item of payload) {
      entries.push(normalizeManifestEntry(item));
    }
    return entries;
  }

  if (Array.isArray(payload.ingests)) {
    for (const item of payload.ingests) {
      entries.push(normalizeManifestEntry(item));
    }
    return entries;
  }

  if (payload.high_scale_request_id && payload.body) {
    entries.push(normalizeManifestEntry(payload));
    return entries;
  }

  throw new Error(
    'governed-adapter-telemetry-ingest: manifest must be an array, { ingests: [] }, or a single ingest object.',
  );
}

/**
 * @param {unknown} item
 * @returns {GovernedAdapterTelemetryIngestEntry}
 */
function normalizeManifestEntry(item) {
  if (item == null || typeof item !== 'object' || Array.isArray(item)) {
    throw new Error('governed-adapter-telemetry-ingest: each manifest entry must be an object.');
  }
  const requestId = String(
    item.high_scale_request_id ?? item.request_id ?? item.highScaleRequestId ?? '',
  ).trim();
  if (!requestId) {
    throw new Error('governed-adapter-telemetry-ingest: each entry requires high_scale_request_id.');
  }
  const body = item.body ?? item.ingest ?? item.telemetry ?? null;
  if (body == null || typeof body !== 'object' || Array.isArray(body)) {
    throw new Error('governed-adapter-telemetry-ingest: each entry requires a metadata-only body object.');
  }
  return {
    high_scale_request_id: requestId,
    body: /** @type {Record<string, unknown>} */ (body),
  };
}

/**
 * @param {{ state?: string } | null | undefined} request
 */
export function shouldIngestTelemetryForRequest(request) {
  return Boolean(request?.state && TELEMETRY_ACTIVE_STATES.has(request.state));
}

/**
 * @param {Array<{ id: string, tenant_id?: string, state?: string }>} requests
 */
export function listTelemetryActiveHighScaleRequests(requests) {
  return requests.filter((request) => shouldIngestTelemetryForRequest(request));
}

/**
 * @param {Record<string, unknown>} body
 */
export function validateManifestIngestBody(body) {
  return validateGovernedAdapterIngestEnvelope(body);
}

/**
 * @param {Array<{
 *   high_scale_request_id: string,
 *   status: 'ingested' | 'skipped' | 'failed',
 *   reason?: string,
 *   snapshot_count?: number,
 *   ingestion_id?: string,
 * }>} results
 */
export function buildGovernedAdapterTelemetryIngestSummary(results) {
  const ingested = results.filter((r) => r.status === 'ingested');
  const skipped = results.filter((r) => r.status === 'skipped');
  const failed = results.filter((r) => r.status === 'failed');
  return {
    processed_count: results.length,
    ingested_count: ingested.length,
    skipped_count: skipped.length,
    failed_count: failed.length,
    ingested_request_ids: ingested.map((r) => r.high_scale_request_id),
    skipped_request_ids: skipped.map((r) => r.high_scale_request_id),
    failed_request_ids: failed.map((r) => r.high_scale_request_id),
    results,
  };
}