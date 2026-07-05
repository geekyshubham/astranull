import { audit } from '../audit.mjs';
import { redactObject } from '../lib/redact.mjs';
import { newId } from '../lib/ids.mjs';
import { incMetric } from '../lib/metrics.mjs';
import { getStore, persistStore } from '../store.mjs';
import { recordEvidence } from './evidence.mjs';
import { recordOwnershipSignalByNonce } from './ownershipVerification.mjs';

const EVENT_RAW_FIELD_DENYLIST = new Set([
  'packet_payload',
  'raw_packet',
  'raw_packets',
  'packet_data',
  'raw_payload',
  'exploit_payload',
  'body',
  'headers',
  'request_body',
  'request_headers',
  'authorization',
  'cookie',
  'raw_log',
  'log_line',
]);
const EVENT_RAW_FIELD_COMPACT_DENYLIST = new Set(
  [...EVENT_RAW_FIELD_DENYLIST].map((key) => key.replace(/_/g, '')),
);

function normalizeEventRawFieldKey(key) {
  return String(key)
    .trim()
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2')
    .replace(/([a-z])([A-Z])/g, '$1_$2')
    .replace(/[^a-zA-Z0-9]+/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase();
}

function eventIngestContainsRawFields(value) {
  if (value == null || typeof value !== 'object') return false;
  if (Array.isArray(value)) return value.some((item) => eventIngestContainsRawFields(item));
  for (const [key, child] of Object.entries(value)) {
    const normalized = normalizeEventRawFieldKey(key);
    const compact = normalized.replace(/_/g, '');
    if (
      EVENT_RAW_FIELD_DENYLIST.has(normalized)
      || EVENT_RAW_FIELD_COMPACT_DENYLIST.has(compact)
      || normalized.startsWith('raw_')
      || compact.startsWith('raw')
    ) {
      return true;
    }
    if (eventIngestContainsRawFields(child)) return true;
  }
  return false;
}

function ensureVault() {
  const store = getStore();
  if (!store.evidenceVault) store.evidenceVault = [];
  if (!store.ingestedEventIds) store.ingestedEventIds = {};
  return store;
}

export function ingestEvent(ctx, body) {
  const store = ensureVault();
  const tenantId = ctx.tenantId;
  if (body.tenant_id && body.tenant_id !== tenantId) {
    audit({
      tenant_id: tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'event.ingest_rejected_cross_tenant',
      resource_type: 'event',
      resource_id: body.event_id ?? null,
      metadata: { attempted_tenant: body.tenant_id },
    });
    persistStore();
    return { error: 'cross_tenant_mismatch', status: 403 };
  }

  const eventId = body.event_id;
  if (!eventId) return { error: 'missing_event_id', status: 400 };

  const key = `${tenantId}:${eventId}`;
  if (store.ingestedEventIds[key]) {
    return { duplicate: true, event: store.ingestedEventIds[key] };
  }

  if (eventIngestContainsRawFields(body)) {
    return { error: 'packet_payload_forbidden', status: 400 };
  }

  const metadata = redactObject(body.metadata ?? {});
  const record = {
    id: newId('event'),
    event_id: eventId,
    tenant_id: tenantId,
    test_run_id: body.test_run_id ?? null,
    source: body.source ?? 'internal',
    signal_type: body.signal_type ?? 'generic',
    timestamp: body.timestamp ?? new Date().toISOString(),
    nonce_hash: body.nonce_hash ?? null,
    metadata,
  };
  store.events.push(record);
  store.ingestedEventIds[key] = record;

  if (record.signal_type === 'ownership_observation' && record.nonce_hash) {
    recordOwnershipSignalByNonce(
      { tenantId },
      { source: 'agent', nonce_hash: record.nonce_hash },
    );
  }

  if (body.evidence) {
    recordEvidence(ctx, {
      evidence_id: body.evidence.evidence_id ?? newId('evidence'),
      test_run_id: body.test_run_id,
      label: body.evidence.label ?? 'ingested_metadata',
      metadata: body.evidence.metadata ?? metadata,
      related_event_id: record.id,
    });
  }

  incMetric('events_ingested_total');
  audit({
    tenant_id: tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'event.ingested',
    resource_type: 'event',
    resource_id: eventId,
  });
  persistStore();
  return { event: record };
}
