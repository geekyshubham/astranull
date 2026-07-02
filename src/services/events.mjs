import { audit } from '../audit.mjs';
import { redactObject } from '../lib/redact.mjs';
import { newId } from '../lib/ids.mjs';
import { incMetric } from '../lib/metrics.mjs';
import { getStore, persistStore } from '../store.mjs';
import { recordEvidence } from './evidence.mjs';

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

  if (body.packet_payload || body.raw_packet) {
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