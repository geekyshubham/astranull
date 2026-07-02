import { redactObject } from '../lib/redact.mjs';
import { newId } from '../lib/ids.mjs';
import { getStore, persistStore } from '../store.mjs';

function ensureVault() {
  const store = getStore();
  if (!store.evidenceVault) store.evidenceVault = [];
  return store.evidenceVault;
}

export function recordEvidence(ctx, body) {
  const vault = ensureVault();
  const id = body.evidence_id ?? newId('evidence');
  const record = {
    id,
    tenant_id: ctx.tenantId,
    test_run_id: body.test_run_id ?? null,
    label: body.label ?? 'metadata_evidence',
    metadata: redactObject(body.metadata ?? {}),
    related_event_id: body.related_event_id ?? null,
    created_at: new Date().toISOString(),
  };
  vault.push(record);
  persistStore();
  return record;
}

export function listEvidence(ctx) {
  return ensureVault().filter((e) => e.tenant_id === ctx.tenantId);
}

export function getEvidence(ctx, id) {
  return ensureVault().find((e) => e.id === id && e.tenant_id === ctx.tenantId) ?? null;
}