import { newId } from '../lib/ids.mjs';
import { redactObject } from '../lib/redact.mjs';
import { getStore, persistStore } from '../store.mjs';

export function auditInternal(entry) {
  const store = getStore();
  if (!Array.isArray(store.internalAuditLog)) store.internalAuditLog = [];
  const record = {
    id: newId('internalAudit'),
    staff_id: entry.staff_id ?? null,
    staff_role: entry.staff_role ?? null,
    tenant_id: entry.tenant_id ?? null,
    action: entry.action,
    resource_type: entry.resource_type ?? 'internal',
    resource_id: entry.resource_id ?? null,
    reason: entry.reason ?? null,
    metadata: redactObject(entry.metadata ?? {}),
    created_at: new Date().toISOString(),
  };
  store.internalAuditLog.push(record);
  persistStore();
  return record;
}