import { createHash } from 'node:crypto';
import { newId } from './lib/ids.mjs';
import { redactObject } from './lib/redact.mjs';
import { getStore, persistStore } from './store.mjs';

/** Canonical form aligned with JSON.parse(JSON.stringify(...)) for hash stability. */
function stableStringify(value) {
  if (value === undefined) {
    return 'null';
  }
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((v) => (v === undefined ? 'null' : stableStringify(v))).join(',')}]`;
  }
  const keys = Object.keys(value).sort().filter((k) => value[k] !== undefined);
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(value[k])}`).join(',')}}`;
}

function hashAuditPayload(payload) {
  return createHash('sha256').update(stableStringify(payload), 'utf8').digest('hex');
}

function lastChainedEntry(auditLog) {
  for (let i = auditLog.length - 1; i >= 0; i -= 1) {
    if (auditLog[i].entry_hash) return auditLog[i];
  }
  return null;
}

function buildHashableRecord(record) {
  const { entry_hash: _eh, ...rest } = record;
  return rest;
}

export function computeEntryHash(record) {
  return hashAuditPayload(buildHashableRecord(record));
}

export function verifyAuditChain(auditLog) {
  if (!Array.isArray(auditLog)) {
    return { valid: false, error: 'audit_log_not_array', index: 0 };
  }
  let lastHash = null;
  let lastSequence = 0;
  for (let i = 0; i < auditLog.length; i += 1) {
    const entry = auditLog[i];
    if (!entry.entry_hash) {
      continue;
    }
    if (typeof entry.sequence !== 'number' || !Number.isInteger(entry.sequence) || entry.sequence < 1) {
      return { valid: false, error: 'invalid_sequence', index: i };
    }
    if (entry.sequence <= lastSequence) {
      return { valid: false, error: 'sequence_not_monotonic', index: i };
    }
    const expectedPrev = lastHash;
    if (entry.prev_hash !== expectedPrev) {
      return { valid: false, error: 'prev_hash_mismatch', index: i };
    }
    const expectedHash = computeEntryHash(entry);
    if (entry.entry_hash !== expectedHash) {
      return { valid: false, error: 'entry_hash_mismatch', index: i };
    }
    lastHash = entry.entry_hash;
    lastSequence = entry.sequence;
  }
  return { valid: true };
}

/**
 * Build a tamper-evident audit record from a raw entry and optional prior chained row.
 * @param {Record<string, unknown>} entry
 * @param {Record<string, unknown> | null | undefined} priorEntry
 * @param {Date} [now]
 */
export function buildAuditRecord(entry, priorEntry, now = new Date()) {
  const redactedEntry = redactObject(entry);
  const priorSequence =
    priorEntry &&
    typeof priorEntry.sequence === 'number' &&
    Number.isInteger(priorEntry.sequence)
      ? priorEntry.sequence
      : null;
  const sequence = priorSequence !== null ? priorSequence + 1 : 1;
  const record = {
    id: newId('event'),
    timestamp: now.toISOString(),
    ...redactedEntry,
    sequence,
    prev_hash: priorEntry?.entry_hash ?? null,
  };
  record.entry_hash = computeEntryHash(record);
  return record;
}

/** Latest globally chained audit row (hash the next `audit()` call will chain from). */
export function getLatestChainedAuditEntry() {
  return lastChainedEntry(getStore().auditLog);
}

export function getLatestChainedAuditEntryForTenant(tenantId) {
  const auditLog = getStore().auditLog;
  for (let i = auditLog.length - 1; i >= 0; i -= 1) {
    const entry = auditLog[i];
    if (entry.tenant_id === tenantId && entry.entry_hash) {
      return entry;
    }
  }
  return null;
}

export function audit(entry) {
  const store = getStore();
  const prior = lastChainedEntry(store.auditLog);
  const record = buildAuditRecord(entry, prior);
  store.auditLog.push(record);
  persistStore();
  return record;
}