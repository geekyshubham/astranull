import { createHash } from 'node:crypto';

export const CUSTODY_SCHEMA_VERSION = 'astranull.custody.v1';
export const CONTENT_CANONICALIZATION = 'json-key-sorted-v1';

export const CUSTODY_UNSUPPORTED_VALUE = 'custody_unsupported_value';

function unsupportedType(value, detail) {
  const tag = detail ?? (value === null ? 'null' : typeof value);
  const err = new Error(`Unsupported value for custody canonicalization: ${tag}`);
  err.code = CUSTODY_UNSUPPORTED_VALUE;
  return err;
}

function isPlainObject(value) {
  if (value === null || typeof value !== 'object') {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function isUnsupportedObject(value) {
  if (typeof Date !== 'undefined' && value instanceof Date) {
    return 'Date';
  }
  if (typeof RegExp !== 'undefined' && value instanceof RegExp) {
    return 'RegExp';
  }
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer(value)) {
    return 'Buffer';
  }
  if (typeof Map !== 'undefined' && value instanceof Map) {
    return 'Map';
  }
  if (typeof Set !== 'undefined' && value instanceof Set) {
    return 'Set';
  }
  if (ArrayBuffer.isView(value) && !Array.isArray(value)) {
    return 'TypedArray';
  }
  return null;
}

/**
 * Deterministic canonical JSON for plain JSON values (key-sorted objects, array order preserved).
 * @param {unknown} value
 * @returns {string}
 */
export function canonicalJsonStringify(value) {
  return stringifyCanonical(normalizeForCanonical(value));
}

function normalizeForCanonical(value) {
  if (value === undefined) {
    return null;
  }
  if (value === null) {
    return null;
  }
  const t = typeof value;
  if (t === 'string' || t === 'boolean') {
    return value;
  }
  if (t === 'number') {
    if (!Number.isFinite(value)) {
      throw unsupportedType(value);
    }
    return value;
  }
  if (t === 'bigint' || t === 'function' || t === 'symbol') {
    throw unsupportedType(value);
  }
  if (Array.isArray(value)) {
    const out = [];
    for (let i = 0; i < value.length; i += 1) {
      const item = Object.prototype.hasOwnProperty.call(value, i) ? value[i] : undefined;
      out.push(normalizeForCanonical(item));
    }
    return out;
  }
  if (t === 'object') {
    const unsupported = isUnsupportedObject(value);
    if (unsupported) {
      throw unsupportedType(value, unsupported);
    }
    if (!isPlainObject(value)) {
      throw unsupportedType(value, 'class_instance');
    }
    const out = {};
    const keys = Object.keys(value).sort();
    for (const key of keys) {
      const v = value[key];
      if (v === undefined) {
        continue;
      }
      out[key] = normalizeForCanonical(v);
    }
    return out;
  }
  throw unsupportedType(value);
}

function stringifyCanonical(value) {
  if (value === null) {
    return 'null';
  }
  const t = typeof value;
  if (t === 'string' || t === 'boolean' || t === 'number') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((v) => stringifyCanonical(v)).join(',')}]`;
  }
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stringifyCanonical(value[k])}`).join(',')}}`;
}

/**
 * @param {unknown} value Plain JSON value (normalized before digest).
 * @returns {string} Lowercase hex SHA-256 of canonical JSON.
 */
export function sha256CanonicalJson(value) {
  const canonical = canonicalJsonStringify(value);
  return createHash('sha256').update(canonical, 'utf8').digest('hex');
}

/**
 * @param {{
 *   tenant_id: string,
 *   artifact_type: string,
 *   artifact_id: string,
 *   format: string,
 *   created_by: string,
 *   content: unknown,
 *   subject_ids?: string[],
 *   previous_audit_hash?: string | null,
 *   previous_tenant_audit_hash?: string | null,
 *   created_at?: string,
 * }} input
 */
export function buildCustodyManifest(input) {
  const subjectIds = [...new Set((input.subject_ids ?? []).filter(Boolean))].sort();
  const manifest = {
    schema_version: CUSTODY_SCHEMA_VERSION,
    tenant_id: input.tenant_id,
    artifact_type: input.artifact_type,
    artifact_id: input.artifact_id,
    format: input.format ?? 'json',
    created_at: input.created_at ?? new Date().toISOString(),
    created_by: input.created_by ?? null,
    content_sha256: sha256CanonicalJson(input.content),
    content_canonicalization: CONTENT_CANONICALIZATION,
    subject_ids: subjectIds,
    previous_audit_hash: input.previous_audit_hash ?? null,
  };
  if (input.previous_tenant_audit_hash != null) {
    manifest.previous_tenant_audit_hash = input.previous_tenant_audit_hash;
  }
  return manifest;
}

/**
 * Metadata-only verification: recompute digest over export payload JSON.
 * @param {{ payload: unknown, custody: Record<string, unknown> }} args
 * @returns {{ ok: true } | { ok: false, error: string }}
 */
export function verifyCustodyManifest({ payload, custody }) {
  if (!custody || typeof custody !== 'object') {
    return { ok: false, error: 'custody_missing' };
  }
  if (custody.schema_version !== CUSTODY_SCHEMA_VERSION) {
    return { ok: false, error: 'schema_version_mismatch' };
  }
  if (custody.content_canonicalization !== CONTENT_CANONICALIZATION) {
    return { ok: false, error: 'canonicalization_mismatch' };
  }
  let expected;
  try {
    expected = sha256CanonicalJson(payload);
  } catch (err) {
    return {
      ok: false,
      error: err?.code === CUSTODY_UNSUPPORTED_VALUE ? 'payload_not_canonicalizable' : 'digest_failed',
    };
  }
  if (custody.content_sha256 !== expected) {
    return { ok: false, error: 'content_sha256_mismatch' };
  }
  return { ok: true };
}