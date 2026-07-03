import { createHash } from 'node:crypto';
import { HttpBodyError } from './http.mjs';
import { newId } from './ids.mjs';
import { redactString } from './redact.mjs';

export const SHA256_HEX_RE = /^[a-f0-9]{64}$/i;

export const FORBIDDEN_ARTIFACT_UPLOAD_KEYS = new Set([
  'attachment',
  'attachments',
  'body',
  'content',
  'contract_body',
  'contract_document',
  'customer_contract',
  'customer_payload',
  'file',
  'file_content',
  'file_data',
  'headers',
  'request_body',
  'request_headers',
  'authorization',
  'cookie',
  'log',
  'log_blob',
  'logs',
  'packet',
  'packet_payload',
  'payload',
  'raw_authorization',
  'raw_body',
  'raw_contract',
  'raw_document',
  'raw_headers',
  'raw_log',
  'raw_packet',
]);
const FORBIDDEN_ARTIFACT_UPLOAD_COMPACT_KEYS = new Set(
  [...FORBIDDEN_ARTIFACT_UPLOAD_KEYS].map((key) => key.replace(/_/g, '')),
);

const JSON_MERGE_FIELDS = new Set(['metadata', 'proof', 'envelope']);

export function normalizeContentSha256(value) {
  if (value == null || value === '') return null;
  const normalized = String(value).trim().toLowerCase();
  if (!SHA256_HEX_RE.test(normalized)) return null;
  return normalized;
}

function containsForbiddenUploadKeys(value, path = '') {
  if (value == null || typeof value !== 'object') return [];
  const hits = [];
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i += 1) {
      hits.push(...containsForbiddenUploadKeys(value[i], `${path}[${i}]`));
    }
    return hits;
  }
  for (const [key, child] of Object.entries(value)) {
    const normalized = String(key)
      .trim()
      .replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2')
      .replace(/([a-z])([A-Z])/g, '$1_$2')
      .replace(/[^a-zA-Z0-9]+/g, '_')
      .replace(/_+/g, '_')
      .replace(/^_+|_+$/g, '')
      .toLowerCase();
    const compact = normalized.replace(/_/g, '');
    if (
      FORBIDDEN_ARTIFACT_UPLOAD_KEYS.has(normalized)
      || FORBIDDEN_ARTIFACT_UPLOAD_COMPACT_KEYS.has(compact)
      || normalized.startsWith('raw_')
      || compact.startsWith('raw')
    ) {
      hits.push(path ? `${path}.${key}` : key);
    }
    hits.push(...containsForbiddenUploadKeys(child, path ? `${path}.${key}` : key));
  }
  return hits;
}

export function validateArtifactUploadBody(body) {
  if (body == null || typeof body !== 'object' || Array.isArray(body)) {
    return { error: 'invalid_artifact_upload', status: 400 };
  }
  if (!body.type || String(body.type).trim() === '') {
    return { error: 'missing_artifact_type', status: 400 };
  }
  const contentSha256 = normalizeContentSha256(body.content_sha256);
  if (!contentSha256) {
    return { error: 'missing_or_invalid_content_sha256', status: 400 };
  }
  const forbidden = containsForbiddenUploadKeys(body);
  if (forbidden.length > 0) {
    return {
      error: 'forbidden_artifact_upload_fields',
      status: 400,
      forbidden_fields: forbidden.slice(0, 20),
    };
  }
  return { ok: true, content_sha256: contentSha256 };
}

export function buildAuthorizationArtifactLedgerEntry(ctx, requestId, artifact, body) {
  const custodyId = artifact.custody_id ?? newId('cust');
  const custodyUri =
    body.custody_uri != null && String(body.custody_uri).trim() !== ''
      ? redactString(String(body.custody_uri))
      : `custody://${custodyId}`;
  return {
    id: artifact.id,
    custody_id: custodyId,
    tenant_id: ctx.tenantId,
    high_scale_request_id: requestId,
    artifact_type: artifact.type,
    content_sha256: artifact.content_sha256,
    custody_uri: custodyUri,
    content_type:
      body.content_type != null && String(body.content_type).trim() !== ''
        ? redactString(String(body.content_type))
        : null,
    filename_redacted:
      body.filename != null && String(body.filename).trim() !== ''
        ? redactString(String(body.filename))
        : null,
    upload_envelope: artifact.upload_envelope ?? 'json',
    reference_uri_redacted: artifact.reference_uri_redacted ?? 'metadata://redacted',
    status: artifact.status,
    created_at: artifact.created_at,
    created_by: ctx.userId,
  };
}

export function ensureAuthorizationArtifactLedger(store) {
  if (!store.highScaleAuthorizationArtifacts) store.highScaleAuthorizationArtifacts = [];
  return store.highScaleAuthorizationArtifacts;
}

function parseMultipartBoundary(contentType) {
  const match = /boundary=(?:"([^"]+)"|([^\s;]+))/i.exec(contentType ?? '');
  return match ? (match[1] || match[2]) : null;
}

function parseJsonField(value, fieldName) {
  if (value == null || value === '') return {};
  try {
    const parsed = JSON.parse(String(value));
    if (parsed != null && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed;
    throw new Error('not_object');
  } catch {
    throw new HttpBodyError('invalid_multipart_json_field', 400);
  }
}

function flattenMultipartFields(fields) {
  const body = { ...fields };
  for (const key of JSON_MERGE_FIELDS) {
    if (body[key] == null) continue;
    const merged = typeof body[key] === 'string' ? parseJsonField(body[key], key) : body[key];
    delete body[key];
    for (const [childKey, childValue] of Object.entries(merged)) {
      if (body[childKey] === undefined) body[childKey] = childValue;
    }
  }
  return body;
}

export function parseMultipartMetadataOnly(buffer, contentType) {
  const boundary = parseMultipartBoundary(contentType);
  if (!boundary) {
    throw new HttpBodyError('invalid_multipart', 400);
  }
  const raw = buffer.toString('latin1');
  const delimiter = `--${boundary}`;
  const parts = raw.split(delimiter);
  const fields = {};

  for (const part of parts) {
    const trimmed = part.replace(/^\r\n/, '').replace(/\r\n$/, '');
    if (!trimmed || trimmed === '--') continue;
    const headerEnd = trimmed.indexOf('\r\n\r\n');
    if (headerEnd < 0) continue;
    const headers = trimmed.slice(0, headerEnd);
    const value = trimmed.slice(headerEnd + 4).replace(/\r\n$/, '');
    const disposition = /content-disposition:[^\r\n]*/i.exec(headers)?.[0] ?? '';
    const nameMatch = /name="([^"]+)"/i.exec(disposition);
    if (!nameMatch) continue;
    const name = nameMatch[1];
    if (/filename="[^"]*"/i.test(disposition)) {
      throw new HttpBodyError('forbidden_file_upload', 400);
    }
    fields[name] = value;
  }

  return flattenMultipartFields(fields);
}

export async function readArtifactUploadBody(req, maxBytes) {
  const contentType = String(req.headers['content-type'] ?? '').toLowerCase();
  if (contentType.includes('multipart/form-data')) {
    const buffer = await readBodyBuffer(req, maxBytes);
    const body = parseMultipartMetadataOnly(buffer, contentType);
    return { body, envelope: 'multipart_metadata' };
  }
  const raw = await readBodyText(req, maxBytes);
  if (!raw.trim()) {
    throw new HttpBodyError('invalid_artifact_upload', 400);
  }
  let body;
  try {
    body = JSON.parse(raw);
  } catch {
    throw new HttpBodyError('invalid_json', 400);
  }
  return { body, envelope: 'json' };
}

export async function readBodyBuffer(req, maxBytes) {
  if (!Number.isInteger(maxBytes) || maxBytes < 1) {
    throw new Error('readBodyBuffer requires a positive integer maxBytes');
  }
  const chunks = [];
  let total = 0;
  let tooLarge = false;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > maxBytes) tooLarge = true;
    else chunks.push(chunk);
  }
  if (tooLarge) {
    throw new HttpBodyError('payload_too_large', 413);
  }
  return Buffer.concat(chunks);
}

async function readBodyText(req, maxBytes) {
  const buffer = await readBodyBuffer(req, maxBytes);
  return buffer.toString('utf8');
}

/** Deterministic SHA-256 for test fixtures and client-side digest hints. */
export function sha256Hex(value) {
  return createHash('sha256').update(String(value)).digest('hex');
}
