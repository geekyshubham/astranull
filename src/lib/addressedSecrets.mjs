import { randomBytes } from 'node:crypto';

const ADDRESSED_VERSION = 'v1';
const ALLOWED_PREFIXES = new Set(['ast_', 'svc_', 'agc_']);
const STRICT_BASE64URL = /^[A-Za-z0-9_-]+$/;

function encodeSegment(value) {
  return Buffer.from(String(value), 'utf8').toString('base64url');
}

function isStrictBase64UrlSegment(segment) {
  return typeof segment === 'string' && segment.length > 0 && STRICT_BASE64URL.test(segment);
}

/** Decode UTF-8 tenant/id segments; reject permissive or non-canonical base64url. */
function decodeUtf8Segment(b64) {
  if (!isStrictBase64UrlSegment(b64)) return null;
  try {
    const decoded = Buffer.from(b64, 'base64url').toString('utf8');
    if (!decoded) return null;
    if (encodeSegment(decoded) !== b64) return null;
    return decoded;
  } catch {
    return null;
  }
}

/**
 * Mint a tenant-addressable secret: `{prefix}v1.{tenantB64}.{idB64}.{random}`.
 */
export function createAddressedSecret(prefix, tenantId, recordId) {
  if (!ALLOWED_PREFIXES.has(prefix)) {
    throw new Error(`createAddressedSecret: unsupported prefix "${prefix}"`);
  }
  if (!tenantId || !recordId) {
    throw new Error('createAddressedSecret: tenantId and recordId are required');
  }
  const tenantB64 = encodeSegment(tenantId);
  const idB64 = encodeSegment(recordId);
  const random = randomBytes(24).toString('base64url');
  return `${prefix}${ADDRESSED_VERSION}.${tenantB64}.${idB64}.${random}`;
}

/**
 * Parse addressed secrets for direct tenant/id lookup under RLS.
 * Returns null for legacy opaque tokens and malformed input.
 */
export function parseAddressedSecret(secret, expectedPrefix) {
  if (!secret || typeof secret !== 'string') return null;
  if (!expectedPrefix || !ALLOWED_PREFIXES.has(expectedPrefix)) return null;
  if (!secret.startsWith(expectedPrefix)) return null;

  const parts = secret.split('.');
  if (parts.length !== 4) return null;

  const [header, tenantB64, idB64, random] = parts;
  if (header !== `${expectedPrefix}${ADDRESSED_VERSION}`) return null;
  if (!isStrictBase64UrlSegment(random)) return null;

  const tenantId = decodeUtf8Segment(tenantB64);
  const id = decodeUtf8Segment(idB64);
  if (!tenantId || !id) return null;

  return { tenantId, id, version: ADDRESSED_VERSION };
}