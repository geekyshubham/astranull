import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

export const ENVELOPE_VERSION = 1;
export const ENVELOPE_ALGORITHM = 'AES-256-GCM';

const KEY_BYTES = 32;
const IV_BYTES = 12;

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

function serializeAad(aadObject) {
  return Buffer.from(stableStringify(aadObject ?? {}), 'utf8');
}

export function loadSecretEncryptionKey(env = process.env, { required = false } = {}) {
  const raw = (env.ASTRANULL_SECRET_ENCRYPTION_KEY ?? '').trim();
  if (!raw) {
    if (required) {
      throw new Error(
        'Refusing to start: ASTRANULL_SECRET_ENCRYPTION_KEY must be set when NODE_ENV=production.',
      );
    }
    return null;
  }

  let key;
  if (/^[0-9a-fA-F]{64}$/.test(raw)) {
    key = Buffer.from(raw, 'hex');
  } else {
    key = Buffer.from(raw, 'base64');
  }

  if (key.length !== KEY_BYTES) {
    throw new Error(
      'ASTRANULL_SECRET_ENCRYPTION_KEY must be a 32-byte key encoded as base64 or 64-character hex.',
    );
  }
  return key;
}

export function encryptSecret(plaintext, key, aadObject) {
  if (!key || key.length !== KEY_BYTES) {
    throw new Error('Secret encryption key must be 32 bytes.');
  }
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(serializeAad(aadObject));
  const ciphertext = Buffer.concat([
    cipher.update(String(plaintext), 'utf8'),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();
  return {
    version: ENVELOPE_VERSION,
    algorithm: ENVELOPE_ALGORITHM,
    iv: iv.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
    auth_tag: authTag.toString('base64'),
    created_at: new Date().toISOString(),
  };
}

export function decryptSecret(envelope, key, aadObject) {
  if (!envelope || envelope.version !== ENVELOPE_VERSION || envelope.algorithm !== ENVELOPE_ALGORITHM) {
    throw new Error('Unsupported or invalid secret envelope.');
  }
  if (!key || key.length !== KEY_BYTES) {
    throw new Error('Secret encryption key must be 32 bytes.');
  }
  const decipher = createDecipheriv(
    'aes-256-gcm',
    key,
    Buffer.from(envelope.iv, 'base64'),
  );
  decipher.setAAD(serializeAad(aadObject));
  decipher.setAuthTag(Buffer.from(envelope.auth_tag, 'base64'));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(envelope.ciphertext, 'base64')),
    decipher.final(),
  ]).toString('utf8');
  return plaintext;
}

export function redactSecretEnvelope(envelope) {
  if (!envelope) return null;
  const { ciphertext: _c, auth_tag: _t, ...meta } = envelope;
  return meta;
}

export function buildSecretAad(record) {
  return {
    id: record.id,
    tenant_id: record.tenant_id,
    purpose: record.purpose,
    name: record.name,
    rotation: record.rotation ?? 0,
  };
}

export function toRedactedSecretRecord(record) {
  const { envelope, ...rest } = record;
  return {
    ...rest,
    envelope: redactSecretEnvelope(envelope),
  };
}