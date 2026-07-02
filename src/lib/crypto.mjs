import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

export function generateSalt() {
  return randomBytes(16).toString('hex');
}

export function hashToken(secret) {
  return createHash('sha256').update(secret, 'utf8').digest('hex');
}

export function hashSecretWithSalt(secret, salt) {
  return createHash('sha256').update(`${salt}:${secret}`, 'utf8').digest('hex');
}

export function verifySecretWithSalt(secret, salt, expectedHash) {
  if (!secret || !salt || !expectedHash) return false;
  const actual = hashSecretWithSalt(secret, salt);
  return safeEqualHex(actual, expectedHash);
}

export function generateTokenSecret() {
  return `ast_${randomBytes(24).toString('base64url')}`;
}

export function generateAgentCredential() {
  return `agc_${randomBytes(24).toString('base64url')}`;
}

export function safeEqualHex(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  try {
    return timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
  } catch {
    return false;
  }
}

export function hashNonce(nonce) {
  return `sha256:${createHash('sha256').update(nonce, 'utf8').digest('hex')}`;
}

export function generateNonce() {
  return randomBytes(16).toString('hex');
}