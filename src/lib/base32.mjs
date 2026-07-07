import { randomBytes } from 'node:crypto';

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * RFC 4648 base32 encode (no padding).
 *
 * @param {Buffer | Uint8Array} buffer
 */
export function encodeBase32(buffer) {
  const bytes = Buffer.from(buffer);
  let bits = 0;
  let value = 0;
  let output = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

/**
 * @param {number} [byteLength=32]
 */
export function randomBase32Token(byteLength = 32) {
  return encodeBase32(randomBytes(byteLength));
}