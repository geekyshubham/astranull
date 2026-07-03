import {
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  sign,
  timingSafeEqual,
  verify,
} from 'node:crypto';
import {
  canonicalJsonStringify,
  CONTENT_CANONICALIZATION,
  CUSTODY_SCHEMA_VERSION,
  sha256CanonicalJson,
} from './custody.mjs';
import { BASE64_DER_RE, fingerprintPublicKeyDerBase64 } from './agentUpdates.mjs';

export const EVIDENCE_SIGNING_SCHEMA_VERSION = 'astranull.evidence_signing.v1';
export const EVIDENCE_SIGNING_ALGORITHMS = Object.freeze(['ed25519', 'hmac-sha256']);
export const KEY_REFERENCE_RE = /^key:\/\/[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$/;
export const SHA256_HEX_RE = /^[a-f0-9]{64}$/;

const SIGNABLE_CUSTODY_FIELDS = Object.freeze([
  'schema_version',
  'tenant_id',
  'artifact_type',
  'artifact_id',
  'format',
  'created_at',
  'created_by',
  'content_sha256',
  'content_canonicalization',
  'subject_ids',
  'previous_audit_hash',
  'previous_tenant_audit_hash',
]);

const FORBIDDEN_CUSTODY_KEYS = new Set([
  'payload',
  'content',
  'body',
  'ciphertext',
  'secret',
  'token',
  'password',
  'signature',
  'private_key',
]);

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function normalizeAlgorithm(raw) {
  if (typeof raw !== 'string') return null;
  const value = raw.trim().toLowerCase();
  return EVIDENCE_SIGNING_ALGORITHMS.includes(value) ? value : null;
}

function safeEqualUtf8(a, b) {
  const left = Buffer.from(String(a), 'utf8');
  const right = Buffer.from(String(b), 'utf8');
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

/**
 * @param {string} keyReference
 */
export function isValidKeyReference(keyReference) {
  return typeof keyReference === 'string' && KEY_REFERENCE_RE.test(keyReference.trim());
}

/**
 * Metadata-only custody manifest fields used for digest + signing envelopes.
 * @param {Record<string, unknown>} custody
 */
export function buildSignableCustodyManifestMetadata(custody) {
  if (!isPlainObject(custody)) {
    throw Object.assign(new Error('custody must be an object'), { code: 'invalid_custody' });
  }
  for (const key of Object.keys(custody)) {
    if (FORBIDDEN_CUSTODY_KEYS.has(key)) {
      throw Object.assign(new Error(`forbidden custody field: ${key}`), { code: 'forbidden_custody_field' });
    }
  }
  const out = {};
  for (const field of SIGNABLE_CUSTODY_FIELDS) {
    if (custody[field] !== undefined) {
      out[field] = custody[field];
    }
  }
  if (Array.isArray(out.subject_ids)) {
    out.subject_ids = [...new Set(out.subject_ids.filter(Boolean))].sort();
  }
  return out;
}

/**
 * @param {{ tenantId: string, custodyManifestDigest: string }} input
 */
export function buildCustodySigningEnvelope({ tenantId, custodyManifestDigest }) {
  return {
    schema_version: CUSTODY_SCHEMA_VERSION,
    signing_schema_version: EVIDENCE_SIGNING_SCHEMA_VERSION,
    content_canonicalization: CONTENT_CANONICALIZATION,
    tenant_id: tenantId,
    custody_manifest_digest: custodyManifestDigest,
  };
}

/**
 * @param {Record<string, unknown>} custody
 * @returns {{ ok: true, signable: Record<string, unknown>, digest: string } | { ok: false, error: string }}
 */
export function digestCustodyManifestMetadata(custody) {
  let signable;
  try {
    signable = buildSignableCustodyManifestMetadata(custody);
  } catch (err) {
    return { ok: false, error: err?.code ?? 'invalid_custody' };
  }
  if (signable.schema_version !== CUSTODY_SCHEMA_VERSION) {
    return { ok: false, error: 'schema_version_mismatch' };
  }
  if (signable.content_canonicalization !== CONTENT_CANONICALIZATION) {
    return { ok: false, error: 'canonicalization_mismatch' };
  }
  if (typeof signable.tenant_id !== 'string' || signable.tenant_id.trim() === '') {
    return { ok: false, error: 'tenant_id_missing' };
  }
  if (typeof signable.artifact_type !== 'string' || signable.artifact_type.trim() === '') {
    return { ok: false, error: 'artifact_type_missing' };
  }
  if (typeof signable.artifact_id !== 'string' || signable.artifact_id.trim() === '') {
    return { ok: false, error: 'artifact_id_missing' };
  }
  if (typeof signable.content_sha256 !== 'string' || !SHA256_HEX_RE.test(signable.content_sha256)) {
    return { ok: false, error: 'content_sha256_invalid' };
  }
  let digest;
  try {
    digest = sha256CanonicalJson(signable);
  } catch {
    return { ok: false, error: 'digest_failed' };
  }
  return { ok: true, signable, digest };
}

/**
 * Parse tenant-scoped signing key references from env without storing private keys in-repo.
 * Shape:
 * {
 *   "ten_a": {
 *     "key://vault/astranull/evidence-signing/staging": {
 *       "algorithm": "ed25519",
 *       "private_key_pkcs8_der_base64": "...",
 *       "public_key_spki_der_base64": "..." // optional for verify-only entries
 *     }
 *   }
 * }
 * @param {NodeJS.ProcessEnv} env
 */
export function parseEvidenceSigningKeyMap(env = process.env) {
  const raw = env.ASTRANULL_EVIDENCE_SIGNING_KEYS_JSON;
  if (raw === undefined || raw === null || String(raw).trim() === '') {
    return {};
  }
  let parsed;
  try {
    parsed = JSON.parse(String(raw));
  } catch {
    throw new Error('ASTRANULL_EVIDENCE_SIGNING_KEYS_JSON must be valid JSON.');
  }
  if (!isPlainObject(parsed)) {
    throw new Error('ASTRANULL_EVIDENCE_SIGNING_KEYS_JSON must be a JSON object.');
  }
  return parsed;
}

function resolveTenantKeyBucket(keyMap, tenantId) {
  const bucket = keyMap?.[tenantId];
  if (!isPlainObject(bucket)) return null;
  return bucket;
}

function loadEd25519PrivateKey(privateKeyPkcs8DerBase64) {
  if (typeof privateKeyPkcs8DerBase64 !== 'string' || privateKeyPkcs8DerBase64.trim() === '') {
    return { error: 'missing_private_key' };
  }
  const trimmed = privateKeyPkcs8DerBase64.trim();
  if (!BASE64_DER_RE.test(trimmed)) {
    return { error: 'invalid_private_key' };
  }
  try {
    const privateKey = createPrivateKey({
      key: Buffer.from(trimmed, 'base64'),
      format: 'der',
      type: 'pkcs8',
    });
    if (privateKey.asymmetricKeyType && privateKey.asymmetricKeyType !== 'ed25519') {
      return { error: 'invalid_private_key' };
    }
    const publicKeyDer = createPublicKey(privateKey).export({ type: 'spki', format: 'der' }).toString('base64');
    return { privateKey, publicKeyDerBase64: publicKeyDer };
  } catch {
    return { error: 'invalid_private_key' };
  }
}

function loadEd25519PublicKey(publicKeySpkiDerBase64) {
  if (typeof publicKeySpkiDerBase64 !== 'string' || publicKeySpkiDerBase64.trim() === '') {
    return { error: 'missing_public_key' };
  }
  const trimmed = publicKeySpkiDerBase64.trim();
  if (!BASE64_DER_RE.test(trimmed)) {
    return { error: 'invalid_public_key' };
  }
  try {
    const publicKey = createPublicKey({
      key: Buffer.from(trimmed, 'base64'),
      format: 'der',
      type: 'spki',
    });
    if (publicKey.asymmetricKeyType && publicKey.asymmetricKeyType !== 'ed25519') {
      return { error: 'invalid_public_key' };
    }
    return { publicKey, publicKeyDerBase64: trimmed };
  } catch {
    return { error: 'invalid_public_key' };
  }
}

/**
 * @param {{
 *   tenantId: string,
 *   keyReference: string,
 *   algorithm: string,
 *   env?: NodeJS.ProcessEnv,
 * }} input
 */
export function resolveTenantSigningMaterial(input) {
  const tenantId = input.tenantId;
  const keyReference = typeof input.keyReference === 'string' ? input.keyReference.trim() : '';
  const algorithm = normalizeAlgorithm(input.algorithm);
  if (!isValidKeyReference(keyReference)) {
    return { error: 'invalid_key_reference', status: 400 };
  }
  if (!algorithm) {
    return { error: 'invalid_algorithm', status: 400 };
  }
  let keyMap;
  try {
    keyMap = parseEvidenceSigningKeyMap(input.env ?? process.env);
  } catch (err) {
    return { error: 'invalid_signing_key_config', status: 500, detail: err.message };
  }
  const bucket = resolveTenantKeyBucket(keyMap, tenantId);
  const entry = bucket?.[keyReference];
  if (!isPlainObject(entry)) {
    return { error: 'unknown_signing_key_reference', status: 400 };
  }
  const entryAlgorithm = normalizeAlgorithm(entry.algorithm);
  if (entryAlgorithm !== algorithm) {
    return { error: 'signing_key_algorithm_mismatch', status: 400 };
  }
  if (algorithm === 'ed25519') {
    const loaded = loadEd25519PrivateKey(entry.private_key_pkcs8_der_base64);
    if (loaded.error) {
      return { error: loaded.error, status: 400 };
    }
    return {
      algorithm,
      keyReference,
      privateKey: loaded.privateKey,
      publicKeyDerBase64: loaded.publicKeyDerBase64,
      publicKeyFingerprintSha256: fingerprintPublicKeyDerBase64(loaded.publicKeyDerBase64),
    };
  }
  const secret = entry.secret;
  if (typeof secret !== 'string' || secret.trim().length < 32) {
    return { error: 'invalid_hmac_secret', status: 400 };
  }
  return {
    algorithm,
    keyReference,
    secret: secret.trim(),
    publicKeyFingerprintSha256: createHash('sha256').update(secret.trim(), 'utf8').digest('hex'),
  };
}

/**
 * @param {{
 *   tenantId: string,
 *   keyReference: string,
 *   algorithm: string,
 *   env?: NodeJS.ProcessEnv,
 * }} input
 */
export function resolveTenantVerificationMaterial(input) {
  const tenantId = input.tenantId;
  const keyReference = typeof input.keyReference === 'string' ? input.keyReference.trim() : '';
  const algorithm = normalizeAlgorithm(input.algorithm);
  if (!isValidKeyReference(keyReference)) {
    return { error: 'invalid_key_reference', status: 400 };
  }
  if (!algorithm) {
    return { error: 'invalid_algorithm', status: 400 };
  }
  let keyMap;
  try {
    keyMap = parseEvidenceSigningKeyMap(input.env ?? process.env);
  } catch (err) {
    return { error: 'invalid_signing_key_config', status: 500, detail: err.message };
  }
  const bucket = resolveTenantKeyBucket(keyMap, tenantId);
  const entry = bucket?.[keyReference];
  if (!isPlainObject(entry)) {
    return { error: 'unknown_signing_key_reference', status: 400 };
  }
  const entryAlgorithm = normalizeAlgorithm(entry.algorithm);
  if (entryAlgorithm !== algorithm) {
    return { error: 'signing_key_algorithm_mismatch', status: 400 };
  }
  if (algorithm === 'ed25519') {
    if (typeof entry.private_key_pkcs8_der_base64 === 'string' && entry.private_key_pkcs8_der_base64.trim() !== '') {
      const loaded = loadEd25519PrivateKey(entry.private_key_pkcs8_der_base64);
      if (loaded.error) {
        return { error: loaded.error, status: 400 };
      }
      return {
        algorithm,
        keyReference,
        publicKeyDerBase64: loaded.publicKeyDerBase64,
        publicKeyFingerprintSha256: fingerprintPublicKeyDerBase64(loaded.publicKeyDerBase64),
      };
    }
    const loaded = loadEd25519PublicKey(entry.public_key_spki_der_base64);
    if (loaded.error) {
      return { error: loaded.error, status: 400 };
    }
    return {
      algorithm,
      keyReference,
      publicKeyDerBase64: loaded.publicKeyDerBase64,
      publicKeyFingerprintSha256: fingerprintPublicKeyDerBase64(loaded.publicKeyDerBase64),
    };
  }
  const secret = entry.secret;
  if (typeof secret !== 'string' || secret.trim().length < 32) {
    return { error: 'invalid_hmac_secret', status: 400 };
  }
  return {
    algorithm,
    keyReference,
    secret: secret.trim(),
    publicKeyFingerprintSha256: createHash('sha256').update(secret.trim(), 'utf8').digest('hex'),
  };
}

export function signEnvelopeWithMaterial(envelope, material) {
  const message = Buffer.from(canonicalJsonStringify(envelope), 'utf8');
  if (material.algorithm === 'ed25519') {
    const signature = sign(null, message, material.privateKey);
    return signature.toString('base64');
  }
  return createHmac('sha256', material.secret).update(message).digest('base64');
}

function signEnvelope(envelope, material) {
  return signEnvelopeWithMaterial(envelope, material);
}

function verifyEnvelopeSignature(envelope, signatureBase64, material) {
  const message = Buffer.from(canonicalJsonStringify(envelope), 'utf8');
  if (material.algorithm === 'ed25519') {
    let signatureBuf;
    try {
      signatureBuf = Buffer.from(signatureBase64, 'base64');
    } catch {
      return false;
    }
    const publicKey = createPublicKey({
      key: Buffer.from(material.publicKeyDerBase64, 'base64'),
      format: 'der',
      type: 'spki',
    });
    return verify(null, message, publicKey, signatureBuf);
  }
  const expected = createHmac('sha256', material.secret).update(message).digest('base64');
  return safeEqualUtf8(expected, signatureBase64);
}

/**
 * @param {{
 *   tenantId: string,
 *   custody: Record<string, unknown>,
 *   keyReference: string,
 *   algorithm: string,
 *   env?: NodeJS.ProcessEnv,
 *   now?: () => Date,
 * }} input
 */
export function signCustodyManifestMetadata(input) {
  const tenantId = input.tenantId;
  const custody = input.custody;
  if (!isPlainObject(custody)) {
    return { error: 'invalid_custody', status: 400 };
  }
  const digestResult = digestCustodyManifestMetadata(custody);
  if (!digestResult.ok) {
    return { error: digestResult.error, status: 400 };
  }
  if (digestResult.signable.tenant_id !== tenantId) {
    return { error: 'tenant_id_mismatch', status: 400 };
  }
  const algorithm = normalizeAlgorithm(input.algorithm);
  if (!algorithm) {
    return { error: 'invalid_algorithm', status: 400 };
  }
  const keyReference = typeof input.keyReference === 'string' ? input.keyReference.trim() : '';
  if (!isValidKeyReference(keyReference)) {
    return { error: 'invalid_key_reference', status: 400 };
  }
  const material = resolveTenantSigningMaterial({
    tenantId,
    keyReference,
    algorithm,
    env: input.env,
  });
  if (material.error) {
    return { error: material.error, status: material.status ?? 400 };
  }
  const envelope = buildCustodySigningEnvelope({
    tenantId,
    custodyManifestDigest: digestResult.digest,
  });
  const signature = signEnvelope(envelope, material);
  const nowFn = input.now ?? (() => new Date());
  return buildSignedCustodyManifestResult({
    algorithm,
    keyReference,
    signature,
    digest: digestResult.digest,
    signable: digestResult.signable,
    publicKeyFingerprintSha256: material.publicKeyFingerprintSha256,
    signingSource: 'env',
    nowFn,
  });
}

function buildSignedCustodyManifestResult({
  algorithm,
  keyReference,
  signature,
  digest,
  signable,
  publicKeyFingerprintSha256,
  signingSource,
  nowFn,
}) {
  const signed = {
    schema_version: EVIDENCE_SIGNING_SCHEMA_VERSION,
    algorithm,
    key_reference: keyReference,
    signature,
    custody_manifest_digest: digest,
    content_sha256: signable.content_sha256,
    artifact_type: signable.artifact_type,
    artifact_id: signable.artifact_id,
    public_key_fingerprint_sha256: publicKeyFingerprintSha256,
    signed_at: nowFn().toISOString(),
  };
  if (signingSource) {
    signed.signing_source = signingSource;
  }
  return { signed };
}

/**
 * @param {{
 *   tenantId: string,
 *   custody: Record<string, unknown>,
 *   keyReference: string,
 *   algorithm: string,
 *   env?: NodeJS.ProcessEnv,
 *   now?: () => Date,
 *   signingAdapter?: {
 *     signDigest: (input: {
 *       tenantId: string,
 *       algorithm: string,
 *       digest: string,
 *       keyReference: string,
 *     }) => Promise<
 *       | { signature: string, publicKeyFingerprintSha256: string, source?: string }
 *       | { error: string, status?: number, detail?: string }
 *     >,
 *   },
 * }} input
 */
export async function signCustodyManifestMetadataAsync(input) {
  const tenantId = input.tenantId;
  const custody = input.custody;
  if (!isPlainObject(custody)) {
    return { error: 'invalid_custody', status: 400 };
  }
  const digestResult = digestCustodyManifestMetadata(custody);
  if (!digestResult.ok) {
    return { error: digestResult.error, status: 400 };
  }
  if (digestResult.signable.tenant_id !== tenantId) {
    return { error: 'tenant_id_mismatch', status: 400 };
  }
  const algorithm = normalizeAlgorithm(input.algorithm);
  if (!algorithm) {
    return { error: 'invalid_algorithm', status: 400 };
  }
  const keyReference = typeof input.keyReference === 'string' ? input.keyReference.trim() : '';
  if (!isValidKeyReference(keyReference)) {
    return { error: 'invalid_key_reference', status: 400 };
  }
  const adapter = input.signingAdapter;
  if (!adapter || typeof adapter.signDigest !== 'function') {
    return { error: 'signing_adapter_missing', status: 500 };
  }
  const signedDigest = await adapter.signDigest({
    tenantId,
    algorithm,
    digest: digestResult.digest,
    keyReference,
  });
  if (signedDigest.error) {
    return {
      error: signedDigest.error,
      status: signedDigest.status ?? 400,
      detail: signedDigest.detail,
    };
  }
  const nowFn = input.now ?? (() => new Date());
  return buildSignedCustodyManifestResult({
    algorithm,
    keyReference,
    signature: signedDigest.signature,
    digest: digestResult.digest,
    signable: digestResult.signable,
    publicKeyFingerprintSha256: signedDigest.publicKeyFingerprintSha256,
    signingSource: signedDigest.source,
    nowFn,
  });
}

/**
 * @param {{
 *   tenantId: string,
 *   custodyManifestDigest: string,
 *   signer: Record<string, unknown>,
 *   env?: NodeJS.ProcessEnv,
 * }} input
 * @returns {{ ok: true } | { ok: false, error: string }}
 */
export function verifyCustodyManifestSignature(input) {
  const tenantId = input.tenantId;
  const digest = String(input.custodyManifestDigest ?? '');
  if (!SHA256_HEX_RE.test(digest)) {
    return { ok: false, error: 'custody_manifest_digest_invalid' };
  }
  const signer = input.signer;
  if (!isPlainObject(signer)) {
    return { ok: false, error: 'signer_missing' };
  }
  const algorithm = normalizeAlgorithm(signer.algorithm);
  if (!algorithm) {
    return { ok: false, error: 'invalid_algorithm' };
  }
  const keyReference = typeof signer.key_reference === 'string' ? signer.key_reference.trim() : '';
  if (!isValidKeyReference(keyReference)) {
    return { ok: false, error: 'invalid_key_reference' };
  }
  const signature = typeof signer.signature === 'string' ? signer.signature.trim() : '';
  if (signature === '') {
    return { ok: false, error: 'signature_missing' };
  }
  const material = resolveTenantVerificationMaterial({
    tenantId,
    keyReference,
    algorithm,
    env: input.env,
  });
  if (material.error) {
    return { ok: false, error: material.error };
  }
  const envelope = buildCustodySigningEnvelope({ tenantId, custodyManifestDigest: digest });
  if (!verifyEnvelopeSignature(envelope, signature, material)) {
    return { ok: false, error: 'signature_verification_failed' };
  }
  return { ok: true };
}