import { readFileSync } from 'node:fs';
import { createHmac, sign } from 'node:crypto';
import { canonicalJsonStringify } from './custody.mjs';
import {
  buildCustodySigningEnvelope,
  isValidKeyReference,
  parseEvidenceSigningKeyMap,
  resolveTenantSigningMaterial,
  SHA256_HEX_RE,
} from './evidenceSigning.mjs';

const DEFAULT_KMS_FETCH_TIMEOUT_MS = 5000;

function normalizeAlgorithm(raw) {
  if (typeof raw !== 'string') return null;
  const value = raw.trim().toLowerCase();
  return value === 'ed25519' || value === 'hmac-sha256' ? value : null;
}

/**
 * Load tenant signing key map from inline JSON or a file path (`ASTRANULL_EVIDENCE_SIGNING_KEY`).
 * @param {NodeJS.ProcessEnv} env
 */
export function loadEvidenceSigningKeyMapEnv(env = process.env) {
  const inline = env.ASTRANULL_EVIDENCE_SIGNING_KEYS_JSON;
  if (inline !== undefined && inline !== null && String(inline).trim() !== '') {
    return parseEvidenceSigningKeyMap(env);
  }
  const keyFile = String(env.ASTRANULL_EVIDENCE_SIGNING_KEY ?? '').trim();
  if (keyFile !== '') {
    let raw;
    try {
      raw = readFileSync(keyFile, 'utf8');
    } catch (err) {
      throw new Error(`ASTRANULL_EVIDENCE_SIGNING_KEY file is unreadable: ${err?.message ?? 'read_failed'}`);
    }
    return parseEvidenceSigningKeyMap({ ASTRANULL_EVIDENCE_SIGNING_KEYS_JSON: raw });
  }
  return {};
}

function signEnvelopeLocally(envelope, material) {
  const message = Buffer.from(canonicalJsonStringify(envelope), 'utf8');
  if (material.algorithm === 'ed25519') {
    const signature = sign(null, message, material.privateKey);
    return signature.toString('base64');
  }
  return createHmac('sha256', material.secret).update(message).digest('base64');
}

/**
 * @param {NodeJS.ProcessEnv} env
 * @param {{ now?: () => Date }} [options]
 */
export function createEnvBackedEvidenceSigningAdapter(env = process.env, options = {}) {
  const envRef = env;
  return {
    mode: 'env',
    async resolveSigningKey({ tenantId, keyReference, algorithm }) {
      const normalizedAlgorithm = normalizeAlgorithm(algorithm);
      const normalizedReference = typeof keyReference === 'string' ? keyReference.trim() : '';
      if (!isValidKeyReference(normalizedReference)) {
        return { error: 'invalid_key_reference', status: 400 };
      }
      if (!normalizedAlgorithm) {
        return { error: 'invalid_algorithm', status: 400 };
      }
      let keyMap;
      try {
        keyMap = loadEvidenceSigningKeyMapEnv(envRef);
      } catch (err) {
        return { error: 'invalid_signing_key_config', status: 500, detail: err.message };
      }
      const material = resolveTenantSigningMaterial({
        tenantId,
        keyReference: normalizedReference,
        algorithm: normalizedAlgorithm,
        env: { ...envRef, ASTRANULL_EVIDENCE_SIGNING_KEYS_JSON: JSON.stringify(keyMap) },
      });
      if (material.error) {
        return { error: material.error, status: material.status ?? 400 };
      }
      return {
        algorithm: normalizedAlgorithm,
        keyReference: normalizedReference,
        publicKeyFingerprintSha256: material.publicKeyFingerprintSha256,
        source: 'env',
      };
    },
    async signDigest({ tenantId, algorithm, digest, keyReference }) {
      const normalizedAlgorithm = normalizeAlgorithm(algorithm);
      const normalizedReference = typeof keyReference === 'string' ? keyReference.trim() : '';
      const digestHex = String(digest ?? '');
      if (!SHA256_HEX_RE.test(digestHex)) {
        return { error: 'custody_manifest_digest_invalid', status: 400 };
      }
      if (!isValidKeyReference(normalizedReference)) {
        return { error: 'invalid_key_reference', status: 400 };
      }
      if (!normalizedAlgorithm) {
        return { error: 'invalid_algorithm', status: 400 };
      }
      let keyMap;
      try {
        keyMap = loadEvidenceSigningKeyMapEnv(envRef);
      } catch (err) {
        return { error: 'invalid_signing_key_config', status: 500, detail: err.message };
      }
      const material = resolveTenantSigningMaterial({
        tenantId,
        keyReference: normalizedReference,
        algorithm: normalizedAlgorithm,
        env: { ...envRef, ASTRANULL_EVIDENCE_SIGNING_KEYS_JSON: JSON.stringify(keyMap) },
      });
      if (material.error) {
        return { error: material.error, status: material.status ?? 400 };
      }
      const envelope = buildCustodySigningEnvelope({
        tenantId,
        custodyManifestDigest: digestHex,
      });
      const signature = signEnvelopeLocally(envelope, material);
      return {
        signature,
        publicKeyFingerprintSha256: material.publicKeyFingerprintSha256,
        source: 'env',
      };
    },
  };
}

/**
 * @param {{
 *   endpoint: string,
 *   env?: NodeJS.ProcessEnv,
 *   fetchFn?: typeof fetch,
 *   fetchTimeoutMs?: number,
 * }} config
 */
export function createExternalKmsEvidenceSigningAdapter(config) {
  const endpoint = String(config.endpoint ?? '').trim().replace(/\/+$/, '');
  const envRef = config.env ?? process.env;
  const fetchFn = config.fetchFn ?? globalThis.fetch;
  const fetchTimeoutMs = Number(config.fetchTimeoutMs ?? envRef.ASTRANULL_KMS_SIGNING_FETCH_TIMEOUT_MS ?? DEFAULT_KMS_FETCH_TIMEOUT_MS);

  async function callKms(path, body) {
    if (!endpoint) {
      return { error: 'kms_signing_not_configured', status: 503 };
    }
    if (typeof fetchFn !== 'function') {
      return { error: 'kms_signing_unavailable', status: 503, detail: 'fetch_unavailable' };
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), fetchTimeoutMs);
    let res;
    try {
      res = await fetchFn(`${endpoint}${path}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', accept: 'application/json' },
        body: JSON.stringify(body),
        signal: controller.signal,
        redirect: 'manual',
      });
    } catch (err) {
      return {
        error: 'kms_signing_unavailable',
        status: 503,
        detail: err?.name === 'AbortError' ? 'timeout' : 'network_error',
      };
    } finally {
      clearTimeout(timer);
    }
    if (!res.ok) {
      return { error: 'kms_signing_unavailable', status: 503, detail: `http_${res.status}` };
    }
    let parsed;
    try {
      parsed = await res.json();
    } catch {
      return { error: 'kms_signing_response_invalid', status: 502 };
    }
    return { body: parsed };
  }

  return {
    mode: 'kms',
    endpoint,
    async resolveSigningKey({ tenantId, keyReference, algorithm }) {
      const normalizedAlgorithm = normalizeAlgorithm(algorithm);
      const normalizedReference = typeof keyReference === 'string' ? keyReference.trim() : '';
      if (!isValidKeyReference(normalizedReference)) {
        return { error: 'invalid_key_reference', status: 400 };
      }
      if (!normalizedAlgorithm) {
        return { error: 'invalid_algorithm', status: 400 };
      }
      const kmsResult = await callKms('/v1/signing-keys/resolve', {
        tenant_id: tenantId,
        key_reference: normalizedReference,
        algorithm: normalizedAlgorithm,
      });
      if (kmsResult.error) {
        return kmsResult;
      }
      const body = kmsResult.body;
      const fingerprint = typeof body?.public_key_fingerprint_sha256 === 'string'
        ? body.public_key_fingerprint_sha256.trim()
        : '';
      if (!SHA256_HEX_RE.test(fingerprint)) {
        return { error: 'kms_signing_response_invalid', status: 502 };
      }
      return {
        algorithm: normalizedAlgorithm,
        keyReference: normalizedReference,
        publicKeyFingerprintSha256: fingerprint,
        source: 'kms',
      };
    },
    async signDigest({ tenantId, algorithm, digest, keyReference }) {
      const normalizedAlgorithm = normalizeAlgorithm(algorithm);
      const normalizedReference = typeof keyReference === 'string' ? keyReference.trim() : '';
      const digestHex = String(digest ?? '');
      if (!SHA256_HEX_RE.test(digestHex)) {
        return { error: 'custody_manifest_digest_invalid', status: 400 };
      }
      if (!isValidKeyReference(normalizedReference)) {
        return { error: 'invalid_key_reference', status: 400 };
      }
      if (!normalizedAlgorithm) {
        return { error: 'invalid_algorithm', status: 400 };
      }
      const kmsResult = await callKms('/v1/sign', {
        tenant_id: tenantId,
        key_reference: normalizedReference,
        algorithm: normalizedAlgorithm,
        digest: digestHex,
      });
      if (kmsResult.error) {
        return kmsResult;
      }
      const body = kmsResult.body;
      const signature = typeof body?.signature === 'string' ? body.signature.trim() : '';
      const fingerprint = typeof body?.public_key_fingerprint_sha256 === 'string'
        ? body.public_key_fingerprint_sha256.trim()
        : '';
      if (signature === '' || !SHA256_HEX_RE.test(fingerprint)) {
        return { error: 'kms_signing_response_invalid', status: 502 };
      }
      return {
        signature,
        publicKeyFingerprintSha256: fingerprint,
        source: 'kms',
      };
    },
  };
}

/**
 * Select env-backed or external KMS signing adapter.
 * @param {{ env?: NodeJS.ProcessEnv, fetchFn?: typeof fetch, fetchTimeoutMs?: number }} [options]
 */
export function createEvidenceSigningKmsAdapter(options = {}) {
  const env = options.env ?? process.env;
  const endpoint = String(env.ASTRANULL_KMS_SIGNING_ENDPOINT ?? '').trim();
  if (endpoint) {
    return createExternalKmsEvidenceSigningAdapter({
      endpoint,
      env,
      fetchFn: options.fetchFn,
      fetchTimeoutMs: options.fetchTimeoutMs,
    });
  }
  return createEnvBackedEvidenceSigningAdapter(env, options);
}