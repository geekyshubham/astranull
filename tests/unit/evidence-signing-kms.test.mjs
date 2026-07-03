import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import { buildCustodyManifest } from '../../src/lib/custody.mjs';
import { signCustodyManifestMetadataAsync, verifyCustodyManifestSignature } from '../../src/lib/evidenceSigning.mjs';
import {
  createEnvBackedEvidenceSigningAdapter,
  createEvidenceSigningKmsAdapter,
  createExternalKmsEvidenceSigningAdapter,
  loadEvidenceSigningKeyMapEnv,
} from '../../src/lib/evidenceSigningKmsAdapter.mjs';
import { signEvidenceSnapshotCustody } from '../../src/services/evidenceSnapshotSigning.mjs';

const TENANT = 'ten_a';
const KEY_REF = 'key://vault/astranull/evidence-signing/staging';
const KMS_KEY_REF = 'key://vault/astranull/evidence-signing/kms-prod';
const HMAC_KEY_REF = 'key://vault/astranull/evidence-signing/hmac-dev';
const HMAC_SECRET = 'dev-only-hmac-secret-32-characters-min';
const envSnapshot = { ...process.env };

function restoreEnv() {
  for (const key of Object.keys(process.env)) {
    if (!(key in envSnapshot)) delete process.env[key];
  }
  Object.assign(process.env, envSnapshot);
}

function ed25519KeyMaterial() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return {
    private_key_pkcs8_der_base64: privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
    public_key_spki_der_base64: publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
  };
}

function custodyManifest(overrides = {}) {
  return buildCustodyManifest({
    tenant_id: TENANT,
    artifact_type: 'report_export',
    artifact_id: 'rpt_kms_1',
    format: 'json',
    created_by: 'usr_soc',
    content: { report_id: 'rpt_kms_1', title: 'KMS signed export' },
    created_at: '2026-07-03T12:00:00.000Z',
    ...overrides,
  });
}

function signingEnv(extra = {}) {
  const ed25519 = ed25519KeyMaterial();
  return {
    ASTRANULL_EVIDENCE_SIGNING_KEYS_JSON: JSON.stringify({
      [TENANT]: {
        [KEY_REF]: {
          algorithm: 'ed25519',
          private_key_pkcs8_der_base64: ed25519.private_key_pkcs8_der_base64,
        },
        [HMAC_KEY_REF]: {
          algorithm: 'hmac-sha256',
          secret: HMAC_SECRET,
        },
        ...extra,
      },
    }),
  };
}

afterEach(() => {
  restoreEnv();
});

describe('evidence signing KMS adapter', () => {
  it('loads signing key maps from inline JSON or ASTRANULL_EVIDENCE_SIGNING_KEY file path', () => {
    const env = signingEnv();
    const inline = loadEvidenceSigningKeyMapEnv(env);
    assert.ok(inline[TENANT][KEY_REF]);

    const dir = mkdtempSync(path.join(tmpdir(), 'astranull-signing-keys-'));
    const keyFile = path.join(dir, 'signing-keys.json');
    writeFileSync(keyFile, env.ASTRANULL_EVIDENCE_SIGNING_KEYS_JSON, 'utf8');
    const fromFile = loadEvidenceSigningKeyMapEnv({
      ASTRANULL_EVIDENCE_SIGNING_KEY: keyFile,
    });
    assert.deepEqual(fromFile, inline);
  });

  it('env-backed adapter resolveSigningKey and signDigest preserve local signatures', async () => {
    const env = signingEnv();
    const adapter = createEnvBackedEvidenceSigningAdapter(env);
    const custody = custodyManifest();
    const resolved = await adapter.resolveSigningKey({
      tenantId: TENANT,
      keyReference: KEY_REF,
      algorithm: 'ed25519',
    });
    assert.equal(resolved.error, undefined);
    assert.equal(resolved.source, 'env');
    assert.match(resolved.publicKeyFingerprintSha256, /^[a-f0-9]{64}$/);

    const signed = await signCustodyManifestMetadataAsync({
      tenantId: TENANT,
      custody,
      keyReference: KEY_REF,
      algorithm: 'ed25519',
      signingAdapter: adapter,
      now: () => new Date('2026-07-03T12:02:00.000Z'),
    });
    assert.equal(signed.error, undefined);
    assert.equal(signed.signed.signing_source, 'env');
    assert.equal(signed.signed.signed_at, '2026-07-03T12:02:00.000Z');

    const verification = verifyCustodyManifestSignature({
      tenantId: TENANT,
      custodyManifestDigest: signed.signed.custody_manifest_digest,
      signer: {
        key_reference: KEY_REF,
        algorithm: 'ed25519',
        signature: signed.signed.signature,
      },
      env,
    });
    assert.deepEqual(verification, { ok: true });
  });

  it('external KMS adapter fails closed when endpoint is unreachable', async () => {
    const adapter = createExternalKmsEvidenceSigningAdapter({
      endpoint: 'http://127.0.0.1:1',
      fetchTimeoutMs: 200,
    });
    const resolved = await adapter.resolveSigningKey({
      tenantId: TENANT,
      keyReference: KMS_KEY_REF,
      algorithm: 'ed25519',
    });
    assert.equal(resolved.error, 'kms_signing_unavailable');
    assert.equal(resolved.status, 503);

    const signed = await adapter.signDigest({
      tenantId: TENANT,
      algorithm: 'ed25519',
      digest: 'a'.repeat(64),
      keyReference: KMS_KEY_REF,
    });
    assert.equal(signed.error, 'kms_signing_unavailable');
    assert.equal(signed.status, 503);
  });

  it('external KMS adapter signs via remote endpoint contract', async () => {
    const env = signingEnv();
    const custody = custodyManifest({ artifact_id: 'rpt_kms_remote' });
    const localAdapter = createEnvBackedEvidenceSigningAdapter(env);
    const localSigned = await signCustodyManifestMetadataAsync({
      tenantId: TENANT,
      custody,
      keyReference: KEY_REF,
      algorithm: 'ed25519',
      signingAdapter: localAdapter,
    });
    assert.equal(localSigned.error, undefined);

    const fetchFn = async (url, init) => {
      const body = JSON.parse(String(init.body));
      if (String(url).endsWith('/v1/signing-keys/resolve')) {
        return {
          ok: true,
          async json() {
            return {
              public_key_fingerprint_sha256: localSigned.signed.public_key_fingerprint_sha256,
            };
          },
        };
      }
      if (String(url).endsWith('/v1/sign')) {
        assert.equal(body.tenant_id, TENANT);
        assert.equal(body.key_reference, KMS_KEY_REF);
        assert.equal(body.algorithm, 'ed25519');
        assert.match(body.digest, /^[a-f0-9]{64}$/);
        return {
          ok: true,
          async json() {
            return {
              signature: localSigned.signed.signature,
              public_key_fingerprint_sha256: localSigned.signed.public_key_fingerprint_sha256,
            };
          },
        };
      }
      return { ok: false, status: 404, async json() { return {}; } };
    };

    const kmsEnv = {
      ASTRANULL_KMS_SIGNING_ENDPOINT: 'https://kms.example.test',
      ...env,
    };
    const adapter = createEvidenceSigningKmsAdapter({ env: kmsEnv, fetchFn });
    assert.equal(adapter.mode, 'kms');

    const resolved = await adapter.resolveSigningKey({
      tenantId: TENANT,
      keyReference: KMS_KEY_REF,
      algorithm: 'ed25519',
    });
    assert.equal(resolved.error, undefined);
    assert.equal(resolved.source, 'kms');

    const signed = await signCustodyManifestMetadataAsync({
      tenantId: TENANT,
      custody,
      keyReference: KMS_KEY_REF,
      algorithm: 'ed25519',
      signingAdapter: adapter,
    });
    assert.equal(signed.error, undefined);
    assert.equal(signed.signed.signing_source, 'kms');
    assert.equal(signed.signed.signature, localSigned.signed.signature);
  });

  it('evidence snapshot signing service uses KMS adapter when endpoint is configured', async () => {
    const env = signingEnv();
    const custody = custodyManifest({ artifact_id: 'rpt_service_kms' });
    const localAdapter = createEnvBackedEvidenceSigningAdapter(env);
    const localSigned = await signCustodyManifestMetadataAsync({
      tenantId: TENANT,
      custody,
      keyReference: KEY_REF,
      algorithm: 'ed25519',
      signingAdapter: localAdapter,
    });

    const fetchFn = async (url) => {
      if (String(url).endsWith('/v1/sign')) {
        return {
          ok: true,
          async json() {
            return {
              signature: localSigned.signed.signature,
              public_key_fingerprint_sha256: localSigned.signed.public_key_fingerprint_sha256,
            };
          },
        };
      }
      return {
        ok: true,
        async json() {
          return {
            public_key_fingerprint_sha256: localSigned.signed.public_key_fingerprint_sha256,
          };
        },
      };
    };

    const result = await signEvidenceSnapshotCustody(
      { tenantId: TENANT, userId: 'usr_soc', role: 'soc' },
      {
        custody,
        key_reference: KEY_REF,
        algorithm: 'ed25519',
      },
      {
        env: {
          ...env,
          ASTRANULL_KMS_SIGNING_ENDPOINT: 'https://kms.example.test',
        },
        fetchFn,
      },
    );
    assert.equal(result.error, undefined);
    assert.equal(result.signed.signing_source, 'kms');
    assert.equal(result.signed.signature, localSigned.signed.signature);
  });
});