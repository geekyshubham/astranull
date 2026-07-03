import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { afterEach, describe, it } from 'node:test';
import { buildCustodyManifest, CUSTODY_SCHEMA_VERSION } from '../../src/lib/custody.mjs';
import {
  buildCustodySigningEnvelope,
  buildSignableCustodyManifestMetadata,
  digestCustodyManifestMetadata,
  signCustodyManifestMetadata,
  verifyCustodyManifestSignature,
} from '../../src/lib/evidenceSigning.mjs';
import { signEvidenceSnapshotCustody } from '../../src/services/evidenceSnapshotSigning.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';
import {
  computeSnapshotHash,
  validateEvidenceSnapshotBatch,
  validateSnapshotSignature,
} from '../../scripts/evidence-snapshot-manifest.mjs';

const TENANT = 'ten_a';
const KEY_REF = 'key://vault/astranull/evidence-signing/staging';
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
    artifact_id: 'rpt_sign_1',
    format: 'json',
    created_by: 'usr_soc',
    content: { report_id: 'rpt_sign_1', title: 'Signed export' },
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
  freshStore();
});

describe('evidence signing library', () => {
  it('digests metadata-only custody manifests', () => {
    const custody = custodyManifest();
    const digestResult = digestCustodyManifestMetadata(custody);
    assert.equal(digestResult.ok, true);
    assert.match(digestResult.digest, /^[a-f0-9]{64}$/);
    assert.equal(digestResult.signable.schema_version, CUSTODY_SCHEMA_VERSION);
    assert.throws(
      () => buildSignableCustodyManifestMetadata({ ...custody, payload: { secret: true } }),
      /forbidden custody field/,
    );
  });

  it('signs custody manifest metadata with tenant-scoped Ed25519 key reference', () => {
    const env = signingEnv();
    const custody = custodyManifest();
    const signed = signCustodyManifestMetadata({
      tenantId: TENANT,
      custody,
      keyReference: KEY_REF,
      algorithm: 'ed25519',
      env,
      now: () => new Date('2026-07-03T12:01:00.000Z'),
    });
    assert.equal(signed.error, undefined);
    assert.equal(signed.signed.algorithm, 'ed25519');
    assert.equal(signed.signed.key_reference, KEY_REF);
    assert.equal(signed.signed.signed_at, '2026-07-03T12:01:00.000Z');
    assert.match(signed.signed.signature, /^[A-Za-z0-9+/]+={0,2}$/);

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

  it('signs custody manifest metadata with tenant-scoped HMAC-SHA256 key reference', () => {
    const env = signingEnv();
    const custody = custodyManifest({ artifact_id: 'rpt_hmac_1' });
    const signed = signCustodyManifestMetadata({
      tenantId: TENANT,
      custody,
      keyReference: HMAC_KEY_REF,
      algorithm: 'hmac-sha256',
      env,
    });
    assert.equal(signed.error, undefined);
    assert.equal(signed.signed.algorithm, 'hmac-sha256');
    const verification = verifyCustodyManifestSignature({
      tenantId: TENANT,
      custodyManifestDigest: signed.signed.custody_manifest_digest,
      signer: {
        key_reference: HMAC_KEY_REF,
        algorithm: 'hmac-sha256',
        signature: signed.signed.signature,
      },
      env,
    });
    assert.deepEqual(verification, { ok: true });
  });

  it('rejects tenant mismatch and unknown key references', () => {
    const env = signingEnv();
    const custody = custodyManifest();
    const mismatch = signCustodyManifestMetadata({
      tenantId: 'ten_other',
      custody,
      keyReference: KEY_REF,
      algorithm: 'ed25519',
      env,
    });
    assert.equal(mismatch.error, 'tenant_id_mismatch');

    const unknown = signCustodyManifestMetadata({
      tenantId: TENANT,
      custody,
      keyReference: 'key://vault/astranull/evidence-signing/missing',
      algorithm: 'ed25519',
      env,
    });
    assert.equal(unknown.error, 'unknown_signing_key_reference');
  });

  it('rejects tampered signatures during verification', () => {
    const env = signingEnv();
    const custody = custodyManifest({ artifact_id: 'rpt_tamper' });
    const signed = signCustodyManifestMetadata({
      tenantId: TENANT,
      custody,
      keyReference: KEY_REF,
      algorithm: 'ed25519',
      env,
    });
    const tampered = Buffer.from(signed.signed.signature, 'base64');
    tampered[0] ^= 0xff;
    const verification = verifyCustodyManifestSignature({
      tenantId: TENANT,
      custodyManifestDigest: signed.signed.custody_manifest_digest,
      signer: {
        key_reference: KEY_REF,
        algorithm: 'ed25519',
        signature: tampered.toString('base64'),
      },
      env,
    });
    assert.equal(verification.ok, false);
    assert.equal(verification.error, 'signature_verification_failed');
  });

  it('builds deterministic signing envelopes from custody digests', () => {
    const envelope = buildCustodySigningEnvelope({
      tenantId: TENANT,
      custodyManifestDigest: 'a'.repeat(64),
    });
    assert.equal(envelope.tenant_id, TENANT);
    assert.equal(envelope.custody_manifest_digest, 'a'.repeat(64));
    assert.equal(envelope.schema_version, CUSTODY_SCHEMA_VERSION);
  });
});

describe('evidence snapshot signing service', () => {
  it('audits metadata-only evidence.snapshot_signed events', async () => {
    Object.assign(process.env, signingEnv());
    const ctx = { tenantId: TENANT, userId: 'usr_soc', role: 'soc' };
    const result = await signEvidenceSnapshotCustody(ctx, {
      custody: custodyManifest(),
      key_reference: KEY_REF,
      algorithm: 'ed25519',
    });
    assert.equal(result.error, undefined);
    const auditEntry = getStore().auditLog.find((entry) => entry.action === 'evidence.snapshot_signed');
    assert.ok(auditEntry);
    assert.equal(auditEntry.metadata.custody_manifest_digest, result.signed.custody_manifest_digest);
    assert.equal(auditEntry.metadata.algorithm, 'ed25519');
    assert.equal('signature' in (auditEntry.metadata ?? {}), false);
  });
});

describe('evidence snapshot manifest signature verification', () => {
  function snapshotWithSignature(signature, digest) {
    const base = {
      snapshot_id: 'snap_2026_07_03_001',
      custody_manifest_digest: digest,
      storage_reference: 'evidence://immutable/tenant-a/2026-07-03/snap-001',
      retention_policy: {
        metadata_retention_days: 90,
        report_days: 365,
        audit_log_days: 2555,
        legal_hold: false,
      },
      signer: {
        key_reference: KEY_REF,
        algorithm: 'ed25519',
        signature_reference: 'evidence://signatures/staging/snap-001',
        signature,
      },
      previous_snapshot_hash: null,
      operator_signoff: {
        operator: 'custody-operator',
        signed_at: '2026-07-03T12:00:00.000Z',
        signoff_reference: 'signoff://custody/snapshot-batch-2026-07-03',
      },
    };
    return { ...base, snapshot_hash: computeSnapshotHash(base) };
  }

  it('accepts batches with valid signer.signature values', () => {
    const env = signingEnv();
    Object.assign(process.env, env);
    const custody = custodyManifest();
    const signed = signCustodyManifestMetadata({
      tenantId: TENANT,
      custody,
      keyReference: KEY_REF,
      algorithm: 'ed25519',
      env,
    });
    const batch = {
      schema_version: 1,
      artifact_type: 'immutable_evidence_snapshot_batch',
      tenant_id: TENANT,
      batch_id: 'snapbatch_2026_07_03',
      snapshots: [snapshotWithSignature(signed.signed.signature, signed.signed.custody_manifest_digest)],
    };
    const validation = validateEvidenceSnapshotBatch(batch);
    assert.equal(validation.ok, true, validation.gaps.join(', '));
  });

  it('reports signature verification gaps for invalid signatures', () => {
    const env = signingEnv();
    const custody = custodyManifest();
    const signed = signCustodyManifestMetadata({
      tenantId: TENANT,
      custody,
      keyReference: KEY_REF,
      algorithm: 'ed25519',
      env,
    });
    const gaps = validateSnapshotSignature({
      tenantId: TENANT,
      snapshot: snapshotWithSignature('invalid-signature', signed.signed.custody_manifest_digest),
      index: 0,
      env,
    });
    assert.ok(gaps.some((gap) => gap.endsWith('signature_verification_failed')));
  });
});