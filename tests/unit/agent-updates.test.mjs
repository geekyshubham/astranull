import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it, beforeEach } from 'node:test';
import { buildAgentPackage } from '../../scripts/package-agent.mjs';
import { CHECK_CATALOG } from '../../src/contracts/checks.mjs';
import {
  createAgentUpdateRelease,
  createAgentUpdateTrustKey,
  isAgentInRollout,
  listAgentUpdateReleases,
  listAgentUpdateTrustKeys,
  pollAgentUpdate,
  recordAgentUpdateStatus,
  requestAgentUpdateRollback,
  revokeAgentUpdateTrustKey,
} from '../../src/services/agentUpdates.mjs';
import { getStore, resetStoreForTests } from '../../src/store.mjs';

const adminCtx = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };
const SHA = 'a'.repeat(64);
const SIGNATURE = 'c2lnYXR1cmU=';
const ROLLBACK_SIGNATURE = 'cm9sbGJhY2s=';

function ed25519PrivateKeyBase64Der() {
  const { privateKey } = generateKeyPairSync('ed25519');
  return privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');
}

function signedAgentPackage(version, signingPrivateKeyBase64) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'astranull-aup-unit-'));
  const result = buildAgentPackage({
    repoRoot: process.cwd(),
    outputDir: tmp,
    version,
    createdAt: '2026-07-01T12:00:00.000Z',
    signingPrivateKeyBase64,
  });
  const signature = result.signatureBase64 ?? fs.readFileSync(result.sigPath, 'utf8').trim();
  return { manifest: result.manifest, signature };
}

function distributionForVersion(version) {
  const name = `astranull-agent-${version}.tar.gz`;
  const base = `https://cdn.example.com/agent/${version}`;
  return {
    manifest_url: `${base}/manifest.json`,
    signature_url: `${base}/manifest.json.sig`,
    artifact_url: `${base}/${name}`,
  };
}

function manifest(version, artifactOverrides = {}) {
  return {
    package: 'astranull-agent',
    version,
    artifact: {
      name: `astranull-agent-${version}.tar.gz`,
      sha256: SHA,
      size: 8192,
      ...artifactOverrides,
    },
    signing: { signed: true },
  };
}

function releaseBody(overrides = {}) {
  const version = overrides.version ?? '2.0.0';
  const rollbackVersion = overrides.rollbackVersion ?? '1.0.0';
  const signingKey = overrides.signingPrivateKeyBase64 ?? ed25519PrivateKeyBase64Der();
  const primary = signedAgentPackage(version, signingKey);
  const rollbackPkg = signedAgentPackage(rollbackVersion, signingKey);
  const body = {
    version,
    channel: 'beta',
    manifest: primary.manifest,
    signature: primary.signature,
    distribution: distributionForVersion(version),
    rollout: { percentage: 100 },
    rollback: {
      version: rollbackVersion,
      manifest: rollbackPkg.manifest,
      signature: rollbackPkg.signature,
      distribution: distributionForVersion(rollbackVersion),
    },
  };
  if (overrides.rollback === null) {
    delete body.rollback;
  }
  return { ...body, ...overrides, manifest: overrides.manifest ?? body.manifest, signature: overrides.signature ?? body.signature };
}

function registerTrustKeyForBody(ctx, body) {
  const pub = body.manifest.signing.public_key_der_base64;
  const created = createAgentUpdateTrustKey(ctx, { public_key_der_base64: pub });
  assert.ok(created.trust_key, created.error);
  return created.trust_key;
}

function trustedReleaseBody(ctx, overrides = {}) {
  const body = releaseBody(overrides);
  registerTrustKeyForBody(ctx, body);
  if (body.rollback?.manifest?.signing?.public_key_der_base64) {
    const rbPub = body.rollback.manifest.signing.public_key_der_base64;
    const mainPub = body.manifest.signing.public_key_der_base64;
    if (rbPub !== mainPub) {
      createAgentUpdateTrustKey(ctx, { public_key_der_base64: rbPub });
    }
  }
  return body;
}

function baseAgent(overrides = {}) {
  return {
    id: 'agt_test001',
    tenant_id: 'ten_demo',
    environment_id: 'env_demo',
    target_group_id: 'tg_1',
    version: '1.0.0',
    ...overrides,
  };
}

function reset(data = {}) {
  process.env.ASTRANULL_NO_PERSIST = '1';
  resetStoreForTests({
    tenants: [{ id: 'ten_demo', name: 'Demo' }],
    environments: [{ id: 'env_demo', tenant_id: 'ten_demo', name: 'Prod' }],
    users: [],
    targetGroups: [],
    targets: [],
    bootstrapTokens: [],
    serviceAccounts: [],
    agents: [baseAgent()],
    agentJobs: [],
    probeJobs: [],
    testRuns: [],
    events: [],
    verdicts: [],
    findings: [],
    reports: [],
    highScaleRequests: [],
    socKillSwitch: { active: false },
    socNotes: [],
    evidenceVault: [],
    ingestedEventIds: {},
    notificationRules: [],
    notificationEvents: [],
    metrics: null,
    readiness: {},
    auditLog: [],
    checkCatalog: CHECK_CATALOG.map((c) => ({ ...c })),
    encryptedSecrets: [],
    agentUpdateReleases: [],
    agentUpdateStatuses: [],
    agentUpdateTrustKeys: [],
    ...data,
  });
}

describe('agent update releases', () => {
  beforeEach(() => reset());

  it('rejects invalid manifests and accepts a valid release', () => {
    const bad = createAgentUpdateRelease(adminCtx, {
      version: '2.0.0',
      signature: SIGNATURE,
      manifest: {
        package: 'other',
        version: '2.0.0',
        artifact: { name: 'astranull-agent-2.0.0.tar.gz', sha256: SHA, size: 1 },
        signing: { signed: true },
      },
    });
    assert.equal(bad.error, 'invalid_package');

    const unsigned = createAgentUpdateRelease(adminCtx, {
      version: '2.0.0',
      signature: SIGNATURE,
      manifest: {
        package: 'astranull-agent',
        version: '2.0.0',
        artifact: { name: 'astranull-agent-2.0.0.tar.gz', sha256: SHA, size: 1 },
        signing: { signed: false },
      },
    });
    assert.equal(unsigned.error, 'unsigned_manifest');

    const ok = createAgentUpdateRelease(adminCtx, trustedReleaseBody(adminCtx));
    assert.ok(ok.release);
    assert.equal(ok.release.version, '2.0.0');
    assert.equal(ok.release.channel, 'beta');
    assert.match(ok.release.id, /^aup_[a-f0-9]{16}$/);
    assert.equal(ok.release.manifest.artifact.name, 'astranull-agent-2.0.0.tar.gz');
    assert.ok(ok.release.manifest.artifact.size > 0);
    assert.equal(listAgentUpdateReleases(adminCtx).length, 1);
    assert.deepEqual(ok.release.distribution, distributionForVersion('2.0.0'));
    assert.deepEqual(ok.release.rollback.distribution, distributionForVersion('1.0.0'));
  });

  it('rejects missing or invalid detached signatures and unsafe artifacts', () => {
    const noSig = createAgentUpdateRelease(adminCtx, {
      version: '2.0.0',
      manifest: manifest('2.0.0'),
      rollout: { percentage: 100 },
    });
    assert.equal(noSig.error, 'missing_signature');

    const badSig = createAgentUpdateRelease(adminCtx, {
      version: '2.0.0',
      manifest: manifest('2.0.0'),
      signature: 'not!!!base64',
      rollout: { percentage: 100 },
    });
    assert.equal(badSig.error, 'invalid_signature');

    const noSize = createAgentUpdateRelease(adminCtx, {
      version: '2.0.0',
      manifest: manifest('2.0.0', { size: 0 }),
      signature: SIGNATURE,
    });
    assert.equal(noSize.error, 'invalid_artifact_size');

    const noName = createAgentUpdateRelease(adminCtx, {
      version: '2.0.0',
      manifest: manifest('2.0.0', { name: '' }),
      signature: SIGNATURE,
    });
    assert.equal(noName.error, 'invalid_artifact_name');

    const unsafeName = createAgentUpdateRelease(adminCtx, {
      version: '2.0.0',
      manifest: manifest('2.0.0', { name: '../evil.tar.gz' }),
      signature: SIGNATURE,
    });
    assert.equal(unsafeName.error, 'invalid_artifact_name');

    const signedPrimary = trustedReleaseBody(adminCtx, { version: '2.0.0', rollback: null });
    const noRollbackSig = createAgentUpdateRelease(adminCtx, {
      ...signedPrimary,
      rollback: { version: '1.0.0', manifest: manifest('1.0.0') },
    });
    assert.equal(noRollbackSig.error, 'missing_rollback_signature');
  });

  it('rejects manifests without a signing public key or with failed Ed25519 verification', () => {
    const body = releaseBody({ rollback: null });
    const noKey = createAgentUpdateRelease(adminCtx, {
      ...body,
      manifest: { ...body.manifest, signing: { signed: true } },
    });
    assert.equal(noKey.error, 'missing_signing_public_key');

    const tampered = createAgentUpdateRelease(adminCtx, {
      ...body,
      manifest: {
        ...body.manifest,
        artifact: { ...body.manifest.artifact, sha256: 'f'.repeat(64) },
      },
    });
    assert.equal(tampered.error, 'signature_verification_failed');
  });

  it('rejects rollback packages that fail cryptographic verification', () => {
    const body = trustedReleaseBody(adminCtx);
    const tamperedRollback = createAgentUpdateRelease(adminCtx, {
      ...body,
      rollback: {
        ...body.rollback,
        manifest: {
          ...body.rollback.manifest,
          artifact: { ...body.rollback.manifest.artifact, sha256: 'e'.repeat(64) },
        },
      },
    });
    assert.equal(tamperedRollback.error, 'invalid_rollback_signature');
  });

  it('deterministic rollout percentage and filters', () => {
    const agent = baseAgent({ id: 'agt_roll', version: '1.0.0' });
    reset({ agents: [agent] });
    createAgentUpdateRelease(adminCtx, {
      ...trustedReleaseBody(adminCtx, { version: '2.0.0', rollback: null }),
      rollout: { percentage: 50 },
    });
    const release = listAgentUpdateReleases(adminCtx)[0];
    const inRollout = isAgentInRollout(agent, {
      tenant_id: 'ten_demo',
      version: '2.0.0',
      rollout: release.rollout,
    });
    const repeat = isAgentInRollout(agent, {
      tenant_id: 'ten_demo',
      version: '2.0.0',
      rollout: release.rollout,
    });
    assert.equal(inRollout, repeat);

    assert.equal(
      isAgentInRollout(agent, { tenant_id: 'ten_demo', version: '2.0.0', rollout: { percentage: 0 } }),
      false,
    );
    assert.equal(
      isAgentInRollout(agent, { tenant_id: 'ten_demo', version: '2.0.0', rollout: { percentage: 100 } }),
      true,
    );
    assert.equal(
      isAgentInRollout(agent, {
        tenant_id: 'ten_demo',
        version: '2.0.0',
        rollout: { percentage: 0, agent_ids: [agent.id] },
      }),
      true,
    );
    assert.equal(
      isAgentInRollout(agent, {
        tenant_id: 'ten_demo',
        version: '2.0.0',
        rollout: { percentage: 100, environment_ids: ['env_other'] },
      }),
      false,
    );
  });

  it('poll upgrade only when version differs and rollback only after applied', () => {
    const agent = baseAgent();
    const created = createAgentUpdateRelease(adminCtx, {
      ...trustedReleaseBody(adminCtx, { version: '2.0.0' }),
      rollout: { percentage: 100, agent_ids: [agent.id] },
    });
    const releaseId = created.release.id;

    let poll = pollAgentUpdate(agent);
    assert.equal(poll.update?.action, 'upgrade');
    assert.equal(poll.update.version, '2.0.0');
    assert.equal(poll.update.manifest.artifact.name, 'astranull-agent-2.0.0.tar.gz');
    assert.deepEqual(poll.update.download, distributionForVersion('2.0.0'));

    agent.version = '2.0.0';
    poll = pollAgentUpdate(agent);
    assert.equal(poll.update, null);

    requestAgentUpdateRollback(adminCtx, releaseId);
    poll = pollAgentUpdate(agent);
    assert.equal(poll.update, null);

    recordAgentUpdateStatus(agent, {
      release_id: releaseId,
      status: 'applied',
      action: 'upgrade',
      installed_version: '2.0.0',
    });
    poll = pollAgentUpdate(agent);
    assert.equal(poll.update?.action, 'rollback');
    assert.equal(poll.update.version, '1.0.0');
    assert.deepEqual(poll.update.download, distributionForVersion('1.0.0'));
  });

  it('rejects invalid hosted distribution URLs and artifact basename mismatch', () => {
    const trusted = trustedReleaseBody(adminCtx, { rollback: null });
    const missing = createAgentUpdateRelease(adminCtx, { ...trusted, distribution: undefined });
    assert.equal(missing.error, 'missing_distribution');

    const httpDist = createAgentUpdateRelease(adminCtx, {
      ...trusted,
      distribution: {
        ...distributionForVersion('2.0.0'),
        artifact_url: 'http://cdn.example.com/agent/2.0.0/astranull-agent-2.0.0.tar.gz',
      },
    });
    assert.equal(httpDist.error, 'invalid_distribution_url');

    const credDist = createAgentUpdateRelease(adminCtx, {
      ...trusted,
      distribution: {
        ...distributionForVersion('2.0.0'),
        manifest_url: 'https://user:pass@cdn.example.com/agent/2.0.0/manifest.json',
      },
    });
    assert.equal(credDist.error, 'invalid_distribution_url');

    const mismatch = createAgentUpdateRelease(adminCtx, {
      ...trusted,
      distribution: {
        ...distributionForVersion('2.0.0'),
        artifact_url: 'https://cdn.example.com/agent/2.0.0/wrong-name.tar.gz',
      },
    });
    assert.equal(mismatch.error, 'artifact_url_mismatch');

    const signedQuery = trustedReleaseBody(adminCtx);
    signedQuery.distribution.artifact_url =
      'https://cdn.example.com/agent/2.0.0/astranull-agent-2.0.0.tar.gz?X-Amz-Signature=abc';
    const withQuery = createAgentUpdateRelease(adminCtx, signedQuery);
    assert.ok(withQuery.release);
    assert.match(withQuery.release.distribution.artifact_url, /\?X-Amz-Signature=abc$/);

    const withRollback = trustedReleaseBody(adminCtx);
    const noRollbackDist = createAgentUpdateRelease(adminCtx, {
      ...withRollback,
      rollback: {
        version: withRollback.rollback.version,
        manifest: withRollback.rollback.manifest,
        signature: withRollback.rollback.signature,
      },
    });
    assert.equal(noRollbackDist.error, 'invalid_rollback_distribution');

    const badRollbackDist = createAgentUpdateRelease(adminCtx, {
      ...withRollback,
      rollback: {
        ...withRollback.rollback,
        distribution: {
          ...distributionForVersion('1.0.0'),
          artifact_url: 'http://cdn.example.com/agent/1.0.0/astranull-agent-1.0.0.tar.gz',
        },
      },
    });
    assert.equal(badRollbackDist.error, 'invalid_rollback_distribution');

    const malformedPathEncoding = createAgentUpdateRelease(adminCtx, {
      ...trusted,
      distribution: {
        ...distributionForVersion('2.0.0'),
        artifact_url: 'https://cdn.example.com/agent/2.0.0/%E0%A4%A.tar.gz',
      },
    });
    assert.equal(malformedPathEncoding.error, 'invalid_distribution_url');
    assert.equal(malformedPathEncoding.status, 400);

    const malformedRollbackEncoding = createAgentUpdateRelease(adminCtx, {
      ...withRollback,
      rollback: {
        ...withRollback.rollback,
        distribution: {
          ...distributionForVersion('1.0.0'),
          artifact_url: 'https://cdn.example.com/agent/1.0.0/%E0%A4%A.tar.gz',
        },
      },
    });
    assert.equal(malformedRollbackEncoding.error, 'invalid_rollback_distribution');
    assert.equal(malformedRollbackEncoding.status, 400);
  });

  it('audits release creation without distribution URLs', () => {
    createAgentUpdateRelease(adminCtx, trustedReleaseBody(adminCtx, { rollback: null }));
    const logged = getStore().auditLog.find((a) => a.action === 'agent_update.release_created');
    assert.ok(logged);
    const serialized = JSON.stringify(logged);
    assert.equal(serialized.includes('cdn.example.com'), false);
    assert.equal(serialized.includes('manifest_url'), false);
  });

  it('records status ledger, updates agent version, and audits without credentials', () => {
    const agent = baseAgent();
    const created = createAgentUpdateRelease(adminCtx, {
      ...trustedReleaseBody(adminCtx, { version: '2.0.0', rollback: null }),
      rollout: { percentage: 100 },
    });
    const result = recordAgentUpdateStatus(agent, {
      release_id: created.release.id,
      status: 'applied',
      installed_version: '2.0.0',
      action: 'upgrade',
    });
    assert.equal(result.status.status, 'applied');
    assert.match(result.status.id, /^aus_[a-f0-9]{16}$/);
    assert.equal(agent.version, '2.0.0');

    const logged = getStore().auditLog.find((a) => a.action === 'agent_update.status_recorded');
    assert.ok(logged);
    const serialized = JSON.stringify(logged);
    assert.equal(serialized.includes('credential'), false);
    assert.equal(serialized.includes('bootstrap'), false);
    assert.equal(serialized.includes('agc_'), false);
  });
});

describe('agent update trust keys', () => {
  beforeEach(() => reset());

  it('creates, lists, and revokes tenant trust keys', () => {
    const body = releaseBody({ rollback: null });
    const pub = body.manifest.signing.public_key_der_base64;
    const created = createAgentUpdateTrustKey(adminCtx, { name: 'prod signer', public_key_der_base64: pub });
    assert.ok(created.trust_key);
    assert.match(created.trust_key.id, /^autk_[a-f0-9]{16}$/);
    assert.equal(created.trust_key.name, 'prod signer');
    assert.match(created.trust_key.fingerprint_sha256, /^[a-f0-9]{64}$/);
    assert.equal(created.trust_key.status, 'active');
    assert.equal(listAgentUpdateTrustKeys(adminCtx).length, 1);

    const revoked = revokeAgentUpdateTrustKey(adminCtx, created.trust_key.id);
    assert.equal(revoked.trust_key.status, 'revoked');
    assert.ok(revoked.trust_key.revoked_at);
  });

  it('rejects duplicate active trust keys for the same fingerprint', () => {
    const body = releaseBody({ rollback: null });
    const pub = body.manifest.signing.public_key_der_base64;
    assert.ok(createAgentUpdateTrustKey(adminCtx, { public_key_der_base64: pub }).trust_key);
    const dup = createAgentUpdateTrustKey(adminCtx, { public_key_der_base64: pub });
    assert.equal(dup.error, 'duplicate_trust_key');
    assert.equal(dup.status, 409);
  });

  it('rejects release before trust registration and accepts after', () => {
    const body = releaseBody({ rollback: null });
    const untrusted = createAgentUpdateRelease(adminCtx, body);
    assert.equal(untrusted.error, 'untrusted_signing_key');

    registerTrustKeyForBody(adminCtx, body);
    const ok = createAgentUpdateRelease(adminCtx, body);
    assert.ok(ok.release);
  });

  it('rejects releases signed by a revoked trust key', () => {
    const body = releaseBody({ rollback: null });
    const key = registerTrustKeyForBody(adminCtx, body);
    revokeAgentUpdateTrustKey(adminCtx, key.id);
    const rejected = createAgentUpdateRelease(adminCtx, body);
    assert.equal(rejected.error, 'untrusted_signing_key');
  });

  it('rejects rollback manifest signed by an untrusted key', () => {
    const primaryKey = ed25519PrivateKeyBase64Der();
    const rollbackKey = ed25519PrivateKeyBase64Der();
    const primary = signedAgentPackage('2.0.0', primaryKey);
    const rollbackPkg = signedAgentPackage('1.0.0', rollbackKey);
    createAgentUpdateTrustKey(adminCtx, {
      public_key_der_base64: primary.manifest.signing.public_key_der_base64,
    });
    const rejected = createAgentUpdateRelease(adminCtx, {
      version: '2.0.0',
      manifest: primary.manifest,
      signature: primary.signature,
      distribution: distributionForVersion('2.0.0'),
      rollout: { percentage: 100 },
      rollback: {
        version: '1.0.0',
        manifest: rollbackPkg.manifest,
        signature: rollbackPkg.signature,
        distribution: distributionForVersion('1.0.0'),
      },
    });
    assert.equal(rejected.error, 'untrusted_signing_key');
  });

  it('audits trust key lifecycle with fingerprint only', () => {
    const body = releaseBody({ rollback: null });
    const created = createAgentUpdateTrustKey(adminCtx, {
      public_key_der_base64: body.manifest.signing.public_key_der_base64,
    });
    revokeAgentUpdateTrustKey(adminCtx, created.trust_key.id);

    const added = getStore().auditLog.find((a) => a.action === 'agent_update.trust_key_added');
    const revoked = getStore().auditLog.find((a) => a.action === 'agent_update.trust_key_revoked');
    assert.ok(added.metadata.fingerprint_sha256);
    assert.ok(revoked.metadata.fingerprint_sha256);
    for (const entry of [added, revoked]) {
      const serialized = JSON.stringify(entry);
      assert.equal(serialized.includes('private'), false);
      assert.equal(serialized.includes('agc_'), false);
      assert.equal(serialized.includes('ast_'), false);
    }
  });
});