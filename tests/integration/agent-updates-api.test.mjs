import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { buildAgentPackage } from '../../scripts/package-agent.mjs';
import { createServer } from '../../src/server.mjs';
import { createBootstrapToken } from '../../src/services/tokens.mjs';
import { agentHeaders, demoHeaders, request } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';
import { getStore } from '../../src/store.mjs';

const SHA = 'b'.repeat(64);
const SIGNATURE = 'c2lnYXR1cmU=';

function ed25519PrivateKeyBase64Der() {
  const { privateKey } = generateKeyPairSync('ed25519');
  return privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');
}

function signedAgentPackage(version, signingPrivateKeyBase64) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'astranull-aup-api-'));
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

function manifest(version) {
  return {
    package: 'astranull-agent',
    version,
    artifact: {
      name: `astranull-agent-${version}.tar.gz`,
      sha256: SHA,
      size: 16384,
    },
    signing: { signed: true },
  };
}

function releaseBody(version = '2.0.0', rollbackVersion = '1.0.0') {
  const signingKey = ed25519PrivateKeyBase64Der();
  const primary = signedAgentPackage(version, signingKey);
  const rollback = signedAgentPackage(rollbackVersion, signingKey);
  return {
    version,
    channel: 'stable',
    manifest: primary.manifest,
    signature: primary.signature,
    distribution: distributionForVersion(version),
    rollout: { percentage: 100, agent_ids: [] },
    rollback: {
      version: rollbackVersion,
      manifest: rollback.manifest,
      signature: rollback.signature,
      distribution: distributionForVersion(rollbackVersion),
    },
  };
}

async function registerTrustKeyForRelease(headers, body) {
  const res = await request(baseUrl, 'POST', '/v1/agent-update-trust-keys', {
    headers,
    body: { public_key_der_base64: body.manifest.signing.public_key_der_base64 },
  });
  assert.equal(res.status, 201);
  return res.json.trust_key;
}

async function createTrustedRelease(headers, version, rollbackVersion) {
  const body = releaseBody(version, rollbackVersion);
  await registerTrustKeyForRelease(headers, body);
  return request(baseUrl, 'POST', '/v1/agent-updates', { headers, body });
}

let baseUrl;
let server;

async function registerAgent(tenant = 'ten_demo', tg = 'tg_1') {
  const ctx = { tenantId: tenant, userId: 'u1', role: 'admin' };
  const { secret } = createBootstrapToken(ctx, { target_group_id: tg, max_registrations: 5 });
  const reg = await request(baseUrl, 'POST', '/v1/agents/register', {
    headers: demoHeaders('admin', tenant),
    body: { bootstrap_token: secret, hostname: 'upd-host', capabilities: ['heartbeat'] },
  });
  assert.equal(reg.status, 201);
  return { agentId: reg.json.agent.id, credential: reg.json.agent_credential };
}

before(() => {
  freshStore();
  server = createServer();
  server.listen(0);
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(() => server.close());

describe('agent updates API', () => {
  it('admin can create and list releases; viewer cannot create', async () => {
    const admin = demoHeaders('admin');
    const created = await createTrustedRelease(admin, '2.0.0');
    assert.equal(created.status, 201);
    assert.equal(created.json.release.version, '2.0.0');
    assert.match(created.json.release.id, /^aup_[a-f0-9]{16}$/);
    assert.ok(created.json.release.manifest.artifact.size > 0);
    assert.deepEqual(created.json.release.distribution, distributionForVersion('2.0.0'));

    const list = await request(baseUrl, 'GET', '/v1/agent-updates', { headers: admin });
    assert.equal(list.status, 200);
    assert.equal(list.json.items.length, 1);
    assert.deepEqual(list.json.items[0].distribution, distributionForVersion('2.0.0'));

    const viewerBody = releaseBody('2.1.0');
    await registerTrustKeyForRelease(admin, viewerBody);
    const viewer = await request(baseUrl, 'POST', '/v1/agent-updates', {
      headers: demoHeaders('viewer'),
      body: viewerBody,
    });
    assert.equal(viewer.status, 403);
  });

  it('admin can manage trust keys; viewer cannot create trust keys', async () => {
    const admin = demoHeaders('admin');
    const body = releaseBody('7.0.0', '6.0.0');
    const created = await request(baseUrl, 'POST', '/v1/agent-update-trust-keys', {
      headers: admin,
      body: { public_key_der_base64: body.manifest.signing.public_key_der_base64, name: 'ci key' },
    });
    assert.equal(created.status, 201);
    assert.match(created.json.trust_key.id, /^autk_[a-f0-9]{16}$/);

    const list = await request(baseUrl, 'GET', '/v1/agent-update-trust-keys', { headers: admin });
    assert.equal(list.status, 200);
    assert.ok(list.json.items.some((k) => k.id === created.json.trust_key.id));

    const viewerCreate = await request(baseUrl, 'POST', '/v1/agent-update-trust-keys', {
      headers: demoHeaders('viewer'),
      body: { public_key_der_base64: body.manifest.signing.public_key_der_base64 },
    });
    assert.equal(viewerCreate.status, 403);

    const revoked = await request(baseUrl, 'POST', `/v1/agent-update-trust-keys/${created.json.trust_key.id}/revoke`, {
      headers: admin,
    });
    assert.equal(revoked.status, 200);
    assert.equal(revoked.json.trust_key.status, 'revoked');
  });

  it('rejects signed releases when signing key is not trusted', async () => {
    const admin = demoHeaders('admin');
    const rejected = await request(baseUrl, 'POST', '/v1/agent-updates', {
      headers: admin,
      body: releaseBody('8.0.0'),
    });
    assert.equal(rejected.status, 400);
    assert.equal(rejected.json.error, 'untrusted_signing_key');
  });

  it('rejects production-incomplete manifests at the API boundary', async () => {
    const admin = demoHeaders('admin');
    const missingSig = await request(baseUrl, 'POST', '/v1/agent-updates', {
      headers: admin,
      body: {
        version: '5.0.0',
        manifest: manifest('5.0.0'),
        rollout: { percentage: 100 },
      },
    });
    assert.equal(missingSig.status, 400);
    assert.equal(missingSig.json.error, 'missing_signature');

    const unsafeManifest = manifest('5.1.0');
    unsafeManifest.artifact.name = '/tmp/pkg.tar.gz';
    const unsafe = await request(baseUrl, 'POST', '/v1/agent-updates', {
      headers: admin,
      body: {
        version: '5.1.0',
        manifest: unsafeManifest,
        signature: SIGNATURE,
        rollout: { percentage: 100 },
      },
    });
    assert.equal(unsafe.status, 400);
    assert.equal(unsafe.json.error, 'invalid_artifact_name');
  });

  it('rejects tampered or unsigned signing metadata at the API boundary', async () => {
    const admin = demoHeaders('admin');
    const signed = releaseBody('6.0.0');
    await registerTrustKeyForRelease(admin, signed);
    const noKey = await request(baseUrl, 'POST', '/v1/agent-updates', {
      headers: admin,
      body: {
        ...signed,
        manifest: { ...signed.manifest, signing: { signed: true } },
      },
    });
    assert.equal(noKey.status, 400);
    assert.equal(noKey.json.error, 'missing_signing_public_key');

    const tampered = await request(baseUrl, 'POST', '/v1/agent-updates', {
      headers: admin,
      body: {
        ...signed,
        manifest: {
          ...signed.manifest,
          artifact: { ...signed.manifest.artifact, sha256: 'd'.repeat(64) },
        },
      },
    });
    assert.equal(tampered.status, 400);
    assert.equal(tampered.json.error, 'signature_verification_failed');
  });

  it('agent polls with credential and ack updates installed version', async () => {
    const admin = demoHeaders('admin');
    const { agentId, credential } = await registerAgent();
    const created = await createTrustedRelease(admin, '3.0.0');
    const releaseId = created.json.release.id;

    const poll = await request(baseUrl, 'GET', `/v1/agents/${agentId}/update`, {
      headers: agentHeaders(credential),
    });
    assert.equal(poll.status, 200);
    assert.equal(poll.json.update.action, 'upgrade');
    assert.equal(poll.json.update.version, '3.0.0');
    assert.equal(poll.json.update.manifest.artifact.name, 'astranull-agent-3.0.0.tar.gz');
    assert.deepEqual(poll.json.update.download, distributionForVersion('3.0.0'));

    const ack = await request(baseUrl, 'POST', `/v1/agents/${agentId}/update-status`, {
      headers: agentHeaders(credential),
      body: {
        release_id: releaseId,
        status: 'applied',
        action: 'upgrade',
        installed_version: '3.0.0',
      },
    });
    assert.equal(ack.status, 201);
    assert.match(ack.json.status.id, /^aus_[a-f0-9]{16}$/);
    const agent = getStore().agents.find((a) => a.id === agentId);
    assert.equal(agent.version, '3.0.0');
  });

  it('rollback action only after applied status', async () => {
    const admin = demoHeaders('admin');
    const { agentId, credential } = await registerAgent();
    const created = await createTrustedRelease(admin, '4.0.0');
    const releaseId = created.json.release.id;

    const rollbackEarly = await request(baseUrl, 'POST', `/v1/agent-updates/${releaseId}/rollback`, {
      headers: admin,
    });
    assert.equal(rollbackEarly.status, 200);

    const pollBefore = await request(baseUrl, 'GET', `/v1/agents/${agentId}/update`, {
      headers: agentHeaders(credential),
    });
    assert.equal(pollBefore.json.update?.action, 'upgrade');

    await request(baseUrl, 'POST', `/v1/agents/${agentId}/update-status`, {
      headers: agentHeaders(credential),
      body: {
        release_id: releaseId,
        status: 'applied',
        installed_version: '4.0.0',
        action: 'upgrade',
      },
    });

    const pollRollback = await request(baseUrl, 'GET', `/v1/agents/${agentId}/update`, {
      headers: agentHeaders(credential),
    });
    assert.equal(pollRollback.json.update.action, 'rollback');
    assert.equal(pollRollback.json.update.version, '1.0.0');
    assert.deepEqual(pollRollback.json.update.download, distributionForVersion('1.0.0'));
  });

  it('rejects invalid distribution at the API boundary', async () => {
    const admin = demoHeaders('admin');
    const body = releaseBody('10.0.0');
    await registerTrustKeyForRelease(admin, body);
    const missing = await request(baseUrl, 'POST', '/v1/agent-updates', {
      headers: admin,
      body: { ...body, distribution: undefined },
    });
    assert.equal(missing.status, 400);
    assert.equal(missing.json.error, 'missing_distribution');

    const badHttp = await request(baseUrl, 'POST', '/v1/agent-updates', {
      headers: admin,
      body: {
        ...body,
        distribution: {
          ...distributionForVersion('10.0.0'),
          artifact_url: 'http://cdn.example.com/agent/10.0.0/astranull-agent-10.0.0.tar.gz',
        },
      },
    });
    assert.equal(badHttp.status, 400);
    assert.equal(badHttp.json.error, 'invalid_distribution_url');

    const malformedEncoding = await request(baseUrl, 'POST', '/v1/agent-updates', {
      headers: admin,
      body: {
        ...body,
        distribution: {
          ...distributionForVersion('10.0.0'),
          artifact_url: 'https://cdn.example.com/agent/10.0.0/%E0%A4%A.tar.gz',
        },
      },
    });
    assert.equal(malformedEncoding.status, 400);
    assert.equal(malformedEncoding.json.error, 'invalid_distribution_url');
  });

  it('isolates releases across tenants', async () => {
    getStore().tenants.push({ id: 'ten_other', name: 'Other' });
    getStore().environments.push({ id: 'env_other', tenant_id: 'ten_other', name: 'Other' });
    getStore().targetGroups.push({
      id: 'tg_other',
      tenant_id: 'ten_other',
      environment_id: 'env_other',
      name: 'TG',
    });

    const adminDemo = demoHeaders('admin', 'ten_demo');
    const created = await createTrustedRelease(adminDemo, '9.0.0');
    assert.equal(created.status, 201);

    const otherAdmin = demoHeaders('admin', 'ten_other', 'usr_other');
    const listOther = await request(baseUrl, 'GET', '/v1/agent-updates', { headers: otherAdmin });
    assert.equal(listOther.status, 200);
    assert.equal(listOther.json.items.length, 0);

    const listDemoKeys = await request(baseUrl, 'GET', '/v1/agent-update-trust-keys', { headers: adminDemo });
    const demoKeyId = listDemoKeys.json.items[0].id;
    const crossRevoke = await request(baseUrl, 'POST', `/v1/agent-update-trust-keys/${demoKeyId}/revoke`, {
      headers: otherAdmin,
    });
    assert.equal(crossRevoke.status, 404);

    const otherBody = releaseBody('9.1.0');
    const otherTrust = await request(baseUrl, 'POST', '/v1/agent-update-trust-keys', {
      headers: otherAdmin,
      body: { public_key_der_base64: otherBody.manifest.signing.public_key_der_base64 },
    });
    assert.equal(otherTrust.status, 201);
    const listTrustDemo = await request(baseUrl, 'GET', '/v1/agent-update-trust-keys', { headers: adminDemo });
    const listTrustOther = await request(baseUrl, 'GET', '/v1/agent-update-trust-keys', { headers: otherAdmin });
    assert.ok(listTrustDemo.json.items.some((k) => k.id === demoKeyId));
    assert.ok(listTrustOther.json.items.some((k) => k.id === otherTrust.json.trust_key.id));
    assert.equal(
      listTrustDemo.json.items.some((k) => k.id === otherTrust.json.trust_key.id),
      false,
    );
  });
});