import assert from 'node:assert/strict';
import { execFile, execFileSync } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { promisify } from 'node:util';
import { createServer } from '../../src/server.mjs';
import { createBootstrapToken } from '../../src/services/tokens.mjs';
import { freshStore } from '../helpers/reset.mjs';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { buildAgentPackage } from '../../scripts/package-agent.mjs';
import {
  containsDisallowedObservationFields,
  createObservationStores,
  extractNonceHashFromLogLine,
  hashNonce,
  loadObservationFile,
  OBSERVATION_MODES,
  pollAndWork,
  pollAndMaybeApplyUpdate,
  runAgentDaemonCycle,
  readAgentCurrentReleaseRecord,
  resolveAgentExecutableFromCurrentRelease,
  filterAgentRestartArgv,
  sanitizeAgentRestartEnv,
  buildAgentRestartCommand,
  restartAgentProcessAfterUpdate,
  resolveAgentUpdateDaemonIntervalMs,
  AGENT_UPDATE_DAEMON_DEFAULT_INTERVAL_MS,
  AGENT_UPDATE_DAEMON_MIN_INTERVAL_MS,
  selectObservationForJob,
  startCanaryListener,
  startLogTail,
  applyAgentUpdatePackage,
  downloadAgentUpdateFile,
  downloadAndApplyAgentUpdatePackage,
  validateAgentControlPlaneUrl,
  validateAgentUpdateDownloadUrl,
  validateAgentUpdateInstallRoot,
  validateAgentUpdateManifest,
  validateAgentUpdateTarballEntries,
  verifyAgentUpdateManifest,
  verifyAgentUpdatePackageFiles,
  verifyPackageSignature,
  buildAgentRegistrationCapabilities,
} from '../../agents/linux/astranull-agent.mjs';
import {
  DEFAULT_COSIGN_SIGNER_REFERENCE,
  DEFAULT_GPG_KEY_REFERENCE,
  buildGpgSigningHook,
} from '../../scripts/package-agent.mjs';

const agentScript = path.join(process.cwd(), 'agents/linux/astranull-agent.mjs');
const nodeBin = process.execPath;
const execFileAsync = promisify(execFile);

function literalPattern(value) {
  return new RegExp(String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
}

let server;
let baseUrl;

before(() => {
  freshStore();
  server = createServer();
  server.listen(0);
  const { port } = server.address();
  baseUrl = `http://127.0.0.1:${port}`;
});

after(() => {
  server?.close();
});

describe('agent module import', () => {
  it('does not execute main on import', () => {
    assert.equal(typeof pollAndWork, 'function');
    assert.equal(typeof hashNonce, 'function');
  });
});

describe('agent observation helpers', () => {
  it('hashes nonce as sha256 hex fingerprint', () => {
    const h = hashNonce('test-nonce-value');
    assert.match(h, /^sha256:[a-f0-9]{64}$/);
    assert.equal(h, hashNonce('test-nonce-value'));
  });

  it('loads packet metadata and mirror JSONL into mode-specific stores', () => {
    const stores = createObservationStores();
    const work = fs.mkdtempSync(path.join(os.tmpdir(), 'astranull-agent-meta-'));
    const nonce = 'probe-nonce-abc';
    const nonceHash = hashNonce(nonce);
    const packetFile = path.join(work, 'packet.jsonl');
    const mirrorFile = path.join(work, 'mirror.jsonl');
    fs.writeFileSync(
      packetFile,
      `${JSON.stringify({ nonce, interface: 'eth0', packet_count: 3, protocol: 'tcp' })}\n`,
    );
    fs.writeFileSync(
      mirrorFile,
      `${JSON.stringify({ nonce_hash: nonceHash, flow_count: 2, direction: 'ingress' })}\n`,
    );

    const packetResult = loadObservationFile(
      packetFile,
      OBSERVATION_MODES.PACKET_METADATA,
      'packet_metadata_file',
      stores.packetMetadata,
    );
    const mirrorResult = loadObservationFile(
      mirrorFile,
      OBSERVATION_MODES.PACKET_MIRROR,
      'mirror_metadata_file',
      stores.packetMirror,
    );

    assert.equal(packetResult.loaded, 1);
    assert.equal(mirrorResult.loaded, 1);
    assert.equal(stores.packetMetadata.get(nonceHash)?.packet_count, 3);
    assert.equal(stores.packetMirror.get(nonceHash)?.flow_count, 2);
    assert.equal(stores.packetMetadata.get(nonceHash)?.nonce, undefined);
  });

  it('ignores records with disallowed payload/header/log fields', () => {
    const stores = createObservationStores();
    const work = fs.mkdtempSync(path.join(os.tmpdir(), 'astranull-agent-bad-'));
    const badFile = path.join(work, 'bad.jsonl');
    fs.writeFileSync(
      badFile,
      `${JSON.stringify({ nonce: 'n1', raw_packet: '00ff' })}\n${JSON.stringify({ nonce: 'n2', nested: { log_line: 'secret' } })}\n`,
    );
    const result = loadObservationFile(
      badFile,
      OBSERVATION_MODES.PACKET_METADATA,
      'packet_metadata_file',
      stores.packetMetadata,
    );
    assert.equal(result.loaded, 0);
    assert.equal(result.ignored, 2);
    assert.equal(stores.packetMetadata.size, 0);
    assert.equal(containsDisallowedObservationFields({ headers: { cookie: 'x' } }), true);
  });

  it('selectObservationForJob returns null when no local signal exists', () => {
    const stores = createObservationStores();
    assert.equal(selectObservationForJob('sha256:deadbeef', stores), null);
  });

  it('selectObservationForJob prefers canary over packet metadata', () => {
    const stores = createObservationStores();
    const nonceHash = hashNonce('priority-nonce');
    stores.packetMetadata.set(nonceHash, {
      observed_at: '2026-01-01T00:00:00.000Z',
      packet_count: 1,
    });
    stores.canary.set(nonceHash, {
      observed_at: '2026-01-02T00:00:00.000Z',
      method: 'GET',
      path: '/canary',
    });
    const selected = selectObservationForJob(nonceHash, stores);
    assert.equal(selected.mode, OBSERVATION_MODES.CANARY);
    assert.equal(selected.metadata.method, 'GET');
    assert.equal(selected.metadata.raw_packet, undefined);
  });

  it('buildAgentRegistrationCapabilities includes WAF flags', () => {
    const base = buildAgentRegistrationCapabilities({});
    assert.ok(base.includes('heartbeat'));
    assert.ok(base.includes('canary'));
    assert.ok(base.includes('waf_canary_observer'));
    assert.ok(base.includes('origin_path_observer'));
    assert.equal(base.includes('waf_validation_ready'), false);

    const full = buildAgentRegistrationCapabilities({
      canaryListen: 8080,
      logFile: '/var/log/access.log',
      packetMetadataFile: '/var/lib/packet.jsonl',
    });
    assert.ok(full.includes('http_access_log_metadata'));
    assert.ok(full.includes('connector_log_pointer'));
    assert.ok(full.includes('waf_validation_ready'));
  });

  it('WAF canary request records route label and observation metadata without headers or cookies', async () => {
    const stores = createObservationStores();
    const server = startCanaryListener(0, stores, { host: '127.0.0.1', log: () => {} });
    try {
      await new Promise((resolve) => server.once('listening', resolve));
      const { port } = server.address();
      const nonce = 'waf-canary-nonce';
      const res = await fetch(`http://127.0.0.1:${port}/waf/canary`, {
        headers: {
          'x-astranull-nonce': nonce,
          'x-astranull-route-label': 'origin_canary',
          'x-astranull-observation-type': 'waf_marker_seen',
          'x-astranull-placement-confidence': '0.91',
          authorization: 'Bearer must-not-store',
          cookie: 'sid=must-not-store',
        },
      });
      assert.equal(res.status, 200);

      const record = stores.canary.get(hashNonce(nonce));
      assert.ok(record);
      assert.equal(record.route_label, 'origin_canary');
      assert.equal(record.observation_type, 'waf_marker_seen');
      assert.equal(record.placement_confidence, 0.91);
      assert.equal(record.headers, undefined);
      assert.equal(record.authorization, undefined);
      assert.equal(record.cookie, undefined);

      const selected = selectObservationForJob(hashNonce(nonce), stores);
      assert.equal(selected.metadata.route_label, 'origin_canary');
      assert.equal(selected.metadata.observation_type, 'waf_marker_seen');
      assert.equal(selected.metadata.placement_confidence, 0.91);
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  it('metadata JSONL with WAF safe fields is accepted for upload', async () => {
    const stores = createObservationStores();
    const work = fs.mkdtempSync(path.join(os.tmpdir(), 'astranull-agent-waf-meta-'));
    const nonce = 'waf-jsonl-nonce';
    const nonceHash = hashNonce(nonce);
    const metaFile = path.join(work, 'waf.jsonl');
    fs.writeFileSync(
      metaFile,
      `${JSON.stringify({
        nonce,
        observation_type: 'waf_marker_seen',
        route_label: 'origin',
        placement_confidence: 0.88,
        log_pointer_hash: `sha256:${'a'.repeat(64)}`,
        direct_origin: true,
        protected_path: false,
      })}\n`,
    );

    const result = loadObservationFile(
      metaFile,
      OBSERVATION_MODES.PACKET_METADATA,
      'packet_metadata_file',
      stores.packetMetadata,
    );
    assert.equal(result.loaded, 1);
    assert.equal(result.ignored, 0);

    const calls = [];
    const api = async (method, path, body) => {
      calls.push({ method, path, body });
      if (method === 'GET' && path.endsWith('/jobs')) {
        return {
          jobs: [
            {
              id: 'job_waf_meta',
              test_run_id: 'run_waf',
              target_id: 'tgt_waf',
              nonce_hash: nonceHash,
            },
          ],
        };
      }
      return {};
    };

    await pollAndWork('agt_waf', { api, stores, log: () => {} });

    const obs = calls.find((c) => c.method === 'POST' && c.path.endsWith('/observations'));
    assert.ok(obs);
    assert.equal(obs.body.metadata.observation_type, 'waf_marker_seen');
    assert.equal(obs.body.metadata.route_label, 'origin');
    assert.equal(obs.body.metadata.placement_confidence, 0.88);
    assert.equal(obs.body.metadata.direct_origin, true);
    assert.equal(obs.body.metadata.protected_path, false);
    assert.match(obs.body.metadata.log_pointer_hash, /^sha256:[a-f0-9]{64}$/);
    assert.equal(obs.body.metadata.body, undefined);
    assert.equal(obs.body.metadata.headers, undefined);
  });

  it('metadata JSONL with raw body header log or payload fields is rejected', () => {
    const stores = createObservationStores();
    const work = fs.mkdtempSync(path.join(os.tmpdir(), 'astranull-agent-waf-bad-'));
    const badFile = path.join(work, 'waf-bad.jsonl');
    const nonceHash = hashNonce('waf-bad-nonce');
    fs.writeFileSync(
      badFile,
      [
        JSON.stringify({
          nonce_hash: nonceHash,
          observation_type: 'waf_marker_seen',
          route_label: 'edge',
          body: 'raw-body',
        }),
        JSON.stringify({
          nonce_hash: nonceHash,
          headers: { 'x-test': '1' },
        }),
        JSON.stringify({
          nonce_hash: nonceHash,
          raw_log: 'GET /secret',
        }),
        JSON.stringify({
          nonce_hash: nonceHash,
          payload: '00ff',
        }),
      ].join('\n') + '\n',
    );

    const result = loadObservationFile(
      badFile,
      OBSERVATION_MODES.PACKET_METADATA,
      'packet_metadata_file',
      stores.packetMetadata,
    );
    assert.equal(result.loaded, 0);
    assert.equal(result.ignored, 4);
    assert.equal(stores.packetMetadata.size, 0);
  });

  it('actual canary listener records sanitized nonce metadata', async () => {
    const stores = createObservationStores();
    const server = startCanaryListener(0, stores, { host: '127.0.0.1', log: () => {} });
    try {
      await new Promise((resolve) => server.once('listening', resolve));
      const { port } = server.address();
      const nonce = 'canary-listener-nonce';
      const res = await fetch(`http://127.0.0.1:${port}/canary/path`, {
        headers: {
          'x-astranull-nonce': nonce,
          authorization: 'Bearer must-not-store',
          cookie: 'sid=must-not-store',
        },
      });
      assert.equal(res.status, 200);

      const record = stores.canary.get(hashNonce(nonce));
      assert.ok(record);
      assert.equal(record.method, 'GET');
      assert.equal(record.path, '/canary/path');
      assert.equal(record.mode, OBSERVATION_MODES.CANARY);
      assert.equal(record.source, 'canary_listener');
      assert.equal(record.nonce, undefined);
      assert.equal(record.headers, undefined);
      assert.equal(record.authorization, undefined);
      assert.equal(record.cookie, undefined);
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  it('canary listener ignores requests without a nonce', async () => {
    const stores = createObservationStores();
    const server = startCanaryListener(0, stores, { host: '127.0.0.1', log: () => {} });
    try {
      await new Promise((resolve) => server.once('listening', resolve));
      const { port } = server.address();
      const res = await fetch(`http://127.0.0.1:${port}/no-nonce`);
      assert.equal(res.status, 200);
      assert.equal(stores.canary.size, 0);
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  it('extractNonceHashFromLogLine normalizes tagged hashes only', () => {
    const hex = 'ABCDEFabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123';
    assert.equal(
      extractNonceHashFromLogLine(`request marker sha256:${hex} status=200`),
      `sha256:${hex.toLowerCase()}`,
    );
    assert.equal(extractNonceHashFromLogLine('request without marker'), null);
  });

  it('log-tail stores line fingerprints without raw log content', () => {
    const stores = createObservationStores();
    const work = fs.mkdtempSync(path.join(os.tmpdir(), 'astranull-agent-logtail-'));
    const logPath = path.join(work, 'access.log');
    const nonceHash = hashNonce('log-tail-nonce');
    fs.writeFileSync(
      logPath,
      `GET /health 200\nGET /canary marker=${nonceHash} authorization=secret\n`,
      'utf8',
    );

    const tail = startLogTail(logPath, stores, { watch: false });
    tail.close();

    const record = stores.logTail.get(nonceHash);
    assert.ok(record);
    assert.equal(record.mode, OBSERVATION_MODES.LOG_TAIL);
    assert.equal(record.source, 'log_tail');
    assert.match(record.line_hash, /^[a-f0-9]{64}$/);
    assert.equal(record.log_line, undefined);
    assert.equal(record.raw_log, undefined);
    assert.equal(stores.logTail.has('request without marker'), false);
  });
});

describe('pollAndWork evidence gating', () => {
  it('acks jobs but does not upload when no matching local signal exists', async () => {
    const calls = [];
    const api = async (method, path, body) => {
      calls.push({ method, path, body });
      if (method === 'GET' && path.endsWith('/jobs')) {
        return {
          jobs: [
            {
              id: 'job_no_signal',
              test_run_id: 'run_1',
              target_id: 'tgt_1',
              nonce_hash: hashNonce('missing-local-signal'),
            },
          ],
        };
      }
      return {};
    };

    await pollAndWork('agt_test', { api, stores: createObservationStores(), log: () => {} });

    const acks = calls.filter((c) => c.method === 'POST' && c.path.includes('/ack'));
    const obs = calls.filter((c) => c.method === 'POST' && c.path.endsWith('/observations'));
    assert.equal(acks.length, 1);
    assert.equal(obs.length, 0);
  });

  it('uploads sanitized observation when packet mirror signal exists', async () => {
    const stores = createObservationStores();
    const nonceHash = hashNonce('mirror-hit');
    stores.packetMirror.set(nonceHash, {
      observed_at: '2026-07-01T12:00:00.000Z',
      flow_count: 4,
      remote_port: 443,
      payload: 'must-not-upload',
    });

    const calls = [];
    const api = async (method, path, body) => {
      calls.push({ method, path, body });
      if (method === 'GET' && path.endsWith('/jobs')) {
        return {
          jobs: [
            {
              id: 'job_mirror',
              test_run_id: 'run_mirror',
              target_id: 'tgt_mirror',
              nonce_hash: nonceHash,
            },
          ],
        };
      }
      return {};
    };

    await pollAndWork('agt_test', { api, stores, log: () => {} });

    const obs = calls.find((c) => c.method === 'POST' && c.path.endsWith('/observations'));
    assert.ok(obs);
    assert.equal(obs.body.nonce_hash, nonceHash);
    assert.equal(obs.body.metadata.mode, OBSERVATION_MODES.PACKET_MIRROR);
    assert.equal(obs.body.metadata.flow_count, 4);
    assert.equal(obs.body.metadata.payload, undefined);
    assert.equal(obs.body.metadata.nonce, undefined);
  });
});

function ed25519PrivateKeyBase64Der() {
  const { privateKey } = generateKeyPairSync('ed25519');
  return privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');
}

function buildSignedAgentPackageForTest(version = '9.9.9-runtime-verify') {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'astranull-agent-verify-'));
  const privateKeyBase64 = ed25519PrivateKeyBase64Der();
  const result = buildAgentPackage({
    repoRoot: process.cwd(),
    outputDir: tmp,
    version,
    createdAt: '2026-07-01T12:00:00.000Z',
    signingPrivateKeyBase64: privateKeyBase64,
  });
  const signatureBase64 = fs.readFileSync(result.sigPath, 'utf8').trim();
  return { ...result, signatureBase64, tmp };
}

describe('agent update manifest verifier', () => {
  it('rejects tampered manifest version with signature failure', () => {
    const pkg = buildSignedAgentPackageForTest();
    const tampered = {
      ...pkg.manifest,
      version: '9.9.9-tampered',
    };
    const result = verifyAgentUpdateManifest({
      manifest: tampered,
      signatureBase64: pkg.signatureBase64,
      trustedPublicKeyDerBase64: pkg.manifest.signing.public_key_der_base64,
    });
    assert.equal(result.ok, false);
    assert.equal(result.error, 'SIGNATURE_VERIFICATION_FAILED');
  });

  it('rejects wrong trusted public key', () => {
    const pkg = buildSignedAgentPackageForTest();
    const otherKey = generateKeyPairSync('ed25519').publicKey
      .export({ type: 'spki', format: 'der' })
      .toString('base64');
    const manifestWithoutEmbeddedKey = {
      ...pkg.manifest,
      signing: {
        algorithm: pkg.manifest.signing.algorithm,
        signed: true,
        signed_at: pkg.manifest.signing.signed_at,
      },
    };
    const result = verifyAgentUpdateManifest({
      manifest: manifestWithoutEmbeddedKey,
      signatureBase64: pkg.signatureBase64,
      trustedPublicKeyDerBase64: otherKey,
    });
    assert.equal(result.ok, false);
    assert.equal(result.error, 'SIGNATURE_VERIFICATION_FAILED');
  });

  it('rejects artifact checksum mismatch when tarball path is supplied', () => {
    const pkg = buildSignedAgentPackageForTest();
    const corrupt = path.join(pkg.tmp, 'corrupt.tar.gz');
    fs.writeFileSync(corrupt, 'not-the-real-tarball');
    const result = verifyAgentUpdateManifest({
      manifest: pkg.manifest,
      signatureBase64: pkg.signatureBase64,
      trustedPublicKeyDerBase64: pkg.manifest.signing.public_key_der_base64,
      artifactPath: corrupt,
    });
    assert.equal(result.ok, false);
    assert.equal(result.error, 'ARTIFACT_CHECKSUM_MISMATCH');
  });

  it('rejects unsigned manifest', () => {
    const pkg = buildSignedAgentPackageForTest();
    const unsigned = {
      ...pkg.manifest,
      signing: { algorithm: 'Ed25519', signed: false },
    };
    const result = verifyAgentUpdateManifest({
      manifest: unsigned,
      signatureBase64: pkg.signatureBase64,
      trustedPublicKeyDerBase64: pkg.manifest.signing.public_key_der_base64,
    });
    assert.equal(result.ok, false);
    assert.equal(result.error, 'UNSIGNED_MANIFEST');
  });

  it('rejects traversal-style artifact names', () => {
    const pkg = buildSignedAgentPackageForTest();
    const unsafe = {
      ...pkg.manifest,
      artifact: {
        ...pkg.manifest.artifact,
        name: '../escape.tar.gz',
      },
    };
    const validated = validateAgentUpdateManifest(unsafe);
    assert.equal(validated.ok, false);
    assert.equal(validated.error, 'ARTIFACT_NAME_UNSAFE');
  });

  it('rejects unsafe manifest version strings', () => {
    const pkg = buildSignedAgentPackageForTest('9.9.9-cli-apply');
    for (const version of ['9.9.9/../escape', '9.9.9\\evil', '..', 'a'.repeat(129)]) {
      const validated = validateAgentUpdateManifest({ ...pkg.manifest, version });
      assert.equal(validated.ok, false, `version ${JSON.stringify(version)} should be rejected`);
      assert.equal(validated.error, 'INVALID_VERSION');
    }
    assert.equal(validateAgentUpdateManifest(pkg.manifest).ok, true);
  });

  it('rejects unsafe manifest file paths', () => {
    const pkg = buildSignedAgentPackageForTest();
    const unsafe = {
      ...pkg.manifest,
      files: [{ ...pkg.manifest.files[0], path: '../astranull-agent.mjs' }],
    };
    const validated = validateAgentUpdateManifest(unsafe);
    assert.equal(validated.ok, false);
    assert.equal(validated.error, 'MANIFEST_FILE_PATH_UNSAFE');
  });

  it('rejects manifest embedded public key that does not match trusted key', () => {
    const pkg = buildSignedAgentPackageForTest();
    const otherKey = generateKeyPairSync('ed25519').publicKey
      .export({ type: 'spki', format: 'der' })
      .toString('base64');
    const result = verifyAgentUpdateManifest({
      manifest: pkg.manifest,
      signatureBase64: pkg.signatureBase64,
      trustedPublicKeyDerBase64: otherKey,
    });
    assert.equal(result.ok, false);
    assert.equal(result.error, 'TRUSTED_PUBLIC_KEY_MISMATCH');
  });
});

describe('agent update package apply', () => {
  it('applies a signed package into an absolute install root', () => {
    const pkg = buildSignedAgentPackageForTest('9.9.9-apply-ok');
    const installRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'astranull-agent-install-'));
    const appliedAt = '2026-07-01T12:34:56.000Z';

    const result = applyAgentUpdatePackage({
      manifest: pkg.manifest,
      signatureBase64: pkg.signatureBase64,
      trustedPublicKeyDerBase64: pkg.manifest.signing.public_key_der_base64,
      artifactPath: pkg.tarballPath,
      installRoot,
      now: () => appliedAt,
    });

    assert.equal(result.ok, true);
    const releaseDir = path.join(installRoot, 'releases', pkg.manifest.version);
    assert.equal(result.releaseDir, releaseDir);
    assert.ok(fs.existsSync(path.join(releaseDir, 'astranull-agent.mjs')));
    const current = JSON.parse(fs.readFileSync(path.join(installRoot, 'current.json'), 'utf8'));
    assert.equal(current.version, pkg.manifest.version);
    assert.equal(current.applied_at, appliedAt);
    assert.equal(current.release_dir, releaseDir);
    assert.equal(current.artifact_sha256, pkg.manifest.artifact.sha256.toLowerCase());
    const stagingLeftovers = fs
      .readdirSync(installRoot)
      .filter((name) => name.startsWith('.astranull-apply-staging-'));
    assert.equal(stagingLeftovers.length, 0);
  });

  it('rejects unsafe manifest version before apply', () => {
    const pkg = buildSignedAgentPackageForTest('a'.repeat(129));
    const installRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'astranull-agent-install-unsafe-ver-'));
    const result = applyAgentUpdatePackage({
      manifest: pkg.manifest,
      signatureBase64: pkg.signatureBase64,
      trustedPublicKeyDerBase64: pkg.manifest.signing.public_key_der_base64,
      artifactPath: pkg.tarballPath,
      installRoot,
    });
    assert.equal(result.ok, false);
    assert.equal(result.error, 'INVALID_VERSION');
    assert.equal(fs.existsSync(path.join(installRoot, 'current.json')), false);
  });

  it('rejects relative install roots', () => {
    const pkg = buildSignedAgentPackageForTest('9.9.9-apply-rel');
    const result = applyAgentUpdatePackage({
      manifest: pkg.manifest,
      signatureBase64: pkg.signatureBase64,
      trustedPublicKeyDerBase64: pkg.manifest.signing.public_key_der_base64,
      artifactPath: pkg.tarballPath,
      installRoot: 'relative/install',
    });
    assert.equal(result.ok, false);
    assert.equal(result.error, 'INSTALL_ROOT_NOT_ABSOLUTE');
    assert.equal(validateAgentUpdateInstallRoot('relative/install').error, 'INSTALL_ROOT_NOT_ABSOLUTE');
  });

  it('rejects unsafe tar entries before extraction', () => {
    const unsafeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'astranull-agent-unsafe-tar-'));
    const rootName = 'astranull-agent-unsafe-root';
    const rootDir = path.join(unsafeDir, rootName);
    fs.mkdirSync(rootDir, { recursive: true });
    fs.writeFileSync(path.join(rootDir, 'ok.txt'), 'ok');
    fs.writeFileSync(path.join(unsafeDir, 'escape.txt'), 'escape');
    const tarballPath = path.join(unsafeDir, 'unsafe.tar.gz');
    execFileSync(
      'tar',
      ['-czf', tarballPath, '-C', unsafeDir, `${rootName}/ok.txt`, `${rootName}/../escape.txt`],
      { stdio: 'pipe' },
    );
    const validated = validateAgentUpdateTarballEntries(tarballPath, rootName);
    assert.equal(validated.ok, false);
    assert.equal(validated.error, 'TARBALL_ENTRY_UNSAFE');
  });

  it('rejects corrupted extracted file checksum mismatch', () => {
    const pkg = buildSignedAgentPackageForTest('9.9.9-apply-corrupt');
    const staging = fs.mkdtempSync(path.join(os.tmpdir(), 'astranull-agent-extract-'));
    const rootName = pkg.manifest.artifact.name.replace(/\.tar\.gz$/i, '');
    execFileSync('tar', ['-xzf', pkg.tarballPath, '-C', staging], { stdio: 'pipe' });
    const extractedRoot = path.join(staging, rootName);
    const target = path.join(extractedRoot, pkg.manifest.files[0].path);
    fs.writeFileSync(target, `${fs.readFileSync(target, 'utf8')}tampered`);
    const verified = verifyAgentUpdatePackageFiles(pkg.manifest, extractedRoot);
    assert.equal(verified.ok, false);
    assert.equal(verified.error, 'PACKAGE_FILE_CHECKSUM_MISMATCH');
  });

  it('rejects manifest file path traversal during package verification', () => {
    const pkg = buildSignedAgentPackageForTest('9.9.9-apply-traversal');
    const staging = fs.mkdtempSync(path.join(os.tmpdir(), 'astranull-agent-extract-traversal-'));
    const rootName = pkg.manifest.artifact.name.replace(/\.tar\.gz$/i, '');
    execFileSync('tar', ['-xzf', pkg.tarballPath, '-C', staging], { stdio: 'pipe' });
    const extractedRoot = path.join(staging, rootName);
    const traversalManifest = {
      ...pkg.manifest,
      files: [{ ...pkg.manifest.files[0], path: '../escape.txt' }],
    };
    const verified = verifyAgentUpdatePackageFiles(traversalManifest, extractedRoot);
    assert.equal(verified.ok, false);
    assert.equal(verified.error, 'MANIFEST_FILE_PATH_UNSAFE');
  });

  it('rejects symlinked package files during verification', () => {
    const pkg = buildSignedAgentPackageForTest('9.9.9-apply-symlink');
    const staging = fs.mkdtempSync(path.join(os.tmpdir(), 'astranull-agent-extract-symlink-'));
    const rootName = pkg.manifest.artifact.name.replace(/\.tar\.gz$/i, '');
    execFileSync('tar', ['-xzf', pkg.tarballPath, '-C', staging], { stdio: 'pipe' });
    const extractedRoot = path.join(staging, rootName);
    const target = path.join(extractedRoot, pkg.manifest.files[0].path);
    const outside = path.join(staging, 'outside-secret.txt');
    fs.writeFileSync(outside, fs.readFileSync(target));
    fs.unlinkSync(target);
    fs.symlinkSync(outside, target);
    const verified = verifyAgentUpdatePackageFiles(pkg.manifest, extractedRoot);
    assert.equal(verified.ok, false);
    assert.equal(verified.error, 'PACKAGE_FILE_NOT_REGULAR');
  });
});

describe('agent update manifest CLI apply', () => {
  it('exits 0 and writes current.json for valid signed package', async () => {
    const pkg = buildSignedAgentPackageForTest('9.9.9-cli-apply');
    const installRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'astranull-agent-cli-install-'));

    const { stdout } = await execFileAsync(
      nodeBin,
      [
        agentScript,
        '--apply-update-manifest',
        pkg.manifestPath,
        '--signature',
        pkg.sigPath,
        '--trusted-public-key',
        pkg.manifest.signing.public_key_der_base64,
        '--artifact',
        pkg.tarballPath,
        '--install-root',
        installRoot,
      ],
      { encoding: 'utf8' },
    );

    assert.match(stdout, /update-manifest-apply: ok/);
    assert.match(stdout, /version: 9\.9\.9-cli-apply/);
    assert.doesNotMatch(stdout, /Bearer|ast_|bootstrap/i);
    assert.doesNotMatch(stdout, literalPattern(pkg.signatureBase64.slice(0, 16)));
    const current = JSON.parse(fs.readFileSync(path.join(installRoot, 'current.json'), 'utf8'));
    assert.equal(current.version, '9.9.9-cli-apply');
  });

  it('rejects relative install root on CLI', async () => {
    const pkg = buildSignedAgentPackageForTest('9.9.9-cli-apply-bad-root');

    await assert.rejects(
      () =>
        execFileAsync(
          nodeBin,
          [
            agentScript,
            '--apply-update-manifest',
            pkg.manifestPath,
            '--signature',
            pkg.sigPath,
            '--trusted-public-key',
            pkg.manifest.signing.public_key_der_base64,
            '--artifact',
            pkg.tarballPath,
            '--install-root',
            'relative/install',
          ],
          { encoding: 'utf8' },
        ),
      (err) => {
        assert.ok(err && typeof err === 'object' && 'code' in err);
        assert.notEqual(err.code, 0);
        const stderr = String(err.stderr ?? '');
        assert.match(stderr, /update-manifest-apply: failed/);
        assert.match(stderr, /INSTALL_ROOT_NOT_ABSOLUTE/);
        return true;
      },
    );
  });
});

function startLocalAgentPackageHttpServer(pkg) {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      const pathname = (req.url ?? '').split('?')[0];
      const routes = {
        '/manifest.json': pkg.manifestPath,
        '/manifest.sig': pkg.sigPath,
        '/artifact.tar.gz': pkg.tarballPath,
      };
      const filePath = routes[pathname];
      if (!filePath) {
        res.writeHead(404);
        res.end();
        return;
      }
      const data = fs.readFileSync(filePath);
      res.writeHead(200, { 'Content-Length': String(data.length) });
      res.end(data);
    });
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({
        server,
        baseUrl: `http://127.0.0.1:${port}`,
      });
    });
  });
}

describe('agent update download and apply', () => {
  it('downloads from local HTTP and applies a signed package', async () => {
    const pkg = buildSignedAgentPackageForTest('9.9.9-download-apply');
    const installRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'astranull-agent-download-install-'));
    const { server, baseUrl } = await startLocalAgentPackageHttpServer(pkg);

    try {
      const result = await downloadAndApplyAgentUpdatePackage({
        manifestUrl: `${baseUrl}/manifest.json`,
        signatureUrl: `${baseUrl}/manifest.sig`,
        artifactUrl: `${baseUrl}/artifact.tar.gz`,
        trustedPublicKeyDerBase64: pkg.manifest.signing.public_key_der_base64,
        installRoot,
        allowInsecureLocalhost: true,
        now: () => '2026-07-01T12:34:56.000Z',
      });

      assert.equal(result.ok, true);
      assert.equal(result.version, '9.9.9-download-apply');
      const current = JSON.parse(fs.readFileSync(path.join(installRoot, 'current.json'), 'utf8'));
      assert.equal(current.version, '9.9.9-download-apply');
    } finally {
      await new Promise((resolve) => server.close(() => resolve()));
    }
  });

  it('CLI --download-and-apply-update exits 0 and writes current.json', async () => {
    const pkg = buildSignedAgentPackageForTest('9.9.9-cli-download-apply');
    const installRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'astranull-agent-cli-download-install-'));
    const { server, baseUrl } = await startLocalAgentPackageHttpServer(pkg);

    try {
      const { stdout } = await execFileAsync(
        nodeBin,
        [
          agentScript,
          '--download-and-apply-update',
          '--manifest-url',
          `${baseUrl}/manifest.json`,
          '--signature-url',
          `${baseUrl}/manifest.sig`,
          '--artifact-url',
          `${baseUrl}/artifact.tar.gz`,
          '--trusted-public-key',
          pkg.manifest.signing.public_key_der_base64,
          '--install-root',
          installRoot,
          '--allow-insecure-localhost-downloads',
        ],
        { encoding: 'utf8' },
      );

      assert.match(stdout, /update-download-apply: ok/);
      assert.match(stdout, /version: 9\.9\.9-cli-download-apply/);
      assert.doesNotMatch(stdout, /Bearer|ast_|bootstrap/i);
      assert.doesNotMatch(stdout, literalPattern(pkg.signatureBase64.slice(0, 16)));
      const current = JSON.parse(fs.readFileSync(path.join(installRoot, 'current.json'), 'utf8'));
      assert.equal(current.version, '9.9.9-cli-download-apply');
    } finally {
      await new Promise((resolve) => server.close(() => resolve()));
    }
  });

  it('rejects insecure non-local HTTP URL without downloading', async () => {
    let requestCount = 0;
    const server = http.createServer((req, res) => {
      requestCount += 1;
      res.end('unused');
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));

    try {
      const dest = path.join(os.tmpdir(), `astranull-agent-no-download-${Date.now()}.bin`);
      const result = await downloadAgentUpdateFile('http://example.com/artifact.tar.gz', dest, {
        allowInsecureLocalhost: false,
      });
      assert.equal(result.ok, false);
      assert.equal(result.error, 'INSECURE_HTTP_NOT_ALLOWED');
      assert.equal(requestCount, 0);
      assert.equal(validateAgentUpdateDownloadUrl('http://example.com/x').error, 'INSECURE_HTTP_NOT_ALLOWED');
    } finally {
      await new Promise((resolve) => server.close(() => resolve()));
    }
  });

  it('rejects URL with embedded credentials', async () => {
    const validated = validateAgentUpdateDownloadUrl('https://user:pass@example.com/manifest.json');
    assert.equal(validated.ok, false);
    assert.equal(validated.error, 'URL_CREDENTIALS_NOT_ALLOWED');

    const dest = path.join(os.tmpdir(), `astranull-agent-creds-${Date.now()}.bin`);
    const downloaded = await downloadAgentUpdateFile(
      'http://user:secret@127.0.0.1/manifest.json',
      dest,
      { allowInsecureLocalhost: true },
    );
    assert.equal(downloaded.ok, false);
    assert.equal(downloaded.error, 'URL_CREDENTIALS_NOT_ALLOWED');
  });

  it('rejects HTTP redirect and does not write destination file', async () => {
    let redirectTargetHits = 0;
    const payload = Buffer.from('valid-package-bytes', 'utf8');
    const server = http.createServer((req, res) => {
      if (req.url === '/redirect-me') {
        res.writeHead(302, { Location: '/package.bin' });
        res.end();
        return;
      }
      if (req.url === '/package.bin') {
        redirectTargetHits += 1;
        res.writeHead(200, { 'Content-Length': String(payload.length) });
        res.end(payload);
        return;
      }
      res.writeHead(404);
      res.end();
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address();
    const url = `http://127.0.0.1:${port}/redirect-me`;

    try {
      const dest = path.join(os.tmpdir(), `astranull-agent-redirect-${Date.now()}.bin`);
      const result = await downloadAgentUpdateFile(url, dest, {
        allowInsecureLocalhost: true,
      });
      assert.equal(result.ok, false);
      assert.equal(result.error, 'DOWNLOAD_HTTP_STATUS');
      assert.equal(result.status, 302);
      assert.equal(redirectTargetHits, 0);
      assert.equal(fs.existsSync(dest), false);
    } finally {
      await new Promise((resolve) => server.close(() => resolve()));
    }
  });

  it('rejects response exceeding maxBytes', async () => {
    const server = http.createServer((req, res) => {
      const body = Buffer.alloc(32, 'z');
      res.writeHead(200, { 'Content-Length': String(body.length) });
      res.end(body);
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address();
    const url = `http://127.0.0.1:${port}/large.bin`;

    try {
      const dest = path.join(os.tmpdir(), `astranull-agent-maxbytes-${Date.now()}.bin`);
      const result = await downloadAgentUpdateFile(url, dest, {
        allowInsecureLocalhost: true,
        maxBytes: 8,
      });
      assert.equal(result.ok, false);
      assert.equal(result.error, 'DOWNLOAD_TOO_LARGE');
      assert.equal(fs.existsSync(dest), false);
    } finally {
      await new Promise((resolve) => server.close(() => resolve()));
    }
  });
});

describe('validateAgentControlPlaneUrl', () => {
  it('accepts HTTPS API URLs', () => {
    const validated = validateAgentControlPlaneUrl('https://api.example.com/v1/');
    assert.equal(validated.ok, true);
    assert.equal(validated.url, 'https://api.example.com/v1');
  });

  it('rejects remote HTTP API URLs', () => {
    assert.equal(validateAgentControlPlaneUrl('http://api.example.com').error, 'INSECURE_HTTP_NOT_ALLOWED');
  });

  it('rejects URL credentials', () => {
    const validated = validateAgentControlPlaneUrl('https://user:pass@api.example.com');
    assert.equal(validated.ok, false);
    assert.equal(validated.error, 'URL_CREDENTIALS_NOT_ALLOWED');
  });

  it('allows localhost HTTP only with explicit override', () => {
    assert.equal(
      validateAgentControlPlaneUrl('http://127.0.0.1:3000').error,
      'INSECURE_LOCALHOST_NOT_ALLOWED',
    );
    const validated = validateAgentControlPlaneUrl('http://127.0.0.1:3000', {
      allowInsecureLocalhost: true,
    });
    assert.equal(validated.ok, true);
    assert.equal(validated.url, 'http://127.0.0.1:3000');
  });
});

describe('agent package signature verifier', () => {
  it('accepts tarball format via signing manifest and update manifest', () => {
    const pkg = buildSignedAgentPackageForTest('9.9.9-package-sig');
    const result = verifyPackageSignature({
      signingManifest: pkg.signingManifest,
      format: 'generic',
      artifactPath: pkg.tarballPath,
      trustedPublicKeyDerBase64: pkg.manifest.signing.public_key_der_base64,
      updateManifest: pkg.manifest,
      signatureBase64: pkg.signatureBase64,
    });
    assert.equal(result.ok, true);
    assert.equal(result.format, 'tarball');
    assert.equal(result.version, '9.9.9-package-sig');
  });

  it('accepts deb format when gpg fingerprint matches signing hook', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'astranull-agent-deb-verify-'));
    const debPath = path.join(tmp, 'astranull-agent-9.9.9-deb.deb');
    fs.writeFileSync(debPath, 'fake-deb-payload-for-test\n');
    const gpg = buildGpgSigningHook();
    const signingManifest = {
      schema_version: 1,
      artifact_type: 'agent_package_signing',
      package: 'astranull-agent',
      version: '9.9.9-deb',
      created_at: '2026-07-01T12:00:00.000Z',
      artifacts: {
        deb: {
          format: 'deb',
          name: path.basename(debPath),
          sha256: createHash('sha256').update(fs.readFileSync(debPath)).digest('hex'),
          size: fs.statSync(debPath).size,
          gpg,
        },
      },
    };
    const result = verifyPackageSignature({
      signingManifest,
      format: 'deb',
      artifactPath: debPath,
      trustedGpgFingerprintSha256: gpg.fingerprint_sha256,
      allowMetadataOnlyTrust: true,
    });
    assert.equal(result.ok, true);
    assert.equal(result.trust_anchor, DEFAULT_GPG_KEY_REFERENCE);
  });

  it('accepts container format when cosign signer matches hook', () => {
    const signingManifest = {
      schema_version: 1,
      artifact_type: 'agent_package_signing',
      package: 'astranull-agent',
      version: '9.9.9-container',
      created_at: '2026-07-01T12:00:00.000Z',
      artifacts: {
        container: {
          format: 'container',
          image: 'registry.example/astranull-agent:9.9.9-container',
          digest_sha256: 'e'.repeat(64),
          cosign: {
            hook: 'metadata_only',
            algorithm: 'cosign',
            signer_reference: DEFAULT_COSIGN_SIGNER_REFERENCE,
            signed: false,
            signature_uri: null,
          },
        },
      },
    };
    const result = verifyPackageSignature({
      signingManifest,
      format: 'container',
      trustedCosignSignerReference: DEFAULT_COSIGN_SIGNER_REFERENCE,
      allowMetadataOnlyTrust: true,
    });
    assert.equal(result.ok, true);
    assert.equal(result.image, 'registry.example/astranull-agent:9.9.9-container');
  });

  it('rejects metadata-only deb trust without explicit developer override', () => {
    const gpg = buildGpgSigningHook();
    const signingManifest = {
      schema_version: 1,
      artifact_type: 'agent_package_signing',
      package: 'astranull-agent',
      version: '9.9.9-deb-meta',
      created_at: '2026-07-01T12:00:00.000Z',
      artifacts: {
        deb: {
          format: 'deb',
          name: 'astranull-agent.deb',
          sha256: 'a'.repeat(64),
          size: 10,
          gpg,
        },
      },
    };
    const result = verifyPackageSignature({
      signingManifest,
      format: 'deb',
      artifactPath: null,
      trustedGpgFingerprintSha256: gpg.fingerprint_sha256,
    });
    assert.equal(result.ok, false);
    assert.equal(result.error, 'METADATA_ONLY_SIGNING_INSUFFICIENT');
  });

  it('rejects gpg fingerprint mismatch for deb packages', () => {
    const gpg = buildGpgSigningHook();
    const signingManifest = {
      schema_version: 1,
      artifact_type: 'agent_package_signing',
      package: 'astranull-agent',
      version: '9.9.9-deb-bad',
      created_at: '2026-07-01T12:00:00.000Z',
      artifacts: {
        deb: {
          format: 'deb',
          name: 'astranull-agent.deb',
          sha256: 'a'.repeat(64),
          size: 10,
          gpg,
        },
      },
    };
    const result = verifyPackageSignature({
      signingManifest,
      format: 'deb',
      artifactPath: null,
      trustedGpgFingerprintSha256: 'b'.repeat(64),
    });
    assert.equal(result.ok, false);
    assert.equal(result.error, 'TRUSTED_GPG_FINGERPRINT_MISMATCH');
  });
});

describe('agent package signature CLI preflight', () => {
  it('exits 0 for tarball generic format with signing manifest', async () => {
    const pkg = buildSignedAgentPackageForTest('9.9.9-cli-package-sig');
    const { stdout } = await execFileAsync(
      nodeBin,
      [
        agentScript,
        '--verify-package-signature',
        '--signing-manifest',
        pkg.signingManifestPath,
        '--package-format',
        'generic',
        '--update-manifest',
        pkg.manifestPath,
        '--signature',
        pkg.sigPath,
        '--trusted-public-key',
        pkg.manifest.signing.public_key_der_base64,
        '--artifact',
        pkg.tarballPath,
      ],
      { encoding: 'utf8' },
    );
    assert.match(stdout, /package-signature-verify: ok/);
    assert.match(stdout, /format: tarball/);
    assert.match(stdout, /version: 9\.9\.9-cli-package-sig/);
  });
});

describe('agent update manifest CLI preflight', () => {
  it('exits 0 on valid signed manifest with artifact', async () => {
    const pkg = buildSignedAgentPackageForTest('9.9.9-cli-ok');
    const { stdout } = await execFileAsync(
      nodeBin,
      [
        agentScript,
        '--verify-update-manifest',
        pkg.manifestPath,
        '--signature',
        pkg.sigPath,
        '--trusted-public-key',
        pkg.manifest.signing.public_key_der_base64,
        '--artifact',
        pkg.tarballPath,
      ],
      { encoding: 'utf8' },
    );
    assert.match(stdout, /update-manifest-verify: ok/);
    assert.match(stdout, /version: 9\.9\.9-cli-ok/);
    assert.doesNotMatch(stdout, /Bearer|ast_|bootstrap/i);
    assert.doesNotMatch(stdout, literalPattern(pkg.signatureBase64.slice(0, 16)));
  });

  it('exits nonzero when signature does not match manifest', async () => {
    const pkg = buildSignedAgentPackageForTest('9.9.9-cli-fail');
    const badSig = path.join(pkg.tmp, 'bad.sig');
    fs.writeFileSync(badSig, Buffer.alloc(64, 1).toString('base64'));

    await assert.rejects(
      () =>
        execFileAsync(
          nodeBin,
          [
            agentScript,
            '--verify-update-manifest',
            pkg.manifestPath,
            '--signature',
            badSig,
            '--trusted-public-key',
            pkg.manifest.signing.public_key_der_base64,
          ],
          { encoding: 'utf8' },
        ),
      (err) => {
        assert.ok(err && typeof err === 'object' && 'code' in err);
        assert.notEqual(err.code, 0);
        const stderr = String(err.stderr ?? '');
        assert.match(stderr, /update-manifest-verify: failed/);
        assert.match(stderr, /SIGNATURE_VERIFICATION_FAILED/);
        return true;
      },
    );
  });
});

describe('agent update daemon helpers', () => {
  it('resolveAgentUpdateDaemonIntervalMs uses default and minimum bounds', () => {
    assert.equal(
      resolveAgentUpdateDaemonIntervalMs({ cliInterval: undefined, envValue: undefined }),
      AGENT_UPDATE_DAEMON_DEFAULT_INTERVAL_MS,
    );
    assert.equal(
      resolveAgentUpdateDaemonIntervalMs({
        cliInterval: AGENT_UPDATE_DAEMON_MIN_INTERVAL_MS - 1,
      }),
      AGENT_UPDATE_DAEMON_DEFAULT_INTERVAL_MS,
    );
    assert.equal(
      resolveAgentUpdateDaemonIntervalMs({ cliInterval: 120_000 }),
      120_000,
    );
    assert.equal(
      resolveAgentUpdateDaemonIntervalMs({ envValue: '45000' }),
      45_000,
    );
  });

  it('readAgentCurrentReleaseRecord validates install root and current.json', () => {
    const installRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'astranull-agent-current-'));
    const missing = readAgentCurrentReleaseRecord(installRoot);
    assert.equal(missing.ok, false);
    assert.equal(missing.error, 'CURRENT_RELEASE_NOT_FOUND');

    fs.writeFileSync(
      path.join(installRoot, 'current.json'),
      `${JSON.stringify({
        version: '1.2.3',
        applied_at: '2026-07-01T00:00:00.000Z',
        release_dir: path.join(installRoot, 'releases', '1.2.3'),
        artifact_sha256: 'a'.repeat(64),
      }, null, 2)}\n`,
    );
    const current = readAgentCurrentReleaseRecord(installRoot);
    assert.equal(current.ok, true);
    assert.equal(current.version, '1.2.3');
    assert.equal(current.releaseDir, path.join(installRoot, 'releases', '1.2.3'));
  });

  it('resolveAgentExecutableFromCurrentRelease returns release agent path', () => {
    const installRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'astranull-agent-exec-'));
    const releaseDir = path.join(installRoot, 'releases', '2.0.0');
    fs.mkdirSync(releaseDir, { recursive: true });
    const executable = path.join(releaseDir, 'astranull-agent.mjs');
    fs.writeFileSync(executable, '#!/usr/bin/env node\n');
    fs.writeFileSync(
      path.join(installRoot, 'current.json'),
      `${JSON.stringify({
        version: '2.0.0',
        applied_at: '2026-07-01T00:00:00.000Z',
        release_dir: releaseDir,
        artifact_sha256: 'b'.repeat(64),
      }, null, 2)}\n`,
    );

    const resolved = resolveAgentExecutableFromCurrentRelease(installRoot);
    assert.equal(resolved.ok, true);
    assert.equal(resolved.executable, executable);
    assert.equal(resolved.version, '2.0.0');
  });

  it('filterAgentRestartArgv strips one-shot flags and keeps update daemon mode', () => {
    const filtered = filterAgentRestartArgv([
      '--once',
      '--api',
      'http://127.0.0.1:3000',
      '--download-and-apply-update',
      '--manifest-url',
      'https://cdn.example.com/manifest.json',
      '--allow-insecure-localhost-api',
      '--allow-insecure-localhost-downloads',
      '--daemon-interval',
      '60000',
    ]);
    assert.ok(filtered.includes('--run-update-daemon'));
    assert.ok(filtered.includes('--api'));
    assert.ok(filtered.includes('--daemon-interval'));
    assert.equal(filtered.includes('--once'), false);
    assert.equal(filtered.includes('--download-and-apply-update'), false);
    assert.equal(filtered.includes('--manifest-url'), false);
    assert.equal(filtered.includes('--allow-insecure-localhost-api'), false);
    assert.equal(filtered.includes('--allow-insecure-localhost-downloads'), false);
  });

  it('sanitizeAgentRestartEnv removes metadata-only trust overrides', () => {
    const sanitized = sanitizeAgentRestartEnv({
      PATH: '/usr/bin',
      ASTRANULL_AGENT_ALLOW_METADATA_ONLY_TRUST: '1',
    });
    assert.equal(sanitized.PATH, '/usr/bin');
    assert.equal(sanitized.ASTRANULL_AGENT_ALLOW_METADATA_ONLY_TRUST, undefined);
  });

  it('buildAgentRestartCommand points Node at the current release executable', () => {
    const installRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'astranull-agent-restart-cmd-'));
    const releaseDir = path.join(installRoot, 'releases', '3.1.4');
    fs.mkdirSync(releaseDir, { recursive: true });
    const executable = path.join(releaseDir, 'astranull-agent.mjs');
    fs.writeFileSync(executable, '#!/usr/bin/env node\n');
    fs.writeFileSync(
      path.join(installRoot, 'current.json'),
      `${JSON.stringify({
        version: '3.1.4',
        applied_at: '2026-07-01T00:00:00.000Z',
        release_dir: releaseDir,
        artifact_sha256: 'c'.repeat(64),
      }, null, 2)}\n`,
    );

    const command = buildAgentRestartCommand({
      installRoot,
      argv: ['--once', '--api', 'http://127.0.0.1:3000'],
      execPath: '/usr/bin/node',
    });
    assert.equal(command.ok, true);
    assert.equal(command.executable, '/usr/bin/node');
    assert.equal(command.argv[0], executable);
    assert.ok(command.argv.includes('--run-update-daemon'));
    assert.equal(command.argv.includes('--once'), false);
  });

  it('restartAgentProcessAfterUpdate re-execs current release and exits', () => {
    const installRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'astranull-agent-restart-exec-'));
    const releaseDir = path.join(installRoot, 'releases', '4.0.0');
    fs.mkdirSync(releaseDir, { recursive: true });
    const executable = path.join(releaseDir, 'astranull-agent.mjs');
    fs.writeFileSync(executable, '#!/usr/bin/env node\n');
    fs.writeFileSync(
      path.join(installRoot, 'current.json'),
      `${JSON.stringify({
        version: '4.0.0',
        applied_at: '2026-07-01T00:00:00.000Z',
        release_dir: releaseDir,
        artifact_sha256: 'd'.repeat(64),
      }, null, 2)}\n`,
    );

    const restartCalls = [];
    let exitCode = null;
    const result = restartAgentProcessAfterUpdate({
      installRoot,
      argv: ['--daemon-interval', '45000'],
      execPath: '/usr/bin/node',
      env: {
        PATH: '/usr/bin',
        ASTRANULL_AGENT_ALLOW_METADATA_ONLY_TRUST: '1',
      },
      restartFn: (payload) => {
        restartCalls.push(payload);
      },
      exitFn: (code) => {
        exitCode = code;
      },
    });

    assert.equal(result.ok, true);
    assert.equal(result.mode, 'reexec');
    assert.equal(restartCalls.length, 1);
    assert.equal(restartCalls[0].executable, '/usr/bin/node');
    assert.equal(restartCalls[0].argv[0], executable);
    assert.equal(restartCalls[0].env.ASTRANULL_AGENT_ALLOW_METADATA_ONLY_TRUST, undefined);
    assert.equal(exitCode, 0);
  });
});

describe('agent auto-update poll', () => {
  it('pollAndMaybeApplyUpdate skips when trust key or install root missing', async () => {
    const result = await pollAndMaybeApplyUpdate('ag_test', {
      api: async () => ({ update: null }),
    });
    assert.equal(result.skipped, 'missing_update_config');
  });

  it('pollAndMaybeApplyUpdate returns null update when control plane has none', async () => {
    const calls = [];
    const result = await pollAndMaybeApplyUpdate('ag_test', {
      trustedPublicKeyDerBase64: 'dGVzdA==',
      installRoot: '/tmp/astranull',
      api: async (method, path) => {
        calls.push([method, path]);
        if (path.endsWith('/update')) return { update: null };
        throw new Error('unexpected');
      },
    });
    assert.equal(result.applied, false);
    assert.equal(result.update, null);
    assert.deepEqual(calls, [['GET', '/v1/agents/ag_test/update']]);
  });

  it('runAgentDaemonCycle invokes heartbeat, jobs, and optional auto-update', async () => {
    const sequence = [];
    await runAgentDaemonCycle('ag_cycle', {
      heartbeat: async (id) => {
        sequence.push(['heartbeat', id]);
      },
      pollAndWork: async (id) => {
        sequence.push(['jobs', id]);
      },
      pollAndMaybeApplyUpdate: async (id) => {
        sequence.push(['update', id]);
        return { applied: false };
      },
      autoUpdate: true,
    });
    assert.deepEqual(sequence, [
      ['heartbeat', 'ag_cycle'],
      ['jobs', 'ag_cycle'],
      ['update', 'ag_cycle'],
    ]);
  });

  it('pollAndMaybeApplyUpdate reports metadata-only statuses through update-status API', async () => {
    const pkg = buildSignedAgentPackageForTest('9.9.9-daemon-status');
    const installRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'astranull-agent-daemon-status-'));
    const { server, baseUrl } = await startLocalAgentPackageHttpServer(pkg);
    const statusBodies = [];

    try {
      const result = await pollAndMaybeApplyUpdate('ag_status', {
        trustedPublicKeyDerBase64: pkg.manifest.signing.public_key_der_base64,
        installRoot,
        allowInsecureLocalhostDownloads: true,
        api: async (method, route, body) => {
          if (method === 'GET' && route.endsWith('/update')) {
            return {
              update: {
                release_id: 'rel_status',
                action: 'upgrade',
                version: pkg.manifest.version,
                download: {
                  manifest_url: `${baseUrl}/manifest.json`,
                  signature_url: `${baseUrl}/manifest.sig`,
                  artifact_url: `${baseUrl}/artifact.tar.gz`,
                },
              },
            };
          }
          if (method === 'POST' && route.endsWith('/update-status')) {
            statusBodies.push(body);
            return { status: { id: `aus_${statusBodies.length}` } };
          }
          throw new Error(`unexpected ${method} ${route}`);
        },
      });

      assert.equal(result.applied, true);
      assert.equal(result.version, pkg.manifest.version);
      assert.deepEqual(
        statusBodies.map((body) => body.status),
        ['downloaded', 'verified', 'applied'],
      );
      assert.equal(statusBodies[0].release_id, 'rel_status');
      assert.equal(statusBodies[0].action, 'upgrade');
      assert.equal(statusBodies[2].installed_version, pkg.manifest.version);
      for (const body of statusBodies) {
        assert.equal(body.manifest_url, undefined);
        assert.equal(body.download, undefined);
        assert.equal(body.signature, undefined);
      }
    } finally {
      await new Promise((resolve) => server.close(() => resolve()));
    }
  });

  it('runAgentDaemonCycle restarts agent after successful update when configured', async () => {
    const installRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'astranull-agent-daemon-restart-'));
    const releaseDir = path.join(installRoot, 'releases', '5.0.0');
    fs.mkdirSync(releaseDir, { recursive: true });
    fs.writeFileSync(path.join(releaseDir, 'astranull-agent.mjs'), '#!/usr/bin/env node\n');
    fs.writeFileSync(
      path.join(installRoot, 'current.json'),
      `${JSON.stringify({
        version: '5.0.0',
        applied_at: '2026-07-01T00:00:00.000Z',
        release_dir: releaseDir,
        artifact_sha256: 'e'.repeat(64),
      }, null, 2)}\n`,
    );

    const restartCalls = [];
    let exitCode = null;
    await runAgentDaemonCycle('ag_restart', {
      heartbeat: async () => {},
      pollAndWork: async () => {},
      pollAndMaybeApplyUpdate: async () => ({
        applied: true,
        version: '5.0.0',
        action: 'upgrade',
        releaseId: 'rel_restart',
      }),
      autoUpdate: true,
      restartAfterUpdate: true,
      installRoot,
      restartFn: (payload) => {
        restartCalls.push(payload);
      },
      exitFn: (code) => {
        exitCode = code;
      },
    });

    assert.equal(restartCalls.length, 1);
    assert.equal(restartCalls[0].argv[0], path.join(releaseDir, 'astranull-agent.mjs'));
    assert.equal(exitCode, 0);
  });
});

describe('agent runtime bootstrap token file', () => {
  it('deletes bootstrap token file after successful registration', async () => {
    const work = fs.mkdtempSync(path.join(os.tmpdir(), 'astranull-agent-run-'));
    const tokenFile = path.join(work, 'bootstrap-token');
    const identity = path.join(work, 'identity.json');

    const ctx = { tenantId: 'ten_demo', userId: 'u1', role: 'admin' };
    const { secret } = createBootstrapToken(ctx, {
      target_group_id: 'tg_1',
      max_registrations: 1,
    });
    fs.writeFileSync(tokenFile, secret, { mode: 0o600 });

    await execFileAsync(
      nodeBin,
      [
        agentScript,
        '--once',
        '--api',
        baseUrl,
        '--allow-insecure-localhost-api',
        '--token-file',
        tokenFile,
        '--identity',
        identity,
        '--tenant',
        'ten_demo',
      ],
      { encoding: 'utf8', env: { ...process.env, ASTRANULL_AUTH_MODE: 'dev-headers' } },
    );

    assert.equal(fs.existsSync(tokenFile), false);
    assert.ok(fs.existsSync(identity));
    const id = JSON.parse(fs.readFileSync(identity, 'utf8'));
    assert.ok(id.agent_id);
    assert.equal(id.tenant_id, 'ten_demo');
  });
});
