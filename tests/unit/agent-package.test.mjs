import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import {
  AGENT_PACKAGE_FILES,
  DEBIAN_MAINTAINER,
  NATIVE_AGENT_ENV_EXAMPLE_PATH,
  NATIVE_AGENT_PACKAGE_FILES,
  PACKAGE_NAME,
  buildAgentPackage,
  buildDebianControlFields,
  buildRpmPackage,
  listDebArMembers,
  listDebDataTarPaths,
  normalizePackageFormats,
  parseCliArgs,
  readDebControlText,
  stageNativeAgentTree,
  buildSignablePayload,
  buildGpgSigningHook,
  buildCosignSigningHook,
  buildPackageSigningManifest,
  DEFAULT_COSIGN_SIGNER_REFERENCE,
  DEFAULT_GPG_KEY_REFERENCE,
  PACKAGE_SIGNING_ARTIFACT_TYPE,
  sha256File,
  stableStringify,
  verifyManifestSignature,
} from '../../scripts/package-agent.mjs';
import {
  buildAgentUpdateSignablePayload,
  stableStringifyForAgentUpdate,
  verifyAgentUpdateManifest,
} from '../../agents/linux/astranull-agent.mjs';

const REPO_ROOT = process.cwd();

const SECRET_PATTERNS = [
  /ast_[A-Za-z0-9_-]{8,}/,
  /bootstrap[_-]?token/i,
  /ASTRANULL_AGENT_SIGNING_PRIVATE_KEY/,
];

function assertNoSecrets(text, label) {
  for (const pattern of SECRET_PATTERNS) {
    assert.doesNotMatch(text, pattern, `${label} must not contain secret-like content (${pattern})`);
  }
}

function ed25519PrivateKeyBase64Der() {
  const { privateKey } = generateKeyPairSync('ed25519');
  return privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');
}

const PACKAGED_AGENT_SOURCE = path.join(REPO_ROOT, 'agents/linux/astranull-agent.mjs');

const FORBIDDEN_PACKAGED_AGENT_IMPORT_PATTERNS = [
  /\.\.\/\.\.\/src\//,
  /\.\.\/src\//,
  /src\/lib\/agentAuth/,
];

describe('packaged agent source isolation', () => {
  it('does not import server-side src modules', () => {
    const source = fs.readFileSync(PACKAGED_AGENT_SOURCE, 'utf8');
    for (const pattern of FORBIDDEN_PACKAGED_AGENT_IMPORT_PATTERNS) {
      assert.doesNotMatch(
        source,
        pattern,
        `packaged agent must not reference ${pattern}`,
      );
    }
  });
});

describe('agent package builder', () => {
  it('builds tarball, manifest, and file metadata in a temp output dir', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'astranull-agent-pkg-'));
    const result = buildAgentPackage({
      repoRoot: REPO_ROOT,
      outputDir: tmp,
      version: '9.9.9-test',
      createdAt: '2026-07-01T12:00:00.000Z',
    });

    assert.ok(fs.existsSync(result.tarballPath));
    assert.ok(fs.existsSync(result.manifestPath));
    assert.equal(result.manifest.package, PACKAGE_NAME);
    assert.equal(result.manifest.version, '9.9.9-test');
    assert.equal(result.manifest.artifact.sha256, sha256File(result.tarballPath));
    assert.equal(result.manifest.artifact.size, fs.statSync(result.tarballPath).size);
    assert.equal(result.manifest.files.length, AGENT_PACKAGE_FILES.length);

    for (const entry of AGENT_PACKAGE_FILES) {
      const src = path.join(REPO_ROOT, entry.src);
      const meta = result.manifest.files.find((f) => f.path === entry.dest);
      assert.ok(meta, `manifest missing ${entry.dest}`);
      assert.equal(meta.sha256, sha256File(src));
      assert.equal(meta.size, fs.statSync(src).size);
      const staged = path.join(result.packageDir, entry.dest);
      assert.ok(fs.existsSync(staged));
    }

    assert.equal(result.manifest.signing.signed, false);
    assert.equal(result.sigPath, null);

    const manifestText = fs.readFileSync(result.manifestPath, 'utf8');
    assertNoSecrets(manifestText, 'manifest');
  });

  it('signs manifest with Ed25519 when private key env is provided', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'astranull-agent-pkg-'));
    const privateKeyBase64 = ed25519PrivateKeyBase64Der();
    const prev = process.env.ASTRANULL_AGENT_SIGNING_PRIVATE_KEY;
    process.env.ASTRANULL_AGENT_SIGNING_PRIVATE_KEY = privateKeyBase64;
    try {
      const result = buildAgentPackage({
        repoRoot: REPO_ROOT,
        outputDir: tmp,
        version: '9.9.9-signed',
        createdAt: '2026-07-01T12:00:00.000Z',
      });

      assert.equal(result.manifest.signing.signed, true);
      assert.ok(result.manifest.signing.public_key_der_base64);
      assert.ok(result.sigPath);
      const sigText = fs.readFileSync(result.sigPath, 'utf8').trim();
      assert.match(sigText, /^[A-Za-z0-9+/]+=*$/);

      assert.ok(
        verifyManifestSignature(
          result.manifest.signing.public_key_der_base64,
          result.manifest,
          sigText,
        ),
      );

      const signable = buildSignablePayload(result.manifest);
      assert.equal(stableStringify(signable), stableStringify(buildSignablePayload(result.manifest)));

      const manifestText = fs.readFileSync(result.manifestPath, 'utf8');
      const sigFileText = fs.readFileSync(result.sigPath, 'utf8');
      assertNoSecrets(manifestText, 'signed manifest');
      assertNoSecrets(sigFileText, 'signature file');
      assert.doesNotMatch(manifestText, new RegExp(privateKeyBase64.slice(0, 24)));
    } finally {
      if (prev === undefined) {
        delete process.env.ASTRANULL_AGENT_SIGNING_PRIVATE_KEY;
      } else {
        process.env.ASTRANULL_AGENT_SIGNING_PRIVATE_KEY = prev;
      }
    }
  });

  it('writes metadata-only signing manifest with gpg and cosign hooks', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'astranull-agent-signing-'));
    const result = buildAgentPackage({
      repoRoot: REPO_ROOT,
      outputDir: tmp,
      version: '9.9.9-signing',
      createdAt: '2026-07-01T12:00:00.000Z',
      formats: ['deb'],
      containerDigestSha256: 'd'.repeat(64),
    });

    assert.ok(result.signingManifestPath);
    assert.ok(fs.existsSync(result.signingManifestPath));
    const signing = JSON.parse(fs.readFileSync(result.signingManifestPath, 'utf8'));
    assert.equal(signing.artifact_type, PACKAGE_SIGNING_ARTIFACT_TYPE);
    assert.equal(signing.version, '9.9.9-signing');
    assert.ok(signing.artifacts.deb);
    assert.equal(signing.artifacts.deb.gpg.hook, 'metadata_only');
    assert.equal(signing.artifacts.deb.gpg.key_reference, DEFAULT_GPG_KEY_REFERENCE);
    assert.equal(signing.artifacts.deb.gpg.signed, false);
    assert.ok(signing.artifacts.container);
    assert.equal(signing.artifacts.container.cosign.signer_reference, DEFAULT_COSIGN_SIGNER_REFERENCE);
    assert.equal(signing.artifacts.container.digest_sha256, 'd'.repeat(64));

    const gpgHook = buildGpgSigningHook({ gpgKeyReference: 'gpg://custom/key' });
    const cosignHook = buildCosignSigningHook({ cosignSignerReference: 'cosign://custom/signer' });
    assert.equal(gpgHook.fingerprint_sha256.length, 64);
    assert.equal(cosignHook.signer_reference, 'cosign://custom/signer');

    const manifest = buildPackageSigningManifest('1.0.0', {
      deb: {
        format: 'deb',
        name: 'astranull-agent_1.0.0_all.deb',
        sha256: 'a'.repeat(64),
        size: 42,
        gpg: gpgHook,
      },
    });
    assert.equal(manifest.artifacts.deb.gpg.key_reference, 'gpg://custom/key');
    assertNoSecrets(JSON.stringify(signing), 'signing manifest');
  });

  it('agent verifier accepts signed package manifest and tarball', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'astranull-agent-pkg-'));
    const privateKeyBase64 = ed25519PrivateKeyBase64Der();
    const result = buildAgentPackage({
      repoRoot: REPO_ROOT,
      outputDir: tmp,
      version: '9.9.9-agent-verify',
      createdAt: '2026-07-01T12:00:00.000Z',
      signingPrivateKeyBase64: privateKeyBase64,
    });

    const sigText = fs.readFileSync(result.sigPath, 'utf8').trim();
    const agentSignable = buildAgentUpdateSignablePayload(result.manifest);
    const packagerSignable = buildSignablePayload(result.manifest);
    assert.equal(
      stableStringifyForAgentUpdate(agentSignable),
      stableStringify(packagerSignable),
    );

    const verified = verifyAgentUpdateManifest({
      manifest: result.manifest,
      signatureBase64: sigText,
      trustedPublicKeyDerBase64: result.manifest.signing.public_key_der_base64,
      artifactPath: result.tarballPath,
    });

    assert.equal(verified.ok, true);
    assert.equal(verified.version, '9.9.9-agent-verify');
    assert.equal(verified.artifact.name, result.manifest.artifact.name);
  });

  it('buildAgentPackage with formats deb produces a valid .deb without secrets', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'astranull-agent-deb-'));
    const result = buildAgentPackage({
      repoRoot: REPO_ROOT,
      outputDir: tmp,
      version: '9.9.9-deb',
      createdAt: '2026-07-01T12:00:00.000Z',
      formats: ['deb'],
    });

    assert.equal(result.tarballPath, null);
    assert.ok(result.debPath);
    assert.ok(fs.existsSync(result.debPath));
    assert.ok(result.nativeMetadata);
    assert.equal(result.nativeMetadata.package, PACKAGE_NAME);
    assert.equal(result.nativeMetadata.version, '9.9.9-deb');

    const deb = fs.readFileSync(result.debPath);
    assert.equal(deb.slice(0, 8).toString('utf8'), '!<arch>\n');
    const members = listDebArMembers(deb);
    assert.deepEqual(
      members.map((m) => m.name),
      ['debian-binary', 'control.tar.gz', 'data.tar.gz'],
    );
    assert.equal(members[0].data.toString('utf8'), '2.0\n');

    const controlText = readDebControlText(deb);
    assert.match(controlText, /^Package: astranull-agent/m);
    assert.match(controlText, /^Version: 9.9.9-deb/m);
    assert.match(controlText, /^Depends: nodejs \(>= 20\)/m);
    assert.match(controlText, /^Architecture: all/m);
    assert.match(controlText, /AstraNull outbound validation agent/);
    assertNoSecrets(controlText, 'deb control');

    const debScan = deb.toString('latin1');
    assertNoSecrets(debScan, 'deb archive');

    const dataPaths = listDebDataTarPaths(deb).map((e) => e.path);
    const binaryPath = NATIVE_AGENT_PACKAGE_FILES.find(
      (e) => e.dest === '/usr/local/bin/astranull-agent.mjs',
    ).dest.replace(/^\//, '');
    const systemdPath = NATIVE_AGENT_PACKAGE_FILES.find(
      (e) => e.dest === '/etc/systemd/system/astranull-agent.service',
    ).dest.replace(/^\//, '');
    const envExamplePath = NATIVE_AGENT_ENV_EXAMPLE_PATH.replace(/^\//, '');
    const stateDirPath = 'var/lib/astranull';

    assert.ok(dataPaths.some((p) => p.includes(binaryPath) || p === `./${binaryPath}`));
    assert.ok(dataPaths.some((p) => p.includes(systemdPath) || p === `./${systemdPath}`));
    assert.ok(
      dataPaths.some(
        (p) => p.includes(envExamplePath) || p === `./${envExamplePath}`,
      ),
    );
    assert.ok(
      dataPaths.some(
        (p) => p === stateDirPath || p === `./${stateDirPath}` || p.endsWith('var/lib/astranull'),
      ),
    );
    assert.ok(!dataPaths.some((p) => p.includes('/etc/astranull/agent.env') && !p.includes('.example')));
    assert.ok(!dataPaths.some((p) => /bootstrap[_-]?token/i.test(p)));
  });

  it('native staged tree includes install paths and no bootstrap token', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'astranull-agent-native-'));
    const { stageDir } = stageNativeAgentTree(REPO_ROOT, path.join(tmp, 'root'));

    for (const entry of NATIVE_AGENT_PACKAGE_FILES) {
      const rel = entry.dest.replace(/^\//, '');
      const staged = path.join(stageDir, rel);
      assert.ok(fs.existsSync(staged), `missing staged ${entry.dest}`);
    }

    const envExample = path.join(stageDir, NATIVE_AGENT_ENV_EXAMPLE_PATH.replace(/^\//, ''));
    assert.ok(fs.existsSync(envExample));
    assert.ok(!fs.existsSync(path.join(stageDir, 'etc/astranull/agent.env')));

    const tokenPath = path.join(stageDir, 'var/lib/astranull/bootstrap-token');
    assert.ok(!fs.existsSync(tokenPath));

    const treeText = fs.readFileSync(envExample, 'utf8');
    assertNoSecrets(treeText, 'native env example');
    assert.match(treeText, /your-astranull-control-plane/);
  });

  it('RPM spec and buildroot contain safe paths and no secrets', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'astranull-agent-rpm-'));
    const rpm = buildRpmPackage({
      repoRoot: REPO_ROOT,
      outputDir: tmp,
      version: '9.9.9-rpm',
      rpmSpecOnly: true,
    });

    assert.ok(fs.existsSync(rpm.specPath));
    assert.ok(fs.existsSync(rpm.buildroot));
    const specText = fs.readFileSync(rpm.specPath, 'utf8');
    assert.match(specText, /^Name:\s+astranull-agent/m);
    assert.match(specText, /Requires:\s+nodejs >= 20/);
    assert.match(specText, /\/usr\/local\/bin\/astranull-agent\.mjs/);
    assert.match(specText, /\/etc\/astranull\/agent\.env\.example/);
    assertNoSecrets(specText, 'rpm spec');

    const buildrootBin = path.join(rpm.buildroot, 'usr/local/bin/astranull-agent.mjs');
    const buildrootUnit = path.join(
      rpm.buildroot,
      'etc/systemd/system/astranull-agent.service',
    );
    const buildrootEnv = path.join(rpm.buildroot, 'etc/astranull/agent.env.example');
    assert.ok(fs.existsSync(buildrootBin));
    assert.ok(fs.existsSync(buildrootUnit));
    assert.ok(fs.existsSync(buildrootEnv));
    assert.ok(!fs.existsSync(path.join(rpm.buildroot, 'var/lib/astranull/bootstrap-token')));
  });

  it('RPM build uses injected exec runner and returns predictable rpm path', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'astranull-agent-rpm-exec-'));
    const version = '9.9.9-rpm-fake';
    const calls = [];
    const fakeExec = (cmd, args, opts) => {
      calls.push({ cmd, args, opts });
      let topDir = null;
      for (let i = 0; i < args.length; i += 1) {
        if (args[i] === '--define' && typeof args[i + 1] === 'string' && args[i + 1].startsWith('_topdir ')) {
          topDir = args[i + 1].slice('_topdir '.length).trim();
          break;
        }
      }
      assert.ok(topDir, 'fake rpmbuild runner must receive _topdir define');
      const rpmsNoarch = path.join(topDir, 'RPMS', 'noarch');
      fs.mkdirSync(rpmsNoarch, { recursive: true });
      const rpmName = `${PACKAGE_NAME}-${version}-1.noarch.rpm`;
      fs.writeFileSync(path.join(rpmsNoarch, rpmName), 'fake-rpm-payload-from-test-runner\n', 'utf8');
    };

    const rpm = buildRpmPackage({
      repoRoot: REPO_ROOT,
      outputDir: tmp,
      version,
      execFileSync: fakeExec,
    });

    assert.equal(calls.length, 1);
    assert.equal(calls[0].cmd, 'rpmbuild');
    assert.ok(calls[0].args.includes('-bb'));
    assert.ok(rpm.rpmPath);
    assert.equal(rpm.rpmPath, rpm.expectedRpmPath);
    assert.ok(fs.existsSync(rpm.rpmPath));
    assertNoSecrets(fs.readFileSync(rpm.specPath, 'utf8'), 'rpm spec after fake build');
  });

  it('RPM build with injected exec throws when no artifact is produced', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'astranull-agent-rpm-no-artifact-'));
    const noopExec = () => {};

    assert.throws(
      () =>
        buildRpmPackage({
          repoRoot: REPO_ROOT,
          outputDir: tmp,
          version: '9.9.9-rpm-no-artifact',
          execFileSync: noopExec,
        }),
      /rpmbuild did not produce an RPM artifact/,
    );
  });

  it('throws when rpm is requested without rpmbuild unless spec-only', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'astranull-agent-rpm-miss-'));
    assert.throws(
      () =>
        buildRpmPackage({
          repoRoot: REPO_ROOT,
          outputDir: tmp,
          version: '9.9.9-rpm-miss',
          rpmbuildAvailable: false,
        }),
      /rpmbuild not found/,
    );
    assert.doesNotThrow(() =>
      buildRpmPackage({
        repoRoot: REPO_ROOT,
        outputDir: tmp,
        version: '9.9.9-rpm-spec',
        rpmSpecOnly: true,
        rpmbuildAvailable: false,
      }),
    );
  });
});

describe('agent package CLI and helpers', () => {
  it('parseCliArgs defaults to tarball-only formats', () => {
    const parsed = parseCliArgs(['node', 'package-agent.mjs']);
    assert.equal(parsed.formats.join(','), 'tarball');
    assert.equal(parsed.rpmSpecOnly, false);
  });

  it('parseCliArgs expands all and deb,rpm', () => {
    const all = parseCliArgs(['node', 'package-agent.mjs', '--format', 'all']);
    assert.deepEqual(all.formats, ['tarball', 'deb', 'rpm']);
    const native = parseCliArgs([
      'node',
      'package-agent.mjs',
      '--format',
      'deb,rpm',
      '--rpm-spec-only',
    ]);
    assert.deepEqual(native.formats, ['deb', 'rpm']);
    assert.equal(native.rpmSpecOnly, true);
  });

  it('normalizePackageFormats rejects unknown values', () => {
    assert.throws(() => normalizePackageFormats(['snap']), /unknown package format/);
  });

  it('buildDebianControlFields includes maintainer and node dependency', () => {
    const fields = buildDebianControlFields('1.2.3');
    assert.equal(fields.Package, PACKAGE_NAME);
    assert.equal(fields.Version, '1.2.3');
    assert.equal(fields.Depends, 'nodejs (>= 20)');
    assert.equal(fields.Maintainer, DEBIAN_MAINTAINER);
  });
});