#!/usr/bin/env node
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from 'node:crypto';
import { execFileSync as defaultExecFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { gunzipSync, gzipSync } from 'node:zlib';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '..');

export const PACKAGE_NAME = 'astranull-agent';

export const AGENT_PACKAGE_FORMATS = ['tarball', 'deb', 'rpm', 'all'];

/** Repo-relative sources mapped to paths inside the tarball root directory. */
export const AGENT_PACKAGE_FILES = [
  { src: 'agents/linux/astranull-agent.mjs', dest: 'astranull-agent.mjs' },
  { src: 'agents/linux/install.sh', dest: 'install.sh' },
  { src: 'agents/linux/uninstall.sh', dest: 'uninstall.sh' },
  { src: 'agents/linux/systemd/astranull-agent.service', dest: 'systemd/astranull-agent.service' },
];

/** Install paths for distro-native packages (absolute paths on target hosts). */
export const NATIVE_AGENT_PACKAGE_FILES = [
  {
    src: 'agents/linux/astranull-agent.mjs',
    dest: '/usr/local/bin/astranull-agent.mjs',
    mode: 0o755,
  },
  {
    src: 'agents/linux/systemd/astranull-agent.service',
    dest: '/etc/systemd/system/astranull-agent.service',
    mode: 0o644,
  },
];

export const NATIVE_AGENT_ENV_EXAMPLE_PATH = '/etc/astranull/agent.env.example';
export const NATIVE_AGENT_STATE_DIR = '/var/lib/astranull';

export const DEBIAN_MAINTAINER = 'AstraNull Packaging <packaging@astranull.invalid>';
export const DEBIAN_HOMEPAGE = 'https://astranull.invalid/';

export const SIGNING_ALGORITHM = 'Ed25519';

export const PACKAGE_SIGNING_SCHEMA_VERSION = 1;
export const PACKAGE_SIGNING_ARTIFACT_TYPE = 'agent_package_signing';
export const PACKAGE_SIGNING_FORMATS = Object.freeze(['tarball', 'deb', 'rpm', 'container']);

export const DEFAULT_GPG_KEY_REFERENCE = 'gpg://astranull/agent-package-signing';
export const DEFAULT_COSIGN_SIGNER_REFERENCE = 'cosign://astranull/agent-release-signer';

const NATIVE_TAR_MTIME = 1704067200; // 2024-01-01T00:00:00Z — stable archive metadata

/** Canonical JSON aligned with sorted keys for deterministic signatures. */
export function stableStringify(value) {
  if (value === undefined) {
    return 'null';
  }
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((v) => (v === undefined ? 'null' : stableStringify(v))).join(',')}]`;
  }
  const keys = Object.keys(value).sort().filter((k) => value[k] !== undefined);
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(value[k])}`).join(',')}}`;
}

export function sha256Buffer(data) {
  return createHash('sha256').update(data).digest('hex');
}

export function sha256File(filePath) {
  return sha256Buffer(fs.readFileSync(filePath));
}

export function readDefaultVersion(repoRoot = ROOT) {
  const pkg = JSON.parse(fs.readFileSync(path.join(repoRoot, 'package.json'), 'utf8'));
  return pkg.version;
}

export function artifactBaseName(version) {
  return `${PACKAGE_NAME}-${version}`;
}

export function normalizePackageFormats(formats) {
  if (formats === undefined || formats === null) {
    return ['tarball'];
  }
  const list = Array.isArray(formats) ? formats : [formats];
  if (list.length === 0) {
    return ['tarball'];
  }
  const expanded = [];
  for (const item of list) {
    if (item === 'all') {
      expanded.push('tarball', 'deb', 'rpm');
    } else if (AGENT_PACKAGE_FORMATS.includes(item)) {
      expanded.push(item);
    } else {
      throw new Error(`package-agent: unknown package format ${item}`);
    }
  }
  return [...new Set(expanded)];
}

/** Debian control file fields for the agent package. */
export function buildDebianControlFields(version, options = {}) {
  const architecture = options.architecture ?? 'all';
  const description = options.description
    ?? 'AstraNull outbound validation agent (metadata-only observation).';
  return {
    Package: PACKAGE_NAME,
    Version: version,
    Architecture: architecture,
    Maintainer: DEBIAN_MAINTAINER,
    Section: 'admin',
    Priority: 'optional',
    Depends: 'nodejs (>= 20)',
    Homepage: DEBIAN_HOMEPAGE,
    Description: description,
  };
}

export function formatDebianControl(fields) {
  const order = [
    'Package',
    'Version',
    'Architecture',
    'Maintainer',
    'Section',
    'Priority',
    'Depends',
    'Homepage',
    'Description',
  ];
  const lines = [];
  for (const key of order) {
    if (fields[key] !== undefined) {
      lines.push(`${key}: ${fields[key]}`);
    }
  }
  return `${lines.join('\n')}\n`;
}

export function agentEnvExampleContent() {
  return [
    '# Example configuration — copy to /etc/astranull/agent.env before enabling the service.',
    '# Do not store enrollment secrets or API credentials in world-readable files.',
    'ASTRANULL_API_URL=https://your-astranull-control-plane.example',
    '# ASTRANULL_AGENT_NAME=my-agent',
    '# Complete enrollment separately; packages never ship operator secrets.',
    '',
  ].join('\n');
}

const DEBIAN_POSTINST = `#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
fi
# Service is not enabled or started until operator configures agent.env and bootstrap.
exit 0
`;

const DEBIAN_PRERM = `#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
  systemctl stop astranull-agent.service 2>/dev/null || true
fi
exit 0
`;

/** Payload covered by Ed25519 signature (manifest body without signature fields). */
export function buildSignablePayload(manifest) {
  return {
    artifact: manifest.artifact,
    created_at: manifest.created_at,
    files: manifest.files,
    package: manifest.package,
    version: manifest.version,
  };
}

export function buildNativePackageMetadata(version, options = {}) {
  const createdAt = options.createdAt ?? new Date().toISOString();
  return {
    package: PACKAGE_NAME,
    version,
    created_at: createdAt,
    formats: options.formats ?? ['deb', 'rpm'],
    install_paths: {
      binary: '/usr/local/bin/astranull-agent.mjs',
      systemd_unit: '/etc/systemd/system/astranull-agent.service',
      env_example: NATIVE_AGENT_ENV_EXAMPLE_PATH,
      state_dir: NATIVE_AGENT_STATE_DIR,
    },
    debian: buildDebianControlFields(version, options.debian),
  };
}

export function loadEd25519PrivateKeyFromBase64Der(privateKeyBase64) {
  const keyDer = Buffer.from(privateKeyBase64, 'base64');
  return createPrivateKey({ key: keyDer, format: 'der', type: 'pkcs8' });
}

export function ed25519PublicKeyDerBase64(privateKey) {
  const publicKey = createPublicKey(privateKey);
  return publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
}

export function signCanonicalPayload(privateKeyBase64, signablePayload) {
  const privateKey = loadEd25519PrivateKeyFromBase64Der(privateKeyBase64);
  const message = Buffer.from(stableStringify(signablePayload), 'utf8');
  const signature = sign(null, message, privateKey);
  return {
    signatureBase64: signature.toString('base64'),
    publicKeyDerBase64: ed25519PublicKeyDerBase64(privateKey),
  };
}

export function verifyManifestSignature(publicKeyDerBase64, manifest, signatureBase64) {
  const publicKey = createPublicKey({
    key: Buffer.from(publicKeyDerBase64, 'base64'),
    format: 'der',
    type: 'spki',
  });
  const signable = buildSignablePayload(manifest);
  const message = Buffer.from(stableStringify(signable), 'utf8');
  const signature = Buffer.from(signatureBase64, 'base64');
  return verify(null, message, publicKey, signature);
}

function artifactRecordFromFile(name, filePath) {
  const data = fs.readFileSync(filePath);
  return {
    name,
    sha256: sha256Buffer(data),
    size: data.length,
  };
}

/** Metadata-only GPG signing hook for native packages (no private keys or signatures). */
export function buildGpgSigningHook(options = {}) {
  const keyReference = options.gpgKeyReference ?? DEFAULT_GPG_KEY_REFERENCE;
  return {
    hook: 'metadata_only',
    algorithm: 'gpg',
    key_reference: keyReference,
    fingerprint_sha256: sha256Buffer(Buffer.from(keyReference, 'utf8')),
    signed: options.gpgSigned === true,
    signature_uri: options.gpgSignatureUri ?? null,
  };
}

/** Metadata-only cosign signing hook for container images (no private keys or signatures). */
export function buildCosignSigningHook(options = {}) {
  const signerReference = options.cosignSignerReference ?? DEFAULT_COSIGN_SIGNER_REFERENCE;
  return {
    hook: 'metadata_only',
    algorithm: 'cosign',
    signer_reference: signerReference,
    signed: options.cosignSigned === true,
    signature_uri: options.cosignSignatureUri ?? null,
  };
}

export function buildTarballSigningArtifactEntry(manifest, options = {}) {
  if (!manifest?.artifact) {
    return null;
  }
  const entry = {
    format: 'tarball',
    name: manifest.artifact.name,
    sha256: manifest.artifact.sha256,
    size: manifest.artifact.size,
    ed25519: {
      algorithm: SIGNING_ALGORITHM,
      signed: manifest.signing?.signed === true,
      public_key_der_base64: manifest.signing?.public_key_der_base64 ?? null,
      manifest_name: options.manifestName ?? null,
      signature_name: options.signatureName ?? null,
    },
  };
  return entry;
}

export function buildNativeSigningArtifactEntry(format, artifact, options = {}) {
  if (!artifact?.name || !artifact?.sha256 || !Number.isInteger(artifact.size)) {
    return null;
  }
  return {
    format,
    name: artifact.name,
    sha256: artifact.sha256,
    size: artifact.size,
    gpg: buildGpgSigningHook(options),
  };
}

export function buildContainerSigningArtifactEntry(options = {}) {
  const image = options.containerImage ?? 'astranull-agent:local';
  const digestSha256 = options.containerDigestSha256 ?? null;
  return {
    format: 'container',
    image,
    digest_sha256: digestSha256,
    cosign: buildCosignSigningHook(options),
  };
}

/**
 * Build a metadata-only signing manifest covering tarball Ed25519 plus GPG/cosign hooks.
 * Does not invoke gpg, cosign, or external signing tools.
 */
export function buildPackageSigningManifest(version, artifacts = {}, options = {}) {
  const createdAt = options.createdAt ?? new Date().toISOString();
  const entries = {};
  if (artifacts.tarball) entries.tarball = artifacts.tarball;
  if (artifacts.deb) entries.deb = artifacts.deb;
  if (artifacts.rpm) entries.rpm = artifacts.rpm;
  if (artifacts.container) entries.container = artifacts.container;

  return {
    schema_version: PACKAGE_SIGNING_SCHEMA_VERSION,
    artifact_type: PACKAGE_SIGNING_ARTIFACT_TYPE,
    package: PACKAGE_NAME,
    version,
    created_at: createdAt,
    artifacts: entries,
    caveats: [
      'Metadata-only signing manifest: records artifact digests and trust-anchor references without private keys or live GPG/cosign signatures.',
      'Tarball Ed25519 signatures are produced only when a release signing private key is configured at package build time.',
      'Native deb/rpm and container hooks document expected GPG/cosign trust anchors for installer-side enforcement.',
    ],
  };
}

function octalField(num, len) {
  return num.toString(8).padStart(len - 1, '0') + '\0';
}

function writeOctalField(header, offset, len, value) {
  const str = octalField(value, len);
  for (let i = 0; i < len; i += 1) {
    header[offset + i] = str.charCodeAt(i);
  }
}

function decimalField(num, len) {
  return String(num).padStart(len - 1, ' ') + '\0';
}

/** Minimal ustar tar writer for reproducible native package payloads. */
export function buildUstarTar(entries) {
  const sorted = [...entries].sort((a, b) => a.name.localeCompare(b.name));
  const chunks = [];
  for (const entry of sorted) {
    const header = Buffer.alloc(512, 0);
    const name = entry.name;
    if (name.length > 100) {
      throw new Error(`package-agent: tar path too long: ${name}`);
    }
    header.write(name, 0, name.length, 'utf8');
    const mode = entry.mode ?? (entry.type === 'directory' ? 0o755 : 0o644);
    writeOctalField(header, 100, 8, mode);
    writeOctalField(header, 108, 8, 0);
    writeOctalField(header, 116, 8, 0);
    const size = entry.type === 'directory' ? 0 : (entry.content?.length ?? 0);
    writeOctalField(header, 124, 12, size);
    writeOctalField(header, 136, 12, NATIVE_TAR_MTIME);
    header.fill(0x20, 148, 156);
    header[156] = entry.type === 'directory' ? '5'.charCodeAt(0) : '0'.charCodeAt(0);
    header.write('ustar\0', 257, 6, 'utf8');
    header.write('00', 263, 2, 'utf8');
    let checksum = 0;
    for (let i = 0; i < 512; i += 1) {
      checksum += header[i];
    }
    writeOctalField(header, 148, 8, checksum);
    chunks.push(header);
    if (entry.type !== 'directory' && entry.content && entry.content.length > 0) {
      chunks.push(entry.content);
      const pad = (512 - (entry.content.length % 512)) % 512;
      if (pad > 0) {
        chunks.push(Buffer.alloc(pad));
      }
    }
  }
  chunks.push(Buffer.alloc(512));
  chunks.push(Buffer.alloc(512));
  return Buffer.concat(chunks);
}

export function buildTarGz(entries) {
  const tar = buildUstarTar(entries);
  return gzipSync(tar, { level: 9, mtime: NATIVE_TAR_MTIME });
}

/** Build a Debian `.deb` ar archive (no dpkg-deb required). */
export function buildArArchive(members) {
  const parts = [Buffer.from('!<arch>\n', 'utf8')];
  for (const member of members) {
    const name = member.name.padEnd(16, ' ');
    const mtime = decimalField(member.mtime ?? NATIVE_TAR_MTIME, 12);
    const uid = decimalField(0, 6);
    const gid = decimalField(0, 6);
    const mode = octalField(member.mode ?? 0o644, 8);
    const size = decimalField(member.data.length, 10);
    const header = Buffer.from(`${name}${mtime}${uid}${gid}${mode}${size}\`` + '\n', 'utf8');
    parts.push(header, member.data);
    if (member.data.length % 2 === 1) {
      parts.push(Buffer.from('\n', 'utf8'));
    }
  }
  return Buffer.concat(parts);
}

export function listDebArMembers(debBuffer) {
  if (!debBuffer.slice(0, 8).equals(Buffer.from('!<arch>\n'))) {
    throw new Error('package-agent: not a deb ar archive');
  }
  let offset = 8;
  const members = [];
  while (offset < debBuffer.length) {
    const header = debBuffer.slice(offset, offset + 60);
    if (header.length < 60) {
      break;
    }
    const name = header.slice(0, 16).toString('utf8').trim();
    const size = Number.parseInt(header.slice(48, 58).toString('utf8').trim(), 10);
    offset += 60;
    const data = debBuffer.slice(offset, offset + size);
    offset += size;
    if (size % 2 === 1) {
      offset += 1;
    }
    members.push({ name, size, data });
  }
  return members;
}

export function readDebControlText(debBuffer) {
  const members = listDebArMembers(debBuffer);
  const controlMember = members.find((m) => m.name === 'control.tar.gz');
  if (!controlMember) {
    throw new Error('package-agent: deb missing control.tar.gz');
  }
  const controlTar = gunzipSync(controlMember.data);
  const controlEntry = extractTarFileByName(controlTar, './control');
  if (!controlEntry) {
    throw new Error('package-agent: control.tar.gz missing control file');
  }
  return controlEntry.toString('utf8');
}

function extractTarFileByName(tarBuffer, targetName) {
  let offset = 0;
  while (offset + 512 <= tarBuffer.length) {
    const header = tarBuffer.slice(offset, offset + 512);
    if (header.every((b) => b === 0)) {
      break;
    }
    const name = header.slice(0, 100).toString('utf8').replace(/\0/g, '').trim();
    const sizeOctal = header.slice(124, 136).toString('utf8').replace(/\0/g, '').trim();
    const size = Number.parseInt(sizeOctal, 8) || 0;
    const typeflag = header[156];
    offset += 512;
    const normalized = name.startsWith('./') ? name : `./${name}`;
    const want = targetName.startsWith('./') ? targetName : `./${targetName}`;
    if (typeflag === 0 || typeflag === 48) {
      const content = tarBuffer.slice(offset, offset + size);
      if (normalized === want || name === targetName.replace(/^\.\//, '')) {
        return content;
      }
    }
    offset += size;
    offset += (512 - (size % 512)) % 512;
  }
  return null;
}

export function listDebDataTarPaths(debBuffer) {
  const members = listDebArMembers(debBuffer);
  const dataMember = members.find((m) => m.name === 'data.tar.gz');
  if (!dataMember) {
    throw new Error('package-agent: deb missing data.tar.gz');
  }
  const dataTar = gunzipSync(dataMember.data);
  const paths = [];
  let offset = 0;
  while (offset + 512 <= dataTar.length) {
    const header = dataTar.slice(offset, offset + 512);
    if (header.every((b) => b === 0)) {
      break;
    }
    const name = header.slice(0, 100).toString('utf8').replace(/\0/g, '').trim();
    const sizeOctal = header.slice(124, 136).toString('utf8').replace(/\0/g, '').trim();
    const size = Number.parseInt(sizeOctal, 8) || 0;
    const typeflag = header[156];
    offset += 512;
    if (name) {
      paths.push({ path: name, type: typeflag === 53 ? 'directory' : 'file' });
    }
    offset += size;
    offset += (512 - (size % 512)) % 512;
  }
  return paths;
}

function destToTarPath(destPath) {
  const trimmed = destPath.replace(/^\//, '');
  return `./${trimmed}`;
}

/**
 * Stage native install tree under stageDir (paths mirror absolute install locations).
 */
export function stageNativeAgentTree(repoRoot, stageDir, options = {}) {
  if (fs.existsSync(stageDir)) {
    fs.rmSync(stageDir, { recursive: true, force: true });
  }
  fs.mkdirSync(stageDir, { recursive: true });

  const stagedFiles = [];
  for (const entry of NATIVE_AGENT_PACKAGE_FILES) {
    const srcPath = path.join(repoRoot, entry.src);
    if (!fs.existsSync(srcPath)) {
      throw new Error(`package-agent: missing source file ${entry.src}`);
    }
    const rel = entry.dest.replace(/^\//, '');
    const destPath = path.join(stageDir, rel);
    fs.mkdirSync(path.dirname(destPath), { recursive: true });
    fs.copyFileSync(srcPath, destPath);
    fs.chmodSync(destPath, entry.mode);
    stagedFiles.push({
      dest: entry.dest,
      sha256: sha256File(destPath),
      mode: entry.mode,
    });
  }

  const envExampleRel = NATIVE_AGENT_ENV_EXAMPLE_PATH.replace(/^\//, '');
  const envExamplePath = path.join(stageDir, envExampleRel);
  fs.mkdirSync(path.dirname(envExamplePath), { recursive: true });
  const envContent = options.envExampleContent ?? agentEnvExampleContent();
  fs.writeFileSync(envExamplePath, envContent, 'utf8');
  fs.chmodSync(envExamplePath, 0o644);
  stagedFiles.push({
    dest: NATIVE_AGENT_ENV_EXAMPLE_PATH,
    sha256: sha256Buffer(Buffer.from(envContent, 'utf8')),
    mode: 0o644,
  });

  const stateDirRel = NATIVE_AGENT_STATE_DIR.replace(/^\//, '');
  const stateDirPath = path.join(stageDir, stateDirRel);
  fs.mkdirSync(stateDirPath, { recursive: true });
  fs.chmodSync(stateDirPath, 0o755);
  stagedFiles.push({
    dest: `${NATIVE_AGENT_STATE_DIR}/`,
    sha256: null,
    mode: 0o755,
  });

  stagedFiles.sort((a, b) => a.dest.localeCompare(b.dest));
  return { stageDir, stagedFiles, envExampleContent: envContent };
}

function nativeTreeToDataTarEntries(stageDir) {
  const entries = [];
  function walk(relDir) {
    const abs = path.join(stageDir, relDir);
    const names = fs.readdirSync(abs).sort();
    for (const name of names) {
      const rel = relDir ? `${relDir}/${name}` : name;
      const full = path.join(stageDir, rel);
      const stat = fs.statSync(full);
      const tarName = destToTarPath(`/${rel}`);
      if (stat.isDirectory()) {
        entries.push({ name: tarName, type: 'directory', mode: stat.mode & 0o777 });
        walk(rel);
      } else {
        entries.push({
          name: tarName,
          type: 'file',
          mode: stat.mode & 0o777,
          content: fs.readFileSync(full),
        });
      }
    }
  }
  walk('');
  return entries;
}

/**
 * Build a `.deb` package from a staged native tree.
 */
export function buildDebianPackage(options = {}) {
  const repoRoot = options.repoRoot ?? ROOT;
  const outputDir = path.resolve(options.outputDir ?? path.join(repoRoot, 'dist', 'agent'));
  const version = options.version ?? readDefaultVersion(repoRoot);
  const stageDir = options.nativeStageDir
    ?? stageNativeAgentTree(repoRoot, path.join(outputDir, `${artifactBaseName(version)}-native-root`), options).stageDir;

  const controlFields = buildDebianControlFields(version, options.debian);
  const controlText = formatDebianControl(controlFields);
  const controlEntries = [
    { name: './control', type: 'file', mode: 0o644, content: Buffer.from(controlText, 'utf8') },
    { name: './postinst', type: 'file', mode: 0o755, content: Buffer.from(DEBIAN_POSTINST, 'utf8') },
    { name: './prerm', type: 'file', mode: 0o755, content: Buffer.from(DEBIAN_PRERM, 'utf8') },
  ];
  const controlTarGz = buildTarGz(controlEntries);
  const dataTarGz = buildTarGz(nativeTreeToDataTarEntries(stageDir));

  const debBuffer = buildArArchive([
    { name: 'debian-binary', mode: 0o644, data: Buffer.from('2.0\n', 'utf8') },
    { name: 'control.tar.gz', mode: 0o644, data: controlTarGz },
    { name: 'data.tar.gz', mode: 0o644, data: dataTarGz },
  ]);

  fs.mkdirSync(outputDir, { recursive: true });
  const debPath = path.join(outputDir, `${artifactBaseName(version)}.deb`);
  fs.writeFileSync(debPath, debBuffer);

  return {
    debPath,
    controlFields,
    size: debBuffer.length,
    sha256: sha256Buffer(debBuffer),
  };
}

export function buildRpmSpecContent(version, options = {}) {
  const release = options.release ?? '1';
  const summary = options.summary ?? 'AstraNull outbound validation agent';
  const description = options.description
    ?? 'Outbound-only validation agent for AstraNull readiness checks.';
  const distTag = '%{?dist}';
  return [
    '%define _build_id_links none',
    `Name:           ${PACKAGE_NAME}`,
    `Version:        ${version}`,
    `Release:        ${release}${distTag}`,
    `Summary:        ${summary}`,
    'License:        Proprietary',
    `URL:            ${DEBIAN_HOMEPAGE}`,
    'BuildArch:      noarch',
    'Requires:       nodejs >= 20',
    '',
    '%description',
    description,
    'Packages install the agent binary and systemd unit. Operators must configure',
    '/etc/astranull/agent.env and bootstrap credentials before starting the service.',
    '',
    '%prep',
    '# No separate prep — files are staged in BUILDROOT by the packager.',
    '',
    '%build',
    '# No compile step — Node.js agent script.',
    '',
    '%install',
    '# %install populated by package-agent buildroot staging',
    '',
    '%post',
    'if command -v systemctl >/dev/null 2>&1; then',
    '  systemctl daemon-reload || true',
    'fi',
    '# Do not enable or start without operator configuration.',
    '',
    '%preun',
    'if command -v systemctl >/dev/null 2>&1; then',
    '  systemctl stop astranull-agent.service 2>/dev/null || true',
    'fi',
    '',
    '%files',
    '%defattr(-,root,root,-)',
    '/usr/local/bin/astranull-agent.mjs',
    '/etc/systemd/system/astranull-agent.service',
    '/etc/astranull/agent.env.example',
    '%dir %attr(0755,root,root) /var/lib/astranull',
    '',
  ].join('\n');
}

/**
 * Prepare RPM spec, SOURCES, and BUILDROOT tree mirroring native install paths.
 */
export function prepareRpmBuild(options = {}) {
  const repoRoot = options.repoRoot ?? ROOT;
  const outputDir = path.resolve(options.outputDir ?? path.join(repoRoot, 'dist', 'agent'));
  const version = options.version ?? readDefaultVersion(repoRoot);
  const base = artifactBaseName(version);
  const topDir = path.join(outputDir, `${base}-rpm`);
  const buildroot = path.join(topDir, 'BUILDROOT', `${PACKAGE_NAME}-${version}-1.x86_64`);

  const { stageDir } = options.nativeStageDir
    ? { stageDir: options.nativeStageDir }
    : stageNativeAgentTree(repoRoot, path.join(outputDir, `${base}-native-root`), options);

  if (fs.existsSync(buildroot)) {
    fs.rmSync(buildroot, { recursive: true, force: true });
  }
  fs.mkdirSync(buildroot, { recursive: true });

  function copyTree(src, dest) {
    fs.mkdirSync(dest, { recursive: true });
    for (const name of fs.readdirSync(src).sort()) {
      const srcPath = path.join(src, name);
      const destPath = path.join(dest, name);
      const stat = fs.statSync(srcPath);
      if (stat.isDirectory()) {
        copyTree(srcPath, destPath);
      } else {
        fs.copyFileSync(srcPath, destPath);
        fs.chmodSync(destPath, stat.mode & 0o777);
      }
    }
  }
  copyTree(stageDir, buildroot);

  fs.mkdirSync(path.join(topDir, 'SPECS'), { recursive: true });
  fs.mkdirSync(path.join(topDir, 'SOURCES'), { recursive: true });
  fs.mkdirSync(path.join(topDir, 'RPMS'), { recursive: true });
  fs.mkdirSync(path.join(topDir, 'SRPMS'), { recursive: true });
  fs.mkdirSync(path.join(topDir, 'BUILD'), { recursive: true });

  const specPath = path.join(topDir, 'SPECS', `${PACKAGE_NAME}.spec`);
  fs.writeFileSync(specPath, buildRpmSpecContent(version, options.rpm), 'utf8');

  const expectedRpmPath = path.join(topDir, 'RPMS', 'noarch', `${base}-1.noarch.rpm`);

  return {
    topDir,
    specPath,
    buildroot,
    expectedRpmPath,
    version,
  };
}

export function isRpmbuildAvailable(execFileSync = defaultExecFileSync) {
  try {
    execFileSync('rpmbuild', ['--version'], { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

/**
 * Build RPM artifact when rpmbuild is available, or spec/buildroot only when requested.
 */
export function buildRpmPackage(options = {}) {
  const rpmSpecOnly = options.rpmSpecOnly === true;
  const execFileSync = options.execFileSync ?? defaultExecFileSync;
  const prepared = prepareRpmBuild(options);

  if (rpmSpecOnly) {
    return {
      ...prepared,
      rpmPath: null,
      specOnly: true,
    };
  }

  const injectedExec = options.execFileSync !== undefined;
  const rpmbuildAvailable = options.rpmbuildAvailable
    ?? (injectedExec ? true : isRpmbuildAvailable(execFileSync));
  if (!injectedExec && !rpmSpecOnly && !rpmbuildAvailable) {
    throw new Error(
      'package-agent: rpmbuild not found on PATH; use --rpm-spec-only to generate spec/BUILDROOT only',
    );
  }

  const rpmbuildArgs = [
    '-bb',
    '--define',
    `_topdir ${prepared.topDir}`,
    '--buildroot',
    prepared.buildroot,
    prepared.specPath,
  ];

  execFileSync('rpmbuild', rpmbuildArgs, { stdio: 'pipe' });

  if (!fs.existsSync(prepared.expectedRpmPath)) {
    const rpmsDir = path.join(prepared.topDir, 'RPMS', 'noarch');
    const candidates = fs.existsSync(rpmsDir)
      ? fs.readdirSync(rpmsDir).filter((f) => f.endsWith('.rpm'))
      : [];
    if (candidates.length === 0) {
      throw new Error('package-agent: rpmbuild did not produce an RPM artifact');
    }
    const rpmPath = path.join(rpmsDir, candidates.sort()[0]);
    return { ...prepared, rpmPath, specOnly: false };
  }

  return {
    ...prepared,
    rpmPath: prepared.expectedRpmPath,
    specOnly: false,
  };
}

function assertTarAvailable(execFileSync = defaultExecFileSync) {
  try {
    execFileSync('tar', ['--version'], { stdio: 'pipe' });
  } catch {
    throw new Error('package-agent: system `tar` is required but was not found on PATH');
  }
}

function createTarball(tarballPath, parentDir, dirName, execFileSync = defaultExecFileSync) {
  assertTarAvailable(execFileSync);
  fs.mkdirSync(path.dirname(tarballPath), { recursive: true });
  execFileSync('tar', ['-czf', tarballPath, '-C', parentDir, dirName], { stdio: 'pipe' });
}

/**
 * Build generic Linux agent directory, tarball, manifest, and optional signature.
 * @returns package build result including optional native artifacts
 */
export function buildAgentPackage(options = {}) {
  const repoRoot = options.repoRoot ?? ROOT;
  const outputDir = path.resolve(options.outputDir ?? path.join(repoRoot, 'dist', 'agent'));
  const version = options.version ?? readDefaultVersion(repoRoot);
  const createdAt = options.createdAt ?? new Date().toISOString();
  const formats = normalizePackageFormats(options.formats);
  const signingPrivateKeyBase64 = options.signingPrivateKeyBase64
    ?? process.env.ASTRANULL_AGENT_SIGNING_PRIVATE_KEY
    ?? null;
  const execFileSync = options.execFileSync ?? defaultExecFileSync;

  const base = artifactBaseName(version);
  const packageDirName = base;
  const packageDir = path.join(outputDir, packageDirName);
  const tarballPath = path.join(outputDir, `${base}.tar.gz`);
  const manifestPath = path.join(outputDir, `${base}.manifest.json`);
  const sigPath = path.join(outputDir, `${base}.manifest.json.sig`);

  const signingManifestPath = path.join(outputDir, `${base}.signing.json`);

  const result = {
    outputDir,
    formats,
    packageDir: null,
    tarballPath: null,
    manifestPath: null,
    sigPath: null,
    manifest: null,
    signatureBase64: null,
    signingManifestPath: null,
    signingManifest: null,
    nativeStageDir: null,
    nativeMetadata: null,
    debPath: null,
    deb: null,
    rpmPath: null,
    rpm: null,
  };

  let nativeStageDir = null;
  if (formats.includes('deb') || formats.includes('rpm')) {
    const staged = stageNativeAgentTree(
      repoRoot,
      path.join(outputDir, `${base}-native-root`),
      options,
    );
    nativeStageDir = staged.stageDir;
    result.nativeStageDir = nativeStageDir;
    result.nativeMetadata = buildNativePackageMetadata(version, {
      createdAt,
      formats: formats.filter((f) => f === 'deb' || f === 'rpm'),
    });
  }

  if (formats.includes('tarball')) {
    if (fs.existsSync(packageDir)) {
      fs.rmSync(packageDir, { recursive: true, force: true });
    }
    fs.mkdirSync(packageDir, { recursive: true });

    const filesMeta = [];
    for (const entry of AGENT_PACKAGE_FILES) {
      const srcPath = path.join(repoRoot, entry.src);
      if (!fs.existsSync(srcPath)) {
        throw new Error(`package-agent: missing source file ${entry.src}`);
      }
      const destPath = path.join(packageDir, entry.dest);
      fs.mkdirSync(path.dirname(destPath), { recursive: true });
      fs.copyFileSync(srcPath, destPath);
      const stat = fs.statSync(destPath);
      filesMeta.push({
        path: entry.dest,
        sha256: sha256File(destPath),
        size: stat.size,
      });
    }
    filesMeta.sort((a, b) => a.path.localeCompare(b.path));

    createTarball(tarballPath, outputDir, packageDirName, execFileSync);
    const artifactStat = fs.statSync(tarballPath);
    const artifactSha256 = sha256File(tarballPath);

    const manifest = {
      package: PACKAGE_NAME,
      version,
      created_at: createdAt,
      files: filesMeta,
      artifact: {
        name: `${base}.tar.gz`,
        sha256: artifactSha256,
        size: artifactStat.size,
      },
      signing: {
        algorithm: SIGNING_ALGORITHM,
        signed: false,
      },
    };

    let signatureBase64 = null;
    if (signingPrivateKeyBase64) {
      const signable = buildSignablePayload(manifest);
      const { signatureBase64: sig, publicKeyDerBase64 } = signCanonicalPayload(
        signingPrivateKeyBase64,
        signable,
      );
      signatureBase64 = sig;
      manifest.signing = {
        algorithm: SIGNING_ALGORITHM,
        signed: true,
        public_key_der_base64: publicKeyDerBase64,
        signed_at: createdAt,
      };
      fs.writeFileSync(sigPath, `${signatureBase64}\n`, 'utf8');
    }

    fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');

    result.packageDir = packageDir;
    result.tarballPath = tarballPath;
    result.manifestPath = manifestPath;
    result.sigPath = signatureBase64 ? sigPath : null;
    result.manifest = manifest;
    result.signatureBase64 = signatureBase64;
  }

  if (formats.includes('deb')) {
    const deb = buildDebianPackage({
      ...options,
      repoRoot,
      outputDir,
      version,
      nativeStageDir,
    });
    result.debPath = deb.debPath;
    result.deb = deb;
  }

  if (formats.includes('rpm')) {
    const rpm = buildRpmPackage({
      ...options,
      repoRoot,
      outputDir,
      version,
      nativeStageDir,
    });
    result.rpm = rpm;
    result.rpmPath = rpm.rpmPath;
  }

  const signingArtifacts = {};
  if (result.manifest) {
    signingArtifacts.tarball = buildTarballSigningArtifactEntry(result.manifest, {
      manifestName: path.basename(result.manifestPath),
      signatureName: result.sigPath ? path.basename(result.sigPath) : null,
    });
  }
  if (result.deb) {
    signingArtifacts.deb = buildNativeSigningArtifactEntry(
      'deb',
      {
        name: path.basename(result.debPath),
        sha256: result.deb.sha256,
        size: result.deb.size,
      },
      options,
    );
  }
  if (result.rpmPath && fs.existsSync(result.rpmPath)) {
    signingArtifacts.rpm = buildNativeSigningArtifactEntry(
      'rpm',
      artifactRecordFromFile(path.basename(result.rpmPath), result.rpmPath),
      options,
    );
  }
  signingArtifacts.container = buildContainerSigningArtifactEntry(options);

  const signingManifest = buildPackageSigningManifest(version, signingArtifacts, {
    createdAt,
  });
  fs.mkdirSync(outputDir, { recursive: true });
  fs.writeFileSync(signingManifestPath, `${JSON.stringify(signingManifest, null, 2)}\n`, 'utf8');
  result.signingManifestPath = signingManifestPath;
  result.signingManifest = signingManifest;

  return result;
}

export function parseCliArgs(argv) {
  let outputDir = path.join(ROOT, 'dist', 'agent');
  let version = readDefaultVersion();
  let formats = ['tarball'];
  let rpmSpecOnly = false;
  let gpgKeyReference = DEFAULT_GPG_KEY_REFERENCE;
  let cosignSignerReference = DEFAULT_COSIGN_SIGNER_REFERENCE;
  let containerImage = 'astranull-agent:local';
  let containerDigestSha256 = null;
  for (let i = 2; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--output-dir') {
      outputDir = argv[i + 1] ?? '';
      i += 1;
    } else if (arg === '--version') {
      version = argv[i + 1] ?? '';
      i += 1;
    } else if (arg === '--gpg-key-reference') {
      gpgKeyReference = argv[i + 1] ?? '';
      i += 1;
    } else if (arg === '--cosign-signer-reference') {
      cosignSignerReference = argv[i + 1] ?? '';
      i += 1;
    } else if (arg === '--container-image') {
      containerImage = argv[i + 1] ?? '';
      i += 1;
    } else if (arg === '--container-digest-sha256') {
      containerDigestSha256 = argv[i + 1] ?? '';
      i += 1;
    } else if (arg === '--format') {
      const fmt = argv[i + 1] ?? '';
      i += 1;
      if (fmt === 'all') {
        formats = ['all'];
      } else {
        formats = fmt.split(',').map((s) => s.trim()).filter(Boolean);
      }
    } else if (arg === '--rpm-spec-only') {
      rpmSpecOnly = true;
    } else if (arg === '-h' || arg === '--help') {
      console.log(`Usage: node scripts/package-agent.mjs [options]

Options:
  --output-dir <path>     Output directory (default dist/agent)
  --version <ver>         Package version (default package.json version)
  --format <fmt>          tarball|deb|rpm|all (comma-separated; default tarball)
  --rpm-spec-only         Generate RPM spec/BUILDROOT only (no rpmbuild)
  --gpg-key-reference <ref>       GPG trust anchor reference for deb/rpm hooks
  --cosign-signer-reference <ref> Cosign signer reference for container hook
  --container-image <ref>         Container image reference for signing manifest hook
  --container-digest-sha256 <hex> Optional image digest for container hook

Environment:
  ASTRANULL_AGENT_SIGNING_PRIVATE_KEY  Optional base64 DER PKCS#8 Ed25519 private key

Creates ${PACKAGE_NAME} Linux packages under the output directory.`);
      process.exit(0);
    } else {
      throw new Error(`package-agent: unknown argument ${arg}`);
    }
  }
  if (!outputDir || !version) {
    throw new Error('package-agent: --output-dir and --version require values');
  }
  return {
    outputDir,
    version,
    formats: normalizePackageFormats(formats),
    rpmSpecOnly,
    gpgKeyReference,
    cosignSignerReference,
    containerImage,
    containerDigestSha256,
  };
}

function main() {
  try {
    const {
      outputDir,
      version,
      formats,
      rpmSpecOnly,
      gpgKeyReference,
      cosignSignerReference,
      containerImage,
      containerDigestSha256,
    } = parseCliArgs(process.argv);
    const result = buildAgentPackage({
      outputDir,
      version,
      formats,
      rpmSpecOnly,
      gpgKeyReference,
      cosignSignerReference,
      containerImage,
      containerDigestSha256,
    });
    console.log('package-agent: ok');
    console.log(`  output_dir: ${result.outputDir}`);
    console.log(`  formats: ${result.formats.join(',')}`);
    if (result.tarballPath) {
      console.log(`  tarball: ${result.tarballPath}`);
    }
    if (result.manifestPath) {
      console.log(`  manifest: ${result.manifestPath}`);
    }
    if (result.sigPath) {
      console.log(`  signature: ${result.sigPath}`);
    }
    if (result.debPath) {
      console.log(`  deb: ${result.debPath}`);
    }
    if (result.rpm?.specPath) {
      console.log(`  rpm_spec: ${result.rpm.specPath}`);
    }
    if (result.rpmPath) {
      console.log(`  rpm: ${result.rpmPath}`);
    }
    if (result.signingManifestPath) {
      console.log(`  signing_manifest: ${result.signingManifestPath}`);
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`package-agent: failed: ${message}`);
    process.exitCode = 1;
  }
}

const isMain =
  process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
  main();
}