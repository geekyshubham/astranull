#!/usr/bin/env node
/**
 * Outbound-only metadata-only observation agent for AstraNull.
 * Polls jobs over HTTPS; no inbound management port required.
 *
 * Optional --canary-listen PORT: customer-approved local HTTP canary for observation
 * metadata only (not a management channel). Disabled by default.
 *
 * Optional --log-file PATH: tail log lines for job nonce hash; uploads metadata with
 * line hash only — never raw log line content with secrets.
 *
 * Optional --packet-metadata-file PATH: JSON Lines packet/flow metadata from customer host tooling.
 * Optional --mirror-metadata-file PATH: JSON Lines metadata from mirror/TAP collector output.
 */

import { createHash, createPublicKey, verify } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import http from 'node:http';
import {
  chmodSync,
  copyFileSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
  existsSync,
  watchFile,
  unwatchFile,
  unlinkSync,
} from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath, URL } from 'node:url';

export const AGENT_VERSION = '0.2.0-production-readiness';

export const AGENT_UPDATE_PACKAGE_NAME = 'astranull-agent';

const AGENT_UPDATE_DEFAULT_MAX_DOWNLOAD_BYTES = 100 * 1024 * 1024;
const AGENT_UPDATE_DEFAULT_DOWNLOAD_TIMEOUT_MS = 30_000;
const AGENT_UPDATE_MIN_DOWNLOAD_TIMEOUT_MS = 1_000;

const AGENT_UPDATE_SHA256_HEX = /^[a-f0-9]{64}$/i;
const AGENT_UPDATE_MAX_VERSION_LENGTH = 128;

function agentUpdatePathHasControlChars(value) {
  if (typeof value !== 'string') {
    return true;
  }
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code < 32 || code === 127) {
      return true;
    }
  }
  return false;
}

export function isSafeAgentUpdateVersion(version) {
  if (typeof version !== 'string' || version.trim() === '') {
    return false;
  }
  if (version.length > AGENT_UPDATE_MAX_VERSION_LENGTH) {
    return false;
  }
  if (version.includes('/') || version.includes('\\') || version.includes('..')) {
    return false;
  }
  if (path.isAbsolute(version)) {
    return false;
  }
  if (agentUpdatePathHasControlChars(version)) {
    return false;
  }
  return true;
}

function isSafeAgentUpdateManifestRelativePath(relativePath) {
  if (typeof relativePath !== 'string' || relativePath.length === 0) {
    return false;
  }
  if (relativePath.startsWith('/') || path.isAbsolute(relativePath)) {
    return false;
  }
  if (relativePath.includes('\\')) {
    return false;
  }
  const parts = relativePath.split('/');
  if (parts.some((part) => part === '' || part === '.' || part === '..')) {
    return false;
  }
  if (agentUpdatePathHasControlChars(relativePath)) {
    return false;
  }
  return true;
}

function resolveAgentUpdatePathUnderRoot(root, relativePath) {
  if (!isSafeAgentUpdateManifestRelativePath(relativePath)) {
    return null;
  }
  const resolvedRoot = path.resolve(root);
  const resolvedFile = path.resolve(resolvedRoot, relativePath);
  const rootPrefix = resolvedRoot.endsWith(path.sep) ? resolvedRoot : `${resolvedRoot}${path.sep}`;
  if (resolvedFile !== resolvedRoot && !resolvedFile.startsWith(rootPrefix)) {
    return null;
  }
  return resolvedFile;
}

/** Canonical JSON aligned with sorted keys for deterministic update signatures. */
export function stableStringifyForAgentUpdate(value) {
  if (value === undefined) {
    return 'null';
  }
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((v) => (v === undefined ? 'null' : stableStringifyForAgentUpdate(v))).join(',')}]`;
  }
  const keys = Object.keys(value).sort().filter((k) => value[k] !== undefined);
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringifyForAgentUpdate(value[k])}`).join(',')}}`;
}

/** Payload covered by Ed25519 signature (manifest body without signature fields). */
export function buildAgentUpdateSignablePayload(manifest) {
  return {
    artifact: manifest.artifact,
    created_at: manifest.created_at,
    files: manifest.files,
    package: manifest.package,
    version: manifest.version,
  };
}

function isSafeAgentUpdateArtifactBasename(name) {
  if (typeof name !== 'string' || name.length === 0) {
    return false;
  }
  if (name.includes('/') || name.includes('\\') || name.includes('..')) {
    return false;
  }
  if (path.isAbsolute(name) || name !== path.basename(name)) {
    return false;
  }
  if (!name.endsWith('.tar.gz')) {
    return false;
  }
  return true;
}

export function validateAgentUpdateManifest(
  manifest,
  { expectedPackage = AGENT_UPDATE_PACKAGE_NAME, expectedVersion } = {},
) {
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
    return { ok: false, error: 'INVALID_MANIFEST' };
  }
  if (manifest.package !== expectedPackage) {
    return { ok: false, error: 'PACKAGE_MISMATCH' };
  }
  if (!isSafeAgentUpdateVersion(manifest.version)) {
    return { ok: false, error: 'INVALID_VERSION' };
  }
  if (expectedVersion !== undefined && manifest.version !== expectedVersion) {
    return { ok: false, error: 'VERSION_MISMATCH' };
  }
  const files = manifest.files;
  if (!Array.isArray(files) || files.length === 0) {
    return { ok: false, error: 'INVALID_MANIFEST_FILES' };
  }
  for (const file of files) {
    if (!file || typeof file !== 'object' || Array.isArray(file)) {
      return { ok: false, error: 'INVALID_MANIFEST_FILE_ENTRY' };
    }
    if (!isSafeAgentUpdateManifestRelativePath(file.path)) {
      return { ok: false, error: 'MANIFEST_FILE_PATH_UNSAFE' };
    }
    if (typeof file.sha256 !== 'string' || !AGENT_UPDATE_SHA256_HEX.test(file.sha256)) {
      return { ok: false, error: 'INVALID_MANIFEST_FILE_CHECKSUM' };
    }
    if (!Number.isInteger(file.size) || file.size <= 0) {
      return { ok: false, error: 'INVALID_MANIFEST_FILE_SIZE' };
    }
  }
  const artifact = manifest.artifact;
  if (!artifact || typeof artifact !== 'object' || Array.isArray(artifact)) {
    return { ok: false, error: 'INVALID_ARTIFACT' };
  }
  if (!isSafeAgentUpdateArtifactBasename(artifact.name)) {
    return { ok: false, error: 'ARTIFACT_NAME_UNSAFE' };
  }
  if (typeof artifact.sha256 !== 'string' || !AGENT_UPDATE_SHA256_HEX.test(artifact.sha256)) {
    return { ok: false, error: 'INVALID_ARTIFACT_CHECKSUM' };
  }
  if (!Number.isInteger(artifact.size) || artifact.size <= 0) {
    return { ok: false, error: 'INVALID_ARTIFACT_SIZE' };
  }
  const signing = manifest.signing;
  if (!signing || typeof signing !== 'object' || signing.signed !== true) {
    return { ok: false, error: 'UNSIGNED_MANIFEST' };
  }
  return {
    ok: true,
    version: manifest.version,
    artifact: {
      name: artifact.name,
      sha256: artifact.sha256.toLowerCase(),
      size: artifact.size,
    },
  };
}

export function verifyAgentUpdateManifest({
  manifest,
  signatureBase64,
  trustedPublicKeyDerBase64,
  artifactPath,
  expectedPackage,
  expectedVersion,
} = {}) {
  const validated = validateAgentUpdateManifest(manifest, { expectedPackage, expectedVersion });
  if (!validated.ok) {
    return validated;
  }

  if (
    manifest.signing.public_key_der_base64 !== undefined
    && manifest.signing.public_key_der_base64 !== trustedPublicKeyDerBase64
  ) {
    return { ok: false, error: 'TRUSTED_PUBLIC_KEY_MISMATCH' };
  }

  if (typeof signatureBase64 !== 'string' || signatureBase64.trim() === '') {
    return { ok: false, error: 'MISSING_SIGNATURE' };
  }
  if (typeof trustedPublicKeyDerBase64 !== 'string' || trustedPublicKeyDerBase64.trim() === '') {
    return { ok: false, error: 'MISSING_TRUSTED_PUBLIC_KEY' };
  }

  let publicKey;
  try {
    publicKey = createPublicKey({
      key: Buffer.from(trustedPublicKeyDerBase64, 'base64'),
      format: 'der',
      type: 'spki',
    });
  } catch {
    return { ok: false, error: 'INVALID_TRUSTED_PUBLIC_KEY' };
  }

  const signable = buildAgentUpdateSignablePayload(manifest);
  const message = Buffer.from(stableStringifyForAgentUpdate(signable), 'utf8');
  let signature;
  try {
    signature = Buffer.from(signatureBase64.trim(), 'base64');
  } catch {
    return { ok: false, error: 'INVALID_SIGNATURE' };
  }

  if (!verify(null, message, publicKey, signature)) {
    return { ok: false, error: 'SIGNATURE_VERIFICATION_FAILED' };
  }

  if (artifactPath) {
    if (!existsSync(artifactPath)) {
      return { ok: false, error: 'ARTIFACT_NOT_FOUND' };
    }
    const data = readFileSync(artifactPath);
    const digest = createHash('sha256').update(data).digest('hex');
    if (digest !== manifest.artifact.sha256.toLowerCase()) {
      return { ok: false, error: 'ARTIFACT_CHECKSUM_MISMATCH' };
    }
    if (data.length !== manifest.artifact.size) {
      return { ok: false, error: 'ARTIFACT_SIZE_MISMATCH' };
    }
  }

  return {
    ok: true,
    version: manifest.version,
    artifact: {
      name: manifest.artifact.name,
      sha256: manifest.artifact.sha256.toLowerCase(),
      size: manifest.artifact.size,
    },
  };
}

function agentUpdateArtifactRootName(artifactName) {
  if (typeof artifactName !== 'string') {
    return '';
  }
  return artifactName.replace(/\.tar\.gz$/i, '');
}

function isSafeAgentUpdateTarEntry(entry, expectedRootName) {
  if (typeof entry !== 'string' || entry.length === 0) {
    return false;
  }
  if (entry.startsWith('/') || entry.includes('\\')) {
    return false;
  }
  const parts = entry.split('/');
  if (parts.some((part) => part === '..')) {
    return false;
  }
  if (entry === expectedRootName || entry === `${expectedRootName}/`) {
    return true;
  }
  const prefix = `${expectedRootName}/`;
  return entry.startsWith(prefix);
}

function listAgentUpdateTarballEntries(artifactPath) {
  return execFileSync('tar', ['-tzf', artifactPath], { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] })
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

export function validateAgentUpdateTarballEntries(artifactPath, expectedRootName) {
  if (!artifactPath || !existsSync(artifactPath)) {
    return { ok: false, error: 'ARTIFACT_NOT_FOUND' };
  }
  if (typeof expectedRootName !== 'string' || expectedRootName.length === 0) {
    return { ok: false, error: 'INVALID_ARTIFACT_ROOT' };
  }
  let entries;
  try {
    entries = listAgentUpdateTarballEntries(artifactPath);
  } catch {
    return { ok: false, error: 'TARBALL_LIST_FAILED' };
  }
  if (entries.length === 0) {
    return { ok: false, error: 'TARBALL_EMPTY' };
  }
  for (const entry of entries) {
    if (!isSafeAgentUpdateTarEntry(entry, expectedRootName)) {
      return { ok: false, error: 'TARBALL_ENTRY_UNSAFE', entry };
    }
  }
  return { ok: true, expectedRootName, entryCount: entries.length };
}

export function verifyAgentUpdatePackageFiles(manifest, extractedRoot) {
  if (!manifest || !Array.isArray(manifest.files) || manifest.files.length === 0) {
    return { ok: false, error: 'INVALID_MANIFEST_FILES' };
  }
  if (typeof extractedRoot !== 'string' || extractedRoot.length === 0) {
    return { ok: false, error: 'INVALID_EXTRACTED_ROOT' };
  }
  for (const file of manifest.files) {
    if (!file || typeof file.path !== 'string' || file.path.length === 0) {
      return { ok: false, error: 'INVALID_MANIFEST_FILE_ENTRY' };
    }
    const filePath = resolveAgentUpdatePathUnderRoot(extractedRoot, file.path);
    if (!filePath) {
      return { ok: false, error: 'MANIFEST_FILE_PATH_UNSAFE', path: file.path };
    }
    let stat;
    try {
      stat = lstatSync(filePath);
    } catch {
      return { ok: false, error: 'PACKAGE_FILE_MISSING', path: file.path };
    }
    if (!stat.isFile()) {
      return { ok: false, error: 'PACKAGE_FILE_NOT_REGULAR', path: file.path };
    }
    const data = readFileSync(filePath);
    const digest = createHash('sha256').update(data).digest('hex');
    if (digest !== String(file.sha256).toLowerCase()) {
      return { ok: false, error: 'PACKAGE_FILE_CHECKSUM_MISMATCH', path: file.path };
    }
    if (data.length !== file.size) {
      return { ok: false, error: 'PACKAGE_FILE_SIZE_MISMATCH', path: file.path };
    }
  }
  return { ok: true, fileCount: manifest.files.length };
}

export function validateAgentUpdateInstallRoot(installRoot) {
  if (typeof installRoot !== 'string' || installRoot.trim() === '') {
    return { ok: false, error: 'MISSING_INSTALL_ROOT' };
  }
  if (!path.isAbsolute(installRoot)) {
    return { ok: false, error: 'INSTALL_ROOT_NOT_ABSOLUTE' };
  }
  const resolved = path.resolve(installRoot);
  if (resolved === path.sep) {
    return { ok: false, error: 'INSTALL_ROOT_UNSAFE' };
  }
  const home = path.resolve(os.homedir());
  if (resolved === home) {
    return { ok: false, error: 'INSTALL_ROOT_UNSAFE' };
  }
  return { ok: true, installRoot: resolved };
}

export function applyAgentUpdatePackage({
  manifest,
  signatureBase64,
  trustedPublicKeyDerBase64,
  artifactPath,
  installRoot,
  expectedVersion,
  now,
} = {}) {
  const installValidated = validateAgentUpdateInstallRoot(installRoot);
  if (!installValidated.ok) {
    return installValidated;
  }

  const verified = verifyAgentUpdateManifest({
    manifest,
    signatureBase64,
    trustedPublicKeyDerBase64,
    artifactPath,
    expectedVersion,
  });
  if (!verified.ok) {
    return verified;
  }

  const expectedRootName = agentUpdateArtifactRootName(manifest.artifact.name);
  const tarValidated = validateAgentUpdateTarballEntries(artifactPath, expectedRootName);
  if (!tarValidated.ok) {
    return tarValidated;
  }

  const resolvedInstallRoot = installValidated.installRoot;
  mkdirSync(resolvedInstallRoot, { recursive: true });
  const stagingParent = path.dirname(resolvedInstallRoot);
  const stagingBase = existsSync(stagingParent) ? stagingParent : resolvedInstallRoot;
  const stagingDir = mkdtempSync(path.join(stagingBase, '.astranull-apply-staging-'));

  const cleanupStaging = () => {
    try {
      rmSync(stagingDir, { recursive: true, force: true });
    } catch {
      /* best-effort */
    }
  };

  try {
    execFileSync('tar', ['-xzf', artifactPath, '-C', stagingDir], { stdio: ['pipe', 'pipe', 'pipe'] });
    const extractedRoot = path.join(stagingDir, expectedRootName);
    if (!existsSync(extractedRoot)) {
      cleanupStaging();
      return { ok: false, error: 'EXTRACTED_ROOT_MISSING' };
    }

    const filesVerified = verifyAgentUpdatePackageFiles(manifest, extractedRoot);
    if (!filesVerified.ok) {
      cleanupStaging();
      return filesVerified;
    }

    const releaseDir = path.join(resolvedInstallRoot, 'releases', manifest.version);
    if (existsSync(releaseDir)) {
      rmSync(releaseDir, { recursive: true, force: true });
    }
    mkdirSync(releaseDir, { recursive: true });

    for (const file of manifest.files) {
      const src = resolveAgentUpdatePathUnderRoot(extractedRoot, file.path);
      const dest = resolveAgentUpdatePathUnderRoot(releaseDir, file.path);
      if (!src || !dest) {
        cleanupStaging();
        return { ok: false, error: 'MANIFEST_FILE_PATH_UNSAFE', path: file.path };
      }
      mkdirSync(path.dirname(dest), { recursive: true });
      copyFileSync(src, dest);
    }

    const appliedAt = typeof now === 'function' ? now() : (now ?? new Date().toISOString());
    const currentRecord = {
      version: manifest.version,
      applied_at: appliedAt,
      release_dir: releaseDir,
      artifact_sha256: manifest.artifact.sha256.toLowerCase(),
    };
    const currentJsonPath = path.join(resolvedInstallRoot, 'current.json');
    writeFileSync(currentJsonPath, `${JSON.stringify(currentRecord, null, 2)}\n`, 'utf8');

    cleanupStaging();
    return {
      ok: true,
      version: manifest.version,
      releaseDir,
      currentJsonPath,
      artifactSha256: currentRecord.artifact_sha256,
    };
  } catch {
    cleanupStaging();
    return { ok: false, error: 'APPLY_FAILED' };
  }
}

function isInsecureLocalhostHttpUrl(parsed) {
  if (parsed.protocol !== 'http:') {
    return false;
  }
  const hostname = parsed.hostname.toLowerCase();
  return hostname === '127.0.0.1' || hostname === 'localhost' || hostname === '::1';
}

export function validateAgentControlPlaneUrl(url, { allowInsecureLocalhost = false } = {}) {
  if (typeof url !== 'string' || url.trim() === '') {
    return { ok: false, error: 'INVALID_URL' };
  }
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return { ok: false, error: 'INVALID_URL' };
  }
  if (parsed.username !== '' || parsed.password !== '') {
    return { ok: false, error: 'URL_CREDENTIALS_NOT_ALLOWED' };
  }
  if (parsed.protocol === 'https:') {
    return { ok: true, url: parsed.href.replace(/\/$/, '') };
  }
  if (parsed.protocol === 'http:') {
    if (isInsecureLocalhostHttpUrl(parsed)) {
      if (allowInsecureLocalhost) {
        return { ok: true, url: parsed.href.replace(/\/$/, '') };
      }
      return { ok: false, error: 'INSECURE_LOCALHOST_NOT_ALLOWED' };
    }
    return { ok: false, error: 'INSECURE_HTTP_NOT_ALLOWED' };
  }
  return { ok: false, error: 'UNSUPPORTED_URL_PROTOCOL' };
}

export function validateAgentUpdateDownloadUrl(url, { allowInsecureLocalhost = false } = {}) {
  if (typeof url !== 'string' || url.trim() === '') {
    return { ok: false, error: 'INVALID_URL' };
  }
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return { ok: false, error: 'INVALID_URL' };
  }
  if (parsed.username !== '' || parsed.password !== '') {
    return { ok: false, error: 'URL_CREDENTIALS_NOT_ALLOWED' };
  }
  if (parsed.protocol === 'https:') {
    return { ok: true, url: parsed.href };
  }
  if (parsed.protocol === 'http:') {
    if (isInsecureLocalhostHttpUrl(parsed)) {
      if (allowInsecureLocalhost) {
        return { ok: true, url: parsed.href };
      }
      return { ok: false, error: 'INSECURE_LOCALHOST_NOT_ALLOWED' };
    }
    return { ok: false, error: 'INSECURE_HTTP_NOT_ALLOWED' };
  }
  return { ok: false, error: 'UNSUPPORTED_URL_PROTOCOL' };
}

export async function downloadAgentUpdateFile(url, destPath, options = {}) {
  const {
    maxBytes = AGENT_UPDATE_DEFAULT_MAX_DOWNLOAD_BYTES,
    timeoutMs = AGENT_UPDATE_DEFAULT_DOWNLOAD_TIMEOUT_MS,
    allowInsecureLocalhost = false,
  } = options;

  const validated = validateAgentUpdateDownloadUrl(url, { allowInsecureLocalhost });
  if (!validated.ok) {
    return validated;
  }

  if (typeof destPath !== 'string' || destPath.trim() === '') {
    return { ok: false, error: 'INVALID_DEST_PATH' };
  }

  const effectiveTimeout =
    typeof timeoutMs === 'number' && timeoutMs >= AGENT_UPDATE_MIN_DOWNLOAD_TIMEOUT_MS
      ? timeoutMs
      : AGENT_UPDATE_DEFAULT_DOWNLOAD_TIMEOUT_MS;

  let response;
  try {
    response = await fetch(validated.url, {
      signal: AbortSignal.timeout(effectiveTimeout),
      redirect: 'manual',
    });
  } catch (err) {
    if (err?.name === 'TimeoutError' || err?.name === 'AbortError') {
      return { ok: false, error: 'DOWNLOAD_TIMEOUT' };
    }
    return { ok: false, error: 'DOWNLOAD_FAILED' };
  }

  if (!response.ok) {
    return { ok: false, error: 'DOWNLOAD_HTTP_STATUS', status: response.status };
  }

  const contentLengthHeader = response.headers.get('content-length');
  if (contentLengthHeader !== null && contentLengthHeader !== '') {
    const contentLength = Number(contentLengthHeader);
    if (Number.isFinite(contentLength) && contentLength > maxBytes) {
      return { ok: false, error: 'DOWNLOAD_TOO_LARGE' };
    }
  }

  try {
    const destDir = path.dirname(destPath);
    if (destDir && destDir !== '.') {
      mkdirSync(destDir, { recursive: true });
    }
    const body = response.body;
    if (!body) {
      return { ok: false, error: 'DOWNLOAD_FAILED' };
    }
    const reader = body.getReader();
    const chunks = [];
    let totalBytes = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      totalBytes += value.byteLength;
      if (totalBytes > maxBytes) {
        return { ok: false, error: 'DOWNLOAD_TOO_LARGE' };
      }
      chunks.push(Buffer.from(value));
    }
    writeFileSync(destPath, Buffer.concat(chunks));
    return { ok: true, bytes: totalBytes, destPath };
  } catch {
    return { ok: false, error: 'DOWNLOAD_FAILED' };
  }
}

export async function downloadAndApplyAgentUpdatePackage({
  manifestUrl,
  signatureUrl,
  artifactUrl,
  trustedPublicKeyDerBase64,
  installRoot,
  expectedVersion,
  allowInsecureLocalhost = false,
  maxBytes,
  timeoutMs,
  now,
} = {}) {
  if (
    !manifestUrl
    || !signatureUrl
    || !artifactUrl
    || !trustedPublicKeyDerBase64
    || !installRoot
  ) {
    return { ok: false, error: 'MISSING_REQUIRED_ARGS' };
  }

  const downloadOptions = {
    allowInsecureLocalhost,
    ...(maxBytes !== undefined ? { maxBytes } : {}),
    ...(timeoutMs !== undefined ? { timeoutMs } : {}),
  };

  const stagingDir = mkdtempSync(path.join(os.tmpdir(), '.astranull-download-staging-'));
  const cleanupDownloadStaging = () => {
    try {
      rmSync(stagingDir, { recursive: true, force: true });
    } catch {
      /* best-effort */
    }
  };

  const manifestPath = path.join(stagingDir, 'manifest.json');
  const signaturePath = path.join(stagingDir, 'manifest.sig');
  const artifactPath = path.join(stagingDir, 'artifact.tar.gz');

  try {
    const manifestDownload = await downloadAgentUpdateFile(manifestUrl, manifestPath, downloadOptions);
    if (!manifestDownload.ok) {
      cleanupDownloadStaging();
      return manifestDownload;
    }

    const signatureDownload = await downloadAgentUpdateFile(signatureUrl, signaturePath, downloadOptions);
    if (!signatureDownload.ok) {
      cleanupDownloadStaging();
      return signatureDownload;
    }

    const artifactDownload = await downloadAgentUpdateFile(artifactUrl, artifactPath, downloadOptions);
    if (!artifactDownload.ok) {
      cleanupDownloadStaging();
      return artifactDownload;
    }

    let manifest;
    try {
      manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
    } catch {
      cleanupDownloadStaging();
      return { ok: false, error: 'INVALID_MANIFEST_FILE' };
    }

    let signatureBase64;
    try {
      signatureBase64 = readFileSync(signaturePath, 'utf8').trim();
    } catch {
      cleanupDownloadStaging();
      return { ok: false, error: 'INVALID_SIGNATURE_FILE' };
    }

    const applied = applyAgentUpdatePackage({
      manifest,
      signatureBase64,
      trustedPublicKeyDerBase64,
      artifactPath,
      installRoot,
      expectedVersion,
      now,
    });

    cleanupDownloadStaging();
    return applied;
  } catch {
    cleanupDownloadStaging();
    return { ok: false, error: 'DOWNLOAD_APPLY_FAILED' };
  }
}

const DISALLOWED_OBSERVATION_KEYS = new Set([
  'raw_packet',
  'raw_packets',
  'packet_payload',
  'packet_data',
  'payload',
  'body',
  'headers',
  'header',
  'authorization',
  'cookie',
  'raw_log',
  'log_line',
  'secret',
  'secrets',
  'token',
  'password',
  'raw_payload',
]);

const SAFE_METADATA_FIELDS = [
  'observed_at',
  'interface',
  'local_ip',
  'local_port',
  'remote_ip',
  'remote_port',
  'protocol',
  'tcp_flags',
  'packet_count',
  'flow_count',
  'direction',
];

const WAF_ROUTE_LABELS = new Set([
  'edge',
  'app',
  'origin',
  'internal_segment',
  'canary',
  'origin_canary',
]);

const WAF_OBSERVATION_TYPE_PATTERN = /^[a-z][a-z0-9_]{0,63}$/i;
const WAF_LOG_POINTER_HASH_PATTERN = /^(?:sha256:)?[a-f0-9]{64}$/i;

const WAF_CANARY_HINT_HEADERS = {
  'x-astranull-observation-type': 'observation_type',
  'x-astranull-route-label': 'route_label',
  'x-astranull-placement-confidence': 'placement_confidence',
  'x-astranull-log-pointer-hash': 'log_pointer_hash',
  'x-astranull-direct-origin': 'direct_origin',
  'x-astranull-protected-path': 'protected_path',
};

/** @returns {string[]} */
export function buildAgentRegistrationCapabilities(agentArgs = {}) {
  const caps = new Set(['heartbeat', 'canary', 'waf_canary_observer', 'origin_path_observer']);
  if (agentArgs.logFile) {
    caps.add('http_access_log_metadata');
    caps.add('connector_log_pointer');
  }
  if (agentArgs.packetMetadataFile || agentArgs.mirrorMetadataFile) {
    caps.add('connector_log_pointer');
  }
  if (agentArgs.canaryListen) {
    caps.add('waf_validation_ready');
  }
  return [...caps];
}

function normalizeWafRouteLabel(value) {
  if (typeof value !== 'string') return null;
  const label = value.trim().toLowerCase();
  return WAF_ROUTE_LABELS.has(label) ? label : null;
}

function normalizeWafObservationType(value) {
  if (typeof value !== 'string') return null;
  const t = value.trim();
  return WAF_OBSERVATION_TYPE_PATTERN.test(t) ? t : null;
}

function normalizePlacementConfidence(value) {
  if (typeof value === 'number' && Number.isFinite(value)) {
    if (value < 0 || value > 1) return null;
    return value;
  }
  if (typeof value === 'string' && value.trim() !== '') {
    const n = Number(value);
    if (!Number.isFinite(n) || n < 0 || n > 1) return null;
    return n;
  }
  return null;
}

function normalizeWafLogPointerHash(value) {
  if (typeof value !== 'string') return null;
  const s = value.trim();
  if (!WAF_LOG_POINTER_HASH_PATTERN.test(s)) return null;
  if (s.startsWith('sha256:')) return `sha256:${s.slice(7).toLowerCase()}`;
  return `sha256:${s.toLowerCase()}`;
}

function normalizeWafBooleanFlag(value) {
  if (value === true || value === 1) return true;
  if (value === false || value === 0) return false;
  if (typeof value === 'string') {
    const s = value.trim().toLowerCase();
    if (s === 'true' || s === '1' || s === 'yes') return true;
    if (s === 'false' || s === '0' || s === 'no') return false;
  }
  return null;
}

function applySafeWafMetadataFields(record, out) {
  const observationType = normalizeWafObservationType(record.observation_type);
  if (observationType) out.observation_type = observationType;

  const routeLabel = normalizeWafRouteLabel(record.route_label);
  if (routeLabel) out.route_label = routeLabel;

  const placementConfidence = normalizePlacementConfidence(record.placement_confidence);
  if (placementConfidence !== null) out.placement_confidence = placementConfidence;

  const logPointerHash = normalizeWafLogPointerHash(record.log_pointer_hash);
  if (logPointerHash) out.log_pointer_hash = logPointerHash;

  const directOrigin = normalizeWafBooleanFlag(record.direct_origin);
  if (directOrigin !== null) out.direct_origin = directOrigin;

  const protectedPath = normalizeWafBooleanFlag(record.protected_path);
  if (protectedPath !== null) out.protected_path = protectedPath;
}

export function extractWafCanaryHintsFromRequest(req) {
  const hints = {};
  for (const [headerName, field] of Object.entries(WAF_CANARY_HINT_HEADERS)) {
    const raw = req.headers[headerName];
    if (raw === undefined || raw === null || raw === '') continue;
    hints[field] = Array.isArray(raw) ? raw[0] : raw;
  }
  return hints;
}

export const OBSERVATION_MODES = {
  CANARY: 'customer_approved_canary_observation',
  LOG_TAIL: 'log_tail_observer',
  PACKET_METADATA: 'packet_metadata_observer',
  PACKET_MIRROR: 'packet_mirror_collector',
};

export function hashNonce(nonce) {
  return `sha256:${createHash('sha256').update(String(nonce), 'utf8').digest('hex')}`;
}

function normalizeNonceHash(value) {
  if (value == null || value === '') return null;
  const s = String(value);
  if (s.startsWith('sha256:')) return s;
  if (/^[a-f0-9]{64}$/i.test(s)) return `sha256:${s.toLowerCase()}`;
  return null;
}

export function containsDisallowedObservationFields(value, seen = new Set()) {
  if (value === null || typeof value !== 'object') return false;
  if (seen.has(value)) return false;
  seen.add(value);
  if (Array.isArray(value)) {
    return value.some((item) => containsDisallowedObservationFields(item, seen));
  }
  for (const [key, nested] of Object.entries(value)) {
    if (DISALLOWED_OBSERVATION_KEYS.has(String(key).toLowerCase())) return true;
    if (containsDisallowedObservationFields(nested, seen)) return true;
  }
  return false;
}

export function sanitizeMetadataRecord(record, mode, source) {
  const out = { mode, source };
  for (const field of SAFE_METADATA_FIELDS) {
    if (record[field] !== undefined && record[field] !== null) {
      out[field] = record[field];
    }
  }
  if (record.line_hash) out.line_hash = record.line_hash;
  if (record.method) out.method = record.method;
  if (record.path) out.path = record.path;
  applySafeWafMetadataFields(record, out);
  if (!out.observed_at) out.observed_at = new Date().toISOString();
  return out;
}

export function createObservationStores() {
  return {
    canary: new Map(),
    logTail: new Map(),
    packetMirror: new Map(),
    packetMetadata: new Map(),
  };
}

const defaultStores = createObservationStores();

export function selectObservationForJob(nonceHash, stores = defaultStores) {
  const order = [
    ['canary', OBSERVATION_MODES.CANARY, 'canary_listener'],
    ['logTail', OBSERVATION_MODES.LOG_TAIL, 'log_tail'],
    ['packetMirror', OBSERVATION_MODES.PACKET_MIRROR, 'mirror_metadata_file'],
    ['packetMetadata', OBSERVATION_MODES.PACKET_METADATA, 'packet_metadata_file'],
  ];
  for (const [storeKey, mode, source] of order) {
    const raw = stores[storeKey].get(nonceHash);
    if (raw) {
      return { mode, source, metadata: sanitizeMetadataRecord(raw, mode, source) };
    }
  }
  return null;
}

export function ingestMetadataRecord(record, mode, source, targetMap) {
  if (!record || typeof record !== 'object' || containsDisallowedObservationFields(record)) {
    return false;
  }
  let nonceHash = normalizeNonceHash(record.nonce_hash);
  if (record.nonce != null && record.nonce !== '') {
    nonceHash = hashNonce(record.nonce);
  }
  if (!nonceHash) return false;
  const stored = sanitizeMetadataRecord(record, mode, source);
  targetMap.set(nonceHash, stored);
  return true;
}

export function loadObservationFile(filePath, mode, source, targetMap) {
  if (!filePath || !existsSync(filePath)) return { loaded: 0, ignored: 0 };
  const text = readFileSync(filePath, 'utf8');
  let loaded = 0;
  let ignored = 0;
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const record = JSON.parse(trimmed);
      if (ingestMetadataRecord(record, mode, source, targetMap)) loaded += 1;
      else ignored += 1;
    } catch {
      ignored += 1;
    }
  }
  return { loaded, ignored };
}

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--api') out.api = argv[++i];
    else if (argv[i] === '--token') out.token = argv[++i];
    else if (argv[i] === '--token-file') out.tokenFile = argv[++i];
    else if (argv[i] === '--identity') out.identity = argv[++i];
    else if (argv[i] === '--tenant') out.tenant = argv[++i];
    else if (argv[i] === '--once') out.once = true;
    else if (argv[i] === '--canary-listen') out.canaryListen = Number(argv[++i]);
    else if (argv[i] === '--log-file') out.logFile = argv[++i];
    else if (argv[i] === '--packet-metadata-file') out.packetMetadataFile = argv[++i];
    else if (argv[i] === '--mirror-metadata-file') out.mirrorMetadataFile = argv[++i];
    else if (argv[i] === '--hostname') out.hostname = argv[++i];
    else if (argv[i] === '--name') out.name = argv[++i];
    else if (argv[i] === '--verify-update-manifest') out.verifyUpdateManifest = argv[++i];
    else if (argv[i] === '--apply-update-manifest') out.applyUpdateManifest = argv[++i];
    else if (argv[i] === '--install-root') out.installRoot = argv[++i];
    else if (argv[i] === '--signature') out.signature = argv[++i];
    else if (argv[i] === '--trusted-public-key') out.trustedPublicKey = argv[++i];
    else if (argv[i] === '--artifact') out.artifact = argv[++i];
    else if (argv[i] === '--expected-version') out.expectedVersion = argv[++i];
    else if (argv[i] === '--download-and-apply-update') out.downloadAndApplyUpdate = true;
    else if (argv[i] === '--manifest-url') out.manifestUrl = argv[++i];
    else if (argv[i] === '--signature-url') out.signatureUrl = argv[++i];
    else if (argv[i] === '--artifact-url') out.artifactUrl = argv[++i];
    else if (argv[i] === '--allow-insecure-localhost-downloads') {
      out.allowInsecureLocalhostDownloads = true;
    }
    else if (argv[i] === '--allow-insecure-localhost-api') {
      out.allowInsecureLocalhostApi = true;
    }
  }
  return out;
}

function runVerifyUpdateManifestPreflight() {
  const manifestPath = args.verifyUpdateManifest;
  const signaturePath = args.signature;
  const trustedPublicKey = args.trustedPublicKey;

  if (!manifestPath || !signaturePath || !trustedPublicKey) {
    console.error('update-manifest-verify: failed');
    console.error('  error: MISSING_REQUIRED_ARGS');
    process.exit(1);
  }

  let manifest;
  try {
    manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  } catch {
    console.error('update-manifest-verify: failed');
    console.error('  error: INVALID_MANIFEST_FILE');
    process.exit(1);
  }

  let signatureBase64;
  try {
    signatureBase64 = readFileSync(signaturePath, 'utf8').trim();
  } catch {
    console.error('update-manifest-verify: failed');
    console.error('  error: INVALID_SIGNATURE_FILE');
    process.exit(1);
  }

  const result = verifyAgentUpdateManifest({
    manifest,
    signatureBase64,
    trustedPublicKeyDerBase64: trustedPublicKey,
    artifactPath: args.artifact,
    expectedVersion: args.expectedVersion,
  });

  if (!result.ok) {
    console.error('update-manifest-verify: failed');
    console.error(`  error: ${result.error}`);
    process.exit(1);
  }

  console.log('update-manifest-verify: ok');
  console.log(`  package: ${AGENT_UPDATE_PACKAGE_NAME}`);
  console.log(`  version: ${result.version}`);
  console.log(`  artifact: ${result.artifact.name}`);
  process.exit(0);
}

function runApplyUpdateManifest() {
  const manifestPath = args.applyUpdateManifest;
  const signaturePath = args.signature;
  const trustedPublicKey = args.trustedPublicKey;
  const artifactPath = args.artifact;
  const installRoot = args.installRoot;

  if (!manifestPath || !signaturePath || !trustedPublicKey || !artifactPath || !installRoot) {
    console.error('update-manifest-apply: failed');
    console.error('  error: MISSING_REQUIRED_ARGS');
    process.exit(1);
  }

  let manifest;
  try {
    manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  } catch {
    console.error('update-manifest-apply: failed');
    console.error('  error: INVALID_MANIFEST_FILE');
    process.exit(1);
  }

  let signatureBase64;
  try {
    signatureBase64 = readFileSync(signaturePath, 'utf8').trim();
  } catch {
    console.error('update-manifest-apply: failed');
    console.error('  error: INVALID_SIGNATURE_FILE');
    process.exit(1);
  }

  const result = applyAgentUpdatePackage({
    manifest,
    signatureBase64,
    trustedPublicKeyDerBase64: trustedPublicKey,
    artifactPath,
    installRoot,
    expectedVersion: args.expectedVersion,
  });

  if (!result.ok) {
    console.error('update-manifest-apply: failed');
    console.error(`  error: ${result.error}`);
    process.exit(1);
  }

  console.log('update-manifest-apply: ok');
  console.log(`  package: ${AGENT_UPDATE_PACKAGE_NAME}`);
  console.log(`  version: ${result.version}`);
  console.log(`  release_dir: ${result.releaseDir}`);
  process.exit(0);
}

async function runDownloadAndApplyUpdate() {
  const manifestUrl = args.manifestUrl;
  const signatureUrl = args.signatureUrl;
  const artifactUrl = args.artifactUrl;
  const trustedPublicKey = args.trustedPublicKey;
  const installRoot = args.installRoot;

  if (!manifestUrl || !signatureUrl || !artifactUrl || !trustedPublicKey || !installRoot) {
    console.error('update-download-apply: failed');
    console.error('  error: MISSING_REQUIRED_ARGS');
    process.exit(1);
  }

  const result = await downloadAndApplyAgentUpdatePackage({
    manifestUrl,
    signatureUrl,
    artifactUrl,
    trustedPublicKeyDerBase64: trustedPublicKey,
    installRoot,
    expectedVersion: args.expectedVersion,
    allowInsecureLocalhost: Boolean(args.allowInsecureLocalhostDownloads),
  });

  if (!result.ok) {
    console.error('update-download-apply: failed');
    console.error(`  error: ${result.error}`);
    process.exit(1);
  }

  console.log('update-download-apply: ok');
  console.log(`  package: ${AGENT_UPDATE_PACKAGE_NAME}`);
  console.log(`  version: ${result.version}`);
  console.log(`  release_dir: ${result.releaseDir}`);
  process.exit(0);
}

const args = parseArgs(process.argv.slice(2));
const rawApiUrl = args.api || process.env.ASTRANULL_API_URL || 'http://localhost:3000';
const allowInsecureLocalhostApi =
  Boolean(args.allowInsecureLocalhostApi) ||
  process.env.ASTRANULL_ALLOW_INSECURE_LOCALHOST_API === '1';
let baseUrl = rawApiUrl.replace(/\/$/, '');
const identityPath =
  args.identity ||
  process.env.ASTRANULL_AGENT_IDENTITY ||
  '/var/lib/astranull/identity.json';

function ensureControlPlaneUrlAllowed() {
  const validated = validateAgentControlPlaneUrl(baseUrl, { allowInsecureLocalhost: allowInsecureLocalhostApi });
  if (!validated.ok) {
    console.error(`control-plane-url: rejected (${validated.error})`);
    process.exit(1);
  }
  baseUrl = validated.url;
}

let effectiveTenantId = args.tenant || process.env.ASTRANULL_TENANT_ID || null;

export function startCanaryListener(port, stores = defaultStores, options = {}) {
  const host = options.host ?? '127.0.0.1';
  const log = options.log ?? console.log;
  const server = http.createServer((req, res) => {
    const nonce = req.headers['x-astranull-nonce'];
    const nonceHash = nonce ? hashNonce(nonce) : null;
    if (nonceHash) {
      const wafHints = extractWafCanaryHintsFromRequest(req);
      const draft = {
        observed_at: new Date().toISOString(),
        method: req.method,
        path: req.url,
        mode: OBSERVATION_MODES.CANARY,
        source: 'canary_listener',
        ...wafHints,
      };
      if (!draft.route_label) draft.route_label = 'canary';
      if (!draft.observation_type) draft.observation_type = 'waf_marker_seen';
      stores.canary.set(nonceHash, sanitizeMetadataRecord(draft, OBSERVATION_MODES.CANARY, 'canary_listener'));
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, mode: OBSERVATION_MODES.CANARY }));
  });
  server.listen(port, host, () => {
    const address = server.address();
    const boundPort = typeof address === 'object' && address ? address.port : port;
    log(`canary listener on ${host}:${boundPort} (observation only, not management)`);
  });
  return server;
}

export function extractNonceHashFromLogLine(line) {
  const tagged = line.match(/sha256:([a-f0-9]{64})/i);
  if (tagged) return `sha256:${tagged[1].toLowerCase()}`;
  return null;
}

export function startLogTail(logPath, stores = defaultStores, options = {}) {
  const scan = () => {
    try {
      const lines = readFileSync(logPath, 'utf8').split('\n').slice(-50);
      for (const line of lines) {
        const nonceHash = extractNonceHashFromLogLine(line);
        if (!nonceHash) continue;
        const lineHash = createHash('sha256').update(line, 'utf8').digest('hex');
        stores.logTail.set(nonceHash, {
          observed_at: new Date().toISOString(),
          line_hash: lineHash,
          mode: OBSERVATION_MODES.LOG_TAIL,
          source: 'log_tail',
        });
      }
    } catch {
      /* ignore */
    }
  };
  scan();
  const shouldWatch = options.watch !== false;
  if (shouldWatch) {
    watchFile(logPath, { interval: options.interval ?? 2000 }, scan);
  }
  return {
    scan,
    close: () => {
      if (shouldWatch) {
        unwatchFile(logPath, scan);
      }
    },
  };
}

function startMetadataFileWatcher(filePath, mode, source, targetMap) {
  const reload = () => {
    loadObservationFile(filePath, mode, source, targetMap);
  };
  reload();
  watchFile(filePath, { interval: 2000 }, reload);
}

let agentCredential = null;

function headers() {
  const h = {
    'Content-Type': 'application/json',
    'x-user-id': 'agent',
  };
  if (effectiveTenantId) {
    h['x-tenant-id'] = effectiveTenantId;
  }
  if (agentCredential) {
    h.Authorization = `Bearer ${agentCredential}`;
  }
  return h;
}

async function api(method, p, body) {
  const res = await fetch(`${baseUrl}${p}`, {
    method,
    headers: headers(),
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  const json = text ? JSON.parse(text) : null;
  if (!res.ok) {
    const err = new Error(json?.error || `HTTP ${res.status}`);
    err.status = res.status;
    throw err;
  }
  return json;
}

function loadIdentity() {
  if (!existsSync(identityPath)) return null;
  return JSON.parse(readFileSync(identityPath, 'utf8'));
}

function saveIdentity(data) {
  const dir = path.dirname(identityPath);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  try {
    chmodSync(dir, 0o700);
  } catch {
    /* ignore on platforms without chmod */
  }
  writeFileSync(identityPath, JSON.stringify(data, null, 2), { mode: 0o600 });
  try {
    chmodSync(identityPath, 0o600);
  } catch {
    /* ignore */
  }
}

function redact(msg) {
  return String(msg)
    .replace(/ast_v1\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){2}/g, '[REDACTED_TOKEN]')
    .replace(/agc_v1\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){2}/g, '[REDACTED_CREDENTIAL]')
    .replace(/ast_[A-Za-z0-9_-]+/g, '[REDACTED_TOKEN]')
    .replace(/agc_[A-Za-z0-9_-]+/g, '[REDACTED_CREDENTIAL]');
}

function readBootstrapToken() {
  const tokenFile =
    args.tokenFile || process.env.ASTRANULL_BOOTSTRAP_TOKEN_FILE || null;
  if (args.token) {
    return { token: args.token, fromFile: null };
  }
  if (process.env.ASTRANULL_BOOTSTRAP_TOKEN) {
    return { token: process.env.ASTRANULL_BOOTSTRAP_TOKEN, fromFile: null };
  }
  if (tokenFile && existsSync(tokenFile)) {
    return { token: readFileSync(tokenFile, 'utf8').trim(), fromFile: tokenFile };
  }
  return { token: null, fromFile: tokenFile };
}

function deleteBootstrapTokenFile(tokenFile) {
  if (!tokenFile || !existsSync(tokenFile)) return;
  try {
    unlinkSync(tokenFile);
  } catch {
    /* ignore */
  }
}

async function register(token, tokenFile) {
  const hostname = args.hostname || process.env.ASTRANULL_AGENT_HOSTNAME || os.hostname();
  const name = args.name || process.env.ASTRANULL_AGENT_NAME || hostname;
  const result = await api('POST', '/v1/agents/register', {
    bootstrap_token: token,
    hostname,
    name,
    capabilities: buildAgentRegistrationCapabilities(args),
  });
  const identity = {
    agent_id: result.agent.id,
    tenant_id: result.agent.tenant_id,
    agent_credential: result.agent_credential,
    registered_at: new Date().toISOString(),
  };
  saveIdentity(identity);
  agentCredential = result.agent_credential;
  effectiveTenantId = result.agent.tenant_id;
  if (tokenFile) {
    deleteBootstrapTokenFile(tokenFile);
  }
  return identity;
}

async function heartbeat(agentId) {
  await api('POST', `/v1/agents/${agentId}/heartbeat`, { version: AGENT_VERSION });
}

export async function pollAndWork(agentId, options = {}) {
  const apiFn = options.api ?? api;
  const stores = options.stores ?? defaultStores;
  const logFn = options.log ?? console.log;
  const { jobs } = await apiFn('GET', `/v1/agents/${agentId}/jobs`);
  for (const job of jobs) {
    await apiFn('POST', `/v1/agents/${agentId}/jobs/${job.id}/ack`);
    const selected = selectObservationForJob(job.nonce_hash, stores);
    if (!selected) {
      logFn(`no local observation signal for job ${job.id}`);
      continue;
    }
    await apiFn('POST', `/v1/agents/${agentId}/observations`, {
      agent_job_id: job.id,
      test_run_id: job.test_run_id,
      target_id: job.target_id,
      nonce_hash: job.nonce_hash,
      metadata: selected.metadata,
    });
    logFn(`observation uploaded for run ${job.test_run_id} mode=${selected.mode}`);
  }
}

async function main() {
  try {
    if (args.downloadAndApplyUpdate) {
      await runDownloadAndApplyUpdate();
      return;
    }

    if (args.applyUpdateManifest) {
      runApplyUpdateManifest();
      return;
    }

    if (args.verifyUpdateManifest) {
      runVerifyUpdateManifestPreflight();
      return;
    }

    ensureControlPlaneUrlAllowed();

    if (args.canaryListen) startCanaryListener(args.canaryListen);
    if (args.logFile) startLogTail(args.logFile);
    if (args.packetMetadataFile) {
      startMetadataFileWatcher(
        args.packetMetadataFile,
        OBSERVATION_MODES.PACKET_METADATA,
        'packet_metadata_file',
        defaultStores.packetMetadata,
      );
    }
    if (args.mirrorMetadataFile) {
      startMetadataFileWatcher(
        args.mirrorMetadataFile,
        OBSERVATION_MODES.PACKET_MIRROR,
        'mirror_metadata_file',
        defaultStores.packetMirror,
      );
    }

    let identity = loadIdentity();
    if (identity?.agent_credential) {
      agentCredential = identity.agent_credential;
    }
    if (identity?.tenant_id) {
      effectiveTenantId = identity.tenant_id;
    }
    if (!identity?.agent_id) {
      const { token, fromFile } = readBootstrapToken();
      if (!token) {
        console.error(
          'Bootstrap token required via --token, --token-file, ASTRANULL_BOOTSTRAP_TOKEN_FILE, or ASTRANULL_BOOTSTRAP_TOKEN',
        );
        process.exit(1);
      }
      identity = await register(token, fromFile);
      console.log(`registered agent ${identity.agent_id}`);
    }

    await heartbeat(identity.agent_id);
    await pollAndWork(identity.agent_id);

    if (args.once) {
      process.exit(0);
    } else {
      console.log('agent idle (use --once for single pass)');
    }
  } catch (err) {
    console.error(redact(err.message));
    process.exit(1);
  }
}

const isEntryPoint =
  process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isEntryPoint) {
  main();
}
