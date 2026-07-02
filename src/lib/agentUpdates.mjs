import { createHash, createPublicKey, verify } from 'node:crypto';

export const SHA256_HEX = /^[a-f0-9]{64}$/i;
export const DETACHED_SIGNATURE_B64 = /^[A-Za-z0-9+/]+={0,2}$/;
export const CHANNELS = new Set(['stable', 'beta', 'canary']);
export const ALLOWED_STATUSES = new Set(['downloaded', 'verified', 'applied', 'failed', 'rolled_back']);
export const ERROR_CODE_RE = /^[a-z][a-z0-9_]{0,31}$/;
export const BASE64_DER_RE = /^[A-Za-z0-9+/]+={0,2}$/;
export const DISTRIBUTION_URL_KEYS = ['manifest_url', 'signature_url', 'artifact_url'];

export function parseHttpsDistributionUrl(urlString) {
  if (typeof urlString !== 'string' || urlString.trim() === '') {
    return { error: 'invalid' };
  }
  let parsed;
  try {
    parsed = new URL(urlString.trim());
  } catch {
    return { error: 'invalid' };
  }
  if (parsed.protocol !== 'https:') {
    return { error: 'invalid' };
  }
  if (parsed.username || parsed.password) {
    return { error: 'invalid' };
  }
  return { href: parsed.href };
}

function artifactBasenameFromUrl(href) {
  let pathname;
  try {
    pathname = new URL(href).pathname;
  } catch {
    return null;
  }
  const segment = pathname.split('/').filter(Boolean).pop() ?? '';
  if (segment === '') {
    return null;
  }
  try {
    return decodeURIComponent(segment);
  } catch {
    return null;
  }
}

export function validateDistribution(
  distribution,
  manifest,
  {
    missingError = 'missing_distribution',
    invalidError = 'invalid_distribution_url',
    mismatchError = 'artifact_url_mismatch',
  } = {},
) {
  if (distribution == null) {
    return { error: missingError, status: 400 };
  }
  if (typeof distribution !== 'object' || Array.isArray(distribution)) {
    return { error: invalidError, status: 400 };
  }
  const normalized = {};
  for (const key of DISTRIBUTION_URL_KEYS) {
    const parsed = parseHttpsDistributionUrl(distribution[key]);
    if (parsed.error) {
      return { error: invalidError, status: 400 };
    }
    normalized[key] = parsed.href;
  }
  const expectedName = manifest?.artifact?.name;
  if (typeof expectedName === 'string' && expectedName.length > 0) {
    const basename = artifactBasenameFromUrl(normalized.artifact_url);
    if (basename == null || basename === '') {
      return { error: invalidError, status: 400 };
    }
    if (basename !== expectedName) {
      return { error: mismatchError, status: 400 };
    }
  }
  return { distribution: normalized };
}

export function toDownloadPayload(distribution) {
  return {
    manifest_url: distribution.manifest_url,
    signature_url: distribution.signature_url,
    artifact_url: distribution.artifact_url,
  };
}

/** Canonical JSON aligned with package-agent and agent runtime verifiers. */
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

export function buildSignableManifestPayload(manifest) {
  return {
    artifact: manifest.artifact,
    created_at: manifest.created_at,
    files: manifest.files,
    package: manifest.package,
    version: manifest.version,
  };
}

export function verifyDetachedManifestSignature(
  manifest,
  signatureTrimmed,
  {
    missingKeyError = 'missing_signing_public_key',
    invalidKeyError = 'invalid_signing_public_key',
    verifyFailedError = 'signature_verification_failed',
  } = {},
) {
  const pubB64 = manifest.signing?.public_key_der_base64;
  if (typeof pubB64 !== 'string' || pubB64.trim() === '') {
    return { error: missingKeyError, status: 400 };
  }
  const trimmedKey = pubB64.trim();
  if (!BASE64_DER_RE.test(trimmedKey)) {
    return { error: invalidKeyError, status: 400 };
  }
  let publicKey;
  try {
    publicKey = createPublicKey({
      key: Buffer.from(trimmedKey, 'base64'),
      format: 'der',
      type: 'spki',
    });
  } catch {
    return { error: invalidKeyError, status: 400 };
  }
  const message = Buffer.from(stableStringify(buildSignableManifestPayload(manifest)), 'utf8');
  let signatureBuf;
  try {
    signatureBuf = Buffer.from(signatureTrimmed, 'base64');
  } catch {
    return { error: verifyFailedError, status: 400 };
  }
  if (!verify(null, message, publicKey, signatureBuf)) {
    return { error: verifyFailedError, status: 400 };
  }
  return null;
}

export function fingerprintPublicKeyDerBase64(trimmedKeyB64) {
  return createHash('sha256').update(Buffer.from(trimmedKeyB64, 'base64')).digest('hex');
}

export function parseEd25519SpkiDerBase64(
  publicKeyDerBase64,
  { missingError = 'missing_public_key', invalidError = 'invalid_public_key' } = {},
) {
  if (typeof publicKeyDerBase64 !== 'string' || publicKeyDerBase64.trim() === '') {
    return { error: missingError, status: 400 };
  }
  const trimmed = publicKeyDerBase64.trim();
  if (!BASE64_DER_RE.test(trimmed)) {
    return { error: invalidError, status: 400 };
  }
  let publicKey;
  try {
    publicKey = createPublicKey({
      key: Buffer.from(trimmed, 'base64'),
      format: 'der',
      type: 'spki',
    });
  } catch {
    return { error: invalidError, status: 400 };
  }
  if (publicKey.asymmetricKeyType && publicKey.asymmetricKeyType !== 'ed25519') {
    return { error: invalidError, status: 400 };
  }
  return { trimmed, fingerprint_sha256: fingerprintPublicKeyDerBase64(trimmed) };
}

export function parseManifestSigningKey(
  manifest,
  { missingError = 'missing_signing_public_key', invalidError = 'invalid_signing_public_key' } = {},
) {
  return parseEd25519SpkiDerBase64(manifest.signing?.public_key_der_base64, {
    missingError,
    invalidError,
  });
}

export function toPublicTrustKey(key) {
  return {
    id: key.id,
    name: key.name,
    fingerprint_sha256: key.fingerprint_sha256,
    status: key.status,
    created_at: key.created_at,
    revoked_at: key.revoked_at,
  };
}

export function isSafeArtifactBasename(name) {
  if (typeof name !== 'string' || name.length === 0) {
    return false;
  }
  if (name.includes('/') || name.includes('\\') || name.includes('..')) {
    return false;
  }
  if (name.startsWith('/') || /^[A-Za-z]:[\\/]/.test(name)) {
    return false;
  }
  if (!name.endsWith('.tar.gz')) {
    return false;
  }
  return true;
}

export function validateDetachedSignature(
  signature,
  { missingError = 'missing_signature', invalidError = 'invalid_signature' } = {},
) {
  if (signature == null) {
    return { error: missingError, status: 400 };
  }
  if (typeof signature !== 'string') {
    return { error: invalidError, status: 400 };
  }
  const trimmed = signature.trim();
  if (trimmed.length === 0) {
    return { error: missingError, status: 400 };
  }
  if (!DETACHED_SIGNATURE_B64.test(trimmed)) {
    return { error: invalidError, status: 400 };
  }
  return { signature: trimmed };
}

export function validateManifest(manifest, expectedVersion) {
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
    return { error: 'invalid_manifest', status: 400 };
  }
  if (manifest.package !== 'astranull-agent') {
    return { error: 'invalid_package', status: 400 };
  }
  if (manifest.version !== expectedVersion) {
    return { error: 'version_mismatch', status: 400 };
  }
  const artifact = manifest.artifact;
  if (!artifact || typeof artifact !== 'object' || Array.isArray(artifact)) {
    return { error: 'invalid_artifact', status: 400 };
  }
  if (!isSafeArtifactBasename(artifact.name)) {
    return { error: 'invalid_artifact_name', status: 400 };
  }
  const sha = artifact.sha256;
  if (typeof sha !== 'string' || !SHA256_HEX.test(sha)) {
    return { error: 'invalid_artifact_sha256', status: 400 };
  }
  if (!Number.isInteger(artifact.size) || artifact.size <= 0) {
    return { error: 'invalid_artifact_size', status: 400 };
  }
  if (manifest.signing?.signed !== true) {
    return { error: 'unsigned_manifest', status: 400 };
  }
  return null;
}

export function normalizeRollout(raw) {
  const rollout = raw && typeof raw === 'object' && !Array.isArray(raw) ? { ...raw } : {};
  let percentage = rollout.percentage ?? 0;
  if (!Number.isInteger(percentage)) percentage = 0;
  if (percentage < 0) percentage = 0;
  if (percentage > 100) percentage = 100;
  rollout.percentage = percentage;
  for (const key of ['environment_ids', 'target_group_ids', 'agent_ids']) {
    if (rollout[key] != null) {
      if (!Array.isArray(rollout[key])) {
        return { error: 'invalid_rollout', status: 400 };
      }
      rollout[key] = rollout[key].map(String);
    }
  }
  return { rollout };
}

export function isAgentInRollout(agent, release) {
  if (!agent || !release || agent.tenant_id !== release.tenant_id) return false;
  const rollout = release.rollout ?? {};
  const envIds = rollout.environment_ids;
  if (Array.isArray(envIds) && envIds.length > 0 && !envIds.includes(agent.environment_id)) {
    return false;
  }
  const tgIds = rollout.target_group_ids;
  if (Array.isArray(tgIds) && tgIds.length > 0 && !tgIds.includes(agent.target_group_id)) {
    return false;
  }
  const agentIds = rollout.agent_ids;
  if (Array.isArray(agentIds) && agentIds.includes(agent.id)) {
    return true;
  }
  const pct = rollout.percentage ?? 0;
  if (pct <= 0) return false;
  if (pct >= 100) return true;
  const material = `${agent.tenant_id}|${agent.id}|${release.version}`;
  const hash = createHash('sha256').update(material, 'utf8').digest();
  const bucket = hash.readUInt32BE(0) % 100;
  return bucket < pct;
}

export function toPublicRelease(release) {
  return {
    id: release.id,
    version: release.version,
    channel: release.channel,
    state: release.state,
    manifest: release.manifest,
    signature: release.signature ?? null,
    distribution: release.distribution,
    rollout: release.rollout,
    rollback: release.rollback
      ? {
          version: release.rollback.version,
          manifest: release.rollback.manifest,
          signature: release.rollback.signature ?? null,
          distribution: release.rollback.distribution,
        }
      : null,
    created_at: release.created_at,
    created_by: release.created_by,
    rollback_requested_at: release.rollback_requested_at ?? null,
  };
}

/**
 * @param {object} agent
 * @param {object[]} releases tenant-scoped releases
 * @param {(releaseId: string) => { status?: string } | null} latestStatusForRelease
 */
export function decideAgentUpdatePoll(agent, releases, latestStatusForRelease) {
  for (const release of releases) {
    if (release.state !== 'rollback_requested' || !release.rollback) continue;
    const latest = latestStatusForRelease(release.id);
    if (latest?.status !== 'applied') continue;
    return {
      update: {
        release_id: release.id,
        action: 'rollback',
        version: release.rollback.version,
        channel: release.channel,
        manifest: release.rollback.manifest,
        signature: release.rollback.signature ?? null,
        download: toDownloadPayload(release.rollback.distribution),
      },
    };
  }

  const actives = releases
    .filter((r) => r.state === 'active')
    .sort((a, b) => b.created_at.localeCompare(a.created_at));

  for (const release of actives) {
    if (!isAgentInRollout(agent, release)) continue;
    const current = agent.version ?? null;
    if (current === release.version) continue;
    const update = {
      release_id: release.id,
      action: 'upgrade',
      version: release.version,
      channel: release.channel,
      manifest: release.manifest,
      signature: release.signature ?? null,
      download: toDownloadPayload(release.distribution),
    };
    if (release.rollback?.version) {
      update.rollback_version = release.rollback.version;
    }
    return { update };
  }

  return { update: null };
}

export function validateAgentUpdateStatusBody(body) {
  const releaseId = body?.release_id;
  if (typeof releaseId !== 'string' || !releaseId) {
    return { error: 'invalid_release_id', status: 400 };
  }
  const status = body?.status;
  if (typeof status !== 'string' || !ALLOWED_STATUSES.has(status)) {
    return { error: 'invalid_status', status: 400 };
  }

  let errorCode = body?.error_code ?? null;
  if (errorCode != null) {
    if (typeof errorCode !== 'string' || !ERROR_CODE_RE.test(errorCode)) {
      return { error: 'invalid_error_code', status: 400 };
    }
  }

  let action = body?.action ?? null;
  if (action != null && typeof action !== 'string') {
    return { error: 'invalid_action', status: 400 };
  }

  let installedVersion = body?.installed_version ?? null;
  if (installedVersion != null) {
    if (typeof installedVersion !== 'string' || !installedVersion.trim() || installedVersion.length > 80) {
      return { error: 'invalid_installed_version', status: 400 };
    }
    installedVersion = installedVersion.trim();
  }

  return { releaseId, status, action, errorCode, installedVersion };
}