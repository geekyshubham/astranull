import { audit } from '../audit.mjs';
import { newId } from '../lib/ids.mjs';
import {
  CHANNELS,
  decideAgentUpdatePoll,
  normalizeRollout,
  parseEd25519SpkiDerBase64,
  parseManifestSigningKey,
  toPublicRelease,
  toPublicTrustKey,
  validateAgentUpdateStatusBody,
  validateDetachedSignature,
  validateDistribution,
  validateManifest,
  verifyDetachedManifestSignature,
} from '../lib/agentUpdates.mjs';
import { getStore, persistStore } from '../store.mjs';

export { isAgentInRollout } from '../lib/agentUpdates.mjs';

function assertTrustedManifestSigningKey(ctx, manifest) {
  const parsed = parseManifestSigningKey(manifest);
  if (parsed.error) return parsed;
  const trusted = getStore().agentUpdateTrustKeys.some(
    (k) =>
      k.tenant_id === ctx.tenantId &&
      k.status === 'active' &&
      k.fingerprint_sha256 === parsed.fingerprint_sha256,
  );
  if (!trusted) {
    return { error: 'untrusted_signing_key', status: 400 };
  }
  return null;
}

function latestStatusForAgentRelease(agentId, releaseId) {
  const matches = getStore().agentUpdateStatuses.filter(
    (s) => s.agent_id === agentId && s.release_id === releaseId,
  );
  if (matches.length === 0) return null;
  return matches.reduce((a, b) => (a.recorded_at >= b.recorded_at ? a : b));
}

export function createAgentUpdateTrustKey(ctx, body) {
  let name = body?.name ?? 'agent update signing key';
  if (name == null) name = 'agent update signing key';
  if (typeof name !== 'string' || name.length > 80) {
    return { error: 'invalid_name', status: 400 };
  }
  name = name.trim() || 'agent update signing key';

  const parsed = parseEd25519SpkiDerBase64(body?.public_key_der_base64);
  if (parsed.error) return parsed;

  const duplicate = getStore().agentUpdateTrustKeys.some(
    (k) =>
      k.tenant_id === ctx.tenantId &&
      k.status === 'active' &&
      k.fingerprint_sha256 === parsed.fingerprint_sha256,
  );
  if (duplicate) {
    return { error: 'duplicate_trust_key', status: 409 };
  }

  const record = {
    id: newId('agentUpdateTrustKey'),
    tenant_id: ctx.tenantId,
    name,
    public_key_der_base64: parsed.trimmed,
    fingerprint_sha256: parsed.fingerprint_sha256,
    status: 'active',
    created_at: new Date().toISOString(),
    created_by: ctx.userId,
    revoked_at: null,
  };
  getStore().agentUpdateTrustKeys.push(record);
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'agent_update.trust_key_added',
    resource_type: 'agent_update_trust_key',
    resource_id: record.id,
    metadata: {
      trust_key_id: record.id,
      fingerprint_sha256: record.fingerprint_sha256,
      name: record.name,
    },
  });
  persistStore();
  return { trust_key: toPublicTrustKey(record) };
}

export function listAgentUpdateTrustKeys(ctx) {
  return getStore()
    .agentUpdateTrustKeys.filter((k) => k.tenant_id === ctx.tenantId)
    .map(toPublicTrustKey);
}

export function revokeAgentUpdateTrustKey(ctx, id) {
  const key = getStore().agentUpdateTrustKeys.find((k) => k.id === id && k.tenant_id === ctx.tenantId);
  if (!key) return { error: 'not_found', status: 404 };
  if (key.status === 'revoked') {
    return { trust_key: toPublicTrustKey(key) };
  }
  key.status = 'revoked';
  key.revoked_at = new Date().toISOString();
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'agent_update.trust_key_revoked',
    resource_type: 'agent_update_trust_key',
    resource_id: key.id,
    metadata: {
      trust_key_id: key.id,
      fingerprint_sha256: key.fingerprint_sha256,
    },
  });
  persistStore();
  return { trust_key: toPublicTrustKey(key) };
}

export function createAgentUpdateRelease(ctx, body) {
  const version = typeof body?.version === 'string' ? body.version.trim() : '';
  if (!version || version.length > 80) {
    return { error: 'invalid_version', status: 400 };
  }
  let channel = body?.channel ?? 'stable';
  if (typeof channel !== 'string') channel = 'stable';
  channel = channel.toLowerCase();
  if (!CHANNELS.has(channel)) {
    return { error: 'invalid_channel', status: 400 };
  }
  const manifestErr = validateManifest(body?.manifest, version);
  if (manifestErr) return manifestErr;

  const sigResult = validateDetachedSignature(body?.signature);
  if (sigResult.error) return sigResult;

  const sigVerifyErr = verifyDetachedManifestSignature(body.manifest, sigResult.signature);
  if (sigVerifyErr) return sigVerifyErr;

  const trustErr = assertTrustedManifestSigningKey(ctx, body.manifest);
  if (trustErr) return trustErr;

  const distResult = validateDistribution(body?.distribution, body.manifest);
  if (distResult.error) return distResult;

  const rolloutResult = normalizeRollout(body?.rollout);
  if (rolloutResult.error) return rolloutResult;

  let rollback = null;
  if (body?.rollback != null) {
    if (typeof body.rollback !== 'object' || Array.isArray(body.rollback)) {
      return { error: 'invalid_rollback', status: 400 };
    }
    const rbVersion = typeof body.rollback.version === 'string' ? body.rollback.version.trim() : '';
    if (!rbVersion || rbVersion.length > 80) {
      return { error: 'invalid_rollback_version', status: 400 };
    }
    const rbManifestErr = validateManifest(body.rollback.manifest, rbVersion);
    if (rbManifestErr) return { ...rbManifestErr, error: 'invalid_rollback_manifest' };
    const rbSigResult = validateDetachedSignature(body.rollback.signature, {
      missingError: 'missing_rollback_signature',
      invalidError: 'invalid_rollback_signature',
    });
    if (rbSigResult.error) return rbSigResult;
    const rbSigVerifyErr = verifyDetachedManifestSignature(body.rollback.manifest, rbSigResult.signature, {
      verifyFailedError: 'invalid_rollback_signature',
    });
    if (rbSigVerifyErr) return rbSigVerifyErr;
    const rbTrustErr = assertTrustedManifestSigningKey(ctx, body.rollback.manifest);
    if (rbTrustErr) return { ...rbTrustErr, error: 'untrusted_signing_key' };
    const rbDistResult = validateDistribution(body.rollback.distribution, body.rollback.manifest, {
      missingError: 'invalid_rollback_distribution',
      invalidError: 'invalid_rollback_distribution',
      mismatchError: 'invalid_rollback_distribution',
    });
    if (rbDistResult.error) return rbDistResult;
    rollback = {
      version: rbVersion,
      manifest: body.rollback.manifest,
      signature: rbSigResult.signature,
      distribution: rbDistResult.distribution,
    };
  }

  const release = {
    id: newId('agentUpdateRelease'),
    tenant_id: ctx.tenantId,
    version,
    channel,
    manifest: body.manifest,
    signature: sigResult.signature,
    distribution: distResult.distribution,
    rollout: rolloutResult.rollout,
    rollback,
    state: 'active',
    created_at: new Date().toISOString(),
    created_by: ctx.userId,
    rollback_requested_at: null,
  };
  getStore().agentUpdateReleases.push(release);
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'agent_update.release_created',
    resource_type: 'agent_update_release',
    resource_id: release.id,
    metadata: { version, channel, rollout_percentage: rolloutResult.rollout.percentage },
  });
  persistStore();
  return { release: toPublicRelease(release) };
}

export function listAgentUpdateReleases(ctx) {
  return getStore()
    .agentUpdateReleases.filter((r) => r.tenant_id === ctx.tenantId)
    .map(toPublicRelease);
}

export function requestAgentUpdateRollback(ctx, releaseId) {
  const release = getStore().agentUpdateReleases.find(
    (r) => r.id === releaseId && r.tenant_id === ctx.tenantId,
  );
  if (!release) return { error: 'not_found', status: 404 };
  if (!release.rollback) {
    return { error: 'rollback_not_available', status: 400 };
  }
  if (release.state === 'rollback_requested') {
    return { release: toPublicRelease(release) };
  }
  release.state = 'rollback_requested';
  release.rollback_requested_at = new Date().toISOString();
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'agent_update.rollback_requested',
    resource_type: 'agent_update_release',
    resource_id: release.id,
    metadata: { version: release.version, rollback_version: release.rollback.version },
  });
  persistStore();
  return { release: toPublicRelease(release) };
}

export function pollAgentUpdate(agent) {
  const releases = getStore().agentUpdateReleases.filter((r) => r.tenant_id === agent.tenant_id);
  return decideAgentUpdatePoll(agent, releases, (releaseId) => latestStatusForAgentRelease(agent.id, releaseId));
}

export function recordAgentUpdateStatus(agent, body) {
  const validated = validateAgentUpdateStatusBody(body);
  if (validated.error) return validated;

  const { releaseId, status, action, errorCode, installedVersion } = validated;
  const release = getStore().agentUpdateReleases.find(
    (r) => r.id === releaseId && r.tenant_id === agent.tenant_id,
  );
  if (!release) return { error: 'not_found', status: 404 };

  const record = {
    id: newId('agentUpdateStatus'),
    tenant_id: agent.tenant_id,
    agent_id: agent.id,
    release_id: releaseId,
    status,
    action,
    installed_version: installedVersion,
    error_code: errorCode,
    recorded_at: new Date().toISOString(),
  };
  getStore().agentUpdateStatuses.push(record);

  if ((status === 'applied' || status === 'rolled_back') && installedVersion) {
    agent.version = installedVersion;
  }

  audit({
    tenant_id: agent.tenant_id,
    actor_user_id: 'agent',
    actor_role: 'agent',
    action: 'agent_update.status_recorded',
    resource_type: 'agent_update_status',
    resource_id: record.id,
    metadata: {
      agent_id: agent.id,
      release_id: releaseId,
      status,
      action,
      installed_version: installedVersion,
      error_code: errorCode,
    },
  });
  persistStore();
  return { status: record };
}