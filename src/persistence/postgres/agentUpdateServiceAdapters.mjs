import { newId } from '../../lib/ids.mjs';
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
} from '../../lib/agentUpdates.mjs';

/** @type {readonly string[]} */
export const AGENT_UPDATE_REPOSITORY_METHODS = Object.freeze([
  'createTrustKey',
  'listTrustKeys',
  'getTrustKeyById',
  'getActiveTrustKeyByFingerprint',
  'revokeTrustKey',
  'createRelease',
  'listReleases',
  'getReleaseById',
  'updateReleaseRollbackRequested',
  'appendStatus',
  'getLatestStatusForAgentRelease',
  'updateAgentVersion',
]);

/** @type {readonly string[]} */
export const POSTGRES_AGENT_UPDATE_SERVICE_METHODS = Object.freeze([
  'createAgentUpdateTrustKey',
  'listAgentUpdateTrustKeys',
  'revokeAgentUpdateTrustKey',
  'createAgentUpdateRelease',
  'listAgentUpdateReleases',
  'requestAgentUpdateRollback',
  'pollAgentUpdate',
  'recordAgentUpdateStatus',
]);

function assertAgentUpdateRepositories(repositories) {
  const agentUpdates = repositories?.agentUpdates;
  if (!agentUpdates || typeof agentUpdates !== 'object') {
    throw new Error('Postgres agent update service adapter requires repositories.agentUpdates.');
  }
  for (const method of AGENT_UPDATE_REPOSITORY_METHODS) {
    if (typeof agentUpdates[method] !== 'function') {
      throw new Error(`Postgres agent update service adapter requires agentUpdates.${method}().`);
    }
  }

  const audit = repositories?.audit;
  if (!audit || typeof audit !== 'object') {
    throw new Error('Postgres agent update service adapter requires repositories.audit.');
  }
  if (typeof audit.appendAuditEvent !== 'function') {
    throw new Error('Postgres agent update service adapter requires audit.appendAuditEvent().');
  }
}

async function assertTrustedManifestSigningKey(ctx, repo, manifest) {
  const parsed = parseManifestSigningKey(manifest);
  if (parsed.error) return parsed;
  const trusted = await repo.getActiveTrustKeyByFingerprint(ctx, parsed.fingerprint_sha256);
  if (!trusted) {
    return { error: 'untrusted_signing_key', status: 400 };
  }
  return null;
}

/**
 * @param {{
 *   agentUpdates?: Record<string, unknown>,
 *   audit?: { appendAuditEvent?: (...args: unknown[]) => unknown },
 * }} repositories
 * @param {{ now?: () => Date, newId?: typeof newId }} [options]
 */
export function createPostgresAgentUpdateServices(repositories, options = {}) {
  assertAgentUpdateRepositories(repositories);
  const repo = repositories.agentUpdates;
  const auditRepo = repositories.audit;
  const nowFn = options.now ?? (() => new Date());
  const newIdFn = options.newId ?? newId;

  return {
    async createAgentUpdateTrustKey(ctx, body) {
      let name = body?.name ?? 'agent update signing key';
      if (name == null) name = 'agent update signing key';
      if (typeof name !== 'string' || name.length > 80) {
        return { error: 'invalid_name', status: 400 };
      }
      name = name.trim() || 'agent update signing key';

      const parsed = parseEd25519SpkiDerBase64(body?.public_key_der_base64);
      if (parsed.error) return parsed;

      const duplicate = await repo.getActiveTrustKeyByFingerprint(ctx, parsed.fingerprint_sha256);
      if (duplicate) {
        return { error: 'duplicate_trust_key', status: 409 };
      }

      const record = {
        id: newIdFn('agentUpdateTrustKey'),
        tenant_id: ctx.tenantId,
        name,
        public_key_der_base64: parsed.trimmed,
        fingerprint_sha256: parsed.fingerprint_sha256,
        status: 'active',
        created_at: nowFn().toISOString(),
        created_by: ctx.userId,
        revoked_at: null,
      };
      const persisted = await repo.createTrustKey(record);
      await auditRepo.appendAuditEvent({
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId,
        actor_role: ctx.role,
        action: 'agent_update.trust_key_added',
        resource_type: 'agent_update_trust_key',
        resource_id: persisted.id,
        metadata: {
          trust_key_id: persisted.id,
          fingerprint_sha256: persisted.fingerprint_sha256,
          name: persisted.name,
        },
      });
      return { trust_key: toPublicTrustKey(persisted) };
    },

    async listAgentUpdateTrustKeys(ctx) {
      const items = await repo.listTrustKeys(ctx);
      return items.map(toPublicTrustKey);
    },

    async revokeAgentUpdateTrustKey(ctx, id) {
      const key = await repo.getTrustKeyById(ctx, id);
      if (!key) return { error: 'not_found', status: 404 };
      if (key.status === 'revoked') {
        return { trust_key: toPublicTrustKey(key) };
      }
      const revokedAt = nowFn().toISOString();
      const persisted = await repo.revokeTrustKey(ctx, id, revokedAt);
      await auditRepo.appendAuditEvent({
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId,
        actor_role: ctx.role,
        action: 'agent_update.trust_key_revoked',
        resource_type: 'agent_update_trust_key',
        resource_id: persisted.id,
        metadata: {
          trust_key_id: persisted.id,
          fingerprint_sha256: persisted.fingerprint_sha256,
        },
      });
      return { trust_key: toPublicTrustKey(persisted) };
    },

    async createAgentUpdateRelease(ctx, body) {
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

      const trustErr = await assertTrustedManifestSigningKey(ctx, repo, body.manifest);
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
        const rbSigVerifyErr = verifyDetachedManifestSignature(
          body.rollback.manifest,
          rbSigResult.signature,
          { verifyFailedError: 'invalid_rollback_signature' },
        );
        if (rbSigVerifyErr) return rbSigVerifyErr;
        const rbTrustErr = await assertTrustedManifestSigningKey(ctx, repo, body.rollback.manifest);
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
        id: newIdFn('agentUpdateRelease'),
        tenant_id: ctx.tenantId,
        version,
        channel,
        manifest: body.manifest,
        signature: sigResult.signature,
        distribution: distResult.distribution,
        rollout: rolloutResult.rollout,
        rollback,
        state: 'active',
        created_at: nowFn().toISOString(),
        created_by: ctx.userId,
        rollback_requested_at: null,
      };
      const persisted = await repo.createRelease(release);
      await auditRepo.appendAuditEvent({
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId,
        actor_role: ctx.role,
        action: 'agent_update.release_created',
        resource_type: 'agent_update_release',
        resource_id: persisted.id,
        metadata: { version, channel, rollout_percentage: rolloutResult.rollout.percentage },
      });
      return { release: toPublicRelease(persisted) };
    },

    async listAgentUpdateReleases(ctx) {
      const items = await repo.listReleases(ctx);
      return items.map(toPublicRelease);
    },

    async requestAgentUpdateRollback(ctx, releaseId) {
      const release = await repo.getReleaseById(ctx, releaseId);
      if (!release) return { error: 'not_found', status: 404 };
      if (!release.rollback) {
        return { error: 'rollback_not_available', status: 400 };
      }
      if (release.state === 'rollback_requested') {
        return { release: toPublicRelease(release) };
      }
      const rollbackRequestedAt = nowFn().toISOString();
      const persisted = await repo.updateReleaseRollbackRequested(ctx, releaseId, {
        state: 'rollback_requested',
        rollback_requested_at: rollbackRequestedAt,
      });
      await auditRepo.appendAuditEvent({
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId,
        actor_role: ctx.role,
        action: 'agent_update.rollback_requested',
        resource_type: 'agent_update_release',
        resource_id: persisted.id,
        metadata: { version: persisted.version, rollback_version: persisted.rollback.version },
      });
      return { release: toPublicRelease(persisted) };
    },

    async pollAgentUpdate(agent) {
      const ctx = { tenantId: agent.tenant_id };
      const releases = await repo.listReleases(ctx);
      const latestByRelease = new Map();
      for (const release of releases) {
        const latest = await repo.getLatestStatusForAgentRelease(ctx, agent.id, release.id);
        if (latest) {
          latestByRelease.set(release.id, latest);
        }
      }
      return decideAgentUpdatePoll(agent, releases, (releaseId) => latestByRelease.get(releaseId) ?? null);
    },

    async recordAgentUpdateStatus(agent, body) {
      const validated = validateAgentUpdateStatusBody(body);
      if (validated.error) return validated;

      const { releaseId, status, action, errorCode, installedVersion } = validated;
      const ctx = { tenantId: agent.tenant_id };
      const release = await repo.getReleaseById(ctx, releaseId);
      if (!release) return { error: 'not_found', status: 404 };

      const record = {
        id: newIdFn('agentUpdateStatus'),
        tenant_id: agent.tenant_id,
        agent_id: agent.id,
        release_id: releaseId,
        status,
        action,
        installed_version: installedVersion,
        error_code: errorCode,
        recorded_at: nowFn().toISOString(),
      };
      const persisted = await repo.appendStatus(record);

      if ((status === 'applied' || status === 'rolled_back') && installedVersion) {
        await repo.updateAgentVersion(ctx, agent.id, installedVersion);
        agent.version = installedVersion;
      }

      await auditRepo.appendAuditEvent({
        tenant_id: agent.tenant_id,
        actor_user_id: 'agent',
        actor_role: 'agent',
        action: 'agent_update.status_recorded',
        resource_type: 'agent_update_status',
        resource_id: persisted.id,
        metadata: {
          agent_id: agent.id,
          release_id: releaseId,
          status,
          action,
          installed_version: installedVersion,
          error_code: errorCode,
        },
      });
      return { status: persisted };
    },
  };
}