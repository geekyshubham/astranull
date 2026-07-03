import { audit } from '../audit.mjs';
import { signCustodyManifestMetadataAsync } from '../lib/evidenceSigning.mjs';
import { createEvidenceSigningKmsAdapter } from '../lib/evidenceSigningKmsAdapter.mjs';

function safeSignedAuditMetadata(signed) {
  return {
    algorithm: signed.algorithm,
    key_reference: signed.key_reference,
    custody_manifest_digest: signed.custody_manifest_digest,
    content_sha256: signed.content_sha256,
    artifact_type: signed.artifact_type,
    artifact_id: signed.artifact_id,
    public_key_fingerprint_sha256: signed.public_key_fingerprint_sha256,
    signing_schema_version: signed.schema_version,
  };
}

async function appendSigningAudit(ctx, signed) {
  const entry = {
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'evidence.snapshot_signed',
    resource_type: 'custody_manifest',
    resource_id: signed.artifact_id ?? null,
    metadata: safeSignedAuditMetadata(signed),
  };
  if (ctx.persistenceMode === 'postgres' && typeof ctx.auditService?.appendAuditEvent === 'function') {
    await ctx.auditService.appendAuditEvent(entry);
    return;
  }
  audit(entry);
}

/**
 * @param {import('../context.mjs').RequestContext} ctx
 * @param {Record<string, unknown>} body
 * @param {{ env?: NodeJS.ProcessEnv, now?: () => Date }} [options]
 */
export async function signEvidenceSnapshotCustody(ctx, body = {}, options = {}) {
  const env = options.env ?? process.env;
  const custody = body.custody;
  const keyReference = body.key_reference ?? body.keyReference;
  const algorithm = body.algorithm;
  const signingAdapter = options.signingAdapter
    ?? createEvidenceSigningKmsAdapter({ env, fetchFn: options.fetchFn });
  const result = await signCustodyManifestMetadataAsync({
    tenantId: ctx.tenantId,
    custody,
    keyReference,
    algorithm,
    env,
    now: options.now,
    signingAdapter,
  });
  if (result.error) {
    return result;
  }
  await appendSigningAudit(ctx, result.signed);
  return result;
}