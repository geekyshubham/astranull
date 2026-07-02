import { audit } from '../audit.mjs';
import { verifyCustodyManifest } from '../lib/custody.mjs';

function safeCustodySummary(custody, result, verifiedAt) {
  const summary = {
    ok: result.ok,
    ...(result.error ? { error: result.error } : {}),
    verified_at: verifiedAt,
  };
  if (custody && typeof custody === 'object') {
    for (const field of [
      'schema_version',
      'artifact_type',
      'artifact_id',
      'content_sha256',
      'content_canonicalization',
    ]) {
      if (custody[field] !== undefined) {
        summary[field] = custody[field];
      }
    }
  }
  return summary;
}

async function appendVerificationAudit(ctx, custody, summary) {
  const entry = {
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'custody.verified',
    resource_type: 'custody_manifest',
    resource_id: custody?.artifact_id ?? null,
    metadata: {
      ok: summary.ok,
      ...(summary.error ? { error: summary.error } : {}),
      ...(summary.artifact_type ? { artifact_type: summary.artifact_type } : {}),
      ...(summary.content_sha256 ? { content_sha256: summary.content_sha256 } : {}),
      ...(summary.schema_version ? { custody_schema_version: summary.schema_version } : {}),
    },
  };
  if (ctx.persistenceMode === 'postgres' && typeof ctx.auditService?.appendAuditEvent === 'function') {
    await ctx.auditService.appendAuditEvent(entry);
    return;
  }
  audit(entry);
}

export async function verifyCustodyExport(ctx, body = {}, options = {}) {
  const nowFn = options.now ?? (() => new Date());
  const result = verifyCustodyManifest({
    payload: body.payload,
    custody: body.custody,
  });
  const summary = safeCustodySummary(body.custody, result, nowFn().toISOString());
  await appendVerificationAudit(ctx, body.custody, summary);
  return { ok: result.ok, verification: summary };
}
