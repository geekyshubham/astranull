import { roleHasPermission } from './contracts/roles.mjs';
import { audit } from './audit.mjs';

function deny(ctx, permission, meta, message) {
  const entry = {
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'rbac.denied',
    resource_type: meta.resource_type ?? 'api',
    resource_id: meta.resource_id ?? null,
    metadata: { permission, ...meta.metadata },
  };
  const auditService = ctx.auditService;
  if (ctx.persistenceMode === 'postgres') {
    if (typeof auditService?.appendAuditEvent === 'function') {
      Promise.resolve(auditService.appendAuditEvent(entry)).catch(() => {});
    }
  } else {
    audit(entry);
  }
  return {
    ok: false,
    status: 403,
    body: { error: 'forbidden', permission, message },
  };
}

export function requirePermission(ctx, permission, meta = {}) {
  if (!roleHasPermission(ctx.role, permission)) {
    return deny(ctx, permission, meta, 'Role lacks required permission.');
  }
  if (Array.isArray(ctx.scopes)) {
    const scopeOk = ctx.scopes.includes('*') || ctx.scopes.includes(permission);
    if (!scopeOk) {
      return deny(ctx, permission, { ...meta, metadata: { ...meta.metadata, reason: 'scope' } }, 'Scope lacks required permission.');
    }
  }
  return { ok: true };
}
