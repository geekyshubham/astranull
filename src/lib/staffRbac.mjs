import { staffRoleHasPermission } from '../contracts/staffRoles.mjs';
import { auditInternal } from '../services/internalAudit.mjs';

function deny(ctx, permission, meta, message) {
  auditInternal({
    staff_id: ctx.staffId ?? ctx.userId,
    staff_role: ctx.staffRole ?? ctx.role,
    action: 'staff.rbac.denied',
    resource_type: meta.resource_type ?? 'api',
    resource_id: meta.resource_id ?? null,
    metadata: { permission, ...meta.metadata },
  });
  return {
    ok: false,
    status: 403,
    body: { error: 'forbidden', permission, message },
  };
}

export function requireStaffPermission(ctx, permission, meta = {}) {
  const staffRole = ctx.staffRole ?? ctx.role;
  if (!staffRoleHasPermission(staffRole, permission)) {
    return deny(ctx, permission, meta, 'Staff role lacks required permission.');
  }
  return { ok: true };
}