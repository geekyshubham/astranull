/** AstraNull staff roles — distinct from customer tenant roles in roles.mjs */

export const STAFF_ROLES = Object.freeze([
  'internal_admin',
  'billing_ops',
  'support_engineer',
  'soc_analyst',
  'soc_lead',
  'security_admin',
]);

export const STAFF_PERMISSIONS = Object.freeze({
  'staff:signup:read': ['internal_admin', 'support_engineer', 'security_admin'],
  'staff:signup:decide': ['internal_admin'],
  'staff:tenant:read': ['internal_admin', 'billing_ops', 'support_engineer', 'security_admin'],
  'staff:tenant:write': ['internal_admin'],
  'staff:subscription:read': ['internal_admin', 'billing_ops', 'support_engineer', 'security_admin'],
  'staff:subscription:write': ['internal_admin', 'billing_ops'],
  'staff:entitlement:write': ['internal_admin'],
  'staff:approval:read': ['internal_admin', 'billing_ops', 'support_engineer', 'security_admin', 'soc_analyst', 'soc_lead'],
  'staff:approval:decide': ['internal_admin', 'billing_ops', 'security_admin', 'soc_analyst', 'soc_lead'],
  'staff:support:write': ['internal_admin', 'support_engineer'],
  'staff:audit:read': ['internal_admin', 'security_admin'],
});

export function staffRoleHasPermission(staffRole, permission) {
  const allowed = STAFF_PERMISSIONS[permission];
  if (!allowed) return false;
  return allowed.includes(staffRole);
}

export function isStaffRole(role) {
  return STAFF_ROLES.includes(role);
}