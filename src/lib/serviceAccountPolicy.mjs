import { randomBytes } from 'node:crypto';
import { PERMISSIONS, SERVICE_ACCOUNT_ROLES } from '../contracts/roles.mjs';
import { createAddressedSecret } from './addressedSecrets.mjs';

export function generateServiceAccountSecret(tenantId, accountId) {
  if (tenantId && accountId) {
    return createAddressedSecret('svc_', tenantId, accountId);
  }
  return `svc_${randomBytes(24).toString('base64url')}`;
}

export function permissionsForRole(role) {
  return Object.keys(PERMISSIONS).filter((p) => PERMISSIONS[p].includes(role));
}

export function validateRequestedScopes(role, scopes) {
  if (!SERVICE_ACCOUNT_ROLES.includes(role)) {
    return { error: 'invalid_role', message: 'Service account role must be admin, engineer, auditor, or viewer.' };
  }
  if (!Array.isArray(scopes) || scopes.length === 0) {
    return { error: 'invalid_scopes', message: 'scopes must be a non-empty array of permission strings.' };
  }
  const allowed = new Set(permissionsForRole(role));
  if (scopes.includes('*')) {
    if (role !== 'admin') {
      return { error: 'invalid_scopes', message: 'Wildcard scope is allowed only for admin service accounts.' };
    }
    if (scopes.length !== 1) {
      return { error: 'invalid_scopes', message: 'Wildcard scope cannot be combined with other scopes.' };
    }
    return { ok: true, scopes: ['*'] };
  }
  for (const scope of scopes) {
    if (typeof scope !== 'string' || !allowed.has(scope)) {
      return {
        error: 'invalid_scopes',
        message: `Scope "${scope}" is not permitted for role "${role}".`,
      };
    }
  }
  return { ok: true, scopes: [...new Set(scopes)] };
}

export function redactServiceAccount(record) {
  if (!record) return record;
  const { secret_salt, secret_hash, ...rest } = record;
  return { ...rest, secret: undefined };
}