import { ROLES } from '../contracts/roles.mjs';
import { STAFF_ROLES } from '../contracts/staffRoles.mjs';
import { mintBundledStagingOidcJwt } from '../lib/bundledStagingOidc.mjs';

const BUNDLED_STAGING_DEMO_TENANT = 'ten_demo';

/**
 * @param {unknown} body
 * @param {{ bundledStagingOidc?: boolean }} runtimeConfig
 */
export function loginBundledStagingPrincipal(body, runtimeConfig) {
  if (!runtimeConfig.bundledStagingOidc) {
    return {
      error: 'login_disabled',
      status: 403,
      message: 'Bundled staging login is not enabled on this deployment.',
    };
  }

  const principal = String(body?.principal ?? 'customer').trim().toLowerCase();
  const expiresIn = 3600;

  if (principal === 'staff') {
    const staffRole = String(body?.staff_role ?? 'internal_admin').trim().toLowerCase();
    if (!STAFF_ROLES.includes(staffRole)) {
      return { error: 'validation_failed', status: 400, fields: ['staff_role'] };
    }
    const staffId = String(body?.staff_id ?? 'staff_admin').trim() || 'staff_admin';
    const accessToken = mintBundledStagingOidcJwt({
      role: staffRole,
      userId: staffId,
      tenantId: BUNDLED_STAGING_DEMO_TENANT,
      extraClaims: { staff_role: staffRole },
      roleClaimKey: 'role',
    });
    return {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: expiresIn,
      principal: 'staff',
      staff_id: staffId,
      staff_role: staffRole,
    };
  }

  const tenantId = String(body?.tenant_id ?? BUNDLED_STAGING_DEMO_TENANT).trim();
  if (tenantId !== BUNDLED_STAGING_DEMO_TENANT) {
    return { error: 'validation_failed', status: 400, fields: ['tenant_id'] };
  }
  const userId = String(body?.user_id ?? 'usr_admin').trim() || 'usr_admin';
  let role = String(body?.role ?? 'admin').trim().toLowerCase();
  if (!ROLES.includes(role)) role = 'viewer';

  const accessToken = mintBundledStagingOidcJwt({
    role,
    userId,
    tenantId,
  });

  return {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: expiresIn,
    principal: 'customer',
    tenant_id: tenantId,
    user_id: userId,
    role,
  };
}