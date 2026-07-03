export const LOCAL_STAGING_ENVIRONMENT = 'local-staging';
export const LOCAL_STAGING_RELEASE_ID = 'rel-local-staging-2026-07-03';
export const DEFAULT_LOCAL_STAGING_BASE_URL = 'http://127.0.0.1:3000';
export const DEFAULT_LOCAL_STAGING_TENANT_ID = 'ten_demo';
export const DEFAULT_LOCAL_STAGING_ADMIN_USER_ID = 'usr_admin';
export const DEFAULT_LOCAL_STAGING_ADMIN_ROLE = 'admin';

export const LOCAL_STAGING_DEMO_IDS = Object.freeze({
  tenantId: DEFAULT_LOCAL_STAGING_TENANT_ID,
  environmentId: 'env_demo',
  targetGroupId: 'tg_demo_origin',
  targetId: 'tgt_demo_1',
  adminUserId: DEFAULT_LOCAL_STAGING_ADMIN_USER_ID,
  socUserId: 'usr_soc',
});

export function isLocalStagingEnvironment(value) {
  if (value === null || value === undefined) return false;
  return String(value).trim().toLowerCase() === LOCAL_STAGING_ENVIRONMENT;
}