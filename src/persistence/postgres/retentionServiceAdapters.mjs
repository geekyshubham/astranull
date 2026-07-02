/** @type {readonly string[]} */
export const RETENTION_REPOSITORY_METHODS = Object.freeze(['runMetadataRetention']);

/** @type {readonly string[]} */
export const POSTGRES_RETENTION_SERVICE_METHODS = Object.freeze([
  'enforceMetadataRetentionForTenant',
  'previewMetadataRetentionForTenant',
]);

/**
 * @param {{ retention?: Record<string, unknown> }} repositories
 */
export function createPostgresRetentionServices(repositories) {
  const retention = repositories?.retention;
  if (!retention || typeof retention !== 'object') {
    throw new Error('Postgres retention service adapter requires repositories.retention.');
  }
  for (const method of RETENTION_REPOSITORY_METHODS) {
    if (typeof retention[method] !== 'function') {
      throw new Error(`Postgres retention service adapter requires retention.${method}().`);
    }
  }

  return {
    async enforceMetadataRetentionForTenant(ctx, tenantId = ctx?.tenantId, options = {}) {
      return retention.runMetadataRetention(
        tenantId,
        { userId: ctx?.userId ?? null, role: ctx?.role ?? 'system' },
        options,
      );
    },

    async previewMetadataRetentionForTenant(ctx, tenantId = ctx?.tenantId, options = {}) {
      return retention.runMetadataRetention(
        tenantId,
        { userId: ctx?.userId ?? null, role: ctx?.role ?? 'system' },
        { ...options, dryRun: true },
      );
    },
  };
}
