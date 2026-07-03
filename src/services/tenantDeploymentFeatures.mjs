import { isConnectorsEnabledForTenant } from '../config.mjs';

/**
 * Tenant-scoped deployment feature flags for authenticated portal UI.
 * @param {{ tenantId?: string | null }} ctx
 * @param {import('../config.mjs').RuntimeConfig} runtimeConfig
 */
export function getTenantDeploymentFeatures(ctx, runtimeConfig) {
  return {
    waf_posture: runtimeConfig.featureFlags?.wafPostureEnabled === true,
    external_discovery: runtimeConfig.featureFlags?.externalDiscoveryEnabled === true,
    connectors: isConnectorsEnabledForTenant(runtimeConfig, ctx.tenantId),
  };
}