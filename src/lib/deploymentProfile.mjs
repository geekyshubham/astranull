export const DEPLOYMENT_PROFILES = Object.freeze(['local-staging', 'hosted-staging', 'production']);

/**
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {'local-staging' | 'hosted-staging' | 'production' | null}
 */
export function resolveDeploymentProfile(env = process.env) {
  const explicit = String(env.ASTRANULL_DEPLOYMENT_PROFILE ?? '').trim();
  if (explicit) {
    if (!DEPLOYMENT_PROFILES.includes(explicit)) {
      throw new Error(
        `Invalid ASTRANULL_DEPLOYMENT_PROFILE "${explicit}". Allowed: ${DEPLOYMENT_PROFILES.join(', ')}.`,
      );
    }
    return explicit;
  }
  if (env.ASTRANULL_BUNDLED_STAGING_OIDC === '1') return 'hosted-staging';
  return null;
}

/**
 * @param {NodeJS.ProcessEnv} [env]
 */
export function isHostedStagingDeployment(env = process.env) {
  return resolveDeploymentProfile(env) === 'hosted-staging';
}

/**
 * @param {NodeJS.ProcessEnv} [env]
 */
export function isProductionDeployment(env = process.env) {
  return resolveDeploymentProfile(env) === 'production';
}