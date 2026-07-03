export const HOSTED_STAGING_ENVIRONMENT = 'staging';
export const HOSTED_STAGING_RELEASE_ID = 'rel-hosted-staging-2026-07-03';
export const DEFAULT_HOSTED_STAGING_TENANT_ID = 'ten_demo';
export const DEFAULT_HOSTED_STAGING_PROBE_WORKER_SECRET = 'hosted-staging-probe-worker-secret-32c';
export const DEFAULT_LOCAL_STAGING_PROBE_WORKER_SECRET = 'local-staging-probe-worker-secret-32c';

export function isHostedStagingEnvironment(value) {
  if (value === null || value === undefined) return false;
  return String(value).trim().toLowerCase() === HOSTED_STAGING_ENVIRONMENT;
}

/**
 * @param {NodeJS.ProcessEnv} [env]
 */
export function resolveHostedStagingBaseUrl(env = process.env) {
  const explicit = String(env.ASTRANULL_HOSTED_STAGING_BASE_URL ?? '').trim().replace(/\/$/, '');
  if (explicit) return explicit;
  const local = String(env.ASTRANULL_LOCAL_STAGING_BASE_URL ?? '').trim().replace(/\/$/, '');
  if (local) return local;
  return '';
}

/**
 * @param {string} baseUrl
 * @param {NodeJS.ProcessEnv} [env]
 */
export function isHostedStagingBaseUrl(baseUrl, env = process.env) {
  const hosted = resolveHostedStagingBaseUrl(env);
  if (hosted && String(baseUrl).trim().replace(/\/$/, '') === hosted) return true;
  return !/^https?:\/\/(127\.0\.0\.1|localhost)(:\d+)?(?:\/|$)/i.test(String(baseUrl ?? '').trim());
}

/**
 * @param {string} [baseUrl]
 * @param {NodeJS.ProcessEnv} [env]
 */
export function resolveStagingProbeWorkerSecret(baseUrl = '', env = process.env) {
  const explicit = String(env.ASTRANULL_PROBE_WORKER_SECRET ?? '').trim();
  if (explicit) return explicit;
  return isHostedStagingBaseUrl(baseUrl, env)
    ? DEFAULT_HOSTED_STAGING_PROBE_WORKER_SECRET
    : DEFAULT_LOCAL_STAGING_PROBE_WORKER_SECRET;
}