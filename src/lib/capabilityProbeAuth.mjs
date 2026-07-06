import { verifyProbeJobSignature } from './probeJobs.mjs';

export const INJECTABLE_IO_DEPS = Object.freeze([
  'fetchFn',
  'connectFn',
  'httpsRequestFn',
  'resolve4Fn',
  'resolve6Fn',
  'resolveFn',
  'resolveNsFn',
  'resolve4ExternalFn',
]);

export function hasInjectableIoDeps(deps = {}) {
  return INJECTABLE_IO_DEPS.some((key) => typeof deps[key] === 'function');
}

/** Fail closed unless the caller is a signed worker, a signed job, or an injectable test consumer. */
export function isLiveCapabilityProbeAuthorized(job, deps = {}) {
  if (deps.signedJobVerified === true) return true;
  if (hasInjectableIoDeps(deps)) return true;
  if (deps.probeWorkerSecret && verifyProbeJobSignature(job, deps.probeWorkerSecret)) return true;
  return false;
}