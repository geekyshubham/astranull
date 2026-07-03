import {
  mapProviderErrorToHealth,
  parseProviderSecret,
} from './common.mjs';
import { getConnectorProvider, supportsOutboundProviderPoll } from './index.mjs';
import { withConnectorPollRetry } from './retry.mjs';

export function shouldAttemptOutboundConnectorPoll(connector, body = {}) {
  if (!connector || connector.status === 'disabled') return false;
  if (connector.config_json?.read_only !== true && connector.config?.read_only !== true) return false;
  if (!supportsOutboundProviderPoll(connector.provider)) return false;
  if (!connector.secret_id) return false;
  if (body.manual_only === true || body.manualOnly === true) return false;
  if (Array.isArray(body.snapshots) && body.snapshots.length > 0) return false;
  return true;
}

/**
 * Resolve vault credentials for provider poll. Returns null when unavailable.
 */
export async function resolveConnectorCredentials({
  ctx,
  connector,
  secretResolver,
}) {
  if (!connector?.secret_id || typeof secretResolver !== 'function') {
    return { credentials: null, error_code: 'credentials_missing' };
  }
  const resolved = await secretResolver(ctx, connector.secret_id, connector.provider);
  if (!resolved || resolved.error) {
    return {
      credentials: null,
      error_code: resolved?.error ?? 'credentials_missing',
    };
  }
  const credentials = parseProviderSecret(resolved.plaintext, connector.provider);
  if (!credentials) {
    return { credentials: null, error_code: 'credentials_missing' };
  }
  return { credentials, error_code: null };
}

/**
 * Execute read-only provider poll with bounded retry/backoff.
 */
export async function executeConnectorProviderPoll({
  connector,
  secretResolver,
  ctx,
  fetchFn = fetch,
  prefetchedMetadata = null,
  now = new Date().toISOString(),
  maxAttempts,
}) {
  const providerImpl = getConnectorProvider(connector.provider);
  if (!providerImpl) {
    const err = new Error(`Unsupported outbound connector provider: ${connector.provider}`);
    err.code = 'unsupported_provider';
    throw err;
  }

  const config = connector.config_json ?? connector.config ?? {};
  let credentials = null;
  if (!prefetchedMetadata) {
    const resolved = await resolveConnectorCredentials({ ctx, connector, secretResolver });
    if (!resolved.credentials) {
      const err = new Error('Connector credentials unavailable for outbound poll.');
      err.code = resolved.error_code ?? 'credentials_missing';
      throw err;
    }
    credentials = resolved.credentials;
  }

  const { result, attempts } = await withConnectorPollRetry(
    async () => providerImpl.poll({
      credentials,
      config,
      fetchFn,
      prefetchedMetadata,
      observedAt: now,
    }),
    { maxAttempts },
  );

  const healthStatus = result.health ?? 'active';
  return {
    snapshots: result.snapshots ?? [],
    health: {
      status: healthStatus,
      health_code: healthStatus,
      attempts,
      permission_gaps: result.permission_gaps ?? [],
      outbound: true,
    },
  };
}

export function buildProviderPollFailure(connector, err, attempts = null) {
  const mapped = mapProviderErrorToHealth(err);
  return {
    snapshots: [],
    health: {
      status: mapped.status,
      health_code: mapped.health_code,
      attempts: attempts ?? err?.attempts ?? null,
      outbound: true,
    },
    error: mapped.health_code,
  };
}