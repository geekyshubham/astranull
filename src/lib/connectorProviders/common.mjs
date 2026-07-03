import { createHash } from 'node:crypto';

export const CONNECTOR_POLL_MAX_ATTEMPTS = 3;
export const CONNECTOR_POLL_BASE_BACKOFF_MS = 250;
export const CONNECTOR_POLL_FETCH_DEFAULT_TIMEOUT_MS = 10_000;
export const CONNECTOR_POLL_MAX_INVENTORY_ITEMS = 200;
export const CONNECTOR_POLL_INVENTORY_PAGE_SIZE = 50;

export function resolveConnectorPollFetchTimeoutMs(env = process.env) {
  const raw = String(env?.ASTRANULL_CONNECTOR_POLL_FETCH_TIMEOUT_MS ?? '').trim();
  if (!raw) return CONNECTOR_POLL_FETCH_DEFAULT_TIMEOUT_MS;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return CONNECTOR_POLL_FETCH_DEFAULT_TIMEOUT_MS;
  }
  return Math.floor(parsed);
}

const POLICY_MODE_VALUES = new Set(['block', 'monitor', 'disabled', 'unknown']);

export function hashRef(value) {
  return createHash('sha256').update(String(value ?? ''), 'utf8').digest('hex').slice(0, 32);
}

function stableStringify(value) {
  if (value === undefined) return 'null';
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((entry) => stableStringify(entry)).join(',')}]`;
  }
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`;
}

export function computeConfigHash(summary) {
  return createHash('sha256').update(stableStringify(summary ?? {}), 'utf8').digest('hex').slice(0, 32);
}

export function normalizePolicyMode(value) {
  const raw = String(value ?? '').trim().toLowerCase();
  if (!raw) return 'unknown';
  if (raw.includes('block') || raw.includes('prevent') || raw.includes('under_attack') || raw === 'high') {
    return 'block';
  }
  if (raw.includes('monitor') || raw.includes('detect') || raw.includes('count') || raw === 'low') {
    return 'monitor';
  }
  if (raw.includes('off') || raw.includes('disable') || raw === 'essentially_off') {
    return 'disabled';
  }
  return POLICY_MODE_VALUES.has(raw) ? raw : 'unknown';
}

export function buildNormalizedSnapshot({
  provider,
  snapshotKind,
  resourceRef,
  displayRef,
  summary = {},
  observedAt,
}) {
  const safeSummary = {
    ...(Array.isArray(summary.hostnames) ? { hostnames: summary.hostnames.map((h) => String(h).trim()).filter(Boolean) } : {}),
    ...(summary.policy_mode ? { policy_mode: normalizePolicyMode(summary.policy_mode) } : {}),
    ...(Number.isFinite(Number(summary.rule_count)) ? { rule_count: Math.max(0, Math.floor(Number(summary.rule_count))) } : {}),
    ...(Array.isArray(summary.managed_rule_versions)
      ? { managed_rule_versions: summary.managed_rule_versions.map((v) => String(v).trim()).filter(Boolean) }
      : {}),
    ...(typeof summary.last_rule_update_at === 'string' && summary.last_rule_update_at.trim()
      ? { last_rule_update_at: summary.last_rule_update_at.trim() }
      : {}),
    ...(typeof summary.rate_limit_summary === 'string' && summary.rate_limit_summary.trim()
      ? { rate_limit_summary: summary.rate_limit_summary.trim() }
      : {}),
    ...(typeof summary.origin_protection_summary === 'string' && summary.origin_protection_summary.trim()
      ? { origin_protection_summary: summary.origin_protection_summary.trim() }
      : {}),
    ...(Array.isArray(summary.tags)
      ? { tags: summary.tags.map((tag) => String(tag).trim()).filter(Boolean) }
      : {}),
    ...(Array.isArray(summary.permission_gaps)
      ? { permission_gaps: summary.permission_gaps.map((gap) => String(gap).trim()).filter(Boolean) }
      : {}),
  };
  safeSummary.config_hash = computeConfigHash(safeSummary);
  const resourceRefHash = hashRef(`${provider}:${resourceRef}`);
  const configHash = safeSummary.config_hash;
  return {
    snapshot_kind: snapshotKind,
    resource_ref_hash: resourceRefHash,
    display_ref: String(displayRef ?? resourceRef).trim(),
    summary: safeSummary,
    config_hash: configHash,
    observed_at: observedAt ?? new Date().toISOString(),
    provider,
  };
}

export function parseProviderSecret(plaintext, provider) {
  const raw = String(plaintext ?? '').trim();
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      if (provider === 'cloudflare') {
        const token = parsed.api_token ?? parsed.token ?? parsed.apiToken ?? null;
        if (typeof token === 'string' && token.trim()) return { api_token: token.trim() };
      }
      if (provider === 'aws_waf') {
        const accessKeyId = parsed.access_key_id ?? parsed.accessKeyId ?? null;
        const secretAccessKey = parsed.secret_access_key ?? parsed.secretAccessKey ?? null;
        const region = parsed.region ?? parsed.aws_region ?? 'us-east-1';
        if (typeof accessKeyId === 'string' && accessKeyId.trim()
          && typeof secretAccessKey === 'string' && secretAccessKey.trim()) {
          return {
            access_key_id: accessKeyId.trim(),
            secret_access_key: secretAccessKey.trim(),
            region: String(region).trim() || 'us-east-1',
            ...(typeof parsed.session_token === 'string' && parsed.session_token.trim()
              ? { session_token: parsed.session_token.trim() }
              : {}),
          };
        }
      }
    }
  } catch {
    // fall through to plain token handling
  }
  if (provider === 'cloudflare') return { api_token: raw };
  return null;
}

export function mapProviderErrorToHealth(err) {
  const code = String(err?.code ?? err?.provider_code ?? '').trim().toLowerCase();
  const status = Number(err?.status ?? err?.http_status ?? 0);
  const message = String(err?.message ?? '').toLowerCase();

  if (code === 'credentials_missing' || code === 'secret_not_found' || code === 'encryption_not_configured') {
    return { status: 'error', health_code: code };
  }
  if (status === 401 || status === 403 || code === 'auth_failed' || message.includes('unauthorized')) {
    return { status: 'revoked', health_code: 'auth_failed' };
  }
  if (status === 429 || code === 'rate_limited' || message.includes('rate limit')) {
    return { status: 'rate_limited', health_code: 'rate_limited' };
  }
  if (code === 'permission_insufficient' || message.includes('permission') || message.includes('forbidden scope')) {
    return { status: 'permission_insufficient', health_code: 'permission_insufficient' };
  }
  if (code === 'degraded' || err?.partial === true) {
    return { status: 'degraded', health_code: 'partial_data' };
  }
  return { status: 'error', health_code: code || 'provider_poll_failed' };
}

export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}