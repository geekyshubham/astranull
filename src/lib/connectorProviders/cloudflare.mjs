import {
  buildNormalizedSnapshot,
  CONNECTOR_POLL_INVENTORY_PAGE_SIZE,
  CONNECTOR_POLL_MAX_INVENTORY_ITEMS,
  hashRef,
  normalizePolicyMode,
  resolveConnectorPollFetchTimeoutMs,
} from './common.mjs';

const CLOUDFLARE_API_BASE = 'https://api.cloudflare.com/client/v4';

function countRulesetEntries(rulesets) {
  let count = 0;
  for (const ruleset of rulesets ?? []) {
    if (Array.isArray(ruleset.rules)) count += ruleset.rules.length;
    if (Array.isArray(ruleset.entries)) count += ruleset.entries.length;
  }
  return count;
}

function deriveCloudflarePolicyMode(zone, rulesets) {
  const securityLevel = zone?.security_level ?? zone?.settings?.security_level?.value ?? null;
  if (securityLevel) return normalizePolicyMode(securityLevel);
  const hasBlockingRuleset = (rulesets ?? []).some((ruleset) => {
    const phase = String(ruleset.phase ?? '').toLowerCase();
    return phase.includes('waf') || phase.includes('http_request_firewall');
  });
  return hasBlockingRuleset ? 'block' : 'unknown';
}

function zoneMatchesConfig(zone, config = {}) {
  const zoneRefHash = config.zone_ref_hash ?? config.zoneRefHash ?? null;
  if (!zoneRefHash) return true;
  const zoneId = zone?.id ?? zone?.zone_id ?? zone?.name;
  return hashRef(`cloudflare:zone:${zoneId}`) === zoneRefHash
    || hashRef(`cloudflare:zone:${zone?.name}`) === zoneRefHash;
}

async function cloudflareFetch(path, token, fetchFn, options = {}) {
  const timeoutMs = Number.isFinite(options.timeoutMs)
    ? options.timeoutMs
    : resolveConnectorPollFetchTimeoutMs();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let res;
  try {
    res = await fetchFn(`${CLOUDFLARE_API_BASE}${path}`, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/json',
      },
      signal: controller.signal,
    });
  } catch (cause) {
    const err = new Error('Failed to fetch Cloudflare API within the bounded timeout.');
    err.code = 'provider_poll_failed';
    err.cause = cause;
    throw err;
  } finally {
    clearTimeout(timer);
  }
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(body?.errors?.[0]?.message ?? `Cloudflare API error (${res.status})`);
    err.status = res.status;
    err.code = res.status === 429 ? 'rate_limited' : 'provider_poll_failed';
    throw err;
  }
  if (body?.success === false) {
    const err = new Error(body?.errors?.[0]?.message ?? 'Cloudflare API request failed');
    err.status = 403;
    err.code = 'permission_insufficient';
    throw err;
  }
  return body;
}

async function listZones(token, fetchFn, fetchOptions) {
  const zones = [];
  let page = 1;
  let truncated = false;

  while (zones.length < CONNECTOR_POLL_MAX_INVENTORY_ITEMS) {
    const zonesBody = await cloudflareFetch(
      `/zones?per_page=${CONNECTOR_POLL_INVENTORY_PAGE_SIZE}&page=${page}`,
      token,
      fetchFn,
      fetchOptions,
    );
    const batch = Array.isArray(zonesBody?.result) ? zonesBody.result : [];
    if (batch.length === 0) break;

    const remaining = CONNECTOR_POLL_MAX_INVENTORY_ITEMS - zones.length;
    zones.push(...batch.slice(0, remaining));

    if (zones.length >= CONNECTOR_POLL_MAX_INVENTORY_ITEMS) {
      const totalPages = Number(zonesBody?.result_info?.total_pages);
      const hasMorePages = Number.isFinite(totalPages) && page < totalPages;
      truncated = batch.length > remaining || hasMorePages || batch.length >= CONNECTOR_POLL_INVENTORY_PAGE_SIZE;
      break;
    }

    if (batch.length < CONNECTOR_POLL_INVENTORY_PAGE_SIZE) break;
    page += 1;
  }

  return { zones, truncated };
}

function normalizePrefetchedZones(prefetched, config, observedAt) {
  const zones = Array.isArray(prefetched?.zones) ? prefetched.zones : [];
  const snapshots = [];
  for (const zone of zones) {
    if (!zoneMatchesConfig(zone, config)) continue;
    const rulesets = Array.isArray(zone.rulesets) ? zone.rulesets : [];
    const summary = {
      hostnames: Array.isArray(zone.hostnames)
        ? zone.hostnames
        : (zone.name ? [String(zone.name)] : []),
      policy_mode: deriveCloudflarePolicyMode(zone, rulesets),
      rule_count: Number.isFinite(Number(zone.rule_count))
        ? Number(zone.rule_count)
        : countRulesetEntries(rulesets),
      ...(zone.rate_limit_summary ? { rate_limit_summary: String(zone.rate_limit_summary) } : {}),
      ...(zone.origin_protection_summary
        ? { origin_protection_summary: String(zone.origin_protection_summary) }
        : {}),
      ...(Array.isArray(zone.permission_gaps) ? { permission_gaps: zone.permission_gaps } : {}),
    };
    snapshots.push(buildNormalizedSnapshot({
      provider: 'cloudflare',
      snapshotKind: 'waf_policy',
      resourceRef: zone.id ?? zone.zone_id ?? zone.name,
      displayRef: zone.name ?? zone.id,
      summary,
      observedAt,
    }));
  }
  return snapshots;
}

/**
 * Read-only Cloudflare zone/ruleset metadata poll.
 */
export async function pollCloudflare({
  credentials,
  config = {},
  fetchFn = fetch,
  prefetchedMetadata = null,
  observedAt,
  fetchTimeoutMs,
}) {
  if (prefetchedMetadata) {
    const snapshots = normalizePrefetchedZones(prefetchedMetadata, config, observedAt);
    return {
      snapshots,
      health: snapshots.length > 0 ? 'active' : 'degraded',
      permission_gaps: snapshots.length === 0 ? ['no_zone_metadata'] : [],
    };
  }

  const token = credentials?.api_token;
  if (!token) {
    const err = new Error('Cloudflare credentials missing api_token.');
    err.code = 'credentials_missing';
    throw err;
  }

  const fetchOptions = {
    timeoutMs: Number.isFinite(fetchTimeoutMs)
      ? fetchTimeoutMs
      : resolveConnectorPollFetchTimeoutMs(),
  };
  const { zones, truncated } = await listZones(token, fetchFn, fetchOptions);
  const snapshots = [];
  const permissionGaps = [];
  if (truncated) permissionGaps.push('truncated_inventory');

  for (const zone of zones) {
    if (!zoneMatchesConfig(zone, config)) continue;
    let rulesets = [];
    const zonePermissionGaps = [];
    try {
      const rulesetsBody = await cloudflareFetch(`/zones/${zone.id}/rulesets`, token, fetchFn, fetchOptions);
      rulesets = Array.isArray(rulesetsBody?.result) ? rulesetsBody.result : [];
    } catch (err) {
      if (err.status === 403) {
        zonePermissionGaps.push(`rulesets:${zone.id}`);
        permissionGaps.push(`rulesets:${zone.id}`);
      } else {
        throw err;
      }
    }

    snapshots.push(buildNormalizedSnapshot({
      provider: 'cloudflare',
      snapshotKind: 'waf_policy',
      resourceRef: zone.id,
      displayRef: zone.name ?? zone.id,
      summary: {
        hostnames: zone.name ? [zone.name] : [],
        policy_mode: deriveCloudflarePolicyMode(zone, rulesets),
        rule_count: countRulesetEntries(rulesets),
        ...(zonePermissionGaps.length > 0 ? { permission_gaps: zonePermissionGaps } : {}),
      },
      observedAt,
    }));
  }

  return {
    snapshots,
    health: permissionGaps.length > 0 ? 'degraded' : 'active',
    permission_gaps: permissionGaps,
  };
}

export const cloudflareProvider = {
  provider: 'cloudflare',
  required_scopes: ['Zone:Read', 'Account:Read'],
  snapshot_kinds: ['waf_policy', 'dns_zone', 'cdn_property'],
  poll: pollCloudflare,
};