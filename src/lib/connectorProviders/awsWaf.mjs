import { signAwsJsonRequest } from './awsSigV4.mjs';
import {
  buildNormalizedSnapshot,
  CONNECTOR_POLL_INVENTORY_PAGE_SIZE,
  CONNECTOR_POLL_MAX_INVENTORY_ITEMS,
  hashRef,
  normalizePolicyMode,
  resolveConnectorPollFetchTimeoutMs,
} from './common.mjs';

const AWS_WAF_SERVICE = 'wafv2';

function resolveRegion(config = {}, credentials = {}) {
  return String(
    config.region_summary
    ?? config.regionSummary
    ?? credentials.region
    ?? 'us-east-1',
  ).trim() || 'us-east-1';
}

function webAclMatchesConfig(webAcl, config = {}) {
  const resourceRefHash = config.resource_ref_hash ?? config.resourceRefHash ?? null;
  if (!resourceRefHash) return true;
  const arn = webAcl?.ARN ?? webAcl?.arn ?? webAcl?.id ?? webAcl?.name;
  return hashRef(`aws_waf:webacl:${arn}`) === resourceRefHash;
}

function deriveAwsPolicyMode(webAcl) {
  const defaultAction = webAcl?.DefaultAction ?? webAcl?.defaultAction ?? {};
  if (defaultAction.Block || defaultAction.block) return 'block';
  if (defaultAction.Count || defaultAction.count) return 'monitor';
  if (defaultAction.Allow || defaultAction.allow) return 'monitor';
  return normalizePolicyMode(webAcl?.policy_mode ?? webAcl?.policyMode ?? 'unknown');
}

function countAwsRules(webAcl) {
  const rules = webAcl?.Rules ?? webAcl?.rules ?? [];
  return Array.isArray(rules) ? rules.length : 0;
}

async function awsWafJsonRequest({
  region,
  target,
  body,
  credentials,
  fetchFn,
  timeoutMs,
}) {
  const host = `${AWS_WAF_SERVICE}.${region}.amazonaws.com`;
  const payload = JSON.stringify(body ?? {});
  const signedHeaders = signAwsJsonRequest({
    host,
    region,
    service: AWS_WAF_SERVICE,
    body: payload,
    credentials,
    amzTarget: target,
  });
  const boundedTimeoutMs = Number.isFinite(timeoutMs)
    ? timeoutMs
    : resolveConnectorPollFetchTimeoutMs();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), boundedTimeoutMs);
  let res;
  try {
    res = await fetchFn(`https://${host}/`, {
      method: 'POST',
      headers: signedHeaders,
      body: payload,
      signal: controller.signal,
    });
  } catch (cause) {
    const err = new Error('Failed to fetch AWS WAF API within the bounded timeout.');
    err.code = 'provider_poll_failed';
    err.cause = cause;
    throw err;
  } finally {
    clearTimeout(timer);
  }
  const parsed = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(parsed?.message ?? `AWS WAF API error (${res.status})`);
    err.status = res.status;
    if (res.status === 429) err.code = 'rate_limited';
    else if (res.status === 401 || res.status === 403) err.code = 'auth_failed';
    else err.code = 'provider_poll_failed';
    throw err;
  }
  return parsed;
}

async function listWebAclSummaries({
  region,
  scope,
  credentials,
  fetchFn,
  timeoutMs,
}) {
  const summaries = [];
  let nextMarker;
  let truncated = false;

  while (summaries.length < CONNECTOR_POLL_MAX_INVENTORY_ITEMS) {
    const listBody = await awsWafJsonRequest({
      region,
      target: 'AWSWAF_20190729.ListWebACLs',
      body: {
        Scope: scope,
        Limit: CONNECTOR_POLL_INVENTORY_PAGE_SIZE,
        ...(nextMarker ? { NextMarker: nextMarker } : {}),
      },
      credentials,
      fetchFn,
      timeoutMs,
    });
    const batch = Array.isArray(listBody?.WebACLs) ? listBody.WebACLs : [];
    if (batch.length === 0) break;

    const remaining = CONNECTOR_POLL_MAX_INVENTORY_ITEMS - summaries.length;
    summaries.push(...batch.slice(0, remaining));

    const marker = listBody?.NextMarker;
    if (summaries.length >= CONNECTOR_POLL_MAX_INVENTORY_ITEMS) {
      truncated = batch.length > remaining || Boolean(marker);
      break;
    }

    if (!marker) break;
    nextMarker = marker;
  }

  return { summaries, truncated };
}

function normalizePrefetchedWebAcls(prefetched, config, observedAt) {
  const webAcls = Array.isArray(prefetched?.web_acls)
    ? prefetched.web_acls
    : (Array.isArray(prefetched?.webAcls) ? prefetched.webAcls : []);
  const snapshots = [];
  for (const webAcl of webAcls) {
    if (!webAclMatchesConfig(webAcl, config)) continue;
    snapshots.push(buildNormalizedSnapshot({
      provider: 'aws_waf',
      snapshotKind: 'waf_policy',
      resourceRef: webAcl.ARN ?? webAcl.arn ?? webAcl.id ?? webAcl.name,
      displayRef: webAcl.Name ?? webAcl.name ?? webAcl.id,
      summary: {
        hostnames: Array.isArray(webAcl.hostnames) ? webAcl.hostnames : [],
        policy_mode: deriveAwsPolicyMode(webAcl),
        rule_count: countAwsRules(webAcl),
        ...(Array.isArray(webAcl.managed_rule_versions)
          ? { managed_rule_versions: webAcl.managed_rule_versions }
          : {}),
        ...(Array.isArray(webAcl.permission_gaps) ? { permission_gaps: webAcl.permission_gaps } : {}),
      },
      observedAt,
    }));
  }
  return snapshots;
}

/**
 * Read-only AWS WAFv2 metadata poll (fetch + SigV4, no AWS SDK).
 */
export async function pollAwsWaf({
  credentials,
  config = {},
  fetchFn = fetch,
  prefetchedMetadata = null,
  observedAt,
  fetchTimeoutMs,
}) {
  if (prefetchedMetadata) {
    const snapshots = normalizePrefetchedWebAcls(prefetchedMetadata, config, observedAt);
    return {
      snapshots,
      health: snapshots.length > 0 ? 'active' : 'degraded',
      permission_gaps: snapshots.length === 0 ? ['no_webacl_metadata'] : [],
    };
  }

  if (!credentials?.access_key_id || !credentials?.secret_access_key) {
    const err = new Error('AWS WAF credentials missing access_key_id or secret_access_key.');
    err.code = 'credentials_missing';
    throw err;
  }

  const region = resolveRegion(config, credentials);
  const scope = String(config.scope ?? '').toLowerCase() === 'cloudfront' ? 'CLOUDFRONT' : 'REGIONAL';
  const fetchOptions = {
    timeoutMs: Number.isFinite(fetchTimeoutMs)
      ? fetchTimeoutMs
      : resolveConnectorPollFetchTimeoutMs(),
  };
  const { summaries, truncated } = await listWebAclSummaries({
    region,
    scope,
    credentials,
    fetchFn,
    timeoutMs: fetchOptions.timeoutMs,
  });
  const snapshots = [];
  const permissionGaps = [];
  if (truncated) permissionGaps.push('truncated_inventory');

  for (const summary of summaries) {
    if (!webAclMatchesConfig(summary, config)) continue;
    let webAcl = summary;
    try {
      webAcl = await awsWafJsonRequest({
        region,
        target: 'AWSWAF_20190729.GetWebACL',
        body: {
          Scope: scope,
          Id: summary.Id,
          Name: summary.Name,
        },
        credentials,
        fetchFn,
        ...fetchOptions,
      });
      webAcl = webAcl?.WebACL ?? summary;
    } catch (err) {
      if (err.status === 403) {
        permissionGaps.push(`get_webacl:${summary.Id}`);
      } else {
        throw err;
      }
    }

    snapshots.push(buildNormalizedSnapshot({
      provider: 'aws_waf',
      snapshotKind: 'waf_policy',
      resourceRef: summary.ARN ?? summary.Arn ?? summary.Id,
      displayRef: summary.Name ?? summary.Id,
      summary: {
        policy_mode: deriveAwsPolicyMode(webAcl),
        rule_count: countAwsRules(webAcl),
        ...(permissionGaps.length > 0 ? { permission_gaps: permissionGaps } : {}),
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

export const awsWafProvider = {
  provider: 'aws_waf',
  required_scopes: ['wafv2:ListWebACLs', 'wafv2:GetWebACL'],
  snapshot_kinds: ['waf_policy', 'cloud_asset'],
  poll: pollAwsWaf,
};