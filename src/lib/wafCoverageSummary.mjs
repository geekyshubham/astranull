/**
 * Dashboard WAF coverage summary (portal revamp §4.3 / migration 0029).
 */

function postureClass(snapshot) {
  const status = String(snapshot?.status ?? 'unknown').toLowerCase();
  if (status === 'protected') return 'protected';
  if (['underprotected', 'unprotected', 'drift'].includes(status)) return 'underprotected';
  return 'unknown';
}

/**
 * @param {{
 *   assets?: Array<{ id: string, tenant_id?: string }>,
 *   currentSnapshotsByAsset?: Map<string, { status?: string, detected_vendor?: string | null }>,
 *   connectors?: Array<{ status?: string }>,
 *   refreshedAt?: string | Date,
 * }} input
 */
export function computeWafCoverageSummaryRow(input = {}) {
  const assets = input.assets ?? [];
  const snapshots = input.currentSnapshotsByAsset ?? new Map();
  const connectors = input.connectors ?? [];
  const refreshedAt =
    input.refreshedAt instanceof Date
      ? input.refreshedAt.toISOString()
      : String(input.refreshedAt ?? new Date().toISOString());

  const counts = { protected: 0, underprotected: 0, unknown: 0 };
  const vendorBuckets = new Map();

  for (const asset of assets) {
    const snapshot = snapshots.get(asset.id) ?? null;
    const posture = postureClass(snapshot);
    counts[posture] += 1;

    const vendorRaw = snapshot?.detected_vendor ?? null;
    const vendor =
      typeof vendorRaw === 'string' && vendorRaw.trim() ? vendorRaw.trim() : 'generic';
    const bucket = vendorBuckets.get(vendor) ?? { assets: 0, protected: 0 };
    bucket.assets += 1;
    if (posture === 'protected') bucket.protected += 1;
    vendorBuckets.set(vendor, bucket);
  }

  const assetsTotal = assets.length;
  const coveragePct =
    assetsTotal === 0
      ? 0
      : Math.round((counts.protected / assetsTotal) * 10000) / 100;

  const byVendor = {};
  for (const [vendor, bucket] of vendorBuckets.entries()) {
    byVendor[vendor] = { assets: bucket.assets, protected: bucket.protected };
  }

  let connectorsActive = 0;
  let connectorsDegraded = 0;
  let connectorsDisabled = 0;
  for (const connector of connectors) {
    const status = String(connector?.status ?? '').toLowerCase();
    if (status === 'active') connectorsActive += 1;
    else if (status === 'error' || status === 'degraded') connectorsDegraded += 1;
    else if (status === 'disabled') connectorsDisabled += 1;
  }

  return {
    assets_total: assetsTotal,
    protected: counts.protected,
    underprotected: counts.underprotected,
    unknown: counts.unknown,
    coverage_pct: coveragePct,
    by_vendor: byVendor,
    connectors_active: connectorsActive,
    connectors_degraded: connectorsDegraded,
    connectors_disabled: connectorsDisabled,
    refreshed_at: refreshedAt,
  };
}

/**
 * @param {Record<string, unknown> | null | undefined} row
 */
export function mapWafCoverageSummaryRow(row) {
  if (!row) return null;
  const byVendor =
    row.by_vendor && typeof row.by_vendor === 'object' && !Array.isArray(row.by_vendor)
      ? row.by_vendor
      : {};
  return {
    assets_total: Number(row.assets_total ?? 0),
    protected: Number(row.protected ?? 0),
    underprotected: Number(row.underprotected ?? 0),
    unknown: Number(row.unknown ?? 0),
    coverage_pct: Number(row.coverage_pct ?? 0),
    by_vendor: byVendor,
    connectors_active: Number(row.connectors_active ?? 0),
    connectors_degraded: Number(row.connectors_degraded ?? 0),
    connectors_disabled: Number(row.connectors_disabled ?? 0),
    refreshed_at:
      row.refreshed_at instanceof Date
        ? row.refreshed_at.toISOString()
        : row.refreshed_at == null
          ? null
          : String(row.refreshed_at),
  };
}