import type { DataItem } from '../../lib/types';
import { EmptyState } from '../ui/empty-state';
import { ShieldHalf } from 'lucide-react';

function getNumber(item: DataItem | null | undefined, keys: string[], fallback: number | null = null) {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (typeof value === 'number' && Number.isFinite(value)) return value;
  }
  return fallback;
}

function getString(item: DataItem | null | undefined, keys: string[], fallback = '') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

function vendorRows(summary: DataItem | null) {
  const byVendor = summary?.by_vendor;
  if (!byVendor || typeof byVendor !== 'object' || Array.isArray(byVendor)) return [];
  return Object.entries(byVendor as Record<string, DataItem>).map(([vendor, stats]) => {
    const assets = getNumber(stats, ['assets', 'assets_total'], 0) ?? 0;
    const protectedCount = getNumber(stats, ['protected'], 0) ?? 0;
    const underprotected = getNumber(stats, ['underprotected'], 0) ?? 0;
    const unknown = getNumber(stats, ['unknown'], 0) ?? 0;
    const total = assets > 0 ? assets : protectedCount + underprotected + unknown;
    const pct = total > 0 ? Math.round((protectedCount / total) * 100) : 0;
    const passPct = total > 0 ? Math.round((protectedCount / total) * 100) : 0;
    const warnPct = total > 0 ? Math.round((underprotected / total) * 100) : 0;
    const failPct = Math.max(0, 100 - passPct - warnPct);
    return { vendor, pct, passPct, warnPct, failPct, total };
  });
}

export function WafSummaryPanel({ summary }: { summary: DataItem | null }) {
  if (!summary) {
    return (
      <EmptyState
        icon={ShieldHalf}
        title="WAF summary unavailable."
        body="Coverage rollups appear when WAF posture is enabled and connectors publish asset metadata."
      />
    );
  }

  const protectedCount = getNumber(summary, ['protected'], 0) ?? 0;
  const underprotected = getNumber(summary, ['underprotected'], 0) ?? 0;
  const coveragePct = getNumber(summary, ['coverage_pct'], null);
  const connectorsActive = getNumber(summary, ['connectors_active'], 0) ?? 0;
  const connectorsDegraded = getNumber(summary, ['connectors_degraded'], 0) ?? 0;
  const connectorsDisabled = getNumber(summary, ['connectors_disabled'], 0) ?? 0;
  const vendors = vendorRows(summary);
  const emptyReason = getString(summary, ['meta', 'empty_reason'], '');

  if (emptyReason && protectedCount === 0 && underprotected === 0 && vendors.length === 0) {
    return (
      <EmptyState
        icon={ShieldHalf}
        title="No WAF assets in scope."
        body={emptyReason}
        actionLabel="Open target groups"
        actionHref="#target-groups"
      />
    );
  }

  return (
    <div className="dash-waf-grid">
      <div className="dash-waf-kpis">
        <div className="dw-kpi">
          <div className="dw-label">Protected</div>
          <div className="dw-value">{protectedCount}</div>
          <div className="dw-note">from WAF coverage summary API</div>
        </div>
        <div className="dw-kpi">
          <div className="dw-label">Underprotected</div>
          <div className="dw-value">{underprotected}</div>
          <div className={`dw-note${underprotected > 0 ? ' dw-note--warn' : ''}`}>drift and policy exceptions</div>
        </div>
        <div className="dw-kpi">
          <div className="dw-label">Coverage</div>
          <div className="dw-value">
            {coveragePct ?? '—'}{coveragePct !== null ? <span className="dw-unit">%</span> : null}
          </div>
          <div className="dw-note">weighted by critical target groups</div>
        </div>
        <div className="dw-kpi">
          <div className="dw-label">Connectors</div>
          <div className="dw-value">{connectorsActive}</div>
          <div className="dw-note">
            {connectorsDegraded > 0 || connectorsDisabled > 0
              ? `${connectorsDegraded} degraded · ${connectorsDisabled} disabled`
              : 'healthy'}
          </div>
        </div>
      </div>
      <div className="dash-waf-vendors">
        <div className="dw-vendor-head">Coverage by vendor</div>
        {vendors.length === 0 ? (
          <p className="muted small">No vendor breakdown returned by coverage summary API.</p>
        ) : vendors.map((row) => (
          <div className="dw-vendor-row" key={row.vendor}>
            <div className="dw-vendor-label mono">{row.vendor}</div>
            <div className="dw-vendor-bar" title={`${row.pct}% protected across ${row.total} assets`}>
              {row.passPct > 0 ? <span className="seg pass" style={{ width: `${row.passPct}%` }} /> : null}
              {row.warnPct > 0 ? <span className="seg warn" style={{ width: `${row.warnPct}%` }} /> : null}
              {row.failPct > 0 ? <span className="seg fail" style={{ width: `${row.failPct}%` }} /> : null}
            </div>
            <div className="dw-vendor-pct mono">{row.pct}%</div>
          </div>
        ))}
      </div>
    </div>
  );
}