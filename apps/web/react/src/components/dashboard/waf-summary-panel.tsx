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

function WafKpi({
  label,
  value,
  note,
  noteWarn = false,
  unit,
}: {
  label: string;
  value: string | number;
  note: string;
  noteWarn?: boolean;
  unit?: string;
}) {
  return (
    <div className="dw-kpi">
      <div className="dw-label">{label}</div>
      <div className="dw-value">
        {value}
        {unit ? <span className="dw-unit">{unit}</span> : null}
      </div>
      <div
        className={`dw-note${noteWarn ? ' dw-note--warn' : ''}`}
        style={noteWarn ? { color: 'var(--warn)' } : undefined}
      >
        {note}
      </div>
    </div>
  );
}

function VendorCoverageRow({
  vendor,
  pct,
  passPct,
  warnPct,
  failPct,
  total,
}: {
  vendor: string;
  pct: number;
  passPct: number;
  warnPct: number;
  failPct: number;
  total: number;
}) {
  return (
    <div className="dw-vendor-row">
      <div className="dw-vendor-label mono">{vendor}</div>
      <div
        className="dw-vendor-bar"
        role="img"
        aria-label={`${vendor}: ${pct}% protected across ${total} assets`}
        title={`${pct}% protected across ${total} assets`}
      >
        {passPct > 0 ? <span className="seg pass" style={{ width: `${passPct}%` }} /> : null}
        {warnPct > 0 ? <span className="seg warn" style={{ width: `${warnPct}%` }} /> : null}
        {failPct > 0 ? <span className="seg fail" style={{ width: `${failPct}%` }} /> : null}
      </div>
      <div className="dw-vendor-pct mono">{pct}%</div>
    </div>
  );
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

  const connectorNote = connectorsDegraded > 0 || connectorsDisabled > 0
    ? `${connectorsDegraded} degraded · ${connectorsDisabled} disabled`
    : 'healthy';

  return (
    <div className={`dash-waf-grid${vendors.length === 0 ? ' dash-waf-grid--solo' : ''}`}>
      <div className="dash-waf-kpis">
        <WafKpi label="Protected" value={protectedCount} note="from WAF coverage summary API" />
        <WafKpi
          label="Underprotected"
          value={underprotected}
          note="drift and policy exceptions"
          noteWarn={underprotected > 0}
        />
        <WafKpi
          label="Coverage"
          value={coveragePct ?? '—'}
          unit={coveragePct !== null ? '%' : undefined}
          note="weighted by critical target groups"
        />
        <WafKpi label="Connectors" value={connectorsActive} note={connectorNote} />
      </div>
      {vendors.length > 0 ? (
        <div className="dash-waf-vendors">
          <div className="dw-vendor-head">Coverage by vendor</div>
          {vendors.map((row) => (
            <VendorCoverageRow key={row.vendor} {...row} />
          ))}
        </div>
      ) : (
        <p className="dash-waf-vendors--empty">
          Vendor coverage breakdown appears when connectors publish per-vendor asset metadata.
        </p>
      )}
    </div>
  );
}