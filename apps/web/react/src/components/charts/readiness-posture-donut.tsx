import { buildConicGradient, resolveReadinessPostureSegments } from '../../lib/readiness-posture';
import type { DataItem, ReadinessPostureSegment, StatePayload } from '../../lib/types';
import { EmptyState } from '../ui/empty-state';
import { Activity } from 'lucide-react';

const SEGMENT_COLORS: Record<string, string> = {
  pass: 'var(--success)',
  review: 'var(--warn)',
  gap: 'var(--danger)',
};

function PostureLegendRow({ segment, total }: { segment: ReadinessPostureSegment; total: number }) {
  const swatch = SEGMENT_COLORS[segment.key];
  const title = `${segment.label} · ${segment.count} of ${total} checks · ${segment.pct}%`;
  // Prototype simplification: the Review row surfaces the count/total form (e.g. "5/50");
  // Pass and Gap keep the percentage form. All counts stay derived from the resolver.
  const value = segment.key === 'review' ? `${segment.count}/${total}` : `${segment.pct}%`;

  return (
    <div className="legend-row" title={title}>
      <span className="ld" style={{ background: swatch }} aria-hidden="true" />
      <span className="lg-label">{segment.label}</span>
      <span className="lg-bar-wrap" style={{ background: 'color-mix(in oklab, var(--fg), transparent 92%)' }}>
        <span className="lg-bar" style={{ width: `${segment.pct}%`, background: swatch }} />
      </span>
      <span className="lg-pct">{value}</span>
    </div>
  );
}

export function ReadinessPostureDonut({
  state,
  runs,
  checks,
}: {
  state: StatePayload | null;
  runs: DataItem[];
  checks: DataItem[];
}) {
  const { segments, total, score } = resolveReadinessPostureSegments(state, runs, checks);
  const correlatedCount = segments.reduce((sum, segment) => sum + segment.count, 0);
  const gradient = buildConicGradient(segments, score);
  const ariaLabel = segments
    .filter((segment) => segment.count > 0)
    .map((segment) => `${segment.label} ${segment.count} checks ${segment.pct} percent`)
    .join('. ');

  if (total <= 0 && score === null) {
    return (
      <EmptyState
        icon={Activity}
        title="Readiness posture unavailable."
        body="Posture segments appear after checks are correlated to validation verdicts."
      />
    );
  }

  return (
    <div className="dash-gauge-block">
      <div
        className="gauge gauge--segmented"
        role="img"
        aria-label={ariaLabel || 'Readiness posture donut'}
        style={{ ['--gauge-gradient' as string]: gradient }}
      >
        <div className="gauge-hole">
          <div className="gauge-score">
            <span className="gauge-score-value">{score ?? '—'}</span>
            {score !== null ? <span className="gauge-score-scale">/100</span> : null}
          </div>
        </div>
      </div>
      <div className="gauge-side">
        <div className="gauge-legend">
          {segments.map((segment) => (
            <PostureLegendRow key={segment.key} segment={segment} total={total} />
          ))}
        </div>
        <p className="muted small">{correlatedCount} checks correlated · this cycle</p>
      </div>
    </div>
  );
}