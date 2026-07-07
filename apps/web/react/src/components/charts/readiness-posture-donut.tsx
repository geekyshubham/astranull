import { buildConicGradient, resolveReadinessPostureSegments } from '../../lib/readiness-posture';
import type { DataItem, StatePayload } from '../../lib/types';
import { EmptyState } from '../ui/empty-state';
import { Activity } from 'lucide-react';

const SEGMENT_COLORS: Record<string, string> = {
  pass: 'var(--success)',
  review: 'var(--warn)',
  gap: 'var(--danger)'
};

export function ReadinessPostureDonut({
  state,
  runs,
  checks
}: {
  state: StatePayload | null;
  runs: DataItem[];
  checks: DataItem[];
}) {
  const { segments, total, score, delta } = resolveReadinessPostureSegments(state, runs, checks);
  const gradient = buildConicGradient(segments);
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
          <div className="gauge-score-cap">Readiness</div>
          <div className="gauge-score">
            <span className="gauge-score-value">{score ?? '—'}</span>
            {score !== null ? <span className="gauge-score-scale">/100</span> : null}
          </div>
          {delta !== null ? (
            <div className="gauge-score-delta" title="Change vs previous validation cycle from readiness API">
              <span>{delta > 0 ? '+' : ''}{delta}</span>
              <span className="gauge-score-delta-cap">vs last cycle</span>
            </div>
          ) : null}
        </div>
      </div>
      <div className="gauge-side">
        <div className="gauge-legend">
          {segments.map((segment) => (
            <div
              key={segment.key}
              className="legend-row"
              title={`${segment.label} · ${segment.count} checks · ${segment.pct}%`}
            >
              <span className="ld" style={{ background: SEGMENT_COLORS[segment.key] }} />
              <span className="lg-label">{segment.label}</span>
              <span className="lg-bar-wrap">
                <span className="lg-bar" style={{ width: `${segment.pct}%`, background: SEGMENT_COLORS[segment.key] }} />
              </span>
              <span className="lg-pct">{segment.pct}%</span>
              <b>{segment.count}</b>
            </div>
          ))}
        </div>
        <p className="muted small">{total} checks correlated · this cycle</p>
      </div>
    </div>
  );
}