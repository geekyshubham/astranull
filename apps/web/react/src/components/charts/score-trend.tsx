import type { DataItem } from '../../lib/types';
import { cn, scoreTone } from '../../lib/utils';

type ScoreTrendProps = {
  runs: DataItem[];
  currentScore: number;
  tone?: 'success' | 'warn' | 'danger';
};

const TONE_STROKE = {
  success: 'var(--success)',
  warn: 'var(--warn)',
  danger: 'var(--danger)',
} as const;

/**
 * Real verdict-band values. Each point on the trend reflects a run's actual
 * published verdict classification — never a synthesized/interpolated value.
 */
const VERDICT_BAND: Record<'pass' | 'review' | 'gap', number> = {
  pass: 95,
  review: 60,
  gap: 20,
};

function runVerdictString(run: DataItem): string {
  const direct = run.verdict;
  if (typeof direct === 'string') return direct;
  if (direct && typeof direct === 'object' && !Array.isArray(direct)) {
    const nested = direct as DataItem;
    const value = nested.verdict ?? nested.status;
    if (typeof value === 'string') return value;
  }
  const status = run.status;
  return typeof status === 'string' ? status : '';
}

function classifyRunVerdict(verdict: string): 'pass' | 'review' | 'gap' | null {
  const key = verdict.trim().toLowerCase();
  if (!key || ['pending', 'planned', 'running', 'collecting'].includes(key)) return null;
  if (['pass', 'passed', 'protected', 'edge_protected', 'allowed_as_expected', 'success', 'ok'].includes(key)) {
    return 'pass';
  }
  if (['review', 'warn', 'warning', 'info', 'unknown', 'underprotected', 'inconclusive', 'misplaced_agent'].includes(key)) {
    return 'review';
  }
  if (['gap', 'fail', 'failed', 'danger', 'penetrated', 'bypassable', 'edge_exposed', 'unprotected'].includes(key)) {
    return 'gap';
  }
  return 'review';
}

const TREND_WIDTH = 320;
const TREND_HEIGHT = 120;
const TREND_PADDING = 12;

function trendCoordinates(values: number[]) {
  const maxValue = Math.max(100, ...values, 1);
  return values.map((value, index) => {
    const x = TREND_PADDING + (index * (TREND_WIDTH - TREND_PADDING * 2)) / Math.max(1, values.length - 1);
    const y = TREND_HEIGHT - TREND_PADDING - (value / maxValue) * (TREND_HEIGHT - TREND_PADDING * 2);
    return { x, y };
  });
}

export function ScoreTrend({ runs, currentScore, tone }: ScoreTrendProps) {
  const end = Number.isFinite(currentScore) ? currentScore : 0;

  const points = [...runs]
    .sort((left, right) =>
      String(left.created_at ?? left.id ?? '').localeCompare(String(right.created_at ?? right.id ?? ''))
    )
    .map((run) => ({ run, bucket: classifyRunVerdict(runVerdictString(run)) }))
    .filter((entry): entry is { run: DataItem; bucket: 'pass' | 'review' | 'gap' } => entry.bucket !== null)
    .map((entry) => ({
      value: VERDICT_BAND[entry.bucket],
      label: String(entry.run.id ?? '').slice(-6),
    }));

  const strokeTone = tone ?? scoreTone(end);
  const strokeColor = TONE_STROKE[strokeTone];

  if (points.length === 0) {
    return (
      <div className="score-trend score-trend--empty" role="img" aria-label="Readiness trend unavailable; no verdicted runs yet.">
        <span className="muted score-trend-caption">
          No verdicted runs yet · current {end}
        </span>
      </div>
    );
  }

  const chartValues = points.map((point) => point.value);
  const maxValue = Math.max(100, ...chartValues);
  const coords = trendCoordinates(chartValues);
  const polylinePoints = coords.map(({ x, y }) => `${x},${y}`).join(' ');
  const baselineY = TREND_HEIGHT - TREND_PADDING;
  const areaPoints = `${coords[0].x},${baselineY} ${polylinePoints} ${coords[coords.length - 1].x},${baselineY}`;
  const gridLevels = [0, 50, 100];
  const gridYs = gridLevels.map(
    (level) => TREND_HEIGHT - TREND_PADDING - (level / maxValue) * (TREND_HEIGHT - TREND_PADDING * 2)
  );

  const ariaLabel = `Readiness verdict trend across ${points.length} verdicted run${points.length === 1 ? '' : 's'}; current score ${end}`;

  return (
    <div className="score-trend" role="img" aria-label={ariaLabel}>
      <svg className="score-trend-svg" viewBox={`0 0 ${TREND_WIDTH} ${TREND_HEIGHT}`} width="100%" preserveAspectRatio="xMidYMid meet">
        {gridYs.map((gy, index) => (
          <line key={gridLevels[index]} className="score-trend-grid" x1={TREND_PADDING} x2={TREND_WIDTH - TREND_PADDING} y1={gy} y2={gy} />
        ))}
        <polygon className={cn('score-trend-area', `score-trend-stroke--${strokeTone}`)} points={areaPoints} />
        <polyline
          className={cn('score-trend-line', `score-trend-stroke--${strokeTone}`)}
          points={polylinePoints}
          fill="none"
          stroke={strokeColor}
          strokeWidth={2}
          vectorEffect="non-scaling-stroke"
        />
        {coords.map(({ x, y }, index) => (
          <circle
            key={`${points[index].label}-${index}`}
            className={cn('score-trend-point', `score-trend-stroke--${strokeTone}`)}
            cx={x}
            cy={y}
            r={3}
            fill={strokeColor}
          />
        ))}
      </svg>
      <span className="muted score-trend-caption">
        {points.length} verdicted run{points.length === 1 ? '' : 's'} · current {end}
      </span>
    </div>
  );
}