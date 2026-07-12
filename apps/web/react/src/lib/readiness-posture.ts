import type { DataItem, ReadinessPostureSegment, StatePayload } from './types';

function getString(item: DataItem | null | undefined, keys: string[], fallback = '') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

function classifyRunVerdict(verdict: string): 'pass' | 'review' | 'gap' | null {
  const key = verdict.trim().toLowerCase();
  if (!key || key === 'pending' || key === 'planned' || key === 'running') return null;
  if (['pass', 'passed', 'protected', 'success', 'ok'].includes(key)) return 'pass';
  if (['review', 'warn', 'warning', 'info', 'unknown', 'underprotected'].includes(key)) return 'review';
  if (['gap', 'fail', 'failed', 'danger', 'penetrated', 'bypassable', 'unprotected'].includes(key)) return 'gap';
  return 'review';
}

export function resolveReadinessPostureSegments(
  state: StatePayload | null,
  runs: DataItem[],
  checks: DataItem[]
): { segments: ReadinessPostureSegment[]; total: number; score: number | null; delta: number | null } {
  const posture = state?.readiness?.posture;
  const score = typeof state?.readiness?.score === 'number' ? state.readiness.score : null;
  const delta = typeof state?.readiness?.delta === 'number' ? state.readiness.delta : null;

  if (posture && typeof posture === 'object') {
    const pass = Number(posture.pass ?? 0);
    const review = Number(posture.review ?? 0);
    const gap = Number(posture.gap ?? 0);
    const total = Number(posture.total ?? pass + review + gap);
    if (total > 0) {
      return {
        score,
        delta,
        total,
        segments: buildSegments(pass, review, gap, total)
      };
    }
  }

  const latestByCheck = new Map<string, string>();
  for (const run of runs) {
    const checkId = getString(run, ['check_id'], '');
    if (!checkId) continue;
    const status = getString(run, ['status'], '');
    if (!['completed', 'verdicted'].includes(status)) continue;
    const verdict = getString(run, ['verdict', 'verdict'], getNestedVerdict(run));
    if (!verdict) continue;
    const existingAt = String(run.updated_at ?? run.completed_at ?? run.created_at ?? '');
    const prev = latestByCheck.get(checkId);
    const prevRun = runs.find((item) => getString(item, ['check_id']) === checkId && getString(item, ['verdict', 'verdict'], getNestedVerdict(item)) === prev);
    const prevAt = prevRun ? String(prevRun.updated_at ?? prevRun.completed_at ?? prevRun.created_at ?? '') : '';
    if (!prev || existingAt.localeCompare(prevAt) >= 0) {
      latestByCheck.set(checkId, verdict);
    }
  }

  let pass = 0;
  let review = 0;
  let gap = 0;
  for (const verdict of latestByCheck.values()) {
    const bucket = classifyRunVerdict(verdict);
    if (bucket === 'pass') pass += 1;
    else if (bucket === 'review') review += 1;
    else if (bucket === 'gap') gap += 1;
  }

  const total = pass + review + gap > 0 ? pass + review + gap : checks.length;
  if (pass + review + gap === 0 && checks.length > 0) {
    return {
      score,
      delta,
      total: checks.length,
      segments: [
        { key: 'pass', label: 'Pass', count: 0, pct: 0 },
        { key: 'review', label: 'Review', count: 0, pct: 0 },
        { key: 'gap', label: 'Gap', count: 0, pct: 0 }
      ]
    };
  }

  return {
    score,
    delta,
    total,
    segments: buildSegments(pass, review, gap, total)
  };
}

function getNestedVerdict(run: DataItem) {
  const verdict = run.verdict;
  if (!verdict || typeof verdict !== 'object' || Array.isArray(verdict)) return '';
  return getString(verdict as DataItem, ['verdict', 'status'], '');
}

function buildSegments(pass: number, review: number, gap: number, total: number): ReadinessPostureSegment[] {
  const safeTotal = total > 0 ? total : 1;
  return [
    { key: 'pass', label: 'Pass', count: pass, pct: Math.round((pass / safeTotal) * 100) },
    { key: 'review', label: 'Review', count: review, pct: Math.round((review / safeTotal) * 100) },
    { key: 'gap', label: 'Gap', count: gap, pct: Math.round((gap / safeTotal) * 100) }
  ];
}

function scoreRingTone(score: number): 'pass' | 'review' | 'gap' {
  if (score >= 80) return 'pass';
  if (score >= 55) return 'review';
  return 'gap';
}

export function buildConicGradient(segments: ReadinessPostureSegment[], score?: number | null) {
  const colorByKey: Record<string, string> = {
    pass: 'var(--success)',
    review: 'var(--warn)',
    gap: 'var(--danger)'
  };
  const track = 'color-mix(in oklab, var(--bg), var(--fg) 6%)';

  // Published readiness score drives ring fill + tone; segment legend stays separate.
  if (typeof score === 'number' && Number.isFinite(score)) {
    const fill = Math.min(100, Math.max(0, Math.round(score)));
    const tone = scoreRingTone(fill);
    return `conic-gradient(from -90deg, ${colorByKey[tone]} 0% ${fill}%, ${track} ${fill}% 100%)`;
  }

  const gapSize = segments.reduce((sum, segment) => sum + segment.count, 0) > 0 ? 0.6 : 0;
  let cursor = 0;
  const stops: string[] = [];
  for (const segment of segments) {
    if (segment.count <= 0) continue;
    const end = cursor + segment.pct;
    stops.push(`${colorByKey[segment.key]} ${cursor}% ${end}%`);
    cursor = end;
    if (gapSize > 0 && cursor < 100) {
      const gapEnd = Math.min(100, cursor + gapSize);
      stops.push(`color-mix(in oklab, var(--bg), var(--fg) 6%) ${cursor}% ${gapEnd}%`);
      cursor = gapEnd;
    }
  }
  if (stops.length === 0) {
    return `conic-gradient(from -90deg, ${track} 0% 100%)`;
  }
  return `conic-gradient(from -90deg, ${stops.join(', ')})`;
}