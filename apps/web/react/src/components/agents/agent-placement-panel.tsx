import { useMemo } from 'react';
import { ListChecks } from 'lucide-react';
import { Badge } from '../ui/badge';
import { Button } from '../ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card';
import { VerifyChip } from '../../lib/verify-chip';
import { ONBOARDING_PLACEMENT_TEST_CHECK_ID } from '../../lib/onboarding';
import { formatPlacementStatus, placementStatusHint } from '../../lib/agent-helpers';
import type { DataItem } from '../../lib/types';
import { formatDate } from '../../lib/utils';

function getString(item: DataItem | null | undefined, keys: string[], fallback = '—') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

const PLACEMENT_GATES = [
  'Bootstrap token exchanged for agent credential',
  'Protected-path canary observed on declared target group',
  'Probe and agent observations correlated under custody'
] as const;

export function AgentPlacementPanel({
  agent,
  agentId,
  targetGroupId,
  runs,
  placementReview,
  onRunPlacement,
  running,
  busy
}: {
  agent: DataItem;
  agentId: string;
  targetGroupId: string;
  runs: DataItem[];
  placementReview: DataItem | null;
  onRunPlacement: () => void;
  running?: boolean;
  busy?: boolean;
}) {
  const placementRun = useMemo(() => runs
    .filter((run) => getString(run, ['check_id']) === ONBOARDING_PLACEMENT_TEST_CHECK_ID)
    .sort((a, b) => String(b.started_at ?? b.created_at ?? '').localeCompare(String(a.started_at ?? a.created_at ?? '')))[0] ?? null, [runs]);

  const verdict = getString(placementRun, ['verdict'], getString(placementRun, ['status'], 'pending'));
  const pass = ['pass', 'verdicted'].includes(verdict.toLowerCase()) || getString(placementRun, ['verdict']) === 'pass';
  const provenance = placementRun
    ? `Placement test ${getString(placementRun, ['id'])} · verdict ${verdict} from test-runs API.`
    : 'No placement test run recorded for this agent scope.';

  return (
    <Card>
      <CardHeader>
        <div>
          <CardTitle>Placement test</CardTitle>
          <CardDescription>Bounded protected-path canary. Metadata-only signal under custody.</CardDescription>
        </div>
        <div className="row-actions">
          {pass ? (
            <span className="verify-chip is-verified" title={provenance}>
              <span className="vc-dot" aria-hidden="true" />
              last run · pass
            </span>
          ) : (
            <VerifyChip state="pending" provenance={provenance} />
          )}
          <Button size="sm" loading={running} disabled={busy || !targetGroupId} onClick={onRunPlacement}>Run placement test</Button>
        </div>
      </CardHeader>
      <CardContent className="stack-tight">
        <div className="pt-grid">
          <div className="pt-cell">
            <div className="pt-label">Last test</div>
            <div className="pt-value mono">{placementRun ? formatDate(placementRun.started_at ?? placementRun.created_at) : '—'}</div>
          </div>
          <div className="pt-cell">
            <div className="pt-label">Duration</div>
            <div className="pt-value mono">{getString(placementRun, ['duration_ms', 'duration'], '—')}</div>
          </div>
          <div className="pt-cell">
            <div className="pt-label">Signal</div>
            <div className="pt-value mono">{getString(placementReview, ['observation_mode'], getString(agent, ['placement_type'], '—'))}</div>
          </div>
          <div className="pt-cell">
            <div className="pt-label">Evidence</div>
            <div className="pt-value mono">{placementRun ? getString(placementRun, ['id']) : '—'}</div>
          </div>
        </div>
        <ul className="placement-gates">
          {PLACEMENT_GATES.map((gate) => (
            <li key={gate}>
              <ListChecks size={14} aria-hidden="true" />
              <span>{gate}</span>
              <Badge tone={pass ? 'success' : 'muted'}>{pass ? 'pass' : 'pending'}</Badge>
            </li>
          ))}
        </ul>
        {placementReview ? (
          <p className="muted" title={placementStatusHint(getString(placementReview, ['status'])) || undefined}>
            Placement review: {formatPlacementStatus(getString(placementReview, ['status']))} · {getString(placementReview, ['summary'], '—')}
          </p>
        ) : null}
      </CardContent>
    </Card>
  );
}