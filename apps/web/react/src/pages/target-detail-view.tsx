import { useEffect, useState } from 'react';
import { Activity, FileCheck2, ShieldHalf, Target, TriangleAlert } from 'lucide-react';
import { populateTargetDetail } from '../lib/target-detail';
import { VerifyChip, resolveTargetVerificationProvenance } from '../lib/verify-chip';
import { buildDetailHref } from '../lib/route-params';
import type { DataItem, PortalConfig, Session } from '../lib/types';
import { formatDate } from '../lib/utils';
import { AnchorButton, Button } from '../components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { emptyStateFromApi, readMetaAction } from '../lib/empty-from-api';
import { DataTable, type TableColumn } from '../components/ui/table';
import { Badge } from '../components/ui/badge';
import { requestJson } from '../lib/api';

function getString(item: DataItem | null | undefined, keys: string[], fallback = '—') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

function DetailEntityLink({ route, id, label }: { route: 'target-group-detail' | 'finding-detail' | 'run-detail'; id: string; label?: string }) {
  if (!id) return <strong>—</strong>;
  return <AnchorButton size="sm" variant="ghost" href={buildDetailHref(route, id)}>{label ?? id}</AnchorButton>;
}

export function TargetDetailView({
  entityId,
  config,
  session,
  onRefresh
}: {
  entityId: string;
  config: PortalConfig;
  session: Session;
  onRefresh: () => Promise<void>;
}) {
  const [detail, setDetail] = useState<Awaited<ReturnType<typeof populateTargetDetail>> | null>(null);
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    let cancelled = false;
    setDetail((current) => ({ ...(current ?? {
      target: null,
      verification: null,
      waf_posture: null,
      checks_applied: [],
      runs_recent: [],
      findings: [],
      loa: null,
      counts: null,
      loading: true
    }), loading: true }));
    populateTargetDetail(config, session, entityId).then((payload) => {
      if (!cancelled) setDetail(payload);
    });
    return () => { cancelled = true; };
  }, [config, session, entityId]);

  const target = detail?.target ?? null;
  const verification = detail?.verification ?? null;
  const wafPosture = detail?.waf_posture ?? null;
  const eligibility = getString(target, ['eligibility'], 'unknown');
  const canRun = !eligibility.startsWith('not');
  const verificationState = getString(verification, ['state'], getString(target, ['verification_state'], 'unverified'));
  const provenance = resolveTargetVerificationProvenance(target, verification);
  const kind = getString(target, ['kind'], 'unknown');
  const showWaf = kind !== 'ip' && verificationState !== 'unverified' && wafPosture;

  async function runBoundedChecks() {
    if (!canRun || !target) return;
    setBusy('run-checks');
    setError('');
    try {
      const targetGroupId = getString(target, ['target_group_id'], '');
      const checkId = getString(detail?.checks_applied?.[0] ?? {}, ['check_id'], '');
      await requestJson(config, session, '/v1/test-runs', {
        method: 'POST',
        body: { target_group_id: targetGroupId, target_id: entityId, check_id: checkId }
      });
      await onRefresh();
      const refreshed = await populateTargetDetail(config, session, entityId);
      setDetail(refreshed);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to start bounded test run.';
      setError(message);
    } finally {
      setBusy('');
    }
  }

  if (!detail || detail.loading) {
    return (
      <div className="content stack-tight" aria-busy="true" aria-live="polite">
        <div className="skeleton skeleton-row" />
        <div className="skeleton skeleton-row" />
        <div className="skeleton skeleton-row" />
      </div>
    );
  }

  if (!target) {
    const emptyMeta = detail.meta && typeof detail.meta === 'object'
      ? detail.meta as DataItem
      : detail.error
        ? { empty_reason: detail.error }
        : null;
    return (
      <div className="content">
        {emptyStateFromApi({
          icon: Target,
          meta: emptyMeta,
          actionHref: readMetaAction(emptyMeta, 'empty_action_href'),
          actionLabel: readMetaAction(emptyMeta, 'empty_action_label')
        })}
      </div>
    );
  }

  const runColumns: TableColumn<DataItem>[] = [
    { key: 'run', label: 'Run', render: (item) => <DetailEntityLink route="run-detail" id={getString(item, ['run_id', 'id'], '')} /> },
    { key: 'policy', label: 'Policy', render: (item) => getString(item, ['policy_id'], '—') },
    { key: 'verdict', label: 'Verdict', render: (item) => <Badge tone="info" title={`Verdict ${getString(item, ['verdict'], 'pending')} from runs API`}>{getString(item, ['verdict'], 'pending')}</Badge> },
    { key: 'started', label: 'Started', render: (item) => formatDate(item.started_at ?? item.created_at) },
    { key: 'agent', label: 'Agent', render: (item) => getString(item, ['agent_id'], '—') }
  ];

  const findingColumns: TableColumn<DataItem>[] = [
    { key: 'id', label: 'Finding', render: (item) => <DetailEntityLink route="finding-detail" id={getString(item, ['id'], '')} label={getString(item, ['title'], getString(item, ['id']))} /> },
    { key: 'severity', label: 'Severity', render: (item) => getString(item, ['severity'], 'unknown') },
    { key: 'state', label: 'State', render: (item) => getString(item, ['state', 'status'], 'open') },
    { key: 'owner', label: 'Owner', render: (item) => getString(item, ['owner_group', 'assignee'], 'unassigned') }
  ];

  const checkColumns: TableColumn<DataItem>[] = [
    { key: 'check', label: 'Check', render: (item) => getString(item, ['check_id'], '—') },
    { key: 'cadence', label: 'Cadence', render: (item) => getString(item, ['cadence'], 'manual') },
    { key: 'verdict', label: 'Last verdict', render: (item) => getString(item, ['last_verdict'], '—') },
    { key: 'ran', label: 'Last ran', render: (item) => formatDate(item.last_ran_at) }
  ];

  return (
    <div className="content stack-tight">
      {error ? <p className="banner banner-error" role="alert">{error}</p> : null}
      <div className="page-head">
        <div>
          <p className="eyebrow">Declared target</p>
          <h2 className="page-title mono">{entityId}</h2>
          <p className="muted">{getString(target, ['value'])} · {kind}</p>
        </div>
        <div className="row-actions">
          <VerifyChip state={verificationState} provenance={provenance} />
          <Badge tone={canRun ? 'success' : 'warn'} title={`Eligibility ${eligibility} from target API`}>{eligibility}</Badge>
          <Button
            className={`btn btn-primary btn-sm${canRun ? '' : ' is-locked'}`}
            disabled={!canRun || busy !== ''}
            title={canRun ? 'Start bounded checks for this target' : 'Verify to enable testing'}
            loading={busy === 'run-checks'}
            onClick={() => void runBoundedChecks()}
          >
            Run bounded checks
          </Button>
        </div>
      </div>

      <Card>
        <CardHeader><CardTitle>Ownership</CardTitle></CardHeader>
        <CardContent className="kv-list">
          <div><span>Target group</span><DetailEntityLink route="target-group-detail" id={getString(target, ['target_group_id'], '')} /></div>
          <div><span>Environment</span><strong>{getString(target, ['environment_id'], 'inherited')}</strong></div>
          <div><span>LOA</span><strong title="LOA state inherited from target group API">{getString(detail.loa, ['state'], getString(detail.loa, ['status'], 'inherited'))}</strong></div>
          {kind === 'fqdn' ? <div><span>DNS TXT</span><VerifyChip state={verificationState.includes('dns') ? 'dns_verified' : verificationState} provenance={provenance} /></div> : null}
          <div><span>Agent binding</span><strong>{getString(target?.agent_binding as DataItem | undefined, ['agent_id'], 'none')}</strong></div>
        </CardContent>
      </Card>

      {showWaf ? (
        <Card>
          <CardHeader><CardTitle>WAF posture</CardTitle><CardDescription>Per-target WAF asset from hydrator API.</CardDescription></CardHeader>
          <CardContent>
            <div className="metric-grid four">
              <div className="kpi"><div className="kpi-label">Posture</div><div className="kpi-value">{getString(wafPosture, ['posture', 'status'], '—')}</div></div>
              <div className="kpi"><div className="kpi-label">Drift</div><div className="kpi-value">{getString(wafPosture, ['drift_reason'], 'none')}</div></div>
              <div className="kpi"><div className="kpi-label">Validation</div><div className="kpi-value">{getString(wafPosture?.validation as DataItem | undefined, ['verdict'], '—')}</div></div>
              <div className="kpi"><div className="kpi-label">Connector</div><div className="kpi-value">{getString(wafPosture?.connector as DataItem | undefined, ['state'], '—')}</div></div>
              <div className="kpi"><div className="kpi-label">Fingerprint</div><div className="kpi-value">{getString(wafPosture?.fingerprint as DataItem | undefined, ['signature'], '—')}</div></div>
              <div className="kpi"><div className="kpi-label">Marker rules</div><div className="kpi-value">{String(wafPosture?.marker_rules ?? '—')}</div></div>
              <div className="kpi"><div className="kpi-label">Origin bypass</div><div className="kpi-value">{getString(wafPosture?.origin_bypass as DataItem | undefined, ['state'], '—')}</div></div>
            </div>
            <p className="muted">{getString(wafPosture, ['notes'], getString(wafPosture, ['summary'], 'No WAF notes returned.'))}</p>
            <pre className="codeblock">{JSON.stringify({
              asset_id: getString(wafPosture, ['asset_id'], ''),
              vendor: getString(wafPosture, ['vendor'], ''),
              target: getString(target, ['value'], ''),
              target_group: getString(target, ['target_group_id'], ''),
              posture: getString(wafPosture, ['posture'], ''),
              drift_reason: getString(wafPosture, ['drift_reason'], ''),
              validation: wafPosture?.validation ?? null,
              connector: wafPosture?.connector ?? null
            }, null, 2)}</pre>
          </CardContent>
        </Card>
      ) : null}

      <Card>
        <CardHeader><CardTitle>Checks applied</CardTitle></CardHeader>
        <CardContent>
          <DataTable columns={checkColumns} items={detail.checks_applied} empty={emptyStateFromApi({ icon: FileCheck2, meta: detail.sectionMeta?.checks })} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle>Recent runs</CardTitle></CardHeader>
        <CardContent>
          <DataTable columns={runColumns} items={detail.runs_recent} empty={emptyStateFromApi({ icon: Activity, meta: detail.sectionMeta?.runs, actionHref: '#runs', actionLabel: 'Open test runs' })} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle>Findings on this target</CardTitle></CardHeader>
        <CardContent>
          <DataTable columns={findingColumns} items={detail.findings} empty={emptyStateFromApi({ icon: TriangleAlert, meta: detail.sectionMeta?.findings, actionHref: '#findings', actionLabel: 'Open findings' })} />
        </CardContent>
      </Card>
    </div>
  );
}