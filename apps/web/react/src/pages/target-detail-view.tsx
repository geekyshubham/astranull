import { useEffect, useState } from 'react';
import { Activity, FileCheck2, ShieldCheck, Target, TriangleAlert } from 'lucide-react';
import { populateTargetDetail } from '../lib/target-detail';
import { VerifyChip, resolveTargetVerificationProvenance } from '../lib/verify-chip';
import { buildDetailHref } from '../lib/route-params';
import type { DataItem, PortalConfig, Session } from '../lib/types';
import { formatDate } from '../lib/utils';
import { AnchorButton, Button } from '../components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { emptyStateFromApi, readMetaAction } from '../lib/empty-from-api';
import { DataTable, type TableColumn } from '../components/ui/table';
import { Badge, type BadgeProps } from '../components/ui/badge';
import { requestJson } from '../lib/api';
import { MetricCard } from './page-components';

type StatTone = NonNullable<BadgeProps['tone']>;

function verificationTone(state: string): StatTone {
  const key = state.trim().toLowerCase();
  if (['agent_verified', 'dns_verified', 'user_confirmed', 'verified'].includes(key)) return 'success';
  if (key === 'unverified') return 'warn';
  return 'muted';
}

function formatTargetLabel(value: string, fallback = '—') {
  const trimmed = value.trim();
  if (!trimmed) return fallback;
  const label = trimmed.replace(/_/g, ' ');
  return label.charAt(0).toUpperCase() + label.slice(1);
}

function getString(item: DataItem | null | undefined, keys: string[], fallback = '—') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

function formatRunDuration(run: DataItem): string {
  const start = Date.parse(String(run.started_at ?? run.created_at ?? ''));
  const end = Date.parse(String(run.completed_at ?? run.finalized_at ?? run.updated_at ?? ''));
  if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start) return '—';
  const totalSeconds = Math.round((end - start) / 1000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  if (minutes <= 0) return `${seconds}s`;
  return `${minutes}m ${String(seconds).padStart(2, '0')}s`;
}

function DetailEntityLink({ route, id, label }: { route: 'target-group-detail' | 'finding-detail' | 'run-detail' | 'target-detail'; id: string; label?: string }) {
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
  // §4.5 header: Run bounded checks is gated when eligibility is not/unverified.
  const canRun = !eligibility.startsWith('not') && !eligibility.startsWith('unverified');
  const verificationState = getString(verification, ['state'], getString(target, ['verification_state'], 'unverified'));
  const provenance = resolveTargetVerificationProvenance(target, verification);
  const kind = getString(target, ['kind'], 'unknown');
  // §4.5 WAF panel visibility: hidden for IP targets and unverified targets that do not yet
  // map to a WAF asset. Shown when a WAF asset exists, or the target is a non-IP target whose
  // verification state is not `unverified`.
  const showWaf = Boolean(wafPosture) || (kind !== 'ip' && verificationState !== 'unverified');

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

  // Header renders in every state (loading / empty / loaded) so the h1 target id is always present.
  function renderHeader() {
    const targetGroupId = getString(target, ['target_group_id'], '');
    const hasTarget = Boolean(target);
    return (
      <div className="page-head">
        <div>
          <p className="eyebrow">Declared scope</p>
          <h1 className="page-title mono">{entityId}</h1>
          <p className="muted">{hasTarget ? `${getString(target, ['value'])} · ${kind}` : 'Per-target validation surface.'}</p>
          {hasTarget ? (
            <div className="detail-status-line">
              <VerifyChip state={verificationState} provenance={provenance} />
              <span className="detail-status-sep" aria-hidden="true">·</span>
              <Badge tone={canRun ? 'success' : 'warn'} title={`Eligibility ${eligibility} from target API`}>{formatTargetLabel(eligibility)}</Badge>
            </div>
          ) : null}
        </div>
        <div className="row-actions">
          {targetGroupId ? (
            <AnchorButton size="sm" variant="secondary" href={buildDetailHref('target-group-detail', targetGroupId)}>← Target group</AnchorButton>
          ) : null}
          {hasTarget ? (
            <Button
              size="sm"
              className={canRun ? undefined : 'is-locked'}
              disabled={!canRun || busy !== ''}
              title={canRun ? 'Start bounded checks for this target' : 'Verify to enable testing'}
              loading={busy === 'run-checks'}
              onClick={() => void runBoundedChecks()}
            >
              Run bounded checks
            </Button>
          ) : null}
        </div>
      </div>
    );
  }

  if (!detail || detail.loading) {
    return (
      <div className="content stack-tight">
        {renderHeader()}
        <div className="stack-tight" aria-busy="true" aria-live="polite">
          <div className="skeleton skeleton-row" />
          <div className="skeleton skeleton-row" />
          <div className="skeleton skeleton-row" />
        </div>
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
      <div className="content stack-tight">
        {renderHeader()}
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
    { key: 'policy', label: 'Policy', render: (item) => getString(item, ['policy_id', 'test_policy_id'], '—') },
    { key: 'verdict', label: 'Verdict', render: (item) => <Badge tone="info" title={`Verdict ${getString(item, ['verdict', 'status'], 'pending')} from runs API`}>{getString(item, ['verdict', 'status'], 'pending')}</Badge> },
    { key: 'agent', label: 'Agent', render: (item) => <span className="mono">{getString(item, ['agent_id'], '—')}</span> },
    { key: 'duration', label: 'Duration', render: (item) => <span className="mono">{formatRunDuration(item)}</span> },
    { key: 'started', label: 'Started', render: (item) => formatDate(item.started_at ?? item.created_at) }
  ];

  const findingColumns: TableColumn<DataItem>[] = [
    { key: 'severity', label: 'Severity', render: (item) => getString(item, ['severity'], 'unknown') },
    { key: 'id', label: 'Finding', render: (item) => <DetailEntityLink route="finding-detail" id={getString(item, ['id'], '')} label={getString(item, ['title'], getString(item, ['id']))} /> },
    { key: 'target', label: 'Target', render: (item) => <DetailEntityLink route="target-detail" id={getString(item, ['target_id'], entityId)} label={getString(item, ['target_value', 'target'], getString(target, ['value'], getString(item, ['target_id'], entityId)))} /> },
    { key: 'state', label: 'State', render: (item) => getString(item, ['state', 'status'], 'open') },
    { key: 'opened', label: 'Opened', render: (item) => formatDate(item.opened_at ?? item.created_at) },
    { key: 'owner', label: 'Owner', render: (item) => getString(item, ['owner_group', 'assignee'], 'unassigned') }
  ];

  const checkColumns: TableColumn<DataItem>[] = [
    { key: 'check', label: 'Check', render: (item) => getString(item, ['check_id'], '—') },
    { key: 'cadence', label: 'Cadence', render: (item) => getString(item, ['cadence'], 'manual') },
    { key: 'verdict', label: 'Last verdict', render: (item) => getString(item, ['last_verdict'], '—') },
    { key: 'ran', label: 'Last ran', render: (item) => formatDate(item.last_ran_at) }
  ];

  const loa = detail.loa;
  const loaState = getString(loa, ['state', 'status'], 'inherited');
  const loaSigned = ['signed', 'active', 'valid'].includes(loaState.trim().toLowerCase());
  const loaCustody = getString(loa, ['custody_digest_sha256', 'custody_digest', 'digest'], '');
  const loaSigner = getString(loa, ['signer_name', 'signed_by'], '');
  const loaSignedAt = loa?.signed_at ?? loa?.updated_at;
  const agentBinding = target.agent_binding && typeof target.agent_binding === 'object' && !Array.isArray(target.agent_binding)
    ? target.agent_binding as DataItem
    : null;
  const agentBindingId = getString(agentBinding, ['agent_id'], 'none');
  const agentBindingAt = agentBinding?.bound_at ?? agentBinding?.last_heartbeat_at ?? agentBinding?.updated_at;
  const dnsCheckedAt = verification?.checked_at ?? verification?.updated_at;
  const ownershipMethod = getString(
    verification,
    ['method', 'ownership_method'],
    kind === 'fqdn' ? 'DNS TXT + agent callback' : kind === 'ip' ? 'Agent callback' : 'Declared scope'
  );
  const expectedBehavior = getString(target, ['expected_behavior', 'expected'], '—');
  const eligibilityReason = getString(
    target,
    ['eligibility_reason'],
    canRun
      ? 'Ownership verified and in scope for bounded validation.'
      : 'Verify ownership and sign the group LOA to unlock bounded validation.'
  );

  return (
    <div className="content stack-tight">
      {error ? <div className="form-banner error" role="alert">{error}</div> : null}
      {renderHeader()}

      <div className="metric-grid four">
        <MetricCard label="Kind" value={kind} sub="Declared target type" icon={Target} tone="info" />
        <MetricCard label="Expected behavior" value={formatTargetLabel(getString(target, ['expected_behavior', 'expected'], '—'))} sub="Declared expectation" icon={Activity} tone="muted" />
        <MetricCard label="Verification" value={formatTargetLabel(verificationState)} sub="Ownership signal from target API" icon={ShieldCheck} tone={verificationTone(verificationState)} />
        <MetricCard label="Eligibility" value={formatTargetLabel(eligibility)} sub={canRun ? 'Eligible for bounded checks' : 'Verify to enable testing'} icon={FileCheck2} tone={canRun ? 'success' : 'warn'} />
      </div>

      <Card>
        <CardHeader><CardTitle>Ownership + eligibility</CardTitle><CardDescription>{ownershipMethod}</CardDescription></CardHeader>
        <CardContent>
          <div className="stack-tight">
            <div className="table-wrap">
              <table className="data-table">
                <tbody>
                  <tr><td className="muted">Ownership method</td><td><div className="kv"><span className="mono">{ownershipMethod}</span></div></td></tr>
                  <tr><td className="muted">Ownership status</td><td><div className="kv"><VerifyChip state={verificationState} provenance={provenance} /></div></td></tr>
                  <tr><td className="muted">Target group</td><td><div className="kv"><span className="mono">{getString(target, ['target_group_id'], '—')}</span></div></td></tr>
                  <tr><td className="muted">Environment</td><td><div className="kv"><span className="mono">{getString(target, ['environment_id'], 'inherited')}</span></div></td></tr>
                  <tr><td className="muted">Expected behavior</td><td><div className="kv"><span className="mono">{expectedBehavior}</span></div></td></tr>
                  {kind === 'fqdn' ? (
                    <tr><td className="muted">DNS TXT</td><td><div className="kv"><VerifyChip state={verificationState.includes('dns') ? 'dns_verified' : verificationState} provenance={provenance} />{dnsCheckedAt ? <span className="kv-meta">{formatDate(dnsCheckedAt)}</span> : null}</div></td></tr>
                  ) : null}
                  {kind !== 'fqdn' ? (
                    <tr><td className="muted">Agent binding</td><td><div className="kv"><span className="mono">{agentBindingId}</span>{agentBindingAt ? <span className="kv-meta">{formatDate(agentBindingAt)}</span> : null}</div></td></tr>
                  ) : null}
                  <tr><td className="muted">Group LOA</td><td><div className="kv"><Badge tone={loaSigned ? 'success' : 'warn'} title="LOA state inherited from target group API">{loaState}</Badge>{loaCustody ? <span className="kv-meta">{loaCustody}</span> : null}</div></td></tr>
                  {loaSigner ? (
                    <tr><td className="muted">LOA signer</td><td><div className="kv"><span>{loaSigner}</span>{loaSignedAt ? <span className="kv-meta">{formatDate(loaSignedAt)}</span> : null}</div></td></tr>
                  ) : null}
                </tbody>
              </table>
            </div>
            <div className="callout">
              <span className="callout-icon" aria-hidden="true"><ShieldCheck size={18} /></span>
              <div className="callout-body">
                <p className="callout-title"><Badge tone={canRun ? 'success' : 'warn'}>{formatTargetLabel(eligibility)}</Badge> for validation</p>
                <p className="callout-desc">{eligibilityReason}</p>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {showWaf ? (
        <Card>
          <CardHeader><CardTitle>WAF posture</CardTitle><CardDescription>Per-target WAF asset from hydrator API.</CardDescription></CardHeader>
          <CardContent>
            <div className="kpi-row">
              <div className="kpi-cell"><div className="kpi-label">Posture</div><div className="kpi-value">{getString(wafPosture, ['posture', 'status'], '—')}</div></div>
              <div className="kpi-cell"><div className="kpi-label">Drift</div><div className="kpi-value">{getString(wafPosture, ['drift_reason'], 'none')}</div></div>
              <div className="kpi-cell"><div className="kpi-label">Validation</div><div className="kpi-value">{getString(wafPosture?.validation as DataItem | undefined, ['verdict'], '—')}</div></div>
              <div className="kpi-cell"><div className="kpi-label">Connector</div><div className="kpi-value">{getString(wafPosture?.connector as DataItem | undefined, ['state'], '—')}</div></div>
              <div className="kpi-cell"><div className="kpi-label">Fingerprint</div><div className="kpi-value mono" title={getString(wafPosture?.fingerprint as DataItem | undefined, ['signature'], '—')}>{getString(wafPosture?.fingerprint as DataItem | undefined, ['signature'], '—')}</div></div>
              <div className="kpi-cell"><div className="kpi-label">Marker rules</div><div className="kpi-value">{String(wafPosture?.marker_rules ?? '—')}</div></div>
              <div className="kpi-cell"><div className="kpi-label">Origin bypass</div><div className="kpi-value">{getString(wafPosture?.origin_bypass as DataItem | undefined, ['state'], '—')}</div></div>
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

      <div className="dash-grid">
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
      </div>

      <Card>
        <CardHeader><CardTitle>Findings on this target</CardTitle></CardHeader>
        <CardContent>
          <DataTable columns={findingColumns} items={detail.findings} empty={emptyStateFromApi({ icon: TriangleAlert, meta: detail.sectionMeta?.findings, actionHref: '#findings', actionLabel: 'Open findings' })} />
        </CardContent>
      </Card>
    </div>
  );
}
