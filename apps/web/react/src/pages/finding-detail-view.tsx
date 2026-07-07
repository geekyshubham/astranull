import { useEffect, useState } from 'react';
import { FileCheck2, TriangleAlert } from 'lucide-react';
import { FindingExplanationPanel } from '../components/findings/finding-explanation-panel';
import { populateFindingAffectedTargets, populateFindingEvidence, readFindingRemediationFields } from '../lib/finding-detail';
import { VerifyChip } from '../lib/verify-chip';
import { requestJson } from '../lib/api';
import { buildDetailHref } from '../lib/route-params';
import type { DataItem, PortalConfig, PortalData, Session } from '../lib/types';
import { formatDate } from '../lib/utils';
import { AnchorButton, Button } from '../components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { EmptyState } from '../components/ui/empty-state';
import { PortalLoadingSkeleton } from '../lib/empty-from-api';
import { Badge } from '../components/ui/badge';
import { DataTable, type TableColumn } from '../components/ui/table';
import { findingSlaDueAt, isFindingSlaBreach, resolveFindingRetestAction } from '../lib/findings-helpers';

function getString(item: DataItem | null | undefined, keys: string[], fallback = '—') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

export function FindingDetailView({
  entity,
  entityId,
  data,
  config,
  session,
  onRefresh,
  loading,
  loadError
}: {
  entity: DataItem;
  entityId: string;
  data: PortalData;
  config: PortalConfig;
  session: Session;
  onRefresh: () => Promise<void>;
  loading: boolean;
  loadError: string;
}) {
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [evidence, setEvidence] = useState<Awaited<ReturnType<typeof populateFindingEvidence>> | null>(null);
  const [affectedTargets, setAffectedTargets] = useState<DataItem[]>([]);

  const remediation = readFindingRemediationFields(entity, data.wafActionItems);
  const remSteps = remediation.remSteps.split('|').map((step) => step.trim()).filter(Boolean);
  const title = getString(entity, ['title', 'summary'], entityId);
  const slaDueAt = findingSlaDueAt(entity);

  useEffect(() => {
    let cancelled = false;
    populateFindingEvidence(config, session, entityId).then((payload) => {
      if (!cancelled) setEvidence(payload);
    });
    return () => { cancelled = true; };
  }, [config, session, entityId]);

  useEffect(() => {
    let cancelled = false;
    const groupId = getString(entity, ['target_group_id'], '');
    if (!groupId) {
      setAffectedTargets([]);
      return undefined;
    }
    requestJson(config, session, `/v1/target-groups/${encodeURIComponent(groupId)}`)
      .then((payload) => {
        if (cancelled) return;
        const targets = Array.isArray((payload as DataItem).targets) ? (payload as DataItem).targets as DataItem[] : [];
        const directTargetId = getString(entity, ['target_id'], '');
        const matched = populateFindingAffectedTargets(entityId, targets);
        if (directTargetId && !matched.some((target) => getString(target, ['id'], '') === directTargetId)) {
          const direct = targets.find((target) => getString(target, ['id'], '') === directTargetId);
          if (direct) matched.unshift(direct);
        }
        setAffectedTargets(matched);
      })
      .catch(() => { if (!cancelled) setAffectedTargets([]); });
    return () => { cancelled = true; };
  }, [config, session, entityId, entity]);

  async function runAction(label: string, action: () => Promise<unknown>, success: string) {
    setBusy(label);
    setError('');
    setMessage('');
    try {
      await action();
      setMessage(success);
      await onRefresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Action failed.');
    } finally {
      setBusy('');
    }
  }

  async function patchFinding(body: Record<string, unknown>, success: string) {
    await runAction(`finding-${entityId}`, () => requestJson(config, session, `/v1/findings/${entityId}`, { method: 'PATCH', body }), success);
  }

  async function markDelivered() {
    if (!remediation.actionItemId) {
      setError('No remediation action item id returned by API.');
      return;
    }
    await runAction(`deliver-${entityId}`, () => requestJson(config, session, `/v1/waf/action-items/${encodeURIComponent(remediation.actionItemId)}/deliver`, { method: 'POST' }), 'Remediation marked delivered.');
  }

  async function verifyChain() {
    await runAction(`verify-${entityId}`, () => requestJson(config, session, evidence?.verify_url ?? '/v1/custody/verify', { method: 'POST', body: { finding_id: entityId } }), 'Custody chain verified.');
  }

  async function exportBundle() {
    await runAction(`export-${entityId}`, () => requestJson(config, session, `/v1/findings/${entityId}/export`, { method: 'POST' }), 'Evidence bundle export requested.');
  }

  const affectedColumns: TableColumn<DataItem>[] = [
    {
      key: 'target',
      label: 'Target',
      render: (item) => <AnchorButton size="sm" variant="ghost" href={buildDetailHref('target-detail', getString(item, ['id'], ''))}>{getString(item, ['value', 'id'], '')}</AnchorButton>
    },
    { key: 'kind', label: 'Kind', render: (item) => getString(item, ['kind'], '—') },
    { key: 'value', label: 'Value', render: (item) => <span className="mono">{getString(item, ['value'], '—')}</span> },
    {
      key: 'verification',
      label: 'Verification',
      render: (item) => <VerifyChip state={getString(item, ['verification_state', 'verification'], 'unverified')} provenance={getString(item, ['verification_title'], 'Verification state from target API.')} />
    },
    { key: 'eligibility', label: 'Eligibility', render: (item) => getString(item, ['eligibility'], '—') },
    { key: 'verdict', label: 'Last verdict', render: (item) => getString(item, ['last_verdict'], '—') }
  ];

  const artifactColumns: TableColumn<DataItem>[] = [
    { key: 'artifact', label: 'Artifact', render: (item) => getString(item, ['id', 'kind'], '—') },
    { key: 'kind', label: 'Kind', render: (item) => getString(item, ['kind'], '—') },
    { key: 'run', label: 'Run', render: (item) => getString(item, ['run_id'], '—') },
    { key: 'sha', label: 'SHA-256', render: (item) => <span className="mono small">{getString(item, ['sha256', 'content_sha256'], '—')}</span> },
    { key: 'sealed', label: 'Sealed', render: (item) => formatDate(item.sealed_at) },
    { key: 'size', label: 'Size', render: (item) => String(item.size_bytes ?? '—') },
    {
      key: 'export',
      label: '',
      render: (item) => <Button className="btn btn-ghost btn-sm" onClick={() => void exportBundle()}>Export</Button>
    }
  ];

  const custodyPreview = {
    finding: entityId,
    bundle_sha256: getString(evidence?.bundle, ['sha256'], ''),
    verified: evidence?.custody_chain?.length ? true : false
  };

  return (
    <div className="content stack-tight">
      <div className="page-head">
        <div>
          <p className="eyebrow">Evidence-backed finding</p>
          <h2 className="page-title">{title}</h2>
          <p className="muted mono">{entityId}</p>
        </div>
      </div>

      {loading ? <PortalLoadingSkeleton rows={2} /> : null}
      {loadError ? <div className="form-banner error">{loadError}</div> : null}
      {(message || error) && !loadError ? <div className={error ? 'form-banner error' : 'form-banner'}>{error || message}</div> : null}

      <Card>
        <CardHeader>
          <CardTitle>Verdict and triage</CardTitle>
          <CardDescription>
            <Badge tone="danger" title={`Severity ${getString(entity, ['severity'], 'unknown')} from finding API`}>{getString(entity, ['severity'], 'unknown')}</Badge>
            {' · '}
            <Badge tone="warn" title={`Status ${getString(entity, ['status'], 'open')} from finding API`}>{getString(entity, ['status'], 'open')}</Badge>
          </CardDescription>
        </CardHeader>
        <CardContent>
          <FindingExplanationPanel finding={entity} config={config} session={session} />
          <div className="kv-list">
            <div><span>Assignee</span><strong>{getString(entity, ['assignee'], 'unassigned')}</strong></div>
            <div><span>SLA due</span><strong title="SLA derived from severity hours and created_at">{slaDueAt ? formatDate(slaDueAt) : '—'}{isFindingSlaBreach(entity) ? ' (breach)' : ''}</strong></div>
          </div>
          <form className="product-form" onSubmit={(event) => {
            event.preventDefault();
            const form = new FormData(event.currentTarget);
            void patchFinding({ assignee: String(form.get('assignee') ?? '').trim(), notes: String(form.get('notes') ?? '').trim() }, 'Triage updated.');
          }}>
            <label><span>Assignee</span><input name="assignee" defaultValue={getString(entity, ['assignee'], '')} /></label>
            <label className="full"><span>Notes</span><textarea name="notes" rows={3} defaultValue={getString(entity, ['notes'], '')} /></label>
            <div className="row-actions">
              <Button type="submit" className="btn btn-secondary btn-sm" loading={busy === `finding-${entityId}`}>Save triage</Button>
              <Button className="btn btn-ghost btn-sm" onClick={() => void patchFinding({ status: 'accepted_risk' }, 'Finding accepted risk.')}>Accept risk</Button>
              <Button className="btn btn-ghost btn-sm" onClick={() => void patchFinding({ status: 'closed' }, 'Finding closed.')}>Close finding</Button>
              <Button className="btn btn-ghost btn-sm" onClick={() => void runAction('retest', async () => {
                const retest = resolveFindingRetestAction(entity);
                if (!retest) throw new Error('Retest context missing from finding API.');
                if (retest.kind === 'safe-run') {
                  await requestJson(config, session, '/v1/test-runs', { method: 'POST', body: { check_id: retest.checkId, target_group_id: getString(entity, ['target_group_id'], ''), target_id: getString(entity, ['target_id'], '') } });
                }
              }, 'Retest started.')}>Retest</Button>
            </div>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle>Affected targets</CardTitle></CardHeader>
        <CardContent>
          {affectedTargets.length === 0 ? (
            <EmptyState
              icon={TriangleAlert}
              title="No declared targets matched."
              body="It may apply at the target-group level: zone-wide, edge-wide: rather than to a single declared target."
            />
          ) : (
            <DataTable columns={affectedColumns} items={affectedTargets} empty={<span className="muted">No affected targets returned.</span>} />
          )}
        </CardContent>
      </Card>

      <Card data-od-id="finding-remediation">
        <CardHeader><CardTitle>Remediation</CardTitle></CardHeader>
        <CardContent>
          <div className="rem-grid">
            <div className="rem-cell"><span className="rem-label">Action</span><span className="rem-value mono">{remediation.remAction || '—'}</span></div>
            <div className="rem-cell"><span className="rem-label">Owner</span><span className="rem-value">{remediation.remOwner || '—'}</span></div>
            <div className="rem-cell"><span className="rem-label">State</span><Badge title={`Remediation state ${remediation.remState} from finding API`}>{remediation.remState || '—'}</Badge></div>
            <div className="rem-cell"><span className="rem-label">SLA</span><span className="rem-value">{remediation.remSla || '—'}</span></div>
          </div>
          <p className="muted">{remediation.remDescription || getString(entity, ['description', 'summary'], 'No remediation description returned by API.')}</p>
          {remSteps.length > 0 ? (
            <ol className="rem-steps">
              {remSteps.map((step, index) => (
                <li key={`${index}-${step}`}><span className="mono">{String(index + 1).padStart(2, '0')}</span> {step}</li>
              ))}
            </ol>
          ) : null}
          <div className="row-actions">
            <Button className="btn btn-ghost btn-sm" onClick={() => void patchFinding({ rem_owner: remediation.remOwner }, 'Remediation owner updated.')}>Reassign owner</Button>
            <Button className="btn btn-secondary btn-sm" disabled={!remediation.actionItemId} loading={busy === `deliver-${entityId}`} onClick={() => void markDelivered()}>Mark delivered</Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <div className="row-actions" style={{ justifyContent: 'space-between', width: '100%' }}>
            <CardTitle>Evidence bundle</CardTitle>
            <div className="row-actions">
              <Button className="btn btn-ghost btn-sm" loading={busy === `verify-${entityId}`} onClick={() => void verifyChain()}>Verify chain</Button>
              <Button className="btn btn-secondary btn-sm" loading={busy === `export-${entityId}`} onClick={() => void exportBundle()}>Export bundle</Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {evidence?.artifacts?.length ? (
            <DataTable columns={artifactColumns} items={evidence.artifacts} empty={<span className="muted">No artifacts in bundle.</span>} />
          ) : (
            <EmptyState icon={FileCheck2} title="No evidence artifacts." body={getString(evidence?.meta, ['empty_reason'], evidence?.error ?? 'Evidence bundle not returned for this finding.')} />
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle>Custody chain</CardTitle><CardDescription>Scoped YAML preview from evidence hydrator.</CardDescription></CardHeader>
        <CardContent>
          <pre className="code">{`finding: ${custodyPreview.finding}\nbundle_sha256: ${custodyPreview.bundle_sha256}\nverified: ${custodyPreview.verified}`}</pre>
        </CardContent>
      </Card>
    </div>
  );
}