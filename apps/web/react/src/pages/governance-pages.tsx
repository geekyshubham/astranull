import { useEffect, useMemo, useState, type FormEvent } from 'react';
import { Bell, CheckCircle2, ClipboardList, Copy, FileCheck2, FileText, Info, Lock, ShieldCheck, Siren } from 'lucide-react';
import { Badge } from '../components/ui/badge';
import { AnchorButton, Button } from '../components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { EmptyState } from '../components/ui/empty-state';
import { Select } from '../components/ui/select';
import { DataTable, type TableColumn } from '../components/ui/table';
import { isStaffSocRole, requestJson, requestSocJson } from '../lib/api';
import {
  computeReleaseEvidenceCoverage,
  pickReleaseEvidenceCustodyUri,
  summarizeReleaseEvidenceValidation
} from '../lib/release-evidence';
import type { DataItem, PortalConfig, PortalData, Session } from '../lib/types';
import { buildDetailHref } from '../lib/route-params';
import { formatDate } from '../lib/utils';
import { MetricCard, PageContextSummary, PageHeader } from './page-components';

function getString(item: DataItem | null | undefined, keys: string[], fallback = '—') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

function getNestedItem(item: DataItem | null | undefined, path: string[]) {
  let current: unknown = item;
  for (const key of path) {
    if (!current || typeof current !== 'object' || Array.isArray(current)) return null;
    current = (current as DataItem)[key];
  }
  return current && typeof current === 'object' && !Array.isArray(current) ? current as DataItem : null;
}

function getNestedString(item: DataItem | null | undefined, path: string[], fallback = '—') {
  let current: unknown = item;
  for (const key of path) {
    if (!current || typeof current !== 'object' || Array.isArray(current)) return fallback;
    current = (current as DataItem)[key];
  }
  if (current !== undefined && current !== null && current !== '') return String(current);
  return fallback;
}

const NOTIFICATION_TRIGGERS = [
  'finding.high_severity',
  'agent.offline',
  'safe_test.completed',
  'high_scale.state_change',
  'report.ready',
  'bootstrap_token.created',
  'bootstrap_token.revoked'
] as const;

const NOTIFICATION_TRIGGER_LABELS: Record<(typeof NOTIFICATION_TRIGGERS)[number], string> = {
  'finding.high_severity': 'High-severity finding',
  'agent.offline': 'Agent offline',
  'safe_test.completed': 'Safe test completed',
  'high_scale.state_change': 'High-scale state change',
  'report.ready': 'Report ready',
  'bootstrap_token.created': 'Bootstrap token created',
  'bootstrap_token.revoked': 'Bootstrap token revoked'
};

function humanizeNotificationTrigger(trigger: string) {
  const known = NOTIFICATION_TRIGGER_LABELS[trigger as (typeof NOTIFICATION_TRIGGERS)[number]];
  if (known) return known;
  return trigger
    .split('.')
    .map((segment) => segment.split('_').map((word) => word.charAt(0).toUpperCase() + word.slice(1)).join(' '))
    .join(' · ');
}

function isFlatMetadataObject(value: unknown): value is Record<string, string | number | boolean | null> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  return Object.values(value).every(
    (entry) => entry === null || ['string', 'number', 'boolean'].includes(typeof entry)
  );
}

function targetGroupDisplayName(data: PortalData, groupId: string) {
  const group = data.targetGroups.find((item) => getString(item, ['id'], '') === groupId);
  return getString(group ?? {}, ['name', 'title'], groupId || '—');
}

function auditEntrySelectionKey(item: DataItem) {
  const id = getString(item, ['id', 'audit_id'], '');
  if (id) return id;
  return [
    getString(item, ['created_at'], ''),
    getString(item, ['action'], ''),
    getString(item, ['resource_type'], ''),
    getString(item, ['resource_id'], '')
  ].join('::');
}

function downloadJsonFile(filename: string, payload: unknown) {
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

function validateNotificationDestination(channel: string, rawDestination: string): { destination: string } | { error: string } {
  const destination = rawDestination.trim();
  if (channel === 'webhook') {
    if (!/^https?:\/\/.+/i.test(destination)) {
      return { error: 'Enter a valid http(s) webhook URL before adding the rule.' };
    }
    try {
      const parsed = new URL(destination);
      if (!['http:', 'https:'].includes(parsed.protocol)) {
        return { error: 'Webhook destination must use http or https.' };
      }
    } catch {
      return { error: 'Enter a valid webhook URL before adding the rule.' };
    }
    return { destination };
  }
  if (channel === 'email') {
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(destination)) {
      return { error: 'Enter a valid email address before adding the rule.' };
    }
    return { destination };
  }
  if (!destination) {
    return { error: 'Enter a destination before adding the rule.' };
  }
  return { destination };
}

function summarizeSocActionPayload(payload: unknown) {
  if (!payload || typeof payload !== 'object') return 'Action completed successfully.';
  const item = payload as DataItem;
  if ('active' in item) {
    return item.active ? 'Kill switch is now active for this tenant.' : 'Kill switch cleared; governed runs may resume when approved.';
  }
  const adapterState = getNestedString(item, ['adapter', 'state'], '');
  if (adapterState && adapterState !== '—') {
    const traffic = getNestedString(item, ['adapter', 'traffic_generated'], 'false');
    return `Adapter status: ${adapterState}${traffic === 'true' ? ', traffic generation reported' : ', no traffic generation reported'}.`;
  }
  const requestState = getString(item, ['state'], '');
  if (requestState && requestState !== '—') return `High-scale request updated — current state is ${requestState}.`;
  const reportId = getString(item, ['id'], '');
  if (reportId && reportId !== '—' && getString(item, ['high_scale_request_id'], '') !== '—') {
    return `Post-test report saved (${reportId}).`;
  }
  return 'SOC action completed successfully.';
}

function canWriteNotifications(role: string | undefined) {
  return role === 'admin' || role === 'owner';
}

function canReadAudit(role: string | undefined) {
  return ['admin', 'owner', 'soc', 'auditor'].includes(String(role ?? ''));
}

function canReadReleaseEvidence(role: string | undefined) {
  return ['admin', 'owner', 'soc', 'auditor'].includes(String(role ?? ''));
}

type GovernanceBadgeTone = 'default' | 'success' | 'warn' | 'danger' | 'info' | 'muted';

function highScaleStateBadgeTone(state: string): GovernanceBadgeTone {
  const normalized = state.trim().toLowerCase();
  if (['closed', 'completed', 'cancelled', 'canceled'].includes(normalized)) return 'success';
  if (['running', 'executing', 'active', 'started'].includes(normalized)) return 'danger';
  if (['scheduled', 'approved'].includes(normalized)) return 'info';
  if (['submitted', 'under_review', 'pending', 'draft'].includes(normalized)) return 'warn';
  return 'muted';
}

function authorizationPackBadgeTone(overall: string): GovernanceBadgeTone {
  const normalized = overall.trim().toLowerCase();
  if (normalized === 'accepted') return 'success';
  if (normalized === 'missing' || normalized === '—' || !normalized) return 'muted';
  return 'warn';
}

function releaseEvidenceStatusBadgeTone(status: string): GovernanceBadgeTone {
  const normalized = status.trim().toLowerCase();
  if (['accepted', 'valid', 'passed', 'recorded'].includes(normalized)) return 'success';
  if (['failed', 'rejected', 'invalid'].includes(normalized)) return 'danger';
  if (['pending', 'review', 'unknown'].includes(normalized)) return 'warn';
  return 'info';
}

function productionReadyBadgeTone(value: unknown): GovernanceBadgeTone {
  if (value === true) return 'success';
  if (value === false) return 'warn';
  return 'muted';
}

function productionReadyLabel(value: unknown) {
  if (value === true) return 'Ready';
  if (value === false) return 'Not ready';
  return 'Unknown';
}

function formatGovernanceStatusLabel(value: string, fallback = '—') {
  const trimmed = value.trim();
  if (!trimmed || trimmed === '—') return fallback;
  return trimmed.replace(/_/g, ' ');
}

function authorizationPackLabel(overall: string) {
  const normalized = overall.trim().toLowerCase();
  if (normalized === 'accepted') return 'Accepted';
  if (normalized === 'missing' || !normalized) return 'Missing';
  return formatGovernanceStatusLabel(overall);
}

const NOTIFICATION_CHANNEL_OPTIONS = [
  { value: 'webhook', label: 'Webhook' },
  { value: 'email', label: 'Email' },
  { value: 'slack', label: 'Slack' },
  { value: 'teams', label: 'Teams' },
  { value: 'in_app', label: 'In-app' }
] as const;

function deliveryAttempts(events: DataItem[]) {
  return events.flatMap((event) => {
    const attempts = Array.isArray(event.delivery_attempts) ? event.delivery_attempts as DataItem[] : [];
    return attempts.map((attempt) => ({
      ...attempt,
      event_id: event.id,
      trigger: event.trigger
    }));
  });
}

export function NotificationsPage({
  data,
  config,
  session,
  onRefresh
}: {
  data: PortalData;
  config: PortalConfig;
  session: Session;
  onRefresh: () => Promise<void>;
}) {
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [destinationError, setDestinationError] = useState('');
  const [ruleDryRunPreview, setRuleDryRunPreview] = useState('');
  const [ruleChannel, setRuleChannel] = useState('webhook');
  const [ruleTrigger, setRuleTrigger] = useState<(typeof NOTIFICATION_TRIGGERS)[number]>('finding.high_severity');
  const canWrite = canWriteNotifications(session.role);
  const attempts = useMemo(() => deliveryAttempts(data.notificationEvents), [data.notificationEvents]);
  const retryItems = attempts.filter((item) => getString(item, ['status']) === 'provider_retry_scheduled');
  const dlqItems = attempts.filter((item) => getString(item, ['status']) === 'provider_failed_dlq');

  const ruleColumns: TableColumn<DataItem>[] = [
    {
      key: 'channel',
      label: 'Channel',
      render: (item) => {
        const channel = getString(item, ['channel']);
        const label = NOTIFICATION_CHANNEL_OPTIONS.find((option) => option.value === channel)?.label ?? formatGovernanceStatusLabel(channel);
        return <Badge tone="info">{label}</Badge>;
      }
    },
    {
      key: 'enabled',
      label: 'Enabled',
      render: (item) => (
        <Badge tone={item.enabled === false ? 'muted' : 'success'}>
          {item.enabled === false ? 'Disabled' : 'Enabled'}
        </Badge>
      )
    },
    { key: 'triggers', label: 'Triggers', render: (item) => (Array.isArray(item.triggers) ? item.triggers.length : 0) },
    { key: 'destination', label: 'Destination', render: (item) => getString(item, ['destination_preview'], 'metadata-only') }
  ];
  const eventColumns: TableColumn<DataItem>[] = [
    { key: 'trigger', label: 'Trigger', render: (item) => humanizeNotificationTrigger(getString(item, ['trigger'])) },
    { key: 'subject', label: 'Subject', render: (item) => getString(item, ['subject']) },
    { key: 'created', label: 'Created', render: (item) => formatDate(item.created_at) }
  ];

  async function runAction<T>(label: string, action: () => Promise<T>, success: string) {
    setBusy(label);
    setError('');
    setMessage('');
    try {
      const result = await action();
      setMessage(success);
      await onRefresh();
      return result;
    } catch (err) {
      const payload = (err as Error & { payload?: unknown }).payload as { error?: string; message?: string } | undefined;
      setError(payload?.message ?? payload?.error ?? (err instanceof Error ? err.message : 'Notification action failed.'));
      return null;
    } finally {
      setBusy('');
    }
  }

  async function handleCreateRule(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formEl = event.currentTarget;
    const form = new FormData(formEl);
    const channel = ruleChannel.trim();
    const trigger = ruleTrigger.trim();
    const validation = validateNotificationDestination(channel, String(form.get('destination_preview') ?? ''));
    if ('error' in validation) {
      setDestinationError(validation.error);
      setRuleDryRunPreview('');
      return;
    }
    setDestinationError('');
    setRuleDryRunPreview('');
    const destination = validation.destination;
    await runAction('create-notification-rule', () => requestJson(config, session, '/v1/notifications', {
      method: 'POST',
      body: {
        channel,
        enabled: true,
        triggers: [trigger],
        destination
      }
    }), 'Notification rule created (metadata-only delivery ledger).');
    formEl.reset();
  }

  function previewRuleFromForm(formEl: HTMLFormElement) {
    const form = new FormData(formEl);
    const channel = ruleChannel.trim();
    const trigger = ruleTrigger.trim();
    const validation = validateNotificationDestination(channel, String(form.get('destination_preview') ?? ''));
    if ('error' in validation) {
      setDestinationError(validation.error);
      setRuleDryRunPreview('');
      return;
    }
    setDestinationError('');
    setRuleDryRunPreview(
      `Dry-run: would create a ${channel} rule for “${humanizeNotificationTrigger(trigger)}” → ${validation.destination} (no ledger write).`
    );
  }

  async function processRetries(dryRun: boolean) {
    if (!dryRun && !window.confirm('Process notification retries now?')) return;
    await runAction(`process-retries-${dryRun ? 'preview' : 'run'}`, () => requestJson(config, session, '/v1/notifications/retries/process', {
      method: 'POST',
      body: { dry_run: dryRun }
    }), dryRun ? 'Due retry preview completed.' : 'Due retries processed (metadata-only).');
  }

  async function redriveDlq(dryRun: boolean) {
    if (!dryRun && !window.confirm('Redrive the DLQ now?')) return;
    const attemptIds = dlqItems
      .map((item) => getString(item, ['id', 'attempt_id'], ''))
      .filter(Boolean);
    await runAction(`redrive-dlq-${dryRun ? 'preview' : 'run'}`, () => requestJson(config, session, '/v1/notifications/dlq/redrive', {
      method: 'POST',
      body: {
        dry_run: dryRun,
        attempt_ids: attemptIds.length > 0 ? attemptIds : undefined
      }
    }), dryRun ? 'DLQ redrive preview completed.' : 'DLQ attempts requeued (metadata-only).');
  }

  return (
    <div className="content">
      <PageHeader route="notifications" />
      {(message || error) && <div className={error ? 'form-banner error' : 'form-banner'}>{error || message}</div>}
      {canWrite ? (
        <Card id="notifications-create-rule">
          <CardHeader>
            <CardTitle>Create notification rule</CardTitle>
            <CardDescription>Metadata-only rule creation. External delivery remains opt-in through server delivery mode.</CardDescription>
          </CardHeader>
          <CardContent>
            <form className="product-form" onSubmit={handleCreateRule} aria-busy={busy === 'create-notification-rule'}>
              <Select
                label="Channel"
                value={ruleChannel}
                options={NOTIFICATION_CHANNEL_OPTIONS.map((option) => ({ value: option.value, label: option.label }))}
                onChange={setRuleChannel}
                disabled={busy !== ''}
              />
              <Select
                label="Trigger"
                value={ruleTrigger}
                options={NOTIFICATION_TRIGGERS.map((trigger) => ({ value: trigger, label: humanizeNotificationTrigger(trigger) }))}
                onChange={(value) => setRuleTrigger(value as (typeof NOTIFICATION_TRIGGERS)[number])}
                disabled={busy !== ''}
              />
              <label className="full"><span>Destination</span><input name="destination_preview" placeholder="https://hooks.example.invalid/notifications" aria-invalid={destinationError ? true : undefined} disabled={busy !== ''} /></label>
              {destinationError ? <p className="form-banner error full">{destinationError}</p> : null}
              {ruleDryRunPreview ? (
                <div className="callout info full"><Info size={18} aria-hidden="true" /><span>{ruleDryRunPreview}</span></div>
              ) : null}
              <div className="form-actions full">
                <Button type="submit" loading={busy === 'create-notification-rule'} disabled={busy !== '' && busy !== 'create-notification-rule'}>Add rule</Button>
                <Button type="button" size="sm" variant="ghost" disabled={busy !== ''} onClick={(clickEvent) => {
                  const form = clickEvent.currentTarget.closest('form');
                  if (form instanceof HTMLFormElement) previewRuleFromForm(form);
                }}>Send test event (dry-run)</Button>
              </div>
            </form>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardContent>
            <EmptyState
              icon={Lock}
              title="Notification write access required."
              body="Switch to owner or admin role to create metadata-only notification rules."
            />
          </CardContent>
        </Card>
      )}
      <PageContextSummary>
        <span className="tabular-nums">{data.notificationRules.length}</span> rules ·{' '}
        <span className="tabular-nums">{data.notificationEvents.length}</span> events ·{' '}
        <span className="tabular-nums">{dlqItems.length}</span> DLQ ({retryItems.length} retries scheduled)
      </PageContextSummary>
      <div className="split" aria-busy={busy !== ''}>
        <Card>
          <CardHeader><CardTitle>Rules</CardTitle></CardHeader>
          <CardContent>
            <DataTable columns={ruleColumns} items={data.notificationRules} empty={<EmptyState icon={Bell} title="No notification rules." body="Create a metadata-only rule to start recording delivery intent." actionLabel={canWrite ? 'Add rule above' : undefined} onAction={canWrite ? () => document.getElementById('notifications-create-rule')?.scrollIntoView({ behavior: 'smooth' }) : undefined} />} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle>Recent events</CardTitle></CardHeader>
          <CardContent>
            <DataTable columns={eventColumns} items={data.notificationEvents.slice().reverse()} empty={<EmptyState icon={ClipboardList} title="No notification events." body="Events appear after configured triggers fire." />} />
          </CardContent>
        </Card>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Delivery operations</CardTitle>
          <CardDescription>Retry and dead-letter queue controls are metadata-only in developer validation. Preview (dry-run) simulates the operation; live actions update delivery state.</CardDescription>
        </CardHeader>
        <CardContent className="stack-tight">
          <section className="operation-panel" aria-labelledby="notification-preview-title">
            <div>
              <h3 id="notification-preview-title">Preview</h3>
              <p>Dry-run — no ledger changes</p>
            </div>
            <div className="row-actions">
              <Button size="sm" variant="ghost" loading={busy === 'process-retries-preview'} disabled={!canWrite || (busy !== '' && busy !== 'process-retries-preview')} onClick={() => void processRetries(true)}>Preview due retries</Button>
              <Button size="sm" variant="ghost" loading={busy === 'redrive-dlq-preview'} disabled={!canWrite || dlqItems.length === 0 || (busy !== '' && busy !== 'redrive-dlq-preview')} onClick={() => void redriveDlq(true)}>Preview DLQ redrive</Button>
            </div>
          </section>
          <section className="operation-panel" aria-labelledby="notification-live-title">
            <div>
              <h3 id="notification-live-title">Live</h3>
              <p>Applies changes — confirmation required</p>
            </div>
            <div className="row-actions">
              <Button size="sm" variant="secondary" loading={busy === 'process-retries-run'} disabled={!canWrite || (busy !== '' && busy !== 'process-retries-run')} onClick={() => void processRetries(false)}>Process due retries</Button>
              <Button size="sm" variant="secondary" loading={busy === 'redrive-dlq-run'} disabled={!canWrite || dlqItems.length === 0 || (busy !== '' && busy !== 'redrive-dlq-run')} onClick={() => void redriveDlq(false)}>Redrive DLQ</Button>
            </div>
          </section>
        </CardContent>
      </Card>
    </div>
  );
}

export function AuditPage({ data, session }: { data: PortalData; session: Session }) {
  const [filter, setFilter] = useState('');
  const [custodyOnly, setCustodyOnly] = useState(false);
  const [selectedId, setSelectedId] = useState('');
  const [showRawAuditMetadata, setShowRawAuditMetadata] = useState(false);
  const allowed = canReadAudit(session.role);
  const items = data.audit.filter((entry) => {
    const action = getString(entry, ['action'], '').toLowerCase();
    if (custodyOnly && !action.includes('custody') && !action.includes('export') && !action.includes('report')) {
      return false;
    }
    if (!filter.trim()) return true;
    const haystack = `${getString(entry, ['action'])} ${getString(entry, ['resource_type'])} ${getString(entry, ['resource_id'])}`.toLowerCase();
    return haystack.includes(filter.trim().toLowerCase());
  });
  const selectedEntry = items.find((entry) => auditEntrySelectionKey(entry) === selectedId) ?? null;

  useEffect(() => {
    setShowRawAuditMetadata(false);
  }, [selectedId]);

  const columns: TableColumn<DataItem>[] = [
    { key: 'time', label: 'Time', render: (item) => formatDate(item.timestamp ?? item.created_at) },
    { key: 'action', label: 'Action', render: (item) => getString(item, ['action']) },
    { key: 'resource', label: 'Resource', render: (item) => `${getString(item, ['resource_type'], '')} ${getString(item, ['resource_id'], '')}`.trim() },
    { key: 'actor', label: 'Actor', render: (item) => getString(item, ['actor_role', 'actor_user_id'], 'system') }
  ];

  return (
    <div className="content">
      <PageHeader route="audit" />
      {!allowed ? (
        <EmptyState icon={ClipboardList} title="Audit access required." body="Switch to owner, admin, SOC, or auditor role to read the tenant audit log." />
      ) : (
        <>
          <div className="split">
          <Card>
            <CardHeader>
              <CardTitle>Audit log</CardTitle>
              <CardDescription>Security-relevant tenant actions with hash-chain integrity on the backend.</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="product-form">
                <label className="full"><span>Filter</span><input value={filter} onChange={(event) => setFilter(event.target.value)} placeholder="action, resource type, or id" /></label>
                <label className="check-row full"><input type="checkbox" name="custody_only" checked={custodyOnly} onChange={(event) => setCustodyOnly(event.target.checked)} /><span>Custody chain only</span></label>
              </div>
              <DataTable
                columns={columns}
                items={items.slice().reverse()}
                selectedId={selectedId || null}
                getRowId={(item) => auditEntrySelectionKey(item)}
                getRowProps={(item) => ({
                  onClick: () => setSelectedId(auditEntrySelectionKey(item))
                })}
                empty={<EmptyState icon={ClipboardList} title="No audit entries." body="Security-relevant actions will appear here after workflow activity." />}
              />
            </CardContent>
          </Card>
          {selectedEntry ? (
            <Card>
              <CardHeader>
                <CardTitle>Custody and metadata drilldown</CardTitle>
                <CardDescription>{getString(selectedEntry, ['action'])} · {getString(selectedEntry, ['resource_type'])}</CardDescription>
              </CardHeader>
              <CardContent className="kv-list">
                <div><span>Actor</span><strong>{getString(selectedEntry, ['actor_user_id'])} ({getString(selectedEntry, ['actor_role'])})</strong></div>
                <div><span>Resource</span><strong>{getString(selectedEntry, ['resource_id'])}</strong></div>
                <div><span>Timestamp</span><strong>{formatDate(selectedEntry.timestamp ?? selectedEntry.created_at)}</strong></div>
                {selectedEntry.metadata && typeof selectedEntry.metadata === 'object' && !Array.isArray(selectedEntry.metadata) ? (
                  isFlatMetadataObject(selectedEntry.metadata)
                    ? Object.entries(selectedEntry.metadata).map(([key, value]) => (
                      <div key={key}><span>{key}</span><strong>{value === null ? 'null' : String(value)}</strong></div>
                    ))
                    : <div><span>Metadata</span><strong className="muted">Structured metadata — use View raw for full JSON.</strong></div>
                ) : (
                  <div><span>Metadata</span><strong>none</strong></div>
                )}
                {selectedEntry.metadata && typeof selectedEntry.metadata === 'object' ? (() => {
                  const metadataJson = JSON.stringify(selectedEntry.metadata, null, 2);
                  const metadataTruncated = metadataJson.length > 1800;
                  const downloadId = getString(selectedEntry, ['id', 'audit_id'], 'audit-entry');
                  return (
                    <div className="full">
                      <div className="row-actions">
                        <Button
                          size="sm"
                          variant="ghost"
                          aria-expanded={showRawAuditMetadata}
                          aria-controls="audit-raw-metadata-panel"
                          onClick={() => setShowRawAuditMetadata((open) => !open)}
                        >
                          {showRawAuditMetadata ? 'Hide raw metadata' : 'View raw'}
                        </Button>
                        {metadataTruncated ? (
                          <Button
                            size="sm"
                            variant="secondary"
                            onClick={() => downloadJsonFile(`audit-metadata-${downloadId}.json`, selectedEntry.metadata)}
                          >
                            Download full metadata
                          </Button>
                        ) : null}
                      </div>
                      {showRawAuditMetadata ? (
                        <div className="stack-tight full" id="audit-raw-metadata-panel">
                          <pre className="codeblock">{metadataJson.slice(0, 1800)}</pre>
                          {metadataTruncated ? <Badge tone="warn">Truncated — download for full JSON</Badge> : null}
                        </div>
                      ) : null}
                    </div>
                  );
                })() : null}
              </CardContent>
            </Card>
          ) : null}
          </div>
        </>
      )}
    </div>
  );
}

export function ReleaseEvidencePage({ data, session }: { data: PortalData; session: Session }) {
  const [showGapTechnicalDetails, setShowGapTechnicalDetails] = useState(false);
  const [clipboardNotice, setClipboardNotice] = useState('');
  const allowed = canReadReleaseEvidence(session.role);
  const attestation = data.releaseAttestation;
  const coverage = computeReleaseEvidenceCoverage(data.releaseEvidence);
  const missingKindColumns: TableColumn<{ kind: string }>[] = [
    { key: 'kind', label: 'Kind', render: (item) => item.kind },
    { key: 'status', label: 'Status', render: () => <Badge tone="warn">Missing</Badge> }
  ];
  const columns: TableColumn<DataItem>[] = [
    { key: 'kind', label: 'Kind', render: (item) => <Badge tone="info">{getString(item, ['kind'])}</Badge> },
    {
      key: 'status',
      label: 'Status',
      render: (item) => {
        const status = getString(item, ['status', 'validation_status'], 'recorded');
        return <Badge tone={releaseEvidenceStatusBadgeTone(status)}>{formatGovernanceStatusLabel(status, 'Recorded')}</Badge>;
      }
    },
    { key: 'validation', label: 'Validation', render: (item) => summarizeReleaseEvidenceValidation(getNestedItem(item, ['validation']) ?? (item.validation as DataItem | undefined) ?? null) },
    { key: 'release', label: 'Release', render: (item) => getString(item, ['release_id', 'id']) },
    { key: 'custody', label: 'Custody', render: (item) => {
      const uri = pickReleaseEvidenceCustodyUri(getNestedItem(item, ['evidence']) ?? (item.evidence as DataItem | undefined));
      if (!uri) return <Badge tone="muted">Metadata only</Badge>;
      return (
        <div className="row-actions">
          <span className="traffic-path-label" title={uri}>
            <code>{uri}</code>
          </span>
          <Button
            size="sm"
            variant="ghost"
            aria-label="Copy custody URI"
            onClick={() => {
              void navigator.clipboard.writeText(uri).then(() => setClipboardNotice('Custody URI copied to clipboard.')).catch(() => setClipboardNotice('Could not copy custody URI.'));
            }}
          >
            <Copy size={14} aria-hidden="true" />
          </Button>
        </div>
      );
    } },
    { key: 'created', label: 'Created', render: (item) => formatDate(item.created_at) }
  ];

  function gapLedgerTechnicalPayload() {
    return {
      exported_at: new Date().toISOString(),
      tenant_id: session.tenant_id ?? 'ten_demo',
      coverage,
      attestation,
      records: data.releaseEvidence.map((item) => ({
        kind: getString(item, ['kind']),
        status: getString(item, ['status']),
        validation: summarizeReleaseEvidenceValidation(getNestedItem(item, ['validation']) ?? (item.validation as DataItem | undefined) ?? null),
        custody_uri: pickReleaseEvidenceCustodyUri(getNestedItem(item, ['evidence']) ?? (item.evidence as DataItem | undefined))
      }))
    };
  }

  function copyGapLedgerSummary() {
    const missingLine = coverage.missing.length > 0
      ? `Missing kinds: ${coverage.missing.join(', ')}.`
      : 'All required kinds are recorded.';
    const summary = [
      `Release evidence gap ledger — ${session.tenant_id ?? 'ten_demo'}`,
      `Recorded ${coverage.recorded} of ${coverage.expected} required kinds.`,
      missingLine,
      `Attestation signoff: ${getNestedString(attestation, ['signoff_status'], 'unknown')}.`,
      `Production ready: ${String(attestation?.production_ready ?? 'unknown')}.`,
      `Exported at ${new Date().toISOString()}.`
    ].join('\n');
    void navigator.clipboard.writeText(summary)
      .then(() => setClipboardNotice('Gap summary copied to clipboard.'))
      .catch(() => setClipboardNotice('Could not copy gap summary.'));
  }

  function copyGapLedgerTechnicalJson() {
    void navigator.clipboard.writeText(JSON.stringify(gapLedgerTechnicalPayload(), null, 2))
      .then(() => setClipboardNotice('Technical JSON copied to clipboard.'))
      .catch(() => setClipboardNotice('Could not copy technical JSON.'));
  }

  return (
    <div className="content">
      <PageHeader route="audit" eyebrow="Release evidence" />
      {!allowed ? (
        <EmptyState icon={FileText} title="Release evidence access required." body="Switch to owner, admin, SOC, or auditor role to inspect production release evidence." />
      ) : (
        <>
          <PageContextSummary>
            Evidence kinds <span className="tabular-nums">{coverage.recorded}/{coverage.expected}</span>
            {coverage.kindsComplete ? ' · inventory complete' : ` · ${coverage.missing.length} missing`} · attestation{' '}
            {formatGovernanceStatusLabel(getNestedString(attestation, ['signoff_status'], 'unknown'), 'unknown')} · production{' '}
            {productionReadyLabel(attestation?.production_ready)}
          </PageContextSummary>
          {clipboardNotice ? <div className="form-banner info" role="status" aria-live="polite">{clipboardNotice}</div> : null}
          <Card>
            <CardHeader>
              <CardTitle>Gap ledger</CardTitle>
              <CardDescription>Kinds not yet attached to accepted release evidence for this tenant.</CardDescription>
            </CardHeader>
            <CardContent className="product-form">
              <p className="muted">Recorded {coverage.recorded} of {coverage.expected} required kinds. Customer launch remains gated by staging, legal, SOC, and security signoffs.</p>
              {coverage.missing.length > 0 ? (
                <div className="stack-tight">
                  <DataTable
                    columns={missingKindColumns}
                    items={coverage.missing.slice(0, 12).map((kind) => ({ kind }))}
                    empty={<EmptyState icon={FileText} title="No missing kinds." body="All required kinds are recorded." />}
                  />
                  {coverage.missing.length > 12 ? <p className="muted">…and {coverage.missing.length - 12} more kinds.</p> : null}
                </div>
              ) : <p className="muted">All required kinds are recorded for this tenant inventory snapshot.</p>}
              <div className="row-actions">
                <Button size="sm" onClick={copyGapLedgerSummary}>Copy gap summary</Button>
                <Button
                  size="sm"
                  variant="ghost"
                  aria-expanded={showGapTechnicalDetails}
                  aria-controls={showGapTechnicalDetails ? 'release-evidence-technical-export' : undefined}
                  onClick={() => setShowGapTechnicalDetails((open) => !open)}
                >
                  {showGapTechnicalDetails ? 'Hide technical export' : 'Technical export'}
                </Button>
              </div>
              {showGapTechnicalDetails ? (
                <div className="expand-panel stack-tight" id="release-evidence-technical-export">
                  <div className="row-actions">
                    <Button size="sm" variant="secondary" onClick={copyGapLedgerTechnicalJson}>Copy technical JSON</Button>
                    <Button
                      size="sm"
                      variant="secondary"
                      onClick={() => downloadJsonFile(`release-evidence-gap-ledger-${session.tenant_id ?? 'tenant'}.json`, gapLedgerTechnicalPayload())}
                    >
                      Download .json
                    </Button>
                  </div>
                </div>
              ) : null}
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Release evidence inventory</CardTitle>
              <CardDescription>Accepted kinds, validation summary, and custody URI previews without raw bodies.</CardDescription>
            </CardHeader>
            <CardContent>
              <DataTable columns={columns} items={data.releaseEvidence} empty={<EmptyState icon={FileText} title="No release evidence records." body="Operator evidence validators populate this inventory during release rehearsals." />} />
            </CardContent>
          </Card>
          {attestation && (
            <Card>
              <CardHeader>
                <CardTitle>Attestation snapshot</CardTitle>
                <CardDescription>Latest staging readiness attestation snapshot for this tenant.</CardDescription>
              </CardHeader>
              <CardContent className="kv-list">
                <div><span>Signoff status</span><strong><Badge tone="info">{formatGovernanceStatusLabel(getNestedString(attestation, ['signoff_status']), '—')}</Badge></strong></div>
                <div><span>Production ready</span><strong><Badge tone={productionReadyBadgeTone(attestation.production_ready)}>{productionReadyLabel(attestation.production_ready)}</Badge></strong></div>
                <div><span>Profile</span><strong>{getNestedString(attestation, ['profile'], 'full')}</strong></div>
                <div><span>Checked at</span><strong>{formatDate(attestation.checked_at ?? attestation.created_at)}</strong></div>
              </CardContent>
            </Card>
          )}
        </>
      )}
    </div>
  );
}

export function SocConsolePage({
  data,
  config,
  session,
  onRefresh,
  staffSocSurface = false
}: {
  data: PortalData;
  config: PortalConfig;
  session: Session;
  onRefresh: () => Promise<void>;
  staffSocSurface?: boolean;
}) {
  const [busy, setBusy] = useState('');
  const [queueRefreshing, setQueueRefreshing] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [output, setOutput] = useState('');
  const [outputSummary, setOutputSummary] = useState('');
  const [showActionTechnicalDetails, setShowActionTechnicalDetails] = useState(false);
  const [lastActionRequestId, setLastActionRequestId] = useState('');

  function setActionOutput(payload: unknown, requestId = '') {
    setOutput(JSON.stringify(payload, null, 2));
    setOutputSummary(summarizeSocActionPayload(payload));
    setShowActionTechnicalDetails(false);
    setLastActionRequestId(requestId);
  }
  const isSoc = staffSocSurface
    ? session.principal === 'staff' && isStaffSocRole(session)
    : session.role === 'soc' && session.principal !== 'staff';

  async function socRequest(path: string, options: { method?: string; body?: unknown } = {}) {
    if (staffSocSurface) return requestSocJson(config, session, path, options);
    return requestJson(config, session, path, options);
  }
  const requestColumns: TableColumn<DataItem>[] = [
    { key: 'id', label: 'Request', render: (item) => getString(item, ['id']) },
    {
      key: 'state',
      label: 'State',
      render: (item) => {
        const state = getString(item, ['state']);
        return <Badge tone={highScaleStateBadgeTone(state)}>{formatGovernanceStatusLabel(state, 'Unknown')}</Badge>;
      }
    },
    { key: 'target', label: 'Target group', render: (item) => targetGroupDisplayName(data, getString(item, ['target_group_id'])) },
    {
      key: 'pack',
      label: 'Pack',
      render: (item) => {
        const overall = getNestedString(item, ['authorization_pack_status', 'overall'], 'missing');
        return <Badge tone={authorizationPackBadgeTone(overall)}>{authorizationPackLabel(overall)}</Badge>;
      }
    },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        const state = getString(item, ['state'], '');
        const packReady = getNestedString(item, ['authorization_pack_status', 'overall'], '') === 'accepted';
        return (
          <div className="stack-tight">
            <AnchorButton size="sm" variant="secondary" href={buildDetailHref('queue-detail', id)}>Open</AnchorButton>
            {['submitted', 'under_review'].includes(state) && packReady ? (
              <Button
                size="sm"
                variant="secondary"
                loading={busy === `approve-${id}`}
                disabled={busy !== '' && busy !== `approve-${id}`}
                onClick={(clickEvent) => {
                  clickEvent.stopPropagation();
                  void socAction(id, 'approve');
                }}
              >
                Quick approve
              </Button>
            ) : null}
          </div>
        );
      }
    }
  ];

  async function socAction(requestId: string, action: string, body: Record<string, unknown> = {}) {
    if (!requestId) return null;
    const lifecycleConfirm: Record<string, string> = {
      approve: `Approve high-scale request ${requestId} and move it to approved?`,
      schedule: `Schedule high-scale request ${requestId} for execution?`,
      start: `Start high-scale execution for ${requestId}? Governed adapter traffic will begin.`,
      stop: `Stop high-scale execution for ${requestId} immediately?`,
      close: `Close high-scale request ${requestId} and finalize the test lifecycle?`
    };
    const lifecycleMessage = lifecycleConfirm[action];
    if (lifecycleMessage && !window.confirm(lifecycleMessage)) return null;
    setBusy(`${action}-${requestId}`);
    setError('');
    setMessage('');
    try {
      const payload = await socRequest(`/internal/soc/high-scale/${encodeURIComponent(requestId)}/${action}`, {
        method: 'POST',
        body
      });
      setActionOutput(payload, requestId);
      setMessage(`SOC ${action} completed for ${requestId}.`);
      setQueueRefreshing(true);
      try {
        await onRefresh();
      } finally {
        setQueueRefreshing(false);
      }
      return payload;
    } catch (err) {
      const payload = (err as Error & { payload?: unknown }).payload as { error?: string; message?: string } | undefined;
      setError(payload?.message ?? payload?.error ?? (err instanceof Error ? err.message : 'SOC action failed.'));
      return null;
    } finally {
      setBusy('');
    }
  }

  async function setKillSwitch(active: boolean) {
    if (active) {
      if (!window.confirm('Activate the tenant kill switch? All high-scale execution for this tenant halts immediately.')) return;
    } else if (!window.confirm('Clear the kill switch and allow high-scale execution to resume?')) return;
    setBusy(active ? 'kill-on' : 'kill-off');
    setError('');
    setMessage('');
    try {
      const payload = await socRequest('/internal/soc/kill-switch', {
        method: 'POST',
        body: { active, reason: active ? 'SOC console activation' : 'SOC console cleared' }
      });
      setActionOutput(payload, '');
      setMessage(active ? 'Kill switch activated.' : 'Kill switch cleared.');
      setQueueRefreshing(true);
      try {
        await onRefresh();
      } finally {
        setQueueRefreshing(false);
      }
    } catch (err) {
      const payload = (err as Error & { payload?: unknown }).payload as { error?: string; message?: string } | undefined;
      setError(payload?.message ?? payload?.error ?? (err instanceof Error ? err.message : 'Kill switch action failed.'));
    } finally {
      setBusy('');
    }
  }

  if (!isSoc) {
    const killSwitchActive = Boolean(data.state?.kill_switch?.active ?? data.state?.kill_switch?.enabled);
    return (
      <div className="content">
        <PageHeader
          route="internal-soc"
          eyebrow={staffSocSurface ? 'Staff SOC execution plane' : 'SOC execution plane'}
        />
        <div className="stack-tight">
          <EmptyState
            icon={ShieldCheck}
            title={staffSocSurface ? 'Staff SOC role required.' : 'SOC role required.'}
            body={staffSocSurface
              ? 'Sign in with a staff soc_analyst or soc_lead role to use the governed high-scale execution console.'
              : 'Switch the workspace role to soc to use the governed high-scale execution console.'}
            actionLabel={staffSocSurface ? 'Open staff login' : undefined}
            actionHref={staffSocSurface ? '/internal/admin/login' : undefined}
          />
          <Card density="compact">
            <CardHeader>
              <CardTitle>Kill switch</CardTitle>
              <CardDescription>Read-only tenant emergency-stop status. Activation and clearance require an SOC role.</CardDescription>
            </CardHeader>
            <CardContent className="kv-list">
              <div><span>Status</span><strong><Badge tone={killSwitchActive ? 'danger' : 'success'}>{killSwitchActive ? 'Active' : 'Inactive'}</Badge></strong></div>
              <div><span>Reason</span><strong>{getString(data.state?.kill_switch as DataItem, ['reason'], 'tenant-scoped emergency stop')}</strong></div>
            </CardContent>
          </Card>
        </div>
      </div>
    );
  }

  const killSwitchActive = Boolean(data.state?.kill_switch?.active ?? data.state?.kill_switch?.enabled);

  return (
    <div className="content">
      <PageHeader
        route="internal-soc"
        eyebrow="SOC execution plane"
        actions={staffSocSurface ? <Badge tone="warn">Staff plane</Badge> : undefined}
      />
      <div className={killSwitchActive ? 'callout warn' : 'callout info'}>
        {killSwitchActive ? <Siren size={18} aria-hidden="true" /> : <ShieldCheck size={18} aria-hidden="true" />}
        <span>
          {killSwitchActive
            ? 'Kill switch is active — governed high-scale execution is halted for this tenant.'
            : 'Kill switch is clear; governed runs may proceed when approved and scheduled.'}
        </span>
      </div>
      <PageContextSummary>
        Queue <span className="tabular-nums">{data.highScale.length}</span> governed requests ·{' '}
        <span className="tabular-nums">{data.state?.open_findings ?? data.findings.length}</span> open findings
      </PageContextSummary>
      {(message || error) && <div className={error ? 'form-banner error' : 'form-banner'}>{error || message}</div>}
      <Card>
        <CardHeader>
          <CardTitle>Kill switch</CardTitle>
          <CardDescription>Tenant-scoped emergency stop for governed high-scale adapter runs.</CardDescription>
        </CardHeader>
        <CardContent className="row-actions">
          <Button size="sm" variant="danger" loading={busy === 'kill-on'} disabled={busy !== '' && busy !== 'kill-on'} onClick={() => void setKillSwitch(true)}>Activate</Button>
          <Button size="sm" variant="secondary" loading={busy === 'kill-off'} disabled={busy !== '' && busy !== 'kill-off'} onClick={() => void setKillSwitch(false)}>Clear</Button>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>High-scale queue</CardTitle>
          <CardDescription>Open a request for the full lifecycle workspace. Quick approve is available here only when the authorization pack is accepted.</CardDescription>
        </CardHeader>
        <CardContent aria-busy={queueRefreshing}>
          <DataTable
            columns={requestColumns}
            items={data.highScale}
            empty={queueRefreshing ? (
              <div className="stack-tight" role="status" aria-live="polite">
                <span className="skeleton skeleton-row" />
                <span className="skeleton skeleton-row" />
              </div>
            ) : (
              <EmptyState icon={ShieldCheck} title="No high-scale requests." body="Customer requests appear here after intake and authorization-pack review." />
            )}
          />
        </CardContent>
      </Card>
      {output ? (
        <Card>
          <CardHeader>
            <CardTitle>
              {lastActionRequestId
                ? <>Action output — <code className="traffic-path-label">{lastActionRequestId}</code></>
                : 'Action output — tenant controls'}
            </CardTitle>
            {lastActionRequestId ? (
              <CardDescription>
                <AnchorButton size="sm" variant="ghost" href={buildDetailHref('soc-request-detail', lastActionRequestId)}>Open request detail</AnchorButton>
              </CardDescription>
            ) : null}
          </CardHeader>
          <CardContent>
            <div className="callout info" role="status" aria-live="polite">
              <CheckCircle2 size={18} aria-hidden="true" />
              <span>{outputSummary || 'Action completed successfully.'}</span>
            </div>
            <Button
              size="sm"
              variant="ghost"
              aria-expanded={showActionTechnicalDetails}
              aria-controls="soc-action-technical-output"
              onClick={() => setShowActionTechnicalDetails((open) => !open)}
            >
              {showActionTechnicalDetails ? 'Hide technical details' : 'View technical details'}
            </Button>
            {showActionTechnicalDetails ? <pre className="codeblock" id="soc-action-technical-output">{output}</pre> : null}
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}
