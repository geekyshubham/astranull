import { useEffect, useMemo, useState, type FormEvent, type ReactNode } from 'react';
import { Activity, Bell, CalendarClock, CheckCircle2, ClipboardList, Copy, FileText, Info, Lock, Search, ShieldCheck, Siren, Users } from 'lucide-react';
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
import { buildLifecycleTimeline } from '../lib/high-scale';
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
  if (channel === 'in_app') {
    return { destination: '' };
  }
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

type ProviderHealthRow = {
  channel: string;
  label: string;
  detail: string;
  ruleCount: number;
  enabledCount: number;
  delivered: number;
  retrying: number;
  dlq: number;
  tone: GovernanceBadgeTone;
  status: string;
};

// Derives per-provider delivery health from real notification rules (configured channels)
// correlated with recorded delivery attempts. No provider status is hardcoded.
function buildProviderHealthRows(rules: DataItem[], attempts: DataItem[]): ProviderHealthRow[] {
  type Acc = { ruleCount: number; enabledCount: number; delivered: number; retrying: number; dlq: number; detail: string };
  const channels = new Map<string, Acc>();
  const ensure = (channel: string): Acc => {
    const existing = channels.get(channel);
    if (existing) return existing;
    const created: Acc = { ruleCount: 0, enabledCount: 0, delivered: 0, retrying: 0, dlq: 0, detail: '' };
    channels.set(channel, created);
    return created;
  };
  for (const rule of rules) {
    const channel = getString(rule, ['channel'], '').trim();
    if (!channel || channel === '—') continue;
    const entry = ensure(channel);
    entry.ruleCount += 1;
    if (rule.enabled !== false) entry.enabledCount += 1;
    if (!entry.detail) {
      const dest = getString(rule, ['destination_preview'], '');
      if (dest && dest !== '—') entry.detail = dest;
    }
  }
  for (const attempt of attempts) {
    const channel = getString(attempt, ['channel'], '').trim();
    if (!channel || channel === '—') continue;
    const entry = ensure(channel);
    const status = getString(attempt, ['status'], '');
    if (status === 'delivered_provider') entry.delivered += 1;
    else if (status === 'provider_retry_scheduled') entry.retrying += 1;
    else if (status === 'provider_failed_dlq') entry.dlq += 1;
    if (!entry.detail) {
      const dest = getString(attempt, ['destination_preview'], '');
      if (dest && dest !== '—') entry.detail = dest;
    }
  }
  return Array.from(channels.entries())
    .map(([channel, entry]) => {
      const label = NOTIFICATION_CHANNEL_OPTIONS.find((option) => option.value === channel)?.label
        ?? formatGovernanceStatusLabel(channel);
      let tone: GovernanceBadgeTone;
      let status: string;
      if (entry.dlq > 0) {
        tone = 'danger';
        status = 'Dead-letter';
      } else if (entry.retrying > 0) {
        tone = 'warn';
        status = 'Retrying';
      } else if (entry.delivered > 0) {
        tone = 'success';
        status = 'Healthy';
      } else {
        tone = 'muted';
        status = entry.ruleCount > 0 ? 'Idle' : 'No rules';
      }
      const detail = entry.detail
        || (entry.ruleCount > 0 ? `${entry.ruleCount} rule${entry.ruleCount === 1 ? '' : 's'}` : 'metadata-only');
      return { channel, label, ...entry, detail, tone, status };
    })
    .sort((left, right) => left.label.localeCompare(right.label));
}

function GovernanceFeedbackBanner({ message, error }: { message: string; error: string }) {
  if (!message && !error) return null;
  return (
    <div
      className={error ? 'form-banner error' : 'form-banner'}
      role={error ? 'alert' : 'status'}
      aria-live="polite"
    >
      {error || message}
    </div>
  );
}

function GovernanceInfoBanner({ children }: { children: ReactNode }) {
  return (
    <div className="form-banner info" role="status" aria-live="polite">
      {children}
    </div>
  );
}

function DeliveryOperationPanel({
  titleId,
  title,
  description,
  children
}: {
  titleId: string;
  title: string;
  description: string;
  children: ReactNode;
}) {
  return (
    <section className="operation-panel" aria-labelledby={titleId}>
      <div>
        <h3 id={titleId}>{title}</h3>
        <p>{description}</p>
      </div>
      <div className="row-actions">{children}</div>
    </section>
  );
}

function KvField({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <span>{label}</span>
      <strong>{children}</strong>
    </div>
  );
}

function KillSwitchReadOnlyCard({ active, reason }: { active: boolean; reason: string }) {
  return (
    <Card density="compact">
      <CardHeader>
        <CardTitle>Kill switch</CardTitle>
        <CardDescription>Read-only tenant emergency-stop status. Activation and clearance require an SOC role.</CardDescription>
      </CardHeader>
      <CardContent className="kv-list">
        <KvField label="Status">
          <Badge tone={active ? 'danger' : 'success'}>{active ? 'Active' : 'Inactive'}</Badge>
        </KvField>
        <KvField label="Reason">{reason}</KvField>
      </CardContent>
    </Card>
  );
}

function ExpandableCodePanel({
  panelId,
  expanded,
  onToggle,
  toggleLabels,
  code,
  truncated,
  downloadLabel,
  onDownload
}: {
  panelId: string;
  expanded: boolean;
  onToggle: () => void;
  toggleLabels: { show: string; hide: string };
  code: string;
  truncated?: boolean;
  downloadLabel?: string;
  onDownload?: () => void;
}) {
  return (
    <div className="full">
      <div className="row-actions">
        <Button
          size="sm"
          variant="ghost"
          aria-expanded={expanded}
          aria-controls={panelId}
          onClick={onToggle}
        >
          {expanded ? toggleLabels.hide : toggleLabels.show}
        </Button>
        {truncated && onDownload && downloadLabel ? (
          <Button size="sm" variant="secondary" onClick={onDownload}>
            {downloadLabel}
          </Button>
        ) : null}
      </div>
      {expanded ? (
        <div className="stack-tight full" id={panelId}>
          <pre className="codeblock">{code}</pre>
          {truncated ? <Badge tone="warn">Truncated — download for full JSON</Badge> : null}
        </div>
      ) : null}
    </div>
  );
}

function TableQueueSkeleton({ rows = 2 }: { rows?: number }) {
  return (
    <div className="stack-tight" role="status" aria-live="polite" aria-label="Loading queue">
      {Array.from({ length: rows }, (_, index) => (
        <span key={index} className="skeleton skeleton-row" />
      ))}
    </div>
  );
}

const SOC_SCHEDULED_STATES = ['scheduled', 'approved'];
const SOC_REVIEW_STATES = ['submitted', 'under_review', 'pending', 'draft'];
const SOC_RUNNING_STATES = ['running', 'executing', 'active', 'started'];

// Validated kill-switch sequence, mirroring the frozen server contract
// (src/contracts/killSwitchValidation.mjs → KILL_SWITCH_REQUIRED_STEP_IDS).
// Rendered as the documented arming sequence; each step is custody-recorded on exercise.
const KILL_SWITCH_VALIDATED_SEQUENCE = [
  'activate_tenant_kill_switch',
  'block_new_safe_runs',
  'cancel_active_safe_runs',
  'probe_fleet_stops_leasing',
  'adapter_stop_path_invoked',
  'audit_timeline_recorded',
  'clear_and_resume_guarded'
] as const;

function normalizeHighScaleState(item: DataItem) {
  return getString(item, ['state'], '').trim().toLowerCase();
}

type SocGoNoGoGate = { key: string; label: string; tone: GovernanceBadgeTone; status: string };

function socPackGate(actionableCount: number, pendingCount: number): { tone: GovernanceBadgeTone; status: string } {
  if (actionableCount === 0) return { tone: 'muted', status: 'No open requests' };
  if (pendingCount === 0) return { tone: 'success', status: 'All accepted' };
  return { tone: 'warn', status: `${pendingCount} pending` };
}

function buildSocGoNoGoGates(
  requests: DataItem[],
  context: { killSwitchActive: boolean; runningCount: number; openFindings: number }
): SocGoNoGoGate[] {
  const actionable = requests.filter((item) =>
    [...SOC_REVIEW_STATES, ...SOC_SCHEDULED_STATES].includes(normalizeHighScaleState(item))
  );
  const packAccepted = actionable.filter(
    (item) => getNestedString(item, ['authorization_pack_status', 'overall'], 'missing') === 'accepted'
  ).length;
  return [
    { key: 'packs', label: 'Authorization packs reviewed', ...socPackGate(actionable.length, actionable.length - packAccepted) },
    {
      key: 'kill',
      label: 'Kill switch clear',
      tone: context.killSwitchActive ? 'danger' : 'success',
      status: context.killSwitchActive ? 'Armed' : 'Clear'
    },
    {
      key: 'execution',
      label: 'Managed execution only',
      tone: context.runningCount > 0 ? 'info' : 'success',
      status: context.runningCount > 0 ? `${context.runningCount} active` : 'Idle'
    },
    {
      key: 'findings',
      label: 'Findings triaged',
      tone: context.openFindings > 0 ? 'warn' : 'success',
      status: context.openFindings > 0 ? `${context.openFindings} open` : 'Clear'
    }
  ];
}

function providerNameForRequest(item: DataItem): string {
  const context = getNestedItem(item, ['provider_context']);
  const contextName = getString(context, ['provider_name', 'provider', 'name'], '');
  if (contextName && contextName !== '—') return contextName;
  const checklist = Array.isArray(item.provider_approval_checklist)
    ? (item.provider_approval_checklist as DataItem[])
    : [];
  for (const entry of checklist) {
    const name = getString(entry, ['provider_name', 'provider', 'name'], '');
    if (name && name !== '—') return name;
  }
  return '';
}

function extractEmergencyContact(contact: unknown): { name: string; detail: string; role: string } {
  if (typeof contact === 'string') return { name: contact, detail: '', role: '' };
  if (contact && typeof contact === 'object' && !Array.isArray(contact)) {
    const item = contact as DataItem;
    return {
      name: getString(item, ['name', 'contact', 'email', 'phone'], '—'),
      detail: getString(item, ['contact', 'email', 'phone'], ''),
      role: getString(item, ['role', 'title'], '')
    };
  }
  return { name: '—', detail: '', role: '' };
}

type ProviderContactRow = { id: string; requestId: string; provider: string; contact: string; role: string };

function buildProviderContactRows(requests: DataItem[]): ProviderContactRow[] {
  return requests.flatMap((request) => {
    const requestId = getString(request, ['id'], '—');
    const provider = providerNameForRequest(request);
    const contacts = Array.isArray(request.emergency_contacts) ? request.emergency_contacts : [];
    if (contacts.length === 0) {
      if (!provider) return [];
      return [{ id: `${requestId}::provider`, requestId, provider, contact: '—', role: '—' }];
    }
    return contacts.map((contact, index) => {
      const info = extractEmergencyContact(contact);
      const label = info.detail && info.detail !== info.name ? `${info.name} · ${info.detail}` : info.name;
      return {
        id: `${requestId}::${index}`,
        requestId,
        provider: provider || '—',
        contact: label,
        role: info.role || '—'
      };
    });
  });
}

const providerContactColumns: TableColumn<ProviderContactRow>[] = [
  { key: 'request', label: 'Request', render: (item) => <span className="mono">{item.requestId}</span> },
  {
    key: 'provider',
    label: 'Provider',
    render: (item) => (item.provider === '—' ? <span className="muted">—</span> : <Badge tone="info">{item.provider}</Badge>)
  },
  { key: 'contact', label: 'Contact', render: (item) => <span className="mono">{item.contact}</span> },
  {
    key: 'role',
    label: 'Role',
    render: (item) => (item.role === '—' ? <span className="muted">—</span> : formatGovernanceStatusLabel(item.role))
  }
];

type SocTimelineRow = { key: string; requestId: string; action: string; at: string; by: string };

function buildSocExecutionTimeline(requests: DataItem[]): SocTimelineRow[] {
  return requests
    .flatMap((request) => {
      const requestId = getString(request, ['id'], '—');
      return buildLifecycleTimeline(request).map((event, index) => ({
        key: `${requestId}::${index}::${event.at}`,
        requestId,
        action: event.action,
        at: event.at,
        by: event.by
      }));
    })
    .sort((left, right) => new Date(right.at).getTime() - new Date(left.at).getTime())
    .slice(0, 12);
}

type SocCrossTenantRow = { id: string; tenantId: string; kind: string; state: string; requestedAt: string };

// Staff SOC surface only. Cross-tenant governed requests come from the staff approval queue
// (`data.internalApprovalRequests`, fetched for staff sessions), filtered to high-scale kinds.
function isHighScaleApprovalKind(kind: string) {
  return kind.trim().toLowerCase().startsWith('high_scale');
}

function buildSocCrossTenantRows(approvals: DataItem[]): SocCrossTenantRow[] {
  return approvals
    .filter((item) => isHighScaleApprovalKind(getString(item, ['kind'], '')))
    .map((item) => ({
      id: getString(item, ['id'], '—'),
      tenantId: getString(item, ['tenant_id'], '—'),
      kind: getString(item, ['kind'], '—'),
      state: getString(item, ['state'], '—'),
      requestedAt: getString(item, ['created_at', 'requested_at'], '')
    }))
    .sort((left, right) => new Date(right.requestedAt).getTime() - new Date(left.requestedAt).getTime());
}

const socCrossTenantColumns: TableColumn<SocCrossTenantRow>[] = [
  { key: 'tenant', label: 'Tenant', render: (item) => <span className="mono">{item.tenantId}</span> },
  { key: 'request', label: 'Request', render: (item) => <span className="mono">{item.id}</span> },
  { key: 'kind', label: 'Kind', render: (item) => <Badge tone="info">{formatGovernanceStatusLabel(item.kind, 'high scale')}</Badge> },
  {
    key: 'state',
    label: 'State',
    render: (item) => <Badge tone={highScaleStateBadgeTone(item.state)}>{formatGovernanceStatusLabel(item.state, 'Unknown')}</Badge>
  },
  { key: 'requested', label: 'Requested', render: (item) => formatDate(item.requestedAt) },
  {
    key: 'actions',
    label: 'Actions',
    render: (item) => (
      <AnchorButton size="sm" variant="secondary" href={buildDetailHref('queue-detail', item.id)}>Open</AnchorButton>
    )
  }
];

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
  const [triggerError, setTriggerError] = useState('');
  const [ruleDryRunPreview, setRuleDryRunPreview] = useState('');
  const [ruleChannel, setRuleChannel] = useState('webhook');
  const [ruleTriggers, setRuleTriggers] = useState<string[]>(['finding.high_severity']);
  const [ruleEnabled, setRuleEnabled] = useState(true);
  const canWrite = canWriteNotifications(session.role);
  const attempts = useMemo(() => deliveryAttempts(data.notificationEvents ?? []), [data.notificationEvents]);
  const deliveredCount = attempts.filter((item) => getString(item, ['status']) === 'delivered_provider').length;
  const retryItems = attempts.filter((item) => getString(item, ['status']) === 'provider_retry_scheduled');
  const dlqItems = attempts.filter((item) => getString(item, ['status']) === 'provider_failed_dlq');
  const providerHealthRows = useMemo(
    () => buildProviderHealthRows(data.notificationRules ?? [], attempts),
    [data.notificationRules, attempts]
  );

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
  const providerColumns: TableColumn<ProviderHealthRow>[] = [
    { key: 'provider', label: 'Provider', render: (item) => <Badge tone="info">{item.label}</Badge> },
    { key: 'channel', label: 'Channel', render: (item) => <span className="muted">{item.detail}</span> },
    { key: 'health', label: 'Health', render: (item) => <Badge tone={item.tone}>{item.status}</Badge> }
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

  function toggleRuleTrigger(trigger: string) {
    setTriggerError('');
    setRuleDryRunPreview('');
    setRuleTriggers((current) =>
      current.includes(trigger) ? current.filter((item) => item !== trigger) : [...current, trigger]
    );
  }

  async function handleCreateRule(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formEl = event.currentTarget;
    const form = new FormData(formEl);
    const channel = ruleChannel.trim();
    const triggers = NOTIFICATION_TRIGGERS.filter((trigger) => ruleTriggers.includes(trigger));
    if (triggers.length === 0) {
      setTriggerError('Select at least one rule kind before adding the rule.');
      setRuleDryRunPreview('');
      return;
    }
    setTriggerError('');
    const validation = validateNotificationDestination(channel, String(form.get('destination_preview') ?? ''));
    if ('error' in validation) {
      setDestinationError(validation.error);
      setRuleDryRunPreview('');
      return;
    }
    setDestinationError('');
    setRuleDryRunPreview('');
    const created = await runAction('create-notification-rule', () => requestJson(config, session, '/v1/notifications', {
      method: 'POST',
      body: {
        channel,
        enabled: ruleEnabled,
        triggers,
        destination: validation.destination
      }
    }), `Notification rule created ${ruleEnabled ? 'enabled' : 'disabled'} (metadata-only delivery ledger).`);
    if (created) {
      formEl.reset();
      setRuleTriggers(['finding.high_severity']);
      setRuleEnabled(true);
    }
  }

  function previewRuleFromForm(formEl: HTMLFormElement) {
    const form = new FormData(formEl);
    const channel = ruleChannel.trim();
    const triggers = NOTIFICATION_TRIGGERS.filter((trigger) => ruleTriggers.includes(trigger));
    if (triggers.length === 0) {
      setTriggerError('Select at least one rule kind before previewing.');
      setRuleDryRunPreview('');
      return;
    }
    setTriggerError('');
    const validation = validateNotificationDestination(channel, String(form.get('destination_preview') ?? ''));
    if ('error' in validation) {
      setDestinationError(validation.error);
      setRuleDryRunPreview('');
      return;
    }
    setDestinationError('');
    const triggerLabels = triggers.map((trigger) => humanizeNotificationTrigger(trigger)).join(', ');
    const target = channel === 'in_app' ? 'in-app feed' : validation.destination;
    setRuleDryRunPreview(
      `Dry-run: would create ${ruleEnabled ? 'an enabled' : 'a disabled'} ${channel} rule for ${triggers.length} trigger${triggers.length === 1 ? '' : 's'} (${triggerLabels}) to ${target}. No ledger write.`
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
      <PageHeader
        route="notifications"
      />
      <div className="metric-grid three">
        <MetricCard label="Delivered" value={deliveredCount} sub="successful deliveries" icon={CheckCircle2} tone="success" />
        <MetricCard label="Retrying" value={retryItems.length} sub="awaiting retry" icon={Bell} tone={retryItems.length > 0 ? 'warn' : 'muted'} />
        <MetricCard label="DLQ" value={dlqItems.length} sub="dead-letter queue" icon={Siren} tone={dlqItems.length > 0 ? 'danger' : 'muted'} />
      </div>
      <GovernanceFeedbackBanner message={message} error={error} />
      {canWrite ? (
        <Card id="notifications-create-rule">
          <CardHeader>
            <CardTitle>Create notification rule</CardTitle>
            <CardDescription>Pick a delivery mode, the rule kinds (triggers) that fire it, and whether it starts enabled. Metadata-only ledger. External delivery stays opt-in through the server delivery mode.</CardDescription>
          </CardHeader>
          <CardContent>
            <form className="product-form" onSubmit={handleCreateRule} aria-busy={busy === 'create-notification-rule'}>
              <Select
                label="Delivery mode"
                value={ruleChannel}
                options={NOTIFICATION_CHANNEL_OPTIONS.map((option) => ({ value: option.value, label: option.label }))}
                onChange={(value) => { setRuleChannel(value); setDestinationError(''); setRuleDryRunPreview(''); }}
                disabled={busy !== ''}
              />
              <label className="full">
                <span>{ruleChannel === 'in_app' ? 'Destination (optional for in-app)' : 'Destination'}</span>
                <input
                  name="destination_preview"
                  placeholder={ruleChannel === 'email' ? 'alerts@example.com' : ruleChannel === 'in_app' ? 'Delivered to the tenant in-app feed' : 'https://hooks.example.invalid/notifications'}
                  aria-invalid={destinationError ? true : undefined}
                  aria-describedby={destinationError ? 'notification-destination-error' : undefined}
                  disabled={busy !== '' || ruleChannel === 'in_app'}
                />
              </label>
              <fieldset className="full">
                <legend>Rule kinds and filters (triggers)</legend>
                {NOTIFICATION_TRIGGERS.map((trigger) => (
                  <label key={trigger} className="check-row">
                    <input
                      type="checkbox"
                      name="triggers"
                      value={trigger}
                      checked={ruleTriggers.includes(trigger)}
                      onChange={() => toggleRuleTrigger(trigger)}
                      disabled={busy !== ''}
                    />
                    <span>{humanizeNotificationTrigger(trigger)}</span>
                  </label>
                ))}
              </fieldset>
              {triggerError ? (
                <p className="form-banner error full" id="notification-trigger-error" role="alert">
                  {triggerError}
                </p>
              ) : null}
              <label className="check-row full">
                <input
                  type="checkbox"
                  name="enabled"
                  checked={ruleEnabled}
                  onChange={(changeEvent) => setRuleEnabled(changeEvent.target.checked)}
                  disabled={busy !== ''}
                />
                <span>Enabled on creation (uncheck to add the rule in a disabled state)</span>
              </label>
              {destinationError ? (
                <p className="form-banner error full" id="notification-destination-error" role="alert">
                  {destinationError}
                </p>
              ) : null}
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
      <Card>
        <CardHeader>
          <CardTitle>Providers</CardTitle>
          <CardDescription>Delivery-provider health derived from configured rules correlated with recorded delivery attempts.</CardDescription>
        </CardHeader>
        <CardContent>
          <DataTable
            columns={providerColumns}
            items={providerHealthRows}
            getRowId={(item) => item.channel}
            empty={<EmptyState icon={Bell} title="No delivery providers." body="Provider health appears once notification rules are created and delivery attempts are recorded." />}
          />
        </CardContent>
      </Card>
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
          <DeliveryOperationPanel titleId="notification-preview-title" title="Preview" description="Dry-run — no ledger changes">
            <Button size="sm" variant="ghost" loading={busy === 'process-retries-preview'} disabled={!canWrite || (busy !== '' && busy !== 'process-retries-preview')} onClick={() => void processRetries(true)}>Preview due retries</Button>
            <Button size="sm" variant="ghost" loading={busy === 'redrive-dlq-preview'} disabled={!canWrite || dlqItems.length === 0 || (busy !== '' && busy !== 'redrive-dlq-preview')} onClick={() => void redriveDlq(true)}>Preview DLQ redrive</Button>
          </DeliveryOperationPanel>
          <DeliveryOperationPanel titleId="notification-live-title" title="Live" description="Applies changes — confirmation required">
            <Button size="sm" variant="secondary" loading={busy === 'process-retries-run'} disabled={!canWrite || (busy !== '' && busy !== 'process-retries-run')} onClick={() => void processRetries(false)}>Process due retries</Button>
            <Button size="sm" variant="secondary" loading={busy === 'redrive-dlq-run'} disabled={!canWrite || dlqItems.length === 0 || (busy !== '' && busy !== 'redrive-dlq-run')} onClick={() => void redriveDlq(false)}>Redrive DLQ</Button>
          </DeliveryOperationPanel>
        </CardContent>
      </Card>
    </div>
  );
}

export function AuditPage({ data, session }: { data: PortalData; session: Session }) {
  const [filter, setFilter] = useState('');
  const [custodyOnly, setCustodyOnly] = useState(false);
  const [actorFilter, setActorFilter] = useState('all');
  const [actionFilter, setActionFilter] = useState('all');
  const [selectedId, setSelectedId] = useState('');
  const [showRawAuditMetadata, setShowRawAuditMetadata] = useState(false);
  const allowed = canReadAudit(session.role);

  const actorOptions = useMemo(() => {
    const actors = new Set<string>();
    for (const entry of data.audit) {
      const actor = getString(entry, ['actor_role', 'actor_user_id'], 'system');
      if (actor !== '—') actors.add(actor);
    }
    return [
      { value: 'all', label: 'all' },
      ...Array.from(actors).sort().map((actor) => ({ value: actor, label: actor }))
    ];
  }, [data.audit]);

  const actionOptions = useMemo(() => {
    const actions = new Set<string>();
    for (const entry of data.audit) {
      const action = getString(entry, ['action'], '');
      if (action !== '—') actions.add(action);
    }
    return [
      { value: 'all', label: 'all' },
      ...Array.from(actions).sort().map((action) => ({ value: action, label: action }))
    ];
  }, [data.audit]);

  const items = data.audit.filter((entry) => {
    const action = getString(entry, ['action'], '').toLowerCase();
    if (custodyOnly && !action.includes('custody') && !action.includes('export') && !action.includes('report')) {
      return false;
    }
    if (actorFilter !== 'all') {
      const actor = getString(entry, ['actor_role', 'actor_user_id'], 'system');
      if (actor !== actorFilter) return false;
    }
    if (actionFilter !== 'all') {
      const entryAction = getString(entry, ['action'], '');
      if (entryAction !== actionFilter) return false;
    }
    if (!filter.trim()) return true;
    const haystack = `${getString(entry, ['action'])} ${getString(entry, ['resource_type'])} ${getString(entry, ['resource_id'])}`.toLowerCase();
    return haystack.includes(filter.trim().toLowerCase());
  });
  const selectedEntry = items.find((entry) => auditEntrySelectionKey(entry) === selectedId) ?? null;

  useEffect(() => {
    setShowRawAuditMetadata(false);
  }, [selectedId]);

  const filtersActive = custodyOnly || actorFilter !== 'all' || actionFilter !== 'all' || filter.trim() !== '';
  const hasAnyAudit = data.audit.length > 0;

  function clearAuditFilters() {
    setCustodyOnly(false);
    setActorFilter('all');
    setActionFilter('all');
    setFilter('');
  }

  function renderAuditEmpty() {
    if (hasAnyAudit && filtersActive) {
      const custodyIsOnlyFilter = custodyOnly && actorFilter === 'all' && actionFilter === 'all' && !filter.trim();
      if (custodyIsOnlyFilter) {
        return (
          <EmptyState
            icon={ClipboardList}
            title="No custody-sealed entries in this view."
            body="Custody chain filter is on, so this view lists export, report, and custody actions. Turn it off to see all security-relevant actions."
            actionLabel="Show all entries"
            onAction={() => setCustodyOnly(false)}
          />
        );
      }
      return (
        <EmptyState
          icon={ClipboardList}
          title="No audit entries match the current filters."
          body="Adjust or clear the custody, actor, action, or search filters to widen the trail."
          actionLabel="Clear filters"
          onAction={clearAuditFilters}
        />
      );
    }
    return (
      <EmptyState
        icon={ClipboardList}
        title="No audit entries."
        body="Security-relevant actions will appear here after workflow activity."
      />
    );
  }

  function formatAuditCustodyDigest(item: DataItem) {
    const hash = getString(item, ['entry_hash'], '');
    if (!hash || hash === '—') return '—';
    if (hash.length <= 12) return `sha256 ${hash}`;
    return `sha256 ${hash.slice(0, 4)}…${hash.slice(-4)}`;
  }

  const columns: TableColumn<DataItem>[] = [
    { key: 'time', label: 'Time', render: (item) => <span className="mono">{formatDate(item.timestamp ?? item.created_at)}</span> },
    { key: 'actor', label: 'Actor', render: (item) => <span className="mono">{getString(item, ['actor_role', 'actor_user_id'], 'system')}</span> },
    { key: 'action', label: 'Action', render: (item) => <span className="mono">{getString(item, ['action'])}</span> },
    {
      key: 'target',
      label: 'Target',
      render: (item) => {
        const resourceId = getString(item, ['resource_id'], '');
        const target = resourceId !== '—'
          ? resourceId
          : `${getString(item, ['resource_type'], '')} ${getString(item, ['resource_id'], '')}`.trim();
        return <span className="mono">{target || '—'}</span>;
      }
    },
    {
      key: 'custody',
      label: 'Custody',
      render: (item) => {
        const digest = formatAuditCustodyDigest(item);
        const fullHash = getString(item, ['entry_hash'], '');
        if (digest === '—') return <span className="muted">—</span>;
        return (
          <span className="mono muted" title={fullHash !== '—' ? fullHash : undefined}>
            {digest}
          </span>
        );
      }
    }
  ];

  return (
    <div className="content">
      <PageHeader route="audit" description="Append-only, custody-sealed event trail. Toggle custody-chain-only to trace the provenance of any verdict or approval." />
      {!allowed ? (
        <EmptyState icon={ClipboardList} title="Audit access required." body="Switch to owner, admin, SOC, or auditor role to read the tenant audit log." />
      ) : (
        <>
          <div className="audit-filter-toolbar">
            <div className="audit-filter-chips">
              <button
                type="button"
                className={`filter-chip${custodyOnly ? ' is-active' : ''}`}
                aria-pressed={custodyOnly}
                onClick={() => setCustodyOnly((current) => !current)}
              >
                Custody chain
              </button>
              {filtersActive ? (
                <button type="button" className="filter-chip" onClick={clearAuditFilters}>Clear filters</button>
              ) : null}
            </div>
            <div className="audit-filter-fields">
              <Select label="Actor" name="audit_actor" value={actorFilter} options={actorOptions} onChange={setActorFilter} />
              <Select label="Action" name="audit_action" value={actionFilter} options={actionOptions} onChange={setActionFilter} />
            </div>
            <label className="audit-search-pill">
              <Search size={15} aria-hidden="true" />
              <input
                value={filter}
                onChange={(event) => setFilter(event.target.value)}
                placeholder="Search action, resource, or id"
                aria-label="Search audit log by action, resource type, or id"
              />
            </label>
          </div>
          <Card>
            <CardHeader>
              <CardTitle>Events</CardTitle>
            </CardHeader>
            <CardContent>
              <DataTable
                columns={columns}
                items={items.slice().reverse()}
                selectedId={selectedId || null}
                getRowId={(item) => auditEntrySelectionKey(item)}
                getRowProps={(item) => ({
                  onClick: () => setSelectedId(auditEntrySelectionKey(item))
                })}
                empty={renderAuditEmpty()}
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
                <KvField label="Actor">
                  {getString(selectedEntry, ['actor_user_id'])} ({getString(selectedEntry, ['actor_role'])})
                </KvField>
                <KvField label="Resource">{getString(selectedEntry, ['resource_id'])}</KvField>
                <KvField label="Timestamp">{formatDate(selectedEntry.timestamp ?? selectedEntry.created_at)}</KvField>
                {getString(selectedEntry, ['entry_hash'], '') !== '—' ? (
                  <KvField label="Entry hash">
                    <span className="mono">{getString(selectedEntry, ['entry_hash'])}</span>
                  </KvField>
                ) : null}
                {selectedEntry.metadata && typeof selectedEntry.metadata === 'object' && !Array.isArray(selectedEntry.metadata) ? (
                  isFlatMetadataObject(selectedEntry.metadata)
                    ? Object.entries(selectedEntry.metadata).map(([key, value]) => (
                      <KvField key={key} label={key}>{value === null ? 'null' : String(value)}</KvField>
                    ))
                    : (
                      <KvField label="Metadata">
                        <span className="muted">Structured metadata — use View raw for full JSON.</span>
                      </KvField>
                    )
                ) : (
                  <KvField label="Metadata">none</KvField>
                )}
                {selectedEntry.metadata && typeof selectedEntry.metadata === 'object' ? (() => {
                  const metadataJson = JSON.stringify(selectedEntry.metadata, null, 2);
                  const metadataTruncated = metadataJson.length > 1800;
                  const downloadId = getString(selectedEntry, ['id', 'audit_id'], 'audit-entry');
                  return (
                    <ExpandableCodePanel
                      panelId="audit-raw-metadata-panel"
                      expanded={showRawAuditMetadata}
                      onToggle={() => setShowRawAuditMetadata((open) => !open)}
                      toggleLabels={{ show: 'View raw', hide: 'Hide raw metadata' }}
                      code={metadataJson.slice(0, 1800)}
                      truncated={metadataTruncated}
                      downloadLabel="Download full metadata"
                      onDownload={() => downloadJsonFile(`audit-metadata-${downloadId}.json`, selectedEntry.metadata)}
                    />
                  );
                })() : null}
              </CardContent>
            </Card>
          ) : null}
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
      tenant_id: session.tenant_id ?? data.state?.tenant_id ?? 'unknown',
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
      `Release evidence gap ledger — ${session.tenant_id ?? data.state?.tenant_id ?? 'unknown'}`,
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
      <PageHeader
        route="audit"
        title="Release evidence"
        description="Accepted release-evidence kinds, coverage gaps, and the latest staging attestation for this tenant."
      />
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
          {clipboardNotice ? <GovernanceInfoBanner>{clipboardNotice}</GovernanceInfoBanner> : null}
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
                <KvField label="Signoff status">
                  <Badge tone="info">{formatGovernanceStatusLabel(getNestedString(attestation, ['signoff_status']), '—')}</Badge>
                </KvField>
                <KvField label="Production ready">
                  <Badge tone={productionReadyBadgeTone(attestation.production_ready)}>{productionReadyLabel(attestation.production_ready)}</Badge>
                </KvField>
                <KvField label="Profile">{getNestedString(attestation, ['profile'], 'full')}</KvField>
                <KvField label="Checked at">{formatDate(attestation.checked_at ?? attestation.created_at)}</KvField>
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
          <KillSwitchReadOnlyCard
            active={killSwitchActive}
            reason={getString(data.state?.kill_switch as DataItem, ['reason'], 'tenant-scoped emergency stop')}
          />
        </div>
      </div>
    );
  }

  const killSwitchActive = Boolean(data.state?.kill_switch?.active ?? data.state?.kill_switch?.enabled);
  const killSwitchReason = getString(data.state?.kill_switch as DataItem, ['reason'], 'tenant-scoped emergency stop');
  const scheduledCount = data.highScale.filter((item) => SOC_SCHEDULED_STATES.includes(normalizeHighScaleState(item))).length;
  const inReviewCount = data.highScale.filter((item) => SOC_REVIEW_STATES.includes(normalizeHighScaleState(item))).length;
  const runningCount = data.highScale.filter((item) => SOC_RUNNING_STATES.includes(normalizeHighScaleState(item))).length;
  const openFindingsCount = Number(data.state?.open_findings ?? data.findings.length) || 0;
  const goNoGoGates = buildSocGoNoGoGates(data.highScale, { killSwitchActive, runningCount, openFindings: openFindingsCount });
  const providerContactRows = buildProviderContactRows(data.highScale);
  const executionTimeline = buildSocExecutionTimeline(data.highScale);
  const crossTenantHighScale = staffSocSurface ? buildSocCrossTenantRows(data.internalApprovalRequests) : [];
  const activeTenantCount = new Set(
    crossTenantHighScale.map((row) => row.tenantId).filter((id) => id && id !== '—')
  ).size;

  return (
    <div className="content">
      <PageHeader
        route="internal-soc"
        eyebrow="SOC execution plane"
        actions={
          <>
            {staffSocSurface ? <Badge tone="warn">Staff plane</Badge> : null}
          </>
        }
      />
      <div className={killSwitchActive ? 'callout warn' : 'callout info'}>
        {killSwitchActive ? <Siren size={18} aria-hidden="true" /> : <ShieldCheck size={18} aria-hidden="true" />}
        <span>
          {killSwitchActive
            ? 'Kill switch is active — governed high-scale execution is halted for this tenant.'
            : 'Kill switch is clear; governed runs may proceed when approved and scheduled.'}
        </span>
      </div>
      <div className="metric-grid four">
        {staffSocSurface ? (
          <MetricCard label="Active tenants" value={activeTenantCount} sub="with governed requests" icon={Users} tone={activeTenantCount > 0 ? 'info' : 'muted'} />
        ) : (
          <MetricCard label="Queue" value={data.highScale.length} sub="governed requests" icon={ShieldCheck} tone={data.highScale.length > 0 ? 'info' : 'muted'} />
        )}
        <MetricCard label="Scheduled" value={scheduledCount} sub="approved or scheduled" icon={CalendarClock} tone={scheduledCount > 0 ? 'info' : 'muted'} />
        <MetricCard label="In review" value={inReviewCount} sub="awaiting SOC decision" icon={ClipboardList} tone={inReviewCount > 0 ? 'warn' : 'muted'} />
        <MetricCard label="Kill switch" value={killSwitchActive ? 'Armed' : 'Clear'} sub="tenant emergency stop" icon={Siren} tone={killSwitchActive ? 'danger' : 'success'} />
      </div>
      <PageContextSummary>
        {staffSocSurface ? (
          <>
            Cross-tenant <span className="tabular-nums">{crossTenantHighScale.length}</span> governed requests across{' '}
            <span className="tabular-nums">{activeTenantCount}</span> tenants ·{' '}
          </>
        ) : null}
        Queue <span className="tabular-nums">{data.highScale.length}</span> governed requests ·{' '}
        <span className="tabular-nums">{data.state?.open_findings ?? data.findings.length}</span> open findings
      </PageContextSummary>
      <GovernanceFeedbackBanner message={message} error={error} />
      <div className="dash-grid">
        <Card>
          <CardHeader>
            <CardTitle>Kill switch</CardTitle>
            <CardDescription>Tenant-scoped emergency stop for governed high-scale adapter runs.</CardDescription>
          </CardHeader>
          <CardContent className="stack-tight">
            <div className="kv-list">
              <KvField label="Status">
                <Badge tone={killSwitchActive ? 'danger' : 'success'}>{killSwitchActive ? 'Armed' : 'Clear'}</Badge>
              </KvField>
              <KvField label="Reason">{killSwitchReason}</KvField>
            </div>
            <div className="row-actions">
              <Button size="sm" variant="danger" loading={busy === 'kill-on'} disabled={busy !== '' && busy !== 'kill-on'} onClick={() => void setKillSwitch(true)}>Activate</Button>
              <Button size="sm" variant="secondary" loading={busy === 'kill-off'} disabled={busy !== '' && busy !== 'kill-off'} onClick={() => void setKillSwitch(false)}>Clear</Button>
            </div>
            <div className="stack-tight">
              <span className="muted text-xs">Validated 7-step arming sequence — custody-recorded on exercise.</span>
              <div className="timeline-list">
                {KILL_SWITCH_VALIDATED_SEQUENCE.map((step, index) => (
                  <div key={step}>
                    <span>{index + 1}</span>
                    <div>
                      <strong className="mono">{step}</strong>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Go / No-Go</CardTitle>
            <CardDescription>Pre-flight gates computed from the current governed queue and tenant safety state.</CardDescription>
          </CardHeader>
          <CardContent className="kv-list">
            {goNoGoGates.map((gate) => (
              <KvField key={gate.key} label={gate.label}>
                <Badge tone={gate.tone}>{gate.status}</Badge>
              </KvField>
            ))}
          </CardContent>
        </Card>
      </div>
      {staffSocSurface ? (
        <Card>
          <CardHeader>
            <CardTitle>Cross-tenant execution</CardTitle>
            <CardDescription>Governed high-scale requests across all customer tenants, sourced from the staff approval queue. Open a request for the full lifecycle workspace.</CardDescription>
          </CardHeader>
          <CardContent>
            <DataTable
              columns={socCrossTenantColumns}
              items={crossTenantHighScale}
              getRowId={(item) => item.id}
              empty={<EmptyState icon={Users} title="No cross-tenant high-scale requests." body="Governed requests across tenants appear here after intake and authorization-pack review." />}
            />
          </CardContent>
        </Card>
      ) : null}
      <Card>
        <CardHeader>
          <CardTitle>High-scale queue</CardTitle>
          <CardDescription>{staffSocSurface
            ? 'Governed requests for the active execution-tenant context. Open a request for the full lifecycle workspace; quick approve is available when the authorization pack is accepted.'
            : 'Open a request for the full lifecycle workspace. Quick approve is available here only when the authorization pack is accepted.'}</CardDescription>
        </CardHeader>
        <CardContent aria-busy={queueRefreshing}>
          <DataTable
            columns={requestColumns}
            items={data.highScale}
            empty={queueRefreshing ? (
              <TableQueueSkeleton />
            ) : (
              <EmptyState icon={ShieldCheck} title="No high-scale requests." body="Customer requests appear here after intake and authorization-pack review." />
            )}
          />
        </CardContent>
      </Card>
      <div className="split">
        <Card>
          <CardHeader>
            <CardTitle>Execution timeline</CardTitle>
            <CardDescription>Lifecycle events across governed requests, newest first.</CardDescription>
          </CardHeader>
          <CardContent>
            {executionTimeline.length === 0 ? (
              <EmptyState icon={Activity} title="No execution timeline yet." body="Lifecycle events appear after SOC approval, scheduling, or execution actions." />
            ) : (
              <div className="timeline-list">
                {executionTimeline.map((event, index) => (
                  <div key={event.key}>
                    <span>{index + 1}</span>
                    <div>
                      <strong>{formatGovernanceStatusLabel(event.action)} · <span className="mono">{event.requestId}</span></strong>
                      <p>{formatDate(event.at)} · {event.by}</p>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Provider contacts</CardTitle>
            <CardDescription>Provider and emergency contacts declared on governed high-scale requests.</CardDescription>
          </CardHeader>
          <CardContent>
            <DataTable
              columns={providerContactColumns}
              items={providerContactRows}
              getRowId={(item) => item.id}
              empty={<EmptyState icon={Users} title="No provider or emergency contacts." body="Contacts appear after authorization-pack intake declares provider and emergency contacts." />}
            />
          </CardContent>
        </Card>
      </div>
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
                <AnchorButton size="sm" variant="ghost" href={buildDetailHref('queue-detail', lastActionRequestId)}>Open request detail</AnchorButton>
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
