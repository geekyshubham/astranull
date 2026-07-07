import { useEffect, useMemo, useState, type FormEvent, type ReactNode } from 'react';
import {
  Activity,
  Bot,
  CheckCircle2,
  ClipboardList,
  Clock3,
  FileCheck2,
  KeyRound,
  ListChecks,
  Network,
  RadioTower,
  ScanSearch,
  ShieldCheck,
  Siren,
  Target,
  TriangleAlert,
  ChevronDown
} from 'lucide-react';
import { Badge } from '../components/ui/badge';
import { AnchorButton, Button } from '../components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { EmptyState } from '../components/ui/empty-state';
import { Progress } from '../components/ui/progress';
import { Select } from '../components/ui/select';
import { DataTable, type TableColumn } from '../components/ui/table';
import { Tabs } from '../components/ui/tabs';
import { AgentInstallMatrix } from '../components/agents/agent-install-matrix';
import { FindingsListView } from '../components/findings/findings-list';
import { RunsPageHeadActions, RunsSocGatePanel } from '../components/runs/runs-soc-gate';
import { ConfirmModal, formatMutationSuccessMessage, renderFriendlyEmptyState } from '../lib/crud-ui';
import { buildEvidenceCustodyManifest } from '../lib/custody';
import { buildEvidenceChainExport, summarizeEvidenceExport } from '../lib/evidence-export';
import {
  computeFindingKpis,
  filterFindingsByTab,
  findingSlaDueAt,
  findingsListSubtitle,
  groupedFindingsBadgeLabel,
  groupFindingsByTargetGroup,
  groupFindingsByVector,
  isFindingSlaBreach,
  type FindingTabId
} from '../lib/findings-helpers';
import {
  agentHeartbeatFreshness,
  filterAgentAuditEntries,
  formatAgentCapabilities,
  formatAgentHealth,
  formatAgentPlacement,
  formatHeartbeatFreshness,
  formatPlacementOverview,
  formatPlacementStatus,
  placementStatusHint,
} from '../lib/agent-helpers';
import { formatRequiredSetupList } from '../lib/capability-probe-labels';
import {
  CHECK_SAFETY_SCOPE_TABS,
  countChecksBySafetyScope,
  filterChecksCatalog,
  type CheckFamilyTabId,
  type CheckSafetyScopeId
} from '../lib/checks-helpers';

import { requestJson } from '../lib/api';

import { routeTabs } from '../lib/prototype-manifest';
import { buildDetailHref } from '../lib/route-params';
import type { DataItem, PortalConfig, PortalData, RouteId, Session } from '../lib/types';
import {
  DRIFT_EVENT_STATUSES,
  VALIDATION_PLAN_SCENARIOS,
  WAF_POSTURE_TABS,
  computeWafAssetPassRate,
  formatWafPassRateDisplay,
  formatWafRuleHealthDisplay,
  retestForDriftEvent,
  roadmapTierIds,
  roadmapTierMeta,
  roadmapTotalItems
} from '../lib/waf-helpers';
import { formatDate, scoreTone } from '../lib/utils';
import type { ProgressTone } from '../components/ui/progress';
import { MetricCard, PageHeader } from './page-components';

const WAF_POSTURE_SURFACE_TABS = [
  ...WAF_POSTURE_TABS,
  { id: 'operations', label: 'Operations' }
] as const;

type WafPostureSurfaceTabId = (typeof WAF_POSTURE_SURFACE_TABS)[number]['id'];

function getString(item: DataItem | null | undefined, keys: string[], fallback = '—') {
  if (!item) return fallback;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
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

const VECTOR_FAMILY_ORDER = [
  'origin',
  'path',
  'l3_l4',
  'dns',
  'l7',
  'waf',
  'tls',
  'protocol',
  'operations',
  'high_scale'
] as const;

const VECTOR_FAMILY_LABELS: Record<string, string> = {
  origin: 'Origin',
  path: 'Path',
  l3_l4: 'L3/L4',
  dns: 'DNS',
  l7: 'L7/API',
  waf: 'WAF',
  tls: 'TLS',
  protocol: 'Protocol',
  operations: 'Operations',
  high_scale: 'High-scale'
};

function formatVectorFamilyLabel(family: string) {
  return VECTOR_FAMILY_LABELS[family] ?? family.replace(/_/g, ' ');
}

function formatSafetyClassLabel(safetyClass: string) {
  if (safetyClass === 'safe') return 'Customer-runnable';
  if (safetyClass === 'soc_gated') return 'SOC request-only';
  return safetyClass.replace(/_/g, ' ');
}

function formatRunStatusLabel(status: string) {
  const labels: Record<string, string> = {
    planned: 'Planned',
    running: 'Running',
    collecting: 'Collecting',
    verdicted: 'Verdicted',
    cancelled: 'Cancelled',
    failed: 'Failed'
  };
  return labels[status] ?? status.replace(/_/g, ' ');
}

function runStatusBadgeTone(status: string): 'default' | 'success' | 'warn' | 'danger' | 'info' | 'muted' {
  if (status === 'verdicted') return 'success';
  if (status === 'running' || status === 'collecting') return 'info';
  if (status === 'cancelled' || status === 'failed') return 'danger';
  if (status === 'planned') return 'muted';
  return 'warn';
}

type BadgeTone = 'default' | 'success' | 'warn' | 'danger' | 'info' | 'muted';

function verdictBadgeTone(verdict: string): BadgeTone {
  const normalized = verdict.toLowerCase();
  if (normalized === 'pass' || normalized === 'ready') return 'success';
  if (normalized === 'fail' || normalized === 'failed') return 'danger';
  if (normalized === 'partial' || normalized === 'inconclusive') return 'warn';
  if (normalized === 'pending' || normalized === '—' || !normalized) return 'muted';
  return 'info';
}

function formatVerdictLabel(verdict: string) {
  const normalized = verdict.toLowerCase();
  const labels: Record<string, string> = {
    pass: 'Pass',
    fail: 'Fail',
    partial: 'Partial',
    pending: 'Pending',
    inconclusive: 'Inconclusive',
    ready: 'Ready',
    failed: 'Failed'
  };
  return labels[normalized] ?? verdict.replace(/_/g, ' ');
}

function findingStatusBadgeTone(status: string): BadgeTone {
  const normalized = status.toLowerCase();
  if (normalized === 'open') return 'warn';
  if (normalized === 'closed' || normalized === 'resolved') return 'success';
  if (normalized === 'accepted_risk') return 'info';
  return 'muted';
}

function formatFindingStatusLabel(status: string) {
  const labels: Record<string, string> = {
    open: 'Open',
    closed: 'Closed',
    accepted_risk: 'Accepted risk',
    resolved: 'Resolved'
  };
  return labels[status.toLowerCase()] ?? status.replace(/_/g, ' ');
}

function wafAssetStatusBadgeTone(status: string): BadgeTone {
  const normalized = status.toLowerCase();
  if (normalized === 'protected') return 'success';
  if (normalized === 'underprotected' || normalized === 'unprotected') return 'danger';
  if (normalized === 'unknown') return 'warn';
  if (normalized === 'excluded') return 'muted';
  return 'warn';
}

function coverageProgressTone(status: string, percent: number): ProgressTone {
  if (status === 'protected') {
    if (percent >= 80) return 'success';
    if (percent >= 50) return 'warn';
    return 'danger';
  }
  if (status === 'excluded') return 'accent';
  if (percent > 0) return 'warn';
  return 'accent';
}

function cveStageBadgeTone(stage: string): BadgeTone {
  const normalized = stage.toLowerCase();
  if (normalized === 'resolved' || normalized === 'closed') return 'success';
  if (normalized === 'triaged' || normalized === 'validated') return 'info';
  if (normalized === 'blocked' || normalized === 'exploited') return 'danger';
  return 'warn';
}

function supplyChainStateBadgeTone(state: string): BadgeTone {
  const normalized = state.toLowerCase();
  if (normalized === 'confirmed') return 'danger';
  if (normalized === 'remediated' || normalized === 'resolved') return 'success';
  if (normalized === 'suspected' || normalized === 'open') return 'warn';
  if (normalized === 'dismissed') return 'muted';
  return 'info';
}

function placementStatusBadgeTone(status: string): BadgeTone {
  if (status === 'proven') return 'success';
  if (status === 'needs_baseline') return 'warn';
  if (status === 'missing_agent' || status === 'misplaced_risk') return 'danger';
  return 'muted';
}

function runDisplayLabelForId(checks: DataItem[], runs: DataItem[], runId: string) {
  if (!runId) return '—';
  const run = runs.find((entry) => getString(entry, ['id']) === runId);
  if (!run) return runId;
  const titled = getString(run, ['name', 'title'], '');
  if (titled) return titled;
  return checkDisplayName(checks, getString(run, ['check_id']));
}

function TableSkeleton({ rows = 4, label = 'Loading' }: { rows?: number; label?: string }) {
  return (
    <div className="stack-tight" aria-busy="true" aria-label={label}>
      {Array.from({ length: rows }, (_, index) => (
        <div key={index} className="skeleton skeleton-row" />
      ))}
    </div>
  );
}

function formatCoverageStatusLabel(status: string) {
  const labels: Record<string, string> = {
    protected: 'Protected',
    underprotected: 'Underprotected',
    unprotected: 'Unprotected',
    unknown: 'Unknown',
    excluded: 'Excluded'
  };
  return labels[status] ?? status.replace(/_/g, ' ');
}

function coverageBucketBadgeTone(status: string, count: number, percent: number): BadgeTone {
  if (status === 'protected') return scoreTone(percent);
  if (status === 'underprotected') return count > 0 ? 'warn' : 'muted';
  if (status === 'unprotected') return count > 0 ? 'danger' : 'muted';
  if (status === 'unknown') return count > 0 ? 'muted' : 'muted';
  if (status === 'excluded') return 'muted';
  return count > 0 ? 'warn' : 'muted';
}

function discoveryEntityStateBadgeTone(state: string): BadgeTone {
  const normalized = state.toLowerCase();
  if (normalized === 'approved' || normalized === 'active' || normalized === 'entity') return 'success';
  if (normalized === 'rejected') return 'danger';
  return 'warn';
}

function scrollElementIntoView(element: HTMLElement | null, block: ScrollLogicalPosition = 'start') {
  if (!element) return;
  const reduced = typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  element.scrollIntoView({ behavior: reduced ? 'auto' : 'smooth', block });
}

function coverageStatusHint(status: string) {
  const hints: Record<string, string> = {
    protected: 'Asset meets declared WAF protection expectations.',
    underprotected: 'Partial coverage or weak rule effectiveness.',
    unprotected: 'No effective WAF coverage on declared scope.',
    unknown: 'Insufficient evidence to classify coverage.',
    excluded: 'Out of scope for WAF posture scoring.'
  };
  return hints[status] ?? '';
}

function checkDisplayName(checks: DataItem[], checkId: string, runId = '') {
  const check = checks.find((entry) => getString(entry, ['check_id']) === checkId);
  const name = getString(check ?? {}, ['name'], checkId);
  return name || runId || 'View run';
}

function truncateText(text: string, max = 72) {
  if (text.length <= max) return text;
  return `${text.slice(0, max).trimEnd()}…`;
}

function formatSnakeLabel(value: string, fallback = '—') {
  const trimmed = value.trim();
  if (!trimmed) return fallback;
  return trimmed
    .split('_')
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
    .join(' ');
}

function formatSeverityLabel(severity: string) {
  return formatSnakeLabel(severity, '—');
}

const VALIDATION_SCENARIO_LABELS: Record<string, string> = {
  marker: 'WAF marker probe',
  fingerprint: 'Fingerprint validation',
  origin_bypass: 'Origin bypass check'
};

const REMEDIATION_STATUS_LABELS: Record<string, string> = {
  open: 'Open',
  ticketed: 'Ticketed',
  remediation_started: 'Remediation started',
  retest_pending: 'Retest pending',
  resolved: 'Resolved',
  accepted_risk: 'Accepted risk'
};

function formatRemediationStatusLabel(status: string) {
  return REMEDIATION_STATUS_LABELS[status] ?? formatSnakeLabel(status);
}

function formatSupplyChainStateLabel(state: string) {
  const labels: Record<string, string> = {
    suspected: 'Suspected',
    confirmed: 'Confirmed',
    remediated: 'Remediated',
    resolved: 'Resolved',
    dismissed: 'Dismissed',
    open: 'Open'
  };
  return labels[state.toLowerCase()] ?? formatSnakeLabel(state);
}

function formatDiscoveryStateLabel(state: string) {
  const labels: Record<string, string> = {
    entity: 'Entity',
    approved: 'Approved',
    approved_target: 'Approved target',
    rejected: 'Rejected',
    pending: 'Pending review',
    candidate: 'Candidate'
  };
  return labels[state.toLowerCase()] ?? formatSnakeLabel(state);
}

const DISCOVERY_REJECT_REASONS = [
  { id: 'not_in_scope', label: 'Not in scope' },
  { id: 'duplicate', label: 'Duplicate' },
  { id: 'low_confidence', label: 'Low confidence' }
] as const;

const REMEDIATION_CHANNEL_LABELS: Record<string, string> = {
  webhook: 'Webhook connector',
  jira: 'Jira',
  servicenow: 'ServiceNow',
  slack: 'Slack',
  siem: 'SIEM export'
};

const SUPPLY_CHAIN_EXPOSURE_TYPES = [
  { id: 'dangling_cname', label: 'Dangling CNAME', hint: 'DNS CNAME points to an unclaimed or expired destination.' },
  { id: 'subdomain_takeover', label: 'Subdomain takeover risk', hint: 'Host may be claimable via a third-party service.' },
  { id: 'orphan_record', label: 'Orphan DNS record', hint: 'Record exists without a matching declared asset.' },
  { id: 'customer_declared', label: 'Customer-declared exposure', hint: 'Manually declared supply-chain concern.' }
] as const;

const AGENT_SURFACE_TABS = [
  { id: 'fleet', label: 'Fleet' },
  { id: 'install', label: 'Install' },
  { id: 'operations', label: 'Operations' }
] as const;

function sortVectorFamilies(families: string[]) {
  return [...families].sort((a, b) => {
    const left = VECTOR_FAMILY_ORDER.indexOf(a as (typeof VECTOR_FAMILY_ORDER)[number]);
    const right = VECTOR_FAMILY_ORDER.indexOf(b as (typeof VECTOR_FAMILY_ORDER)[number]);
    if (left === -1 && right === -1) return a.localeCompare(b);
    if (left === -1) return 1;
    if (right === -1) return -1;
    return left - right;
  });
}

function getNumber(item: DataItem, keys: string[], fallback = 0) {
  for (const key of keys) {
    const value = item[key];
    if (typeof value === 'number' && Number.isFinite(value)) return value;
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

function getNestedNumber(item: DataItem | null | undefined, path: string[], fallback = 0) {
  let current: unknown = item;
  for (const key of path) {
    if (!current || typeof current !== 'object' || Array.isArray(current)) return fallback;
    current = (current as DataItem)[key];
  }
  return typeof current === 'number' && Number.isFinite(current) ? current : fallback;
}

function featureEnabled(data: PortalData, key: 'waf_posture' | 'external_discovery') {
  const features = data.deploymentFeatures as { waf_posture?: boolean; external_discovery?: boolean } | null;
  return features?.[key] === true;
}

const ACTION_ITEM_STATUSES = ['open', 'ticketed', 'remediation_started', 'retest_pending', 'resolved', 'accepted_risk'] as const;
const CLOSED_ACTION_ITEM_STATUSES = new Set(['resolved', 'accepted_risk']);
const REMEDIATION_CHANNELS = ['webhook', 'jira', 'servicenow', 'slack', 'siem'] as const;

async function runAction<T>(
  setBusy: (v: string) => void,
  setError: (v: string) => void,
  setMessage: (v: string) => void,
  label: string,
  action: () => Promise<T>,
  success: string,
  onRefresh?: () => Promise<void>
) {
  setBusy(label);
  setError('');
  setMessage('');
  try {
    const result = await action();
    setMessage(success);
    if (onRefresh) await onRefresh();
    return result;
  } catch (err) {
    const payload = (err as Error & { payload?: unknown }).payload as { error?: string; message?: string } | undefined;
    setError(payload?.message ?? payload?.error ?? (err instanceof Error ? err.message : 'Action failed.'));
    return null;
  } finally {
    setBusy('');
  }
}

export function AgentsPage({
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
  const [tokenSecret, setTokenSecret] = useState('');
  const [agentTab, setAgentTab] = useState('fleet');

  const [placementReviews, setPlacementReviews] = useState<DataItem | null>(null);
  const [updateReleases, setUpdateReleases] = useState<DataItem[]>([]);
  const [trustKeys, setTrustKeys] = useState<DataItem[]>([]);
  const [auxLoading, setAuxLoading] = useState(false);
  const onlineAgents = data.agents.filter((agent) => getString(agent, ['status']) === 'online').length;
  const firstGroup = data.targetGroups[0] ?? null;
  const agentTabOptions = AGENT_SURFACE_TABS.map((tab) => ({ id: tab.id, label: tab.label }));
  const placementSummary = getNestedItem(placementReviews, ['summary']);
  const placementReviewRows = Array.isArray(placementReviews?.reviews) ? placementReviews.reviews as DataItem[] : [];
  const agentAuditEntries = filterAgentAuditEntries(data.audit);
  const placementReviewColumns: TableColumn<DataItem>[] = [
    {
      key: 'group',
      label: 'Target group',
      render: (review) => getString(review, ['target_group_name', 'target_group_id'], 'group')
    },
    {
      key: 'status',
      label: 'Placement status',
      render: (review) => {
        const status = getString(review, ['status'], 'unknown');
        const hint = placementStatusHint(status);
        return <Badge tone={placementStatusBadgeTone(status)} title={hint || undefined}>{formatPlacementStatus(status)}</Badge>;
      }
    },
    {
      key: 'summary',
      label: 'Summary',
      render: (review) => getString(review, ['summary'], '—')
    }
  ];

  const fleetColumns: TableColumn<DataItem>[] = [
    {
      key: 'id',
      label: 'ID',
      render: (item) => (
        <code className="traffic-path-label" title={getString(item, ['id'])}>{getString(item, ['id'])}</code>
      )
    },
    {
      key: 'health',
      label: 'Health',
      render: (item) => {
        const health = formatAgentHealth(item);
        const tone = health === 'online' ? 'success' : health === 'revoked' ? 'danger' : 'muted';
        return <Badge tone={tone}>{health}</Badge>;
      }
    },
    { key: 'version', label: 'Version', render: (item) => getString(item, ['version', 'agent_version'], '—') },
    { key: 'placement', label: 'Placement', render: (item) => formatAgentPlacement(item) },
    { key: 'last_heartbeat', label: 'Last heartbeat', render: (item) => formatDate(item.last_heartbeat_at) },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        const revoked = getString(item, ['status']) === 'revoked';
        return (
          <div className="row-actions">
            <AnchorButton size="sm" variant="secondary" href={buildDetailHref('agent-detail', id)}>Detail</AnchorButton>
            {!revoked ? <Button size="sm" variant="danger" loading={busy === `revoke-${id}`} disabled={busy !== ''} aria-label={`Revoke agent ${getString(item, ['hostname', 'name', 'id'], id)}`} onClick={() => void revokeAgent(id)}>Revoke</Button> : null}
          </div>
        );
      }
    }
  ];

  const healthColumns: TableColumn<DataItem>[] = [
    { key: 'name', label: 'Agent', render: (item) => getString(item, ['hostname', 'name', 'id']) },
    { key: 'status', label: 'Status', render: (item) => <Badge tone={getString(item, ['status']) === 'online' ? 'success' : 'muted'}>{formatAgentHealth(item)}</Badge> },
    { key: 'freshness', label: 'Heartbeat', render: (item) => formatHeartbeatFreshness(agentHeartbeatFreshness(item)) },
    { key: 'heartbeat', label: 'Last heartbeat', render: (item) => formatDate(item.last_heartbeat_at) },
    { key: 'version', label: 'Version', render: (item) => getString(item, ['version'], '—') },
    { key: 'fingerprint', label: 'Gateway fingerprint', render: (item) => <code>{getString(item, ['fingerprint'], 'not registered')}</code> }
  ];

  const capabilityColumns: TableColumn<DataItem>[] = [
    { key: 'name', label: 'Agent', render: (item) => getString(item, ['hostname', 'name', 'id']) },
    { key: 'capabilities', label: 'Observation modes', render: (item) => formatAgentCapabilities(item) },
    { key: 'environment', label: 'Environment', render: (item) => getString(item, ['environment_id'], 'tenant scope') },
    { key: 'group', label: 'Target group', render: (item) => getString(item, ['target_group_id'], 'unbound') }
  ];

  const releaseColumns: TableColumn<DataItem>[] = [
    { key: 'version', label: 'Version', render: (item) => getString(item, ['version']) },
    { key: 'channel', label: 'Channel', render: (item) => getString(item, ['channel'], 'stable') },
    { key: 'state', label: 'State', render: (item) => <Badge tone="info">{getString(item, ['state'], 'active')}</Badge> },
    { key: 'rollout', label: 'Rollout', render: (item) => `${getNestedNumber(item, ['rollout', 'percentage'], 100)}%` },
    { key: 'created', label: 'Created', render: (item) => formatDate(item.created_at) },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        const canRollback = Boolean(item.rollback) && getString(item, ['state']) !== 'rollback_requested';
        return canRollback ? (
          <Button size="sm" variant="secondary" loading={busy === `rollback-${id}`} disabled={busy !== ''} aria-label={`Request rollback for release ${getString(item, ['version'], id)}`} onClick={() => void requestReleaseRollback(id)}>Request rollback</Button>
        ) : <span className="muted">—</span>;
      }
    }
  ];

  const trustKeyColumns: TableColumn<DataItem>[] = [
    { key: 'name', label: 'Name', render: (item) => getString(item, ['name']) },
    { key: 'fingerprint', label: 'Fingerprint', render: (item) => <code>{getString(item, ['fingerprint_sha256'])}</code> },
    {
      key: 'status',
      label: 'Status',
      render: (item) => {
        const status = getString(item, ['status']);
        return <Badge tone={status === 'active' ? 'success' : 'muted'}>{formatSnakeLabel(status)}</Badge>;
      }
    },
    { key: 'created', label: 'Created', render: (item) => formatDate(item.created_at) },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        const active = getString(item, ['status']) === 'active';
        return active ? (
          <Button size="sm" variant="danger" loading={busy === `trust-revoke-${id}`} disabled={busy !== ''} aria-label={`Revoke trust key ${getString(item, ['name'], id)}`} onClick={() => void revokeTrustKey(id)}>Revoke</Button>
        ) : <span className="muted">revoked</span>;
      }
    }
  ];

  const logColumns: TableColumn<DataItem>[] = [
    { key: 'action', label: 'Action', render: (item) => getString(item, ['action']) },
    { key: 'resource', label: 'Resource', render: (item) => `${getString(item, ['resource_type'])}:${getString(item, ['resource_id'])}` },
    { key: 'actor', label: 'Actor', render: (item) => getString(item, ['actor_role'], 'system') },
    { key: 'when', label: 'Recorded', render: (item) => formatDate(item.created_at ?? item.timestamp) }
  ];

  useEffect(() => {
    if (!['operations', 'install', 'fleet'].includes(agentTab)) return undefined;
    let cancelled = false;
    setAuxLoading(true);
    requestJson(config, session, '/v1/placement/reviews')
      .then((payload) => {
        if (!cancelled) setPlacementReviews(payload as DataItem);
      })
      .catch(() => {
        if (!cancelled) setPlacementReviews(null);
      })
      .finally(() => {
        if (!cancelled) setAuxLoading(false);
      });
    return () => { cancelled = true; };
  }, [agentTab, config, session]);

  useEffect(() => {
    if (agentTab !== 'operations') return undefined;
    let cancelled = false;
    setAuxLoading(true);
    Promise.all([
      requestJson(config, session, '/v1/agent-updates'),
      requestJson(config, session, '/v1/agent-update-trust-keys')
    ])
      .then(([releasesPayload, trustPayload]) => {
        if (cancelled) return;
        const releases = Array.isArray((releasesPayload as { items?: unknown }).items)
          ? (releasesPayload as { items: DataItem[] }).items
          : [];
        const keys = Array.isArray((trustPayload as { items?: unknown }).items)
          ? (trustPayload as { items: DataItem[] }).items
          : [];
        setUpdateReleases(releases);
        setTrustKeys(keys);
      })
      .catch(() => {
        if (!cancelled) {
          setUpdateReleases([]);
          setTrustKeys([]);
        }
      })
      .finally(() => {
        if (!cancelled) setAuxLoading(false);
      });
    return () => { cancelled = true; };
  }, [agentTab, config, session]);

  async function createBootstrapToken() {
    const body: DataItem = {
      name: 'agent-install',
      expires_in_minutes: 60,
      max_registrations: 1
    };
    const environmentId = getString(firstGroup, ['environment_id'], '');
    const targetGroupId = getString(firstGroup, ['id'], '');
    if (environmentId) body.environment_id = environmentId;
    if (targetGroupId) body.target_group_id = targetGroupId;
    const created = await runAction(setBusy, setError, setMessage, 'create-bootstrap-token', () => requestJson(config, session, '/v1/bootstrap-tokens', {
      method: 'POST',
      body
    }), 'Bootstrap token created. Copy the one-time secret now.', onRefresh);
    const secret = getString(created as DataItem, ['secret'], getNestedString(created as DataItem, ['token', 'secret'], ''));
    if (secret) setTokenSecret(secret);
  }

  async function revokeAgent(id: string) {
    if (!id) return;
    if (!window.confirm('Revoke this agent\'s credentials? It will stop reporting until re-registered.')) return;
    await runAction(setBusy, setError, setMessage, `revoke-${id}`, () => requestJson(config, session, `/v1/agents/${id}/revoke`, { method: 'POST' }), 'Agent revoked. Heartbeat and jobs will be rejected.', onRefresh);
  }

  async function requestReleaseRollback(releaseId: string) {
    if (!releaseId) return;
    if (!window.confirm('Request rollback for this agent release? Eligible agents will move to the previous signed version.')) return;
    await runAction(setBusy, setError, setMessage, `rollback-${releaseId}`, () => requestJson(config, session, `/v1/agent-updates/${releaseId}/rollback`, { method: 'POST' }), 'Rollback requested for eligible agents.', async () => {
      const payload = await requestJson(config, session, '/v1/agent-updates') as { items?: DataItem[] };
      setUpdateReleases(Array.isArray(payload.items) ? payload.items : []);
      await onRefresh();
    });
  }

  async function revokeTrustKey(keyId: string) {
    if (!keyId) return;
    if (!window.confirm('Revoke this agent update trust key? Agents will reject updates signed with it.')) return;
    await runAction(setBusy, setError, setMessage, `trust-revoke-${keyId}`, () => requestJson(config, session, `/v1/agent-update-trust-keys/${keyId}/revoke`, { method: 'POST' }), 'Trust key revoked.', async () => {
      const payload = await requestJson(config, session, '/v1/agent-update-trust-keys') as { items?: DataItem[] };
      setTrustKeys(Array.isArray(payload.items) ? payload.items : []);
      await onRefresh();
    });
  }

  async function handleAddTrustKey(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    await runAction(setBusy, setError, setMessage, 'add-trust-key', () => requestJson(config, session, '/v1/agent-update-trust-keys', {
      method: 'POST',
      body: {
        name: String(form.get('name') ?? '').trim() || 'agent update signing key',
        public_key_der_base64: String(form.get('public_key_der_base64') ?? '').trim()
      }
    }), 'Trust key registered.', async () => {
      const payload = await requestJson(config, session, '/v1/agent-update-trust-keys') as { items?: DataItem[] };
      setTrustKeys(Array.isArray(payload.items) ? payload.items : []);
      event.currentTarget.reset();
      await onRefresh();
    });
  }

  return (
    <div className="content">
      <PageHeader route="agents" />
      <div className="metric-grid three">
        <MetricCard label="Declared groups" value={data.targetGroups.length} sub="Manual or API import only" icon={Target} tone="info" />
        <MetricCard label="Agents" value={data.agents.length} sub="Outbound-only control channel" icon={Bot} tone="success" />
        <MetricCard label="Online agents" value={onlineAgents} sub="Current heartbeat status" icon={RadioTower} tone={onlineAgents > 0 ? 'success' : 'muted'} />
      </div>
      {(message || error) && <div className={error ? 'form-banner error' : 'form-banner'}>{error || message}</div>}
      <Tabs value={agentTab} options={agentTabOptions} onChange={setAgentTab} className="tabs-wrap" />
      {agentTab === 'install' ? (
        <AgentInstallMatrix
          data={data}
          tokenSecret={tokenSecret}
          onCreateToken={() => void createBootstrapToken()}
          createBusy={busy === 'create-bootstrap-token'}
          actionsDisabled={busy !== ''}
        />
      ) : null}
      {agentTab === 'fleet' ? (
        <Card>
          <CardHeader>
            <CardTitle>Agent fleet</CardTitle>
            <CardDescription>Registered outbound agents. Revoke invalidates credentials immediately.</CardDescription>
          </CardHeader>
          <CardContent aria-busy={auxLoading || undefined}>
            {auxLoading ? <TableSkeleton rows={3} label="Refreshing agent fleet" /> : null}
            {!auxLoading ? <DataTable
              columns={fleetColumns}
              items={data.agents}
              empty={(
                <EmptyState
                  icon={Bot}
                  title="No agents have registered yet."
                  body="Create a bootstrap token on the Install tab, then install an outbound-only agent."
                  actionLabel="Go to Install"
                  onAction={() => setAgentTab('install')}
                />
              )}
            /> : null}
          </CardContent>
        </Card>
      ) : null}
      {agentTab === 'operations' ? (
        <div className="stack">
          <Card>
            <CardHeader>
              <CardTitle>Agent health</CardTitle>
              <CardDescription>Heartbeat freshness and gateway trust metadata for each registered agent.</CardDescription>
            </CardHeader>
            <CardContent>
              {auxLoading ? <TableSkeleton rows={3} label="Loading agent health" /> : null}
              {!auxLoading ? <DataTable
                columns={healthColumns}
                items={data.agents}
                empty={<EmptyState icon={Activity} title="No agents to monitor." body="Register an agent to see heartbeat freshness and version posture." />}
              /> : null}
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Agent coverage by target group</CardTitle>
              <CardDescription>
                A target group is a set of URLs or hosts you want to test together. Each group needs its own agent on the traffic path.
              </CardDescription>
            </CardHeader>
            <CardContent>
              {auxLoading ? <TableSkeleton rows={3} label="Loading placement reviews" /> : null}
              {!auxLoading && placementReviewRows.length === 0 ? (
                <EmptyState icon={Target} title="No placement reviews yet." body="Declare target groups and register agents to compute placement confidence." />
              ) : null}
              {!auxLoading && placementReviewRows.length > 0 ? (
                <DataTable
                  columns={placementReviewColumns}
                  items={placementReviewRows}
                  empty={<EmptyState icon={Target} title="No placement reviews yet." body="Declare target groups and register agents to compute placement confidence." />}
                />
              ) : null}
              {placementSummary ? (
                <div className="stack-tight">
                  <p className="muted">{formatPlacementOverview(placementSummary)}</p>
                </div>
              ) : null}
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Agent capabilities</CardTitle>
              <CardDescription>Observation modes reported on registration and each heartbeat.</CardDescription>
            </CardHeader>
            <CardContent>
              <DataTable
                columns={capabilityColumns}
                items={data.agents}
                empty={<EmptyState icon={ListChecks} title="No capability reports yet." body="Capabilities appear after the first agent heartbeat." />}
              />
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Agent audit trail</CardTitle>
              <CardDescription>Metadata-only lifecycle events for agent registration, heartbeat, revoke, and updates—not host operational logs.</CardDescription>
            </CardHeader>
            <CardContent>
              <DataTable
                columns={logColumns}
                items={agentAuditEntries}
                empty={<EmptyState icon={ClipboardList} title="No agent audit events yet." body="Registration, heartbeat, revoke, and update actions appear here after agents connect." />}
              />
            </CardContent>
          </Card>
          <div className="split">
            <Card>
              <CardHeader>
                <CardTitle>Release rollout</CardTitle>
                <CardDescription>Tenant release rollouts. Agents pull signed updates over the outbound channel.</CardDescription>
              </CardHeader>
              <CardContent>
                {auxLoading ? <TableSkeleton rows={3} label="Loading agent releases" /> : null}
                {!auxLoading ? <DataTable
                  columns={releaseColumns}
                  items={updateReleases}
                  empty={<EmptyState icon={Bot} title="No agent releases published." body="Publish signed manifests through your operator packaging workflow to roll out agent versions." />}
                /> : null}
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>Trust keys</CardTitle>
                <CardDescription>Ed25519 signing keys that agents trust for update manifests.</CardDescription>
              </CardHeader>
              <CardContent className="product-form">
                {auxLoading ? <TableSkeleton rows={2} label="Loading trust keys" /> : null}
                {!auxLoading ? <DataTable
                  columns={trustKeyColumns}
                  items={trustKeys}
                  empty={<EmptyState icon={KeyRound} title="No trust keys registered." body="Add the public key from your agent update signing ceremony." />}
                /> : null}
                <form className="product-form" onSubmit={(event) => void handleAddTrustKey(event)}>
                  <label><span>Key name</span><input name="name" placeholder="production signing key" /></label>
                  <label className="full"><span>Public key (DER base64)</span><textarea name="public_key_der_base64" rows={3} placeholder="MCowBQYDK2VwAyEA…" required /></label>
                  <div className="form-actions full"><Button type="submit" loading={busy === 'add-trust-key'} disabled={busy !== ''}>Register trust key</Button></div>
                </form>
              </CardContent>
            </Card>
          </div>
        </div>
      ) : null}
    </div>
  );
}

export function ValidationSurfacePage({
  route,
  data,
  config,
  session,
  onRefresh
}: {
  route: RouteId;
  data: PortalData;
  config: PortalConfig;
  session: Session;
  onRefresh: () => Promise<void>;
}) {
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [checkFilter, setCheckFilter] = useState<CheckFamilyTabId>('recommended');
  const [checkSafetyScope, setCheckSafetyScope] = useState<CheckSafetyScopeId>('all');
  const [findingTab, setFindingTab] = useState<FindingTabId>('open');
  const [exportOutput, setExportOutput] = useState('');
  const [showTechnicalExport, setShowTechnicalExport] = useState(false);
  const [showFullEvidenceChain, setShowFullEvidenceChain] = useState(false);
  const [evidenceCustodyPreview, setEvidenceCustodyPreview] = useState<DataItem | null>(null);
  const [showEvidenceExportCenter, setShowEvidenceExportCenter] = useState(() => data.evidence.length > 0);
  const [exportPartialMissCount, setExportPartialMissCount] = useState(0);
  const [clipboardNotice, setClipboardNotice] = useState('');
  const [runStatusFilter, setRunStatusFilter] = useState('all');
  const [runStartTargetPreview, setRunStartTargetPreview] = useState('');
  const [runStartTargetLoading, setRunStartTargetLoading] = useState(false);
  const [showSocRequestForm, setShowSocRequestForm] = useState(false);
  const [cancelRunId, setCancelRunId] = useState('');
  const evidenceChainCap = 12;

  const firstGroup = data.targetGroups[0] ?? null;
  const safeCheck = data.checks.find((check) => getString(check, ['safety_class']) === 'safe') ?? null;
  const inFlightRuns = data.runs.filter((run) => ['running', 'collecting', 'planned'].includes(getString(run, ['status'], '')));

  const checkSafetyCounts = useMemo(() => countChecksBySafetyScope(data.checks), [data.checks]);
  const filteredChecks = useMemo(
    () => filterChecksCatalog(data.checks, checkFilter, checkSafetyScope),
    [data.checks, checkFilter, checkSafetyScope]
  );

  const filteredRuns = useMemo(() => {
    const sorted = [...data.runs].sort((a, b) => {
      const left = Date.parse(String(a.started_at ?? a.created_at ?? '')) || 0;
      const right = Date.parse(String(b.started_at ?? b.created_at ?? '')) || 0;
      return right - left;
    });
    if (runStatusFilter === 'all') return sorted;
    return sorted.filter((run) => getString(run, ['status'], '') === runStatusFilter);
  }, [data.runs, runStatusFilter]);

  useEffect(() => {
    if (route !== 'runs') return undefined;
    const targetGroupId = getString(firstGroup, ['id'], '');
    if (!targetGroupId) {
      setRunStartTargetPreview('');
      setRunStartTargetLoading(false);
      return undefined;
    }
    let cancelled = false;
    setRunStartTargetLoading(true);
    requestJson(config, session, `/v1/target-groups/${targetGroupId}`)
      .then((detail) => {
        if (cancelled) return;
        const targets = Array.isArray((detail as DataItem).targets) ? (detail as DataItem).targets as DataItem[] : [];
        const firstTarget = targets[0];
        const label = firstTarget
          ? `${getString(firstTarget, ['value', 'hostname', 'id'])} (${getString(firstTarget, ['id'])})`
          : '';
        setRunStartTargetPreview(label);
      })
      .catch(() => {
        if (!cancelled) setRunStartTargetPreview('');
      })
      .finally(() => {
        if (!cancelled) setRunStartTargetLoading(false);
      });
    return () => { cancelled = true; };
  }, [route, firstGroup, config, session]);

  useEffect(() => {
    if (data.evidence.length > 0) setShowEvidenceExportCenter(true);
  }, [data.evidence.length]);

  useEffect(() => {
    if (route !== 'runs' || inFlightRuns.length === 0) return undefined;
    const timer = window.setInterval(() => {
      void onRefresh();
    }, 12000);
    return () => window.clearInterval(timer);
  }, [route, inFlightRuns.length, onRefresh]);

  async function startSafeRun(checkId?: string) {
    const targetGroupId = getString(firstGroup, ['id'], '');
    const resolvedCheckId = checkId ?? getString(safeCheck ?? {}, ['check_id'], '');
    if (!targetGroupId || !resolvedCheckId) {
      setError('Declare a target group and safe check before starting a run.');
      return;
    }
    const detail = await requestJson(config, session, `/v1/target-groups/${targetGroupId}`) as DataItem;
    const targets = Array.isArray(detail.targets) ? detail.targets as DataItem[] : [];
    const targetId = getString(targets[0] ?? {}, ['id'], '');
    const targetLabel = getString(targets[0] ?? {}, ['value', 'hostname', 'id'], targetId);
    if (!targetId) {
      setError('Add at least one target to the declared group before starting a run.');
      return;
    }
    const groupLabel = getString(firstGroup, ['name', 'id'], targetGroupId);
    const checkLabel = checkDisplayName(data.checks, resolvedCheckId);
    if (!window.confirm(`Start a safe validation run?\n\nTarget group: ${groupLabel}\nTarget: ${targetLabel}\nCheck: ${checkLabel}`)) return;
    await runAction(setBusy, setError, setMessage, 'start-safe-run', () => requestJson(config, session, '/v1/test-runs', {
      method: 'POST',
      body: { target_group_id: targetGroupId, target_id: targetId, check_id: resolvedCheckId }
    }), 'Safe validation run started.', onRefresh);
  }

  async function cancelRun(id: string) {
    if (!id) return;
    setCancelRunId(id);
  }

  async function confirmCancelRun() {
    const id = cancelRunId;
    if (!id) return;
    setBusy(`cancel-${id}`);
    setError('');
    setMessage('');
    try {
      const result = await requestJson(config, session, `/v1/test-runs/${id}/cancel`, { method: 'POST' });
      setMessage(formatMutationSuccessMessage('Run cancelled.', result));
      setCancelRunId('');
      await onRefresh();
    } catch (err) {
      const payload = (err as Error & { payload?: unknown }).payload as { error?: string; message?: string } | undefined;
      setError(payload?.message ?? payload?.error ?? (err instanceof Error ? err.message : 'Cancel run failed.'));
    } finally {
      setBusy('');
    }
  }

  async function finalizeRun(id: string) {
    if (!id) return;
    if (!window.confirm('Force finalize this run now? This locks the verdict.')) return;
    await runAction(setBusy, setError, setMessage, `finalize-${id}`, () => requestJson(config, session, `/v1/test-runs/${id}/finalize`, { method: 'POST' }), 'Run finalized after observation window.', onRefresh);
  }

  async function exportEvidenceChain() {
    if (!data.evidence.length) {
      setError('No evidence records available to export.');
      return;
    }
    const preview = buildEvidenceChainExport({
      evidence: data.evidence,
      runs: data.runs,
      findings: data.findings
    });
    const summary = summarizeEvidenceExport(preview).map(([label, value]) => `${label}: ${value}`).join('\n');
    if (!window.confirm(`Export evidence chain JSON?\n\nThis fetches up to 20 recent run details for verdict correlation.\n\n${summary}`)) return;
    setBusy('export-evidence-chain');
    setError('');
    setMessage('');
    setClipboardNotice('');
    setExportPartialMissCount(0);
    try {
      const verdicts: DataItem[] = [];
      let partialMisses = 0;
      for (const run of data.runs.slice(-20)) {
        const runId = getString(run, ['id'], '');
        if (!runId) continue;
        try {
          const detail = await requestJson(config, session, `/v1/test-runs/${runId}`) as DataItem;
          const verdict = detail.verdict as DataItem | undefined;
          if (verdict) verdicts.push({ ...verdict, test_run_id: runId });
        } catch {
          partialMisses += 1;
        }
      }
      setExportPartialMissCount(partialMisses);
      const exportData = buildEvidenceChainExport({
        evidence: data.evidence,
        runs: data.runs,
        verdicts,
        findings: data.findings
      });
      const custody = await buildEvidenceCustodyManifest(exportData.payload, session.tenant_id ?? 'ten_demo');
      const verified = await requestJson(config, session, '/v1/custody/verify', {
        method: 'POST',
        body: { payload: exportData.payload, custody }
      }) as DataItem;
      setExportOutput(exportData.json);
      setEvidenceCustodyPreview(getNestedItem(verified, ['verification']) ?? verified);
      setMessage(partialMisses > 0
        ? `Evidence chain exported with custody verified. ${partialMisses} run(s) missing verdict detail.`
        : 'Evidence chain exported and custody digest verified.');
      try {
        await navigator.clipboard.writeText(exportData.json);
        setClipboardNotice('Export JSON copied to clipboard.');
      } catch {
        setClipboardNotice('Could not copy to clipboard. Use Copy export JSON or download from preview.');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Evidence chain export failed.');
      setEvidenceCustodyPreview(null);
    } finally {
      setBusy('');
    }
  }

  if (route === 'checks') {
    const checkTabOptions = routeTabs('checks').map((tab) => ({ id: tab.id as CheckFamilyTabId, label: tab.label }));
    const safetyScopeOptions = CHECK_SAFETY_SCOPE_TABS.map((tab) => ({
      id: tab.id,
      label: `${tab.label} (${checkSafetyCounts[tab.id]})`
    }));
    const columns: TableColumn<DataItem>[] = [
      {
        key: 'check',
        label: 'Check',
        render: (item) => {
          const checkId = getString(item, ['check_id'], '');
          const name = getString(item, ['name'], '');
          return (
            <div className="stack-tight">
              <strong>{name || checkId}</strong>
              {name ? <span className="muted small"><code>{checkId}</code></span> : null}
            </div>
          );
        }
      },
      {
        key: 'family',
        label: 'Family',
        render: (item) => <Badge tone="info">{formatVectorFamilyLabel(getString(item, ['vector_family']))}</Badge>
      },
      {
        key: 'safety',
        label: 'Safety',
        render: (item) => {
          const safetyClass = getString(item, ['safety_class'], '');
          return <Badge tone={safetyClass === 'safe' ? 'success' : 'warn'}>{formatSafetyClassLabel(safetyClass)}</Badge>;
        }
      },
      {
        key: 'description',
        label: 'Summary',
        render: (item) => {
          const description = getString(item, ['description'], '');
          if (!description || description === '—') return '—';
          return <span title={description}>{truncateText(description)}</span>;
        }
      },
      {
        key: 'setup',
        label: 'Required setup',
        render: (item) => {
          const setup = formatRequiredSetupList(item);
          if (setup.length === 0) return <span className="muted">—</span>;
          return <span title={setup.join(' · ')}>{truncateText(setup.join(', '), 56)}</span>;
        }
      },
      {
        key: 'probe',
        label: 'Probe profile',
        render: (item) => {
          const kind = getString(item, ['probe_profile', 'kind'], '');
          if (!kind || kind === '—') return <span className="muted">Unknown</span>;
          return formatSnakeLabel(kind);
        }
      },
      {
        key: 'actions',
        label: 'Actions',
        render: (item) => {
          const checkId = getString(item, ['check_id'], '');
          const isSafe = getString(item, ['safety_class']) === 'safe';
          return (
            <div className="row-actions row-actions--spaced">
              <AnchorButton variant="secondary" href="#test-policies">Bind in policy</AnchorButton>
              {isSafe ? (
                <Button variant="ghost" loading={busy === 'start-safe-run'} disabled={busy !== ''} onClick={() => void startSafeRun(checkId)}>Start safe run</Button>
              ) : null}
            </div>
          );
        }
      }
    ];
    return (
      <div className="content">
        <PageHeader route="checks" />
        <div className="metric-grid three">
          <MetricCard label="Catalog checks" value={checkSafetyCounts.all} sub="Tenant-visible definitions" icon={ListChecks} tone="info" />
          <MetricCard label="Runnable" value={checkSafetyCounts.safe} sub="Customer-safe scope" icon={ShieldCheck} tone="success" />
          <MetricCard label="SOC-only" value={checkSafetyCounts.soc} sub="Request through SOC" icon={Siren} tone="warn" />
        </div>
        <Card>
          <CardHeader>
            <CardTitle>Check library</CardTitle>
            <CardDescription>
              Browse the validation catalog by safety scope and vector family. High-scale checks remain request-only through SOC.
              {' '}
              <span className="muted small">
                {checkSafetyCounts.all} catalog · {checkSafetyCounts.safe} runnable · {checkSafetyCounts.soc} SOC-only
              </span>
            </CardDescription>
          </CardHeader>
          <CardContent>
            <fieldset className="filter-fieldset">
              <legend>Safety scope</legend>
              <Tabs value={checkSafetyScope} options={safetyScopeOptions} onChange={setCheckSafetyScope} className="tabs-wrap" />
            </fieldset>
            <fieldset className="filter-fieldset">
              <legend>Vector family</legend>
              <Tabs value={checkFilter} options={checkTabOptions} onChange={(value) => setCheckFilter(value as CheckFamilyTabId)} className="tabs-wrap" />
            </fieldset>
            <DataTable
              columns={columns}
              items={filteredChecks}
              empty={checkFilter === 'custom' ? (
                <EmptyState icon={ListChecks} title="No custom checks in catalog." body="Customer-defined safe checks bind through test policies after staff-reviewed scope declaration." actionLabel="Open test policies" actionHref="#test-policies" />
              ) : (
                <EmptyState icon={ListChecks} title="No checks in this family." body="The check catalog appears after your tenant is provisioned and scope is declared." />
              )}
            />
          </CardContent>
        </Card>
      </div>
    );
  }

  if (route === 'runs') {
    const runStatusTabs = [
      { id: 'all', label: 'All' },
      { id: 'running', label: 'Running' },
      { id: 'collecting', label: 'Collecting' },
      { id: 'verdicted', label: 'Verdicted' },
      { id: 'cancelled', label: 'Cancelled' },
      { id: 'failed', label: 'Failed' }
    ];
    const runColumns: TableColumn<DataItem>[] = [
      {
        key: 'run',
        label: 'Run',
        render: (item) => {
          const id = getString(item, ['id'], '');
          const checkId = getString(item, ['check_id'], '');
          return (
            <div className="stack-tight">
              <AnchorButton variant="secondary" href={buildDetailHref('run-detail', id)} aria-label={`Open run ${id}`}>{checkDisplayName(data.checks, checkId, id)}</AnchorButton>
              <span className="muted small"><code>{id}</code></span>
            </div>
          );
        }
      },
      {
        key: 'status',
        label: 'Status',
        render: (item) => {
          const status = getString(item, ['status'], '');
          return <Badge tone={runStatusBadgeTone(status)}>{formatRunStatusLabel(status)}</Badge>;
        }
      },
      {
        key: 'verdict',
        label: 'Verdict',
        render: (item) => {
          const verdict = getString(item, ['verdict', 'verdict'], 'pending');
          return <Badge tone={verdictBadgeTone(verdict)}>{formatVerdictLabel(verdict)}</Badge>;
        }
      },
      { key: 'time', label: 'Started', render: (item) => formatDate(item.started_at ?? item.created_at) },
      {
        key: 'actions',
        label: 'Actions',
        render: (item) => {
          const id = getString(item, ['id'], '');
          const status = getString(item, ['status'], '');
          const cancellable = ['planned', 'running', 'collecting'].includes(status);
          return (
            <div className="row-actions row-actions--spaced">
              <AnchorButton variant="secondary" href={buildDetailHref('run-detail', id)}>View run</AnchorButton>
              {cancellable ? (
                <>
                  <Button size="sm" variant="danger" loading={busy === `cancel-${id}`} disabled={busy !== ''} onClick={() => void cancelRun(id)}>Cancel</Button>
                  <Button size="sm" variant="ghost" loading={busy === `finalize-${id}`} disabled={busy !== ''} onClick={() => void finalizeRun(id)}>Finalize</Button>
                </>
              ) : null}
            </div>
          );
        }
      }
    ];
    const canStartRun = Boolean(firstGroup && safeCheck && runStartTargetPreview);
    const startDisabledReason = !firstGroup
      ? 'Declare a target group first.'
      : !safeCheck
        ? 'No customer-runnable check in catalog.'
        : !runStartTargetPreview
          ? 'Add at least one target to the first target group.'
          : '';
    return (
      <div className="content">
        <PageHeader
          route="runs"
          actions={(
            <RunsPageHeadActions
              onRefresh={() => void onRefresh()}
              onRequestSoc={() => setShowSocRequestForm(true)}
              onStartSafeRun={() => void startSafeRun()}
              refreshBusy={busy === 'refresh-runs'}
              safeRunBusy={busy === 'start-safe-run'}
              safeRunDisabled={busy !== '' || !canStartRun}
            />
          )}
        />
        <RunsSocGatePanel
          data={data}
          config={config}
          session={session}
          onRefresh={onRefresh}
          onMessage={setMessage}
          onError={setError}
          busy={busy}
          setBusy={setBusy}
          requestFormOpen={showSocRequestForm}
          onRequestFormOpenChange={setShowSocRequestForm}
        />
        {inFlightRuns.length > 0 ? (
          <div className="form-banner info" role="status">Runs in progress — auto-refreshing every 12s ({inFlightRuns.length} active).</div>
        ) : null}
        {(message || error) && <div className={error ? 'form-banner error' : 'form-banner neutral'}>{error || message}</div>}
        <Card>
          <CardHeader>
            <CardTitle>Start safe validation</CardTitle>
            <CardDescription>Confirm the resolved target group, target, and check before starting a bounded safe run.</CardDescription>
          </CardHeader>
          <CardContent className="stack-tight">
            <div className="kv-list kv-list--compact">
              <div><span>Target group</span><strong>{firstGroup ? getString(firstGroup, ['name', 'id']) : '—'}</strong></div>
              <div>
                <span>Target</span>
                {runStartTargetLoading ? (
                  <span className="skeleton skeleton-text" aria-busy="true" aria-label="Loading target preview" />
                ) : (
                  <strong>{runStartTargetPreview || '—'}</strong>
                )}
              </div>
              <div>
                <span>Check</span>
                {safeCheck ? (
                  <div className="stack-tight">
                    <AnchorButton variant="ghost" href="#checks">{getString(safeCheck, ['name'], getString(safeCheck, ['check_id']))}</AnchorButton>
                    <span className="muted small"><code>{getString(safeCheck, ['check_id'])}</code></span>
                  </div>
                ) : (
                  <strong>—</strong>
                )}
              </div>
            </div>
            {startDisabledReason ? <p className="muted">{startDisabledReason}</p> : null}
            <Button loading={busy === 'start-safe-run'} disabled={busy !== '' || !canStartRun} onClick={() => void startSafeRun()}>Start safe run</Button>
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle>Test runs</CardTitle><CardDescription>Live safe-validation runs with probe results, agent observations, and verdicts. Open a run for detail, or cancel or finalize in flight.</CardDescription></CardHeader>
          <CardContent>
            <Tabs value={runStatusFilter} options={runStatusTabs} onChange={setRunStatusFilter} className="tabs-wrap" />
            <DataTable
              columns={runColumns}
              items={filteredRuns}
              empty={renderFriendlyEmptyState({
                icon: Activity,
                title: 'No test runs yet.',
                body: 'Start a safe validation run after declaring target scope.',
                actionLabel: 'Run safe checks',
                onAction: () => void startSafeRun()
              })}
            />
          </CardContent>
        </Card>
        <ConfirmModal
          open={Boolean(cancelRunId)}
          title={`Cancel run ${cancelRunId}`}
          description={<p>Are you sure? This stops probe jobs immediately and writes an audit entry.</p>}
          confirmLabel="Cancel run"
          busy={busy === `cancel-${cancelRunId}`}
          onCancel={() => setCancelRunId('')}
          onConfirm={() => void confirmCancelRun()}
        />
      </div>
    );
  }

  if (route === 'findings') {
    return (
      <div className="content">
        <PageHeader route="findings" />
        {(message || error) && <div className={error ? 'form-banner error' : 'form-banner neutral'}>{error || message}</div>}
        <Card>
          <CardHeader>
            <CardTitle>Findings</CardTitle>
            <CardDescription>Filter, sort, and paginate evidence-backed gaps. Detail panels live on finding detail.</CardDescription>
          </CardHeader>
          <CardContent className="findings-surface-wrap">
            <FindingsListView findings={data.findings} checks={data.checks} targetGroups={data.targetGroups} />
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="content">
      <PageHeader route={route} />
      <EmptyState icon={ListChecks} title="Validation surface unavailable." body="This route is not wired in the revamp navigation." actionLabel="Open dashboard" actionHref="#dashboard" />
    </div>
  );
}

