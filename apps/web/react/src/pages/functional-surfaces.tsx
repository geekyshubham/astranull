import { useEffect, useMemo, useState, type FormEvent, type HTMLAttributes, type ReactNode } from 'react';
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
import { MetricCard, PageContextSummary, PageHeader } from './page-components';

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

function getRunVerdictValue(run: DataItem) {
  const verdict = run.verdict;
  if (verdict && typeof verdict === 'object' && !Array.isArray(verdict)) {
    const nested = getString(verdict as DataItem, ['verdict'], '');
    if (nested) return nested;
  }
  return getString(run, ['verdict', 'verdict'], '');
}

function buildLatestCheckVerdictMap(runs: DataItem[]) {
  const map = new Map<string, { verdict: string; runId: string }>();
  const sortKeys = new Map<string, string>();
  for (const run of runs) {
    const checkId = getString(run, ['check_id'], '');
    if (!checkId) continue;
    const status = getString(run, ['status'], '');
    if (!['completed', 'verdicted'].includes(status)) continue;
    const verdict = getRunVerdictValue(run);
    if (!verdict) continue;
    const at = String(run.updated_at ?? run.completed_at ?? run.started_at ?? run.created_at ?? '');
    const prevAt = sortKeys.get(checkId) ?? '';
    if (!prevAt || at.localeCompare(prevAt) >= 0) {
      sortKeys.set(checkId, at);
      map.set(checkId, { verdict, runId: getString(run, ['id'], '') });
    }
  }
  return map;
}

function formatCheckModeLabel(safetyClass: string) {
  if (safetyClass === 'safe') return 'safe';
  if (safetyClass === 'soc_gated') return 'SOC-gated';
  return formatSafetyClassLabel(safetyClass);
}

function checkModeBadgeTone(safetyClass: string): BadgeTone {
  if (safetyClass === 'safe') return 'success';
  if (safetyClass === 'soc_gated') return 'info';
  return 'muted';
}

function formatCheckBoundLabel(check: DataItem) {
  const maxRate = check.max_rate;
  if (typeof maxRate === 'number' && Number.isFinite(maxRate) && maxRate > 0) {
    return `${maxRate} RPS`;
  }
  if (typeof maxRate === 'string' && maxRate.trim()) {
    return maxRate.replace(/_/g, ' ');
  }
  const kind = getNestedString(check, ['probe_profile', 'kind'], '');
  if (kind === 'metadata_marker' || kind === 'ops_readiness') return 'metadata';
  const profile = check.probe_profile;
  if (profile && typeof profile === 'object' && !Array.isArray(profile)) {
    const maxRequests = Number((profile as DataItem).max_requests);
    if (Number.isFinite(maxRequests) && maxRequests === 1) return 'metadata';
  }
  return '—';
}

function formatCatalogVerdictLabel(verdict: string) {
  const key = verdict.trim().toLowerCase();
  if (!key) return '—';
  if (['pass', 'passed', 'protected', 'ready', 'success', 'ok'].includes(key)) return 'Pass';
  if (['gap', 'fail', 'failed', 'unprotected', 'bypassable', 'penetrated'].includes(key)) return 'Gap';
  if (['review', 'partial', 'inconclusive', 'warn', 'warning', 'medium'].includes(key)) return 'Review';
  if (key === 'request') return 'request';
  return formatVerdictLabel(verdict);
}

function catalogVerdictBadgeTone(verdict: string): BadgeTone {
  const label = formatCatalogVerdictLabel(verdict);
  if (label === 'Pass') return 'success';
  if (label === 'Gap') return 'danger';
  if (label === 'Review') return 'warn';
  if (label === 'request') return 'muted';
  return verdictBadgeTone(verdict);
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

function resolveTargetGroupName(groups: DataItem[], groupId: string) {
  if (!groupId) return '—';
  const group = groups.find((item) => getString(item, ['id'], '') === groupId);
  return getString(group ?? {}, ['name', 'title'], groupId);
}

function formatRunDuration(run: DataItem) {
  const start = Date.parse(String(run.started_at ?? run.created_at ?? ''));
  const end = Date.parse(String(run.completed_at ?? run.finalized_at ?? run.updated_at ?? ''));
  if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start) return '—';
  const totalSeconds = Math.round((end - start) / 1000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  if (minutes <= 0) return `${seconds}s`;
  return `${minutes}m ${String(seconds).padStart(2, '0')}s`;
}

const IN_PROGRESS_RUN_STATUSES = new Set(['running', 'collecting']);

function isInProgressRunStatus(status: string) {
  return IN_PROGRESS_RUN_STATUSES.has(status);
}

function formatStartedAgo(value: unknown) {
  const started = Date.parse(String(value ?? ''));
  if (!Number.isFinite(started)) return '';
  const diffMs = Date.now() - started;
  if (diffMs < 0) return 'started just now';
  const seconds = Math.floor(diffMs / 1000);
  if (seconds < 60) return `started ${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `started ${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `started ${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `started ${days}d ago`;
}

// Scoped runtime style (guarded, tokens only) — mirrors the ui/* primitive pattern
// (see components/ui/badge.tsx / button.tsx). Provides the in-progress live-pulse dot
// with prefers-reduced-motion support. Does NOT modify the shared stylesheet.
const FUNCTIONAL_SURFACE_STYLE_ID = 'astranull-functional-surface-styles';

function ensureFunctionalSurfaceStyles() {
  if (typeof document === 'undefined') return;
  if (document.getElementById(FUNCTIONAL_SURFACE_STYLE_ID)) return;
  const node = document.createElement('style');
  node.id = FUNCTIONAL_SURFACE_STYLE_ID;
  node.textContent = `
.run-live-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--info);
  flex: none;
  animation: astranull-run-live-pulse 1.5s ease-in-out infinite;
}
@keyframes astranull-run-live-pulse {
  0%, 100% { opacity: 1; transform: scale(1); }
  50% { opacity: 0.35; transform: scale(0.7); }
}
@media (prefers-reduced-motion: reduce) {
  .run-live-dot { animation: none; opacity: 0.85; }
}
`;
  document.head.appendChild(node);
}

// Buckets a catalog check into a coarse verdict-status key for the checks status filter.
function checkStatusFilterKey(
  check: DataItem,
  verdicts: Map<string, { verdict: string; runId: string }>
) {
  const checkId = getString(check, ['check_id'], '');
  const latest = verdicts.get(checkId);
  if (latest?.verdict) {
    const label = formatCatalogVerdictLabel(latest.verdict);
    if (label === 'Pass') return 'pass';
    if (label === 'Gap') return 'gap';
    if (label === 'Review') return 'review';
    if (label === 'request') return 'request';
    return 'review';
  }
  if (getString(check, ['safety_class'], '') === 'soc_gated') return 'request';
  return 'untested';
}

const CHECK_FAMILY_FILTER_OPTIONS: { value: CheckFamilyTabId; label: string }[] = [
  { value: 'all', label: 'All families' },
  { value: 'recommended', label: 'Recommended' },
  { value: 'origin-bypass', label: 'Origin bypass' },
  { value: 'l3l4', label: 'L3 / L4' },
  { value: 'dns', label: 'DNS' },
  { value: 'l7api', label: 'L7 / API' },
  { value: 'protocols', label: 'Protocols / TLS' },
  { value: 'high-scale', label: 'High-scale (SOC)' }
];

const CHECK_STATUS_FILTER_OPTIONS = [
  { value: 'all', label: 'All statuses' },
  { value: 'pass', label: 'Pass' },
  { value: 'gap', label: 'Gap' },
  { value: 'review', label: 'Review' },
  { value: 'request', label: 'SOC request' },
  { value: 'untested', label: 'Untested' }
];

const TOKEN_EXPIRY_OPTIONS = [
  { value: '15', label: '15 minutes' },
  { value: '60', label: '1 hour' },
  { value: '240', label: '4 hours' },
  { value: '1440', label: '24 hours' }
];

const MASKED_TOKEN_SECRET = '\u2022'.repeat(32);

function TableSkeleton({ rows = 4, label = 'Loading' }: { rows?: number; label?: string }) {
  return (
    <div className="stack-tight" aria-busy="true" aria-label={label}>
      {Array.from({ length: rows }, (_, index) => (
        <div key={index} className="skeleton skeleton-row" />
      ))}
    </div>
  );
}

function MutationFeedbackBanner({
  message,
  error,
  neutral = false
}: {
  message: string;
  error: string;
  neutral?: boolean;
}) {
  if (!message && !error) return null;
  const className = error ? 'form-banner error' : neutral ? 'form-banner neutral' : 'form-banner';
  return (
    <div className={className} role={error ? 'alert' : 'status'} aria-live="polite">
      {error || message}
    </div>
  );
}

function FilterFieldset({ legend, children }: { legend: string; children: ReactNode }) {
  return (
    <fieldset className="filter-fieldset">
      <legend>{legend}</legend>
      {children}
    </fieldset>
  );
}

type SurfaceTableCardProps<T> = {
  title: string;
  description: ReactNode;
  columns: TableColumn<T>[];
  items: T[];
  empty: ReactNode;
  loading?: boolean;
  loadingLabel?: string;
  loadingRows?: number;
  contentClassName?: string;
  getRowProps?: (item: T, index: number) => Omit<HTMLAttributes<HTMLTableRowElement>, 'key'>;
  getRowId?: (item: T, index: number) => string | number;
};

function SurfaceTableCard<T>({
  title,
  description,
  columns,
  items,
  empty,
  loading = false,
  loadingLabel = 'Loading table',
  loadingRows = 3,
  contentClassName,
  getRowProps,
  getRowId
}: SurfaceTableCardProps<T>) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent className={contentClassName} aria-busy={loading || undefined}>
        {loading ? (
          <TableSkeleton rows={loadingRows} label={loadingLabel} />
        ) : (
          <DataTable columns={columns} items={items} empty={empty} getRowProps={getRowProps} getRowId={getRowId} />
        )}
      </CardContent>
    </Card>
  );
}

function isInteractiveTableTarget(target: EventTarget | null) {
  return Boolean(target && (target as HTMLElement).closest('a, button'));
}

function buildDetailHashRowProps(
  detailRoute: string,
  id: string,
  ariaLabel: string
): Omit<HTMLAttributes<HTMLTableRowElement>, 'key'> {
  if (!id) return {};
  const hash = `${detailRoute}?id=${encodeURIComponent(id)}`;
  return {
    role: 'link',
    tabIndex: 0,
    style: { cursor: 'pointer' },
    'aria-label': ariaLabel,
    onClick: (event) => {
      if (isInteractiveTableTarget(event.target)) return;
      window.location.hash = hash;
    },
    onKeyDown: (event) => {
      if (event.key !== 'Enter' && event.key !== ' ') return;
      if (isInteractiveTableTarget(event.target)) return;
      event.preventDefault();
      window.location.hash = hash;
    }
  };
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
  const [tokenId, setTokenId] = useState('');
  const [tokenExpiryMinutes, setTokenExpiryMinutes] = useState('60');
  const [tokenRevealed, setTokenRevealed] = useState(false);
  const [tokenRevoked, setTokenRevoked] = useState(false);
  const [copyNotice, setCopyNotice] = useState('');
  const [updateReleases, setUpdateReleases] = useState<DataItem[]>([]);
  const [trustKeys, setTrustKeys] = useState<DataItem[]>([]);
  const [auxLoading, setAuxLoading] = useState(false);
  const [agentsTab, setAgentsTab] = useState<'fleet' | 'install' | 'operations'>('fleet');

  const onlineAgents = data.agents.filter((agent) => getString(agent, ['status']) === 'online').length;
  const firstGroup = data.targetGroups[0] ?? null;

  // Load agent update releases + update-signing trust keys for the rollout / trust-key
  // panels. Both GET /v1/agent-updates and GET /v1/agent-update-trust-keys return
  // `{ items: [...] }`. There are no sub-tabs on this surface, so load once on mount.
  useEffect(() => {
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
  }, [config, session]);

  const fleetColumns: TableColumn<DataItem>[] = [
    {
      key: 'agent',
      label: 'Agent',
      render: (item) => (
        <code className="traffic-path-label" title={getString(item, ['id'])}>{getString(item, ['id'])}</code>
      )
    },
    { key: 'hostname', label: 'Hostname', render: (item) => <span className="muted">{getString(item, ['hostname', 'name'], '—')}</span> },
    { key: 'environment', label: 'Env', render: (item) => <code className="traffic-path-label">{getString(item, ['environment_id'], 'tenant scope')}</code> },
    { key: 'version', label: 'Version', render: (item) => <code className="traffic-path-label">{getString(item, ['version', 'agent_version'], '—')}</code> },
    { key: 'heartbeat', label: 'Heartbeat', render: (item) => <span className="muted">{formatDate(item.last_heartbeat_at)}</span> },
    {
      key: 'placement',
      label: 'Placement',
      render: (item) => {
        const placement = getString(item, ['placement_type', 'placement'], '');
        const label = placement ? placement.replace(/_/g, ' ') : 'unbound';
        return <Badge tone="muted" title="Placement type reported on agent registration">{label}</Badge>;
      }
    },
    {
      key: 'status',
      label: 'Status',
      render: (item) => {
        const status = getString(item, ['status', 'state'], 'unknown');
        const tone = status === 'online' ? 'success' : status === 'revoked' ? 'danger' : 'muted';
        return <Badge tone={tone} title="Agent status from heartbeat and credential state">{formatAgentHealth(item)}</Badge>;
      }
    },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        const revoked = getString(item, ['status', 'state'], '') === 'revoked';
        if (revoked) return <span className="muted">revoked</span>;
        if (!id) return <span className="muted">—</span>;
        return (
          <div className="row-actions">
            <Button
              size="sm"
              variant="danger"
              loading={busy === `revoke-${id}`}
              disabled={busy !== ''}
              aria-label={`Revoke agent ${getString(item, ['hostname', 'name', 'id'], id)}`}
              onClick={() => void revokeAgent(id)}
            >
              Revoke
            </Button>
          </div>
        );
      }
    }
  ];

  const releaseColumns: TableColumn<DataItem>[] = [
    { key: 'version', label: 'Version', render: (item) => <code className="traffic-path-label">{getString(item, ['version'])}</code> },
    { key: 'channel', label: 'Channel', render: (item) => <span className="muted">{getString(item, ['channel'], 'stable')}</span> },
    { key: 'state', label: 'State', render: (item) => <Badge tone="info" title="Release rollout state from agent-updates">{formatSnakeLabel(getString(item, ['state'], 'active'))}</Badge> },
    { key: 'rollout', label: 'Rollout', render: (item) => <span className="num tabular-nums">{getNestedNumber(item, ['rollout', 'percentage'], 100)}%</span> },
    { key: 'created', label: 'Created', render: (item) => <span className="muted">{formatDate(item.created_at)}</span> },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        const canRollback = Boolean(item.rollback) && getString(item, ['state']) !== 'rollback_requested';
        return canRollback ? (
          <Button
            size="sm"
            variant="secondary"
            loading={busy === `rollback-${id}`}
            disabled={busy !== ''}
            aria-label={`Request rollback for release ${getString(item, ['version'], id)}`}
            onClick={() => void requestReleaseRollback(id)}
          >
            Request rollback
          </Button>
        ) : <span className="muted">—</span>;
      }
    }
  ];

  const trustKeyColumns: TableColumn<DataItem>[] = [
    { key: 'name', label: 'Name', render: (item) => getString(item, ['name']) },
    { key: 'fingerprint', label: 'Fingerprint', render: (item) => <code className="traffic-path-label" title={getString(item, ['fingerprint_sha256'])}>{getString(item, ['fingerprint_sha256'])}</code> },
    {
      key: 'status',
      label: 'Status',
      render: (item) => {
        const status = getString(item, ['status']);
        return <Badge tone={status === 'active' ? 'success' : 'muted'}>{formatSnakeLabel(status)}</Badge>;
      }
    },
    { key: 'created', label: 'Created', render: (item) => <span className="muted">{formatDate(item.created_at)}</span> },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        const active = getString(item, ['status']) === 'active';
        return active ? (
          <Button
            size="sm"
            variant="danger"
            loading={busy === `trust-revoke-${id}`}
            disabled={busy !== ''}
            aria-label={`Revoke trust key ${getString(item, ['name'], id)}`}
            onClick={() => void revokeTrustKey(id)}
          >
            Revoke
          </Button>
        ) : <span className="muted">revoked</span>;
      }
    }
  ];

  async function createBootstrapToken() {
    const minutes = Number(tokenExpiryMinutes);
    const expiryMinutes = Number.isFinite(minutes) && minutes > 0 ? minutes : 60;
    const body: DataItem = {
      name: 'agent-install',
      // Backend honors `expires_at`; `expires_in_minutes` alone is ignored and falls back
      // to a 24h default (see src/services/tokens.mjs). Send both so the chosen TTL applies.
      expires_at: new Date(Date.now() + expiryMinutes * 60 * 1000).toISOString(),
      expires_in_minutes: expiryMinutes,
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
    const createdItem = (created as DataItem) ?? {};
    const secret = getString(createdItem, ['secret'], getNestedString(createdItem, ['token', 'secret'], ''));
    const createdId = getString(createdItem, ['id'], getNestedString(createdItem, ['token', 'id'], ''));
    if (secret) {
      setTokenSecret(secret);
      setTokenId(createdId);
      setTokenRevealed(false);
      setTokenRevoked(false);
      setCopyNotice('');
    }
  }

  async function copyTokenSecret() {
    if (!tokenSecret) return;
    try {
      await navigator.clipboard.writeText(tokenSecret);
      setCopyNotice('Secret copied to clipboard.');
    } catch {
      setCopyNotice('Clipboard copy failed. Reveal the secret and copy it manually.');
    }
  }

  async function revokeBootstrapToken() {
    if (!tokenId) {
      setError('No bootstrap token id was returned, so it cannot be revoked from here.');
      return;
    }
    if (!window.confirm('Revoke this bootstrap token? New agent registrations using it will fail.')) return;
    const result = await runAction(
      setBusy,
      setError,
      setMessage,
      `revoke-bootstrap-${tokenId}`,
      () => requestJson(config, session, `/v1/bootstrap-tokens/${tokenId}/revoke`, { method: 'POST' }),
      'Bootstrap token revoked.',
      onRefresh
    );
    if (result) {
      setTokenRevoked(true);
      setTokenRevealed(false);
    }
  }

  async function refreshAgentReleases() {
    const payload = await requestJson(config, session, '/v1/agent-updates') as { items?: DataItem[] };
    setUpdateReleases(Array.isArray(payload.items) ? payload.items : []);
  }

  async function refreshTrustKeys() {
    const payload = await requestJson(config, session, '/v1/agent-update-trust-keys') as { items?: DataItem[] };
    setTrustKeys(Array.isArray(payload.items) ? payload.items : []);
  }

  async function revokeAgent(id: string) {
    if (!id) return;
    if (!window.confirm("Revoke this agent's credentials? It will stop reporting until re-registered.")) return;
    await runAction(
      setBusy,
      setError,
      setMessage,
      `revoke-${id}`,
      () => requestJson(config, session, `/v1/agents/${id}/revoke`, { method: 'POST' }),
      'Agent revoked. Heartbeat and jobs will be rejected.',
      onRefresh
    );
  }

  async function requestReleaseRollback(releaseId: string) {
    if (!releaseId) return;
    if (!window.confirm('Request rollback for this agent release? Eligible agents will move to the previous signed version.')) return;
    await runAction(
      setBusy,
      setError,
      setMessage,
      `rollback-${releaseId}`,
      () => requestJson(config, session, `/v1/agent-updates/${releaseId}/rollback`, { method: 'POST' }),
      'Rollback requested for eligible agents.',
      async () => {
        await refreshAgentReleases();
        await onRefresh();
      }
    );
  }

  async function revokeTrustKey(keyId: string) {
    if (!keyId) return;
    if (!window.confirm('Revoke this agent update trust key? Agents will reject updates signed with it.')) return;
    await runAction(
      setBusy,
      setError,
      setMessage,
      `trust-revoke-${keyId}`,
      () => requestJson(config, session, `/v1/agent-update-trust-keys/${keyId}/revoke`, { method: 'POST' }),
      'Trust key revoked.',
      async () => {
        await refreshTrustKeys();
        await onRefresh();
      }
    );
  }

  async function handleAddTrustKey(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    // Capture the form node before awaiting — event.currentTarget is nulled after the
    // synchronous handler returns, so form.reset() must use the captured reference.
    const form = event.currentTarget;
    const formData = new FormData(form);
    await runAction(
      setBusy,
      setError,
      setMessage,
      'add-trust-key',
      () => requestJson(config, session, '/v1/agent-update-trust-keys', {
        method: 'POST',
        body: {
          name: String(formData.get('name') ?? '').trim() || 'agent update signing key',
          public_key_der_base64: String(formData.get('public_key_der_base64') ?? '').trim()
        }
      }),
      'Trust key registered.',
      async () => {
        await refreshTrustKeys();
        form.reset();
        await onRefresh();
      }
    );
  }

  // Prototype-parity: #screen-agents page-head exposes a Refresh action. Refresh the
  // portal fleet data plus the separately-loaded release rollout / trust-key panels.
  async function handleAgentsRefresh() {
    setBusy('refresh');
    setError('');
    setMessage('');
    try {
      await Promise.all([refreshAgentReleases(), refreshTrustKeys(), onRefresh()]);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Refresh failed.');
    } finally {
      setBusy('');
    }
  }

  return (
    <div className="content">
      <PageHeader route="agents" />
      <PageContextSummary>
        <span className="tabular-nums">{data.targetGroups.length}</span> declared groups ·{' '}
        <span className="tabular-nums">{data.agents.length}</span> agents ·{' '}
        <span className="tabular-nums">{onlineAgents}</span> online
      </PageContextSummary>
      <MutationFeedbackBanner message={message} error={error} />
      <Tabs
        value={agentsTab}
        options={[
          { id: 'fleet' as const, label: 'Fleet', count: data.agents.length },
          { id: 'install' as const, label: 'Install' },
          { id: 'operations' as const, label: 'Operations' }
        ]}
        onChange={setAgentsTab}
        className="tabs-wrap"
        ariaLabel="Agents sections"
        getTabId={(id) => `agents-tab-${id}`}
        getPanelId={(id) => `agents-panel-${id}`}
      />
      {agentsTab === 'fleet' ? (
        <div className="stack" role="tabpanel" id="agents-panel-fleet" aria-labelledby="agents-tab-fleet">
        <SurfaceTableCard
          title="Installed agents"
          description="Outbound-only observation agents. They call AstraNull over HTTPS. Click a row to open the agent detail."
          columns={fleetColumns}
          items={data.agents}
          getRowProps={(item) => {
            const id = getString(item, ['id'], '');
            return buildDetailHashRowProps(
              'agent-detail',
              id,
              `Open agent ${getString(item, ['hostname', 'name', 'id'], id)} detail`
            );
          }}
          empty={(
            <EmptyState
              icon={Bot}
              title="No agents have registered yet."
              body="Create a bootstrap token below, then install an outbound-only agent."
            />
          )}
        />
        </div>
      ) : null}
      {agentsTab === 'install' ? (
        <div className="stack" role="tabpanel" id="agents-panel-install" aria-labelledby="agents-tab-install">
        <Card>
          <CardHeader>
            <CardTitle>Bootstrap token</CardTitle>
            <CardDescription>
              Pick a token lifetime, then use “Create bootstrap token” below. The one-time secret is shown once — reveal, copy, or revoke it here.
            </CardDescription>
          </CardHeader>
          <CardContent className="stack-tight">
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 'var(--space-3)' }}>
              <Select
                label="Token expiry"
                value={tokenExpiryMinutes}
                options={TOKEN_EXPIRY_OPTIONS}
                onChange={setTokenExpiryMinutes}
                disabled={busy !== ''}
              />
            </div>
            {tokenSecret ? (
              <Card className="secret-card">
                <CardHeader>
                  <CardTitle>One-time bootstrap token secret</CardTitle>
                  <CardDescription>
                    Shown once. It is not returned by list APIs and will not be visible after refresh.
                    {tokenId ? <> Token id <code className="traffic-path-label">{tokenId}</code>.</> : null}
                  </CardDescription>
                </CardHeader>
                <CardContent className="stack-tight">
                  <pre className="codeblock" aria-label="Bootstrap token secret">
                    {tokenRevoked ? 'Token revoked.' : tokenRevealed ? tokenSecret : MASKED_TOKEN_SECRET}
                  </pre>
                  <div className="row-actions">
                    <Button
                      variant="secondary"
                      size="sm"
                      aria-pressed={tokenRevealed}
                      disabled={tokenRevoked}
                      onClick={() => setTokenRevealed((value) => !value)}
                    >
                      {tokenRevealed ? 'Hide' : 'Reveal'}
                    </Button>
                    <Button
                      variant="secondary"
                      size="sm"
                      disabled={tokenRevoked}
                      onClick={() => void copyTokenSecret()}
                    >
                      Copy
                    </Button>
                    <Button
                      variant="danger"
                      size="sm"
                      loading={busy === `revoke-bootstrap-${tokenId}`}
                      disabled={!tokenId || tokenRevoked || (busy !== '' && busy !== `revoke-bootstrap-${tokenId}`)}
                      onClick={() => void revokeBootstrapToken()}
                    >
                      {tokenRevoked ? 'Revoked' : 'Revoke'}
                    </Button>
                  </div>
                  {copyNotice ? <p className="muted" role="status" aria-live="polite">{copyNotice}</p> : null}
                </CardContent>
              </Card>
            ) : null}
          </CardContent>
        </Card>
        <AgentInstallMatrix
          data={data}
          tokenSecret={tokenSecret}
          onCreateToken={() => void createBootstrapToken()}
          createBusy={busy === 'create-bootstrap-token'}
          actionsDisabled={busy !== ''}
        />
        </div>
      ) : null}
      {agentsTab === 'operations' ? (
        <div className="stack" role="tabpanel" id="agents-panel-operations" aria-labelledby="agents-tab-operations">
        <div className="split">
          <SurfaceTableCard
            title="Release rollout"
            description="Tenant agent release rollouts. Agents pull signed updates over the outbound channel. Request rollback to move eligible agents to the previous signed version."
            columns={releaseColumns}
            items={updateReleases}
            loading={auxLoading}
            loadingLabel="Loading agent releases"
            empty={(
              <EmptyState
                icon={Bot}
                title="No agent releases published."
                body="Publish signed manifests through your operator packaging workflow to roll out agent versions."
              />
            )}
          />
          <Card>
            <CardHeader>
              <CardTitle>Trust keys</CardTitle>
              <CardDescription>
                Ed25519 signing keys that agents trust for update manifests. Revoking a key makes agents reject updates signed with it.
              </CardDescription>
            </CardHeader>
            <CardContent className="product-form stack">
              {auxLoading ? (
                <TableSkeleton rows={2} label="Loading trust keys" />
              ) : (
                <DataTable
                  columns={trustKeyColumns}
                  items={trustKeys}
                  empty={(
                    <EmptyState
                      icon={KeyRound}
                      title="No trust keys registered."
                      body="Add the public key from your agent update signing ceremony."
                    />
                  )}
                />
              )}
              <form className="product-form" onSubmit={(event) => void handleAddTrustKey(event)} aria-label="Register agent update trust key">
                <label><span>Key name</span><input name="name" placeholder="production signing key" /></label>
                <label className="full"><span>Public key (DER base64)</span><textarea name="public_key_der_base64" rows={3} placeholder="MCowBQYDK2VwAyEA…" required /></label>
                <div className="form-actions full">
                  <Button type="submit" loading={busy === 'add-trust-key'} disabled={busy !== ''}>Register trust key</Button>
                </div>
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
  const [checkStatusFilter, setCheckStatusFilter] = useState('all');
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
  const latestCheckVerdicts = useMemo(() => buildLatestCheckVerdictMap(data.runs), [data.runs]);

  const visibleChecks = useMemo(() => {
    if (checkStatusFilter === 'all') return filteredChecks;
    return filteredChecks.filter((check) => checkStatusFilterKey(check, latestCheckVerdicts) === checkStatusFilter);
  }, [filteredChecks, checkStatusFilter, latestCheckVerdicts]);

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
    }, 8000);
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
      const custody = await buildEvidenceCustodyManifest(exportData.payload, session.tenant_id ?? data.state?.tenant_id ?? 'unknown');
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

  // Prototype-parity: #screen-checks and #screen-findings page-heads expose a Refresh
  // action. Reuses the portal onRefresh so the catalog / findings reflect fresh state.
  async function handleSurfaceRefresh() {
    setBusy('refresh');
    setError('');
    setMessage('');
    try {
      await onRefresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Refresh failed.');
    } finally {
      setBusy('');
    }
  }

  if (route === 'checks') {
    const columns: TableColumn<DataItem>[] = [
      {
        key: 'name',
        label: 'Name',
        render: (item) => <strong>{getString(item, ['name', 'check_id'], '—')}</strong>
      },
      {
        key: 'family',
        label: 'Family',
        render: (item) => (
          <Badge tone="info" title="Vector family from check catalog">
            {formatVectorFamilyLabel(getString(item, ['vector_family'], ''))}
          </Badge>
        )
      },
      {
        key: 'description',
        label: 'Description',
        render: (item) => {
          const desc = getString(item, ['description', 'summary'], '');
          return desc
            ? <span className="cell-truncate" title={desc}>{desc}</span>
            : <span className="muted">—</span>;
        }
      },
      {
        key: 'targets',
        label: 'Targets',
        render: (item) => {
          const targets = Array.isArray(item.supported_targets)
            ? (item.supported_targets as unknown[]).map((value) => String(value))
            : [];
          return targets.length
            ? <code className="traffic-path-label">{targets.join(', ')}</code>
            : <span className="muted">—</span>;
        }
      },
      {
        key: 'check',
        label: 'Check ID',
        render: (item) => (
          <code className="traffic-path-label" title={getString(item, ['check_id'])}>{getString(item, ['check_id'])}</code>
        )
      }
    ];
    return (
      <div className="content">
        <PageHeader route="checks" />
        <Card>
          <CardHeader>
            <CardTitle>Check catalog</CardTitle>
            <CardDescription>
              Filter by vector family, safety class, and last verdict. Showing{' '}
              <span className="tabular-nums">{visibleChecks.length}</span> of{' '}
              <span className="tabular-nums">{data.checks.length}</span> checks.
            </CardDescription>
          </CardHeader>
          <CardContent className="stack-tight">
            <div
              role="group"
              aria-label="Check catalog filters"
              style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 'var(--space-3)' }}
            >
              <Select
                label="Vector family"
                value={checkFilter}
                options={CHECK_FAMILY_FILTER_OPTIONS}
                onChange={(value) => setCheckFilter(value as CheckFamilyTabId)}
              />
              <Select
                label="Safety class"
                value={checkSafetyScope}
                options={CHECK_SAFETY_SCOPE_TABS.map((tab) => ({
                  value: tab.id,
                  label: `${tab.label} (${checkSafetyCounts[tab.id]})`
                }))}
                onChange={(value) => setCheckSafetyScope(value as CheckSafetyScopeId)}
              />
              <Select
                label="Last verdict"
                value={checkStatusFilter}
                options={CHECK_STATUS_FILTER_OPTIONS}
                onChange={setCheckStatusFilter}
              />
            </div>
            <DataTable
              columns={columns}
              items={visibleChecks}
              getRowProps={(item) => {
                const checkId = getString(item, ['check_id'], '');
                return checkId ? buildDetailHashRowProps('check-detail', checkId, `Open ${checkId}`) : {};
              }}
              empty={(
                data.checks.length === 0 ? (
                  <EmptyState icon={ListChecks} title="No checks in catalog." body="The check catalog appears after your tenant is provisioned and scope is declared." />
                ) : (
                  <EmptyState icon={ListChecks} title="No checks match these filters." body="Adjust the vector family, safety class, or last-verdict filter to see more checks." />
                )
              )}
            />
          </CardContent>
        </Card>
      </div>
    );
  }

  if (route === 'runs') {
    ensureFunctionalSurfaceStyles();
    const runColumns: TableColumn<DataItem>[] = [
      {
        key: 'run',
        label: 'Run',
        render: (item) => <code className="traffic-path-label" title={getString(item, ['id'])}>{getString(item, ['id'])}</code>
      },
      {
        key: 'group',
        label: 'Target group',
        render: (item) => resolveTargetGroupName(data.targetGroups, getString(item, ['target_group_id']))
      },
      {
        key: 'checks',
        label: 'Checks',
        render: (item) => {
          const checkCount = getNumber(item, ['check_count'], -1);
          if (checkCount >= 0) return <span className="num tabular-nums">{checkCount}</span>;
          return checkDisplayName(data.checks, getString(item, ['check_id']), getString(item, ['id']));
        }
      },
      {
        key: 'status',
        label: 'Status',
        render: (item) => {
          const status = getString(item, ['status'], 'planned');
          const inProgress = isInProgressRunStatus(status);
          const startedAgo = inProgress ? formatStartedAgo(item.started_at ?? item.created_at) : '';
          return (
            <span style={{ display: 'inline-flex', flexDirection: 'column', gap: '2px', alignItems: 'flex-start' }}>
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                {inProgress ? <span className="run-live-dot" aria-hidden="true" /> : null}
                <Badge tone={runStatusBadgeTone(status)} title="Run lifecycle status from API">
                  {inProgress ? `In progress · ${formatRunStatusLabel(status)}` : formatRunStatusLabel(status)}
                </Badge>
              </span>
              {startedAgo ? <span className="muted" style={{ fontSize: 'var(--text-xs)' }}>{startedAgo}</span> : null}
            </span>
          );
        }
      },
      {
        key: 'verdict',
        label: 'Verdict',
        render: (item) => {
          const verdict = getRunVerdictValue(item) || 'pending';
          return <Badge tone={verdictBadgeTone(verdict)} title="Correlated run verdict">{formatVerdictLabel(verdict)}</Badge>;
        }
      },
      {
        key: 'duration',
        label: 'Duration',
        render: (item) => <code className="traffic-path-label">{formatRunDuration(item)}</code>
      },
      {
        key: 'agent',
        label: 'Agent',
        render: (item) => <code className="traffic-path-label">{getString(item, ['agent_id', 'observed_agent_id'], '—')}</code>
      },
      {
        key: 'started',
        label: 'Started',
        render: (item) => <span className="muted">{formatDate(item.started_at ?? item.created_at)}</span>
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
          <div className="form-banner info" role="status" aria-live="polite">
            Runs in progress — live status auto-refreshes every 8s ({inFlightRuns.length} active). Verdicts appear when the observation window closes.
          </div>
        ) : null}
        {!canStartRun && startDisabledReason ? (
          <div className="form-banner neutral" role="note">
            Start a safe run from “Run safe checks” above once ready — {startDisabledReason}
          </div>
        ) : null}
        <MutationFeedbackBanner message={message} error={error} neutral />
        <Card>
          <CardHeader><CardTitle>Recent runs</CardTitle><CardDescription>safe runs · click a row to open the correlated verdict</CardDescription></CardHeader>
          <CardContent>
            <DataTable
              columns={runColumns}
              items={filteredRuns}
              getRowProps={(item) => {
                const id = getString(item, ['id'], '');
                return buildDetailHashRowProps('run-detail', id, `Open ${id} detail`);
              }}
              empty={renderFriendlyEmptyState({
                icon: Activity,
                title: 'No test runs yet.',
                body: 'Start a safe validation run after declaring target scope.',
                actionLabel: 'Start safe run',
                onAction: () => void startSafeRun()
              })}
            />
          </CardContent>
        </Card>
      </div>
    );
  }

  if (route === 'findings') {
    return (
      <div className="content">
        <PageHeader route="findings" />
        <MutationFeedbackBanner message={message} error={error} neutral />
        <Card>
          <CardHeader>
            <CardTitle>Findings</CardTitle>
            <CardDescription>click a card to open the correlated verdict</CardDescription>
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

