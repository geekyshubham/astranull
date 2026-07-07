import { useEffect, useState, type FormEvent, type ReactNode } from 'react';
import {
  Activity,
  Bot,
  CheckCircle2,
  ClipboardList,
  Clock3,
  FileCheck2,
  FileText,
  KeyRound,
  LifeBuoy,
  ListChecks,
  Network,
  PlugZap,
  RadioTower,
  ScanSearch,
  ServerCog,
  ShieldCheck,
  Siren,
  Target,
  TriangleAlert,
  UserCog
} from 'lucide-react';
import { ReadinessPostureDonut } from '../components/charts/readiness-posture-donut';
import { WafSummaryPanel } from '../components/dashboard/waf-summary-panel';
import { ScoreTrend } from '../components/charts/score-trend';
import { VectorHeatmap } from '../components/charts/vector-heatmap';
import { Badge } from '../components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { TargetGroupPicker } from '../components/policies/target-group-picker';
import { EmptyState } from '../components/ui/empty-state';
import { emptyStateFromApi, readMetaAction } from '../lib/empty-from-api';
import { ConfirmModal, formatMutationSuccessMessage, renderFriendlyEmptyState } from '../lib/crud-ui';
import { Progress, type ProgressTone } from '../components/ui/progress';
import { DataTable, type TableColumn } from '../components/ui/table';
import { Select, type SelectOption } from '../components/ui/select';
import { AnchorButton, Button } from '../components/ui/button';
import { Tabs } from '../components/ui/tabs';
import { buildApiHeaders, requestJson } from '../lib/api';
import { canAccessRoute } from '../lib/route-access';
import {
  ONBOARDING_HEARTBEAT_POLL_MS,
  ONBOARDING_PLACEMENT_TEST_CHECK_ID,
  agentHasRecentHeartbeat,
  extractPlacementDiagnosticsFromReadiness,
  placementTestComplete,
  resolveOnboardingHeartbeatState,
  summarizeOnboardingPlacementConfidenceHint
} from '../lib/onboarding';
import { resolveDashboardMetrics, resolveRecentRuns } from '../lib/dashboard-metrics';
import { buildEnvironmentReadinessRows } from '../lib/environments';
import { buildDetailHref } from '../lib/route-params';
import { DEFENSIVE_RULES, ROUTE_BY_ID } from '../lib/navigation';
import { routeTabs } from '../lib/prototype-manifest';
import type { DataItem, PortalConfig, PortalData, ReadinessFactor, RouteId, Session } from '../lib/types';
import { formatDate, formatNumber, scoreTone } from '../lib/utils';

function getString(item: DataItem, keys: string[], fallback = '—') {
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== '') return String(value);
  }
  return fallback;
}

function getNumber(item: DataItem, keys: string[], fallback = 0) {
  for (const key of keys) {
    const value = item[key];
    if (typeof value === 'number' && Number.isFinite(value)) return value;
  }
  return fallback;
}

function getNestedNumber(item: DataItem | null | undefined, path: string[], fallback = 0) {
  let current: unknown = item;
  for (const key of path) {
    if (!current || typeof current !== 'object' || Array.isArray(current)) return fallback;
    current = (current as DataItem)[key];
  }
  return typeof current === 'number' && Number.isFinite(current) ? current : fallback;
}

function getNestedItem(item: DataItem | null | undefined, path: string[]) {
  let current: unknown = item;
  for (const key of path) {
    if (!current || typeof current !== 'object' || Array.isArray(current)) return null;
    current = (current as DataItem)[key];
  }
  return current && typeof current === 'object' && !Array.isArray(current) ? current as DataItem : null;
}

function getNestedArray(item: DataItem | null | undefined, path: string[]) {
  let current: unknown = item;
  for (const key of path) {
    if (!current || typeof current !== 'object' || Array.isArray(current)) return [];
    current = (current as DataItem)[key];
  }
  return Array.isArray(current) ? current as DataItem[] : [];
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

function getHashQueryParam(key: string) {
  if (typeof window === 'undefined') return '';
  const hash = window.location.hash.replace(/^#/, '');
  const queryInHash = hash.includes('?') ? hash.slice(hash.indexOf('?') + 1) : '';
  const params = new URLSearchParams(queryInHash || window.location.search);
  return params.get(key) ?? '';
}

type UiBadgeTone = 'default' | 'success' | 'warn' | 'danger' | 'info' | 'muted';

function scoreProgressTone(score: number): ProgressTone {
  if (score >= 80) return 'success';
  if (score >= 55) return 'warn';
  return 'danger';
}

const TARGET_KIND_SELECT_OPTIONS: SelectOption[] = [
  { value: 'fqdn', label: 'FQDN' },
  { value: 'url', label: 'URL' },
  { value: 'ip_port', label: 'IP/Port' },
  { value: 'dns', label: 'DNS service' },
  { value: 'canary', label: 'Canary endpoint' }
];

const POLICY_CADENCE_OPTIONS: SelectOption[] = [
  { value: 'manual', label: 'Manual' },
  { value: 'daily', label: 'Daily' },
  { value: 'weekly', label: 'Weekly' },
  { value: 'monthly', label: 'Monthly' },
  { value: 'event_driven', label: 'Event-driven' }
];

const POLICY_VERDICT_OPTIONS: SelectOption[] = [
  { value: 'pass', label: 'Pass' },
  { value: 'warn', label: 'Warn' },
  { value: 'fail', label: 'Fail' },
  { value: 'manual_review', label: 'Manual review' }
];

const BOOTSTRAP_EXPIRY_OPTIONS: SelectOption[] = [
  { value: '15m', label: '15 minutes' },
  { value: '1h', label: '1 hour' },
  { value: '24h', label: '24 hours' }
];

function formatPolicyStateLabel(state: string) {
  if (state === 'paused') return 'Paused';
  if (state === 'active') return 'Active';
  return state.replace(/_/g, ' ');
}

function formatPolicyCadenceLabel(cadence: string) {
  return POLICY_CADENCE_OPTIONS.find((option) => option.value === cadence)?.label ?? cadence.replace(/_/g, ' ');
}

function formatPolicyVerdictLabel(verdict: string) {
  return POLICY_VERDICT_OPTIONS.find((option) => option.value === verdict)?.label ?? verdict.replace(/_/g, ' ');
}

function formatRunStatusLabel(status: string) {
  const labels: Record<string, string> = {
    planned: 'Planned',
    running: 'Running',
    collecting: 'Collecting',
    completed: 'Completed',
    verdicted: 'Verdicted',
    cancelled: 'Cancelled',
    failed: 'Failed'
  };
  return labels[status] ?? status.replace(/_/g, ' ');
}

function runStatusBadgeTone(status: string): UiBadgeTone {
  if (status === 'verdicted' || status === 'completed') return 'success';
  if (status === 'running' || status === 'collecting') return 'info';
  if (status === 'cancelled' || status === 'failed') return 'danger';
  if (status === 'planned') return 'muted';
  return 'warn';
}

function findingSeverityBadgeTone(severity: string): UiBadgeTone {
  const normalized = severity.toLowerCase();
  if (normalized === 'critical' || normalized === 'high') return 'danger';
  if (normalized === 'medium') return 'warn';
  if (normalized === 'low') return 'info';
  return 'muted';
}

function highScaleStateBadgeTone(state: string): UiBadgeTone {
  if (['submitted', 'under_review'].includes(state)) return 'warn';
  if (['approved', 'scheduled', 'completed', 'executed'].includes(state)) return 'success';
  if (['rejected', 'cancelled', 'stopped'].includes(state)) return 'danger';
  return 'info';
}

function lifecycleBadgeTone(state: string): UiBadgeTone {
  if (state === 'active') return 'success';
  if (state === 'suspended') return 'danger';
  return 'warn';
}

function subscriptionStatusBadgeTone(status: string): UiBadgeTone {
  if (status === 'active') return 'success';
  if (status === 'past_due' || status === 'suspended') return 'warn';
  if (status === 'cancelled') return 'muted';
  return 'info';
}

function DashboardWorkspaceSkeleton() {
  return (
    <div className="dashboard-grid" aria-busy="true" aria-live="polite">
      <Card className="score-card" density="compact">
        <CardContent className="stack-tight">
          <div className="skeleton skeleton-text" />
          <div className="skeleton" />
        </CardContent>
      </Card>
      <div className="metric-grid">
        {Array.from({ length: 4 }, (_, index) => (
          <Card key={index} className="metric-card" density="compact">
            <div className="skeleton skeleton-text" />
            <div className="skeleton skeleton-text" />
          </Card>
        ))}
      </div>
    </div>
  );
}

const SUPPORT_CONTACT_MAILTO = 'mailto:support@astranull.example?subject=AstraNull%20support%20request';

function featureEnabled(data: PortalData, key: 'waf_posture' | 'external_discovery' | 'connectors') {
  return Boolean(data.deploymentFeatures?.[key]);
}

export function PageHeader({
  route,
  eyebrow,
  variant = 'default',
  actions
}: {
  route: RouteId;
  eyebrow?: string;
  variant?: 'default' | 'detail';
  actions?: ReactNode;
}) {
  const item = ROUTE_BY_ID.get(route);
  if (variant === 'detail') {
    return (
      <div className="page-head page-head-detail">
        {eyebrow ? <p className="eyebrow">{eyebrow}</p> : null}
      </div>
    );
  }
  return (
    <div className="page-head">
      <div>
        <p className="eyebrow">{eyebrow ?? item?.group}</p>
        <h2>{item?.label}</h2>
        <p>{item?.description}</p>
      </div>
      {actions ? <div className="row-actions">{actions}</div> : null}
    </div>
  );
}

export function MetricCard({
  label,
  value,
  sub,
  icon: Icon,
  tone = 'default',
  showStatusBadge
}: {
  label: string;
  value: string | number;
  sub: string;
  icon: typeof Activity;
  tone?: 'default' | 'success' | 'warn' | 'danger' | 'info' | 'muted';
  /** When true, shows a corner status badge. Defaults to on for non-default tones. */
  showStatusBadge?: boolean;
}) {
  const cornerBadge = showStatusBadge ?? (tone === 'warn' || tone === 'danger');
  return (
    <Card className={cornerBadge ? 'metric-card' : 'metric-card plain-metric'}>
      <div className="metric-icon">
        <Icon size={18} />
      </div>
      <div>
        <span>{label}</span>
        <strong>{value}</strong>
        <p>{sub}</p>
      </div>
      {cornerBadge ? (
        <Badge tone={tone}>{tone === 'warn' ? 'attention' : 'critical'}</Badge>
      ) : null}
    </Card>
  );
}

/** One-line operational summary — use instead of hero metric grids on governed pages. */
export function PageContextSummary({ children }: { children: ReactNode }) {
  return <p className="page-context-summary">{children}</p>;
}

export function DefensiveRulesPanel() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Product guardrails</CardTitle>
        <CardDescription>Every workflow in this UI keeps the defensive validation rules visible.</CardDescription>
      </CardHeader>
      <CardContent className="rule-grid">
        {DEFENSIVE_RULES.map((rule) => (
          <div className="rule" key={rule.title}>
            <CheckCircle2 size={17} />
            <div>
              <strong>{rule.title}</strong>
              <p>{rule.body}</p>
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

type DashboardTabId = 'overview' | 'risk-trends';

const DASHBOARD_TAB_STORAGE_KEY = 'astranull-dashboard-tab';
const DASHBOARD_TAB_IDS: readonly DashboardTabId[] = ['overview', 'risk-trends'];

function readDashboardTabId(): DashboardTabId {
  const fromHash = getHashQueryParam('tab');
  if (DASHBOARD_TAB_IDS.includes(fromHash as DashboardTabId)) return fromHash as DashboardTabId;
  if (typeof window !== 'undefined') {
    const stored = window.sessionStorage.getItem(DASHBOARD_TAB_STORAGE_KEY);
    if (stored && DASHBOARD_TAB_IDS.includes(stored as DashboardTabId)) return stored as DashboardTabId;
  }
  return 'overview';
}

function persistDashboardTab(tab: DashboardTabId) {
  if (typeof window === 'undefined') return;
  window.sessionStorage.setItem(DASHBOARD_TAB_STORAGE_KEY, tab);
  const base = `${window.location.pathname}${window.location.search}#dashboard`;
  window.history.replaceState(null, '', `${base}?tab=${encodeURIComponent(tab)}`);
}

function agentsForTargetGroup(data: PortalData, groupId: string) {
  return data.agents.filter((agent) => getString(agent, ['target_group_id']) === groupId);
}

function businessServiceRows(data: PortalData) {
  return data.targetGroups
    .filter((group) => group.archived_at == null)
    .map((group) => {
      const groupId = getString(group, ['id'], '');
      const boundAgents = agentsForTargetGroup(data, groupId);
      const onlineAgents = boundAgents.filter((agent) => getString(agent, ['status']) === 'online').length;
      const openFindings = data.findings.filter((finding) =>
        getString(finding, ['target_group_id']) === groupId &&
        getString(finding, ['status'], 'open') === 'open'
      ).length;
      const completedRuns = data.runs.filter((run) =>
        getString(run, ['target_group_id']) === groupId &&
        ['completed', 'verdicted'].includes(getString(run, ['status']))
      ).length;
      return {
        group,
        groupId,
        boundAgents: boundAgents.length,
        onlineAgents,
        openFindings,
        completedRuns
      };
    });
}

function evidenceFeedRows(data: PortalData, limit = 10) {
  const custodyAudit = data.audit
    .filter((entry) => {
      const action = getString(entry, ['action', 'event_type']).toLowerCase();
      return action.includes('evidence') || action.includes('custody') || action.includes('export');
    })
    .map((entry) => ({
      id: getString(entry, ['id'], ''),
      kind: getString(entry, ['action', 'event_type'], 'audit'),
      created_at: entry.created_at ?? entry.timestamp,
      source: 'audit'
    }));

  const evidenceRows = [...data.evidence]
    .map((item) => ({
      id: getString(item, ['id'], ''),
      kind: getString(item, ['kind', 'type'], 'evidence'),
      created_at: item.created_at,
      source: 'evidence'
    }));

  return [...evidenceRows, ...custodyAudit]
    .sort((left, right) => String(right.created_at ?? '').localeCompare(String(left.created_at ?? '')))
    .slice(0, limit);
}

function targetGroupDisplayName(data: PortalData, groupId: string) {
  const group = data.targetGroups.find((item) => getString(item, ['id'], '') === groupId);
  return getString(group ?? {}, ['name', 'title'], groupId || '—');
}

function checkDisplayName(data: PortalData, checkId: string) {
  const check = data.checks.find((item) => getString(item, ['check_id'], '') === checkId);
  return getString(check ?? {}, ['name', 'title'], checkId || '—');
}

function runDisplayLabel(data: PortalData, run: DataItem) {
  const titled = getString(run, ['name', 'title'], '');
  if (titled) return titled;
  const checkName = checkDisplayName(data, getString(run, ['check_id']));
  const groupName = targetGroupDisplayName(data, getString(run, ['target_group_id']));
  return `${checkName} · ${groupName}`;
}

function evidenceDisplayLabel(item: DataItem) {
  return getString(item, ['title', 'label'], '') || getString(item, ['kind', 'type'], 'Evidence record');
}

function highScaleRequestLabel(data: PortalData, request: DataItem) {
  const objective = getString(request, ['objective', 'reason'], '').trim();
  if (objective) return objective;
  return targetGroupDisplayName(data, getString(request, ['target_group_id']));
}

type DashboardNextStep = { key: string; title: string; detail: string; href: string; tone: 'warn' | 'info' | 'success' };

function buildDashboardNextSteps(data: PortalData, metrics: ReturnType<typeof resolveDashboardMetrics>): DashboardNextStep[] {
  const steps: DashboardNextStep[] = [];
  const activeGroups = data.targetGroups.filter((group) => group.archived_at == null);
  if (activeGroups.length === 0) {
    steps.push({
      key: 'declare-scope',
      title: 'Declare your first target group',
      detail: 'Add the business services you want to validate before any checks can run.',
      href: '#target-groups',
      tone: 'info'
    });
  }
  if (metrics.agentsOnline === 0 && data.agents.length === 0) {
    steps.push({
      key: 'install-agent',
      title: 'Install an outbound observation agent',
      detail: 'Issue a bootstrap token and confirm heartbeat so inside observations correlate with probes.',
      href: '#target-groups',
      tone: 'info'
    });
  }
  if (metrics.openFindings > 0) {
    const topFinding = data.findings.find((finding) => getString(finding, ['status'], 'open') === 'open');
    const findingId = getString(topFinding ?? {}, ['id'], '');
    steps.push({
      key: 'triage-findings',
      title: `Triage ${metrics.openFindings} open finding${metrics.openFindings === 1 ? '' : 's'}`,
      detail: topFinding ? getString(topFinding, ['title'], 'Review evidence-backed gaps.') : 'Review evidence-backed gaps.',
      href: findingId ? buildDetailHref('finding-detail', findingId) : '#findings',
      tone: 'warn'
    });
  }
  if (!data.runs.some((run) => ['completed', 'verdicted'].includes(getString(run, ['status'])))) {
    steps.push({
      key: 'first-run',
      title: 'Run a bounded safe validation',
      detail: 'Complete at least one low-volume check to populate readiness evidence.',
      href: '#runs',
      tone: 'info'
    });
  }
  if (data.highScale.some((request) => ['submitted', 'under_review'].includes(getString(request, ['state'])))) {
    steps.push({
      key: 'high-scale-pack',
      title: 'Finish high-scale authorization metadata',
      detail: 'SOC review stays blocked until required authorization artifacts are uploaded.',
      href: '#runs',
      tone: 'warn'
    });
  }
  return steps.slice(0, 5);
}

function declaredEnvironmentComplete(data: PortalData) {
  const fromGroups = new Set(
    data.targetGroups
      .filter((group) => group.archived_at == null)
      .map((group) => getString(group, ['environment_id'], '').trim())
      .filter(Boolean)
  );
  if (fromGroups.size > 0) return true;
  return data.bootstrapTokens.some((token) => getString(token, ['environment_id'], '').trim() !== '');
}

function declaredTargetGroupComplete(data: PortalData) {
  return data.targetGroups.some((group) => group.archived_at == null);
}

export function DashboardPage({ data }: { data: PortalData }) {
  const [tab, setTab] = useState<DashboardTabId>(readDashboardTabId);
  const tabOptions = routeTabs('dashboard').map((item) => ({ id: item.id as DashboardTabId, label: item.label }));
  const workspaceHydrating = !data.state && data.targetGroups.length === 0 && data.runs.length === 0;

  useEffect(() => {
    const onHashChange = () => {
      const next = readDashboardTabId();
      setTab((current) => (current === next ? current : next));
    };
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);

  function handleDashboardTabChange(next: DashboardTabId) {
    setTab(next);
    persistDashboardTab(next);
  }
  const score = typeof data.state?.readiness?.score === 'number' ? data.state.readiness.score : null;
  const factors = Array.isArray(data.state?.readiness?.factors) ? data.state.readiness.factors : [];
  const metrics = resolveDashboardMetrics(data);
  const recentRuns = resolveRecentRuns(data);
  const openFindingRows = data.findings
    .filter((finding) => getString(finding, ['status'], 'open') === 'open')
    .slice(0, 5);
  const agingFindings = [...data.findings]
    .filter((finding) => getString(finding, ['status'], 'open') === 'open')
    .sort((left, right) => String(left.created_at ?? left.id ?? '').localeCompare(String(right.created_at ?? right.id ?? '')))
    .slice(0, 8);
  const nextSteps = buildDashboardNextSteps(data, metrics);
  const prioritizedNext = nextSteps[0] ?? null;
  const topTargetGroups = [...data.targetGroups]
    .sort((left, right) => String(right.criticality ?? right.business_criticality ?? '').localeCompare(String(left.criticality ?? left.business_criticality ?? '')))
    .slice(0, 4);
  const topAgents = [...data.agents].slice(0, 4);
  const agentsOnline = metrics.agentsOnline;
  const agentsTotal = data.agents.length;
  const lastValidation = recentRuns[0] ? formatDate(recentRuns[0].created_at ?? recentRuns[0].started_at) : '—';

  return (
    <div className="content">
      <PageHeader route="dashboard" eyebrow="Readiness command center" />
      <Tabs value={tab} options={tabOptions} onChange={handleDashboardTabChange} className="tabs-wrap" />
      {tab === 'overview' ? (
        workspaceHydrating ? (
          <DashboardWorkspaceSkeleton />
        ) : (
        <>
          <div className="metric-grid four">
            <MetricCard label="Readiness score" value={score ?? '—'} sub="Evidence-backed readiness from state API" icon={Activity} tone={score === null ? 'muted' : 'info'} />
            <MetricCard label="Open findings" value={metrics.openFindings} sub="Evidence-backed gaps" icon={TriangleAlert} tone={metrics.openFindings > 0 ? 'warn' : 'success'} />
            <MetricCard label="Agents online" value={`${agentsOnline}/${agentsTotal || agentsOnline}`} sub="Outbound-only observers" icon={Bot} tone="success" />
            <MetricCard label="Last validation" value={lastValidation} sub={recentRuns[0] ? getString(recentRuns[0], ['id'], 'recent run') : 'No runs yet'} icon={ListChecks} tone="muted" />
          </div>

          <Card>
            <CardHeader>
              <CardTitle>Readiness posture</CardTitle>
              <CardDescription>Segmented pass, review, and gap counts from correlated checks.</CardDescription>
            </CardHeader>
            <CardContent>
              <ReadinessPostureDonut state={data.state} runs={data.runs} checks={data.checks} />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Correlation matrix</CardTitle>
              <CardDescription>Vector coverage by declared target group.</CardDescription>
            </CardHeader>
            <CardContent>
              <VectorHeatmap checks={data.checks} targetGroups={data.targetGroups} testPolicies={data.testPolicies} runs={data.runs} evidence={data.evidence} />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>WAF summary</CardTitle>
              <CardDescription>Rolled up across declared target groups. Per-target detail on the target page.</CardDescription>
            </CardHeader>
            <CardContent>
              <WafSummaryPanel summary={data.wafCoverageSummary} />
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>What to do next</CardTitle>
              <CardDescription>One prioritized action from your current readiness posture — complete it before diving into charts and feeds.</CardDescription>
            </CardHeader>
            <CardContent>
              {!prioritizedNext ? (
                <EmptyState icon={CheckCircle2} title="No urgent setup steps." body="Keep running safe validations and triage new findings as evidence arrives." actionLabel="Open test runs" actionHref="#runs" />
              ) : (
                <div className="stack-tight">
                  <div className="row-actions">
                    <Badge tone={prioritizedNext.tone}>{prioritizedNext.tone === 'warn' ? 'priority' : 'suggested'}</Badge>
                    <strong>{prioritizedNext.title}</strong>
                  </div>
                  <p className="muted">{prioritizedNext.detail}</p>
                  <AnchorButton href={prioritizedNext.href} variant="secondary" size="sm">Go to step</AnchorButton>
                  {nextSteps.length > 1 ? (
                    <ul className="dashboard-link-list muted">
                      {nextSteps.slice(1, 4).map((step) => (
                        <li key={step.key}>
                          <div>
                            <strong>{step.title}</strong>
                            <span>{step.detail}</span>
                          </div>
                          <AnchorButton size="sm" variant="ghost" href={step.href}>Open</AnchorButton>
                        </li>
                      ))}
                    </ul>
                  ) : null}
                </div>
              )}
            </CardContent>
          </Card>
          <div className="split split--single">
            <Card>
              <CardHeader>
                <CardTitle>Weighted factors</CardTitle>
                <CardDescription>
                  No factor can pass without supporting evidence. Heatmap, aging findings, and the evidence feed live on the Risk Trends and Evidence Feed tabs.
                </CardDescription>
              </CardHeader>
              <CardContent className="factor-list">
                {factors.length === 0 ? (
                  <EmptyState
                    icon={FileCheck2}
                    title="No readiness factors returned."
                    body="Factors appear after the platform publishes evidence-backed scoring inputs."
                    actionLabel="Open target groups"
                    actionHref="#target-groups"
                  />
                ) : (
                  factors.map((factor: ReadinessFactor) => {
                    const value = Math.round(factor.score ?? 0);
                    return (
                      <div className="factor" key={factor.key ?? factor.label}>
                        <div>
                          <strong>{factor.label ?? factor.key}</strong>
                          <span>{factor.reason ?? factor.detail ?? 'Awaiting evidence.'}</span>
                        </div>
                        <Badge tone={scoreTone(value)}>{value}%</Badge>
                        <Progress value={value} tone={scoreProgressTone(value)} label={factor.label ?? factor.key ?? 'Readiness factor'} />
                      </div>
                    );
                  })
                )}
              </CardContent>
            </Card>
          </div>
          <div className="split">
            <Card>
              <CardHeader>
                <CardTitle>Recent test runs</CardTitle>
                <CardDescription>Latest bounded validation activity with links to run detail.</CardDescription>
              </CardHeader>
              <CardContent>
                {recentRuns.length === 0 ? (
                  <EmptyState icon={ListChecks} title="No test runs yet." body="Start a safe validation from Test Runs after declaring scope." actionLabel="Open test runs" actionHref="#runs" />
                ) : (
                  <ul className="dashboard-link-list">
                    {recentRuns.map((run) => {
                      const id = getString(run, ['id'], '');
                      const href = buildDetailHref('run-detail', id);
                      return (
                        <li key={id}>
                          <div>
                            <strong>{runDisplayLabel(data, run)}</strong>
                            <span className="row-actions">
                              <Badge tone={runStatusBadgeTone(getString(run, ['status']))}>{formatRunStatusLabel(getString(run, ['status']))}</Badge>
                              <span className="muted">{formatDate(run.created_at ?? run.started_at)}</span>
                            </span>
                          </div>
                          <AnchorButton size="sm" variant="secondary" href={href}>Open</AnchorButton>
                        </li>
                      );
                    })}
                  </ul>
                )}
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>Open findings</CardTitle>
                <CardDescription>Evidence-backed gaps that still need triage or remediation.</CardDescription>
              </CardHeader>
              <CardContent>
                {openFindingRows.length === 0 ? (
                  <EmptyState icon={TriangleAlert} title="No open findings." body="Findings appear after validation runs produce evidence-backed gaps." actionLabel="Open findings" actionHref="#findings" />
                ) : (
                  <ul className="dashboard-link-list">
                    {openFindingRows.map((finding) => {
                      const id = getString(finding, ['id'], '');
                      const href = id ? buildDetailHref('finding-detail', id) : '#findings';
                      return (
                        <li key={id}>
                          <div>
                            <strong>{getString(finding, ['title', 'id'])}</strong>
                            <span className="row-actions">
                              <Badge tone={findingSeverityBadgeTone(getString(finding, ['severity']))}>{getString(finding, ['severity'], 'unknown')}</Badge>
                              <span className="muted">{getString(finding, ['assignee'], 'unassigned')}</span>
                            </span>
                          </div>
                          <AnchorButton size="sm" variant="secondary" href={href}>Triage</AnchorButton>
                        </li>
                      );
                    })}
                  </ul>
                )}
              </CardContent>
            </Card>
          </div>
          <div className="split">
            <Card>
              <CardHeader>
                <CardTitle>Target group status</CardTitle>
                <CardDescription>Top groups by criticality from target group API.</CardDescription>
              </CardHeader>
              <CardContent>
                {topTargetGroups.length === 0 ? (
                  <EmptyState icon={Target} title="No target groups yet." body="Declare target groups to map business services to validation scope." actionHref="#target-groups" actionLabel="Open target groups" />
                ) : (
                  <ul className="dashboard-link-list">
                    {topTargetGroups.map((group) => {
                      const id = getString(group, ['id'], '');
                      const open = data.findings.filter((finding) => getString(finding, ['target_group_id']) === id && getString(finding, ['status']) === 'open').length;
                      return (
                        <li key={id}>
                          <div>
                            <strong>{getString(group, ['name', 'id'], id)}</strong>
                            <span className="muted">{open} open findings</span>
                          </div>
                          <AnchorButton size="sm" variant="secondary" href={buildDetailHref('target-group-detail', id)}>Open</AnchorButton>
                        </li>
                      );
                    })}
                  </ul>
                )}
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>Agent health</CardTitle>
                <CardDescription>Outbound-only heartbeat readout.</CardDescription>
              </CardHeader>
              <CardContent>
                {topAgents.length === 0 ? (
                  <EmptyState icon={Bot} title="No agents registered." body="Install an outbound agent after declaring target scope." actionHref="#agents" actionLabel="Open agents" />
                ) : (
                  <ul className="dashboard-link-list">
                    {topAgents.map((agent) => {
                      const id = getString(agent, ['id'], '');
                      return (
                        <li key={id}>
                          <div>
                            <strong>{getString(agent, ['hostname', 'name', 'id'], id)}</strong>
                            <span className="row-actions">
                              <Badge tone={getString(agent, ['status']) === 'online' ? 'success' : 'warn'} title={`Agent status ${getString(agent, ['status'], 'unknown')} from agents API`}>{getString(agent, ['status'], 'unknown')}</Badge>
                              <span className="muted">{formatDate(agent.last_heartbeat_at ?? agent.updated_at)}</span>
                            </span>
                          </div>
                          <AnchorButton size="sm" variant="secondary" href={buildDetailHref('agent-detail', id)}>Open</AnchorButton>
                        </li>
                      );
                    })}
                  </ul>
                )}
              </CardContent>
            </Card>
          </div>
          <details className="full">
            <summary>Product guardrails (defensive validation rules)</summary>
            <DefensiveRulesPanel />
          </details>
        </>
        )
      ) : null}
      {tab === 'risk-trends' ? (
        <div className="risk-trends-grid">
          <Card>
            <CardHeader>
              <CardTitle>Readiness trend</CardTitle>
              <CardDescription>Score trajectory derived from bounded validation run history.</CardDescription>
            </CardHeader>
            <CardContent>
              {score === null ? (
                <EmptyState icon={Activity} title="Readiness score unavailable." body="Trend appears after the platform publishes an evidence-backed score." />
              ) : (
                <ScoreTrend runs={data.runs} currentScore={score} />
              )}
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Vector coverage matrix</CardTitle>
              <CardDescription>Coverage by vector family and declared target group.</CardDescription>
            </CardHeader>
            <CardContent>
              <VectorHeatmap
                checks={data.checks}
                targetGroups={data.targetGroups}
                testPolicies={data.testPolicies}
                runs={data.runs}
                evidence={data.evidence}
              />
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Aging open findings</CardTitle>
              <CardDescription>Oldest open gaps that still pressure readiness.</CardDescription>
            </CardHeader>
            <CardContent>
              {agingFindings.length === 0 ? (
                <EmptyState icon={TriangleAlert} title="No open findings." body="Open findings appear after validation runs produce evidence-backed gaps." actionLabel="Open findings" actionHref="#findings" />
              ) : (
                <ul className="dashboard-link-list">
                  {agingFindings.map((finding) => {
                    const id = getString(finding, ['id'], '');
                    return (
                      <li key={id}>
                        <div>
                          <strong>{getString(finding, ['title', 'id'])}</strong>
                          <span className="row-actions">
                            <Badge tone={findingSeverityBadgeTone(getString(finding, ['severity']))}>{getString(finding, ['severity'], 'unknown')}</Badge>
                            <span className="muted">opened {formatDate(finding.created_at)}</span>
                          </span>
                        </div>
                        <AnchorButton size="sm" variant="secondary" href={id ? buildDetailHref('finding-detail', id) : '#findings'}>Triage</AnchorButton>
                      </li>
                    );
                  })}
                </ul>
              )}
            </CardContent>
          </Card>
        </div>
      ) : null}

    </div>
  );
}

export function OnboardingPage({
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
  const [heartbeatSkipped, setHeartbeatSkipped] = useState(false);
  const [pollStartedAt, setPollStartedAt] = useState<number | null>(null);
  const [polledAgents, setPolledAgents] = useState<DataItem[] | null>(null);
  const [heartbeatPollError, setHeartbeatPollError] = useState('');
  const firstGroup = data.targetGroups[0] ?? null;
  const firstTargetId = getString(firstGroup ?? {}, ['first_target_id'], '');
  const safeCheck = data.checks.find((check) => getString(check, ['safety_class']) === 'safe') ?? data.checks[0] ?? null;
  const placementDiagnostics = extractPlacementDiagnosticsFromReadiness(data.state?.readiness as DataItem | undefined);
  const agentsForHeartbeat = polledAgents ?? data.agents;
  const heartbeatState = resolveOnboardingHeartbeatState(agentsForHeartbeat, {
    pollStartedAt: pollStartedAt ?? undefined
  });
  const placementHint = summarizeOnboardingPlacementConfidenceHint(
    heartbeatState.agents[0] ?? agentsForHeartbeat[0] ?? null,
    placementDiagnostics
  );
  const placementDone = placementTestComplete(data.runs);
  const heartbeatVerified = heartbeatSkipped
    || agentsForHeartbeat.some((agent) => agentHasRecentHeartbeat(agent));
  const steps = [
    ['Environment', declaredEnvironmentComplete(data)],
    ['Target group', declaredTargetGroupComplete(data)],
    ['Bootstrap token', data.bootstrapTokens.length > 0 || Boolean(tokenSecret)],
    ['Agent heartbeat', heartbeatVerified],
    ['Placement test', placementDone],
    ['First safe run', data.runs.some((run) =>
      getString(run, ['check_id']) !== ONBOARDING_PLACEMENT_TEST_CHECK_ID
      && ['completed', 'verdicted', 'running'].includes(getString(run, ['status']))
    )]
  ] as const;

  const shouldPollHeartbeat = Boolean(tokenSecret || data.bootstrapTokens.length > 0)
    && !heartbeatSkipped
    && heartbeatState.status !== 'online'
    && heartbeatState.status !== 'timeout';

  useEffect(() => {
    if (!shouldPollHeartbeat) return undefined;
    const startedAt = pollStartedAt ?? Date.now();
    if (pollStartedAt === null) setPollStartedAt(startedAt);

    async function pollAgents() {
      try {
        const payload = await requestJson(config, session, '/v1/agents') as { items?: DataItem[] };
        const items = Array.isArray(payload.items) ? payload.items : [];
        setPolledAgents(items);
        setHeartbeatPollError('');
        const state = resolveOnboardingHeartbeatState(items, { pollStartedAt: startedAt });
        if (state.status === 'online' || state.status === 'timeout') {
          await onRefresh();
        }
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Agent heartbeat poll failed.';
        setHeartbeatPollError(`${message} Retrying every ${ONBOARDING_HEARTBEAT_POLL_MS / 1000}s.`);
      }
    }

    void pollAgents();
    const timer = window.setInterval(() => {
      void pollAgents();
    }, ONBOARDING_HEARTBEAT_POLL_MS);
    return () => window.clearInterval(timer);
  }, [config, session, onRefresh, pollStartedAt, shouldPollHeartbeat]);

  async function runOnboardingAction<T>(label: string, action: () => Promise<T>, success: string) {
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
      setError(payload?.message ?? payload?.error ?? (err instanceof Error ? err.message : 'Onboarding action failed.'));
      return null;
    } finally {
      setBusy('');
    }
  }

  async function handleCreateScope(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const created = await runOnboardingAction('onboard-create-group', async () => {
      const group = await requestJson(config, session, '/v1/target-groups', {
        method: 'POST',
        body: {
          name: String(form.get('name') ?? 'Onboarding group').trim(),
          environment_id: String(form.get('environment_id') ?? 'env_onboarding').trim(),
          timezone: 'UTC'
        }
      }) as DataItem;
      const groupId = getString(group, ['id'], '');
      if (String(form.get('target_value') ?? '').trim()) {
        await requestJson(config, session, `/v1/target-groups/${groupId}/targets`, {
          method: 'POST',
          body: {
            kind: 'fqdn',
            value: String(form.get('target_value') ?? '').trim()
          }
        });
      }
      return group;
    }, 'Declared target group and optional first target created.');
    if (created) event.currentTarget.reset();
  }

  async function createBootstrapToken() {
    const created = await runOnboardingAction('onboard-create-token', () => requestJson(config, session, '/v1/bootstrap-tokens', {
      method: 'POST',
      body: {
        name: 'onboarding-install',
        environment_id: getString(firstGroup, ['environment_id'], 'env_demo'),
        ...(getString(firstGroup, ['id'], '') ? { target_group_id: getString(firstGroup, ['id'], '') } : {}),
        expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
        max_registrations: 1
      }
    }), 'Bootstrap token created. Copy the one-time secret now.');
    const secret = getString(created as DataItem, ['secret'], getNestedString(created as DataItem, ['token', 'secret'], ''));
    if (secret) setTokenSecret(secret);
  }

  async function resolveFirstTargetId(targetGroupId: string) {
    let targetId = firstTargetId;
    if (!targetId) {
      const detail = await requestJson(config, session, `/v1/target-groups/${targetGroupId}`) as DataItem;
      const targets = Array.isArray(detail.targets) ? detail.targets as DataItem[] : [];
      targetId = getString(targets[0] ?? {}, ['id'], '');
    }
    return targetId;
  }

  async function handleStartRun() {
    const targetGroupId = getString(firstGroup, ['id'], '');
    const checkId = getString(safeCheck ?? {}, ['check_id'], '');
    if (!targetGroupId || !checkId) {
      setError('Create a target group and ensure a safe check exists before starting a run.');
      return;
    }
    const targetId = await resolveFirstTargetId(targetGroupId);
    if (!targetId) {
      setError('Add at least one declared target before starting a safe validation run.');
      return;
    }
    await runOnboardingAction('onboard-start-run', () => requestJson(config, session, '/v1/test-runs', {
      method: 'POST',
      body: { target_group_id: targetGroupId, target_id: targetId, check_id: checkId }
    }), 'Safe validation run started from onboarding.');
  }

  async function handleStartPlacementTest() {
    const targetGroupId = getString(firstGroup, ['id'], '');
    if (!targetGroupId) {
      setError('Create a target group before starting the placement test.');
      return;
    }
    const targetId = await resolveFirstTargetId(targetGroupId);
    if (!targetId) {
      setError('Add at least one declared target before starting the placement test.');
      return;
    }
    await runOnboardingAction('onboard-start-placement-test', () => requestJson(config, session, '/v1/test-runs', {
      method: 'POST',
      body: {
        target_group_id: targetGroupId,
        target_id: targetId,
        check_id: ONBOARDING_PLACEMENT_TEST_CHECK_ID
      }
    }), 'Placement test run started — inspect observations on Test Runs when complete.');
  }

  const installToken = tokenSecret || '<BOOTSTRAP_TOKEN>';
  const heartbeatSeconds = Math.floor((heartbeatState.elapsedMs ?? 0) / 1000);
  return (
    <div className="content">
      <PageHeader route="target-groups" eyebrow="Guided setup" />
      {(message || error) && <div className={error ? 'form-banner error' : 'form-banner'}>{error || message}</div>}
      <Card>
        <CardHeader>
          <CardTitle>First validation path</CardTitle>
          <CardDescription>One environment, one target group, one outbound agent, one bounded validation run.</CardDescription>
        </CardHeader>
        <CardContent className="step-grid">
          {steps.flatMap(([label, complete], stepIndex) => (complete ? [] : [(
            <div className="step-card" key={label}>
              <span>{stepIndex + 1}</span>
              <strong>{label}</strong>
              <p>Not started</p>
            </div>
          )]))}
          {steps.some(([, complete]) => complete) ? (
            <details className="full">
              <summary>{steps.filter(([, complete]) => complete).length} completed step(s)</summary>
              <div className="step-grid">
                {steps.filter(([, complete]) => complete).map(([label]) => (
                  <div className="step-card done" key={label}>
                    <span><CheckCircle2 size={16} /></span>
                    <strong>{label}</strong>
                    <p>Complete</p>
                  </div>
                ))}
              </div>
            </details>
          ) : null}
        </CardContent>
      </Card>
      <div className="split">
        <Card>
          <CardHeader>
            <CardTitle>Create declared scope</CardTitle>
            <CardDescription>Step 1: create the first target group and optional FQDN target.</CardDescription>
          </CardHeader>
          <CardContent>
            <form className="product-form" onSubmit={handleCreateScope} aria-busy={busy === 'onboard-create-group' || undefined}>
              <fieldset disabled={busy !== ''}>
              <label><span>Group name</span><input name="name" defaultValue="Onboarding origin group" required /></label>
              <label>
                <span>Environment ID</span>
                <input name="environment_id" defaultValue="env_onboarding" placeholder="production" required />
              </label>
              <p className="muted full">Opaque environment slug stored on the target group — see <AnchorButton href="#environments" variant="ghost" size="sm">Environments</AnchorButton> for readiness by environment.</p>
              <label className="full"><span>First target (optional)</span><input name="target_value" placeholder="origin.example.com" /></label>
              <div className="form-actions full"><Button type="submit" loading={busy === 'onboard-create-group'}>Create target group</Button></div>
              </fieldset>
            </form>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Bootstrap token and safe run</CardTitle>
            <CardDescription>Step 2–3: issue install token, then start the first bounded validation run.</CardDescription>
          </CardHeader>
          <CardContent className="product-form">
            <div className="form-actions full">
              <Button loading={busy === 'onboard-create-token'} disabled={busy !== ''} onClick={() => void createBootstrapToken()}>Create bootstrap token</Button>
              <Button variant="secondary" loading={busy === 'onboard-start-run'} disabled={busy !== '' || !firstGroup || !safeCheck} onClick={() => void handleStartRun()}>Start safe validation run</Button>
            </div>
            {tokenSecret ? (
              <>
                <pre className="codeblock">{`curl -fsSL ${typeof window !== 'undefined' ? window.location.origin : ''}/agents/install.sh \\
  | sudo ASTRANULL_API_URL="${typeof window !== 'undefined' ? window.location.origin : ''}" \\
       ASTRANULL_BOOTSTRAP_TOKEN="${installToken}" bash`}</pre>
                <p className="muted">One-time token shown. It will not be displayed again after refresh.</p>
              </>
            ) : (
              <p className="muted">Create a bootstrap token to reveal the one-time install command.</p>
            )}
          </CardContent>
        </Card>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Agent heartbeat verification</CardTitle>
          <CardDescription>Checks for a fresh agent heartbeat every {ONBOARDING_HEARTBEAT_POLL_MS / 1000}s after a bootstrap token is issued.</CardDescription>
        </CardHeader>
        <CardContent>
          {heartbeatState.status === 'online' ? (
            <div className="onboarding-heartbeat-panel onboarding-heartbeat-panel--online">
              <p className="onboarding-heartbeat-status onboarding-heartbeat-status--online">
                Agent online — last heartbeat {getString(heartbeatState.agents[0] ?? {}, ['last_heartbeat_at'], 'received')}.
              </p>
              <p className="muted onboarding-placement-hint"><strong>Placement confidence:</strong> {placementHint}</p>
              <p className="muted">Proceed to the optional placement test or start the first safe validation.</p>
            </div>
          ) : heartbeatState.status === 'timeout' ? (
            <div className="onboarding-heartbeat-panel onboarding-heartbeat-panel--timeout">
              <EmptyState
                icon={Clock3}
                title="Heartbeat timeout reached."
                body="No fresh agent heartbeat was observed within the onboarding window. Continue without an agent or regenerate the bootstrap token."
                actionLabel="Open Agents (install)"
                actionHref="#agents"
              />
              {!heartbeatSkipped ? (
                <div className="form-actions">
                  <Button
                    variant="secondary"
                    disabled={busy !== ''}
                    onClick={() => {
                      if (!window.confirm('Continue without an agent? Inside observations will be missing and readiness correlation will be degraded.')) return;
                      setHeartbeatSkipped(true);
                    }}
                  >
                    Continue without agent
                  </Button>
                </div>
              ) : null}
            </div>
          ) : (
            <div className="onboarding-heartbeat-panel onboarding-heartbeat-panel--waiting" aria-busy="true">
              <p className="onboarding-heartbeat-status onboarding-heartbeat-status--waiting" aria-live="polite">
                <span className="onboarding-heartbeat-spinner" aria-hidden="true" />
                <Badge tone="info">Listening</Badge>
                {heartbeatState.status === 'stale'
                  ? 'Agent registered but heartbeat is stale — waiting for a fresh heartbeat…'
                  : 'Waiting for agent heartbeat…'}
              </p>
              <div className="skeleton-row" aria-hidden="true">
                <div className="skeleton skeleton-text" />
                <div className="skeleton skeleton-text" />
              </div>
              <p className="muted">Listening for agent heartbeats every {ONBOARDING_HEARTBEAT_POLL_MS / 1000}s (elapsed {heartbeatSeconds}s).</p>
              {heartbeatPollError ? <div className="form-banner error">{heartbeatPollError}</div> : null}
              <p className="muted onboarding-placement-hint"><strong>Placement confidence:</strong> {placementHint}</p>
              <div className="row-actions onboarding-troubleshoot">
                <span className="muted">Agent not connecting?</span>
                <AnchorButton size="sm" variant="secondary" href="#agents">Open Agents (install)</AnchorButton>
                <Button size="sm" variant="secondary" loading={busy === 'onboard-create-token'} disabled={busy !== ''} onClick={() => void createBootstrapToken()}>Create bootstrap token</Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Placement test</CardTitle>
          <CardDescription>Runs a bounded protected-path canary check — metadata only, no exploit payloads.</CardDescription>
        </CardHeader>
        <CardContent className="product-form">
          {placementDone ? (
            <p className="muted onboarding-placement-done">Placement test run started — inspect observations on Test Runs when complete.</p>
          ) : (
            <>
              <Button loading={busy === 'onboard-start-placement-test'} disabled={busy !== '' || !firstGroup} onClick={() => void handleStartPlacementTest()}>Start placement test</Button>
              <p className="muted">Optional — skip if you will run the first safe validation immediately after heartbeat verification.</p>
            </>
          )}
          <div className="callout-list">
            <div className="callout info"><RadioTower size={18} /><span>Install where the agent can observe target traffic.</span></div>
            <div className="callout warn"><Clock3 size={18} /><span>Run a safe canary before relying on verdicts.</span></div>
            <div className="callout"><FileCheck2 size={18} /><span>Evidence vault records the placement signal.</span></div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

export function TargetGroupsPage({
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
  const [addTargetGroupId, setAddTargetGroupId] = useState(() => getString(data.targetGroups[0] ?? {}, ['id'], ''));
  const [addTargetKind, setAddTargetKind] = useState('fqdn');
  const [environmentFilter, setEnvironmentFilter] = useState(() => getHashQueryParam('environment_id'));
  const [showCreateMoreOptions, setShowCreateMoreOptions] = useState(false);
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const environments = [...new Set(data.targetGroups.map((group) => getString(group, ['environment_id'], '')).filter(Boolean))];
  const declaredTargetTotal = data.targetGroups.reduce((sum, group) => sum + getNumber(group, ['target_count']), 0);
  const filteredGroups = environmentFilter
    ? data.targetGroups.filter((group) => getString(group, ['environment_id'], '') === environmentFilter)
    : data.targetGroups;
  const addTargetGroup = data.targetGroups.find((group) => getString(group, ['id'], '') === addTargetGroupId) ?? data.targetGroups[0] ?? null;
  const effectiveGroupId = getString(addTargetGroup ?? {}, ['id'], addTargetGroupId);

  useEffect(() => {
    const onHashChange = () => setEnvironmentFilter(getHashQueryParam('environment_id'));
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);

  useEffect(() => {
    const firstId = getString(filteredGroups[0] ?? data.targetGroups[0] ?? {}, ['id'], '');
    if (!addTargetGroupId && firstId) setAddTargetGroupId(firstId);
    if (addTargetGroupId && filteredGroups.length > 0 && !filteredGroups.some((group) => getString(group, ['id'], '') === addTargetGroupId)) {
      setAddTargetGroupId(getString(filteredGroups[0], ['id'], ''));
    }
  }, [data.targetGroups, filteredGroups, addTargetGroupId]);

  const groupColumns: TableColumn<DataItem>[] = [
    { key: 'name', label: 'Group', render: (item) => getString(item, ['name', 'id']) },
    { key: 'env', label: 'Environment', render: (item) => getString(item, ['environment_id']) },
    { key: 'timezone', label: 'Timezone', render: (item) => getString(item, ['timezone']) },
    { key: 'created', label: 'Created', render: (item) => formatDate(item.created_at) },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        return (
          <AnchorButton size="sm" variant="secondary" href={buildDetailHref('target-group-detail', id)}>Manage</AnchorButton>
        );
      }
    }
  ];

  async function runTargetAction<T>(label: string, action: () => Promise<T>, success: string) {
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
      setError(payload?.message ?? payload?.error ?? (err instanceof Error ? err.message : 'Action failed.'));
      return null;
    } finally {
      setBusy('');
    }
  }

  async function handleCreateGroup(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const name = String(form.get('name') ?? '').trim();
    if (!name) {
      setError('Target group name is required.');
      return;
    }
    const created = await runTargetAction('create-target-group', () => requestJson(config, session, '/v1/target-groups', {
      method: 'POST',
      body: {
        name,
        environment_id: String(form.get('environment_id') ?? 'prod').trim() || 'prod',
        description: String(form.get('description') ?? '').trim(),
        timezone: String(form.get('timezone') ?? 'UTC').trim() || 'UTC',
        safety_policy: {
          max_concurrent_runs: Number(form.get('max_concurrent_runs') ?? 1),
          min_seconds_between_runs: Number(form.get('min_seconds_between_runs') ?? 300)
        }
      }
    }), 'Target group created from declared customer scope.');
    if (created && typeof created === 'object' && 'id' in created) {
      const id = String((created as { id: string }).id);
      setAddTargetGroupId(id);
      formElement.reset();
    }
  }

  async function handleAddTarget(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!effectiveGroupId) {
      setError('Create or select a target group before adding a target.');
      return;
    }
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const value = String(form.get('value') ?? '').trim();
    if (!value) {
      setError('Target value is required.');
      return;
    }
    await runTargetAction(`add-target-${effectiveGroupId}`, () => requestJson(config, session, `/v1/target-groups/${effectiveGroupId}/targets`, {
      method: 'POST',
      body: {
        kind: String(form.get('kind') ?? 'fqdn'),
        value
      }
    }), 'Declared target added to the selected group.');
    formElement.reset();
  }

  return (
    <div className="content">
      <PageHeader route="target-groups" />
      <div className="metric-grid three">
        <MetricCard label="Declared groups" value={data.targetGroups.length} sub="Customer-provided scope only" icon={Target} tone="info" />
        <MetricCard label="Declared targets" value={declaredTargetTotal} sub="Across all active groups" icon={Network} tone={declaredTargetTotal > 0 ? 'info' : 'muted'} />
        <MetricCard label="Environments" value={environments.length} sub="Derived from target-group records" icon={ShieldCheck} tone="muted" />
      </div>
      {(message || error) && (
        <div className={error ? 'form-banner error' : 'form-banner'}>{error || message}</div>
      )}
      {environmentFilter ? (
        <div className="form-banner info row-actions">
          <span>Showing groups in environment <strong>{environmentFilter}</strong>.</span>
          <AnchorButton href="#target-groups" variant="ghost" size="sm">Clear filter</AnchorButton>
        </div>
      ) : null}
      <div className="split">
        <Card>
          <CardHeader>
            <CardTitle>Create declared target group</CardTitle>
            <CardDescription>Customers declare scope manually. AstraNull does not discover inventory automatically.</CardDescription>
          </CardHeader>
          <CardContent>
            <form className="product-form" onSubmit={handleCreateGroup}>
              <label>
                <span>Name</span>
                <input name="name" placeholder="Retail Checkout - Production" required />
              </label>
              <label>
                <span>Environment</span>
                <input name="environment_id" placeholder="prod" defaultValue="prod" />
              </label>
              <details className="full" open={showCreateMoreOptions} onToggle={(event) => setShowCreateMoreOptions((event.currentTarget as HTMLDetailsElement).open)}>
                <summary>More options</summary>
                <label className="full">
                  <span>Description</span>
                  <textarea name="description" rows={3} placeholder="Business service, owner, and known protection context." />
                </label>
                <label>
                  <span>Timezone</span>
                  <input name="timezone" defaultValue="UTC" />
                </label>
                <label>
                  <span>Max concurrent runs</span>
                  <input name="max_concurrent_runs" type="number" min="1" max="5" defaultValue="1" />
                </label>
                <label>
                  <span>Cooldown between runs (seconds)</span>
                  <input name="min_seconds_between_runs" type="number" min="60" defaultValue="300" />
                </label>
              </details>
              <div className="form-actions full">
                <Button type="submit" loading={busy === 'create-target-group'}>Create group</Button>
              </div>
            </form>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Add declared target</CardTitle>
            <CardDescription>Add FQDN, URL, IP/port, DNS, or canary targets to the selected group.</CardDescription>
          </CardHeader>
          <CardContent>
            <form className="product-form" onSubmit={handleAddTarget}>
              <input type="hidden" name="kind" value={addTargetKind} />
              <Select
                className="full"
                label="Selected group"
                value={effectiveGroupId}
                disabled={filteredGroups.length === 0}
                options={filteredGroups.length === 0
                  ? [{ value: '', label: 'No target groups yet' }]
                  : filteredGroups.map((group) => ({
                    value: getString(group, ['id']),
                    label: getString(group, ['name', 'id'])
                  }))}
                onChange={setAddTargetGroupId}
              />
              <Select
                label="Target type"
                value={addTargetKind}
                options={TARGET_KIND_SELECT_OPTIONS}
                onChange={setAddTargetKind}
              />
              <label>
                <span>Value</span>
                <input name="value" placeholder="checkout.example.com" required />
              </label>
              <div className="form-actions full">
                <Button type="submit" loading={busy.startsWith('add-target-')} disabled={busy !== '' || !effectiveGroupId}>Add target</Button>
              </div>
            </form>
          </CardContent>
        </Card>
      </div>
      <Card>
        <CardHeader>
          <div>
            <CardTitle>Declared target groups</CardTitle>
            <CardDescription>Declared business scope for validation. Archived groups are removed from this active list.</CardDescription>
          </div>
          <Badge tone="info">{filteredGroups.length} active{environmentFilter ? ' (filtered)' : ''}</Badge>
        </CardHeader>
        <CardContent>
          <DataTable
            columns={groupColumns}
            items={filteredGroups}
            empty={emptyStateFromApi({
              icon: Target,
              meta: data.targetGroupsMeta,
              actionHref: readMetaAction(data.targetGroupsMeta, 'empty_action_href'),
              actionLabel: readMetaAction(data.targetGroupsMeta, 'empty_action_label')
            })}
          />
        </CardContent>
      </Card>
    </div>
  );
}

export function ValidationPage({
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
  const source = route === 'checks' ? data.checks : route === 'runs' ? data.runs : data.findings;
  const emptyIcon = route === 'findings' ? TriangleAlert : ListChecks;
  const firstGroup = data.targetGroups[0] ?? null;
  const safeCheck = data.checks.find((check) => getString(check, ['safety_class']) === 'safe') ?? null;

  async function runValidationAction<T>(label: string, action: () => Promise<T>, success: string) {
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
      setError(payload?.message ?? payload?.error ?? (err instanceof Error ? err.message : 'Validation action failed.'));
      return null;
    } finally {
      setBusy('');
    }
  }

  async function startSafeRun() {
    const targetGroupId = getString(firstGroup, ['id'], '');
    const checkId = getString(safeCheck ?? {}, ['check_id'], '');
    if (!targetGroupId || !checkId) {
      setError('Declare a target group and safe check before starting a run.');
      return;
    }
    const detail = await requestJson(config, session, `/v1/target-groups/${targetGroupId}`) as DataItem;
    const targets = Array.isArray(detail.targets) ? detail.targets as DataItem[] : [];
    const targetId = getString(targets[0] ?? {}, ['id'], '');
    if (!targetId) {
      setError('Add at least one target to the declared group before starting a run.');
      return;
    }
    await runValidationAction('start-safe-run', () => requestJson(config, session, '/v1/test-runs', {
      method: 'POST',
      body: { target_group_id: targetGroupId, target_id: targetId, check_id: checkId }
    }), 'Safe validation run started.');
  }

  async function patchFinding(id: string, body: Record<string, unknown>, success: string) {
    if (!id) return;
    await runValidationAction(`finding-${id}`, () => requestJson(config, session, `/v1/findings/${id}`, {
      method: 'PATCH',
      body
    }), success);
  }

  const columns: TableColumn<DataItem>[] = [
    { key: 'name', label: 'Item', render: (item) => getString(item, ['name', 'title', 'check_id', 'id']) },
    { key: 'status', label: 'Status', render: (item) => <Badge tone={getString(item, ['status', 'verdict'], 'ready') === 'open' ? 'warn' : 'success'}>{getString(item, ['status', 'verdict'], 'ready')}</Badge> },
    { key: 'type', label: 'Type', render: (item) => getString(item, ['family', 'kind', 'severity', 'safety_class'], 'safe validation') },
    { key: 'time', label: 'Time', render: (item) => formatDate(item.created_at ?? item.started_at ?? item.updated_at) },
    ...(route === 'findings' ? [{
      key: 'actions',
      label: 'Actions',
      render: (item: DataItem) => {
        const id = getString(item, ['id'], '');
        return (
          <div className="row-actions">
            <Button size="sm" variant="secondary" disabled={busy !== ''} onClick={() => void patchFinding(id, { status: 'accepted_risk' }, 'Finding marked accepted risk.')}>Accept risk</Button>
            <Button size="sm" variant="ghost" disabled={busy !== ''} onClick={() => void patchFinding(id, { status: 'closed' }, 'Finding closed.')}>Close</Button>
          </div>
        );
      }
    }] as TableColumn<DataItem>[] : [])
  ];

  return (
    <div className="content">
      <PageHeader route={route} />
      <div className="metric-grid three">
        <MetricCard label="Checks" value={data.checks.length} sub="Bounded safe catalog" icon={ListChecks} tone="info" />
        <MetricCard label="Runs" value={data.runs.length} sub="Probe plus agent correlation" icon={Activity} tone="success" />
        <MetricCard label="Evidence" value={data.evidence.length} sub="Custody-ready records" icon={FileCheck2} tone="muted" />
      </div>
      {(message || error) && <div className={error ? 'form-banner error' : 'form-banner'}>{error || message}</div>}
      {route === 'runs' && (
        <Card>
          <CardHeader>
            <CardTitle>Start safe validation</CardTitle>
            <CardDescription>Creates a bounded run against the first declared target in the first active target group.</CardDescription>
          </CardHeader>
          <CardContent>
            <Button loading={busy === 'start-safe-run'} disabled={busy !== '' || !firstGroup || !safeCheck} onClick={() => void startSafeRun()}>
              Start safe run
            </Button>
          </CardContent>
        </Card>
      )}
      <Card>
        <CardHeader>
          <CardTitle>{ROUTE_BY_ID.get(route)?.label}</CardTitle>
          <CardDescription>Verdicts should always explain what was observed and what evidence supports the outcome.</CardDescription>
        </CardHeader>
        <CardContent>
          <DataTable
            columns={columns}
            items={source}
            empty={<EmptyState icon={emptyIcon} title="No evidence-backed records yet." body="Run a safe validation after target group and agent setup. High-scale validation remains request-only for customers." actionLabel="Open target groups" actionHref="#target-groups" />}
          />
        </CardContent>
      </Card>
    </div>
  );
}

export function GovernancePage({ route, data }: { route: RouteId; data: PortalData }) {
  const source =
    route === 'notifications' ? data.notificationRules :
      route === 'audit' ? data.audit :
        data.runs;
  const columns: TableColumn<DataItem>[] = [
    { key: 'id', label: 'Record', render: (item) => getString(item, ['title', 'name', 'id']) },
    { key: 'state', label: 'State', render: (item) => <Badge tone={getString(item, ['status', 'state'], 'recorded') === 'open' ? 'warn' : 'muted'}>{getString(item, ['status', 'state'], 'recorded')}</Badge> },
    { key: 'owner', label: 'Owner', render: (item) => getString(item, ['owner', 'actor_id', 'requested_by', 'created_by'], 'AstraNull') },
    { key: 'time', label: 'Time', render: (item) => formatDate(item.created_at ?? item.updated_at) }
  ];
  return (
    <div className="content">
      <PageHeader route={route} />
      <div className="metric-grid three">
        <MetricCard label="High-scale requests" value={data.highScale.length} sub="SOC controls required" icon={ShieldCheck} tone="muted" />
        <MetricCard label="Release evidence" value={data.releaseEvidence.length} sub="Metadata-only inventory" icon={FileText} tone="info" />
        <MetricCard label="Audit entries" value={formatNumber(data.audit.length)} sub="Security-relevant actions" icon={FileCheck2} tone="success" />
      </div>
      <Card>
        <CardHeader>
          <CardTitle>{ROUTE_BY_ID.get(route)?.label}</CardTitle>
          <CardDescription>Governance actions favor approval artifacts, custody, and fail-closed access boundaries.</CardDescription>
        </CardHeader>
        <CardContent>
          <DataTable
            columns={columns}
            items={source}
            empty={<EmptyState icon={ShieldCheck} title="No governance records yet." body="Requests, approvals, reports, and audit records appear here after controlled workflow activity." />}
          />
        </CardContent>
      </Card>
    </div>
  );
}

type ReportExportPreview = {
  reportId: string;
  format: string;
  title: string;
  contentSha256?: string;
  artifactId?: string;
  schemaVersion?: string;
  verification?: DataItem | null;
  textPreview?: string;
};

const REPORT_KIND_OPTIONS = [
  { value: 'executive', label: 'Executive' },
  { value: 'board', label: 'Board' },
  { value: 'technical', label: 'Technical' },
  { value: 'soc', label: 'SOC' },
  { value: 'audit', label: 'Audit' },
  { value: 'soc2', label: 'SOC 2' },
  { value: 'iso27001', label: 'ISO 27001' },
  { value: 'dora', label: 'DORA' },
  { value: 'nis2', label: 'NIS2' },
  { value: 'internal_audit', label: 'Internal audit' }
];

export function ReportsPage({
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
  const [preview, setPreview] = useState<ReportExportPreview | null>(null);
  const [reportKind, setReportKind] = useState('technical');
  const reports = data.reports;
  const latestReport = reports[0] ?? null;
  const reportExports = data.audit.filter((entry) => getString(entry, ['action'], '') === 'report.exported').length;
  const reportColumns: TableColumn<DataItem>[] = [
    {
      key: 'title',
      label: 'Report',
      render: (item) => {
        const id = getString(item, ['id'], '');
        const title = getString(item, ['title', 'id']);
        return id
          ? <AnchorButton size="sm" variant="ghost" href={buildDetailHref('report-detail', id)}>{title}</AnchorButton>
          : title;
      }
    },
    { key: 'kind', label: 'Kind', render: (item) => <Badge tone="info">{getString(item, ['kind'])}</Badge> },
    {
      key: 'readiness',
      label: 'Readiness',
      render: (item) => {
        const score = getNestedNumber(item, ['summary', 'readiness_score'], 0);
        return <Badge tone={scoreTone(score)}>{score}%</Badge>;
      }
    },
    { key: 'findings', label: 'Open findings', render: (item) => getNestedNumber(item, ['summary', 'open_findings'], 0) },
    { key: 'created', label: 'Created', render: (item) => formatDate(item.created_at) },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        const rowBusy = busy.startsWith(`export-${id}-`);
        const rowBlocked = busy !== '' && !rowBusy;
        return (
          <div className="row-actions" aria-busy={rowBusy || undefined}>
            <AnchorButton size="sm" variant="secondary" href={buildDetailHref('report-detail', id)}>Detail</AnchorButton>
            <details className="disclosure">
              <summary>Export</summary>
              <div className="row-actions row-actions--spaced">
                <Button size="sm" variant="secondary" loading={busy === `export-${id}-json`} disabled={rowBlocked} onClick={() => void exportReport(id, 'json')}>JSON</Button>
                <Button size="sm" variant="secondary" loading={busy === `export-${id}-markdown`} disabled={rowBlocked} onClick={() => void exportReport(id, 'markdown')}>Markdown</Button>
                <Button size="sm" variant="secondary" loading={busy === `export-${id}-html`} disabled={rowBlocked} onClick={() => void exportReport(id, 'html')}>HTML</Button>
              </div>
            </details>
          </div>
        );
      }
    }
  ];

  async function runReportAction<T>(label: string, action: () => Promise<T>, success: string) {
    setBusy(label);
    setError('');
    setMessage('');
    try {
      const result = await action();
      setMessage(success);
      return result;
    } catch (err) {
      const payload = (err as Error & { payload?: unknown }).payload as { error?: string; message?: string } | undefined;
      setError(payload?.message ?? payload?.error ?? (err instanceof Error ? err.message : 'Report action failed.'));
      return null;
    } finally {
      setBusy('');
    }
  }

  async function handleCreateReport(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const title = String(form.get('title') ?? '').trim() || 'AstraNull Readiness Summary';
    const kind = String(form.get('kind') ?? 'technical');
    const created = await runReportAction('create-report', () => requestJson(config, session, '/v1/reports', {
      method: 'POST',
      body: { title, kind }
    }), 'Report generated.');
    if (created && typeof created === 'object') {
      formElement.reset();
      setReportKind('technical');
      await onRefresh();
      const id = getString(created as DataItem, ['id'], '');
      if (id) {
        setMessage('Report generated — JSON export with custody metadata started automatically.');
        await exportReport(id, 'json');
      }
    }
  }

  async function exportReport(reportId: string, format: 'json' | 'markdown' | 'html') {
    if (!reportId) return;
    await runReportAction(`export-${reportId}-${format}`, async () => {
      const headers = buildApiHeaders(config, session);
      const response = await fetch(`/v1/reports/${encodeURIComponent(reportId)}/export?format=${format}`, { headers });
      const contentType = response.headers.get('content-type') ?? '';
      if (!response.ok) {
        const payload = await response.json().catch(() => null);
        throw new Error(String(payload?.message ?? payload?.error ?? `Export returned ${response.status}`));
      }
      if (format === 'json' || contentType.includes('application/json')) {
        const exported = await response.json();
        const custody = getNestedItem(exported, ['custody']);
        const payload = getNestedItem(exported, ['payload']);
        let verification: DataItem | null = null;
        if (custody && payload) {
          const verified = await requestJson(config, session, '/v1/custody/verify', {
            method: 'POST',
            body: { payload, custody }
          });
          verification = getNestedItem(verified as DataItem, ['verification']) ?? verified as DataItem;
        }
        setPreview({
          reportId,
          format,
          title: getNestedString(payload, ['title'], getString(reports.find((report) => getString(report, ['id'], '') === reportId) ?? {}, ['title'], reportId)),
          contentSha256: getString(custody ?? {}, ['content_sha256'], ''),
          artifactId: getString(custody ?? {}, ['artifact_id'], ''),
          schemaVersion: getString(custody ?? {}, ['schema_version'], ''),
          verification
        });
        await onRefresh();
        return exported;
      }
      const textPayload = await response.text();
      setPreview({
        reportId,
        format,
        title: getString(reports.find((report) => getString(report, ['id'], '') === reportId) ?? {}, ['title'], reportId),
        textPreview: textPayload.slice(0, 900)
      });
      await onRefresh();
      return textPayload;
    }, `Report exported as ${format}.`);
  }

  return (
    <div className="content">
      <PageHeader route="reports" />
      <PageContextSummary>
        <span className="tabular-nums">{reports.length}</span> reports ·{' '}
        <span className="tabular-nums">{reportExports}</span> custody exports recorded
      </PageContextSummary>
      {(message || error) && (
        <div className={error ? 'form-banner error' : 'form-banner'}>
          {error || message}
        </div>
      )}
      <div className="split">
        <Card>
          <CardHeader>
            <CardTitle>Generate report</CardTitle>
            <CardDescription>Create a tenant-scoped report from current readiness, run, finding, and compliance mapping data. Generating a report also exports JSON with custody metadata.</CardDescription>
          </CardHeader>
          <CardContent>
            <form className="product-form" onSubmit={handleCreateReport} aria-busy={busy === 'create-report' || undefined}>
              <label className="full">
                <span>Title</span>
                <input name="title" placeholder="Q3 readiness evidence pack" />
              </label>
              <Select
                label="Report kind"
                name="kind"
                value={reportKind}
                options={REPORT_KIND_OPTIONS}
                onChange={setReportKind}
              />
              <div className="form-actions full">
                <Button type="submit" loading={busy === 'create-report'}>Generate report</Button>
              </div>
            </form>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Export custody</CardTitle>
            <CardDescription>JSON exports include custody verification; Markdown and HTML previews show the first ~900 characters only.</CardDescription>
          </CardHeader>
          <CardContent className={preview ? 'kv-list' : ''}>
            {!preview ? (
              <EmptyState icon={FileCheck2} title="No export selected." body="Generate or export a report to inspect custody metadata." />
            ) : preview.contentSha256 ? (
              <>
                <div><span>Report</span><strong>{preview.title}</strong></div>
                <div><span>Artifact</span><strong>{preview.artifactId}</strong></div>
                <div><span>content_sha256</span><strong>{preview.contentSha256}</strong></div>
                <div><span>Schema</span><strong>{preview.schemaVersion}</strong></div>
                <div><span>Verification</span><Badge tone={preview.verification?.ok === true ? 'success' : 'warn'}>{preview.verification?.ok === true ? 'verified' : 'check required'}</Badge></div>
              </>
            ) : (
              <>
                <p className="muted">Preview truncated — use export buttons on the report row for the full artifact.</p>
                <pre className="codeblock">{preview.textPreview}</pre>
              </>
            )}
          </CardContent>
        </Card>
      </div>
      <Card>
        <CardHeader>
          <div>
            <CardTitle>Generated reports</CardTitle>
            <CardDescription>Each row can be re-exported as JSON, Markdown, or HTML with custody audit metadata.</CardDescription>
          </div>
          <Badge tone="info">{reports.length} records</Badge>
        </CardHeader>
        <CardContent className="stack-tight" aria-busy={busy.startsWith('export-') || busy === 'create-report' || undefined}>
          <p className="table-caption muted">
            {latestReport
              ? `Latest: ${getString(latestReport, ['kind'])} · ${formatDate(latestReport.created_at)}`
              : 'No reports generated yet — create one from the form above.'}
          </p>
          <DataTable
            columns={reportColumns}
            items={reports}
            empty={<EmptyState icon={FileText} title="No reports generated." body="Generate a report after validation activity to create a custody-ready evidence artifact." />}
          />
          {/*
            PDF export is intentionally out of scope for this slice: backend `src/services/reports.mjs`
            supports json|markdown|html only. Immutable PDF rendering and signing remain a release-gate boundary.
          */}
          <p className="muted">PDF export is not available in this slice; backend report exports support JSON, Markdown, and HTML only.</p>
        </CardContent>
      </Card>

    </div>
  );
}

function expiresAtFromForm(value: string) {
  const now = Date.now();
  if (value === '15m') return new Date(now + 15 * 60 * 1000).toISOString();
  if (value === '1h') return new Date(now + 60 * 60 * 1000).toISOString();
  if (value === '24h') return new Date(now + 24 * 60 * 60 * 1000).toISOString();
  if (value === '30d') return new Date(now + 30 * 24 * 60 * 60 * 1000).toISOString();
  return null;
}

type SettingsTab = 'organization' | 'access' | 'security' | 'privacy';

const SETTINGS_TAB_OPTIONS: { id: SettingsTab; label: string }[] = [
  { id: 'organization', label: 'Organization' },
  { id: 'access', label: 'Access' },
  { id: 'security', label: 'Security' },
  { id: 'privacy', label: 'Privacy' }
];

function readOidcPosture(config: PortalConfig) {
  const siteConfig = config.siteConfig;
  const issuer = getNestedString(siteConfig, ['oidc', 'issuer'], '')
    || getString(siteConfig, ['oidc_issuer'], '');
  const audience = getNestedString(siteConfig, ['oidc', 'audience'], '')
    || getString(siteConfig, ['oidc_audience'], '');
  return {
    authMode: config.authMode,
    issuer: issuer && issuer !== '—' ? issuer : null,
    audience: audience && audience !== '—' ? audience : null,
    bundledStagingLogin: config.bundledLoginEnabled
  };
}

export function SettingsPage({
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
  const [tab, setTab] = useState<SettingsTab>('organization');
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [oneTimeSecret, setOneTimeSecret] = useState<{ label: string; value: string } | null>(null);
  const [rotateSecretId, setRotateSecretId] = useState('');
  const [bootstrapTargetGroupId, setBootstrapTargetGroupId] = useState('');
  const [bootstrapExpiry, setBootstrapExpiry] = useState('1h');
  const tenant = data.tenant;
  const bootstrapTargetGroupOptions: SelectOption[] = [
    { value: '', label: 'No default binding' },
    ...data.targetGroups.map((group) => ({
      value: getString(group, ['id']),
      label: getString(group, ['name', 'id'])
    }))
  ];
  const privacy = getNestedItem(tenant, ['privacy_settings']) ?? {};
  const evidenceRetention = getNestedItem(privacy, ['evidence_retention']) ?? {};
  const metadataRetentionDays = getNumber(privacy, ['metadata_retention_days'], 90);
  const oidcPosture = readOidcPosture(config);
  const routeAccessContext = {
    principal: session.principal,
    staffRole: session.staff_role,
  };
  const role = session.role ?? 'admin';
  const canReadAudit = canAccessRoute(role, 'audit', routeAccessContext);
  const canReadNotifications = canAccessRoute(role, 'notifications', routeAccessContext);
  const settingsTabOptions = SETTINGS_TAB_OPTIONS;
  const tokenColumns: TableColumn<DataItem>[] = [
    { key: 'name', label: 'Token', render: (item) => getString(item, ['name', 'id']) },
    { key: 'environment', label: 'Environment', render: (item) => getString(item, ['environment_id']) },
    { key: 'usage', label: 'Usage', render: (item) => `${getNumber(item, ['registrations_used'])}/${getNumber(item, ['max_registrations'], 1)}` },
    { key: 'expires', label: 'Expires', render: (item) => formatDate(item.expires_at) },
    { key: 'state', label: 'State', render: (item) => <Badge tone={item.revoked_at ? 'muted' : 'success'}>{item.revoked_at ? 'revoked' : 'active'}</Badge> },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        return <Button size="sm" variant="danger" disabled={busy !== '' || Boolean(item.revoked_at)} onClick={() => void revokeBootstrapToken(id)}>Revoke</Button>;
      }
    }
  ];
  const serviceAccountColumns: TableColumn<DataItem>[] = [
    { key: 'name', label: 'Account', render: (item) => getString(item, ['name', 'id']) },
    { key: 'role', label: 'Role', render: (item) => <Badge tone="info">{getString(item, ['role'])}</Badge> },
    { key: 'scopes', label: 'Scopes', render: (item) => Array.isArray(item.scopes) ? item.scopes.join(', ') : 'role defaults' },
    { key: 'expires', label: 'Expires', render: (item) => item.expires_at ? formatDate(item.expires_at) : 'No expiry' },
    { key: 'state', label: 'State', render: (item) => <Badge tone={item.revoked_at ? 'muted' : 'success'}>{item.revoked_at ? 'revoked' : 'active'}</Badge> },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        return (
          <div className="row-actions">
            <Button size="sm" variant="secondary" disabled={busy !== '' || Boolean(item.revoked_at)} onClick={() => void rotateServiceAccount(id)}>Rotate</Button>
            <Button size="sm" variant="danger" disabled={busy !== '' || Boolean(item.revoked_at)} onClick={() => void revokeServiceAccount(id)}>Revoke</Button>
          </div>
        );
      }
    }
  ];

  async function runSettingsAction<T>(label: string, action: () => Promise<T>, success: string) {
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
      setError(payload?.message ?? payload?.error ?? (err instanceof Error ? err.message : 'Action failed.'));
      return null;
    } finally {
      setBusy('');
    }
  }

  async function handleCreateBootstrapToken(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const name = String(form.get('name') ?? '').trim() || 'Install token';
    const expiry = expiresAtFromForm(String(form.get('expiry') ?? '1h'));
    const maxRegistrations = Number(form.get('max_registrations') ?? 1);
    const targetGroupId = String(form.get('target_group_id') ?? '').trim();
    const result = await runSettingsAction('create-bootstrap-token', () => requestJson(config, session, '/v1/bootstrap-tokens', {
      method: 'POST',
      body: {
        name,
        environment_id: String(form.get('environment_id') ?? 'env_demo'),
        ...(targetGroupId ? { target_group_id: targetGroupId } : {}),
        max_registrations: Number.isFinite(maxRegistrations) && maxRegistrations > 0 ? maxRegistrations : 1,
        ...(expiry ? { expires_at: expiry } : {})
      }
    }), 'Bootstrap token created. Copy the secret now; it is shown once.');
    if (result && typeof result === 'object' && 'secret' in result && typeof (result as { secret?: unknown }).secret === 'string') {
      setOneTimeSecret({ label: 'Bootstrap token secret', value: String((result as { secret: string }).secret) });
      formElement.reset();
    }
  }

  async function handleCreateServiceAccount(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const requestedScopes = String(form.get('scopes') ?? '')
      .split(',')
      .map((scope) => scope.trim())
      .filter(Boolean);
    const scopes = requestedScopes.length ? requestedScopes : ['tenant:read'];
    const result = await runSettingsAction('create-service-account', () => requestJson(config, session, '/v1/service-accounts', {
      method: 'POST',
      body: {
        name: String(form.get('name') ?? '').trim() || 'Automation account',
        role: String(form.get('role') ?? 'viewer'),
        scopes,
        ...(expiresAtFromForm(String(form.get('expiry') ?? '')) ? { expires_at: expiresAtFromForm(String(form.get('expiry') ?? '')) } : {})
      }
    }), 'Service account created. Copy the API secret now; it is shown once.');
    if (result && typeof result === 'object' && 'secret' in result && typeof (result as { secret?: unknown }).secret === 'string') {
      setOneTimeSecret({ label: 'Service API secret', value: String((result as { secret: string }).secret) });
      formElement.reset();
    }
  }

  async function revokeBootstrapToken(id: string) {
    if (!id) return;
    if (!window.confirm('Revoke this bootstrap token? New agent registrations using it will fail.')) return;
    await runSettingsAction(`revoke-bootstrap-${id}`, () => requestJson(config, session, `/v1/bootstrap-tokens/${id}/revoke`, { method: 'POST' }), 'Bootstrap token revoked.');
  }

  async function revokeServiceAccount(id: string) {
    if (!id) return;
    if (!window.confirm('Revoke this service account? API calls using its secret will stop working.')) return;
    await runSettingsAction(`revoke-service-${id}`, () => requestJson(config, session, `/v1/service-accounts/${id}/revoke`, { method: 'POST' }), 'Service account revoked.');
  }

  async function rotateServiceAccount(id: string) {
    if (!id) return;
    if (!window.confirm('Rotate this service account? The current API secret will stop working immediately.')) return;
    const result = await runSettingsAction(`rotate-service-${id}`, () => requestJson(config, session, `/v1/service-accounts/${id}/rotate`, { method: 'POST' }), 'Service account rotated. Copy the new API secret now; it is shown once.');
    if (result && typeof result === 'object' && 'secret' in result && typeof (result as { secret?: unknown }).secret === 'string') {
      setOneTimeSecret({ label: 'Rotated service API secret', value: String((result as { secret: string }).secret) });
    }
  }

  async function handleSaveOrganization(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const name = String(form.get('name') ?? '').trim();
    if (!name) {
      setError('Organization name is required.');
      return;
    }
    await runSettingsAction('save-organization', () => requestJson(config, session, '/v1/tenants/current', {
      method: 'PATCH',
      body: { name }
    }), 'Organization settings saved.');
  }

  async function handleSaveRetention(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!window.confirm('Save retention settings? Shorter windows can immediately purge stored metadata.')) return;
    const form = new FormData(event.currentTarget);
    const metadataDays = Number(form.get('metadata_retention_days') ?? 90);
    const reportDays = Number(form.get('report_days') ?? 365);
    const auditLogDays = Number(form.get('audit_log_days') ?? 2555);
    const highScaleArtifactDays = Number(form.get('high_scale_artifact_days') ?? 2555);
    const legalHold = form.get('legal_hold') === 'on';
    await runSettingsAction('save-retention', () => requestJson(config, session, '/v1/tenants/current', {
      method: 'PATCH',
      body: {
        privacy_settings: {
          metadata_retention_days: metadataDays,
          evidence_retention: {
            report_days: reportDays,
            audit_log_days: auditLogDays,
            high_scale_artifact_days: highScaleArtifactDays,
            legal_hold: legalHold
          }
        }
      }
    }), 'Retention policy saved. Metadata purge runs immediately when retention days change.');
  }

  async function handleCreateVaultSecret(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const purpose = String(form.get('purpose') ?? '').trim();
    const name = String(form.get('name') ?? '').trim();
    const plaintext = String(form.get('plaintext') ?? '').trim();
    if (!purpose || !name || !plaintext) {
      setError('Purpose, name, and credential value are required.');
      return;
    }
    if (!window.confirm('Store this integration secret? Authorized internal workflows will use the new credential.')) return;
    await runSettingsAction('create-vault-secret', () => requestJson(config, session, '/v1/secrets', {
      method: 'POST',
      body: {
        purpose,
        name,
        plaintext,
        metadata: { source: 'settings_vault' }
      }
    }), 'Integration secret stored. Plaintext is never returned by list APIs.');
    formElement.reset();
  }

  async function handleRotateVaultSecret(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const id = String(form.get('secret_id') ?? rotateSecretId).trim();
    const plaintext = String(form.get('plaintext') ?? '').trim();
    if (!id || !plaintext) {
      setError('Select a secret and provide the replacement credential value.');
      return;
    }
    if (!window.confirm('Rotate this vault secret? The current credential will stop working for authorized internal workflows.')) return;
    await runSettingsAction(`rotate-vault-${id}`, () => requestJson(config, session, `/v1/secrets/${id}/rotate`, {
      method: 'POST',
      body: { plaintext }
    }), 'Secret rotated. Prior credential stops working for authorized internal workflows.');
    formElement.reset();
    setRotateSecretId('');
  }

  const secretColumns: TableColumn<DataItem>[] = [
    { key: 'name', label: 'Name', render: (item) => getString(item, ['name', 'id']) },
    { key: 'purpose', label: 'Purpose', render: (item) => <Badge tone="info">{getString(item, ['purpose'])}</Badge> },
    { key: 'rotation', label: 'Rotation', render: (item) => getNumber(item, ['rotation']) },
    { key: 'updated', label: 'Updated', render: (item) => formatDate(item.updated_at ?? item.created_at) },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        return (
          <Button
            size="sm"
            variant="secondary"
            disabled={busy !== ''}
            onClick={() => {
              setRotateSecretId(id);
              setTab('security');
            }}
          >
            Rotate
          </Button>
        );
      }
    }
  ];

  return (
    <div className="content">
      <PageHeader route="settings" eyebrow="Tenant configuration" />
      <PageContextSummary>
        {getString(tenant ?? {}, ['name'], 'Organization')} ·{' '}
        <span className="tabular-nums">{data.secrets.length}</span> vault secrets ·{' '}
        <span className="tabular-nums">{metadataRetentionDays}</span>d metadata retention
      </PageContextSummary>
      <Tabs value={tab} options={settingsTabOptions} onChange={setTab} className="tabs-wrap" />
      {(message || error) && (
        <div className={error ? 'form-banner error' : 'form-banner'}>
          {error || message}
        </div>
      )}
      {oneTimeSecret && (
        <Card className="secret-card">
          <CardHeader>
            <div>
              <CardTitle>{oneTimeSecret.label}</CardTitle>
              <CardDescription>This value is shown once. It is not returned by list APIs and will not be visible after refresh.</CardDescription>
            </div>
            <div className="row-actions">
              <Button
                variant="secondary"
                size="sm"
                onClick={() => {
                  void navigator.clipboard.writeText(oneTimeSecret.value).then(() => {
                    setMessage('Secret copied to clipboard.');
                    setError('');
                  }).catch(() => {
                    setError('Clipboard copy failed. Select the secret manually.');
                  });
                }}
              >
                Copy secret
              </Button>
              <Button variant="ghost" size="sm" onClick={() => setOneTimeSecret(null)}>Dismiss</Button>
            </div>
          </CardHeader>
          <CardContent>
            <pre className="codeblock">{oneTimeSecret.value}</pre>
          </CardContent>
        </Card>
      )}

      {tab === 'organization' && (
        <>
        <div className="split">
          <Card>
            <CardHeader>
              <CardTitle>Organization profile</CardTitle>
              <CardDescription>Organization display name and residency metadata. Privacy defaults stay metadata-only.</CardDescription>
            </CardHeader>
            <CardContent>
              {tenant ? (
                <form className="product-form" onSubmit={handleSaveOrganization}>
                  <label className="full">
                    <span>Organization name</span>
                    <input name="name" defaultValue={getString(tenant, ['name'])} required />
                  </label>
                  <label>
                    <span>Tenant ID</span>
                    <input value={getString(tenant, ['id'])} readOnly />
                  </label>
                  <label>
                    <span>Data region</span>
                    <input value={getString(tenant, ['data_region'], 'unrecorded')} readOnly />
                  </label>
                  <div className="form-actions full">
                    <Button type="submit" loading={busy === 'save-organization'}>Save organization</Button>
                  </div>
                </form>
              ) : (
                <EmptyState
                  icon={ShieldCheck}
                  variant="skeleton"
                  title="Organization profile loading…"
                  body="Tenant settings are not available yet for this session. Refresh the page or retry in a moment."
                  actionLabel="Refresh page"
                  onAction={() => window.location.reload()}
                />
              )}
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Workspace inventory</CardTitle>
              <CardDescription>Live workspace counts — not editable here.</CardDescription>
            </CardHeader>
            <CardContent className="kv-list">
              <div><span>Target groups</span><strong>{data.targetGroups.length}</strong></div>
              <div><span>Agents</span><strong>{data.agents.length}</strong></div>
              <div><span>Evidence records</span><strong>{data.evidence.length}</strong></div>
              <div><span>Environments</span><strong>{new Set(data.targetGroups.map((group) => getString(group, ['environment_id'], 'unassigned'))).size}</strong></div>
            </CardContent>
          </Card>
        </div>
        <Card>
          <CardHeader>
            <CardTitle>Session &amp; access posture</CardTitle>
            <CardDescription>Read-only session view. User invites and enterprise SSO mapping are provisioned by AstraNull support.</CardDescription>
          </CardHeader>
          <CardContent className="kv-list">
            <div><span>User ID</span><strong>{session.user_id ?? '—'}</strong></div>
            <div><span>Role</span><strong>{session.role ?? '—'}</strong></div>
            <div><span>Tenant</span><strong>{session.tenant_id ?? data.state?.tenant_id ?? '—'}</strong></div>
            <div><span>Auth mode</span><strong>{config.authMode}</strong></div>
          </CardContent>
          <CardContent className="settings-list">
            <div><ShieldCheck size={18} /><span>Tenant user invites and role changes are not self-service on this screen.</span></div>
            <div><FileCheck2 size={18} /><span>API credentials live under Access; vault secrets under Security; audit history on the Audit page.</span></div>
          </CardContent>
          {session.principal === 'staff' ? (
            <CardContent className="row-actions">
              <AnchorButton href="#admin" variant="secondary" size="sm">Staff admin console</AnchorButton>
            </CardContent>
          ) : null}
        </Card>
        {canReadAudit ? (
          <Card>
            <CardHeader>
              <div>
                <CardTitle>Tenant audit log</CardTitle>
                <CardDescription>Immutable security-relevant history lives on the Audit page — Settings does not duplicate that log.</CardDescription>
              </div>
              <AnchorButton href="#audit" variant="secondary" size="sm">Open audit log</AnchorButton>
            </CardHeader>
            <CardContent className="row-actions">
              {canReadNotifications ? <AnchorButton href="#notifications" variant="ghost" size="sm">Notification rules</AnchorButton> : null}
              <AnchorButton href="#integrations" variant="ghost" size="sm">Integrations</AnchorButton>
            </CardContent>
          </Card>
        ) : null}
        </>
      )}

      {tab === 'access' && (
        <>
          <div className="split">
            <Card>
              <CardHeader>
                <CardTitle>Create bootstrap token</CardTitle>
                <CardDescription>Issue a short-lived one-time install secret for outbound agent registration.</CardDescription>
              </CardHeader>
              <CardContent>
                <form className="product-form" onSubmit={handleCreateBootstrapToken}>
                  <label>
                    <span>Name</span>
                    <input name="name" placeholder="prod-edge-install" />
                  </label>
                  <label>
                    <span>Environment</span>
                    <input name="environment_id" defaultValue="env_demo" />
                  </label>
                  <input type="hidden" name="target_group_id" value={bootstrapTargetGroupId} />
                  <input type="hidden" name="expiry" value={bootstrapExpiry} />
                  <Select
                    label="Target group"
                    value={bootstrapTargetGroupId}
                    options={bootstrapTargetGroupOptions}
                    onChange={setBootstrapTargetGroupId}
                  />
                  <Select
                    label="Expiry"
                    value={bootstrapExpiry}
                    options={BOOTSTRAP_EXPIRY_OPTIONS}
                    onChange={setBootstrapExpiry}
                  />
                  <label>
                    <span>Max registrations</span>
                    <input name="max_registrations" type="number" min="1" max="50" defaultValue="1" />
                  </label>
                  <div className="form-actions full">
                    <Button type="submit" loading={busy === 'create-bootstrap-token'}>Create token</Button>
                  </div>
                </form>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>Create service account</CardTitle>
                <CardDescription>Create scoped API automation credentials. Secrets are returned once and list views stay redacted.</CardDescription>
              </CardHeader>
              <CardContent>
                <form className="product-form" onSubmit={handleCreateServiceAccount}>
                  <label>
                    <span>Name</span>
                    <input name="name" placeholder="ci-evidence-reader" />
                  </label>
                  <label>
                    <span>Role</span>
                    <select name="role" defaultValue="viewer">
                      <option value="viewer">Viewer</option>
                      <option value="auditor">Auditor</option>
                      <option value="engineer">Engineer</option>
                      <option value="admin">Admin</option>
                    </select>
                  </label>
                  <label className="full">
                    <span>Scopes</span>
                    <input name="scopes" defaultValue="tenant:read,evidence:read" />
                  </label>
                  <label>
                    <span>Expiry</span>
                    <select name="expiry" defaultValue="">
                      <option value="">No expiry</option>
                      <option value="24h">24 hours</option>
                      <option value="30d">30 days</option>
                    </select>
                  </label>
                  <div className="form-actions full">
                    <Button type="submit" loading={busy === 'create-service-account'}>Create API key</Button>
                  </div>
                </form>
              </CardContent>
            </Card>
          </div>
          <Card>
            <CardHeader>
              <div>
                <CardTitle>Bootstrap tokens</CardTitle>
                <CardDescription>Install tokens are redacted after creation and can be revoked immediately.</CardDescription>
              </div>
              <Badge tone="info">{data.bootstrapTokens.length} records</Badge>
            </CardHeader>
            <CardContent>
              <DataTable
                columns={tokenColumns}
                items={data.bootstrapTokens}
                empty={<EmptyState icon={KeyRound} title="No bootstrap tokens." body="Create a short-lived token before installing an outbound-only agent." />}
              />
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <div>
                <CardTitle>Service accounts</CardTitle>
                <CardDescription>Automation credentials are scoped, auditable, rotatable, and redacted after creation.</CardDescription>
              </div>
              <Badge tone="success">{data.serviceAccounts.length} records</Badge>
            </CardHeader>
            <CardContent>
              <DataTable
                columns={serviceAccountColumns}
                items={data.serviceAccounts}
                empty={<EmptyState icon={UserCog} title="No service accounts." body="Create an API key only for a clear automation owner and scope." />}
              />
            </CardContent>
          </Card>
        </>
      )}

      {tab === 'security' && (
        <>
          <Card>
            <CardHeader>
              <CardTitle>Enterprise SSO posture</CardTitle>
              <CardDescription>Read-only sign-in configuration for this deployment. Secrets and JWKS URLs are never exposed.</CardDescription>
            </CardHeader>
            <CardContent className="kv-list">
              <div><span>Auth mode</span><strong>{oidcPosture.authMode}</strong></div>
              <div><span>OIDC issuer</span><strong>{oidcPosture.issuer ?? 'Not exposed on public readiness endpoints'}</strong></div>
              <div><span>OIDC audience</span><strong>{oidcPosture.audience ?? 'Not exposed on public readiness endpoints'}</strong></div>
              <div><span>Bundled staging login</span><strong>{oidcPosture.bundledStagingLogin ? 'Enabled' : 'Disabled'}</strong></div>
              <div><span>Login URL</span><strong>{config.loginUrl}</strong></div>
            </CardContent>
            <CardContent className="settings-list">
              <div><ShieldCheck size={18} /><span>Production human auth defaults to `oidc-jwt` with JWKS verification; developer validation may use `dev-headers` or bundled staging login.</span></div>
              <div><KeyRound size={18} /><span>Issuer and audience values are configured server-side. Public site-config currently exposes `auth_mode` only unless your deployment extends the payload.</span></div>
            </CardContent>
          </Card>
          <div className="split">
            <Card>
              <CardHeader>
                <CardTitle>Store integration secret</CardTitle>
                <CardDescription>Plaintext is accepted only on create/rotate. List APIs return metadata-only envelopes.</CardDescription>
              </CardHeader>
              <CardContent>
                <form className="product-form" onSubmit={handleCreateVaultSecret}>
                  <label>
                    <span>Purpose</span>
                    <select name="purpose" defaultValue="integration_credential">
                      <option value="integration_credential">Integration credential</option>
                      <option value="waf_connector">WAF connector</option>
                      <option value="webhook_signing">Webhook signing</option>
                      <option value="provider_api">Provider API</option>
                    </select>
                  </label>
                  <label>
                    <span>Name</span>
                    <input name="name" placeholder="cloudflare:edge-readonly" required />
                  </label>
                  <label className="full">
                    <span>Credential value</span>
                    <textarea name="plaintext" rows={4} placeholder="API token or JSON credential" required />
                  </label>
                  <div className="form-actions full">
                    <Button type="submit" loading={busy === 'create-vault-secret'}>Store secret</Button>
                  </div>
                </form>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>Rotate stored secret</CardTitle>
                <CardDescription>Rotation replaces the encrypted envelope; plaintext is never returned after storage.</CardDescription>
              </CardHeader>
              <CardContent>
                <form className="product-form" onSubmit={handleRotateVaultSecret}>
                  <label className="full">
                    <span>Secret</span>
                    <select name="secret_id" value={rotateSecretId} onChange={(event) => setRotateSecretId(event.target.value)} required>
                      <option value="">Select secret</option>
                      {data.secrets.map((secret) => (
                        <option key={getString(secret, ['id'])} value={getString(secret, ['id'])}>
                          {getString(secret, ['name'])} · {getString(secret, ['purpose'])}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label className="full">
                    <span>Replacement credential</span>
                    <textarea name="plaintext" rows={4} placeholder="New API token or JSON credential" required />
                  </label>
                  <div className="form-actions full">
                    <Button type="submit" disabled={busy !== '' || data.secrets.length === 0}>Rotate secret</Button>
                  </div>
                </form>
              </CardContent>
            </Card>
          </div>
          <Card>
            <CardHeader>
              <div>
                <CardTitle>Secret vault inventory</CardTitle>
                <CardDescription>Stored secret metadata only — no plaintext, ciphertext, or auth tags.</CardDescription>
              </div>
              <Badge tone="info">{data.secrets.length} records</Badge>
            </CardHeader>
            <CardContent>
              <DataTable
                columns={secretColumns}
                items={data.secrets}
                empty={<EmptyState icon={KeyRound} title="No secrets stored." body="Store connector or integration credentials here before referencing them from read-only connector workflows." actionLabel="Open Integrations" actionHref="#integrations" />}
              />
            </CardContent>
          </Card>
        </>
      )}

      {tab === 'privacy' && (
        <Card>
          <CardHeader>
            <CardTitle>Privacy and retention</CardTitle>
            <CardDescription>Updates metadata and evidence retention for this tenant. Shorter windows can purge stored metadata immediately.</CardDescription>
          </CardHeader>
          <CardContent>
            <form className="product-form" onSubmit={handleSaveRetention}>
              <label>
                <span>Metadata retention (days)</span>
                <input name="metadata_retention_days" type="number" min="1" max="3650" defaultValue={metadataRetentionDays} />
                <span className="muted">Recommended default: 90 days — events, vault metadata, and notification history.</span>
              </label>
              <label>
                <span>Report archive (days)</span>
                <input name="report_days" type="number" min="30" max="3650" defaultValue={getNumber(evidenceRetention, ['report_days'], 365)} />
                <span className="muted">Recommended default: 365 days — generated readiness report artifacts.</span>
              </label>
              <label>
                <span>Audit log retention (days)</span>
                <input name="audit_log_days" type="number" min="365" max="3650" defaultValue={getNumber(evidenceRetention, ['audit_log_days'], 2555)} />
                <span className="muted">Recommended default: 2555 days (~7 years) — security audit trail.</span>
              </label>
              <label>
                <span>High-scale artifact retention (days)</span>
                <input name="high_scale_artifact_days" type="number" min="365" max="3650" defaultValue={getNumber(evidenceRetention, ['high_scale_artifact_days'], 2555)} />
                <span className="muted">Recommended default: 2555 days — SOC authorization packs and artifacts.</span>
              </label>
              <label className="check-row full">
                <input name="legal_hold" type="checkbox" defaultChecked={Boolean(evidenceRetention.legal_hold)} />
                <span>Legal hold — block metadata deletions while legal hold is active (read-only boundary for production legal workflows).</span>
              </label>
              <div className="form-actions full">
                <Button type="submit" loading={busy === 'save-retention'} disabled={!tenant}>Save retention policy</Button>
              </div>
            </form>
          </CardContent>
          <CardContent className="settings-list">
            <div><FileCheck2 size={18} /><span>Metadata retention applies to events, evidence vault, reports, and notification events for the current tenant.</span></div>
            <div><ShieldCheck size={18} /><span>Audit logs, findings, test runs, and authorization artifacts follow separate production retention gates documented in the API reference.</span></div>
          </CardContent>
        </Card>
      )}

    </div>
  );
}

export function EnvironmentsPage({ data }: { data: PortalData }) {
  const rows = buildEnvironmentReadinessRows({
    targetGroups: data.targetGroups,
    runs: data.runs,
    findings: data.findings
  });
  const avgCoverage = rows.length
    ? Math.round(rows.reduce((sum, row) => sum + row.coverage, 0) / rows.length)
    : 0;
  const totalOpenFindings = rows.reduce((sum, row) => sum + row.openFindings, 0);

  return (
    <div className="content">
      <PageHeader route="environments" />
      <div className="metric-grid three">
        <MetricCard label="Environments" value={rows.length} sub="From declared target groups" icon={ServerCog} tone="info" />
        <MetricCard label="Avg coverage" value={`${avgCoverage}%`} sub="Groups with completed runs" icon={Activity} tone={avgCoverage >= 100 ? 'success' : avgCoverage > 0 ? 'warn' : 'muted'} />
        <MetricCard label="Open findings" value={totalOpenFindings} sub="Across all environments" icon={TriangleAlert} tone={totalOpenFindings > 0 ? 'warn' : 'success'} />
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Environment readiness</CardTitle>
          <CardDescription>
            Segment declared groups by operational environment and current validation evidence. Coverage bar = share of groups with completed runs.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {rows.length === 0 ? (
            <EmptyState icon={ServerCog} title="No environments yet." body="Create a declared target group with an environment ID to populate this view." actionLabel="Open Target Groups" actionHref="#target-groups" />
          ) : (
            <>
          <div className="row-actions environment-legend">
            <Badge tone="success">Fully covered</Badge>
            <Badge tone="warn">Partial evidence</Badge>
            <Badge tone="danger">Needs evidence</Badge>
          </div>
          <div className="environment-grid">
          {rows.map((row) => (
            <div
              className="environment-card"
              key={row.id}
            >
              <div>
                <strong>{row.id}</strong>
                <Badge
                  tone={row.coverage === 100 && row.openFindings === 0 ? 'success' : row.coverage > 0 ? 'warn' : 'danger'}
                  aria-label={`Readiness state: ${row.state}`}
                >
                  {row.state}
                </Badge>
              </div>
              <Progress value={row.coverage} tone={scoreProgressTone(row.coverage)} label={`${row.id} coverage`} />
              <span className="muted">{row.groupsWithEvidence}/{row.groupCount} groups with completed runs</span>
              <span className="muted">{row.completedRuns} completed or verdicted runs</span>
              <span className="muted">{row.openFindings} open findings</span>
              <AnchorButton size="sm" variant="secondary" href={`#target-groups?environment_id=${encodeURIComponent(row.id)}`}>View target groups</AnchorButton>
            </div>
          ))}
          </div>
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

export function PolicyPage({
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
  const [policyTargetGroupIds, setPolicyTargetGroupIds] = useState<string[]>([]);
  const [policyCheckId, setPolicyCheckId] = useState('');
  const [policyCadence, setPolicyCadence] = useState('weekly');
  const [policyExpectedVerdict, setPolicyExpectedVerdict] = useState('pass');
  const [archivePolicyId, setArchivePolicyId] = useState('');
  const safeChecks = data.checks.filter((check) => getString(check, ['safety_class']) === 'safe');
  const socGatedChecks = data.checks.filter((check) => getString(check, ['safety_class']) === 'soc_gated');
  const policyCheckOptions: SelectOption[] = [
    { value: '', label: 'Select safe check' },
    ...safeChecks.map((check) => ({
      value: getString(check, ['check_id']),
      label: getString(check, ['name', 'check_id'])
    }))
  ];
  const policyColumns: TableColumn<DataItem>[] = [
    {
      key: 'target',
      label: 'Target group',
      render: (item) => {
        const targetGroup = item.target_group && typeof item.target_group === 'object' ? item.target_group as DataItem : {};
        const groupId = getString(item, ['target_group_id'], getString(targetGroup, ['id'], ''));
        const label = getString(targetGroup, ['name', 'id'], groupId);
        return groupId
          ? <AnchorButton size="sm" variant="ghost" href={buildDetailHref('target-group-detail', groupId)}>{label}</AnchorButton>
          : label;
      }
    },
    {
      key: 'check',
      label: 'Check',
      render: (item) => {
        const check = item.check && typeof item.check === 'object' ? item.check as DataItem : {};
        const checkId = getString(item, ['check_id'], getString(check, ['check_id'], ''));
        const label = getString(check, ['name', 'check_id'], checkId);
        return checkId ? <AnchorButton size="sm" variant="ghost" href="#checks">{label}</AnchorButton> : label;
      }
    },
    { key: 'state', label: 'State', render: (item) => {
      const state = getString(item, ['state'], 'active');
      return <Badge tone={state === 'paused' ? 'warn' : 'success'}>{formatPolicyStateLabel(state)}</Badge>;
    } },
    { key: 'cadence', label: 'Cadence', render: (item) => <Badge tone="info">{formatPolicyCadenceLabel(getString(item, ['cadence']))}</Badge> },
    { key: 'expected', label: 'Expected verdict', render: (item) => <Badge tone="info">{formatPolicyVerdictLabel(getString(item, ['expected_verdict']))}</Badge> },
    { key: 'targets', label: 'Targets', render: (item) => getNumber(item, ['target_count']) },
    { key: 'updated', label: 'Updated', render: (item) => formatDate(item.updated_at ?? item.created_at) },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        const state = getString(item, ['state'], 'active');
        const rowPatchBusy = busy === `patch-policy-${id}`;
        const rowArchiveBusy = busy === `archive-policy-${id}`;
        const rowBlocked = busy !== '' && !rowPatchBusy && !rowArchiveBusy;
        return (
          <div className="row-actions" aria-busy={rowPatchBusy || rowArchiveBusy || undefined}>
            <Button variant="secondary" loading={rowPatchBusy} disabled={rowBlocked || rowArchiveBusy} onClick={() => void patchPolicy(id, { cadence: 'weekly' }, 'Policy cadence updated to weekly.')}>
              Set weekly cadence
            </Button>
            <Button variant="secondary" loading={rowPatchBusy} disabled={rowBlocked || rowArchiveBusy} onClick={() => void patchPolicy(id, { state: state === 'paused' ? 'active' : 'paused' }, state === 'paused' ? 'Policy resumed.' : 'Policy paused.')}>
              {state === 'paused' ? 'Resume' : 'Pause'}
            </Button>
            <Button variant="danger" loading={rowArchiveBusy} disabled={rowBlocked || rowPatchBusy} onClick={() => setArchivePolicyId(id)}>Archive</Button>
          </div>
        );
      }
    }
  ];

  async function runPolicyAction<T>(label: string, action: () => Promise<T>, success: string) {
    setBusy(label);
    setError('');
    setMessage('');
    try {
      const result = await action();
      setMessage(formatMutationSuccessMessage(success, result));
      await onRefresh();
      return result;
    } catch (err) {
      const payload = (err as Error & { payload?: unknown }).payload as { error?: string; message?: string } | undefined;
      setError(payload?.message ?? payload?.error ?? (err instanceof Error ? err.message : 'Action failed.'));
      return null;
    } finally {
      setBusy('');
    }
  }

  async function handleCreatePolicy(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const checkId = String(form.get('check_id') ?? '').trim();
    if (policyTargetGroupIds.length === 0) {
      setError('Select at least one declared target group before creating policies.');
      return;
    }
    if (!checkId) {
      setError('Select a safe check from the catalog before creating a policy.');
      return;
    }
    const day = String(form.get('safe_window_day') ?? '').trim();
    const start = String(form.get('safe_window_start') ?? '').trim();
    const end = String(form.get('safe_window_end') ?? '').trim();
    const safe_windows = day && start && end
      ? [{ day, start, end, timezone: String(form.get('safe_window_timezone') ?? 'UTC').trim() || 'UTC' }]
      : [];
    const bodyBase = {
      check_id: checkId,
      cadence: String(form.get('cadence') ?? 'manual'),
      expected_verdict: String(form.get('expected_verdict') ?? 'pass'),
      safe_windows
    };
    setBusy('create-test-policy');
    setError('');
    setMessage('');
    try {
      let lastResult: unknown = null;
      for (const targetGroupId of policyTargetGroupIds) {
        lastResult = await requestJson(config, session, '/v1/test-policies', {
          method: 'POST',
          body: { ...bodyBase, target_group_id: targetGroupId }
        });
      }
      setMessage(formatMutationSuccessMessage(
        `Created ${policyTargetGroupIds.length} test ${policyTargetGroupIds.length === 1 ? 'policy' : 'policies'} from declared scope and safe check catalog.`,
        lastResult
      ));
      setPolicyTargetGroupIds([]);
      formElement.reset();
      await onRefresh();
    } catch (err) {
      const payload = (err as Error & { payload?: unknown }).payload as { error?: string; message?: string } | undefined;
      setError(payload?.message ?? payload?.error ?? (err instanceof Error ? err.message : 'Action failed.'));
    } finally {
      setBusy('');
    }
  }

  async function patchPolicy(id: string, body: Record<string, unknown>, success: string) {
    if (!id) return;
    if ('cadence' in body && body.cadence === 'weekly') {
      if (!window.confirm('Set this policy cadence to weekly? Scheduled runs will follow the weekly window.')) return;
    }
    if ('state' in body) {
      const pausing = body.state === 'paused';
      if (!window.confirm(pausing ? 'Pause this policy? Scheduled runs under it will stop.' : 'Resume this policy?')) return;
    }
    await runPolicyAction(`patch-policy-${id}`, () => requestJson(config, session, `/v1/test-policies/${id}`, {
      method: 'PATCH',
      body
    }), success);
  }

  async function archivePolicy(id: string) {
    if (!id) return;
    await runPolicyAction(`archive-policy-${id}`, () => requestJson(config, session, `/v1/test-policies/${id}`, { method: 'DELETE' }), 'Test policy archived.');
    setArchivePolicyId('');
  }

  return (
    <div className="content">
      <PageHeader route="test-policies" />
      {(message || error) && (
        <div className={error ? 'form-banner error' : 'form-banner neutral'}>{error || message}</div>
      )}
      <div className="split">
      <Card id="test-policies-create">
        <CardHeader>
          <CardTitle>Create safe validation policy</CardTitle>
          <CardDescription>
            Bind a customer-runnable safe check to an active declared target group. SOC-gated checks remain request-only.
            {' '}
            <span className="muted small">
              {data.testPolicies.length} active · {safeChecks.length} safe checks · {socGatedChecks.length} SOC-gated
            </span>
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form className="product-form" onSubmit={handleCreatePolicy}>
            <input type="hidden" name="check_id" value={policyCheckId} />
            <input type="hidden" name="cadence" value={policyCadence} />
            <input type="hidden" name="expected_verdict" value={policyExpectedVerdict} />
            <TargetGroupPicker
              groups={data.targetGroups}
              selectedIds={policyTargetGroupIds}
              onChange={setPolicyTargetGroupIds}
              disabled={data.targetGroups.length === 0 || busy !== ''}
            />
            <Select
              label="Safe check"
              value={policyCheckId}
              options={policyCheckOptions}
              disabled={safeChecks.length === 0}
              onChange={setPolicyCheckId}
            />
            <Select
              label="Cadence"
              value={policyCadence}
              options={POLICY_CADENCE_OPTIONS}
              onChange={setPolicyCadence}
            />
            <Select
              label="Expected verdict"
              value={policyExpectedVerdict}
              options={POLICY_VERDICT_OPTIONS}
              onChange={setPolicyExpectedVerdict}
            />
            <details className="full">
              <summary>Safe window (optional)</summary>
              <label>
                <span>Safe window day</span>
                <input name="safe_window_day" placeholder="Mon" />
              </label>
              <label>
                <span>Window timezone</span>
                <input name="safe_window_timezone" defaultValue="UTC" />
              </label>
              <label>
                <span>Window start</span>
                <input name="safe_window_start" type="time" />
              </label>
              <label>
                <span>Window end</span>
                <input name="safe_window_end" type="time" />
              </label>
            </details>
            <div className="form-actions full">
              <Button type="submit" loading={busy === 'create-test-policy'} disabled={data.targetGroups.length === 0 || safeChecks.length === 0}>
                Create policy
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <div>
            <CardTitle>Safe validation policies</CardTitle>
            <CardDescription>Scheduled bindings between declared target groups and customer-runnable safe checks.</CardDescription>
          </div>
          {data.testPolicies.length > 0 ? <Badge tone="info">{data.testPolicies.length} active</Badge> : null}
        </CardHeader>
        <CardContent>
          <DataTable
            columns={policyColumns}
            items={data.testPolicies}
            getRowProps={(item) => {
              const id = getString(item, ['id'], '');
              const rowBusy = busy === `patch-policy-${id}` || busy === `archive-policy-${id}`;
              return rowBusy ? { 'aria-busy': true } : {};
            }}
            empty={renderFriendlyEmptyState({
              icon: ClipboardList,
              title: 'No test policies yet.',
              body: 'Create a safe validation policy after declaring target groups and reviewing the safe check catalog.',
              actionLabel: 'Create policy above',
              onAction: () => document.querySelector('#test-policies-create')?.scrollIntoView({ behavior: 'smooth' })
            })}
          />
        </CardContent>
      </Card>
      </div>
      <ConfirmModal
        open={Boolean(archivePolicyId)}
        title={`Archive test policy ${archivePolicyId}`}
        description={<p>Are you sure? Scheduled runs under this policy will stop and an audit entry will be written.</p>}
        confirmLabel="Archive policy"
        busy={busy === `archive-policy-${archivePolicyId}`}
        onCancel={() => setArchivePolicyId('')}
        onConfirm={() => void archivePolicy(archivePolicyId)}
      />
    </div>
  );
}

const CONNECTOR_SNAPSHOT_KIND_OPTIONS = [
  { value: 'waf_policy', label: 'WAF policy' },
  { value: 'cdn_property', label: 'CDN property' },
  { value: 'dns_zone', label: 'DNS zone' },
  { value: 'cloud_asset', label: 'Cloud asset' },
  { value: 'vulnerability', label: 'Vulnerability' }
] as const;

export function IntegrationPage({
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
  const [selectedConnectorId, setSelectedConnectorId] = useState('');
  const [showConnectorAdvanced, setShowConnectorAdvanced] = useState(false);
  const [snapshots, setSnapshots] = useState<DataItem[]>([]);
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const featureFlags = data.deploymentFeatures as { connectors?: boolean; waf_posture?: boolean } | null;
  const connectorsEnabled = featureFlags?.connectors === true;
  const activeConnectors = data.connectors.filter(
    (connector) => getString(connector, ['status'], '').toLowerCase() !== 'disabled'
  );
  const selectedConnector =
    activeConnectors.find((connector) => getString(connector, ['id'], '') === selectedConnectorId) ?? activeConnectors[0];
  const effectiveConnectorId = getString(selectedConnector ?? {}, ['id'], '');

  const connectorColumns: TableColumn<DataItem>[] = [
    { key: 'name', label: 'Connector', render: (item) => getString(item, ['name', 'id']) },
    { key: 'provider', label: 'Provider', render: (item) => <Badge tone="info">{getString(item, ['provider'])}</Badge> },
    { key: 'status', label: 'Status', render: (item) => <Badge tone={getString(item, ['status']) === 'active' ? 'success' : getString(item, ['status']) === 'error' ? 'danger' : 'muted'}>{getString(item, ['status'])}</Badge> },
    { key: 'last_poll', label: 'Last poll', render: (item) => formatDate(item.last_polled_at ?? item.last_success_at ?? item.last_poll_at) },
    { key: 'poll_errors', label: 'Poll errors', render: (item) => getNumber(item, ['poll_error_count', 'error_count'], 0) },
    { key: 'secret', label: 'Secret ref', render: (item) => getString(item, ['secret_id'], 'manual snapshots only') },
    { key: 'updated', label: 'Updated', render: (item) => formatDate(item.updated_at ?? item.created_at) },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        const status = getString(item, ['status'], '').toLowerCase();
        const isDisabled = status === 'disabled';
        const rowBusy = busy === `validate-${id}` || busy === `poll-${id}` || busy === `snapshots-${id}` || busy === `disable-${id}`;
        const rowBlocked = busy !== '' && !rowBusy;
        return (
          <div className="row-actions" aria-busy={rowBusy || undefined}>
            <Button size="sm" variant="secondary" loading={busy === `validate-${id}`} disabled={rowBlocked || isDisabled} onClick={() => void validateConnector(id)}>Validate</Button>
            <Button size="sm" variant="secondary" loading={busy === `poll-${id}`} disabled={rowBlocked || isDisabled} onClick={() => void pollConnector(id)}>Poll now</Button>
            <Button size="sm" variant="ghost" loading={busy === `snapshots-${id}`} disabled={rowBlocked} onClick={() => void loadSnapshots(id)}>Snapshots</Button>
            <Button size="sm" variant="danger" loading={busy === `disable-${id}`} disabled={rowBlocked || isDisabled} onClick={() => void disableConnector(id)}>Disable</Button>
          </div>
        );
      }
    }
  ];

  async function runAction<T>(label: string, action: () => Promise<T>, success: string) {
    setBusy(label);
    setError('');
    setMessage('');
    try {
      const result = await action();
      setMessage(formatMutationSuccessMessage(success, result));
      await onRefresh();
      return result;
    } catch (err) {
      const payload = (err as Error & { payload?: unknown }).payload as { error?: string; message?: string } | undefined;
      setError(payload?.message ?? payload?.error ?? (err instanceof Error ? err.message : 'Action failed.'));
      return null;
    } finally {
      setBusy('');
    }
  }

  async function handleCreateConnector(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const provider = String(form.get('provider') ?? 'cloudflare');
    const name = String(form.get('name') ?? '').trim();
    const secretInput = String(form.get('secret') ?? '').trim();
    const externalSecretId = String(form.get('secret_id') ?? '').trim();
    const resourceRefHash = String(form.get('resource_ref_hash') ?? '').trim();
    const region = String(form.get('region') ?? '').trim();
    const defaultSnapshotKind = String(form.get('default_snapshot_kind') ?? 'waf_policy');
    if (!name) {
      setError('Connector name is required.');
      return;
    }
    if (secretInput && !window.confirm('Store this provider credential in the encrypted tenant vault before creating the connector?')) return;
    await runAction('create-connector', async () => {
      let secretId = externalSecretId || null;
      if (secretInput) {
        const stored = await requestJson(config, session, '/v1/secrets', {
          method: 'POST',
          body: {
            purpose: 'waf_connector',
            name: `${provider}:${name}`,
            plaintext: secretInput,
            metadata: { provider, read_only: true }
          }
        }) as { secret?: { id?: string } };
        secretId = stored.secret?.id ?? null;
      }
      const created = await requestJson(config, session, '/v1/connectors', {
        method: 'POST',
        body: {
          provider,
          name,
          ...(secretId ? { secret_id: secretId } : {}),
          status: 'active',
          config: {
            read_only: true,
            default_snapshot_kind: defaultSnapshotKind,
            ...(provider === 'cloudflare' && resourceRefHash ? { zone_ref_hash: resourceRefHash } : {}),
            ...(provider === 'aws_waf' && resourceRefHash ? { resource_ref_hash: resourceRefHash } : {}),
            ...(provider === 'aws_waf' && region ? { region_summary: region } : {})
          }
        }
      }) as { connector?: DataItem };
      formElement.reset();
      if (created.connector?.id) setSelectedConnectorId(String(created.connector.id));
      return created;
    }, 'Connector created from backend API.');
  }

  async function validateConnector(id: string) {
    if (!id) return;
    await runAction(`validate-${id}`, () => requestJson(config, session, `/v1/connectors/${id}/validate`, { method: 'POST' }), 'Connector validation completed.');
  }

  async function pollConnector(id: string) {
    if (!id) return;
    const result = await runAction(`poll-${id}`, () => requestJson(config, session, `/v1/connectors/${id}/poll`, { method: 'POST', body: {} }), 'Connector poll requested.');
    const nextSnapshots = result && typeof result === 'object' && 'snapshots' in result ? (result as { snapshots?: DataItem[] }).snapshots : null;
    if (Array.isArray(nextSnapshots)) setSnapshots(nextSnapshots);
  }

  async function disableConnector(id: string) {
    if (!id) return;
    if (!window.confirm('Disable this connector? Deliveries through it will stop.')) return;
    await runAction(`disable-${id}`, () => requestJson(config, session, `/v1/connectors/${id}/disable`, { method: 'POST', body: { reason: 'Disabled from integrations page.' } }), 'Connector disabled.');
  }

  async function loadSnapshots(id: string) {
    if (!id) return;
    const result = await runAction(`snapshots-${id}`, () => requestJson(config, session, `/v1/connectors/${id}/snapshots`), 'Connector snapshots loaded.');
    const items = result && typeof result === 'object' && 'items' in result ? (result as { items?: DataItem[] }).items : null;
    setSnapshots(Array.isArray(items) ? items : []);
    setSelectedConnectorId(id);
  }

  async function handleManualSnapshot(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const id = effectiveConnectorId;
    if (!id) {
      setError('Create or select a connector before adding a snapshot.');
      return;
    }
    const form = new FormData(formElement);
    const hostnames = String(form.get('hostnames') ?? '')
      .split(',')
      .map((value) => value.trim())
      .filter(Boolean);
    const ruleCount = Number(form.get('rule_count') ?? 0);
    const snapshot = {
      snapshot_kind: String(form.get('snapshot_kind') ?? 'waf_policy'),
      display_ref: String(form.get('display_ref') ?? '').trim(),
      resource_ref_hash: String(form.get('resource_ref_hash') ?? '').trim(),
      config_hash: String(form.get('config_hash') ?? '').trim(),
      summary: {
        policy_mode: String(form.get('policy_mode') ?? 'monitor'),
        rule_count: Number.isFinite(ruleCount) ? ruleCount : 0,
        ...(hostnames.length ? { hostnames } : {})
      }
    };
    if (!snapshot.display_ref || !snapshot.resource_ref_hash || !snapshot.config_hash) {
      setError('Display ref, resource hash, and config hash are required for a metadata snapshot.');
      return;
    }
    const result = await runAction(
      `snapshot-${id}`,
      () => requestJson(config, session, `/v1/connectors/${id}/poll`, { method: 'POST', body: { manual_only: true, snapshots: [snapshot] } }),
      'Manual connector snapshot ingested.'
    );
    const nextSnapshots = result && typeof result === 'object' && 'snapshots' in result ? (result as { snapshots?: DataItem[] }).snapshots : null;
    if (Array.isArray(nextSnapshots)) setSnapshots(nextSnapshots);
    formElement.reset();
  }

  return (
    <div className="content">
      <PageHeader route="integrations" eyebrow="Connectors" />
      <PageContextSummary>
        <span className="tabular-nums">{data.connectors.length}</span> connectors ·{' '}
        <span className="tabular-nums">{data.secrets.length}</span> secret refs · WAF posture{' '}
        {featureFlags?.waf_posture ? 'enabled' : 'off'}
      </PageContextSummary>
      {!connectorsEnabled ? (
        <Card>
          <CardHeader>
            <CardTitle>Connectors are disabled for this tenant</CardTitle>
            <CardDescription>Connectors and WAF posture enrichment are disabled for this tenant. Contact support to enable read-only connector features.</CardDescription>
          </CardHeader>
          <CardContent className="callout-list">
            <div className="callout info"><ShieldCheck size={18} /><span>Core DDoS validation still works from declared target groups without cloud credentials.</span></div>
            <div className="callout"><FileCheck2 size={18} /><span>Connector credentials must be stored as encrypted secret references before provider polling.</span></div>
          </CardContent>
        </Card>
      ) : (
        <>
          <Card>
            <CardHeader>
              <CardTitle>Create read-only connector</CardTitle>
              <CardDescription>Store a provider credential in the encrypted secret vault or reference an existing secret, then create a metadata-only connector.</CardDescription>
            </CardHeader>
            <CardContent>
              {activeConnectors.length === 0 ? (
                <form className="product-form" onSubmit={handleCreateConnector} aria-busy={busy === 'create-connector' || undefined}>
                  <fieldset disabled={busy !== ''}>
                  <label>
                    <span>Provider</span>
                    <select name="provider" defaultValue="cloudflare">
                      <option value="cloudflare">Cloudflare</option>
                      <option value="aws_waf">AWS WAF</option>
                    </select>
                  </label>
                  <label>
                    <span>Name</span>
                    <input name="name" placeholder="edge-readonly" required />
                  </label>
                  <label className="full">
                    <span>API key or credential JSON</span>
                    <textarea name="secret" rows={4} placeholder='Cloudflare token, or AWS JSON: {"access_key_id":"...","secret_access_key":"...","region":"us-east-1"}' />
                  </label>
                  <p className="muted full">Credentials are stored encrypted in the tenant secret vault before the connector is created. Plaintext is never shown again after submit.</p>
                  <div className="form-actions full">
                    <Button loading={busy === 'create-connector'} disabled={busy !== ''} type="submit">Create connector</Button>
                  </div>
                  </fieldset>
                </form>
              ) : (
              <details className="disclosure">
                <summary>Expand intake form</summary>
                <form className="product-form" onSubmit={handleCreateConnector} aria-busy={busy === 'create-connector' || undefined}>
                  <fieldset disabled={busy !== ''}>
                  <label>
                    <span>Provider</span>
                    <select name="provider" defaultValue="cloudflare">
                      <option value="cloudflare">Cloudflare</option>
                      <option value="aws_waf">AWS WAF</option>
                    </select>
                  </label>
                  <label>
                    <span>Name</span>
                    <input name="name" placeholder="edge-readonly" required />
                  </label>
                  <label className="full">
                    <span>API key or credential JSON</span>
                    <textarea name="secret" rows={4} placeholder='Cloudflare token, or AWS JSON: {"access_key_id":"...","secret_access_key":"...","region":"us-east-1"}' />
                  </label>
                  <p className="muted full">Credentials are stored encrypted in the tenant secret vault before the connector is created. Plaintext is never shown again after submit.</p>
                  <details className="full" open={showConnectorAdvanced} onToggle={(event) => setShowConnectorAdvanced((event.currentTarget as HTMLDetailsElement).open)}>
                    <summary>Advanced options</summary>
                    <label>
                      <span>Existing secret ref</span>
                      <input name="secret_id" placeholder="secret_..." />
                    </label>
                    <label>
                      <span>Resource hash</span>
                      <input name="resource_ref_hash" placeholder="Optional zone/web ACL hash" />
                    </label>
                    <label>
                      <span>AWS region</span>
                      <input name="region" placeholder="us-east-1" />
                    </label>
                    <label>
                      <span>Default snapshot kind</span>
                      <select name="default_snapshot_kind" defaultValue="waf_policy">
                        {CONNECTOR_SNAPSHOT_KIND_OPTIONS.map((option) => (
                          <option key={option.value} value={option.value}>{option.label}</option>
                        ))}
                      </select>
                    </label>
                  </details>
                  <div className="form-actions full">
                    <Button loading={busy === 'create-connector'} disabled={busy !== ''} type="submit">Create connector</Button>
                  </div>
                  </fieldset>
                </form>
              </details>
              )}
            </CardContent>
          </Card>
          <p className="surface-label">Manual metadata ingest</p>
          <Card>
              <CardHeader>
                <CardTitle>Manual metadata snapshot</CardTitle>
                <CardDescription>Use this when provider polling is unavailable or encryption is not configured locally.</CardDescription>
              </CardHeader>
              <CardContent>
                <form className="product-form" onSubmit={handleManualSnapshot}>
                  <label className="full">
                    <span>Connector</span>
                    <select value={effectiveConnectorId} onChange={(event) => setSelectedConnectorId(event.target.value)}>
                      {activeConnectors.map((connector) => (
                        <option key={getString(connector, ['id'])} value={getString(connector, ['id'])}>
                          {getString(connector, ['name'])} - {getString(connector, ['provider'])}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label>
                    <span>Snapshot kind</span>
                    <select name="snapshot_kind" defaultValue="waf_policy">
                      {CONNECTOR_SNAPSHOT_KIND_OPTIONS.map((option) => (
                        <option key={option.value} value={option.value}>{option.label}</option>
                      ))}
                    </select>
                  </label>
                  <label>
                    <span>Display ref</span>
                    <input name="display_ref" placeholder="zone-a" required />
                  </label>
                  <label>
                    <span>Resource hash</span>
                    <input name="resource_ref_hash" placeholder="res_hash_1" required />
                  </label>
                  <label>
                    <span>Config hash</span>
                    <input name="config_hash" placeholder="cfg_hash_1" required />
                  </label>
                  <label>
                    <span>Policy mode</span>
                    <select name="policy_mode" defaultValue="monitor">
                      <option value="block">Block</option>
                      <option value="monitor">Monitor</option>
                      <option value="unknown">Unknown</option>
                    </select>
                  </label>
                  <label>
                    <span>Rule count</span>
                    <input name="rule_count" type="number" min="0" defaultValue="0" />
                  </label>
                  <label className="full">
                    <span>Hostnames</span>
                    <input name="hostnames" placeholder="app.example.com, api.example.com" />
                  </label>
                  <div className="form-actions full">
                    <Button disabled={busy !== '' || !effectiveConnectorId} type="submit">Ingest snapshot</Button>
                  </div>
                </form>
              </CardContent>
            </Card>
          {(message || error) && (
            <div className={error ? 'form-banner error' : 'form-banner'}>
              {error || message}
            </div>
          )}
          <Card>
            <CardHeader>
              <div>
                <CardTitle>Configured connectors</CardTitle>
                <CardDescription>Validate, poll, and disable connectors — plaintext credentials are never rendered.</CardDescription>
              </div>
              <Badge tone="info">{data.connectors.length} total</Badge>
            </CardHeader>
            <CardContent>
              <DataTable
                columns={connectorColumns}
                items={data.connectors}
                empty={<EmptyState icon={PlugZap} title="No connectors configured." body="Create a read-only connector or continue using manual evidence workflows without provider access." />}
              />
            </CardContent>
          </Card>
          <details>
            <summary>Connector snapshots ({snapshots.length} loaded)</summary>
            <Card>
              <CardHeader>
                <div>
                  <CardTitle>Connector snapshots</CardTitle>
                  <CardDescription>Snapshots come from backend poll results or manual metadata ingest.</CardDescription>
                </div>
                <Badge tone="muted">{snapshots.length} loaded</Badge>
              </CardHeader>
              <CardContent className="queue-list">
                {snapshots.length === 0 ? (
                  <EmptyState icon={FileCheck2} title="No snapshots loaded." body="Select a connector action to load or ingest metadata snapshots." />
                ) : snapshots.map((snapshot) => (
                  <div key={getString(snapshot, ['id'])}>
                    <Badge tone="info">{getString(snapshot, ['snapshot_kind'])}</Badge>
                    <span>{getString(snapshot, ['display_ref'])} - {formatDate(snapshot.observed_at ?? snapshot.created_at)}</span>
                  </div>
                ))}
              </CardContent>
            </Card>
          </details>
        </>
      )}
    </div>
  );
}

export function SupportPage({ data, session }: { data: PortalData; session: Session }) {
  const summary = data.subscriptionSummary;
  const support = getNestedItem(summary, ['support']);
  const usage = getNestedItem(summary, ['usage']);
  const account = getNestedItem(summary, ['account']);
  const recentAudit = getNestedArray(support, ['recent_audit']);
  const openFindings = getNumber(usage ?? {}, ['open_findings']);
  const pendingHighScale = getNumber(usage ?? {}, ['pending_high_scale_requests']);
  const supportOwner = getString(support ?? {}, ['owner'], 'Unassigned');
  const escalationState = getString(support ?? {}, ['escalation_state'], summary ? 'nominal' : 'No record');
  const routeAccessContext = {
    principal: session.principal,
    staffRole: session.staff_role,
  };
  const role = session.role ?? 'admin';
  const canReadNotifications = canAccessRoute(role, 'notifications', routeAccessContext);
  const supportRows = summary
    ? [
        { label: 'Support owner', value: supportOwner, icon: LifeBuoy },
        { label: 'Account lifecycle', value: getString(account ?? support ?? {}, ['lifecycle_state'], 'unrecorded'), icon: ShieldCheck },
        { label: 'Region', value: getString(account ?? support ?? {}, ['region'], 'unrecorded'), icon: Network },
        { label: 'Recent tenant audit records', value: formatNumber(getNumber(usage ?? {}, ['audit_events'])), icon: FileCheck2 }
      ]
    : [];

  return (
    <div className="content">
      <PageHeader
        route="support"
        eyebrow="Readiness support"
        actions={<AnchorButton href={SUPPORT_CONTACT_MAILTO} variant="default" size="sm">Contact support</AnchorButton>}
      />
      <PageContextSummary>
        Owner {summary ? supportOwner : '—'} ·{' '}
        <span className="tabular-nums">{summary ? openFindings : '—'}</span> open findings ·{' '}
        <span className="tabular-nums">{summary ? pendingHighScale : '—'}</span> SOC escalations
        {summary ? ` (${escalationState.replaceAll('_', ' ')})` : ''}
      </PageContextSummary>
      <div className="split">
        <Card>
          <CardHeader>
            <CardTitle>Support readiness</CardTitle>
            <CardDescription>Tenant support posture from account, findings, high-scale, and audit records.</CardDescription>
          </CardHeader>
          <CardContent className="settings-list">
            {supportRows.length === 0 ? (
              <EmptyState icon={LifeBuoy} title="No support account record." body="Approve a signup request or attach tenant account metadata before support readiness can show live ownership." />
            ) : supportRows.map(({ label, value, icon: RowIcon }) => (
              <div key={label}>
                <RowIcon size={18} />
                <span>
                  <strong>{label}</strong>
                  {' — '}
                  {label === 'Account lifecycle'
                    ? <Badge tone={lifecycleBadgeTone(value)}>{value}</Badge>
                    : value}
                </span>
              </div>
            ))}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Recent support evidence</CardTitle>
            <CardDescription>Latest tenant audit events exposed as metadata-only support context.</CardDescription>
          </CardHeader>
          <CardContent className="queue-list">
            {recentAudit.length === 0 ? (
              <EmptyState icon={FileCheck2} title="No recent support evidence." body="Tenant audit entries will appear here after support-relevant actions are recorded." />
            ) : recentAudit.map((entry) => (
              <div key={getString(entry, ['id', 'created_at', 'action'])} className="stack-tight">
                <div className="row-actions">
                  <Badge tone="info">{getString(entry, ['resource_type'], 'audit')}</Badge>
                  <AnchorButton size="sm" variant="ghost" href="#audit">{getString(entry, ['action'])}</AnchorButton>
                </div>
                <span className="muted">{formatDate(entry.created_at)}</span>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Support workflows</CardTitle>
          <CardDescription>Customer-safe escalation paths that stay within governed validation boundaries.</CardDescription>
        </CardHeader>
        <CardContent className="row-actions">
          <AnchorButton href="#findings" variant="secondary" size="sm">Review open findings ({openFindings})</AnchorButton>
          <AnchorButton href="#runs" variant="secondary" size="sm">Request SOC-governed test ({pendingHighScale} pending)</AnchorButton>
          {canReadNotifications ? <AnchorButton href="#notifications" variant="secondary" size="sm">Notification rules</AnchorButton> : null}
        </CardContent>
      </Card>
    </div>
  );
}

const ENTITLEMENT_FEATURES = ['waf_posture', 'external_discovery', 'connectors', 'high_scale_program'] as const;

const ENTITLEMENT_FEATURE_LABELS: Record<(typeof ENTITLEMENT_FEATURES)[number], string> = {
  waf_posture: 'WAF posture',
  external_discovery: 'External discovery',
  connectors: 'Connectors',
  high_scale_program: 'High-scale program'
};

function formatEntitlementGrantSource(value: string) {
  if (!value || value === 'plan only') return 'Plan default';
  if (value.startsWith('plan:')) return `Plan default (${value.slice(5)})`;
  return value;
}

function usageMeter(label: string, used: number, limit: number) {
  const hasLimit = limit >= 0;
  const percent = hasLimit && limit > 0 ? Math.min(100, Math.round((used / limit) * 100)) : 0;
  return (
    <div className="factor" key={label}>
      <div>
        <strong>{label}</strong>
        <span>{hasLimit ? `${used} / ${limit}` : `${used} recorded`}</span>
      </div>
      <Badge tone={hasLimit && used >= limit ? 'warn' : 'info'}>{hasLimit ? `${percent}%` : 'unlimited'}</Badge>
      {hasLimit ? <Progress value={percent} tone={used >= limit ? 'warn' : 'accent'} /> : null}
    </div>
  );
}

export function SubscriptionPage({ data }: { data: PortalData }) {
  const summary = data.subscriptionSummary;
  const subscription = getNestedItem(summary, ['subscription']);
  const plan = getNestedItem(summary, ['plan']);
  const account = getNestedItem(summary, ['account']);
  const usage = getNestedItem(summary, ['usage']);
  const support = getNestedItem(summary, ['support']);
  const planEntitlements = getNestedItem(plan, ['feature_entitlements']) ?? getNestedItem(subscription, ['feature_entitlements']);
  const effectiveEntitlements = getNestedItem(subscription, ['effective_entitlements']);
  const entitlementGrants = Array.isArray(subscription?.entitlement_grants) ? subscription.entitlement_grants as DataItem[] : [];
  const hasSubscription = Boolean(subscription);
  const planLabel = hasSubscription ? getString(plan ?? {}, ['name'], getString(subscription ?? {}, ['plan_id'], 'Recorded plan')) : 'Not configured';
  const safeRunsLimit = getNestedNumber(subscription, ['limits', 'safe_runs_per_hour'], -1);
  const safeRunsUsed = getNumber(usage ?? {}, ['safe_runs_started_last_hour']);
  const highScaleEnabled = effectiveEntitlements?.high_scale_program === true;
  const targetGroupLimit = getNestedNumber(subscription, ['limits', 'target_groups'], -1);
  const targetGroupUsage = getNumber(usage ?? {}, ['target_groups']);
  const usersLimit = getNestedNumber(subscription, ['limits', 'users'], -1);
  const agentsLimit = getNestedNumber(subscription, ['limits', 'agents'], -1);
  const supportOwner = getString(support ?? account ?? {}, ['owner', 'support_owner'], '');

  if (!hasSubscription) {
    return (
      <div className="content">
        <PageHeader route="subscription" eyebrow="Entitlements" />
        <EmptyState
          icon={LifeBuoy}
          title="No subscription configured for this tenant."
          body="Limits, entitlements, and billing metadata stay hidden until staff provisioning completes. Contact AstraNull support for provisioning or billing assistance."
          actionLabel="Contact support"
          actionHref={SUPPORT_CONTACT_MAILTO}
        />
        <div className="row-actions row-actions--spaced">
          <AnchorButton href="#support" variant="secondary">Open support workspace</AnchorButton>
        </div>
      </div>
    );
  }

  return (
    <div className="content">
      <PageHeader route="subscription" eyebrow="Entitlements" />
      <PageContextSummary>
        {planLabel} · safe runs{' '}
        <span className="tabular-nums">{safeRunsUsed}</span>
        {safeRunsLimit >= 0 ? ` / ${safeRunsLimit}` : ''} per hour · high-scale program{' '}
        {highScaleEnabled ? 'enabled' : 'disabled'}
      </PageContextSummary>
      <div className="split">
        <Card>
          <CardHeader>
            <CardTitle>Contract posture</CardTitle>
            <CardDescription>Billing metadata, entitlement limits, and account state for this tenant.</CardDescription>
          </CardHeader>
          <CardContent className="kv-list">
              <>
                <div><span>Plan</span><strong>{planLabel}</strong></div>
                <div><span>Status</span><Badge tone={subscriptionStatusBadgeTone(getString(subscription ?? {}, ['status']))}>{getString(subscription ?? {}, ['status'])}</Badge></div>
                <div><span>Effective</span><strong>{formatDate(subscription?.effective_at)}</strong></div>
                <div><span>Renewal</span><strong>{formatDate(subscription?.renewal_at)}</strong></div>
                <div><span>Data region</span><strong>{getString(account ?? support ?? {}, ['region'], 'unrecorded')}</strong></div>
                <div><span>Lifecycle</span><Badge tone={lifecycleBadgeTone(getString(account ?? support ?? {}, ['lifecycle_state'], 'unrecorded'))}>{getString(account ?? support ?? {}, ['lifecycle_state'], 'unrecorded')}</Badge></div>
                <div><span>Support owner</span><strong>{getString(account ?? {}, ['support_owner'], supportOwner || 'unassigned')}</strong></div>
                <div><span>Contract ref</span><strong>{getString(account ?? {}, ['contract_reference'], 'unrecorded')}</strong></div>
              </>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Usage against limits</CardTitle>
            <CardDescription>Live workspace counts compared to subscription limits.</CardDescription>
          </CardHeader>
          <CardContent className="factor-list">
              <>
                {usageMeter('Target groups', targetGroupUsage, targetGroupLimit)}
                {usageMeter('Users', getNumber(usage ?? {}, ['users']), usersLimit)}
                {usageMeter('Agents', getNumber(usage ?? {}, ['agents']), agentsLimit)}
                {usageMeter('Safe runs / hour', safeRunsUsed, safeRunsLimit)}
                <div className="factor">
                  <div><strong>Open findings</strong><span>{getNumber(usage ?? {}, ['open_findings'])} active records</span></div>
                  <Badge tone={getNumber(usage ?? {}, ['open_findings']) > 0 ? 'warn' : 'success'}>{getNumber(usage ?? {}, ['open_findings'])}</Badge>
                </div>
                <div className="factor">
                  <div><strong>Pending high-scale</strong><span>{getNumber(usage ?? {}, ['pending_high_scale_requests'])} awaiting SOC workflow</span></div>
                  <Badge tone={getNumber(usage ?? {}, ['pending_high_scale_requests']) > 0 ? 'warn' : 'muted'}>{getNumber(usage ?? {}, ['pending_high_scale_requests'])}</Badge>
                </div>
              </>
          </CardContent>
        </Card>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Entitlement breakdown</CardTitle>
          <CardDescription>Plan defaults, staff grants, and effective feature access for this tenant.</CardDescription>
        </CardHeader>
        <CardContent>
            <DataTable
              columns={[
                {
                  key: 'feature',
                  label: 'Feature',
                  render: (item) => {
                    const feature = getString(item, ['feature']);
                    return ENTITLEMENT_FEATURE_LABELS[feature as (typeof ENTITLEMENT_FEATURES)[number]] ?? feature;
                  }
                },
                {
                  key: 'plan',
                  label: 'Plan default',
                  render: (item) => (
                    <Badge tone={item.plan_enabled === true ? 'success' : 'muted'}>
                      {item.plan_enabled === true ? 'enabled' : 'disabled'}
                    </Badge>
                  )
                },
                {
                  key: 'effective',
                  label: 'Effective',
                  render: (item) => (
                    <Badge tone={item.effective_enabled === true ? 'success' : 'warn'}>
                      {item.effective_enabled === true ? 'enabled' : 'disabled'}
                    </Badge>
                  )
                },
                {
                  key: 'grant',
                  label: 'Grant source',
                  render: (item) => formatEntitlementGrantSource(getString(item, ['grant_source'], 'plan only'))
                }
              ]}
              items={ENTITLEMENT_FEATURES.map((feature) => {
                const grant = entitlementGrants.find((entry) => getString(entry, ['feature'], '') === feature);
                return {
                  feature,
                  plan_enabled: planEntitlements?.[feature] === true,
                  effective_enabled: effectiveEntitlements?.[feature] === true,
                  grant_source: grant ? getString(grant, ['source'], 'staff grant') : 'plan only'
                };
              })}
              empty={<EmptyState icon={ShieldCheck} title="No entitlement features." body="Plan feature entitlements were not returned by the subscription API." />}
            />
        </CardContent>
      </Card>
    </div>
  );
}

export function StaffSurfacePage({
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
  const [entitlementTenantId, setEntitlementTenantId] = useState(() => getString(data.internalTenants[0] ?? {}, ['tenant_id', 'id'], 'ten_demo'));
  const [entitlementFeature, setEntitlementFeature] = useState('waf_posture');
  const [entitlementAction, setEntitlementAction] = useState('true');
  const [subscriptionSnapshot, setSubscriptionSnapshot] = useState<DataItem | null>(null);
  const entitlementFeatures = ['waf_posture', 'external_discovery', 'connectors', 'high_scale_program'] as const;
  const internalTenantOptions: SelectOption[] = data.internalTenants.length > 0
    ? data.internalTenants.map((tenant) => {
      const tenantId = getString(tenant, ['tenant_id', 'id'], '');
      return {
        value: tenantId,
        label: getString(tenant, ['name', 'tenant_id'], tenantId)
      };
    })
    : [{ value: entitlementTenantId, label: entitlementTenantId || 'No tenant selected' }];
  const entitlementFeatureOptions: SelectOption[] = entitlementFeatures.map((feature) => ({
    value: feature,
    label: ENTITLEMENT_FEATURE_LABELS[feature] ?? feature
  }));
  const entitlementActionOptions: SelectOption[] = [
    { value: 'true', label: 'Grant / enable' },
    { value: 'false', label: 'Revoke / disable' }
  ];
  const isStaff = session.principal === 'staff';
  const [adminTab, setAdminTab] = useState('signup-queue');
  const adminTabOptions = routeTabs('admin').map((tab) => ({ id: tab.id, label: tab.label }));
  const overview = data.internalOverview;
  const queueDepth = getNumber(overview ?? {}, ['pending_signups']) + getNumber(overview ?? {}, ['pending_approval_requests']);
  const tenantCount = getNumber(overview ?? {}, ['tenant_count'], data.internalTenants.length);
  const highScaleReviews = getNumber(overview ?? {}, ['high_scale_reviews']);
  async function runStaffAction<T>(label: string, action: () => Promise<T>, success: string) {
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
      setError(payload?.message ?? payload?.error ?? (err instanceof Error ? err.message : 'Staff action failed.'));
      return null;
    } finally {
      setBusy('');
    }
  }

  async function approveSignup(id: string) {
    if (!window.confirm('Approve this signup request? A tenant account will be provisioned.')) return;
    await runStaffAction(`approve-signup-${id}`, () => requestJson(config, session, `/internal/admin/signup-requests/${id}/approve`, {
      method: 'POST',
      body: { reason: 'Approved from React staff console.' }
    }), 'Signup request approved and tenant provisioned.');
  }

  async function rejectSignup(id: string) {
    if (!window.confirm('Reject this signup request? No tenant will be provisioned for this applicant.')) return;
    await runStaffAction(`reject-signup-${id}`, () => requestJson(config, session, `/internal/admin/signup-requests/${id}/reject`, {
      method: 'POST',
      body: { reason: 'Rejected from React staff console.' }
    }), 'Signup request rejected.');
  }

  async function decideApproval(id: string, decision: 'approve' | 'reject') {
    if (decision === 'approve') {
      if (!window.confirm('Approve this internal approval request? The requested action will proceed.')) return;
    } else if (!window.confirm('Reject this internal approval request? The requested action will not proceed.')) return;
    await runStaffAction(`approval-${id}-${decision}`, () => requestJson(config, session, `/internal/admin/approval-requests/${id}/decision`, {
      method: 'POST',
      body: { decision, reason: `${decision} from React staff console.` }
    }), `Approval request ${decision}d.`);
  }

  useEffect(() => {
    if (!isStaff || !entitlementTenantId) {
      setSubscriptionSnapshot(null);
      return;
    }
    let cancelled = false;
    requestJson(config, session, `/internal/admin/tenants/${encodeURIComponent(entitlementTenantId)}/subscription`)
      .then((payload) => {
        if (!cancelled) setSubscriptionSnapshot(payload as DataItem);
      })
      .catch(() => {
        if (!cancelled) setSubscriptionSnapshot(null);
      });
    return () => {
      cancelled = true;
    };
  }, [config, session, entitlementTenantId, isStaff, data.internalTenants]);

  async function grantEntitlement(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const feature = String(form.get('feature') ?? '').trim();
    const enabled = String(form.get('enabled') ?? 'true') === 'true';
    const reason = String(form.get('reason') ?? '').trim();
    if (!entitlementTenantId || !feature) {
      setError('Select a tenant and feature before granting entitlements.');
      return;
    }
    const featureLabel = ENTITLEMENT_FEATURE_LABELS[feature as (typeof ENTITLEMENT_FEATURES)[number]] ?? feature;
    if (enabled) {
      if (!window.confirm(`Grant the ${featureLabel} entitlement for this tenant?`)) return;
    } else if (!window.confirm(`Revoke the ${featureLabel} entitlement? The feature will be disabled for this tenant.`)) return;
    await runStaffAction(`entitlement-${entitlementTenantId}-${feature}`, () => requestJson(config, session, `/internal/admin/tenants/${encodeURIComponent(entitlementTenantId)}/entitlements`, {
      method: 'POST',
      body: { feature, enabled, reason: reason || `Entitlement ${enabled ? 'granted' : 'revoked'} from React staff console.` }
    }), `${feature} entitlement ${enabled ? 'granted' : 'revoked'} for ${entitlementTenantId}.`);
  }

  const effectiveEntitlements = getNestedItem(subscriptionSnapshot, ['effective_entitlements'])
    ?? getNestedItem(subscriptionSnapshot, ['subscription', 'effective_entitlements']);

  const signupColumns: TableColumn<DataItem>[] = [
    { key: 'org', label: 'Organization', render: (item) => getString(item, ['organization_name', 'id']) },
    { key: 'state', label: 'State', render: (item) => <Badge tone={['submitted', 'under_review'].includes(getString(item, ['state'])) ? 'warn' : 'info'}>{getString(item, ['state'])}</Badge> },
    { key: 'plan', label: 'Plan', render: (item) => getString(item, ['requested_plan']) },
    { key: 'created', label: 'Created', render: (item) => formatDate(item.created_at) },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        const state = getString(item, ['state'], '');
        if (!['submitted', 'under_review'].includes(state)) return '—';
        const rowBusy = busy === `approve-signup-${id}` || busy === `reject-signup-${id}`;
        const rowBlocked = busy !== '' && !rowBusy;
        return (
          <div className="row-actions" aria-busy={rowBusy || undefined}>
            <Button size="sm" variant="secondary" loading={busy === `approve-signup-${id}`} disabled={rowBlocked} onClick={() => void approveSignup(id)}>Approve</Button>
            <Button size="sm" variant="danger" loading={busy === `reject-signup-${id}`} disabled={rowBlocked} onClick={() => void rejectSignup(id)}>Reject</Button>
          </div>
        );
      }
    }
  ];
  const tenantColumns: TableColumn<DataItem>[] = [
    { key: 'tenant', label: 'Tenant', render: (item) => getString(item, ['name', 'tenant_id']) },
    { key: 'state', label: 'Lifecycle', render: (item) => <Badge tone={getString(item, ['lifecycle_state']) === 'active' ? 'success' : 'warn'}>{getString(item, ['lifecycle_state'])}</Badge> },
    { key: 'plan', label: 'Plan', render: (item) => getString(item, ['plan_id']) },
    { key: 'owner', label: 'Support owner', render: (item) => getString(item, ['support_owner'], 'unassigned') },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const tenantId = getString(item, ['tenant_id', 'id'], '');
        return tenantId
          ? <AnchorButton size="sm" variant="secondary" href={buildDetailHref('tenant-detail', tenantId)}>Detail</AnchorButton>
          : '—';
      }
    }
  ];
  const approvalColumns: TableColumn<DataItem>[] = [
    { key: 'kind', label: 'Kind', render: (item) => getString(item, ['kind']) },
    { key: 'state', label: 'State', render: (item) => <Badge tone={['submitted', 'under_review'].includes(getString(item, ['state'])) ? 'warn' : 'success'}>{getString(item, ['state'])}</Badge> },
    { key: 'tenant', label: 'Tenant', render: (item) => getString(item, ['tenant_id']) },
    { key: 'created', label: 'Created', render: (item) => formatDate(item.created_at) },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const id = getString(item, ['id'], '');
        const state = getString(item, ['state'], '');
        if (!['submitted', 'under_review'].includes(state)) return '—';
        const rowBusy = busy === `approval-${id}-approve` || busy === `approval-${id}-reject`;
        const rowBlocked = busy !== '' && !rowBusy;
        return (
          <div className="row-actions" aria-busy={rowBusy || undefined}>
            <Button size="sm" variant="secondary" loading={busy === `approval-${id}-approve`} disabled={rowBlocked} onClick={() => void decideApproval(id, 'approve')}>Approve</Button>
            <Button size="sm" variant="danger" loading={busy === `approval-${id}-reject`} disabled={rowBlocked} onClick={() => void decideApproval(id, 'reject')}>Reject</Button>
          </div>
        );
      }
    }
  ];
  const auditColumns: TableColumn<DataItem>[] = [
    { key: 'action', label: 'Action', render: (item) => getString(item, ['action']) },
    { key: 'staff', label: 'Staff', render: (item) => getString(item, ['staff_id']) },
    { key: 'tenant', label: 'Tenant', render: (item) => getString(item, ['tenant_id']) },
    { key: 'created', label: 'Created', render: (item) => formatDate(item.created_at) }
  ];
  return (
    <div className="content">
      <PageHeader route={route} eyebrow={route === 'internal-soc' ? 'Staff SOC surface' : 'Staff-only surface'} />
      {(message || error) && <div className={error ? 'form-banner error' : 'form-banner'}>{error || message}</div>}
      <PageContextSummary>
        Review queue <span className="tabular-nums">{queueDepth}</span> ·{' '}
        <span className="tabular-nums">{tenantCount}</span> tenants ·{' '}
        <span className="tabular-nums">{highScaleReviews}</span> SOC reviews pending
      </PageContextSummary>
      {!isStaff ? (
        <Card>
          <CardHeader>
            <CardTitle>Staff session required</CardTitle>
            <CardDescription>Internal management data is only fetched after staff authentication.</CardDescription>
          </CardHeader>
          <CardContent>
            <EmptyState icon={UserCog} title="No staff principal." body="Use the staff sign-in surface to load internal management queues and audit records." actionLabel="Open staff login" actionHref="/internal/admin/login" />
          </CardContent>
        </Card>
      ) : (
        <>
          <Tabs value={adminTab} options={adminTabOptions} onChange={setAdminTab} className="tabs-wrap" />
          {adminTab === 'overview' ? (
            <Card density="compact">
              <CardHeader><CardTitle>Staff overview</CardTitle><CardDescription>Queue depth and tenant posture from internal management APIs.</CardDescription></CardHeader>
              <CardContent className="kv-list">
                <div><span>Review queue</span><strong>{queueDepth}</strong></div>
                <div><span>Tenants</span><strong>{tenantCount}</strong></div>
                <div><span>SOC reviews pending</span><strong>{highScaleReviews}</strong></div>
              </CardContent>
            </Card>
          ) : null}
          {adminTab === 'signup-queue' ? (
            <Card density="compact" className="staff-queue-priority">
              <CardHeader>
                <CardTitle>Signup queue</CardTitle>
                <CardDescription>Requests from the staff-only signup review API.</CardDescription>
              </CardHeader>
              <CardContent>
                <DataTable columns={signupColumns} items={data.internalSignupRequests} empty={renderFriendlyEmptyState({ icon: ClipboardList, title: 'No signup requests.', body: 'Reviewed account intake records will appear here after customers submit requests.' })} />
              </CardContent>
            </Card>
          ) : null}
          {adminTab === 'tenants' ? (
            <Card density="compact">
              <CardHeader>
                <CardTitle>Tenant directory</CardTitle>
                <CardDescription>Managed tenant account and subscription metadata.</CardDescription>
              </CardHeader>
              <CardContent>
                <DataTable columns={tenantColumns} items={data.internalTenants} empty={renderFriendlyEmptyState({ icon: Target, title: 'No managed tenants.', body: 'Provisioned tenants appear here after staff approval creates account records.' })} />
              </CardContent>
            </Card>
          ) : null}
          {adminTab === 'approvals' ? (
            <Card density="compact">
              <CardHeader>
                <CardTitle>Approval requests</CardTitle>
                <CardDescription>Unified internal approvals, including subscription exceptions.</CardDescription>
              </CardHeader>
              <CardContent>
                <DataTable columns={approvalColumns} items={data.internalApprovalRequests} empty={renderFriendlyEmptyState({ icon: ShieldCheck, title: 'No internal approvals.', body: 'Pending approval records will appear here when backend workflows create them.' })} />
              </CardContent>
            </Card>
          ) : null}
          {adminTab === 'audit' ? (
            <Card density="compact">
              <CardHeader>
                <CardTitle>Internal audit</CardTitle>
                <CardDescription>Recent staff actions from the internal audit API.</CardDescription>
              </CardHeader>
              <CardContent>
                <DataTable columns={auditColumns} items={data.internalAudit} empty={renderFriendlyEmptyState({ icon: FileCheck2, title: 'No internal audit events.', body: 'Staff decisions and support actions will be listed after they are recorded.' })} />
              </CardContent>
            </Card>
          ) : null}
          <Card>
            <CardHeader>
              <CardTitle>Support owner assignment</CardTitle>
              <CardDescription>Assign the AstraNull support owner for the selected tenant.</CardDescription>
            </CardHeader>
            <CardContent>
              <form className="product-form" onSubmit={(event) => {
                event.preventDefault();
                const owner = String(new FormData(event.currentTarget).get('support_owner') ?? '').trim();
                if (!entitlementTenantId || !owner) return;
                if (!window.confirm(`Assign support owner "${owner}" for tenant ${entitlementTenantId}?`)) return;
                void runStaffAction(`support-owner-${entitlementTenantId}`, () => requestJson(config, session, `/internal/admin/tenants/${encodeURIComponent(entitlementTenantId)}`, {
                  method: 'PATCH',
                  body: { support_owner: owner, reason: 'Support owner updated from React staff console.' }
                }), `Support owner updated for ${entitlementTenantId}.`);
              }}>
                <Select
                  label="Tenant"
                  name="tenant_id"
                  value={entitlementTenantId}
                  options={internalTenantOptions}
                  onChange={setEntitlementTenantId}
                />
                <label className="full"><span>Support owner</span><input name="support_owner" placeholder="owner@customer.example" required /></label>
                <div className="form-actions full"><Button type="submit" loading={busy.startsWith('support-owner-')}>Assign support owner</Button></div>
              </form>
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Entitlement grants</CardTitle>
              <CardDescription>Grant or revoke plan feature entitlements for the selected tenant.</CardDescription>
            </CardHeader>
            <CardContent className="product-form">
              <Select
                label="Tenant"
                value={entitlementTenantId}
                options={internalTenantOptions}
                onChange={setEntitlementTenantId}
              />
              {effectiveEntitlements ? (
                <div className="kv-list">
                  {entitlementFeatures.map((feature) => (
                    <div key={feature}>
                      <span>{ENTITLEMENT_FEATURE_LABELS[feature] ?? feature}</span>
                      <Badge tone={effectiveEntitlements[feature] === true ? 'success' : 'muted'}>{effectiveEntitlements[feature] === true ? 'enabled' : 'disabled'}</Badge>
                    </div>
                  ))}
                </div>
              ) : <p className="muted">Effective entitlements load after tenant subscription is fetched.</p>}
              <form className="product-form" onSubmit={grantEntitlement}>
                <Select
                  label="Feature"
                  name="feature"
                  value={entitlementFeature}
                  options={entitlementFeatureOptions}
                  onChange={setEntitlementFeature}
                />
                <Select
                  label="Action"
                  name="enabled"
                  value={entitlementAction}
                  options={entitlementActionOptions}
                  onChange={setEntitlementAction}
                />
                <label className="full"><span>Reason</span><input name="reason" placeholder="Verified plan exception" required /></label>
                <div className="form-actions full"><Button type="submit" loading={busy.startsWith('entitlement-')} disabled={!entitlementTenantId}>Apply entitlement</Button></div>
              </form>
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}
