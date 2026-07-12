import { useEffect, useMemo, useRef, useState, type FormEvent, type HTMLAttributes, type KeyboardEvent, type ReactNode } from 'react';
import { Activity, Bot, ClipboardList, FileCheck2, FileText, Network, ShieldCheck, Siren, Target, TriangleAlert, UserCog, Users } from 'lucide-react';
import { FindingExplanationPanel } from '../components/findings/finding-explanation-panel';
import { Badge, type BadgeProps } from '../components/ui/badge';
import { AnchorButton, Button } from '../components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { EmptyState } from '../components/ui/empty-state';
import { Progress } from '../components/ui/progress';
import { DataTable, type TableColumn } from '../components/ui/table';
import { Select } from '../components/ui/select';
import { Tabs } from '../components/ui/tabs';
import { buildApiHeaders, isStaffSocRole, requestJson, requestSocJson } from '../lib/api';
import { ROUTE_BY_ID } from '../lib/navigation';
import { buildDetailHref, getRouteEntityId } from '../lib/route-params';
import { buildEvidenceCustodyManifest, CUSTODY_CONTENT_CANONICALIZATION } from '../lib/custody';
import type { DataItem, PortalConfig, PortalData, RouteId, Session } from '../lib/types';
import { formatDate, scoreTone } from '../lib/utils';
import { buildEnvironmentReadinessRows } from '../lib/environments';
import { AgentHeartbeatPanel } from '../components/agents/agent-heartbeat-panel';
import { AgentPlacementPanel } from '../components/agents/agent-placement-panel';
import { CapabilityProbeResultsPanel } from '../components/runs/capability-probe-panel';
import { ConfirmModal, formatMutationSuccessMessage } from '../lib/crud-ui';
import { ONBOARDING_PLACEMENT_TEST_CHECK_ID } from '../lib/onboarding';
import { RunTimelineViz, TruthTablePanel, VerdictExplanationPanel } from '../components/runs/run-proof-panels';
import {
  agentHeartbeatFreshness,
  filterAgentAuditEntries,
  formatAgentCapabilities,
  formatAgentHealth,
  formatAgentPlacement,
  formatPlacementStatus,
  placementStatusHint,
} from '../lib/agent-helpers';
import { findingSlaDueAt, isFindingSlaBreach, resolveFindingRetestAction } from '../lib/findings-helpers';
import {
  authorizationArtifactPurpose,
  authorizationArtifactTitle,
  authorizationArtifactTypesForRequest,
  bestArtifactForType,
  buildLifecycleTimeline,
  buildMetadataArtifactUploadBody,
  explainArtifactReviewStatus,
  packRequirementForType,
  socDevScheduleWindow
} from '../lib/high-scale';
import { routeTabs } from '../lib/prototype-manifest';
import { ReadinessGauge } from '../components/charts/readiness-gauge';
import { MetricCard, PageContextSummary } from './page-components';
import { TargetGroupDetailView as TargetGroupDetailViewRevamp } from './target-group-detail-view';
import { TargetDetailView } from './target-detail-view';
import { FindingDetailView as FindingDetailViewRevamp } from './finding-detail-view';


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

function getNestedNumber(item: DataItem | null | undefined, path: string[], fallback = 0) {
  let current: unknown = item;
  for (const key of path) {
    if (!current || typeof current !== 'object' || Array.isArray(current)) return fallback;
    current = (current as DataItem)[key];
  }
  return typeof current === 'number' && Number.isFinite(current) ? current : fallback;
}

function getNestedArray(item: DataItem | null | undefined, path: string[]) {
  let current: unknown = item;
  for (const key of path) {
    if (!current || typeof current !== 'object' || Array.isArray(current)) return [];
    current = (current as DataItem)[key];
  }
  return Array.isArray(current) ? current as DataItem[] : [];
}

function getNestedItem(item: DataItem | null | undefined, path: string[]) {
  let current: unknown = item;
  for (const key of path) {
    if (!current || typeof current !== 'object' || Array.isArray(current)) return null;
    current = (current as DataItem)[key];
  }
  return current && typeof current === 'object' && !Array.isArray(current) ? current as DataItem : null;
}

function isExternalOnlyVerdictSignal(entity: DataItem | null | undefined) {
  if (!entity) return false;
  const topConfidence = getString(entity, ['confidence'], '');
  const topHint = getString(entity, ['strengthen_hint'], '');
  const topPlacement = getString(entity, ['placement'], '');
  const verdictConfidence = getNestedString(entity, ['verdict', 'confidence'], '');
  const verdictHint = getNestedString(entity, ['verdict', 'strengthen_hint'], '');
  const verdictPlacement = getNestedString(entity, ['verdict', 'placement'], '');
  return (
    topConfidence === 'external_only'
    || topHint === 'deploy_agent'
    || topPlacement === 'unverified'
    || verdictConfidence === 'external_only'
    || verdictHint === 'deploy_agent'
    || verdictPlacement === 'unverified'
  );
}

function ownershipStatusBadgeTone(status: string): BadgeProps['tone'] {
  const key = normalizeStatusKey(status);
  if (key === 'user_confirmed' || key === 'agent_verified' || key === 'dns_verified') return 'success';
  if (key === 'unverified') return 'warn';
  return 'muted';
}

function validationModeBadgeTone(mode: string): BadgeProps['tone'] {
  return normalizeStatusKey(mode) === 'external_only' ? 'warn' : 'info';
}

function probeEndpointStatusBadgeTone(status: string): BadgeProps['tone'] {
  const normalized = normalizeStatusKey(status);
  if (normalized === 'reported') return 'success';
  if (normalized === 'rejected') return 'danger';
  return 'muted';
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

type FactorEntry = { label: string; body: string; value: number };

function formatFactorLabel(value: string) {
  return value.replace(/_/g, ' ');
}

const SIGNAL_TYPE_LABELS: Record<string, string> = {
  probe_result: 'Probe result',
  agent_observation: 'Agent observation',
  agent_no_observation: 'Agent no observation',
  verdict_published: 'Verdict published',
  run_started: 'Run started',
  run_cancelled: 'Run cancelled'
};

function humanizeSignalType(value: string) {
  const key = value.trim();
  if (!key) return 'Event';
  return SIGNAL_TYPE_LABELS[key] ?? formatFactorLabel(key);
}

function checkDisplayName(checks: DataItem[], checkId: string) {
  const check = checks.find((entry) => getString(entry, ['check_id'], '') === checkId);
  return getString(check ?? {}, ['name', 'title'], checkId);
}

function runDisplayLabel(runs: DataItem[], runId: string) {
  const run = runs.find((entry) => getString(entry, ['id'], '') === runId);
  if (!run) return runId;
  const checkId = getString(run, ['check_id'], '');
  const when = formatDate(run.started_at ?? run.created_at);
  return checkId ? `${checkId} · ${when}` : when || runId;
}

function targetDisplayLabel(targets: DataItem[], targetId: string) {
  const target = targets.find((entry) => getString(entry, ['id'], '') === targetId);
  return getString(target ?? {}, ['value', 'hostname', 'label'], targetId);
}

const STAFF_ENTITLEMENT_LABELS: Record<string, string> = {
  waf_posture: 'WAF posture',
  external_discovery: 'External discovery',
  connectors: 'Connectors',
  high_scale_program: 'High-scale program'
};

const SUPPLY_CHAIN_EXPOSURE_TYPES = [
  { id: 'dangling_cname', label: 'Dangling CNAME' },
  { id: 'subdomain_takeover', label: 'Subdomain takeover risk' },
  { id: 'orphan_record', label: 'Orphan DNS record' },
  { id: 'customer_declared', label: 'Customer-declared exposure' }
] as const;

const SUPPLY_CHAIN_PHASE_LABELS: Record<string, { label: string; description: string }> = {
  AP2_manual_custody: { label: 'Manual custody (AP2)', description: 'Customer retains manual custody before governed activation.' },
  AP3_governed_active: { label: 'Governed active (AP3)', description: 'Governed active protection with signed authorization.' }
};

function discoveryEyebrow(state: string) {
  const normalized = state.toLowerCase();
  if (['approved', 'approved_target', 'imported', 'entity'].includes(normalized)) return 'Discovery entity';
  if (normalized === 'rejected') return 'Rejected candidate';
  return 'Discovery candidate';
}

function formatConfidencePercent(entity: DataItem) {
  const raw = entity.confidence ?? entity.confidence_score;
  if (typeof raw === 'number' && Number.isFinite(raw)) {
    const pct = raw <= 1 ? Math.round(raw * 100) : Math.round(raw);
    return `${pct}%`;
  }
  const text = getString(entity, ['confidence', 'confidence_score'], '');
  return text || '—';
}

async function sha256HexBrowser(input: string) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

/** Trigger a client-side download of a JSON payload (evidence artifact export with custody manifest). */
function triggerJsonDownload(filename: string, payload: unknown) {
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

/** Human-readable byte size for evidence artifact KPIs; returns '' when size is unknown so callers can omit gracefully. */
function formatEvidenceSize(entity: DataItem): string {
  const raw = getNestedNumber(entity, ['size_bytes'], NaN);
  const bytes = Number.isFinite(raw) ? raw : getNestedNumber(entity, ['metadata', 'size_bytes'], NaN);
  if (!Number.isFinite(bytes) || bytes < 0) return '';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/** Build a `key: value` code block, omitting rows whose value is absent so no fake data is rendered. */
function evidenceCodeBlock(rows: Array<[string, string]>): string {
  return rows
    .filter(([, value]) => value && value !== '—')
    .map(([key, value]) => `${key}: ${value}`)
    .join('\n');
}

type AuthorizationArtifactDraft = {
  filename: string;
  content_sha256: string;
  custody_id: string;
};

function buildEvidenceBackedFactors(
  route: RouteId,
  entity: DataItem,
  extras: { cveMatches: DataItem[] }
): FactorEntry[] {
  if (route === 'run-detail') {
    const placementScore = getNestedNumber(entity, ['verdict', 'placement_confidence', 'score'], NaN);
    const verdict = getNestedString(entity, ['verdict', 'verdict'], getString(entity, ['status'], 'pending'));
    const factors: FactorEntry[] = [];
    if (Number.isFinite(placementScore)) {
      factors.push({
        label: 'Placement confidence',
        body: getNestedString(entity, ['verdict', 'placement_confidence', 'level'], 'Recorded from verdict evidence.'),
        value: Math.round(placementScore)
      });
    }
    if (verdict !== 'pending') {
      factors.push({
        label: 'Verdict outcome',
        body: getNestedString(entity, ['verdict', 'explanation'], getNestedString(entity, ['verdict', 'conclusion'], 'Final verdict recorded for this test run.')),
        value: verdict === 'pass' ? 100 : verdict === 'fail' ? 65 : 50
      });
    }
    return factors;
  }

  return [];
}

function FactorPanel({
  factors,
  emptyTitle = 'No evidence factors yet.',
  emptyBody = 'Factors appear after the backend returns entity-specific readiness or posture signals.'
}: {
  factors: FactorEntry[];
  emptyTitle?: string;
  emptyBody?: string;
}) {
  if (factors.length === 0) {
    return (
      <EmptyState
        icon={FileCheck2}
        title={emptyTitle}
        body={emptyBody}
      />
    );
  }
  return (
    <div className="factor-list">
      {factors.map((factor) => (
        <div className="factor" key={factor.label}>
          <div>
            <strong>{factor.label}</strong>
            <span>{factor.body}</span>
          </div>
          <Badge tone={scoreTone(factor.value)}>{factor.value}%</Badge>
          <Progress value={factor.value} tone={scoreTone(factor.value)} label={factor.label ?? 'Readiness factor'} />
        </div>
      ))}
    </div>
  );
}

function TimelinePanel({ items }: { items: Array<{ label: string; at?: unknown }> }) {
  if (items.length === 0) {
    return <p className="muted">No timeline milestones recorded for this entity.</p>;
  }
  return (
    <div className="timeline-list">
      {items.map((item, index) => (
        <div key={`${item.label}-${index}`}>
          <span aria-hidden="true" />
          <div>
            <strong>{item.label}</strong>
            <p>{formatDate(item.at)}</p>
          </div>
        </div>
      ))}
    </div>
  );
}

const DETAIL_GROUP_LABELS: Record<string, string> = {
  scope: 'Scope',
  validation: 'Validation',
  posture: 'Posture',
  governance: 'Governance',
  staff: 'Staff'
};

type StatusBadgeTone = NonNullable<BadgeProps['tone']>;

const DETAIL_SKELETON_KV_ROWS = 6;
const DETAIL_SKELETON_TAB_COUNT = 4;

function normalizeStatusKey(value: string) {
  return value.trim().toLowerCase().replace(/\s+/g, '_');
}

function formatStatusLabel(value: string, fallback = '—') {
  const trimmed = value.trim();
  if (!trimmed) return fallback;
  const label = trimmed.replace(/_/g, ' ');
  return label.charAt(0).toUpperCase() + label.slice(1);
}

function runStatusBadgeTone(status: string): StatusBadgeTone {
  const key = normalizeStatusKey(status);
  if (['completed', 'finalized', 'succeeded', 'pass'].includes(key)) return 'success';
  if (['running', 'collecting', 'planned', 'pending', 'queued'].includes(key)) return 'info';
  if (['failed', 'cancelled', 'canceled', 'error'].includes(key)) return 'danger';
  if (['stopped', 'stopping'].includes(key)) return 'warn';
  return 'muted';
}

function verdictBadgeTone(verdict: string): StatusBadgeTone {
  const key = normalizeStatusKey(verdict);
  if (key === 'pass') return 'success';
  if (key === 'fail') return 'danger';
  if (key === 'inconclusive') return 'warn';
  return 'info';
}

function findingSeverityBadgeTone(severity: string): StatusBadgeTone {
  const key = normalizeStatusKey(severity);
  if (['critical', 'high'].includes(key)) return 'danger';
  if (['medium', 'moderate'].includes(key)) return 'warn';
  if (['low', 'info'].includes(key)) return 'info';
  return 'muted';
}

function findingStatusBadgeTone(status: string): StatusBadgeTone {
  const key = normalizeStatusKey(status);
  if (key === 'closed') return 'success';
  if (key === 'accepted_risk') return 'muted';
  if (key === 'open') return 'warn';
  return 'info';
}

function agentStatusBadgeTone(status: string): StatusBadgeTone {
  const key = normalizeStatusKey(status);
  if (key === 'active' || key === 'online') return 'success';
  if (key === 'revoked' || key === 'disabled') return 'danger';
  if (key === 'degraded' || key === 'stale') return 'warn';
  return 'muted';
}

function placementStatusBadgeTone(status: string): StatusBadgeTone {
  if (status === 'proven') return 'success';
  if (status === 'needs_baseline') return 'warn';
  if (status === 'missing_agent' || status === 'misplaced_risk') return 'danger';
  return 'muted';
}

function discoveryEntityStateBadgeTone(state: string): StatusBadgeTone {
  const key = normalizeStatusKey(state);
  if (['approved', 'active', 'entity', 'imported'].includes(key)) return 'success';
  if (key === 'rejected') return 'danger';
  return 'warn';
}

function signupRequestStateTone(state: string): StatusBadgeTone {
  const key = normalizeStatusKey(state);
  if (['approved', 'provisioned', 'active'].includes(key)) return 'success';
  if (['rejected', 'denied', 'cancelled', 'canceled'].includes(key)) return 'danger';
  if (['under_review', 'reviewing', 'in_review'].includes(key)) return 'warn';
  if (['submitted', 'pending', 'recorded'].includes(key)) return 'info';
  return 'muted';
}

function supplyChainExposureLabel(type: string) {
  const match = SUPPLY_CHAIN_EXPOSURE_TYPES.find((entry) => entry.id === type);
  return match?.label ?? formatStatusLabel(type);
}

function highScaleStateBadgeTone(state: string): StatusBadgeTone {
  const key = normalizeStatusKey(state);
  if (['closed', 'completed'].includes(key)) return 'success';
  if (['running', 'scheduled', 'approved'].includes(key)) return 'info';
  if (['stopped', 'under_review', 'submitted'].includes(key)) return 'warn';
  if (['rejected', 'failed'].includes(key)) return 'danger';
  return 'muted';
}

function artifactReviewBadgeTone(status: string): StatusBadgeTone {
  const key = normalizeStatusKey(status);
  if (key === 'accepted') return 'success';
  if (key === 'rejected') return 'danger';
  if (key === 'pending_review' || key === 'pending') return 'warn';
  return 'info';
}

function reportStatusBadgeTone(status: string): StatusBadgeTone {
  const key = normalizeStatusKey(status);
  if (['ready', 'published', 'complete', 'completed'].includes(key)) return 'success';
  if (['generating', 'pending', 'draft'].includes(key)) return 'info';
  if (['failed', 'error'].includes(key)) return 'danger';
  return 'muted';
}

function cveStageBadgeTone(stage: string): StatusBadgeTone {
  const key = normalizeStatusKey(stage);
  if (['validated', 'mitigated', 'closed'].includes(key)) return 'success';
  if (['triage', 'ingest'].includes(key)) return 'info';
  if (['exposed', 'active'].includes(key)) return 'danger';
  return 'warn';
}

function supplyChainStateBadgeTone(state: string): StatusBadgeTone {
  const key = normalizeStatusKey(state);
  if (key === 'confirmed') return 'danger';
  if (key === 'suspected') return 'warn';
  if (key === 'mitigated' || key === 'resolved') return 'success';
  return 'muted';
}

function subscriptionStatusBadgeTone(status: string): StatusBadgeTone {
  const key = normalizeStatusKey(status);
  if (['active', 'trialing'].includes(key)) return 'success';
  if (['past_due', 'paused'].includes(key)) return 'warn';
  if (['canceled', 'cancelled', 'suspended'].includes(key)) return 'danger';
  return 'info';
}

function lifecycleBadgeTone(state: string): StatusBadgeTone {
  const key = normalizeStatusKey(state);
  if (key === 'active') return 'success';
  if (key === 'suspended') return 'danger';
  if (key === 'pending') return 'warn';
  return 'muted';
}

function StatusBadge({ value, tone, fallback = '—' }: { value: string; tone: StatusBadgeTone; fallback?: string }) {
  const label = formatStatusLabel(value, fallback);
  return <Badge tone={tone}>{label}</Badge>;
}

function DetailPageIntro({ route, eyebrow }: { route: RouteId; eyebrow?: string }) {
  const item = ROUTE_BY_ID.get(route);
  const description = item?.description?.trim();
  return (
    <>
      <p className="eyebrow">{eyebrow ?? item?.group}</p>
      {description ? <p className="muted small">{description}</p> : null}
    </>
  );
}

function DetailKvSkeletonRows({ rows = DETAIL_SKELETON_KV_ROWS }: { rows?: number }) {
  return (
    <>
      {Array.from({ length: rows }, (_, index) => (
        <div key={index}>
          <span className="skeleton skeleton-text" />
          <strong className="skeleton skeleton-text" />
        </div>
      ))}
    </>
  );
}

const DETAIL_LIST_LINKS: Partial<Record<RouteId, { label: string; href: string }>> = {
  'run-detail': { label: 'Test runs', href: '#runs' },
  'agent-detail': { label: 'Agents', href: '#agents' },
  'target-group-detail': { label: 'Target groups', href: '#target-groups' },
  'target-detail': { label: 'Target groups', href: '#target-groups' },
  'report-detail': { label: 'Reports', href: '#reports' },
  'tenant-detail': { label: 'Admin console', href: '#admin' },
  'finding-detail': { label: 'Findings', href: '#findings' },
  'evidence-detail': { label: 'Evidence vault', href: '#evidence' },
  'queue-detail': { label: 'SOC console', href: '#internal-soc' }
};

const DETAIL_LINK_ROUTES: RouteId[] = [
  'run-detail',
  'agent-detail',
  'target-group-detail',
  'target-detail',
  'tenant-detail',
  'report-detail',
  'finding-detail',
  'evidence-detail',
  'queue-detail'
];

function detailEntityTitle(route: RouteId, entity: DataItem, entityId: string, context?: { checks?: DataItem[] }) {
  if (route === 'run-detail') {
    const checkId = getString(entity, ['check_id'], '');
    return checkId && context?.checks ? checkDisplayName(context.checks, checkId) : getString(entity, ['check_id'], entityId);
  }
  if (route === 'finding-detail') return getString(entity, ['title', 'label', 'kind', 'id'], entityId);
  if (route === 'queue-detail') {
    return getString(entity, ['objective', 'reason', 'id'], entityId);
  }
  if (route === 'target-detail') return getString(entity, ['value', 'id'], entityId);
  if (route === 'agent-detail') return getString(entity, ['hostname', 'name'], entityId);
  if (route === 'target-group-detail') return getString(entity, ['name'], entityId);
  if (route === 'report-detail') return getString(entity, ['title'], entityId);
  if (route === 'tenant-detail') {
    const tenant = getNestedItem(entity, ['tenant']) ?? entity;
    return getString(tenant, ['name'], entityId);
  }
  return getString(entity, ['name', 'hostname', 'canonical_url', 'cve_id', 'organization_name', 'id'], entityId);
}

function DetailBreadcrumb({ route, title, entityId }: { route: RouteId; title: string; entityId?: string }) {
  const routeMeta = ROUTE_BY_ID.get(route);
  const listLink = DETAIL_LIST_LINKS[route];
  const listHref = listLink?.href;
  const groupLabel = routeMeta?.group ? (DETAIL_GROUP_LABELS[routeMeta.group] ?? routeMeta.group) : 'Detail';
  const listLabel = listLink?.label ?? routeMeta?.label ?? 'List';
  return (
    <p className="muted stack-tight">
      {listLink && listHref ? (
        <AnchorButton size="sm" variant="ghost" href={listHref}>← Back to {listLink.label}</AnchorButton>
      ) : null}
      {groupLabel} › {listLabel} › {title}
    </p>
  );
}

function DetailEntityHeading({
  route,
  entityId,
  title,
  eyebrow
}: {
  route: RouteId;
  entityId: string;
  title: string;
  eyebrow?: string;
}) {
  return (
    <>
      {eyebrow ? <p className="eyebrow">{eyebrow}</p> : null}
      <DetailBreadcrumb route={route} title={title} entityId={entityId} />
      <h1>{title}</h1>
      {title !== entityId ? <p className="muted"><code>{entityId}</code></p> : null}
    </>
  );
}

function DetailPageHeader({
  route,
  eyebrow,
  entityId,
  title,
  actions
}: {
  route: RouteId;
  eyebrow?: string;
  entityId: string;
  title: string;
  actions?: ReactNode;
}) {
  return (
    <div className="page-head">
      <div>
        <DetailEntityHeading route={route} entityId={entityId} title={title} eyebrow={eyebrow} />
      </div>
      {actions ? <div className="row-actions">{actions}</div> : null}
    </div>
  );
}

function DetailLoadingPlaceholder({
  label = 'Loading…',
  variant = 'page'
}: {
  label?: string;
  variant?: 'page' | 'compact' | 'layout';
}) {
  if (variant === 'compact') {
    return (
      <div className="kv-list" aria-busy="true" aria-label={label}>
        <DetailKvSkeletonRows rows={3} />
      </div>
    );
  }
  if (variant === 'layout') {
    return (
      <div className="detail-layout" aria-busy="true" aria-label={label}>
        <Card density="compact">
          <CardHeader>
            <span className="skeleton skeleton-text" aria-hidden="true" />
            <span className="skeleton skeleton-text" aria-hidden="true" />
          </CardHeader>
          <CardContent className="kv-list">
            <DetailKvSkeletonRows rows={4} />
          </CardContent>
        </Card>
        <Card density="compact" className="detail-primary">
          <CardHeader>
            <span className="skeleton skeleton-text" aria-hidden="true" />
            <span className="skeleton skeleton-text" aria-hidden="true" />
          </CardHeader>
          <CardContent className="kv-list">
            <DetailKvSkeletonRows rows={4} />
          </CardContent>
        </Card>
      </div>
    );
  }
  return (
    <div className="stack-tight" aria-busy="true" aria-label={label}>
      <div className="row-actions" aria-hidden="true">
        {Array.from({ length: DETAIL_SKELETON_TAB_COUNT }, (_, index) => (
          <span key={index} className="skeleton skeleton-row" />
        ))}
      </div>
      <Card density="compact">
        <CardHeader>
          <span className="skeleton skeleton-text" aria-hidden="true" />
          <span className="skeleton skeleton-text" aria-hidden="true" />
        </CardHeader>
        <CardContent className="kv-list">
          <DetailKvSkeletonRows />
        </CardContent>
      </Card>
    </div>
  );
}

function DetailEntityLink({
  route,
  id,
  label
}: {
  route: RouteId;
  id: string;
  label?: string;
}) {
  const resolved = (label ?? id).trim();
  if (!id || id === '—') return <strong>—</strong>;
  if (!DETAIL_LINK_ROUTES.includes(route)) return <strong>{resolved}</strong>;
  return (
    <AnchorButton size="sm" variant="ghost" href={buildDetailHref(route, id)}>
      {resolved}
    </AnchorButton>
  );
}

function DetailKvField({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <span>{label}</span>
      <strong>{children}</strong>
    </div>
  );
}

function DetailKvHintField({ label, value, hint }: { label: string; value: ReactNode; hint: string }) {
  return (
    <div className="kv-stack">
      <span>{label}</span>
      <div className="stack-tight">
        <strong>{value}</strong>
        <p className="muted small">{hint}</p>
      </div>
    </div>
  );
}

function DetailKvMonoField({ label, value, compact }: { label: string; value: string; compact?: boolean }) {
  return (
    <div className="kv-stack kv-mono-field">
      <span>{label}</span>
      <code className={compact ? 'mono-hash small' : 'mono-hash'} title={value}>{value}</code>
    </div>
  );
}

function DetailCodeBlock({ label, children }: { label: string; children: string }) {
  return (
    <pre className="codeblock" aria-label={label}>
      {children}
    </pre>
  );
}

function DetailStatusBanners({
  loadError,
  error,
  message,
  successTone = 'default',
  mode = 'split',
  hideMessageWhenLoadError = true,
  children
}: {
  loadError?: string;
  error?: string;
  message?: string;
  successTone?: 'default' | 'neutral';
  mode?: 'split' | 'combined';
  hideMessageWhenLoadError?: boolean;
  children?: ReactNode;
}) {
  const successClass = successTone === 'neutral' ? 'form-banner neutral' : 'form-banner';
  if (mode === 'combined') {
    const text = error || loadError || message;
    if (!text && !children) return null;
    const isError = Boolean(error || loadError);
    return (
      <div className={isError ? 'form-banner error' : successClass} role={isError ? 'alert' : 'status'}>
        {text}
        {children}
      </div>
    );
  }
  const showActionBanner = Boolean(message || error) && !(hideMessageWhenLoadError && loadError);
  return (
    <>
      {loadError ? (
        <div className="form-banner error" role="alert">
          {loadError}
        </div>
      ) : null}
      {showActionBanner ? (
        <div className={error ? 'form-banner error' : successClass} role={error ? 'alert' : 'status'}>
          {error || message}
          {children}
        </div>
      ) : null}
    </>
  );
}

function AgentProbeEndpointKvSection({
  hasDetails,
  status,
  error,
  fqdn,
  ip
}: {
  hasDetails: boolean;
  status: string;
  error: string;
  fqdn: string;
  ip: string;
}) {
  if (!hasDetails) return null;
  return (
    <>
      <div>
        <span>Probe endpoint status</span>
        {status ? (
          <Badge tone={probeEndpointStatusBadgeTone(status)}>{formatFactorLabel(status)}</Badge>
        ) : (
          <strong>—</strong>
        )}
      </div>
      {error ? (
        <DetailKvMonoField label="Probe endpoint error" value={error} />
      ) : null}
      {fqdn && fqdn !== '—' ? (
        <DetailKvMonoField label="Declared FQDN" value={fqdn} />
      ) : null}
      {ip && ip !== '—' ? (
        <DetailKvMonoField label="Declared IP" value={ip} />
      ) : null}
    </>
  );
}

function useEntityDetail<T extends DataItem>(
  enabled: boolean,
  config: PortalConfig,
  session: Session,
  path: string,
  fallback: T | null
) {
  const [detail, setDetail] = useState<T | null>(fallback);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(enabled && Boolean(path));

  useEffect(() => {
    if (!enabled || !path) {
      setDetail(fallback);
      setLoading(false);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError('');
    requestJson(config, session, path)
      .then((payload) => {
        if (!cancelled) setDetail(payload as T);
      })
      .catch((err) => {
        if (!cancelled) {
          setDetail(fallback);
          setError(err instanceof Error ? err.message : 'Could not load entity detail.');
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [config, session, path, enabled, fallback]);

  return { detail, error, loading };
}

function useListBackedDetail<T extends DataItem>(
  enabled: boolean,
  config: PortalConfig,
  session: Session,
  listPath: string,
  entityId: string,
  fallback: T | null
) {
  const [detail, setDetail] = useState<T | null>(fallback);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(enabled && Boolean(entityId));

  useEffect(() => {
    if (!enabled || !entityId) {
      setDetail(fallback);
      setLoading(false);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError('');
    requestJson(config, session, listPath)
      .then((payload) => {
        if (cancelled) return;
        const items = Array.isArray((payload as { items?: unknown }).items)
          ? (payload as { items: T[] }).items
          : [];
        const match = items.find((item) => getString(item, ['id'], '') === entityId) ?? null;
        setDetail(match ?? fallback);
        if (!match && !fallback) {
          setError('Entity not found in your workspace lists.');
        }
      })
      .catch((err) => {
        if (!cancelled) {
          setDetail(fallback);
          setError(err instanceof Error ? err.message : 'Could not load entity detail.');
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [config, session, listPath, enabled, entityId, fallback]);

  return { detail, error, loading };
}

function formatRunDuration(entity: DataItem) {
  const start = entity.started_at ?? entity.created_at;
  const end = getNestedString(entity, ['verdict', 'finalized_at'], '') || entity.completed_at || entity.updated_at;
  if (!start || !end) return '—';
  const ms = new Date(String(end)).getTime() - new Date(String(start)).getTime();
  if (!Number.isFinite(ms) || ms < 0) return '—';
  const totalSeconds = Math.round(ms / 1000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return minutes > 0 ? `${minutes}m ${seconds}s` : `${seconds}s`;
}

function RunDetailView({
  entity,
  entityId,
  data,
  config,
  session,
  onRefresh,
  runEvents,
  loading,
  loadError
}: {
  entity: DataItem;
  entityId: string;
  data: PortalData;
  config: PortalConfig;
  session: Session;
  onRefresh: () => Promise<void>;
  runEvents: DataItem[];
  loading: boolean;
  loadError: string;
}) {
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const verdict = entity.verdict as DataItem | undefined;
  const probeEvents = runEvents.filter((event) => getString(event, ['signal_type']) === 'probe_result');
  const agentEvents = runEvents.filter((event) => ['agent_observation', 'agent_no_observation'].includes(getString(event, ['signal_type'])));
  const relatedEvidence = data.evidence.filter((item) => getString(item, ['test_run_id'], '') === entityId);
  const relatedFindings = data.findings.filter((finding) => getString(finding, ['test_run_id'], '') === entityId);
  const status = getString(entity, ['status'], '');
  const cancellable = ['planned', 'running', 'collecting'].includes(status);

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

  async function cancelRun() {
    if (!window.confirm('Cancel this run in progress?')) return;
    await runAction(`cancel-${entityId}`, () => requestJson(config, session, `/v1/test-runs/${entityId}/cancel`, { method: 'POST' }), 'Run cancelled.');
  }

  async function finalizeRun() {
    if (!window.confirm('Force finalize this run now? This locks the verdict.')) return;
    await runAction(`finalize-${entityId}`, () => requestJson(config, session, `/v1/test-runs/${entityId}/finalize`, { method: 'POST' }), 'Run finalized after observation window.');
  }

  const milestoneTimeline = [
    { label: 'Run created', at: entity.created_at },
    { label: 'Run started', at: entity.started_at },
    { label: 'Probe window', at: entity.probe_started_at ?? entity.updated_at },
    { label: 'Verdict recorded', at: getNestedString(entity, ['verdict', 'finalized_at'], '') || entity.completed_at }
  ].filter((item) => item.at);

  const runTitle = detailEntityTitle('run-detail', entity, entityId, { checks: data.checks });
  const groupId = getString(entity, ['target_group_id'], '');
  const groupName = groupId
    ? getString(data.targetGroups.find((group) => getString(group, ['id'], '') === groupId) ?? {}, ['name'], groupId)
    : '—';
  const verdictValue = getNestedString(entity, ['verdict', 'verdict'], 'pending');
  const primaryFinding = relatedFindings[0] ?? null;
  const runPolicyId = getString(entity, ['policy_id', 'test_policy_id'], '');
  const correlatingAgentId = getString(agentEvents[0] ?? {}, ['agent_id'], '');
  const rawEventColumns: TableColumn<DataItem>[] = [
    { key: 'signal', label: 'Signal', render: (event) => humanizeSignalType(getString(event, ['signal_type'], 'event')) },
    { key: 'source', label: 'Source', render: (event) => getString(event, ['source'], '—') },
    { key: 'reference', label: 'Reference', render: (event) => <span className="mono small">{getString(event, ['check_id', 'agent_id', 'target_id'], '—')}</span> },
    { key: 'recorded', label: 'Recorded', render: (event) => formatDate(event.timestamp ?? event.created_at) },
    { key: 'event_id', label: 'Event id', render: (event) => <span className="mono small">{getString(event, ['id'], '—')}</span> }
  ];

  return (
    <div className="content">
      <DetailPageHeader
        route="run-detail"
        eyebrow="Test run evidence"
        entityId={entityId}
        title={runTitle}
        actions={(
          <>
            <AnchorButton size="sm" variant="secondary" href="#runs">Test runs</AnchorButton>
            {primaryFinding ? (
              <AnchorButton size="sm" variant="default" href={buildDetailHref('finding-detail', getString(primaryFinding, ['id'], ''))}>Open finding</AnchorButton>
            ) : null}
            {cancellable ? (
              <>
                <Button size="sm" variant="danger" loading={busy === `cancel-${entityId}`} disabled={busy !== ''} onClick={() => void cancelRun()}>Cancel</Button>
                <Button size="sm" variant="ghost" loading={busy === `finalize-${entityId}`} disabled={busy !== ''} onClick={() => void finalizeRun()}>Finalize</Button>
              </>
            ) : null}
          </>
        )}
      />
      {loading ? <DetailLoadingPlaceholder label="Loading run detail…" /> : null}
      <DetailStatusBanners loadError={loadError} error={error} message={message} successTone="neutral" />
      {!loading ? (
      <>
      <div className="metric-grid four">
        <MetricCard label="Target group" value={groupName} sub="Declared scope under test" icon={Target} tone="info" />
        <MetricCard label="Check" value={checkDisplayName(data.checks, getString(entity, ['check_id'], ''))} sub={getString(entity, ['vector_family'], 'safe check')} icon={FileCheck2} tone="muted" />
        <MetricCard label="Verdict" value={formatStatusLabel(verdictValue, 'pending')} sub={`placement ${getNestedString(verdict ?? {}, ['placement_confidence', 'level'], 'unknown')}`} icon={ShieldCheck} tone={verdictBadgeTone(verdictValue)} />
        <MetricCard label="Duration" value={formatRunDuration(entity)} sub={formatStatusLabel(status, 'pending')} icon={Activity} tone="muted" />
      </div>
      <div className="dash-grid">
        <Card>
          <CardHeader>
            <CardTitle>Timeline</CardTitle>
            <CardDescription>
              Ordered run lifecycle from scheduling through final verdict{runPolicyId ? <> · policy <code>{runPolicyId}</code></> : null}{correlatingAgentId ? <> · agent <code>{correlatingAgentId}</code></> : null}.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <TimelinePanel items={milestoneTimeline} />
            <RunTimelineViz events={runEvents} />
          </CardContent>
        </Card>
        <div className="stack-tight">
          <Card>
            <CardHeader>
              <CardTitle>Probe result</CardTitle>
              <CardDescription>Outside observations from bounded probes.</CardDescription>
            </CardHeader>
            <CardContent>
              {probeEvents.length === 0 ? (
                <EmptyState icon={Activity} title="No probe results yet." body="Outside probe observations appear after the probe window runs." />
              ) : (
                <CapabilityProbeResultsPanel events={probeEvents} />
              )}
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Agent observation</CardTitle>
              <CardDescription>Inside observations from outbound-only canaries.</CardDescription>
            </CardHeader>
            <CardContent>
              {agentEvents.length === 0 ? (
                <EmptyState icon={Bot} title="No agent observations yet." body="Outbound canary observations appear when agents report on this run." />
              ) : (
                <div className="kv-list">
                  {agentEvents.map((event, index) => (
                    <div key={getString(event, ['id'], String(index))}>
                      <span>{humanizeSignalType(getString(event, ['signal_type']))}</span>
                      <strong>
                        <DetailEntityLink route="agent-detail" id={getString(event, ['agent_id'], '')} label={getString(event, ['agent_id'], getString(event, ['source'], 'agent'))} />
                        {' · '}{formatDate(event.timestamp ?? event.created_at)}
                      </strong>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Correlation matrix</CardTitle>
          <CardDescription>Verdict = probe ∧ agent. Truth table and verdict explanation from observed facts.</CardDescription>
        </CardHeader>
        <CardContent>
          <VerdictExplanationPanel detail={entity} events={runEvents} />
          <TruthTablePanel detail={entity} />
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Evidence chain</CardTitle>
          <CardDescription>Custody-ready artifacts generated by this run.</CardDescription>
        </CardHeader>
        <CardContent>
          {relatedEvidence.length === 0 ? (
            <EmptyState icon={FileCheck2} title="No linked evidence yet." body="Custody records are generated when this run publishes verdict evidence." actionLabel="Open evidence vault" actionHref="#evidence" />
          ) : (
            <>
              <div className="kv-list">
                {relatedEvidence.map((item) => {
                  const evidenceId = getString(item, ['id'], '');
                  const evidenceLabel = getString(item, ['label', 'kind', 'signal_type'], 'evidence');
                  const digest = getString(item, ['content_sha256', 'custody_digest'], '');
                  return (
                    <div key={evidenceId}>
                      <span>{evidenceLabel}</span>
                      <strong>
                        <DetailEntityLink route="evidence-detail" id={evidenceId} label={evidenceLabel} />
                        {digest && digest !== '—' ? <span className="muted small"> · <code>{digest.slice(0, 16)}</code></span> : null}
                      </strong>
                    </div>
                  );
                })}
              </div>
              {relatedFindings.length > 0 ? (
                <div className="row-actions">
                  <AnchorButton size="sm" variant="ghost" href="#findings">Open findings</AnchorButton>
                </div>
              ) : null}
            </>
          )}
        </CardContent>
      </Card>
      {runEvents.length > 0 ? (
        <Card>
          <CardHeader>
            <CardTitle>Raw events</CardTitle>
            <CardDescription>Read-only metadata-only signals ingested for this run — probe results and agent observations, newest as returned by the run event log.</CardDescription>
          </CardHeader>
          <CardContent>
            <DataTable
              columns={rawEventColumns}
              items={runEvents}
              empty={<span className="muted">No raw events recorded for this run.</span>}
            />
          </CardContent>
        </Card>
      ) : null}
      </>
      ) : null}
    </div>
  );
}

const STAFF_ENTITLEMENT_FEATURES = ['waf_posture', 'external_discovery', 'connectors', 'high_scale_program'] as const;

function TenantDetailView({
  entityId,
  detail,
  data,
  config,
  session,
  onRefresh,
  loading,
  loadError
}: {
  entityId: string;
  detail: DataItem | null;
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
  const [tab, setTab] = useState('overview');
  const [subscriptionSnapshot, setSubscriptionSnapshot] = useState<DataItem | null>(null);
  const [subscriptionError, setSubscriptionError] = useState('');
  const [localDetail, setLocalDetail] = useState<DataItem | null>(detail);
  const [entitlementFeature, setEntitlementFeature] = useState<string>(STAFF_ENTITLEMENT_FEATURES[0]);
  const [entitlementEnabled, setEntitlementEnabled] = useState('true');

  useEffect(() => {
    setLocalDetail(detail);
  }, [detail]);

  const resolvedDetail = localDetail;
  const tenant = getNestedItem(resolvedDetail, ['tenant']) ?? resolvedDetail;
  const account = getNestedItem(resolvedDetail, ['account']);
  const subscription = getNestedItem(resolvedDetail, ['subscription']) ?? subscriptionSnapshot;
  const users = getNestedArray(resolvedDetail, ['users']);
  const signupRequest = getNestedItem(resolvedDetail, ['signup_request']);
  const recentAudit = getNestedArray(resolvedDetail, ['recent_tenant_audit']);
  const relatedApprovals = data.internalApprovalRequests.filter(
    (item) => getString(item, ['tenant_id'], '') === entityId
  );
  const lifecycleState = getString(account, ['lifecycle_state'], 'active');
  // KPIs sourced from real records only: agents from the loaded tenant-scoped agent list, MRR from
  // the subscription/account billing payload when present (graceful — no fabricated dollar figure).
  const tenantAgents = data.agents.filter((item) => getString(item, ['tenant_id'], '') === entityId);
  const mrrValue = getString(subscription, ['mrr', 'monthly_recurring_revenue', 'amount'], '')
    || getString(account, ['mrr', 'monthly_recurring_revenue'], '');

  const effectiveEntitlements = getNestedItem(subscription, ['effective_entitlements'])
    ?? getNestedItem(subscriptionSnapshot, ['effective_entitlements']);

  useEffect(() => {
    if (!entityId || session.principal !== 'staff') {
      setSubscriptionSnapshot(null);
      setSubscriptionError('');
      return;
    }
    let cancelled = false;
    setSubscriptionError('');
    requestJson(config, session, `/internal/admin/tenants/${encodeURIComponent(entityId)}/subscription`)
      .then((payload) => {
        if (!cancelled) setSubscriptionSnapshot(payload as DataItem);
      })
      .catch((err) => {
        if (!cancelled) {
          setSubscriptionSnapshot(null);
          setSubscriptionError(err instanceof Error ? err.message : 'Could not load subscription entitlements.');
        }
      });
    return () => { cancelled = true; };
  }, [config, session, entityId, resolvedDetail]);

  async function reloadTenantDetail() {
    const [tenantPayload, subscriptionPayload] = await Promise.all([
      requestJson(config, session, `/internal/admin/tenants/${encodeURIComponent(entityId)}`),
      requestJson(config, session, `/internal/admin/tenants/${encodeURIComponent(entityId)}/subscription`).catch(() => null)
    ]);
    setLocalDetail(tenantPayload as DataItem);
    if (subscriptionPayload) setSubscriptionSnapshot(subscriptionPayload as DataItem);
  }

  async function runStaffAction<T>(label: string, action: () => Promise<T>, success: string) {
    setBusy(label);
    setError('');
    setMessage('');
    try {
      const result = await action();
      setMessage(success);
      await reloadTenantDetail();
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

  async function patchLifecycle(nextState: string) {
    const impact = nextState === 'suspended'
      ? 'Suspend this tenant? Users will lose access until it is reactivated.'
      : 'Activate this tenant? Users will regain access to this tenant.';
    if (!window.confirm(impact)) return;
    await runStaffAction(`lifecycle-${entityId}-${nextState}`, () => requestJson(config, session, `/internal/admin/tenants/${encodeURIComponent(entityId)}`, {
      method: 'PATCH',
      body: { lifecycle_state: nextState, reason: `Lifecycle set to ${nextState} from tenant detail.` }
    }), `Tenant lifecycle updated to ${nextState}.`);
  }

  async function patchSupportOwner(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const owner = String(new FormData(event.currentTarget).get('support_owner') ?? '').trim();
    if (!owner) return;
    await runStaffAction(`support-owner-${entityId}`, () => requestJson(config, session, `/internal/admin/tenants/${encodeURIComponent(entityId)}`, {
      method: 'PATCH',
      body: { support_owner: owner, reason: 'Support owner updated from tenant detail.' }
    }), 'Support owner updated.');
  }

  async function grantEntitlement(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const feature = String(form.get('feature') ?? '').trim();
    const enabled = String(form.get('enabled') ?? 'true') === 'true';
    const reason = String(form.get('reason') ?? '').trim();
    if (!feature) return;
    if (!window.confirm(`${enabled ? 'Grant' : 'Revoke'} entitlement "${feature}" for this tenant? This changes product access immediately.`)) return;
    await runStaffAction(`entitlement-${entityId}-${feature}`, () => requestJson(config, session, `/internal/admin/tenants/${encodeURIComponent(entityId)}/entitlements`, {
      method: 'POST',
      body: { feature, enabled, reason: reason || `Entitlement ${enabled ? 'granted' : 'revoked'} from tenant detail.` }
    }), `${feature} entitlement ${enabled ? 'granted' : 'revoked'}.`);
  }

  async function resendInvite(userId: string) {
    await runStaffAction(`resend-${entityId}-${userId}`, () => requestJson(config, session, `/internal/admin/tenants/${encodeURIComponent(entityId)}/users/${encodeURIComponent(userId)}/resend-invite`, {
      method: 'POST',
      body: {}
    }), 'Invite resend recorded.');
  }

  async function disableUser(userId: string) {
    if (!window.confirm('Disable this user? They will lose access to this tenant until re-enabled by staff.')) return;
    await runStaffAction(`disable-${entityId}-${userId}`, () => requestJson(config, session, `/internal/admin/tenants/${encodeURIComponent(entityId)}/users/${encodeURIComponent(userId)}/disable`, {
      method: 'POST',
      body: { reason: 'Disabled from tenant detail.' }
    }), 'User disabled.');
  }

  const userColumns: TableColumn<DataItem>[] = [
    { key: 'email', label: 'Email', render: (item) => getString(item, ['email']) },
    { key: 'role', label: 'Role', render: (item) => <Badge tone="info">{getString(item, ['role'])}</Badge> },
    { key: 'status', label: 'Status', render: (item) => <Badge tone={getString(item, ['status']) === 'active' ? 'success' : 'warn'}>{getString(item, ['status'])}</Badge> },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => {
        const userId = getString(item, ['id'], '');
        if (getString(item, ['status']) === 'disabled') return '—';
        return (
          <div className="row-actions">
            <Button size="sm" variant="ghost" disabled={busy !== ''} onClick={() => void resendInvite(userId)}>Resend invite</Button>
            <Button size="sm" variant="danger" disabled={busy !== ''} onClick={() => void disableUser(userId)}>Disable</Button>
          </div>
        );
      }
    }
  ];

  const approvalColumns: TableColumn<DataItem>[] = [
    { key: 'kind', label: 'Kind', render: (item) => getString(item, ['kind']) },
    { key: 'state', label: 'State', render: (item) => <Badge tone="warn">{getString(item, ['state'])}</Badge> },
    { key: 'created', label: 'Created', render: (item) => formatDate(item.created_at) }
  ];

  const auditColumns: TableColumn<DataItem>[] = [
    { key: 'action', label: 'Action', render: (item) => getString(item, ['action']) },
    { key: 'actor', label: 'Actor', render: (item) => getString(item, ['actor_user_id', 'staff_id'], '—') },
    { key: 'resource', label: 'Resource', render: (item) => `${getString(item, ['resource_type'])}:${getString(item, ['resource_id'], '—')}` },
    { key: 'created', label: 'Created', render: (item) => formatDate(item.created_at) }
  ];

  const tenantTitle = getString(tenant, ['name'], entityId);

  return (
    <div className="content">
      <DetailPageHeader
        route="tenant-detail"
        eyebrow="Staff tenant operations"
        entityId={entityId}
        title={tenantTitle}
        actions={(
          <>
            <AnchorButton size="sm" variant="secondary" href="#admin">Staff admin</AnchorButton>
            {lifecycleState !== 'active' ? (
              <Button size="sm" variant="secondary" disabled={busy !== ''} onClick={() => void patchLifecycle('active')}>Activate</Button>
            ) : (
              <Button size="sm" variant="danger" disabled={busy !== ''} onClick={() => void patchLifecycle('suspended')}>Suspend</Button>
            )}
          </>
        )}
      />
      <PageContextSummary>
        <StatusBadge value={lifecycleState} tone={lifecycleBadgeTone(lifecycleState)} /> · plan {getString(subscription, ['plan_id'], '—')} ·{' '}
        <span className="tabular-nums">{users.length}</span> users ·{' '}
        <span className="tabular-nums">{recentAudit.length}</span> recent audit events
      </PageContextSummary>
      {loading ? <DetailLoadingPlaceholder label="Loading tenant detail…" /> : null}
      <DetailStatusBanners loadError={loadError} error={error} message={message} mode="combined" />
      {!loading ? (
      <>
      <div className="metric-grid four">
        <MetricCard label="Lifecycle" value={formatStatusLabel(lifecycleState, 'active')} sub="Account state from staff administration" icon={ShieldCheck} tone={lifecycleState === 'active' ? 'success' : 'warn'} />
        <MetricCard label="Plan" value={getString(subscription, ['plan_id'], '—')} sub={formatStatusLabel(getString(subscription, ['status'], 'unknown'))} icon={FileText} tone="muted" />
        <MetricCard label="Region" value={getString(account, ['region'], '—')} sub="Data residency region" icon={Network} tone="info" />
        <MetricCard label="Agents" value={tenantAgents.length} sub="Outbound observers in workspace scope" icon={Bot} tone={tenantAgents.length > 0 ? 'success' : 'muted'} />
        <MetricCard label="Users" value={users.length} sub="Tenant-scoped identities" icon={Users} tone="info" />
        <MetricCard label="MRR" value={mrrValue || '—'} sub={mrrValue ? `plan ${getString(subscription, ['plan_id'], '—')}` : 'not reported in billing payload'} icon={FileText} tone="muted" />
        <MetricCard label="Approvals" value={relatedApprovals.length} sub="Internal requests for this tenant" icon={ClipboardList} tone={relatedApprovals.length > 0 ? 'warn' : 'muted'} />
        <MetricCard label="Audit events" value={recentAudit.length} sub="Recent tenant-scoped audit entries" icon={FileCheck2} tone="muted" />
      </div>
      <Tabs value={tab} options={[{ id: 'overview', label: 'Overview' }, { id: 'users', label: 'Users' }]} onChange={setTab} className="tabs-wrap" />
      {tab === 'overview' ? (
      <>
        <div className="split">
          <Card>
            <CardHeader>
              <CardTitle>Account status</CardTitle>
              <CardDescription>Lifecycle and subscription posture for this tenant.</CardDescription>
            </CardHeader>
            <CardContent className="kv-list">
              <div><span>Lifecycle</span><StatusBadge value={lifecycleState} tone={lifecycleBadgeTone(lifecycleState)} /></div>
              <div><span>Plan</span><strong>{getString(subscription, ['plan_id'], '—')}</strong></div>
              <div><span>Subscription status</span><StatusBadge value={getString(subscription, ['status'], '—')} tone={subscriptionStatusBadgeTone(getString(subscription, ['status'], ''))} /></div>
              <div><span>Users</span><strong>{users.length}</strong></div>
              <div><span>Name</span><strong>{getString(tenant, ['name'])}</strong></div>
              <div><span>Tenant ID</span><strong><code>{entityId}</code></strong></div>
              <div><span>Region</span><strong>{getString(account, ['region'], '—')}</strong></div>
              <div><span>Support owner</span><strong>{getString(account, ['support_owner'], 'unassigned')}</strong></div>
              <div><span>Created</span><strong>{formatDate(tenant?.created_at)}</strong></div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Subscription</CardTitle>
              <CardDescription>Plan and entitlement summary for this tenant.</CardDescription>
            </CardHeader>
            <CardContent className="kv-list">
              <div><span>Plan</span><strong>{getString(subscription, ['plan_id'], '—')}</strong></div>
              <div><span>Status</span><StatusBadge value={getString(subscription, ['status'], '—')} tone={subscriptionStatusBadgeTone(getString(subscription, ['status'], ''))} /></div>
              <div><span>Effective from</span><strong>{formatDate(subscription?.effective_from ?? subscription?.created_at)}</strong></div>
              {effectiveEntitlements ? STAFF_ENTITLEMENT_FEATURES.map((feature) => (
                <div key={feature}>
                  <span>{STAFF_ENTITLEMENT_LABELS[feature] ?? feature}</span>
                  <strong>{effectiveEntitlements[feature] === true ? 'enabled' : 'disabled'}</strong>
                </div>
              )) : <p className="muted">Subscription entitlements appear when the subscription record is available.</p>}
            </CardContent>
          </Card>
        </div>
        <Card>
          <CardHeader>
            <CardTitle>Provisioning signup</CardTitle>
            <CardDescription>Signup request that created this tenant, if recorded.</CardDescription>
          </CardHeader>
          <CardContent>
            {signupRequest ? (
              <div className="kv-list">
                <div><span>Request ID</span><strong><code>{getString(signupRequest, ['id'])}</code></strong></div>
                <div><span>State</span><StatusBadge value={getString(signupRequest, ['state'])} tone={signupRequestStateTone(getString(signupRequest, ['state']))} fallback="recorded" /></div>
              </div>
            ) : (
              <EmptyState icon={ClipboardList} title="No linked signup request." body="Tenants provisioned outside the signup queue may not have a signup_request reference." actionLabel="Open staff admin" actionHref="#admin" />
            )}
          </CardContent>
        </Card>
          <Card>
            <CardHeader>
              <CardTitle>Support owner</CardTitle>
              <CardDescription>Assign the customer support owner for this tenant.</CardDescription>
            </CardHeader>
            <CardContent>
              <form className="product-form" onSubmit={patchSupportOwner}>
                <label className="full"><span>Support owner</span><input name="support_owner" defaultValue={getString(account, ['support_owner'], '')} placeholder="owner@customer.example" required /></label>
                <div className="form-actions full"><Button type="submit" loading={busy === `support-owner-${entityId}`} disabled={busy !== ''}>Save support owner</Button></div>
              </form>
            </CardContent>
          </Card>
        <Card>
          <CardHeader>
            <CardTitle>Entitlement grants</CardTitle>
            <CardDescription>Grant or revoke product features for this tenant.</CardDescription>
          </CardHeader>
          <CardContent>
            {subscriptionError ? <div className="form-banner error">{subscriptionError}</div> : null}
            <form className="product-form" onSubmit={grantEntitlement}>
              <Select
                label="Feature"
                name="feature"
                value={entitlementFeature}
                onChange={setEntitlementFeature}
                options={STAFF_ENTITLEMENT_FEATURES.map((feature) => ({
                  value: feature,
                  label: STAFF_ENTITLEMENT_LABELS[feature] ?? feature
                }))}
              />
              <Select
                label="Action"
                name="enabled"
                value={entitlementEnabled}
                onChange={setEntitlementEnabled}
                options={[
                  { value: 'true', label: 'Grant / enable' },
                  { value: 'false', label: 'Revoke / disable' }
                ]}
              />
              <label className="full"><span>Reason</span><input name="reason" placeholder="Verified plan exception" required /></label>
              <div className="form-actions full"><Button type="submit" disabled={busy !== ''}>Apply entitlement</Button></div>
            </form>
          </CardContent>
        </Card>
        <div className="split">
        <Card>
          <CardHeader>
            <CardTitle>Approval requests</CardTitle>
            <CardDescription>Internal approvals scoped to this tenant.</CardDescription>
          </CardHeader>
          <CardContent>
            <DataTable columns={approvalColumns} items={relatedApprovals} empty={<EmptyState icon={ShieldCheck} title="No approval requests." body="Pending internal approvals for this tenant will appear here." actionLabel="Open staff admin" actionHref="#admin" />} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Internal audit</CardTitle>
            <CardDescription>Recent tenant-scoped audit entries from tenant detail payload.</CardDescription>
          </CardHeader>
          <CardContent>
            <DataTable columns={auditColumns} items={recentAudit} empty={<EmptyState icon={FileCheck2} title="No audit events yet." body="Tenant security-relevant actions appear after staff or customer mutations are recorded." />} />
          </CardContent>
        </Card>
        </div>
      </>
      ) : null}
      {tab === 'users' ? (
        <Card>
          <CardHeader>
            <CardTitle>Tenant users</CardTitle>
            <CardDescription>Resend invites or disable users through staff support APIs. Owner and member identities scoped to this tenant.</CardDescription>
          </CardHeader>
          <CardContent>
            <DataTable columns={userColumns} items={users} empty={<EmptyState icon={Users} title="No users on this tenant." body="Provisioned tenants include an initial owner invite." />} />
          </CardContent>
        </Card>
      ) : null}
      </>
      ) : null}
    </div>
  );
}

function TargetGroupDetailView({
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
  const [tab, setTab] = useState('overview');
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [dnsChallenge, setDnsChallenge] = useState<DataItem | null>(null);
  const [dnsVerifyResult, setDnsVerifyResult] = useState<DataItem | null>(null);
  const [ownershipVerifications, setOwnershipVerifications] = useState<DataItem[]>([]);
  const [ownershipVerificationsLoading, setOwnershipVerificationsLoading] = useState(false);

  const validationMode = getString(entity, ['validation_mode'], 'agent_assisted');
  const ownershipStatus = getString(entity, ['ownership_status'], 'unverified');

  useEffect(() => {
    let cancelled = false;
    setOwnershipVerificationsLoading(true);
    requestJson(config, session, '/v1/ownership-verifications')
      .then((payload) => {
        if (cancelled) return;
        const items = Array.isArray((payload as DataItem).items) ? (payload as DataItem).items as DataItem[] : [];
        setOwnershipVerifications(items.filter((item) => getString(item, ['target_group_id'], '') === entityId));
      })
      .catch(() => { if (!cancelled) setOwnershipVerifications([]); })
      .finally(() => { if (!cancelled) setOwnershipVerificationsLoading(false); });
    return () => { cancelled = true; };
  }, [config, session, entityId]);

  const targets = getNestedArray(entity, ['targets']);
  const relatedRuns = data.runs.filter((run) => getString(run, ['target_group_id'], '') === entityId);
  const relatedFindings = data.findings.filter((finding) => getString(finding, ['target_group_id'], '') === entityId);
  const relatedAgents = data.agents.filter((agent) => getString(agent, ['target_group_id'], '') === entityId);
  const relatedPolicies = data.testPolicies.filter((policy) => getString(policy, ['target_group_id'], '') === entityId);
  const openFindings = relatedFindings.filter((finding) => getString(finding, ['status'], 'open') === 'open');
  const lastRun = [...relatedRuns].sort((left, right) => {
    const leftAt = String(left.updated_at ?? left.created_at ?? '');
    const rightAt = String(right.updated_at ?? right.created_at ?? '');
    return rightAt.localeCompare(leftAt);
  })[0] ?? null;

  const tabOptions = routeTabs('target-group-detail').map((item) => ({ id: item.id, label: item.label }));

  const targetColumns: TableColumn<DataItem>[] = [
    { key: 'kind', label: 'Type', render: (item) => <Badge tone="info">{getString(item, ['kind'])}</Badge> },
    { key: 'value', label: 'Target', render: (item) => getString(item, ['value']) },
    { key: 'created', label: 'Created', render: (item) => formatDate(item.created_at) }
  ];

  const runColumns: TableColumn<DataItem>[] = [
    {
      key: 'id',
      label: 'Run',
      render: (item) => (
        <DetailEntityLink
          route="run-detail"
          id={getString(item, ['id'], '')}
          label={checkDisplayName(data.checks, getString(item, ['check_id'], ''))}
        />
      )
    },
    { key: 'check', label: 'Check', render: (item) => getString(item, ['check_id']) },
    { key: 'status', label: 'Status', render: (item) => <StatusBadge value={getString(item, ['status'], 'pending')} tone={runStatusBadgeTone(getString(item, ['status'], 'pending'))} fallback="pending" /> },
    { key: 'when', label: 'When', render: (item) => formatDate(item.updated_at ?? item.created_at) },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => (
        <AnchorButton size="sm" variant="ghost" href={buildDetailHref('run-detail', getString(item, ['id'], ''))}>Open</AnchorButton>
      )
    }
  ];

  const findingColumns: TableColumn<DataItem>[] = [
    {
      key: 'id',
      label: 'Finding',
      render: (item) => (
        <DetailEntityLink
          route="finding-detail"
          id={getString(item, ['id'], '')}
          label={getString(item, ['title', 'summary'], getString(item, ['id']))}
        />
      )
    },
    { key: 'severity', label: 'Severity', render: (item) => <StatusBadge value={getString(item, ['severity'], 'unknown')} tone={findingSeverityBadgeTone(getString(item, ['severity'], 'unknown'))} fallback="unknown" /> },
    { key: 'status', label: 'Status', render: (item) => <StatusBadge value={getString(item, ['status'], 'open')} tone={findingStatusBadgeTone(getString(item, ['status'], 'open'))} fallback="open" /> },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => (
        <AnchorButton size="sm" variant="ghost" href={buildDetailHref('finding-detail', getString(item, ['id'], ''))}>Triage</AnchorButton>
      )
    }
  ];

  const agentColumns: TableColumn<DataItem>[] = [
    { key: 'hostname', label: 'Agent', render: (item) => getString(item, ['hostname', 'name', 'id']) },
    { key: 'status', label: 'Status', render: (item) => <StatusBadge value={getString(item, ['status'], 'unknown')} tone={agentStatusBadgeTone(getString(item, ['status'], 'unknown'))} fallback="unknown" /> },
    { key: 'heartbeat', label: 'Last heartbeat', render: (item) => formatDate(item.last_heartbeat_at ?? item.updated_at) },
    {
      key: 'actions',
      label: 'Actions',
      render: (item) => (
        <AnchorButton size="sm" variant="ghost" href={buildDetailHref('agent-detail', getString(item, ['id'], ''))}>Detail</AnchorButton>
      )
    }
  ];

  const policyColumns: TableColumn<DataItem>[] = [
    { key: 'id', label: 'Policy', render: (item) => <code>{getString(item, ['id'])}</code> },
    { key: 'check', label: 'Check', render: (item) => getString(item, ['check_id']) },
    { key: 'cadence', label: 'Cadence', render: (item) => getString(item, ['cadence', 'schedule'], 'manual') },
    { key: 'enabled', label: 'Enabled', render: (item) => <Badge tone={item.enabled === false ? 'muted' : 'success'}>{item.enabled === false ? 'Disabled' : 'Enabled'}</Badge> }
  ];

  async function runGroupAction(label: string, action: () => Promise<unknown>, success: string) {
    setBusy(label);
    setError('');
    setMessage('');
    try {
      await action();
      setMessage(success);
      await onRefresh();
    } catch (err) {
      const payload = (err as Error & { payload?: unknown }).payload as { error?: string; message?: string } | undefined;
      setError(payload?.message ?? payload?.error ?? (err instanceof Error ? err.message : 'Action failed.'));
    } finally {
      setBusy('');
    }
  }

  async function handlePatchGroup(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    await runGroupAction(`patch-target-group-${entityId}`, () => requestJson(config, session, `/v1/target-groups/${entityId}`, {
      method: 'PATCH',
      body: {
        name: String(form.get('name') ?? getString(entity, ['name'])).trim(),
        description: String(form.get('description') ?? '').trim(),
        timezone: String(form.get('timezone') ?? 'UTC').trim() || 'UTC'
      }
    }), 'Target group settings saved.');
  }

  async function archiveGroup() {
    if (!window.confirm('Archive this target group?')) return;
    await runGroupAction(`archive-target-group-${entityId}`, () => requestJson(config, session, `/v1/target-groups/${entityId}`, {
      method: 'DELETE'
    }), 'Target group archived.');
    window.location.hash = '#target-groups';
  }

  async function refreshOwnershipVerifications() {
    setOwnershipVerificationsLoading(true);
    try {
      const payload = await requestJson(config, session, '/v1/ownership-verifications') as DataItem;
      const items = Array.isArray(payload.items) ? payload.items as DataItem[] : [];
      setOwnershipVerifications(items.filter((item) => getString(item, ['target_group_id'], '') === entityId));
    } catch {
      setOwnershipVerifications([]);
    } finally {
      setOwnershipVerificationsLoading(false);
    }
  }

  async function setValidationMode(mode: 'agent_assisted' | 'external_only') {
    if (mode === validationMode) return;
    await runGroupAction(`validation-mode-${entityId}`, () => requestJson(config, session, `/v1/target-groups/${entityId}`, {
      method: 'PATCH',
      body: { validation_mode: mode }
    }), 'Validation mode updated.');
  }

  async function issueDnsOwnershipChallenge() {
    await runGroupAction(`dns-issue-${entityId}`, async () => {
      const result = await requestJson(config, session, `/v1/target-groups/${entityId}/dns-ownership`, { method: 'POST' }) as DataItem;
      setDnsChallenge(result);
      setDnsVerifyResult(null);
    }, 'DNS TXT challenge issued.');
  }

  async function verifyDnsOwnership() {
    await runGroupAction(`dns-verify-${entityId}`, async () => {
      const result = await requestJson(config, session, `/v1/target-groups/${entityId}/dns-ownership/verify`, { method: 'POST' }) as DataItem;
      setDnsVerifyResult(result);
    }, 'DNS ownership verification completed.');
  }

  async function confirmOwnershipVerification(verificationId: string) {
    await runGroupAction(`confirm-ownership-${verificationId}`, () => requestJson(config, session, `/v1/ownership-verifications/${encodeURIComponent(verificationId)}/confirm`, { method: 'POST' }), 'Ownership confirmed.');
    await refreshOwnershipVerifications();
  }

  async function verifyOwnershipSetup() {
    const onlineAgent = relatedAgents.find((agent) => getString(agent, ['status']) === 'online');
    if (!onlineAgent) {
      setError('No online agent bound to this target group.');
      setMessage('');
      return;
    }
    const agentId = getString(onlineAgent, ['id'], '');
    setBusy(`verify-setup-${entityId}`);
    setError('');
    setMessage('');
    try {
      const result = await requestJson(config, session, '/v1/ownership-verifications/verify-setup', {
        method: 'POST',
        body: { target_group_id: entityId, agent_id: agentId },
      }) as DataItem;
      if (result.ready === false) {
        const payload = result as DataItem & { message?: string };
        setError(payload.message ?? getString(result, ['error'], 'Setup verification failed.'));
        return;
      }
      const declaredFqdn = getString(result, ['declared_fqdn'], '—');
      setMessage(`Setup verified for ${declaredFqdn}: agent online, bound, token valid, FQDN declared in group.`);
    } catch (err) {
      const payload = (err as Error & { payload?: unknown }).payload as { error?: string; message?: string } | undefined;
      setError(payload?.message ?? payload?.error ?? (err instanceof Error ? err.message : 'Setup verification failed.'));
    } finally {
      setBusy('');
    }
  }

  return (
    <div className="content">
      <div className="page-head">
        <div>
          <DetailEntityHeading
            route="target-group-detail"
            entityId={entityId}
            title={detailEntityTitle('target-group-detail', entity, entityId)}
            eyebrow="Declared business service"
          />
          <p className="muted">
            {targets.length} declared targets · {getString(entity, ['environment_id'], 'tenant scope')}
          </p>
        </div>
        <div className="row-actions">
          <AnchorButton size="sm" variant="secondary" href="#target-groups">All groups</AnchorButton>
          <AnchorButton size="sm" variant="default" href="#runs">Run checks</AnchorButton>
        </div>
      </div>
      <div className="metric-grid four">
        <MetricCard label="Targets" value={targets.length} sub="Declared · never auto-discovered" icon={Target} tone="info" />
        <MetricCard label="Bound agents" value={relatedAgents.length} sub="Outbound observers for this group" icon={Bot} tone="success" />
        <MetricCard label="Open findings" value={openFindings.length} sub="Unresolved gaps on this group" icon={TriangleAlert} tone={openFindings.length > 0 ? 'danger' : 'muted'} />
        <MetricCard label="Last run" value={lastRun ? checkDisplayName(data.checks, getString(lastRun, ['check_id'], getString(lastRun, ['id']))) : '—'} sub={lastRun ? formatDate(lastRun.updated_at ?? lastRun.created_at) : 'No runs yet'} icon={Activity} tone="muted" />
      </div>
      {loading ? <DetailLoadingPlaceholder label="Loading target group detail…" /> : null}
      <DetailStatusBanners loadError={loadError} error={error} message={message} />
      {!loading ? (
      <>
      <Tabs value={tab} options={tabOptions} onChange={setTab} className="tabs-wrap" />
      {tab === 'overview' ? (
        <div className="split">
          <Card>
            <CardHeader>
              <CardTitle>Validation posture</CardTitle>
              <CardDescription>Readiness signals for this declared group.</CardDescription>
            </CardHeader>
            <CardContent className="kv-list">
              <div><span>Latest run status</span>{lastRun ? <StatusBadge value={getString(lastRun, ['status'], 'pending')} tone={runStatusBadgeTone(getString(lastRun, ['status'], 'pending'))} fallback="pending" /> : <strong>none</strong>}</div>
              <div><span>Latest run</span>{lastRun ? <DetailEntityLink route="run-detail" id={getString(lastRun, ['id'], '')} label={checkDisplayName(data.checks, getString(lastRun, ['check_id'], getString(lastRun, ['id'])))} /> : <strong>none</strong>}</div>
              <div><span>Open findings</span><strong>{openFindings.length}</strong></div>
              <div><span>Recent runs</span><strong>{relatedRuns.length}</strong></div>
              <div><span>Bound policies</span><strong>{relatedPolicies.length}</strong></div>
              <div><span>Evidence records</span><strong>{data.evidence.filter((item) => getString(item, ['target_group_id'], '') === entityId).length}</strong></div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Group summary</CardTitle>
              <CardDescription>Declaration metadata for this business service.</CardDescription>
            </CardHeader>
            <CardContent className="kv-list">
              <div><span>Name</span><strong>{getString(entity, ['name'])}</strong></div>
              <div><span>Environment</span><strong>{getString(entity, ['environment_id'])}</strong></div>
              <div><span>Timezone</span><strong>{getString(entity, ['timezone'], 'UTC')}</strong></div>
              <div><span>Created</span><strong>{formatDate(entity.created_at)}</strong></div>
              <div><span>Description</span><strong>{getString(entity, ['description'], 'No description recorded.')}</strong></div>
              <div><span>Group ID</span><strong><code>{entityId}</code></strong></div>
            </CardContent>
          </Card>
        </div>
      ) : null}
      {tab === 'scope' ? (
        <Card>
          <CardHeader>
            <div>
              <CardTitle>Declared targets</CardTitle>
              <CardDescription>Manual declarations loaded from the target-group detail API.</CardDescription>
            </div>
            <Badge tone="success">{targets.length} targets</Badge>
          </CardHeader>
          <CardContent>
            <DataTable
              columns={targetColumns}
              items={targets}
              empty={<EmptyState icon={Target} title="No targets declared." body="Add targets from the Target Groups page." actionLabel="Open Target Groups" actionHref="#target-groups" />}
            />
            <div className="form-actions">
              <AnchorButton size="sm" variant="secondary" href="#target-groups">Manage targets</AnchorButton>
            </div>
          </CardContent>
        </Card>
      ) : null}
      {tab === 'agents' ? (
        <Card>
          <CardHeader>
            <CardTitle>Bound agents</CardTitle>
            <CardDescription>Outbound observers scoped to this target group.</CardDescription>
          </CardHeader>
          <CardContent>
            <DataTable
              columns={agentColumns}
              items={relatedAgents}
              empty={<EmptyState icon={Bot} title="No agents bound." body="Install an outbound agent and bind it to this declared group." actionLabel="Open agents" actionHref="#agents" />}
            />
          </CardContent>
        </Card>
      ) : null}
      {tab === 'validation' ? (
        <div className="metric-grid three">
          <Card>
            <CardHeader>
              <CardTitle>Checks on this group</CardTitle>
              <CardDescription>Safe test policies bound to this declared group.</CardDescription>
            </CardHeader>
            <CardContent>
              <DataTable
                columns={policyColumns}
                items={relatedPolicies}
                empty={<EmptyState icon={FileCheck2} title="No policies bound." body="Bind safe checks through test policies before scheduling runs." actionLabel="Open test policies" actionHref="#test-policies" />}
              />
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Recent runs</CardTitle>
              <CardDescription>Validation runs filtered by target group.</CardDescription>
            </CardHeader>
            <CardContent>
              <DataTable
                columns={runColumns}
                items={relatedRuns}
                empty={<EmptyState icon={Activity} title="No runs yet." body="Start a safe run after declaring targets and binding checks." actionLabel="Open test runs" actionHref="#runs" />}
              />
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Findings on this group</CardTitle>
              <CardDescription>Open and closed gaps tied to this declared scope.</CardDescription>
            </CardHeader>
            <CardContent>
              <DataTable
                columns={findingColumns}
                items={relatedFindings}
                empty={<EmptyState icon={TriangleAlert} title="No findings recorded." body="Findings appear after validation runs surface gaps." actionLabel="Open findings" actionHref="#findings" />}
              />
            </CardContent>
          </Card>
        </div>
      ) : null}
      {tab === 'settings' ? (
        <div className="stack-tight">
          <Card>
            <CardHeader>
              <CardTitle>Ownership &amp; validation</CardTitle>
              <CardDescription>Confirm you control this scope and choose how AstraNull validates it.</CardDescription>
            </CardHeader>
            <CardContent className="stack-tight">
              <div className="kv-list">
                <div>
                  <span>Validation mode</span>
                  <Badge tone={validationModeBadgeTone(validationMode)}>{formatFactorLabel(validationMode)}</Badge>
                </div>
                <div>
                  <span>Ownership status</span>
                  <Badge tone={ownershipStatusBadgeTone(ownershipStatus)}>{formatFactorLabel(ownershipStatus)}</Badge>
                </div>
              </div>
              <div className="row-actions">
                <Button
                  size="sm"
                  variant={validationMode === 'agent_assisted' ? 'default' : 'secondary'}
                  loading={busy === `validation-mode-${entityId}`}
                  disabled={busy !== ''}
                  onClick={() => void setValidationMode('agent_assisted')}
                >
                  Agent-assisted
                </Button>
                <Button
                  size="sm"
                  variant={validationMode === 'external_only' ? 'default' : 'secondary'}
                  loading={busy === `validation-mode-${entityId}`}
                  disabled={busy !== ''}
                  onClick={() => void setValidationMode('external_only')}
                >
                  External only
                </Button>
                <Button
                  size="sm"
                  variant="secondary"
                  loading={busy === `verify-setup-${entityId}`}
                  disabled={busy !== '' || relatedAgents.length === 0}
                  onClick={() => void verifyOwnershipSetup()}
                >
                  Verify my setup
                </Button>
              </div>
              {validationMode === 'external_only' ? (
                <p className="muted small">
                  External-only mode: AstraNull scans the declared FQDN/IP only. Verdicts are labeled external_only (edge evidence, origin not proven). Deploy an agent to strengthen.
                </p>
              ) : null}
              <Card>
                <CardHeader>
                  <CardTitle>DNS TXT ownership</CardTitle>
                  <CardDescription>Publish a TXT record to prove DNS control of the declared FQDN.</CardDescription>
                </CardHeader>
                <CardContent className="stack-tight">
                  <div className="row-actions">
                    <Button size="sm" variant="secondary" loading={busy === `dns-issue-${entityId}`} disabled={busy !== ''} onClick={() => void issueDnsOwnershipChallenge()}>
                      Issue DNS TXT challenge
                    </Button>
                    <Button size="sm" variant="default" loading={busy === `dns-verify-${entityId}`} disabled={busy !== '' || !dnsChallenge} onClick={() => void verifyDnsOwnership()}>
                      Verify DNS ownership
                    </Button>
                  </div>
                  {dnsChallenge ? (
                    <div className="stack-tight">
                      <p className="muted small">Add this TXT record at your DNS provider, then run verification.</p>
                      <DetailCodeBlock label="DNS TXT ownership record">{`Name: ${getString(dnsChallenge, ['record_name'], '—')}\nType: TXT\nValue: ${getString(dnsChallenge, ['record_value'], '—')}`}</DetailCodeBlock>
                      <p className="muted small">Challenge status: <strong>{getString(dnsChallenge, ['status'], 'pending')}</strong></p>
                    </div>
                  ) : null}
                  {dnsVerifyResult ? (
                    <p className="muted small">
                      Verification: <Badge tone={getString(dnsVerifyResult, ['status'], '') === 'verified' ? 'success' : 'danger'}>{getString(dnsVerifyResult, ['status'], '—')}</Badge>
                      {' · '}
                      Ownership: <Badge tone={ownershipStatusBadgeTone(getString(dnsVerifyResult, ['ownership_status'], ownershipStatus))}>{formatFactorLabel(getString(dnsVerifyResult, ['ownership_status'], ownershipStatus))}</Badge>
                    </p>
                  ) : null}
                </CardContent>
              </Card>
              <Card>
                <CardHeader>
                  <CardTitle>Ownership verifications</CardTitle>
                  <CardDescription>Probe and agent observations used to confirm declared FQDN ownership.</CardDescription>
                </CardHeader>
                <CardContent>
                  {ownershipVerificationsLoading ? <DetailLoadingPlaceholder label="Loading ownership verifications…" variant="compact" /> : null}
                  {!ownershipVerificationsLoading && ownershipVerifications.length === 0 ? (
                    <EmptyState icon={ShieldCheck} title="No ownership verifications yet." body="Run validation with declared FQDNs or complete DNS TXT verification to populate records." />
                  ) : null}
                  {!ownershipVerificationsLoading && ownershipVerifications.length > 0 ? (
                    <div className="stack-tight">
                      {ownershipVerifications.map((item) => {
                        const verificationId = getString(item, ['id'], '');
                        const status = getString(item, ['status'], 'unknown');
                        const confirmedBy = getString(item, ['confirmed_by_user_id'], '');
                        const probeObserved = item.probe_observed === true;
                        const agentObserved = item.agent_observed === true;
                        return (
                          <div key={verificationId || getString(item, ['declared_fqdn'], '')} className="kv-list">
                            <div><span>Declared FQDN</span><strong>{getString(item, ['declared_fqdn'], '—')}</strong></div>
                            <div><span>Status</span><Badge tone={status === 'verified' ? 'success' : status === 'failed' ? 'danger' : 'muted'}>{formatFactorLabel(status)}</Badge></div>
                            <div><span>Probe observed</span><Badge tone={probeObserved ? 'success' : 'muted'}>{probeObserved ? 'yes' : 'no'}</Badge></div>
                            <div><span>Agent observed</span><Badge tone={agentObserved ? 'success' : 'muted'}>{agentObserved ? 'yes' : 'no'}</Badge></div>
                            {status === 'verified' && !confirmedBy && verificationId ? (
                              <div className="form-actions">
                                <Button
                                  size="sm"
                                  variant="default"
                                  loading={busy === `confirm-ownership-${verificationId}`}
                                  disabled={busy !== ''}
                                  onClick={() => void confirmOwnershipVerification(verificationId)}
                                >
                                  Confirm ownership
                                </Button>
                              </div>
                            ) : null}
                          </div>
                        );
                      })}
                    </div>
                  ) : null}
                </CardContent>
              </Card>
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Group settings</CardTitle>
              <CardDescription>Patch declaration metadata without changing unrelated inventory.</CardDescription>
            </CardHeader>
            <CardContent>
              <form key={entityId} className="product-form" onSubmit={handlePatchGroup}>
                <label>
                  <span>Name</span>
                  <input name="name" defaultValue={getString(entity, ['name'])} />
                </label>
                <label>
                  <span>Timezone</span>
                  <input name="timezone" defaultValue={getString(entity, ['timezone'], 'UTC')} />
                </label>
                <label className="full">
                  <span>Description</span>
                  <textarea name="description" rows={3} defaultValue={getString(entity, ['description'], '')} />
                </label>
                <div className="form-actions full">
                  <Button type="submit" loading={busy === `patch-target-group-${entityId}`} disabled={busy !== ''}>Save settings</Button>
                  <AnchorButton size="sm" variant="secondary" href="#target-groups">Manage targets</AnchorButton>
                  <Button type="button" variant="danger" disabled={busy !== ''} onClick={() => void archiveGroup()}>Archive group</Button>
                </div>
              </form>
            </CardContent>
          </Card>
        </div>
      ) : null}
      </>
      ) : null}
    </div>
  );
}

function AgentDetailView({
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
  const [tab, setTab] = useState('overview');
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [revokeConfirmOpen, setRevokeConfirmOpen] = useState(false);
  const [placementReviews, setPlacementReviews] = useState<DataItem | null>(null);
  const [auxLoading, setAuxLoading] = useState(false);
  const tabOptions = routeTabs('agent-detail').map((item) => ({ id: item.id, label: item.label }));
  const targetGroupId = getString(entity, ['target_group_id'], '');
  const probeEndpoint = getNestedItem(entity, ['probe_endpoint']);
  const probeEndpointStatus = getString(entity, ['probe_endpoint_status'], '');
  const probeEndpointError = getString(entity, ['probe_endpoint_error'], '');
  const declaredProbeFqdn = probeEndpoint ? getNestedString(probeEndpoint, ['declared_fqdn'], '') : '';
  const declaredProbeIp = probeEndpoint ? getNestedString(probeEndpoint, ['declared_ip'], '') : '';
  const hasProbeEndpointDetails = Boolean(probeEndpointStatus || probeEndpointError || probeEndpoint);
  const placementReview = Array.isArray(placementReviews?.reviews)
    ? (placementReviews.reviews as DataItem[]).find((review) => getString(review, ['target_group_id'], '') === targetGroupId)
    : null;
  const agentLogs = filterAgentAuditEntries(data.audit, entityId);
  const agentAuditColumns: TableColumn<DataItem>[] = [
    { key: 'action', label: 'Action', render: (item) => getString(item, ['action']) },
    { key: 'resource', label: 'Resource', render: (item) => `${getString(item, ['resource_type'])}:${getString(item, ['resource_id'])}` },
    { key: 'actor', label: 'Actor', render: (item) => getString(item, ['actor_role'], 'system') },
    { key: 'when', label: 'Recorded', render: (item) => formatDate(item.created_at ?? item.timestamp) }
  ];
  // Recent observations = real correlated runs on this agent's declared target group (no fabricated rows).
  const agentObservationRuns = targetGroupId
    ? data.runs
        .filter((run) => getString(run, ['target_group_id'], '') === targetGroupId)
        .sort((left, right) =>
          String(right.updated_at ?? right.created_at ?? '').localeCompare(String(left.updated_at ?? left.created_at ?? ''))
        )
        .slice(0, 8)
    : [];
  const observationRunColumns: TableColumn<DataItem>[] = [
    { key: 'run', label: 'Run', render: (run) => <span className="mono small">{getString(run, ['id'], '—')}</span> },
    { key: 'check', label: 'Check', render: (run) => checkDisplayName(data.checks, getString(run, ['check_id'], '')) },
    {
      key: 'verdict',
      label: 'Agrees with probe',
      render: (run) => {
        const value = getNestedString(run, ['verdict', 'verdict'], getString(run, ['status'], 'pending'));
        return <StatusBadge value={value} tone={verdictBadgeTone(value)} fallback="pending" />;
      }
    },
    { key: 'sealed', label: 'Sealed', render: (run) => <span className="muted">{formatDate(run.updated_at ?? run.created_at)}</span> }
  ];
  // Placement evidence record built from the real agent entity; empty rows are omitted so no placeholder data is shown.
  const placementEvidenceBlock = evidenceCodeBlock([
    ['agent_id', entityId],
    ['hostname', getString(entity, ['hostname', 'name'], '')],
    ['environment', getString(entity, ['environment_id'], '')],
    ['placement_kind', formatAgentPlacement(entity)],
    ['outbound_only', 'true']
  ]);

  useEffect(() => {
    if (tab !== 'placement') return undefined;
    let cancelled = false;
    setAuxLoading(true);
    const query = targetGroupId ? `/v1/placement/reviews?target_group_id=${encodeURIComponent(targetGroupId)}` : '/v1/placement/reviews';
    requestJson(config, session, query)
      .then((payload) => { if (!cancelled) setPlacementReviews(payload as DataItem); })
      .catch(() => { if (!cancelled) setPlacementReviews(null); })
      .finally(() => { if (!cancelled) setAuxLoading(false); });
    return () => { cancelled = true; };
  }, [tab, config, session, targetGroupId]);

  async function revokeAgent() {
    if (!entityId || getString(entity, ['status']) === 'revoked') return;
    setBusy(`revoke-${entityId}`);
    setError('');
    setMessage('');
    try {
      const result = await requestJson(config, session, `/v1/agents/${encodeURIComponent(entityId)}/revoke`, { method: 'POST' });
      setMessage(formatMutationSuccessMessage('Agent revoked.', result));
      setRevokeConfirmOpen(false);
      await onRefresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Agent revoke failed.');
    } finally {
      setBusy('');
    }
  }

  async function runPlacementTest() {
    if (!targetGroupId) {
      setError('Bind this agent to a target group before running a placement test.');
      return;
    }
    setBusy(`placement-${entityId}`);
    setError('');
    setMessage('');
    try {
      const detail = await requestJson(config, session, `/v1/target-groups/${encodeURIComponent(targetGroupId)}`) as DataItem;
      const targets = Array.isArray(detail.targets) ? detail.targets as DataItem[] : [];
      const targetId = getString(targets[0] ?? {}, ['id'], '');
      if (!targetId) {
        setError('Add at least one target to the bound group before running placement test.');
        return;
      }
      const result = await requestJson(config, session, '/v1/test-runs', {
        method: 'POST',
        body: {
          target_group_id: targetGroupId,
          target_id: targetId,
          check_id: ONBOARDING_PLACEMENT_TEST_CHECK_ID
        }
      });
      setMessage(formatMutationSuccessMessage('Placement test started.', result));
      await onRefresh();
    } catch (err) {
      const payload = (err as Error & { payload?: unknown }).payload as { error?: string; message?: string } | undefined;
      setError(payload?.message ?? payload?.error ?? (err instanceof Error ? err.message : 'Placement test failed.'));
    } finally {
      setBusy('');
    }
  }

  return (
    <div className="content">
      <div className="page-head">
        <div>
          <DetailEntityHeading
            route="agent-detail"
            entityId={entityId}
            title={detailEntityTitle('agent-detail', entity, entityId)}
            eyebrow="Outbound observer"
          />
          <p className="muted detail-status-line">
            <StatusBadge value={getString(entity, ['status'], 'unknown')} tone={agentStatusBadgeTone(getString(entity, ['status'], 'unknown'))} fallback="unknown" />
            <span className="detail-status-sep" aria-hidden="true">·</span>
            <span>{formatAgentCapabilities(entity)}</span>
          </p>
        </div>
        <div className="row-actions">
          <AnchorButton size="sm" variant="secondary" href="#agents">Tenant agent settings</AnchorButton>
        </div>
      </div>
      {loading ? <DetailLoadingPlaceholder label="Loading agent detail…" /> : null}
      <DetailStatusBanners loadError={loadError} error={error} message={message} />
      {!loading ? (
      <>
      <div className="metric-grid four">
        <MetricCard label="Heartbeat" value={agentHeartbeatFreshness(entity)} sub={formatDate(entity.last_heartbeat_at)} icon={Bot} tone="info" />
        <MetricCard label="Version" value={getString(entity, ['version'], 'unknown')} sub={getString(entity, ['environment_id'], 'tenant scope')} icon={ShieldCheck} tone="muted" />
        <MetricCard label="Placement" value={formatAgentPlacement(entity)} sub={targetGroupId ? `bound · ${targetGroupId}` : 'no group assignment'} icon={Target} tone={targetGroupId ? 'success' : 'warn'} />
        <MetricCard label="Status" value={formatAgentHealth(entity)} sub="From last heartbeat" icon={Activity} tone={getString(entity, ['status']) === 'online' ? 'success' : getString(entity, ['status']) === 'revoked' ? 'danger' : 'muted'} />
      </div>
      <Tabs value={tab} options={tabOptions} onChange={setTab} className="tabs-wrap" />
      {tab === 'overview' ? (
        <>
        <AgentHeartbeatPanel
          agent={entity}
          agentId={entityId}
          audit={data.audit}
          onRefresh={() => void onRefresh()}
          refreshing={busy !== ''}
        />
        <AgentPlacementPanel
          agent={entity}
          agentId={entityId}
          targetGroupId={targetGroupId}
          runs={data.runs}
          placementReview={placementReview ?? null}
          onRunPlacement={() => void runPlacementTest()}
          running={busy === `placement-${entityId}`}
          busy={busy !== ''}
        />
        <div className="dash-grid">
          <Card>
            <CardHeader>
              <CardTitle>Placement evidence</CardTitle>
              <CardDescription>Declared · outbound-only. Placement is tied to the environment declared at install — never inferred from cloud inventory.</CardDescription>
            </CardHeader>
            <CardContent className="stack-tight">
              <div className="kv-list">
                <div><span>Environment</span><strong>{getString(entity, ['environment_id'], 'tenant scope')}</strong></div>
                <div><span>Direction</span><strong>egress HTTPS only</strong></div>
                <div><span>Placement</span><strong>{formatAgentPlacement(entity)}</strong></div>
              </div>
              {placementEvidenceBlock ? (
                <DetailCodeBlock label="Placement evidence record">{placementEvidenceBlock}</DetailCodeBlock>
              ) : (
                <EmptyState icon={ShieldCheck} title="No placement evidence yet." body="Placement evidence appears after the agent registers with declared environment metadata." />
              )}
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <div>
                <CardTitle>Recent observations</CardTitle>
                <CardDescription>Correlated · metadata-only runs on this agent's declared target group.</CardDescription>
              </div>
              <AnchorButton size="sm" variant="ghost" href="#runs">View runs</AnchorButton>
            </CardHeader>
            <CardContent>
              <DataTable
                columns={observationRunColumns}
                items={agentObservationRuns}
                getRowId={(run) => getString(run, ['id'], '')}
                getRowProps={(run) => detailRowNavProps('run-detail', getString(run, ['id'], ''))}
                empty={<EmptyState icon={Activity} title={targetGroupId ? 'No correlated runs yet.' : 'Agent not bound to a group.'} body={targetGroupId ? 'Runs on this target group appear here once safe checks execute.' : 'Bind this agent to a target group to correlate run observations.'} actionLabel="Open test runs" actionHref="#runs" />}
              />
            </CardContent>
          </Card>
        </div>
        <div className="split">
          <Card>
            <CardHeader>
              <CardTitle>Agent status</CardTitle>
              <CardDescription>Health, placement, and binding for this outbound observer.</CardDescription>
            </CardHeader>
            <CardContent className="kv-list">
              <div><span>Placement</span><strong>{formatAgentPlacement(entity)}</strong></div>
              <div><span>Capabilities</span><strong>{formatAgentCapabilities(entity)}</strong></div>
              <div><span>Target group</span>{targetGroupId ? <DetailEntityLink route="target-group-detail" id={targetGroupId} /> : <strong>unbound</strong>}</div>
              <div><span>Hostname</span><strong>{getString(entity, ['hostname', 'name'])}</strong></div>
              <div><span>Environment</span><strong>{getString(entity, ['environment_id'], 'tenant scope')}</strong></div>
              <div><span>Last heartbeat</span><strong>{formatDate(entity.last_heartbeat_at ?? entity.updated_at)}</strong></div>
              <div><span>Version</span><strong>{getString(entity, ['version'], 'unknown')}</strong></div>
              <DetailKvMonoField label="Gateway fingerprint" value={getString(entity, ['fingerprint'], 'not registered')} />
              <AgentProbeEndpointKvSection
                hasDetails={hasProbeEndpointDetails}
                status={probeEndpointStatus}
                error={probeEndpointError}
                fqdn={declaredProbeFqdn}
                ip={declaredProbeIp}
              />
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Lifecycle</CardTitle>
              <CardDescription>Revoke stops heartbeat until re-registered with a new bootstrap token from the fleet page.</CardDescription>
            </CardHeader>
            <CardContent className="stack-tight">
              <div className="kv-list">
                <div><span>Installed</span><strong>{formatDate(entity.installed_at ?? entity.registered_at ?? entity.created_at)}</strong></div>
                <div><span>Last heartbeat</span><strong>{formatDate(entity.last_heartbeat_at ?? entity.updated_at)}</strong></div>
                <div><span>Status</span><StatusBadge value={getString(entity, ['status'], 'unknown')} tone={agentStatusBadgeTone(getString(entity, ['status'], 'unknown'))} fallback="unknown" /></div>
              </div>
              <div className="row-actions">
                {getString(entity, ['status']) !== 'revoked' ? (
                  <Button size="sm" variant="danger" loading={busy === `revoke-${entityId}`} disabled={busy !== ''} onClick={() => setRevokeConfirmOpen(true)}>Revoke agent</Button>
                ) : (
                  <p className="muted">This agent is revoked. Issue a new bootstrap token on <AnchorButton size="sm" variant="ghost" href="#agents">Agents</AnchorButton> to re-register.</p>
                )}
                <AnchorButton size="sm" variant="secondary" href="#agents">Open fleet install &amp; upgrades</AnchorButton>
              </div>
            </CardContent>
          </Card>
        </div>
        <ConfirmModal
          open={revokeConfirmOpen}
          title={`Revoke agent ${entityId}`}
          description={<p>Are you sure? Revoked agents stop reporting until re-registered with a new bootstrap token.</p>}
          confirmLabel="Revoke agent"
          busy={busy === `revoke-${entityId}`}
          onCancel={() => setRevokeConfirmOpen(false)}
          onConfirm={() => void revokeAgent()}
        />
        </>
      ) : null}
      {tab === 'health' ? (
        <Card>
          <CardHeader>
            <CardTitle>Health signals</CardTitle>
            <CardDescription>Heartbeat freshness derived from agent record timestamps.</CardDescription>
          </CardHeader>
          <CardContent className="kv-list">
            <div><span>Heartbeat freshness</span><strong>{agentHeartbeatFreshness(entity)}</strong></div>
            <div><span>Last heartbeat</span><strong>{formatDate(entity.last_heartbeat_at)}</strong></div>
            <div><span>Status</span><StatusBadge value={getString(entity, ['status'], 'unknown')} tone={agentStatusBadgeTone(getString(entity, ['status'], 'unknown'))} fallback="unknown" /></div>
            <div><span>Version</span><strong>{getString(entity, ['version'], 'unknown')}</strong></div>
            <AgentProbeEndpointKvSection
              hasDetails={hasProbeEndpointDetails}
              status={probeEndpointStatus}
              error={probeEndpointError}
              fqdn={declaredProbeFqdn}
              ip={declaredProbeIp}
            />
          </CardContent>
        </Card>
      ) : null}
      {tab === 'placement' ? (
        <Card>
          <CardHeader>
            <CardTitle>Placement review</CardTitle>
            <CardDescription>Target-group placement confidence from placement reviews.</CardDescription>
          </CardHeader>
          <CardContent className="kv-list">
            {auxLoading ? <DetailLoadingPlaceholder label="Loading placement review…" variant="compact" /> : null}
            <div><span>Target group</span>{targetGroupId ? <DetailEntityLink route="target-group-detail" id={targetGroupId} /> : <strong>unbound</strong>}</div>
            <div>
              <span>Placement status</span>
              <span title={placementStatusHint(getString(placementReview, ['status'], '')) || undefined}>
                <StatusBadge
                  value={formatPlacementStatus(getString(placementReview, ['status'], 'unknown'))}
                  tone={placementStatusBadgeTone(getString(placementReview, ['status'], 'unknown'))}
                  fallback="unknown"
                />
              </span>
            </div>
            <div><span>Observation mode</span><strong>{getString(placementReview, ['observation_mode'], '—')}</strong></div>
            <div><span>Summary</span><strong>{getString(placementReview, ['summary'], getNestedString(placementReviews, ['summary', 'summary'], 'Awaiting baseline traffic evidence.'))}</strong></div>
          </CardContent>
        </Card>
      ) : null}
      {tab === 'audit' ? (
        <Card>
          <CardHeader>
            <CardTitle>Audit trail</CardTitle>
            <CardDescription>Metadata-only lifecycle events for this agent.</CardDescription>
          </CardHeader>
          <CardContent>
            <DataTable
              columns={agentAuditColumns}
              items={agentLogs}
              empty={<EmptyState icon={ClipboardList} title="No audit events for this agent yet." body="Registration, heartbeat, revoke, and update actions appear after lifecycle activity." />}
            />
          </CardContent>
        </Card>
      ) : null}
      </>
      ) : null}
    </div>
  );
}

function FindingDetailView({
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
  const [tab, setTab] = useState('summary');
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [exportOutput, setExportOutput] = useState('');
  const [showTechnicalExport, setShowTechnicalExport] = useState(false);
  const tabOptions = [
    { id: 'summary', label: 'Summary' },
    { id: 'explanation', label: 'Explanation' },
    { id: 'triage', label: 'Triage' }
  ];
  const testRunId = getString(entity, ['test_run_id'], '');
  const slaDueAt = findingSlaDueAt(entity);
  const title = detailEntityTitle('finding-detail', entity, entityId);

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

  async function patchFinding(body: Record<string, unknown>, success: string, confirmMessage?: string) {
    if (confirmMessage && !window.confirm(confirmMessage)) return;
    await runAction(`finding-${entityId}`, () => requestJson(config, session, `/v1/findings/${entityId}`, { method: 'PATCH', body }), success);
  }

  async function retestFinding() {
    if (!window.confirm('Start a retest for this finding?')) return;
    const retestAction = resolveFindingRetestAction(entity);
    if (!retestAction) {
      setError('Finding is missing retest context (check_id, WAF asset, or CVE pipeline item).');
      return;
    }
    if (retestAction.kind === 'waf-validation') {
      await runAction(`retest-waf-${entityId}`, () => requestJson(config, session, '/v1/waf/validations', {
        method: 'POST',
        body: { waf_asset_id: retestAction.wafAssetId, modes: ['marker'] }
      }), 'WAF validation retest started.');
      return;
    }
    if (retestAction.kind === 'cve-retest') {
      await runAction(`retest-cve-${entityId}`, () => requestJson(config, session, `/v1/waf/cve-pipeline/${encodeURIComponent(retestAction.pipelineId)}/retest`, { method: 'POST' }), 'CVE pipeline retest started.');
      return;
    }
    if (retestAction.kind === 'cve-retest-url') {
      await runAction(`retest-cve-url-${entityId}`, () => requestJson(config, session, retestAction.retestUrl, { method: 'POST' }), 'CVE retest started.');
      return;
    }
    const targetGroupId = getString(data.targetGroups[0] ?? {}, ['id'], '');
    const checkId = retestAction.checkId;
    const detail = await requestJson(config, session, `/v1/target-groups/${targetGroupId}`) as DataItem;
    const targets = Array.isArray(detail.targets) ? detail.targets as DataItem[] : [];
    const targetId = getString(targets[0] ?? {}, ['id'], '');
    if (!targetGroupId || !targetId || !checkId) {
      setError('Declare target scope before starting a retest run.');
      return;
    }
    await runAction(`retest-run-${entityId}`, () => requestJson(config, session, '/v1/test-runs', {
      method: 'POST',
      body: { target_group_id: targetGroupId, target_id: targetId, check_id: checkId }
    }), 'Safe validation retest started.');
  }

  async function exportFinding() {
    setBusy(`export-finding-${entityId}`);
    setError('');
    try {
      const payload = await requestJson(config, session, `/v1/findings/${entityId}/export`, { method: 'POST' });
      setExportOutput(JSON.stringify(payload, null, 2));
      setMessage('Finding export generated with custody manifest.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Export failed.');
    } finally {
      setBusy('');
    }
  }

  return (
    <div className="content">
      <DetailPageHeader route="finding-detail" eyebrow="Evidence-backed finding" entityId={entityId} title={title} />
      {loading ? <DetailLoadingPlaceholder label="Loading finding detail…" /> : null}
      <DetailStatusBanners loadError={loadError} error={error} message={message} successTone="neutral" />
      {!loading ? (
      <>
      <Tabs value={tab} options={tabOptions} onChange={setTab} className="tabs-wrap" />
      {tab === 'summary' ? (
        <>
        {isExternalOnlyVerdictSignal(entity) ? (
          <Card>
            <CardHeader>
              <CardTitle>Strengthen this verdict</CardTitle>
              <CardDescription>This verdict is based on external-only edge evidence. Deploy the AstraNull agent on the target path to prove whether traffic reached origin.</CardDescription>
            </CardHeader>
            <CardContent>
              <AnchorButton size="sm" variant="default" href="#agents">Deploy agent to strengthen</AnchorButton>
            </CardContent>
          </Card>
        ) : null}
        <Card>
          <CardHeader>
            <CardTitle>Finding summary</CardTitle>
            <CardDescription>
              <StatusBadge value={getString(entity, ['severity'])} tone={findingSeverityBadgeTone(getString(entity, ['severity']))} />
              {' · '}
              <StatusBadge value={getString(entity, ['status'])} tone={findingStatusBadgeTone(getString(entity, ['status']))} />
            </CardDescription>
          </CardHeader>
          <CardContent className="kv-list">
            <DetailKvField label="Assignee">{getString(entity, ['assignee'], 'unassigned')}</DetailKvField>
            <DetailKvHintField
              label="SLA due"
              value={<>{slaDueAt ? formatDate(slaDueAt) : '—'}{isFindingSlaBreach(entity) ? ' (breach)' : ''}</>}
              hint="SLA window is based on severity hours from creation."
            />
            <div><span>Target group</span><DetailEntityLink route="target-group-detail" id={getString(entity, ['target_group_id'], '')} /></div>
            <div><span>Related run</span>{testRunId ? <DetailEntityLink route="run-detail" id={testRunId} label={runDisplayLabel(data.runs, testRunId)} /> : <strong>—</strong>}</div>
            <div className="row-actions">
              <AnchorButton size="sm" variant="secondary" href="#findings">Open findings</AnchorButton>
              <Button size="sm" variant="ghost" loading={busy.startsWith('retest-')} disabled={busy !== ''} onClick={() => void retestFinding()}>Retest</Button>
            </div>
          </CardContent>
        </Card>
        </>
      ) : null}
      {tab === 'explanation' ? (
        <Card>
          <CardHeader><CardTitle>Why this finding?</CardTitle><CardDescription>Verdict explanation correlated to the originating test run.</CardDescription></CardHeader>
          <CardContent><FindingExplanationPanel finding={entity} config={config} session={session} /></CardContent>
        </Card>
      ) : null}
      {tab === 'triage' ? (
        <>
          <Card>
            <CardHeader><CardTitle>Owner &amp; status</CardTitle><CardDescription>Assign an owner and change finding status with confirmation.</CardDescription></CardHeader>
            <CardContent>
              <form className="product-form" onSubmit={(event) => {
                event.preventDefault();
                const form = new FormData(event.currentTarget);
                void patchFinding({
                  assignee: String(form.get('assignee') ?? '').trim(),
                  notes: String(form.get('notes') ?? '').trim()
                }, 'Triage notes updated.');
              }}>
                <label className="full"><span>Assignee</span><input name="assignee" defaultValue={getString(entity, ['assignee'], '')} /></label>
                <label className="full"><span>Triage notes</span><textarea name="notes" rows={4} defaultValue={getString(entity, ['notes'], '')} /></label>
                <div className="form-actions full"><Button type="submit" loading={busy === `finding-${entityId}`} disabled={busy !== ''}>Save triage</Button></div>
              </form>
              <div className="row-actions">
                <Button
                  size="sm"
                  variant="secondary"
                  loading={busy === `finding-${entityId}`}
                  disabled={busy !== '' || getString(entity, ['status']) === 'accepted_risk'}
                  onClick={() => void patchFinding({ status: 'accepted_risk' }, 'Finding marked accepted risk.', 'Accept risk on this finding? Document the exception in triage notes before continuing.')}
                >
                  Accept risk
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  loading={busy === `finding-${entityId}`}
                  disabled={busy !== '' || getString(entity, ['status']) === 'closed'}
                  onClick={() => void patchFinding({ status: 'closed' }, 'Finding closed.', 'Close this finding? Ensure retest or closure evidence is recorded.')}
                >
                  Close finding
                </Button>
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader><CardTitle>Custody export</CardTitle><CardDescription>Generate a custody-backed export for auditors.</CardDescription></CardHeader>
            <CardContent>
              <div className="row-actions">
                <Button size="sm" variant="secondary" loading={busy === `export-finding-${entityId}`} disabled={busy !== ''} onClick={() => void exportFinding()}>Export with custody</Button>
                <label className="auth-check-row">
                  <input
                    type="checkbox"
                    checked={showTechnicalExport}
                    aria-label="Show technical export preview"
                    onChange={(event) => setShowTechnicalExport(event.target.checked)}
                  />
                  <span>Show technical export preview</span>
                </label>
              </div>
              {showTechnicalExport && exportOutput ? (
                <DetailCodeBlock label="Finding custody export preview">{exportOutput}</DetailCodeBlock>
              ) : null}
            </CardContent>
          </Card>
        </>
      ) : null}
      </>
      ) : null}
    </div>
  );
}

function EvidenceDetailView({
  data,
  config,
  session
}: {
  data: PortalData;
  config: PortalConfig;
  session: Session;
}) {
  const entityId = getRouteEntityId('');
  const evidenceList = data.evidence;
  const initialFallback = evidenceList.find((item) => getString(item, ['id', 'evidence_id'], '') === entityId) ?? null;
  const [entity, setEntity] = useState<DataItem | null>(initialFallback);
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState('');
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    if (!entityId) {
      setEntity(null);
      return;
    }
    let cancelled = false;
    const localFallback = evidenceList.find((item) => getString(item, ['id', 'evidence_id'], '') === entityId) ?? null;
    setEntity(localFallback);
    setLoading(true);
    setLoadError('');
    requestJson(config, session, `/v1/evidence/${encodeURIComponent(entityId)}`)
      .then((payload) => {
        if (cancelled) return;
        if (payload && typeof payload === 'object' && !Array.isArray(payload)) {
          setEntity(payload as DataItem);
        }
      })
      .catch((err) => {
        if (cancelled) return;
        if (localFallback) {
          setEntity(localFallback);
        } else {
          setLoadError(err instanceof Error ? err.message : 'Evidence artifact unavailable.');
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [entityId, config, session, evidenceList]);

  if (!entityId) {
    return (
      <div className="content">
        <DetailPageHeader
          route="evidence-detail"
          eyebrow="Validation · evidence artifact"
          entityId=""
          title="Evidence artifact"
        />
        <EmptyState
          icon={ShieldCheck}
          title="No evidence artifact selected."
          body="Open an artifact from a run's evidence chain or a finding's evidence bundle."
          actionLabel="Open findings"
          actionHref="#findings"
        />
      </div>
    );
  }

  if (!entity && loading) {
    return (
      <div className="content">
        <DetailPageIntro route="evidence-detail" eyebrow="Validation · evidence artifact" />
        <DetailLoadingPlaceholder label="Loading evidence artifact…" />
      </div>
    );
  }

  if (!entity) {
    return (
      <div className="content">
        <DetailPageHeader
          route="evidence-detail"
          eyebrow={`Validation · evidence artifact · ${entityId}`}
          entityId={entityId}
          title={entityId}
        />
        <EmptyState
          icon={ShieldCheck}
          title="Evidence artifact not found."
          body={loadError || 'The requested artifact is missing or outside this tenant scope.'}
          actionLabel="Open findings"
          actionHref="#findings"
        />
      </div>
    );
  }

  const artifactId = getString(entity, ['artifact_id', 'id', 'evidence_id'], entityId);
  const kind = getString(entity, ['kind', 'label', 'signal_type'], '');
  const producedBy = getString(entity, ['produced_by', 'source'], getNestedString(entity, ['metadata', 'source'], ''));
  const runId = getString(entity, ['test_run_id', 'run_id'], '');
  const sizeLabel = formatEvidenceSize(entity);
  const sealedAtRaw = getString(entity, ['sealed_at'], getString(entity, ['created_at', 'timestamp'], ''));
  const verified = getString(entity, ['verified'], '');
  const sha256 = getString(entity, ['content_sha256', 'sha256', 'custody_digest'], getNestedString(entity, ['metadata', 'sha256'], ''));
  const chainPosition = getString(entity, ['chain_position'], '');
  const bundle = getString(entity, ['bundle', 'bundle_id'], '');
  const bundleSha256 = getString(entity, ['bundle_sha256'], '');

  const findingId = (() => {
    const direct = getString(entity, ['finding_id'], '');
    if (direct) return direct;
    const byEvidence = data.findings.find((finding) => {
      const ids = Array.isArray(finding.evidence_ids) ? (finding.evidence_ids as unknown[]).map(String) : [];
      return ids.includes(artifactId) || ids.includes(entityId);
    });
    if (byEvidence) return getString(byEvidence, ['id'], '');
    if (runId) {
      const byRun = data.findings.find((finding) => getString(finding, ['test_run_id'], '') === runId);
      if (byRun) return getString(byRun, ['id'], '');
    }
    return '';
  })();

  const sealedPayload = getNestedItem(entity, ['metadata']) ?? getNestedItem(entity, ['payload']) ?? getNestedItem(entity, ['content']);
  const payloadJson = sealedPayload && Object.keys(sealedPayload).length > 0 ? JSON.stringify(sealedPayload, null, 2) : '';

  let custodyLabel = 'Metadata only';
  let custodyTone: 'success' | 'info' | 'muted' = 'muted';
  if (verified === 'true' || verified === 'verified') {
    custodyLabel = 'Verified';
    custodyTone = 'success';
  } else if (sha256) {
    custodyLabel = 'Sealed';
    custodyTone = 'info';
  }

  const artifactRecord = evidenceCodeBlock([
    ['artifact_id', artifactId],
    ['kind', kind],
    ['produced_by', producedBy],
    ['run', runId],
    ['finding', findingId],
    ['size', sizeLabel],
    ['sealed_at', sealedAtRaw ? formatDate(sealedAtRaw) : ''],
    ['verified', verified]
  ]);

  const custodyRecord = evidenceCodeBlock([
    ['sha256', sha256],
    ['digest_kind', sha256 ? CUSTODY_CONTENT_CANONICALIZATION : ''],
    ['chain_position', chainPosition],
    ['bundle', bundle],
    ['bundle_sha256', bundleSha256]
  ]);

  function buildArtifactExportPayload(): Record<string, unknown> {
    const payload: Record<string, unknown> = {
      exported_at: new Date().toISOString(),
      evidence_ids: [artifactId],
      artifact_id: artifactId
    };
    if (kind) payload.kind = kind;
    if (producedBy) payload.produced_by = producedBy;
    if (runId) payload.run = runId;
    if (findingId) payload.finding = findingId;
    if (sizeLabel) payload.size = sizeLabel;
    if (sealedAtRaw) payload.sealed_at = sealedAtRaw;
    if (verified) payload.verified = verified;
    if (sha256) payload.content_sha256 = sha256;
    if (chainPosition) payload.chain_position = chainPosition;
    if (bundle) payload.bundle = bundle;
    if (bundleSha256) payload.bundle_sha256 = bundleSha256;
    if (sealedPayload && Object.keys(sealedPayload).length > 0) payload.payload = sealedPayload;
    return payload;
  }

  async function verifyChain() {
    setBusy('verify');
    setError('');
    setMessage('');
    try {
      const payload = buildArtifactExportPayload();
      const manifest = await buildEvidenceCustodyManifest(
        sealedPayload && Object.keys(sealedPayload).length > 0 ? sealedPayload : payload,
        session.tenant_id
      );
      const recomputed = getString(manifest as DataItem, ['content_sha256'], '');
      const sealedIsFull = Boolean(sha256) && !sha256.includes('…') && sha256.length >= 64;
      if (sealedIsFull && recomputed) {
        if (recomputed === sha256) {
          setMessage(`Custody digest verified — recomputed ${CUSTODY_CONTENT_CANONICALIZATION} matches the sealed digest.`);
        } else {
          setError('Custody mismatch — the recomputed digest does not match the sealed digest for this artifact.');
        }
      } else if (recomputed) {
        setMessage(`Recomputed ${CUSTODY_CONTENT_CANONICALIZATION} digest ${recomputed.slice(0, 12)}… over the sealed contents. Full custody-chain verification runs server-side against the sealed vault record.`);
      } else {
        setError('No sealed contents available on this record to recompute a digest.');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Verify chain failed.');
    } finally {
      setBusy('');
    }
  }

  async function exportArtifact() {
    setBusy('export');
    setError('');
    setMessage('');
    try {
      const payload = buildArtifactExportPayload();
      const custody = await buildEvidenceCustodyManifest(payload, session.tenant_id);
      triggerJsonDownload(`evidence-${artifactId}.json`, { payload, custody });
      setMessage('Evidence artifact exported with custody manifest.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Export failed.');
    } finally {
      setBusy('');
    }
  }

  return (
    <div className="content">
      <DetailPageHeader
        route="evidence-detail"
        eyebrow={`Validation · evidence artifact · ${artifactId}`}
        entityId={artifactId}
        title={artifactId}
        actions={(
          <>
            {findingId ? (
              <AnchorButton size="sm" variant="secondary" href={buildDetailHref('finding-detail', findingId)}>← Finding</AnchorButton>
            ) : null}
            <Button size="sm" variant="ghost" loading={busy === 'verify'} disabled={busy !== ''} onClick={() => void verifyChain()}>Verify chain</Button>
            <Button size="sm" variant="default" loading={busy === 'export'} disabled={busy !== ''} onClick={() => void exportArtifact()}>Export artifact</Button>
          </>
        )}
      />
      <p className="muted small">Sealed evidence artifact — metadata-only custody record, chain position, digest, and payload for one run artifact.</p>
      {loading ? <DetailLoadingPlaceholder label="Refreshing evidence artifact…" variant="compact" /> : null}
      <DetailStatusBanners loadError={loadError} error={error} message={message} />

      <div className="metric-grid four">
        <MetricCard label="Kind" value={kind || '—'} sub="Artifact classification" icon={FileCheck2} tone="info" />
        <MetricCard label="Run" value={runId || '—'} sub="Originating test run" icon={Activity} tone="muted" />
        <MetricCard label="Size" value={sizeLabel || '—'} sub="Sealed payload size" icon={FileText} tone="muted" />
        <MetricCard label="Custody" value={custodyLabel} sub={sha256 ? CUSTODY_CONTENT_CANONICALIZATION : 'metadata-only vault record'} icon={ShieldCheck} tone={custodyTone} />
      </div>

      <div className="dash-grid">
        <Card>
          <CardHeader>
            <CardTitle>Artifact record</CardTitle>
            <CardDescription>Sealed metadata for this artifact. Absent fields are omitted.</CardDescription>
          </CardHeader>
          <CardContent>
            {artifactRecord ? (
              <DetailCodeBlock label="Artifact record">{artifactRecord}</DetailCodeBlock>
            ) : (
              <p className="muted">No artifact metadata recorded for this evidence id.</p>
            )}
            {runId ? (
              <div className="row-actions">
                <DetailEntityLink route="run-detail" id={runId} label="Open originating run" />
              </div>
            ) : null}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Custody &amp; digest</CardTitle>
            <CardDescription>Chain position and canonical digest. Metadata-only — no raw payloads.</CardDescription>
          </CardHeader>
          <CardContent>
            {custodyRecord ? (
              <DetailCodeBlock label="Custody and digest">{custodyRecord}</DetailCodeBlock>
            ) : (
              <EmptyState icon={ShieldCheck} title="No custody digest recorded." body="This artifact has no sealed SHA-256 digest or bundle reference in the vault record." />
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Payload</CardTitle>
          <CardDescription>Sealed JSON contents of this artifact (metadata-only; redacted server-side).</CardDescription>
        </CardHeader>
        <CardContent>
          {payloadJson ? (
            <DetailCodeBlock label="Sealed payload">{payloadJson}</DetailCodeBlock>
          ) : (
            <EmptyState icon={FileText} title="No sealed payload contents." body="This artifact carries no metadata payload, or the payload was fully redacted server-side." />
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function HighScaleDetailView({
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
  const [tab, setTab] = useState('overview');
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [drafts, setDrafts] = useState<Record<string, AuthorizationArtifactDraft>>({});
  const [lastFailedUploadType, setLastFailedUploadType] = useState('');
  const tabOptions = [
    { id: 'overview', label: 'Overview' },
    { id: 'authorization', label: 'Authorization pack' },
    { id: 'lifecycle', label: 'Lifecycle' },
    { id: 'provider', label: 'Provider checklist' }
  ];
  const packStatus = getNestedItem(entity, ['authorization_pack_status']);
  const artifacts = Array.isArray(entity.artifacts) ? entity.artifacts as DataItem[] : [];
  const providerChecklist = Array.isArray(entity.provider_approval_checklist) ? entity.provider_approval_checklist as DataItem[] : [];
  const lifecycleTrail = buildLifecycleTimeline(entity);
  const targetGroup = data.targetGroups.find((group) => getString(group, ['id'], '') === getString(entity, ['target_group_id'], ''));
  const title = detailEntityTitle('queue-detail', entity, entityId);
  const requiredArtifactTypes = authorizationArtifactTypesForRequest(entity);

  function draftForType(type: string): AuthorizationArtifactDraft {
    return drafts[type] ?? { filename: '', content_sha256: '', custody_id: '' };
  }

  function updateDraft(type: string, field: keyof AuthorizationArtifactDraft, value: string) {
    setDrafts((current) => {
      const existing = current[type];
      return {
        ...current,
        [type]: {
          filename: existing?.filename ?? '',
          content_sha256: existing?.content_sha256 ?? '',
          custody_id: existing?.custody_id ?? '',
          [field]: value
        }
      };
    });
  }

  async function uploadAuthorizationArtifact(type: string) {
    const draft = draftForType(type);
    const filename = draft.filename.trim();
    if (!filename) {
      setError('Filename is required before upload.');
      setMessage('');
      return;
    }
    setBusy(`upload-${type}`);
    setError('');
    setMessage('');
    setLastFailedUploadType('');
    try {
      let contentSha256 = draft.content_sha256.trim();
      if (!contentSha256) {
        contentSha256 = await sha256HexBrowser(`authorization-artifact:${entityId}:${type}:${filename}`);
      }
      const body = buildMetadataArtifactUploadBody(entity, type, {
        filename,
        content_sha256: contentSha256,
        custody_id: draft.custody_id.trim() || undefined
      });
      await requestJson(config, session, `/v1/high-scale-requests/${encodeURIComponent(entityId)}/artifacts`, {
        method: 'POST',
        body
      });
      setMessage(`${authorizationArtifactTitle(type)} metadata uploaded.`);
      await onRefresh();
    } catch (err) {
      setLastFailedUploadType(type);
      setError(err instanceof Error ? err.message : 'Authorization artifact upload failed.');
    } finally {
      setBusy('');
    }
  }

  return (
    <div className="content">
      <DetailPageHeader route="queue-detail" eyebrow="SOC-gated validation" entityId={entityId} title={title} />
      {loading ? <DetailLoadingPlaceholder label="Loading high-scale request…" /> : null}
      <DetailStatusBanners loadError={loadError} error={error} message={message}>
        {error && lastFailedUploadType ? (
          <div className="row-actions">
            <Button size="sm" variant="secondary" loading={busy === `upload-${lastFailedUploadType}`} disabled={busy !== ''} onClick={() => void uploadAuthorizationArtifact(lastFailedUploadType)}>Retry upload</Button>
          </div>
        ) : null}
      </DetailStatusBanners>
      {!loading ? (
      <>
      <Tabs value={tab} options={tabOptions} onChange={setTab} className="tabs-wrap" />
      {tab === 'overview' ? (
        <Card>
          <CardHeader><CardTitle>Request overview</CardTitle></CardHeader>
          <CardContent className="kv-list">
            <div><span>State</span><StatusBadge value={getString(entity, ['state'])} tone={highScaleStateBadgeTone(getString(entity, ['state']))} /></div>
            <div><span>Target group</span><strong>{getString(targetGroup ?? {}, ['name'], getString(entity, ['target_group_id']))}</strong></div>
            <div><span>Pack status</span><StatusBadge value={getString(packStatus ?? {}, ['overall'], 'missing')} tone={artifactReviewBadgeTone(getString(packStatus ?? {}, ['overall'], 'missing'))} fallback="missing" /></div>
            <div><span>Window start</span><strong>{formatDate(getNestedString(entity, ['requested_window', 'window_start'], ''))}</strong></div>
            <AnchorButton size="sm" variant="secondary" href="#runs">Open high-scale requests</AnchorButton>
          </CardContent>
        </Card>
      ) : null}
      {tab === 'authorization' ? (
        <Card>
          <CardHeader><CardTitle>Authorization artifacts</CardTitle><CardDescription>Metadata-only pack references uploaded for SOC review.</CardDescription></CardHeader>
          <CardContent className="stack-tight">
            <div className="artifact-upload-grid">
              {requiredArtifactTypes.map((type) => {
                const draft = draftForType(type);
                const bestArtifact = bestArtifactForType(artifacts, type);
                const requirement = packRequirementForType(packStatus, type);
                const uploadBusy = busy === `upload-${type}`;
                return (
                  <div key={type} className="artifact-upload-card">
                    <div className="artifact-upload-card__header">
                      <div>
                        <strong>{authorizationArtifactTitle(type)}</strong>
                        <p className="muted small">{authorizationArtifactPurpose(type)}</p>
                      </div>
                    </div>
                    <p className="muted small">{explainArtifactReviewStatus(type, requirement, bestArtifact)}</p>
                    <div className="product-form compact">
                      <label className="full">
                        <span>File name</span>
                        <input
                          value={draft.filename}
                          placeholder={`${type}.pdf`}
                          onChange={(event) => updateDraft(type, 'filename', event.target.value)}
                        />
                      </label>
                      <label className="full">
                        <span>Content digest (SHA-256)</span>
                        <input
                          value={draft.content_sha256}
                          placeholder="Optional — computed from metadata if blank"
                          onChange={(event) => updateDraft(type, 'content_sha256', event.target.value)}
                        />
                      </label>
                      <label className="full">
                        <span>Custody record id</span>
                        <input
                          value={draft.custody_id}
                          placeholder={`custody_${entityId}_${type}`}
                          onChange={(event) => updateDraft(type, 'custody_id', event.target.value)}
                        />
                      </label>
                      <div className="form-actions full">
                        <Button
                          size="sm"
                          variant="secondary"
                          loading={uploadBusy}
                          disabled={busy !== ''}
                          onClick={() => void uploadAuthorizationArtifact(type)}
                        >
                          Upload
                        </Button>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
            <div className="artifact-upload-card__meta">
              <strong>Uploaded artifacts</strong>
              {artifacts.length === 0 ? <p className="muted">No artifacts uploaded yet.</p> : (
                <div className="kv-list">
                  {artifacts.map((artifact) => {
                    const type = getString(artifact, ['type']);
                    const artifactStatus = getString(artifact, ['status'], 'pending_review');
                    const digestPreview = getString(artifact, ['content_sha256'], '—').slice(0, 16);
                    return (
                      <div key={getString(artifact, ['id'], type)}>
                        <span>{authorizationArtifactTitle(type)}</span>
                        <strong>
                          <StatusBadge value={artifactStatus} tone={artifactReviewBadgeTone(artifactStatus)} fallback="pending_review" />
                          {' · '}
                          <code className="small">{digestPreview}</code>
                        </strong>
                        <p className="muted small">{explainArtifactReviewStatus(type, packRequirementForType(packStatus, type), artifact)}</p>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      ) : null}
      {tab === 'lifecycle' ? (
        <Card>
          <CardHeader><CardTitle>Lifecycle trail</CardTitle></CardHeader>
          <CardContent><TimelinePanel items={lifecycleTrail.map((event) => ({ label: event.action, at: event.at }))} /></CardContent>
        </Card>
      ) : null}
      {tab === 'provider' ? (
        <Card>
          <CardHeader><CardTitle>Provider checklist</CardTitle></CardHeader>
          <CardContent>
            {providerChecklist.length === 0 ? <p className="muted">No provider checklist items recorded.</p> : (
              <div className="kv-list">
                {providerChecklist.map((item, index) => (
                  <div key={getString(item, ['id'], String(index))}>
                    <span>{getString(item, ['label', 'provider_name', 'requirement'])}</span>
                    <StatusBadge value={getString(item, ['status'], 'pending')} tone={artifactReviewBadgeTone(getString(item, ['status'], 'pending'))} fallback="pending" />
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      ) : null}
      </>
      ) : null}
    </div>
  );
}

function SocRequestDetailView({
  entity,
  entityId,
  config,
  session,
  onRefresh
}: {
  entity: DataItem;
  entityId: string;
  config: PortalConfig;
  session: Session;
  onRefresh: () => Promise<void>;
}) {
  const [tab, setTab] = useState('workspace');
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [adapterStatus, setAdapterStatus] = useState<DataItem | null>(null);
  const [socNotes, setSocNotes] = useState<DataItem[]>([]);
  const [notesLoading, setNotesLoading] = useState(false);
  const [postTestReport, setPostTestReport] = useState<DataItem | null>(null);
  const [reportBusy, setReportBusy] = useState(false);
  const staffSocSurface = session.principal === 'staff' && isStaffSocRole(session);
  const isSoc = staffSocSurface || (session.role === 'soc' && session.principal !== 'staff');

  async function socFetch(path: string, options: { method?: string; body?: unknown } = {}) {
    if (staffSocSurface) return requestSocJson(config, session, path, options);
    return requestJson(config, session, path, options);
  }

  async function loadPostTestReport() {
    setReportBusy(true);
    try {
      const payload = await socFetch(`/internal/soc/high-scale/${encodeURIComponent(entityId)}/post-test-report`);
      const record = payload as DataItem | null;
      if (record && typeof record === 'object' && !record.error && getString(record, ['id'], '')) {
        setPostTestReport(record);
      } else {
        setPostTestReport(null);
      }
    } catch {
      setPostTestReport(null);
    } finally {
      setReportBusy(false);
    }
  }

  async function submitPostTestReport(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const customer_summary = String(form.get('customer_summary') ?? '').trim();
    const impact_summary = String(form.get('impact_summary') ?? '').trim();
    if (!customer_summary && !impact_summary) {
      setError('Add a customer summary or impact summary before attaching the post-test report.');
      return;
    }
    setBusy(`report-${entityId}`);
    setError('');
    setMessage('');
    try {
      await socFetch(`/internal/soc/high-scale/${encodeURIComponent(entityId)}/post-test-report`, {
        method: 'POST',
        body: { customer_summary, impact_summary }
      });
      setMessage('Post-test report attached. You can now close the request.');
      await loadPostTestReport();
      await onRefresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Attach post-test report failed.');
    } finally {
      setBusy('');
    }
  }
  const artifacts = Array.isArray(entity.artifacts) ? entity.artifacts as DataItem[] : [];
  const packStatus = getNestedItem(entity, ['authorization_pack_status']);
  const title = detailEntityTitle('queue-detail', entity, entityId);
  const tabOptions = [
    { id: 'workspace', label: 'Workspace' },
    { id: 'artifacts', label: 'Artifacts' },
    { id: 'adapter', label: 'Adapter' },
    { id: 'notes', label: 'Notes' }
  ];

  async function socAction(action: string, body: Record<string, unknown> = {}) {
    const lifecycleConfirm: Record<string, string> = {
      approve: `Approve high-scale request ${entityId} and move it to approved?`,
      schedule: `Schedule high-scale request ${entityId} for execution?`,
      start: `Start high-scale execution for ${entityId}? Governed adapter traffic will begin.`,
      stop: `Stop high-scale execution for ${entityId} immediately?`,
      close: `Close high-scale request ${entityId} and finalize the test lifecycle?`
    };
    const lifecycleMessage = lifecycleConfirm[action];
    if (lifecycleMessage && !window.confirm(lifecycleMessage)) return;
    setBusy(`${action}-${entityId}`);
    setError('');
    setMessage('');
    try {
      await socFetch(`/internal/soc/high-scale/${encodeURIComponent(entityId)}/${action}`, { method: 'POST', body });
      setMessage(`SOC ${action} completed.`);
      await onRefresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'SOC action failed.');
    } finally {
      setBusy('');
    }
  }

  async function reviewArtifact(artifactId: string, status: 'accepted' | 'rejected') {
    if (status === 'accepted') {
      if (!window.confirm('Accept this authorization artifact? Acceptance authorizes high-scale execution to proceed.')) return;
    } else if (!window.confirm('Reject this authorization artifact?')) return;
    await socAction(`artifacts/${artifactId}/review`, { status, notes: `SOC ${status} via request detail` });
  }

  async function loadAdapterStatus() {
    setBusy(`adapter-${entityId}`);
    setError('');
    try {
      const payload = await socFetch(`/internal/soc/high-scale/${encodeURIComponent(entityId)}/adapter-status`);
      setAdapterStatus(payload as DataItem);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Adapter status unavailable.');
      setAdapterStatus(null);
    } finally {
      setBusy('');
    }
  }

  async function submitSocNote(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const body = String(new FormData(form).get('body') ?? '').trim();
    if (!body) return;
    await socAction('notes', { body });
    form.reset();
    void loadSocNotes();
  }

  async function loadSocNotes() {
    setNotesLoading(true);
    try {
      const payload = await socFetch(`/internal/soc/high-scale/${encodeURIComponent(entityId)}/notes`);
      const items = Array.isArray((payload as { items?: unknown }).items) ? (payload as { items: DataItem[] }).items : [];
      setSocNotes(items);
    } catch {
      setSocNotes([]);
    } finally {
      setNotesLoading(false);
    }
  }

  useEffect(() => {
    if (!isSoc || !entityId) return;
    void loadSocNotes();
  }, [entityId, isSoc]);

  useEffect(() => {
    if (!isSoc || !entityId || getString(entity, ['state'], '') !== 'stopped') {
      setPostTestReport(null);
      return;
    }
    void loadPostTestReport();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [entityId, isSoc, entity]);

  if (!isSoc) {
    const isStaffPrincipal = session.principal === 'staff';
    return (
      <div className="content">
        <DetailPageIntro route="queue-detail" eyebrow="SOC execution workspace" />
        <EmptyState
          icon={ShieldCheck}
          title={isStaffPrincipal ? 'Staff SOC role required.' : 'SOC role required.'}
          body={isStaffPrincipal
            ? 'Sign in with a staff SOC analyst or lead role to operate governed high-scale requests.'
            : 'Switch the workspace role to soc to operate governed high-scale requests.'}
          actionLabel={isStaffPrincipal ? 'Open staff login' : 'Open SOC console'}
          actionHref={isStaffPrincipal ? '/internal/admin/login' : '#internal-soc'}
        />
      </div>
    );
  }

  const state = getString(entity, ['state'], '');
  const packReady = getNestedString(entity, ['authorization_pack_status', 'overall'], '') === 'accepted';
  const hasPostTestReport = Boolean(postTestReport && getString(postTestReport, ['id'], ''));
  // Pre-flight gates + KPI strip are derived from real request evidence only.
  const windowStart = getNestedString(entity, ['scheduled_window', 'window_start'], '') || getNestedString(entity, ['requested_window', 'window_start'], '');
  const windowEnd = getNestedString(entity, ['scheduled_window', 'window_end'], '') || getNestedString(entity, ['requested_window', 'window_end'], '');
  const windowConfirmed = Boolean(windowStart && windowEnd);
  const scopeSealed = Boolean(getString(entity, ['scope_hash'], '') || getNestedItem(entity, ['scope_confirmation']));
  const socApprovalsCount = Array.isArray(entity.soc_approvals) ? (entity.soc_approvals as DataItem[]).length : 0;
  const stateTone = highScaleStateBadgeTone(state);
  const preflightGates = [
    { label: 'Authorization pack accepted', pass: packReady },
    { label: 'Safe window confirmed', pass: windowConfirmed },
    { label: 'Scope hash sealed', pass: scopeSealed },
    { label: 'SOC approval recorded', pass: socApprovalsCount > 0 }
  ];

  return (
    <div className="content">
      <DetailPageHeader route="queue-detail" eyebrow="SOC execution workspace" entityId={entityId} title={title} />
      <DetailStatusBanners error={error} message={message} hideMessageWhenLoadError={false} />
      <div className="metric-grid four">
        <MetricCard label="State" value={formatStatusLabel(state, 'submitted')} sub="Governed lifecycle state" icon={ShieldCheck} tone={stateTone === 'danger' ? 'danger' : stateTone === 'warn' ? 'warn' : stateTone === 'success' ? 'success' : 'info'} />
        <MetricCard label="Pack" value={formatStatusLabel(getString(packStatus ?? {}, ['overall'], 'missing'), 'missing')} sub="Authorization pack review" icon={FileCheck2} tone={packReady ? 'success' : 'warn'} />
        <MetricCard label="Target group" value={getString(entity, ['target_group_id'], '—')} sub="Declared scope under request" icon={Target} tone="muted" />
        <MetricCard label="Window" value={windowConfirmed ? formatDate(windowStart) : 'Unscheduled'} sub={windowConfirmed ? 'Confirmed safe window' : 'Awaiting schedule'} icon={Activity} tone={windowConfirmed ? 'info' : 'muted'} />
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Go / No-Go gates</CardTitle>
          <CardDescription>Pre-flight readiness derived from real request evidence. Every gate must pass before governed execution starts.</CardDescription>
        </CardHeader>
        <CardContent>
          <ul className="placement-gates" aria-label="Pre-flight execution gates">
            {preflightGates.map((gate) => (
              <li key={gate.label}>
                <ShieldCheck size={14} aria-hidden="true" style={{ color: gate.pass ? 'var(--success)' : 'var(--fg-2)' }} />
                <span>{gate.label}</span>
                <Badge tone={gate.pass ? 'success' : 'muted'} aria-label={`${gate.label}: ${gate.pass ? 'pass' : 'pending'}`}>{gate.pass ? 'pass' : 'pending'}</Badge>
              </li>
            ))}
          </ul>
        </CardContent>
      </Card>
      <Tabs value={tab} options={tabOptions} onChange={setTab} className="tabs-wrap" />
      {tab === 'workspace' ? (
        <Card>
          <CardHeader><CardTitle>Queue context</CardTitle><CardDescription>Lifecycle actions for {entityId}</CardDescription></CardHeader>
          <CardContent className="kv-list">
            <div><span>State</span><StatusBadge value={state} tone={highScaleStateBadgeTone(state)} /></div>
            <div><span>Pack</span><StatusBadge value={getString(packStatus ?? {}, ['overall'], 'missing')} tone={artifactReviewBadgeTone(getString(packStatus ?? {}, ['overall'], 'missing'))} fallback="missing" /></div>
            <div className="row-actions">
              {['submitted', 'under_review'].includes(state) && packReady ? <Button size="sm" variant="secondary" loading={busy === `approve-${entityId}`} disabled={busy !== ''} onClick={() => void socAction('approve')}>Approve</Button> : null}
              {state === 'approved' ? <Button size="sm" variant="secondary" loading={busy === `schedule-${entityId}`} disabled={busy !== ''} onClick={() => void socAction('schedule', socDevScheduleWindow())}>Schedule</Button> : null}
              {state === 'scheduled' ? <Button size="sm" variant="default" loading={busy === `start-${entityId}`} disabled={busy !== ''} onClick={() => void socAction('start')}>Start</Button> : null}
              {state === 'running' ? <Button size="sm" variant="danger" loading={busy === `stop-${entityId}`} disabled={busy !== ''} onClick={() => void socAction('stop')}>Stop</Button> : null}
              {state === 'stopped' && hasPostTestReport ? <Button size="sm" variant="secondary" loading={busy === `close-${entityId}`} disabled={busy !== ''} onClick={() => void socAction('close')}>Close</Button> : null}
              {state === 'stopped' && !hasPostTestReport ? <Button size="sm" variant="secondary" disabled title="Attach a post-test report before closing">Close</Button> : null}
              <AnchorButton size="sm" variant="ghost" href="#internal-soc">Open SOC console</AnchorButton>
            </div>
            {state === 'stopped' && reportBusy ? <p className="muted small">Checking for an attached post-test report…</p> : null}
            {state === 'stopped' && !reportBusy && hasPostTestReport ? (
              <p className="muted small">Post-test report attached — this request can be closed. Closing finalizes the governed test lifecycle.</p>
            ) : null}
            {state === 'stopped' && !reportBusy && !hasPostTestReport ? (
              <div className="stack-tight">
                <p className="muted small">Attach a post-test report before closing. The governed lifecycle rejects Close without one (409 <code>post_test_report_required</code>).</p>
                <form className="product-form" aria-busy={busy === `report-${entityId}` || undefined} onSubmit={(event) => void submitPostTestReport(event)}>
                  <label className="full"><span>Customer summary</span><textarea name="customer_summary" rows={2} disabled={busy === `report-${entityId}`} placeholder="Customer-facing summary of the governed high-scale test outcome." /></label>
                  <label className="full"><span>Impact summary</span><textarea name="impact_summary" rows={2} disabled={busy === `report-${entityId}`} placeholder="Impact, residual risk, and recommended next steps." /></label>
                  <div className="form-actions full"><Button type="submit" size="sm" variant="default" loading={busy === `report-${entityId}`} disabled={busy !== ''}>Attach post-test report</Button></div>
                </form>
              </div>
            ) : null}
          </CardContent>
        </Card>
      ) : null}
      {tab === 'artifacts' ? (
        <Card>
          <CardHeader><CardTitle>Authorization artifacts</CardTitle></CardHeader>
          <CardContent>
            {artifacts.length === 0 ? <p className="muted">No artifacts uploaded.</p> : (
              <div className="kv-list">
                {artifacts.map((artifact) => {
                  const artifactId = getString(artifact, ['id'], '');
                  const type = getString(artifact, ['type']);
                  const reviewBusy = busy === `artifacts/${artifactId}/review-${entityId}`;
                  return (
                    <div key={artifactId || type}>
                      <span>{authorizationArtifactTitle(type)}</span>
                      <div className="row-actions">
                        <StatusBadge value={getString(artifact, ['status'])} tone={artifactReviewBadgeTone(getString(artifact, ['status']))} />
                        <Button size="sm" variant="secondary" loading={reviewBusy} disabled={busy !== ''} onClick={() => void reviewArtifact(artifactId, 'accepted')}>Accept</Button>
                        <Button size="sm" variant="ghost" loading={reviewBusy} disabled={busy !== ''} onClick={() => void reviewArtifact(artifactId, 'rejected')}>Reject</Button>
                      </div>
                      <p className="muted small">{explainArtifactReviewStatus(type, packRequirementForType(packStatus, type), artifact)}</p>
                    </div>
                  );
                })}
              </div>
            )}
          </CardContent>
        </Card>
      ) : null}
      {tab === 'adapter' ? (
        <Card>
          <CardHeader><CardTitle>Adapter status</CardTitle></CardHeader>
          <CardContent>
            <Button size="sm" variant="secondary" loading={busy === `adapter-${entityId}`} disabled={busy !== ''} onClick={() => void loadAdapterStatus()}>Refresh adapter status</Button>
            {adapterStatus ? (
              <div className="kv-list">
                <div><span>State</span><strong>{getNestedString(adapterStatus, ['adapter', 'state'], getString(adapterStatus, ['state']))}</strong></div>
                <div><span>Traffic generated</span><Badge tone={getNestedString(adapterStatus, ['adapter', 'traffic_generated'], 'false') === 'true' ? 'warn' : 'muted'}>{getNestedString(adapterStatus, ['adapter', 'traffic_generated'], 'false') === 'true' ? 'Yes' : 'No'}</Badge></div>
              </div>
            ) : <p className="muted">Adapter status not loaded yet.</p>}
          </CardContent>
        </Card>
      ) : null}
      {tab === 'notes' ? (
        <Card>
          <CardHeader><CardTitle>SOC notes</CardTitle><CardDescription>Thread before adding execution context.</CardDescription></CardHeader>
          <CardContent>
            {notesLoading ? <DetailLoadingPlaceholder label="Loading SOC notes…" variant="compact" /> : null}
            {socNotes.length > 0 ? (
              <div className="kv-list stack-tight">
                {socNotes.map((note, index) => (
                  <div key={getString(note, ['id'], String(index))}>
                    <span>{formatDate(note.created_at)}</span>
                    <strong>{getString(note, ['body'])}</strong>
                  </div>
                ))}
              </div>
            ) : !notesLoading ? <p className="muted">No SOC notes recorded yet.</p> : null}
            <form className="product-form" aria-busy={notesLoading || undefined} onSubmit={(event) => void submitSocNote(event)}>
              <label className="full"><span>Note</span><textarea name="body" rows={4} disabled={notesLoading} placeholder="Execution context, customer coordination, or stop rationale." /></label>
              <div className="form-actions full"><Button type="submit" loading={busy === `notes-${entityId}`} disabled={busy !== '' || notesLoading}>Add note</Button></div>
            </form>
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}

/**
 * Whole-row click-through props matching the prototype's `role="link"` rows.
 * Navigates to a detail route via the hash + `?id=` pattern (see lib/route-params).
 */
function detailRowNavProps(route: RouteId, id: string): Omit<HTMLAttributes<HTMLTableRowElement>, 'key'> {
  if (!id) return {};
  const go = () => { window.location.hash = `${route}?id=${encodeURIComponent(id)}`; };
  return {
    role: 'link',
    tabIndex: 0,
    style: { cursor: 'pointer' },
    'aria-label': `Open ${id}`,
    onClick: go,
    onKeyDown: (event: KeyboardEvent<HTMLTableRowElement>) => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        go();
      }
    }
  };
}

/** Verdict/outcome badge tone shared by the environment/check/policy detail surfaces. */
function outcomeBadgeTone(value: string): StatusBadgeTone {
  const key = normalizeStatusKey(value);
  if (['pass', 'passed', 'success', 'ok', 'covered'].includes(key)) return 'success';
  if (['fail', 'failed', 'gap'].includes(key)) return 'danger';
  if (['review', 'manual_review', 'warn', 'warning', 'partial', 'inconclusive', 'needs_evidence'].includes(key)) return 'warn';
  if (['soc_gated', 'request', 'pending', 'none'].includes(key)) return 'muted';
  return 'info';
}

const CHECK_VECTOR_FAMILY_LABELS: Record<string, string> = {
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

function formatCheckFamilyLabel(family: string) {
  if (!family) return '—';
  return CHECK_VECTOR_FAMILY_LABELS[family] ?? formatFactorLabel(family);
}

function formatCheckModeLabel(safetyClass: string) {
  if (safetyClass === 'safe') return 'safe';
  if (safetyClass === 'soc_gated') return 'SOC-gated';
  return safetyClass ? formatFactorLabel(safetyClass) : '—';
}

/** Human-readable rate bound from a check record, mirroring the checks list surface. */
function checkBoundLabel(check: DataItem) {
  const maxRate = check.max_rate;
  if (typeof maxRate === 'number' && Number.isFinite(maxRate) && maxRate > 0) return `${maxRate} RPS`;
  if (typeof maxRate === 'string' && maxRate.trim()) return maxRate.replace(/_/g, ' ');
  const kind = getNestedString(check, ['probe_profile', 'kind'], '');
  if (kind === 'metadata_marker' || kind === 'ops_readiness') return 'metadata';
  const maxRequests = getNestedNumber(check, ['probe_profile', 'max_requests'], NaN);
  if (Number.isFinite(maxRequests) && maxRequests === 1) return 'metadata';
  return getString(check, ['bound', 'rate_limit'], 'metadata');
}

function runVerdictValue(run: DataItem) {
  const verdict = run.verdict;
  if (verdict && typeof verdict === 'object' && !Array.isArray(verdict)) {
    const nested = getString(verdict as DataItem, ['verdict', 'status', 'result'], '');
    if (nested) return nested;
  }
  return getString(run, ['verdict'], '');
}

/** Latest completed/verdicted run outcome for a given check id. */
function latestCheckVerdict(runs: DataItem[], checkId: string): { verdict: string; runId: string } | null {
  let best: { verdict: string; runId: string; at: string } | null = null;
  for (const run of runs) {
    if (getString(run, ['check_id'], '') !== checkId) continue;
    if (!['completed', 'verdicted'].includes(getString(run, ['status'], ''))) continue;
    const verdict = runVerdictValue(run);
    if (!verdict) continue;
    const at = String(run.updated_at ?? run.completed_at ?? run.started_at ?? run.created_at ?? '');
    if (!best || at.localeCompare(best.at) >= 0) {
      best = { verdict, runId: getString(run, ['id'], ''), at };
    }
  }
  return best ? { verdict: best.verdict, runId: best.runId } : null;
}

/** Latest run outcome for a given target group id. */
function latestGroupVerdict(runs: DataItem[], groupId: string): { verdict: string; runId: string } | null {
  let best: { verdict: string; runId: string; at: string } | null = null;
  for (const run of runs) {
    if (getString(run, ['target_group_id'], '') !== groupId) continue;
    const verdict = runVerdictValue(run);
    const at = String(run.updated_at ?? run.completed_at ?? run.started_at ?? run.created_at ?? '');
    if (!best || at.localeCompare(best.at) >= 0) {
      best = { verdict: verdict || getString(run, ['status'], 'pending'), runId: getString(run, ['id'], ''), at };
    }
  }
  return best ? { verdict: best.verdict, runId: best.runId } : null;
}

function formatPolicySafeWindow(policy: DataItem) {
  const windows = policy.safe_windows;
  if (Array.isArray(windows) && windows.length > 0 && windows[0] && typeof windows[0] === 'object') {
    const first = windows[0] as DataItem;
    const day = getString(first, ['day'], '');
    const start = getString(first, ['start'], '');
    const end = getString(first, ['end'], '');
    if (start || end) {
      const range = start && end ? `${start}–${end}` : start || end;
      return day ? `${day} ${range}` : range;
    }
  }
  return getString(policy, ['safe_window', 'window'], '—');
}

function EnvironmentDetailPage({ entityId, data }: { entityId: string; data: PortalData }) {
  if (!entityId) {
    return (
      <div className="content">
        <DetailPageIntro route="environment-detail" eyebrow="Declared scope" />
        <EmptyState
          icon={Network}
          title="No environment selected."
          body="Open an environment from the list with ?id= or use the Detail link on #environments."
          actionLabel="Open environments"
          actionHref="#environments"
        />
      </div>
    );
  }

  const rows = buildEnvironmentReadinessRows({ targetGroups: data.targetGroups, runs: data.runs, findings: data.findings });
  const row = rows.find((item) => item.id === entityId) ?? null;

  if (!row) {
    return (
      <div className="content">
        <DetailPageIntro route="environment-detail" eyebrow="Declared scope" />
        <EmptyState
          icon={Network}
          title="Environment not found."
          body="This environment id has no declared target groups in your workspace scope."
          actionLabel="Open environments"
          actionHref="#environments"
        />
      </div>
    );
  }

  const groups = row.groups;
  const envAgents = data.agents.filter((agent) => getString(agent, ['environment_id'], '') === entityId);
  const names = [...new Set(groups.map((group) => getString(group, ['name', 'display_name'], '')).filter((name) => name && name !== '—'))];
  const displayName = names.length === 0 ? entityId : names.length === 1 ? names[0] : `${names[0]} (+${names.length - 1})`;
  let region = '—';
  for (const group of groups) {
    const candidate = getString(group, ['region', 'region_summary', 'location'], '');
    if (candidate && candidate !== '—') { region = candidate; break; }
  }

  const status = row.coverage === 100 && row.openFindings === 0
    ? { label: 'Validated', tone: 'success' as StatusBadgeTone }
    : row.coverage > 0
      ? { label: 'Review', tone: 'warn' as StatusBadgeTone }
      : envAgents.length === 0 && row.groupCount > 0
        ? { label: 'No agent', tone: 'muted' as StatusBadgeTone }
        : { label: 'Needs evidence', tone: 'muted' as StatusBadgeTone };

  const groupIds = new Set(groups.map((group) => getString(group, ['id'], '')));
  const validationHistory = [...data.runs]
    .filter((run) => groupIds.has(getString(run, ['target_group_id'], '')))
    .sort((left, right) => String(right.updated_at ?? right.created_at ?? '').localeCompare(String(left.updated_at ?? left.created_at ?? '')))
    .slice(0, 6)
    .map((run) => {
      const checkName = checkDisplayName(data.checks, getString(run, ['check_id'], ''));
      const verdict = runVerdictValue(run) || getString(run, ['status'], 'pending');
      return { label: `${checkName} — ${formatStatusLabel(verdict)}`, at: run.updated_at ?? run.created_at };
    });

  const groupColumns: TableColumn<DataItem>[] = [
    { key: 'id', label: 'Group', render: (item) => <code>{getString(item, ['id'])}</code> },
    { key: 'name', label: 'Name', render: (item) => getString(item, ['name', 'display_name']) },
    { key: 'targets', label: 'Targets', render: (item) => <span className="tabular-nums">{getNestedNumber(item, ['target_count'])}</span> },
    {
      key: 'verdict',
      label: 'Verdict',
      render: (item) => {
        const outcome = latestGroupVerdict(data.runs, getString(item, ['id'], ''));
        return outcome
          ? <StatusBadge value={outcome.verdict} tone={outcomeBadgeTone(outcome.verdict)} fallback="pending" />
          : <span className="muted">—</span>;
      }
    }
  ];

  const agentColumns: TableColumn<DataItem>[] = [
    { key: 'agent', label: 'Agent', render: (item) => <code>{getString(item, ['hostname', 'name', 'id'])}</code> },
    { key: 'heartbeat', label: 'Heartbeat', render: (item) => <span className="muted">{formatDate(item.last_heartbeat_at ?? item.updated_at)}</span> },
    { key: 'status', label: 'Status', render: (item) => <StatusBadge value={getString(item, ['status'], 'unknown')} tone={agentStatusBadgeTone(getString(item, ['status'], 'unknown'))} fallback="unknown" /> }
  ];

  return (
    <div className="content">
      <DetailPageHeader
        route="environment-detail"
        eyebrow="Declared scope"
        entityId={entityId}
        title={displayName}
        actions={<AnchorButton size="sm" variant="secondary" href="#environments">← Environments</AnchorButton>}
      />
      <div className="metric-grid four">
        <MetricCard label="Target groups" value={row.groupCount} sub="Declared in this environment" icon={Target} tone="info" />
        <MetricCard label="Agents" value={envAgents.length} sub="Outbound observers in scope" icon={Bot} tone={envAgents.length > 0 ? 'success' : 'warn'} />
        <MetricCard label="Open findings" value={row.openFindings} sub="Unresolved across groups" icon={TriangleAlert} tone={row.openFindings > 0 ? 'danger' : 'muted'} />
        <MetricCard label="Status" value={status.label} sub={`Region ${region} · coverage ${row.coverage}%`} icon={ShieldCheck} tone={status.tone === 'muted' ? 'muted' : status.tone === 'warn' ? 'warn' : 'success'} />
      </div>
      <div className="dash-grid">
        <Card>
          <CardHeader>
            <CardTitle>Target groups in environment</CardTitle>
            <CardDescription>Declared · verdict-backed. Open a group to review evidence.</CardDescription>
          </CardHeader>
          <CardContent>
            <DataTable
              columns={groupColumns}
              items={groups}
              getRowId={(item) => getString(item, ['id'], '')}
              getRowProps={(item) => detailRowNavProps('target-group-detail', getString(item, ['id'], ''))}
              empty={<EmptyState icon={Target} title="No target groups declared." body="Declare target groups against this environment to populate validation evidence." actionLabel="Open target groups" actionHref="#target-groups" />}
            />
          </CardContent>
        </Card>
        <div className="stack-tight">
          <Card>
            <CardHeader>
              <CardTitle>Agents</CardTitle>
              <CardDescription>Outbound-only observers reporting in this environment.</CardDescription>
            </CardHeader>
            <CardContent>
              <DataTable
                columns={agentColumns}
                items={envAgents}
                getRowId={(item) => getString(item, ['id'], '')}
                getRowProps={(item) => detailRowNavProps('agent-detail', getString(item, ['id'], ''))}
                empty={<EmptyState icon={Bot} title="No agents in this environment." body="Install an outbound agent and bind it to a target group in this environment." actionLabel="Open agents" actionHref="#agents" />}
              />
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Validation history</CardTitle>
              <CardDescription>Recent runs across target groups in this environment.</CardDescription>
            </CardHeader>
            <CardContent>
              <TimelinePanel items={validationHistory} />
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}

function CheckDetailPage({ entityId, data }: { entityId: string; data: PortalData }) {
  if (!entityId) {
    return (
      <div className="content">
        <DetailPageIntro route="check-detail" eyebrow="Validation" />
        <EmptyState
          icon={FileCheck2}
          title="No check selected."
          body="Open a check from the list with ?id= or use the Detail link on #checks."
          actionLabel="Open checks"
          actionHref="#checks"
        />
      </div>
    );
  }

  const check = data.checks.find((item) => getString(item, ['check_id', 'id'], '') === entityId) ?? null;

  if (!check) {
    return (
      <div className="content">
        <DetailPageIntro route="check-detail" eyebrow="Validation" />
        <EmptyState
          icon={FileCheck2}
          title="Check not found."
          body="This check id is not present in the workspace check catalog."
          actionLabel="Open checks"
          actionHref="#checks"
        />
      </div>
    );
  }

  const family = getString(check, ['vector_family', 'family'], '');
  const safetyClass = getString(check, ['safety_class'], '');
  const bound = checkBoundLabel(check);
  const description = getString(check, ['description', 'summary'], 'Bounded safe check correlated with agent observation before a verdict is asserted.');
  const latest = latestCheckVerdict(data.runs, entityId);
  const method = getString(check, ['method'], safetyClass === 'safe' ? `${bound} · agent-corroborated` : 'governed · SOC-scheduled');
  const title = getString(check, ['name', 'check_id', 'id'], entityId);
  const definition = [
    `check_id: ${entityId}`,
    `family: ${family || '—'}`,
    `mode: ${formatCheckModeLabel(safetyClass)}`,
    `bound: ${bound}`,
    `method: ${method}`,
    `last_verdict: ${latest ? latest.verdict : 'none'}`
  ].join('\n');

  const toList = (value: unknown): string[] =>
    Array.isArray(value) ? value.map((entry) => String(entry)).filter(Boolean) : [];
  const humanize = (value: string) => value.replace(/_/g, ' ');
  const remediation = getString(check, ['remediation_template', 'remediation'], '');
  const verdictLogic = getString(check, ['verdict_logic'], '');
  const explanation = getString(check, ['explanation_template', 'explanation'], '');
  const expectedBehavior = getString(check, ['default_expected_behavior'], '');
  const supportedTargets = toList(check.supported_targets);
  const agentModes = toList(check.required_agent_modes);
  const prerequisites = toList(check.prerequisites);
  const customerSetup = toList(check.required_customer_setup);
  const evidenceRequired = toList(check.evidence_required);
  const stopConditions = toList(check.stop_conditions);
  const maxEvents = getNestedNumber(check, ['safety_constraints', 'max_events'], 0);
  const maxDuration = getNestedNumber(check, ['safety_constraints', 'max_duration_seconds'], 0);
  const maxConcurrent = getNestedNumber(check, ['safety_constraints', 'max_concurrent_runs_per_target_group'], 0);
  const probeProfile = getNestedItem(check, ['probe_profile']);
  const probeKind = probeProfile ? getString(probeProfile, ['kind'], '') : '';
  const probeRequests = getNestedNumber(check, ['probe_profile', 'max_requests'], 0);

  return (
    <div className="content">
      <DetailPageHeader
        route="check-detail"
        eyebrow="Validation"
        entityId={entityId}
        title={title}
        actions={<AnchorButton size="sm" variant="secondary" href="#checks">← Checks</AnchorButton>}
      />
      <p className="check-detail-lead">{description}</p>
      <div className="metric-grid four">
        <MetricCard label="Family" value={formatCheckFamilyLabel(family)} sub="Vector family" icon={Network} tone="info" />
        <MetricCard label="Mode" value={formatCheckModeLabel(safetyClass)} sub={safetyClass === 'soc_gated' ? 'SOC request-only' : 'Customer-runnable'} icon={ShieldCheck} tone={safetyClass === 'soc_gated' ? 'warn' : 'success'} />
        <MetricCard label="Bound" value={bound} sub="Rate / probe bound" icon={Activity} tone="muted" />
        <MetricCard label="Last verdict" value={latest ? formatStatusLabel(latest.verdict) : 'None'} sub={latest ? 'From most recent run' : 'No runs yet'} icon={FileCheck2} tone={latest ? (outcomeBadgeTone(latest.verdict) === 'danger' ? 'danger' : outcomeBadgeTone(latest.verdict) === 'warn' ? 'warn' : 'success') : 'muted'} />
      </div>
      {remediation ? (
        <Card>
          <CardHeader>
            <CardTitle>Remediation</CardTitle>
            <CardDescription>Recommended action when this check surfaces a gap.</CardDescription>
          </CardHeader>
          <CardContent>
            <p className="check-detail-text">{remediation}</p>
          </CardContent>
        </Card>
      ) : null}
      {verdictLogic || explanation || expectedBehavior ? (
        <Card>
          <CardHeader>
            <CardTitle>Detection logic and verdict path</CardTitle>
            <CardDescription>How outside probes and inside agents are correlated before this check asserts a verdict.</CardDescription>
          </CardHeader>
          <CardContent className="stack">
            {verdictLogic ? (
              <div>
                <p className="check-fact-label">Verdict logic</p>
                <p className="check-detail-text">{verdictLogic}</p>
              </div>
            ) : null}
            {explanation ? (
              <div>
                <p className="check-fact-label">Explanation</p>
                <p className="check-detail-text">{explanation}</p>
              </div>
            ) : null}
            {expectedBehavior ? (
              <div>
                <p className="check-fact-label">Expected behavior</p>
                <p className="check-detail-text">{humanize(expectedBehavior)}</p>
              </div>
            ) : null}
          </CardContent>
        </Card>
      ) : null}
      {supportedTargets.length || agentModes.length || prerequisites.length || customerSetup.length ? (
        <Card>
          <CardHeader>
            <CardTitle>Requirements &amp; scope</CardTitle>
            <CardDescription>What must be declared and placed before this check can run.</CardDescription>
          </CardHeader>
          <CardContent className="stack">
            {supportedTargets.length ? (
              <div>
                <p className="check-fact-label">Supported targets</p>
                <div className="row-actions">{supportedTargets.map((target) => <Badge key={target} tone="muted">{target}</Badge>)}</div>
              </div>
            ) : null}
            {agentModes.length ? (
              <div>
                <p className="check-fact-label">Required agent modes</p>
                <div className="row-actions">{agentModes.map((mode) => <Badge key={mode} tone="muted">{humanize(mode)}</Badge>)}</div>
              </div>
            ) : null}
            {customerSetup.length ? (
              <div>
                <p className="check-fact-label">Required customer setup</p>
                <ul className="check-detail-list">{customerSetup.map((item) => <li key={item}>{humanize(item)}</li>)}</ul>
              </div>
            ) : null}
            {prerequisites.length ? (
              <div>
                <p className="check-fact-label">Prerequisites</p>
                <ul className="check-detail-list">{prerequisites.map((item) => <li key={item}>{humanize(item)}</li>)}</ul>
              </div>
            ) : null}
          </CardContent>
        </Card>
      ) : null}
      {evidenceRequired.length || stopConditions.length || maxEvents || maxDuration || probeKind ? (
        <Card>
          <CardHeader>
            <CardTitle>Evidence &amp; safety bounds</CardTitle>
            <CardDescription>How the run stays bounded and what evidence a verdict requires.</CardDescription>
          </CardHeader>
          <CardContent className="stack">
            {evidenceRequired.length ? (
              <div>
                <p className="check-fact-label">Evidence required</p>
                <div className="row-actions">{evidenceRequired.map((item) => <Badge key={item} tone="info">{humanize(item)}</Badge>)}</div>
              </div>
            ) : null}
            {maxEvents || maxDuration || maxConcurrent ? (
              <div>
                <p className="check-fact-label">Safety bounds</p>
                <div className="row-actions">
                  {maxEvents ? <Badge tone="muted">max {maxEvents} events</Badge> : null}
                  {maxDuration ? <Badge tone="muted">max {maxDuration}s</Badge> : null}
                  {maxConcurrent ? <Badge tone="muted">{maxConcurrent} concurrent / group</Badge> : null}
                </div>
              </div>
            ) : null}
            {probeKind ? (
              <div>
                <p className="check-fact-label">Probe profile</p>
                <div className="row-actions">
                  <code className="traffic-path-label">{probeKind}</code>
                  {probeRequests ? <Badge tone="muted">{probeRequests} request{probeRequests === 1 ? '' : 's'}</Badge> : null}
                </div>
              </div>
            ) : null}
            {stopConditions.length ? (
              <div>
                <p className="check-fact-label">Stop conditions</p>
                <ul className="check-detail-list">{stopConditions.map((item) => <li key={item}>{humanize(item)}</li>)}</ul>
              </div>
            ) : null}
          </CardContent>
        </Card>
      ) : null}
      <Card>
        <CardHeader>
          <CardTitle>Definition</CardTitle>
          <CardDescription>
            {latest ? <>last run <DetailEntityLink route="run-detail" id={latest.runId} /></> : 'No runs recorded for this check yet.'}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <DetailCodeBlock label="Check definition">{definition}</DetailCodeBlock>
        </CardContent>
      </Card>
    </div>
  );
}

function PolicyDetailPage({ entityId, data }: { entityId: string; data: PortalData }) {
  if (!entityId) {
    return (
      <div className="content">
        <DetailPageIntro route="policy-detail" eyebrow="Validation" />
        <EmptyState
          icon={ClipboardList}
          title="No policy selected."
          body="Open a policy from the list with ?id= or use the Detail link on #test-policies."
          actionLabel="Open test policies"
          actionHref="#test-policies"
        />
      </div>
    );
  }

  const policy = data.testPolicies.find((item) => getString(item, ['id', 'policy_id'], '') === entityId) ?? null;

  if (!policy) {
    return (
      <div className="content">
        <DetailPageIntro route="policy-detail" eyebrow="Validation" />
        <EmptyState
          icon={ClipboardList}
          title="Policy not found."
          body="This policy id is not present in your workspace test policies."
          actionLabel="Open test policies"
          actionHref="#test-policies"
        />
      </div>
    );
  }

  const targetGroupNested = getNestedItem(policy, ['target_group']);
  const targetGroupId = getString(policy, ['target_group_id'], getString(targetGroupNested ?? {}, ['id'], ''));
  const targetGroupLabel = getString(targetGroupNested ?? {}, ['name', 'id'], targetGroupId || '—');
  const targetCount = getNestedNumber(policy, ['target_count']);
  const targetsSummary = targetGroupLabel !== '—' && targetCount > 0 ? `${targetGroupLabel} (${targetCount})` : targetGroupLabel;
  const cadence = getString(policy, ['cadence'], 'manual');
  const safeWindow = formatPolicySafeWindow(policy);
  const expected = getString(policy, ['expected_verdict'], 'pass');
  const owner = getString(policy, ['owner', 'created_by'], 'unassigned');
  const checkNested = getNestedItem(policy, ['check']);
  const checkId = getString(policy, ['check_id'], getString(checkNested ?? {}, ['check_id'], ''));
  const linkedCheck = data.checks.find((item) => getString(item, ['check_id', 'id'], '') === checkId) ?? checkNested;
  const gated = policy.soc_gated === true || getString(linkedCheck ?? {}, ['safety_class'], '') === 'soc_gated';
  const title = getString(policy, ['id', 'policy_id'], entityId);
  const binding = [
    `policy_id: ${entityId}`,
    `targets: ${targetsSummary}`,
    `check: ${checkId || '—'}`,
    `cadence: ${cadence}`,
    `safe_window: ${safeWindow}`,
    `expected_verdict: ${expected}`,
    `soc_gated: ${gated ? 'true' : 'false'}`,
    `owner: ${owner}`
  ].join('\n');

  return (
    <div className="content">
      <DetailPageHeader
        route="policy-detail"
        eyebrow="Validation"
        entityId={entityId}
        title={title}
        actions={<AnchorButton size="sm" variant="secondary" href="#test-policies">← Scheduler</AnchorButton>}
      />
      <div className="metric-grid four">
        <MetricCard label="Cadence" value={formatFactorLabel(cadence)} sub="Scheduled run cadence" icon={Activity} tone="info" />
        <MetricCard label="Safe window" value={safeWindow} sub="Declared execution window" icon={ShieldCheck} tone="muted" />
        <MetricCard label="Expected verdict" value={formatStatusLabel(expected)} sub={gated ? 'SOC-gated policy' : 'Customer-runnable'} icon={FileCheck2} tone={outcomeBadgeTone(expected) === 'danger' ? 'danger' : outcomeBadgeTone(expected) === 'warn' ? 'warn' : outcomeBadgeTone(expected) === 'muted' ? 'muted' : 'success'} />
        <MetricCard label="Owner" value={owner} sub="Accountable team" icon={Users} tone="muted" />
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Binding</CardTitle>
          <CardDescription>
            {targetGroupId ? <>target group <DetailEntityLink route="target-group-detail" id={targetGroupId} label={targetGroupLabel} /></> : 'No target group bound to this policy.'}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <DetailCodeBlock label="Policy binding">{binding}</DetailCodeBlock>
        </CardContent>
      </Card>
    </div>
  );
}

export function DetailRoutePage({
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
  const [runEvents, setRunEvents] = useState<DataItem[]>([]);
  const entityId = useMemo(() => getRouteEntityId(''), [route]);

  const targetGroupFallback = data.targetGroups.find((item) => getString(item, ['id'], '') === entityId) ?? null;
  const agentFallback = data.agents.find((item) => getString(item, ['id'], '') === entityId) ?? null;
  const runFallback = data.runs.find((item) => getString(item, ['id'], '') === entityId) ?? null;
  const tenantFallback = data.internalTenants.find((item) => getString(item, ['tenant_id', 'id'], '') === entityId) ?? null;
  const findingFallback = data.findings.find((item) => getString(item, ['id'], '') === entityId) ?? null;
  const highScaleFallback = data.highScale.find((item) => getString(item, ['id'], '') === entityId) ?? null;

  const targetGroupDetail = useEntityDetail(
    route === 'target-group-detail' && Boolean(entityId),
    config,
    session,
    `/v1/target-groups/${encodeURIComponent(entityId)}`,
    targetGroupFallback
  );
  const runDetail = useEntityDetail(
    route === 'run-detail' && Boolean(entityId),
    config,
    session,
    `/v1/test-runs/${encodeURIComponent(entityId)}`,
    runFallback
  );
  const tenantDetail = useEntityDetail(
    route === 'tenant-detail' && Boolean(entityId) && session.principal === 'staff',
    config,
    session,
    `/internal/admin/tenants/${encodeURIComponent(entityId)}`,
    null
  );
  const findingDetailState = useEntityDetail(
    route === 'finding-detail' && Boolean(entityId),
    config,
    session,
    `/v1/findings/${encodeURIComponent(entityId)}`,
    findingFallback
  );
  // Agent detail is sourced by id from the real GET /v1/agents tenant list: the backend exposes
  // GET /v1/agents plus /v1/agents/:id/{revoke,heartbeat,jobs,observations,update} but no single
  // GET /v1/agents/:id document route, so a list-backed lookup returns the real agent record by id
  // without a fabricated endpoint that would 404 (postgres_route_not_wired) in Postgres mode.
  const agentDetail = useListBackedDetail(
    route === 'agent-detail' && Boolean(entityId),
    config,
    session,
    '/v1/agents',
    entityId,
    agentFallback
  );
  const highScaleDetail = useListBackedDetail(
    route === 'queue-detail' && Boolean(entityId),
    config,
    session,
    '/v1/high-scale-requests',
    entityId,
    highScaleFallback
  );
  const detailState =
    route === 'target-group-detail' ? targetGroupDetail
      : route === 'run-detail' ? runDetail
        : route === 'agent-detail' ? agentDetail
          : { detail: null as DataItem | null, error: '', loading: false };

  const entity =
    route === 'tenant-detail' ? tenantFallback
      : route === 'queue-detail' ? (highScaleDetail.detail ?? highScaleFallback)
        : detailState.detail;

  useEffect(() => {
    if (route !== 'run-detail' || !entityId) {
      setRunEvents([]);
      return;
    }
    let cancelled = false;
    requestJson(config, session, `/v1/test-runs/${encodeURIComponent(entityId)}/events`)
      .then((payload) => {
        if (cancelled) return;
        const items = Array.isArray((payload as { items?: unknown }).items) ? (payload as { items: DataItem[] }).items : [];
        setRunEvents(items);
      })
      .catch(() => {
        if (!cancelled) setRunEvents([]);
      });
    return () => { cancelled = true; };
  }, [route, entityId, config, session]);

  async function runDetailAction(label: string, action: () => Promise<unknown>, success: string) {
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

  async function revokeAgent(agentId: string) {
    if (!agentId) return;
    setBusy(`revoke-${agentId}`);
    setError('');
    setMessage('');
    try {
      await requestJson(config, session, `/v1/agents/${encodeURIComponent(agentId)}/revoke`, { method: 'POST' });
      setMessage('Agent revoked.');
      await onRefresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Agent revoke failed.');
    } finally {
      setBusy('');
    }
  }

  if (route === 'tenant-detail') {
    if (!entityId) {
      return (
        <div className="content">
          <DetailPageIntro route={route} eyebrow="Staff tenant operations" />
          <EmptyState icon={Target} title="No tenant selected." body="Open a tenant from the staff directory with ?id= or use the Detail link on #admin." actionLabel="Open staff admin" actionHref="#admin" />
        </div>
      );
    }
    if (session.principal !== 'staff') {
      return (
        <div className="content">
          <DetailPageIntro route={route} eyebrow="Staff tenant operations" />
          <EmptyState icon={UserCog} title="Staff session required." body="Tenant detail is available after staff sign-in." actionLabel="Open staff login" actionHref="/internal/admin/login" />
        </div>
      );
    }
    return (
      <TenantDetailView
        entityId={entityId}
        detail={tenantDetail.detail}
        data={data}
        config={config}
        session={session}
        onRefresh={onRefresh}
        loading={tenantDetail.loading}
        loadError={tenantDetail.error}
      />
    );
  }

  if (route === 'finding-detail') {
    if (!entityId) {
      return (
        <div className="content">
          <DetailPageIntro route={route} eyebrow="Evidence-backed finding" />
          <EmptyState icon={TriangleAlert} title="No finding selected." body="Open a finding from the list with ?id= or use the View link on #findings." actionLabel="Open findings" actionHref="#findings" />
        </div>
      );
    }
    const findingEntity = findingDetailState.detail ?? findingFallback;
    if (!findingEntity && findingDetailState.loading) {
      return (
        <div className="content">
          <DetailPageIntro route={route} eyebrow="Evidence-backed finding" />
          <DetailLoadingPlaceholder label="Loading finding detail…" />
        </div>
      );
    }
    if (!findingEntity) {
      return (
        <div className="content">
          <DetailPageIntro route={route} eyebrow="Evidence-backed finding" />
          <EmptyState icon={TriangleAlert} title="Finding not found." body={findingDetailState.error || 'The requested finding is missing or outside this tenant scope.'} actionLabel="Open findings" actionHref="#findings" />
        </div>
      );
    }
    return (
      <FindingDetailViewRevamp
        entity={findingEntity}
        entityId={entityId}
        data={data}
        config={config}
        session={session}
        onRefresh={onRefresh}
        loading={findingDetailState.loading}
        loadError={findingDetailState.error}
      />
    );
  }

  if (route === 'target-detail') {
    if (!entityId) {
      return (
        <div className="content">
          <DetailPageIntro route={route} eyebrow="Declared target" />
          <EmptyState icon={Target} title="No target selected." body="Open a target from a target group detail table." actionLabel="Open target groups" actionHref="#target-groups" />
        </div>
      );
    }
    return <TargetDetailView entityId={entityId} config={config} session={session} onRefresh={onRefresh} />;
  }

  if (route === 'environment-detail') {
    return <EnvironmentDetailPage entityId={entityId} data={data} />;
  }

  if (route === 'check-detail') {
    return <CheckDetailPage entityId={entityId} data={data} />;
  }

  if (route === 'policy-detail') {
    return <PolicyDetailPage entityId={entityId} data={data} />;
  }

  if (route === 'evidence-detail') {
    return <EvidenceDetailView data={data} config={config} session={session} />;
  }

  if (route === 'queue-detail') {
    if (!entityId) {
      return (
        <div className="content">
          <DetailPageIntro route={route} eyebrow="SOC execution workspace" />
          <EmptyState icon={ShieldCheck} title="No SOC request selected." body="Open a queue item from Test runs or the SOC console with ?id=." actionLabel="Open SOC console" actionHref="#internal-soc" />
        </div>
      );
    }
    if (!highScaleFallback) {
      return (
        <div className="content">
          <DetailPageIntro route={route} eyebrow="SOC execution workspace" />
          <EmptyState icon={ShieldCheck} title="SOC request not found." body="The requested high-scale item is missing or outside this tenant scope." actionLabel="Open SOC console" actionHref="#internal-soc" />
        </div>
      );
    }
    return (
      <SocRequestDetailView
        entity={highScaleFallback}
        entityId={entityId}
        config={config}
        session={session}
        onRefresh={onRefresh}
      />
    );
  }

  if (route === 'target-group-detail') {
    if (!entityId) {
      return (
        <div className="content">
          <DetailPageIntro route={route} eyebrow="Declared business service" />
          <EmptyState
            icon={Target}
            title="No target group selected."
            body="Open a group from the list with ?id= or use the Detail link on #target-groups."
            actionLabel="Open target groups"
            actionHref="#target-groups"
          />
        </div>
      );
    }
    if (!entity && detailState.loading) {
      return (
        <div className="content">
          <DetailPageIntro route={route} eyebrow="Declared business service" />
          <DetailLoadingPlaceholder label="Loading target group detail…" />
        </div>
      );
    }
    if (!entity) {
      return (
        <div className="content">
          <DetailPageIntro route={route} eyebrow="Declared business service" />
          <EmptyState
            icon={Target}
            title="Target group not found."
            body={detailState.error || 'The requested group is missing, archived, or outside this tenant scope.'}
            actionLabel="Open target groups"
            actionHref="#target-groups"
          />
        </div>
      );
    }
    return (
      <TargetGroupDetailViewRevamp
        entity={entity}
        entityId={entityId}
        data={data}
        config={config}
        session={session}
        onRefresh={onRefresh}
        loading={detailState.loading}
        loadError={detailState.error}
      />
    );
  }

  if (!entityId) {
    const noSelectionByRoute: Partial<Record<RouteId, { eyebrow: string; title: string; body: string; actionLabel: string; actionHref: string; icon: typeof Target }>> = {
      'run-detail': {
        eyebrow: 'Test run evidence',
        title: 'No test run selected.',
        body: 'Open a run from the list with ?id= or use the Detail link on #runs.',
        actionLabel: 'Open test runs',
        actionHref: '#runs',
        icon: Activity
      },
      'agent-detail': {
        eyebrow: 'Outbound agent',
        title: 'No agent selected.',
        body: 'Open an agent from the list with ?id= or use the Detail link on #agents.',
        actionLabel: 'Open agents',
        actionHref: '#agents',
        icon: Bot
      },
      'finding-detail': {
        eyebrow: 'Evidence-backed finding',
        title: 'No finding selected.',
        body: 'Open a finding from the list with ?id= or use the View link on #findings.',
        actionLabel: 'Open findings',
        actionHref: '#findings',
        icon: TriangleAlert
      },
      'queue-detail': {
        eyebrow: 'SOC execution workspace',
        title: 'No SOC request selected.',
        body: 'Open a queue item from Test runs or the SOC console with ?id=.',
        actionLabel: 'Open SOC console',
        actionHref: '#internal-soc',
        icon: ShieldCheck
      },
      'target-detail': {
        eyebrow: 'Declared target',
        title: 'No target selected.',
        body: 'Open a target from a target group detail table.',
        actionLabel: 'Open target groups',
        actionHref: '#target-groups',
        icon: Target
      }
    };
    const noSelection = noSelectionByRoute[route];
    return (
      <div className="content">
        <DetailPageIntro route={route} eyebrow={noSelection?.eyebrow ?? 'Detail surface'} />
        <EmptyState
          icon={noSelection?.icon ?? Target}
          title={noSelection?.title ?? 'No entity selected.'}
          body={noSelection?.body ?? 'Open a list row with ?id= or use the Detail link on the parent list page.'}
          actionLabel={noSelection?.actionLabel}
          actionHref={noSelection?.actionHref}
        />
      </div>
    );
  }

  if (!entity && detailState.loading) {
    return (
      <div className="content">
        <DetailPageIntro route={route} eyebrow="Entity detail" />
        <DetailLoadingPlaceholder label="Loading entity detail…" />
      </div>
    );
  }

  if (!entity) {
    const listHrefByRoute: Partial<Record<RouteId, { actionLabel: string; actionHref: string }>> = {
      'run-detail': { actionLabel: 'Open test runs', actionHref: '#runs' },
      'agent-detail': { actionLabel: 'Open agents', actionHref: '#agents' },
    };
    const listLink = listHrefByRoute[route];
    return (
      <div className="content">
        <DetailPageIntro route={route} eyebrow="Entity detail" />
        <EmptyState
          icon={Target}
          title="Entity not found."
          body={detailState.error || 'The requested record is missing or outside this tenant scope.'}
          actionLabel={listLink?.actionLabel}
          actionHref={listLink?.actionHref}
        />
      </div>
    );
  }

  if (route === 'run-detail') {
    return (
      <RunDetailView
        entity={entity}
        entityId={entityId}
        data={data}
        config={config}
        session={session}
        onRefresh={onRefresh}
        runEvents={runEvents}
        loading={detailState.loading}
        loadError={detailState.error}
      />
    );
  }

  if (route === 'agent-detail') {
    if (!entity && agentDetail.loading) {
      return (
        <div className="content">
          <DetailPageIntro route={route} eyebrow="Outbound observer" />
          <DetailLoadingPlaceholder label="Loading agent detail…" />
        </div>
      );
    }
    if (!entity) {
      return (
        <div className="content">
          <DetailPageIntro route={route} eyebrow="Outbound observer" />
          <EmptyState icon={Bot} title="Agent not found." body={agentDetail.error || 'The requested agent is missing or outside this tenant scope.'} actionLabel="Open agents" actionHref="#agents" />
        </div>
      );
    }
    return (
      <AgentDetailView
        entity={entity}
        entityId={entityId}
        data={data}
        config={config}
        session={session}
        onRefresh={onRefresh}
        loading={agentDetail.loading}
        loadError={agentDetail.error}
      />
    );
  }

  return (
    <div className="content">
      <DetailPageIntro route={route} eyebrow="Detail surface" />
      <EmptyState
        icon={Target}
        title="Unsupported detail route."
        body="This detail view is not available in the revamp navigation."
        actionLabel="Open dashboard"
        actionHref="#dashboard"
      />
    </div>
  );

}

type ReportCoverageRow = {
  id: string;
  name: string;
  runs: number;
  openFindings: number;
  verdict: string;
};

export function ReportDetailPage({
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
  const [previewLoading, setPreviewLoading] = useState(false);
  const previewLockedRef = useRef(false);
  const entityId = useMemo(() => getRouteEntityId(''), []);
  const reportFallback = data.reports.find((item) => getString(item, ['id'], '') === entityId) ?? null;
  const reportDetail = useEntityDetail(
    Boolean(entityId),
    config,
    session,
    `/v1/reports/${encodeURIComponent(entityId)}`,
    reportFallback
  );
  const report = reportDetail.detail;

  useEffect(() => {
    previewLockedRef.current = false;
  }, [entityId]);

  useEffect(() => {
    if (!entityId || !report) {
      setPreview(null);
      setPreviewLoading(false);
      return;
    }
    if (previewLockedRef.current) return;
    let cancelled = false;
    setPreviewLoading(true);
    setError('');
    async function loadCustodyPreview() {
      try {
        const headers = buildApiHeaders(config, session);
        const response = await fetch(`/v1/reports/${encodeURIComponent(entityId)}/export?format=json`, { headers });
        if (!response.ok) {
          const payload = await response.json().catch(() => null);
          throw new Error(String(payload?.message ?? payload?.error ?? `Export returned ${response.status}`));
        }
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
        if (!cancelled) {
          setPreview({
            reportId: entityId,
            format: 'json',
            title: getNestedString(payload, ['title'], getString(report, ['title', 'id'], entityId)),
            contentSha256: getString(custody ?? {}, ['content_sha256'], ''),
            artifactId: getString(custody ?? {}, ['artifact_id'], ''),
            schemaVersion: getString(custody ?? {}, ['schema_version'], ''),
            verification
          });
        }
      } catch (err) {
        if (!cancelled) {
          setPreview(null);
          setError(err instanceof Error ? err.message : 'Could not load custody preview.');
        }
      } finally {
        if (!cancelled) setPreviewLoading(false);
      }
    }
    void loadCustodyPreview();
    return () => {
      cancelled = true;
    };
  }, [entityId, report, config, session]);

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
        previewLockedRef.current = true;
        setPreview({
          reportId,
          format,
          title: getNestedString(payload, ['title'], getString(report, ['title', 'id'], reportId)),
          contentSha256: getString(custody ?? {}, ['content_sha256'], ''),
          artifactId: getString(custody ?? {}, ['artifact_id'], ''),
          schemaVersion: getString(custody ?? {}, ['schema_version'], ''),
          verification
        });
        await onRefresh();
        return exported;
      }
      const textPayload = await response.text();
      previewLockedRef.current = true;
      setPreview({
        reportId,
        format,
        title: getString(report, ['title', 'id'], reportId),
        textPreview: textPayload.slice(0, 900)
      });
      await onRefresh();
      return textPayload;
    }, `Report exported as ${format}.`);
  }

  async function copyCustodyDigest() {
    const digest = preview?.contentSha256 ?? '';
    if (!digest) {
      setError('No custody digest available yet — export JSON to compute it first.');
      return;
    }
    try {
      await navigator.clipboard.writeText(digest);
      setError('');
      setMessage('Custody digest copied to clipboard.');
    } catch {
      setError('Clipboard unavailable — copy the digest from the custody preview manually.');
    }
  }

  if (!entityId) {
    return (
      <div className="content">
        <DetailPageIntro route="report-detail" eyebrow="Report detail" />
        <EmptyState
          icon={FileText}
          title="No report selected."
          body="Open a report from the Reports list with ?id= or use the Detail link on #reports."
          actionLabel="Open Reports"
          actionHref="#reports"
        />
      </div>
    );
  }

  if (!report && reportDetail.loading) {
    return (
      <div className="content">
        <DetailPageIntro route="report-detail" eyebrow="Report detail" />
        <DetailLoadingPlaceholder label="Loading report detail…" variant="layout" />
      </div>
    );
  }

  if (!report) {
    return (
      <div className="content">
        <DetailPageIntro route="report-detail" eyebrow="Report detail" />
        <EmptyState
          icon={FileText}
          title="Report not found."
          body={reportDetail.error || 'The requested report is missing or outside this tenant scope.'}
          actionLabel="Open Reports"
          actionHref="#reports"
        />
      </div>
    );
  }

  const verificationOk = preview?.verification ? getString(preview.verification, ['ok'], '') : '';
  const readinessScore = getNestedNumber(report, ['summary', 'readiness_score'], 0);
  const openFindings = getNestedNumber(report, ['summary', 'open_findings'], 0);

  const coverageRows: ReportCoverageRow[] = data.targetGroups.map((group) => {
    const groupId = getString(group, ['id'], '');
    const groupRuns = data.runs.filter((run) => getString(run, ['target_group_id'], '') === groupId);
    const groupOpenFindings = data.findings.filter(
      (finding) => getString(finding, ['target_group_id'], '') === groupId && getString(finding, ['status'], 'open') === 'open'
    );
    const outcome = latestGroupVerdict(data.runs, groupId);
    return {
      id: groupId,
      name: getString(group, ['name'], groupId),
      runs: groupRuns.length,
      openFindings: groupOpenFindings.length,
      verdict: outcome ? outcome.verdict : 'pending'
    };
  });
  const coverageColumns: TableColumn<ReportCoverageRow>[] = [
    { key: 'surface', label: 'Surface', render: (item) => <code>{item.name}</code> },
    { key: 'runs', label: 'Checks run', render: (item) => <span className="tabular-nums">{item.runs}</span> },
    { key: 'findings', label: 'Open findings', render: (item) => <span className="tabular-nums">{item.openFindings}</span> },
    { key: 'verdict', label: 'Last verdict', render: (item) => <StatusBadge value={item.verdict} tone={outcomeBadgeTone(item.verdict)} fallback="pending" /> }
  ];

  const reportTitle = detailEntityTitle('report-detail', report, entityId);

  return (
    <div className="content">
      <DetailPageHeader
        route="report-detail"
        eyebrow="Report detail"
        entityId={entityId}
        title={reportTitle}
        actions={(
          <>
            <AnchorButton size="sm" variant="secondary" href="#reports">Reports</AnchorButton>
            <Button size="sm" variant="default" loading={busy === `export-${entityId}-json`} disabled={busy !== ''} onClick={() => void exportReport(entityId, 'json')}>Export JSON</Button>
          </>
        )}
      />
      <DetailStatusBanners loadError={reportDetail.error} error={error} message={message} mode="combined" />
      {reportDetail.loading || previewLoading ? (
        <DetailLoadingPlaceholder label={reportDetail.loading ? 'Loading report detail…' : 'Loading custody preview…'} variant="layout" />
      ) : (
      <>
      <div className="metric-grid">
        <MetricCard label="Readiness" value={readinessScore} sub="Score out of 100" icon={ShieldCheck} tone={scoreTone(readinessScore)} />
        <MetricCard label="Status" value={formatStatusLabel(getString(report, ['status'], 'ready'))} sub="Delivery status" icon={FileCheck2} tone={reportStatusBadgeTone(getString(report, ['status'], 'ready')) === 'success' ? 'success' : 'muted'} />
        <MetricCard label="Open findings" value={openFindings} sub="Unresolved gaps at generation" icon={TriangleAlert} tone={openFindings > 0 ? 'danger' : 'muted'} />
        <MetricCard label="Kind" value={getString(report, ['kind'], '—')} sub="Report template" icon={FileText} tone="muted" />
        <MetricCard label="Generated" value={formatDate(report.created_at)} sub="Custody-sealed at generation" icon={ClipboardList} tone="muted" />
      </div>
      <div className="detail-layout">
        <Card>
          <CardHeader>
            <CardTitle>Report summary</CardTitle>
            <CardDescription>Readiness and delivery status for this generated report.</CardDescription>
          </CardHeader>
          <CardContent className="kv-list report-summary-layout">
            <ReadinessGauge score={readinessScore} />
            <div><span>Status</span><StatusBadge value={getString(report, ['status'], 'ready')} tone={reportStatusBadgeTone(getString(report, ['status'], 'ready'))} fallback="ready" /></div>
            <div><span>Open findings</span><strong>{openFindings}</strong></div>
            <div><span>Kind</span><strong>{getString(report, ['kind'])}</strong></div>
            <div><span>Created</span><strong>{formatDate(report.created_at)}</strong></div>
            <div><span>Report ID</span><strong><code>{entityId}</code></strong></div>
          </CardContent>
        </Card>
        <Card className="detail-primary">
          <CardHeader>
            <CardTitle>Custody preview</CardTitle>
            <CardDescription>JSON export digest metadata verified against custody manifests.</CardDescription>
          </CardHeader>
          <CardContent className={preview?.contentSha256 || preview?.textPreview ? 'kv-list' : ''}>
            {!preview && !previewLoading ? (
              <EmptyState icon={FileCheck2} title="Custody preview unavailable." body="Export JSON to inspect custody metadata for this report." />
            ) : preview?.contentSha256 ? (
              <>
                <DetailKvMonoField label="Artifact" value={preview.artifactId ?? '—'} compact />
                <DetailKvMonoField label="Content digest (SHA-256)" value={preview.contentSha256} compact />
                <DetailKvField label="Schema">{preview.schemaVersion ?? '—'}</DetailKvField>
                <div><span>Verification</span><StatusBadge value={verificationOk || 'verified'} tone={verificationOk === 'false' ? 'danger' : 'success'} fallback="verified" /></div>
                <div className="row-actions">
                  <Button size="sm" variant="ghost" disabled={!preview.contentSha256} onClick={() => void copyCustodyDigest()}>Copy custody digest</Button>
                </div>
              </>
            ) : preview?.textPreview ? (
              <>
                <p className="muted">JSON custody export unavailable — showing truncated {preview.format} preview (first 900 characters).</p>
                <DetailCodeBlock label="Report export preview">{preview.textPreview}</DetailCodeBlock>
              </>
            ) : null}
          </CardContent>
        </Card>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Coverage by surface</CardTitle>
          <CardDescription>Declared target groups with checks run, open findings, and last verdict from sealed evidence.</CardDescription>
        </CardHeader>
        <CardContent>
          <DataTable
            columns={coverageColumns}
            items={coverageRows}
            getRowId={(item) => item.id}
            getRowProps={(item) => detailRowNavProps('target-group-detail', item.id)}
            empty={<EmptyState icon={Target} title="No declared surfaces yet." body="Coverage appears after target groups are declared and validated." actionLabel="Open target groups" actionHref="#target-groups" />}
          />
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Export formats</CardTitle>
          <CardDescription>Export this report as JSON, Markdown, or HTML. JSON exports include custody manifests for verification.</CardDescription>
        </CardHeader>
        <CardContent className="stack-tight">
          <div className="row-actions">
            <Button size="sm" variant="secondary" loading={busy === `export-${entityId}-json`} disabled={busy !== ''} onClick={() => void exportReport(entityId, 'json')}>Export JSON</Button>
            <Button size="sm" variant="secondary" loading={busy === `export-${entityId}-markdown`} disabled={busy !== ''} onClick={() => void exportReport(entityId, 'markdown')}>Export Markdown</Button>
            <Button size="sm" variant="secondary" loading={busy === `export-${entityId}-html`} disabled={busy !== ''} onClick={() => void exportReport(entityId, 'html')}>Export HTML</Button>
            <AnchorButton size="sm" variant="ghost" href="#reports">Back to reports</AnchorButton>
          </div>
          {/*
            PDF export is intentionally out of scope for this slice: backend `src/services/reports.mjs`
            supports json|markdown|html only. Immutable PDF rendering and signing remain a release-gate boundary.
          */}
          <p className="muted">PDF export is not available in this slice; backend report exports support JSON, Markdown, and HTML only.</p>
        </CardContent>
      </Card>
      </>
      )}
    </div>
  );
}
