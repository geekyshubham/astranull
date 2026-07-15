import {
  Activity,
  Bell,
  Bot,
  CalendarClock,
  ClipboardList,
  CreditCard,
  FileText,
  Gauge,
  KeyRound,
  LifeBuoy,
  LayoutDashboard,
  ListChecks,
  LockKeyhole,
  PlugZap,
  ServerCog,
  ShieldCheck,
  Target,
  TriangleAlert,
  UserCog
} from 'lucide-react';
import type { NavItem, RouteId, SurfaceKind } from './types';

export const NAV_GROUP_LABELS: Record<SurfaceKind, string> = {
  overview: 'Overview',
  scope: 'Declared scope',
  validation: 'Validation',
  governance: 'Governance',
  staff: 'Staff'
};

/** Fifteen customer-visible sidebar items + two staff items (detail routes omitted). */
export const NAV_ITEMS: NavItem[] = [
  {
    id: 'dashboard',
    label: 'Dashboard',
    group: 'overview',
    description: 'Readiness score, coverage, vectors, findings, and SOC status.',
    icon: LayoutDashboard
  },
  {
    id: 'environments',
    label: 'Environments',
    group: 'scope',
    description: 'Declared environment IDs with validation evidence, findings, and active scope counts.',
    icon: ServerCog
  },
  {
    id: 'target-groups',
    label: 'Target groups',
    group: 'scope',
    description: 'Customer-declared business services, expected behavior, and owners.',
    icon: Target
  },
  {
    id: 'agents',
    label: 'Agents',
    group: 'scope',
    description: 'Outbound-only observation agents, placement, versions, and health.',
    icon: Bot
  },
  {
    id: 'checks',
    label: 'Checks',
    group: 'validation',
    description: 'Safe-by-default readiness checks and SOC-gated high-scale scenarios.',
    icon: ListChecks
  },
  {
    id: 'test-policies',
    label: 'Scheduler',
    group: 'validation',
    description: 'Scheduled validation cadences, safe windows, and target bindings. Each schedule declares when bounded checks run and the verdict they expect. High-scale scenarios stay SOC-scheduled.',
    icon: CalendarClock
  },
  {
    id: 'runs',
    label: 'Test runs',
    group: 'validation',
    description: 'Execution timeline, probe results, agent observations, and verdicts.',
    icon: Activity
  },
  {
    id: 'findings',
    label: 'Findings',
    group: 'validation',
    description: 'Evidence-backed gaps, owners, SLAs, and remediation status.',
    icon: TriangleAlert
  },
  {
    id: 'reports',
    label: 'Reports',
    group: 'governance',
    description: 'Executive, technical, SOC, audit, release, and WAF report builders.',
    icon: FileText
  },
  {
    id: 'integrations',
    label: 'Integrations',
    group: 'governance',
    description: 'Notification, ticketing, SIEM, SOAR, and optional read-only provider connectors.',
    icon: PlugZap
  },
  {
    id: 'notifications',
    label: 'Notifications',
    group: 'governance',
    description: 'Safe in-app rules, provider status, retries, and DLQ recovery.',
    icon: Bell
  },
  {
    id: 'audit',
    label: 'Audit log',
    group: 'governance',
    description: 'Tenant actions, security-relevant changes, and custody chain records.',
    icon: ClipboardList
  },
  {
    id: 'release-evidence',
    label: 'Release evidence',
    group: 'governance',
    description: 'Production release evidence coverage, gap ledger, and staging attestation.',
    icon: FileText
  },
  {
    id: 'settings',
    label: 'Settings',
    group: 'governance',
    description: 'Tenant profile, roles, tokens, retention, SSO, and safe defaults.',
    icon: KeyRound
  },
  {
    id: 'support',
    label: 'Support',
    group: 'governance',
    description: 'Support readiness, escalation paths, runbook references, and non-production on-call posture.',
    icon: LifeBuoy
  },
  {
    id: 'subscription',
    label: 'Billing',
    group: 'governance',
    description: 'Plan, entitlements, limits, billing state, contract references, and effective dates.',
    icon: CreditCard
  },
  {
    id: 'admin',
    label: 'Admin console',
    group: 'staff',
    description: 'Internal overview for sign-ups, tenant lifecycle, approvals, support, and internal audit.',
    icon: UserCog
  },
  {
    id: 'internal-soc',
    label: 'SOC console',
    group: 'staff',
    description: 'Dedicated staff SOC execution plane with kill switch, Go/No-Go checklist, provider contacts, and timeline.',
    icon: Gauge
  }
];

/** Detail routes reachable via deep-link but hidden from the sidebar. */
export const DETAIL_ROUTE_ITEMS: NavItem[] = [
  {
    id: 'environment-detail',
    label: 'Environment detail',
    group: 'scope',
    description: 'Declared environment scope, agents, target groups, validation evidence, and findings.',
    icon: ServerCog
  },
  {
    id: 'check-detail',
    label: 'Check detail',
    group: 'validation',
    description: 'Vector family, safety mode, bounds, expected behavior, and recent verdicts for one check.',
    icon: ListChecks
  },
  {
    id: 'policy-detail',
    label: 'Policy detail',
    group: 'validation',
    description: 'Cadence, target bindings, expected verdicts, safe windows, and high-scale gating for one policy.',
    icon: ClipboardList
  },
  {
    id: 'target-group-detail',
    label: 'Target group detail',
    group: 'scope',
    description: 'Ownership ladder, DNS TXT, declared targets, findings, and runs for one group.',
    icon: Target
  },
  {
    id: 'target-detail',
    label: 'Target detail',
    group: 'scope',
    description: 'Per-target checks, runs, findings, WAF posture, and verification ladder.',
    icon: Target
  },
  {
    id: 'agent-detail',
    label: 'Agent detail',
    group: 'scope',
    description: 'Identity, heartbeat, capabilities, placement evidence, logs, and update history for one outbound agent.',
    icon: Bot
  },
  {
    id: 'run-detail',
    label: 'Run detail',
    group: 'validation',
    description: 'Timeline, probe result, agent observation, correlation truth table, and evidence chain for one run.',
    icon: Activity
  },
  {
    id: 'finding-detail',
    label: 'Finding detail',
    group: 'validation',
    description: 'Verdict explanation, triage state, remediation, evidence bundle, and custody export for one finding.',
    icon: TriangleAlert
  },
  {
    id: 'evidence-detail',
    label: 'Evidence detail',
    group: 'validation',
    description: 'Artifact record, custody chain position, SHA-256 digest, and sealed payload for one evidence artifact.',
    icon: ShieldCheck
  },
  {
    id: 'report-detail',
    label: 'Report detail',
    group: 'governance',
    description: 'Report kind, custody preview, export formats, and digest verification for one generated report.',
    icon: FileText
  },
  {
    id: 'tenant-detail',
    label: 'Tenant detail',
    group: 'staff',
    description: 'Tenant lifecycle, users, entitlements, notes, support actions, subscriptions, and audit activity.',
    icon: UserCog
  },
  {
    id: 'queue-detail',
    label: 'Queue detail',
    group: 'staff',
    description: 'SOC execution workspace with queue context, artifacts, adapter telemetry, and notes for one request.',
    icon: ShieldCheck
  }
];

export const ROUTE_BY_ID = new Map<RouteId, NavItem>(
  [...NAV_ITEMS, ...DETAIL_ROUTE_ITEMS].map((item) => [item.id, item])
);

function routeIdFromHash(hash: string): RouteId | null {
  const raw = hash.replace(/^#/, '');
  const routePart = raw.includes('?') ? raw.slice(0, raw.indexOf('?')) : raw;
  return ROUTE_BY_ID.has(routePart as RouteId) ? routePart as RouteId : null;
}

export function getRouteFromHash(): RouteId {
  return routeIdFromHash(window.location.hash) ?? 'dashboard';
}

export function getRouteFromLocation(): RouteId {
  const hashRoute = routeIdFromHash(window.location.hash);
  if (hashRoute) return hashRoute;
  const pathRoute = window.location.pathname.replace(/^\/+/, '').replace(/\/+$/, '');
  if (window.location.pathname === '/internal/admin') return 'admin';
  if (window.location.pathname === '/internal/soc') return 'internal-soc';
  if (pathRoute === 'internal-soc.html') return 'internal-soc';
  if (pathRoute === 'index.html') return 'dashboard';
  const normalizedPathRoute = pathRoute.endsWith('.html') ? pathRoute.slice(0, -5) : pathRoute;
  if (ROUTE_BY_ID.has(normalizedPathRoute as RouteId)) return normalizedPathRoute as RouteId;
  if (ROUTE_BY_ID.has(pathRoute as RouteId)) return pathRoute as RouteId;
  if (pathRoute === 'app' || pathRoute === '') return 'dashboard';
  return 'dashboard';
}

export const PLATFORM_PROMISE =
  'AstraNull proves DDoS readiness for customer-declared targets without requiring cloud credentials or automatic IP inventory discovery.';

export const DEFENSIVE_RULES = [
  {
    title: 'No-access-first',
    body: 'Core workflows start from customer-declared targets and do not require cloud credentials.'
  },
  {
    title: 'Outbound-only agents',
    body: 'Agents call AstraNull over outbound HTTPS; no inbound management ports are required.'
  },
  {
    title: 'SOC-gated high-scale',
    body: 'Customers request high-scale validation; SOC approves, schedules, coordinates, stops, and closes.'
  },
  {
    title: 'Evidence over assumptions',
    body: 'Every verdict links back to observed probe data, agent observations, health signals, approvals, or declarations.'
  }
];

export const STAFF_LINKS = [
  {
    label: 'Internal Admin',
    href: '/internal/admin',
    icon: LockKeyhole,
    description: 'Staff-only tenant, sign-up, support, and approval management.'
  },
  {
    label: 'SOC console',
    href: '/internal/soc',
    icon: Gauge,
    description: 'Staff execution plane for governed high-scale operations.'
  }
];