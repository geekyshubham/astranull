import type { RouteId, SurfaceKind } from './types';

export type PrototypeSurface = {
  id: string;
  label: string;
  route: string;
  routeId?: string;
  audience: 'Public' | 'Customer' | 'Staff' | 'SOC' | 'Operator';
  group: SurfaceKind | 'public' | 'operator';
  source: string;
  status: 'React implemented' | 'Backend/API backed' | 'Operator workflow' | 'Intentional boundary';
  summary: string;
};

export type PageTab = {
  id: string;
  label: string;
  summary: string;
  evidence: string;
};

export type FeatureItem = {
  name: string;
  surface: string;
  status: 'Visible' | 'Partial' | 'API-backed' | 'Operator-only' | 'Staff-only' | 'By design hidden';
  relationship: string;
};

export type FeatureGroup = {
  id: string;
  title: string;
  summary: string;
  items: FeatureItem[];
};

export type RelationshipFlow = {
  title: string;
  steps: string[];
  outcome: string;
};

export const PROTOTYPE_PROJECT = {
  id: 'c2cc0262-cba8-47ed-a941-3b02fcaf8159',
  name: 'AstraNull',
  source: '/Users/checkred_admin/Library/Application Support/Open Design/namespaces/release-stable/data/projects/c2cc0262-cba8-47ed-a941-3b02fcaf8159',
  designSystem: [
    'Geist and Geist Mono typography',
    'White surfaces, black primary actions, restrained semantic status color',
    'shadcn-style cards, badges, tabs, tables, buttons, progress, and form controls',
    'Sticky sidebar plus topbar shell with responsive drawer behavior',
    'Evidence-first empty states, custody previews, and approval language'
  ]
};

export const PROTOTYPE_SURFACES: PrototypeSurface[] = [
  {
    id: 'public-landing',
    label: 'Public Landing',
    route: '/',
    routeId: 'dashboard',
    audience: 'Public',
    group: 'public',
    source: 'landing.html',
    status: 'React implemented',
    summary: 'Positioning, no-access-first promise, public entry actions, and safety framing.'
  },
  {
    id: 'signup',
    label: 'Sign-up Intake',
    route: '/signup',
    audience: 'Public',
    group: 'public',
    source: 'signup.html',
    status: 'React implemented',
    summary: 'Reviewed access request form with high-scale interest captured as a governed signal.'
  },
  {
    id: 'signup-status',
    label: 'Sign-up Status',
    route: '/signup-status',
    audience: 'Public',
    group: 'public',
    source: 'signup-status.html',
    status: 'React implemented',
    summary: 'Request status lookup surface for public account intake.'
  },
  {
    id: 'login',
    label: 'Customer Login',
    route: '/login',
    audience: 'Public',
    group: 'public',
    source: 'login.html',
    status: 'React implemented',
    summary: 'Customer portal entry that supports local dev headers and bundled staging sessions.'
  },
  {
    id: 'staff-login',
    label: 'Staff Login',
    route: '/internal/admin/login',
    audience: 'Staff',
    group: 'staff',
    source: 'staff-login.html',
    status: 'React implemented',
    summary: 'Staff entry into internal management and SOC-only surfaces.'
  },
  {
    id: 'customer-shell',
    label: 'Customer Portal Shell',
    route: '/app',
    routeId: 'dashboard',
    audience: 'Customer',
    group: 'overview',
    source: 'index.html',
    status: 'React implemented',
    summary: 'Single React host for the authenticated portal and product route aliases.'
  },
  {
    id: 'dashboard',
    label: 'Dashboard',
    route: '/dashboard',
    routeId: 'dashboard',
    audience: 'Customer',
    group: 'overview',
    source: 'dashboard.html',
    status: 'React implemented',
    summary: 'Readiness score, vectors, target coverage, recent evidence, and governance summary.'
  },
  {
    id: 'onboarding',
    label: 'Onboarding',
    route: '/onboarding',
    routeId: 'onboarding',
    audience: 'Customer',
    group: 'overview',
    source: 'onboarding.html',
    status: 'React implemented',
    summary: 'Guided first environment, target group, outbound agent, heartbeat, safe run, and evidence review.'
  },
  {
    id: 'environments',
    label: 'Environments',
    route: '/environments',
    routeId: 'environments',
    audience: 'Customer',
    group: 'scope',
    source: 'environments.html',
    status: 'React implemented',
    summary: 'Environment IDs from active target groups with validation evidence, findings, and coverage.'
  },
  {
    id: 'target-groups',
    label: 'Target Groups',
    route: '/target-groups',
    routeId: 'target-groups',
    audience: 'Customer',
    group: 'scope',
    source: 'target-groups.html',
    status: 'React implemented',
    summary: 'Customer-declared business services, target rows, expected behavior, checks, runs, findings, and settings.'
  },
  {
    id: 'target-group-detail',
    label: 'Target Group Detail',
    route: '/target-group-detail',
    routeId: 'target-group-detail',
    audience: 'Customer',
    group: 'scope',
    source: 'target-group-detail.html',
    status: 'React implemented',
    summary: 'Per-service deep view for targets, behavior, agents, checks, runs, findings, and audit-safe settings.'
  },
  {
    id: 'agents',
    label: 'Agents',
    route: '/agents',
    routeId: 'agents',
    audience: 'Customer',
    group: 'scope',
    source: 'agents.html',
    status: 'React implemented',
    summary: 'Install commands, outbound-only fleet status, placement, capabilities, logs, and upgrade posture.'
  },
  {
    id: 'agent-detail',
    label: 'Agent Detail',
    route: '/agent-detail',
    routeId: 'agent-detail',
    audience: 'Customer',
    group: 'scope',
    source: 'agent-detail.html',
    status: 'React implemented',
    summary: 'One agent identity, heartbeat, placement confidence, capabilities, logs, and update history.'
  },
  {
    id: 'checks',
    label: 'Checks Library',
    route: '/checks',
    routeId: 'checks',
    audience: 'Customer',
    group: 'validation',
    source: 'checks.html',
    status: 'React implemented',
    summary: 'Recommended checks, origin bypass, L3/L4, DNS, L7/API, protocol, high-scale, and custom coverage.'
  },
  {
    id: 'test-policies',
    label: 'Test Policies',
    route: '/test-policies',
    routeId: 'test-policies',
    audience: 'Customer',
    group: 'validation',
    source: 'test-policies.html',
    status: 'React implemented',
    summary: 'Cadence, declared target bindings, expected verdicts, windows, and safe-by-default policy cards.'
  },
  {
    id: 'runs',
    label: 'Test Runs',
    route: '/runs',
    routeId: 'runs',
    audience: 'Customer',
    group: 'validation',
    source: 'runs.html',
    status: 'React implemented',
    summary: 'Run list, summary, timeline, probe results, agent observations, correlation, evidence, and event review.'
  },
  {
    id: 'run-detail',
    label: 'Run Detail',
    route: '/run-detail',
    routeId: 'run-detail',
    audience: 'Customer',
    group: 'validation',
    source: 'run-detail.html',
    status: 'React implemented',
    summary: 'Verdict explanation, timeline, truth table, evidence chain, and safe-run context.'
  },
  {
    id: 'findings',
    label: 'Findings',
    route: '/findings',
    routeId: 'findings',
    audience: 'Customer',
    group: 'validation',
    source: 'findings.html',
    status: 'React implemented',
    summary: 'Open, grouped, accepted-risk, closed, SLA, why-this-finding, export, and retest workflow.'
  },
  {
    id: 'evidence',
    label: 'Evidence Vault',
    route: '/evidence',
    routeId: 'evidence',
    audience: 'Customer',
    group: 'validation',
    source: 'evidence.html',
    status: 'React implemented',
    summary: 'Evidence ledger, custody-safe exports, source material, and reporting links.'
  },
  {
    id: 'waf-posture',
    label: 'WAF Posture',
    route: '/waf-posture',
    routeId: 'waf-posture',
    audience: 'Customer',
    group: 'validation',
    source: 'waf-posture.html',
    status: 'React implemented',
    summary: 'WAF assets, roadmap, scenario cadence, drift, connectors, validation plans, reports, and evidence.'
  },
  {
    id: 'waf-asset-detail',
    label: 'WAF Asset Detail',
    route: '/waf-asset-detail',
    routeId: 'waf-asset-detail',
    audience: 'Customer',
    group: 'validation',
    source: 'waf-asset-detail.html',
    status: 'React implemented',
    summary: 'Per-asset effectiveness, rules, geography, drift, exceptions, validation runs, and actions.'
  },
  {
    id: 'cve-pipeline',
    label: 'CVE Pipeline',
    route: '/cve-pipeline',
    routeId: 'cve-pipeline',
    audience: 'Customer',
    group: 'validation',
    source: 'cve-pipeline.html',
    status: 'React implemented',
    summary: 'Live exposure intake, triage, matches, recommendations, staged mitigations, retests, and playbooks.'
  },
  {
    id: 'supply-chain',
    label: 'Supply Chain',
    route: '/supply-chain',
    routeId: 'supply-chain',
    audience: 'Customer',
    group: 'validation',
    source: 'supply-chain.html',
    status: 'React implemented',
    summary: 'CNAME, dependency, vendor, redirect, and subdomain risk categories with custody-safe remediation.'
  },
  {
    id: 'remediation',
    label: 'Remediation',
    route: '/remediation',
    routeId: 'remediation',
    audience: 'Customer',
    group: 'validation',
    source: 'remediation.html',
    status: 'React implemented',
    summary: 'Action items, ticket previews, SIEM/SOAR-safe delivery, retests, and closure evidence.'
  },
  {
    id: 'discovery',
    label: 'Discovery',
    route: '/discovery',
    routeId: 'discovery',
    audience: 'Customer',
    group: 'validation',
    source: 'discovery.html',
    status: 'React implemented',
    summary: 'Approval-gated candidates, modes, sources, decisions, and imports into declared target groups.'
  },
  {
    id: 'discovery-entity',
    label: 'Discovery Entity',
    route: '/discovery-entity',
    routeId: 'discovery-entity',
    audience: 'Customer',
    group: 'validation',
    source: 'discovery-entity.html',
    status: 'React implemented',
    summary: 'Entity source evidence, confidence, decision trail, promote, and dismiss workflow.'
  },
  {
    id: 'high-scale',
    label: 'High-Scale Requests',
    route: '/high-scale',
    routeId: 'high-scale',
    audience: 'Customer',
    group: 'governance',
    source: 'high-scale.html',
    status: 'React implemented',
    summary: 'Customer request form, authorization pack, window, contacts, provider approval, and post-test custody.'
  },
  {
    id: 'soc',
    label: 'SOC Console',
    route: '/soc',
    routeId: 'soc',
    audience: 'SOC',
    group: 'governance',
    source: 'soc.html',
    status: 'React implemented',
    summary: 'SOC queue, go/no-go checklist, kill switch, lifecycle actions, provider contacts, and notes.'
  },
  {
    id: 'reports',
    label: 'Reports',
    route: '/reports',
    routeId: 'reports',
    audience: 'Customer',
    group: 'governance',
    source: 'reports.html',
    status: 'React implemented',
    summary: 'Executive, technical, SOC, audit, WAF, release, and custody-oriented report builders.'
  },
  {
    id: 'integrations',
    label: 'Integrations',
    route: '/integrations',
    routeId: 'integrations',
    audience: 'Customer',
    group: 'governance',
    source: 'integrations.html',
    status: 'React implemented',
    summary: 'Notification, ticketing, SIEM/SOAR, and optional read-only provider connectors.'
  },
  {
    id: 'notifications',
    label: 'Notifications',
    route: '/notifications',
    routeId: 'notifications',
    audience: 'Customer',
    group: 'governance',
    source: 'notifications.html',
    status: 'React implemented',
    summary: 'Rules, events, provider state, retry, and DLQ recovery controls with metadata-only outputs.'
  },
  {
    id: 'audit',
    label: 'Audit Log',
    route: '/audit',
    routeId: 'audit',
    audience: 'Customer',
    group: 'governance',
    source: 'audit.html',
    status: 'React implemented',
    summary: 'Tenant audit table, filters, custody activity, and security-relevant changes.'
  },
  {
    id: 'release-evidence',
    label: 'Release Evidence',
    route: '/release-evidence',
    routeId: 'release-evidence',
    audience: 'Customer',
    group: 'governance',
    source: 'release-evidence.html',
    status: 'React implemented',
    summary: 'Staging attestation, required evidence kinds, gap ledger, bundles, and launch-gate status.'
  },
  {
    id: 'settings',
    label: 'Settings',
    route: '/settings',
    routeId: 'settings',
    audience: 'Customer',
    group: 'governance',
    source: 'settings.html',
    status: 'React implemented',
    summary: 'Organization, users, roles, API keys, SSO/SAML, notifications, integrations, retention, and audit links.'
  },
  {
    id: 'support',
    label: 'Support',
    route: '/support',
    routeId: 'support',
    audience: 'Customer',
    group: 'governance',
    source: 'support.html',
    status: 'React implemented',
    summary: 'Support readiness, runbook references, escalation, and custody-safe support notes.'
  },
  {
    id: 'subscription',
    label: 'Subscription',
    route: '/subscription',
    routeId: 'subscription',
    audience: 'Customer',
    group: 'governance',
    source: 'subscription.html',
    status: 'React implemented',
    summary: 'Plan, entitlements, limits, billing state, contract references, and effective dates.'
  },
  {
    id: 'admin',
    label: 'Admin Console',
    route: '/admin',
    routeId: 'admin',
    audience: 'Staff',
    group: 'staff',
    source: 'admin.html',
    status: 'React implemented',
    summary: 'Staff overview, sign-up queue, tenant lifecycle, approvals, support operations, and internal audit.'
  },
  {
    id: 'tenant-detail',
    label: 'Tenant Detail',
    route: '/tenant-detail',
    routeId: 'tenant-detail',
    audience: 'Staff',
    group: 'staff',
    source: 'tenant-detail.html',
    status: 'React implemented',
    summary: 'Tenant state, users, entitlements, support notes, subscriptions, and audit activity.'
  },
  {
    id: 'internal-soc',
    label: 'Internal SOC',
    route: '/internal/soc',
    routeId: 'internal-soc',
    audience: 'SOC',
    group: 'staff',
    source: 'internal-soc.html',
    status: 'React implemented',
    summary: 'Dedicated staff SOC plane for governed high-scale reviews, scheduling, kill switch, and closure.'
  },
  {
    id: 'probe-worker',
    label: 'Probe Worker',
    route: 'workers/probe-worker.mjs',
    audience: 'Operator',
    group: 'operator',
    source: 'workers/probe-worker.mjs',
    status: 'Operator workflow',
    summary: 'Leased metadata-only probe worker hidden from customer UI by design.'
  },
  {
    id: 'linux-agent',
    label: 'Linux Agent Package',
    route: 'agents/linux/*',
    audience: 'Operator',
    group: 'operator',
    source: 'agents/linux',
    status: 'Operator workflow',
    summary: 'Outbound-only agent install, systemd, Docker, Helm, update, and verification workflows.'
  }
];

export const PAGE_TAB_SETS: Partial<Record<RouteId, PageTab[]>> = {
  dashboard: [
    { id: 'overview', label: 'Overview', summary: 'Readiness score, open gaps, and current operating state.', evidence: 'Readiness factors, findings, runs, and WAF summary.' },
    { id: 'risk-trends', label: 'Risk trends', summary: 'Score trend, vector coverage, and aging finding pressure.', evidence: 'Run and finding history.' }
  ],
  'target-groups': [
    { id: 'overview', label: 'Overview', summary: 'Declared target groups with readiness and owner context.', evidence: 'Customer-provided scope declaration.' },
    { id: 'targets', label: 'Targets', summary: 'Manual or CSV/API-imported targets only.', evidence: 'Declared targets and explicit expected behavior.' },
    { id: 'expected-behavior', label: 'Expected Behavior', summary: 'Expected paths, health signals, and protective baseline.', evidence: 'Customer declaration and observed safe checks.' },
    { id: 'agents', label: 'Agents', summary: 'Outbound observers bound to declared scope.', evidence: 'Agent heartbeat and placement confidence.' },
    { id: 'checks', label: 'Checks', summary: 'Safe check bindings and coverage.', evidence: 'Check catalog and policy bindings.' },
    { id: 'runs', label: 'Runs', summary: 'Recent safe validation activity.', evidence: 'Run timeline and verdicts.' },
    { id: 'findings', label: 'Findings', summary: 'Open and closed gaps for this group.', evidence: 'Finding custody references.' },
    { id: 'settings', label: 'Settings', summary: 'Archive, owners, windows, and safety policy.', evidence: 'Audited tenant action.' }
  ],
  agents: [
    { id: 'install', label: 'Install', summary: 'Bootstrap-token install commands for Linux, Docker, and Kubernetes.', evidence: 'One-time token issuance and install proof.' },
    { id: 'fleet', label: 'Fleet', summary: 'Online, stale, and versioned agent inventory.', evidence: 'Outbound heartbeat and agent records.' },
    { id: 'health', label: 'Health', summary: 'Heartbeat freshness, gateway trust, and diagnostic state.', evidence: 'Agent health and mTLS gateway evidence.' },
    { id: 'placement', label: 'Placement', summary: 'Confidence that the agent observes the right traffic path.', evidence: 'Canary and placement diagnostics.' },
    { id: 'capabilities', label: 'Capabilities', summary: 'Supported observation and metadata signals.', evidence: 'Agent capability report.' },
    { id: 'logs', label: 'Logs', summary: 'Audit-safe operational log summaries.', evidence: 'Metadata-only event references.' },
    { id: 'upgrades', label: 'Upgrades', summary: 'Version rollout, rollback, and package provenance.', evidence: 'SBOM and release evidence.' }
  ],
  checks: [
    { id: 'recommended', label: 'Recommended', summary: 'Starter checks based on declared service context.', evidence: 'Check catalog safety class and target bindings.' },
    { id: 'origin-bypass', label: 'Origin Bypass', summary: 'Bounded origin protection checks.', evidence: 'Probe metadata and agent observation.' },
    { id: 'l3l4', label: 'L3/L4', summary: 'Low-volume TCP and reachability validation families.', evidence: 'Bounded probe results.' },
    { id: 'dns', label: 'DNS', summary: 'Resolver and delegation readiness checks.', evidence: 'DNS lookup metadata.' },
    { id: 'l7api', label: 'L7/API', summary: 'Safe application path and API posture checks.', evidence: 'HEAD/marker observations without sensitive content.' },
    { id: 'protocols', label: 'Protocols', summary: 'TLS and protocol hygiene checks.', evidence: 'Handshake and metadata observations.' },
    { id: 'high-scale', label: 'High-Scale', summary: 'Request-only scenarios that require SOC governance.', evidence: 'Authorization pack and SOC decision artifacts.' },
    { id: 'custom', label: 'Custom', summary: 'Customer-defined safe checks bound to declarations.', evidence: 'Policy record and reviewed scope.' }
  ],
  'test-policies': [
    { id: 'cadence', label: 'Cadence', summary: 'Daily, weekly, monthly, and event-driven safe validation windows.', evidence: 'Policy schedule and target binding.' },
    { id: 'bindings', label: 'Target Bindings', summary: 'Policies bind only to declared target groups.', evidence: 'Declared target-group reference.' },
    { id: 'expected-verdicts', label: 'Expected Verdicts', summary: 'Expected pass, warn, or fail behavior for each safe check.', evidence: 'Customer declaration and check contract.' },
    { id: 'windows', label: 'Safe Windows', summary: 'Local maintenance and observation windows.', evidence: 'Policy record and audit.' },
    { id: 'guardrails', label: 'Guardrails', summary: 'Low-volume and bounded validation settings.', evidence: 'Safe test policy enforcement.' },
    { id: 'soc-gates', label: 'SOC Gates', summary: 'High-scale policies remain request-only for customers.', evidence: 'Authorization and SOC decision artifacts.' }
  ],
  runs: [
    { id: 'summary', label: 'Summary', summary: 'Current verdict, target group, check family, and guardrail state.', evidence: 'Run record and policy snapshot.' },
    { id: 'timeline', label: 'Timeline', summary: 'Ordered run lifecycle from scheduling through final verdict.', evidence: 'Run events and audit entries.' },
    { id: 'probe-results', label: 'Probe Results', summary: 'Outside observations from bounded probes.', evidence: 'Probe result records.' },
    { id: 'agent-observations', label: 'Agent Observations', summary: 'Inside observations from outbound-only canaries.', evidence: 'Agent observation records.' },
    { id: 'correlation', label: 'Correlation', summary: 'Truth table explaining why the verdict was assigned.', evidence: 'Observed facts and correlation logic.' },
    { id: 'evidence', label: 'Evidence', summary: 'Custody-ready artifacts generated by the run.', evidence: 'Evidence ledger references.' },
    { id: 'events', label: 'Raw Events', summary: 'Sanitized event envelope review for support and audit.', evidence: 'Redacted event metadata.' }
  ],
  findings: [
    { id: 'open', label: 'Open', summary: 'Unresolved gaps with severity and owner.', evidence: 'Finding records and run evidence.' },
    { id: 'target-group', label: 'By Target Group', summary: 'Group findings by declared business service.', evidence: 'Target group mapping.' },
    { id: 'vector', label: 'By Vector', summary: 'Group findings by vector family and safety class.', evidence: 'Check catalog and verdict.' },
    { id: 'accepted-risk', label: 'Accepted Risk', summary: 'Owner-approved exceptions with expiry.', evidence: 'Accepted-risk artifact and audit entry.' },
    { id: 'closed', label: 'Closed', summary: 'Resolved findings with closure evidence.', evidence: 'Retest or explicit closure record.' },
    { id: 'sla', label: 'SLA', summary: 'Due dates, owner aging, and escalation state.', evidence: 'Finding timeline.' }
  ],
  reports: [
    { id: 'builder', label: 'Builder', summary: 'Report kind, period, audience, and included evidence.', evidence: 'Report request.' },
    { id: 'executive', label: 'Executive', summary: 'Readiness and business-risk summary.', evidence: 'Readiness score and findings.' },
    { id: 'technical', label: 'Technical', summary: 'Run details, vectors, and remediation context.', evidence: 'Run and finding evidence.' },
    { id: 'soc', label: 'SOC', summary: 'High-scale authorization, schedule, and post-test summary.', evidence: 'SOC artifacts.' },
    { id: 'audit', label: 'Audit', summary: 'Custody, controls, and security-relevant action trail.', evidence: 'Audit entries and evidence ledger.' },
    { id: 'custody', label: 'Custody', summary: 'Digest references and export manifest.', evidence: 'Custody manifest.' },
    { id: 'waf', label: 'WAF', summary: 'Coverage, drift, connector health, and roadmap.', evidence: 'WAF reports and snapshots.' }
  ],
  notifications: [
    { id: 'rules', label: 'Rules', summary: 'In-app, email, chat, webhook, and owner routing rules.', evidence: 'Notification rule records.' },
    { id: 'events', label: 'Events', summary: 'Recent delivery and event state.', evidence: 'Notification event records.' },
    { id: 'providers', label: 'Providers', summary: 'Credential status and configuration evidence.', evidence: 'Provider metadata.' },
    { id: 'retry', label: 'Retry', summary: 'Safe retry preview and due-work processing.', evidence: 'Retry queue metadata.' },
    { id: 'dlq', label: 'DLQ', summary: 'Dead-letter redrive with redacted output.', evidence: 'DLQ metadata.' }
  ],
  audit: [
    { id: 'tenant-audit', label: 'Tenant Audit', summary: 'Tenant-scoped security and custody activity.', evidence: 'Audit log records.' },
    { id: 'filters', label: 'Filters', summary: 'Actor, action, object, and time filters.', evidence: 'Audit query context.' },
    { id: 'exports', label: 'Exports', summary: 'Auditor-friendly export and report links.', evidence: 'Custody export references.' }
  ],
  settings: [
    { id: 'organization', label: 'Organization', summary: 'Tenant profile, environments, support owner, and residency.', evidence: 'Tenant record.' },
    { id: 'users-roles', label: 'Users & Roles', summary: 'User access and permission model.', evidence: 'Role contracts and audit.' },
    { id: 'api-keys', label: 'API Keys', summary: 'Service accounts, bootstrap tokens, revoke, and rotate.', evidence: 'Token and service-account records.' },
    { id: 'sso', label: 'SSO/SAML', summary: 'Enterprise OIDC/JWKS posture with production-safe defaults.', evidence: 'Auth configuration.' },
    { id: 'notifications', label: 'Notifications', summary: 'Default routing and provider links.', evidence: 'Notification rule records.' },
    { id: 'integrations', label: 'Integrations', summary: 'Optional connectors and remediation delivery.', evidence: 'Connector and secret metadata.' },
    { id: 'retention', label: 'Data Retention', summary: 'Retention days, purge state, and privacy controls.', evidence: 'Retention policy record.' },
    { id: 'audit', label: 'Audit Log', summary: 'Settings changes and security-sensitive events.', evidence: 'Audit trail.' }
  ],
  admin: [
    { id: 'overview', label: 'Overview', summary: 'Staff metrics, pending sign-ups, approvals, and support posture.', evidence: 'Internal management API.' },
    { id: 'signup-queue', label: 'Sign-up Queue', summary: 'Approve, reject, request info, and provision tenant.', evidence: 'Signup request record.' },
    { id: 'tenants', label: 'Tenants', summary: 'Tenant lifecycle, status, plan, users, and support actions.', evidence: 'Tenant detail record.' },
    { id: 'approvals', label: 'Approvals', summary: 'Internal approval queue and decision ledger.', evidence: 'Approval record.' },
    { id: 'audit', label: 'Internal Audit', summary: 'Staff actions and management-plane audit.', evidence: 'Internal audit log.' }
  ],
  'internal-soc': [
    { id: 'queue', label: 'Queue', summary: 'High-scale requests requiring SOC review.', evidence: 'Request and authorization pack.' },
    { id: 'authorization', label: 'Authorization', summary: 'Go/no-go checklist, provider contacts, legal proof, and runbook state.', evidence: 'Accepted authorization artifacts.' },
    { id: 'schedule', label: 'Schedule', summary: 'Approved window and coordination state.', evidence: 'SOC schedule action.' },
    { id: 'live-run', label: 'Live Run', summary: 'Lifecycle status, notes, telemetry summary, and kill switch.', evidence: 'SOC-controlled events.' },
    { id: 'closeout', label: 'Closeout', summary: 'Post-test report, stop state, and closure evidence.', evidence: 'Post-test report and audit.' }
  ]
};

export const DETAIL_TAB_SETS: Partial<Record<RouteId, PageTab[]>> = {
  'target-detail': [
    { id: 'overview', label: 'Overview', summary: 'Per-target verification, WAF posture, and counts.', evidence: 'GET /v1/targets/:id hydrator.' },
    { id: 'ownership', label: 'Ownership', summary: 'Verification ladder and DNS/agent state.', evidence: 'target_verifications rows.' },
    { id: 'findings', label: 'Findings', summary: 'Open and closed findings on this target.', evidence: 'findings filtered by target_id.' }
  ],
  'finding-detail': [
    { id: 'overview', label: 'Overview', summary: 'Severity, status, and verdict explanation.', evidence: 'Finding detail API.' },
    { id: 'remediation', label: 'Remediation', summary: 'Owner, SLA, steps, and delivery state.', evidence: 'Remediation contract fields.' },
    { id: 'evidence', label: 'Evidence', summary: 'Bundle artifacts and custody chain.', evidence: 'Finding evidence hydrator.' }
  ],
  'queue-detail': [
    { id: 'overview', label: 'Overview', summary: 'SOC-gated request lifecycle and authorization pack.', evidence: 'High-scale request API.' },
    { id: 'artifacts', label: 'Artifacts', summary: 'Metadata-only authorization artifacts.', evidence: 'Artifact ledger.' },
    { id: 'notes', label: 'Notes', summary: 'SOC execution notes thread.', evidence: 'SOC notes API.' }
  ],
  'target-group-detail': [
    { id: 'overview', label: 'Overview', summary: 'Readiness, runs, and declaration metadata for this service.', evidence: 'Target group detail API.' },
    { id: 'scope', label: 'Scope & behavior', summary: 'Declared targets and expected protection behavior.', evidence: 'Customer-provided scope declaration.' },
    { id: 'validation', label: 'Validation', summary: 'Policies, runs, and findings for this group.', evidence: 'Run and finding records.' },
    { id: 'agents', label: 'Agents', summary: 'Outbound observers bound to this group.', evidence: 'Agent heartbeat records.' },
    { id: 'settings', label: 'Settings', summary: 'Archive, owners, and safety policy.', evidence: 'Audited tenant action.' }
  ],
  'agent-detail': [
    { id: 'overview', label: 'Overview', summary: 'Status, binding, and capabilities for one agent.', evidence: 'Agent record and heartbeat.' },
    { id: 'health', label: 'Health', summary: 'Heartbeat freshness and diagnostic state.', evidence: 'Agent health metadata.' },
    { id: 'placement', label: 'Placement', summary: 'Target-group placement confidence.', evidence: 'Placement review records.' },
    { id: 'audit', label: 'Audit', summary: 'Metadata-only lifecycle events for this agent.', evidence: 'Tenant audit trail.' }
  ],
  'run-detail': PAGE_TAB_SETS.runs,
  'tenant-detail': [
    { id: 'overview', label: 'Overview', summary: 'Lifecycle, plan, and subscription summary.', evidence: 'Staff tenant detail API.' },
    { id: 'users', label: 'Users', summary: 'Tenant users and support owner.', evidence: 'Tenant user records.' },
    { id: 'entitlements', label: 'Entitlements', summary: 'Plan features and grant controls.', evidence: 'Subscription entitlements.' },
    { id: 'provisioning', label: 'Provisioning', summary: 'Signup request that created this tenant.', evidence: 'Signup request record.' },
    { id: 'audit', label: 'Audit', summary: 'Recent tenant-scoped audit entries.', evidence: 'Internal audit log.' }
  ]
};

export const FEATURE_GROUPS: FeatureGroup[] = [
  {
    id: 'public-auth',
    title: 'Public, Auth, And Intake',
    summary: 'Visitor, customer, and staff entry surfaces from the prototype are now React views.',
    items: [
      { name: 'Public product positioning', surface: 'Public Landing', status: 'Visible', relationship: 'Routes visitors to reviewed sign-up and customer login.' },
      { name: 'Public sign-up request intake', surface: 'Sign-up Intake', status: 'Visible', relationship: 'Feeds staff review, tenant provisioning, subscription, and invite flow.' },
      { name: 'Sign-up status lookup', surface: 'Sign-up Status', status: 'Visible', relationship: 'Extends public request lifecycle without direct tenant provisioning.' },
      { name: 'Customer authentication entry', surface: 'Customer Login', status: 'Visible', relationship: 'Opens tenant-scoped portal session.' },
      { name: 'Staff authentication entry', surface: 'Staff Login', status: 'Visible', relationship: 'Separates internal management from customer portal.' },
      { name: 'Public site configuration API', surface: '/v1/public/site-config', status: 'API-backed', relationship: 'Supplies configured login, sign-up, and plan metadata.' }
    ]
  },
  {
    id: 'scope-onboarding',
    title: 'Declared Scope And Onboarding',
    summary: 'Core onboarding keeps target scope customer-declared and evidence-backed.',
    items: [
      { name: 'Tenant and environment management', surface: 'Environments, Settings', status: 'Partial', relationship: 'Environments scope target groups and run history.' },
      { name: 'Target groups and declared targets', surface: 'Target Groups, Target Detail', status: 'Visible', relationship: 'The declared target group is the unit of validation.' },
      { name: 'Expected behavior model', surface: 'Target Groups', status: 'Visible', relationship: 'Expected paths and health signals support verdict interpretation.' },
      { name: 'CSV/API import for declared scope', surface: 'Target Groups, APIs', status: 'Partial', relationship: 'Imports are declarations, not autonomous discovery.' },
      { name: 'Guided first safe run', surface: 'Onboarding', status: 'Visible', relationship: 'Connects setup to first bounded validation evidence.' },
      { name: 'Role-based navigation and permissions', surface: 'Portal Shell', status: 'Partial', relationship: 'Controls SOC, audit, and release evidence visibility.' }
    ]
  },
  {
    id: 'agent-probe',
    title: 'Outbound Agents And Probe Fleet',
    summary: 'Inside/outside observations stay bounded and traceable.',
    items: [
      { name: 'Outbound-only agent install', surface: 'Agents, Onboarding', status: 'Visible', relationship: 'Agent calls AstraNull over outbound HTTPS and needs no inbound management port.' },
      { name: 'Agent heartbeat and placement', surface: 'Agents, Agent Detail', status: 'Visible', relationship: 'Heartbeat plus placement canary increases confidence.' },
      { name: 'Agent package, Helm, Docker, systemd', surface: 'Linux Agent Package', status: 'Operator-only', relationship: 'Supports customer operators outside the portal.' },
      { name: 'Agent revoke, update, rollback, trust keys', surface: 'Agents, Release Evidence', status: 'Partial', relationship: 'Lifecycle operations are governed through APIs and evidence.' },
      { name: 'Probe profiles', surface: 'Checks, Runs', status: 'Partial', relationship: 'Bounded HTTP HEAD, DNS, TCP, and marker probes support verdicts.' },
      { name: 'Internal probe worker jobs', surface: 'Probe Worker', status: 'By design hidden', relationship: 'Leased worker implementation is not exposed as customer controls.' }
    ]
  },
  {
    id: 'validation-verdicts',
    title: 'Safe Validation And Verdicts',
    summary: 'Checks, runs, findings, and scoring preserve safe-by-default behavior.',
    items: [
      { name: 'Safe check catalog', surface: 'Checks Library', status: 'Visible', relationship: 'Safe and SOC-gated checks are clearly separated.' },
      { name: 'Check families', surface: 'Checks Library', status: 'Visible', relationship: 'Origin, L3/L4, DNS, L7/API, TLS, protocol, operations, and high-scale families.' },
      { name: 'Safe test policies', surface: 'Test Policies', status: 'Visible', relationship: 'Binds cadence, expected verdict, target group, and safe windows.' },
      { name: 'Run detail visualizations', surface: 'Test Runs, Run Detail', status: 'Visible', relationship: 'Timeline, probe results, observations, correlation, evidence, and events.' },
      { name: 'Correlation engine and verdict logic', surface: 'Runs, Evidence, Dashboard', status: 'Partial', relationship: 'Verdicts link to observed facts instead of assumptions.' },
      { name: 'Readiness scoring', surface: 'Dashboard, Reports', status: 'Visible', relationship: 'Aggregates coverage, findings, freshness, placement, and SOC readiness.' },
      { name: 'Findings triage', surface: 'Findings', status: 'Visible', relationship: 'Open, grouped, accepted-risk, closed, SLA, export, assign, close, and retest views.' }
    ]
  },
  {
    id: 'evidence-reporting',
    title: 'Evidence, Reports, And Custody',
    summary: 'Every result can be traced to evidence and exported with custody context.',
    items: [
      { name: 'Evidence ledger', surface: 'Evidence Vault', status: 'Visible', relationship: 'Stores run, finding, report, and release-ready evidence references.' },
      { name: 'Evidence snapshot signing', surface: 'Release Evidence, APIs', status: 'API-backed', relationship: 'Produces signed manifests for release and compliance.' },
      { name: 'Custody verification', surface: 'Reports, Evidence APIs', status: 'API-backed', relationship: 'Verifies digest and custody references.' },
      { name: 'Event ingestion', surface: 'Events API', status: 'API-backed', relationship: 'Adds metadata-only events and deduplicates observations.' },
      { name: 'Report builder', surface: 'Reports', status: 'Visible', relationship: 'Executive, technical, SOC, audit, custody, WAF, and release views.' },
      { name: 'Production release evidence ledger', surface: 'Release Evidence', status: 'Visible', relationship: 'Tracks required launch-gate evidence and open gaps.' }
    ]
  },
  {
    id: 'waf-posture',
    title: 'WAF Posture Management',
    summary: 'WAF add-on surfaces assets, connectors, drift, validation, reports, and risk analytics.',
    items: [
      { name: 'WAF posture console', surface: 'WAF Posture', status: 'Visible', relationship: 'Central console for WAF coverage, roadmap, assets, drift, and evidence.' },
      { name: 'WAF asset coverage and effectiveness', surface: 'WAF Asset Detail', status: 'Visible', relationship: 'Pass rate, control-bypass classes, risk tier, and actions.' },
      { name: 'WAF deployment roadmap and risk scoring', surface: 'WAF Posture', status: 'Visible', relationship: 'Turns posture evidence into prioritized rollout recommendations.' },
      { name: 'WAF scenario cadence', surface: 'WAF Posture', status: 'Visible', relationship: 'Safe scenarios are scheduled and explained without customer-run high-scale controls.' },
      { name: 'WAF validation planning and runs', surface: 'WAF Posture, Evidence', status: 'Partial', relationship: 'Plans and safe runs create protected-claim evidence.' },
      { name: 'WAF drift queue, scans, retests', surface: 'WAF Posture', status: 'Partial', relationship: 'Drift events connect to retest and remediation actions.' },
      { name: 'WAF read-only connectors', surface: 'WAF Posture, Integrations', status: 'Partial', relationship: 'Optional connector snapshots enrich posture but are not core requirements.' },
      { name: 'WAF report kinds and catalog', surface: 'Reports, WAF Posture', status: 'Partial', relationship: 'Executive coverage, technical evidence, drift audit, connector health, compliance, and board brief.' }
    ]
  },
  {
    id: 'cve-supply-discovery',
    title: 'CVE, Discovery, And Supply Chain',
    summary: 'Exposure workflows stay reviewed, metadata-only, and linked to declared scope.',
    items: [
      { name: 'Live exposure CVE pipeline', surface: 'CVE Pipeline', status: 'Partial', relationship: 'Ingests CVEs and maps them to declared WAF assets.' },
      { name: 'CVE triage, match, recommend', surface: 'CVE Pipeline', status: 'Partial', relationship: 'Shows triage factors and asset matches while advanced actions stay API-backed.' },
      { name: 'CVE stage, retest, playbook approval', surface: 'CVE Pipeline APIs', status: 'API-backed', relationship: 'Supports multi-vendor mitigation approval and validation.' },
      { name: 'Enhanced discovery modes', surface: 'Discovery', status: 'Visible', relationship: 'D0-D4 modes remain approval-gated and never required for core inventory.' },
      { name: 'Discovery candidate inbox', surface: 'Discovery, Discovery Entity', status: 'Visible', relationship: 'Candidates require decision before import into declared scope.' },
      { name: 'Approved candidate import', surface: 'Discovery', status: 'Partial', relationship: 'Imports approved candidates into existing declared target groups.' },
      { name: 'Supply-chain risk detection', surface: 'Supply Chain', status: 'Visible', relationship: 'Tracks dangling CNAME, deleted app, dependency, redirect, vendor, and subdomain risks.' },
      { name: 'Supply-chain active-protection phases', surface: 'Supply Chain APIs', status: 'API-backed', relationship: 'Phase authorization governs any active-protection transition.' }
    ]
  },
  {
    id: 'remediation-notifications',
    title: 'Remediation And Notifications',
    summary: 'Action items, provider delivery, retries, and DLQ are visible without leaking sensitive content.',
    items: [
      { name: 'Action-item remediation', surface: 'Remediation, Findings', status: 'Partial', relationship: 'Converts findings, CVEs, and supply-chain risks into owner work.' },
      { name: 'Remediation delivery preview', surface: 'Remediation, Integrations', status: 'Partial', relationship: 'Ticketing and SIEM/SOAR outputs are redacted and opt-in.' },
      { name: 'Notification rules and events', surface: 'Notifications', status: 'Visible', relationship: 'Routes safe in-app and provider notifications.' },
      { name: 'Notification provider credentials', surface: 'Notifications APIs', status: 'API-backed', relationship: 'Secret storage is metadata-only from the UI perspective.' },
      { name: 'Notification retry and DLQ redrive', surface: 'Notifications', status: 'Partial', relationship: 'Preview and recovery flows expose only operational metadata.' },
      { name: 'Integrations catalog', surface: 'Integrations', status: 'Visible', relationship: 'Groups connectors, ticketing, notification, and remediation delivery options.' }
    ]
  },
  {
    id: 'high-scale-soc',
    title: 'High-Scale And SOC Governance',
    summary: 'High-scale validation is request-only for customers and execution-governed by SOC.',
    items: [
      { name: 'Customer high-scale request', surface: 'High-Scale Requests', status: 'Visible', relationship: 'Customers submit scope, objective, window, contacts, and confirmation.' },
      { name: 'High-scale authorization pack', surface: 'High-Scale, SOC, Reports', status: 'Partial', relationship: 'Captures customer, provider, legal, and runbook approval artifacts.' },
      { name: 'SOC review and approval', surface: 'SOC, Internal SOC', status: 'Staff-only', relationship: 'Only SOC can approve or reject high-scale readiness.' },
      { name: 'SOC scheduling, live status, stop, close', surface: 'SOC, Internal SOC', status: 'Staff-only', relationship: 'Lifecycle controls are isolated from customer UI.' },
      { name: 'SOC kill switch', surface: 'SOC, Internal SOC', status: 'Staff-only', relationship: 'Emergency state is audited and visible to SOC operators.' },
      { name: 'Provider approval artifacts', surface: 'High-Scale, Release Evidence', status: 'Partial', relationship: 'Provider approvals contribute to readiness and release evidence.' },
      { name: 'Post-test report', surface: 'SOC, Reports', status: 'Partial', relationship: 'Closure requires stopped state and stored report evidence.' }
    ]
  },
  {
    id: 'staff-management',
    title: 'Internal Management',
    summary: 'The previously broken internal admin surface is now represented as React views.',
    items: [
      { name: 'Internal management overview', surface: 'Admin Console', status: 'Visible', relationship: 'Shows pending sign-ups, approvals, tenants, support, and audit counts.' },
      { name: 'Staff signup queue', surface: 'Admin Console', status: 'Staff-only', relationship: 'Review, request info, approve, reject, and provision tenants.' },
      { name: 'Staff tenant operations', surface: 'Admin Console, Tenant Detail', status: 'Staff-only', relationship: 'Suspend, reactivate, view users, support notes, and lifecycle state.' },
      { name: 'Staff subscription and entitlements', surface: 'Admin Console, Subscription', status: 'Partial', relationship: 'Shows plan and entitlement state while writes stay API-governed.' },
      { name: 'Staff user support', surface: 'Admin Console, Support', status: 'Partial', relationship: 'Invite resend, disable user, and support-note flows.' },
      { name: 'Internal approval queue', surface: 'Admin Console', status: 'Partial', relationship: 'Lists approval requests and decision context.' },
      { name: 'Break-glass status', surface: 'Internal APIs', status: 'API-backed', relationship: 'Emergency access remains audited and separate from general UI.' }
    ]
  },
  {
    id: 'settings-ops-security',
    title: 'Settings, Security, And Operations',
    summary: 'Production readiness, privacy, observability, and release operations are surfaced at the right layer.',
    items: [
      { name: 'Service accounts and API keys', surface: 'Settings', status: 'Partial', relationship: 'Create, revoke, rotate, and audit automation access.' },
      { name: 'Secret vault', surface: 'Settings APIs', status: 'API-backed', relationship: 'Tenant-scoped encrypted metadata with no plaintext read path.' },
      { name: 'Privacy retention', surface: 'Settings', status: 'Partial', relationship: 'Retention status and purge controls support compliance.' },
      { name: 'Rate limiting', surface: 'API layer', status: 'API-backed', relationship: 'Protects public and API routes.' },
      { name: 'Observability', surface: '/health, /ready, /metrics, /v1/observability', status: 'API-backed', relationship: 'Health, readiness, metrics, and operational state.' },
      { name: 'Postgres persistence and migrations', surface: 'Operator scripts', status: 'Operator-only', relationship: 'Migrations, repositories, and tenant query audit support production.' },
      { name: 'Backup, restore, and DR drills', surface: 'Release Evidence', status: 'Operator-only', relationship: 'Produces operational evidence for release readiness.' },
      { name: 'Staging and hosted verification scripts', surface: 'Release Evidence, package scripts', status: 'Operator-only', relationship: 'Feeds release evidence and attestation workflows.' }
    ]
  }
];

export const RELATIONSHIP_FLOWS: RelationshipFlow[] = [
  {
    title: 'Declared Scope To First Verdict',
    steps: ['Environment', 'Target group', 'Expected behavior', 'Outbound agent', 'Safe check', 'Run correlation', 'Evidence vault'],
    outcome: 'A readiness verdict backed by customer declaration, probe result, agent observation, and custody reference.'
  },
  {
    title: 'Finding To Closure',
    steps: ['Finding triage', 'Owner assignment', 'Remediation action', 'Safe retest', 'Evidence export', 'Audit entry'],
    outcome: 'A closed or accepted-risk finding with an explainable trail.'
  },
  {
    title: 'High-Scale Request To SOC Closeout',
    steps: ['Customer request', 'Authorization pack', 'SOC review', 'Schedule', 'Live status', 'Stop or complete', 'Post-test report'],
    outcome: 'SOC-governed high-scale workflow with no customer execution controls.'
  },
  {
    title: 'WAF Posture To Roadmap',
    steps: ['Asset snapshot', 'Scenario cadence', 'Validation plan', 'Drift queue', 'CVE match', 'Action item', 'Report'],
    outcome: 'Risk-prioritized WAF readiness roadmap grounded in metadata and safe validation evidence.'
  },
  {
    title: 'Discovery Candidate To Declared Scope',
    steps: ['Candidate inbox', 'Source evidence', 'Owner review', 'Approval decision', 'Import', 'Policy binding'],
    outcome: 'A reviewed candidate becomes explicit declared scope only after approval.'
  },
  {
    title: 'Release Evidence To Attestation',
    steps: ['Local or hosted verification', 'Evidence collection', 'Gap audit', 'Bundle manifest', 'Attestation', 'Launch gate'],
    outcome: 'Production readiness is visible without exposing operator workflows as customer controls.'
  }
];

export function routeTabs(route: RouteId) {
  return PAGE_TAB_SETS[route] ?? DETAIL_TAB_SETS[route] ?? [];
}

export function featureCounts() {
  return {
    surfaces: PROTOTYPE_SURFACES.length,
    tabs: Object.values(PAGE_TAB_SETS).reduce((total, tabs) => total + (tabs?.length ?? 0), 0),
    featureGroups: FEATURE_GROUPS.length,
    featureItems: FEATURE_GROUPS.reduce((total, group) => total + group.items.length, 0),
    flows: RELATIONSHIP_FLOWS.length
  };
}
