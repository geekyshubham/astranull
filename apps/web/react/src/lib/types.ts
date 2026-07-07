import type { LucideIcon } from 'lucide-react';

export type SurfaceKind = 'overview' | 'scope' | 'validation' | 'governance' | 'staff';

export type RouteId =
  | 'dashboard'
  | 'environments'
  | 'target-groups'
  | 'target-group-detail'
  | 'target-detail'
  | 'agents'
  | 'agent-detail'
  | 'checks'
  | 'test-policies'
  | 'runs'
  | 'run-detail'
  | 'findings'
  | 'finding-detail'
  | 'reports'
  | 'report-detail'
  | 'integrations'
  | 'notifications'
  | 'audit'
  | 'settings'
  | 'support'
  | 'subscription'
  | 'admin'
  | 'tenant-detail'
  | 'internal-soc'
  | 'queue-detail';

export type NavItem = {
  id: RouteId;
  label: string;
  group: SurfaceKind;
  description: string;
  icon: LucideIcon;
  count?: string;
};

export type Session = {
  mode?: string;
  principal?: string;
  tenant_id?: string;
  user_id?: string;
  role?: string;
  staff_id?: string;
  staff_role?: string;
  staff_login_path?: string;
  access_token?: string;
  expires_at?: number;
};

export type PortalConfig = {
  authMode: string;
  siteConfig: Record<string, unknown>;
  bundledLoginEnabled: boolean;
  loginUrl: string;
  portalPath: string;
  staffLoginPath: string;
};

export type ReadinessFactor = {
  key?: string;
  label?: string;
  score?: number;
  weight?: number;
  reason?: string;
  detail?: string;
};

export type ReadinessPostureSegment = {
  key: 'pass' | 'review' | 'gap';
  label: string;
  count: number;
  pct: number;
};

export type StatePayload = {
  tenant_id?: string;
  readiness?: {
    score?: number;
    factors?: ReadinessFactor[];
    summary?: string;
    delta?: number;
    posture?: {
      pass?: number;
      review?: number;
      gap?: number;
      total?: number;
    };
  };
  target_groups?: number;
  agents_online?: number;
  agents_total?: number;
  recent_runs?: DataItem[];
  open_findings?: number;
  high_scale_requests?: number;
  last_validation_at?: string;
  kill_switch?: {
    active?: boolean;
    enabled?: boolean;
    reason?: string;
    updated_at?: string;
  };
};

export type DataItem = Record<string, unknown>;

export type PortalData = {
  state: StatePayload | null;
  tenant: DataItem | null;
  targetGroups: DataItem[];
  targetGroupsMeta: DataItem | null;
  agents: DataItem[];
  checks: DataItem[];
  testPolicies: DataItem[];
  runs: DataItem[];
  findings: DataItem[];
  evidence: DataItem[];
  highScale: DataItem[];
  reports: DataItem[];
  notificationRules: DataItem[];
  notificationEvents: DataItem[];
  releaseEvidence: DataItem[];
  releaseAttestation: DataItem | null;
  audit: DataItem[];
  connectors: DataItem[];
  secrets: DataItem[];
  bootstrapTokens: DataItem[];
  serviceAccounts: DataItem[];
  wafAssets: DataItem[];
  wafCoverage: DataItem | null;
  wafCoverageSummary: DataItem | null;
  wafRiskRoadmap: DataItem | null;
  wafValidations: DataItem[];
  wafDriftEvents: DataItem[];
  wafExceptions: DataItem[];
  wafValidationPlans: DataItem[];
  wafRetests: DataItem[];
  wafActionItems: DataItem[];
  cvePipeline: DataItem[];
  supplyChainRisks: DataItem[];
  discoveryEntities: DataItem[];
  discoveryCandidates: DataItem[];
  discoveryInbox: DataItem[];
  discoverySummary: DataItem | null;
  subscriptionSummary: DataItem | null;
  internalOverview: DataItem | null;
  internalSignupRequests: DataItem[];
  internalTenants: DataItem[];
  internalApprovalRequests: DataItem[];
  internalAudit: DataItem[];
  deploymentFeatures: DataItem | null;
  loaded: boolean;
  error: string | null;
};

export type BadgeTone = 'default' | 'success' | 'warn' | 'danger' | 'info' | 'muted';