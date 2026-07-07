import type { PortalConfig, PortalData, RouteId, Session } from '../lib/types';
import { DetailRoutePage, ReportDetailPage } from './detail-pages';
import { AgentsPage, ValidationSurfacePage } from './functional-surfaces';
import {
  DashboardPage,
  EnvironmentsPage,
  GovernancePage,
  IntegrationPage,
  PolicyPage,
  ReportsPage,
  SettingsPage,
  StaffSurfacePage,
  SubscriptionPage,
  SupportPage,
  TargetGroupsPage
} from './page-components';
import { AuditPage, NotificationsPage, SocConsolePage } from './governance-pages';

export function RouteView({
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
  if (route === 'dashboard') return <DashboardPage data={data} />;
  if (route === 'environments') return <EnvironmentsPage data={data} />;
  if (route === 'target-groups') return <TargetGroupsPage data={data} config={config} session={session} onRefresh={onRefresh} />;
  if (route === 'agents') return <AgentsPage data={data} config={config} session={session} onRefresh={onRefresh} />;
  if ([
    'target-group-detail',
    'target-detail',
    'agent-detail',
    'run-detail',
    'finding-detail',
    'tenant-detail',
    'queue-detail'
  ].includes(route)) {
    return <DetailRoutePage route={route} data={data} config={config} session={session} onRefresh={onRefresh} />;
  }
  if (route === 'test-policies') return <PolicyPage data={data} config={config} session={session} onRefresh={onRefresh} />;
  if (['checks', 'runs', 'findings'].includes(route)) {
    return <ValidationSurfacePage route={route} data={data} config={config} session={session} onRefresh={onRefresh} />;
  }
  if (route === 'integrations') {
    return <IntegrationPage data={data} config={config} session={session} onRefresh={onRefresh} />;
  }
  if (route === 'reports') return <ReportsPage data={data} config={config} session={session} onRefresh={onRefresh} />;
  if (route === 'report-detail') return <ReportDetailPage data={data} config={config} session={session} onRefresh={onRefresh} />;
  if (route === 'notifications') return <NotificationsPage data={data} config={config} session={session} onRefresh={onRefresh} />;
  if (route === 'audit') return <AuditPage data={data} session={session} />;
  if (route === 'support') return <SupportPage data={data} session={session} />;
  if (route === 'subscription') return <SubscriptionPage data={data} />;
  if (route === 'internal-soc') {
    return <SocConsolePage data={data} config={config} session={session} onRefresh={onRefresh} staffSocSurface />;
  }
  if (route === 'admin') {
    return <StaffSurfacePage route={route} data={data} config={config} session={session} onRefresh={onRefresh} />;
  }
  if (route === 'settings') {
    return <SettingsPage data={data} config={config} session={session} onRefresh={onRefresh} />;
  }
  return <GovernancePage route={route} data={data} />;
}