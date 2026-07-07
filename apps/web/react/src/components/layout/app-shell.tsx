import { Menu, PanelLeftClose, PanelLeftOpen, Search, X } from 'lucide-react';
import type { ReactNode } from 'react';
import { useMemo, useState } from 'react';
import { clearSession } from '../../lib/api';
import { NAV_GROUP_LABELS, NAV_ITEMS, ROUTE_BY_ID } from '../../lib/navigation';
import { canAccessRoute } from '../../lib/route-access';
import type { NavItem, PortalData, RouteId, Session } from '../../lib/types';
import { cn } from '../../lib/utils';
import { Button } from '../ui/button';
import { Select } from '../ui/select';
import { Brand } from './brand';

type AppShellProps = {
  route: RouteId;
  session: Session;
  data: PortalData;
  onRouteChange: (route: RouteId) => void;
  onRoleChange: (role: string) => void;
  onRefresh: () => void;
  children: ReactNode;
};

const roles = [
  { value: 'admin', label: 'admin', description: 'Full developer validation access' },
  { value: 'engineer', label: 'engineer', description: 'Runs, agents, target groups' },
  { value: 'soc', label: 'soc', description: 'SOC-gated workflow preview' },
  { value: 'auditor', label: 'auditor', description: 'Evidence and audit visibility' },
  { value: 'viewer', label: 'viewer', description: 'Read-only workspace' },
  { value: 'owner', label: 'owner', description: 'Tenant owner access' }
];

function NavLink({ item, active, onClick }: { item: NavItem; active: boolean; onClick: () => void }) {
  const Icon = item.icon;
  return (
    <button type="button" className={cn('nav-item', active && 'active', active && 'is-active')} onClick={onClick} title={item.label}>
      <Icon size={16} />
      <span>{item.label}</span>
      {item.count ? <span className="nav-count">{item.count}</span> : null}
    </button>
  );
}

export function AppShell({ route, session, data, onRouteChange, onRoleChange, children }: AppShellProps) {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => {
    try {
      return window.localStorage.getItem('astranull.react.sidebar.collapsed') === '1';
    } catch {
      return false;
    }
  });
  const current = ROUTE_BY_ID.get(route) ?? NAV_ITEMS[0];
  const tenantId = session.tenant_id ?? data.state?.tenant_id ?? 'unknown';
  const environment = (data.state as { environment?: string } | null)?.environment ?? '';
  const visibleNavItems = useMemo(() => {
    const role = session.role ?? 'admin';
    return NAV_ITEMS.filter((item) => {
      if (item.id.endsWith('-detail')) {
        return false;
      }
      return canAccessRoute(role, item.id, {
        principal: session.principal,
        staffRole: session.staff_role,
      });
    });
  }, [session.principal, session.role, session.staff_role]);

  const grouped = useMemo(() => {
    return visibleNavItems.reduce<Record<string, NavItem[]>>((acc, item) => {
      acc[item.group] = [...(acc[item.group] ?? []), item];
      return acc;
    }, {});
  }, [visibleNavItems]);

  function navigate(next: RouteId) {
    window.location.hash = next;
    onRouteChange(next);
    setSidebarOpen(false);
  }

  function logout() {
    clearSession();
    window.location.href = '/login';
  }

  function toggleSidebarCollapsed() {
    setSidebarCollapsed((currentValue) => {
      const next = !currentValue;
      try {
        window.localStorage.setItem('astranull.react.sidebar.collapsed', next ? '1' : '0');
      } catch {
        // Best-effort preference persistence only.
      }
      return next;
    });
  }

  const CollapseIcon = sidebarCollapsed ? PanelLeftOpen : PanelLeftClose;

  return (
    <div className={cn('app-shell', sidebarCollapsed && 'sidebar-collapsed')}>
      <aside className={cn('sidebar', sidebarOpen && 'open')}>
        <Button
          variant="secondary"
          size="icon"
          className="sidebar-collapse"
          style={{ width: 40, height: 40, minWidth: 40, minHeight: 40 }}
          onClick={toggleSidebarCollapsed}
          aria-label={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          title={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          <CollapseIcon size={16} />
        </Button>
        <div className="sidebar-head">
          <Brand />
          <Button variant="ghost" size="icon" className="sidebar-close" onClick={() => setSidebarOpen(false)} aria-label="Close navigation">
            <X size={17} />
          </Button>
        </div>
        <nav className="nav-scroll" aria-label="Portal">
          {(Object.keys(grouped) as Array<keyof typeof NAV_GROUP_LABELS>)
            .filter((group) => (grouped[group]?.length ?? 0) > 0)
            .map((group) => (
            <div className="nav-group" key={group}>
              <p>{NAV_GROUP_LABELS[group]}</p>
              {grouped[group]?.map((item) => (
                <NavLink key={item.id} item={item} active={item.id === route} onClick={() => navigate(item.id)} />
              ))}
            </div>
          ))}
        </nav>
        <div className="sidebar-foot">
          <span>
            <b>{tenantId}</b>
            {environment ? <> · {environment}</> : null}
          </span>
          <span>safe-by-default · SOC-gated</span>
          <Select
            label="Role"
            className="sidebar-role"
            value={session.role ?? 'admin'}
            options={roles}
            onChange={onRoleChange}
          />
          <div className="sidebar-foot-actions">
            <a href="/">Public site</a>
            <Button type="button" variant="ghost" size="sm" onClick={logout}>
              Sign out
            </Button>
          </div>
        </div>
      </aside>
      <div className={cn('scrim', sidebarOpen && 'open')} onClick={() => setSidebarOpen(false)} aria-hidden="true" />
      <main className="main">
        <header className="topbar">
          <Button variant="ghost" size="icon" className="menu-btn" onClick={() => setSidebarOpen(true)} aria-label="Open navigation">
            <Menu size={18} />
          </Button>
          <div className="crumbs">
            <span>{NAV_GROUP_LABELS[current.group]}</span>
            <span className="sep">›</span>
            <b>{current.label}</b>
          </div>
          <div className="topbar-spacer" aria-hidden="true" />
          <label className="search">
            <Search size={15} aria-hidden="true" />
            <input type="search" placeholder="Search runs, findings, agents…" aria-label="Search" />
          </label>
        </header>
        {children}
      </main>
    </div>
  );
}