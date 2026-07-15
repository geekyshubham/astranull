import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { AppShell } from './components/layout/app-shell';
import { EMPTY_PORTAL_DATA, ensurePortalSession, fetchPortalData, loadSession, portalSurface, saveSession, sessionIdentity } from './lib/api';
import { getRouteFromLocation } from './lib/navigation';
import { canAccessRoute } from './lib/route-access';
import type { PortalConfig, PortalData, RouteId, Session } from './lib/types';
import { LoginPage, PublicLandingPage, SignupPage, SignupStatusPage, StaffLoginPage } from './pages/public-pages';
import { RouteView } from './pages/router';

function LoadingScreen() {
  return (
    <div className="loading-screen">
      <div className="loading-card">
        <div className="spinner" />
        <strong>Loading AstraNull</strong>
        <p>Preparing the readiness console.</p>
      </div>
    </div>
  );
}

function isPublicOnlyPath(path: string) {
  return ['/', '/landing.html', '/login', '/login.html', '/signup', '/signup.html', '/signup-status', '/internal/admin/login', '/staff-login.html'].includes(path);
}

export default function App() {
  const [route, setRoute] = useState<RouteId>(() => getRouteFromLocation());
  const [path, setPath] = useState(() => window.location.pathname);
  const [config, setConfig] = useState<PortalConfig | null>(null);
  const [session, setSession] = useState<Session | null>(() => loadSession());
  const [data, setData] = useState<PortalData>(EMPTY_PORTAL_DATA);
  const [loading, setLoading] = useState(true);

  const activeSession = useMemo(() => session ?? {}, [session]);

  const refresh = useCallback(async (nextConfig: PortalConfig | null, nextSession: Session, nextRoute?: RouteId) => {
    if (!nextConfig) return;
    try {
      const payload = await fetchPortalData(nextConfig, nextSession, { route: nextRoute ?? route });
      setData(payload);
    } catch (error) {
      setData((current) => ({
        ...current,
        loaded: true,
        error: error instanceof Error ? error.message : 'Could not load workspace data.'
      }));
    }
  }, [route]);

  useEffect(() => {
    let mounted = true;
    async function boot() {
      const gate = await ensurePortalSession(portalSurface(window.location.pathname));
      if (!mounted) return;
      if (gate.redirectToLogin && !isPublicOnlyPath(window.location.pathname)) {
        window.location.replace(gate.loginUrl ?? '/login');
        return;
      }
      const nextConfig = gate.config;
      const nextSession = gate.session;
      setConfig(nextConfig);
      setSession(nextSession);
      if (!isPublicOnlyPath(window.location.pathname) && nextSession) {
        await refresh(nextConfig, nextSession, getRouteFromLocation());
      }
      if (mounted) setLoading(false);
    }
    boot().catch((error) => {
      if (!mounted) return;
      setData({
        ...EMPTY_PORTAL_DATA,
        loaded: true,
        error: error instanceof Error ? error.message : 'Could not initialize the portal.'
      });
      setLoading(false);
    });
    return () => {
      mounted = false;
    };
  }, [refresh]);

  useEffect(() => {
    function onHashChange() {
      const nextRoute = getRouteFromLocation();
      const stored = loadSession();
      const role = stored?.role ?? activeSession.role;
      const accessContext = {
        principal: stored?.principal ?? activeSession.principal,
        staffRole: stored?.staff_role ?? activeSession.staff_role,
      };
      if (!canAccessRoute(role, nextRoute, accessContext)) {
        window.location.replace(`${window.location.pathname}${window.location.search}#dashboard`);
        setRoute('dashboard');
      } else {
        setRoute(nextRoute);
      }
      setPath(window.location.pathname);
    }
    window.addEventListener('hashchange', onHashChange);
    window.addEventListener('popstate', onHashChange);
    return () => {
      window.removeEventListener('hashchange', onHashChange);
      window.removeEventListener('popstate', onHashChange);
    };
  }, [activeSession.principal, activeSession.role, activeSession.staff_role]);

  useEffect(() => {
    if (!config || loading) return;
    const stored = loadSession();
    if (!stored) return;
    if (sessionIdentity(stored) === sessionIdentity(session)) return;
    setSession(stored);
    void refresh(config, stored, route);
  }, [route, path, config, loading, refresh, session]);

  useEffect(() => {
    if (loading || !config) return;
    const role = activeSession.role;
    if (!canAccessRoute(role, route, {
      principal: activeSession.principal,
      staffRole: activeSession.staff_role,
    })) {
      window.location.replace(`${window.location.pathname}${window.location.search}#dashboard`);
      setRoute('dashboard');
    }
  }, [loading, config, route, activeSession.principal, activeSession.role, activeSession.staff_role]);

  // Re-hydrate when the hash route changes so staff SOC / queue-detail get SOC tenant headers
  // after navigating from Admin (or other surfaces that skipped customer /v1 hydrate).
  // Skip the first observation to avoid duplicating the boot-time fetch.
  const routeHydratePrimed = useRef(false);
  useEffect(() => {
    if (loading || !config || !session) return;
    if (isPublicOnlyPath(path)) return;
    if (!routeHydratePrimed.current) {
      routeHydratePrimed.current = true;
      return;
    }
    void refresh(config, session, route);
  }, [route, loading, config, session, path, refresh]);

  function handleRoleChange(role: string) {
    // Role switcher is a local dev-headers convenience only — never elevate OIDC sessions.
    if (config?.authMode !== 'dev-headers') return;
    const next = {
      ...activeSession,
      mode: 'dev-headers',
      principal: 'customer',
      role
    };
    saveSession(next);
    setSession(next);
    void refresh(config, next);
  }

  /** Always re-read sessionStorage so SOC execution-tenant updates are not stale. */
  const handleRefresh = useCallback(async () => {
    if (!config) return;
    const stored = loadSession() ?? activeSession;
    if (sessionIdentity(stored) !== sessionIdentity(session)) {
      setSession(stored);
    }
    await refresh(config, stored, route);
  }, [config, activeSession, session, refresh, route]);

  if (loading || !config) return <LoadingScreen />;

  if (path === '/' || path === '/landing.html') return <PublicLandingPage config={config} />;
  if (path === '/login' || path === '/login.html') return <LoginPage config={config} />;
  if (path === '/signup' || path === '/signup.html') return <SignupPage config={config} />;
  if (path === '/signup-status') return <SignupStatusPage />;
  if (path === '/internal/admin/login' || path === '/staff-login.html') return <StaffLoginPage config={config} />;

  return (
    <AppShell
      route={route}
      session={activeSession}
      data={data}
      onRouteChange={setRoute}
      onRoleChange={handleRoleChange}
      onRefresh={() => void handleRefresh()}
      showRoleSwitcher={config.authMode === 'dev-headers' && activeSession.principal !== 'staff'}
    >
      <RouteView route={route} data={data} config={config} session={activeSession} onRefresh={handleRefresh} />
    </AppShell>
  );
}
