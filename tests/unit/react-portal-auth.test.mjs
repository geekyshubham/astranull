import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { canAccessRoute } from '../../apps/web/react/src/lib/route-access.mjs';

/**
 * Mirrors pure helpers in apps/web/react/src/lib/api.ts for node:test coverage.
 */
function isOidcJwtMode(config) {
  return config.authMode === 'oidc-jwt';
}

function isExternalAuthUrl(url) {
  const trimmed = url.trim();
  return /^https?:\/\//i.test(trimmed);
}

function resolveOidcLoginRedirect(config, surface = 'customer') {
  if (!isOidcJwtMode(config) || config.bundledLoginEnabled) return null;
  const loginUrl = surface === 'staff' ? config.staffLoginPath : config.loginUrl;
  return isExternalAuthUrl(loginUrl) ? loginUrl : null;
}

function portalSurface(pathname) {
  const path = pathname.replace(/\/+$/, '') || '/';
  if (path === '/internal/admin' || path.startsWith('/internal/admin/')) {
    return 'staff';
  }
  return 'customer';
}

function sessionFromLoginResponse(loginResponse) {
  const expiresIn = Number(loginResponse.expires_in ?? 3600);
  return {
    mode: 'oidc',
    access_token: String(loginResponse.access_token ?? ''),
    principal: String(loginResponse.principal ?? 'customer'),
    tenant_id: loginResponse.tenant_id != null ? String(loginResponse.tenant_id) : undefined,
    user_id: loginResponse.user_id != null ? String(loginResponse.user_id) : undefined,
    role: loginResponse.role != null ? String(loginResponse.role) : undefined,
    staff_id: loginResponse.staff_id != null ? String(loginResponse.staff_id) : undefined,
    staff_role: loginResponse.staff_role != null ? String(loginResponse.staff_role) : undefined,
    expires_at: Date.now() + expiresIn * 1000,
  };
}

function buildBearerHeaders(session) {
  const headers = { accept: 'application/json' };
  const token = String(session?.access_token ?? '').trim();
  if (token) headers.authorization = `Bearer ${token}`;
  return headers;
}

describe('react portal auth helpers', () => {
  it('detects external enterprise login URLs', () => {
    assert.equal(isExternalAuthUrl('https://idp.example/oauth2/authorize'), true);
    assert.equal(isExternalAuthUrl('/login'), false);
    assert.equal(isExternalAuthUrl('/app'), false);
  });

  it('redirects oidc-jwt deployments to configured IdP URLs when bundled login is disabled', () => {
    const config = {
      authMode: 'oidc-jwt',
      bundledLoginEnabled: false,
      loginUrl: 'https://idp.example/oauth2/authorize',
      staffLoginPath: '/internal/admin/login',
    };
    assert.equal(resolveOidcLoginRedirect(config, 'customer'), 'https://idp.example/oauth2/authorize');
    assert.equal(resolveOidcLoginRedirect(config, 'staff'), null);
  });

  it('keeps bundled staging login on the local login surface', () => {
    const config = {
      authMode: 'oidc-jwt',
      bundledLoginEnabled: true,
      loginUrl: '/login',
      staffLoginPath: '/internal/admin/login',
    };
    assert.equal(resolveOidcLoginRedirect(config, 'customer'), null);
  });

  it('maps bundled staging login responses into bearer sessions', () => {
    const session = sessionFromLoginResponse({
      access_token: 'jwt.example',
      expires_in: 120,
      principal: 'customer',
      tenant_id: 'ten_demo',
      user_id: 'usr_admin',
      role: 'admin',
    });
    assert.equal(session.mode, 'oidc');
    assert.equal(session.access_token, 'jwt.example');
    assert.equal(session.principal, 'customer');
    assert.equal(session.tenant_id, 'ten_demo');
    assert.ok(session.expires_at > Date.now());
  });

  it('builds Authorization bearer headers from stored access tokens', () => {
    const headers = buildBearerHeaders({ access_token: '  token-value  ' });
    assert.equal(headers.authorization, 'Bearer token-value');
    assert.equal(buildBearerHeaders({}).authorization, undefined);
  });

  it('derives staff surface from internal admin paths', () => {
    assert.equal(portalSurface('/internal/admin'), 'staff');
    assert.equal(portalSurface('/internal/admin/'), 'staff');
    assert.equal(portalSurface('/internal/admin/login'), 'staff');
    assert.equal(portalSurface('/app'), 'customer');
    assert.equal(portalSurface('/login'), 'customer');
    assert.equal(portalSurface('/'), 'customer');
  });
});

describe('react portal route access', () => {
  it('hides notifications for viewer without notification:read', () => {
    assert.equal(canAccessRoute('viewer', 'notifications'), false);
    assert.equal(canAccessRoute('auditor', 'notifications'), true);
    assert.equal(canAccessRoute('engineer', 'notifications'), true);
    assert.equal(canAccessRoute('admin', 'notifications'), true);
  });

  it('shows audit for auditor roles allowed by backend RBAC', () => {
    assert.equal(canAccessRoute('auditor', 'audit'), true);
    assert.equal(canAccessRoute('viewer', 'audit'), false);
    assert.equal(canAccessRoute('auditor', 'reports'), true);
    assert.equal(canAccessRoute('viewer', 'reports'), true);
  });

  it('restricts staff SOC console to staff principals with SOC staff roles', () => {
    assert.equal(canAccessRoute('soc', 'internal-soc', { principal: 'customer' }), false);
    assert.equal(canAccessRoute('admin', 'internal-soc', { principal: 'customer' }), false);
    assert.equal(canAccessRoute('viewer', 'internal-soc', { principal: 'customer' }), false);
    assert.equal(canAccessRoute('admin', 'internal-soc', { principal: 'staff', staffRole: 'soc_analyst' }), true);
    assert.equal(canAccessRoute('admin', 'internal-soc', { principal: 'staff', staffRole: 'support_engineer' }), false);
  });

  it('shows staff SOC surface only for staff principals with SOC staff roles', () => {
    assert.equal(canAccessRoute('admin', 'internal-soc', { principal: 'staff', staffRole: 'soc_analyst' }), true);
    assert.equal(canAccessRoute('admin', 'internal-soc', { principal: 'staff', staffRole: 'support_engineer' }), false);
    assert.equal(canAccessRoute('soc', 'internal-soc', { principal: 'customer' }), false);
  });

  it('keeps broadly readable routes visible to viewer', () => {
    assert.equal(canAccessRoute('viewer', 'dashboard'), true);
    assert.equal(canAccessRoute('viewer', 'findings'), true);
    assert.equal(canAccessRoute('viewer', 'settings'), true);
  });

  it('aligns staff SOC route gate with operational SOC roles only', () => {
    assert.equal(canAccessRoute('admin', 'internal-soc', { principal: 'staff', staffRole: 'admin' }), false);
    assert.equal(canAccessRoute('admin', 'internal-soc', { principal: 'staff', staffRole: 'internal_admin' }), false);
    assert.equal(canAccessRoute('admin', 'internal-soc', { principal: 'staff', staffRole: 'soc_lead' }), true);
  });

  it('allows customers to open queue-detail for authorization pack completion', () => {
    assert.equal(canAccessRoute('engineer', 'queue-detail', { principal: 'customer' }), true);
    assert.equal(canAccessRoute('viewer', 'queue-detail', { principal: 'customer' }), true);
    assert.equal(canAccessRoute('admin', 'queue-detail', { principal: 'staff', staffRole: 'support_engineer' }), true);
  });

  it('gates release-evidence by release_evidence:read', () => {
    assert.equal(canAccessRoute('viewer', 'release-evidence'), false);
    assert.equal(canAccessRoute('engineer', 'release-evidence'), false);
    assert.equal(canAccessRoute('auditor', 'release-evidence'), true);
    assert.equal(canAccessRoute('admin', 'release-evidence'), true);
  });
});
