import {
  fetchPortalConfig,
  loadSession,
  saveSession,
  sessionFromLoginResponse,
} from './portal-auth.mjs';

const form = document.getElementById('staffLoginForm');
const errorEl = document.getElementById('staffLoginError');
const introEl = document.getElementById('staffLoginIntro');
const submitBtn = document.getElementById('staffLoginSubmit');

function showError(message) {
  if (!errorEl) return;
  errorEl.hidden = !message;
  errorEl.textContent = message ?? '';
}

const config = await fetchPortalConfig();
const existing = loadSession();
if (existing?.access_token && existing.principal === 'staff') {
  window.location.replace('/internal/admin');
}

if (config.authMode === 'dev-headers' && introEl) {
  introEl.textContent = 'Developer validation mode — continue with staff dev headers (no password required).';
}

if (!config.bundledLoginEnabled && config.authMode !== 'dev-headers') {
  showError('Staff SSO is required for this deployment.');
  if (submitBtn) submitBtn.disabled = true;
}

form?.addEventListener('submit', async (event) => {
  event.preventDefault();
  showError('');

  const staffId = document.getElementById('staffId')?.value?.trim() ?? 'staff_admin';
  const staffRole = document.getElementById('staffRole')?.value ?? 'internal_admin';

  const staffLoginPath = window.location.pathname;

  if (config.authMode === 'dev-headers') {
    saveSession({
      mode: 'dev-headers',
      principal: 'staff',
      staff_id: staffId,
      staff_role: staffRole,
      staff_login_path: staffLoginPath,
    });
    window.location.replace('/internal/admin');
    return;
  }

  try {
    const res = await fetch('/v1/auth/bundled-staging-login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({
        principal: 'staff',
        staff_id: staffId,
        staff_role: staffRole,
      }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      showError(data.message ?? data.error ?? 'Staff login failed.');
      return;
    }
    saveSession({ ...sessionFromLoginResponse(data), staff_login_path: staffLoginPath });
    window.location.replace('/internal/admin');
  } catch (err) {
    showError(err instanceof Error ? err.message : 'Staff login failed.');
  }
});