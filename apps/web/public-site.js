async function loadSiteConfig() {
  try {
    const res = await fetch('/v1/public/site-config');
    if (!res.ok) return null;
    return res.json();
  } catch {
    return null;
  }
}

function applyLoginLinks(loginUrl) {
  for (const id of ['loginLink', 'heroLogin']) {
    const el = document.getElementById(id);
    if (el) el.href = loginUrl;
  }
}

function applySignupLinks(signupEnabled, signupPath = '/signup') {
  for (const id of ['signupLink', 'heroSignup']) {
    const el = document.getElementById(id);
    if (!el) continue;
    if (!signupEnabled) {
      el.style.display = 'none';
    } else {
      el.href = signupPath;
    }
  }
}

const config = await loadSiteConfig();
if (config?.promise) {
  const hero = document.getElementById('heroPromise');
  if (hero) hero.textContent = config.promise;
}
if (config?.login_url) applyLoginLinks(config.login_url);
applySignupLinks(config?.signup_enabled !== false, config?.signup_path ?? '/signup');