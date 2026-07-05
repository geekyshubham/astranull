#!/usr/bin/env node
/**
 * Customer-only browser E2E: landing → login → all portal routes.
 * Asserts staff login is not exposed on any customer-facing page.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');

const CUSTOMER_ROUTES = [
  'dashboard', 'onboarding', 'environments', 'target-groups', 'agents', 'checks',
  'runs', 'findings', 'evidence', 'waf-posture', 'cve-pipeline', 'supply-chain',
  'remediation', 'discovery', 'high-scale', 'soc', 'reports', 'notifications',
  'audit', 'release-evidence', 'settings',
];

const CUSTOMER_ASSETS = ['/react-app.js', '/react-app.css'];
const STAFF_LEAK_RE = /\/internal\/admin|staff-login|Internal management sign-in|AstraNull staff\?/i;

function parseArgs(argv = []) {
  const opts = { baseUrl: process.env.ASTRANULL_HOSTED_STAGING_BASE_URL ?? 'http://127.0.0.1:3000', help: false };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') opts.help = true;
    else if (arg === '--base-url') opts.baseUrl = argv[++i];
  }
  return opts;
}

function ensurePlaywrightCore() {
  const check = spawnSync('npm', ['ls', 'playwright-core', '--depth=0'], { cwd: REPO_ROOT, encoding: 'utf8' });
  if (check.status !== 0) {
    const install = spawnSync('npm', ['install', '--no-save', 'playwright-core@1.52.0'], {
      cwd: REPO_ROOT, stdio: 'inherit',
    });
    if (install.status !== 0) throw new Error('Failed to install playwright-core');
  }
}

async function launchBrowser(chromium) {
  const launchOpts = { headless: true };
  try {
    return await chromium.launch({ ...launchOpts, channel: 'chrome' });
  } catch {
    try {
      return await chromium.launch(launchOpts);
    } catch {
      return chromium.connectOverCDP('ws://127.0.0.1:9222');
    }
  }
}

function assertNoStaffLeak(fail, step, text) {
  if (STAFF_LEAK_RE.test(text)) {
    fail(step, 'staff surface leaked in customer UI');
  }
}

/**
 * @param {string} baseUrl
 */
export async function runCustomerBrowserE2e(baseUrl) {
  const { chromium } = await import('playwright-core');
  const failures = [];
  const consoleErrors = [];
  const notFoundUrls = [];

  function fail(step, detail) {
    failures.push({ step, detail });
    console.error('FAIL', step, detail);
  }

  const browser = await launchBrowser(chromium);
  const page = await browser.newPage();
  page.on('pageerror', (err) => consoleErrors.push(String(err)));
  page.on('console', (msg) => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });
  page.on('response', (resp) => { if (resp.status() === 404) notFoundUrls.push(resp.url()); });

  try {
    for (const asset of CUSTOMER_ASSETS) {
      const resp = await page.request.get(baseUrl + asset);
      const ct = resp.headers()['content-type'] ?? '';
      if (!resp.ok()) { fail(`asset ${asset}`, `HTTP ${resp.status()}`); continue; }
      if (asset.endsWith('.mjs') && !/javascript/i.test(ct)) fail(`mime ${asset}`, ct || 'missing content-type');
    }

    const siteConfig = await page.request.get(`${baseUrl}/v1/public/site-config`);
    if (siteConfig.ok()) {
      const cfg = await siteConfig.json();
      if (cfg.staff_login_path || cfg.internal_admin_path) {
        fail('site-config privacy', 'staff paths published in public site-config');
      }
    }

    for (const customerPath of ['/', '/login', '/signup']) {
      await page.goto(`${baseUrl}${customerPath}`, { waitUntil: 'networkidle', timeout: 60000 });
      const html = await page.content();
      const text = await page.locator('body').innerText();
      assertNoStaffLeak(fail, `staff leak ${customerPath}`, html + text);
    }

    await page.goto(`${baseUrl}/login`, { waitUntil: 'networkidle', timeout: 60000 });
    await page.getByRole('button', { name: 'Continue to portal' }).click({ timeout: 30000 });
    try {
      await page.waitForURL((url) => url.pathname === '/app' || url.pathname.startsWith('/app'), { timeout: 30000 });
    } catch {
      const errText = await page.locator('[role="alert"], .form-error').first().textContent().catch(() => '');
      fail('login redirect', `still on ${page.url()}${errText ? ` error=${errText}` : ''}`);
    }

    try {
      await page.waitForFunction(() => {
        const text = document.body.innerText ?? '';
        const hasShell = text.includes('Customer readiness console') || text.includes('Live workspace');
        const hasNav = document.querySelectorAll('.nav-item').length > 3;
        return hasShell && hasNav && !text.includes('Sign-in required');
      }, { timeout: 30000 });
    } catch {
      fail('dashboard load', await page.locator('body').innerText().catch(() => ''));
    }

    const portalHtml = await page.content();
    const portalText = await page.locator('body').innerText();
    assertNoStaffLeak(fail, 'staff leak /app', portalHtml + portalText);

    for (const route of CUSTOMER_ROUTES) {
      await page.goto(`${baseUrl}/app#${route}`, { waitUntil: 'networkidle' });
      await page.waitForTimeout(600);
      const viewText = await page.locator('main.main, body').first().innerText();
      if (/Sign-in required|Unable to load this page: unauthorized/i.test(viewText)) {
        fail(`route ${route}`, viewText.slice(0, 180));
        continue;
      }
      if (/Unable to load this page/i.test(viewText) && !/Your current role cannot access/i.test(viewText)) {
        fail(`route ${route}`, viewText.slice(0, 180));
      }
      assertNoStaffLeak(fail, `staff leak route ${route}`, await page.content());
    }
  } finally {
    await browser.close();
  }

  if (consoleErrors.some((e) => /Failed to load module script/i.test(e))) {
    fail('module script mime', consoleErrors.filter((e) => /Failed to load module script/i.test(e)).join(' | '));
  }
  if (notFoundUrls.length) {
    console.log('404 urls:', JSON.stringify([...new Set(notFoundUrls)].slice(0, 20), null, 2));
  }

  const result = {
    schema_version: 1,
    artifact_type: 'customer_portal_browser_e2e',
    created_at: new Date().toISOString(),
    base_url: baseUrl,
    ok: failures.length === 0,
    failures,
    consoleErrorCount: consoleErrors.length,
    notFoundCount: notFoundUrls.length,
  };
  try {
    const outDir = path.join(REPO_ROOT, 'output/release-evidence');
    mkdirSync(outDir, { recursive: true });
    writeFileSync(path.join(outDir, 'customer_portal_browser_e2e.json'), `${JSON.stringify(result, null, 2)}\n`);
  } catch {
    // attest artifact is best-effort for local runs
  }
  console.log(JSON.stringify(result, null, 2));
  return failures.length === 0 ? 0 : 1;
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) {
    console.log('Usage: node scripts/hosted-portal-browser-e2e.mjs [--base-url URL]');
    return 0;
  }
  ensurePlaywrightCore();
  return runCustomerBrowserE2e(String(opts.baseUrl).replace(/\/$/, ''));
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  main().then((code) => process.exit(code ?? 0));
}