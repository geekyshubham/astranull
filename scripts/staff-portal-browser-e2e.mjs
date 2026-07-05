#!/usr/bin/env node
/**
 * Staff-only browser E2E (unlinked surface): direct URL login → internal admin routes.
 * Not part of customer-facing verification.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..');
const STAFF_ROUTES = ['overview', 'signup-queue', 'tenants', 'approvals', 'audit'];

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

async function runStaffBrowserE2e(baseUrl) {
  const { chromium } = await import('playwright-core');
  const failures = [];

  function fail(step, detail) {
    failures.push({ step, detail });
    console.error('FAIL', step, detail);
  }

  let browser;
  try {
    browser = await chromium.launch({ headless: true, channel: 'chrome' });
  } catch {
    browser = await chromium.launch({ headless: true });
  }

  const page = await browser.newPage();
  try {
    const staffModuleResp = await page.request.get(`${baseUrl}/react-app.js`);
    const staffCt = staffModuleResp.headers()['content-type'] ?? '';
    if (!/javascript/i.test(staffCt)) fail('react-app.js mime', staffCt || 'missing content-type');

    await page.goto(`${baseUrl}/internal/admin/login`, { waitUntil: 'networkidle', timeout: 60000 });
    await page.waitForSelector('#staffLoginSubmit', { timeout: 15000 });
    await page.click('#staffLoginSubmit');

    try {
      await page.waitForURL((url) => url.pathname === '/internal/admin' || url.pathname.startsWith('/internal/admin'), { timeout: 30000 });
    } catch {
      const errText = await page.locator('#staffLoginError').textContent().catch(() => '');
      fail('staff login redirect', `still on ${page.url()}${errText ? ` error=${errText}` : ''}`);
    }

    await page.waitForFunction(() => {
      const view = document.getElementById('staffView');
      return view && !view.textContent.includes('Sign-in required');
    }, { timeout: 30000 }).catch(async () => {
      fail('staff overview load', await page.locator('#staffView').innerText().catch(() => ''));
    });

    for (const route of STAFF_ROUTES) {
      await page.goto(`${baseUrl}/internal/admin#${route}`, { waitUntil: 'networkidle' });
      await page.waitForTimeout(500);
      const viewText = await page.locator('#staffView').innerText();
      if (/Sign-in required|Could not load/i.test(viewText) && !/\b0\b/.test(viewText)) {
        fail(`staff route ${route}`, viewText.slice(0, 180));
      }
    }
  } finally {
    await browser.close();
  }

  const result = {
    schema_version: 1,
    artifact_type: 'staff_portal_browser_e2e',
    created_at: new Date().toISOString(),
    base_url: baseUrl,
    ok: failures.length === 0,
    failures,
  };
  try {
    const outDir = path.join(REPO_ROOT, 'output/release-evidence');
    mkdirSync(outDir, { recursive: true });
    writeFileSync(path.join(outDir, 'staff_portal_browser_e2e.json'), `${JSON.stringify(result, null, 2)}\n`);
  } catch {
    // best-effort attest artifact
  }
  console.log(JSON.stringify(result, null, 2));
  return failures.length === 0 ? 0 : 1;
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) {
    console.log('Usage: node scripts/staff-portal-browser-e2e.mjs [--base-url URL]');
    return 0;
  }
  ensurePlaywrightCore();
  return runStaffBrowserE2e(String(opts.baseUrl).replace(/\/$/, ''));
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  main().then(
    (code) => process.exit(code ?? 0),
    (err) => {
      console.error(err instanceof Error ? err.message : String(err));
      process.exit(1);
    },
  );
}