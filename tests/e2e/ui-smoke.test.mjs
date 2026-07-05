import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { after, before, describe, it } from 'node:test';
import { createServer } from '../../src/server.mjs';
import { demoHeaders, request } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';

let baseUrl;
let server;

const REQUIRED_NAV_LABELS = [
  'Dashboard',
  'Environments',
  'Evidence Vault',
  'Reports',
  'Release Evidence',
  'Settings',
  'Notifications',
  'Vector coverage matrix',
  'WAF Posture',
];

const LEGACY_ASSETS = [
  '/app.js',
  '/ui-helpers.js',
  '/styles.css',
  '/public-site.js',
  '/signup.js',
  '/internal-admin.js',
  '/login.mjs',
  '/portal-auth.mjs',
  '/staff-login.mjs',
  '/verdict-explanation.mjs',
];

before(() => {
  process.env.ASTRANULL_NO_PERSIST = '1';
  freshStore();
  server = createServer();
  server.listen(0);
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(() => server.close());

describe('ui and api smoke', () => {
  it('serves React SPA shell assets and rejects legacy static pages', async () => {
    const landing = await request(baseUrl, 'GET', '/');
    assert.equal(landing.status, 200);
    assert.match(landing.text, /AstraNull/);
    assert.match(landing.text, /id="root"/);
    assert.match(landing.text, /react-app\.js/);
    assert.match(landing.text, /react-app\.css/);
    assert.doesNotMatch(landing.text, /public-site\.js/);
    assert.doesNotMatch(landing.text, /href="\/styles\.css"/);
    assert.doesNotMatch(landing.text, /src="\/app\.js"/);

    const appShell = await request(baseUrl, 'GET', '/app');
    assert.equal(appShell.status, 200);
    assert.match(appShell.text, /id="root"/);
    assert.match(appShell.text, /react-app\.js/);

    for (const asset of LEGACY_ASSETS) {
      const legacy = await request(baseUrl, 'GET', asset);
      assert.equal(legacy.status, 404, `legacy asset should be removed: ${asset}`);
    }

    const reactAppJs = await request(baseUrl, 'GET', '/react-app.js');
    assert.equal(reactAppJs.status, 200);
    assert.ok(reactAppJs.text.includes('customer-declared'), 'React app should state customer-declared scope');
    assert.ok(reactAppJs.text.includes('cloud credentials'), 'React app should state no cloud credentials');
    assert.ok(reactAppJs.text.includes('automatic IP inventory discovery'), 'React app should reject automatic IP inventory discovery');
    assert.ok(reactAppJs.text.includes('No-access-first'), 'React app should surface no-access-first copy');
    for (const label of REQUIRED_NAV_LABELS) {
      assert.ok(reactAppJs.text.includes(label), `missing nav label: ${label}`);
    }
    assert.ok(reactAppJs.text.includes('/v1/bootstrap-tokens'), 'React settings page creates and manages bootstrap tokens');
    assert.ok(reactAppJs.text.includes('/v1/service-accounts'), 'React settings page creates and manages service accounts');
    assert.ok(reactAppJs.text.includes('/v1/tenants/current'), 'React settings page loads and patches tenant settings');
    assert.ok(reactAppJs.text.includes('/v1/secrets'), 'React settings page manages encrypted secret vault');
    assert.ok(reactAppJs.text.includes('/v1/target-groups'), 'React target groups page creates declared scope records');
    assert.ok(reactAppJs.text.includes('/v1/test-policies'), 'React test policies page creates safe policy records');
    assert.ok(reactAppJs.text.includes('/internal/soc/high-scale/'), 'React SOC console calls governed SOC execution routes');
    assert.ok(reactAppJs.text.includes('/internal/admin/signup-requests/'), 'React staff console approves signup requests');
    assert.ok(reactAppJs.text.includes('Create target group'), 'React onboarding page creates declared scope through APIs');
    assert.ok(reactAppJs.text.includes('Start safe run'), 'React runs page exposes safe validation start controls');
    assert.ok(reactAppJs.text.includes('/v1/waf/assets'), 'React WAF posture page creates assets through backend API');
    assert.ok(reactAppJs.text.includes('/v1/high-scale-requests'), 'React high-scale page creates governed request records');
    assert.equal(reactAppJs.text.includes('Workspace tabs'), false, 'React app must not render prototype SurfaceTabsPanel copy');
    assert.equal(reactAppJs.text.includes('React surfaces'), false, 'Public landing must not show fixed prototype surface counts');

    const reactCss = await request(baseUrl, 'GET', '/react-app.css');
    assert.equal(reactCss.status, 200);
    assert.ok(reactCss.text.length > 50);
    assert.ok(reactCss.text.includes('.verdict-explanation'));
    assert.ok(reactCss.text.includes('.public-hero'));

    const navigationSource = readFileSync(new URL('../../apps/web/react/src/lib/navigation.ts', import.meta.url), 'utf8');
    assert.ok(navigationSource.includes('routeIdFromHash'), 'React router resolves detail routes with hash query params');

    const favicon = await request(baseUrl, 'GET', '/favicon.ico');
    assert.equal(favicon.status, 204);

    const state = await request(baseUrl, 'GET', '/v1/state', { headers: demoHeaders('admin') });
    assert.equal(state.status, 200);
    assert.ok(state.json.readiness);

    const checks = await request(baseUrl, 'GET', '/v1/checks');
    assert.equal(checks.status, 200);
    assert.ok(checks.json.items.length >= 1);

    const removedUiCoverage = await request(baseUrl, 'GET', '/v1/ui/prototype-coverage', {
      headers: demoHeaders('admin'),
    });
    assert.equal(removedUiCoverage.status, 404);
  });
});