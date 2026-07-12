import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, it } from 'node:test';

const ROOT = process.cwd();
const REACT_SRC = path.join(ROOT, 'apps/web/react/src');

function read(rel) {
  return readFileSync(path.join(REACT_SRC, rel), 'utf8');
}

/**
 * Regression guard for the "no fabricated runtime values in the portal" audit.
 * Under oidc-jwt nothing fabricated may be displayed or sent; dev/staging identity
 * literals must stay behind their existing dev-headers/bundled-staging gates only.
 */
describe('portal has no fabricated runtime fallbacks (audit FT-PROV)', () => {
  it('app-shell does not fabricate a "dev" environment or "ten_demo" tenant for display', () => {
    const src = read('components/layout/app-shell.tsx');
    assert.ok(!/environment[^\n]*\?\?\s*'dev'/.test(src), 'environment must not fall back to fabricated dev');
    assert.ok(!/tenantId\s*=\s*[^\n]*\?\?\s*'ten_demo'/.test(src), 'tenant label must not fabricate ten_demo');
    assert.ok(/environment[^\n]*\?\?\s*''/.test(src), 'environment should resolve to empty when unknown');
    assert.ok(/tenantId\s*=\s*[^\n]*\?\?\s*'unknown'/.test(src), 'tenant label should use neutral unknown when unresolved');
    assert.ok(/\{environment \? <> · \{environment\}<\/> : null\}/.test(src), 'environment separator should only render for real values');
  });

  it('login/staff forms do not prefill fabricated identities', () => {
    const src = read('pages/public-pages.tsx');
    assert.ok(!/useState\('usr_admin'\)/.test(src), 'customer login must not prefill usr_admin');
    assert.ok(!/useState\('staff_admin'\)/.test(src), 'staff login must not prefill staff_admin');
    assert.ok(!/\|\|\s*'usr_admin'/.test(src), 'no usr_admin identity fallback on submit');
    assert.ok(!/\|\|\s*'staff_admin'/.test(src), 'no staff_admin identity fallback on submit');
    // Identity is user-entered and trimmed.
    assert.ok(/user_id: userId\.trim\(\),/.test(src), 'customer user_id comes from the entered value');
    assert.ok(/staff_id: staffId\.trim\(\),/.test(src), 'staff_id comes from the entered value');
  });

  it('the tenant_id sent by bundled/dev login stays gated (not shown, not oidc identity)', () => {
    const src = read('pages/public-pages.tsx');
    // ten_demo may only appear inside gated dev/bundled login paths and the optional Try demo CTA
    // (all unreachable under a pure oidc-jwt build when loginDisabled short-circuits).
    const occurrences = src.match(/'ten_demo'/g) ?? [];
    assert.equal(occurrences.length, 3, 'ten_demo should only exist in gated login and Try demo paths');
  });

  it('api.ts no longer ships the dead ensureDevSession helper', () => {
    const src = read('lib/api.ts');
    assert.ok(!/ensureDevSession/.test(src), 'dead ensureDevSession with hardcoded identity must be removed');
  });

  it('App.tsx role change no longer fabricates identity', () => {
    const src = read('App.tsx');
    assert.ok(!/\?\?\s*'ten_demo'/.test(src), 'role change must not fabricate ten_demo');
    assert.ok(!/\?\?\s*'usr_admin'/.test(src), 'role change must not fabricate usr_admin');
  });

  it('governance/functional exports source tenant from real state, not ten_demo', () => {
    const gov = read('pages/governance-pages.tsx');
    const func = read('pages/functional-surfaces.tsx');
    assert.ok(!/\?\?\s*'ten_demo'/.test(gov), 'governance export must not fabricate ten_demo');
    assert.ok(!/\?\?\s*'ten_demo'/.test(func), 'custody export must not fabricate ten_demo');
    assert.ok(/data\.state\?\.tenant_id \?\? 'unknown'/.test(gov), 'governance export derives tenant from real state');
    assert.ok(/data\.state\?\.tenant_id \?\? 'unknown'/.test(func), 'custody export derives tenant from real state');
  });

  it('internal entitlement form does not default to a fabricated tenant', () => {
    const src = read('pages/page-components.tsx');
    assert.ok(!/\['tenant_id', 'id'\],\s*'ten_demo'/.test(src), 'entitlement tenant must not default to ten_demo');
    assert.ok(/\['tenant_id', 'id'\],\s*''\)/.test(src), 'entitlement tenant defaults to empty until a real tenant is chosen');
  });

  it('vector heatmap renders real coverage states, never invented percentages', () => {
    const src = read('components/charts/vector-heatmap.tsx');
    assert.ok(!/\$\{score\}%/.test(src), 'heatmap must not print invented percentages');
    assert.ok(!/return 100;|return 75;|return 50;/.test(src), 'heatmap must not bucket into heuristic scores');
    assert.ok(/'no-data'/.test(src) && /'No data'/.test(src), 'heatmap must expose an explicit no-data state');
  });
});

/**
 * Mirrors familyCoverage() from components/charts/vector-heatmap.tsx so the coverage
 * derivation is exercised as behavior (node:test cannot import the tsx directly).
 */
function itemTargetGroupId(item) {
  return String(item.target_group_id ?? item.targetGroupId ?? '');
}
function itemCheckId(item) {
  return String(item.check_id ?? item.checkId ?? '');
}
function familyCoverage({ checkIds, groupId, testPolicies, runs, evidence }) {
  if (!groupId || checkIds.size === 0) {
    return { status: 'no-data', policyCount: 0, runCount: 0, evidenceCount: 0 };
  }
  const policyCount = testPolicies.filter((p) => itemTargetGroupId(p) === groupId && checkIds.has(itemCheckId(p))).length;
  const runCount = runs.filter((r) => itemTargetGroupId(r) === groupId && checkIds.has(itemCheckId(r))).length;
  const evidenceCount = evidence.filter((e) => itemTargetGroupId(e) === groupId && checkIds.has(itemCheckId(e))).length;
  let status = 'none';
  if (evidenceCount > 0) status = 'evidence';
  else if (runCount > 0) status = 'run';
  else if (policyCount > 0) status = 'policy';
  return { status, policyCount, runCount, evidenceCount };
}

describe('vector heatmap coverage derives from real data only', () => {
  const checkIds = new Set(['chk_1']);
  const gid = 'grp_1';

  it('reports no-data when no checks map to the family', () => {
    const cov = familyCoverage({ checkIds: new Set(), groupId: gid, testPolicies: [], runs: [], evidence: [] });
    assert.equal(cov.status, 'no-data');
  });

  it('reports no-data when there is no declared group', () => {
    const cov = familyCoverage({ checkIds, groupId: '', testPolicies: [], runs: [], evidence: [] });
    assert.equal(cov.status, 'no-data');
  });

  it('reports "none" when checks exist but no policy/run/evidence records do', () => {
    const cov = familyCoverage({ checkIds, groupId: gid, testPolicies: [], runs: [], evidence: [] });
    assert.equal(cov.status, 'none');
    assert.equal(cov.evidenceCount, 0);
  });

  it('promotes to policy, then run, then evidence as real records appear', () => {
    const policy = { target_group_id: gid, check_id: 'chk_1' };
    const run = { target_group_id: gid, check_id: 'chk_1' };
    const ev = { target_group_id: gid, check_id: 'chk_1' };

    assert.equal(familyCoverage({ checkIds, groupId: gid, testPolicies: [policy], runs: [], evidence: [] }).status, 'policy');
    assert.equal(familyCoverage({ checkIds, groupId: gid, testPolicies: [policy], runs: [run], evidence: [] }).status, 'run');
    const withEvidence = familyCoverage({ checkIds, groupId: gid, testPolicies: [policy], runs: [run], evidence: [ev] });
    assert.equal(withEvidence.status, 'evidence');
    assert.equal(withEvidence.evidenceCount, 1);
    assert.equal(withEvidence.runCount, 1);
    assert.equal(withEvidence.policyCount, 1);
  });

  it('ignores records from other target groups', () => {
    const otherPolicy = { target_group_id: 'grp_other', check_id: 'chk_1' };
    const cov = familyCoverage({ checkIds, groupId: gid, testPolicies: [otherPolicy], runs: [], evidence: [] });
    assert.equal(cov.status, 'none');
    assert.equal(cov.policyCount, 0);
  });
});
