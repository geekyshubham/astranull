import assert from 'node:assert/strict';
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
  'SOC Console',
  'Vector coverage matrix',
  'WAF Posture',
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
  it('serves shell assets and core API payloads', async () => {
    const index = await request(baseUrl, 'GET', '/');
    assert.equal(index.status, 200);
    assert.match(index.text, /AstraNull/);
    assert.match(index.text, /app\.js/);

    const appJs = await request(baseUrl, 'GET', '/app.js');
    assert.equal(appJs.status, 200);
    assert.ok(appJs.text.includes('customer-declared targets'), 'app should state customer-declared targets');
    assert.ok(appJs.text.includes('cloud credentials'), 'app should state no cloud credentials');
    assert.ok(appJs.text.includes('automatic IP inventory discovery'), 'app should reject automatic IP inventory discovery');
    assert.ok(appJs.text.includes('No-access-first'), 'app should surface no-access-first copy');
    assert.ok(appJs.text.includes('PLATFORM_PROMISE'), 'app should define PLATFORM_PROMISE');
    for (const label of REQUIRED_NAV_LABELS) {
      assert.ok(appJs.text.includes(label), `missing nav label: ${label}`);
    }
    assert.ok(appJs.text.includes('SOC authorization pack'));
    const viewHighScale = appJs.text.match(/async function viewHighScale\(\)[\s\S]*?(?=\nasync function )/)?.[0] ?? '';
    assert.ok(viewHighScale.includes('data-action="hs-submit-request"'), 'high-scale submit form');
    assert.ok(viewHighScale.includes('hsScopeConfirmation'), 'scope confirmation field');
    assert.ok(viewHighScale.includes('id="high-scale"'), 'high-scale page anchor');
    assert.ok(!viewHighScale.includes('data-action="soc-start"'), 'customer high-scale page must not expose SOC start');
    assert.ok(appJs.text.includes('lastHighScaleOut'), 'durable high-scale output state');
    assert.ok(appJs.text.includes('setHighScaleOut'), 'high-scale output setter');
    assert.ok(appJs.text.includes('hsRequestOut'), 'high-scale output element id');
    assert.ok(appJs.text.includes('from \'./ui-helpers.js\''));
    assert.ok(appJs.text.includes('data-action="copy-install"'));
    assert.ok(appJs.text.includes('data-action="onboard-start-run"'));
    assert.ok(appJs.text.includes('data-action="export-evidence-chain"'));
    assert.ok(appJs.text.includes('evidenceCustodyPreview'));
    assert.ok(appJs.text.includes('findingCustodyPreview'));
    assert.ok(appJs.text.includes('reportCustodyPreview'));
    assert.ok(appJs.text.includes('data-action="export-finding"'));
    assert.ok(appJs.text.includes('Custody manifest preview'));
    assert.ok(appJs.text.includes('No raw payloads or secrets are rendered in this preview.'));
    assert.ok(appJs.text.includes('data-action="export-report-selected"'));
    assert.ok(appJs.text.includes('reportKindSelect'));

    const uiHelpers = await request(baseUrl, 'GET', '/ui-helpers.js');
    assert.equal(uiHelpers.status, 200);
    assert.ok(uiHelpers.text.includes('buildInstallCommands'));
    assert.ok(uiHelpers.text.includes('buildEvidenceChainExport'));
    assert.ok(uiHelpers.text.includes('renderReportBuilder'));
    assert.ok(uiHelpers.text.includes('renderSupportReadinessPanel'));
    assert.ok(uiHelpers.text.includes('buildSupportReadinessPreview'));
    assert.ok(appJs.text.includes('data-action="soc-review-pack"'));
    assert.ok(appJs.text.includes('data-action="soc-schedule"'));
    assert.ok(appJs.text.includes('data-action="soc-post-report"'));
    assert.ok(appJs.text.includes('data-action="soc-close"'));
    assert.ok(appJs.text.includes('data-action="soc-kill-on"'));
    assert.ok(appJs.text.includes('socDevScheduleWindow'));
    assert.ok(appJs.text.includes('post_test_report_required'));

    assert.ok(appJs.text.includes("route === 'waf-posture'"), 'waf-posture route wired');
    assert.ok(appJs.text.includes('viewWafPosture'), 'waf-posture view');
    assert.ok(appJs.text.includes('data-action="waf-create-demo-asset"'), 'waf demo asset action');
    assert.ok(appJs.text.includes('data-action="waf-run-validation"'), 'waf run validation action');
    assert.ok(appJs.text.includes('data-action="waf-finalize-pass"'), 'waf finalize pass action');
    assert.ok(appJs.text.includes('waf_feature_disabled'), 'waf disabled state copy');
    assert.ok(appJs.text.includes('Metadata-only summaries are shown here'), 'waf metadata-only evidence panel');
    assert.ok(appJs.text.includes('lastWafOut'), 'durable waf output state');
    assert.ok(appJs.text.includes('id="wafOut"'), 'waf output element');
    assert.ok(!appJs.text.includes('raw_payload'), 'waf UI must not reference raw_payload');
    assert.ok(!appJs.text.includes('exploit_payload'), 'waf UI must not reference exploit payloads');
    assert.ok(!appJs.text.match(/\battack\b/i), 'waf UI must avoid attack terminology');

    const css = await request(baseUrl, 'GET', '/styles.css');
    assert.equal(css.status, 200);
    assert.ok(css.text.length > 50);
    assert.ok(css.text.includes('.soc-action-grid'));
    assert.ok(css.text.includes('.soc-out'));
    assert.ok(css.text.includes('.onboarding-wizard'));
    assert.ok(css.text.includes('.install-command-row'));
    assert.ok(css.text.includes('.evidence-chain-actions'));
    assert.ok(css.text.includes('.report-builder'));
    assert.ok(appJs.text.includes('buildSupportReadinessPreview'));
    assert.ok(appJs.text.includes('renderSupportReadinessPanel'));
    assert.ok(uiHelpers.text.includes('supportReadinessPanel'));
    assert.ok(uiHelpers.text.includes('not staffed production on-call'));
    assert.ok(css.text.includes('.support-readiness-panel'));
    assert.ok(css.text.includes('.waf-out'));
    assert.ok(css.text.includes('.waf-status-pill'));

    const VIZ_HELPERS = [
      'renderReadinessGauge',
      'renderReadinessRadar',
      'renderVectorHeatmap',
      'renderScoreTrend',
      'renderTrafficPath',
      'renderTruthTable',
      'renderSocSwimlane',
    ];
    for (const name of VIZ_HELPERS) {
      assert.ok(appJs.text.includes(`function ${name}`), `missing viz helper: ${name}`);
    }
    assert.ok(
      appJs.text.includes('misplaced_agent') || appJs.text.includes('normalizeVerdictKey'),
      'app should map misplaced_agent correlation verdict for viz',
    );
    assert.ok(appJs.text.includes('renderRunTimeline'), 'run visual timeline helper');
    assert.ok(appJs.text.includes('renderReadinessGauge(s.readiness.score)'), 'dashboard uses gauge');
    assert.ok(appJs.text.includes('renderTrafficPath(detail)'), 'runs page uses traffic path');
    const verdictExplanation = await request(baseUrl, 'GET', '/verdict-explanation.mjs');
    assert.equal(verdictExplanation.status, 200);
    assert.ok(verdictExplanation.text.includes('function renderVerdictExplanation'), 'verdict explanation helper');
    assert.ok(appJs.text.includes("from './verdict-explanation.mjs'"), 'app imports verdict explanation module');
    assert.ok(appJs.text.includes('renderVerdictExplanation(detail, events)'), 'runs page uses verdict explanation');
    assert.ok(appJs.text.includes('renderFindingVerdictExplanation(finding, runDetail, events)'), 'findings detail explanation');
    assert.ok(appJs.text.includes('data-action="view-finding"'), 'findings list detail selection');
    assert.ok(appJs.text.includes('finding-detail'), 'findings detail card');
    assert.ok(verdictExplanation.text.includes('Why this verdict?'), 'verdict explanation heading');
    assert.ok(verdictExplanation.text.includes('Why this finding?'), 'finding explanation heading');
    assert.ok(
      verdictExplanation.text.includes('placement_confidence'),
      'verdict explanation should prefer backend placement_confidence',
    );
    assert.ok(
      verdictExplanation.text.includes('formatPlacementConfidenceFromVerdict'),
      'placement confidence formatter for backend field',
    );
    assert.ok(
      verdictExplanation.text.includes('metadata?.external_result') ||
        verdictExplanation.text.includes('meta.external_result') ||
        verdictExplanation.text.includes('metadata.external_result'),
      'probe evidence should read external_result from metadata when top-level is absent',
    );
    assert.ok(appJs.text.includes('renderSocSwimlane'), 'SOC page uses swimlane');
    assert.ok(appJs.text.includes('renderReleaseEvidencePanel'), 'release evidence panel helper');
    assert.ok(appJs.text.includes("route === 'release-evidence'"), 'release evidence route wired');
    assert.ok(appJs.text.includes('viewReleaseEvidence'), 'release evidence view');
    assert.ok(appJs.text.includes('fetchReleaseEvidencePanelData'), 'release evidence API fetch');
    assert.ok(appJs.text.includes('fetchReleaseEvidenceAttestationData'), 'release evidence attestation fetch');
    assert.ok(appJs.text.includes('renderStagingReadinessAttestationPanel'), 'staging attestation panel helper');
    assert.ok(
      appJs.text.includes('/v1/production-release-evidence/attestation'),
      'release evidence attestation route',
    );
    assert.ok(
      uiHelpers.text.includes('does <strong>not</strong> mean production readiness is complete'),
      'release evidence must not imply production readiness complete',
    );
    assert.ok(uiHelpers.text.includes('renderReleaseEvidencePanel'));
    assert.ok(uiHelpers.text.includes('renderStagingReadinessAttestationPanel'));
    assert.ok(uiHelpers.text.includes('pickReleaseEvidenceCustodyUri'));

    const VIZ_CLASSES = [
      '.viz-grid',
      '.readiness-gauge',
      '.readiness-radar',
      '.vector-heatmap',
      '.score-trend',
      '.traffic-path',
      '.verdict-explanation',
      '.verdict-explanation-grid',
      '.truth-table-viz',
      '.soc-swimlane',
      '.release-evidence-panel',
      '.release-evidence-gate',
      '.staging-readiness-attestation-panel',
    ];
    for (const cls of VIZ_CLASSES) {
      assert.ok(css.text.includes(cls), `missing viz css: ${cls}`);
    }

    const favicon = await request(baseUrl, 'GET', '/favicon.ico');
    assert.equal(favicon.status, 204);

    const state = await request(baseUrl, 'GET', '/v1/state', { headers: demoHeaders('admin') });
    assert.equal(state.status, 200);
    assert.ok(state.json.readiness);

    const checks = await request(baseUrl, 'GET', '/v1/checks');
    assert.equal(checks.status, 200);
    assert.ok(checks.json.items.length >= 1);
  });
});
