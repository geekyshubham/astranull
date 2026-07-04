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
    const landing = await request(baseUrl, 'GET', '/');
    assert.equal(landing.status, 200);
    assert.match(landing.text, /AstraNull/);
    assert.match(landing.text, /No-access-first/);
    assert.match(landing.text, /Sign up/);

    const index = await request(baseUrl, 'GET', '/app');
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
    assert.ok(appJs.text.includes('data-action="onboard-retry-heartbeat"'));
    assert.ok(appJs.text.includes('data-action="onboard-start-placement-test"'));
    assert.ok(appJs.text.includes('setupOnboardingHeartbeatPoll'));
    assert.ok(appJs.text.includes("api('/v1/agents')"));
    assert.ok(appJs.text.includes('onboardingHeartbeatTimedOut'));
    assert.ok(appJs.text.includes('data-action="export-evidence-chain"'));
    assert.ok(appJs.text.includes('evidenceCustodyPreview'));
    assert.ok(appJs.text.includes('findingCustodyPreview'));
    assert.ok(appJs.text.includes('reportCustodyPreview'));
    assert.ok(appJs.text.includes('data-action="export-finding"'));
    assert.ok(appJs.text.includes('Custody manifest preview'));
    assert.ok(appJs.text.includes('No raw payloads or secrets are rendered in this preview.'));
    assert.ok(appJs.text.includes('data-action="export-report-selected"'));
    assert.ok(appJs.text.includes('reportKindSelect'));
    assert.ok(appJs.text.includes('/v1/notifications/retries/process'), 'notification retry processing route');
    assert.ok(appJs.text.includes('/v1/notifications/dlq/redrive'), 'notification DLQ redrive route');
    assert.ok(appJs.text.includes('data-action="process-notification-retries"'), 'notification retry action');
    assert.ok(appJs.text.includes('data-action="redrive-notification-dlq"'), 'notification DLQ redrive action');
    assert.ok(appJs.text.includes('lastNotificationRetryResult'), 'notification retry output state');
    assert.ok(appJs.text.includes('lastNotificationRedriveResult'), 'notification redrive output state');
    assert.ok(appJs.text.includes("channel: 'in_app'"), 'notification quick action uses safe in-app default');

    const uiHelpers = await request(baseUrl, 'GET', '/ui-helpers.js');
    assert.equal(uiHelpers.status, 200);
    assert.ok(uiHelpers.text.includes('renderFriendlyEmptyState'));
    assert.ok(uiHelpers.text.includes('PAGE_EMPTY_STATES'));
    assert.ok(appJs.text.includes('renderFriendlyEmptyState'));
    assert.ok(appJs.text.includes('data-action="goto-onboarding"'));
    assert.ok(appJs.text.includes('data-action="tg-detail"'));
    assert.ok(appJs.text.includes('renderTargetGroupDetailPanel'));
    assert.ok(appJs.text.includes('data-tg-tab'));
    assert.ok(appJs.text.includes('data-action="tg-save-settings"'));
    assert.ok(appJs.text.includes('data-action="tg-archive"'));
    assert.ok(appJs.text.includes('data-action="tg-target-save"'));
    assert.ok(appJs.text.includes('data-action="tg-target-delete"'));
    assert.ok(appJs.text.includes("method: 'PATCH'"));
    assert.ok(appJs.text.includes("method: 'DELETE'"));
    assert.ok(appJs.text.includes('/v1/target-groups/${groupId}'));
    assert.ok(appJs.text.includes('/v1/target-groups/${groupId}/targets/${targetId}'));
    assert.ok(appJs.text.includes('data-action="finding-status"'));
    assert.ok(uiHelpers.text.includes('onboarding-troubleshoot'));
    assert.ok(uiHelpers.text.includes('renderOnboardingHeartbeatPanel'));
    assert.ok(uiHelpers.text.includes('resolveOnboardingHeartbeatState'));
    assert.ok(uiHelpers.text.includes('summarizeOnboardingPlacementConfidenceHint'));
    assert.ok(uiHelpers.text.includes('onboarding_heartbeat'));
    assert.ok(uiHelpers.text.includes('verify_heartbeat'));
    assert.ok(uiHelpers.text.includes('path.protected_canary.safe'));
    assert.ok(uiHelpers.text.includes('renderTargetGroupDetailPanel'));
    assert.ok(uiHelpers.text.includes('TARGET_GROUP_DETAIL_TABS'));
    assert.ok(uiHelpers.text.includes('data-action="tg-archive"'));
    assert.ok(appJs.text.includes('Recent test runs'));
    assert.ok(uiHelpers.text.includes('buildInstallCommands'));
    assert.ok(uiHelpers.text.includes('buildEvidenceChainExport'));
    assert.ok(uiHelpers.text.includes('renderReportBuilder'));
    assert.ok(uiHelpers.text.includes('renderSupportReadinessPanel'));
    assert.ok(uiHelpers.text.includes('buildSupportReadinessPreview'));
    assert.ok(appJs.text.includes("['soc', 'SOC Console']"), 'SOC operator route still exists');
    assert.ok(appJs.text.includes('data-action="soc-review-pack"'));
    assert.ok(appJs.text.includes('data-action="soc-schedule"'));
    assert.ok(appJs.text.includes('data-action="soc-post-report"'));
    assert.ok(appJs.text.includes('data-action="soc-close"'));
    assert.ok(appJs.text.includes('data-action="soc-kill-on"'));
    assert.ok(appJs.text.includes('socDevScheduleWindow'));
    assert.ok(appJs.text.includes('post_test_report_required'));
    assert.ok(appJs.text.includes('scope_and_rate_plan'), 'authorization pack uses policy artifact type');
    assert.ok(!appJs.text.includes('scope_rate_plan'), 'authorization pack must not use stale scope/rate type');
    assert.ok(appJs.text.includes('content_sha256'), 'artifact upload includes required digest');
    assert.ok(appJs.text.includes('await sha256Hex'), 'artifact digest is computed before upload');
    assert.ok(appJs.text.includes('await buildHsArtifactUploadBody'), 'artifact upload awaits digest helper');
    assert.ok(appJs.text.includes("if (id === 'soc') return perms.socHighScale"), 'SOC console nav must be SOC-only');
    assert.ok(appJs.text.includes("if (id === 'audit') return perms.auditRead"), 'audit nav gated by audit:read');
    assert.ok(appJs.text.includes("if (id === 'release-evidence') return perms.releaseEvidenceRead"), 'release evidence nav gated');
    assert.ok(appJs.text.includes("route = 'dashboard'"), 'hidden routes fall back to dashboard');
    assert.ok(appJs.text.includes("request.authorization_pack_status?.overall === 'accepted'"), 'SOC approve requires accepted authorization pack');
    assert.ok(appJs.text.includes('state === \'stopped\' && request.hasPostTestReport'), 'SOC close requires stopped request and stored report');
    assert.ok(appJs.text.includes('/internal/soc/high-scale/${r.id}/post-test-report'), 'SOC console checks post-test report existence');

    assert.ok(appJs.text.includes("route === 'waf-posture'"), 'waf-posture route wired');
    assert.ok(appJs.text.includes('viewWafPosture'), 'waf-posture view');
    assert.ok(appJs.text.includes('fetchWafConsolePayload'), 'waf console fetches tolerate partial API failures');
    assert.ok(appJs.text.includes('Validation runs are temporarily unavailable'), 'waf validations degraded state copy');
    assert.ok(appJs.text.includes('Coverage data is temporarily unavailable'), 'waf coverage degraded state copy');
    const discoveryImportHandler = appJs.text.match(
      /document\.querySelectorAll\('\[data-action="discovery-import"\]'\)[\s\S]*?\}\);/,
    )?.[0] ?? '';
    assert.equal(discoveryImportHandler.includes("target_group_id: 'tg_1'"), false, 'discovery import must not hardcode tg_1');
    assert.ok(appJs.text.includes('discoveryImportTargetGroup_${b.dataset.id}'), 'discovery import reads candidate-specific declared target group select');
    assert.ok(appJs.text.includes('vizEsc(r.reason'), 'SOC queue reason must be escaped');
    assert.ok(appJs.text.includes('vizEsc(r.target_group_id'), 'SOC queue target group must be escaped');
    assert.ok(appJs.text.includes("api('/v1/target-groups')"), 'discovery view loads target groups');
    assert.ok(appJs.text.includes('data-action="waf-create-demo-asset"'), 'waf demo asset action');
    assert.ok(appJs.text.includes('data-action="waf-run-validation"'), 'waf run validation action');
    assert.ok(!appJs.text.includes('data-action="waf-finalize-pass"'), 'waf finalize pass action must not be exposed');
    assert.ok(appJs.text.includes('/v1/waf/retests'), 'waf retests list fetch');
    assert.ok(appJs.text.includes('buildRetestMapByDriftEventId'), 'waf retest hydration helper');
    assert.ok(appJs.text.includes('/v1/waf/reports/'), 'waf report export API');
    assert.ok(appJs.text.includes('renderWafReportsPanel'), 'waf reports panel helper');
    assert.ok(appJs.text.includes('renderWafCriticalityCard'), 'waf criticality overview card');
    assert.ok(appJs.text.includes('/v1/waf/coverage/criticality'), 'waf criticality rollup fetch');
    assert.ok(appJs.text.includes('renderWafVendorMixCard'), 'waf vendor mix overview card');
    assert.ok(appJs.text.includes('/v1/waf/coverage/vendors'), 'waf vendor rollup fetch');
    assert.ok(appJs.text.includes('renderWafGeographyCard'), 'waf geography overview card');
    assert.ok(appJs.text.includes('/v1/waf/coverage/geography'), 'waf geography rollup fetch');
    assert.ok(appJs.text.includes('renderWafRoadmapPanel'), 'waf roadmap panel');
    assert.ok(appJs.text.includes('/v1/waf/coverage/risk-roadmap'), 'waf risk roadmap fetch');
    assert.ok(appJs.text.includes('renderWafPostureTabs'), 'waf posture sub-tabs');
    assert.ok(appJs.text.includes('renderWafAssetsTable'), 'waf assets table with effectiveness columns');
    assert.ok(appJs.text.includes('renderWafAssetEffectivenessSection'), 'waf asset detail effectiveness');
    assert.ok(appJs.text.includes('data-waf-posture-tab'), 'waf posture tab controls');
    assert.ok(appJs.text.includes('data-action="waf-view-asset"'), 'waf asset detail action');
    assert.ok(appJs.text.includes('activeWafPostureTab'), 'waf posture tab state');
    assert.ok(appJs.text.includes('selectedWafAssetId'), 'waf selected asset state');
    assert.ok(appJs.text.includes('data-action="waf-report-export"'), 'waf report export action');
    assert.ok(appJs.text.includes('data-action="waf-report-custody-preview"'), 'waf report custody preview action');
    assert.ok(appJs.text.includes('/v1/waf/drift-events'), 'waf drift events fetch');
    assert.ok(appJs.text.includes('renderWafDriftQueue'), 'waf drift queue helper');
    assert.ok(appJs.text.includes('renderWafValidationPlansPanel'), 'waf validation plans panel helper');
    assert.ok(appJs.text.includes('/v1/waf/validation-plans'), 'waf validation plans fetch');
    assert.ok(appJs.text.includes('/v1/waf/validation-plans/scheduled'), 'waf scheduled validation plans fetch');
    assert.ok(appJs.text.includes('fetchWafValidationPlansPanelData'), 'isolated validation plan fetch');
    assert.ok(appJs.text.includes('data-action="waf-plan-create"'), 'waf plan create action');
    assert.ok(appJs.text.includes('data-action="waf-plan-execute"'), 'waf plan execute action');
    assert.ok(appJs.text.includes('data-action="waf-plan-cancel"'), 'waf plan cancel action');
    assert.ok(appJs.text.includes('/v1/connectors'), 'waf connectors list fetch');
    assert.ok(appJs.text.includes('renderWafConnectorsPanel'), 'waf connectors panel helper');
    assert.ok(appJs.text.includes('wafConnectorRead'), 'waf connector read permission modeled');
    assert.ok(appJs.text.includes("roleHasUiPermission(role, 'waf:connector_read')"), 'waf connector read role check');
    assert.ok(appJs.text.includes('permissionDenied'), 'waf connector permission denied state');
    assert.ok(appJs.text.includes('forbidden|permission|unauthorized'), 'waf connector forbidden branch');
    assert.ok(appJs.text.includes('renderWafScenarioCadencePanel'), 'waf scenario cadence panel helper');
    assert.ok(appJs.text.includes('/v1/waf/scenario-intake'), 'waf scenario intake API');
    assert.ok(appJs.text.includes('/v1/waf/products'), 'waf product catalog API');
    assert.ok(appJs.text.includes('data-action="waf-scenario-intake-submit"'), 'waf scenario intake submit action');
    assert.ok(uiHelpers.text.includes('Control-bypass taxonomy'), 'control bypass taxonomy copy');
    assert.ok(appJs.text.includes('fetchWafConnectorsPanelData'), 'isolated connectors fetch');
    assert.ok(appJs.text.includes('data-action="waf-connector-poll"'), 'waf connector poll action');
    assert.ok(appJs.text.includes('summarizeWafConnectorPollResult'), 'waf connector poll result redaction');
    assert.ok(appJs.text.includes('summarizeWafConnectorPollError'), 'waf connector poll error redaction');
    assert.ok(appJs.text.includes('runWafConnectorPoll'), 'waf connector poll runner');
    assert.ok(appJs.text.includes('data-action="waf-drift-status"'), 'waf drift status action');
    assert.ok(appJs.text.includes('data-action="waf-drift-retest"'), 'waf drift retest action');
    assert.ok(appJs.text.includes('data-action="waf-retest-execute"'), 'waf retest execute action');
    assert.ok(appJs.text.includes('data-action="waf-retest-complete"'), 'waf retest complete action');
    assert.ok(appJs.text.includes('waf_feature_disabled'), 'waf disabled state copy');
    assert.ok(appJs.text.includes('Metadata-only summaries are shown here'), 'waf metadata-only evidence panel');
    assert.ok(appJs.text.includes('lastWafOut'), 'durable waf output state');
    assert.ok(appJs.text.includes('id="wafOut"'), 'waf output element');
    assert.ok(appJs.text.includes('summarizeWafActionResult'), 'waf action result redaction helper');
    assert.ok(appJs.text.includes('summarizeWafActionError'), 'waf action error redaction helper');
    assert.ok(!appJs.text.includes('setWafOut(result ?? { ok: true })'), 'waf actions must not dump raw API JSON');
    assert.ok(!appJs.text.includes('raw_payload'), 'waf UI must not reference raw_payload');
    assert.ok(!appJs.text.includes('exploit_payload'), 'waf UI must not reference exploit payloads');
    assert.ok(!appJs.text.match(/\battack\b/i), 'waf UI must avoid attack terminology');

    const css = await request(baseUrl, 'GET', '/styles.css');
    assert.equal(css.status, 200);
    assert.ok(css.text.length > 50);
    assert.ok(css.text.includes('.soc-action-grid'));
    assert.ok(css.text.includes('.soc-out'));
    assert.ok(css.text.includes('.onboarding-wizard'));
    assert.ok(css.text.includes('.onboarding-heartbeat-panel'));
    assert.ok(css.text.includes('.onboarding-placement-hint'));
    assert.ok(css.text.includes('.friendly-empty'));
    assert.ok(css.text.includes('.friendly-empty-actions'));
    assert.ok(css.text.includes('.notification-ops-panel'));
    assert.ok(css.text.includes('.notification-dlq-table'));
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
    assert.ok(css.text.includes('.waf-reports-panel'));
    assert.ok(css.text.includes('.waf-criticality-card'));
    assert.ok(css.text.includes('.waf-vendor-mix-card'));
    assert.ok(css.text.includes('.waf-geography-card'));
    assert.ok(css.text.includes('.waf-roadmap-panel'));
    assert.ok(css.text.includes('.waf-posture-tabs'));
    assert.ok(css.text.includes('.waf-assets-table'));
    assert.ok(css.text.includes('.waf-asset-effectiveness'));
    assert.ok(uiHelpers.text.includes('renderWafVendorMixCard'));
    assert.ok(uiHelpers.text.includes('renderWafGeographyCard'));
    assert.ok(uiHelpers.text.includes('renderWafRoadmapPanel'));
    assert.ok(uiHelpers.text.includes('renderWafPostureTabs'));
    assert.ok(uiHelpers.text.includes('renderWafAssetsTable'));
    assert.ok(uiHelpers.text.includes('renderWafAssetEffectivenessSection'));
    assert.ok(uiHelpers.text.includes('computeWafAssetPassRate'));
    assert.ok(css.text.includes('.waf-drift-queue'));
    assert.ok(css.text.includes('.waf-plan-panel'));
    assert.ok(css.text.includes('.waf-plan-form'));
    assert.ok(css.text.includes('.waf-plan-table'));
    assert.ok(css.text.includes('.waf-plan-actions'));
    assert.ok(css.text.includes('.waf-connectors-panel'));
    assert.ok(css.text.includes('.waf-connectors-table'));
    assert.ok(uiHelpers.text.includes('renderWafReportsPanel'));
    assert.ok(uiHelpers.text.includes('compliance_audit'), 'waf compliance report picker option');
    assert.ok(uiHelpers.text.includes('board_roadmap_brief'), 'waf board roadmap report picker option');
    assert.ok(uiHelpers.text.includes('renderWafCriticalityCard'));
    assert.ok(uiHelpers.text.includes('buildRetestMapByDriftEventId'));
    assert.ok(uiHelpers.text.includes('renderWafDriftQueue'));
    assert.ok(uiHelpers.text.includes('renderWafValidationPlansPanel'));
    assert.ok(uiHelpers.text.includes('renderWafConnectorsPanel'));
    assert.ok(uiHelpers.text.includes('Validation plans are temporarily unavailable'));
    assert.ok(uiHelpers.text.includes('Connector health is temporarily unavailable'));
    assert.ok(uiHelpers.text.includes('Connector access denied'));
    assert.ok(uiHelpers.text.includes('summarizeWafConnectorHealthSummary'));
    assert.ok(uiHelpers.text.includes('resolveWafConnectorLastPollAt'));
    assert.ok(uiHelpers.text.includes('renderNotificationOpsPanel'));
    assert.ok(uiHelpers.text.includes('provider_failed_dlq'));
    assert.ok(uiHelpers.text.includes('redrive-notification-dlq'));
    assert.ok(uiHelpers.text.includes('notification-redrive-result'));
    assert.ok(uiHelpers.text.includes('ASTRANULL_NOTIFICATION_DELIVERY_MODE'));
    assert.ok(uiHelpers.text.includes('rate_limit_marker'), 'waf plan scenario contract id');
    assert.ok(!uiHelpers.text.includes('rate_limit_safe'), 'waf plan must not offer invalid scenario id');
    assert.ok(uiHelpers.text.includes("id: 'daily'"), 'waf plan daily schedule');
    assert.ok(uiHelpers.text.includes("id: 'weekly'"), 'waf plan weekly schedule');
    assert.ok(uiHelpers.text.includes("id: 'monthly'"), 'waf plan monthly schedule');
    assert.ok(!uiHelpers.text.includes("id: 'hourly'"), 'waf plan must not offer hourly schedule');
    assert.ok(!uiHelpers.text.includes('data-waf-drift-note'), 'drift note input removed');

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
      uiHelpers.text.includes('does <strong>not</strong> prove customer-specific launch by itself'),
      'release evidence must not imply customer-specific launch by itself',
    );
    assert.ok(uiHelpers.text.includes('renderPlacementDiagnosticsPanel'));
    assert.ok(uiHelpers.text.includes('extractPlacementDiagnosticsFromReadiness'));
    assert.ok(uiHelpers.text.includes('renderProbeProfileKind'));
    assert.ok(appJs.text.includes('renderPlacementDiagnosticsPanel'));
    assert.ok(appJs.text.includes('renderAgentFleetTable'));
    assert.ok(css.text.includes('.placement-diagnostics-panel'));
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
