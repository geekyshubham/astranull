import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import {
  ONBOARDING_HEARTBEAT_TIMEOUT_MS,
  ONBOARDING_PLACEMENT_TEST_CHECK_ID,
  ONBOARDING_STEPS,
  PAGE_EMPTY_STATES,
  PRODUCTION_RELEASE_EVIDENCE_KINDS,
  UI_REPORT_KINDS,
  agentHasRecentHeartbeat,
  buildEvidenceChainExport,
  buildInstallCommands,
  buildSupportReadinessPreview,
  computeOnboardingProgress,
  computeReleaseEvidenceCoverage,
  pickReleaseEvidenceCustodyUri,
  renderAgentFleetTable,
  renderTargetGroupDetailPanel,
  TARGET_GROUP_DETAIL_TABS,
  renderFriendlyEmptyState,
  renderInstallCommandsPanel,
  renderOnboardingHeartbeatPanel,
  renderOnboardingPlacementTestPanel,
  renderOnboardingWizard,
  formatStagingAttestationProfileLabel,
  renderReleaseEvidencePanel,
  resolveReleaseEvidenceBadge,
  resolveStagingAttestationBadge,
  renderStagingReadinessAttestationPanel,
  renderReportBuilder,
  renderSupportReadinessPanel,
  renderNotificationOpsPanel,
  extractPlacementDiagnosticsFromReadiness,
  renderPlacementDiagnosticsPanel,
  renderProbeProfileKind,
  resolveOnboardingHeartbeatState,
  summarizeOnboardingPlacementConfidenceHint,
  summarizeReleaseEvidenceValidation,
  summarizeStagingAttestationEvidenceCounts,
  SUPPORT_READINESS_DEFAULT_PREVIEW,
  renderWafDriftQueue,
  renderWafCriticalityCard,
  renderWafVendorMixCard,
  renderWafGeographyCard,
  renderWafRoadmapPanel,
  renderWafReportsPanel,
  renderWafPostureTabs,
  renderWafAssetsTable,
  renderWafAssetEffectivenessSection,
  computeWafAssetPassRate,
  formatWafPassRateDisplay,
  formatWafRuleHealthDisplay,
  resolveWafControlBypassStatus,
  renderWafValidationPlansPanel,
  renderWafConnectorsPanel,
  roleHasUiPermission,
  resolveWafConnectorLastPollAt,
  summarizeWafConnectorHealthSummary,
  summarizeWafConnectorPollResult,
  summarizeWafConnectorPollError,
  summarizeWafDriftPostureSummary,
  renderDiscoveryPage,
} from '../../apps/web/ui-helpers.js';
import { PRODUCTION_RELEASE_EVIDENCE_KINDS as CONTRACT_KINDS } from '../../src/contracts/productionReleaseEvidence.mjs';

describe('ui-helpers', () => {
  it('renderDiscoveryPage gates import on canApprove and renders target group selector', () => {
    const approvedCandidate = {
      id: 'cand_1',
      hostname: 'app.example.com',
      source_type: 'passive',
      confidence: 0.8,
      ownership_status: 'verified',
      state: 'approved_target',
      first_seen_at: '2026-01-01T00:00:00Z',
      last_seen_at: '2026-01-02T00:00:00Z',
    };
    const withApprove = renderDiscoveryPage({
      inbox: [approvedCandidate],
      candidates: [],
      entities: [],
      targetGroups: [{ id: 'tg_declared', name: 'Declared edge' }],
      canApprove: true,
      canWrite: false,
    });
    assert.ok(withApprove.includes('data-action="discovery-import"'));
    assert.ok(withApprove.includes('id="discoveryImportTargetGroup_cand_1"'));
    assert.ok(withApprove.includes('value="tg_declared"'));
    assert.equal(withApprove.includes('canWrite'), false);

    const withoutApprove = renderDiscoveryPage({
      inbox: [approvedCandidate],
      candidates: [],
      entities: [],
      targetGroups: [{ id: 'tg_declared', name: 'Declared edge' }],
      canApprove: false,
      canWrite: true,
    });
    assert.equal(withoutApprove.includes('data-action="discovery-import"'), false);
    assert.equal(withoutApprove.includes('discoveryImportTargetGroup'), false);
  });

  it('roleHasUiPermission aligns frontend controls with RBAC intent', () => {
    assert.equal(roleHasUiPermission('viewer', 'waf:run'), false);
    assert.equal(roleHasUiPermission('viewer', 'high_scale:request'), false);
    assert.equal(roleHasUiPermission('viewer', 'environment:write'), false);
    assert.equal(roleHasUiPermission('viewer', 'target_group:write'), false);
    assert.equal(roleHasUiPermission('viewer', 'test_run:start'), false);
    assert.equal(roleHasUiPermission('viewer', 'audit:read'), false);
    assert.equal(roleHasUiPermission('engineer', 'environment:write'), true);
    assert.equal(roleHasUiPermission('engineer', 'waf:run'), true);
    assert.equal(roleHasUiPermission('engineer', 'waf:write'), true);
    assert.equal(roleHasUiPermission('engineer', 'waf:connector_read'), true);
    assert.equal(roleHasUiPermission('engineer', 'waf:connector_write'), false);
    assert.equal(roleHasUiPermission('auditor', 'waf:connector_read'), true);
    assert.equal(roleHasUiPermission('auditor', 'waf:connector_write'), false);
    assert.equal(roleHasUiPermission('engineer', 'high_scale:request'), true);
    assert.equal(roleHasUiPermission('viewer', 'waf:connector_read'), false);
    assert.equal(roleHasUiPermission('admin', 'waf:connector_write'), true);
    assert.equal(roleHasUiPermission('owner', 'high_scale:write'), true);
    assert.equal(roleHasUiPermission('soc', 'soc:high_scale'), true);
    assert.equal(roleHasUiPermission('soc', 'soc:kill_switch'), true);
    assert.equal(roleHasUiPermission('admin', 'soc:kill_switch'), false);
  });

  it('buildInstallCommands returns linux, docker, and helm snippets with token placeholder', () => {
    const cmds = buildInstallCommands({ apiBase: 'http://localhost:3999', token: 'tok_abc' });
    assert.ok(cmds.linux.includes('install.sh'));
    assert.ok(cmds.linux.includes('tok_abc'));
    assert.ok(cmds.docker.includes('docker run'));
    assert.ok(cmds.helm.includes('helm upgrade --install'));
    assert.ok(cmds.helm.includes('agents/linux/helm'));
  });

  it('renderInstallCommandsPanel includes tabs and copy button', () => {
    const html = renderInstallCommandsPanel(buildInstallCommands(), 'docker');
    assert.match(html, /data-install-tab="linux"/);
    assert.match(html, /data-install-tab="docker"/);
    assert.match(html, /data-action="copy-install"/);
    assert.match(html, /data-active-install-tab="docker"/);
  });

  it('buildEvidenceChainExport lists evidence IDs and chain links', () => {
    const out = buildEvidenceChainExport({
      evidence: [{
        id: 'ev_1',
        label: 'probe',
        test_run_id: 'run_1',
        created_at: '2026-01-01T00:00:00Z',
        metadata: { plaintext: 'secret-should-not-export' },
        raw_payload: 'forbidden',
      }],
      runs: [{ id: 'run_1', status: 'verdicted' }],
      verdicts: [{ test_run_id: 'run_1', verdict: 'protected', evidence_ids: ['ev_1'], confidence: 'high' }],
      findings: [],
    });
    assert.deepEqual(out.payload.evidence_ids, ['ev_1']);
    assert.equal(out.payload.chain[0].verdict, 'protected');
    assert.match(out.json, /ev_1/);
    assert.equal(out.idList, 'ev_1');
    assert.equal(out.json.includes('secret-should-not-export'), false);
    assert.equal(out.json.includes('forbidden'), false);
  });

  it('agentHasRecentHeartbeat and resolveOnboardingHeartbeatState detect online and timeout', () => {
    const now = Date.parse('2026-07-03T12:00:00.000Z');
    const fresh = {
      id: 'ag_1',
      status: 'online',
      last_heartbeat_at: '2026-07-03T11:59:30.000Z',
    };
    assert.equal(agentHasRecentHeartbeat(fresh, now), true);
    assert.equal(agentHasRecentHeartbeat({ ...fresh, status: 'offline' }, now), false);
    assert.equal(agentHasRecentHeartbeat({ ...fresh, last_heartbeat_at: null }, now), false);

    const onlineState = resolveOnboardingHeartbeatState([fresh], { nowMs: now, pollStartedAt: now - 5000 });
    assert.equal(onlineState.status, 'online');
    assert.equal(onlineState.agents[0].id, 'ag_1');

    const waitingState = resolveOnboardingHeartbeatState([], { nowMs: now, pollStartedAt: now - 5000 });
    assert.equal(waitingState.status, 'waiting');

    const timeoutState = resolveOnboardingHeartbeatState([], {
      nowMs: now,
      pollStartedAt: now - ONBOARDING_HEARTBEAT_TIMEOUT_MS - 1,
    });
    assert.equal(timeoutState.status, 'timeout');
  });

  it('renderOnboardingHeartbeatPanel shows waiting, online, and troubleshooting empty state', () => {
    const waiting = renderOnboardingHeartbeatPanel(
      { status: 'waiting', agents: [], elapsedMs: 4000 },
      { placementHint: 'Placement confidence cannot be proven yet' },
    );
    assert.match(waiting, /onboarding-heartbeat-panel--waiting/);
    assert.match(waiting, /GET \/v1\/agents/);
    assert.match(waiting, /Placement confidence:/);

    const online = renderOnboardingHeartbeatPanel({
      status: 'online',
      agents: [{ id: 'ag_1', last_heartbeat_at: '2026-07-03T12:00:00.000Z' }],
      elapsedMs: 9000,
    }, { placementHint: 'Canary-capable agent detected' });
    assert.match(online, /onboarding-heartbeat-panel--online/);
    assert.match(online, /last heartbeat/);

    const timeout = renderOnboardingHeartbeatPanel({
      status: 'timeout',
      agents: [],
      elapsedMs: ONBOARDING_HEARTBEAT_TIMEOUT_MS,
    }, { allowSkip: true });
    assert.match(timeout, /data-empty-page="onboarding_heartbeat"/);
    assert.match(timeout, /data-action="onboard-retry-heartbeat"/);
    assert.match(timeout, /data-action="onboard-skip-heartbeat"/);
  });

  it('summarizeOnboardingPlacementConfidenceHint and placement test panel stay metadata-only', () => {
    const proven = summarizeOnboardingPlacementConfidenceHint(null, {
      groups: [{ status: 'proven' }],
    });
    assert.match(proven, /baseline traffic was observed/);

    const canary = summarizeOnboardingPlacementConfidenceHint(
      { capabilities: ['canary', 'heartbeat'] },
      { groups: [] },
    );
    assert.match(canary, /Canary-capable agent detected/);

    const placementHtml = renderOnboardingPlacementTestPanel();
    assert.match(placementHtml, /data-action="onboard-start-placement-test"/);
    assert.match(placementHtml, new RegExp(ONBOARDING_PLACEMENT_TEST_CHECK_ID));
    assert.equal(placementHtml.includes('raw_payload'), false);
  });

  it('computeOnboardingProgress advances when prerequisites exist', () => {
    const empty = computeOnboardingProgress({
      environments: [],
      targetGroups: [],
      targets: [],
      agents: [],
      runs: [],
      hasToken: false,
    });
    assert.equal(empty.currentStep, 0);
    assert.equal(empty.steps[0].id, ONBOARDING_STEPS[0].id);

    const mid = computeOnboardingProgress({
      environments: [{ id: 'env_1' }],
      targetGroups: [{ id: 'tg_1' }],
      targets: [{ id: 't_1' }],
      agents: [],
      runs: [],
      hasToken: true,
    });
    assert.equal(mid.checks.environment, true);
    assert.equal(mid.checks.token, true);
    assert.ok(mid.currentStep >= 4);
  });

  it('renderFriendlyEmptyState renders next-action CTAs for primary pages', () => {
    const html = renderFriendlyEmptyState(PAGE_EMPTY_STATES.dashboard);
    assert.match(html, /friendly-empty/);
    assert.match(html, /data-empty-page="dashboard"/);
    assert.match(html, /data-action="create-tg"/);
    assert.match(html, /data-action="goto-onboarding"/);
    assert.match(html, /internet-facing service/);
    assert.equal(html.includes('<script'), false);

    const requiredPages = [
      'dashboard',
      'target_groups',
      'agents',
      'runs',
      'findings',
      'evidence',
      'audit',
      'reports',
      'high_scale',
    ];
    for (const page of requiredPages) {
      assert.ok(PAGE_EMPTY_STATES[page]?.message, `missing empty state copy: ${page}`);
      assert.ok(PAGE_EMPTY_STATES[page]?.primary?.action, `missing primary CTA: ${page}`);
    }
  });

  it('renderAgentFleetTable uses friendly empty state when fleet is empty', () => {
    const html = renderAgentFleetTable([], []);
    assert.match(html, /friendly-empty/);
    assert.match(html, /data-action="goto-onboarding"/);
    assert.match(html, /observe this target/);
  });

  it('renderOnboardingWizard surfaces active step panel actions', () => {
    const tokenStep = computeOnboardingProgress({
      environments: [{ id: 'env_1' }],
      targetGroups: [{ id: 'tg_1' }],
      targets: [{ id: 't_1' }],
      agents: [],
      runs: [],
      hasToken: false,
    });
    const tokenHtml = renderOnboardingWizard(tokenStep, buildInstallCommands());
    assert.match(tokenHtml, /data-action="onboard-create-token"/);

    const runStep = computeOnboardingProgress({
      environments: [{ id: 'env_1' }],
      targetGroups: [{ id: 'tg_1' }],
      targets: [{ id: 't_1' }],
      agents: [],
      runs: [],
      hasToken: true,
    });
    const runHtml = renderOnboardingWizard(runStep, buildInstallCommands(), { tokenSecret: 'sec_once' });
    assert.match(runHtml, /onboarding-heartbeat-panel/);
    assert.match(runHtml, /GET \/v1\/agents/);
    assert.match(runHtml, /onboarding-wizard/);
    assert.equal(runStep.steps.find((s) => s.id === 'token')?.done, true);
    assert.equal(runStep.steps.find((s) => s.id === 'verify_heartbeat')?.done, false);

    const safeRunStep = computeOnboardingProgress({
      environments: [{ id: 'env_1' }],
      targetGroups: [{ id: 'tg_1' }],
      targets: [{ id: 't_1' }],
      agents: [],
      runs: [],
      hasToken: true,
      heartbeatSkipped: true,
    });
    const safeRunHtml = renderOnboardingWizard(safeRunStep, buildInstallCommands(), { tokenSecret: 'sec_once' });
    assert.match(safeRunHtml, /data-action="onboard-start-run"/);

    const installProgress = computeOnboardingProgress({
      environments: [{ id: 'env_1' }],
      targetGroups: [{ id: 'tg_1' }],
      targets: [{ id: 't_1' }],
      agents: [],
      runs: [],
      hasToken: true,
    });
    const installHtml = renderOnboardingWizard({
      ...installProgress,
      currentStep: installProgress.steps.findIndex((s) => s.id === 'install'),
    }, buildInstallCommands(), { tokenSecret: 'sec_once' });
    assert.match(installHtml, /onboarding-troubleshoot/);
    assert.match(installHtml, /data-action="goto-agents"/);
    assert.match(installHtml, /data-action="goto-settings"/);

    const heartbeatProgress = computeOnboardingProgress({
      environments: [{ id: 'env_1' }],
      targetGroups: [{ id: 'tg_1' }],
      targets: [{ id: 't_1' }],
      agents: [],
      runs: [],
      hasToken: true,
      nowMs: Date.parse('2026-07-03T12:00:00.000Z'),
    });
    const heartbeatStep = heartbeatProgress.steps.find((s) => s.id === 'verify_heartbeat');
    assert.ok(heartbeatStep);
    assert.equal(heartbeatStep.optional, false);
    const heartbeatHtml = renderOnboardingWizard({
      ...heartbeatProgress,
      currentStep: heartbeatProgress.steps.findIndex((s) => s.id === 'verify_heartbeat'),
    }, buildInstallCommands(), {
      heartbeatState: { status: 'waiting', agents: [], elapsedMs: 1000 },
      placementHint: 'Placement confidence cannot be proven yet',
    });
    assert.match(heartbeatHtml, /onboarding-heartbeat-panel/);
    assert.match(heartbeatHtml, /GET \/v1\/agents/);
    assert.match(heartbeatHtml, /Placement confidence:/);

    const placementProgress = computeOnboardingProgress({
      environments: [{ id: 'env_1' }],
      targetGroups: [{ id: 'tg_1' }],
      targets: [{ id: 't_1' }],
      agents: [{
        id: 'ag_1',
        status: 'online',
        last_heartbeat_at: '2026-07-03T11:59:30.000Z',
      }],
      runs: [],
      hasToken: true,
      nowMs: Date.parse('2026-07-03T12:00:00.000Z'),
    });
    assert.equal(placementProgress.checks.verify_heartbeat, true);
    const placementHtml = renderOnboardingWizard({
      ...placementProgress,
      currentStep: placementProgress.steps.findIndex((s) => s.id === 'placement_test'),
    }, buildInstallCommands(), {
      placementHint: 'Run the optional placement test',
    });
    assert.match(placementHtml, /data-action="onboard-start-placement-test"/);
    assert.match(placementHtml, new RegExp(ONBOARDING_PLACEMENT_TEST_CHECK_ID));
    assert.equal(ONBOARDING_STEPS.some((s) => s.id === 'verify_heartbeat'), true);
    assert.equal(ONBOARDING_STEPS.some((s) => s.id === 'placement_test'), true);
  });

  it('renderReportBuilder exposes executive, technical, and audit kinds', () => {
    const html = renderReportBuilder('technical', 'markdown', false);
    for (const kind of ['executive', 'technical', 'audit']) {
      assert.ok(UI_REPORT_KINDS.some((k) => k.id === kind));
      assert.match(html, new RegExp(`value="${kind}"`));
    }
    assert.match(html, /data-action="gen-report"/);
    assert.match(html, /data-action="export-report-selected"/);
    assert.match(html, /name="reportFormat"/);
  });

  it('release evidence helpers stay aligned with backend kinds and avoid raw bodies', () => {
    assert.deepEqual(PRODUCTION_RELEASE_EVIDENCE_KINDS, CONTRACT_KINDS);
    const uri = pickReleaseEvidenceCustodyUri({
      review_report_uri: 'evidence://security/report',
      evidence_uri: 'evidence://bundle/main',
    });
    assert.equal(uri, 'evidence://bundle/main');
    assert.equal(summarizeReleaseEvidenceValidation({ ok: true }), 'Contract valid (metadata-only)');
    assert.match(
      summarizeReleaseEvidenceValidation({ ok: false, missing_fields: ['evidence_uri'] }),
      /Invalid/,
    );
    const coverage = computeReleaseEvidenceCoverage([
      { kind: 'migration_apply' },
      { kind: 'edge_protection' },
    ]);
    assert.equal(coverage.recorded, 2);
    assert.ok(coverage.missing.length > 0);
    const html = renderReleaseEvidencePanel({
      items: [{
        kind: 'migration_apply',
        status: 'accepted',
        release_id: 'rel_test',
        created_at: '2026-07-02T12:00:00.000Z',
        validation: { ok: true },
        evidence: { evidence_uri: 'evidence://migrations/runner', runner_evidence_uri: 'ignored' },
      }],
    });
    assert.match(html, /Inventory incomplete/);
    assert.doesNotMatch(html, /Release gates open/);
    assert.match(html, /does <strong>not<\/strong> prove customer-specific launch by itself/);
    assert.match(html, /rel_test/);
    assert.match(html, /evidence:\/\/migrations\/runner/);
    assert.equal(html.includes('runner_evidence_uri'), false);
    assert.equal(html.includes('secret-token'), false);
    const denied = renderReleaseEvidencePanel({ permissionDenied: true });
    assert.match(denied, /release_evidence:read/);
  });

  it('staging readiness attestation panel summarizes gates without raw evidence bodies', () => {
    const blocked = {
      production_ready: false,
      signoff_status: 'missing_evidence',
      release_id: 'rel_blocked',
      required_evidence_kinds: {
        required: ['migration_apply', 'edge_protection'],
        present: ['migration_apply'],
        missing: ['edge_protection'],
        invalid: [{
          kind: 'operator_runbook_exercise',
          missing_fields: ['evidence_uri'],
          forbidden_fields: [],
        }],
        rejected: [{ kind: 'kill_switch_drill', status: 'rejected' }],
      },
      blocker_summary: ['Missing required evidence kind(s): edge_protection'],
      record_counts: { total: 2, required_kinds_with_records: 1 },
    };
    const blockedHtml = renderStagingReadinessAttestationPanel(blocked);
    assert.match(blockedHtml, /staging-readiness-attestation/);
    assert.match(blockedHtml, /Inventory incomplete/);
    assert.match(blockedHtml, /docs\/release-checklist\.md/);
    assert.match(blockedHtml, /rel_blocked/);
    assert.match(blockedHtml, /Missing required evidence kind/);
    assert.equal(blockedHtml.includes('SECRET_EVIDENCE_BODY'), false);
    assert.equal(blockedHtml.includes('"evidence"'), false);

    const ready = {
      production_ready: true,
      signoff_status: 'evidence_complete',
      release_id: 'rel_ready',
      required_evidence_kinds: {
        required: ['migration_apply'],
        present: ['migration_apply'],
        missing: [],
        invalid: [],
        rejected: [],
      },
      blocker_summary: [],
      record_counts: { total: 1, required_kinds_with_records: 1 },
    };
    const readyHtml = renderStagingReadinessAttestationPanel(ready);
    assert.match(readyHtml, /production_ready/);
    assert.match(readyHtml, />true</);
    assert.match(readyHtml, /Repo evidence complete — customer launch still gated/);

    const profileReady = {
      ...ready,
      profile: 'safe-validation-ga',
      required_evidence_kinds: {
        required: ['migration_apply'],
        present: ['migration_apply'],
        missing: [],
        invalid: [],
        rejected: [],
        profile: 'safe-validation-ga',
      },
    };
    const profileHtml = renderStagingReadinessAttestationPanel(profileReady);
    assert.match(profileHtml, /Profile inventory complete \(safe-validation-ga\) — customer launch still gated/);
    assert.doesNotMatch(profileHtml, /Repo evidence complete — customer launch still gated/);
    assert.match(readyHtml, /does <strong>not<\/strong> clear production promotion/);
    assert.equal(readyHtml.includes('raw_dump'), false);

    const denied = renderStagingReadinessAttestationPanel(null, { permissionDenied: true });
    assert.match(denied, /release_evidence:read/);
    const errored = renderStagingReadinessAttestationPanel(null, { loadError: 'not_found' });
    assert.match(errored, /Unable to load staging readiness attestation/);
    assert.match(errored, /not_found/);

    const counts = summarizeStagingAttestationEvidenceCounts(blocked.required_evidence_kinds);
    assert.equal(counts.present, 1);
    assert.equal(counts.missing, 1);
    assert.equal(counts.invalid, 1);
    assert.equal(counts.rejected, 1);

    const enriched = {
      ...ready,
      profile: 'safe-validation-ga',
      customer_production_ready: false,
      release_checklist_gates: {
        combined: { unchecked: 2, in_progress: 5, complete: 10, open_gates: true },
      },
      external_gates: {
        local_developer_validation_cannot_satisfy: true,
        message: 'SECRET_EXTERNAL_GATE_MESSAGE',
        categories: [{ id: 'soc', label: 'SOC signoff' }],
      },
      external_verification: {
        complete: false,
        live_external_count: 0,
        required_domain_count: 5,
        metadata_only_count: 3,
        unverified_count: 2,
        blocker_summary: ['Enterprise IdP/SSO tenant-role mapping and MFA policy: live_external_manifest_required'],
      },
      evidence: { body: 'SECRET_EVIDENCE_BODY', raw_payload: 'packet_dump' },
      notes: 'operator note with tok_secret_abc123',
    };
    const enrichedHtml = renderStagingReadinessAttestationPanel(enriched);
    assert.match(enrichedHtml, /<dt>profile<\/dt>/);
    assert.match(enrichedHtml, /safe-validation-ga/);
    assert.match(enrichedHtml, /Checklist gates:/);
    assert.match(enrichedHtml, /unchecked <strong>2<\/strong>/);
    assert.match(enrichedHtml, /in progress <strong>5<\/strong>/);
    assert.match(enrichedHtml, /complete <strong>10<\/strong>/);
    assert.match(enrichedHtml, /Local validation cannot satisfy external staging, security, SOC, or legal gates/);
    assert.match(enrichedHtml, /customer_production_ready/);
    assert.match(enrichedHtml, />false</);
    assert.match(enrichedHtml, /External verification:/);
    assert.match(enrichedHtml, /External verification blockers/);
    assert.equal(enrichedHtml.includes('SECRET_EVIDENCE_BODY'), false);
    assert.equal(enrichedHtml.includes('SECRET_EXTERNAL_GATE_MESSAGE'), false);
    assert.equal(enrichedHtml.includes('tok_secret_abc123'), false);
    assert.equal(enrichedHtml.includes('packet_dump'), false);

    const completeItems = PRODUCTION_RELEASE_EVIDENCE_KINDS.map((kind) => ({
      kind,
      status: 'accepted',
      release_id: 'rel_complete',
      created_at: '2026-07-02T12:00:00.000Z',
      validation: { ok: true },
    }));
    const completePanel = renderReleaseEvidencePanel({
      items: completeItems,
      attestation: {
        production_ready: true,
        profile: 'safe-validation-ga',
        signoff_status: 'evidence_complete',
      },
    });
    assert.match(completePanel, /Profile inventory complete \(safe-validation-ga\) — customer launch still gated/);
    assert.doesNotMatch(completePanel, /Release gates open/);

    const blockedPanel = renderReleaseEvidencePanel({
      items: completeItems,
      attestation: {
        production_ready: false,
        signoff_status: 'missing_evidence',
      },
    });
    assert.match(blockedPanel, /Kinds attached — attestation blocked/);

    assert.equal(
      resolveReleaseEvidenceBadge({ items: [], attestation: null }),
      '<span class="badge badge--muted">No evidence attached</span>',
    );
    assert.equal(formatStagingAttestationProfileLabel('full'), 'full (31 kinds)');
    assert.match(
      resolveStagingAttestationBadge({ production_ready: true, profile: 'high-scale-ga' }),
      /Profile inventory complete \(high-scale-ga\)/,
    );

    const compactEnriched = renderStagingReadinessAttestationPanel(enriched, { compact: true });
    assert.match(compactEnriched, /staging-readiness-attestation-panel--compact/);
    assert.match(compactEnriched, /safe-validation-ga/);
    assert.match(compactEnriched, /Checklist gates:/);
    assert.equal(readyHtml.includes('<dt>profile</dt>'), false);
  });

  it('buildSupportReadinessPreview uses safe defaults and merges release evidence metadata', () => {
    const defaults = buildSupportReadinessPreview();
    assert.equal(defaults.staffing_mode, 'developer_validation');
    assert.match(defaults.disclaimer, /does not mean 24\/7 production support/);
    assert.equal(defaults.soc_escalation_state.kill_switch_active, false);
    assert.equal(defaults.escalation_contacts[0].contact_reference.includes('@'), false);

    const merged = buildSupportReadinessPreview({
      kill_switch: { active: true, reason: 'drill', updated_at: '2026-07-02T00:00:00.000Z' },
      release_evidence_items: [{
        kind: 'support_readiness',
        evidence: {
          validation: { ok: true },
          readiness_summary: {
            readiness_id: 'support-readiness-2026-07-02',
            sla_policy_reference: 'policy://support/customer-sla/v2026-07',
            soc_escalation_path_reference: 'runbook://support/soc-escalation-v3',
            support_signoff_owner: 'support-lead',
          },
        },
      }],
    });
    assert.equal(merged.soc_escalation_state.kill_switch_active, true);
    assert.equal(merged.staffing_mode, 'evidence_indexed');
    assert.equal(merged.sla_policy_reference, 'policy://support/customer-sla/v2026-07');
    assert.equal(merged.readiness_id, 'support-readiness-2026-07-02');
  });

  it('renderSupportReadinessPanel avoids private contact details and release custody UI', () => {
    const html = renderSupportReadinessPanel(buildSupportReadinessPreview());
    assert.match(html, /supportReadinessPanel/);
    assert.match(html, /not staffed production on-call/);
    assert.match(html, /escalation:\/\/support\/primary-queue/);
    assert.equal(html.includes('Custody manifest preview'), false);
    assert.equal(html.includes('release-evidence-panel'), false);
    assert.equal(SUPPORT_READINESS_DEFAULT_PREVIEW.escalation_contacts.every(
      (c) => !String(c.contact_reference).includes('@'),
    ), true);
  });

  it('renderTargetGroupDetailPanel exposes tabbed targets, runs, and settings CRUD', () => {
    const base = {
      id: 'tg_1',
      name: 'Checkout<script>',
      description: 'Edge scope',
      safety_policy: { max_runs_per_hour: 12, min_seconds_between_runs: 30 },
      targets: [{
        id: 'tgt_1',
        kind: 'fqdn',
        value: 'api.example.com',
        expected_behavior: 'must_block_before_origin',
      }],
    };
    const runs = [{
      id: 'run_1',
      status: 'verdicted',
      check_id: 'origin.direct_bypass.safe',
      created_at: '2026-07-03T12:00:00.000Z',
    }];
    const agents = [{
      id: 'ag_1',
      name: 'edge-agent',
      status: 'online',
      target_group_id: 'tg_1',
    }];

    const writeOpts = { canWrite: true, canRun: true };
    const targetsHtml = renderTargetGroupDetailPanel(base, runs, agents, 'targets', writeOpts);
    for (const tab of TARGET_GROUP_DETAIL_TABS) {
      assert.match(targetsHtml, new RegExp(`data-tg-tab="${tab.id}"`));
    }
    assert.match(targetsHtml, /data-active-tg-tab="targets"/);
    assert.match(targetsHtml, /data-action="tg-target-save"/);
    assert.match(targetsHtml, /data-action="tg-target-delete"/);
    assert.match(targetsHtml, /Checkout&lt;script>/);
    assert.match(targetsHtml, /edge-agent/);
    assert.equal(targetsHtml.includes('<script>'), false);

    const runsHtml = renderTargetGroupDetailPanel(base, runs, agents, 'runs', writeOpts);
    assert.match(runsHtml, /data-tg-tab-panel="runs"/);
    assert.match(runsHtml, /run_1/);

    const settingsHtml = renderTargetGroupDetailPanel(base, runs, agents, 'settings', writeOpts);
    assert.match(settingsHtml, /tgSettingsName/);
    assert.match(settingsHtml, /tgSettingsDescription/);
    assert.match(settingsHtml, /tgSettingsMaxRuns/);
    assert.match(settingsHtml, /data-action="tg-save-settings"/);
    assert.match(settingsHtml, /data-action="tg-archive"/);
  });

  it('renderTargetGroupDetailPanel hides mutation controls when write/run denied', () => {
    const base = {
      id: 'tg_1',
      name: 'Checkout',
      targets: [{
        id: 'tgt_1',
        kind: 'fqdn',
        value: 'api.example.com',
        expected_behavior: 'must_block_before_origin',
      }],
    };
    const deniedHtml = renderTargetGroupDetailPanel(base, [], [], 'targets', { canWrite: false, canRun: false });
    assert.equal(deniedHtml.includes('data-action="tg-target-save"'), false);
    assert.equal(deniedHtml.includes('data-action="start-run"'), false);
    assert.match(deniedHtml, /Read-only/);
  });

  it('app shell wires friendly empty states, tg detail, and finding triage actions', () => {
    const appJs = readFileSync(new URL('../../apps/web/app.js', import.meta.url), 'utf8');
    assert.match(appJs, /renderFriendlyEmptyState/);
    assert.match(appJs, /PAGE_EMPTY_STATES/);
    assert.match(appJs, /data-action="goto-onboarding"/);
    assert.match(appJs, /data-action="tg-detail"/);
    assert.match(appJs, /data-tg-tab/);
    assert.match(appJs, /data-action="tg-save-settings"/);
    assert.match(appJs, /data-action="tg-archive"/);
    assert.match(appJs, /data-action="tg-target-save"/);
    assert.match(appJs, /data-action="tg-target-delete"/);
    assert.match(appJs, /renderTargetGroupDetailPanel/);
    assert.match(appJs, /data-action="finding-status"/);
    assert.match(appJs, /Recent test runs/);
    assert.match(appJs, /High-scale \/ SOC requests/);
  });

  it('renderPlacementDiagnosticsPanel surfaces per-target-group statuses', () => {
    const html = renderPlacementDiagnosticsPanel({
      summary: 'Placement diagnostics: 1 proven, 0 need baseline, 1 missing agent, 0 misplaced risk (of 2 group(s)).',
      proven: 1,
      needs_baseline: 0,
      missing_agent: 1,
      misplaced_risk: 0,
      unbound_online_agent_count: 0,
      groups: [
        {
          target_group_id: 'tg_1',
          target_group_name: 'Checkout',
          status: 'proven',
          warnings: [],
          bound_agent_ids: ['ag_1'],
          online_bound_agent_ids: ['ag_1'],
          recent_observation_count: 2,
        },
        {
          target_group_id: 'tg_2',
          target_group_name: 'API',
          status: 'missing_agent',
          warnings: ['no_bound_agent'],
          bound_agent_ids: [],
          online_bound_agent_ids: [],
          recent_observation_count: 0,
        },
      ],
    });
    assert.match(html, /placement-diagnostics-panel/);
    assert.match(html, /Checkout/);
    assert.match(html, /placement-status-pill--proven/);
    assert.match(html, /placement-status-pill--missing_agent/);
  });

  it('extractPlacementDiagnosticsFromReadiness reads agent_placement factor', () => {
    const diagnostics = extractPlacementDiagnosticsFromReadiness({
      factors: [{ key: 'agent_placement', placement_diagnostics: { proven: 1, groups: [] } }],
    });
    assert.equal(diagnostics.proven, 1);
  });

  it('renderProbeProfileKind shows bounded profile kind or SOC-gated', () => {
    assert.match(
      renderProbeProfileKind({ probe_profile: { kind: 'http_head', max_requests: 1 } }),
      /http_head/,
    );
    assert.equal(renderProbeProfileKind({ risk_class: 'soc_gated' }), 'SOC-gated');
  });

  it('renderNotificationOpsPanel summarizes retry and DLQ attempts without raw destinations', () => {
    const html = renderNotificationOpsPanel({
      rules: [{ id: 'nrule_1', channel: 'webhook', destination: 'https://hooks.example.invalid/token' }],
      events: [{
        id: 'nevt_1',
        trigger: 'report.ready',
        subject: 'Report',
        metadata: { token: 'ast_v1.secret' },
        delivery_attempts: [
          {
            id: 'natt_retry',
            rule_id: 'nrule_1',
            channel: 'webhook',
            destination: 'https://hooks.example.invalid/ast_v1.secret',
            destination_preview: 'webhook://hooks.example.invalid/...',
            status: 'provider_retry_scheduled',
            attempt_number: 1,
            max_attempts: 3,
            next_retry_at: '2026-07-03T00:00:00.000Z',
          },
          {
            id: 'natt_dlq',
            rule_id: 'nrule_1',
            channel: 'webhook',
            destination: 'https://hooks.example.invalid/ast_v1.secret',
            destination_preview: 'webhook://hooks.example.invalid/...',
            status: 'provider_failed_dlq',
            reason: 'webhook_http_error',
            provider_error: 'webhook_http_error',
            attempt_number: 3,
            max_attempts: 3,
          },
        ],
      }],
    }, {
      canWrite: true,
      lastRetryResult: { due_count: 1, processed: [{ status: 'provider_failed_dlq' }], dry_run: false },
    });
    assert.match(html, /Delivery operations/);
    assert.match(html, /Retry scheduled: <strong>1<\/strong>/);
    assert.match(html, /DLQ: <strong>1<\/strong>/);
    assert.match(html, /data-action="process-notification-retries"/);
    assert.match(html, /webhook_http_error/);
    assert.equal(html.includes('ast_v1.secret'), false);
    assert.equal(html.includes('https://hooks.example.invalid/ast_v1.secret'), false);
    assert.equal(html.includes('destination&quot;'), false);
  });

  it('renderNotificationOpsPanel includes per-DLQ redrive controls and redrive summary', () => {
    const html = renderNotificationOpsPanel({
      rules: [{ id: 'nrule_1', channel: 'webhook' }],
      events: [{
        id: 'nevt_1',
        trigger: 'report.ready',
        subject: 'Report',
        delivery_attempts: [{
          id: 'natt_dlq',
          rule_id: 'nrule_1',
          channel: 'webhook',
          destination: 'https://hooks.example.invalid/secret',
          destination_preview: 'webhook://hooks.example.invalid/...',
          status: 'provider_failed_dlq',
          reason: 'webhook_http_error',
          attempt_number: 3,
          max_attempts: 3,
        }],
      }],
    }, {
      canWrite: true,
      lastRedriveResult: {
        requeued_count: 1,
        skipped_count: 0,
        still_dlq_count: 0,
        dry_run: false,
      },
    });
    assert.match(html, /data-action="redrive-notification-dlq"/);
    assert.match(html, /data-attempt-id="natt_dlq"/);
    assert.match(html, /Last DLQ redrive: requeued 1/);
    assert.match(html, /ASTRANULL_NOTIFICATION_DELIVERY_MODE/);
    assert.match(html, /staging delivery evidence/);
    assert.equal(html.includes('https://hooks.example.invalid/secret'), false);
  });

  it('renderWafCriticalityCard shows rollup rows and empty state', () => {
    const empty = renderWafCriticalityCard({ items: [] });
    assert.match(empty, /Criticality coverage/);
    assert.match(empty, /No WAF assets with declared criticality yet/);

    const html = renderWafCriticalityCard({
      items: [
        {
          business_criticality: 'payment',
          asset_count: 2,
          coverage_ratio: 0.5,
          protected: 1,
          underprotected: 0,
          unprotected: 1,
          critical_gap_count: 1,
        },
      ],
    });
    assert.match(html, /payment/);
    assert.match(html, /Critical gaps/);
    assert.match(html, /50%/);
    assert.equal(html.includes('<script'), false);
  });

  it('renderWafDriftQueue empty state explains evidence-backed drift only', () => {
    const html = renderWafDriftQueue({ items: [] });
    assert.match(html, /waf-drift-empty/);
    assert.match(html, /evidence-backed posture weakening/i);
    assert.equal(html.includes('raw_payload'), false);
    assert.equal(html.includes('exploit_payload'), false);
  });

  it('renderWafDriftQueue escapes drift fields and redacts unsafe summary keys', () => {
    const summary = summarizeWafDriftPostureSummary({
      status: 'protected',
      reason_codes: ['marker_rule_not_blocking'],
      detected_product: 'cdn-waf',
      raw_payload: 'must-not-render',
      exploit_payload: 'forbidden',
      headers: { authorization: 'secret' },
    });
    assert.equal(summary.includes('must-not-render'), false);
    assert.equal(summary.includes('forbidden'), false);
    assert.equal(summary.includes('secret'), false);
    assert.match(summary, /protected/);
    assert.match(summary, /marker_rule_not_blocking/);

    const html = renderWafDriftQueue({
      canWrite: true,
      items: [{
        id: 'drf_<x>',
        drift_type: 'marker<script>',
        waf_asset_id: 'waf_1',
        severity: 'high',
        status: 'open',
        created_at: '2026-07-01T12:00:00Z',
        before_summary: { status: 'protected' },
        after_summary: { status: 'underprotected', raw_payload: 'nope' },
        finding_id: 'fnd_"1"',
      }],
      assetLabelById: { waf_1: 'https://app.example.com' },
      retestByDriftId: {
        'drf_<x>': { id: 'rt_1', status: 'requested' },
      },
    });
    assert.match(html, /marker&lt;script>/);
    assert.equal(html.includes('<script>'), false);
    assert.match(html, /data-action="waf-drift-status"/);
    assert.match(html, /data-action="waf-drift-retest"/);
    assert.match(html, /data-action="waf-retest-execute"/);
    assert.equal(html.includes('data-waf-drift-note'), false);
    assert.equal(html.includes('waf-drift-note-input'), false);
    assert.equal(html.match(/data-action="waf-retest-complete"/g)?.length ?? 0, 0);
    assert.equal(html.includes('raw_payload'), false);
    assert.equal(html.includes('nope'), false);
    assert.match(html, /developer-validation workflow visibility/i);
  });

  it('renderWafDriftQueue shows retest follow-up controls by remembered status', () => {
    const baseItem = {
      id: 'drf_1',
      drift_type: 'marker',
      waf_asset_id: 'waf_1',
      severity: 'medium',
      status: 'open',
      created_at: '2026-07-01T12:00:00Z',
      before_summary: { status: 'protected' },
      after_summary: { status: 'underprotected' },
    };
    const requestedHtml = renderWafDriftQueue({
      canWrite: true,
      items: [baseItem],
      retestByDriftId: { drf_1: { id: 'rt_req', status: 'requested' } },
    });
    assert.match(requestedHtml, /data-action="waf-retest-execute"/);
    assert.equal(requestedHtml.includes('data-action="waf-retest-complete"'), false);

    const delegatedHtml = renderWafDriftQueue({
      canWrite: true,
      items: [baseItem],
      retestByDriftId: { drf_1: { id: 'rt_del', status: 'delegated' } },
    });
    assert.equal(delegatedHtml.includes('data-action="waf-retest-execute"'), false);
    assert.match(delegatedHtml, /data-action="waf-retest-complete"/);

    const completedHtml = renderWafDriftQueue({
      canWrite: true,
      items: [baseItem],
      retestByDriftId: { drf_1: { id: 'rt_done', status: 'completed' } },
    });
    assert.equal(completedHtml.includes('data-action="waf-retest-execute"'), false);
    assert.equal(completedHtml.includes('data-action="waf-retest-complete"'), false);
    assert.match(completedHtml, /waf-retest-terminal/);
    assert.match(completedHtml, /completed/);
  });

  it('renderWafValidationPlansPanel shows unavailable warning without breaking layout', () => {
    const html = renderWafValidationPlansPanel({
      unavailable: { code: 'postgres_waf_orchestrator_unavailable', message: 'postgres_waf_orchestrator_unavailable' },
      targetGroups: [{ id: 'tg_1', name: 'Edge' }],
      plans: [{
        id: 'vp_stale',
        target_group_id: 'tg_1',
        mode: 'manual',
        state: 'scheduled',
        scenarios: ['marker'],
        created_at: '2026-07-01T12:00:00Z',
      }],
    });
    assert.match(html, /waf-plan-panel/);
    assert.match(html, /waf-plan-warning/);
    assert.match(html, /postgres_waf_orchestrator_unavailable/);
    assert.match(html, /Validation plans are temporarily unavailable/);
    assert.doesNotMatch(html, /No validation plans yet/);
    assert.match(html, /data-action="waf-plan-create" disabled/);
    assert.equal(html.includes('data-action="waf-plan-execute"'), false);
    assert.equal(html.includes('data-action="waf-plan-cancel"'), false);
    assert.match(html, /not final WAF posture closure/i);
  });

  it('renderWafValidationPlansPanel uses contract-valid scenario and schedule options', () => {
    const html = renderWafValidationPlansPanel({
      plans: [],
      targetGroups: [{ id: 'tg_1', name: 'Edge' }],
    });
    assert.match(html, /rate_limit_marker/);
    assert.equal(html.includes('rate_limit_safe'), false);
    assert.match(html, /value="daily"/);
    assert.match(html, /value="weekly"/);
    assert.match(html, /value="monthly"/);
    assert.equal(html.includes('hourly'), false);
  });

  it('renderWafValidationPlansPanel treats failed plans as terminal for row actions', () => {
    const html = renderWafValidationPlansPanel({
      plans: [{
        id: 'vp_failed',
        target_group_id: 'tg_1',
        mode: 'manual',
        state: 'failed',
        scenarios: ['marker'],
        created_at: '2026-07-01T12:00:00Z',
      }],
      targetGroups: [{ id: 'tg_1', name: 'Edge' }],
    });
    assert.match(html, /failed/);
    assert.equal(html.includes('data-action="waf-plan-execute"'), false);
    assert.equal(html.includes('data-action="waf-plan-cancel"'), false);
  });

  it('renderWafValidationPlansPanel empty state and form require declared target groups', () => {
    const html = renderWafValidationPlansPanel({ plans: [], targetGroups: [] });
    assert.match(html, /waf-plan-empty/);
    assert.match(html, /Declare at least one target group/);
    assert.match(html, /disabled/);
  });

  it('renderWafValidationPlansPanel renders plan rows with safe summaries only', () => {
    const html = renderWafValidationPlansPanel({
      plans: [{
        id: 'vp_<1>',
        target_group_id: 'tg_1',
        mode: 'scheduled',
        state: 'running',
        schedule_interval: 'daily',
        scenarios: ['marker', 'fingerprint'],
        created_at: '2026-07-01T12:00:00Z',
        executed_at: '2026-07-01T12:05:00Z',
        continuation_required: true,
        delegated_jobs: [{
          test_run_id: 'run_must_not_render',
          probe_job_id: 'job_must_not_render',
          scenario: 'marker',
        }],
      }],
      scheduledPlans: [{
        id: 'vp_<1>',
        target_group_id: 'tg_1',
        mode: 'scheduled',
        state: 'running',
      }],
      targetGroups: [{ id: 'tg_1', name: 'Edge<script>' }],
    });
    assert.match(html, /vp_&lt;1>/);
    assert.match(html, /Edge&lt;script>/);
    assert.match(html, /data-action="waf-plan-execute"/);
    assert.match(html, /data-action="waf-plan-cancel"/);
    assert.match(html, />required</);
    assert.match(html, /daily/);
    assert.match(html, /marker/);
    assert.equal(html.includes('run_must_not_render'), false);
    assert.equal(html.includes('job_must_not_render'), false);
    assert.equal(html.includes('probe_job_id'), false);
    assert.match(html, /Delegated jobs/);
    assert.match(html, /<td>1<\/td>/);
  });

  it('renderWafVendorMixCard renders vendor mix rows and empty state', () => {
    const empty = renderWafVendorMixCard({ vendor_mix: [] });
    assert.match(empty, /waf-vendor-mix-card/);
    assert.match(empty, /No vendor detections yet/i);

    const html = renderWafVendorMixCard({
      vendor_mix: [{
        vendor: 'cloudflare',
        product: 'Cloudflare WAF',
        asset_count: 2,
        protected_count: 1,
        protected_share_pct: 50,
      }],
    });
    assert.match(html, /cloudflare/);
    assert.match(html, /50%/);
    assert.equal(html.includes('<script>'), false);
  });

  it('renderWafGeographyCard renders geography rollups', () => {
    const html = renderWafGeographyCard({
      items: [{
        region_code: 'us-east',
        region_label: 'US East',
        asset_count: 3,
        coverage_ratio: 0.67,
        unprotected_critical_count: 1,
      }],
    });
    assert.match(html, /waf-geography-card/);
    assert.match(html, /us-east/);
    assert.match(html, /67%/);
  });

  it('renderWafRoadmapPanel renders tier sections with factor breakdown', () => {
    const empty = renderWafRoadmapPanel({ tiers: {} });
    assert.match(empty, /waf-roadmap-empty/);

    const html = renderWafRoadmapPanel({
      method: 'waf_risk_v1',
      generated_at: '2026-07-03T12:00:00Z',
      tiers: {
        tier_1: [{
          waf_asset_id: 'waf_1',
          hostname: 'app.example.com',
          owner_hint: 'edge-team',
          risk_score: 82,
          posture_status: 'unprotected',
          primary_reason_codes: ['coverage_gap'],
          recommended_action: 'Deploy WAF',
          detected_vendor: 'none',
        }],
        tier_2: [],
        tier_3: [],
        tier_4: [],
      },
    });
    assert.match(html, /Tier 1/);
    assert.match(html, /app\.example\.com/);
    assert.match(html, /waf-roadmap-factors/);
    assert.match(html, /Deploy WAF/);
  });

  it('renderWafReportsPanel exposes compliance and board report kinds', () => {
    const html = renderWafReportsPanel({
      selectedKind: 'compliance_audit',
      selectedFormat: 'json',
    });
    assert.match(html, /value="executive_coverage"/);
    assert.match(html, /value="compliance_audit" selected/);
    assert.match(html, /Compliance audit/);
    assert.match(html, /value="board_roadmap_brief"/);
    assert.match(html, /Board roadmap brief/);
    assert.equal(html.includes('raw payload'), false);
  });

  it('renderWafPostureTabs marks active tab', () => {
    const html = renderWafPostureTabs('roadmap');
    assert.match(html, /data-waf-posture-tab="roadmap"/);
    assert.match(html, /waf-posture-tab active[^>]*data-waf-posture-tab="roadmap"/);
    assert.match(html, /data-waf-posture-tab="overview"/);
  });

  it('renderWafAssetsTable shows pass rate and rule health columns', () => {
    const html = renderWafAssetsTable({
      assets: [{
        id: 'waf_1',
        canonical_url: 'https://app.example.com',
        posture_status: 'protected',
        detected_vendor: 'cloudflare',
        target_group_id: 'tg_1',
        owner_hint: 'edge',
        effectiveness: { rule_count: 12, last_rule_update_at: '2026-07-01T00:00:00Z' },
      }],
      validations: [{
        waf_asset_id: 'waf_1',
        status: 'finalized',
        finalized_at: '2026-07-03T00:00:00Z',
        summary_json: { validation_passed: true },
      }],
      tgNameById: { tg_1: 'Edge' },
    });
    assert.match(html, /Pass rate/);
    assert.match(html, /Rule health/);
    assert.match(html, /12 rules/);
    assert.match(html, /data-action="waf-view-asset"/);
  });

  it('renderWafAssetsTable suppresses write and run controls when permissions are false', () => {
    const empty = renderWafAssetsTable({
      assets: [],
      canWrite: false,
      canRun: false,
    });
    assert.equal(empty.includes('data-action="waf-create-demo-asset"'), false);
    assert.match(empty, /Ask an engineer or admin/);

    const html = renderWafAssetsTable({
      assets: [{
        id: 'waf_1',
        canonical_url: 'https://app.example.com',
        posture_status: 'unknown',
      }],
      canWrite: false,
      canRun: false,
    });
    assert.match(html, /data-action="waf-view-asset"/);
    assert.equal(html.includes('data-action="waf-run-validation"'), false);
  });

  it('computeWafAssetPassRate and formatWafPassRateDisplay derive lookback pass rate', () => {
    const rate = computeWafAssetPassRate('waf_1', [
      {
        waf_asset_id: 'waf_1',
        status: 'finalized',
        finalized_at: '2026-07-03T00:00:00Z',
        summary_json: { validation_passed: true },
      },
      {
        waf_asset_id: 'waf_1',
        status: 'finalized',
        finalized_at: '2026-07-02T00:00:00Z',
        summary_json: { validation_passed: false },
      },
    ]);
    assert.equal(rate, 50);
    assert.equal(formatWafPassRateDisplay(rate, 30), '50% (30d)');
    assert.equal(formatWafPassRateDisplay(null), '—');
  });

  it('formatWafRuleHealthDisplay and resolveWafControlBypassStatus handle connector and bypass metadata', () => {
    assert.equal(formatWafRuleHealthDisplay({ rule_count: 8, last_rule_update_at: '2026-07-01T00:00:00Z' }), '8 rules · updated 2026-07-01 00:00:00');
    assert.equal(formatWafRuleHealthDisplay(null), '—');
    assert.equal(resolveWafControlBypassStatus({ control_bypass_status: 'confirmed' }), 'confirmed');
    assert.equal(resolveWafControlBypassStatus(null, ['origin_bypass_confirmed']), 'confirmed');
    assert.equal(resolveWafControlBypassStatus(null, ['marker_rule_not_blocking']), 'suspected');
    assert.equal(resolveWafControlBypassStatus(null, []), 'none');
  });

  it('renderWafAssetEffectivenessSection renders effectiveness metrics and risk factors', () => {
    const empty = renderWafAssetEffectivenessSection(null);
    assert.match(empty, /Select an asset/i);

    const html = renderWafAssetEffectivenessSection({
      asset: { id: 'waf_1', canonical_url: 'https://app.example.com' },
      current_posture: {
        risk_score: 72,
        priority_band: 'tier_2',
        reason_codes: ['validation_failed'],
        risk_factors: [{ factor: 'protection_state', value: 'underprotected', contribution: 18 }],
      },
      effectiveness: {
        scenario_pass_rate: 66.67,
        lookback_days: 30,
        control_bypass_status: 'suspected',
        rule_count: 5,
        last_rule_update_at: '2026-07-01T00:00:00Z',
      },
    });
    assert.match(html, /waf-asset-effectiveness/);
    assert.match(html, /66\.67%/);
    assert.match(html, /5 rules/);
    assert.match(html, /protection_state/);
    assert.match(html, /suspected/);
  });

  it('renderWafConnectorsPanel empty state explains optional connector mode', () => {
    const html = renderWafConnectorsPanel({ connectors: [] });
    assert.match(html, /waf-connectors-empty/);
    assert.match(html, /No WAF connectors configured/i);
    assert.match(html, /no-access mode/i);
    assert.equal(html.includes('api_token'), false);
    assert.equal(html.includes('raw_payload'), false);
  });

  it('renderWafConnectorsPanel escapes connector fields and shows poll control', () => {
    const html = renderWafConnectorsPanel({
      canWrite: true,
      connectors: [{
        id: 'conn_<1>',
        provider: 'cloudflare<script>',
        name: 'edge<script>',
        status: 'active',
        secret_id: 'sec_must_not_render',
        last_success_at: '2026-07-02T12:00:00Z',
        config: {
          read_only: true,
          zone_ref_hash: 'zone_hash_secret',
          polling_interval_minutes: 15,
          api_token: 'must-not-render',
        },
      }],
    });
    assert.match(html, /cloudflare&lt;script>/);
    assert.match(html, /edge&lt;script>/);
    assert.match(html, /data-action="waf-connector-poll"/);
    assert.match(html, /Poll now/);
    assert.doesNotMatch(html, /data-action="waf-connector-poll"[^>]*disabled/);
    assert.equal(html.includes('<script>'), false);
    assert.equal(html.includes('sec_must_not_render'), false);
    assert.equal(html.includes('zone_hash_secret'), false);
    assert.equal(html.includes('api_token'), false);
    assert.equal(html.includes('must-not-render'), false);
    assert.match(html, /outbound_credential: configured/);
    assert.match(html, /zone_ref_hash: configured/);
  });

  it('renderWafConnectorsPanel disables poll for disabled connectors', () => {
    const html = renderWafConnectorsPanel({
      connectors: [{
        id: 'conn_disabled',
        provider: 'aws_waf',
        name: 'edge',
        status: 'disabled',
        config: { read_only: true },
      }],
    });
    assert.match(html, /data-action="waf-connector-poll"[^>]*disabled/);
  });

  it('renderWafConnectorsPanel disables row poll when connector health is denied or unavailable', () => {
    const connector = {
      id: 'conn_active',
      provider: 'cloudflare',
      name: 'edge',
      status: 'active',
      config: { read_only: true },
    };
    const denied = renderWafConnectorsPanel({
      permissionDenied: { code: 'forbidden' },
      connectors: [connector],
    });
    assert.match(denied, /Connector access denied/);
    assert.match(denied, /data-action="waf-connector-poll"[^>]*disabled/);

    const unavailable = renderWafConnectorsPanel({
      unavailable: { code: 'connectors_unavailable' },
      connectors: [connector],
    });
    assert.match(unavailable, /Connectors unavailable/);
    assert.match(unavailable, /data-action="waf-connector-poll"[^>]*disabled/);
  });

  it('renderWafConnectorsPanel shows unavailable warning without breaking layout', () => {
    const html = renderWafConnectorsPanel({
      unavailable: { code: 'waf_feature_disabled', message: 'waf_feature_disabled' },
      connectors: [],
    });
    assert.match(html, /waf-connectors-warning/);
    assert.match(html, /waf_feature_disabled/);
    assert.match(html, /Connector health is temporarily unavailable/);
    assert.doesNotMatch(html, /No WAF connectors configured yet/);
  });

  it('renderWafConnectorsPanel shows permission denial separately from outages', () => {
    const html = renderWafConnectorsPanel({
      permissionDenied: { code: 'forbidden', message: 'forbidden' },
      connectors: [],
    });
    assert.match(html, /Connector access denied/);
    assert.match(html, /Your role cannot read connector health/);
    assert.match(html, /Core WAF posture remains available/);
    assert.doesNotMatch(html, /temporarily unavailable/);
    assert.doesNotMatch(html, /Retry after the service is restored/);
  });

  it('resolveWafConnectorLastPollAt prefers last_poll_at then last_success_at', () => {
    assert.equal(
      resolveWafConnectorLastPollAt({ last_poll_at: '2026-07-03T00:00:00Z', last_success_at: '2026-07-02T00:00:00Z' }),
      '2026-07-03T00:00:00Z',
    );
    assert.equal(
      resolveWafConnectorLastPollAt({ last_success_at: '2026-07-02T00:00:00Z' }),
      '2026-07-02T00:00:00Z',
    );
    assert.equal(resolveWafConnectorLastPollAt({}), null);
  });

  it('summarizeWafConnectorHealthSummary omits unsafe config keys and bounds output', () => {
    const summary = summarizeWafConnectorHealthSummary({
      status: 'error',
      secret_id: 'sec_pointer',
      last_error_at: '2026-07-02T12:00:00Z',
      config: {
        read_only: true,
        api_token: 'must-not-render',
        zone_ref_hash: 'hash_1',
        owner_hint: `owner_${'o'.repeat(80)}`,
      },
    });
    assert.equal(summary.includes('must-not-render'), false);
    assert.equal(summary.includes('sec_pointer'), false);
    assert.equal(summary.includes('hash_1'), false);
    assert.match(summary, /read_only: yes/);
    assert.match(summary, /zone_ref_hash: configured/);
    assert.match(summary, /outbound_credential: configured/);
    assert.ok(summary.length <= 220);
  });

  it('summarizeWafConnectorPollResult redacts poll job metadata only', () => {
    const summary = summarizeWafConnectorPollResult({
      poll_job: {
        id: 'poll_1',
        status: 'completed',
        snapshot_count: 2,
        health: { status: 'active', health_code: 'ok', attempts: 1 },
      },
      snapshots: [
        { summary: { rule_count: 99, raw_body: 'secret' } },
        { summary: { hostnames: ['app.example.com'] } },
      ],
    });
    assert.equal(summary.ok, true);
    assert.equal(summary.poll_job.id, 'poll_1');
    assert.equal(summary.poll_job.snapshot_count, 2);
    assert.equal(summary.snapshots_count, 2);
    assert.equal(summary.poll_job.health.health_code, 'ok');
    assert.equal('raw_body' in summary, false);
    assert.equal('snapshots' in summary, false);
  });

  it('summarizeWafConnectorPollError maps connector poll failures safely', () => {
    const summary = summarizeWafConnectorPollError({
      message: 'connector_poll_failed',
      pollMessage: 'Outbound connector poll failed; manual metadata snapshots remain supported.',
      pollHealth: {
        status: 'error',
        health_code: 'encryption_not_configured',
        attempts: 2,
        provider_response: 'must-not-render',
      },
    });
    assert.equal(summary.ok, false);
    assert.equal(summary.error, 'connector_poll_failed');
    assert.match(summary.guidance, /Outbound connector poll failed/i);
    assert.equal(summary.health.health_code, 'encryption_not_configured');
    assert.equal(summary.health.attempts, 2);
    assert.equal('provider_response' in (summary.health ?? {}), false);
  });

  it('summarizeWafDriftPostureSummary bounds long values and omits unsafe keys', () => {
    const longCode = `code_${'x'.repeat(80)}`;
    const summary = summarizeWafDriftPostureSummary({
      status: `status_${'s'.repeat(80)}`,
      reason_codes: [longCode, 'ok_code', 'extra_should_trim'],
      detected_product: `product_${'p'.repeat(80)}`,
      raw_payload: 'must-not-render',
      exploit_payload: 'forbidden',
    });
    assert.equal(summary.includes('must-not-render'), false);
    assert.equal(summary.includes('forbidden'), false);
    assert.ok(summary.length <= 220);
    assert.ok(!summary.includes('x'.repeat(80)));
  });

  it('app.js summarizes WAF action output instead of dumping raw API JSON', () => {
    const appJs = readFileSync(new URL('../../apps/web/app.js', import.meta.url), 'utf8');
    assert.match(appJs, /function summarizeWafActionResult|export function summarizeWafActionResult/);
    assert.match(appJs, /summarizeWafActionError/);
    assert.match(appJs, /setWafOut\(summarizeWafActionResult/);
    assert.equal(appJs.includes('setWafOut(result ?? { ok: true })'), false);
    assert.equal(appJs.includes('data-waf-drift-note'), false);
    assert.equal(appJs.includes('notes ? { notes }'), false);
  });

  it('app shell includes custody manifest previews for evidence, finding, and report exports', () => {
    const appJs = readFileSync(new URL('../../apps/web/app.js', import.meta.url), 'utf8');
    assert.match(appJs, /Custody manifest preview/);
    assert.match(appJs, /data-action="export-finding"/);
    assert.match(appJs, /data-action="view-finding"/);
    assert.match(appJs, /renderFindingVerdictExplanation/);
    assert.match(appJs, /No raw payloads or secrets are rendered in this preview\./);
    assert.match(appJs, /evidenceCustodyPreview/);
    assert.match(appJs, /reportCustodyPreview/);
    assert.match(appJs, /findingCustodyPreview/);
    assert.match(appJs, /renderSupportReadinessPanel/);
    assert.match(appJs, /buildSupportReadinessPreview/);
    const uiHelpersSrc = readFileSync(new URL('../../apps/web/ui-helpers.js', import.meta.url), 'utf8');
    assert.match(uiHelpersSrc, /supportReadinessPanel/);
  });
});
