import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import {
  ONBOARDING_STEPS,
  PRODUCTION_RELEASE_EVIDENCE_KINDS,
  UI_REPORT_KINDS,
  buildEvidenceChainExport,
  buildInstallCommands,
  buildSupportReadinessPreview,
  computeOnboardingProgress,
  computeReleaseEvidenceCoverage,
  pickReleaseEvidenceCustodyUri,
  renderInstallCommandsPanel,
  renderOnboardingWizard,
  renderReleaseEvidencePanel,
  renderStagingReadinessAttestationPanel,
  renderReportBuilder,
  renderSupportReadinessPanel,
  summarizeReleaseEvidenceValidation,
  summarizeStagingAttestationEvidenceCounts,
  SUPPORT_READINESS_DEFAULT_PREVIEW,
} from '../../apps/web/ui-helpers.js';
import { PRODUCTION_RELEASE_EVIDENCE_KINDS as CONTRACT_KINDS } from '../../src/contracts/productionReleaseEvidence.mjs';

describe('ui-helpers', () => {
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
    assert.match(runHtml, /data-action="onboard-start-run"/);
    assert.match(runHtml, /onboarding-wizard/);
    assert.equal(runStep.steps.find((s) => s.id === 'token')?.done, true);
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
    assert.match(html, /does <strong>not<\/strong> mean production readiness is complete/);
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
    assert.match(blockedHtml, /Attestation blocked/);
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
    assert.match(readyHtml, /promotion gates still open/);
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
      release_checklist_gates: {
        combined: { unchecked: 2, in_progress: 5, complete: 10, open_gates: true },
      },
      external_gates: {
        local_developer_validation_cannot_satisfy: true,
        message: 'SECRET_EXTERNAL_GATE_MESSAGE',
        categories: [{ id: 'soc', label: 'SOC signoff' }],
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
    assert.equal(enrichedHtml.includes('SECRET_EVIDENCE_BODY'), false);
    assert.equal(enrichedHtml.includes('SECRET_EXTERNAL_GATE_MESSAGE'), false);
    assert.equal(enrichedHtml.includes('tok_secret_abc123'), false);
    assert.equal(enrichedHtml.includes('packet_dump'), false);

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
