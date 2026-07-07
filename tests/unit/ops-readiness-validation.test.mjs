import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  buildOpsReadinessData,
  executeOpsReadinessProbe,
  isOpsReadinessProbeKind,
  pickLatestAcceptedEvidence,
  resolveOpsReadinessScenario,
} from '../../src/lib/opsReadinessValidation.mjs';
import { getCheckById } from '../../src/contracts/checks.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';

const SUPPORT_EVIDENCE = {
  readiness_id: 'support_readiness_2026_07_02_staging',
  environment: 'staging',
  on_call_rotation: {
    rotation_name: 'platform-primary',
    owner: 'support-oncall-lead',
    schedule_reference: 'pagerduty://services/astranull-platform-primary',
  },
  escalation_contacts: [
    { role: 'support', contact_reference: 'escalation://support/primary-queue' },
    { role: 'engineering', contact_reference: 'escalation://eng/platform-oncall' },
    { role: 'soc', contact_reference: 'escalation://soc/high-scale' },
  ],
  sla_policy: {
    policy_reference: 'policy://support/customer-sla/v2026-07',
    severity_tiers: [
      { severity: 'S1', response_minutes: 15 },
      { severity: 'S2', response_minutes: 60 },
      { severity: 'S3', response_minutes: 240 },
    ],
  },
  incident_tabletop: {
    tabletop_id: 'tabletop_2026_07_01_soc_escalation',
    conducted_at: '2026-07-01T18:00:00.000Z',
    scenario_reference: 'scenario://drills/agent-mass-offline-s2',
    owner: 'incident-commander',
    evidence_uri: 'evidence://support/tabletop/2026-07-01',
  },
  soc_escalation_path: {
    path_reference: 'runbook://support/soc-escalation-v3',
    severity_routes: [
      { severity: 'S1', escalation_reference: 'escalation://soc/kill-switch-page' },
      { severity: 'S2', escalation_reference: 'escalation://soc/review-queue' },
    ],
  },
  customer_comms_templates: [
    {
      template_id: 'incident_initial_notice',
      purpose: 'initial_customer_notification',
      reference_uri: 'template://comms/incident-initial-v2',
    },
    {
      template_id: 'incident_resolution',
      purpose: 'resolution_summary',
      reference_uri: 'template://comms/incident-resolution-v2',
    },
  ],
  support_signoff: {
    signoff_owner: 'support-operations-lead',
    signed_at: '2026-07-02T12:00:00.000Z',
    signoff_reference: 'signoff://support/readiness-ga-prep',
  },
};

describe('ops readiness validation', () => {
  it('detects ops_readiness probe profile kind', () => {
    const check = getCheckById('ops.runbook_contact_validation.safe');
    assert.equal(isOpsReadinessProbeKind(check), true);
    assert.equal(isOpsReadinessProbeKind(getCheckById('l3.forbidden_udp_port.safe')), false);
  });

  it('passes runbook validation when support_readiness evidence is accepted', () => {
    freshStore();
    getStore().productionReleaseEvidence.push({
      id: 'evidence_support',
      tenant_id: 'ten_demo',
      kind: 'support_readiness',
      status: 'accepted',
      evidence: SUPPORT_EVIDENCE,
      created_at: '2026-07-02T12:00:00.000Z',
    });

    const check = getCheckById('ops.runbook_contact_validation.safe');
    const probe = executeOpsReadinessProbe(
      { tenantId: 'ten_demo' },
      check,
      { id: 'tgt_1', value: 'canary' },
    );
    assert.equal(probe.external_result, 'connected');
    assert.equal(probe.metadata.ops_validation_ok, true);
    assert.equal(probe.metadata.scenario, 'runbook_contacts');
  });

  it('fails runbook validation when support_readiness evidence is missing', () => {
    freshStore();
    const check = getCheckById('ops.runbook_contact_validation.safe');
    const probe = executeOpsReadinessProbe(
      { tenantId: 'ten_demo' },
      check,
      { id: 'tgt_1', value: 'canary' },
    );
    assert.equal(probe.external_result, 'error');
    assert.equal(probe.metadata.ops_validation_ok, false);
  });

  it('passes kill-switch dry-run when audit trail exists without activation', () => {
    freshStore();
    getStore().auditLog.push({
      tenant_id: 'ten_demo',
      action: 'soc.kill_switch.cleared',
      created_at: '2026-07-02T10:00:00.000Z',
    });

    const check = getCheckById('ops.kill_switch_drill.safe');
    const probe = executeOpsReadinessProbe(
      { tenantId: 'ten_demo' },
      check,
      { id: 'tgt_1', value: 'canary' },
    );
    assert.equal(probe.external_result, 'connected');
    assert.equal(probe.metadata.dry_run, true);
    assert.deepEqual(probe.metadata.readiness_signals, ['kill_switch_audit']);
  });
});

describe('ops readiness validation — Postgres injected data path', () => {
  it('resolves scenario from probe profile and check id', () => {
    assert.equal(
      resolveOpsReadinessScenario(getCheckById('ops.runbook_contact_validation.safe')),
      'runbook_contacts',
    );
    assert.equal(
      resolveOpsReadinessScenario(getCheckById('ops.kill_switch_drill.safe')),
      'kill_switch_readiness',
    );
  });

  it('pickLatestAcceptedEvidence filters by tenant, kind, status, and recency', () => {
    const ledger = [
      { id: 'old', kind: 'support_readiness', tenant_id: 'ten_demo', status: 'accepted', created_at: '2026-01-01T00:00:00.000Z', evidence: {} },
      { id: 'new', kind: 'support_readiness', tenant_id: 'ten_demo', status: 'approved', created_at: '2026-06-01T00:00:00.000Z', evidence: {} },
      { id: 'other_tenant', kind: 'support_readiness', tenant_id: 'ten_other', status: 'accepted', created_at: '2026-07-01T00:00:00.000Z', evidence: {} },
      { id: 'rejected', kind: 'support_readiness', tenant_id: 'ten_demo', status: 'rejected', created_at: '2026-08-01T00:00:00.000Z', evidence: {} },
    ];
    assert.equal(pickLatestAcceptedEvidence(ledger, 'support_readiness', 'ten_demo').id, 'new');
    assert.equal(pickLatestAcceptedEvidence(ledger, 'kill_switch_drill', 'ten_demo'), null);
    assert.equal(pickLatestAcceptedEvidence([], 'support_readiness', 'ten_demo'), null);
  });

  it('buildOpsReadinessData derives runbook evidence from a Postgres-style ledger', () => {
    const data = buildOpsReadinessData({
      scenario: 'runbook_contacts',
      tenantId: 'ten_demo',
      releaseEvidenceLedger: [
        { id: 'evd', kind: 'support_readiness', tenant_id: 'ten_demo', status: 'accepted', created_at: '2026-06-01T00:00:00.000Z', evidence: SUPPORT_EVIDENCE },
      ],
    });
    assert.equal(data.evidenceRecord.id, 'evd');
  });

  it('buildOpsReadinessData derives kill-switch signals from record, audit, and drill inputs', () => {
    const data = buildOpsReadinessData({
      scenario: 'kill_switch_readiness',
      tenantId: 'ten_demo',
      killSwitchRecord: { updated_at: '2026-06-01T00:00:00.000Z' },
      auditEntries: [{ action: 'soc.kill_switch.cleared' }],
      releaseEvidenceLedger: [
        { id: 'drill', kind: 'kill_switch_drill', tenant_id: 'ten_demo', status: 'accepted', created_at: '2026-06-02T00:00:00.000Z', evidence: {} },
      ],
    });
    assert.equal(data.hasKillSwitchState, true);
    assert.ok(data.auditHit);
    assert.equal(data.drillRecord.id, 'drill');
  });

  it('executeOpsReadinessProbe honors explicit readiness data without touching the dev store', () => {
    freshStore();
    // Intentionally leave the dev store empty: the probe must use injected data.
    const check = getCheckById('ops.runbook_contact_validation.safe');
    const data = buildOpsReadinessData({
      scenario: 'runbook_contacts',
      tenantId: 'ten_demo',
      releaseEvidenceLedger: [
        { id: 'evd', kind: 'support_readiness', tenant_id: 'ten_demo', status: 'accepted', created_at: '2026-06-01T00:00:00.000Z', evidence: SUPPORT_EVIDENCE },
      ],
    });
    const probe = executeOpsReadinessProbe({ tenantId: 'ten_demo' }, check, { id: 'tgt_1', value: 'canary' }, data);
    assert.equal(probe.external_result, 'connected');
    assert.equal(probe.metadata.ops_validation_ok, true);
    assert.equal(getStore().productionReleaseEvidence.length, 0);
  });

  it('executeOpsReadinessProbe returns error from injected empty ledger (never a hardcoded pass)', () => {
    freshStore();
    const check = getCheckById('ops.runbook_contact_validation.safe');
    const data = buildOpsReadinessData({
      scenario: 'runbook_contacts',
      tenantId: 'ten_demo',
      releaseEvidenceLedger: [],
    });
    const probe = executeOpsReadinessProbe({ tenantId: 'ten_demo' }, check, { id: 'tgt_1', value: 'canary' }, data);
    assert.equal(probe.external_result, 'error');
    assert.equal(probe.metadata.ops_validation_ok, false);
  });

  it('executeOpsReadinessProbe kill-switch scenario reports state signal from injected record', () => {
    freshStore();
    const check = getCheckById('ops.kill_switch_drill.safe');
    const data = buildOpsReadinessData({
      scenario: 'kill_switch_readiness',
      tenantId: 'ten_demo',
      killSwitchRecord: { updated_at: '2026-06-01T00:00:00.000Z' },
      auditEntries: [],
      releaseEvidenceLedger: [],
    });
    const probe = executeOpsReadinessProbe({ tenantId: 'ten_demo' }, check, { id: 'tgt_1', value: 'canary' }, data);
    assert.equal(probe.external_result, 'connected');
    assert.deepEqual(probe.metadata.readiness_signals, ['kill_switch_state']);
    assert.equal(probe.metadata.kill_switch_activated ?? false, false);
  });
});
