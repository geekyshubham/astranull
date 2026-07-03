import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  computePlacementDiagnostics,
  publicPlacementDiagnosticsPayload,
  summarizePlacementDiagnostics,
} from '../../src/services/placement.mjs';
import {
  computeReadiness,
  RECENT_EVIDENCE_WINDOW_DAYS,
  WEIGHT_AGENT_PLACEMENT,
  WEIGHT_EVIDENCE_FRESHNESS,
  WEIGHT_SOC_GOVERNANCE,
  WEIGHT_VERDICTS,
} from '../../src/services/readiness.mjs';
import { REQUIRED_ARTIFACT_TYPES } from '../../src/services/highScale.mjs';
import { artifactProofBody } from '../helpers/highScalePayload.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';

function daysAgo(n) {
  return new Date(Date.now() - n * 24 * 60 * 60 * 1000).toISOString();
}

function daysAhead(n) {
  return new Date(Date.now() + n * 24 * 60 * 60 * 1000).toISOString();
}

function factor(result, key) {
  return result.factors.find((f) => f.key === key);
}

describe('readiness scoring', () => {
  it('is explainable with factors', () => {
    freshStore();
    const r = computeReadiness('ten_demo');
    assert.ok(r.score >= 0 && r.score <= 100);
    assert.ok(r.factors.length >= 4);
    for (const f of r.factors) {
      assert.ok(f.label);
      assert.ok(f.detail);
    }
  });

  it('empty tenant state stays explainable and does not award SOC points by absence', () => {
    freshStore();
    const r = computeReadiness('ten_demo');
    const soc = factor(r, 'soc_readiness');
    assert.equal(soc.score, 0);
    assert.match(soc.detail, /No high-scale governance evidence recorded yet/);
    const freshness = factor(r, 'evidence_freshness');
    assert.equal(freshness.score, 0);
    assert.match(freshness.detail, /No evidence-backed validations yet/);
    const verdictsFactor = factor(r, 'verdicts');
    assert.equal(verdictsFactor.score, 0);
    assert.match(verdictsFactor.detail, /absence of findings is not proof/i);
  });

  it('stale completed run does not earn evidence freshness', () => {
    freshStore();
    const store = getStore();
    store.testRuns.push({
      id: 'run_stale',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      check_id: 'origin.direct_reachability.safe',
      status: 'verdicted',
      completed_at: daysAgo(RECENT_EVIDENCE_WINDOW_DAYS + 5),
      created_at: daysAgo(RECENT_EVIDENCE_WINDOW_DAYS + 10),
    });
    store.verdicts.push({
      id: 'v_stale',
      tenant_id: 'ten_demo',
      test_run_id: 'run_stale',
      verdict: 'protected',
      created_at: daysAgo(RECENT_EVIDENCE_WINDOW_DAYS + 5),
      evidence_ids: [],
    });

    const r = computeReadiness('ten_demo');
    assert.equal(factor(r, 'evidence_freshness').score, 0);
    assert.match(factor(r, 'evidence_freshness').detail, /stale/i);
    assert.equal(factor(r, 'coverage').score, 0);
  });

  it('recent run without verdict/event/evidence does not earn freshness', () => {
    freshStore();
    getStore().testRuns.push({
      id: 'run_bare',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      check_id: 'origin.direct_reachability.safe',
      status: 'completed',
      completed_at: new Date().toISOString(),
      created_at: new Date().toISOString(),
    });

    const r = computeReadiness('ten_demo');
    assert.equal(factor(r, 'evidence_freshness').score, 0);
    assert.match(factor(r, 'evidence_freshness').detail, /No evidence-backed validations yet/);
    assert.equal(factor(r, 'coverage').score, 0);
  });

  it('recent run with verdict/evidence earns freshness and coverage', () => {
    freshStore();
    const store = getStore();
    store.testRuns.push({
      id: 'run_recent',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      check_id: 'origin.direct_reachability.safe',
      status: 'verdicted',
      completed_at: new Date().toISOString(),
      created_at: new Date().toISOString(),
    });
    store.verdicts.push({
      id: 'v_recent',
      tenant_id: 'ten_demo',
      test_run_id: 'run_recent',
      verdict: 'protected',
      created_at: new Date().toISOString(),
      evidence_ids: ['evt_1'],
    });
    store.events.push({
      id: 'evt_1',
      tenant_id: 'ten_demo',
      test_run_id: 'run_recent',
      signal_type: 'probe_result',
      timestamp: new Date().toISOString(),
    });

    const r = computeReadiness('ten_demo');
    assert.equal(factor(r, 'evidence_freshness').score, WEIGHT_EVIDENCE_FRESHNESS);
    assert.equal(factor(r, 'coverage').score, 40);
    assert.match(factor(r, 'coverage').detail, /1 of 1 target group/);
  });

  it('high-scale request with accepted required artifacts and two distinct approvals earns SOC points', () => {
    freshStore();
    const store = getStore();
    const artifacts = REQUIRED_ARTIFACT_TYPES.map((type, i) => {
      const proof = artifactProofBody(type);
      return {
        id: `art_${i}`,
        type,
        status: 'accepted',
        approval_reference: proof.approval_reference,
        approver: proof.approver,
        valid_window: proof.valid_window,
        approved_scenario_families: proof.approved_scenario_families,
        max_rate: proof.max_rate,
        max_duration_minutes: proof.max_duration_minutes,
        emergency_contacts: proof.emergency_contacts,
        abort_criteria: proof.abort_criteria,
      };
    });
    store.highScaleRequests.push({
      id: 'hs_ok',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_1',
      state: 'approved',
      artifacts,
      soc_approvals: [
        { user_id: 'usr_a', at: new Date().toISOString() },
        { user_id: 'usr_b', at: new Date().toISOString() },
      ],
      audit_trail: [{ action: 'approve', at: new Date().toISOString() }],
    });

    const r = computeReadiness('ten_demo');
    const soc = factor(r, 'soc_readiness');
    assert.equal(soc.score, WEIGHT_SOC_GOVERNANCE);
    assert.match(soc.detail, /authorization pack accepted/i);
  });

  it('pending high-scale request without complete artifacts/approvals does not earn SOC points and explains missing gates', () => {
    freshStore();
    getStore().highScaleRequests.push({
      id: 'hs_pending',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_1',
      state: 'submitted',
      artifacts: [{ id: 'art_0', type: REQUIRED_ARTIFACT_TYPES[0], status: 'accepted' }],
      soc_approvals: [{ user_id: 'usr_a', at: new Date().toISOString() }],
      audit_trail: [],
    });

    const r = computeReadiness('ten_demo');
    const soc = factor(r, 'soc_readiness');
    assert.equal(soc.score, 0);
    assert.match(soc.detail, /gates remain/i);
    assert.match(soc.detail, /SOC approvals 1\/2/);
    assert.match(soc.detail, /missing accepted artifacts/i);
    assert.ok(REQUIRED_ARTIFACT_TYPES.includes('business_approval'));
    assert.ok(REQUIRED_ARTIFACT_TYPES.includes('legal_approval'));
  });

  it('future-dated run, verdict, and event do not earn freshness or coverage', () => {
    freshStore();
    const store = getStore();
    const future = daysAhead(3);
    store.testRuns.push({
      id: 'run_future',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      check_id: 'origin.direct_reachability.safe',
      status: 'verdicted',
      completed_at: future,
      created_at: future,
    });
    store.verdicts.push({
      id: 'v_future',
      tenant_id: 'ten_demo',
      test_run_id: 'run_future',
      verdict: 'protected',
      created_at: future,
      evidence_ids: ['evt_future'],
    });
    store.events.push({
      id: 'evt_future',
      tenant_id: 'ten_demo',
      test_run_id: 'run_future',
      signal_type: 'probe_result',
      timestamp: future,
    });

    const r = computeReadiness('ten_demo');
    assert.equal(factor(r, 'evidence_freshness').score, 0);
    assert.equal(factor(r, 'coverage').score, 0);
  });

  it('recent evidence-backed run for undeclared target group does not earn coverage', () => {
    freshStore();
    const store = getStore();
    const now = new Date().toISOString();
    store.testRuns.push({
      id: 'run_undeclared_tg',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_not_declared',
      target_id: 'tgt_1',
      check_id: 'origin.direct_reachability.safe',
      status: 'verdicted',
      completed_at: now,
      created_at: now,
    });
    store.verdicts.push({
      id: 'v_undeclared',
      tenant_id: 'ten_demo',
      test_run_id: 'run_undeclared_tg',
      verdict: 'protected',
      created_at: now,
      evidence_ids: ['evt_ud'],
    });
    store.events.push({
      id: 'evt_ud',
      tenant_id: 'ten_demo',
      test_run_id: 'run_undeclared_tg',
      signal_type: 'probe_result',
      timestamp: now,
    });

    const r = computeReadiness('ten_demo');
    assert.equal(factor(r, 'coverage').score, 0);
    assert.match(factor(r, 'coverage').detail, /0 of 1 target group/);
  });

  it('recent verdict with no open findings earns full verdict factor', () => {
    freshStore();
    const store = getStore();
    const now = new Date().toISOString();
    store.testRuns.push({
      id: 'run_v_ok',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      check_id: 'origin.direct_reachability.safe',
      status: 'verdicted',
      completed_at: now,
      created_at: now,
    });
    store.verdicts.push({
      id: 'v_ok',
      tenant_id: 'ten_demo',
      test_run_id: 'run_v_ok',
      verdict: 'protected',
      created_at: now,
      evidence_ids: [],
    });

    const r = computeReadiness('ten_demo');
    assert.equal(factor(r, 'verdicts').score, WEIGHT_VERDICTS);
    assert.match(factor(r, 'verdicts').detail, /0 open finding/);
    assert.match(factor(r, 'verdicts').detail, /1 recent/);
  });

  it('open findings reduce verdict factor when recent verdicts exist', () => {
    freshStore();
    const store = getStore();
    const now = new Date().toISOString();
    store.verdicts.push({
      id: 'v_penalty',
      tenant_id: 'ten_demo',
      test_run_id: 'run_x',
      verdict: 'exposed',
      created_at: now,
      evidence_ids: [],
    });
    store.findings.push({
      id: 'f_1',
      tenant_id: 'ten_demo',
      status: 'open',
      severity: 'high',
    });
    store.findings.push({
      id: 'f_2',
      tenant_id: 'ten_demo',
      status: 'open',
      severity: 'medium',
    });

    const r = computeReadiness('ten_demo');
    assert.equal(factor(r, 'verdicts').score, WEIGHT_VERDICTS - 20);
    assert.match(factor(r, 'verdicts').detail, /2 open finding/);
    assert.match(factor(r, 'verdicts').detail, /1 recent/);
  });

  it('placement diagnostics: no bound agent returns missing_agent', () => {
    freshStore();
    const d = computePlacementDiagnostics('ten_demo');
    assert.equal(d.groups.length, 1);
    assert.equal(d.groups[0].status, 'missing_agent');
    assert.ok(d.groups[0].warnings.includes('no_bound_agent'));
  });

  it('placement diagnostics: online unbound agent does not prove target group', () => {
    freshStore();
    getStore().agents.push({
      id: 'agent_unbound',
      tenant_id: 'ten_demo',
      name: 'unbound',
      status: 'online',
      target_group_id: null,
      created_at: new Date().toISOString(),
    });
    const d = computePlacementDiagnostics('ten_demo');
    assert.equal(d.groups[0].status, 'missing_agent');
    assert.ok(d.groups[0].warnings.includes('unbound_agent_only'));
    assert.deepEqual(d.groups[0].online_bound_agent_ids, []);
  });

  it('placement diagnostics: online bound agent without observations returns needs_baseline', () => {
    freshStore();
    getStore().agents.push({
      id: 'agent_bound',
      tenant_id: 'ten_demo',
      name: 'bound',
      status: 'online',
      target_group_id: 'tg_1',
      created_at: new Date().toISOString(),
    });
    const d = computePlacementDiagnostics('ten_demo');
    assert.equal(d.groups[0].status, 'needs_baseline');
    assert.ok(d.groups[0].warnings.includes('no_recent_observation'));
  });

  it('placement diagnostics: recent agent observation for group returns proven', () => {
    freshStore();
    const store = getStore();
    const now = new Date().toISOString();
    store.agents.push({
      id: 'agent_bound',
      tenant_id: 'ten_demo',
      name: 'bound',
      status: 'online',
      target_group_id: 'tg_1',
      created_at: now,
    });
    store.testRuns.push({
      id: 'run_place',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      check_id: 'origin.direct_reachability.safe',
      status: 'verdicted',
      created_at: now,
    });
    store.events.push({
      id: 'evt_obs',
      tenant_id: 'ten_demo',
      test_run_id: 'run_place',
      signal_type: 'agent_observation',
      agent_id: 'agent_bound',
      timestamp: now,
    });
    const d = computePlacementDiagnostics('ten_demo');
    assert.equal(d.groups[0].status, 'proven');
    assert.equal(d.groups[0].recent_observation_count, 1);
  });

  it('publicPlacementDiagnosticsPayload includes per-group metadata for UI', () => {
    freshStore();
    getStore().agents.push({
      id: 'agent_bound',
      tenant_id: 'ten_demo',
      name: 'bound',
      status: 'online',
      target_group_id: 'tg_1',
      created_at: new Date().toISOString(),
    });
    const diagnostics = computePlacementDiagnostics('ten_demo');
    const payload = publicPlacementDiagnosticsPayload(diagnostics);
    assert.equal(payload.groups.length, 1);
    assert.equal(payload.groups[0].target_group_id, 'tg_1');
    assert.equal(payload.groups[0].status, 'needs_baseline');
    assert.ok(Array.isArray(payload.groups[0].warnings));
  });

  it('readiness agent_placement factor includes placement diagnostics summary', () => {
    freshStore();
    getStore().agents.push({
      id: 'agent_bound',
      tenant_id: 'ten_demo',
      name: 'bound',
      status: 'online',
      target_group_id: 'tg_1',
      created_at: new Date().toISOString(),
    });
    const r = computeReadiness('ten_demo');
    const placement = factor(r, 'agent_placement');
    assert.ok(placement.placement_diagnostics);
    assert.match(placement.detail, /Placement diagnostics:/);
    assert.match(placement.detail, /need baseline/);
    const summary = summarizePlacementDiagnostics(computePlacementDiagnostics('ten_demo'));
    assert.equal(placement.placement_diagnostics.needs_baseline, summary.needs_baseline);
    assert.ok(Array.isArray(placement.placement_diagnostics.groups));
    assert.equal(placement.placement_diagnostics.groups[0].status, 'needs_baseline');
  });

  it('readiness does not over-award placement for unbound online agents only', () => {
    freshStore();
    getStore().agents.push({
      id: 'agent_unbound',
      tenant_id: 'ten_demo',
      name: 'unbound',
      status: 'online',
      target_group_id: null,
      created_at: new Date().toISOString(),
    });
    const r = computeReadiness('ten_demo');
    const placement = factor(r, 'agent_placement');
    assert.equal(placement.score, 0);
    assert.match(placement.detail, /Unbound online agents do not prove placement/);
  });

  it('readiness awards full placement weight when group is proven', () => {
    freshStore();
    const store = getStore();
    const now = new Date().toISOString();
    store.agents.push({
      id: 'agent_bound',
      tenant_id: 'ten_demo',
      name: 'bound',
      status: 'online',
      target_group_id: 'tg_1',
      created_at: now,
    });
    store.testRuns.push({
      id: 'run_proven',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      check_id: 'origin.direct_reachability.safe',
      status: 'verdicted',
      created_at: now,
    });
    store.events.push({
      id: 'evt_proven',
      tenant_id: 'ten_demo',
      test_run_id: 'run_proven',
      signal_type: 'agent_observation',
      agent_id: 'agent_bound',
      timestamp: now,
    });
    const r = computeReadiness('ten_demo');
    assert.equal(factor(r, 'agent_placement').score, WEIGHT_AGENT_PLACEMENT);
    assert.match(factor(r, 'agent_placement').detail, /1 proven/);
  });

  it('stale-only verdicts do not earn full verdict factor credit', () => {
    freshStore();
    const store = getStore();
    store.verdicts.push({
      id: 'v_old',
      tenant_id: 'ten_demo',
      test_run_id: 'run_old',
      verdict: 'protected',
      created_at: daysAgo(RECENT_EVIDENCE_WINDOW_DAYS + 2),
      evidence_ids: [],
    });

    const r = computeReadiness('ten_demo');
    assert.equal(factor(r, 'verdicts').score, 0);
    assert.match(factor(r, 'verdicts').detail, /0 recent/);
    assert.match(factor(r, 'verdicts').detail, /stale/i);
    assert.match(factor(r, 'verdicts').detail, /does not support full posture credit/i);
  });
});