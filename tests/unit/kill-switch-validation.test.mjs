import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  KILL_SWITCH_REQUIRED_STEP_IDS,
  KILL_SWITCH_REQUIRED_STEPS,
  validateKillSwitchExerciseEvidence,
} from '../../src/contracts/killSwitchValidation.mjs';

function completeExercise() {
  return {
    exercise_id: 'ks_2026_07_02',
    steps: KILL_SWITCH_REQUIRED_STEPS.map((step) => ({
      step_id: step.step_id,
      evidence_uri: `evidence://kill-switch/${step.step_id}`,
      validated_at: '2026-07-02T00:00:00.000Z',
      operator: 'soc-shift-lead',
      tenant_id: 'ten_demo',
      blocked_run_reference: 'run_blocked_after_ks',
      cancelled_run_ids: ['run_active_1'],
      worker_pool_reference: 'probe-fleet/staging/pool-a',
      adapter_stop_reference: 'adapter-stop/staging/request-1',
      audit_event_ids: ['audit_1', 'audit_2'],
      resume_decision_reference: 'change://resume-after-review',
    })),
  };
}

describe('kill switch validation evidence contract', () => {
  it('lists required exercise steps in order', () => {
    assert.deepEqual(KILL_SWITCH_REQUIRED_STEP_IDS, [
      'activate_tenant_kill_switch',
      'block_new_safe_runs',
      'cancel_active_safe_runs',
      'probe_fleet_stops_leasing',
      'adapter_stop_path_invoked',
      'audit_timeline_recorded',
      'clear_and_resume_guarded',
    ]);
  });

  it('accepts a complete metadata-only exercise', () => {
    assert.deepEqual(validateKillSwitchExerciseEvidence(completeExercise()), {
      ok: true,
      missing_steps: [],
      invalid_steps: [],
      missing_fields: [],
      forbidden_fields: [],
    });
  });

  it('reports missing exercise steps', () => {
    const evidence = completeExercise();
    evidence.steps = evidence.steps.filter(
      (step) => step.step_id !== 'probe_fleet_stops_leasing',
    );
    const result = validateKillSwitchExerciseEvidence(evidence);
    assert.equal(result.ok, false);
    assert.deepEqual(result.missing_steps, ['probe_fleet_stops_leasing']);
  });

  it('reports missing required step fields', () => {
    const evidence = completeExercise();
    const adapterStep = evidence.steps.find(
      (step) => step.step_id === 'adapter_stop_path_invoked',
    );
    delete adapterStep.adapter_stop_reference;

    const result = validateKillSwitchExerciseEvidence(evidence);
    assert.equal(result.ok, false);
    assert.deepEqual(result.missing_fields, [
      {
        step_id: 'adapter_stop_path_invoked',
        fields: ['adapter_stop_reference'],
      },
    ]);
  });

  it('rejects unknown steps', () => {
    const evidence = completeExercise();
    evidence.steps.push({
      step_id: 'run_unmanaged_traffic',
      evidence_uri: 'evidence://bad',
      validated_at: '2026-07-02T00:00:00.000Z',
      operator: 'soc-shift-lead',
    });
    const result = validateKillSwitchExerciseEvidence(evidence);
    assert.equal(result.ok, false);
    assert.deepEqual(result.invalid_steps, [
      { step_id: 'run_unmanaged_traffic', reason: 'unknown_step' },
    ]);
  });

  it('rejects raw or secret-bearing evidence fields', () => {
    const evidence = completeExercise();
    evidence.steps[0].raw_headers = { authorization: 'Bearer unsafe' };
    evidence.steps[1].metadata = { packet_payload: 'unsafe' };

    const result = validateKillSwitchExerciseEvidence(evidence);
    assert.equal(result.ok, false);
    assert.deepEqual(result.forbidden_fields.sort(), [
      'steps[0].raw_headers',
      'steps[0].raw_headers.authorization',
      'steps[1].metadata.packet_payload',
    ]);
  });
});
