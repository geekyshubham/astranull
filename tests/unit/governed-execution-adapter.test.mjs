import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  GOVERNED_ADAPTER_REQUIRED_CAPABILITIES,
  GOVERNED_ADAPTER_REQUIRED_FIELDS,
  GOVERNED_ADAPTER_TYPES,
  governedAdapterProductionReadiness,
  validateGovernedAdapterRegistration,
} from '../../src/contracts/governedExecutionAdapter.mjs';

function completeRegistration() {
  return {
    adapter_id: 'adapter_partner_lab_1',
    adapter_type: 'partner_adapter',
    owner: 'soc-operations',
    approved_provider_path: 'partner_lab',
    scope_validation: 'Adapter accepts signed scope hash and rejects target drift.',
    soc_token_binding: 'Short-lived SOC token bound to request id and scope hash.',
    stop_path: 'Primary API stop plus partner bridge escalation reference.',
    kill_switch_integration: 'Tenant kill switch invokes stop_or_abort before state close.',
    evidence_export: 'Metadata export with provider run id, state, timestamps, and stop evidence.',
    audit_event_contract: 'start, stop, status, metrics, evidence export, and failures audited.',
    staging_validation_uri: 'evidence://staging/governed-adapter/adapter_partner_lab_1',
    reviewed_at: '2026-07-02T00:00:00.000Z',
    capabilities: [...GOVERNED_ADAPTER_REQUIRED_CAPABILITIES],
  };
}

describe('governed execution adapter contract', () => {
  it('defines supported adapter types and required capabilities', () => {
    assert.deepEqual(GOVERNED_ADAPTER_TYPES, [
      'partner_adapter',
      'provider_fire_drill',
      'internal_lab',
      'manual_coordination',
    ]);
    assert.ok(GOVERNED_ADAPTER_REQUIRED_CAPABILITIES.includes('kill_switch_stop_path'));
    assert.ok(GOVERNED_ADAPTER_REQUIRED_FIELDS.includes('staging_validation_uri'));
  });

  it('accepts a complete metadata-only adapter registration', () => {
    assert.deepEqual(validateGovernedAdapterRegistration(completeRegistration()), {
      ok: true,
      missing_fields: [],
      invalid_fields: [],
      missing_capabilities: [],
      forbidden_fields: [],
    });
  });

  it('reports missing required fields and capabilities', () => {
    const registration = completeRegistration();
    delete registration.stop_path;
    registration.capabilities = registration.capabilities.filter(
      (capability) => capability !== 'evidence_export',
    );

    const result = validateGovernedAdapterRegistration(registration);
    assert.equal(result.ok, false);
    assert.deepEqual(result.missing_fields, ['stop_path']);
    assert.deepEqual(result.missing_capabilities, ['evidence_export']);
  });

  it('rejects unsupported adapter types', () => {
    const registration = completeRegistration();
    registration.adapter_type = 'freeform_generator';
    const result = validateGovernedAdapterRegistration(registration);
    assert.equal(result.ok, false);
    assert.deepEqual(result.invalid_fields, [
      {
        field: 'adapter_type',
        reason: 'unsupported_adapter_type',
        allowed: GOVERNED_ADAPTER_TYPES,
      },
    ]);
  });

  it('rejects secrets, raw commands, payloads, and traffic-generator metadata', () => {
    const registration = completeRegistration();
    registration.connection = {
      api_key: 'should-not-be-here',
      raw_command: 'run traffic',
    };
    registration.traffic_generator = { payload: 'unsafe' };

    const result = validateGovernedAdapterRegistration(registration);
    assert.equal(result.ok, false);
    assert.deepEqual(result.forbidden_fields.sort(), [
      'connection.api_key',
      'connection.raw_command',
      'traffic_generator',
      'traffic_generator.payload',
    ]);
  });

  it('summarizes production readiness without exposing registration internals', () => {
    const summary = governedAdapterProductionReadiness(completeRegistration());
    assert.equal(summary.ready, true);
    assert.equal(summary.adapter_id, 'adapter_partner_lab_1');
    assert.equal(summary.adapter_type, 'partner_adapter');
    assert.equal(summary.validation.ok, true);
  });
});
