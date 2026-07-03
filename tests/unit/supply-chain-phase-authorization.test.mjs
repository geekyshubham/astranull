import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  canAdvanceSupplyChainPhase,
  normalizePhaseAuthorization,
  validatePhaseAuthorizationGate,
} from '../../src/contracts/supplyChainPhaseAuthorization.mjs';

describe('supply chain phase authorization contract', () => {
  it('requires metadata-only authorization fields for AP2 and AP3', () => {
    const ap2 = normalizePhaseAuthorization('AP2_manual_custody', {
      customer_approval_reference: 'cust-approval-1',
      customer_signed_at: '2026-07-03T12:00:00.000Z',
      custody_ids: ['custody://doc-1'],
      manual_workflow_owner: 'dns-team',
    });
    assert.equal(ap2.target_phase, 'AP2_manual_custody');
    assert.equal(ap2.authorization.manual_workflow_owner, 'dns-team');

    const ap3 = normalizePhaseAuthorization('AP3_governed_active', {
      customer_approval_reference: 'cust-approval-2',
      legal_approval_reference: 'legal-approval-1',
      legal_signed_at: '2026-07-03T13:00:00.000Z',
      provider_terms_reference: 'provider-terms-v3',
      custody_ids: ['custody://doc-2'],
      insurance_review_reference: 'insurance-review-1',
      release_back_workflow_reference: 'release-back-runbook-1',
    });
    assert.equal(ap3.target_phase, 'AP3_governed_active');
    assert.equal(ap3.authorization.legal_approval_reference, 'legal-approval-1');
  });

  it('enforces single-step phase advancement and eligible risk states', () => {
    assert.equal(canAdvanceSupplyChainPhase('AP1_ticket_workflow', 'AP2_manual_custody'), true);
    assert.equal(canAdvanceSupplyChainPhase('AP0_detect_only', 'AP2_manual_custody'), false);
    assert.equal(canAdvanceSupplyChainPhase('AP2_manual_custody', 'AP3_governed_active'), true);

    assert.throws(
      () => validatePhaseAuthorizationGate({
        currentPhase: 'AP0_detect_only',
        targetPhase: 'AP2_manual_custody',
        riskState: 'confirmed',
      }),
      (err) => err.code === 'invalid_phase_transition',
    );

    assert.throws(
      () => validatePhaseAuthorizationGate({
        currentPhase: 'AP2_manual_custody',
        targetPhase: 'AP3_governed_active',
        riskState: 'confirmed',
      }),
      (err) => err.code === 'invalid_risk_state_for_phase',
    );

    assert.equal(
      validatePhaseAuthorizationGate({
        currentPhase: 'AP2_manual_custody',
        targetPhase: 'AP3_governed_active',
        riskState: 'customer_custody',
      }),
      true,
    );
  });

  it('rejects skipping AP2 before AP3 and missing legal metadata', () => {
    assert.throws(
      () => validatePhaseAuthorizationGate({
        currentPhase: 'AP1_ticket_workflow',
        targetPhase: 'AP3_governed_active',
        riskState: 'customer_custody',
      }),
      (err) => err.code === 'invalid_phase_transition',
    );

    assert.throws(
      () => normalizePhaseAuthorization('AP3_governed_active', {
        customer_approval_reference: 'cust-approval-2',
        legal_signed_at: '2026-07-03T13:00:00.000Z',
        provider_terms_reference: 'provider-terms-v3',
        custody_ids: ['custody://doc-2'],
        insurance_review_reference: 'insurance-review-1',
        release_back_workflow_reference: 'release-back-runbook-1',
      }),
      (err) => err.code === 'missing_phase_authorization_fields',
    );
  });
});