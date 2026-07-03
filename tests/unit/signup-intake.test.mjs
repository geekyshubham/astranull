import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  canTransitionSignupState,
  customerSafeRejectionReason,
  extractEmailDomain,
  validateSignupRequestInput,
} from '../../src/contracts/signupIntake.mjs';

describe('signup intake contract', () => {
  it('validates required signup fields', () => {
    const ok = validateSignupRequestInput({
      organization_name: 'Acme Corp',
      contact_email: 'admin@acme.example',
      contact_name: 'Jordan Lee',
      requested_plan: 'professional',
      intended_use: 'Defensive DDoS readiness validation for declared production origins.',
      region: 'us',
    });
    assert.equal(ok.ok, true);
    assert.equal(ok.value.email_domain, 'acme.example');
  });

  it('rejects invalid email and plan', () => {
    const bad = validateSignupRequestInput({
      organization_name: 'A',
      contact_email: 'not-an-email',
      contact_name: 'X',
      requested_plan: 'mega',
      intended_use: 'short',
      region: '',
    });
    assert.equal(bad.ok, false);
    assert.ok(bad.errors.includes('organization_name'));
    assert.ok(bad.errors.includes('contact_email'));
    assert.ok(bad.errors.includes('requested_plan'));
  });

  it('enforces signup state transitions', () => {
    assert.equal(canTransitionSignupState('submitted', 'under_review'), true);
    assert.equal(canTransitionSignupState('approved', 'provisioned'), true);
    assert.equal(canTransitionSignupState('rejected', 'approved'), false);
  });

  it('extracts email domain and trims customer-safe rejection copy', () => {
    assert.equal(extractEmailDomain('User@Example.COM'), 'example.com');
    const long = 'x'.repeat(300);
    assert.ok(customerSafeRejectionReason(long).length <= 240);
  });
});