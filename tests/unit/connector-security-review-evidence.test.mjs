import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  createConnectorSecurityReviewManifest,
  REQUIRED_CONNECTOR_PROVIDERS,
  validateConnectorSecurityReviewEvidence,
} from '../../scripts/connector-security-review-evidence.mjs';

function validEvidence(overrides = {}) {
  return {
    release_id: 'rel_connector_review_1',
    tenant_scope: 'ten_demo',
    connector_providers: [...REQUIRED_CONNECTOR_PROVIDERS],
    read_only_enforced: true,
    vault_only_secret_refs: true,
    feature_flag_plan: {
      flag_name: 'ASTRANULL_CONNECTORS_ENABLED',
      default_enabled: false,
      tenant_overrides: [{ tenant_id: 'ten_demo', enabled: true }],
    },
    soc_signoff: {
      owner: 'soc-lead',
      signed_at: '2026-07-01T12:00:00.000Z',
      reference: 'soc://connector-review/ten_demo',
    },
    security_signoff: {
      owner: 'security-lead',
      signed_at: '2026-07-01T12:00:00.000Z',
      reference: 'security://connector-review/ten_demo',
    },
    ...overrides,
  };
}

describe('connector security review evidence', () => {
  it('accepts complete metadata-only evidence', () => {
    const evidence = validEvidence();
    const runtimeConfig = {
      featureFlags: {
        connectorsEnabledDefault: false,
        connectorsEnabledTenants: { ten_demo: true },
      },
    };
    const validation = validateConnectorSecurityReviewEvidence(evidence, { runtimeConfig });
    assert.equal(validation.ok, true);
    const manifest = createConnectorSecurityReviewManifest({ evidence, runtimeConfig });
    assert.equal(manifest.artifact_type, 'connector_security_review_evidence');
    assert.equal(manifest.validation.ok, true);
    assert.equal(manifest.connector_providers.length, REQUIRED_CONNECTOR_PROVIDERS.length);
  });

  it('rejects forbidden credentials and raw configs', () => {
    const evidence = validEvidence({
      connector_providers: ['cloudflare', { api_key: 'unsafe' }],
    });
    const validation = validateConnectorSecurityReviewEvidence(evidence);
    assert.equal(validation.ok, false);
    assert.ok(validation.forbidden_fields.length > 0);
  });

  it('requires read-only and vault-only secret refs posture', () => {
    const evidence = validEvidence({
      read_only_enforced: false,
      vault_only_secret_refs: false,
    });
    const validation = validateConnectorSecurityReviewEvidence(evidence);
    assert.equal(validation.ok, false);
    assert.ok(
      validation.invalid_fields.some((entry) => entry.field === 'read_only_enforced'),
    );
    assert.ok(
      validation.invalid_fields.some((entry) => entry.field === 'vault_only_secret_refs'),
    );
  });

  it('reports provider coverage gaps', () => {
    const evidence = validEvidence({
      connector_providers: ['cloudflare', 'aws'],
    });
    const validation = validateConnectorSecurityReviewEvidence(evidence);
    assert.equal(validation.ok, false);
    assert.ok(validation.coverage_gaps.some((gap) => gap.startsWith('missing_provider:')));
  });
});