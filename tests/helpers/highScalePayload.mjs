import assert from 'node:assert/strict';
import { REQUIRED_ARTIFACT_TYPES } from '../../src/services/highScale.mjs';
import { getStore } from '../../src/store.mjs';
import { demoHeaders, request } from './http.mjs';

/** Pre–SOC-009 expansion artifact set (for negative authorization-pack tests). */
export const LEGACY_REQUIRED_ARTIFACT_TYPES = [
  'customer_authorization_letter',
  'target_ownership_confirmation',
  'emergency_contacts',
  'stop_criteria',
  'test_plan',
];

function defaultProofWindow() {
  return {
    valid_from: new Date().toISOString(),
    valid_to: new Date(Date.now() + 86400000 * 30).toISOString(),
  };
}

export function artifactProofBody(type, overrides = {}) {
  const base = {
    type,
    reference_uri: 'metadata://pack/demo',
    approval_reference: 'REF-DEMO-001',
    approver: 'Customer Approver',
    valid_window: defaultProofWindow(),
    approved_targets: ['tg_1'],
    approved_scenario_families: ['volumetric_metadata'],
    max_rate: '1000_rps_metadata',
    max_duration_minutes: 30,
    emergency_contacts: [{ name: 'On-call', contact: 'ops@example.invalid' }],
    abort_criteria: { threshold: 'error_rate_above_5pct', auto_stop: true },
    retention_policy: { retain_days: 90, classification: 'governance' },
  };
  return { ...base, ...overrides };
}

export function validHighScaleRequestPayload(overrides = {}) {
  const windowStart = new Date(Date.now() + 86400000).toISOString();
  const windowEnd = new Date(Date.now() + 172800000).toISOString();
  return {
    target_group_id: 'tg_1',
    objective: 'Scheduled readiness drill',
    environment: 'staging',
    business_criticality: 'high',
    requested_scenario_families: ['volumetric_metadata'],
    requested_limits: { max_rate: '500_rps_metadata', max_duration_minutes: 45 },
    stop_criteria: { abort_on_customer_signal: true, max_error_rate_pct: 5 },
    abort_criteria: { threshold: 'error_rate_above_5pct', auto_stop: true },
    requested_window: {
      window_start: windowStart,
      window_end: windowEnd,
      timezone: 'UTC',
    },
    emergency_contacts: [{ name: 'On-call', contact: 'ops@example.invalid' }],
    provider_context: { provider_name: 'Cloudflare' },
    scope_confirmation: true,
    ...overrides,
  };
}

export async function acceptRequiredAuthorizationArtifactsOnly(baseUrl, hsId, socHeaders) {
  for (const type of REQUIRED_ARTIFACT_TYPES) {
    const up = await request(baseUrl, 'POST', `/v1/high-scale-requests/${hsId}/artifacts`, {
      headers: demoHeaders('engineer'),
      body: artifactProofBody(type),
    });
    assert.equal(up.status, 201);
    const review = await request(
      baseUrl,
      'POST',
      `/internal/soc/high-scale/${hsId}/artifacts/${up.json.id}/review`,
      { headers: socHeaders, body: { status: 'accepted' } },
    );
    assert.equal(review.status, 200);
  }
}

export async function acceptLegacyAuthorizationArtifactsOnly(baseUrl, hsId, socHeaders) {
  for (const type of LEGACY_REQUIRED_ARTIFACT_TYPES) {
    const up = await request(baseUrl, 'POST', `/v1/high-scale-requests/${hsId}/artifacts`, {
      headers: demoHeaders('engineer'),
      body: artifactProofBody(type),
    });
    assert.equal(up.status, 201);
    const review = await request(
      baseUrl,
      'POST',
      `/internal/soc/high-scale/${hsId}/artifacts/${up.json.id}/review`,
      { headers: socHeaders, body: { status: 'accepted' } },
    );
    assert.equal(review.status, 200);
  }
}

export async function acceptHighScaleAuthorizationPack(baseUrl, hsId, socHeaders) {
  await acceptRequiredAuthorizationArtifactsOnly(baseUrl, hsId, socHeaders);
  const req = getStore().highScaleRequests.find((r) => r.id === hsId);
  for (const item of req?.provider_approval_checklist ?? []) {
    const up = await request(baseUrl, 'POST', `/v1/high-scale-requests/${hsId}/artifacts`, {
      headers: demoHeaders('engineer'),
      body: {
        type: 'provider_approval',
        provider_name: item.provider_name,
        reference_uri: 'metadata://pack/provider',
        approval_reference: 'PROV-REF-001',
        valid_window: defaultProofWindow(),
        approved_targets: ['tg_1'],
        approved_scenario_families: ['volumetric_metadata'],
        contact_path: 'provider-war-room@example.invalid',
        approved_limits: { max_rate: '500_rps_metadata', max_duration_minutes: 45 },
        provider_specific_evidence: {
          approval_path: item.approval_path ?? 'manual_coordination',
          provider_key: item.provider_key ?? 'generic',
        },
        emergency_stop_path: 'provider-stop-bridge',
      },
    });
    assert.equal(up.status, 201);
    const review = await request(
      baseUrl,
      'POST',
      `/internal/soc/high-scale/${hsId}/artifacts/${up.json.id}/review`,
      { headers: socHeaders, body: { status: 'accepted' } },
    );
    assert.equal(review.status, 200);
  }
}
