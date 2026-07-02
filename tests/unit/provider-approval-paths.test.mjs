import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  buildProviderApprovalChecklist,
  syncChecklistFromProviderArtifact,
  syncChecklistFromProviderArtifactReview,
} from '../../src/lib/highScalePolicy.mjs';
import {
  buildProviderApprovalMetadata,
  getProviderApprovalPath,
  listProviderApprovalPaths,
  normalizeProviderKey,
  providerApprovalMissingFields,
} from '../../src/contracts/providerApprovalPaths.mjs';

const REQUIRED_KEYS = [
  'aws',
  'azure',
  'gcp',
  'cloudflare',
  'akamai',
  'cdn_other',
  'isp_carrier',
  'on_prem_lab',
  'partner_lab',
  'generic',
];

function completeProviderBody(overrides = {}) {
  return {
    provider_name: 'Cloudflare',
    approval_reference: 'CF-1001',
    valid_window: { valid_to: new Date(Date.now() + 86400000).toISOString() },
    approved_targets: ['tg_1'],
    approved_scenario_families: ['volumetric_metadata'],
    contact_path: 'provider-war-room@example.invalid',
    approved_limits: { max_rate: '500_rps_metadata', max_duration_minutes: 30 },
    provider_specific_evidence: { provider_ticket: 'CF-1001' },
    emergency_stop_path: 'provider-stop-bridge',
    ...overrides,
  };
}

describe('provider approval path catalog', () => {
  it('lists required provider profiles', () => {
    const keys = listProviderApprovalPaths().map((p) => p.provider_key);
    for (const key of REQUIRED_KEYS) assert.ok(keys.includes(key), key);
  });

  it('normalizes common provider names', () => {
    assert.equal(normalizeProviderKey('Amazon Web Services'), 'aws');
    assert.equal(normalizeProviderKey('Microsoft Azure'), 'azure');
    assert.equal(normalizeProviderKey('Google Cloud'), 'gcp');
    assert.equal(normalizeProviderKey('Cloudflare'), 'cloudflare');
    assert.equal(normalizeProviderKey('Akamai'), 'akamai');
    assert.equal(normalizeProviderKey('unknown provider'), 'generic');
    assert.equal(getProviderApprovalPath('AWS').approval_path, 'provider_fire_drill');
  });

  it('reports missing fields until provider approval metadata is complete', () => {
    const partial = buildProviderApprovalMetadata({ provider_name: 'Cloudflare' });
    assert.ok(partial.missing_fields.includes('approval_reference'));
    assert.ok(partial.missing_fields.includes('emergency_stop_path'));

    const complete = providerApprovalMissingFields({
      provider_name: 'Cloudflare',
      ...completeProviderBody(),
    });
    assert.deepEqual(complete, []);
  });

  it('builds checklist rows with provider path metadata', () => {
    const checklist = buildProviderApprovalChecklist({
      provider_context: { provider_name: 'AWS', requires_provider_approval: true },
    });
    assert.equal(checklist.length, 1);
    assert.equal(checklist[0].provider_key, 'aws');
    assert.equal(checklist[0].approval_path, 'provider_fire_drill');
    assert.ok(checklist[0].accepted_test_paths.length > 0);
    assert.ok(checklist[0].missing_fields.includes('approval_reference'));
  });

  it('keeps reviewed provider artifact partial until required metadata is present', () => {
    const req = {
      provider_approval_checklist: buildProviderApprovalChecklist({
        provider_context: { provider_name: 'Cloudflare', requires_provider_approval: true },
      }),
    };
    const partialArtifact = { id: 'art_partial', provider_name: 'Cloudflare' };
    syncChecklistFromProviderArtifact(req, partialArtifact, { provider_name: 'Cloudflare' });
    syncChecklistFromProviderArtifactReview(req, {
      ...partialArtifact,
      status: 'accepted',
      reviewed_at: new Date().toISOString(),
      reviewed_by: 'usr_soc',
    });
    assert.equal(req.provider_approval_checklist[0].status, 'partial');
    assert.ok(req.provider_approval_checklist[0].missing_fields.length > 0);

    const completeArtifact = {
      id: 'art_complete',
      provider_name: 'Cloudflare',
      ...completeProviderBody(),
    };
    syncChecklistFromProviderArtifact(req, completeArtifact, completeProviderBody());
    syncChecklistFromProviderArtifactReview(req, {
      ...completeArtifact,
      status: 'accepted',
      reviewed_at: new Date().toISOString(),
      reviewed_by: 'usr_soc',
    });
    assert.equal(req.provider_approval_checklist[0].status, 'accepted');
    assert.deepEqual(req.provider_approval_checklist[0].missing_fields, []);
  });
});
