import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  WAF_RISK_METHOD,
  assignPriorityBand,
  computeAssetRiskAssessment,
  enrichSnapshotWithRisk,
} from '../../src/services/wafRiskService.mjs';

describe('wafRiskService', () => {
  it('scores unprotected payment assets into tier_1 with explainable factors', () => {
    const assessment = computeAssetRiskAssessment({
      asset: {
        id: 'asset_payment',
        business_criticality: 'payment',
        traffic_tier: 'high',
        asset_kind: 'checkout',
        compliance_tags: ['pci'],
      },
      snapshot: {
        waf_asset_id: 'asset_payment',
        status: 'unprotected',
        reason_codes: ['marker_rule_not_blocking'],
      },
      validationSummary: {
        validation_failed: true,
      },
      computedAt: '2026-07-03T00:00:00.000Z',
    });

    assert.equal(assessment.method, WAF_RISK_METHOD);
    assert.ok(assessment.risk_score >= 75);
    assert.equal(assessment.priority_band, 'tier_1');
    assert.ok(assessment.factors.some((f) => f.factor === 'protection_state'));
    assert.ok(assessment.factors.some((f) => f.factor === 'business_criticality'));
    assert.equal(assessment.recommended_action, 'deploy_waf_blocking');
  });

  it('promotes origin bypass to tier_1 even when score is moderate', () => {
    const assessment = computeAssetRiskAssessment({
      asset: {
        id: 'asset_bypass',
        business_criticality: 'low',
        traffic_tier: 'low',
      },
      snapshot: {
        status: 'underprotected',
        reason_codes: ['origin_bypass_confirmed'],
      },
      validationSummary: {
        origin_bypass_confirmed: true,
      },
    });

    assert.equal(assessment.priority_band, 'tier_1');
    assert.equal(assessment.recommended_action, 'close_origin_bypass');
    assert.ok(assessment.factors.some((f) => f.factor === 'origin_bypass' && f.contribution === 25));
  });

  it('assigns tier_4 for excluded assets', () => {
    const band = assignPriorityBand({
      riskScore: 90,
      asset: { business_criticality: 'payment' },
      snapshot: { status: 'excluded', reason_codes: ['policy_exception_active'] },
      factors: [],
    });
    assert.equal(band, 'tier_4');
  });

  it('clamps scores to 0-100 and persists on snapshots', () => {
    const assessment = computeAssetRiskAssessment({
      asset: {
        id: 'asset_max',
        business_criticality: 'payment',
        traffic_tier: 'high',
        asset_kind: 'admin',
        compliance_tags: ['pci', 'hipaa'],
      },
      snapshot: {
        status: 'unprotected',
        reason_codes: ['origin_bypass_confirmed'],
      },
      validationSummary: {
        validation_failed: true,
        origin_bypass_confirmed: true,
      },
      cveMatches: [{ validation_status: 'exposed', risk_score: 90, known_exploited: true }],
      targetGroup: { settings_json: { hosting_environment: 'unknown' } },
    });

    assert.ok(assessment.risk_score <= 100);
    const enriched = enrichSnapshotWithRisk({ risk_score: 0 }, assessment);
    assert.equal(enriched.risk_score, assessment.risk_score);
    assert.deepEqual(enriched.risk_factors_json, assessment.factors);
    assert.equal(enriched.priority_band, assessment.priority_band);
  });
});