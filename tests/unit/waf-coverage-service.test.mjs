import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  buildCoverageSummary,
  computeCoverageDailyRollup,
  buildCriticalityRollup,
  buildEntityRollup,
  buildGeographyRollup,
  buildRiskRoadmap,
  buildVendorBreakdown,
  buildVendorConsolidation,
} from '../../src/services/wafCoverageService.mjs';

const assets = [
  {
    id: 'asset_a',
    canonical_url: 'https://pay.example.com',
    owner_hint: 'payments',
    business_criticality: 'payment',
    target_group_id: 'tg_1',
  },
  {
    id: 'asset_b',
    canonical_url: 'https://www.example.com',
    owner_hint: 'marketing',
    business_criticality: 'low',
    target_group_id: 'tg_2',
  },
];

const snapshots = new Map([
  [
    'asset_a',
    {
      waf_asset_id: 'asset_a',
      status: 'unprotected',
      detected_vendor: 'cloudflare',
      detected_product: 'Cloudflare WAF',
      created_at: '2026-07-03T10:00:00.000Z',
    },
  ],
  [
    'asset_b',
    {
      waf_asset_id: 'asset_b',
      status: 'protected',
      detected_vendor: 'akamai',
      detected_product: 'Akamai WAF',
      created_at: '2026-07-03T10:00:00.000Z',
    },
  ],
]);

describe('wafCoverageService', () => {
  it('builds coverage summary ratio and trend buckets', () => {
    const summary = buildCoverageSummary({
      assets,
      currentSnapshotsByAsset: snapshots,
      historicalSnapshots: [...snapshots.values()],
      windowDays: 7,
      now: new Date('2026-07-03T12:00:00.000Z'),
    });

    assert.equal(summary.total, 2);
    assert.equal(summary.total_assets, 2);
    assert.equal(summary.protected, 1);
    assert.equal(summary.unprotected, 1);
    assert.equal(summary.coverage_ratio, 0.5);
    assert.equal(summary.trend.length, 7);
    assert.equal(summary.trend.at(-1).protected, 1);
  });

  it('computes a single-day coverage rollup bucket', () => {
    const rollup = computeCoverageDailyRollup({
      assets,
      currentSnapshotsByAsset: snapshots,
      rollupDate: '2026-07-03',
    });
    assert.equal(rollup.rollup_date, '2026-07-03');
    assert.equal(rollup.total_assets, 2);
    assert.equal(rollup.protected, 1);
    assert.equal(rollup.unprotected, 1);
    assert.equal(rollup.coverage_ratio, 0.5);
  });

  it('rolls up vendor mix for executive charts', () => {
    const vendors = buildVendorBreakdown({
      assets,
      currentSnapshotsByAsset: snapshots,
    });

    assert.equal(vendors.items.length, 2);
    assert.ok(vendors.vendor_mix.some((entry) => entry.vendor === 'cloudflare'));
    assert.equal(
      vendors.items.find((entry) => entry.vendor === 'cloudflare').unprotected_count,
      1,
    );
  });

  it('rolls up criticality buckets with critical gap counts', () => {
    const criticality = buildCriticalityRollup({
      assets,
      currentSnapshotsByAsset: snapshots,
    });

    const payment = criticality.items.find((item) => item.business_criticality === 'payment');
    assert.ok(payment);
    assert.equal(payment.asset_count, 1);
    assert.equal(payment.unprotected, 1);
    assert.equal(payment.critical_gap_count, 1);
    assert.equal(payment.coverage_ratio, 0);

    const low = criticality.items.find((item) => item.business_criticality === 'low');
    assert.ok(low);
    assert.equal(low.protected, 1);
    assert.equal(low.critical_gap_count, 0);
  });

  it('rolls up entities from owner hints', () => {
    const entities = buildEntityRollup({
      assets,
      currentSnapshotsByAsset: snapshots,
      targetGroups: [
        { id: 'tg_1', name: 'Payments', settings_json: {} },
        { id: 'tg_2', name: 'Marketing', settings_json: {} },
      ],
    });

    assert.ok(entities.items.some((item) => item.name === 'payments'));
    assert.ok(entities.items.some((item) => item.critical_gap_count >= 1));
  });

  it('rolls up geography from declared target-group metadata', () => {
    const geography = buildGeographyRollup({
      assets,
      currentSnapshotsByAsset: snapshots,
      targetGroups: [
        {
          id: 'tg_1',
          name: 'Payments',
          environment_id: 'env_us',
          settings_json: { region_code: 'us-east', region_label: 'US East' },
        },
        {
          id: 'tg_2',
          name: 'Marketing',
          settings_json: { region_code: 'eu-west', region_label: 'EU West' },
        },
      ],
      environments: [{ id: 'env_us', name: 'US Prod', data_region: 'us-east' }],
    });

    assert.ok(geography.items.some((item) => item.region_code === 'us-east'));
    assert.ok(geography.items.some((item) => item.region_code === 'eu-west'));
  });

  it('builds tiered roadmap with recommended actions', () => {
    const roadmap = buildRiskRoadmap({
      assets,
      currentSnapshotsByAsset: snapshots,
      validationSummaryByAsset: new Map([
        ['asset_a', { validation_failed: true }],
        ['asset_b', { validation_passed: true }],
      ]),
      generatedAt: '2026-07-03T12:00:00.000Z',
    });

    assert.equal(roadmap.method, 'waf_risk_v1');
    assert.ok(roadmap.tiers.tier_1.length >= 1);
    assert.equal(roadmap.tiers.tier_1[0].waf_asset_id, 'asset_a');
    assert.ok(roadmap.tiers.tier_1[0].risk_score >= 50);
  });

  it('returns read-only vendor consolidation advisory metadata', () => {
    const advisory = buildVendorConsolidation({
      assets: [
        assets[0],
        {
          ...assets[1],
          canonical_url: 'https://api.example.com',
          id: 'asset_c',
        },
      ],
      currentSnapshotsByAsset: new Map([
        ...snapshots.entries(),
        [
          'asset_c',
          {
            waf_asset_id: 'asset_c',
            status: 'protected',
            detected_vendor: 'cloudflare',
            detected_product: 'Cloudflare WAF',
          },
        ],
      ]),
      connectors: [{ provider: 'cloudflare', status: 'active' }],
      driftEvents: [],
    });

    assert.ok(advisory.vendor_footprint.length >= 1);
    assert.ok(advisory.consolidation_opportunities[0].advisory === 'non_prescriptive');
    assert.ok(advisory.operating_cost_signals[0].advisory === 'read_only_operating_cost_signal');
  });
});