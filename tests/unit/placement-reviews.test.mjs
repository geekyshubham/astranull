import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { computePlacementDiagnosticsFromData } from '../../src/lib/placementDiagnosticsCompute.mjs';
import {
  buildPlacementReviewsPayload,
  listPlacementReviews,
} from '../../src/services/placement.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';

describe('placement reviews API service', () => {
  it('buildPlacementReviewsPayload exposes metadata-only review rows and summary', () => {
    const diagnostics = computePlacementDiagnosticsFromData({
      tenantId: 'ten_demo',
      groups: [{ id: 'tg_1', tenant_id: 'ten_demo', name: 'Origin' }],
      agents: [],
      runs: [],
      events: [],
      nowMs: Date.parse('2026-07-03T12:00:00.000Z'),
    });
    const payload = buildPlacementReviewsPayload(diagnostics);
    assert.equal(payload.reviews.length, 1);
    assert.equal(payload.reviews[0].target_group_id, 'tg_1');
    assert.equal(payload.reviews[0].status, 'missing_agent');
    assert.equal(payload.summary.total_groups, 1);
    assert.equal(payload.computed_at, '2026-07-03T12:00:00.000Z');
    assert.deepEqual(payload.unbound_online_agent_ids, []);
  });

  it('listPlacementReviews returns all target groups for tenant', () => {
    freshStore();
    const result = listPlacementReviews({ tenantId: 'ten_demo' });
    assert.ok(Array.isArray(result.reviews));
    assert.equal(result.reviews.length, getStore().targetGroups.filter((g) => g.tenant_id === 'ten_demo').length);
    assert.ok(result.summary);
    assert.match(result.summary.summary, /Placement diagnostics:/);
  });

  it('listPlacementReviews filters by target_group_id', () => {
    freshStore();
    const result = listPlacementReviews(
      { tenantId: 'ten_demo' },
      { target_group_id: 'tg_1' },
    );
    assert.equal(result.target_group_id, 'tg_1');
    assert.equal(result.reviews.length, 1);
    assert.equal(result.reviews[0].target_group_id, 'tg_1');
    assert.equal(result.summary.total_groups, 1);
  });

  it('listPlacementReviews returns not_found for unknown target group', () => {
    freshStore();
    const result = listPlacementReviews(
      { tenantId: 'ten_demo' },
      { target_group_id: 'tg_missing' },
    );
    assert.equal(result.error, 'not_found');
    assert.equal(result.status, 404);
  });
});