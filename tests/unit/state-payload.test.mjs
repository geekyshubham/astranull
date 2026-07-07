import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  buildGetStatePayload,
  computeHighScaleStatus,
  deriveHighScaleStatus,
  resolveHighScaleStatus,
} from '../../src/lib/statePayload.mjs';

const KILL_SWITCH = { active: false, tenant_id: 'ten_demo' };

describe('state payload builder (dev-json ↔ Postgres parity)', () => {
  it('computeHighScaleStatus prefers rollup and respects wiring', () => {
    assert.equal(
      computeHighScaleStatus({
        rollupStatus: 'degraded',
        highScaleWired: true,
        highScaleRequests: [{ state: 'under_review' }],
      }),
      'degraded',
    );
    assert.equal(
      computeHighScaleStatus({ highScaleWired: true, highScaleRequests: [] }),
      'available',
    );
    assert.equal(
      computeHighScaleStatus({ highScaleWired: false, highScaleRequests: [] }),
      'postgres_high_scale_not_wired',
    );
    assert.equal(
      computeHighScaleStatus({
        highScaleWired: true,
        highScaleRequests: [{ state: 'under_review' }],
      }),
      'pending',
    );
    assert.equal(
      computeHighScaleStatus({
        highScaleWired: true,
        highScaleRequests: [{ state: 'running' }],
      }),
      'active',
    );
    assert.equal(
      computeHighScaleStatus({
        highScaleWired: true,
        killSwitch: { active: true },
        highScaleRequests: [],
      }),
      'degraded',
    );
  });

  it('deriveHighScaleStatus delegates to computeHighScaleStatus', () => {
    assert.equal(
      deriveHighScaleStatus({
        rollup: { high_scale_status: 'degraded' },
        highScaleWired: true,
      }),
      'degraded',
    );
  });

  it('buildGetStatePayload returns identical keys for rollup-backed fixtures', () => {
    const rollup = {
      readiness: { score: 57, factors: [], persistence: 'rollup' },
      target_groups: 42,
      agents_online: 3,
      recent_runs: [{ id: 'run_1' }],
      open_findings: 9,
      high_scale_requests: 2,
      high_scale_status: 'pending',
    };
    const computed = {
      readiness: { score: 99, factors: [], persistence: 'computed' },
      target_groups: 1,
      agents_online: 0,
      recent_runs: [],
      open_findings: 0,
      high_scale_requests: 0,
    };

    const payload = buildGetStatePayload({
      tenantId: 'ten_demo',
      rollup,
      computed,
      killSwitch: KILL_SWITCH,
      highScaleWired: true,
      highScaleRequests: [{ state: 'submitted' }, { state: 'closed' }],
    });

    assert.equal(payload.tenant_id, 'ten_demo');
    assert.equal(payload.readiness.score, 57);
    assert.equal(payload.target_groups, 42);
    assert.equal(payload.agents_online, 3);
    assert.deepEqual(payload.recent_runs, [{ id: 'run_1' }]);
    assert.equal(payload.open_findings, 9);
    assert.equal(payload.high_scale_requests, 2);
    assert.equal(payload.high_scale_status, 'pending');
    assert.deepEqual(payload.kill_switch, KILL_SWITCH);

    const unwired = buildGetStatePayload({
      tenantId: 'ten_demo',
      rollup: null,
      computed,
      killSwitch: KILL_SWITCH,
      highScaleWired: false,
      highScaleRequests: [],
    });
    assert.equal(unwired.high_scale_status, 'postgres_high_scale_not_wired');
    assert.equal(unwired.readiness.score, 99);

    assert.equal(
      resolveHighScaleStatus({
        rollup: { high_scale_status: 'degraded' },
        computed: { high_scale_status: 'available' },
      }),
      'degraded',
    );
  });
});