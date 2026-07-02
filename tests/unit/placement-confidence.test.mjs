import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  computePlacementConfidence,
  resolveObservationMode,
} from '../../src/services/placement.mjs';
import {
  computePlacementConfidence as pureComputePlacementConfidence,
} from '../../src/lib/placementConfidence.mjs';
import { freshStore } from '../helpers/reset.mjs';
import { getStore } from '../../src/store.mjs';

function baseRun(overrides = {}) {
  return {
    id: 'run_1',
    tenant_id: 'ten_demo',
    target_group_id: 'tg_1',
    target_id: 'tgt_1',
    check_id: 'origin.direct_bypass.safe',
    ...overrides,
  };
}

function seedBoundAgent(overrides = {}) {
  getStore().agents.push({
    id: 'ag_1',
    tenant_id: 'ten_demo',
    status: 'online',
    target_group_id: 'tg_1',
    capabilities: ['canary', 'heartbeat'],
    ...overrides,
  });
}

describe('placement confidence helper', () => {
  it('resolveObservationMode prefers event metadata then agent placement', () => {
    const agent = { placement_type: 'host', capabilities: ['heartbeat'] };
    const event = { metadata: { mode: 'canary_observation' } };
    assert.equal(resolveObservationMode(agent, event), 'canary');
    assert.equal(resolveObservationMode(agent, null), 'host');
  });

  it('resolveObservationMode returns unknown when capabilities imply multiple families', () => {
    const agent = { capabilities: ['canary', 'packet', 'heartbeat'] };
    assert.equal(resolveObservationMode(agent, null), 'unknown');
    assert.equal(resolveObservationMode(agent, { metadata: {} }), 'unknown');
  });

  it('resolveObservationMode infers mode when capabilities imply exactly one family', () => {
    const agent = { capabilities: ['canary', 'heartbeat'] };
    assert.equal(resolveObservationMode(agent, null), 'canary');
  });

  it('Medium when multiple capability families leave observation mode unknown', () => {
    freshStore();
    seedBoundAgent({ capabilities: ['canary', 'packet', 'heartbeat'] });
    const run = baseRun();
    const matchingObservation = {
      id: 'event_obs_ambiguous',
      agent_id: 'ag_1',
      signal_type: 'agent_observation',
      metadata: {},
    };
    const pc = computePlacementConfidence(getStore(), run, {
      matchingObservation,
      agentObserved: true,
      agent: getStore().agents[0],
    });
    assert.equal(pc.level, 'Medium');
    assert.equal(pc.observation_mode, 'unknown');
    assert.equal(pc.status, 'observed_this_run');
  });

  it('High when bound online agent has correlated host/sidecar/canary observation', () => {
    freshStore();
    seedBoundAgent({ placement_type: 'sidecar' });
    const run = baseRun();
    const matchingObservation = {
      id: 'event_obs_1',
      agent_id: 'ag_1',
      signal_type: 'agent_observation',
      metadata: { observation_mode: 'sidecar' },
    };
    const pc = computePlacementConfidence(getStore(), run, {
      matchingObservation,
      agentObserved: true,
      agent: getStore().agents[0],
    });
    assert.equal(pc.level, 'High');
    assert.equal(pc.status, 'observed_this_run');
    assert.equal(pc.observation_mode, 'sidecar');
    assert.equal(pc.evidence_event_id, 'event_obs_1');
    assert.equal(pc.agent_id, 'ag_1');
  });

  it('Medium when observation mode is packet mirror or log tail', () => {
    freshStore();
    seedBoundAgent({ capabilities: ['packet', 'heartbeat'] });
    const run = baseRun();
    const matchingObservation = {
      id: 'event_obs_2',
      agent_id: 'ag_1',
      metadata: { mode: 'packet_mirror' },
    };
    const pc = computePlacementConfidence(getStore(), run, {
      matchingObservation,
      agentObserved: true,
    });
    assert.equal(pc.level, 'Medium');
    assert.equal(pc.observation_mode, 'packet_mirror');
  });

  it('Low when bound online agent exists but run finalized without observation', () => {
    freshStore();
    seedBoundAgent();
    const run = baseRun();
    const pc = computePlacementConfidence(getStore(), run, {
      agentObserved: false,
      finalizedWithoutObservation: true,
      agent: getStore().agents[0],
    });
    assert.equal(pc.level, 'Low');
    assert.equal(pc.status, 'not_observed_this_run');
    assert.equal(pc.agent_id, 'ag_1');
    assert.match(pc.reason, /external probe/i);
  });

  it('Invalid when no agent is bound to the target group', () => {
    freshStore();
    getStore().agents.push({
      id: 'ag_unbound',
      tenant_id: 'ten_demo',
      status: 'online',
      target_group_id: null,
      capabilities: ['canary'],
    });
    const run = baseRun();
    const pc = computePlacementConfidence(getStore(), run, {
      agentObserved: false,
      finalizedWithoutObservation: true,
    });
    assert.equal(pc.level, 'Invalid');
    assert.equal(pc.status, 'missing_agent');
    assert.ok(pc.warnings.includes('unbound_agent_only'));
  });

  it('Invalid when observation comes from unbound online agent', () => {
    freshStore();
    getStore().agents.push({
      id: 'ag_unbound',
      tenant_id: 'ten_demo',
      status: 'online',
      target_group_id: null,
      capabilities: ['canary'],
    });
    const run = baseRun();
    const matchingObservation = {
      id: 'event_obs_3',
      agent_id: 'ag_unbound',
      metadata: { mode: 'canary' },
    };
    const pc = computePlacementConfidence(getStore(), run, {
      matchingObservation,
      agentObserved: true,
    });
    assert.equal(pc.level, 'Invalid');
    assert.equal(pc.status, 'missing_agent');
  });

  it('Invalid when bound agents are offline (misplaced_risk)', () => {
    freshStore();
    seedBoundAgent({ status: 'offline' });
    const run = baseRun();
    const pc = computePlacementConfidence(getStore(), run, {
      finalizedWithoutObservation: true,
    });
    assert.equal(pc.level, 'Invalid');
    assert.equal(pc.status, 'misplaced_risk');
    assert.ok(pc.warnings.includes('no_online_bound_agent'));
  });

  it('pure placementConfidence module matches service re-export', () => {
    freshStore();
    seedBoundAgent();
    const run = baseRun();
    const store = getStore();
    const fromService = computePlacementConfidence(store, run, { finalizedWithoutObservation: true });
    const fromPure = pureComputePlacementConfidence(store, run, { finalizedWithoutObservation: true });
    assert.deepEqual(fromPure, fromService);
  });
});