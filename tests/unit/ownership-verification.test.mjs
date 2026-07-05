import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';
import { hashNonce } from '../../src/lib/crypto.mjs';
import {
  confirmOwnership,
  createOwnershipChallenge,
  recordOwnershipSignal,
  recordOwnershipSignalByNonce,
  verifyOwnershipSetup,
} from '../../src/services/ownershipVerification.mjs';
import { ingestEvent } from '../../src/services/events.mjs';
import { freshStore } from '../helpers/reset.mjs';
import { getStore } from '../../src/store.mjs';

const ctx = { tenantId: 'ten_demo', userId: 'u1', role: 'owner' };

afterEach(() => {
  freshStore();
});

function seedOnlineAgent(overrides = {}) {
  const store = getStore();
  if (!Array.isArray(store.ownershipVerifications)) {
    store.ownershipVerifications = [];
  }
  const agent = {
    id: 'agent_1',
    tenant_id: 'ten_demo',
    name: 'canary',
    status: 'online',
    target_group_id: 'tg_1',
    probe_endpoint: { declared_fqdn: 'origin.test' },
    last_token_validation_status: 'valid',
    ...overrides,
  };
  store.agents.push(agent);
  return agent;
}

describe('ownership verification', () => {
  it('createOwnershipChallenge succeeds and stores challenge_sent record with nonce', () => {
    freshStore();
    seedOnlineAgent();

    const result = createOwnershipChallenge(ctx, {
      target_group_id: 'tg_1',
      agent_id: 'agent_1',
    });

    assert.equal(result.error, undefined);
    assert.equal(result.verification.status, 'challenge_sent');
    assert.equal(typeof result.nonce, 'string');
    assert.ok(result.nonce.length > 0);
    assert.equal(getStore().ownershipVerifications.length, 1);
    assert.equal(
      getStore().ownershipVerifications[0].challenge_nonce_hash,
      hashNonce(result.nonce),
    );
  });

  it('rejects declared_fqdn not in target group', () => {
    freshStore();
    seedOnlineAgent({
      probe_endpoint: { declared_fqdn: 'evil.test' },
    });

    const result = createOwnershipChallenge(ctx, {
      target_group_id: 'tg_1',
      agent_id: 'agent_1',
    });

    assert.equal(result.error, 'declared_fqdn_not_in_target_group');
    assert.equal(result.status, 400);
  });

  it('rejects agent with invalid token', () => {
    freshStore();
    seedOnlineAgent({ last_token_validation_status: 'invalid' });

    const result = createOwnershipChallenge(ctx, {
      target_group_id: 'tg_1',
      agent_id: 'agent_1',
    });

    assert.equal(result.error, 'agent_token_invalid');
    assert.equal(result.status, 409);
  });

  it('rejects agent not bound to target group', () => {
    freshStore();
    seedOnlineAgent({ target_group_id: 'tg_other' });

    const result = createOwnershipChallenge(ctx, {
      target_group_id: 'tg_1',
      agent_id: 'agent_1',
    });

    assert.equal(result.error, 'agent_not_bound_to_target_group');
    assert.equal(result.status, 400);
  });

  it('recordOwnershipSignal verifies after probe and agent with matching nonce', () => {
    freshStore();
    seedOnlineAgent();

    const created = createOwnershipChallenge(ctx, {
      target_group_id: 'tg_1',
      agent_id: 'agent_1',
    });
    const id = created.verification.id;
    const nonceHash = hashNonce(created.nonce);

    const probe = recordOwnershipSignal(ctx, id, { source: 'probe', nonce_hash: nonceHash });
    assert.equal(probe.verification.probe_observed, true);
    assert.equal(probe.verification.status, 'challenge_sent');

    const agent = recordOwnershipSignal(ctx, id, { source: 'agent', nonce_hash: nonceHash });
    assert.equal(agent.verification.agent_observed, true);
    assert.equal(agent.verification.status, 'verified');
    assert.ok(agent.verification.verified_at);

    const group = getStore().targetGroups.find((g) => g.id === 'tg_1');
    assert.equal(group.ownership_status, 'agent_verified');
  });

  it('recordOwnershipSignal rejects wrong nonce_hash', () => {
    freshStore();
    seedOnlineAgent();

    const created = createOwnershipChallenge(ctx, {
      target_group_id: 'tg_1',
      agent_id: 'agent_1',
    });

    const result = recordOwnershipSignal(ctx, created.verification.id, {
      source: 'probe',
      nonce_hash: 'sha256:deadbeef',
    });

    assert.equal(result.error, 'nonce_mismatch');
    assert.equal(result.status, 400);
  });

  it('confirmOwnership after verified sets user confirmation and target group status', () => {
    freshStore();
    seedOnlineAgent();

    const created = createOwnershipChallenge(ctx, {
      target_group_id: 'tg_1',
      agent_id: 'agent_1',
    });
    const nonceHash = hashNonce(created.nonce);
    recordOwnershipSignal(ctx, created.verification.id, { source: 'probe', nonce_hash: nonceHash });
    recordOwnershipSignal(ctx, created.verification.id, { source: 'agent', nonce_hash: nonceHash });

    const confirmed = confirmOwnership(ctx, created.verification.id);
    assert.equal(confirmed.verification.confirmed_by_user_id, 'u1');
    assert.ok(confirmed.verification.confirmed_at);

    const group = getStore().targetGroups.find((g) => g.id === 'tg_1');
    assert.equal(group.ownership_status, 'user_confirmed');
  });

  it('ingestEvent ownership_observation verifies after probe signal via nonce correlation', () => {
    freshStore();
    seedOnlineAgent();

    const created = createOwnershipChallenge(ctx, {
      target_group_id: 'tg_1',
      agent_id: 'agent_1',
    });
    const nonceHash = created.verification.challenge_nonce_hash;

    const probe = recordOwnershipSignalByNonce(
      { tenantId: ctx.tenantId },
      { source: 'probe', nonce_hash: nonceHash },
    );
    assert.equal(probe.verification.probe_observed, true);
    assert.equal(probe.verification.status, 'challenge_sent');

    const ingested = ingestEvent(ctx, {
      event_id: 'e-own-1',
      signal_type: 'ownership_observation',
      nonce_hash: nonceHash,
    });
    assert.equal(ingested.error, undefined);

    const verification = getStore().ownershipVerifications.find(
      (v) => v.id === created.verification.id,
    );
    assert.equal(verification.status, 'verified');
    assert.ok(verification.verified_at);
    assert.equal(verification.agent_observed, true);

    const group = getStore().targetGroups.find((g) => g.id === 'tg_1');
    assert.equal(group.ownership_status, 'agent_verified');
  });

  it('confirmOwnership rejects before verified', () => {
    freshStore();
    seedOnlineAgent();

    const created = createOwnershipChallenge(ctx, {
      target_group_id: 'tg_1',
      agent_id: 'agent_1',
    });

    const result = confirmOwnership(ctx, created.verification.id);
    assert.equal(result.error, 'ownership_not_verified');
    assert.equal(result.status, 409);
  });

  it('verifyOwnershipSetup returns ready for a valid setup without persisting', () => {
    freshStore();
    seedOnlineAgent();

    const result = verifyOwnershipSetup(ctx, {
      target_group_id: 'tg_1',
      agent_id: 'agent_1',
    });

    assert.equal(result.dry_run, true);
    assert.equal(result.ready, true);
    assert.equal(result.target_group_id, 'tg_1');
    assert.equal(result.agent_id, 'agent_1');
    assert.equal(result.declared_fqdn, 'origin.test');
    assert.deepEqual(result.checks, {
      agent_online: true,
      agent_bound: true,
      token_valid: true,
      fqdn_declared: true,
    });
    assert.equal(getStore().ownershipVerifications.length, 0);
    const audit = getStore().auditLog.find(
      (e) => e.action === 'ownership_verification.setup_verified',
    );
    assert.ok(audit);
  });

  it('verifyOwnershipSetup returns agent_not_online when agent is offline', () => {
    freshStore();
    seedOnlineAgent({ status: 'offline' });

    const result = verifyOwnershipSetup(ctx, {
      target_group_id: 'tg_1',
      agent_id: 'agent_1',
    });

    assert.equal(result.dry_run, true);
    assert.equal(result.ready, false);
    assert.equal(result.error, 'agent_not_online');
    assert.equal(result.status, 409);
  });

  it('verifyOwnershipSetup returns target_group_not_found for missing group', () => {
    freshStore();
    seedOnlineAgent();

    const result = verifyOwnershipSetup(ctx, {
      target_group_id: 'tg_missing',
      agent_id: 'agent_1',
    });

    assert.equal(result.dry_run, true);
    assert.equal(result.ready, false);
    assert.equal(result.error, 'target_group_not_found');
    assert.equal(result.status, 404);
  });
});