import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';
import {
  issueChallenge,
  verifyChallenge,
} from '../../src/services/dnsOwnership.mjs';
import { freshStore } from '../helpers/reset.mjs';
import { getStore } from '../../src/store.mjs';

const ctx = { tenantId: 'ten_demo', userId: 'u1', role: 'owner' };

afterEach(() => {
  freshStore();
});

describe('dns ownership', () => {
  it('issues challenge with _astranull-challenge record on fqdn target', () => {
    freshStore();
    const result = issueChallenge(ctx, 'tg_1', 'tgt_1');
    assert.equal(result.error, undefined);
    assert.ok(result.challenge);
    assert.equal(result.challenge.state, 'pending');
    assert.equal(result.challenge.record_name, '_astranull-challenge.origin.test');
    assert.match(result.challenge.record_value, /^[A-Z2-7]+$/);
    const row = getStore().dnsChallenges.find((c) => c.id === result.challenge.id);
    assert.equal(row.record_value, result.challenge.record_value);
  });

  it('verify succeeds when TXT matches token', async () => {
    freshStore();
    const issued = issueChallenge(ctx, 'tg_1', 'tgt_1');
    const resolveTxt = async () => [[issued.challenge.record_value]];

    const result = await verifyChallenge(ctx, issued.challenge.id, { resolveTxt });
    assert.equal(result.verified, true);
    assert.equal(result.challenge.state, 'resolved');
    const verification = getStore().targetVerifications.find(
      (v) => v.source_ref?.dns_challenge_id === issued.challenge.id,
    );
    assert.equal(verification?.state, 'dns_verified');
  });

  it('verify fails when TXT does not match', async () => {
    freshStore();
    const issued = issueChallenge(ctx, 'tg_1', 'tgt_1');
    const resolveTxt = async () => [['wrong-token']];

    const result = await verifyChallenge(ctx, issued.challenge.id, { resolveTxt });
    assert.equal(result.verified, false);
    assert.equal(result.challenge.state, 'pending');
  });
});