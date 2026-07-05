import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';
import {
  issueDnsOwnershipChallenge,
  verifyDnsOwnership,
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
    const result = issueDnsOwnershipChallenge(ctx, { target_group_id: 'tg_1' });
    assert.equal(result.error, undefined);
    assert.equal(result.status, 'pending');
    assert.equal(result.record_name, '_astranull-challenge.origin.test');
    const group = getStore().targetGroups.find((g) => g.id === 'tg_1');
    assert.equal(group.dns_ownership.record_value, result.record_value);
    assert.equal(group.dns_ownership.status, 'pending');
  });

  it('verify succeeds when TXT matches token', async () => {
    freshStore();
    const issued = issueDnsOwnershipChallenge(ctx, { target_group_id: 'tg_1' });
    const resolveTxt = async () => [[issued.record_value]];

    const result = await verifyDnsOwnership(
      ctx,
      { target_group_id: 'tg_1' },
      { resolveTxt },
    );
    assert.equal(result.status, 'verified');
    assert.equal(result.ownership_status, 'dns_verified');
    const group = getStore().targetGroups.find((g) => g.id === 'tg_1');
    assert.equal(group.ownership_status, 'dns_verified');
  });

  it('verify fails when TXT does not match', async () => {
    freshStore();
    issueDnsOwnershipChallenge(ctx, { target_group_id: 'tg_1' });
    const resolveTxt = async () => [['wrong-token']];

    const result = await verifyDnsOwnership(
      ctx,
      { target_group_id: 'tg_1' },
      { resolveTxt },
    );
    assert.equal(result.status, 'failed');
    assert.notEqual(result.ownership_status, 'dns_verified');
  });
});