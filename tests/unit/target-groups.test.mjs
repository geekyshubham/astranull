import assert from 'node:assert/strict';
import { beforeEach, describe, it } from 'node:test';
import {
  addTarget,
  archiveTargetGroup,
  createTargetGroup,
  deleteTarget,
  getTargetGroup,
  listTargetGroups,
  patchTarget,
  patchTargetGroup,
} from '../../src/services/targetGroups.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';

const ctx = { tenantId: 'ten_demo', userId: 'usr_1', role: 'engineer' };

describe('target group service CRUD', () => {
  beforeEach(() => {
    freshStore();
  });

  it('patches group settings and excludes archived groups from list/get', () => {
    const group = createTargetGroup(ctx, { name: 'Original' });
    const patched = patchTargetGroup(ctx, group.id, {
      name: 'Updated',
      description: 'New description',
      timezone: 'America/New_York',
    });
    assert.equal(patched.name, 'Updated');
    assert.equal(patched.description, 'New description');
    assert.equal(patched.timezone, 'America/New_York');

    const archived = archiveTargetGroup(ctx, group.id);
    assert.equal(archived.archived, true);
    assert.equal(getTargetGroup(ctx, group.id), null);
    assert.equal(listTargetGroups(ctx).some((g) => g.id === group.id), false);
  });

  it('blocks archive when an active run exists for the group', () => {
    const group = createTargetGroup(ctx, { name: 'Busy group' });
    const target = addTarget(ctx, group.id, { value: 'busy.example.com' });
    getStore().testRuns.push({
      id: 'run_active',
      tenant_id: ctx.tenantId,
      target_group_id: group.id,
      target_id: target.id,
      status: 'running',
      check_id: 'dns_authority_exposure',
    });

    const blocked = archiveTargetGroup(ctx, group.id);
    assert.equal(blocked.error, 'target_group_active_run');
    assert.equal(blocked.status, 409);
  });

  it('patches and deletes targets with active-run guard', () => {
    const group = createTargetGroup(ctx, { name: 'Targets' });
    const target = addTarget(ctx, group.id, { value: 'one.example.com' });

    const patched = patchTarget(ctx, group.id, target.id, {
      value: 'two.example.com',
      metadata: { source: 'manual' },
    });
    assert.equal(patched.value, 'two.example.com');
    assert.deepEqual(patched.metadata, { source: 'manual' });

    getStore().testRuns.push({
      id: 'run_target_active',
      tenant_id: ctx.tenantId,
      target_group_id: group.id,
      target_id: target.id,
      status: 'collecting',
      check_id: 'dns_authority_exposure',
    });
    const blocked = deleteTarget(ctx, group.id, target.id);
    assert.equal(blocked.error, 'target_active_run');
    assert.equal(blocked.status, 409);

    getStore().testRuns.pop();
    const deleted = deleteTarget(ctx, group.id, target.id);
    assert.equal(deleted.deleted, true);
    assert.equal(getTargetGroup(ctx, group.id).targets.length, 0);
  });
});