import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';
import {
  createTargetGroup,
  patchTargetGroup,
} from '../../src/services/targetGroups.mjs';
import { freshStore } from '../helpers/reset.mjs';

const ctx = { tenantId: 'ten_demo', userId: 'u1', role: 'owner' };

afterEach(() => {
  freshStore();
});

describe('target group validation_mode', () => {
  it('defaults to agent_assisted on create', () => {
    freshStore();
    const g = createTargetGroup(ctx, { name: 'Default mode' });
    assert.equal(g.validation_mode, 'agent_assisted');
  });

  it('persists external_only on create', () => {
    freshStore();
    const g = createTargetGroup(ctx, {
      name: 'External',
      validation_mode: 'external_only',
    });
    assert.equal(g.validation_mode, 'external_only');
  });

  it('patch toggles validation_mode', () => {
    freshStore();
    const g = createTargetGroup(ctx, { name: 'Toggle' });
    assert.equal(g.validation_mode, 'agent_assisted');

    const patched = patchTargetGroup(ctx, g.id, { validation_mode: 'external_only' });
    assert.equal(patched.validation_mode, 'external_only');

    const back = patchTargetGroup(ctx, g.id, { validation_mode: 'anything_else' });
    assert.equal(back.validation_mode, 'agent_assisted');
  });
});