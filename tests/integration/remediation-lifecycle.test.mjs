import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';
import { getStore } from '../../src/store.mjs';
import { attachToFinding, updateState } from '../../src/services/remediation.mjs';
import { freshStore } from '../helpers/reset.mjs';

const ctx = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };

describe('finding remediation lifecycle (FT-CRUD-REM-01)', () => {
  afterEach(() => freshStore());

  it('attach → state transitions open→in_progress→delivered→resolved with audit', () => {
    freshStore();
    const findingId = 'fnd_rem_lifecycle';
    getStore().findings.push({
      id: findingId,
      tenant_id: ctx.tenantId,
      target_group_id: 'tg_1',
      title: 'Remediation lifecycle finding',
      state: 'open',
    });

    const attached = attachToFinding(ctx, findingId, {
      action_slug: 'origin_restrict',
      owner_group: 'edge-sre',
      description: 'Restrict origin access',
      steps: ['Block origin', 'Validate WAF'],
    });
    assert.equal(attached.remediation.state, 'open');

    const inProgress = updateState(ctx, attached.remediation.id, 'in_progress');
    assert.equal(inProgress.remediation.state, 'in_progress');

    const delivered = updateState(ctx, attached.remediation.id, 'delivered');
    assert.equal(delivered.remediation.state, 'delivered');
    assert.ok(delivered.remediation.delivered_at);

    const resolved = updateState(ctx, attached.remediation.id, 'resolved');
    assert.equal(resolved.remediation.state, 'resolved');

    const audits = getStore().auditLog.filter(
      (entry) => entry.resource_id === attached.remediation.id,
    );
    assert.ok(audits.some((entry) => entry.action === 'finding.remediation.attached'));
    assert.ok(audits.filter((entry) => entry.action === 'finding.remediation.updated').length >= 3);
  });
});