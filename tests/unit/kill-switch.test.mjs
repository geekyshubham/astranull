import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { setKillSwitch } from '../../src/services/highScale.mjs';
import { isKillSwitchActiveForTenant } from '../../src/services/killSwitchState.mjs';
import { startTestRun } from '../../src/services/testRuns.mjs';
import { getStore } from '../../src/store.mjs';
import { freshStore } from '../helpers/reset.mjs';

const demoCtx = { tenantId: 'ten_demo', userId: 'u1', role: 'soc' };
const otherCtx = { tenantId: 'ten_other', userId: 'u2', role: 'soc' };

function seedAgent(tenantId = 'ten_demo') {
  getStore().agents.push({
    id: `ag_${tenantId}`,
    tenant_id: tenantId,
    status: 'online',
    capabilities: ['canary', 'packet', 'heartbeat'],
    target_group_id: 'tg_1',
  });
}

function seedOtherTenant() {
  getStore().tenants.push({ id: 'ten_other', name: 'Other' });
  getStore().targetGroups.push({
    id: 'tg_other',
    tenant_id: 'ten_other',
    environment_id: 'env_demo',
    name: 'Other TG',
    expected_behavior_default: 'must_block_before_origin',
  });
  getStore().targets.push({
    id: 'tgt_other',
    tenant_id: 'ten_other',
    target_group_id: 'tg_other',
    kind: 'fqdn',
    value: 'other.test',
    expected_behavior: 'must_block_before_origin',
  });
}

describe('SOC kill switch — safe runs', () => {
  it('activating kill switch cancels active safe runs and returns cancelled_run_ids', () => {
    freshStore();
    seedAgent();
    const started = startTestRun(demoCtx, {
      check_id: 'origin.direct_bypass.safe',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
    });
    assert.ok(started.run);
    assert.equal(started.run.status, 'collecting');

    const ks = setKillSwitch(demoCtx, true, 'incident');
    assert.ok(ks.cancelled_run_ids.includes(started.run.id));
    const run = getStore().testRuns.find((r) => r.id === started.run.id);
    assert.equal(run.status, 'cancelled');
    assert.equal(run.cancelled_by_kill_switch, true);
    assert.ok(run.completed_at);
    assert.ok(
      getStore().auditLog.some(
        (a) => a.action === 'test_run.kill_switch_auto_cancel' && a.resource_id === started.run.id,
      ),
    );
  });

  it('blocks new safe run starts while kill switch is active for tenant', () => {
    freshStore();
    seedAgent();
    setKillSwitch(demoCtx, true, 'hold');
    const blocked = startTestRun(
      { tenantId: 'ten_demo', userId: 'eng', role: 'engineer' },
      {
        check_id: 'origin.direct_bypass.safe',
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
      },
    );
    assert.equal(blocked.error, 'kill_switch_active');
    assert.equal(blocked.status, 423);
    assert.ok(getStore().auditLog.some((a) => a.action === 'test_run.kill_switch_denied'));
  });

  it('clearing kill switch permits safe starts again', () => {
    freshStore();
    seedAgent();
    setKillSwitch(demoCtx, true, 'hold');
    setKillSwitch(demoCtx, false, 'cleared');
    const started = startTestRun(
      { tenantId: 'ten_demo', userId: 'eng', role: 'engineer' },
      {
        check_id: 'origin.direct_bypass.safe',
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
      },
    );
    assert.ok(started.run);
    assert.equal(isKillSwitchActiveForTenant('ten_demo'), false);
  });

  it('tenant-scoped kill switch does not block other tenants', () => {
    freshStore();
    seedAgent();
    seedOtherTenant();
    seedAgent('ten_other');
    getStore().socKillSwitch = {
      active: true,
      tenant_id: 'ten_other',
      reason: 'other tenant only',
      updated_at: new Date().toISOString(),
    };
    assert.equal(isKillSwitchActiveForTenant('ten_other'), true);
    assert.equal(isKillSwitchActiveForTenant('ten_demo'), false);

    const demoStart = startTestRun(
      { tenantId: 'ten_demo', userId: 'eng', role: 'engineer' },
      {
        check_id: 'origin.direct_bypass.safe',
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
      },
    );
    assert.ok(demoStart.run);

    const otherBlocked = startTestRun(otherCtx, {
      check_id: 'origin.direct_bypass.safe',
      target_group_id: 'tg_other',
      target_id: 'tgt_other',
    });
    assert.equal(otherBlocked.error, 'kill_switch_active');
  });

  it('legacy global active kill switch without tenant_id blocks all tenants', () => {
    freshStore();
    seedAgent();
    getStore().socKillSwitch = { active: true, reason: 'global', updated_at: new Date().toISOString() };
    assert.equal(isKillSwitchActiveForTenant('ten_demo'), true);
    const blocked = startTestRun(
      { tenantId: 'ten_demo', userId: 'eng', role: 'engineer' },
      {
        check_id: 'origin.direct_bypass.safe',
        target_group_id: 'tg_1',
        target_id: 'tgt_1',
      },
    );
    assert.equal(blocked.error, 'kill_switch_active');
  });

  it('does not cancel verdicted or already cancelled runs on activation', () => {
    freshStore();
    seedAgent();
    const started = startTestRun(demoCtx, {
      check_id: 'origin.direct_bypass.safe',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
    });
    const run = getStore().testRuns.find((r) => r.id === started.run.id);
    run.status = 'verdicted';
    run.completed_at = new Date().toISOString();

    getStore().testRuns.push({
      id: 'run_cancelled',
      tenant_id: 'ten_demo',
      target_group_id: 'tg_1',
      target_id: 'tgt_1',
      check_id: 'origin.direct_bypass.safe',
      status: 'cancelled',
      created_at: new Date().toISOString(),
    });

    const ks = setKillSwitch(demoCtx, true, 'noop');
    assert.deepEqual(ks.cancelled_run_ids, []);
    assert.equal(run.status, 'verdicted');
  });
});