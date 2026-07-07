import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';
import { CHECK_CATALOG } from '../../src/contracts/checks.mjs';
import { getStore } from '../../src/store.mjs';
import { getTargetDetail } from '../../src/services/targetDetail.mjs';
import { freshStore } from '../helpers/reset.mjs';

const ctx = { tenantId: 'ten_demo', userId: 'usr_admin', role: 'admin' };

describe('check enable/disable lifecycle (FT-CRUD-CHK-01)', () => {
  afterEach(() => freshStore());

  it('enabling and disabling checks updates checks_applied on target detail', async () => {
    freshStore();
    const store = getStore();
    store.checkCatalog = CHECK_CATALOG.map((check) => ({
      ...check,
      id: check.check_id,
      default_enabled: false,
      enabled_groups: [],
    }));

    const checkId = 'dns.authoritative_response.safe';
    const before = await getTargetDetail(ctx, 'tgt_1');
    assert.equal(before.error, undefined);
    assert.equal(before.checks_applied.length, 0);

    const catalog = store.checkCatalog.find((check) => check.check_id === checkId);
    catalog.enabled_groups = ['tg_1'];
    const enabled = await getTargetDetail(ctx, 'tgt_1');
    assert.ok(enabled.checks_applied.some((row) => row.check_id === checkId));

    catalog.enabled_groups = [];
    const disabled = await getTargetDetail(ctx, 'tgt_1');
    assert.equal(disabled.checks_applied.length, 0);
  });
});