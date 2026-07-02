import { audit } from '../audit.mjs';
import { newId } from '../lib/ids.mjs';
import { getStore, persistStore } from '../store.mjs';
import { normalizeSafetyPolicy } from './safeTestPolicy.mjs';

export function listTargetGroups(ctx) {
  return getStore().targetGroups.filter((g) => g.tenant_id === ctx.tenantId);
}

export function getTargetGroup(ctx, id) {
  const g = getStore().targetGroups.find((x) => x.id === id && x.tenant_id === ctx.tenantId);
  if (!g) return null;
  const targets = getStore().targets.filter((t) => t.target_group_id === id && t.tenant_id === ctx.tenantId);
  return { ...g, targets };
}

export function createTargetGroup(ctx, body) {
  const id = newId('tg');
  const record = {
    id,
    tenant_id: ctx.tenantId,
    environment_id: body.environment_id ?? 'env_demo',
    name: body.name ?? 'New target group',
    description: body.description ?? '',
    expected_behavior_default: body.expected_behavior_default ?? 'must_block_before_origin',
    timezone: body.timezone ?? 'UTC',
    safe_test_windows: Array.isArray(body.safe_test_windows) ? body.safe_test_windows : [],
    safety_policy: normalizeSafetyPolicy(body.safety_policy),
    created_at: new Date().toISOString(),
  };
  getStore().targetGroups.push(record);
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'target_group.created',
    resource_type: 'target_group',
    resource_id: id,
  });
  persistStore();
  return record;
}

export function addTarget(ctx, groupId, body) {
  const group = getStore().targetGroups.find((g) => g.id === groupId && g.tenant_id === ctx.tenantId);
  if (!group) return null;
  const id = newId('target');
  const record = {
    id,
    tenant_id: ctx.tenantId,
    target_group_id: groupId,
    kind: body.kind ?? 'fqdn',
    value: body.value,
    expected_behavior: body.expected_behavior ?? group.expected_behavior_default,
    created_at: new Date().toISOString(),
  };
  getStore().targets.push(record);
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'target.added',
    resource_type: 'target',
    resource_id: id,
    metadata: { target_group_id: groupId },
  });
  persistStore();
  return record;
}