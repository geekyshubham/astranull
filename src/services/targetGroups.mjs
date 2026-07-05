import { audit } from '../audit.mjs';
import { newId } from '../lib/ids.mjs';
import { getStore, persistStore } from '../store.mjs';
import { normalizeSafetyPolicy } from './safeTestPolicy.mjs';

const ACTIVE_RUN_STATUSES = new Set(['planned', 'running', 'collecting']);

export function isArchivedTargetGroup(group) {
  return Boolean(group?.archived_at);
}

export function activeTargetGroupsForTenant(tenantId) {
  return getStore().targetGroups.filter(
    (g) => g.tenant_id === tenantId && !isArchivedTargetGroup(g),
  );
}

function activeRunForGroup(tenantId, targetGroupId) {
  return getStore().testRuns.find(
    (run) =>
      run.tenant_id === tenantId
      && run.target_group_id === targetGroupId
      && ACTIVE_RUN_STATUSES.has(run.status),
  ) ?? null;
}

function activeRunForTarget(tenantId, targetGroupId, targetId) {
  return getStore().testRuns.find(
    (run) =>
      run.tenant_id === tenantId
      && run.target_group_id === targetGroupId
      && run.target_id === targetId
      && ACTIVE_RUN_STATUSES.has(run.status),
  ) ?? null;
}

export function listTargetGroups(ctx) {
  return activeTargetGroupsForTenant(ctx.tenantId);
}

export function getTargetGroup(ctx, id) {
  const g = getStore().targetGroups.find(
    (x) => x.id === id && x.tenant_id === ctx.tenantId && !isArchivedTargetGroup(x),
  );
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
    ownership_status: 'unverified',
    validation_mode:
      body.validation_mode === 'external_only' ? 'external_only' : 'agent_assisted',
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
  const group = getStore().targetGroups.find(
    (g) => g.id === groupId && g.tenant_id === ctx.tenantId && !isArchivedTargetGroup(g),
  );
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

export function patchTargetGroup(ctx, id, body = {}) {
  const group = getStore().targetGroups.find(
    (g) => g.id === id && g.tenant_id === ctx.tenantId && !isArchivedTargetGroup(g),
  );
  if (!group) return null;

  if (body.name !== undefined) group.name = String(body.name).trim() || group.name;
  if (body.description !== undefined) group.description = String(body.description ?? '');
  if (body.environment_id !== undefined) group.environment_id = String(body.environment_id).trim();
  if (body.expected_behavior_default !== undefined) {
    group.expected_behavior_default = String(body.expected_behavior_default).trim();
  }
  if (body.timezone !== undefined) group.timezone = String(body.timezone).trim() || 'UTC';
  if (Array.isArray(body.safe_test_windows)) group.safe_test_windows = body.safe_test_windows;
  if (body.safety_policy !== undefined) group.safety_policy = normalizeSafetyPolicy(body.safety_policy);
  if (body.validation_mode !== undefined) {
    group.validation_mode =
      body.validation_mode === 'external_only' ? 'external_only' : 'agent_assisted';
  }

  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'target_group.updated',
    resource_type: 'target_group',
    resource_id: id,
  });
  persistStore();
  return group;
}

export function archiveTargetGroup(ctx, id) {
  const group = getStore().targetGroups.find(
    (g) => g.id === id && g.tenant_id === ctx.tenantId && !isArchivedTargetGroup(g),
  );
  if (!group) return null;
  if (activeRunForGroup(ctx.tenantId, id)) {
    return { error: 'target_group_active_run', status: 409 };
  }

  group.archived_at = new Date().toISOString();
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'target_group.archived',
    resource_type: 'target_group',
    resource_id: id,
  });
  persistStore();
  return { archived: true, id };
}

export function patchTarget(ctx, groupId, targetId, body = {}) {
  const group = getStore().targetGroups.find(
    (g) => g.id === groupId && g.tenant_id === ctx.tenantId && !isArchivedTargetGroup(g),
  );
  if (!group) return null;

  const target = getStore().targets.find(
    (t) => t.id === targetId && t.target_group_id === groupId && t.tenant_id === ctx.tenantId,
  );
  if (!target) return null;

  if (body.value !== undefined) target.value = String(body.value).trim();
  if (body.kind !== undefined) target.kind = String(body.kind).trim() || target.kind;
  if (body.expected_behavior !== undefined) {
    target.expected_behavior = String(body.expected_behavior).trim();
  }
  if (body.metadata !== undefined && typeof body.metadata === 'object' && !Array.isArray(body.metadata)) {
    target.metadata = body.metadata;
  }

  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'target.updated',
    resource_type: 'target',
    resource_id: targetId,
    metadata: { target_group_id: groupId },
  });
  persistStore();
  return target;
}

export function deleteTarget(ctx, groupId, targetId) {
  const group = getStore().targetGroups.find(
    (g) => g.id === groupId && g.tenant_id === ctx.tenantId && !isArchivedTargetGroup(g),
  );
  if (!group) return null;

  const index = getStore().targets.findIndex(
    (t) => t.id === targetId && t.target_group_id === groupId && t.tenant_id === ctx.tenantId,
  );
  if (index < 0) return null;
  if (activeRunForTarget(ctx.tenantId, groupId, targetId)) {
    return { error: 'target_active_run', status: 409 };
  }

  getStore().targets.splice(index, 1);
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'target.deleted',
    resource_type: 'target',
    resource_id: targetId,
    metadata: { target_group_id: groupId },
  });
  persistStore();
  return { deleted: true, id: targetId };
}
