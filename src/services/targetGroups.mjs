import { audit } from '../audit.mjs';
import { newId } from '../lib/ids.mjs';
import { getStore, persistStore } from '../store.mjs';
import { normalizeSafetyPolicy } from './safeTestPolicy.mjs';

const ACTIVE_RUN_STATUSES = new Set(['planned', 'running', 'collecting']);

export function isArchivedTargetGroup(group) {
  return Boolean(group?.deleted_at ?? group?.archived_at);
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

export function listTargetGroups(ctx, options = {}) {
  const includeArchived = options.archived === true;
  const groups = getStore().targetGroups.filter((g) => g.tenant_id === ctx.tenantId);
  if (includeArchived) {
    return groups.filter((g) => isArchivedTargetGroup(g));
  }
  return groups.filter((g) => !isArchivedTargetGroup(g));
}

export function listTargetGroupsEnvelope(ctx, options = {}) {
  const items = listTargetGroups(ctx, options);
  return {
    items,
    count: items.length,
    meta: {
      empty_reason: items.length
        ? null
        : options.archived
          ? 'No archived target groups match this tenant.'
          : 'No target groups have been declared for this tenant yet.',
    },
  };
}

export function getTargetGroup(ctx, id) {
  const g = getStore().targetGroups.find(
    (x) => x.id === id && x.tenant_id === ctx.tenantId && !isArchivedTargetGroup(x),
  );
  if (!g) return null;
  const targets = getStore().targets
    .filter((t) => t.target_group_id === id && t.tenant_id === ctx.tenantId)
    .map((target) => ({
      ...target,
      verification_state: target.verification_state ?? target.verify_state ?? 'unverified',
    }));
  const runsRecent = (getStore().testRuns ?? [])
    .filter((run) => run.tenant_id === ctx.tenantId && run.target_group_id === id)
    .sort((a, b) => String(b.started_at ?? b.created_at).localeCompare(String(a.started_at ?? a.created_at)))
    .slice(0, 6)
    .map((run) => ({
      id: run.id,
      policy_id: run.policy_id ?? run.test_policy_id ?? null,
      check_count: run.check_count ?? run.check_id ?? null,
      verdict: run.verdict ?? run.status ?? 'pending',
      started_at: run.started_at ?? run.created_at,
      agent_id: run.agent_id ?? null,
    }));
  const findingsOnGroup = (getStore().findings ?? [])
    .filter((finding) => finding.tenant_id === ctx.tenantId && finding.target_group_id === id)
    .map((finding) => ({
      id: finding.id,
      target_id: finding.target_id ?? null,
      title: finding.title,
      severity: finding.severity,
      status: finding.status ?? finding.state ?? 'open',
    }));
  const loa = (getStore().loaSignatures ?? []).find(
    (row) => row.tenant_id === ctx.tenantId && row.target_group_id === id && row.state === 'signed',
  );
  return {
    ...g,
    targets,
    target_count: targets.length,
    runs_recent: runsRecent,
    findings_on_group: findingsOnGroup,
    loa: loa
      ? {
          state: loa.state,
          signer_name: loa.signer_name,
          signed_at: loa.signed_at,
          custody_digest_sha256: loa.custody_digest_sha256,
        }
      : g.loa ?? null,
    loa_state: loa?.state ?? g.loa_state ?? 'required',
    meta: {
      targets_empty_reason: targets.length
        ? null
        : 'No targets have been declared for this group yet.',
      runs_empty_reason: runsRecent.length
        ? null
        : 'No test runs have been recorded for this target group yet.',
      findings_empty_reason: findingsOnGroup.length
        ? null
        : 'No findings are published for this target group yet.',
    },
  };
}

export function createTargetGroup(ctx, body) {
  const id = newId('tg');
  const record = {
    id,
    tenant_id: ctx.tenantId,
    environment_id: body.environment_id ?? 'env_demo',
    name: body.name ?? 'New target group',
    description: body.description ?? '',
    expected_behavior_default: body.expected_behavior_default ?? null,
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
    expected_behavior: body.expected_behavior ?? null,
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

  const now = new Date().toISOString();
  group.deleted_at = now;
  group.deleted_by = ctx.userId;
  group.archived_at = now;
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'target_group.archived',
    resource_type: 'target_group',
    resource_id: id,
    metadata: { deleted_at: now, deleted_by: ctx.userId },
  });
  persistStore();
  return { archived: true, id, deleted_at: now, deleted_by: ctx.userId };
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

/**
 * Restores an archived target group (portal revamp §3.8).
 *
 * @param {import('../context.mjs').TenantScope} ctx
 * @param {string} groupId
 */
export function restoreArchived(ctx, groupId) {
  const group = getStore().targetGroups.find(
    (g) => g.id === groupId && g.tenant_id === ctx.tenantId,
  );
  if (!group) {
    return { error: 'not_found', status: 404 };
  }
  if (!isArchivedTargetGroup(group)) {
    return { error: 'not_archived', status: 404 };
  }

  delete group.deleted_at;
  delete group.deleted_by;
  delete group.archived_at;

  const auditEntry = audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'target_group.restored',
    resource_type: 'target_group',
    resource_id: groupId,
  });
  persistStore();
  return { target_group: group, audit_entry_id: auditEntry.id };
}

/**
 * Bulk import targets from connector inventory (portal revamp §3.5).
 *
 * @param {import('../context.mjs').TenantScope} ctx
 * @param {string} groupId
 * @param {{ source?: string, items?: unknown[] }} _body
 */
export function bulkImportTargets(ctx, groupId, body = {}) {
  const group = getStore().targetGroups.find(
    (g) => g.id === groupId && g.tenant_id === ctx.tenantId && !isArchivedTargetGroup(g),
  );
  if (!group) {
    return { error: 'target_group_not_found', status: 404 };
  }

  const source = String(body.source ?? 'connector').trim();
  const items = Array.isArray(body.items) ? body.items : [];
  const imported = [];
  const skipped = [];

  for (const item of items) {
    const kind = String(item.kind ?? 'fqdn').trim().toLowerCase();
    const value = String(item.value ?? '').trim();
    if (!value) {
      skipped.push({ value: '', reason: 'missing_value' });
      continue;
    }
    const existing = getStore().targets.find(
      (t) =>
        t.tenant_id === ctx.tenantId
        && t.target_group_id === groupId
        && t.kind === kind
        && String(t.value).trim().toLowerCase() === value.toLowerCase(),
    );
    if (existing) {
      skipped.push({ value, reason: 'already_imported' });
      continue;
    }

    const verify_state = kind === 'fqdn' ? 'pending' : 'awaiting_heartbeat';
    const target = {
      id: newId('target'),
      tenant_id: ctx.tenantId,
      target_group_id: groupId,
      kind,
      value,
      expected_behavior: item.expected_behavior ?? null,
      verify_state,
      import_source: source,
      created_at: new Date().toISOString(),
    };
    getStore().targets.push(target);
    if (!getStore().targetVerifications) getStore().targetVerifications = [];
    getStore().targetVerifications.push({
      id: newId('tv'),
      tenant_id: ctx.tenantId,
      target_id: target.id,
      state: verify_state === 'pending' ? 'pending' : 'unverified',
      source_kind: 'manual_override',
      source_ref: { source, bulk_import: true },
      transitioned_at: target.created_at,
      transitioned_by: ctx.userId ?? 'system',
      audit_entry_id: audit({
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId,
        actor_role: ctx.role,
        action: 'target.bulk_imported',
        resource_type: 'target',
        resource_id: target.id,
        metadata: { target_group_id: groupId, source },
      }).id,
    });
    imported.push(target);
  }

  if (imported.length) persistStore();
  return { imported, skipped, count: imported.length };
}
