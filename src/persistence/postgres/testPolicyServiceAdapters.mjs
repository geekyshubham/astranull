import { getCheckById, isCustomerRunnable } from '../../contracts/checks.mjs';
import { newId } from '../../lib/ids.mjs';
import { redactObject } from '../../lib/redact.mjs';

const CADENCES = new Set(['manual', 'daily', 'weekly', 'monthly', 'event_driven']);
const EXPECTED_VERDICTS = new Set(['pass', 'warn', 'fail', 'manual_review']);

/** @type {readonly string[]} */
export const TEST_POLICY_REPOSITORY_METHODS = Object.freeze([
  'listTestPolicies',
  'getActiveTestPolicy',
  'createTestPolicy',
  'updateTestPolicy',
  'archiveTestPolicy',
]);

/** @type {readonly string[]} */
export const TEST_POLICY_CORE_CATALOG_REPOSITORY_METHODS = Object.freeze(['getTargetGroup']);

/** @type {readonly string[]} */
export const TEST_POLICY_AUDIT_REPOSITORY_METHODS = Object.freeze(['appendAuditEvent']);

/** @type {readonly string[]} */
export const POSTGRES_TEST_POLICY_SERVICE_METHODS = Object.freeze([
  'listTestPolicies',
  'createTestPolicy',
  'patchTestPolicy',
  'archiveTestPolicy',
]);

function normalizeCadence(value) {
  const cadence = String(value ?? 'manual').trim();
  return CADENCES.has(cadence) ? cadence : 'manual';
}

function normalizeExpectedVerdict(value) {
  const verdict = String(value ?? 'pass').trim();
  return EXPECTED_VERDICTS.has(verdict) ? verdict : 'pass';
}

function normalizeSafeWindows(value) {
  if (!Array.isArray(value)) return [];
  return value
    .filter((item) => item && typeof item === 'object' && !Array.isArray(item))
    .map((item) => ({
      day: String(item.day ?? '').trim(),
      start: String(item.start ?? '').trim(),
      end: String(item.end ?? '').trim(),
      timezone: String(item.timezone ?? 'UTC').trim() || 'UTC',
    }))
    .filter((item) => item.day && item.start && item.end)
    .slice(0, 14);
}

function publicCheck(check) {
  if (!check) return null;
  return {
    check_id: check.check_id,
    name: check.name,
    vector_family: check.vector_family,
    safety_class: check.safety_class,
    risk_class: check.risk_class,
    safety_constraints: check.safety_constraints,
    default_expected_behavior: check.default_expected_behavior,
  };
}

function assertRepositoryMethods(repo, label, methods) {
  if (!repo || typeof repo !== 'object') {
    throw new Error(`Postgres test policy service adapter requires repositories.${label}.`);
  }
  for (const method of methods) {
    if (typeof repo[method] !== 'function') {
      throw new Error(`Postgres test policy service adapter requires ${label}.${method}().`);
    }
  }
}

/**
 * @param {{
 *   testPolicies?: Record<string, unknown>,
 *   coreCatalog?: Record<string, unknown>,
 *   audit?: { appendAuditEvent?: (...args: unknown[]) => unknown },
 * }} repositories
 * @param {{ now?: () => Date }} [options]
 */
export function createPostgresTestPolicyServices(repositories, options = {}) {
  assertRepositoryMethods(repositories?.testPolicies, 'testPolicies', TEST_POLICY_REPOSITORY_METHODS);
  assertRepositoryMethods(
    repositories?.coreCatalog,
    'coreCatalog',
    TEST_POLICY_CORE_CATALOG_REPOSITORY_METHODS,
  );
  assertRepositoryMethods(repositories?.audit, 'audit', TEST_POLICY_AUDIT_REPOSITORY_METHODS);

  const testPolicies = repositories.testPolicies;
  const coreCatalog = repositories.coreCatalog;
  const audit = repositories.audit;
  const nowFn = options.now ?? (() => new Date());

  async function appendAudit(ctx, action, resourceId, metadata) {
    await audit.appendAuditEvent(
      {
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId,
        actor_role: ctx.role,
        action,
        resource_type: 'test_policy',
        resource_id: resourceId,
        metadata: metadata == null ? undefined : redactObject(metadata),
      },
      { now: nowFn() },
    );
  }

  async function loadActiveGroup(ctx, groupId, cache) {
    if (cache.has(groupId)) return cache.get(groupId);
    // getTargetGroup returns null for archived/deleted/missing groups, matching
    // the dev "active target group" filter.
    const group = await coreCatalog.getTargetGroup(ctx, groupId);
    cache.set(groupId, group);
    return group;
  }

  async function enrichPolicy(ctx, policy, cache) {
    const group = await loadActiveGroup(ctx, policy.target_group_id, cache);
    const check = getCheckById(policy.check_id);
    return {
      ...policy,
      target_group: group
        ? {
            id: group.id,
            name: group.name,
            environment_id: group.environment_id,
            expected_behavior_default: group.expected_behavior_default,
          }
        : null,
      check: publicCheck(check),
      target_count: group ? (group.targets ?? []).length : 0,
    };
  }

  return {
    async listTestPolicies(ctx) {
      const rows = await testPolicies.listTestPolicies(ctx);
      const cache = new Map();
      const enriched = [];
      for (const policy of rows) {
        const group = await loadActiveGroup(ctx, policy.target_group_id, cache);
        if (!group) continue;
        enriched.push(await enrichPolicy(ctx, policy, cache));
      }
      return enriched;
    },

    async createTestPolicy(ctx, body = {}) {
      const targetGroupId = String(body.target_group_id ?? '').trim();
      if (!targetGroupId) return { error: 'missing_target_group_id', status: 400 };
      const cache = new Map();
      const targetGroup = await loadActiveGroup(ctx, targetGroupId, cache);
      if (!targetGroup) return { error: 'target_group_not_found', status: 404 };

      const checkId = String(body.check_id ?? '').trim();
      const check = getCheckById(checkId);
      if (!check) return { error: 'unknown_check', status: 400 };
      if (!isCustomerRunnable(check)) {
        return {
          error: 'soc_gated_check',
          status: 403,
          message:
            'This check requires a SOC-governed high-scale request, not a customer-runnable policy.',
        };
      }

      const now = nowFn().toISOString();
      const record = {
        id: newId('policy'),
        tenant_id: ctx.tenantId,
        target_group_id: targetGroup.id,
        check_id: check.check_id,
        cadence: normalizeCadence(body.cadence),
        expected_verdict: normalizeExpectedVerdict(body.expected_verdict),
        safe_windows: normalizeSafeWindows(body.safe_windows),
        state: 'active',
        safety_policy_snapshot: {
          target_group_safety_policy: targetGroup.safety_policy ?? null,
          check_safety_constraints: check.safety_constraints ?? null,
          check_probe_profile: check.probe_profile ?? null,
        },
        created_at: now,
        updated_at: now,
      };
      const stored = await testPolicies.createTestPolicy(ctx, record);
      await appendAudit(ctx, 'test_policy.created', stored.id, {
        target_group_id: targetGroup.id,
        check_id: check.check_id,
      });
      return enrichPolicy(ctx, stored, cache);
    },

    async patchTestPolicy(ctx, id, body = {}) {
      const existing = await testPolicies.getActiveTestPolicy(ctx, id);
      if (!existing) return null;

      const patch = { updated_at: nowFn().toISOString() };
      if (body.cadence !== undefined) patch.cadence = normalizeCadence(body.cadence);
      if (body.expected_verdict !== undefined) {
        patch.expected_verdict = normalizeExpectedVerdict(body.expected_verdict);
      }
      if (body.safe_windows !== undefined) patch.safe_windows = normalizeSafeWindows(body.safe_windows);
      if (body.state !== undefined) {
        const state = String(body.state).trim();
        if (['active', 'paused'].includes(state)) patch.state = state;
      }

      const updated = await testPolicies.updateTestPolicy(ctx, id, patch);
      if (!updated) return null;
      await appendAudit(ctx, 'test_policy.updated', updated.id);
      return enrichPolicy(ctx, updated, new Map());
    },

    async archiveTestPolicy(ctx, id) {
      const existing = await testPolicies.getActiveTestPolicy(ctx, id);
      if (!existing) return null;
      const archived = await testPolicies.archiveTestPolicy(ctx, id, {
        now: nowFn().toISOString(),
      });
      if (!archived) return null;
      await appendAudit(ctx, 'test_policy.archived', id);
      return { archived: true, id };
    },
  };
}
