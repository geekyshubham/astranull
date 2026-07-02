import { createHash } from 'node:crypto';
import { getStore } from '../store.mjs';

export function computeScopeHashFromTargets(targetGroupId, targets) {
  const parts = (targets ?? [])
    .map((t) => `${t.id}:${t.kind}:${t.value}`)
    .sort();
  const payload = `${targetGroupId}|${parts.join('|')}`;
  return createHash('sha256').update(payload, 'utf8').digest('hex');
}

export function computeTargetGroupScopeHash(tenantId, targetGroupId) {
  const targets = getStore().targets.filter(
    (t) => t.tenant_id === tenantId && t.target_group_id === targetGroupId,
  );
  return computeScopeHashFromTargets(targetGroupId, targets);
}