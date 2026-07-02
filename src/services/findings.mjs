import { audit } from '../audit.mjs';
import { newId } from '../lib/ids.mjs';
import { getStore, persistStore } from '../store.mjs';
import { emitNotification } from './notifications.mjs';

export function upsertFindingFromVerdict(ctx, verdict, run, target) {
  const store = getStore();
  const existing = store.findings.find(
    (f) =>
      f.tenant_id === ctx.tenantId &&
      f.target_group_id === run.target_group_id &&
      f.target_id === target.id &&
      f.check_id === run.check_id &&
      f.status === 'open',
  );
  if (existing) {
    existing.last_verdict_id = verdict.id;
    existing.updated_at = new Date().toISOString();
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'finding.updated',
      resource_type: 'finding',
      resource_id: existing.id,
    });
    persistStore();
    return existing;
  }
  const finding = {
    id: newId('finding'),
    tenant_id: ctx.tenantId,
    target_group_id: run.target_group_id,
    target_id: target.id,
    check_id: run.check_id,
    test_run_id: run.id,
    verdict_id: verdict.id,
    title: `Finding: ${verdict.verdict} on ${target.value}`,
    severity: verdict.severity ?? 'medium',
    status: 'open',
    assignee: null,
    notes: verdict.explanation,
    evidence_ids: verdict.evidence_ids,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };
  store.findings.push(finding);
  if (['high', 'critical'].includes(finding.severity)) {
    emitNotification(ctx, {
      trigger: 'finding.high_severity',
      subject: finding.title,
      metadata: { finding_id: finding.id, severity: finding.severity },
    });
  }
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'finding.created',
    resource_type: 'finding',
    resource_id: finding.id,
  });
  persistStore();
  return finding;
}

export function listFindings(ctx) {
  return getStore().findings.filter((f) => f.tenant_id === ctx.tenantId);
}

export function getFinding(ctx, id) {
  return getStore().findings.find((f) => f.id === id && f.tenant_id === ctx.tenantId) ?? null;
}

export function patchFinding(ctx, id, body) {
  const f = getFinding(ctx, id);
  if (!f) return null;
  if (body.status) f.status = body.status;
  if (body.assignee !== undefined) f.assignee = body.assignee;
  if (body.notes !== undefined) f.notes = body.notes;
  f.updated_at = new Date().toISOString();
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'finding.updated',
    resource_type: 'finding',
    resource_id: id,
    metadata: body,
  });
  persistStore();
  return f;
}