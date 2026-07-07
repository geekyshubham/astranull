import { audit } from '../audit.mjs';
import { newId } from '../lib/ids.mjs';
import { getStore, persistStore } from '../store.mjs';

const REMEDIATION_STATES = new Set([
  'open',
  'in_progress',
  'delivered',
  'accepted_risk',
  'resolved',
]);

function ensureRemediationStore() {
  const store = getStore();
  if (!Array.isArray(store.findingRemediations)) store.findingRemediations = [];
  return store;
}

function findRemediationByFinding(ctx, findingId) {
  return ensureRemediationStore().findingRemediations.find(
    (row) => row.tenant_id === ctx.tenantId && row.finding_id === findingId,
  ) ?? null;
}

function findRemediationById(ctx, remediationId) {
  return ensureRemediationStore().findingRemediations.find(
    (row) => row.id === remediationId && row.tenant_id === ctx.tenantId,
  ) ?? null;
}

function defaultRemediationFromPayload(findingId, payload = {}) {
  const steps = Array.isArray(payload.steps)
    ? payload.steps.map((step) => String(step))
    : typeof payload.steps === 'string'
      ? payload.steps.split('|').map((step) => step.trim()).filter(Boolean)
      : ['Review finding evidence', 'Apply recommended control change', 'Re-run validation'];
  return {
    action_slug: String(payload.action_slug ?? payload.action ?? 'origin_restrict'),
    owner_group: String(payload.owner_group ?? payload.owner ?? 'edge-sre'),
    description: String(payload.description ?? 'Remediation plan for linked finding.'),
    steps,
    sla_hours: payload.sla_hours ?? null,
  };
}

/**
 * @param {import('../context.mjs').TenantScope} ctx
 * @param {string} findingId
 * @param {Record<string, unknown>} remediation
 */
export function attachToFinding(ctx, findingId, remediation = {}) {
  const existing = findRemediationByFinding(ctx, findingId);
  if (existing) {
    return { remediation: existing };
  }

  const defaults = defaultRemediationFromPayload(findingId, remediation);
  const now = new Date().toISOString();
  const recordId = newId('rem');
  const auditEntry = audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'finding.remediation.attached',
    resource_type: 'finding_remediation',
    resource_id: recordId,
    metadata: { finding_id: findingId, action_slug: defaults.action_slug },
  });

  const record = {
    id: recordId,
    tenant_id: ctx.tenantId,
    finding_id: findingId,
    action_slug: defaults.action_slug,
    owner_group: defaults.owner_group,
    state: 'open',
    sla_hours: defaults.sla_hours,
    sla_deadline: defaults.sla_hours
      ? new Date(Date.now() + defaults.sla_hours * 60 * 60 * 1000).toISOString()
      : null,
    description: defaults.description,
    steps: defaults.steps,
    created_at: now,
    updated_at: now,
    delivered_at: null,
    delivered_via: null,
    delivered_ref: null,
    audit_entry_id: auditEntry.id,
  };
  ensureRemediationStore().findingRemediations.push(record);
  persistStore();
  return { remediation: record, audit_entry_id: auditEntry.id };
}

/**
 * @param {import('../context.mjs').TenantScope} ctx
 * @param {{
 *   findingId: string,
 *   actionItemId?: string,
 *   channel?: string,
 *   targetRef?: string | null,
 *   dryRun?: boolean,
 * }} input
 */
export function markFindingRemediationDelivered(ctx, input) {
  let record = findRemediationByFinding(ctx, input.findingId);
  if (!record) {
    const attached = attachToFinding(ctx, input.findingId, {
      action_slug: 'waf_action_delivery',
      owner_group: 'edge-sre',
      description: 'Auto-attached remediation for WAF action-item delivery.',
    });
    record = attached.remediation;
  }
  if (!record) return null;

  const now = new Date().toISOString();
  const channel = String(input.channel ?? 'manual').trim().toLowerCase() || 'manual';
  record.state = 'delivered';
  record.delivered_at = now;
  record.delivered_via = channel;
  record.delivered_ref = input.targetRef ?? input.actionItemId ?? null;
  record.updated_at = now;

  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'finding.remediation.delivered',
    resource_type: 'finding_remediation',
    resource_id: record.id,
    metadata: {
      finding_id: input.findingId,
      delivered_via: channel,
      delivered_ref: record.delivered_ref,
      action_item_id: input.actionItemId ?? null,
    },
  });
  persistStore();
  return record;
}

/**
 * @param {import('../context.mjs').TenantScope} ctx
 * @param {string} actionItemId
 * @param {string} channel
 * @param {string} [targetRef]
 */
export function deliver(ctx, actionItemId, channel, targetRef) {
  return {
    action_item: { action_item_id: actionItemId },
    delivery_receipt: {
      action_item_id: actionItemId,
      channel,
      target_ref: targetRef ?? null,
      status: 'delegated_to_waf_action_item_deliver',
    },
    meta: { note: 'Use POST /v1/waf/action-items/:id/deliver for delivery execution.' },
  };
}

/**
 * @param {import('../context.mjs').TenantScope} ctx
 * @param {string} remediationId
 * @param {string} state
 */
export function updateState(ctx, remediationId, state) {
  const nextState = String(state ?? '').trim();
  if (!REMEDIATION_STATES.has(nextState)) {
    return {
      error: 'invalid_state',
      status: 400,
      message: `state must be one of: ${[...REMEDIATION_STATES].join(', ')}`,
    };
  }

  const record = findRemediationById(ctx, remediationId);
  if (!record) {
    return { error: 'not_found', status: 404 };
  }

  const previous = record.state;
  record.state = nextState;
  record.updated_at = new Date().toISOString();
  if (nextState === 'delivered' && !record.delivered_at) {
    record.delivered_at = record.updated_at;
    record.delivered_via = record.delivered_via ?? 'manual';
  }

  const auditEntry = audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'finding.remediation.updated',
    resource_type: 'finding_remediation',
    resource_id: remediationId,
    metadata: { previous_state: previous, state: nextState },
  });
  persistStore();
  return { remediation: record, audit_entry_id: auditEntry.id };
}