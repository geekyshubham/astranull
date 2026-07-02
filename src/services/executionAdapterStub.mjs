/**
 * SOC execution adapter boundary — dry-run metadata only; never generates traffic.
 */

import { audit } from '../audit.mjs';
import { getStore, persistStore } from '../store.mjs';
import { isKillSwitchActiveForTenant } from './killSwitchState.mjs';

function isWithinWindow(window) {
  if (!window?.window_start || !window?.window_end) return false;
  const now = Date.now();
  return now >= new Date(window.window_start).getTime() && now <= new Date(window.window_end).getTime();
}

function getRequest(tenantId, requestId) {
  return getStore().highScaleRequests.find((r) => r.id === requestId && r.tenant_id === tenantId) ?? null;
}

function gate(ctx, requestId, { requireRunning = false, allowKillSwitch = false } = {}) {
  const req = getRequest(ctx.tenantId, requestId);
  if (!req) return { error: 'not_found', status: 404 };
  if (!req.scope_hash) return { error: 'missing_scope_hash', status: 409 };
  if (!allowKillSwitch && isKillSwitchActiveForTenant(ctx.tenantId)) {
    return { error: 'kill_switch_active', status: 409 };
  }
  if (requireRunning && req.state !== 'running') {
    return { error: 'not_running', status: 409, request: req };
  }
  if (!['approved', 'scheduled', 'running', 'stopped'].includes(req.state) && !requireRunning) {
    if (!['scheduled', 'running'].includes(req.state)) {
      return { error: 'invalid_state', status: 409, request: req };
    }
  }
  return { request: req };
}

export function dryRun(ctx, requestId, metadata = {}) {
  const g = gate(ctx, requestId);
  if (g.error) return g;
  const req = g.request;
  if (!isWithinWindow(req.scheduled_window)) {
    return { error: 'outside_schedule_window', status: 409 };
  }
  return {
    mode: 'dry_run',
    request_id: requestId,
    scope_hash: req.scope_hash,
    note: 'Governed dry-run adapter — no traffic generated.',
    metadata,
  };
}

export function start(ctx, requestId, metadata = {}) {
  const g = gate(ctx, requestId);
  if (g.error) return g;
  const req = g.request;
  if (req.state !== 'scheduled' && req.state !== 'running') {
    return { error: 'invalid_state', status: 409 };
  }
  if (!isWithinWindow(req.scheduled_window)) {
    return { error: 'outside_schedule_window', status: 409 };
  }
  if (metadata.scope_hash && metadata.scope_hash !== req.scope_hash) {
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'high_scale.scope_hash_rejected',
      resource_type: 'high_scale_request',
      resource_id: requestId,
    });
    persistStore();
    return { error: 'scope_hash_mismatch', status: 409 };
  }
  req.adapter = {
    status: 'stub_running',
    started_at: new Date().toISOString(),
    traffic_generated: false,
    last_action: 'start',
  };
  persistStore();
  return {
    mode: 'adapter_stub',
    request_id: requestId,
    traffic_generated: false,
    note: 'SOC governed dry-run adapter start — governed boundary only.',
  };
}

export function stop(ctx, requestId, reason) {
  const g = gate(ctx, requestId, { requireRunning: true, allowKillSwitch: true });
  if (g.error) return g;
  const req = g.request;
  req.adapter = {
    ...(req.adapter ?? {}),
    status: 'stub_stopped',
    stopped_at: new Date().toISOString(),
    stop_reason: reason ?? null,
    traffic_generated: false,
    last_action: 'stop',
  };
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'high_scale.adapter_stub_stopped',
    resource_type: 'high_scale_request',
    resource_id: requestId,
    metadata: { reason },
  });
  persistStore();
  return { mode: 'adapter_stub', request_id: requestId, stopped: true };
}

export function status(ctx, requestId) {
  const req = getRequest(ctx.tenantId, requestId);
  if (!req) return null;
  return {
    request_id: requestId,
    state: req.state,
    scope_hash: req.scope_hash,
    adapter: req.adapter ?? { status: 'idle', traffic_generated: false },
    kill_switch: isKillSwitchActiveForTenant(ctx.tenantId),
  };
}

export function metrics(ctx, requestId) {
  const req = getRequest(ctx.tenantId, requestId);
  if (!req) return null;
  return {
    request_id: requestId,
    simulated_rps: 0,
    simulated_packets: 0,
    traffic_generated: false,
    note: 'Governed dry-run adapter metrics — no live traffic.',
  };
}

export function evidenceExport(ctx, requestId) {
  const req = getRequest(ctx.tenantId, requestId);
  if (!req) return null;
  const notes = (getStore().socNotes ?? []).filter(
    (n) => n.high_scale_request_id === requestId && n.tenant_id === ctx.tenantId,
  );
  return {
    request_id: requestId,
    state: req.state,
    scope_hash: req.scope_hash,
    artifacts: (req.artifacts ?? []).map((a) => ({
      id: a.id,
      type: a.type,
      status: a.status,
      reference_uri: a.reference_uri_redacted,
    })),
    soc_notes: notes.map((n) => ({ id: n.id, body: n.body, at: n.created_at })),
    traffic_generated: false,
  };
}