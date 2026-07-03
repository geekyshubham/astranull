import { audit } from '../audit.mjs';
import {
  buildAuthorizationArtifactLedgerEntry,
  ensureAuthorizationArtifactLedger,
  validateArtifactUploadBody,
} from '../lib/authorizationArtifactLedger.mjs';
import { normalizeGovernedAdapterTelemetryIngest } from '../lib/governedAdapterTelemetry.mjs';
import { computeTargetGroupScopeHash } from '../lib/scopeHash.mjs';
import { newId } from '../lib/ids.mjs';
import { redactObject, redactString } from '../lib/redact.mjs';
import { incMetric } from '../lib/metrics.mjs';
import { getStore, persistStore } from '../store.mjs';
import * as adapterStub from './executionAdapterStub.mjs';
import { isKillSwitchActiveForTenant } from './killSwitchState.mjs';
import { emitNotification } from './notifications.mjs';
import { autoCancelActiveSafeRunsForKillSwitch } from './testRuns.mjs';
import {
  STATES,
  REQUIRED_ARTIFACT_TYPES,
  TELEMETRY_ACTIVE_STATES,
  TELEMETRY_CATEGORIES,
  TELEMETRY_LIVE_STATUSES,
  authorizationPackComplete,
  authorizationPackIncompleteResponse,
  bodySummaryFields,
  buildArtifactFromUpload,
  buildAuthorizationRequirementStatuses,
  buildProviderApprovalChecklist,
  buildTimeline,
  distinctSocApprovalCount,
  evaluateHighScaleAdapterStartGate,
  isWithinScheduledWindow,
  parseObservedAt,
  refreshAuthorizationPackStatus,
  storeOptionalHighScaleFields,
  summarizeAdapter,
  summarizeArtifacts,
  summarizeSocNotes,
  summarizeTelemetryForReport,
  syncChecklistFromProviderArtifact,
  syncChecklistFromProviderArtifactReview,
  telemetryObjectContainsForbiddenKeys,
  validateHighScaleIntakeFields,
} from '../lib/highScalePolicy.mjs';

export { STATES, REQUIRED_ARTIFACT_TYPES, buildAuthorizationRequirementStatuses, refreshAuthorizationPackStatus, buildProviderApprovalChecklist };

function ensureNotes() {
  const store = getStore();
  if (!store.socNotes) store.socNotes = [];
  return store.socNotes;
}

function ensureSocReports() {
  const store = getStore();
  if (!store.socReports) store.socReports = [];
  return store.socReports;
}

function ensureHighScaleTelemetry() {
  const store = getStore();
  if (!store.highScaleTelemetry) store.highScaleTelemetry = [];
  return store.highScaleTelemetry;
}

export function summarizeTelemetryForReportFromStore(tenantId, requestId) {
  const items = ensureHighScaleTelemetry().filter(
    (t) => t.tenant_id === tenantId && t.high_scale_request_id === requestId,
  );
  return summarizeTelemetryForReport(items);
}

function findSocReport(tenantId, requestId) {
  return (
    ensureSocReports().find((r) => r.tenant_id === tenantId && r.high_scale_request_id === requestId) ?? null
  );
}

export function upsertPostTestReport(ctx, requestId, body) {
  const req = getHighScaleRequest(ctx.tenantId, requestId);
  if (!req) return null;
  if (req.state !== 'stopped') {
    return { error: 'report_requires_stopped_request', status: 409, state: req.state };
  }

  const existing = findSocReport(ctx.tenantId, requestId);
  const now = new Date().toISOString();
  const summary = bodySummaryFields(body, existing);
  const notes = ensureNotes().filter(
    (n) => n.high_scale_request_id === requestId && n.tenant_id === ctx.tenantId,
  );
  const derived = {
    timeline: buildTimeline(req),
    artifacts: summarizeArtifacts(req),
    soc_notes: summarizeSocNotes(notes),
    adapter: summarizeAdapter(req),
    telemetry_summary: summarizeTelemetryForReportFromStore(ctx.tenantId, requestId),
    final_state: req.state,
  };

  let report;
  let auditAction;
  if (existing) {
    report = {
      ...existing,
      ...summary,
      ...derived,
      updated_at: now,
      updated_by: ctx.userId,
    };
    auditAction = 'high_scale.post_test_report_updated';
  } else {
    report = {
      id: newId('socrep'),
      tenant_id: ctx.tenantId,
      high_scale_request_id: requestId,
      created_at: now,
      created_by: ctx.userId,
      updated_at: now,
      updated_by: ctx.userId,
      ...summary,
      ...derived,
    };
    ensureSocReports().push(report);
    auditAction = 'high_scale.post_test_report_created';
  }

  const idx = ensureSocReports().findIndex((r) => r.id === report.id);
  if (idx >= 0) ensureSocReports()[idx] = report;

  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: auditAction,
    resource_type: 'soc_post_test_report',
    resource_id: report.id,
    metadata: {
      high_scale_request_id: requestId,
      report_id: report.id,
      final_state: req.state,
    },
  });
  persistStore();
  return { report, created: !existing };
}

export function getPostTestReport(ctx, requestId) {
  const req = getHighScaleRequest(ctx.tenantId, requestId);
  if (!req) return null;
  const report = findSocReport(ctx.tenantId, requestId);
  if (!report) return { error: 'not_found', status: 404 };
  return report;
}

function auditStartGateDenied(ctx, req, reason, metadata = {}) {
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'high_scale.start_gate_denied',
    resource_type: 'high_scale_request',
    resource_id: req.id,
    metadata: { reason, ...metadata },
  });
  persistStore();
}

function notifyStateChange(ctx, req, action) {
  emitNotification(ctx, {
    trigger: 'high_scale.state_change',
    subject: `High-scale request ${req.id} → ${req.state}`,
    metadata: { request_id: req.id, action, state: req.state },
  });
}

function validateHighScaleTargetScope(tenantId, targetGroupId) {
  if (!targetGroupId) {
    return { error: 'missing_target_group_id', status: 400 };
  }
  const group = getStore().targetGroups.find((g) => g.id === targetGroupId && g.tenant_id === tenantId);
  if (!group) {
    return { error: 'target_group_not_found', status: 404 };
  }
  const targets = getStore().targets.filter(
    (t) => t.tenant_id === tenantId && t.target_group_id === targetGroupId,
  );
  if (targets.length === 0) {
    return { error: 'target_group_empty', status: 400 };
  }
  return null;
}

export function createHighScaleRequest(ctx, body) {
  const scopeError = validateHighScaleTargetScope(ctx.tenantId, body.target_group_id);
  if (scopeError) return scopeError;

  const intake = validateHighScaleIntakeFields(body);
  if (intake.error) return intake;

  const id = newId('hs');
  const text = intake.reasonOrObjective;
  const record = {
    id,
    tenant_id: ctx.tenantId,
    target_group_id: body.target_group_id,
    reason: text,
    objective: text,
    requested_window: intake.requested_window,
    emergency_contacts: intake.emergency_contacts,
    scope_confirmation: true,
    provider_context: body.provider_context ? redactObject(body.provider_context) : null,
    state: 'submitted',
    created_at: new Date().toISOString(),
    created_by: ctx.userId,
    audit_trail: [],
    scheduled_window: null,
    artifacts: [],
    scope_hash: null,
    soc_approvals: [],
    provider_approval_checklist: buildProviderApprovalChecklist(body),
    environment: intake.environment,
    business_criticality: intake.business_criticality,
    requested_scenario_families: intake.requested_scenario_families,
    requested_limits: intake.requested_limits,
    stop_criteria: intake.stop_criteria,
    abort_criteria: intake.abort_criteria,
    ...storeOptionalHighScaleFields(body),
  };
  refreshAuthorizationPackStatus(record);
  getStore().highScaleRequests.push(record);
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'high_scale.request_submitted',
    resource_type: 'high_scale_request',
    resource_id: id,
  });
  notifyStateChange(ctx, record, 'submitted');
  persistStore();
  return record;
}

export function listHighScaleRequests(ctx) {
  return getStore().highScaleRequests.filter((h) => h.tenant_id === ctx.tenantId);
}

export function getHighScaleRequest(tenantId, id) {
  return getStore().highScaleRequests.find((h) => h.id === id && h.tenant_id === tenantId) ?? null;
}

export function addArtifact(ctx, requestId, body, options = {}) {
  const req = getHighScaleRequest(ctx.tenantId, requestId);
  if (!req) return null;
  const validation = validateArtifactUploadBody(body);
  if (validation.error) return validation;
  const artifact = buildArtifactFromUpload(ctx, body, { uploadEnvelope: options.uploadEnvelope });
  if (!req.artifacts) req.artifacts = [];
  req.artifacts.push(artifact);
  const store = getStore();
  const ledgerEntry = buildAuthorizationArtifactLedgerEntry(ctx, requestId, artifact, body);
  ensureAuthorizationArtifactLedger(store).push(ledgerEntry);
  if (artifact.type === 'provider_approval') {
    syncChecklistFromProviderArtifact(req, artifact, body);
  }
  refreshAuthorizationPackStatus(req);
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'high_scale.artifact_uploaded',
    resource_type: 'high_scale_artifact',
    resource_id: artifact.id,
    metadata: {
      request_id: requestId,
      type: artifact.type,
      custody_id: artifact.custody_id,
      content_sha256: artifact.content_sha256,
      upload_envelope: artifact.upload_envelope,
    },
  });
  persistStore();
  return artifact;
}

export function listArtifacts(ctx, requestId) {
  const req = getHighScaleRequest(ctx.tenantId, requestId);
  if (!req) return null;
  return req.artifacts ?? [];
}

export function reviewArtifact(ctx, requestId, artifactId, body) {
  const req = getHighScaleRequest(ctx.tenantId, requestId);
  if (!req) return null;
  const art = (req.artifacts ?? []).find((a) => a.id === artifactId);
  if (!art) return { error: 'not_found', status: 404 };
  art.status = body.status === 'accepted' ? 'accepted' : 'rejected';
  art.reviewed_at = new Date().toISOString();
  art.reviewed_by = ctx.userId;
  art.review_notes = body.notes ?? null;
  if (art.type === 'provider_approval') {
    syncChecklistFromProviderArtifactReview(req, art);
  }
  refreshAuthorizationPackStatus(req);
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'high_scale.artifact_reviewed',
    resource_type: 'high_scale_artifact',
    resource_id: artifactId,
    metadata: { status: art.status, request_id: requestId },
  });
  persistStore();
  return art;
}

export function addSocNote(ctx, requestId, body) {
  const req = getHighScaleRequest(ctx.tenantId, requestId);
  if (!req) return null;
  const note = {
    id: newId('note'),
    tenant_id: ctx.tenantId,
    high_scale_request_id: requestId,
    body: body.body ?? '',
    created_at: new Date().toISOString(),
    author: ctx.userId,
  };
  ensureNotes().push(note);
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'high_scale.soc_note_added',
    resource_type: 'high_scale_request',
    resource_id: requestId,
  });
  persistStore();
  return note;
}

export function listSocNotes(ctx, requestId) {
  const req = getHighScaleRequest(ctx.tenantId, requestId);
  if (!req) return null;
  return ensureNotes().filter((n) => n.high_scale_request_id === requestId && n.tenant_id === ctx.tenantId);
}

export function recordHighScaleTelemetry(ctx, requestId, body) {
  const req = getHighScaleRequest(ctx.tenantId, requestId);
  if (!req) return null;
  if (!TELEMETRY_ACTIVE_STATES.has(req.state)) {
    return { error: 'telemetry_not_active', status: 409, state: req.state };
  }

  const category = body?.category != null ? String(body.category).trim() : '';
  if (!TELEMETRY_CATEGORIES.has(category)) {
    return { error: 'invalid_category', status: 400 };
  }

  let live_status = null;
  if (body?.live_status != null && body.live_status !== '') {
    live_status = String(body.live_status).trim();
    if (!TELEMETRY_LIVE_STATUSES.has(live_status)) {
      return { error: 'invalid_live_status', status: 400 };
    }
  }

  const observed = parseObservedAt(body?.observed_at);
  if (!observed.ok) return observed;

  if (telemetryObjectContainsForbiddenKeys(body)) {
    return { error: 'forbidden_telemetry_fields', status: 400 };
  }

  const metrics =
    body?.metrics != null && typeof body.metrics === 'object' && !Array.isArray(body.metrics)
      ? redactObject(body.metrics)
      : null;
  const source =
    body?.source != null && body.source !== '' ? redactString(String(body.source)) : null;

  const record = {
    id: newId('hstel'),
    tenant_id: ctx.tenantId,
    high_scale_request_id: requestId,
    category,
    live_status,
    observed_at: observed.value,
    source,
    metrics,
    created_at: new Date().toISOString(),
    recorded_by: ctx.userId,
  };
  ensureHighScaleTelemetry().push(record);

  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'high_scale.telemetry_recorded',
    resource_type: 'high_scale_telemetry',
    resource_id: record.id,
    metadata: {
      high_scale_request_id: requestId,
      category,
      live_status,
    },
  });
  persistStore();
  return record;
}

export function listHighScaleTelemetry(ctx, requestId) {
  const req = getHighScaleRequest(ctx.tenantId, requestId);
  if (!req) return null;
  return ensureHighScaleTelemetry()
    .filter((t) => t.tenant_id === ctx.tenantId && t.high_scale_request_id === requestId)
    .sort((a, b) => String(b.observed_at).localeCompare(String(a.observed_at)));
}

function persistHighScaleTelemetryRecord(ctx, requestId, fields) {
  const record = {
    id: newId('hstel'),
    tenant_id: ctx.tenantId,
    high_scale_request_id: requestId,
    category: fields.category,
    live_status: fields.live_status,
    observed_at: fields.observed_at,
    source: fields.source,
    metrics: fields.metrics,
    created_at: new Date().toISOString(),
    recorded_by: ctx.userId,
  };
  ensureHighScaleTelemetry().push(record);
  return record;
}

export function ingestGovernedAdapterTelemetry(ctx, requestId, body) {
  const req = getHighScaleRequest(ctx.tenantId, requestId);
  if (!req) return null;
  if (!TELEMETRY_ACTIVE_STATES.has(req.state)) {
    return { error: 'telemetry_not_active', status: 409, state: req.state };
  }

  const ingestion_id = newId('hsteling');
  const normalized = normalizeGovernedAdapterTelemetryIngest(body, { ingestion_id });
  if (!normalized.ok) return normalized;

  const records = normalized.records.map((fields) =>
    persistHighScaleTelemetryRecord(ctx, requestId, fields),
  );

  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'high_scale.adapter_telemetry_ingested',
    resource_type: 'high_scale_telemetry_ingest',
    resource_id: ingestion_id,
    metadata: {
      high_scale_request_id: requestId,
      adapter_id: normalized.adapter_id,
      provider_key: normalized.provider_key,
      snapshot_count: records.length,
      ingestion_id,
    },
  });
  persistStore();

  return {
    ingestion_id,
    adapter_id: normalized.adapter_id,
    adapter_type: normalized.adapter_type,
    provider_key: normalized.provider_key,
    provider_run_id: normalized.provider_run_id,
    snapshot_count: records.length,
    records,
  };
}

export function transitionHighScale(ctx, id, action, metadata = {}) {
  const req = getHighScaleRequest(ctx.tenantId, id);
  if (!req) return null;

  const allowed = {
    approve: ['submitted', 'under_review'],
    schedule: ['approved'],
    start: ['scheduled'],
    stop: ['running'],
    close: ['stopped'],
  };

  const nextState = {
    approve: 'approved',
    schedule: 'scheduled',
    start: 'running',
    stop: 'stopped',
    close: 'closed',
  };

  if (action === 'stop' && req.state !== 'running') {
    return { error: 'not_running', state: req.state, status: 409 };
  }

  if (!allowed[action]?.includes(req.state)) {
    return { error: 'invalid_transition', state: req.state, status: 409 };
  }

  if (action === 'close' && !findSocReport(ctx.tenantId, id)) {
    return { error: 'post_test_report_required', status: 409 };
  }

  let resolvedState = nextState[action];

  if (action === 'approve') {
    if (!authorizationPackComplete(req)) {
      return authorizationPackIncompleteResponse(req);
    }
    if (!req.soc_approvals) req.soc_approvals = [];
    if (req.soc_approvals.some((a) => a.user_id === ctx.userId)) {
      return { error: 'duplicate_soc_approval', status: 409 };
    }
    req.soc_approvals.push({ user_id: ctx.userId, at: new Date().toISOString() });
    if (distinctSocApprovalCount(req) < 2) {
      resolvedState = 'under_review';
      audit({
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId,
        actor_role: ctx.role,
        action: 'high_scale.soc_approval_recorded',
        resource_type: 'high_scale_request',
        resource_id: id,
        metadata: { approvals: distinctSocApprovalCount(req) },
      });
    } else {
      req.scope_hash = computeTargetGroupScopeHash(ctx.tenantId, req.target_group_id);
      resolvedState = 'approved';
      audit({
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId,
        actor_role: ctx.role,
        action: 'high_scale.approved',
        resource_type: 'high_scale_request',
        resource_id: id,
        metadata: { scope_hash: req.scope_hash },
      });
    }
  }

  if (action === 'schedule') {
    const window_start = metadata.window_start;
    const window_end = metadata.window_end;
    if (!window_start || !window_end) {
      return { error: 'missing_schedule_window', status: 409 };
    }
    if (!req.scope_hash) {
      return { error: 'missing_scope_hash', status: 409 };
    }
    req.scheduled_window = { window_start, window_end, scope_hash: req.scope_hash };
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'high_scale.scheduled',
      resource_type: 'high_scale_request',
      resource_id: id,
      metadata: { window_start, window_end, scope_hash: req.scope_hash },
    });
  }

  if (action === 'start') {
    if (distinctSocApprovalCount(req) < 2) {
      auditStartGateDenied(ctx, req, 'insufficient_soc_approvals');
      return { error: 'insufficient_soc_approvals', status: 409 };
    }
    if (isKillSwitchActiveForTenant(ctx.tenantId)) {
      auditStartGateDenied(ctx, req, 'kill_switch_active');
      return { error: 'kill_switch_active', status: 409 };
    }
    if (!req.scheduled_window?.window_start || !req.scheduled_window?.window_end) {
      auditStartGateDenied(ctx, req, 'missing_schedule_window');
      return { error: 'missing_schedule_window', status: 409 };
    }
    if (!isWithinScheduledWindow(req.scheduled_window)) {
      auditStartGateDenied(ctx, req, 'outside_schedule_window', {
        window_start: req.scheduled_window.window_start,
        window_end: req.scheduled_window.window_end,
      });
      return { error: 'outside_schedule_window', status: 409 };
    }
    const currentScope = computeTargetGroupScopeHash(ctx.tenantId, req.target_group_id);
    if (currentScope !== req.scope_hash) {
      auditStartGateDenied(ctx, req, 'scope_hash_mismatch', { expected: req.scope_hash, actual: currentScope });
      return { error: 'scope_hash_mismatch', status: 409 };
    }
    const adapterGate = evaluateHighScaleAdapterStartGate(metadata.adapter_mode);
    if (adapterGate) {
      auditStartGateDenied(ctx, req, adapterGate.error);
      return adapterGate;
    }
    const adapterResult = adapterStub.start(ctx, id, { scope_hash: req.scope_hash, ...metadata });
    if (adapterResult.error) {
      auditStartGateDenied(ctx, req, adapterResult.error);
      return adapterResult;
    }
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'high_scale.adapter_stub_started',
      resource_type: 'high_scale_request',
      resource_id: id,
      metadata: {
        note: 'Governed dry-run adapter — no traffic generator executed.',
        ...metadata,
      },
    });
  }

  if (action === 'stop') {
    const stopResult = adapterStub.stop(ctx, id, metadata.reason);
    if (stopResult?.error) {
      return stopResult;
    }
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'high_scale.stop',
      resource_type: 'high_scale_request',
      resource_id: id,
      metadata,
    });
  }

  req.state = resolvedState;
  req.audit_trail.push({
    action,
    at: new Date().toISOString(),
    by: ctx.userId,
    metadata,
  });

  if (action !== 'schedule' && action !== 'start' && action !== 'approve' && action !== 'stop') {
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: `high_scale.${action}`,
      resource_type: 'high_scale_request',
      resource_id: id,
      metadata,
    });
  } else if (action === 'start') {
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'high_scale.start',
      resource_type: 'high_scale_request',
      resource_id: id,
      metadata,
    });
  }

  incMetric('high_scale_transitions_total');
  notifyStateChange(ctx, req, action);
  persistStore();
  return req;
}

function autoStopRunningHighScaleRequests(ctx, reason) {
  const stoppedRequestIds = [];
  for (const req of getStore().highScaleRequests) {
    if (req.tenant_id !== ctx.tenantId || req.state !== 'running') continue;
    const stopResult = adapterStub.stop(ctx, req.id, reason ?? 'kill_switch');
    if (stopResult?.error) continue;
    req.state = 'stopped';
    req.audit_trail.push({
      action: 'kill_switch_auto_stop',
      at: new Date().toISOString(),
      by: ctx.userId,
      metadata: { reason: reason ?? null },
    });
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'high_scale.kill_switch_auto_stop',
      resource_type: 'high_scale_request',
      resource_id: req.id,
      metadata: { reason: reason ?? null },
    });
    stoppedRequestIds.push(req.id);
    notifyStateChange(ctx, req, 'stop');
  }
  return stoppedRequestIds;
}

export function setKillSwitch(ctx, active, reason) {
  const prev = getStore().socKillSwitch ?? {};
  let stoppedRequestIds = [];
  let cancelledRunIds = [];
  if (active) {
    stoppedRequestIds = autoStopRunningHighScaleRequests(ctx, reason);
    cancelledRunIds = autoCancelActiveSafeRunsForKillSwitch(ctx, reason);
  }
  getStore().socKillSwitch = {
    active,
    reason: reason ?? null,
    updated_at: new Date().toISOString(),
    updated_by: ctx.userId,
    tenant_id: ctx.tenantId ?? prev.tenant_id ?? null,
    stopped_request_ids: stoppedRequestIds,
    cancelled_run_ids: cancelledRunIds,
  };
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: active ? 'soc.kill_switch.activated' : 'soc.kill_switch.cleared',
    resource_type: 'platform',
    resource_id: 'kill_switch',
    metadata: {
      reason,
      tenant_id: getStore().socKillSwitch.tenant_id,
      stopped_request_ids: stoppedRequestIds,
      cancelled_run_ids: cancelledRunIds,
    },
  });
  persistStore();
  return getStore().socKillSwitch;
}
