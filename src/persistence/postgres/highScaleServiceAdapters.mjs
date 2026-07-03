import { validateArtifactUploadBody } from '../../lib/authorizationArtifactLedger.mjs';
import { newId } from '../../lib/ids.mjs';
import { redactObject, redactString } from '../../lib/redact.mjs';
import { incMetric } from '../../lib/metrics.mjs';
import { computeScopeHashFromTargets } from '../../lib/scopeHash.mjs';
import { normalizeGovernedAdapterTelemetryIngest } from '../../lib/governedAdapterTelemetry.mjs';
import { evaluateHighScaleAdapterStartGate } from '../../lib/highScalePolicy.mjs';
import {
  TELEMETRY_ACTIVE_STATES,
  TELEMETRY_CATEGORIES,
  TELEMETRY_LIVE_STATUSES,
  authorizationPackComplete,
  authorizationPackIncompleteResponse,
  applyDryRunAdapterStart,
  applyDryRunAdapterStop,
  bodySummaryFields,
  buildArtifactFromUpload,
  buildIntakeRiskReviewJson,
  buildProviderApprovalChecklist,
  buildTimeline,
  distinctSocApprovalCount,
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
} from '../../lib/highScalePolicy.mjs';

const CANCELLABLE_RUN_STATUSES = ['planned', 'running', 'collecting'];

/** @type {readonly string[]} */
export const HIGH_SCALE_REPOSITORY_METHODS = Object.freeze([
  'createHighScaleRequest',
  'listHighScaleRequests',
  'getHighScaleRequest',
  'updateHighScaleRequest',
  'listRunningHighScaleRequests',
  'insertAuthorizationArtifact',
  'updateAuthorizationArtifact',
  'listAuthorizationArtifacts',
  'appendSocNote',
  'listSocNotes',
  'appendTelemetry',
  'listTelemetry',
  'getSocReport',
  'upsertSocReport',
]);

/** @type {readonly string[]} */
export const HIGH_SCALE_KILL_SWITCH_REPOSITORY_METHODS = Object.freeze([
  'isKillSwitchActiveForTenant',
  'getKillSwitchRecord',
  'upsertKillSwitch',
]);

/** @type {readonly string[]} */
export const POSTGRES_HIGH_SCALE_SERVICE_METHODS = Object.freeze([
  'createHighScaleRequest',
  'listHighScaleRequests',
  'addArtifact',
  'listArtifacts',
  'reviewArtifact',
  'addSocNote',
  'listSocNotes',
  'getAdapterStatus',
  'recordHighScaleTelemetry',
  'ingestGovernedAdapterTelemetry',
  'listHighScaleTelemetry',
  'upsertPostTestReport',
  'getPostTestReport',
  'transitionHighScale',
  'setKillSwitch',
]);

function assertHighScaleRepositories(repositories) {
  const highScale = repositories?.highScale;
  if (!highScale || typeof highScale !== 'object') {
    throw new Error('Postgres high-scale service adapter requires repositories.highScale.');
  }
  for (const method of HIGH_SCALE_REPOSITORY_METHODS) {
    if (typeof highScale[method] !== 'function') {
      throw new Error(`Postgres high-scale service adapter requires highScale.${method}().`);
    }
  }
  const coreCatalog = repositories?.coreCatalog;
  if (!coreCatalog || typeof coreCatalog.getTargetGroup !== 'function') {
    throw new Error('Postgres high-scale service adapter requires coreCatalog.getTargetGroup().');
  }
  const audit = repositories?.audit;
  if (!audit || typeof audit.appendAuditEvent !== 'function') {
    throw new Error('Postgres high-scale service adapter requires audit.appendAuditEvent().');
  }
  const killSwitch = repositories?.killSwitch;
  if (!killSwitch || typeof killSwitch.isKillSwitchActiveForTenant !== 'function') {
    throw new Error('Postgres high-scale service adapter requires killSwitch.isKillSwitchActiveForTenant().');
  }
  for (const method of ['getKillSwitchRecord', 'upsertKillSwitch']) {
    if (typeof killSwitch[method] !== 'function') {
      throw new Error(`Postgres high-scale service adapter requires killSwitch.${method}().`);
    }
  }
  const validationEvidence = repositories?.validationEvidence;
  if (!validationEvidence || typeof validationEvidence.listTestRuns !== 'function') {
    throw new Error('Postgres high-scale service adapter requires validationEvidence.listTestRuns().');
  }
  if (typeof validationEvidence.updateTestRun !== 'function') {
    throw new Error('Postgres high-scale service adapter requires validationEvidence.updateTestRun().');
  }
  const probeJobs = repositories?.probeJobs;
  if (!probeJobs || typeof probeJobs.cancelOpenProbeJobsForTestRuns !== 'function') {
    throw new Error(
      'Postgres high-scale service adapter requires probeJobs.cancelOpenProbeJobsForTestRuns().',
    );
  }
}

async function appendAudit(auditRepo, ctx, action, resource_type, resource_id, metadata = {}) {
  await auditRepo.appendAuditEvent({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action,
    resource_type,
    resource_id,
    metadata,
  });
}

async function notifyStateChangeOptional(notifications, ctx, req, action) {
  if (!notifications || typeof notifications.emitNotification !== 'function') return;
  try {
    await notifications.emitNotification(ctx, {
      trigger: 'high_scale.state_change',
      subject: `High-scale request ${req.id} → ${req.state}`,
      metadata: { request_id: req.id, action, state: req.state },
    });
  } catch {
    // notification delivery must not block SOC transitions
  }
}

async function persistRequestPack(repo, ctx, req) {
  const patch = buildRequestPackPatch(req);
  return repo.updateHighScaleRequest(ctx, req.id, patch);
}

function buildRequestPackPatch(req) {
  refreshAuthorizationPackStatus(req);
  const risk = {
    environment: req.environment,
    business_criticality: req.business_criticality,
    requested_scenario_families: req.requested_scenario_families,
    requested_limits: req.requested_limits,
    stop_criteria: req.stop_criteria,
    abort_criteria: req.abort_criteria,
    maintenance_approval: req.maintenance_approval,
    provider_contacts: req.provider_contacts,
    authorization_pack_status: req.authorization_pack_status,
  };
  return {
    artifacts: req.artifacts,
    provider_approval_checklist: req.provider_approval_checklist,
    risk_review_json: risk,
    adapter: req.adapter,
    updated_at: new Date().toISOString(),
  };
}

async function validateTargetScope(coreCatalog, ctx, targetGroupId) {
  if (!targetGroupId) {
    return { error: 'missing_target_group_id', status: 400 };
  }
  const group = await coreCatalog.getTargetGroup(ctx, targetGroupId);
  if (!group) {
    return { error: 'target_group_not_found', status: 404 };
  }
  const targets = group.targets ?? [];
  if (targets.length === 0) {
    return { error: 'target_group_empty', status: 400 };
  }
  return { group, targets };
}

async function autoCancelActiveSafeRunsForKillSwitch(ctx, reason, validationEvidence, auditRepo) {
  const runs = await validationEvidence.listTestRuns(ctx, {
    statuses: CANCELLABLE_RUN_STATUSES,
    limit: 500,
  });
  const cancelledRunIds = [];
  const now = new Date().toISOString();
  for (const run of runs) {
    const summary = { ...(run.summary ?? {}), cancelled_by_kill_switch: true };
    await validationEvidence.updateTestRun(ctx, run.id, {
      status: 'cancelled',
      completed_at: now,
      summary,
    });
    await appendAudit(auditRepo, ctx, 'test_run.kill_switch_auto_cancel', 'test_run', run.id, {
      reason: reason ?? null,
      check_id: run.check_id,
      target_group_id: run.target_group_id,
    });
    cancelledRunIds.push(run.id);
  }
  return cancelledRunIds;
}

/**
 * @param {{
 *   highScale?: Record<string, unknown>,
 *   coreCatalog?: Record<string, unknown>,
 *   audit?: { appendAuditEvent?: (...args: unknown[]) => unknown },
 *   killSwitch?: Record<string, unknown>,
 *   validationEvidence?: Record<string, unknown>,
 *   notifications?: { emitNotification?: (...args: unknown[]) => unknown },
 * }} repositories
 * @param {{ now?: () => Date, newId?: typeof newId, notifications?: { emitNotification?: (...args: unknown[]) => unknown } }} [options]
 */
export function createPostgresHighScaleServices(repositories, options = {}) {
  assertHighScaleRepositories(repositories);
  const repo = repositories.highScale;
  const coreCatalog = repositories.coreCatalog;
  const auditRepo = repositories.audit;
  const killSwitchRepo = repositories.killSwitch;
  const validationEvidence = repositories.validationEvidence;
  const probeJobsRepo = repositories.probeJobs;
  const notifications = options.notifications ?? repositories.notifications;
  const nowFn = options.now ?? (() => new Date());
  const newIdFn = options.newId ?? newId;

  return {
    async createHighScaleRequest(ctx, body) {
      const scope = await validateTargetScope(coreCatalog, ctx, body.target_group_id);
      if (scope.error) return scope;

      const intake = validateHighScaleIntakeFields(body);
      if (intake.error) return intake;

      const id = newIdFn('hs');
      const text = intake.reasonOrObjective;
      const optional = storeOptionalHighScaleFields(body);
      const record = {
        id,
        target_group_id: body.target_group_id,
        reason: text,
        objective: text,
        requested_window: intake.requested_window,
        emergency_contacts: intake.emergency_contacts,
        scope_confirmation: true,
        provider_context: body.provider_context ? redactObject(body.provider_context) : null,
        state: 'submitted',
        created_at: nowFn().toISOString(),
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
        ...optional,
        risk_review_json: buildIntakeRiskReviewJson(intake, body, optional),
        adapter: {},
      };
      refreshAuthorizationPackStatus(record);
      record.risk_review_json.authorization_pack_status = record.authorization_pack_status;
      const created = await repo.createHighScaleRequest(ctx, record);
      await appendAudit(auditRepo, ctx, 'high_scale.request_submitted', 'high_scale_request', id);
      await notifyStateChangeOptional(notifications, ctx, created, 'submitted');
      return created;
    },

    async listHighScaleRequests(ctx) {
      return repo.listHighScaleRequests(ctx);
    },

    async addArtifact(ctx, requestId, body, options = {}) {
      const req = await repo.getHighScaleRequest(ctx, requestId);
      if (!req) return null;
      const validation = validateArtifactUploadBody(body);
      if (validation.error) return validation;
      const artifact = buildArtifactFromUpload(ctx, body, { uploadEnvelope: options.uploadEnvelope });
      if (!req.artifacts) req.artifacts = [];
      req.artifacts.push(artifact);
      if (artifact.type === 'provider_approval') {
        syncChecklistFromProviderArtifact(req, artifact, body);
      }
      if (typeof repo.insertAuthorizationArtifactAndUpdateRequest === 'function') {
        await repo.insertAuthorizationArtifactAndUpdateRequest(ctx, requestId, artifact, buildRequestPackPatch(req));
      } else {
        await repo.insertAuthorizationArtifact(ctx, requestId, artifact);
        await persistRequestPack(repo, ctx, req);
      }
      await appendAudit(auditRepo, ctx, 'high_scale.artifact_uploaded', 'high_scale_artifact', artifact.id, {
        request_id: requestId,
        type: artifact.type,
        custody_id: artifact.custody_id,
        content_sha256: artifact.content_sha256,
        upload_envelope: artifact.upload_envelope,
      });
      return artifact;
    },

    async listArtifacts(ctx, requestId) {
      const req = await repo.getHighScaleRequest(ctx, requestId);
      if (!req) return null;
      const artifacts = await repo.listAuthorizationArtifacts(ctx, requestId);
      return artifacts.length ? artifacts : (req.artifacts ?? []);
    },

    async reviewArtifact(ctx, requestId, artifactId, body) {
      const req = await repo.getHighScaleRequest(ctx, requestId);
      if (!req) return null;
      const art = (req.artifacts ?? []).find((a) => a.id === artifactId);
      if (!art) return { error: 'not_found', status: 404 };
      art.status = body.status === 'accepted' ? 'accepted' : 'rejected';
      art.reviewed_at = nowFn().toISOString();
      art.reviewed_by = ctx.userId;
      art.review_notes = body.notes ?? null;
      if (art.type === 'provider_approval') {
        syncChecklistFromProviderArtifactReview(req, art);
      }
      const artifactPatch = {
        status: art.status,
        reviewed_by: art.reviewed_by,
        reviewed_at: art.reviewed_at,
        metadata: { review_notes: art.review_notes },
      };
      if (typeof repo.updateAuthorizationArtifactAndRequest === 'function') {
        await repo.updateAuthorizationArtifactAndRequest(
          ctx,
          requestId,
          artifactId,
          artifactPatch,
          buildRequestPackPatch(req),
        );
      } else {
        await repo.updateAuthorizationArtifact(ctx, requestId, artifactId, artifactPatch);
        await persistRequestPack(repo, ctx, req);
      }
      await appendAudit(auditRepo, ctx, 'high_scale.artifact_reviewed', 'high_scale_artifact', artifactId, {
        status: art.status,
        request_id: requestId,
      });
      return art;
    },

    async addSocNote(ctx, requestId, body) {
      const req = await repo.getHighScaleRequest(ctx, requestId);
      if (!req) return null;
      const note = {
        id: newIdFn('note'),
        body: body.body ?? '',
        created_at: nowFn().toISOString(),
        author: ctx.userId,
      };
      const persisted = await repo.appendSocNote(ctx, requestId, note);
      await appendAudit(auditRepo, ctx, 'high_scale.soc_note_added', 'high_scale_request', requestId);
      return persisted;
    },

    async listSocNotes(ctx, requestId) {
      const req = await repo.getHighScaleRequest(ctx, requestId);
      if (!req) return null;
      return repo.listSocNotes(ctx, requestId);
    },

    async getAdapterStatus(ctx, requestId) {
      const req = await repo.getHighScaleRequest(ctx, requestId);
      if (!req) return null;
      const kill_switch = await killSwitchRepo.isKillSwitchActiveForTenant(ctx);
      return {
        request_id: requestId,
        state: req.state,
        scope_hash: req.scope_hash,
        adapter: req.adapter ?? { status: 'idle', traffic_generated: false },
        kill_switch,
      };
    },

    async recordHighScaleTelemetry(ctx, requestId, body) {
      const req = await repo.getHighScaleRequest(ctx, requestId);
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
        id: newIdFn('hstel'),
        high_scale_request_id: requestId,
        category,
        live_status,
        observed_at: observed.value,
        source,
        metrics,
        created_at: nowFn().toISOString(),
        recorded_by: ctx.userId,
      };
      const persisted = await repo.appendTelemetry(ctx, record);
      await appendAudit(auditRepo, ctx, 'high_scale.telemetry_recorded', 'high_scale_telemetry', record.id, {
        high_scale_request_id: requestId,
        category,
        live_status,
      });
      return persisted;
    },

    async ingestGovernedAdapterTelemetry(ctx, requestId, body) {
      const req = await repo.getHighScaleRequest(ctx, requestId);
      if (!req) return null;
      if (!TELEMETRY_ACTIVE_STATES.has(req.state)) {
        return { error: 'telemetry_not_active', status: 409, state: req.state };
      }

      const ingestion_id = newIdFn('hsteling');
      const normalized = normalizeGovernedAdapterTelemetryIngest(body, { ingestion_id });
      if (!normalized.ok) return normalized;

      const records = [];
      for (const fields of normalized.records) {
        const record = {
          id: newIdFn('hstel'),
          high_scale_request_id: requestId,
          category: fields.category,
          live_status: fields.live_status,
          observed_at: fields.observed_at,
          source: fields.source,
          metrics: fields.metrics,
          created_at: nowFn().toISOString(),
          recorded_by: ctx.userId,
        };
        records.push(await repo.appendTelemetry(ctx, record));
      }

      await appendAudit(
        auditRepo,
        ctx,
        'high_scale.adapter_telemetry_ingested',
        'high_scale_telemetry_ingest',
        ingestion_id,
        {
          high_scale_request_id: requestId,
          adapter_id: normalized.adapter_id,
          provider_key: normalized.provider_key,
          snapshot_count: records.length,
          ingestion_id,
        },
      );

      return {
        ingestion_id,
        adapter_id: normalized.adapter_id,
        adapter_type: normalized.adapter_type,
        provider_key: normalized.provider_key,
        provider_run_id: normalized.provider_run_id,
        snapshot_count: records.length,
        records,
      };
    },

    async listHighScaleTelemetry(ctx, requestId) {
      const req = await repo.getHighScaleRequest(ctx, requestId);
      if (!req) return null;
      return repo.listTelemetry(ctx, requestId);
    },

    async upsertPostTestReport(ctx, requestId, body) {
      const snapshot = typeof repo.getHighScaleReportSnapshot === 'function'
        ? await repo.getHighScaleReportSnapshot(ctx, requestId)
        : null;
      const req = snapshot?.request ?? await repo.getHighScaleRequest(ctx, requestId);
      if (!req) return null;
      if (req.state !== 'stopped') {
        return { error: 'report_requires_stopped_request', status: 409, state: req.state };
      }
      const existing = snapshot?.report ?? await repo.getSocReport(ctx, requestId);
      const now = nowFn().toISOString();
      const summary = bodySummaryFields(body, existing);
      const notes = snapshot?.notes ?? await repo.listSocNotes(ctx, requestId);
      const telemetry = snapshot?.telemetry ?? await repo.listTelemetry(ctx, requestId);
      const normalizedArtifacts = snapshot
        ? req.artifacts ?? []
        : await repo.listAuthorizationArtifacts(ctx, requestId);
      const reportRequest = {
        ...req,
        artifacts: normalizedArtifacts.length ? normalizedArtifacts : (req.artifacts ?? []),
      };
      const derived = {
        timeline: buildTimeline(reportRequest),
        artifacts: summarizeArtifacts(reportRequest),
        soc_notes: summarizeSocNotes(notes),
        adapter: summarizeAdapter(reportRequest),
        telemetry_summary: summarizeTelemetryForReport(telemetry),
        final_state: reportRequest.state,
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
          id: newIdFn('socrep'),
          high_scale_request_id: requestId,
          created_at: now,
          created_by: ctx.userId,
          updated_at: now,
          updated_by: ctx.userId,
          ...summary,
          ...derived,
        };
        auditAction = 'high_scale.post_test_report_created';
      }
      const persisted = await repo.upsertSocReport(ctx, requestId, report);
      await appendAudit(auditRepo, ctx, auditAction, 'soc_post_test_report', persisted.id, {
        high_scale_request_id: requestId,
        report_id: persisted.id,
        final_state: req.state,
      });
      return { report: persisted, created: !existing };
    },

    async getPostTestReport(ctx, requestId) {
      const req = await repo.getHighScaleRequest(ctx, requestId);
      if (!req) return null;
      const report = await repo.getSocReport(ctx, requestId);
      if (!report) return { error: 'not_found', status: 404 };
      return report;
    },

    async transitionHighScale(ctx, id, action, metadata = {}) {
      const req = await repo.getHighScaleRequest(ctx, id);
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
      if (action === 'close') {
        const report = await repo.getSocReport(ctx, id);
        if (!report) return { error: 'post_test_report_required', status: 409 };
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
        const approvalsBefore = distinctSocApprovalCount(req);
        if (approvalsBefore < 1) {
          req.soc_approvals.push({ user_id: ctx.userId, at: nowFn().toISOString() });
          resolvedState = 'under_review';
          await appendAudit(auditRepo, ctx, 'high_scale.soc_approval_recorded', 'high_scale_request', id, {
            approvals: distinctSocApprovalCount(req),
          });
        } else {
          const scope = await validateTargetScope(coreCatalog, ctx, req.target_group_id);
          if (scope.error) {
            await appendAudit(auditRepo, ctx, 'high_scale.approval_gate_denied', 'high_scale_request', id, {
              reason: scope.error,
            });
            return { error: scope.error, status: scope.status };
          }
          req.soc_approvals.push({ user_id: ctx.userId, at: nowFn().toISOString() });
          req.scope_hash = computeScopeHashFromTargets(req.target_group_id, scope.targets);
          resolvedState = 'approved';
          await appendAudit(auditRepo, ctx, 'high_scale.approved', 'high_scale_request', id, {
            scope_hash: req.scope_hash,
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
        await appendAudit(auditRepo, ctx, 'high_scale.scheduled', 'high_scale_request', id, {
          window_start,
          window_end,
          scope_hash: req.scope_hash,
        });
      }

      if (action === 'start') {
        if (distinctSocApprovalCount(req) < 2) {
          await appendAudit(auditRepo, ctx, 'high_scale.start_gate_denied', 'high_scale_request', id, {
            reason: 'insufficient_soc_approvals',
          });
          return { error: 'insufficient_soc_approvals', status: 409 };
        }
        if (await killSwitchRepo.isKillSwitchActiveForTenant(ctx)) {
          await appendAudit(auditRepo, ctx, 'high_scale.start_gate_denied', 'high_scale_request', id, {
            reason: 'kill_switch_active',
          });
          return { error: 'kill_switch_active', status: 409 };
        }
        if (!req.scheduled_window?.window_start || !req.scheduled_window?.window_end) {
          await appendAudit(auditRepo, ctx, 'high_scale.start_gate_denied', 'high_scale_request', id, {
            reason: 'missing_schedule_window',
          });
          return { error: 'missing_schedule_window', status: 409 };
        }
        if (!isWithinScheduledWindow(req.scheduled_window)) {
          await appendAudit(auditRepo, ctx, 'high_scale.start_gate_denied', 'high_scale_request', id, {
            reason: 'outside_schedule_window',
            window_start: req.scheduled_window.window_start,
            window_end: req.scheduled_window.window_end,
          });
          return { error: 'outside_schedule_window', status: 409 };
        }
        const scope = await validateTargetScope(coreCatalog, ctx, req.target_group_id);
        if (scope.error) {
          await appendAudit(auditRepo, ctx, 'high_scale.start_gate_denied', 'high_scale_request', id, {
            reason: scope.error,
          });
          return { error: scope.error, status: scope.status };
        }
        const currentScope = computeScopeHashFromTargets(req.target_group_id, scope.targets);
        if (currentScope !== req.scope_hash) {
          await appendAudit(auditRepo, ctx, 'high_scale.start_gate_denied', 'high_scale_request', id, {
            reason: 'scope_hash_mismatch',
            expected: req.scope_hash,
            actual: currentScope,
          });
          return { error: 'scope_hash_mismatch', status: 409 };
        }
        const adapterGate = evaluateHighScaleAdapterStartGate(metadata.adapter_mode);
        if (adapterGate) {
          await appendAudit(auditRepo, ctx, 'high_scale.start_gate_denied', 'high_scale_request', id, {
            reason: adapterGate.error,
          });
          return adapterGate;
        }
        applyDryRunAdapterStart(req);
        await appendAudit(auditRepo, ctx, 'high_scale.adapter_stub_started', 'high_scale_request', id, {
          note: 'Governed dry-run adapter — no traffic generator executed.',
          ...metadata,
        });
      }

      if (action === 'stop') {
        applyDryRunAdapterStop(req, metadata.reason);
        await appendAudit(auditRepo, ctx, 'high_scale.adapter_stub_stopped', 'high_scale_request', id, {
          reason: metadata.reason,
        });
        await appendAudit(auditRepo, ctx, 'high_scale.stop', 'high_scale_request', id, metadata);
      }

      req.state = resolvedState;
      req.audit_trail = [...(req.audit_trail ?? []), {
        action,
        at: nowFn().toISOString(),
        by: ctx.userId,
        metadata,
      }];

      if (action === 'start') {
        await appendAudit(auditRepo, ctx, 'high_scale.start', 'high_scale_request', id, metadata);
      } else if (!['schedule', 'approve', 'stop'].includes(action)) {
        await appendAudit(auditRepo, ctx, `high_scale.${action}`, 'high_scale_request', id, metadata);
      }

      let updated = await repo.updateHighScaleRequest(ctx, id, {
        state: req.state,
        audit_trail: req.audit_trail,
        soc_approvals: req.soc_approvals,
        scope_hash: req.scope_hash,
        scheduled_window: req.scheduled_window,
        adapter: req.adapter,
        updated_at: nowFn().toISOString(),
      });

      if (
        action === 'approve'
        && updated?.state === 'under_review'
        && distinctSocApprovalCount(updated) >= 2
        && !updated.scope_hash
      ) {
        const scope = await validateTargetScope(coreCatalog, ctx, updated.target_group_id);
        if (!scope.error) {
          const scopeHash = computeScopeHashFromTargets(updated.target_group_id, scope.targets);
          updated = await repo.updateHighScaleRequest(ctx, id, {
            state: 'approved',
            scope_hash: scopeHash,
            soc_approvals: updated.soc_approvals,
            audit_trail: [
              ...(updated.audit_trail ?? []),
              {
                action: 'approve_promoted_after_concurrent_soc_merge',
                at: nowFn().toISOString(),
                by: ctx.userId,
                metadata: { scope_hash: scopeHash },
              },
            ],
            updated_at: nowFn().toISOString(),
          });
          await appendAudit(auditRepo, ctx, 'high_scale.approved', 'high_scale_request', id, {
            scope_hash: scopeHash,
            concurrent_soc_merge: true,
          });
        }
      }

      incMetric('high_scale_transitions_total');
      await notifyStateChangeOptional(notifications, ctx, updated, action);
      return updated;
    },

    async setKillSwitch(ctx, active, reason) {
      let stoppedRequestIds = [];
      let cancelledRunIds = [];
      let cancelledProbeJobIds = [];
      if (active) {
        const running = await repo.listRunningHighScaleRequests(ctx);
        for (const req of running) {
          applyDryRunAdapterStop(req, reason ?? 'kill_switch');
          req.state = 'stopped';
          req.audit_trail = [
            ...(req.audit_trail ?? []),
            {
              action: 'kill_switch_auto_stop',
              at: nowFn().toISOString(),
              by: ctx.userId,
              metadata: { reason: reason ?? null },
            },
          ];
          await repo.updateHighScaleRequest(ctx, req.id, {
            state: 'stopped',
            adapter: req.adapter,
            audit_trail: req.audit_trail,
            updated_at: nowFn().toISOString(),
          });
          await appendAudit(auditRepo, ctx, 'high_scale.adapter_stub_stopped', 'high_scale_request', req.id, {
            reason: reason ?? 'kill_switch',
          });
          await appendAudit(auditRepo, ctx, 'high_scale.kill_switch_auto_stop', 'high_scale_request', req.id, {
            reason: reason ?? null,
          });
          stoppedRequestIds.push(req.id);
          await notifyStateChangeOptional(notifications, ctx, req, 'stop');
        }
        cancelledRunIds = await autoCancelActiveSafeRunsForKillSwitch(
          ctx,
          reason,
          validationEvidence,
          auditRepo,
        );
        const cancelAt = nowFn().toISOString();
        const cancelledJobs = await probeJobsRepo.cancelOpenProbeJobsForTestRuns(
          ctx,
          cancelledRunIds,
          cancelAt,
        );
        for (const job of cancelledJobs) {
          cancelledProbeJobIds.push(job.id);
          await appendAudit(auditRepo, ctx, 'probe_job.kill_switch_auto_cancel', 'probe_job', job.id, {
            reason: reason ?? null,
            test_run_id: job.test_run_id,
          });
        }
      }
      const now = nowFn().toISOString();
      const record = await killSwitchRepo.upsertKillSwitch(ctx, {
        active,
        reason: reason ?? null,
        updated_by: ctx.userId,
        updated_at: now,
      });
      await appendAudit(auditRepo, ctx, active ? 'soc.kill_switch.activated' : 'soc.kill_switch.cleared', 'platform', 'kill_switch', {
        reason,
        tenant_id: ctx.tenantId,
        stopped_request_ids: stoppedRequestIds,
        cancelled_run_ids: cancelledRunIds,
        cancelled_probe_job_ids: cancelledProbeJobIds,
      });
      return {
        ...record,
        stopped_request_ids: stoppedRequestIds,
        cancelled_run_ids: cancelledRunIds,
        cancelled_probe_job_ids: cancelledProbeJobIds,
      };
    },
  };
}
