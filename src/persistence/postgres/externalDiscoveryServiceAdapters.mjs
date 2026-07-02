import { createHash } from 'node:crypto';
import { loadRuntimeConfig } from '../../config.mjs';
import {
  canTransition,
  createCandidate as normalizeCandidate,
  createEntity as normalizeEntity,
  isDeclaredOnlyDiscoveryMode,
  validateCandidate,
} from '../../contracts/externalDiscovery.mjs';
import { newId } from '../../lib/ids.mjs';
import { redactObject } from '../../lib/redact.mjs';
import { createAuditRepository } from './auditRepository.mjs';
import { createExternalDiscoveryRepository } from './externalDiscoveryRepository.mjs';

const INBOX_STATES = new Set(['candidate', 'needs_review']);
const APPROVABLE_STATES = new Set(['candidate', 'needs_review']);
const REJECTABLE_STATES = new Set(['discovered', 'candidate', 'needs_review']);

function contractError(err, fallbackStatus = 400) {
  return {
    error: err.code ?? 'invalid_request',
    status: fallbackStatus,
    message: err.message,
  };
}

function discoveryFeatureDisabled() {
  return loadRuntimeConfig().featureFlags.externalDiscoveryEnabled !== true;
}

function featureDisabledResponse() {
  return { error: 'discovery_feature_disabled', status: 404 };
}

function normalizeHostname(hostname) {
  return String(hostname ?? '').trim().toLowerCase();
}

function computeCandidateScopeHash(tenantId, candidate) {
  const payload = [
    tenantId,
    candidate.hostname,
    candidate.source_type,
    candidate.source_ref,
  ].join('|');
  return createHash('sha256').update(payload, 'utf8').digest('hex');
}

function formatEntity(record) {
  return {
    id: record.id,
    entity_id: record.entity_id ?? record.id,
    entity_type: record.entity_type,
    name: record.name,
    display_name: record.display_name,
    root_domains: record.root_domains ?? [],
    country: record.country,
    confidence: record.confidence,
    source: record.source,
    ...(record.parent_entity_id ? { parent_entity_id: record.parent_entity_id } : {}),
    created_at: record.created_at,
    ...(record.updated_at ? { updated_at: record.updated_at } : {}),
  };
}

function formatCandidate(record) {
  return {
    id: record.id,
    candidate_id: record.candidate_id ?? record.id,
    hostname: record.hostname,
    source_type: record.source_type,
    source_ref: record.source_ref,
    confidence: record.confidence,
    ownership_status: record.ownership_status,
    approval_status: record.approval_status,
    state: record.state,
    first_seen_at: record.first_seen_at,
    last_seen_at: record.last_seen_at,
    evidence_summary: record.evidence_summary ?? {},
    ...(record.entity_id ? { entity_id: record.entity_id } : {}),
    ...(record.scope_hash ? { scope_hash: record.scope_hash } : {}),
    ...(record.rejection_reason ? { rejection_reason: record.rejection_reason } : {}),
    created_at: record.created_at,
    ...(record.updated_at ? { updated_at: record.updated_at } : {}),
  };
}

function resolveDiscoveryMode(ctx, body = {}) {
  const fromBody = typeof body.discovery_mode === 'string' ? body.discovery_mode.trim() : '';
  if (fromBody) return fromBody;
  const fromCtx = typeof ctx.discoveryMode === 'string' ? ctx.discoveryMode.trim() : '';
  if (fromCtx) return fromCtx;
  return 'D0_declared_only';
}

function approvalStatusForState(state) {
  if (state === 'approved_target') return 'approved';
  if (state === 'rejected') return 'rejected';
  if (state === 'exception') return 'exception';
  return null;
}

/**
 * @param {import('pg').Pool} pool
 * @param {{
 *   now?: () => Date,
 *   newId?: typeof newId,
 * }} [options]
 */
export function createPostgresExternalDiscoveryServices(pool, options = {}) {
  const discoveryRepo = createExternalDiscoveryRepository(pool);
  const auditRepo = createAuditRepository(pool);
  const nowFn = options.now ?? (() => new Date());
  const newIdFn = options.newId ?? newId;

  return {
    async listEntities(ctx) {
      if (discoveryFeatureDisabled()) return featureDisabledResponse();
      const items = await discoveryRepo.listEntities(ctx);
      return items.map((entry) => formatEntity(entry));
    },

    async createEntity(ctx, body) {
      if (discoveryFeatureDisabled()) return featureDisabledResponse();
      try {
        validateCandidate(body);
        const normalized = normalizeEntity(body);
        const existing = (await discoveryRepo.listEntities(ctx)).find(
          (entry) => entry.entity_id === normalized.entity_id || entry.id === normalized.entity_id,
        );
        if (existing) {
          return {
            error: 'duplicate_entity',
            status: 409,
            message: 'entity_id already exists for tenant.',
          };
        }
        const now = nowFn().toISOString();
        const id = newIdFn('id');
        const record = await discoveryRepo.insertEntity(ctx, {
          id,
          tenant_id: ctx.tenantId,
          ...normalized,
          created_at: now,
          updated_at: now,
        });
        await auditRepo.appendAuditEvent({
          tenant_id: ctx.tenantId,
          actor_user_id: ctx.userId,
          actor_role: ctx.role,
          action: 'discovery.entity.created',
          resource_type: 'discovery_entity',
          resource_id: id,
          metadata: redactObject({
            entity_id: normalized.entity_id,
            entity_type: normalized.entity_type,
          }),
        });
        return { entity: formatEntity({ ...record, entity_id: normalized.entity_id }) };
      } catch (err) {
        return contractError(err);
      }
    },

    async listCandidates(ctx) {
      if (discoveryFeatureDisabled()) return featureDisabledResponse();
      const items = await discoveryRepo.listCandidates(ctx);
      return items.map((entry) => formatCandidate(entry));
    },

    async createCandidate(ctx, body) {
      if (discoveryFeatureDisabled()) return featureDisabledResponse();
      try {
        validateCandidate(body);
        const normalized = normalizeCandidate(body);
        const now = nowFn().toISOString();
        const id = newIdFn('id');
        const result = await discoveryRepo.insertCandidate(ctx, {
          id,
          tenant_id: ctx.tenantId,
          ...normalized,
          state: normalized.state ?? 'candidate',
          created_at: now,
          updated_at: now,
        });
        if (!result.deduplicated) {
          await auditRepo.appendAuditEvent({
            tenant_id: ctx.tenantId,
            actor_user_id: ctx.userId,
            actor_role: ctx.role,
            action: 'discovery.candidate.created',
            resource_type: 'discovery_candidate',
            resource_id: id,
            metadata: redactObject({
              hostname: normalized.hostname,
              source_type: normalized.source_type,
              state: normalized.state ?? 'candidate',
            }),
          });
        }
        return { candidate: formatCandidate(result.candidate), deduplicated: result.deduplicated };
      } catch (err) {
        return contractError(err);
      }
    },

    async approveCandidateToTarget(ctx, id, body = {}) {
      if (discoveryFeatureDisabled()) return featureDisabledResponse();
      const candidate = await discoveryRepo.getCandidate(ctx, id);
      if (!candidate) {
        return { error: 'discovery_candidate_not_found', status: 404 };
      }
      if (!APPROVABLE_STATES.has(candidate.state)) {
        return {
          error: 'invalid_discovery_transition',
          status: 400,
          message: `Cannot approve candidate in state ${candidate.state}.`,
        };
      }
      if (!canTransition(candidate.state, 'approved_target')) {
        return {
          error: 'invalid_discovery_transition',
          status: 400,
          message: `Transition from ${candidate.state} to approved_target is not allowed.`,
        };
      }

      const now = nowFn().toISOString();
      const scope_hash =
        typeof body.scope_hash === 'string' && body.scope_hash.trim()
          ? body.scope_hash.trim()
          : computeCandidateScopeHash(ctx.tenantId, candidate);
      const updated = await discoveryRepo.updateCandidateState(ctx, id, {
        state: 'approved_target',
        approval_status: 'approved',
        scope_hash,
        updated_at: now,
      });

      await auditRepo.appendAuditEvent({
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId,
        actor_role: ctx.role,
        action: 'discovery.candidate.approved',
        resource_type: 'discovery_candidate',
        resource_id: candidate.id,
        metadata: redactObject({
          actor: ctx.userId,
          scope_hash,
          source_summary: {
            source_type: candidate.source_type,
            source_ref: candidate.source_ref,
            confidence: candidate.confidence,
            ...(typeof body.source_summary === 'object' && body.source_summary !== null
              ? body.source_summary
              : {}),
          },
          hostname: candidate.hostname,
        }),
      });
      return { candidate: formatCandidate(updated) };
    },

    async rejectCandidate(ctx, id, body = {}) {
      if (discoveryFeatureDisabled()) return featureDisabledResponse();
      const candidate = await discoveryRepo.getCandidate(ctx, id);
      if (!candidate) {
        return { error: 'discovery_candidate_not_found', status: 404 };
      }
      if (!REJECTABLE_STATES.has(candidate.state)) {
        return {
          error: 'invalid_discovery_transition',
          status: 400,
          message: `Cannot reject candidate in state ${candidate.state}.`,
        };
      }
      if (!canTransition(candidate.state, 'rejected')) {
        return {
          error: 'invalid_discovery_transition',
          status: 400,
          message: `Transition from ${candidate.state} to rejected is not allowed.`,
        };
      }

      const now = nowFn().toISOString();
      const rejection_reason =
        typeof body.reason === 'string' && body.reason.trim() ? body.reason.trim() : 'out_of_scope';
      const updated = await discoveryRepo.updateCandidateState(ctx, id, {
        state: 'rejected',
        approval_status: 'rejected',
        rejection_reason,
        evidence_summary: {},
        updated_at: now,
      });

      await auditRepo.appendAuditEvent({
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId,
        actor_role: ctx.role,
        action: 'discovery.candidate.rejected',
        resource_type: 'discovery_candidate',
        resource_id: candidate.id,
        metadata: redactObject({ rejection_reason }),
      });
      return { candidate: formatCandidate(updated) };
    },

    async patchCandidateState(ctx, id, state, body = {}) {
      if (discoveryFeatureDisabled()) return featureDisabledResponse();
      const nextState = typeof state === 'string' ? state.trim() : '';
      if (!nextState) {
        return { error: 'invalid_request', status: 400, message: 'state is required.' };
      }

      const candidate = await discoveryRepo.getCandidate(ctx, id);
      if (!candidate) {
        return { error: 'discovery_candidate_not_found', status: 404 };
      }

      if (nextState === 'tested' && candidate.state !== 'approved_target') {
        return {
          error: 'discovery_candidate_not_approved',
          status: 403,
          message: 'Unapproved candidates cannot be tested.',
        };
      }

      if (!canTransition(candidate.state, nextState)) {
        return {
          error: 'invalid_discovery_transition',
          status: 400,
          message: `Transition from ${candidate.state} to ${nextState} is not allowed.`,
        };
      }

      const now = nowFn().toISOString();
      const previousState = candidate.state;
      const updates = {
        state: nextState,
        updated_at: now,
      };
      const approvalStatus = approvalStatusForState(nextState);
      if (approvalStatus) {
        updates.approval_status = approvalStatus;
      }
      if (nextState === 'rejected') {
        updates.rejection_reason =
          typeof body.reason === 'string' && body.reason.trim() ? body.reason.trim() : 'out_of_scope';
        updates.evidence_summary = {};
      }

      const updated = await discoveryRepo.updateCandidateState(ctx, id, updates);
      await auditRepo.appendAuditEvent({
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId,
        actor_role: ctx.role,
        action: 'discovery.candidate.state_changed',
        resource_type: 'discovery_candidate',
        resource_id: candidate.id,
        metadata: redactObject({
          previous_state: previousState,
          state: nextState,
          ...(typeof body.note === 'string' && body.note.trim() ? { note: body.note.trim() } : {}),
        }),
      });
      return { candidate: formatCandidate(updated) };
    },

    async getDiscoveryInbox(ctx) {
      if (discoveryFeatureDisabled()) return featureDisabledResponse();
      const items = (await discoveryRepo.listCandidates(ctx))
        .filter((candidate) => INBOX_STATES.has(candidate.state))
        .map((candidate) => formatCandidate(candidate));
      return { items, count: items.length };
    },

    canImportCandidateToTargetGroup(candidate) {
      return candidate?.state === 'approved_target';
    },

    declaredOnlyModeActive(ctx, body = {}) {
      return isDeclaredOnlyDiscoveryMode(resolveDiscoveryMode(ctx, body));
    },
  };
}