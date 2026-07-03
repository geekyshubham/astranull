import { createHash } from 'node:crypto';
import { loadRuntimeConfig } from '../../config.mjs';
import {
  buildDiscoveryReportSummary,
  canTransition,
  createCandidate as normalizeCandidate,
  createEntity as normalizeEntity,
  isDeclaredOnlyDiscoveryMode,
  validateCandidate,
} from '../../contracts/externalDiscovery.mjs';
import { parsePassiveDiscoveryRecords } from '../../lib/discoverySources.mjs';
import { newId } from '../../lib/ids.mjs';
import { redactObject } from '../../lib/redact.mjs';
import { normalizeWafAssetInput } from '../../contracts/wafPosture.mjs';
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
    ...(record.approved_target_id ? { approved_target_id: record.approved_target_id } : {}),
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

function parseImportBoolean(value, fallback = true) {
  if (value === undefined || value === null) return fallback;
  if (typeof value === 'boolean') return value;
  if (value === '1' || value === 1 || value === 'true') return true;
  if (value === '0' || value === 0 || value === 'false') return false;
  return fallback;
}

function approvalStatusForState(state) {
  if (state === 'approved_target') return 'approved';
  if (state === 'rejected') return 'rejected';
  if (state === 'exception') return 'exception';
  return null;
}

/**
 * @param {{
 *   coreCatalog?: Record<string, unknown>,
 *   wafPosture?: Record<string, unknown>,
 * }} repositories
 * @param {{
 *   pool?: import('pg').Pool,
 *   now?: () => Date,
 *   newId?: typeof newId,
 * }} [options]
 */
export function createPostgresExternalDiscoveryServices(repositories, options = {}) {
  const pool = options.pool;
  if (!pool) {
    throw new Error('Postgres external discovery service adapter requires options.pool.');
  }
  const coreCatalog = repositories?.coreCatalog;
  const wafRepo = repositories?.wafPosture;
  if (!coreCatalog || typeof coreCatalog.addTarget !== 'function') {
    throw new Error('Postgres external discovery service adapter requires coreCatalog.addTarget().');
  }
  if (!wafRepo || typeof wafRepo.createWafAsset !== 'function') {
    throw new Error('Postgres external discovery service adapter requires wafPosture.createWafAsset().');
  }
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
        const id = normalized.entity_id;
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

    async ingestDiscoveryCandidates(ctx, source, records) {
      if (discoveryFeatureDisabled()) return featureDisabledResponse();
      try {
        const parsedRecords = parsePassiveDiscoveryRecords(source, records);
        const now = nowFn().toISOString();
        let created = 0;
        let updated = 0;
        const candidates = [];

        for (const parsed of parsedRecords) {
          const existing = await discoveryRepo.findCandidateByHostname(ctx, parsed.hostname);
          if (existing) {
            const mergedEvidence = {
              ...(existing.evidence_summary ?? {}),
              ...parsed.evidence_summary,
              last_observed_at: parsed.last_seen_at,
            };
            const updatedRecord = await discoveryRepo.updateCandidateState(ctx, existing.id, {
              last_seen_at: parsed.last_seen_at,
              confidence: Math.max(existing.confidence ?? 0, parsed.confidence),
              evidence_summary: mergedEvidence,
              updated_at: now,
            });
            updated += 1;
            candidates.push(formatCandidate(updatedRecord));
            continue;
          }

          const id = newIdFn('id');
          const result = await discoveryRepo.insertCandidate(ctx, {
            id,
            tenant_id: ctx.tenantId,
            candidate_id: newIdFn('id'),
            hostname: parsed.hostname,
            source_type: parsed.source_type,
            source_ref: parsed.source_ref,
            confidence: parsed.confidence,
            ownership_status: parsed.ownership_status,
            approval_status: parsed.approval_status,
            first_seen_at: parsed.first_seen_at,
            last_seen_at: parsed.last_seen_at,
            evidence_summary: parsed.evidence_summary,
            state: parsed.state,
            created_at: now,
            updated_at: now,
          });
          created += 1;
          candidates.push(formatCandidate(result.candidate));
        }

        await auditRepo.appendAuditEvent({
          tenant_id: ctx.tenantId,
          actor_user_id: ctx.userId,
          actor_role: ctx.role,
          action: 'discovery.source_ingested',
          resource_type: 'discovery_source_batch',
          resource_id: String(source),
          metadata: redactObject({
            source,
            record_count: parsedRecords.length,
            created_count: created,
            updated_count: updated,
          }),
        });

        return {
          source,
          ingested: parsedRecords.length,
          created,
          updated,
          candidates,
        };
      } catch (err) {
        return contractError(err);
      }
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

    async getDiscoveryReportSummary(ctx) {
      if (discoveryFeatureDisabled()) return featureDisabledResponse();
      const candidates = await discoveryRepo.listCandidates(ctx);
      return {
        summary: buildDiscoveryReportSummary(candidates, {
          generated_at: nowFn().toISOString(),
        }),
      };
    },

    async importCandidateToTargetGroup(ctx, id, body = {}) {
      if (discoveryFeatureDisabled()) return featureDisabledResponse();
      const candidate = await discoveryRepo.getCandidate(ctx, id);
      if (!candidate) {
        return { error: 'discovery_candidate_not_found', status: 404 };
      }
      if (candidate.approved_target_id || candidate.evidence_summary?.imported_target_group_id) {
        return {
          error: 'discovery_candidate_already_imported',
          status: 409,
          message: 'Candidate has already been imported to a declared target.',
        };
      }
      if (!this.canImportCandidateToTargetGroup(candidate)) {
        return {
          error: 'discovery_candidate_not_approved',
          status: 403,
          message: 'Candidate must be approved before import into a target group.',
        };
      }

      const targetGroupId =
        typeof body.target_group_id === 'string' ? body.target_group_id.trim() : '';
      if (!targetGroupId) {
        return {
          error: 'invalid_request',
          status: 400,
          message: 'target_group_id is required.',
        };
      }

      const targetGroup = await coreCatalog.getTargetGroup(ctx, targetGroupId);
      if (!targetGroup) {
        return {
          error: 'target_group_not_found',
          status: 404,
          message: 'Target group not found for tenant.',
        };
      }

      const environmentId =
        typeof body.environment_id === 'string' && body.environment_id.trim()
          ? body.environment_id.trim()
          : null;
      if (environmentId && targetGroup.environment_id !== environmentId) {
        return {
          error: 'invalid_request',
          status: 400,
          message: 'environment_id does not match target group environment.',
        };
      }

      const hostname = normalizeHostname(candidate.hostname);
      if (!hostname) {
        return {
          error: 'invalid_request',
          status: 400,
          message: 'Candidate hostname is required for import.',
        };
      }

      const now = nowFn().toISOString();
      const target = await coreCatalog.addTarget(ctx, targetGroupId, {
        kind: 'fqdn',
        value: hostname,
      });
      if (!target) {
        return {
          error: 'target_group_not_found',
          status: 404,
          message: 'Target group not found for tenant.',
        };
      }

      let wafAsset = null;
      const createWafAssetRequested = parseImportBoolean(body.create_waf_asset, true);
      if (createWafAssetRequested) {
        try {
          const normalized = normalizeWafAssetInput({
            target_group_id: targetGroupId,
            target_id: target.id,
            hostname,
            expected_waf_required: true,
          });
          const wafAssetId = newIdFn('id');
          wafAsset = await wafRepo.createWafAsset(ctx, {
            id: wafAssetId,
            tenant_id: ctx.tenantId,
            target_group_id: normalized.target_group_id,
            target_id: normalized.target_id,
            environment_id: targetGroup.environment_id ?? null,
            canonical_url: normalized.canonical_url,
            asset_kind: normalized.asset_kind ?? 'unknown',
            expected_waf_required: normalized.expected_waf_required,
            expected_vendor_hint: normalized.expected_vendor_hint ?? null,
            business_criticality: normalized.business_criticality ?? 'medium',
            traffic_tier: normalized.traffic_tier ?? 'unknown',
            compliance_tags: normalized.compliance_tags ?? [],
            owner_hint: normalized.owner_hint ?? null,
            created_at: now,
            updated_at: now,
          });
          await auditRepo.appendAuditEvent({
            tenant_id: ctx.tenantId,
            actor_user_id: ctx.userId,
            actor_role: ctx.role,
            action: 'waf.asset.created',
            resource_type: 'waf_asset',
            resource_id: wafAsset.id,
            metadata: redactObject({
              target_group_id: wafAsset.target_group_id,
              target_id: wafAsset.target_id,
            }),
          });
        } catch (err) {
          return contractError(err);
        }
      }

      const updated = await discoveryRepo.updateCandidateState(ctx, id, {
        approval_status: 'approved',
        approved_target_id: target.id,
        evidence_summary: {
          ...(candidate.evidence_summary ?? {}),
          state: 'approved_target',
          imported_at: now,
          imported_target_group_id: targetGroupId,
          ...(environmentId ? { imported_environment_id: environmentId } : {}),
        },
        updated_at: now,
      });

      await auditRepo.appendAuditEvent({
        tenant_id: ctx.tenantId,
        actor_user_id: ctx.userId,
        actor_role: ctx.role,
        action: 'discovery.candidate_imported',
        resource_type: 'discovery_candidate',
        resource_id: candidate.id,
        metadata: redactObject({
          hostname: candidate.hostname,
          target_group_id: targetGroupId,
          target_id: target.id,
          ...(environmentId ? { environment_id: environmentId } : {}),
          ...(wafAsset ? { waf_asset_id: wafAsset.id } : {}),
          source_type: candidate.source_type,
          source_ref: candidate.source_ref,
        }),
      });

      return {
        candidate: formatCandidate(updated),
        target,
        ...(wafAsset ? { waf_asset: wafAsset } : {}),
      };
    },

    canImportCandidateToTargetGroup(candidate) {
      return candidate?.state === 'approved_target' && !candidate?.approved_target_id;
    },

    declaredOnlyModeActive(ctx, body = {}) {
      return isDeclaredOnlyDiscoveryMode(resolveDiscoveryMode(ctx, body));
    },
  };
}
