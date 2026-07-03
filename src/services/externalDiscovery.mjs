import { createHash } from 'node:crypto';
import { audit } from '../audit.mjs';
import { loadRuntimeConfig } from '../config.mjs';
import {
  buildDiscoveryReportSummary,
  canTransition,
  createCandidate as normalizeCandidate,
  createEntity as normalizeEntity,
  isDeclaredOnlyDiscoveryMode,
  validateCandidate,
} from '../contracts/externalDiscovery.mjs';
import { parsePassiveDiscoveryRecords } from '../lib/discoverySources.mjs';
import { newId } from '../lib/ids.mjs';
import { getStore, persistStore } from '../store.mjs';
import { addTarget } from './targetGroups.mjs';
import { createWafAsset } from './wafPosture.mjs';

const INBOX_STATES = new Set(['candidate', 'needs_review']);
const APPROVABLE_STATES = new Set(['candidate', 'needs_review']);
const REJECTABLE_STATES = new Set(['discovered', 'candidate', 'needs_review']);

function ensureStoreShape() {
  const store = getStore();
  if (!Array.isArray(store.discoveryEntities)) store.discoveryEntities = [];
  if (!Array.isArray(store.discoveryCandidates)) store.discoveryCandidates = [];
  return store;
}

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

function guardDiscoveryEnabled() {
  if (discoveryFeatureDisabled()) {
    return featureDisabledResponse();
  }
  return null;
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
    entity_id: record.entity_id,
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
    candidate_id: record.candidate_id,
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

function findCandidate(ctx, id) {
  ensureStoreShape();
  return (
    getStore().discoveryCandidates.find(
      (c) => c.id === id && c.tenant_id === ctx.tenantId,
    ) ?? null
  );
}

function parseImportBoolean(value, fallback = true) {
  if (value === undefined || value === null) return fallback;
  if (typeof value === 'boolean') return value;
  if (value === '1' || value === 1 || value === 'true') return true;
  if (value === '0' || value === 0 || value === 'false') return false;
  return fallback;
}

function findTargetGroup(ctx, targetGroupId) {
  return (
    getStore().targetGroups.find(
      (g) => g.id === targetGroupId && g.tenant_id === ctx.tenantId,
    ) ?? null
  );
}

function findCandidateByHostname(ctx, hostname) {
  ensureStoreShape();
  const normalized = normalizeHostname(hostname);
  return (
    getStore().discoveryCandidates.find(
      (c) => c.tenant_id === ctx.tenantId && normalizeHostname(c.hostname) === normalized,
    ) ?? null
  );
}

function resolveDiscoveryMode(ctx, body = {}) {
  const fromBody = typeof body.discovery_mode === 'string' ? body.discovery_mode.trim() : '';
  if (fromBody) return fromBody;
  const fromCtx = typeof ctx.discoveryMode === 'string' ? ctx.discoveryMode.trim() : '';
  if (fromCtx) return fromCtx;
  return 'D0_declared_only';
}

export function listEntities(ctx) {
  const disabled = guardDiscoveryEnabled();
  if (disabled) return disabled;
  ensureStoreShape();
  return getStore()
    .discoveryEntities.filter((e) => e.tenant_id === ctx.tenantId)
    .map((e) => formatEntity(e));
}

export function createEntity(ctx, body) {
  const disabled = guardDiscoveryEnabled();
  if (disabled) return disabled;
  ensureStoreShape();
  try {
    validateCandidate(body);
    const normalized = normalizeEntity(body);
    const existing = getStore().discoveryEntities.find(
      (e) => e.tenant_id === ctx.tenantId && e.entity_id === normalized.entity_id,
    );
    if (existing) {
      return { error: 'duplicate_entity', status: 409, message: 'entity_id already exists for tenant.' };
    }
    const now = new Date().toISOString();
    const id = newId('id');
    const record = {
      id,
      tenant_id: ctx.tenantId,
      ...normalized,
      created_at: now,
      updated_at: now,
    };
    getStore().discoveryEntities.push(record);
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'discovery.entity.created',
      resource_type: 'discovery_entity',
      resource_id: id,
      metadata: {
        entity_id: normalized.entity_id,
        entity_type: normalized.entity_type,
      },
    });
    persistStore();
    return { entity: formatEntity(record) };
  } catch (err) {
    return contractError(err);
  }
}

export function listCandidates(ctx) {
  const disabled = guardDiscoveryEnabled();
  if (disabled) return disabled;
  ensureStoreShape();
  return getStore()
    .discoveryCandidates.filter((c) => c.tenant_id === ctx.tenantId)
    .map((c) => formatCandidate(c));
}

export function ingestDiscoveryCandidates(ctx, source, records) {
  const disabled = guardDiscoveryEnabled();
  if (disabled) return disabled;
  ensureStoreShape();
  try {
    const parsedRecords = parsePassiveDiscoveryRecords(source, records);
    const now = new Date().toISOString();
    const beforeTargets = getStore().targets?.length ?? 0;
    const beforeGroups = getStore().targetGroups?.length ?? 0;
    let created = 0;
    let updated = 0;
    const candidates = [];

    for (const parsed of parsedRecords) {
      const existing = findCandidateByHostname(ctx, parsed.hostname);
      if (existing) {
        existing.last_seen_at = parsed.last_seen_at;
        existing.confidence = Math.max(existing.confidence ?? 0, parsed.confidence);
        existing.evidence_summary = {
          ...(existing.evidence_summary ?? {}),
          ...parsed.evidence_summary,
          last_observed_at: parsed.last_seen_at,
        };
        existing.updated_at = now;
        updated += 1;
        candidates.push(formatCandidate(existing));
        continue;
      }

      const id = newId('id');
      const record = {
        id,
        tenant_id: ctx.tenantId,
        candidate_id: newId('id'),
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
      };
      getStore().discoveryCandidates.push(record);
      created += 1;
      candidates.push(formatCandidate(record));
    }

    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'discovery.source_ingested',
      resource_type: 'discovery_source_batch',
      resource_id: String(source),
      metadata: {
        source,
        record_count: parsedRecords.length,
        created_count: created,
        updated_count: updated,
      },
    });
    persistStore();

    const afterTargets = getStore().targets?.length ?? 0;
    const afterGroups = getStore().targetGroups?.length ?? 0;
    if (afterTargets !== beforeTargets || afterGroups !== beforeGroups) {
      return {
        error: 'discovery_ingest_target_mutation_forbidden',
        status: 500,
        message: 'Passive discovery ingest must not create targets automatically.',
      };
    }

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
}

export function createCandidate(ctx, body) {
  const disabled = guardDiscoveryEnabled();
  if (disabled) return disabled;
  ensureStoreShape();
  try {
    validateCandidate(body);
    const normalized = normalizeCandidate(body);
    const existing = findCandidateByHostname(ctx, normalized.hostname);
    const now = new Date().toISOString();
    if (existing) {
      existing.last_seen_at = normalized.last_seen_at;
      existing.confidence = normalized.confidence;
      existing.evidence_summary = normalized.evidence_summary;
      existing.updated_at = now;
      persistStore();
      return { candidate: formatCandidate(existing), deduplicated: true };
    }

    const id = newId('id');
    const record = {
      id,
      tenant_id: ctx.tenantId,
      ...normalized,
      state: normalized.state ?? 'candidate',
      created_at: now,
      updated_at: now,
    };
    getStore().discoveryCandidates.push(record);
    audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'discovery.candidate.created',
      resource_type: 'discovery_candidate',
      resource_id: id,
      metadata: {
        hostname: record.hostname,
        source_type: record.source_type,
        state: record.state,
      },
    });
    persistStore();
    return { candidate: formatCandidate(record) };
  } catch (err) {
    return contractError(err);
  }
}

export function approveCandidateToTarget(ctx, id, body = {}) {
  const disabled = guardDiscoveryEnabled();
  if (disabled) return disabled;
  ensureStoreShape();
  const candidate = findCandidate(ctx, id);
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

  const now = new Date().toISOString();
  const scope_hash =
    typeof body.scope_hash === 'string' && body.scope_hash.trim()
      ? body.scope_hash.trim()
      : computeCandidateScopeHash(ctx.tenantId, candidate);
  const source_summary = {
    source_type: candidate.source_type,
    source_ref: candidate.source_ref,
    confidence: candidate.confidence,
    ...(typeof body.source_summary === 'object' && body.source_summary !== null
      ? body.source_summary
      : {}),
  };

  candidate.state = 'approved_target';
  candidate.approval_status = 'approved';
  candidate.scope_hash = scope_hash;
  candidate.updated_at = now;

  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'discovery.candidate.approved',
    resource_type: 'discovery_candidate',
    resource_id: candidate.id,
    metadata: {
      actor: ctx.userId,
      scope_hash,
      source_summary,
      hostname: candidate.hostname,
    },
  });
  persistStore();
  return { candidate: formatCandidate(candidate) };
}

export function rejectCandidate(ctx, id, body = {}) {
  const disabled = guardDiscoveryEnabled();
  if (disabled) return disabled;
  ensureStoreShape();
  const candidate = findCandidate(ctx, id);
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

  const now = new Date().toISOString();
  candidate.state = 'rejected';
  candidate.approval_status = 'rejected';
  candidate.rejection_reason =
    typeof body.reason === 'string' && body.reason.trim() ? body.reason.trim() : 'out_of_scope';
  candidate.evidence_summary = {};
  candidate.updated_at = now;

  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'discovery.candidate.rejected',
    resource_type: 'discovery_candidate',
    resource_id: candidate.id,
    metadata: {
      rejection_reason: candidate.rejection_reason,
    },
  });
  persistStore();
  return { candidate: formatCandidate(candidate) };
}

export function patchCandidateState(ctx, id, state, body = {}) {
  const disabled = guardDiscoveryEnabled();
  if (disabled) return disabled;
  ensureStoreShape();

  const nextState = typeof state === 'string' ? state.trim() : '';
  if (!nextState) {
    return { error: 'invalid_request', status: 400, message: 'state is required.' };
  }

  const candidate = findCandidate(ctx, id);
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

  const now = new Date().toISOString();
  const previousState = candidate.state;
  candidate.state = nextState;
  candidate.updated_at = now;

  if (nextState === 'approved_target') {
    candidate.approval_status = 'approved';
  } else if (nextState === 'rejected') {
    candidate.approval_status = 'rejected';
    candidate.rejection_reason =
      typeof body.reason === 'string' && body.reason.trim() ? body.reason.trim() : 'out_of_scope';
    candidate.evidence_summary = {};
  } else if (nextState === 'exception') {
    candidate.approval_status = 'exception';
  }

  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'discovery.candidate.state_changed',
    resource_type: 'discovery_candidate',
    resource_id: candidate.id,
    metadata: {
      previous_state: previousState,
      state: nextState,
      ...(typeof body.note === 'string' && body.note.trim() ? { note: body.note.trim() } : {}),
    },
  });
  persistStore();
  return { candidate: formatCandidate(candidate) };
}

export function getDiscoveryInbox(ctx) {
  const disabled = guardDiscoveryEnabled();
  if (disabled) return disabled;
  ensureStoreShape();
  const items = getStore()
    .discoveryCandidates.filter(
      (c) => c.tenant_id === ctx.tenantId && INBOX_STATES.has(c.state),
    )
    .map((c) => formatCandidate(c));
  return { items, count: items.length };
}

export function getDiscoveryReportSummary(ctx) {
  const disabled = guardDiscoveryEnabled();
  if (disabled) return disabled;
  ensureStoreShape();
  const candidates = getStore().discoveryCandidates.filter(
    (c) => c.tenant_id === ctx.tenantId,
  );
  return {
    summary: buildDiscoveryReportSummary(candidates),
  };
}

export function importCandidateToTargetGroup(ctx, id, body = {}) {
  const disabled = guardDiscoveryEnabled();
  if (disabled) return disabled;
  ensureStoreShape();

  const candidate = findCandidate(ctx, id);
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
  if (!canImportCandidateToTargetGroup(candidate)) {
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

  const targetGroup = findTargetGroup(ctx, targetGroupId);
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

  const target = addTarget(ctx, targetGroupId, {
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
    const wafResult = createWafAsset(ctx, {
      target_group_id: targetGroupId,
      target_id: target.id,
      hostname,
      expected_waf_required: true,
    });
    if (wafResult.error) {
      return wafResult;
    }
    wafAsset = wafResult.asset;
  }

  const now = new Date().toISOString();
  candidate.approved_target_id = target.id;
  candidate.approval_status = 'approved';
  candidate.state = 'approved_target';
  candidate.evidence_summary = {
    ...(candidate.evidence_summary ?? {}),
    imported_at: now,
    imported_target_group_id: targetGroupId,
    ...(environmentId ? { imported_environment_id: environmentId } : {}),
  };
  candidate.updated_at = now;

  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'discovery.candidate_imported',
    resource_type: 'discovery_candidate',
    resource_id: candidate.id,
    metadata: {
      hostname: candidate.hostname,
      target_group_id: targetGroupId,
      target_id: target.id,
      ...(environmentId ? { environment_id: environmentId } : {}),
      ...(wafAsset ? { waf_asset_id: wafAsset.id } : {}),
      source_type: candidate.source_type,
      source_ref: candidate.source_ref,
    },
  });
  persistStore();

  return {
    candidate: formatCandidate(candidate),
    target,
    ...(wafAsset ? { waf_asset: wafAsset } : {}),
  };
}

export function canImportCandidateToTargetGroup(candidate) {
  return candidate?.state === 'approved_target' && !candidate?.approved_target_id;
}

export function declaredOnlyModeActive(ctx, body = {}) {
  return isDeclaredOnlyDiscoveryMode(resolveDiscoveryMode(ctx, body));
}
