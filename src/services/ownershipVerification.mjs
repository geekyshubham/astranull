import { audit } from '../audit.mjs';
import { generateNonce, hashNonce } from '../lib/crypto.mjs';
import { newId } from '../lib/ids.mjs';
import { getStore, persistStore } from '../store.mjs';
import { createOwnershipChallengeJob } from './probeCoordinator.mjs';
import { isArchivedTargetGroup } from './targetGroups.mjs';

const OPEN_STATUSES = new Set(['challenge_sent', 'verified']);

function findTargetGroup(ctx, targetGroupId) {
  return getStore().targetGroups.find(
    (g) => g.id === targetGroupId && g.tenant_id === ctx.tenantId && !isArchivedTargetGroup(g),
  ) ?? null;
}

function groupFqdnTargets(tenantId, targetGroupId) {
  return getStore().targets
    .filter(
      (t) => t.tenant_id === tenantId && t.target_group_id === targetGroupId && t.kind === 'fqdn',
    )
    .map((t) => String(t.value).trim().toLowerCase());
}

function findVerification(ctx, id) {
  return getStore().ownershipVerifications.find(
    (v) => v.id === id && v.tenant_id === ctx.tenantId,
  ) ?? null;
}

function findOpenVerificationByNonce(tenantId, nonce_hash) {
  return getStore().ownershipVerifications.find(
    (v) =>
      v.tenant_id === tenantId
      && v.challenge_nonce_hash === nonce_hash
      && OPEN_STATUSES.has(v.status),
  ) ?? null;
}

function auditVerification(ctx, id, action) {
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId ?? null,
    actor_role: ctx.role ?? 'system',
    action,
    resource_type: 'ownership_verification',
    resource_id: id,
  });
}

function applyOwnershipSignal(ctx, record, { source, nonce_hash }) {
  if (!OPEN_STATUSES.has(record.status)) {
    return { error: 'ownership_verification_not_open', status: 409 };
  }
  if (nonce_hash !== record.challenge_nonce_hash) {
    return { error: 'nonce_mismatch', status: 400 };
  }

  if (source === 'probe') {
    record.probe_observed = true;
  } else if (source === 'agent') {
    record.agent_observed = true;
  } else {
    return { error: 'invalid_source', status: 400 };
  }

  if (record.probe_observed && record.agent_observed && record.status === 'challenge_sent') {
    const now = new Date().toISOString();
    record.status = 'verified';
    record.verified_at = now;
    const group = findTargetGroup(ctx, record.target_group_id);
    if (group) {
      group.ownership_status = 'agent_verified';
    }
    auditVerification(ctx, record.id, 'ownership_verification.agent_verified');
  }

  persistStore();
  return { verification: record };
}

function validateOwnershipChallengeInputs(ctx, body) {
  const targetGroupId = body.target_group_id;
  const agentId = body.agent_id;

  const group = findTargetGroup(ctx, targetGroupId);
  if (!group) return { error: 'target_group_not_found', status: 404 };

  const agent = getStore().agents.find(
    (a) => a.id === agentId && a.tenant_id === ctx.tenantId,
  );
  if (!agent) return { error: 'agent_not_found', status: 404 };

  if (agent.target_group_id !== group.id) {
    return { error: 'agent_not_bound_to_target_group', status: 400 };
  }
  if (agent.status !== 'online') {
    return { error: 'agent_not_online', status: 409 };
  }
  if (agent.last_token_validation_status === 'invalid') {
    return { error: 'agent_token_invalid', status: 409 };
  }

  const declaredFqdnRaw = agent.probe_endpoint?.declared_fqdn ?? null;
  if (!declaredFqdnRaw) {
    return { error: 'agent_probe_endpoint_missing', status: 409 };
  }
  const declaredFqdn = String(declaredFqdnRaw).trim().toLowerCase();
  const fqdnSet = new Set(groupFqdnTargets(ctx.tenantId, group.id));
  if (!fqdnSet.has(declaredFqdn)) {
    return { error: 'declared_fqdn_not_in_target_group', status: 400 };
  }

  return { group, agent, targetGroupId, agentId, declaredFqdn };
}

export function verifyOwnershipSetup(ctx, body, _runtimeConfig) {
  const validated = validateOwnershipChallengeInputs(ctx, body);
  if (validated.error) {
    return {
      dry_run: true,
      ready: false,
      error: validated.error,
      status: validated.status,
    };
  }

  const { targetGroupId, agentId, declaredFqdn } = validated;
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId ?? null,
    actor_role: ctx.role ?? 'system',
    action: 'ownership_verification.setup_verified',
    resource_type: 'ownership_verification',
    resource_id: targetGroupId,
  });

  return {
    dry_run: true,
    ready: true,
    target_group_id: targetGroupId,
    agent_id: agentId,
    declared_fqdn: declaredFqdn,
    checks: {
      agent_online: true,
      agent_bound: true,
      token_valid: true,
      fqdn_declared: true,
    },
  };
}

export function createOwnershipChallenge(ctx, body, runtimeConfig) {
  const validated = validateOwnershipChallengeInputs(ctx, body);
  if (validated.error) {
    return { error: validated.error, status: validated.status };
  }

  const { group, targetGroupId, agentId, declaredFqdn } = validated;

  const nonce = generateNonce();
  const challenge_nonce_hash = hashNonce(nonce);
  const id = newId('own');
  const now = new Date().toISOString();
  const record = {
    id,
    tenant_id: ctx.tenantId,
    target_group_id: targetGroupId,
    agent_id: agentId,
    declared_fqdn: declaredFqdn,
    status: 'challenge_sent',
    challenge_nonce_hash,
    probe_observed: false,
    agent_observed: false,
    verified_at: null,
    confirmed_by_user_id: null,
    confirmed_at: null,
    created_at: now,
    created_by: ctx.userId,
  };
  getStore().ownershipVerifications.push(record);
  auditVerification(ctx, id, 'ownership_verification.challenge_created');

  if (runtimeConfig?.probeMode === 'signed-worker' && runtimeConfig.probeWorkerSecret) {
    const job = createOwnershipChallengeJob(ctx, { verification: record }, runtimeConfig);
    if (job) {
      record.probe_job_id = job.id;
    }
  }

  persistStore();
  return { verification: record, nonce };
}

export function recordOwnershipSignal(ctx, id, { source, nonce_hash }) {
  const record = findVerification(ctx, id);
  if (!record) return { error: 'ownership_verification_not_found', status: 404 };
  return applyOwnershipSignal(ctx, record, { source, nonce_hash });
}

export function recordOwnershipSignalByNonce({ tenantId }, { source, nonce_hash }) {
  const record = findOpenVerificationByNonce(tenantId, nonce_hash);
  if (!record) return { error: 'ownership_verification_not_found', status: 404 };
  return applyOwnershipSignal({ tenantId }, record, { source, nonce_hash });
}

export function confirmOwnership(ctx, id) {
  const record = findVerification(ctx, id);
  if (!record) return { error: 'ownership_verification_not_found', status: 404 };

  if (record.status !== 'verified') {
    return { error: 'ownership_not_verified', status: 409 };
  }

  const now = new Date().toISOString();
  record.confirmed_by_user_id = ctx.userId;
  record.confirmed_at = now;
  const group = findTargetGroup(ctx, record.target_group_id);
  if (group) {
    group.ownership_status = 'user_confirmed';
  }
  auditVerification(ctx, id, 'ownership_verification.user_confirmed');
  persistStore();
  return { verification: record };
}

export function listOwnershipVerifications(ctx) {
  return getStore().ownershipVerifications.filter((v) => v.tenant_id === ctx.tenantId);
}

export function getOwnershipVerification(ctx, id) {
  return findVerification(ctx, id);
}

const LADDER_STEP_IDS = Object.freeze([
  'declared',
  'dns_verified',
  'agent_verified',
  'user_confirmed',
]);

const LADDER_LABELS = Object.freeze({
  declared: 'Declared',
  dns_verified: 'DNS verified',
  agent_verified: 'Agent verified',
  user_confirmed: 'User confirmed',
});

const VERIFY_PREREQ_STATES = new Set(['agent_verified', 'user_confirmed']);

const VERIFICATION_RANK = Object.freeze({
  unverified: 0,
  pending: 1,
  dns_verified: 2,
  agent_verified: 3,
  user_confirmed: 4,
});

function latestVerificationByTarget(ctx, targetIds) {
  const verifications = (getStore().targetVerifications ?? []).filter(
    (v) => v.tenant_id === ctx.tenantId && targetIds.includes(v.target_id),
  );
  const latestByTarget = new Map();
  for (const row of verifications) {
    const prev = latestByTarget.get(row.target_id);
    if (!prev) {
      latestByTarget.set(row.target_id, row);
      continue;
    }
    const prevAt = String(prev.transitioned_at);
    const rowAt = String(row.transitioned_at);
    if (rowAt > prevAt) {
      latestByTarget.set(row.target_id, row);
      continue;
    }
    if (rowAt === prevAt && (VERIFICATION_RANK[row.state] ?? 0) > (VERIFICATION_RANK[prev.state] ?? 0)) {
      latestByTarget.set(row.target_id, row);
    }
  }
  return latestByTarget;
}

function getActiveLoa(ctx, groupId) {
  return (getStore().loaSignatures ?? []).find(
    (row) =>
      row.tenant_id === ctx.tenantId
      && row.target_group_id === groupId
      && row.state === 'signed',
  ) ?? null;
}

/**
 * Server-computed verification ladder (portal revamp §3.4).
 *
 * @param {import('../context.mjs').TenantScope} ctx
 * @param {string} groupId
 */
export function getLadder(ctx, groupId) {
  const group = findTargetGroup(ctx, groupId);
  if (!group) return { error: 'target_group_not_found', status: 404 };

  const targets = getStore().targets.filter(
    (t) => t.tenant_id === ctx.tenantId && t.target_group_id === groupId,
  );
  const latestByTarget = latestVerificationByTarget(
    ctx,
    targets.map((t) => t.id),
  );

  const total = targets.length;
  const steps = LADDER_STEP_IDS.map((id) => {
    let count = 0;
    if (id === 'declared') {
      count = total;
    } else {
      for (const state of latestByTarget.values()) {
        if (state.state === id) count += 1;
      }
    }
    return {
      id,
      label: LADDER_LABELS[id] ?? id,
      done: total > 0 && count >= total,
      count,
      total,
    };
  });

  return {
    steps,
    meta: total === 0
      ? { empty_reason: 'No targets declared for this group; the verification ladder cannot be computed yet.' }
      : undefined,
  };
}

/**
 * Elevates a target to user_confirmed (portal revamp §3.4).
 *
 * @param {import('../context.mjs').TenantScope} ctx
 * @param {string} groupId
 * @param {string} targetId
 * @param {{ signer?: string, note?: string }} _signer
 */
export function confirmTarget(ctx, groupId, targetId, signer = {}) {
  const group = findTargetGroup(ctx, groupId);
  if (!group) return { error: 'target_group_not_found', status: 404 };

  const target = getStore().targets.find(
    (t) =>
      t.id === targetId
      && t.tenant_id === ctx.tenantId
      && t.target_group_id === groupId,
  );
  if (!target) return { error: 'target_not_found', status: 404 };

  const activeLoa = getActiveLoa(ctx, groupId);
  if (!activeLoa) return { error: 'loa_missing', status: 409 };

  const latestByTarget = latestVerificationByTarget(ctx, [targetId]);
  const current = latestByTarget.get(targetId);
  const currentState = current?.state ?? 'pending';
  if (!VERIFY_PREREQ_STATES.has(currentState) && currentState !== 'agent_verified') {
    if (currentState === 'pending' || currentState === 'unverified' || currentState === 'dns_verified') {
      return { error: 'verify_prereq_not_met', status: 409 };
    }
  }
  if (!VERIFY_PREREQ_STATES.has(currentState)) {
    return { error: 'verify_prereq_not_met', status: 409 };
  }

  const now = new Date().toISOString();
  const verification = {
    id: newId('tv'),
    tenant_id: ctx.tenantId,
    target_id: targetId,
    state: 'user_confirmed',
    source_kind: 'user_attestation',
    source_ref: {
      signer: signer.signer ?? ctx.userId,
      note: signer.note ?? null,
      loa_id: activeLoa.id,
    },
    transitioned_at: now,
    transitioned_by: ctx.userId ?? 'system',
    audit_entry_id: null,
  };
  const auditEntry = audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'target_verification.user_confirmed',
    resource_type: 'target',
    resource_id: targetId,
    metadata: { target_group_id: groupId, loa_id: activeLoa.id },
  });
  verification.audit_entry_id = auditEntry.id;
  if (!getStore().targetVerifications) getStore().targetVerifications = [];
  getStore().targetVerifications.push(verification);
  target.verify_state = 'user_confirmed';
  persistStore();

  return {
    target,
    verification: {
      state: verification.state,
      source_kind: verification.source_kind,
      source_ref: verification.source_ref,
      transitioned_at: verification.transitioned_at,
    },
    audit_entry_id: auditEntry.id,
  };
}