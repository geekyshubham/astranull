import { randomBytes } from 'node:crypto';
import { audit } from '../audit.mjs';
import { encodeBase32 } from '../lib/base32.mjs';
import { newId } from '../lib/ids.mjs';
import { getStore, persistStore } from '../store.mjs';
import { isArchivedTargetGroup } from './targetGroups.mjs';

const CHALLENGE_TTL_SECONDS = 60;
const CHALLENGE_LIFETIME_MS = 15 * 60 * 1000;
const DNS_TIMEOUT_MS = 4000;
const VERIFY_RATE_LIMIT = 6;
const VERIFY_RATE_WINDOW_MS = 60_000;

/** @type {Map<string, { windowStart: number, count: number }>} */
const verifyRateBuckets = new Map();

function nowIso() {
  return new Date().toISOString();
}

function addMinutesIso(iso, minutes) {
  return new Date(new Date(iso).getTime() + minutes * 60_000).toISOString();
}

function findActiveTargetGroup(ctx, targetGroupId) {
  return (
    getStore().targetGroups.find(
      (g) =>
        g.id === targetGroupId
        && g.tenant_id === ctx.tenantId
        && !isArchivedTargetGroup(g),
    ) ?? null
  );
}

function findTarget(ctx, targetGroupId, targetId) {
  if (!targetId) return null;
  return (
    getStore().targets.find(
      (t) =>
        t.id === targetId
        && t.tenant_id === ctx.tenantId
        && t.target_group_id === targetGroupId,
    ) ?? null
  );
}

function resolveFqdnDomain(ctx, targetGroupId, targetId) {
  const target = targetId
    ? findTarget(ctx, targetGroupId, targetId)
    : getStore().targets.find(
        (t) =>
          t.tenant_id === ctx.tenantId
          && t.target_group_id === targetGroupId
          && t.kind === 'fqdn',
      );
  if (!target?.value) return null;
  return String(target.value).trim().toLowerCase();
}

function flattenTxtRecords(records) {
  if (!Array.isArray(records)) return [];
  const out = [];
  for (const entry of records) {
    if (Array.isArray(entry)) {
      for (const chunk of entry) out.push(String(chunk));
    } else {
      out.push(String(entry));
    }
  }
  return out;
}

function formatChallenge(row) {
  return {
    id: row.id,
    tenant_id: row.tenant_id,
    target_group_id: row.target_group_id,
    target_id: row.target_id ?? null,
    record_name: row.record_name,
    record_value: row.record_value,
    ttl_seconds: row.ttl_seconds,
    state: row.state,
    issued_at: row.issued_at,
    expires_at: row.expires_at,
    resolved_at: row.resolved_at ?? null,
    last_checked_at: row.last_checked_at ?? null,
    last_check_result: row.last_check_result ?? null,
    audit_entry_id: row.audit_entry_id ?? null,
  };
}

function findPendingChallengeForTarget(ctx, targetGroupId, targetId) {
  return (getStore().dnsChallenges ?? []).find(
    (row) =>
      row.tenant_id === ctx.tenantId
      && row.target_group_id === targetGroupId
      && row.target_id === targetId
      && row.state === 'pending'
      && new Date(row.expires_at).getTime() > Date.now(),
  ) ?? null;
}

function appendTargetVerification(ctx, targetId, challengeId, auditEntryId) {
  const id = newId('tv');
  const record = {
    id,
    tenant_id: ctx.tenantId,
    target_id: targetId,
    state: 'dns_verified',
    source_kind: 'dns_txt',
    source_ref: { dns_challenge_id: challengeId },
    transitioned_at: nowIso(),
    transitioned_by: ctx.userId ?? 'system',
    audit_entry_id: auditEntryId,
  };
  if (!getStore().targetVerifications) getStore().targetVerifications = [];
  getStore().targetVerifications.push(record);
  const target = getStore().targets.find((t) => t.id === targetId);
  if (target) target.verify_state = 'dns_verified';
  return record;
}

function checkVerifyRateLimit(targetId) {
  const key = `dns_verify:${targetId}`;
  const now = Date.now();
  const bucket = verifyRateBuckets.get(key);
  if (!bucket || now - bucket.windowStart >= VERIFY_RATE_WINDOW_MS) {
    verifyRateBuckets.set(key, { windowStart: now, count: 1 });
    return { allowed: true };
  }
  bucket.count += 1;
  if (bucket.count > VERIFY_RATE_LIMIT) {
    return { allowed: false, retryAfterSeconds: Math.ceil((VERIFY_RATE_WINDOW_MS - (now - bucket.windowStart)) / 1000) };
  }
  return { allowed: true };
}

async function resolveTxtWithTimeout(recordName, resolveTxt) {
  let resolveFn = resolveTxt;
  if (!resolveFn) {
    const dns = await import('node:dns/promises');
    resolveFn = dns.resolveTxt.bind(dns);
  }
  const timeout = new Promise((_, reject) => {
    setTimeout(() => {
      const err = new Error('DNS lookup timed out');
      err.code = 'ETIMEOUT';
      reject(err);
    }, DNS_TIMEOUT_MS);
  });
  return Promise.race([resolveFn(recordName), timeout]);
}

/**
 * @param {import('../context.mjs').TenantScope} ctx
 * @param {string} groupId
 * @param {string} [targetId]
 */
export function issueChallenge(ctx, groupId, targetId) {
  const group = findActiveTargetGroup(ctx, groupId);
  if (!group) return { error: 'target_group_not_found', status: 404 };

  const resolvedTargetId = targetId ?? findTarget(ctx, groupId, targetId)?.id ?? null;
  const fqdnTarget = targetId
    ? findTarget(ctx, groupId, targetId)
    : getStore().targets.find(
        (t) =>
          t.tenant_id === ctx.tenantId
          && t.target_group_id === groupId
          && t.kind === 'fqdn',
      );
  const effectiveTargetId = fqdnTarget?.id ?? null;

  const domain = resolveFqdnDomain(ctx, groupId, effectiveTargetId);
  if (!domain) return { error: 'no_fqdn_target', status: 409 };

  if (effectiveTargetId && findPendingChallengeForTarget(ctx, groupId, effectiveTargetId)) {
    return { error: 'challenge_active', status: 409 };
  }

  const issued_at = nowIso();
  const expires_at = addMinutesIso(issued_at, 15);
  const record_value = encodeBase32(randomBytes(32));
  const challenge = {
    id: newId('dns'),
    tenant_id: ctx.tenantId,
    target_group_id: groupId,
    target_id: effectiveTargetId,
    record_name: `_astranull-challenge.${domain}`,
    record_value,
    ttl_seconds: CHALLENGE_TTL_SECONDS,
    state: 'pending',
    issued_at,
    expires_at,
    resolved_at: null,
    last_checked_at: null,
    last_check_result: null,
    audit_entry_id: null,
  };

  const auditEntry = audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'dns_ownership.challenge_issued',
    resource_type: 'dns_challenge',
    resource_id: challenge.id,
    metadata: { target_group_id: groupId, target_id: effectiveTargetId },
  });
  challenge.audit_entry_id = auditEntry.id;

  if (!getStore().dnsChallenges) getStore().dnsChallenges = [];
  getStore().dnsChallenges.push(challenge);
  persistStore();

  return {
    challenge: formatChallenge(challenge),
    audit_entry_id: auditEntry.id,
  };
}

/**
 * @param {import('../context.mjs').TenantScope} ctx
 * @param {string} challengeId
 * @param {{ resolveTxt?: (name: string) => Promise<unknown> }} [options]
 */
export async function verifyChallenge(ctx, challengeId, options = {}) {
  const challenge = (getStore().dnsChallenges ?? []).find(
    (row) => row.id === challengeId && row.tenant_id === ctx.tenantId,
  );
  if (!challenge) return { error: 'challenge_not_found', status: 404 };

  const group = findActiveTargetGroup(ctx, challenge.target_group_id);
  if (!group) return { error: 'target_group_not_found', status: 404 };

  if (challenge.state !== 'pending') {
    return {
      challenge: formatChallenge(challenge),
      verified: challenge.state === 'resolved',
    };
  }

  const rateKey = challenge.target_id ?? challenge.id;
  const rate = checkVerifyRateLimit(rateKey);
  if (!rate.allowed) {
    return { error: 'rate_limited', status: 429, retry_after_seconds: rate.retryAfterSeconds };
  }

  const checked_at = nowIso();
  let lookup;
  let timedOut = false;
  try {
    lookup = await resolveTxtWithTimeout(challenge.record_name, options.resolveTxt);
  } catch (err) {
    if (err?.code === 'ETIMEOUT') {
      timedOut = true;
      lookup = [];
    } else {
      lookup = [];
    }
  }

  const values = flattenTxtRecords(lookup);
  const matched = values.some((v) => v === challenge.record_value);
  challenge.last_checked_at = checked_at;
  challenge.last_check_result = {
    resolver: 'system',
    records: values,
    matched,
    timed_out: timedOut,
  };

  let auditEntry = null;
  if (matched) {
    challenge.state = 'resolved';
    challenge.resolved_at = checked_at;
    auditEntry = audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'dns_ownership.verified',
      resource_type: 'dns_challenge',
      resource_id: challenge.id,
      metadata: { target_group_id: challenge.target_group_id, target_id: challenge.target_id },
    });
    if (challenge.target_id) {
      appendTargetVerification(ctx, challenge.target_id, challenge.id, auditEntry.id);
    }
  } else {
    auditEntry = audit({
      tenant_id: ctx.tenantId,
      actor_user_id: ctx.userId,
      actor_role: ctx.role,
      action: 'dns_ownership.verify_checked',
      resource_type: 'dns_challenge',
      resource_id: challenge.id,
      metadata: { matched: false, timed_out: timedOut },
    });
  }

  persistStore();

  const response = {
    challenge: formatChallenge(challenge),
    verified: matched,
    audit_entry_id: auditEntry?.id ?? null,
  };
  if (timedOut) {
    response.meta = { timeout: true };
  }
  return response;
}

/**
 * @param {import('../context.mjs').TenantScope} ctx
 * @param {string} groupId
 */
export function listChallenges(ctx, groupId) {
  const group = findActiveTargetGroup(ctx, groupId);
  if (!group) return { error: 'target_group_not_found', status: 404 };

  const items = (getStore().dnsChallenges ?? [])
    .filter((row) => row.tenant_id === ctx.tenantId && row.target_group_id === groupId)
    .map(formatChallenge);
  return {
    items,
    count: items.length,
    meta: items.length
      ? undefined
      : { empty_reason: 'no_dns_challenges_recorded', target_group_id: groupId },
  };
}

/** Backward-compatible adapter for legacy callers + unit tests. */
export function issueDnsOwnershipChallenge(ctx, { target_group_id, target_id }) {
  const result = issueChallenge(ctx, target_group_id, target_id);
  if (result.error) return result;
  return {
    ...result.challenge,
    challenge: result.challenge,
    audit_entry_id: result.audit_entry_id,
  };
}

/** Backward-compatible adapter — accepts challenge_id via target_group_id wrapper from server. */
export async function verifyDnsOwnership(ctx, { target_group_id, challenge_id }, options = {}) {
  if (challenge_id) {
    const result = await verifyChallenge(ctx, challenge_id, options);
    if (result.error) return result;
    return result;
  }

  const group = findActiveTargetGroup(ctx, target_group_id);
  if (!group) return { error: 'target_group_not_found', status: 404 };
  const pending = (getStore().dnsChallenges ?? []).find(
    (row) =>
      row.tenant_id === ctx.tenantId
      && row.target_group_id === target_group_id
      && row.state === 'pending',
  );
  if (!pending) return { error: 'no_dns_challenge', status: 409 };
  return verifyChallenge(ctx, pending.id, options);
}