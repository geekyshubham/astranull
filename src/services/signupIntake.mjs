import { createFixedWindowRateLimiter } from '../lib/rateLimit.mjs';
import { audit } from '../audit.mjs';
import {
  canTransitionSignupState,
  customerSafeRejectionReason,
  validateSignupRequestInput,
} from '../contracts/signupIntake.mjs';
import { newId } from '../lib/ids.mjs';
import { getStore, persistStore } from '../store.mjs';
import { auditInternal } from './internalAudit.mjs';
import {
  applyPlanRetentionToTenant,
  createTenantSubscription,
  upsertTenantAccount,
} from './subscriptions.mjs';

const PUBLIC_SIGNUP_RATE = new Map();
let signupEventsRateLimiter = createFixedWindowRateLimiter({
  windowMs: 60_000,
  maxRequests: 12,
});

const SIGNUP_EVENT_MESSAGE_MAX = 500;

export function resetSignupRateLimitsForTests() {
  PUBLIC_SIGNUP_RATE.clear();
  signupEventsRateLimiter = createFixedWindowRateLimiter({
    windowMs: 60_000,
    maxRequests: 12,
  });
}

function ensureSignupEventsStore() {
  const store = getStore();
  if (!Array.isArray(store.signupQueueEvents)) store.signupQueueEvents = [];
  return store;
}

function truncateSignupMessage(message) {
  if (message == null) return null;
  const text = String(message);
  return text.length > SIGNUP_EVENT_MESSAGE_MAX ? text.slice(0, SIGNUP_EVENT_MESSAGE_MAX) : text;
}

export function appendSignupQueueEvent({
  requestId,
  eventKind,
  actor = 'system',
  message = null,
  tenantId = null,
  createdAt = new Date().toISOString(),
}) {
  const record = {
    id: newId('sqe'),
    tenant_id: tenantId,
    request_id: requestId,
    event_kind: eventKind,
    actor,
    message: truncateSignupMessage(message),
    created_at: createdAt,
  };
  ensureSignupEventsStore().signupQueueEvents.push(record);
  persistStore();
  return record;
}

function checkPublicSignupRate(clientKey, maxPerHour = 20) {
  const now = Date.now();
  const windowMs = 60 * 60 * 1000;
  const bucket = PUBLIC_SIGNUP_RATE.get(clientKey) ?? [];
  const fresh = bucket.filter((ts) => now - ts < windowMs);
  if (fresh.length >= maxPerHour) {
    return { ok: false, retryAfterSeconds: Math.ceil((fresh[0] + windowMs - now) / 1000) };
  }
  fresh.push(now);
  PUBLIC_SIGNUP_RATE.set(clientKey, fresh);
  return { ok: true };
}

function findDuplicateSignup(store, emailDomain, organization) {
  const org = organization.trim().toLowerCase();
  const domain = emailDomain.trim().toLowerCase();
  const requests = store.signupRequests ?? [];
  return requests.find((r) => {
    if (['rejected'].includes(r.state)) return false;
    return r.email_domain === domain
      || r.organization_name.trim().toLowerCase() === org;
  }) ?? null;
}

export function createSignupRequest(body, options = {}) {
  const validated = validateSignupRequestInput(body);
  if (!validated.ok) {
    return { error: 'validation_failed', fields: validated.errors };
  }

  const clientKey = options.clientKey ?? 'anonymous';
  const rate = checkPublicSignupRate(clientKey);
  if (!rate.ok) {
    return { error: 'rate_limited', retry_after_seconds: rate.retryAfterSeconds };
  }

  const store = getStore();
  if (!Array.isArray(store.signupRequests)) store.signupRequests = [];
  const duplicate = findDuplicateSignup(
    store,
    validated.value.email_domain,
    validated.value.organization_name,
  );
  if (duplicate) {
    return { error: 'duplicate_request', existing_id: duplicate.id };
  }

  const now = new Date().toISOString();
  const record = {
    id: newId('signup'),
    ...validated.value,
    state: 'submitted',
    reviewer_staff_id: null,
    decision_reason: null,
    customer_notice: null,
    provisioned_tenant_id: null,
    created_at: now,
    updated_at: now,
    decided_at: null,
  };
  store.signupRequests.push(record);
  appendSignupQueueEvent({
    requestId: record.id,
    eventKind: 'submitted',
    actor: 'system',
    message: 'Signup request submitted for review.',
    createdAt: now,
  });
  persistStore();

  auditInternal({
    staff_id: null,
    staff_role: null,
    action: 'signup.request_submitted',
    resource_type: 'signup_request',
    resource_id: record.id,
    metadata: {
      organization_name: record.organization_name,
      email_domain: record.email_domain,
      requested_plan: record.requested_plan,
      region: record.region,
      high_scale_interest: record.high_scale_interest,
    },
  });

  return { request: sanitizeSignupForPublic(record) };
}

export function getSignupRequest(id) {
  const store = getStore();
  const record = (store.signupRequests ?? []).find((r) => r.id === id);
  if (!record) return null;
  return record;
}

export function sanitizeSignupForPublic(record) {
  return {
    id: record.id,
    organization_name: record.organization_name,
    state: record.state,
    requested_plan: record.requested_plan,
    region: record.region,
    created_at: record.created_at,
    updated_at: record.updated_at,
    customer_notice: record.customer_notice ?? null,
    provisioned_tenant_id: record.state === 'customer_invited' ? record.provisioned_tenant_id : null,
  };
}

export function listSignupRequests(filters = {}) {
  const store = getStore();
  let items = [...(store.signupRequests ?? [])];
  if (filters.state) {
    items = items.filter((r) => r.state === filters.state);
  }
  items.sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
  return items;
}

function transitionSignup(record, toState, patch = {}) {
  if (!canTransitionSignupState(record.state, toState)) {
    return { error: 'invalid_state_transition', from: record.state, to: toState };
  }
  record.state = toState;
  record.updated_at = new Date().toISOString();
  if (patch.reviewer_staff_id) record.reviewer_staff_id = patch.reviewer_staff_id;
  if (patch.decision_reason !== undefined) record.decision_reason = patch.decision_reason;
  if (patch.customer_notice !== undefined) record.customer_notice = patch.customer_notice;
  if (patch.provisioned_tenant_id !== undefined) {
    record.provisioned_tenant_id = patch.provisioned_tenant_id;
  }
  if (['approved', 'rejected', 'provisioned', 'customer_invited'].includes(toState)) {
    record.decided_at = record.updated_at;
  }
  const eventKindByState = {
    under_review: 'review_started',
    approved: 'approved',
    rejected: 'rejected',
    provisioned: 'provisioned',
    customer_invited: 'provisioned',
  };
  const eventKind = eventKindByState[toState];
  if (eventKind) {
    appendSignupQueueEvent({
      requestId: record.id,
      eventKind,
      actor: patch.reviewer_staff_id ? `staff:${patch.reviewer_staff_id}` : 'system',
      message: patch.customer_notice ?? patch.decision_reason ?? null,
      tenantId: record.provisioned_tenant_id ?? null,
      createdAt: record.updated_at,
    });
  }
  persistStore();
  return { request: record };
}

function provisionTenantFromSignup(staffCtx, record) {
  const store = getStore();
  const tenantId = newId('tenant');
  const envId = newId('env');
  const ownerUserId = newId('user');
  const now = new Date().toISOString();

  store.tenants.push({
    id: tenantId,
    name: record.organization_name,
    created_at: now,
    privacy_settings: {
      store_packet_payloads: false,
      metadata_retention_days: 90,
      redact_headers_by_default: true,
    },
  });
  store.environments.push({
    id: envId,
    tenant_id: tenantId,
    name: 'Production Validation',
    created_at: now,
  });
  store.users.push({
    id: ownerUserId,
    tenant_id: tenantId,
    email: record.contact_email,
    role: 'owner',
    name: record.contact_name,
    status: 'invited',
    invited_at: now,
  });
  store.readiness[tenantId] = {
    score: 0,
    factors: [],
    updated_at: now,
  };

  const sub = createTenantSubscription(tenantId, record.requested_plan);
  if (sub.error) return sub;
  applyPlanRetentionToTenant(tenantId, record.requested_plan);
  upsertTenantAccount(tenantId, {
    legal_name: record.organization_name,
    region: record.region,
    lifecycle_state: 'active',
    support_owner: staffCtx.staffId ?? staffCtx.userId,
  });

  persistStore();

  audit({
    tenant_id: tenantId,
    actor_user_id: staffCtx.staffId ?? staffCtx.userId,
    actor_role: staffCtx.staffRole ?? staffCtx.role,
    action: 'tenant.provisioned_from_signup',
    resource_type: 'tenant',
    resource_id: tenantId,
    metadata: {
      signup_request_id: record.id,
      requested_plan: record.requested_plan,
      owner_user_id: ownerUserId,
    },
  });

  return {
    tenant_id: tenantId,
    environment_id: envId,
    owner_user_id: ownerUserId,
    owner_invite: {
      user_id: ownerUserId,
      email: record.contact_email,
      status: 'invited',
    },
  };
}

export function approveSignupRequest(staffCtx, id, body = {}) {
  const store = getStore();
  const record = store.signupRequests.find((r) => r.id === id);
  if (!record) return null;
  if (record.state === 'submitted') {
    const review = transitionSignup(record, 'under_review', {
      reviewer_staff_id: staffCtx.staffId ?? staffCtx.userId,
    });
    if (review.error) return review;
  }
  const approved = transitionSignup(record, 'approved', {
    reviewer_staff_id: staffCtx.staffId ?? staffCtx.userId,
    decision_reason: body.reason ?? 'approved',
  });
  if (approved.error) return approved;

  auditInternal({
    staff_id: staffCtx.staffId ?? staffCtx.userId,
    staff_role: staffCtx.staffRole ?? staffCtx.role,
    action: 'signup.request_approved',
    resource_type: 'signup_request',
    resource_id: id,
    reason: body.reason ?? null,
    metadata: { requested_plan: record.requested_plan },
  });

  if (body.provision !== false) {
    const provisioned = provisionTenantFromSignup(staffCtx, record);
    if (provisioned.error) return provisioned;
    transitionSignup(record, 'provisioned', {
      provisioned_tenant_id: provisioned.tenant_id,
    });
    transitionSignup(record, 'customer_invited', {
      customer_notice: 'Your AstraNull account is ready. Check your email for login instructions.',
    });
    return {
      request: record,
      provisioning: provisioned,
    };
  }

  return { request: record };
}

export function rejectSignupRequest(staffCtx, id, body = {}) {
  const store = getStore();
  const record = store.signupRequests.find((r) => r.id === id);
  if (!record) return null;
  if (record.state === 'submitted') {
    const review = transitionSignup(record, 'under_review', {
      reviewer_staff_id: staffCtx.staffId ?? staffCtx.userId,
    });
    if (review.error) return review;
  }
  const staffReason = String(body.reason ?? '').trim() || 'Request declined during review.';
  const customerNotice = customerSafeRejectionReason(body.customer_notice ?? staffReason);
  const rejected = transitionSignup(record, 'rejected', {
    reviewer_staff_id: staffCtx.staffId ?? staffCtx.userId,
    decision_reason: staffReason,
    customer_notice: customerNotice,
  });
  if (rejected.error) return rejected;

  auditInternal({
    staff_id: staffCtx.staffId ?? staffCtx.userId,
    staff_role: staffCtx.staffRole ?? staffCtx.role,
    action: 'signup.request_rejected',
    resource_type: 'signup_request',
    resource_id: id,
    reason: staffReason,
    metadata: { customer_notice_length: customerNotice.length },
  });

  return { request: record };
}

/**
 * Customer-facing signup queue events (portal revamp §3.9).
 *
 * @param {string} requestId
 */
export function listEvents(requestId, options = {}) {
  if (options.rateLimitKey) {
    const rate = signupEventsRateLimiter.check(options.rateLimitKey);
    if (!rate.allowed) {
      return {
        error: 'rate_limited',
        status: 429,
        retry_after_seconds: rate.retryAfterSeconds,
      };
    }
  }

  const events = (getStore().signupQueueEvents ?? [])
    .filter((row) => row.request_id === requestId)
    .sort((a, b) => String(a.created_at).localeCompare(String(b.created_at)))
    .map((row) => ({
      ...row,
      message: truncateSignupMessage(row.message),
    }));
  return {
    events,
    count: events.length,
    meta: events.length
      ? undefined
      : { empty_reason: 'no_signup_events_recorded', request_id: requestId },
  };
}