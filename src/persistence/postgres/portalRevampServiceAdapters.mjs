import { randomBytes } from 'node:crypto';
import { buildAuditRecord } from '../../audit.mjs';
import { encodeBase32 } from '../../lib/base32.mjs';
import { buildLoaCustodyDigest } from '../../lib/authorizationArtifactLedger.mjs';
import { newId } from '../../lib/ids.mjs';
import { PORTAL_REVAMP_REPOSITORY_METHODS } from './portalRevampRepository.mjs';

/** @type {readonly string[]} */
export const POSTGRES_PORTAL_DNS_SERVICE_METHODS = Object.freeze([
  'listChallenges',
  'issueDnsOwnershipChallenge',
  'verifyDnsOwnership',
]);

/** @type {readonly string[]} */
export const POSTGRES_LOA_SERVICE_METHODS = Object.freeze(['sign', 'revoke', 'getActive']);

/** @type {readonly string[]} */
export const POSTGRES_TARGET_DETAIL_SERVICE_METHODS = Object.freeze(['getTargetDetail']);

/** @type {readonly string[]} */
export const POSTGRES_REMEDIATION_SERVICE_METHODS = Object.freeze([
  'attachToFinding',
  'deliver',
  'updateState',
]);

/** @type {readonly string[]} */
export const POSTGRES_PORTAL_OWNERSHIP_SERVICE_METHODS = Object.freeze([
  'getLadder',
  'confirmTarget',
]);

/** @type {readonly string[]} */
export const POSTGRES_PORTAL_FINDINGS_SERVICE_METHODS = Object.freeze(['getEvidenceBundle']);

/** @type {readonly string[]} */
export const POSTGRES_PORTAL_TARGET_GROUPS_SERVICE_METHODS = Object.freeze([
  'restoreArchived',
  'bulkImportTargets',
]);

/** @type {readonly string[]} */
export const POSTGRES_PORTAL_WAF_SERVICE_METHODS = Object.freeze([
  'getCoverageSummary',
  'getConnectorInventory',
]);

/** @type {readonly string[]} */
export const POSTGRES_PORTAL_SIGNUP_SERVICE_METHODS = Object.freeze(['listEvents']);

function assertPortalRevampRepository(repositories) {
  const repo = repositories?.portalRevamp;
  if (!repo || typeof repo !== 'object') {
    throw new Error('Postgres portal revamp adapter requires repositories.portalRevamp.');
  }
  for (const method of PORTAL_REVAMP_REPOSITORY_METHODS) {
    if (typeof repo[method] !== 'function') {
      throw new Error(`Postgres portal revamp adapter requires portalRevamp.${method}().`);
    }
  }
}

const EMPTY_COUNTS = Object.freeze({
  runs_total: 0,
  findings_open: 0,
  findings_closed: 0,
});

const EMPTY_COVERAGE_SUMMARY = Object.freeze({
  assets_total: 0,
  protected: 0,
  underprotected: 0,
  unknown: 0,
  coverage_pct: 0,
  by_vendor: {},
  connectors_active: 0,
  connectors_degraded: 0,
  connectors_disabled: 0,
  refreshed_at: null,
});

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

const DNS_TIMEOUT_MS = 4000;
const VERIFY_RATE_LIMIT = 6;
const VERIFY_RATE_WINDOW_MS = 60_000;

/** @type {Map<string, { windowStart: number, count: number }>} */
const verifyRateBuckets = new Map();

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
    return {
      allowed: false,
      retryAfterSeconds: Math.ceil((VERIFY_RATE_WINDOW_MS - (now - bucket.windowStart)) / 1000),
    };
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
 * @param {{ repositories: Record<string, unknown> }} deps
 */
export function createPostgresPortalRevampServices(deps) {
  const repositories = deps?.repositories ?? deps;
  assertPortalRevampRepository(repositories);
  const portalRevamp = repositories.portalRevamp;

  const auditRepo = repositories.audit;
  const validationEvidence = repositories.validationEvidence;

  const portalDns = {
    async listChallenges(ctx, groupId) {
      const items = await portalRevamp.listDnsChallengesByGroup(ctx, groupId);
      const count = items.length;
      return {
        items,
        count,
        meta: count
          ? undefined
          : { empty_reason: 'no_dns_challenges_recorded', target_group_id: groupId },
      };
    },
    async issueDnsOwnershipChallenge(ctx, { target_group_id, target_id }) {
      const domain = await portalRevamp.resolveFqdnDomain(ctx, target_group_id, target_id ?? null);
      if (!domain) return { error: 'no_fqdn_target', status: 409 };

      const pending = (await portalRevamp.listDnsChallengesByGroup(ctx, target_group_id))
        .find(
          (row) =>
            row.target_id === (target_id ?? null)
            && row.state === 'pending'
            && new Date(row.expires_at).getTime() > Date.now(),
        );
      if (pending) return { error: 'challenge_active', status: 409 };

      const issued_at = new Date().toISOString();
      const expires_at = new Date(Date.now() + 15 * 60_000).toISOString();
      const record = {
        id: newId('dns'),
        target_group_id: target_group_id,
        target_id: target_id ?? null,
        record_name: `_astranull-challenge.${domain}`,
        record_value: encodeBase32(randomBytes(32)),
        ttl_seconds: 60,
        state: 'pending',
        issued_at,
        expires_at,
      };
      const challenge = await portalRevamp.insertDnsChallenge(ctx, record, auditRepo);
      return { challenge, audit_entry_id: challenge.audit_entry_id };
    },
    async verifyDnsOwnership(ctx, { target_group_id, challenge_id }, options = {}) {
      let challenge = challenge_id
        ? await portalRevamp.findDnsChallenge(ctx, challenge_id)
        : null;
      if (!challenge && target_group_id) {
        challenge = (await portalRevamp.listDnsChallengesByGroup(ctx, target_group_id))
          .find((row) => row.state === 'pending');
      }
      if (!challenge) return { error: 'challenge_not_found', status: 404 };
      if (challenge.state !== 'pending') {
        return {
          challenge,
          verified: challenge.state === 'resolved',
          audit_entry_id: challenge.audit_entry_id,
        };
      }

      const rateKey = challenge.target_id ?? challenge.id;
      const rate = checkVerifyRateLimit(rateKey);
      if (!rate.allowed) {
        return { error: 'rate_limited', status: 429, retry_after_seconds: rate.retryAfterSeconds };
      }

      const checked_at = new Date().toISOString();
      let lookup;
      let timedOut = false;
      try {
        lookup = await resolveTxtWithTimeout(challenge.record_name, options.resolveTxt);
      } catch (err) {
        timedOut = err?.code === 'ETIMEOUT';
        lookup = [];
      }

      const values = flattenTxtRecords(lookup);
      const matched = values.some((v) => v === challenge.record_value);
      const last_check_result = {
        resolver: 'system',
        records: values,
        matched,
        timed_out: timedOut,
      };

      let auditEntryId = challenge.audit_entry_id;
      let verified = false;
      if (matched) {
        const prior = await auditRepo.getLastAuditEntry(ctx.tenantId);
        const auditEntry = buildAuditRecord({
          tenant_id: ctx.tenantId,
          actor_user_id: ctx.userId,
          actor_role: ctx.role,
          action: 'dns_ownership.verified',
          resource_type: 'dns_challenge',
          resource_id: challenge.id,
        }, prior);
        await auditRepo.appendAuditEntry(auditEntry);
        auditEntryId = auditEntry.id;
        verified = true;
        const updated = await portalRevamp.updateDnsChallenge(ctx, challenge.id, {
          state: 'resolved',
          resolved_at: checked_at,
          last_checked_at: checked_at,
          last_check_result,
          audit_entry_id: auditEntryId,
        }, auditRepo);
        if (challenge.target_id) {
          await portalRevamp.insertTargetVerification(ctx, {
            id: newId('tv'),
            target_id: challenge.target_id,
            state: 'dns_verified',
            source_kind: 'dns_txt',
            source_ref: { dns_challenge_id: challenge.id },
            transitioned_at: checked_at,
            transitioned_by: ctx.userId ?? 'system',
          }, auditRepo);
        }
        challenge = updated ?? challenge;
      } else {
        const prior = await auditRepo.getLastAuditEntry(ctx.tenantId);
        const auditEntry = buildAuditRecord({
          tenant_id: ctx.tenantId,
          actor_user_id: ctx.userId,
          actor_role: ctx.role,
          action: 'dns_ownership.verify_checked',
          resource_type: 'dns_challenge',
          resource_id: challenge.id,
          metadata: { matched: false, timed_out: timedOut },
        }, prior);
        await auditRepo.appendAuditEntry(auditEntry);
        auditEntryId = auditEntry.id;
        challenge = await portalRevamp.updateDnsChallenge(ctx, challenge.id, {
          last_checked_at: checked_at,
          last_check_result,
          audit_entry_id: auditEntryId,
        }, auditRepo) ?? challenge;
      }

      const response = {
        challenge,
        verified,
        audit_entry_id: auditEntryId,
      };
      if (timedOut) response.meta = { timeout: true };
      return response;
    },
  };

  const loa = {
    async sign(ctx, groupId, payload) {
      if (payload?.attested !== true) return { error: 'attestation_required', status: 403 };
      const active = await portalRevamp.getActiveLoaByGroup(ctx, groupId);
      if (active) return { error: 'loa_active', status: 409 };
      const signed_at = new Date().toISOString();
      const scope_snapshot = { targets: payload.scope_ack ?? [], excluded: [] };
      const custody_digest_sha256 = buildLoaCustodyDigest({
        tenant_id: ctx.tenantId,
        target_group_id: groupId,
        signer_name: payload.signer_name,
        signer_email: payload.signer_email,
        signed_at,
        scope_snapshot,
      });
      const loaRecord = await portalRevamp.insertLoaSignature(
        ctx,
        {
          id: newId('loa'),
          target_group_id: groupId,
          state: 'signed',
          signer_name: payload.signer_name,
          signer_title: payload.signer_title,
          signer_email: payload.signer_email,
          signed_at,
          expires_at: null,
          emergency_contact: payload.emergency_contact ?? {},
          attested: true,
          scope_snapshot,
          custody_artifact_id: newId('art'),
          custody_digest_sha256,
        },
        auditRepo,
      );
      return {
        loa: loaRecord,
        custody_artifact_id: loaRecord.custody_artifact_id,
        custody_digest_sha256,
        audit_entry_id: loaRecord.audit_entry_id,
      };
    },
    async revoke(ctx, loaId, _reason) {
      const record = await portalRevamp.updateLoaSignature(ctx, loaId, { state: 'revoked' }, auditRepo);
      if (!record) return { error: 'not_found', status: 404 };
      return { loa: record, audit_entry_id: record.audit_entry_id };
    },
    async getActive(ctx, groupId) {
      const active = await portalRevamp.getActiveLoaByGroup(ctx, groupId);
      return {
        loa: active,
        meta: active ? undefined : { empty_reason: 'no_active_loa' },
      };
    },
  };

  const targetDetail = {
    async getTargetDetail(ctx, targetId, _query = {}) {
      const bundle = await portalRevamp.getTargetDetailBundle(ctx, targetId, _query);
      if (bundle) return bundle;
      return { error: 'not_found', status: 404 };
    },
  };

  const remediation = {
    async attachToFinding(ctx, findingId, payload = {}) {
      const existing = await portalRevamp.getFindingRemediationByFinding(ctx, findingId);
      if (existing) return { remediation: existing };

      const steps = Array.isArray(payload.steps)
        ? payload.steps.map((step) => String(step))
        : ['Review finding evidence', 'Apply recommended control change', 'Re-run validation'];
      const record = await portalRevamp.insertFindingRemediation(ctx, {
        id: `rem_${Date.now()}`,
        finding_id: findingId,
        action_slug: String(payload.action_slug ?? 'origin_restrict'),
        owner_group: String(payload.owner_group ?? 'edge-sre'),
        state: 'open',
        description: String(payload.description ?? 'Remediation plan for linked finding.'),
        steps,
        audit_entry_id: `aud_${Date.now()}`,
      });
      return { remediation: record };
    },
    async deliver(_ctx, actionItemId, channel, targetRef) {
      return {
        action_item: { action_item_id: actionItemId },
        delivery_receipt: {
          action_item_id: actionItemId,
          channel,
          target_ref: targetRef ?? null,
          status: 'delegated_to_waf_action_item_deliver',
        },
      };
    },
    async updateState(ctx, remediationId, state) {
      const record = await portalRevamp.updateFindingRemediation(ctx, remediationId, {
        state: String(state ?? '').trim(),
      });
      if (!record) return { error: 'not_found', status: 404 };
      return { remediation: record };
    },
  };

  const portalOwnership = {
    async getLadder(ctx, groupId) {
      const counts = await portalRevamp.getVerificationLadderCounts(ctx, groupId);
      const total = counts?.total ?? 0;
      const steps = LADDER_STEP_IDS.map((id) => ({
        id,
        label: LADDER_LABELS[id] ?? id,
        done: total > 0 && (counts?.[id] ?? 0) >= total,
        count: counts?.[id] ?? 0,
        total,
      }));
      return {
        steps,
        meta: total === 0
          ? { empty_reason: 'No targets declared for this group; the verification ladder cannot be computed yet.' }
          : undefined,
      };
    },
    async confirmTarget(ctx, groupId, targetId, signer) {
      const active = await portalRevamp.getActiveLoaByGroup(ctx, groupId);
      if (!active) return { error: 'loa_missing', status: 409 };
      const current = await portalRevamp.getTargetVerificationCurrent(ctx, targetId);
      if (!current || !['agent_verified', 'user_confirmed'].includes(current.state)) {
        return { error: 'verify_prereq_not_met', status: 409 };
      }
      const verification = await portalRevamp.insertTargetVerification(ctx, {
        id: newId('tv'),
        target_id: targetId,
        state: 'user_confirmed',
        source_kind: 'user_attestation',
        source_ref: { signer: signer?.signer ?? ctx.userId, loa_id: active.id },
        transitioned_at: new Date().toISOString(),
        transitioned_by: ctx.userId ?? 'system',
      }, auditRepo);
      return {
        target: { id: targetId, target_group_id: groupId },
        verification,
      };
    },
  };

  const portalFindings = {
    async getEvidenceBundle(ctx, findingId) {
      if (!validationEvidence?.getFinding) {
        return {
          finding: null,
          bundle: null,
          artifacts: [],
          custody_chain: [],
          verify_url: '/v1/custody/verify',
          meta: { empty_reason: 'evidence_service_unavailable', finding_id: findingId },
        };
      }

      const finding = await validationEvidence.getFinding(ctx, findingId);
      if (!finding) {
        return {
          finding: null,
          bundle: null,
          artifacts: [],
          custody_chain: [],
          verify_url: '/v1/custody/verify',
          meta: { empty_reason: 'finding_not_found', finding_id: findingId },
        };
      }

      const vault = finding.test_run_id && validationEvidence.listEvidenceForRun
        ? await validationEvidence.listEvidenceForRun(ctx, finding.test_run_id)
        : validationEvidence.listEvidence
          ? await validationEvidence.listEvidence(ctx, { findingId })
          : [];

      if (!vault.length) {
        return {
          finding: { id: finding.id, title: finding.title ?? null, run_id: finding.test_run_id ?? null },
          bundle: null,
          artifacts: [],
          custody_chain: [],
          verify_url: '/v1/custody/verify',
          meta: { empty_reason: 'no_evidence_bundle_sealed_for_finding', finding_id: findingId },
        };
      }

      const artifacts = vault.map((row) => ({
        id: row.id,
        kind: row.label ?? row.kind ?? 'metadata_evidence',
        run_id: row.test_run_id ?? finding.test_run_id ?? null,
        sha256: row.sha256 ?? row.content_sha256 ?? row.metadata?.sha256 ?? null,
        sealed_at: row.sealed_at ?? row.created_at ?? null,
        size_bytes: row.size_bytes ?? row.metadata?.size_bytes ?? null,
      }));

      const custody_chain = artifacts
        .filter((art) => art.sha256)
        .map((art, index) => ({
          step: index + 1,
          kind: `${art.kind}_sealed`,
          sha256: art.sha256,
          at: art.sealed_at,
        }));

      return {
        finding: { id: finding.id, title: finding.title ?? null, run_id: finding.test_run_id ?? null },
        bundle: null,
        artifacts,
        custody_chain,
        verify_url: '/v1/custody/verify',
      };
    },
  };

  const portalTargetGroups = {
    async restoreArchived(ctx, groupId) {
      const restored = await portalRevamp.restoreTargetGroup(ctx, groupId, auditRepo);
      if (!restored) {
        return { error: 'not_archived', status: 404 };
      }
      return { target_group: restored };
    },
    async bulkImportTargets(_ctx, groupId, _body) {
      return {
        imported: [],
        skipped: [],
        count: 0,
        meta: { empty_reason: 'no_targets_imported', target_group_id: groupId },
      };
    },
  };

  const portalWaf = {
    async getCoverageSummary(ctx) {
      const row = await portalRevamp.getWafCoverageSummaryRow(ctx);
      if (row) return row;
      return {
        ...EMPTY_COVERAGE_SUMMARY,
        meta: { empty_reason: 'coverage_summary_not_populated', tenant_id: ctx.tenantId },
      };
    },
    async getConnectorInventory(_ctx, connectorId, _query = {}) {
      return {
        provider: null,
        account: null,
        scope: null,
        discovered_at: null,
        items: [],
        count: 0,
        meta: { empty_reason: 'connector_inventory_not_populated', connector_id: connectorId },
      };
    },
  };

  const portalSignup = {
    async listEvents(requestId, options = {}) {
      if (options.rateLimitKey && options.rateLimit?.check) {
        const rate = options.rateLimit.check(options.rateLimitKey);
        if (!rate.allowed) {
          return {
            error: 'rate_limited',
            status: 429,
            retry_after_seconds: rate.retryAfterSeconds,
          };
        }
      }
      const events = await portalRevamp.listSignupQueueEvents(requestId, {
        truncateMessageChars: 500,
      });
      return {
        events,
        count: events.length,
        meta: events.length
          ? undefined
          : { empty_reason: 'no_signup_events_recorded', request_id: requestId },
      };
    },
  };

  return {
    portalDns,
    loa,
    targetDetail,
    remediation,
    portalOwnership,
    portalFindings,
    portalTargetGroups,
    portalWaf,
    portalSignup,
  };
}

/**
 * Merges portal revamp listChallenges into an existing dnsOwnership service adapter.
 *
 * @param {Record<string, unknown>} dnsOwnership
 * @param {{ listChallenges: (...args: unknown[]) => unknown }} portalDns
 */
export function mergePortalDnsOwnershipServices(dnsOwnership, portalDns) {
  return {
    ...dnsOwnership,
    listChallenges: portalDns.listChallenges.bind(portalDns),
    issueDnsOwnershipChallenge: portalDns.issueDnsOwnershipChallenge.bind(portalDns),
    verifyDnsOwnership: portalDns.verifyDnsOwnership.bind(portalDns),
  };
}

/**
 * Merges portal revamp ownership helpers into an existing ownershipVerification adapter.
 *
 * @param {Record<string, unknown>} ownershipVerification
 * @param {{ getLadder: (...args: unknown[]) => unknown, confirmTarget: (...args: unknown[]) => unknown }} portalOwnership
 */
export function mergePortalOwnershipVerificationServices(ownershipVerification, portalOwnership) {
  return {
    ...ownershipVerification,
    getLadder: portalOwnership.getLadder.bind(portalOwnership),
    confirmTarget: portalOwnership.confirmTarget.bind(portalOwnership),
  };
}