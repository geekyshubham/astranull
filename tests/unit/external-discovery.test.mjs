import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it } from 'node:test';
import {
  canTransition,
  createCandidate,
  createEntity,
  scoreConfidence,
  validateCandidate,
} from '../../src/contracts/externalDiscovery.mjs';
import * as targetGroups from '../../src/services/targetGroups.mjs';
import * as externalDiscovery from '../../src/services/externalDiscovery.mjs';
import { getStore, resetStoreForTests } from '../../src/store.mjs';

const adminCtx = {
  tenantId: 'ten_demo',
  userId: 'usr_admin',
  role: 'admin',
  discoveryMode: 'D3_entity_discovery',
};

const originalDiscoveryFlag = process.env.ASTRANULL_EXTERNAL_DISCOVERY_ENABLED;

function enableDiscovery() {
  process.env.ASTRANULL_EXTERNAL_DISCOVERY_ENABLED = '1';
}

function disableDiscovery() {
  process.env.ASTRANULL_EXTERNAL_DISCOVERY_ENABLED = '0';
}

function baseStore() {
  return {
    tenants: [{ id: 'ten_demo', name: 'Demo' }],
    environments: [{ id: 'env_demo', tenant_id: 'ten_demo', name: 'Default' }],
    targetGroups: [
      {
        id: 'tg_demo',
        tenant_id: 'ten_demo',
        environment_id: 'env_demo',
        name: 'Declared targets',
        created_at: '2026-07-01T00:00:00.000Z',
      },
    ],
    targets: [
      {
        id: 'tgt_demo',
        tenant_id: 'ten_demo',
        target_group_id: 'tg_demo',
        kind: 'fqdn',
        value: 'app.example.com',
        created_at: '2026-07-01T00:00:00.000Z',
      },
    ],
    auditLog: [],
    discoveryEntities: [],
    discoveryCandidates: [],
  };
}

function validEntityInput(overrides = {}) {
  return {
    entity_id: 'ent_parent_1',
    entity_type: 'parent_organization',
    name: 'Example Corp',
    display_name: 'Example Corporation',
    root_domains: ['example.com'],
    country: 'US',
    confidence: 0.9,
    source: 'customer_import',
    ...overrides,
  };
}

function validCandidateInput(overrides = {}) {
  return {
    candidate_id: 'cand_sub_1',
    hostname: 'shop.example.com',
    source_type: 'dns',
    source_ref: 'redacted:dns-zone-ref-hash',
    confidence: 0.72,
    ownership_status: 'likely_owned',
    approval_status: 'not_requested',
    first_seen_at: '2026-07-01T10:00:00.000Z',
    last_seen_at: '2026-07-01T12:00:00.000Z',
    evidence_summary: {
      root_domain_match: true,
      dns_record_type: 'CNAME',
    },
    ...overrides,
  };
}

function latestAudit(action) {
  const entries = getStore().auditLog.filter((e) => e.action === action);
  return entries[entries.length - 1] ?? null;
}

describe('external discovery contract', () => {
  it('validates entity creation required fields and entity types', () => {
    const entity = createEntity(validEntityInput());
    assert.equal(entity.entity_type, 'parent_organization');
    assert.deepEqual(entity.root_domains, ['example.com']);

    assert.throws(
      () => createEntity(validEntityInput({ entity_type: 'unknown_type' })),
      /entity_type must be one of/,
    );
    assert.throws(
      () => createEntity(validEntityInput({ name: '' })),
      /name is required/,
    );
    assert.throws(
      () => createEntity(validEntityInput({ root_domains: [] })),
      /root_domains must be a non-empty array/,
    );
  });

  it('validates metadata-only candidates and rejects forbidden raw content', () => {
    const candidate = createCandidate(validCandidateInput());
    assert.equal(candidate.hostname, 'shop.example.com');
    assert.equal(candidate.evidence_summary.dns_record_type, 'CNAME');

    assert.throws(
      () => createCandidate(validCandidateInput({ html_content: '<html></html>' })),
      /Forbidden candidate field/,
    );
    assert.throws(
      () => validateCandidate({ raw_page_body: 'secret page text' }),
      /Forbidden candidate field/,
    );
    assert.throws(
      () => createCandidate(validCandidateInput({
        evidence_summary: { html_content: 'not allowed' },
      })),
      /Forbidden candidate field/,
    );
  });

  it('allows valid lifecycle transitions and rejects invalid ones', () => {
    assert.equal(canTransition('discovered', 'candidate'), true);
    assert.equal(canTransition('candidate', 'needs_review'), true);
    assert.equal(canTransition('needs_review', 'approved_target'), true);
    assert.equal(canTransition('approved_target', 'tested'), true);
    assert.equal(canTransition('tested', 'posture_tracked'), true);

    assert.equal(canTransition('candidate', 'tested'), false);
    assert.equal(canTransition('discovered', 'approved_target'), false);
    assert.equal(canTransition('rejected', 'candidate'), false);
    assert.equal(canTransition('posture_tracked', 'tested'), false);
  });

  it('scores confidence from weighted signal sources', () => {
    assert.equal(scoreConfidence({ customer_provided_target: true }), 0.95);
    assert.equal(scoreConfidence({ connector_owned_asset: true }), 0.85);
    assert.equal(scoreConfidence({ dns_under_approved_root: true }), 0.8);
    assert.equal(scoreConfidence({ passive_dns_only: true }), 0.4);

    const combined = scoreConfidence({
      dns_under_approved_root: true,
      registrar_mismatch: true,
    });
    assert.equal(combined, 0.6);

    assert.equal(scoreConfidence(['customer_provided_target']), 0.95);
    assert.equal(scoreConfidence({}), 0);
  });
});

describe('external discovery service', () => {
  beforeEach(() => {
    enableDiscovery();
    resetStoreForTests(baseStore());
  });

  afterEach(() => {
    if (originalDiscoveryFlag === undefined) {
      delete process.env.ASTRANULL_EXTERNAL_DISCOVERY_ENABLED;
    } else {
      process.env.ASTRANULL_EXTERNAL_DISCOVERY_ENABLED = originalDiscoveryFlag;
    }
  });

  it('filters discovery inbox to candidate and needs_review states only', () => {
    externalDiscovery.createCandidate(adminCtx, validCandidateInput({
      candidate_id: 'cand_inbox_1',
      hostname: 'inbox-a.example.com',
    }));

    const reviewCandidate = externalDiscovery.createCandidate(adminCtx, validCandidateInput({
      candidate_id: 'cand_inbox_2',
      hostname: 'inbox-b.example.com',
    }));
    externalDiscovery.patchCandidateState(
      adminCtx,
      reviewCandidate.candidate.id,
      'needs_review',
      { note: 'ownership unclear' },
    );

    externalDiscovery.createCandidate(adminCtx, validCandidateInput({
      candidate_id: 'cand_inbox_3',
      hostname: 'discovered-only.example.com',
      state: 'discovered',
    }));

    const approved = externalDiscovery.createCandidate(adminCtx, validCandidateInput({
      candidate_id: 'cand_inbox_4',
      hostname: 'approved.example.com',
      state: 'approved_target',
      approval_status: 'approved',
    }));
    assert.ok(approved.candidate);

    const inbox = externalDiscovery.getDiscoveryInbox(adminCtx);
    assert.equal(inbox.count, 2);
    assert.deepEqual(
      inbox.items.map((item) => item.hostname).sort(),
      ['inbox-a.example.com', 'inbox-b.example.com'].sort(),
    );
  });

  it('creates approval audit event with actor and scope hash', () => {
    const created = externalDiscovery.createCandidate(adminCtx, validCandidateInput({
      candidate_id: 'cand_approve_1',
      hostname: 'approve-me.example.com',
    }));
    const result = externalDiscovery.approveCandidateToTarget(adminCtx, created.candidate.id, {
      source_summary: { connector_snapshot_id: 'snap_hash_1' },
    });
    assert.equal(result.candidate.state, 'approved_target');
    assert.equal(result.candidate.approval_status, 'approved');
    assert.ok(result.candidate.scope_hash);

    const auditEntry = latestAudit('discovery.candidate.approved');
    assert.ok(auditEntry);
    assert.equal(auditEntry.actor_user_id, adminCtx.userId);
    assert.equal(auditEntry.metadata.actor, adminCtx.userId);
    assert.equal(auditEntry.metadata.scope_hash, result.candidate.scope_hash);
    assert.equal(auditEntry.metadata.source_summary.source_type, 'dns');
    assert.equal(auditEntry.metadata.source_summary.connector_snapshot_id, 'snap_hash_1');
  });

  it('stores minimal metadata on rejection', () => {
    const created = externalDiscovery.createCandidate(adminCtx, validCandidateInput({
      candidate_id: 'cand_reject_1',
      hostname: 'reject-me.example.com',
      evidence_summary: { root_domain_match: true, cert_san_count: 3 },
    }));
    const result = externalDiscovery.rejectCandidate(adminCtx, created.candidate.id, {
      reason: 'third_party_hosting',
    });
    assert.equal(result.candidate.state, 'rejected');
    assert.equal(result.candidate.approval_status, 'rejected');
    assert.equal(result.candidate.rejection_reason, 'third_party_hosting');
    assert.deepEqual(result.candidate.evidence_summary, {});
    assert.equal(result.candidate.raw_page_body, undefined);

    const auditEntry = latestAudit('discovery.candidate.rejected');
    assert.ok(auditEntry);
    assert.deepEqual(auditEntry.metadata, { rejection_reason: 'third_party_hosting' });
  });

  it('returns discovery_feature_disabled when feature flag is off', () => {
    disableDiscovery();
    const result = externalDiscovery.getDiscoveryInbox(adminCtx);
    assert.deepEqual(result, { error: 'discovery_feature_disabled', status: 404 });

    const createResult = externalDiscovery.createCandidate(adminCtx, validCandidateInput());
    assert.equal(createResult.error, 'discovery_feature_disabled');
  });

  it('blocks unapproved candidates from transitioning to tested', () => {
    const created = externalDiscovery.createCandidate(adminCtx, validCandidateInput({
      candidate_id: 'cand_unapproved_1',
      hostname: 'unapproved.example.com',
    }));
    const blocked = externalDiscovery.patchCandidateState(
      adminCtx,
      created.candidate.id,
      'tested',
    );
    assert.equal(blocked.error, 'discovery_candidate_not_approved');
    assert.equal(blocked.status, 403);

    const approved = externalDiscovery.approveCandidateToTarget(adminCtx, created.candidate.id);
    const allowed = externalDiscovery.patchCandidateState(
      adminCtx,
      approved.candidate.id,
      'tested',
    );
    assert.equal(allowed.candidate.state, 'tested');
    assert.equal(externalDiscovery.canImportCandidateToTargetGroup(created.candidate), false);
    assert.equal(externalDiscovery.canImportCandidateToTargetGroup(approved.candidate), true);
  });

  it('keeps declared-only mode from changing existing target group behavior', () => {
    const d0Ctx = { ...adminCtx, discoveryMode: 'D0_declared_only' };
    assert.equal(externalDiscovery.declaredOnlyModeActive(d0Ctx), true);

    const beforeGroups = targetGroups.listTargetGroups(d0Ctx);
    const beforeTargets = getStore().targets.length;

    externalDiscovery.createEntity(d0Ctx, validEntityInput({ entity_id: 'ent_d0_1' }));
    externalDiscovery.createCandidate(d0Ctx, validCandidateInput({
      candidate_id: 'cand_d0_1',
      hostname: 'd0-candidate.example.com',
    }));

    const afterGroups = targetGroups.listTargetGroups(d0Ctx);
    assert.deepEqual(afterGroups, beforeGroups);
    assert.equal(getStore().targets.length, beforeTargets);
    assert.equal(getStore().targetGroups.length, 1);
  });
});