import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it } from 'node:test';
import {
  buildDiscoveryReportSummary,
  canTransition,
  confidenceHistogramBucket,
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

  it('maps confidence scores into histogram buckets', () => {
    assert.equal(confidenceHistogramBucket(0), '0.0-0.2');
    assert.equal(confidenceHistogramBucket(0.19), '0.0-0.2');
    assert.equal(confidenceHistogramBucket(0.2), '0.2-0.4');
    assert.equal(confidenceHistogramBucket(0.67), '0.6-0.8');
    assert.equal(confidenceHistogramBucket(1), '0.8-1.0');
  });

  it('builds metadata-only discovery report summary aggregates', () => {
    const summary = buildDiscoveryReportSummary(
      [
        { source_type: 'dns', confidence: 0.82, approval_status: 'not_requested' },
        { source_type: 'ct_log', confidence: 0.67, approval_status: 'pending' },
        { source_type: 'passive_dns', confidence: 0.35, approval_status: 'pending' },
        { source_type: 'connector', confidence: 0.91, approval_status: 'approved' },
        { source_type: 'registry', confidence: 0.18, approval_status: 'rejected' },
        { source_type: 'page_link', confidence: 0.55, approval_status: 'exception' },
      ],
      { generated_at: '2026-07-03T12:00:00.000Z' },
    );
    assert.equal(summary.generated_at, '2026-07-03T12:00:00.000Z');
    assert.equal(summary.total_candidates, 6);
    assert.equal(summary.candidate_sources.dns, 1);
    assert.equal(summary.candidate_sources.ct_log, 1);
    assert.equal(summary.approval_states.pending, 2);
    assert.equal(summary.approval_states.approved, 1);
    assert.equal(summary.confidence_histogram['0.8-1.0'], 2);
    assert.equal(summary.hostname, undefined);
    assert.equal(summary.evidence_summary, undefined);
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

  it('returns metadata-only discovery report summary for tenant candidates', () => {
    externalDiscovery.createCandidate(adminCtx, validCandidateInput({
      candidate_id: 'cand_summary_1',
      hostname: 'summary-a.example.com',
      source_type: 'dns',
      confidence: 0.8,
      approval_status: 'pending',
    }));
    externalDiscovery.createCandidate(adminCtx, validCandidateInput({
      candidate_id: 'cand_summary_2',
      hostname: 'summary-b.example.com',
      source_type: 'ct_log',
      confidence: 0.45,
      approval_status: 'not_requested',
    }));

    const result = externalDiscovery.getDiscoveryReportSummary(adminCtx);
    assert.equal(result.summary.total_candidates, 2);
    assert.equal(result.summary.candidate_sources.dns, 1);
    assert.equal(result.summary.candidate_sources.ct_log, 1);
    assert.equal(result.summary.approval_states.pending, 1);
    assert.equal(result.summary.approval_states.not_requested, 1);
    assert.equal(result.summary.hostname, undefined);
    assert.equal(result.summary.evidence_summary, undefined);
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

  it('ingests passive source records into inbox without creating targets', () => {
    const beforeTargets = getStore().targets.length;
    const beforeGroups = getStore().targetGroups.length;

    const result = externalDiscovery.ingestDiscoveryCandidates(adminCtx, 'passive_dns', [
      {
        hostname: 'passive-a.example.com',
        source_type: 'passive_dns',
        confidence: 0.45,
        observed_at: '2026-07-03T10:00:00.000Z',
      },
      {
        hostname: 'ct-b.example.com',
        source_type: 'certificate_transparency',
        confidence: 0.62,
        observed_at: '2026-07-03T11:00:00.000Z',
      },
    ]);
    assert.equal(result.error, 'invalid_discovery_source_record');

    const ingest = externalDiscovery.ingestDiscoveryCandidates(adminCtx, 'certificate_transparency', [
      {
        hostname: 'ct-b.example.com',
        source_type: 'certificate_transparency',
        confidence: 0.62,
        observed_at: '2026-07-03T11:00:00.000Z',
      },
    ]);
    assert.equal(ingest.created, 1);
    assert.equal(ingest.candidates[0].source_type, 'ct_log');
    assert.equal(ingest.candidates[0].approval_status, 'pending');

    const passive = externalDiscovery.ingestDiscoveryCandidates(adminCtx, 'passive_dns', [
      {
        hostname: 'passive-a.example.com',
        source_type: 'passive_dns',
        confidence: 0.45,
        observed_at: '2026-07-03T10:00:00.000Z',
      },
    ]);
    assert.equal(passive.created, 1);

    const inbox = externalDiscovery.getDiscoveryInbox(adminCtx);
    assert.equal(inbox.count, 2);

    const auditEntry = latestAudit('discovery.source_ingested');
    assert.ok(auditEntry);
    assert.equal(auditEntry.metadata.source, 'passive_dns');
    assert.equal(auditEntry.metadata.created_count, 1);

    assert.equal(getStore().targets.length, beforeTargets);
    assert.equal(getStore().targetGroups.length, beforeGroups);
  });

  it('imports approved candidate into target group with optional WAF asset', () => {
    const created = externalDiscovery.createCandidate(adminCtx, validCandidateInput({
      candidate_id: 'cand_import_1',
      hostname: 'import-me.example.com',
    }));
    const approved = externalDiscovery.approveCandidateToTarget(adminCtx, created.candidate.id);
    const beforeTargets = getStore().targets.length;
    const beforeWafAssets = getStore().wafAssets?.length ?? 0;

    const imported = externalDiscovery.importCandidateToTargetGroup(adminCtx, approved.candidate.id, {
      target_group_id: 'tg_demo',
      environment_id: 'env_demo',
      create_waf_asset: true,
    });
    assert.equal(imported.target.kind, 'fqdn');
    assert.equal(imported.target.value, 'import-me.example.com');
    assert.equal(imported.target.target_group_id, 'tg_demo');
    assert.ok(imported.waf_asset);
    assert.equal(imported.waf_asset.target_id, imported.target.id);
    assert.equal(imported.candidate.approved_target_id, imported.target.id);
    assert.equal(imported.candidate.approval_status, 'approved');
    assert.equal(imported.candidate.state, 'approved_target');

    assert.equal(getStore().targets.length, beforeTargets + 1);
    assert.equal(getStore().wafAssets.length, beforeWafAssets + 1);

    const auditEntry = latestAudit('discovery.candidate_imported');
    assert.ok(auditEntry);
    assert.equal(auditEntry.metadata.target_group_id, 'tg_demo');
    assert.equal(auditEntry.metadata.target_id, imported.target.id);
    assert.equal(auditEntry.metadata.waf_asset_id, imported.waf_asset.id);

    const duplicate = externalDiscovery.importCandidateToTargetGroup(adminCtx, approved.candidate.id, {
      target_group_id: 'tg_demo',
    });
    assert.equal(duplicate.error, 'discovery_candidate_already_imported');
    assert.equal(duplicate.status, 409);
  });

  it('rejects import for unapproved candidates', () => {
    const created = externalDiscovery.createCandidate(adminCtx, validCandidateInput({
      candidate_id: 'cand_import_blocked',
      hostname: 'not-approved.example.com',
    }));
    const blocked = externalDiscovery.importCandidateToTargetGroup(adminCtx, created.candidate.id, {
      target_group_id: 'tg_demo',
    });
    assert.equal(blocked.error, 'discovery_candidate_not_approved');
    assert.equal(blocked.status, 403);
  });

  it('imports approved candidate without WAF asset when create_waf_asset is false', () => {
    const created = externalDiscovery.createCandidate(adminCtx, validCandidateInput({
      candidate_id: 'cand_import_no_waf',
      hostname: 'no-waf.example.com',
    }));
    const approved = externalDiscovery.approveCandidateToTarget(adminCtx, created.candidate.id);
    const beforeWafAssets = getStore().wafAssets?.length ?? 0;

    const imported = externalDiscovery.importCandidateToTargetGroup(adminCtx, approved.candidate.id, {
      target_group_id: 'tg_demo',
      create_waf_asset: false,
    });
    assert.equal(imported.waf_asset, undefined);
    assert.equal(getStore().wafAssets?.length ?? 0, beforeWafAssets);
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