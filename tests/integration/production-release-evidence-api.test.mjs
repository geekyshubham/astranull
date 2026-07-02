import assert from 'node:assert/strict';
import { after, afterEach, before, describe, it } from 'node:test';
import { PRODUCTION_RELEASE_EVIDENCE_KINDS } from '../../src/contracts/productionReleaseEvidence.mjs';
import { createServer } from '../../src/server.mjs';
import { getStore } from '../../src/store.mjs';
import {
  completeEvidenceRecords,
  PRODUCTION_RELEASE_EVIDENCE_COMPLETE,
} from '../fixtures/productionReleaseEvidenceComplete.mjs';
import { demoHeaders, request } from '../helpers/http.mjs';
import { freshStore } from '../helpers/reset.mjs';

const envSnapshot = { ...process.env };

let baseUrl;
let server;

const SECURITY_REVIEW_EVIDENCE = {
  reviewer_org: 'Independent Security Review Co',
  scope_summary: 'Production API, UI, SOC workflow, agent control, and release process.',
  review_report_uri: 'evidence://security-review/report',
  findings_status: 'all-critical-high-remediated',
  remediation_tracker_uri: 'evidence://security-review/remediation-tracker',
  risk_acceptance_reference: 'risk://accepted-medium-items',
  reviewed_at: '2026-07-02T00:00:00.000Z',
  security_owner: 'security-lead',
};

function restoreEnv() {
  for (const key of Object.keys(process.env)) {
    if (!(key in envSnapshot)) delete process.env[key];
  }
  Object.assign(process.env, envSnapshot);
}

before(() => {
  freshStore();
  process.env.ASTRANULL_NO_PERSIST = '1';
  server = createServer();
  server.listen(0);
  const { port } = server.address();
  baseUrl = `http://127.0.0.1:${port}`;
});

after(() => {
  server?.close();
  restoreEnv();
});

afterEach(() => {
  freshStore();
  process.env.ASTRANULL_NO_PERSIST = '1';
});

describe('production release evidence API', () => {
  it('lets admins create, list, and get metadata-only release evidence', async () => {
    const admin = demoHeaders('admin', 'ten_demo', 'usr_release_admin');
    const created = await request(baseUrl, 'POST', '/v1/production-release-evidence', {
      headers: admin,
      body: {
        kind: 'third_party_security_review',
        release_id: 'rel_2026_07_02',
        evidence: SECURITY_REVIEW_EVIDENCE,
        notes: 'security review accepted with svc_v1.fake.fake.fake redacted',
      },
    });
    assert.equal(created.status, 201);
    assert.equal(created.json.evidence.kind, 'third_party_security_review');
    assert.equal(created.json.evidence.release_id, 'rel_2026_07_02');
    assert.equal(created.json.evidence.status, 'accepted');
    assert.equal(created.json.evidence.created_by, 'usr_release_admin');
    assert.equal(created.json.evidence.notes.includes('svc_v1.fake.fake.fake'), false);
    assert.equal(created.json.evidence.validation.ok, true);

    const listed = await request(baseUrl, 'GET', '/v1/production-release-evidence', {
      headers: admin,
    });
    assert.equal(listed.status, 200);
    assert.equal(listed.json.items.length, 1);
    assert.equal(listed.json.items[0].id, created.json.evidence.id);

    const fetched = await request(
      baseUrl,
      'GET',
      `/v1/production-release-evidence/${created.json.evidence.id}`,
      { headers: admin },
    );
    assert.equal(fetched.status, 200);
    assert.equal(fetched.json.id, created.json.evidence.id);
  });

  it('rejects viewer reads and writes', async () => {
    const viewer = demoHeaders('viewer', 'ten_demo', 'usr_viewer');
    const list = await request(baseUrl, 'GET', '/v1/production-release-evidence', {
      headers: viewer,
    });
    assert.equal(list.status, 403);
    assert.equal(list.json.permission, 'release_evidence:read');

    const create = await request(baseUrl, 'POST', '/v1/production-release-evidence', {
      headers: viewer,
      body: {
        kind: 'third_party_security_review',
        evidence: SECURITY_REVIEW_EVIDENCE,
      },
    });
    assert.equal(create.status, 403);
    assert.equal(create.json.permission, 'release_evidence:write');
  });

  it('returns missing field errors without persisting', async () => {
    const admin = demoHeaders('admin');
    const evidence = { ...SECURITY_REVIEW_EVIDENCE };
    delete evidence.review_report_uri;
    const created = await request(baseUrl, 'POST', '/v1/production-release-evidence', {
      headers: admin,
      body: {
        kind: 'third_party_security_review',
        evidence,
      },
    });
    assert.equal(created.status, 400);
    assert.equal(created.json.error, 'missing_evidence_fields');
    assert.deepEqual(created.json.missing_fields, ['review_report_uri']);
    assert.equal(getStore().productionReleaseEvidence.length, 0);
  });

  it('returns invalid field errors and does not persist weak governed adapter evidence', async () => {
    const admin = demoHeaders('admin');
    const created = await request(baseUrl, 'POST', '/v1/production-release-evidence', {
      headers: admin,
      body: {
        kind: 'governed_adapter',
        evidence: {
          ...PRODUCTION_RELEASE_EVIDENCE_COMPLETE.governed_adapter,
          adapter_type: 'partner_http',
        },
      },
    });
    assert.equal(created.status, 400);
    assert.equal(created.json.error, 'invalid_evidence_fields');
    assert.ok(created.json.invalid_fields.some((entry) => entry.field === 'adapter_type'));
    assert.equal(getStore().productionReleaseEvidence.length, 0);
  });

  it('returns forbidden field errors and does not persist raw or secret-bearing evidence', async () => {
    const admin = demoHeaders('admin');
    const created = await request(baseUrl, 'POST', '/v1/production-release-evidence', {
      headers: admin,
      body: {
        kind: 'third_party_security_review',
        evidence: {
          ...SECURITY_REVIEW_EVIDENCE,
          token: 'svc_v1.fake.fake.fake',
          attachment: { raw_log: 'contains sensitive evidence' },
        },
      },
    });
    assert.equal(created.status, 400);
    assert.equal(created.json.error, 'forbidden_evidence_fields');
    assert.deepEqual(created.json.forbidden_fields.sort(), ['attachment', 'attachment.raw_log', 'token']);
    assert.equal(getStore().productionReleaseEvidence.length, 0);
  });

  it('keeps audit metadata free of evidence text and secret markers', async () => {
    const admin = demoHeaders('soc', 'ten_demo', 'usr_soc');
    const secretMarker = 'ast_v1.fake.fake.fake';
    const created = await request(baseUrl, 'POST', '/v1/production-release-evidence', {
      headers: admin,
      body: {
        kind: 'third_party_security_review',
        release_id: 'rel_audit_safe',
        evidence: SECURITY_REVIEW_EVIDENCE,
        notes: `do not leak ${secretMarker}`,
      },
    });
    assert.equal(created.status, 201);
    const auditEntry = getStore().auditLog.find(
      (entry) => entry.action === 'production_release_evidence.recorded',
    );
    assert.ok(auditEntry);
    assert.deepEqual(auditEntry.metadata, {
      kind: 'third_party_security_review',
      release_id: 'rel_audit_safe',
    });
    const auditText = JSON.stringify(auditEntry);
    assert.equal(auditText.includes('Independent Security Review Co'), false);
    assert.equal(auditText.includes(secretMarker), false);
  });

  it('denies attestation reads to viewers', async () => {
    const viewer = demoHeaders('viewer', 'ten_demo', 'usr_viewer');
    const res = await request(baseUrl, 'GET', '/v1/production-release-evidence/attestation', {
      headers: viewer,
    });
    assert.equal(res.status, 403);
    assert.equal(res.json.permission, 'release_evidence:read');
  });

  it('returns metadata-only attestation with production_ready false when evidence is missing', async () => {
    const admin = demoHeaders('admin');
    const res = await request(baseUrl, 'GET', '/v1/production-release-evidence/attestation', {
      headers: admin,
    });
    assert.equal(res.status, 200);
    assert.equal(res.json.attestation.artifact_type, 'staging_readiness_attestation');
    assert.equal(res.json.attestation.production_ready, false);
    assert.equal(res.json.attestation.signoff_status, 'missing_evidence');
    assert.deepEqual(res.json.records, []);
    assert.equal(
      res.json.attestation.required_evidence_kinds.missing.length,
      PRODUCTION_RELEASE_EVIDENCE_KINDS.length,
    );
    assert.ok(res.json.attestation.blocker_summary.length > 0);
  });

  it('returns production_ready true when all required kinds are accepted and omits evidence bodies', async () => {
    const admin = demoHeaders('admin', 'ten_demo', 'usr_release_complete');
    const releaseId = 'rel_attestation_complete';
    const markerNote = 'operator note must not leak in attestation';
    const markerScope = PRODUCTION_RELEASE_EVIDENCE_COMPLETE.third_party_security_review.scope_summary;

    for (const record of completeEvidenceRecords(PRODUCTION_RELEASE_EVIDENCE_KINDS)) {
      const created = await request(baseUrl, 'POST', '/v1/production-release-evidence', {
        headers: admin,
        body: {
          kind: record.kind,
          release_id: releaseId,
          evidence: record.evidence,
          notes: markerNote,
        },
      });
      assert.equal(created.status, 201, `expected 201 for kind ${record.kind}`);
    }

    const res = await request(baseUrl, 'GET', '/v1/production-release-evidence/attestation', {
      headers: admin,
    });
    assert.equal(res.status, 200);
    assert.equal(res.json.attestation.production_ready, true);
    assert.equal(res.json.attestation.signoff_status, 'evidence_complete');
    assert.equal(res.json.attestation.release_id, releaseId);
    assert.equal(res.json.records.length, PRODUCTION_RELEASE_EVIDENCE_KINDS.length);
    for (const summary of res.json.records) {
      assert.ok(summary.id);
      assert.ok(summary.kind);
      assert.equal(summary.status, 'accepted');
      assert.equal('evidence' in summary, false);
      assert.equal('notes' in summary, false);
      assert.ok(summary.validation?.ok);
    }

    const blob = JSON.stringify(res.json);
    assert.equal(blob.includes(markerNote), false);
    assert.equal(blob.includes(markerScope), false);
    assert.equal(blob.includes('reviewer_org'), false);
  });

  it('rejects rehearsal and sample release evidence before persistence', async () => {
    const admin = demoHeaders('admin', 'ten_demo', 'usr_rehearsal_reject');
    const record = completeEvidenceRecords(['third_party_security_review'])[0];

    const sampleRelease = await request(baseUrl, 'POST', '/v1/production-release-evidence', {
      headers: admin,
      body: {
        kind: record.kind,
        release_id: 'rel-sample-rehearsal',
        evidence: record.evidence,
      },
    });
    assert.equal(sampleRelease.status, 400);
    assert.equal(sampleRelease.json.error, 'rehearsal_evidence_rejected');
    assert.equal(getStore().productionReleaseEvidence.length, 0);

    const flaggedBody = await request(baseUrl, 'POST', '/v1/production-release-evidence', {
      headers: admin,
      body: {
        kind: record.kind,
        release_id: 'rel_real_gate',
        rehearsal_only: true,
        evidence: record.evidence,
      },
    });
    assert.equal(flaggedBody.status, 400);
    assert.equal(flaggedBody.json.error, 'rehearsal_evidence_rejected');
    assert.equal(getStore().productionReleaseEvidence.length, 0);

    const attestation = await request(baseUrl, 'GET', '/v1/production-release-evidence/attestation', {
      headers: admin,
    });
    assert.equal(attestation.status, 200);
    assert.equal(attestation.json.attestation.production_ready, false);
    assert.notEqual(attestation.json.attestation.signoff_status, 'evidence_complete');
  });

  it('isolates list and get by tenant', async () => {
    const tenantA = demoHeaders('admin', 'ten_demo', 'usr_admin_a');
    const tenantB = demoHeaders('admin', 'ten_other', 'usr_admin_b');
    const created = await request(baseUrl, 'POST', '/v1/production-release-evidence', {
      headers: tenantA,
      body: {
        kind: 'third_party_security_review',
        evidence: SECURITY_REVIEW_EVIDENCE,
      },
    });
    assert.equal(created.status, 201);

    const listed = await request(baseUrl, 'GET', '/v1/production-release-evidence', {
      headers: tenantB,
    });
    assert.equal(listed.status, 200);
    assert.deepEqual(listed.json.items, []);

    const fetched = await request(
      baseUrl,
      'GET',
      `/v1/production-release-evidence/${created.json.evidence.id}`,
      { headers: tenantB },
    );
    assert.equal(fetched.status, 404);
  });
});
