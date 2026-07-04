import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  assertSubmittableEvidenceRecord,
  collectReleaseIds,
  dryRunEvidenceRejection,
  isDryRunEvidenceRecord,
  isNonSubmittableEvidenceRecord,
  promotionEnvironmentRejection,
  recordBelongsToReleaseScope,
  resolveAttestationReleaseScope,
} from '../../src/contracts/releaseEvidenceProvenance.mjs';

describe('release evidence provenance', () => {
  it('detects dry-run and draft records', () => {
    assert.equal(isDryRunEvidenceRecord({ dry_run: true }), true);
    assert.equal(isDryRunEvidenceRecord({ submittable: false }), true);
    assert.equal(isDryRunEvidenceRecord({ collector_dry_run: true }), true);
    assert.equal(isNonSubmittableEvidenceRecord({ status: 'draft' }), true);
    assert.equal(isDryRunEvidenceRecord({ status: 'accepted' }), false);
  });

  it('rejects dry-run bodies at API boundary', () => {
    assert.deepEqual(dryRunEvidenceRejection({ dry_run: true }), {
      error: 'dry_run_evidence_rejected',
      status: 400,
    });
    assert.equal(dryRunEvidenceRejection({ kind: 'migration_apply' }), null);
  });

  it('assertSubmittableEvidenceRecord throws for non-submittable records', () => {
    assert.throws(
      () => assertSubmittableEvidenceRecord({ kind: 'migration_apply', dry_run: true }),
      /non-submittable/,
    );
  });

  it('promotionEnvironmentRejection rejects local-staging by default', () => {
    assert.deepEqual(
      promotionEnvironmentRejection({
        kind: 'migration_apply',
        evidence: { environment: 'local-staging' },
      }),
      {
        error: 'local_staging_evidence_rejected',
        status: 400,
        environment: 'local-staging',
        allowed: ['staging', 'production'],
      },
    );
    assert.equal(
      promotionEnvironmentRejection(
        { kind: 'migration_apply', evidence: { environment: 'staging' } },
      ),
      null,
    );
  });

  it('resolveAttestationReleaseScope rejects mixed release ids without filter', () => {
    const records = [
      { kind: 'a', release_id: 'rel_A', status: 'accepted' },
      { kind: 'b', release_id: 'rel_B', status: 'accepted' },
    ];
    const mixed = resolveAttestationReleaseScope(records);
    assert.equal(mixed.mixedReleaseIds, true);
    assert.deepEqual(mixed.releaseIds, ['rel_A', 'rel_B']);

    const scoped = resolveAttestationReleaseScope(records, 'rel_A');
    assert.equal(scoped.mixedReleaseIds, false);
    assert.equal(scoped.releaseId, 'rel_A');
    assert.equal(scoped.records.length, 1);
  });

  it('collectReleaseIds ignores empty release ids', () => {
    assert.deepEqual(
      collectReleaseIds([
        { release_id: 'rel_A' },
        { release_id: '' },
        { release_id: null },
      ]),
      ['rel_A'],
    );
  });

  it('resolveAttestationReleaseScope excludes missing or blank release_id for filtered attestation', () => {
    const records = [
      { kind: 'third_party_security_review', release_id: 'rel_A', status: 'accepted' },
      { kind: 'migration_apply', status: 'accepted' },
      { kind: 'operator_runbook_exercise', release_id: '', status: 'accepted' },
      { kind: 'edge_protection', release_id: 'rel_B', status: 'accepted' },
    ];

    const scoped = resolveAttestationReleaseScope(records, 'rel_A');
    assert.equal(scoped.mixedReleaseIds, false);
    assert.equal(scoped.releaseId, 'rel_A');
    assert.equal(scoped.records.length, 1);
    assert.equal(scoped.records[0].kind, 'third_party_security_review');
    assert.equal(recordBelongsToReleaseScope(records[1], 'rel_A'), false);
    assert.equal(recordBelongsToReleaseScope(records[2], 'rel_A'), false);
  });

  it('resolveAttestationReleaseScope excludes unscoped records when inventory has one release_id', () => {
    const records = [
      { kind: 'a', release_id: 'rel_A', status: 'accepted' },
      { kind: 'b', status: 'accepted' },
      { kind: 'c', release_id: '   ', status: 'accepted' },
    ];
    const scoped = resolveAttestationReleaseScope(records);
    assert.equal(scoped.mixedReleaseIds, false);
    assert.equal(scoped.releaseId, 'rel_A');
    assert.equal(scoped.records.length, 1);
    assert.equal(scoped.records[0].kind, 'a');
  });
});