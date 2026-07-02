import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  buildCustodyManifest,
  canonicalJsonStringify,
  CUSTODY_SCHEMA_VERSION,
  CUSTODY_UNSUPPORTED_VALUE,
  sha256CanonicalJson,
  verifyCustodyManifest,
} from '../../src/lib/custody.mjs';

describe('custody canonicalization and verification', () => {
  it('sorts object keys recursively and preserves array order', () => {
    const a = { z: 1, a: { y: 2, b: 3 }, items: [3, 1, 2] };
    const b = { a: { b: 3, y: 2 }, items: [3, 1, 2], z: 1 };
    assert.equal(canonicalJsonStringify(a), canonicalJsonStringify(b));
    assert.equal(
      canonicalJsonStringify(a),
      '{"a":{"b":3,"y":2},"items":[3,1,2],"z":1}',
    );
  });

  it('omits undefined object properties and maps undefined array slots to null', () => {
    assert.equal(canonicalJsonStringify({ a: 1, drop: undefined }), '{"a":1}');
    assert.equal(canonicalJsonStringify([1, undefined, 2]), '[1,null,2]');
  });

  it('rejects non-finite numbers and unsupported types', () => {
    assert.throws(() => canonicalJsonStringify(Number.NaN), /Unsupported/);
    assert.throws(() => canonicalJsonStringify(1n), /Unsupported/);
  });

  it('rejects Date, Map, and class instances with custody_unsupported_value', () => {
    for (const value of [new Date(), new Map([['a', 1]]), new Set([1]), /x/, Buffer.from('ab')]) {
      assert.throws(
        () => canonicalJsonStringify(value),
        (err) => err.code === CUSTODY_UNSUPPORTED_VALUE,
      );
    }
    class Box {
      constructor(x) {
        this.x = x;
      }
    }
    assert.throws(
      () => canonicalJsonStringify(new Box(1)),
      (err) => err.code === CUSTODY_UNSUPPORTED_VALUE,
    );
    assert.equal(
      verifyCustodyManifest({
        payload: { nested: new Date() },
        custody: buildCustodyManifest({
          tenant_id: 't',
          artifact_type: 'finding_export',
          artifact_id: 'f1',
          content: { ok: true },
        }),
      }).error,
      'payload_not_canonicalizable',
    );
  });

  it('canonicalizes sparse arrays like explicit undefined entries', () => {
    const sparse = [1, , 2];
    const explicit = [1, undefined, 2];
    assert.equal(canonicalJsonStringify(sparse), canonicalJsonStringify(explicit));
    assert.equal(canonicalJsonStringify(sparse), '[1,null,2]');
  });

  it('buildCustodyManifest defaults format and created_by for JSON-stable metadata', () => {
    const manifest = buildCustodyManifest({
      tenant_id: 'ten_demo',
      artifact_type: 'finding_export',
      artifact_id: 'f1',
      content: { a: 1 },
    });
    assert.equal(manifest.format, 'json');
    assert.equal(manifest.created_by, null);
    assert.equal('created_by' in manifest, true);
    assert.equal('format' in manifest, true);
    assert.equal('previous_tenant_audit_hash' in manifest, false);
  });

  it('buildCustodyManifest digests content and sorts subject_ids', () => {
    const content = { report_id: 'rpt_1', title: 'T' };
    const manifest = buildCustodyManifest({
      tenant_id: 'ten_demo',
      artifact_type: 'report_export',
      artifact_id: 'rpt_1',
      format: 'json',
      created_by: 'usr_1',
      content,
      subject_ids: ['ev_2', 'ev_1', 'rpt_1'],
      previous_audit_hash: 'abc',
      created_at: '2026-01-01T00:00:00.000Z',
    });
    assert.equal(manifest.schema_version, CUSTODY_SCHEMA_VERSION);
    assert.equal(manifest.content_sha256, sha256CanonicalJson(content));
    assert.deepEqual(manifest.subject_ids, ['ev_1', 'ev_2', 'rpt_1']);
    assert.equal(manifest.previous_audit_hash, 'abc');
  });

  it('verifyCustodyManifest accepts matching payload digest', () => {
    const payload = { finding_id: 'fnd_1', severity: 'high' };
    const custody = buildCustodyManifest({
      tenant_id: 'ten_demo',
      artifact_type: 'finding_export',
      artifact_id: 'fnd_1',
      format: 'json',
      created_by: 'usr_1',
      content: payload,
    });
    assert.deepEqual(verifyCustodyManifest({ payload, custody }), { ok: true });
  });

  it('verifyCustodyManifest rejects tampered payload', () => {
    const payload = { finding_id: 'fnd_1', severity: 'high' };
    const custody = buildCustodyManifest({
      tenant_id: 'ten_demo',
      artifact_type: 'finding_export',
      artifact_id: 'fnd_1',
      format: 'json',
      created_by: 'usr_1',
      content: payload,
    });
    const tampered = { ...payload, severity: 'low' };
    const result = verifyCustodyManifest({ payload: tampered, custody });
    assert.equal(result.ok, false);
    assert.equal(result.error, 'content_sha256_mismatch');
  });
});