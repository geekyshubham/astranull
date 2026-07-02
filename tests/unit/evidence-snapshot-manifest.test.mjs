import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import {
  computeSnapshotHash,
  createEvidenceSnapshotManifest,
  main,
  parseArgs,
  validateEvidenceSnapshotBatch,
} from '../../scripts/evidence-snapshot-manifest.mjs';

const DIGEST_A = 'a'.repeat(64);
const DIGEST_B = 'b'.repeat(64);

const tempDirs = [];

function tempDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-snapshot-manifest-'));
  tempDirs.push(dir);
  return dir;
}

function writeJson(file, value) {
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop(), { recursive: true, force: true });
  }
});

function snapshotBody(overrides = {}) {
  const base = {
    snapshot_id: 'snap_2026_07_02_001',
    custody_manifest_digest: DIGEST_A,
    storage_reference: 'evidence://immutable/tenant-a/2026-07-02/snap-001',
    retention_policy: {
      metadata_retention_days: 90,
      report_days: 365,
      audit_log_days: 2555,
      legal_hold: false,
    },
    signer: {
      key_reference: 'key://vault/astranull/evidence-signing/staging',
      algorithm: 'ed25519',
      signature_reference: 'evidence://signatures/staging/snap-001',
    },
    previous_snapshot_hash: null,
    operator_signoff: {
      operator: 'custody-operator',
      signed_at: '2026-07-02T12:00:00.000Z',
      signoff_reference: 'signoff://custody/snapshot-batch-2026-07-02',
    },
    ...overrides,
  };
  return { ...base, snapshot_hash: computeSnapshotHash(base) };
}

function buildValidBatch(extraSnapshots = []) {
  const first = snapshotBody();
  const snapshots = [first];
  for (const extra of extraSnapshots) {
    const prevHash = snapshots[snapshots.length - 1].snapshot_hash;
    const next = snapshotBody({
      snapshot_id: extra.snapshot_id,
      custody_manifest_digest: extra.custody_manifest_digest ?? DIGEST_B,
      storage_reference: extra.storage_reference ?? 'evidence://immutable/tenant-a/2026-07-02/snap-002',
      previous_snapshot_hash: prevHash,
      ...extra,
    });
    snapshots.push(next);
  }
  return {
    schema_version: 1,
    artifact_type: 'immutable_evidence_snapshot_batch',
    tenant_id: 'ten_a',
    batch_id: 'snapbatch_2026_07_02',
    snapshots,
  };
}

describe('evidence snapshot manifest utility', () => {
  it('parses CLI arguments', () => {
    assert.deepEqual(parseArgs(['--input', 'batch.json']), {
      input: 'batch.json',
      out: 'output/evidence-snapshot-manifest.json',
      validateOnly: false,
      help: false,
    });
    assert.throws(() => parseArgs([]), /--input is required/);
  });

  it('accepts a valid chained snapshot batch', () => {
    const batch = buildValidBatch([
      { snapshot_id: 'snap_2026_07_02_002' },
    ]);
    const result = validateEvidenceSnapshotBatch(batch);
    assert.equal(result.ok, true);
    assert.deepEqual(result.gaps, []);
    assert.deepEqual(result.forbidden_fields, []);
    assert.equal(result.snapshot_count, 2);
  });

  it('reports broken chain and missing legal hold gaps', () => {
    const broken = buildValidBatch([{ snapshot_id: 'snap_2026_07_02_002' }]);
    broken.snapshots[1].previous_snapshot_hash = 'c'.repeat(64);
    const chainResult = validateEvidenceSnapshotBatch(broken);
    assert.equal(chainResult.ok, false);
    assert.ok(chainResult.gaps.includes('snapshots[1].previous_snapshot_hash:chain_break'));

    const missingHold = buildValidBatch();
    delete missingHold.snapshots[0].retention_policy.legal_hold;
    const holdResult = validateEvidenceSnapshotBatch(missingHold);
    assert.equal(holdResult.ok, false);
    assert.ok(holdResult.gaps.includes('snapshots[0].retention_policy.legal_hold:missing'));
  });

  it('rejects forbidden raw payload fields', () => {
    const batch = buildValidBatch();
    batch.snapshots[0].evidence_payload = { packet_payload: 'do not store' };
    const result = validateEvidenceSnapshotBatch(batch);
    assert.equal(result.ok, false);
    assert.ok(result.forbidden_fields.includes('snapshots[0].evidence_payload'));

    assert.throws(
      () => createEvidenceSnapshotManifest({ batch, validation: result }),
      /forbidden content/,
    );
  });

  it('creates a redacted manifest without secrets or database URLs', () => {
    const batch = buildValidBatch();
    batch.snapshots[0].operator_signoff.signoff_reference =
      'signoff://custody/ast_v1.fake.fake.fake';
    batch.snapshots[0].snapshot_hash = computeSnapshotHash(batch.snapshots[0]);
    const validation = validateEvidenceSnapshotBatch(batch);
    const manifest = createEvidenceSnapshotManifest({
      batch,
      validation,
      createdAt: '2026-07-02T13:00:00.000Z',
    });
    assert.equal(manifest.validation.ok, true);
    assert.equal(manifest.artifact_type, 'immutable_evidence_snapshot_manifest');
    const blob = JSON.stringify(manifest);
    assert.equal(blob.includes('ast_v1.fake.fake.fake'), false);
    assert.match(blob, /\[REDACTED\]/);
    assert.equal(manifest.summary.snapshots.length, 1);
  });

  it('writes manifest via CLI main', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'batch.json');
    const out = path.join(dir, 'manifest.json');
    writeJson(input, buildValidBatch());
    const code = await main(['--input', input, '--out', out]);
    assert.equal(code, 0);
    assert.equal(existsSync(out), true);
    const written = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(written.validation.ok, true);
    assert.deepEqual(written.gaps, []);
    assert.equal(written.summary.tenant_id, 'ten_a');
  });
});