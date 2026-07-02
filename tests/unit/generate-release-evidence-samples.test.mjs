import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import { PRODUCTION_RELEASE_EVIDENCE_KINDS } from '../../src/contracts/productionReleaseEvidence.mjs';
import {
  FORBIDDEN_SECRET_MARKERS,
  SAMPLE_OUTPUT_FILES,
  SAMPLE_REHEARSAL_CAVEATS,
  assertSampleArtifactsValid,
  buildSampleEvidenceRecords,
  generateSampleArtifacts,
  main,
  parseArgs,
} from '../../scripts/generate-release-evidence-samples.mjs';

const tempDirs = [];

function tempDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-sample-evidence-'));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop(), { recursive: true, force: true });
  }
});

describe('generate release evidence samples', () => {
  it('parses defaults and explicit CLI arguments', () => {
    assert.deepEqual(parseArgs([]), {
      outDir: 'output',
      releaseId: 'rel-sample-rehearsal',
      validateOnly: false,
      help: false,
    });
    assert.deepEqual(parseArgs([
      '--out-dir',
      'tmp/out',
      '--release-id',
      'rel_custom',
      '--validate-only',
    ]), {
      outDir: 'tmp/out',
      releaseId: 'rel_custom',
      validateOnly: true,
      help: false,
    });
    assert.throws(() => parseArgs(['--unknown']), /Unknown argument/);
  });

  it('builds sample records for every required production release evidence kind', () => {
    const payload = buildSampleEvidenceRecords({
      releaseId: 'rel_kinds',
      createdAt: '2026-07-02T12:00:00.000Z',
    });
    assert.equal(payload.artifact_type, 'production_release_evidence_sample_records');
    assert.equal(payload.rehearsal_only, true);
    assert.equal(payload.records.length, PRODUCTION_RELEASE_EVIDENCE_KINDS.length);
    const kinds = new Set(payload.records.map((entry) => entry.kind));
    for (const kind of PRODUCTION_RELEASE_EVIDENCE_KINDS) {
      assert.ok(kinds.has(kind), `missing sample record for ${kind}`);
      assert.equal(payload.records.find((entry) => entry.kind === kind).status, 'accepted');
    }
    for (const caveat of SAMPLE_REHEARSAL_CAVEATS) {
      assert.ok(payload.caveats.includes(caveat));
    }
  });

  it('generates a structurally complete bundle with rehearsal-only attestation from the fixture', () => {
    const artifacts = generateSampleArtifacts({
      releaseId: 'rel_fixture_complete',
      createdAt: '2026-07-02T12:00:00.000Z',
    });

    assert.equal(artifacts.bundle.coverage.complete, true);
    assert.equal(artifacts.bundle.records.length, PRODUCTION_RELEASE_EVIDENCE_KINDS.length);
    for (const record of artifacts.bundle.records) {
      assert.equal(record.validation.ok, true, `bundle validation failed for ${record.kind}`);
    }

    assert.equal(artifacts.attestation.production_ready, false);
    assert.equal(artifacts.attestation.signoff_status, 'rehearsal_only');
    assert.equal(artifacts.attestation.required_evidence_kinds.missing.length, 0);
    assert.ok(artifacts.attestation.blocker_summary.some((line) => /Rehearsal\/sample evidence/.test(line)));

    assertSampleArtifactsValid(artifacts);

    for (const caveat of SAMPLE_REHEARSAL_CAVEATS) {
      assert.ok(artifacts.bundle.caveats.includes(caveat));
      assert.ok(artifacts.attestation.caveats.includes(caveat));
    }
    assert.equal(artifacts.bundle.rehearsal_only, true);
    assert.equal(artifacts.attestation.rehearsal_only, true);
  });

  it('omits forbidden secret markers from generated artifacts', () => {
    const artifacts = generateSampleArtifacts({ releaseId: 'rel_forbidden_scan' });
    const blob = JSON.stringify(artifacts);
    for (const marker of FORBIDDEN_SECRET_MARKERS) {
      assert.equal(blob.includes(marker), false, `found forbidden marker: ${marker}`);
    }
  });

  it('validate-only succeeds without writing output files', async () => {
    const dir = tempDir();
    const code = await main(['--out-dir', dir, '--validate-only', '--release-id', 'rel_validate']);
    assert.equal(code, 0);
    assert.equal(existsSync(path.join(dir, SAMPLE_OUTPUT_FILES.records)), false);
    assert.equal(existsSync(path.join(dir, SAMPLE_OUTPUT_FILES.bundle)), false);
    assert.equal(existsSync(path.join(dir, SAMPLE_OUTPUT_FILES.attestation)), false);
  });

  it('writes default output files under --out-dir', async () => {
    const dir = tempDir();
    const code = await main(['--out-dir', dir, '--release-id', 'rel_write']);
    assert.equal(code, 0);

    const recordsPath = path.join(dir, SAMPLE_OUTPUT_FILES.records);
    const bundlePath = path.join(dir, SAMPLE_OUTPUT_FILES.bundle);
    const attestationPath = path.join(dir, SAMPLE_OUTPUT_FILES.attestation);
    assert.equal(existsSync(recordsPath), true);
    assert.equal(existsSync(bundlePath), true);
    assert.equal(existsSync(attestationPath), true);

    const records = JSON.parse(readFileSync(recordsPath, 'utf8'));
    const bundle = JSON.parse(readFileSync(bundlePath, 'utf8'));
    const attestation = JSON.parse(readFileSync(attestationPath, 'utf8'));

    assert.equal(records.release_id, 'rel_write');
    assert.equal(bundle.release_id, 'rel_write');
    assert.equal(attestation.release_id, 'rel_write');
    assert.equal(bundle.coverage.complete, true);
    assert.equal(attestation.production_ready, false);
    assert.equal(attestation.signoff_status, 'rehearsal_only');

    const combined = JSON.stringify({ records, bundle, attestation });
    for (const marker of FORBIDDEN_SECRET_MARKERS) {
      assert.equal(combined.includes(marker), false, `written output contains ${marker}`);
    }
    for (const caveat of SAMPLE_REHEARSAL_CAVEATS) {
      assert.ok(combined.includes(caveat));
    }
  });
});