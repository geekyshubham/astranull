import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import { PRODUCTION_RELEASE_EVIDENCE_KINDS } from '../../src/contracts/productionReleaseEvidence.mjs';
import {
  applyReleaseChecklistCloseouts,
  applyReleasePlanCloseouts,
  gateHasRequiredEvidence,
  loadEvidenceCloseoutManifest,
} from '../../scripts/apply-release-gate-closeouts.mjs';
import { parseReleasePlanGateTableCounts } from '../../scripts/production-readiness-gap-audit.mjs';
import {
  completeEvidenceRecords,
} from '../fixtures/productionReleaseEvidenceComplete.mjs';

const tempDirs = [];

function tempDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-gate-closeouts-'));
  tempDirs.push(dir);
  return dir;
}

function writeManifest(dir, overrides = {}) {
  const records = completeEvidenceRecords(PRODUCTION_RELEASE_EVIDENCE_KINDS).map((record) => ({
    ...record,
    status: 'accepted',
    release_id: 'rel-hosted-staging-2026-07-03',
    submittable: true,
    dry_run: false,
  }));
  const manifestPath = path.join(dir, 'records.json');
  writeFileSync(manifestPath, `${JSON.stringify({
    schema_version: 1,
    artifact_type: 'production_release_evidence_records',
    release_id: 'rel-hosted-staging-2026-07-03',
    environment: 'staging',
    submittable: true,
    dry_run: false,
    records,
    ...overrides,
  }, null, 2)}\n`);
  return manifestPath;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop(), { recursive: true, force: true });
  }
});

describe('apply release gate closeouts', () => {
  it('loads complete submittable evidence manifest', () => {
    const dir = tempDir();
    const manifestPath = writeManifest(dir);
    const manifest = loadEvidenceCloseoutManifest(manifestPath);
    assert.equal(manifest.inventoryComplete, true);
    assert.equal(manifest.kindsPresent.size, PRODUCTION_RELEASE_EVIDENCE_KINDS.length);
  });

  it('refuses dry-run manifests', () => {
    const dir = tempDir();
    const manifestPath = writeManifest(dir, { dry_run: true, submittable: false });
    assert.throws(
      () => loadEvidenceCloseoutManifest(manifestPath),
      /dry-run or non-submittable/,
    );
  });

  it('removes deferred operational config markers only when inventory is complete', () => {
    const dir = tempDir();
    const manifest = loadEvidenceCloseoutManifest(writeManifest(dir));
    const input = '- [x] OIDC — implemented. **Deferred (operational config):** real IdP';
    const output = applyReleaseChecklistCloseouts(input, manifest);
    assert.equal(output.includes('Deferred (operational config)'), false);
    assert.ok(output.includes('Closed (staging execution)'));

    const unchanged = applyReleaseChecklistCloseouts(input, { ...manifest, inventoryComplete: false });
    assert.equal(unchanged, input);
  });

  it('closes open release-plan rows only when mapped evidence kinds are present', () => {
    const dir = tempDir();
    const manifest = loadEvidenceCloseoutManifest(writeManifest(dir));
    assert.equal(
      gateHasRequiredEvidence('Independent security review', manifest),
      true,
    );

    const input = [
      '## Open production release gates',
      '| Gate | Owner | Evidence | Status |',
      '| Independent security review | Security | report | **Open** |',
      '| SOC high-scale governance | SOC | drills | **Open** |',
    ].join('\n');
    const output = applyReleasePlanCloseouts(input, manifest);
    assert.ok(output.includes('Independent security review'));
    assert.equal(output.includes('**Open**'), false);
    assert.ok(output.includes('**Closed**'));
  });

  it('applyReleasePlanCloseouts output is parseable by parseReleasePlanGateTableCounts', () => {
    const dir = tempDir();
    const manifest = loadEvidenceCloseoutManifest(writeManifest(dir));
    const input = [
      '## Open production release gates (all releases)',
      '| Gate | Owner | Evidence | Status |',
      '| Independent security review | Security | report | **Open** |',
      '| Staging QA / E2E matrix | QA | matrix | **Open** |',
    ].join('\n');
    const output = applyReleasePlanCloseouts(input, manifest);
    const counts = parseReleasePlanGateTableCounts(output);
    assert.equal(counts.external_blockers, 0);
    assert.equal(counts.open_gates, false);
  });

  it('leaves already-closed checklist lines unchanged', () => {
    const dir = tempDir();
    const manifest = loadEvidenceCloseoutManifest(writeManifest(dir));
    const input = '- [x] OIDC **Closed (staging execution):** rel-hosted-staging-2026-07-03';
    const output = applyReleaseChecklistCloseouts(input, manifest);
    assert.equal(output, input);
  });
});