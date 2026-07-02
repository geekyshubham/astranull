import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import {
  assertSafePackageReference,
  collectAgentSbomProvenanceEvidence,
  createAgentSbomProvenanceManifest,
  detectEvidenceSecrets,
  digestFileArtifact,
  main,
  parseArgs,
  validateProvenanceDocument,
  validateSbomDocument,
} from '../../scripts/agent-sbom-provenance-evidence.mjs';

const tempDirs = [];

function tempDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-agent-sbom-'));
  tempDirs.push(dir);
  return dir;
}

function writeJson(file, value) {
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function writeBytes(file, content) {
  writeFileSync(file, content);
}

function sha256Hex(content) {
  return createHash('sha256').update(content).digest('hex');
}

const MINIMAL_SBOM = {
  bomFormat: 'CycloneDX',
  specVersion: '1.4',
  serialNumber: 'urn:uuid:11111111-1111-4111-8111-111111111111',
  components: [{ type: 'application', name: 'astranull-agent', version: '1.0.0' }],
};

const MINIMAL_PROVENANCE = {
  _type: 'https://in-toto.io/Statement/v1',
  subject: [{ name: 'astranull-agent', digest: { sha256: 'abc' } }],
  materials: [{ uri: 'git+https://example/astranull@main' }],
  predicateType: 'https://slsa.dev/provenance/v1',
  predicate: { builder: { id: 'local-builder' } },
};

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop(), { recursive: true, force: true });
  }
});

describe('agent SBOM/provenance evidence utility', () => {
  it('parses defaults and explicit CLI arguments', () => {
    assert.deepEqual(parseArgs([
      '--package',
      'dist/agent/pkg.tar.gz',
      '--sbom',
      'sbom.json',
      '--provenance',
      'prov.json',
    ]), {
      package: 'dist/agent/pkg.tar.gz',
      sbom: 'sbom.json',
      provenance: 'prov.json',
      out: 'output/agent-sbom-provenance-evidence.json',
      format: 'generic',
      help: false,
    });

    const opts = parseArgs([
      '--package',
      'pkg.deb',
      '--sbom',
      'sbom.json',
      '--provenance',
      'prov.json',
      '--out',
      'evidence.json',
      '--format',
      'deb',
    ]);
    assert.equal(opts.format, 'deb');
    assert.equal(opts.out, 'evidence.json');
    assert.throws(() => parseArgs([]), /--package is required/);
    assert.throws(() => parseArgs(['--package', 'x', '--sbom', 's']), /--provenance is required/);
    assert.throws(
      () => parseArgs(['--package', 'x', '--sbom', 's', '--provenance', 'p', '--format', 'msi']),
      /Invalid format/,
    );
  });

  it('computes digest and size for non-empty files', () => {
    const dir = tempDir();
    const file = path.join(dir, 'artifact.tar.gz');
    const body = 'agent-package-bytes';
    writeBytes(file, body);
    const digest = digestFileArtifact(file, 'package');
    assert.equal(digest.sha256, sha256Hex(body));
    assert.equal(digest.size, Buffer.byteLength(body));
    assert.throws(() => digestFileArtifact(path.join(dir, 'missing')), /not found/);
    writeBytes(path.join(dir, 'empty'), '');
    assert.throws(() => digestFileArtifact(path.join(dir, 'empty')), /empty/);
  });

  it('rejects unsafe package names and path traversal references', () => {
    assert.equal(assertSafePackageReference('dist/agent/astranull-agent.tar.gz'), 'astranull-agent.tar.gz');
    assert.throws(() => assertSafePackageReference('../escape.tar.gz'), /Unsafe package/);
    assert.throws(() => assertSafePackageReference('foo/../../bar.tar.gz'), /Unsafe package/);
    assert.throws(() => assertSafePackageReference('bad name.tar.gz'), /Unsafe package name/);
  });

  it('validates CycloneDX and SPDX SBOM markers', () => {
    assert.deepEqual(validateSbomDocument(MINIMAL_SBOM), {
      sbom_format: 'cyclonedx',
      spec_version: '1.4',
      serial_number: 'urn:uuid:11111111-1111-4111-8111-111111111111',
      spdx_id: null,
      component_count: 1,
    });
    assert.deepEqual(validateSbomDocument({
      spdxVersion: 'SPDX-2.3',
      SPDXID: 'SPDXRef-DOCUMENT',
      packages: [{ name: 'astranull-agent' }],
    }).sbom_format, 'spdx');
    assert.throws(() => validateSbomDocument({ name: 'not-sbom' }), /CycloneDX or SPDX/);
  });

  it('validates provenance subject, materials, and predicate metadata', () => {
    assert.equal(validateProvenanceDocument(MINIMAL_PROVENANCE).subject_count, 1);
    assert.equal(validateProvenanceDocument(MINIMAL_PROVENANCE).materials_count, 1);
    assert.throws(
      () => validateProvenanceDocument({ subject: [], materials: [] }),
      /subject, materials, and predicate/,
    );
  });

  it('rejects evidence containing obvious secrets or tokens', () => {
    assert.throws(
      () => detectEvidenceSecrets('bootstrap ast_v1.fake.fake.fake', 'SBOM'),
      /forbidden secret/,
    );
    assert.throws(
      () => detectEvidenceSecrets('postgres://user:pass@db.example/astranull', 'provenance'),
      /forbidden secret/,
    );
    assert.doesNotThrow(() => detectEvidenceSecrets('safe-metadata-only', 'SBOM'));
  });

  it('creates a redacted manifest without echoing sensitive summary keys', () => {
    const manifest = createAgentSbomProvenanceManifest({
      createdAt: '2026-07-02T00:00:00.000Z',
      format: 'tar',
      packageName: 'astranull-agent.tar.gz',
      package: { path: '/tmp/pkg.tar.gz', sha256: 'aa'.repeat(32), size: 10 },
      sbom: { path: '/tmp/sbom.json', sha256: 'bb'.repeat(32), size: 20 },
      provenance: { path: '/tmp/prov.json', sha256: 'cc'.repeat(32), size: 30 },
      sbomSummary: { spec_version: '1.4', token: 'must-not-appear' },
      provenanceSummary: { predicate_type: 'slsa', api_key: 'hidden' },
    });
    assert.equal(manifest.artifact_type, 'agent_sbom_provenance');
    const blob = JSON.stringify(manifest);
    assert.equal(blob.includes('must-not-appear'), false);
    assert.equal(blob.includes('hidden'), false);
    assert.match(blob, /does not execute packages/);
    assert.match(blob, /not a substitute|still requires package signing|install matrix/);
  });

  it('writes evidence output from real files', async () => {
    const dir = tempDir();
    const pkg = path.join(dir, 'astranull-agent.tar.gz');
    const sbom = path.join(dir, 'sbom.json');
    const prov = path.join(dir, 'provenance.json');
    const out = path.join(dir, 'evidence.json');
    writeBytes(pkg, 'tarball-contents');
    writeJson(sbom, MINIMAL_SBOM);
    writeJson(prov, MINIMAL_PROVENANCE);

    const code = await main([
      '--package',
      pkg,
      '--sbom',
      sbom,
      '--provenance',
      prov,
      '--format',
      'tar',
      '--out',
      out,
    ]);
    assert.equal(code, 0);
    assert.equal(existsSync(out), true);
    const manifest = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(manifest.package_format, 'tar');
    assert.equal(manifest.package.name, 'astranull-agent.tar.gz');
    assert.equal(manifest.package.sha256, sha256Hex('tarball-contents'));
    assert.equal(manifest.sbom.summary.sbom_format, 'cyclonedx');
    assert.equal(manifest.provenance.summary.materials_count, 1);
  });

  it('collectAgentSbomProvenanceEvidence rejects secret-bearing SBOM JSON', () => {
    const dir = tempDir();
    const pkg = path.join(dir, 'pkg.tar.gz');
    const sbom = path.join(dir, 'sbom.json');
    const prov = path.join(dir, 'provenance.json');
    writeBytes(pkg, 'pkg');
    writeJson(sbom, { ...MINIMAL_SBOM, comment: 'svc_v1.fake.fake.fake' });
    writeJson(prov, MINIMAL_PROVENANCE);
    assert.throws(
      () => collectAgentSbomProvenanceEvidence({ package: pkg, sbom, provenance: prov }),
      /forbidden secret/,
    );
  });
});