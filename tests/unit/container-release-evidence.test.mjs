import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import { validateProductionReleaseEvidence } from '../../src/contracts/productionReleaseEvidence.mjs';
import { PRODUCTION_RELEASE_EVIDENCE_COMPLETE as COMPLETE } from '../fixtures/productionReleaseEvidenceComplete.mjs';
import {
  buildDockerBuildCommand,
  buildDockerInspectCommand,
  buildProductionReleaseEvidenceWrapper,
  buildScannerCommand,
  createContainerEvidenceManifest,
  createControlPlaneContainerReleaseArtifact,
  main,
  parseArgs,
  validateControlPlaneContainerReleaseEvidence,
} from '../../scripts/container-release-evidence.mjs';

const VALID_EVIDENCE = { ...COMPLETE.control_plane_container_release };

const tempDirs = [];

function tempDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-container-evidence-'));
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

describe('container release evidence helpers', () => {
  it('parses defaults and explicit CLI arguments', () => {
    assert.deepEqual(parseArgs([]), {
      image: 'astranull-control-plane:local',
      dockerfile: 'Dockerfile',
      context: '.',
      out: 'output/container-release-evidence.json',
      scanner: 'none',
      promotionTarget: null,
      commit: null,
      requireScan: false,
      input: null,
      releaseId: null,
      validateOnly: false,
    });

    const opts = parseArgs([
      '--image',
      'registry.example/astranull:1',
      '--dockerfile',
      'Dockerfile',
      '--context',
      '.',
      '--out',
      'evidence.json',
      '--scanner',
      'trivy',
      '--promotion-target',
      'prod',
      '--commit',
      'abc123',
      '--require-scan',
      '--input',
      'release.json',
      '--release-id',
      'rel-1',
      '--validate-only',
    ]);
    assert.equal(opts.image, 'registry.example/astranull:1');
    assert.equal(opts.scanner, 'trivy');
    assert.equal(opts.requireScan, true);
    assert.equal(opts.input, 'release.json');
    assert.equal(opts.releaseId, 'rel-1');
    assert.equal(opts.validateOnly, true);
  });

  it('requires a real scanner when scan evidence is mandatory', () => {
    assert.throws(() => parseArgs(['--require-scan']), /requires --scanner/);
    assert.throws(() => parseArgs(['--scanner', 'unknown']), /Invalid scanner/);
  });

  it('builds docker and scanner commands without shell interpolation', () => {
    const opts = parseArgs(['--image', 'astranull:test', '--scanner', 'grype']);
    assert.deepEqual(buildDockerBuildCommand(opts), {
      cmd: 'docker',
      args: [
        'build',
        '--pull',
        '--label',
        'org.opencontainers.image.title=AstraNull Control Plane',
        '-f',
        'Dockerfile',
        '-t',
        'astranull:test',
        '.',
      ],
    });
    assert.deepEqual(buildDockerInspectCommand(opts), {
      cmd: 'docker',
      args: ['image', 'inspect', 'astranull:test', '--format', '{{json .}}'],
    });
    assert.deepEqual(buildScannerCommand(opts), {
      cmd: 'grype',
      args: ['astranull:test', '-o', 'json', '--fail-on', 'high'],
    });
    assert.equal(buildScannerCommand(parseArgs(['--scanner', 'none'])), null);
  });

  it('creates a safe release evidence manifest without env or secret dumps', () => {
    const manifest = createContainerEvidenceManifest({
      createdAt: '2026-07-02T00:00:00.000Z',
      image: 'astranull:test',
      dockerfile: 'Dockerfile',
      context: '.',
      imageId: 'sha256:abc',
      repoDigests: ['registry.example/astranull@sha256:def'],
      scanner: 'trivy',
      scanStatus: 'passed',
      promotionTarget: 'staging',
      commit: 'abc123',
      env: { ASTRANULL_DATABASE_URL: 'postgres://secret' },
    });
    assert.equal(manifest.schema_version, 1);
    assert.equal(manifest.artifact_type, 'control_plane_container');
    assert.equal(manifest.image_id, 'sha256:abc');
    assert.deepEqual(manifest.repo_digests, ['registry.example/astranull@sha256:def']);
    assert.equal(manifest.scan_status, 'passed');
    const blob = JSON.stringify(manifest);
    assert.equal(blob.includes('ASTRANULL_DATABASE_URL'), false);
    assert.equal(blob.includes('postgres://secret'), false);
    assert.match(blob, /Production promotion still requires/);
  });
});

describe('control plane container release production evidence', () => {
  it('accepts contract-valid metadata-only evidence', () => {
    const validation = validateControlPlaneContainerReleaseEvidence(VALID_EVIDENCE);
    assert.equal(validation.ok, true);
    assert.deepEqual(validation.missing_fields, []);
    assert.deepEqual(validation.forbidden_fields, []);

    const artifact = createControlPlaneContainerReleaseArtifact({ evidence: VALID_EVIDENCE, validation });
    assert.equal(artifact.production_release_evidence.kind, 'control_plane_container_release');
    const contract = validateProductionReleaseEvidence(
      'control_plane_container_release',
      artifact.production_release_evidence.evidence,
    );
    assert.equal(contract.ok, true);
  });

  it('rejects missing required fields', () => {
    const validation = validateControlPlaneContainerReleaseEvidence({
      ...VALID_EVIDENCE,
      evidence_uri: '',
      rollback_reference: null,
    });
    assert.equal(validation.ok, false);
    assert.ok(validation.missing_fields.includes('evidence_uri'));
    assert.ok(validation.missing_fields.includes('rollback_reference'));
  });

  it('rejects forbidden nested raw and secret fields', () => {
    const withRawScan = {
      ...VALID_EVIDENCE,
      scan_summary: {
        ...VALID_EVIDENCE.scan_summary,
        raw_scan_log: 'CVE-2026-0001 full output',
      },
    };
    const rawValidation = validateControlPlaneContainerReleaseEvidence(withRawScan);
    assert.equal(rawValidation.ok, false);
    assert.ok(rawValidation.forbidden_fields.some((field) => field.includes('raw_scan_log')));

    const withToken = {
      ...VALID_EVIDENCE,
      signing_summary: {
        ...VALID_EVIDENCE.signing_summary,
        registry_token: 'reg_v1.secret.token',
      },
    };
    const tokenValidation = validateControlPlaneContainerReleaseEvidence(withToken);
    assert.equal(tokenValidation.ok, false);
    assert.ok(tokenValidation.forbidden_fields.some((field) => field.includes('registry_token')));
  });

  it('does not leak registry credentials into production release evidence output', () => {
    const tainted = {
      ...VALID_EVIDENCE,
      promotion_summary: {
        ...VALID_EVIDENCE.promotion_summary,
        registry_credentials: {
          auths: {
            'registry.example': { auth: 'c3VwZXItc2VjcmV0OnBhc3N3b3Jk' },
          },
        },
      },
    };
    const validation = validateControlPlaneContainerReleaseEvidence(tainted);
    assert.equal(validation.ok, false);

    const { wrapper } = buildProductionReleaseEvidenceWrapper({
      evidence: tainted,
      validation,
    });
    const blob = JSON.stringify(wrapper);
    assert.equal(blob.includes('c3VwZXItc2VjcmV0OnBhc3N3b3Jk'), false);
    assert.equal(blob.includes('super-secret'), false);
    assert.equal(blob.includes('registry_credentials'), false);
    assert.equal(blob.includes('auths'), false);
  });

  it('writes metadata-only artifacts via --input without docker', async () => {
    const dir = tempDir();
    const inputPath = path.join(dir, 'input.json');
    const outPath = path.join(dir, 'artifact.json');
    writeJson(inputPath, VALID_EVIDENCE);

    const code = await main(['--input', inputPath, '--out', outPath, '--validate-only']);
    assert.equal(code, 0);
    assert.equal(existsSync(outPath), false);

    const writeCode = await main(['--input', inputPath, '--out', outPath]);
    assert.equal(writeCode, 0);
    const artifact = JSON.parse(readFileSync(outPath, 'utf8'));
    assert.equal(artifact.artifact_type, 'control_plane_container_release_evidence');
    assert.equal(artifact.production_release_evidence.kind, 'control_plane_container_release');
    assert.equal(
      validateProductionReleaseEvidence(
        'control_plane_container_release',
        artifact.production_release_evidence.evidence,
      ).ok,
      true,
    );
  });
});