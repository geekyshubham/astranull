import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import {
  AGENT_INSTALL_MATRIX_CHECKS,
  AGENT_INSTALL_MATRIX_FORMATS,
  createAgentInstallMatrixSummary,
  main,
  parseArgs,
  validateMatrixEvidence,
} from '../../scripts/agent-install-matrix-evidence.mjs';

const tempDirs = [];

function tempDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-agent-matrix-'));
  tempDirs.push(dir);
  return dir;
}

function writeJson(file, value) {
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function checkPassed(extra = {}) {
  return {
    status: 'passed',
    observed_at: '2026-07-02T00:00:00.000Z',
    ...extra,
  };
}

function buildRow(format, overrides = {}) {
  const { checks: checkOverrides, ...rest } = overrides;
  const signingFormat = format === 'generic' ? 'tarball' : format;
  const trustAnchorByFormat = {
    generic: 'ed25519://tenant/agent-update-trust-key',
    deb: 'gpg://astranull/agent-package-signing',
    rpm: 'gpg://astranull/agent-package-signing',
    container: 'cosign://astranull/agent-release-signer',
    kubernetes: 'cosign://astranull/agent-release-signer',
  };
  const checks = {
    install: checkPassed(),
    heartbeat: checkPassed({ heartbeat_count: 2 }),
    job_poll: checkPassed({ job_poll_count: 1 }),
    upgrade_rollback: checkPassed(),
    revoke: checkPassed(),
    uninstall: checkPassed(),
    no_inbound_port: checkPassed({ inbound_listener_count: 0 }),
    signature_verify: checkPassed({
      signing_format: signingFormat,
      trust_anchor_reference: trustAnchorByFormat[format],
    }),
    ...checkOverrides,
  };
  const row = {
    format,
    environment: 'staging',
    agent_id_redacted: 'ag_…01',
    checks,
    ...rest,
  };
  if (format === 'container') {
    row.runtime = row.runtime ?? 'docker';
    row.image_reference_redacted = row.image_reference_redacted ?? 'registry.example/astranull-agent@sha256:…01';
  }
  if (format === 'kubernetes') {
    row.runtime = row.runtime ?? 'kubernetes';
    row.deployment_mode = row.deployment_mode ?? 'daemonset';
    row.namespace_redacted = row.namespace_redacted ?? 'astranull-…';
  }
  return row;
}

function completeMatrixRows() {
  return AGENT_INSTALL_MATRIX_FORMATS.map((format) => buildRow(format));
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop(), { recursive: true, force: true });
  }
});

describe('agent install matrix evidence utility', () => {
  it('parses defaults and explicit CLI arguments', () => {
    assert.deepEqual(parseArgs(['--input', 'matrix.json']), {
      input: 'matrix.json',
      out: 'output/agent-install-matrix-evidence.json',
      matrixId: null,
      validateOnly: false,
      help: false,
    });
    assert.deepEqual(parseArgs([
      '--input',
      'matrix.json',
      '--out',
      'summary.json',
      '--matrix-id',
      'matrix_staging_2026_07',
      '--validate-only',
    ]), {
      input: 'matrix.json',
      out: 'summary.json',
      matrixId: 'matrix_staging_2026_07',
      validateOnly: true,
      help: false,
    });
    assert.throws(() => parseArgs([]), /--input is required/);
  });

  it('accepts a complete matrix across all required formats', () => {
    const summary = createAgentInstallMatrixSummary({
      matrixId: 'matrix_complete',
      rows: completeMatrixRows(),
    });
    assert.equal(summary.overall_status, 'passed');
    assert.equal(summary.rows.length, AGENT_INSTALL_MATRIX_FORMATS.length);
    assert.deepEqual(summary.coverage_gaps.missing_formats, []);
    assert.deepEqual(summary.coverage_gaps.failed_checks, []);
    for (const format of AGENT_INSTALL_MATRIX_FORMATS) {
      const row = summary.rows.find((r) => r.format === format);
      assert.ok(row, `missing summary row for ${format}`);
      assert.equal(row.status, 'passed');
      for (const check of AGENT_INSTALL_MATRIX_CHECKS) {
        assert.equal(row.checks[check], 'passed');
      }
    }
  });

  it('reports missing format coverage gaps', () => {
    const rows = completeMatrixRows().filter((r) => r.format !== 'kubernetes');
    const summary = createAgentInstallMatrixSummary({ rows });
    assert.equal(summary.overall_status, 'incomplete');
    assert.deepEqual(summary.coverage_gaps.missing_formats, ['kubernetes']);
    assert.equal(summary.coverage_gaps.formats_covered.includes('kubernetes'), false);
  });

  it('marks matrix failed when revoke or uninstall checks fail', () => {
    const revokeFail = createAgentInstallMatrixSummary({
      rows: [
        buildRow('generic', {
          checks: {
            revoke: { status: 'failed', observed_at: '2026-07-02T01:00:00.000Z' },
          },
        }),
      ],
    });
    assert.equal(revokeFail.overall_status, 'failed');
    assert.deepEqual(revokeFail.coverage_gaps.failed_checks, ['generic.revoke']);

    const uninstallFail = createAgentInstallMatrixSummary({
      rows: [
        buildRow('deb', {
          checks: {
            uninstall: { status: 'failed', observed_at: '2026-07-02T01:00:00.000Z' },
          },
        }),
      ],
    });
    assert.equal(uninstallFail.overall_status, 'failed');
    assert.deepEqual(uninstallFail.coverage_gaps.failed_checks, ['deb.uninstall']);
  });

  it('rejects forbidden token and log fields', () => {
    assert.throws(
      () => validateMatrixEvidence({
        rows: [
          buildRow('generic', {
            token: 'ast_v1.fake.fake.fake',
          }),
        ],
      }),
      /forbidden field\(s\): token/,
    );
    assert.throws(
      () => validateMatrixEvidence({
        rows: [
          buildRow('container', {
            checks: {
              install: checkPassed(),
              heartbeat: checkPassed(),
              job_poll: checkPassed(),
              upgrade_rollback: checkPassed(),
              revoke: checkPassed(),
              uninstall: checkPassed(),
              no_inbound_port: checkPassed({ inbound_listener_count: 0 }),
            },
            attachment: { raw_log: 'must not persist' },
          }),
        ],
      }),
      /forbidden field\(s\): attachment.raw_log/,
    );
  });

  it('validate-only does not write output', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'input.json');
    const out = path.join(dir, 'summary.json');
    writeJson(input, { matrix_id: 'matrix_validate', rows: completeMatrixRows() });
    const code = await main(['--input', input, '--out', out, '--validate-only']);
    assert.equal(code, 0);
    assert.equal(existsSync(out), false);
  });

  it('writes generated output and omits secret extras from input envelope', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'input.json');
    const out = path.join(dir, 'summary.json');
    writeJson(input, {
      matrix_id: 'matrix_write',
      rows: completeMatrixRows(),
      database_url: 'postgres://secret',
      token: 'ast_v1.fake.fake.fake',
    });
    const code = await main(['--input', input, '--out', out, '--matrix-id', 'matrix_write']);
    assert.equal(code, 0);
    const summary = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(summary.matrix_id, 'matrix_write');
    assert.equal(summary.overall_status, 'passed');
    const blob = JSON.stringify(summary);
    assert.equal(blob.includes('postgres://secret'), false);
    assert.equal(blob.includes('ast_v1.fake.fake.fake'), false);
    assert.equal(blob.includes('database_url'), false);
  });

  it('requires docker and kubernetes scenario metadata', () => {
    assert.throws(
      () => validateMatrixEvidence({
        rows: [buildRow('container', { runtime: '' })],
      }),
      /runtime required for container scenario/,
    );
    assert.throws(
      () => validateMatrixEvidence({
        rows: [buildRow('kubernetes', { deployment_mode: '' })],
      }),
      /deployment_mode required for kubernetes scenario/,
    );
    const summary = createAgentInstallMatrixSummary({ rows: completeMatrixRows() });
    const container = summary.rows.find((r) => r.format === 'container');
    const kubernetes = summary.rows.find((r) => r.format === 'kubernetes');
    assert.equal(container.runtime, 'docker');
    assert.equal(kubernetes.runtime, 'kubernetes');
    assert.equal(kubernetes.deployment_mode, 'daemonset');
    assert.equal(container.checks.signature_verify, 'passed');
  });

  it('redacts token-like strings in allowed metadata fields', () => {
    const summary = createAgentInstallMatrixSummary({
      rows: [
        buildRow('generic', {
          agent_id_redacted: 'ag svc_v1.fake.fake.fake note',
        }),
      ],
    });
    const blob = JSON.stringify(summary);
    assert.equal(blob.includes('svc_v1.fake.fake.fake'), false);
    assert.match(blob, /\[REDACTED\]/);
  });
});