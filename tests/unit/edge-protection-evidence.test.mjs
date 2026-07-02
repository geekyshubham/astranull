import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import {
  EDGE_PROTECTION_CONTROL_IDS,
  EDGE_PROTECTION_REQUIRED_CONTROLS,
} from '../../src/contracts/edgeProtectionBaseline.mjs';
import {
  createEdgeProtectionEvidenceSummary,
  loadEvidenceFromOptions,
  main,
  mergeEvidenceSources,
  parseArgs,
  validateEdgeProtectionReleaseEvidence,
} from '../../scripts/edge-protection-evidence.mjs';

const tempDirs = [];

function tempDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-edge-protection-'));
  tempDirs.push(dir);
  return dir;
}

function writeJson(file, value) {
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function completeControls() {
  return EDGE_PROTECTION_REQUIRED_CONTROLS.map((control) => ({
    control_id: control.control_id,
    evidence_uri: `evidence://edge/${control.control_id}`,
    validated_at: '2026-07-02T00:00:00.000Z',
    owner: 'security-team',
    tls_policy: 'TLS 1.2+ with managed certificate rotation',
    allowed_hosts: ['app.astranull.example', 'api.astranull.example'],
    limit_summary: 'Gateway enforces bounded body, header count, and header size limits.',
    protection_summary: 'Credential-stuffing and bot protections enabled at the edge.',
    rule_family_summary: 'Managed API and application rule groups in block/challenge mode.',
    origin_exposure_summary: 'Origin accepts traffic only from the edge or private network.',
    log_destination: 'siem://edge-events',
    health_path_policy: '/health and /ready are allowlisted with narrow method and rate policy.',
    header_policy_summary: 'HSTS, frame, content-type, and referrer policies enabled.',
    spoofing_control_summary: 'Proxy strips inbound forwarding headers before adding trusted values.',
  }));
}

function completeEvidence(overrides = {}) {
  return {
    release_id: 'rel_2026_07_02',
    edge_stack_summary: 'Managed WAF and API gateway in front of customer API and UI; CDN caches static UI assets.',
    rate_limiting_summary: 'Per-IP and per-route rate limits at the gateway with burst caps on auth and write paths.',
    logging_redaction_summary: 'Edge access logs route to SIEM with authorization, cookie, and body fields stripped.',
    signoff_owner: 'security-lead',
    signoff_at: '2026-07-02T12:00:00.000Z',
    controls: completeControls(),
    ...overrides,
  };
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop(), { recursive: true, force: true });
  }
});

describe('edge protection evidence CLI', () => {
  it('parses defaults and explicit CLI arguments', () => {
    assert.deepEqual(parseArgs(['--input', 'evidence.json']), {
      input: 'evidence.json',
      controlsFile: null,
      out: 'output/edge-protection-evidence.json',
      releaseId: null,
      edgeStackSummary: null,
      rateLimitingSummary: null,
      loggingRedactionSummary: null,
      signoffOwner: null,
      signoffAt: null,
      validateOnly: false,
      help: false,
    });
    assert.deepEqual(parseArgs([
      '--controls-file',
      'controls.json',
      '--out',
      'summary.json',
      '--release-id',
      'rel_flags',
      '--edge-stack-summary',
      'CDN + WAF',
      '--rate-limiting-summary',
      'Gateway limits',
      '--logging-redaction-summary',
      'Redacted logs',
      '--signoff-owner',
      'sec-owner',
      '--signoff-at',
      '2026-07-02T00:00:00.000Z',
      '--validate-only',
    ]), {
      input: null,
      controlsFile: 'controls.json',
      out: 'summary.json',
      releaseId: 'rel_flags',
      edgeStackSummary: 'CDN + WAF',
      rateLimitingSummary: 'Gateway limits',
      loggingRedactionSummary: 'Redacted logs',
      signoffOwner: 'sec-owner',
      signoffAt: '2026-07-02T00:00:00.000Z',
      validateOnly: true,
      help: false,
    });
    assert.throws(() => parseArgs([]), /--input or --controls-file is required/);
  });

  it('merges JSON input with explicit release metadata flags', () => {
    const merged = mergeEvidenceSources(
      {
        releaseId: 'rel_from_flag',
        edgeStackSummary: 'Flagged WAF/CDN stack',
        rateLimitingSummary: 'Flagged limits',
        loggingRedactionSummary: 'Flagged redaction',
        signoffOwner: 'flag-owner',
        signoffAt: '2026-07-02T01:00:00.000Z',
      },
      {
        fileEvidence: {
          release_id: 'rel_from_file',
          controls: completeControls(),
        },
      },
    );
    assert.equal(merged.release_id, 'rel_from_flag');
    assert.equal(merged.edge_stack_summary, 'Flagged WAF/CDN stack');
    assert.equal(merged.controls.length, EDGE_PROTECTION_CONTROL_IDS.length);
  });

  it('accepts complete metadata-only evidence', () => {
    const evidence = completeEvidence();
    const validation = validateEdgeProtectionReleaseEvidence(evidence);
    assert.equal(validation.ok, true);
    const summary = createEdgeProtectionEvidenceSummary({
      createdAt: '2026-07-02T00:00:00.000Z',
      evidence,
    });
    assert.equal(summary.artifact_type, 'edge_protection_release_evidence');
    assert.equal(summary.release_id, 'rel_2026_07_02');
    assert.equal(summary.controls.length, EDGE_PROTECTION_CONTROL_IDS.length);
    assert.equal(summary.signoff.owner, 'security-lead');
  });

  it('reports missing controls and release metadata', () => {
    const evidence = completeEvidence();
    delete evidence.signoff_owner;
    evidence.controls = evidence.controls.filter(
      (control) => control.control_id !== 'origin_shielding',
    );
    const validation = validateEdgeProtectionReleaseEvidence(evidence);
    assert.equal(validation.ok, false);
    assert.deepEqual(validation.missing_controls, ['origin_shielding']);
    assert.deepEqual(validation.missing_release_fields, ['signoff_owner']);
    assert.throws(
      () => createEdgeProtectionEvidenceSummary({ evidence }),
      /Missing release metadata field\(s\): signoff_owner/,
    );
  });

  it('rejects raw payload and forbidden evidence fields', () => {
    const evidence = completeEvidence();
    const securityHeaders = evidence.controls.find(
      (control) => control.control_id === 'security_headers',
    );
    securityHeaders.raw_headers = { authorization: 'Bearer should-not-appear' };
    evidence.controls[0].metadata = { raw_log_line: 'GET /private token=secret' };

    const validation = validateEdgeProtectionReleaseEvidence(evidence);
    assert.equal(validation.ok, false);
    assert.throws(
      () => createEdgeProtectionEvidenceSummary({ evidence }),
      /Forbidden field\(s\):/,
    );
  });

  it('validate-only does not write output', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'input.json');
    const out = path.join(dir, 'summary.json');
    writeJson(input, completeEvidence());
    const code = await main(['--input', input, '--out', out, '--validate-only']);
    assert.equal(code, 0);
    assert.equal(existsSync(out), false);
  });

  it('writes redacted summary output from JSON input', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'input.json');
    const out = path.join(dir, 'summary.json');
    writeJson(input, completeEvidence({
      edge_stack_summary: 'reviewed svc_v1.fake.fake.fake at the edge',
      token: 'ast_v1.fake.fake.fake',
    }));
    const code = await main(['--input', input, '--out', out]);
    assert.equal(code, 0);
    const summary = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(summary.validation.ok, true);
    assert.match(summary.edge_stack_summary, /\[REDACTED\]/);
    const blob = JSON.stringify(summary);
    assert.equal(blob.includes('svc_v1.fake.fake.fake'), false);
    assert.equal(blob.includes('ast_v1.fake.fake.fake'), false);
    assert.equal(blob.includes('raw_headers'), false);
  });

  it('builds evidence from controls file plus explicit flags', async () => {
    const dir = tempDir();
    const controlsFile = path.join(dir, 'controls.json');
    const out = path.join(dir, 'summary.json');
    writeJson(controlsFile, { controls: completeControls() });
    const code = await main([
      '--controls-file',
      controlsFile,
      '--release-id',
      'rel_cli',
      '--edge-stack-summary',
      'API gateway with managed WAF rules',
      '--rate-limiting-summary',
      'Gateway rate limits on /v1 and auth routes',
      '--logging-redaction-summary',
      'Authorization and cookie fields omitted from edge logs',
      '--signoff-owner',
      'release-security',
      '--signoff-at',
      '2026-07-02T15:00:00.000Z',
      '--out',
      out,
    ]);
    assert.equal(code, 0);
    const summary = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(summary.release_id, 'rel_cli');
    assert.equal(summary.controls.length, EDGE_PROTECTION_CONTROL_IDS.length);
    const loaded = loadEvidenceFromOptions({
      controlsFile,
      releaseId: 'rel_cli',
      edgeStackSummary: 'API gateway with managed WAF rules',
      rateLimitingSummary: 'Gateway rate limits on /v1 and auth routes',
      loggingRedactionSummary: 'Authorization and cookie fields omitted from edge logs',
      signoffOwner: 'release-security',
      signoffAt: '2026-07-02T15:00:00.000Z',
    });
    assert.equal(validateEdgeProtectionReleaseEvidence(loaded).ok, true);
  });
});