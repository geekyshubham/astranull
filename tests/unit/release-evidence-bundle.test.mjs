import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, it } from 'node:test';
import { PRODUCTION_RELEASE_EVIDENCE_KINDS } from '../../src/contracts/productionReleaseEvidence.mjs';
import {
  createReleaseEvidenceBundle,
  main,
  parseArgs,
  parseInputJson,
  summarizeBundleCoverage,
  validateEvidenceRecord,
} from '../../scripts/release-evidence-bundle.mjs';
import {
  NEW_PRODUCTION_RELEASE_EVIDENCE_KINDS,
  PRODUCTION_RELEASE_EVIDENCE_COMPLETE,
  completeEvidenceRecords,
} from '../fixtures/productionReleaseEvidenceComplete.mjs';

const FIXTURES_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '../fixtures/release-evidence-samples');
const SECURITY_REVIEW = PRODUCTION_RELEASE_EVIDENCE_COMPLETE.third_party_security_review;
const GOVERNED_ADAPTER = PRODUCTION_RELEASE_EVIDENCE_COMPLETE.governed_adapter;

const tempDirs = [];

function tempDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-release-evidence-'));
  tempDirs.push(dir);
  return dir;
}

function writeJson(file, value) {
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function loadSampleJson(filename) {
  return JSON.parse(readFileSync(path.join(FIXTURES_DIR, filename), 'utf8'));
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop(), { recursive: true, force: true });
  }
});

describe('release evidence bundle utility', () => {
  it('parses defaults and explicit CLI arguments', () => {
    assert.deepEqual(parseArgs(['--input', 'evidence.json']), {
      input: 'evidence.json',
      out: 'output/release-evidence-bundle.json',
      releaseId: null,
      validateOnly: false,
      help: false,
    });
    assert.deepEqual(parseArgs([
      '--input',
      'evidence.json',
      '--out',
      'bundle.json',
      '--release-id',
      'rel_2026_07_02',
      '--validate-only',
    ]), {
      input: 'evidence.json',
      out: 'bundle.json',
      releaseId: 'rel_2026_07_02',
      validateOnly: true,
      help: false,
    });
    assert.throws(() => parseArgs([]), /--input is required/);
  });

  it('creates a valid metadata-only bundle', () => {
    const bundle = createReleaseEvidenceBundle({
      createdAt: '2026-07-02T00:00:00.000Z',
      releaseId: 'rel_2026_07_02',
      records: [{ kind: 'third_party_security_review', evidence: SECURITY_REVIEW }],
      database_url: 'postgres://secret',
    });
    assert.equal(bundle.schema_version, 1);
    assert.equal(bundle.artifact_type, 'production_release_evidence_bundle');
    assert.equal(bundle.release_id, 'rel_2026_07_02');
    assert.equal(bundle.records.length, 1);
    assert.equal(bundle.records[0].kind, 'third_party_security_review');
    assert.equal(bundle.records[0].release_id, 'rel_2026_07_02');
    assert.equal(bundle.records[0].validation.ok, true);
    assert.deepEqual(bundle.coverage.supported_kinds, [...PRODUCTION_RELEASE_EVIDENCE_KINDS]);
    assert.equal(bundle.coverage.complete, false);
    const blob = JSON.stringify(bundle);
    assert.equal(blob.includes('postgres://secret'), false);
  });

  it('accepts every supported production release evidence kind', () => {
    const records = completeEvidenceRecords(PRODUCTION_RELEASE_EVIDENCE_KINDS);
    const bundle = createReleaseEvidenceBundle({
      createdAt: '2026-07-02T00:00:00.000Z',
      releaseId: 'rel_full',
      records,
    });
    assert.equal(bundle.records.length, PRODUCTION_RELEASE_EVIDENCE_KINDS.length);
    assert.equal(bundle.coverage.complete, true);
    assert.deepEqual(bundle.coverage.kinds_missing, []);
    for (const kind of PRODUCTION_RELEASE_EVIDENCE_KINDS) {
      const record = bundle.records.find((entry) => entry.kind === kind);
      assert.ok(record, `missing bundled record for ${kind}`);
      assert.equal(record.validation.ok, true);
    }
  });

  it('loads JSON samples for newly added evidence kinds', () => {
    for (const kind of NEW_PRODUCTION_RELEASE_EVIDENCE_KINDS) {
      const sample = loadSampleJson(`${kind}.json`);
      assert.equal(sample.kind, kind);
      const bundled = validateEvidenceRecord(sample);
      assert.equal(bundled.validation.ok, true);
    }
  });

  it('bundles full-release sample input from fixtures', async () => {
    const dir = tempDir();
    const input = path.join(FIXTURES_DIR, 'full-release-bundle-input.json');
    const out = path.join(dir, 'bundle.json');
    const code = await main(['--input', input, '--out', out, '--release-id', 'rel_fixture_full']);
    assert.equal(code, 0);
    const bundle = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(bundle.coverage.complete, true);
    assert.equal(bundle.records.length, PRODUCTION_RELEASE_EVIDENCE_KINDS.length);
  });

  it('summarizes bundle coverage for partial inputs', () => {
    const summary = summarizeBundleCoverage([
      { kind: 'migration_apply' },
      { kind: 'operator_runbook_exercise' },
    ]);
    assert.equal(summary.complete, false);
    assert.ok(summary.kinds_missing.length > 0);
    assert.ok(!summary.kinds_missing.includes('migration_apply'));
  });

  it('rejects missing required fields', () => {
    const evidence = { ...SECURITY_REVIEW };
    delete evidence.review_report_uri;
    assert.throws(
      () => validateEvidenceRecord({ kind: 'third_party_security_review', evidence }),
      /missing required field\(s\): review_report_uri/,
    );
  });

  it('rejects forbidden raw or secret-bearing fields', () => {
    assert.throws(
      () => validateEvidenceRecord({
        kind: 'third_party_security_review',
        evidence: {
          ...SECURITY_REVIEW,
          token: 'svc_v1.fake.fake.fake',
          attachment: { raw_log: 'do not store' },
        },
      }),
      /forbidden field\(s\): token, attachment, attachment.raw_log/,
    );
  });

  it('rejects shared-contract forbidden nested fields through bundle validation', () => {
    const cases = [
      { kind: 'observability_slo', path: 'metric_scrape_auth.secret', value: 'rotate-me' },
      { kind: 'probe_fleet_matrix', path: 'rows[0].logs', value: ['line'] },
      { kind: 'vector_safety_policy', path: 'customer_runnable_policies[0].payload', value: 'bytes' },
      { kind: 'secret_rotation_drill', path: 'drill_summary.ciphertext', value: 'enc' },
      { kind: 'support_readiness', path: 'readiness_summary.password', value: 'x' },
      { kind: 'evidence_snapshot_manifest', path: 'summary.snapshots[0].attachment', value: {} },
      { kind: 'postgres_tenant_query_audit', path: 'findings[0].raw_sql', value: 'SELECT' },
      { kind: 'notification_provider_config', path: 'providers[0].api_key', value: 'key' },
    ];
    for (const { kind, path: fieldPath, value } of cases) {
      const evidence = structuredClone(PRODUCTION_RELEASE_EVIDENCE_COMPLETE[kind]);
      const segments = fieldPath.split('.');
      let cursor = evidence;
      for (let i = 0; i < segments.length - 1; i += 1) {
        const segment = segments[i];
        const match = segment.match(/^(.+)\[(\d+)\]$/);
        if (match) {
          if (!cursor[match[1]]) cursor[match[1]] = [];
          if (!cursor[match[1]][Number(match[2])]) cursor[match[1]][Number(match[2])] = {};
          cursor = cursor[match[1]][Number(match[2])];
        } else {
          cursor = cursor[segment];
        }
      }
      const last = segments[segments.length - 1];
      const lastMatch = last.match(/^(.+)\[(\d+)\]$/);
      if (lastMatch) {
        if (!cursor[lastMatch[1]]) cursor[lastMatch[1]] = [];
        cursor[lastMatch[1]][Number(lastMatch[2])] = value;
      } else {
        cursor[last] = value;
      }
      assert.throws(() => {
        validateEvidenceRecord({ kind, evidence });
      }, (err) => {
        assert.match(err.message, /forbidden field\(s\):/);
        assert.ok(err.message.includes(fieldPath), `${kind}: expected ${fieldPath} in ${err.message}`);
        return true;
      });
    }
  });

  it('validate-only does not write output', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'input.json');
    const out = path.join(dir, 'bundle.json');
    writeJson(input, { records: [{ kind: 'third_party_security_review', evidence: SECURITY_REVIEW }] });
    const code = await main(['--input', input, '--out', out, '--release-id', 'rel_validate', '--validate-only']);
    assert.equal(code, 0);
    assert.equal(existsSync(out), false);
  });

  it('writes generated output and omits unknown secret extras', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'input.json');
    const out = path.join(dir, 'bundle.json');
    writeJson(input, {
      records: [{ kind: 'third_party_security_review', evidence: SECURITY_REVIEW, notes: 'ready' }],
      token: 'ast_v1.fake.fake.fake',
      database_url: 'postgres://secret',
    });
    const code = await main(['--input', input, '--out', out, '--release-id', 'rel_write']);
    assert.equal(code, 0);
    const bundle = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(bundle.records[0].notes, 'ready');
    const blob = JSON.stringify(bundle);
    assert.equal(blob.includes('ast_v1.fake.fake.fake'), false);
    assert.equal(blob.includes('postgres://secret'), false);
  });

  it('rejects top-level rehearsal_only on createReleaseEvidenceBundle', () => {
    assert.throws(
      () => createReleaseEvidenceBundle({
        rehearsal_only: true,
        releaseId: 'rel_prod',
        records: [{ kind: 'third_party_security_review', evidence: SECURITY_REVIEW }],
      }),
      /Rehearsal\/sample evidence cannot be bundled/,
    );
  });

  it('rejects sample and rehearsal top-level release ids', () => {
    assert.throws(
      () => createReleaseEvidenceBundle({
        releaseId: 'rel-sample-rehearsal',
        records: [{ kind: 'third_party_security_review', evidence: SECURITY_REVIEW }],
      }),
      /Rehearsal\/sample evidence cannot be bundled/,
    );
  });

  it('rejects per-record rehearsal_only and sample release ids', () => {
    assert.throws(
      () => createReleaseEvidenceBundle({
        releaseId: 'rel_prod',
        records: [{
          kind: 'third_party_security_review',
          evidence: SECURITY_REVIEW,
          rehearsal_only: true,
        }],
      }),
      /Rehearsal\/sample evidence cannot be bundled/,
    );
    assert.throws(
      () => createReleaseEvidenceBundle({
        releaseId: 'rel_prod',
        records: [{
          kind: 'third_party_security_review',
          evidence: SECURITY_REVIEW,
          release_id: 'rel_sample_walkthrough',
        }],
      }),
      /Rehearsal\/sample evidence cannot be bundled/,
    );
  });

  it('rejects dry-run and draft records from bundles', () => {
    assert.throws(
      () => createReleaseEvidenceBundle({
        release_id: 'rel_prod',
        dry_run: true,
        submittable: false,
        records: [{ kind: 'third_party_security_review', evidence: SECURITY_REVIEW }],
      }),
      /non-submittable/,
    );
    assert.throws(
      () => createReleaseEvidenceBundle({
        release_id: 'rel_prod',
        records: [{
          kind: 'third_party_security_review',
          evidence: SECURITY_REVIEW,
          status: 'draft',
          dry_run: true,
          submittable: false,
        }],
      }),
      /non-submittable/,
    );
  });

  it('rejects evidence.rehearsal_only on records', () => {
    assert.throws(
      () => createReleaseEvidenceBundle({
        releaseId: 'rel_prod',
        records: [{
          kind: 'third_party_security_review',
          evidence: { ...SECURITY_REVIEW, rehearsal_only: true },
        }],
      }),
      /Rehearsal\/sample evidence cannot be bundled/,
    );
  });

  it('CLI object input with top-level rehearsal_only rejects', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'input.json');
    writeJson(input, {
      rehearsal_only: true,
      release_id: 'rel_prod',
      records: [{ kind: 'third_party_security_review', evidence: SECURITY_REVIEW }],
    });
    await assert.rejects(
      () => main(['--input', input, '--release-id', 'rel_cli_override']),
      /Rehearsal\/sample evidence cannot be bundled/,
    );
  });

  it('parseInputJson preserves top-level markers on object input', () => {
    const dir = tempDir();
    const input = path.join(dir, 'input.json');
    writeJson(input, {
      release_id: 'rel_from_file',
      rehearsal_only: false,
      records: [{ kind: 'third_party_security_review', evidence: SECURITY_REVIEW }],
    });
    const parsed = parseInputJson(input);
    assert.equal(parsed.release_id, 'rel_from_file');
    assert.equal(parsed.rehearsal_only, undefined);
    assert.equal(parsed.records.length, 1);
  });

  it('validateEvidenceRecord rejects strict contract invalid fields', () => {
    assert.throws(
      () => validateEvidenceRecord({
        kind: 'governed_adapter',
        evidence: { ...GOVERNED_ADAPTER, adapter_type: 'partner_http' },
      }),
      /governed_adapter contains invalid field\(s\): adapter_type/,
    );
    assert.throws(
      () => validateEvidenceRecord({
        kind: 'governed_adapter',
        evidence: {
          ...GOVERNED_ADAPTER,
          dry_run_status: {
            ...GOVERNED_ADAPTER.dry_run_status,
            traffic_generated: true,
          },
        },
      }),
      /dry_run_status\.traffic_generated/,
    );
  });

  it('redacts token-looking strings in allowed evidence fields and notes', () => {
    const bundle = createReleaseEvidenceBundle({
      releaseId: 'rel_redact',
      records: [{
        kind: 'third_party_security_review',
        evidence: {
          ...SECURITY_REVIEW,
          scope_summary: 'reviewed svc_v1.fake.fake.fake in staging reference',
        },
        notes: 'operator note ast_v1.fake.fake.fake',
      }],
    });
    const blob = JSON.stringify(bundle);
    assert.equal(blob.includes('svc_v1.fake.fake.fake'), false);
    assert.equal(blob.includes('ast_v1.fake.fake.fake'), false);
    assert.match(blob, /\[REDACTED\]/);
  });
});