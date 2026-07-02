import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import {
  REQUIRED_CONCURRENCY_ROUTE_FAMILIES,
  createPostgresConcurrencyManifest,
  main,
  parseArgs,
  validatePostgresConcurrencyEvidence,
} from '../../scripts/postgres-concurrency-evidence.mjs';

const tempDirs = [];

function tempDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-pg-concurrency-'));
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

function buildValidEvidence(overrides = {}) {
  return {
    schema_version: 1,
    artifact_type: 'postgres_tenant_concurrency_evidence',
    environment: 'staging',
    tenant_count: 3,
    concurrent_actors: 12,
    duration_seconds: 180,
    route_families_exercised: [...REQUIRED_CONCURRENCY_ROUTE_FAMILIES],
    isolation: {
      cross_tenant_read_rejections: 48,
      cross_tenant_write_rejections: 22,
      cross_tenant_leaks: 0,
    },
    rls_evidence: {
      error_ids: ['rls_err_staging_20260702_01', 'rls_err_staging_20260702_02'],
      audit_evidence_ids: ['aud_staging_20260702_09'],
    },
    operator_signoff: {
      operator: 'platform-ops',
      signed_at: '2026-07-02T18:00:00.000Z',
      reference: 'ticket://staging/concurrency/2026-07-02',
    },
    ...overrides,
  };
}

describe('postgres concurrency evidence parser', () => {
  it('parses CLI arguments', () => {
    assert.deepEqual(parseArgs(['--input', 'evidence.json']), {
      input: 'evidence.json',
      out: 'output/postgres-concurrency-evidence-manifest.json',
      validateOnly: false,
      help: false,
    });
    assert.throws(() => parseArgs([]), /--input is required/);
  });
});

describe('postgres concurrency evidence validation', () => {
  it('accepts valid metadata-only staging evidence', () => {
    const result = validatePostgresConcurrencyEvidence(buildValidEvidence());
    assert.equal(result.ok, true);
    assert.deepEqual(result.errors, []);
    assert.deepEqual(result.forbidden_fields, []);
    assert.deepEqual(result.coverage_gaps, []);
  });

  it('reports missing route family coverage gaps', () => {
    const evidence = buildValidEvidence({
      route_families_exercised: REQUIRED_CONCURRENCY_ROUTE_FAMILIES.filter(
        (family) => family !== 'audit' && family !== 'state',
      ),
    });
    const result = validatePostgresConcurrencyEvidence(evidence);
    assert.equal(result.ok, false);
    assert.deepEqual(result.coverage_gaps, [
      'missing_route_family:state',
      'missing_route_family:audit',
    ]);
  });

  it('fails when cross-tenant leaks are observed', () => {
    const result = validatePostgresConcurrencyEvidence(
      buildValidEvidence({
        isolation: {
          cross_tenant_read_rejections: 10,
          cross_tenant_write_rejections: 4,
          cross_tenant_leaks: 2,
        },
      }),
    );
    assert.equal(result.ok, false);
    assert.match(result.errors.join('; '), /cross_tenant_leaks must be 0/);
  });

  it('rejects forbidden database URLs and raw SQL in evidence strings', () => {
    const urlResult = validatePostgresConcurrencyEvidence(
      buildValidEvidence({
        operator_signoff: {
          operator: 'platform-ops',
          signed_at: '2026-07-02T18:00:00.000Z',
          reference: 'postgresql://user:pass@db.internal/astranull',
        },
      }),
    );
    assert.equal(urlResult.ok, false);
    assert.ok(urlResult.forbidden_fields.some((f) => f.includes('database_url_pattern')));

    const sqlResult = validatePostgresConcurrencyEvidence(
      buildValidEvidence({
        rls_evidence: {
          error_ids: ['SELECT id, tenant_id FROM targets WHERE tenant_id = $1'],
          audit_evidence_ids: ['aud_staging_20260702_09'],
        },
      }),
    );
    assert.equal(sqlResult.ok, false);
    assert.ok(sqlResult.forbidden_fields.some((f) => f.includes('raw_sql_pattern')));

    const keyResult = validatePostgresConcurrencyEvidence(
      buildValidEvidence({ database_url: 'postgres://secret' }),
    );
    assert.equal(keyResult.ok, false);
    assert.ok(keyResult.forbidden_fields.includes('database_url'));
  });

  it('creates a redacted manifest without secrets or row payloads', () => {
    const manifest = createPostgresConcurrencyManifest({
      createdAt: '2026-07-02T19:00:00.000Z',
      evidence: buildValidEvidence({
        operator_signoff: {
          operator: 'platform-ops',
          signed_at: '2026-07-02T18:00:00.000Z',
          reference: 'ticket://staging/concurrency/ast_v1.redacted.token.here',
        },
      }),
    });
    assert.equal(manifest.validation_ok, true);
    assert.equal(manifest.artifact_type, 'postgres_tenant_concurrency_manifest');
    assert.deepEqual(manifest.coverage_gaps, []);
    const blob = JSON.stringify(manifest);
    assert.equal(blob.includes('ast_v1.redacted'), false);
    assert.equal(blob.includes('postgres://'), false);
    assert.equal(manifest.summary.tenant_count, 3);
    assert.match(manifest.summary.operator_signoff.reference, /\[REDACTED\]/);
  });

  it('writes manifest via CLI main', async () => {
    const dir = tempDir();
    const input = path.join(dir, 'evidence.json');
    const out = path.join(dir, 'manifest.json');
    writeJson(input, buildValidEvidence());
    const code = await main(['--input', input, '--out', out]);
    assert.equal(code, 0);
    assert.equal(existsSync(out), true);
    const written = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(written.validation_ok, true);
    assert.equal(written.summary.concurrent_actors, 12);
  });
});