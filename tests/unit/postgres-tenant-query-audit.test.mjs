import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, it } from 'node:test';
import {
  GLOBAL_TABLES,
  ROOT,
  SKIP_FILE_BASENAMES,
  TENANT_SCOPED_TABLES,
  assertReportMetadataOnly,
  auditFiles,
  auditSourceFile,
  buildProductionTenantQueryAuditEvidence,
  buildQueryLabel,
  defaultPostgresAuditPaths,
  extractSingleQuotedQueryRegions,
  hasTenantContext,
  main,
  normalizeAuditPath,
  normalizeAuditReport,
  parseArgs,
} from '../../scripts/postgres-tenant-query-audit.mjs';

const tempDirs = [];

function tempDir() {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'astranull-pg-tenant-audit-'));
  tempDirs.push(dir);
  return dir;
}

function writeFixture(name, source) {
  const dir = tempDir();
  const file = path.join(dir, name);
  writeFileSync(file, source);
  return file;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop(), { recursive: true, force: true });
  }
});

describe('postgres tenant query audit parser', () => {
  it('parses CLI arguments', () => {
    assert.deepEqual(parseArgs(['--paths', 'a.mjs,b.mjs', '--out', 'out.json']), {
      paths: ['a.mjs', 'b.mjs'],
      out: 'out.json',
      evidenceUri: '',
      allowFindings: false,
      help: false,
    });
    assert.deepEqual(parseArgs(['--allow-findings']), {
      paths: [],
      out: '',
      evidenceUri: '',
      allowFindings: true,
      help: false,
    });
    assert.throws(() => parseArgs(['--paths']), /--paths requires/);
  });

  it('exposes allowlists and default scan targets', () => {
    assert.ok(TENANT_SCOPED_TABLES.includes('test_runs'));
    assert.ok(GLOBAL_TABLES.has('platform_metrics'));
    assert.ok(SKIP_FILE_BASENAMES.has('migrations.mjs'));
    const defaults = defaultPostgresAuditPaths();
    assert.ok(defaults.some((p) => p.endsWith('coreCatalogRepository.mjs')));
    assert.ok(!defaults.some((p) => p.endsWith('migrations.mjs')));
  });
});

describe('postgres tenant query audit heuristics', () => {
  it('accepts clean tenant-scoped SQL with tenant_id predicate', () => {
    const source = `
      export function repo() {
        return withTenantContext(pool, ctx.tenantId, async (client) => {
          await client.query(
            \`SELECT id FROM test_runs WHERE tenant_id = $1 AND id = $2\`,
            [ctx.tenantId, runId],
          );
        });
      }
    `;
    const file = writeFixture('clean.mjs', source);
    const findings = auditSourceFile(file, source);
    assert.deepEqual(findings, []);
  });

  it('flags suspicious tenant table access without tenant context indicators', () => {
    const source = `
      export async function bad(pool) {
        await pool.query(\`SELECT id, status FROM test_runs WHERE id = $1\`, [runId]);
      }
    `;
    const file = writeFixture('suspicious.mjs', source);
    const findings = auditSourceFile(file, source);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].check, 'missing_tenant_context');
    assert.equal(findings[0].table, 'test_runs');
    assert.equal(findings[0].query_label, 'SELECT:test_runs');
  });

  it('allows documented global table queries', () => {
    const source = `
      export async function metrics(pool) {
        await pool.query(\`SELECT counter_name, value FROM platform_metrics WHERE counter_name = $1\`);
      }
    `;
    const file = writeFixture('global.mjs', source);
    const findings = auditSourceFile(file, source);
    assert.deepEqual(findings, []);
  });

  it('accepts dynamic WHERE builders that inject tenant_id predicates nearby', () => {
    const source = `
      async function queryEvidenceList(client, tenantId) {
        const conditions = ['tenant_id = $1'];
        await client.query(
          \`SELECT id FROM evidence_vault WHERE \${conditions.join(' AND ')}\`,
          [tenantId],
        );
      }
    `;
    const file = writeFixture('dynamic-where.mjs', source);
    assert.deepEqual(auditSourceFile(file, source), []);
  });

  it('recognizes withTenantContext and tenants id predicate exceptions', () => {
    assert.equal(
      hasTenantContext('SELECT id FROM tenants WHERE id = $1', 'tenants', ''),
      true,
    );
    assert.equal(
      hasTenantContext('SELECT active FROM soc_kill_switch', 'soc_kill_switch', 'withTenantContext(pool, id,'),
      true,
    );
    assert.equal(buildQueryLabel('SELECT id FROM events WHERE tenant_id = $1', 'events'), 'SELECT:events');
  });

  it('accepts tenant predicate builders declared before dynamic WHERE joins', () => {
    const source = `
      async function queryRuns(client, tenantId) {
        const conditions = ["tenant_id = $1"];
        await client.query(
          \`SELECT id FROM test_runs WHERE \${conditions.join(' AND ')}\`,
          [tenantId],
        );
      }
    `;
    const file = writeFixture('double-quote-conditions.mjs', source);
    assert.deepEqual(auditSourceFile(file, source), []);
  });

  it('flags single-quoted tenant table SQL without tenant context', () => {
    const source = `
      export async function bad(pool) {
        await pool.query('SELECT id FROM agents WHERE id = $1', [agentId]);
      }
    `;
    const file = writeFixture('quoted.mjs', source);
    const findings = auditSourceFile(file, source);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].table, 'agents');
  });

  it('ignores non-tenant single-quoted utility SQL', () => {
    const source = `
      await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [tenantId]);
    `;
    const file = writeFixture('utility.mjs', source);
    assert.deepEqual(auditSourceFile(file, source), []);
    assert.equal(extractSingleQuotedQueryRegions(source).length, 1);
  });
});

describe('postgres tenant query audit report', () => {
  it('writes metadata-only JSON output without SQL or customer data leakage', () => {
    const clean = writeFixture(
      'ok.mjs',
      `await client.query(\`SELECT id FROM agents WHERE tenant_id = $1\`);`,
    );
    const bad = writeFixture(
      'bad.mjs',
      `await pool.query(\`SELECT secret FROM encrypted_secrets WHERE id = $1\`);`,
    );
    const out = path.join(tempDir(), 'report.json');
    const code = main(['--paths', `${clean},${bad}`, '--out', out, '--allow-findings']);
    assert.equal(code, 0);
    assert.ok(existsSync(out));

    const report = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(report.artifact_type, 'postgres_tenant_query_audit');
    assert.equal(report.finding_count, 1);
    assert.equal(report.findings[0].table, 'encrypted_secrets');
    assert.ok(assertReportMetadataOnly(report));

    const raw = readFileSync(out, 'utf8');
    assert.ok(!raw.includes('customer_data'));
    assert.ok(!raw.includes('WHERE id = $1'));
    assert.ok(!raw.includes('SELECT secret'));
    assert.ok(raw.length < 2000);
  });

  it('exits nonzero when findings exist unless allow-findings is set', () => {
    const bad = writeFixture(
      'only-bad.mjs',
      `await pool.query(\`UPDATE findings SET status = 'open' WHERE id = $1\`);`,
    );
    assert.equal(main(['--paths', bad]), 1);
    assert.equal(main(['--paths', bad, '--allow-findings']), 0);
  });

  it('aggregates multi-file audits via auditFiles', () => {
    const good = writeFixture('good.mjs', `await client.query(\`DELETE FROM events WHERE tenant_id = $1\`);`);
    const report = auditFiles([good]);
    assert.equal(report.finding_count, 0);
    assert.ok(report.scanned_files.includes(good));
  });

  it('normalizes absolute paths to repo-relative paths in reports', () => {
    const abs = path.join(ROOT, 'src/persistence/postgres/coreCatalogRepository.mjs');
    const report = normalizeAuditReport(
      {
        artifact_type: 'postgres_tenant_query_audit',
        schema_version: 1,
        scanned_files: [abs],
        finding_count: 1,
        findings: [{ file: abs, line: 10, check: 'missing_tenant_context', table: 'agents', query_label: 'SELECT:agents' }],
      },
      ROOT,
    );
    assert.equal(report.scanned_files[0], 'src/persistence/postgres/coreCatalogRepository.mjs');
    assert.equal(report.findings[0].file, 'src/persistence/postgres/coreCatalogRepository.mjs');
    assert.equal(normalizeAuditPath(abs, ROOT), 'src/persistence/postgres/coreCatalogRepository.mjs');
  });
});

describe('postgres tenant query audit production bundle', () => {
  it('audits the default postgres repository bundle with zero findings', () => {
    const report = auditFiles(defaultPostgresAuditPaths());
    assert.equal(report.finding_count, 0, JSON.stringify(report.findings));
    assert.ok(report.scanned_files.length >= 20);
  });

  it('builds contract-valid production release evidence', () => {
    const evidence = buildProductionTenantQueryAuditEvidence({
      root: ROOT,
      evidenceUri: 'evidence://ci/tenant-query-audit',
    });
    assert.equal(evidence.finding_count, 0);
    assert.equal(evidence.evidence_uri, 'evidence://ci/tenant-query-audit');
    assert.ok(evidence.scanned_files.every((file) => !path.isAbsolute(file)));
    assert.ok(assertReportMetadataOnly(evidence));
  });
});