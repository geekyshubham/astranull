import assert from 'node:assert/strict';
import { beforeEach, describe, it } from 'node:test';
import {
  REPORT_KINDS,
  buildComplianceMapping,
  getReportTemplate,
  listReportTemplates,
  normalizeReportKind,
} from '../../src/contracts/complianceReports.mjs';
import { verifyCustodyManifest } from '../../src/lib/custody.mjs';
import { createReport, exportReport } from '../../src/services/reports.mjs';
import { freshStore } from '../helpers/reset.mjs';

const CTX = { tenantId: 'ten_demo', userId: 'usr_test', role: 'admin' };
const SECRET_MARKERS = [/ast_[A-Za-z0-9_-]{8,}/, /agc_[A-Za-z0-9_-]{8,}/];

function assertNoSecrets(text) {
  for (const pattern of SECRET_MARKERS) {
    assert.doesNotMatch(text, pattern);
  }
}

describe('compliance report contracts', () => {
  it('lists all report templates and normalizes kinds with unknown fallback', () => {
    const templates = listReportTemplates();
    assert.equal(templates.length, REPORT_KINDS.length);
    assert.deepEqual(
      templates.map((t) => t.kind).sort(),
      [...REPORT_KINDS].sort(),
    );
    assert.equal(normalizeReportKind('soc2'), 'soc2');
    assert.equal(normalizeReportKind('SOC-2'), 'soc2');
    assert.equal(normalizeReportKind('iso-27001'), 'iso27001');
    assert.equal(normalizeReportKind('not_a_real_kind'), 'technical');
    assert.equal(normalizeReportKind(undefined), 'technical');
  });

  it('buildComplianceMapping covers framework report kinds', () => {
    for (const kind of ['soc2', 'iso27001', 'dora', 'nis2', 'internal_audit']) {
      const mapping = buildComplianceMapping(kind);
      const template = getReportTemplate(kind);
      assert.equal(mapping.report_kind, template.kind);
      assert.ok(mapping.entries.length >= 3);
      assert.ok(mapping.entries.every((e) => e.framework && e.control_id && e.control_area));
      assert.ok(mapping.disclaimer.includes('does not certify'));
    }
  });
});

describe('report service compliance export', () => {
  beforeEach(() => {
    freshStore();
  });

  it('creates DORA report with compliance summary and exports mapping in all formats', () => {
    const report = createReport(CTX, { kind: 'dora', title: 'DORA mapping test' });
    assert.equal(report.kind, 'dora');
    assert.equal(report.summary.compliance.report_kind, 'dora');
    assert.ok(report.summary.compliance.control_mapping_count >= 3);
    assert.ok(report.summary.compliance.frameworks.includes('DORA'));

    const jsonOut = exportReport(CTX, report.id, 'json');
    assert.ok(jsonOut);
    assert.ok(jsonOut.payload.compliance_mapping);
    assert.equal(jsonOut.payload.compliance_mapping.report_kind, 'dora');
    assert.ok(jsonOut.payload.compliance_mapping.entries.some((e) => e.framework === 'DORA'));
    assert.equal(
      verifyCustodyManifest({ payload: jsonOut.payload, custody: jsonOut.custody }).ok,
      true,
    );
    assertNoSecrets(JSON.stringify(jsonOut));

    const mdOut = exportReport(CTX, report.id, 'markdown');
    assert.match(mdOut.content, /## Compliance mapping/);
    assert.match(mdOut.content, /DORA/);
    assert.match(mdOut.content, /## Custody/);
    assertNoSecrets(mdOut.content);

    const htmlOut = exportReport(CTX, report.id, 'html');
    assert.match(htmlOut.content, /<h2>Compliance mapping<\/h2>/);
    assert.match(htmlOut.content, /DORA/);
    assertNoSecrets(htmlOut.content);
  });

  it('SOC 2 export includes framework controls without raw payloads', () => {
    const report = createReport(CTX, { kind: 'soc2', title: 'SOC 2 pack' });
    const jsonOut = exportReport(CTX, report.id, 'json');
    const soc2Entries = jsonOut.payload.compliance_mapping.entries.filter((e) => e.framework === 'SOC 2');
    assert.ok(soc2Entries.length >= 4);
    assert.doesNotMatch(JSON.stringify(jsonOut.payload), /packet_payload|raw_packet/);
  });
});