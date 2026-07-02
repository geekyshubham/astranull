import {
  audit,
  getLatestChainedAuditEntry,
  getLatestChainedAuditEntryForTenant,
} from '../audit.mjs';
import { buildCustodyManifest } from '../lib/custody.mjs';
import { getCheckById } from '../contracts/checks.mjs';
import { redactObject } from '../lib/redact.mjs';
import { newId } from '../lib/ids.mjs';
import { getStore, persistStore } from '../store.mjs';
import { computeReadiness } from './readiness.mjs';
import { listSocNotes } from './highScale.mjs';
import {
  buildComplianceMapping,
  buildHtmlComplianceSection,
  buildMarkdownComplianceSection,
  buildReportComplianceSummary,
  normalizeReportKind,
} from '../contracts/complianceReports.mjs';

export function createReport(ctx, body) {
  const store = getStore();
  const readiness = computeReadiness(ctx.tenantId);
  const runs = store.testRuns.filter((r) => r.tenant_id === ctx.tenantId).slice(-10);
  const findings = store.findings.filter((f) => f.tenant_id === ctx.tenantId && f.status === 'open');
  const id = newId('report');
  const reportKind = normalizeReportKind(body.kind);
  const report = {
    id,
    tenant_id: ctx.tenantId,
    kind: reportKind,
    title: body.title ?? 'AstraNull Readiness Summary',
    status: 'ready',
    summary: {
      readiness_score: readiness.score,
      readiness_factors: readiness.factors,
      open_findings: findings.length,
      recent_runs: runs.map((r) => ({ id: r.id, status: r.status, check_id: r.check_id })),
      compliance: buildReportComplianceSummary(reportKind),
    },
    run_ids: runs.map((r) => r.id),
    created_at: new Date().toISOString(),
    created_by: ctx.userId,
  };
  store.reports.push(report);
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'report.generated',
    resource_type: 'report',
    resource_id: id,
  });
  persistStore();
  return report;
}

export function getReport(ctx, id) {
  return getStore().reports.find((r) => r.id === id && r.tenant_id === ctx.tenantId) ?? null;
}

function buildExportPayload(ctx, report) {
  const store = getStore();
  const runs = (report.run_ids ?? [])
    .map((rid) => store.testRuns.find((r) => r.id === rid && r.tenant_id === ctx.tenantId))
    .filter(Boolean);
  const verdicts = runs.map((r) => store.verdicts.find((v) => v.test_run_id === r.id)).filter(Boolean);
  const hs = store.highScaleRequests.filter((h) => h.tenant_id === ctx.tenantId);
  const socNotes = hs.flatMap((h) => listSocNotes(ctx, h.id) ?? []);
  const complianceMapping = buildComplianceMapping(report.kind);
  return redactObject({
    report_id: report.id,
    title: report.title,
    kind: report.kind,
    summary: report.summary,
    compliance_mapping: complianceMapping,
    runs: runs.map((r) => ({
      id: r.id,
      check_id: r.check_id,
      vector_family: getCheckById(r.check_id)?.vector_family,
      safety_class: getCheckById(r.check_id)?.safety_class,
      status: r.status,
    })),
    verdicts: verdicts.map((v) => ({
      test_run_id: v.test_run_id,
      verdict: v.verdict,
      confidence: v.confidence,
      placement_confidence: v.placement_confidence ?? null,
      evidence_ids: v.evidence_ids,
      explanation: v.explanation,
    })),
    soc_notes: socNotes.map((n) => ({ request_id: n.high_scale_request_id, body: n.body, at: n.created_at })),
  });
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function collectReportExportSubjectIds(report, payload) {
  const ids = new Set([report.id]);
  for (const r of payload.runs ?? []) {
    if (r.id) ids.add(r.id);
  }
  for (const v of payload.verdicts ?? []) {
    if (v.test_run_id) ids.add(v.test_run_id);
    for (const eid of v.evidence_ids ?? []) {
      if (eid) ids.add(eid);
    }
  }
  return [...ids];
}

function custodyAuditMetadata(custody) {
  return {
    format: custody.format,
    content_sha256: custody.content_sha256,
    custody_schema_version: custody.schema_version,
  };
}

function buildMarkdownCustodySection(custody) {
  const lines = [
    '## Custody',
    `- artifact_id: ${custody.artifact_id}`,
    `- content_sha256: ${custody.content_sha256}`,
    `- canonicalization: ${custody.content_canonicalization}`,
    `- created_at: ${custody.created_at}`,
  ];
  if (custody.previous_audit_hash) {
    lines.push(`- previous_audit_hash: ${custody.previous_audit_hash}`);
  }
  return lines;
}

function buildHtmlCustodySection(custody) {
  const prev = custody.previous_audit_hash
    ? `<li>previous_audit_hash: ${escapeHtml(custody.previous_audit_hash)}</li>`
    : '';
  return `<h2>Custody</h2>
<ul>
<li>artifact_id: ${escapeHtml(custody.artifact_id)}</li>
<li>content_sha256: ${escapeHtml(custody.content_sha256)}</li>
<li>canonicalization: ${escapeHtml(custody.content_canonicalization)}</li>
<li>created_at: ${escapeHtml(custody.created_at)}</li>
${prev}
</ul>`;
}

function buildHtmlExport(payload, custody) {
  const runs = (payload.runs ?? [])
    .map(
      (r) =>
        `<tr><td>${escapeHtml(r.id)}</td><td>${escapeHtml(r.check_id)}</td><td>${escapeHtml(r.vector_family ?? '')}</td><td>${escapeHtml(r.status)}</td></tr>`,
    )
    .join('');
  const verdicts = (payload.verdicts ?? [])
    .map(
      (v) =>
        `<tr><td>${escapeHtml(v.test_run_id)}</td><td>${escapeHtml(v.verdict)}</td><td>${escapeHtml((v.evidence_ids ?? []).join(', '))}</td></tr>`,
    )
    .join('');
  const socNotes = (payload.soc_notes ?? [])
    .map((n) => `<li>${escapeHtml(n.at)}: ${escapeHtml(n.body)}</li>`)
    .join('');
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>${escapeHtml(payload.title)}</title>
<style>
body{font-family:system-ui,sans-serif;margin:2rem;color:#1a1a1a;line-height:1.5}
h1{font-size:1.5rem}h2{font-size:1.1rem;margin-top:1.5rem}
table{border-collapse:collapse;width:100%;margin:0.5rem 0}
th,td{border:1px solid #ccc;padding:0.4rem 0.6rem;text-align:left;font-size:0.9rem}
th{background:#f4f4f4}
.muted{color:#555;font-size:0.85rem}
.score{font-size:2rem;font-weight:600}
</style>
</head>
<body>
<h1>${escapeHtml(payload.title)}</h1>
<p class="muted">AstraNull readiness report · kind: ${escapeHtml(payload.kind)} · metadata-only export</p>
<p>Readiness score: <span class="score">${escapeHtml(String(payload.summary?.readiness_score ?? 'n/a'))}</span></p>
<p>Open findings: ${escapeHtml(String(payload.summary?.open_findings ?? 0))}</p>
<h2>Recent runs</h2>
<table><thead><tr><th>Run</th><th>Check</th><th>Vector</th><th>Status</th></tr></thead><tbody>${runs || '<tr><td colspan="4">None</td></tr>'}</tbody></table>
<h2>Verdicts</h2>
<table><thead><tr><th>Run</th><th>Verdict</th><th>Evidence</th></tr></thead><tbody>${verdicts || '<tr><td colspan="3">None</td></tr>'}</tbody></table>
<h2>SOC notes</h2>
<ul>${socNotes || '<li>None</li>'}</ul>
${buildHtmlComplianceSection(payload.compliance_mapping)}
${buildHtmlCustodySection(custody)}
<p class="muted">Secrets redacted. No external assets. Review this export before sharing outside your organization.</p>
</body>
</html>`;
}

export function exportReport(ctx, id, format) {
  const report = getReport(ctx, id);
  if (!report) return null;
  const payload = buildExportPayload(ctx, report);
  const exportFormat = format === 'html' || format === 'markdown' ? format : 'json';
  const priorGlobal = getLatestChainedAuditEntry();
  const priorTenant = getLatestChainedAuditEntryForTenant(ctx.tenantId);
  const custody = buildCustodyManifest({
    tenant_id: ctx.tenantId,
    artifact_type: 'report_export',
    artifact_id: report.id,
    format: exportFormat,
    created_by: ctx.userId,
    content: payload,
    subject_ids: collectReportExportSubjectIds(report, payload),
    previous_audit_hash: priorGlobal?.entry_hash ?? null,
    previous_tenant_audit_hash: priorTenant?.entry_hash ?? null,
  });
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'report.exported',
    resource_type: 'report',
    resource_id: id,
    metadata: custodyAuditMetadata(custody),
  });
  persistStore();
  if (format === 'html') {
    return { format: 'html', content: buildHtmlExport(payload, custody), payload, custody };
  }
  if (format === 'markdown') {
    const lines = [
      `# ${payload.title}`,
      '',
      `Readiness score: **${payload.summary?.readiness_score ?? 'n/a'}**`,
      '',
      '## Recent runs',
      ...(payload.runs ?? []).map(
        (r) => `- ${r.id}: ${r.check_id} (${r.vector_family}) → ${r.status}`,
      ),
      '',
      '## Verdicts',
      ...(payload.verdicts ?? []).map(
        (v) => `- Run ${v.test_run_id}: **${v.verdict}** — evidence: ${(v.evidence_ids ?? []).join(', ')}`,
      ),
      '',
      '## SOC notes',
      ...(payload.soc_notes ?? []).map((n) => `- ${n.at}: ${n.body}`),
      '',
      ...buildMarkdownComplianceSection(payload.compliance_mapping),
      ...buildMarkdownCustodySection(custody),
      '',
      '_Metadata-only export; secrets redacted._',
    ];
    return { format: 'markdown', content: lines.join('\n'), payload, custody };
  }
  return { format: 'json', payload, custody };
}

export function exportFinding(ctx, id) {
  const store = getStore();
  const finding = store.findings.find((f) => f.id === id && f.tenant_id === ctx.tenantId);
  if (!finding) return null;
  const check = getCheckById(finding.check_id);
  const payload = redactObject({
    finding_id: finding.id,
    title: finding.title,
    severity: finding.severity,
    status: finding.status,
    check_id: finding.check_id,
    vector_family: check?.vector_family,
    remediation_template: check?.remediation_template,
    evidence_ids: finding.evidence_ids,
    notes: finding.notes,
  });
  const priorGlobal = getLatestChainedAuditEntry();
  const priorTenant = getLatestChainedAuditEntryForTenant(ctx.tenantId);
  const subjectIds = [finding.id, ...(finding.evidence_ids ?? [])].filter(Boolean);
  const custody = buildCustodyManifest({
    tenant_id: ctx.tenantId,
    artifact_type: 'finding_export',
    artifact_id: finding.id,
    format: 'json',
    created_by: ctx.userId,
    content: payload,
    subject_ids: subjectIds,
    previous_audit_hash: priorGlobal?.entry_hash ?? null,
    previous_tenant_audit_hash: priorTenant?.entry_hash ?? null,
  });
  audit({
    tenant_id: ctx.tenantId,
    actor_user_id: ctx.userId,
    actor_role: ctx.role,
    action: 'finding.exported',
    resource_type: 'finding',
    resource_id: id,
    metadata: custodyAuditMetadata(custody),
  });
  persistStore();
  return { ...payload, custody };
}