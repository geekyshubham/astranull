import { getCheckById } from '../../contracts/checks.mjs';
import {
  buildComplianceMapping,
  buildHtmlComplianceSection,
  buildMarkdownComplianceSection,
  buildReportComplianceSummary,
  normalizeReportKind,
} from '../../contracts/complianceReports.mjs';
import { buildCustodyManifest } from '../../lib/custody.mjs';
import { newId } from '../../lib/ids.mjs';
import { redactObject } from '../../lib/redact.mjs';
import {
  STATE_AGENT_CONTROL_REPOSITORY_METHODS,
  STATE_CORE_CATALOG_REPOSITORY_METHODS,
  STATE_HIGH_SCALE_REPOSITORY_METHODS,
  STATE_KILL_SWITCH_REPOSITORY_METHODS,
  STATE_VALIDATION_EVIDENCE_REPOSITORY_METHODS,
  createPostgresStateServices,
} from './stateServiceAdapters.mjs';

/** @type {readonly string[]} */
export const REPORT_REPOSITORY_METHODS = Object.freeze([
  'createReport',
  'getReport',
  'listRunsForReport',
  'listVerdictsForRunIds',
]);

/** @type {readonly string[]} */
export const REPORT_VALIDATION_EVIDENCE_REPOSITORY_METHODS = Object.freeze([
  'listTestRuns',
  'listFindings',
  'getFinding',
]);

/** @type {readonly string[]} */
export const REPORT_AUDIT_REPOSITORY_METHODS = Object.freeze(['appendAuditEvent', 'getLastAuditEntry']);

/** @type {readonly string[]} */
export const POSTGRES_REPORT_SERVICE_METHODS = Object.freeze([
  'createReport',
  'getReport',
  'exportReport',
  'exportFinding',
]);

const REPORT_READINESS_STATE_FALLBACK_DETAIL =
  'Report readiness summary could not be computed because state service dependencies were not injected.';

function repositoryHasMethods(repo, methods) {
  if (!repo || typeof repo !== 'object') return false;
  return methods.every((method) => typeof repo[method] === 'function');
}

function hasReportReadinessStateDependencies(repositories) {
  return (
    repositoryHasMethods(repositories?.coreCatalog, STATE_CORE_CATALOG_REPOSITORY_METHODS)
    && repositoryHasMethods(repositories?.agentControl, STATE_AGENT_CONTROL_REPOSITORY_METHODS)
    && repositoryHasMethods(
      repositories?.validationEvidence,
      STATE_VALIDATION_EVIDENCE_REPOSITORY_METHODS,
    )
    && repositoryHasMethods(repositories?.highScale, STATE_HIGH_SCALE_REPOSITORY_METHODS)
    && repositoryHasMethods(repositories?.killSwitch, STATE_KILL_SWITCH_REPOSITORY_METHODS)
  );
}

function assertReportServiceDependencies(repositories) {
  const reports = repositories?.reports;
  if (!reports || typeof reports !== 'object') {
    throw new Error('Postgres report service adapter requires repositories.reports.');
  }
  for (const method of REPORT_REPOSITORY_METHODS) {
    if (typeof reports[method] !== 'function') {
      throw new Error(`Postgres report service adapter requires reports.${method}().`);
    }
  }

  const validationEvidence = repositories?.validationEvidence;
  if (!validationEvidence || typeof validationEvidence !== 'object') {
    throw new Error('Postgres report service adapter requires repositories.validationEvidence.');
  }
  for (const method of REPORT_VALIDATION_EVIDENCE_REPOSITORY_METHODS) {
    if (typeof validationEvidence[method] !== 'function') {
      throw new Error(`Postgres report service adapter requires validationEvidence.${method}().`);
    }
  }

  const audit = repositories?.audit;
  if (!audit || typeof audit !== 'object') {
    throw new Error('Postgres report service adapter requires repositories.audit.');
  }
  for (const method of REPORT_AUDIT_REPOSITORY_METHODS) {
    if (typeof audit[method] !== 'function') {
      throw new Error(`Postgres report service adapter requires audit.${method}().`);
    }
  }
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
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

function mapRunForExport(run) {
  const check = getCheckById(run.check_id);
  return {
    id: run.id,
    check_id: run.check_id,
    vector_family: check?.vector_family ?? run.vector_family,
    safety_class: check?.safety_class ?? run.safety_class,
    status: run.status,
  };
}

function mapVerdictForExport(verdict) {
  return {
    test_run_id: verdict.test_run_id,
    verdict: verdict.verdict,
    confidence: verdict.confidence,
    placement_confidence: verdict.placement_confidence ?? null,
    evidence_ids: verdict.evidence_ids,
    explanation: verdict.explanation,
  };
}

async function priorAuditHashes(auditRepo, tenantId) {
  const prior = await auditRepo.getLastAuditEntry(tenantId);
  const hash = prior?.entry_hash ?? null;
  return { previous_audit_hash: hash, previous_tenant_audit_hash: hash };
}

/**
 * @param {{
 *   reports?: Record<string, unknown>,
 *   validationEvidence?: Record<string, unknown>,
 *   audit?: Record<string, unknown>,
 * }} repositories
 * @param {{ now?: () => Date, newId?: typeof newId }} [options]
 */
export function createPostgresReportServices(repositories, options = {}) {
  assertReportServiceDependencies(repositories);
  const reportsRepo = repositories.reports;
  const validationEvidence = repositories.validationEvidence;
  const auditRepo = repositories.audit;
  const nowFn = options.now ?? (() => new Date());
  const newIdFn = options.newId ?? newId;
  const stateGetState = hasReportReadinessStateDependencies(repositories)
    ? createPostgresStateServices(repositories, { now: nowFn }).getState
    : null;

  const reports = {
    async createReport(ctx, body) {
      const runs = await validationEvidence.listTestRuns(ctx, { limit: 10 });
      const findings = await validationEvidence.listFindings(ctx);
      const openFindings = (findings ?? []).filter((f) => f.status === 'open');
      let readinessScore = null;
      /** @type {unknown} */
      let readinessFactors = {
        status: 'postgres_report_readiness_summary_not_wired',
        detail: REPORT_READINESS_STATE_FALLBACK_DETAIL,
      };
      if (stateGetState) {
        const state = await stateGetState(ctx);
        const readiness = state?.readiness ?? {};
        readinessScore = readiness.score ?? null;
        readinessFactors = readiness.factors ?? [];
      }
      const id = newIdFn('report');
      const reportKind = normalizeReportKind(body?.kind);
      const record = {
        id,
        tenant_id: ctx.tenantId,
        kind: reportKind,
        title: body?.title ?? 'AstraNull Readiness Summary',
        status: 'ready',
        summary: {
          readiness_score: readinessScore,
          readiness_factors: readinessFactors,
          open_findings: openFindings.length,
          recent_runs: (runs ?? []).map((r) => ({
            id: r.id,
            status: r.status,
            check_id: r.check_id,
          })),
          compliance: buildReportComplianceSummary(reportKind),
        },
        run_ids: (runs ?? []).map((r) => r.id),
        created_at: nowFn().toISOString(),
        created_by: ctx.userId,
      };
      const report = await reportsRepo.createReport(ctx, record);
      await auditRepo.appendAuditEvent(
        {
          tenant_id: ctx.tenantId,
          actor_user_id: ctx.userId,
          actor_role: ctx.role,
          action: 'report.generated',
          resource_type: 'report',
          resource_id: id,
        },
        { now: nowFn() },
      );
      return report;
    },

    async getReport(ctx, id) {
      return reportsRepo.getReport(ctx, id);
    },

    async exportReport(ctx, id, format) {
      const report = await reportsRepo.getReport(ctx, id);
      if (!report) return null;

      const runRows = await reportsRepo.listRunsForReport(ctx, report.run_ids ?? []);
      const verdictRows = await reportsRepo.listVerdictsForRunIds(ctx, report.run_ids ?? []);
      const complianceMapping = buildComplianceMapping(report.kind);
      const payload = redactObject({
        report_id: report.id,
        title: report.title,
        kind: report.kind,
        summary: report.summary,
        compliance_mapping: complianceMapping,
        runs: runRows.map(mapRunForExport),
        verdicts: verdictRows.map(mapVerdictForExport),
        soc_notes: [],
      });

      const exportFormat = format === 'html' || format === 'markdown' ? format : 'json';
      const prior = await priorAuditHashes(auditRepo, ctx.tenantId);
      const custody = buildCustodyManifest({
        tenant_id: ctx.tenantId,
        artifact_type: 'report_export',
        artifact_id: report.id,
        format: exportFormat,
        created_by: ctx.userId,
        content: payload,
        subject_ids: collectReportExportSubjectIds(report, payload),
        previous_audit_hash: prior.previous_audit_hash,
        previous_tenant_audit_hash: prior.previous_tenant_audit_hash,
      });

      await auditRepo.appendAuditEvent(
        {
          tenant_id: ctx.tenantId,
          actor_user_id: ctx.userId,
          actor_role: ctx.role,
          action: 'report.exported',
          resource_type: 'report',
          resource_id: id,
          metadata: custodyAuditMetadata(custody),
        },
        { now: nowFn() },
      );

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
    },

    async exportFinding(ctx, id) {
      const finding = await validationEvidence.getFinding(ctx, id);
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

      const prior = await priorAuditHashes(auditRepo, ctx.tenantId);
      const subjectIds = [finding.id, ...(finding.evidence_ids ?? [])].filter(Boolean);
      const custody = buildCustodyManifest({
        tenant_id: ctx.tenantId,
        artifact_type: 'finding_export',
        artifact_id: finding.id,
        format: 'json',
        created_by: ctx.userId,
        content: payload,
        subject_ids: subjectIds,
        previous_audit_hash: prior.previous_audit_hash,
        previous_tenant_audit_hash: prior.previous_tenant_audit_hash,
      });

      await auditRepo.appendAuditEvent(
        {
          tenant_id: ctx.tenantId,
          actor_user_id: ctx.userId,
          actor_role: ctx.role,
          action: 'finding.exported',
          resource_type: 'finding',
          resource_id: id,
          metadata: custodyAuditMetadata(custody),
        },
        { now: nowFn() },
      );

      return { ...payload, custody };
    },
  };

  return { reports };
}
