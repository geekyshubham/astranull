/**
 * Compliance report templates and control-to-evidence mappings.
 * Maps observed AstraNull evidence buckets to frameworks; does not certify compliance.
 */

export const COMPLIANCE_DISCLAIMER =
  'Maps observed platform evidence to control areas; does not certify compliance. Requires auditor review.';

/** @type {readonly string[]} */
export const REPORT_KINDS = Object.freeze([
  'executive',
  'board',
  'technical',
  'soc',
  'audit',
  'soc2',
  'iso27001',
  'dora',
  'nis2',
  'internal_audit',
]);

const KIND_ALIASES = Object.freeze({
  exec: 'executive',
  'internal-audit': 'internal_audit',
  internalaudit: 'internal_audit',
  'iso-27001': 'iso27001',
  iso_27001: 'iso27001',
  'soc-2': 'soc2',
  soc_2: 'soc2',
});

/** @type {Record<string, { id: string, title: string, audience: string, primary_frameworks: string[] }>} */
const TEMPLATES = {
  executive: {
    id: 'executive',
    title: 'Executive DDoS Readiness Brief',
    audience: 'executive_leadership',
    primary_frameworks: ['governance'],
  },
  board: {
    id: 'board',
    title: 'Board Risk & Resilience Summary',
    audience: 'board_and_risk_committee',
    primary_frameworks: ['governance'],
  },
  technical: {
    id: 'technical',
    title: 'Technical Readiness & Validation Report',
    audience: 'security_engineering',
    primary_frameworks: ['operational'],
  },
  soc: {
    id: 'soc',
    title: 'SOC Operations & High-Scale Governance Report',
    audience: 'soc_operators',
    primary_frameworks: ['incident_operations'],
  },
  audit: {
    id: 'audit',
    title: 'Audit Evidence Pack (Metadata)',
    audience: 'internal_external_auditors',
    primary_frameworks: ['auditability'],
  },
  soc2: {
    id: 'soc2',
    title: 'SOC 2 Readiness Evidence Mapping',
    audience: 'compliance_and_auditors',
    primary_frameworks: ['SOC 2'],
  },
  iso27001: {
    id: 'iso27001',
    title: 'ISO/IEC 27001 Annex A Evidence Mapping',
    audience: 'compliance_and_auditors',
    primary_frameworks: ['ISO 27001'],
  },
  dora: {
    id: 'dora',
    title: 'DORA ICT Risk & Resilience Evidence Mapping',
    audience: 'financial_sector_compliance',
    primary_frameworks: ['DORA'],
  },
  nis2: {
    id: 'nis2',
    title: 'NIS2 Cybersecurity Measures Evidence Mapping',
    audience: 'essential_entity_compliance',
    primary_frameworks: ['NIS2'],
  },
  internal_audit: {
    id: 'internal_audit',
    title: 'Internal Audit Control Evidence Mapping',
    audience: 'internal_audit',
    primary_frameworks: ['internal_audit'],
  },
};

/** @type {readonly string[]} */
const EVIDENCE_SOURCES = Object.freeze([
  'report_summary',
  'readiness_score',
  'test_runs',
  'verdicts',
  'findings',
  'high_scale_authorization_artifacts',
  'soc_notes',
  'audit_log',
  'export_custody',
]);

function entry(framework, controlId, controlArea, evidenceSources, reportSections, status) {
  return {
    framework,
    control_id: controlId,
    control_area: controlArea,
    evidence_sources: evidenceSources,
    report_sections: reportSections,
    status,
  };
}

/** @type {Record<string, ReturnType<typeof entry>[]>} */
const MAPPINGS_BY_KIND = {
  executive: [
    entry(
      'governance',
      'EXEC-AVAIL',
      'availability/resilience',
      ['readiness_score', 'report_summary', 'verdicts', 'findings'],
      ['summary', 'readiness_score', 'open_findings'],
      'requires auditor review',
    ),
    entry(
      'governance',
      'EXEC-IR',
      'incident response',
      ['soc_notes', 'high_scale_authorization_artifacts', 'audit_log'],
      ['soc_notes', 'summary'],
      'maps evidence, does not certify compliance',
    ),
    entry(
      'governance',
      'EXEC-LOG',
      'logging/auditability',
      ['export_custody', 'audit_log'],
      ['custody'],
      'requires auditor review',
    ),
  ],
  board: [
    entry(
      'governance',
      'BOARD-RISK',
      'operational resilience',
      ['readiness_score', 'findings', 'verdicts'],
      ['summary', 'verdicts'],
      'requires auditor review',
    ),
    entry(
      'governance',
      'BOARD-SUPPLIER',
      'supplier/provider governance',
      ['report_summary', 'high_scale_authorization_artifacts'],
      ['summary'],
      'maps evidence, does not certify compliance',
    ),
    entry(
      'governance',
      'BOARD-DP',
      'data protection',
      ['export_custody', 'report_summary'],
      ['custody'],
      'metadata-only; requires legal review',
    ),
  ],
  technical: [
    entry(
      'operational',
      'TECH-AVAIL',
      'availability/resilience',
      ['test_runs', 'verdicts', 'readiness_score'],
      ['recent_runs', 'verdicts'],
      'maps evidence, does not certify compliance',
    ),
    entry(
      'operational',
      'TECH-CHANGE',
      'change/release management',
      ['test_runs', 'findings', 'report_summary'],
      ['recent_runs', 'summary'],
      'requires auditor review',
    ),
    entry(
      'operational',
      'TECH-LOG',
      'logging/auditability',
      ['export_custody', 'audit_log'],
      ['custody'],
      'requires auditor review',
    ),
  ],
  soc: [
    entry(
      'incident_operations',
      'SOC-IR',
      'incident response',
      ['soc_notes', 'high_scale_authorization_artifacts', 'audit_log'],
      ['soc_notes'],
      'maps evidence, does not certify compliance',
    ),
    entry(
      'incident_operations',
      'SOC-ACCESS',
      'access control',
      ['high_scale_authorization_artifacts', 'audit_log'],
      ['soc_notes', 'summary'],
      'requires auditor review',
    ),
    entry(
      'incident_operations',
      'SOC-RES',
      'operational resilience',
      ['test_runs', 'verdicts', 'readiness_score'],
      ['verdicts', 'recent_runs'],
      'requires auditor review',
    ),
  ],
  audit: [
    entry(
      'auditability',
      'AUD-LOG',
      'logging/auditability',
      ['audit_log', 'export_custody'],
      ['custody'],
      'requires auditor review',
    ),
    entry(
      'auditability',
      'AUD-EVID',
      'availability/resilience',
      ['test_runs', 'verdicts', 'findings'],
      ['verdicts', 'recent_runs'],
      'metadata-only evidence references',
    ),
    entry(
      'auditability',
      'AUD-HS',
      'incident response',
      ['high_scale_authorization_artifacts', 'soc_notes'],
      ['soc_notes'],
      'maps evidence, does not certify compliance',
    ),
  ],
  soc2: [
    entry(
      'SOC 2',
      'CC6.1',
      'access control',
      ['audit_log', 'high_scale_authorization_artifacts'],
      ['summary', 'soc_notes'],
      'requires auditor review',
    ),
    entry(
      'SOC 2',
      'CC7.2',
      'incident response',
      ['soc_notes', 'high_scale_authorization_artifacts', 'audit_log'],
      ['soc_notes'],
      'maps evidence, does not certify compliance',
    ),
    entry(
      'SOC 2',
      'CC8.1',
      'change/release management',
      ['test_runs', 'findings', 'verdicts'],
      ['recent_runs', 'verdicts'],
      'requires auditor review',
    ),
    entry(
      'SOC 2',
      'A1.2',
      'availability/resilience',
      ['readiness_score', 'test_runs', 'verdicts', 'findings'],
      ['summary', 'verdicts'],
      'maps evidence, does not certify compliance',
    ),
    entry(
      'SOC 2',
      'CC4.1',
      'logging/auditability',
      ['export_custody', 'audit_log'],
      ['custody'],
      'requires auditor review',
    ),
  ],
  iso27001: [
    entry(
      'ISO 27001',
      'A.5.15',
      'access control',
      ['audit_log', 'high_scale_authorization_artifacts'],
      ['summary', 'soc_notes'],
      'requires auditor review',
    ),
    entry(
      'ISO 27001',
      'A.5.24',
      'incident response',
      ['soc_notes', 'high_scale_authorization_artifacts'],
      ['soc_notes'],
      'maps evidence, does not certify compliance',
    ),
    entry(
      'ISO 27001',
      'A.8.9',
      'change/release management',
      ['test_runs', 'findings', 'verdicts'],
      ['recent_runs', 'verdicts'],
      'requires auditor review',
    ),
    entry(
      'ISO 27001',
      'A.8.16',
      'availability/resilience',
      ['readiness_score', 'verdicts', 'findings'],
      ['summary', 'verdicts'],
      'maps evidence, does not certify compliance',
    ),
    entry(
      'ISO 27001',
      'A.8.15',
      'logging/auditability',
      ['export_custody', 'audit_log'],
      ['custody'],
      'requires auditor review',
    ),
  ],
  dora: [
    entry(
      'DORA',
      'Art. 11',
      'operational resilience',
      ['readiness_score', 'test_runs', 'verdicts', 'findings'],
      ['summary', 'verdicts', 'recent_runs'],
      'requires auditor review',
    ),
    entry(
      'DORA',
      'Art. 17',
      'incident response',
      ['soc_notes', 'high_scale_authorization_artifacts', 'audit_log'],
      ['soc_notes'],
      'maps evidence, does not certify compliance',
    ),
    entry(
      'DORA',
      'Art. 28',
      'supplier/provider governance',
      ['report_summary', 'high_scale_authorization_artifacts'],
      ['summary'],
      'requires legal and auditor review',
    ),
    entry(
      'DORA',
      'Art. 9',
      'logging/auditability',
      ['export_custody', 'audit_log'],
      ['custody'],
      'requires auditor review',
    ),
  ],
  nis2: [
    entry(
      'NIS2',
      'Art. 21(2)(c)',
      'incident response',
      ['soc_notes', 'high_scale_authorization_artifacts', 'audit_log'],
      ['soc_notes'],
      'maps evidence, does not certify compliance',
    ),
    entry(
      'NIS2',
      'Art. 21(2)(d)',
      'availability/resilience',
      ['readiness_score', 'test_runs', 'verdicts'],
      ['summary', 'verdicts'],
      'requires auditor review',
    ),
    entry(
      'NIS2',
      'Art. 21(2)(j)',
      'logging/auditability',
      ['export_custody', 'audit_log'],
      ['custody'],
      'requires auditor review',
    ),
    entry(
      'NIS2',
      'Art. 21(2)(g)',
      'access control',
      ['audit_log', 'high_scale_authorization_artifacts'],
      ['summary'],
      'requires auditor review',
    ),
  ],
  internal_audit: [
    entry(
      'internal_audit',
      'IA-AC',
      'access control',
      ['audit_log', 'high_scale_authorization_artifacts'],
      ['summary', 'soc_notes'],
      'requires auditor review',
    ),
    entry(
      'internal_audit',
      'IA-IR',
      'incident response',
      ['soc_notes', 'high_scale_authorization_artifacts'],
      ['soc_notes'],
      'maps evidence, does not certify compliance',
    ),
    entry(
      'internal_audit',
      'IA-AVAIL',
      'availability/resilience',
      ['readiness_score', 'findings', 'verdicts', 'test_runs'],
      ['summary', 'verdicts'],
      'requires auditor review',
    ),
    entry(
      'internal_audit',
      'IA-AUDIT',
      'logging/auditability',
      ['export_custody', 'audit_log'],
      ['custody'],
      'requires auditor review',
    ),
    entry(
      'internal_audit',
      'IA-DP',
      'data protection',
      ['export_custody', 'report_summary'],
      ['custody', 'summary'],
      'metadata-only; requires legal review',
    ),
  ],
};

const DEFAULT_KIND = 'technical';

/**
 * @param {string | undefined | null} kind
 * @returns {string}
 */
export function normalizeReportKind(kind) {
  if (kind == null || String(kind).trim() === '') {
    return DEFAULT_KIND;
  }
  const raw = String(kind).trim().toLowerCase().replace(/-/g, '_');
  const aliased = KIND_ALIASES[raw] ?? KIND_ALIASES[String(kind).trim().toLowerCase()] ?? raw;
  if (REPORT_KINDS.includes(aliased)) {
    return aliased;
  }
  return DEFAULT_KIND;
}

export function listReportTemplates() {
  return REPORT_KINDS.map((kind) => {
    const t = TEMPLATES[kind];
    return {
      kind,
      id: t.id,
      title: t.title,
      audience: t.audience,
      primary_frameworks: [...t.primary_frameworks],
    };
  });
}

/**
 * @param {string} kind
 */
export function getReportTemplate(kind) {
  const normalized = normalizeReportKind(kind);
  const t = TEMPLATES[normalized];
  return {
    kind: normalized,
    id: t.id,
    title: t.title,
    audience: t.audience,
    primary_frameworks: [...t.primary_frameworks],
    evidence_source_catalog: [...EVIDENCE_SOURCES],
    disclaimer: COMPLIANCE_DISCLAIMER,
  };
}

/**
 * @param {string} kind
 */
export function buildComplianceMapping(kind) {
  const normalized = normalizeReportKind(kind);
  const template = getReportTemplate(normalized);
  const entries = (MAPPINGS_BY_KIND[normalized] ?? MAPPINGS_BY_KIND[DEFAULT_KIND]).map((e) => ({
    ...e,
    evidence_sources: [...e.evidence_sources],
    report_sections: [...e.report_sections],
  }));
  return {
    report_kind: normalized,
    template: {
      id: template.id,
      title: template.title,
      audience: template.audience,
      primary_frameworks: template.primary_frameworks,
    },
    disclaimer: COMPLIANCE_DISCLAIMER,
    entries,
  };
}

/**
 * Summary fields stored on generated reports (no raw evidence).
 * @param {string} kind
 */
export function buildReportComplianceSummary(kind) {
  const mapping = buildComplianceMapping(kind);
  const frameworks = [...new Set(mapping.entries.map((e) => e.framework))];
  return {
    report_kind: mapping.report_kind,
    template_id: mapping.template.id,
    template_title: mapping.template.title,
    frameworks,
    control_mapping_count: mapping.entries.length,
    disclaimer: mapping.disclaimer,
  };
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * @param {ReturnType<typeof buildComplianceMapping>} complianceMapping
 */
export function buildMarkdownComplianceSection(complianceMapping) {
  const lines = [
    '## Compliance mapping',
    '',
    `_${complianceMapping.disclaimer}_`,
    '',
    `Template: **${complianceMapping.template.title}** (${complianceMapping.report_kind})`,
    '',
  ];
  for (const e of complianceMapping.entries) {
    lines.push(
      `### ${e.framework} · ${e.control_id}`,
      `- Control area: ${e.control_area}`,
      `- Evidence sources: ${e.evidence_sources.join(', ')}`,
      `- Report sections: ${e.report_sections.join(', ')}`,
      `- Status: ${e.status}`,
      '',
    );
  }
  return lines;
}

/**
 * @param {ReturnType<typeof buildComplianceMapping>} complianceMapping
 */
export function buildHtmlComplianceSection(complianceMapping) {
  const rows = complianceMapping.entries
    .map(
      (e) =>
        `<tr><td>${escapeHtml(e.framework)}</td><td>${escapeHtml(e.control_id)}</td><td>${escapeHtml(e.control_area)}</td><td>${escapeHtml(e.evidence_sources.join(', '))}</td><td>${escapeHtml(e.status)}</td></tr>`,
    )
    .join('');
  return `<h2>Compliance mapping</h2>
<p class="muted">${escapeHtml(complianceMapping.disclaimer)}</p>
<p>Template: <strong>${escapeHtml(complianceMapping.template.title)}</strong> (${escapeHtml(complianceMapping.report_kind)})</p>
<table><thead><tr><th>Framework</th><th>Control</th><th>Area</th><th>Evidence sources</th><th>Status</th></tr></thead><tbody>${rows || '<tr><td colspan="5">None</td></tr>'}</tbody></table>`;
}