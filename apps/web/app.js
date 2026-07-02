import {
  buildEvidenceChainExport,
  buildInstallCommands,
  computeOnboardingProgress,
  renderEvidenceChainPanel,
  renderInstallCommandsPanel,
  renderOnboardingWizard,
  buildSupportReadinessPreview,
  renderReleaseEvidencePanel,
  renderStagingReadinessAttestationPanel,
  renderReportBuilder,
  renderSupportReadinessPanel,
  renderCvePipelinePage,
  renderDiscoveryPage,
  renderSupplyChainPage,
  renderRemediationPage,
  DISCOVERY_MODES,
} from './ui-helpers.js';
import {
  renderFindingVerdictExplanation,
  renderVerdictExplanation,
} from './verdict-explanation.mjs';

/** User-facing platform promise (no-access-first, customer-declared scope). */
const PLATFORM_PROMISE =
  'AstraNull proves DDoS readiness for customer-declared targets without requiring cloud credentials or automatic IP inventory discovery.';

const NAV = [
  ['dashboard', 'Dashboard'],
  ['onboarding', 'Onboarding'],
  ['environments', 'Environments'],
  ['target-groups', 'Target Groups'],
  ['agents', 'Agents'],
  ['checks', 'Checks'],
  ['runs', 'Test Runs'],
  ['findings', 'Findings'],
  ['evidence', 'Evidence Vault'],
  ['waf-posture', 'WAF Posture'],
  ['cve-pipeline', 'CVE Pipeline'],
  ['supply-chain', 'Supply Chain'],
  ['remediation', 'Remediation'],
  ['discovery', 'Discovery'],
  ['high-scale', 'High-Scale Requests'],
  ['soc', 'SOC Console'],
  ['reports', 'Reports'],
  ['notifications', 'Notifications'],
  ['audit', 'Audit Log'],
  ['release-evidence', 'Release Evidence'],
  ['settings', 'Settings'],
];

let route = 'dashboard';
let selectedFindingId = null;
let lastTokenSecret = null;
let lastReportId = null;
let lastReportSummary = null;
let lastReportKind = 'executive';
let lastReportFormat = 'json';
let activeInstallTab = 'linux';
let lastEvidenceExport = null;
let lastEvidenceCustodyPreview = null;
let lastFindingCustodyPreview = null;
let lastReportCustodyPreview = null;
let lastSocOut = { payload: 'No SOC action yet.', isError: false };
let lastHighScaleOut = { payload: 'No request submitted yet.', isError: false };
let lastWafOut = { payload: 'No WAF posture action yet.', isError: false };
let wafFeatureEnabled = true;
let discoveryFeatureEnabled = false;
let selectedCveId = null;
let lastCveDetail = null;
let showCveIngestForm = false;
let activeDiscoveryTab = 'inbox';
let discoveryMode = 'D0_declared_only';
let selectedSupplyChainRiskId = null;
let showSupplyCnameForm = false;
let showSupplyDependencyForm = false;
let selectedActionItemId = null;
let remediationGroupedView = false;

const CUSTODY_SCHEMA_VERSION = 'astranull.custody.v1';
const CUSTODY_CONTENT_CANONICALIZATION = 'json-key-sorted-v1';

const el = (id) => document.getElementById(id);

function headers() {
  return {
    'Content-Type': 'application/json',
    'x-tenant-id': el('tenantId').value,
    'x-user-id': 'usr_admin',
    'x-role': el('role').value,
  };
}

async function api(path, opts = {}) {
  const res = await fetch(path, { ...opts, headers: { ...headers(), ...(opts.headers || {}) } });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || data.message || res.statusText);
  return data;
}

const VIZ_STROKE = { ok: '#247a54', danger: '#b4232f', warn: '#9a6b06', muted: '#aeb9c5', accent: '#126b83' };

function vizEsc(text) {
  return String(text ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;');
}

function formatUtc(value) {
  if (!value) return '—';
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? String(value) : parsed.toISOString();
}

function isPlainObject(value) {
  if (value === null || typeof value !== 'object') return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function normalizeForCustody(value) {
  if (value === undefined || value === null) return null;
  const t = typeof value;
  if (t === 'string' || t === 'boolean') return value;
  if (t === 'number') {
    if (!Number.isFinite(value)) throw new Error('custody_unsupported_value');
    return value;
  }
  if (t === 'bigint' || t === 'function' || t === 'symbol') {
    throw new Error('custody_unsupported_value');
  }
  if (Array.isArray(value)) {
    return value.map((item, index) => (
      Object.prototype.hasOwnProperty.call(value, index) ? normalizeForCustody(item) : null
    ));
  }
  if (!isPlainObject(value)) throw new Error('custody_unsupported_value');
  const out = {};
  for (const key of Object.keys(value).sort()) {
    if (value[key] === undefined) continue;
    out[key] = normalizeForCustody(value[key]);
  }
  return out;
}

function stringifyCanonical(value) {
  if (value === null) return 'null';
  const t = typeof value;
  if (t === 'string' || t === 'boolean' || t === 'number') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => stringifyCanonical(item)).join(',')}]`;
  }
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stringifyCanonical(value[key])}`).join(',')}}`;
}

function canonicalJsonStringifyForCustody(value) {
  return stringifyCanonical(normalizeForCustody(value));
}

async function sha256Hex(text) {
  if (!globalThis.crypto?.subtle) throw new Error('custody_digest_unavailable');
  const bytes = new TextEncoder().encode(text);
  const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function sha256CanonicalJsonForCustody(value) {
  return sha256Hex(canonicalJsonStringifyForCustody(value));
}

async function verifyCustodyManifestLocal({ payload, custody }) {
  if (!custody || typeof custody !== 'object') return { ok: false, error: 'custody_missing' };
  if (custody.schema_version !== CUSTODY_SCHEMA_VERSION) return { ok: false, error: 'schema_version_mismatch' };
  if (custody.content_canonicalization !== CUSTODY_CONTENT_CANONICALIZATION) {
    return { ok: false, error: 'canonicalization_mismatch' };
  }
  try {
    const digest = await sha256CanonicalJsonForCustody(payload);
    if (custody.content_sha256 !== digest) return { ok: false, error: 'content_sha256_mismatch' };
    return { ok: true };
  } catch {
    return { ok: false, error: 'digest_failed' };
  }
}

function renderMetadataTable(rows) {
  const filtered = rows.filter(([, value]) => value !== undefined && value !== null && value !== '');
  if (!filtered.length) return '<p class="muted">No metadata available.</p>';
  return `<table><tbody>${filtered.map(([label, value]) => `<tr><th scope="row">${vizEsc(label)}</th><td>${value}</td></tr>`).join('')}</tbody></table>`;
}

function renderCustodyStatusPill(preview) {
  if (!preview) return '<span class="pill">Awaiting export</span>';
  const cls = preview.statusTone ? ` ${preview.statusTone}` : '';
  return `<span class="pill${cls}">${vizEsc(preview.statusLabel || 'Awaiting export')}</span>`;
}

function renderExportInspectionPanel({
  panelId,
  heading,
  emptyMessage,
  description = 'No raw payloads or secrets are rendered in this preview.',
  summaryRows = [],
  preview = null,
  contentHtml = '',
  errorMessage = '',
}) {
  const summaryHtml = summaryRows.length
    ? `<h5>Export summary</h5>${renderMetadataTable(summaryRows)}`
    : '';
  const custodyRows = preview
    ? [
      ['Status', renderCustodyStatusPill(preview)],
      ['Artifact type', `<code>${vizEsc(preview.artifactType || '—')}</code>`],
      ['Artifact ID', preview.artifactId ? `<code>${vizEsc(preview.artifactId)}</code>` : 'Pending signed snapshot rollout'],
      ['Format', vizEsc(preview.format || 'json')],
      ['Schema', `<code>${vizEsc(preview.schemaVersion || CUSTODY_SCHEMA_VERSION)}</code>`],
      ['Digest', preview.contentSha256 ? `<code>${vizEsc(preview.contentSha256)}</code>` : 'Unavailable'],
      ['Canonicalization', `<code>${vizEsc(preview.contentCanonicalization || CUSTODY_CONTENT_CANONICALIZATION)}</code>`],
      ['Created at', vizEsc(formatUtc(preview.createdAt))],
      ['Created by', vizEsc(preview.createdBy || 'UI / export request')],
      ['Tenant', vizEsc(preview.tenantId || el('tenantId')?.value || '—')],
      ['Previous audit hash', preview.previousAuditHash ? `<code>${vizEsc(preview.previousAuditHash)}</code>` : '—'],
      ['Previous tenant audit hash', preview.previousTenantAuditHash ? `<code>${vizEsc(preview.previousTenantAuditHash)}</code>` : '—'],
      ['Subjects', preview.subjectIds?.length ? preview.subjectIds.map((id) => `<code>${vizEsc(id)}</code>`).join(', ') : '—'],
    ]
    : [];
  const bodyHtml = errorMessage
    ? `<div class="empty">${vizEsc(errorMessage)}</div>`
    : preview
      ? `${renderMetadataTable(custodyRows)}<p class="muted">${vizEsc(preview.note || 'Digest metadata only. Durable immutable custody and external signing remain separate release gates.')}</p>`
      : `<div class="empty">${vizEsc(emptyMessage)}</div>`;
  return `<div class="card" id="${panelId}" tabindex="-1">
    <h4>${vizEsc(heading)}</h4>
    <p class="muted">${vizEsc(description)}</p>
    ${summaryHtml}
    <h5>Custody manifest preview</h5>
    ${bodyHtml}
    ${contentHtml}
  </div>`;
}

function focusPanel(panelId) {
  const node = document.getElementById(panelId);
  if (node) node.focus();
}

function replacePanel(panelId, html) {
  const node = document.getElementById(panelId);
  if (!node) return;
  node.outerHTML = html;
  focusPanel(panelId);
}

function summarizeEvidenceExport(exportData) {
  const payload = exportData?.payload || {};
  return [
    ['Evidence IDs', String((payload.evidence_ids || []).length)],
    ['Chain links', String((payload.chain || []).length)],
    ['Orphan references', String((payload.orphan_references || []).length)],
    ['Exported at', vizEsc(formatUtc(payload.exported_at))],
  ];
}

function summarizeFindingExport(data) {
  return [
    ['Finding ID', `<code>${vizEsc(data.finding_id || data.id || '—')}</code>`],
    ['Title', vizEsc(data.title || '—')],
    ['Severity', vizEsc(data.severity || '—')],
    ['Status', vizEsc(data.status || '—')],
    ['Evidence refs', String((data.evidence_ids || []).length)],
  ];
}

function summarizeReportExport(payload, format) {
  return [
    ['Report ID', `<code>${vizEsc(payload?.report_id || lastReportId || '—')}</code>`],
    ['Title', vizEsc(payload?.title || '—')],
    ['Kind', vizEsc(payload?.kind || lastReportKind || '—')],
    ['Readiness score', vizEsc(String(payload?.readiness_score ?? payload?.score ?? '—'))],
    ['Findings', String(Array.isArray(payload?.findings) ? payload.findings.length : 0)],
    ['Selected format', vizEsc(format || lastReportFormat)],
  ];
}

async function buildCustodyPreviewFromExport({ payload, custody, fallbackType, fallbackFormat, note }) {
  const verification = await verifyCustodyManifestLocal({ payload, custody });
  return {
    statusLabel: verification.ok ? 'Digest verified locally' : `Verification failed: ${verification.error}`,
    statusTone: verification.ok ? 'safe' : 'high',
    artifactType: custody?.artifact_type || fallbackType,
    artifactId: custody?.artifact_id || null,
    format: custody?.format || fallbackFormat || 'json',
    schemaVersion: custody?.schema_version || CUSTODY_SCHEMA_VERSION,
    contentSha256: custody?.content_sha256 || null,
    contentCanonicalization: custody?.content_canonicalization || CUSTODY_CONTENT_CANONICALIZATION,
    createdAt: custody?.created_at || null,
    createdBy: custody?.created_by || null,
    tenantId: custody?.tenant_id || null,
    previousAuditHash: custody?.previous_audit_hash || null,
    previousTenantAuditHash: custody?.previous_tenant_audit_hash || null,
    subjectIds: Array.isArray(custody?.subject_ids) ? custody.subject_ids : [],
    note,
  };
}

async function buildEvidenceCustodyPreview(exportData) {
  const digest = await sha256CanonicalJsonForCustody(exportData.payload);
  return {
    statusLabel: 'Preview only',
    statusTone: '',
    artifactType: 'evidence_chain_export_preview',
    artifactId: null,
    format: 'json',
    schemaVersion: CUSTODY_SCHEMA_VERSION,
    contentSha256: digest,
    contentCanonicalization: CUSTODY_CONTENT_CANONICALIZATION,
    createdAt: exportData.payload.exported_at || null,
    createdBy: 'UI export preview',
    tenantId: el('tenantId')?.value || null,
    previousAuditHash: null,
    previousTenantAuditHash: null,
    subjectIds: exportData.payload.evidence_ids || [],
    note: 'UI-generated digest preview only. Immutable snapshot signing and retained custody storage remain open production gates.',
  };
}

function renderReportContentPreview(format, content) {
  if (format === 'markdown') {
    return `<details open><summary>Markdown preview</summary><pre>${vizEsc(content)}</pre></details>`;
  }
  if (format === 'html') {
    return `<details open><summary>HTML preview (self-contained)</summary><iframe sandbox="" srcdoc="${vizEsc(content)}" style="width:100%;min-height:320px;border:1px solid var(--border)"></iframe></details>`;
  }
  return '<p class="muted">JSON export stays metadata-only in the UI preview. Use the custody manifest preview to inspect export integrity fields.</p>';
}

function normalizeVerdictKey(verdict) {
  if (verdict === 'misplaced_agent') return 'misplaced';
  return verdict;
}

function heatClassFromVerdict(verdict) {
  const key = normalizeVerdictKey(verdict);
  if (!key) return 'na';
  if (key === 'protected') return 'pass';
  if (key === 'bypassable' || key === 'penetrated') return 'fail';
  if (key === 'misplaced' || key === 'inconclusive') return 'warn';
  return 'pending';
}

function renderReadinessGauge(score, max = 100) {
  const s = Math.max(0, Math.min(max, Number(score) || 0));
  const pct = s / max;
  const r = 42;
  const cx = 50;
  const cy = 50;
  const start = Math.PI;
  const end = start + Math.PI * pct;
  const x1 = cx + r * Math.cos(start);
  const y1 = cy + r * Math.sin(start);
  const x2 = cx + r * Math.cos(end);
  const y2 = cy + r * Math.sin(end);
  const large = pct > 0.5 ? 1 : 0;
  const arc = pct > 0
    ? `<path d="M ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2}" fill="none" stroke="${VIZ_STROKE.accent}" stroke-width="8" stroke-linecap="round"/>`
    : '';
  return `<div class="readiness-gauge" role="img" aria-label="Readiness score ${s}">
    <svg viewBox="0 0 100 56" width="100%" height="auto" preserveAspectRatio="xMidYMid meet">
      <path d="M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}" fill="none" stroke="#e8eef3" stroke-width="8" stroke-linecap="round"/>
      ${arc}
      <text x="${cx}" y="${cy - 4}" text-anchor="middle" font-size="14" font-weight="600" fill="#17202a">${s}</text>
      <text x="${cx}" y="${cy + 10}" text-anchor="middle" font-size="6" fill="#667789">readiness</text>
    </svg>
  </div>`;
}

function renderReadinessRadar(factors) {
  const items = (factors || []).slice(0, 8);
  const fallback = [
    { label: 'Verdicts', score: 0 },
    { label: 'Agents', score: 0 },
    { label: 'Scope', score: 0 },
    { label: 'Evidence', score: 0 },
  ];
  const dims = items.length ? items : fallback;
  const n = dims.length;
  const cx = 60;
  const cy = 60;
  const maxR = 36;
  const grid = [0.25, 0.5, 0.75, 1].map((t) => {
    const gp = dims.map((_, i) => {
      const angle = (Math.PI * 2 * i) / n - Math.PI / 2;
      const r = maxR * t;
      return `${cx + r * Math.cos(angle)},${cy + r * Math.sin(angle)}`;
    }).join(' ');
    return `<polygon points="${gp}" fill="none" stroke="#e0e6ec" stroke-width="0.5"/>`;
  }).join('');
  const axes = dims.map((f, i) => {
    const angle = (Math.PI * 2 * i) / n - Math.PI / 2;
    const x = cx + maxR * Math.cos(angle);
    const y = cy + maxR * Math.sin(angle);
    const lx = cx + (maxR + 12) * Math.cos(angle);
    const ly = cy + (maxR + 12) * Math.sin(angle);
    const short = (f.label || f.key || 'factor').slice(0, 10);
    return `<line x1="${cx}" y1="${cy}" x2="${x}" y2="${y}" stroke="#d7dee7"/>
      <text x="${lx}" y="${ly}" text-anchor="middle" dominant-baseline="middle" font-size="5" fill="#667789">${vizEsc(short)}</text>`;
  }).join('');
  const poly = dims.map((f, i) => {
    const angle = (Math.PI * 2 * i) / n - Math.PI / 2;
    const r = maxR * (Math.min(100, Math.max(0, Number(f.score) || 0)) / 100);
    return `${cx + r * Math.cos(angle)},${cy + r * Math.sin(angle)}`;
  }).join(' ');
  return `<div class="readiness-radar" role="img" aria-label="Readiness factor radar">
    <svg viewBox="0 0 120 120" width="100%" height="auto" preserveAspectRatio="xMidYMid meet">${grid}${axes}
      <polygon points="${poly}" fill="rgba(18,107,131,0.22)" stroke="${VIZ_STROKE.accent}" stroke-width="1.5"/>
    </svg>
  </div>`;
}

function renderVectorHeatmap(targetGroups, checksPayload, runsPayload, hsPayload, verdictByRunId = {}) {
  const groups = targetGroups?.items?.length ? targetGroups.items : [{ id: '—', name: 'No target groups' }];
  const checks = checksPayload?.items || checksPayload || [];
  const families = [...new Set(checks.map((c) => c.vector_family).filter(Boolean))].sort();
  const cols = [...new Set([...(families.length ? families : ['origin', 'l3_l4', 'dns', 'l7']), 'high_scale'])].sort();
  const runs = runsPayload?.items || runsPayload || [];
  const hsItems = hsPayload?.items || hsPayload || [];
  const checkById = Object.fromEntries(checks.map((c) => [c.check_id || c.id, c]));

  function cellState(tgId, fam) {
    if (tgId === '—') return 'na';
    const hs = hsItems.filter((r) => r.target_group_id === tgId);
    if (fam === 'high_scale') {
      if (!hs.length) return 'na';
      const last = hs[hs.length - 1];
      if (['submitted', 'approved'].includes(last.state)) return 'pending';
      if (['scheduled', 'running'].includes(last.state)) return 'warn';
      if (['stopped', 'closed'].includes(last.state)) return 'pass';
      return 'pending';
    }
    const familyRuns = runs.filter((r) => r.target_group_id === tgId).slice().reverse();
    const match = familyRuns.find((r) => {
      const famFromRun = r.vector_family || checkById[r.check_id]?.vector_family;
      return famFromRun === fam;
    });
    if (!match) return 'na';
    const v = verdictByRunId[match.id];
    if (v) return heatClassFromVerdict(v);
    if (['completed', 'verdicted'].includes(match.status)) return 'pending';
    return 'warn';
  }

  const colLabels = cols.map((f) => `<th scope="col">${vizEsc(f.replace(/_/g, '/'))}</th>`).join('');
  const body = groups.map((g) => {
    const cells = cols.map((f) => {
      const st = cellState(g.id, f);
      return `<td><span class="heatmap-cell heatmap-cell--${st}" title="${vizEsc(f)}">${st === 'na' ? 'N/A' : st}</span></td>`;
    }).join('');
    return `<tr><th scope="row">${vizEsc(g.name)}</th>${cells}</tr>`;
  }).join('');
  return `<div class="vector-heatmap">
    <table class="heatmap-table"><thead><tr><th scope="col">Target group</th>${colLabels}</tr></thead><tbody>${body}</tbody></table>
    <p class="muted viz-legend">Cells reflect latest safe-run verdict evidence per vector family (metadata-only probes).</p>
  </div>`;
}

function renderScoreTrend(runsPayload, currentScore) {
  const runs = [...(runsPayload?.items || runsPayload || [])].sort((a, b) =>
    String(a.created_at || a.id).localeCompare(String(b.created_at || b.id)),
  );
  const end = Number(currentScore) || 0;
  const points = runs.length
    ? runs.map((r, i) => {
      const frac = (i + 1) / runs.length;
      return { v: Math.round(end * (0.5 + 0.5 * frac)), label: (r.id || '').slice(-6) || String(i + 1) };
    })
    : [{ v: end, label: 'now' }];
  if (runs.length) points[points.length - 1].v = end;
  const w = 200;
  const h = 48;
  const pad = 4;
  const maxV = Math.max(100, ...points.map((p) => p.v), 1);
  const coords = points.map((p, i) => {
    const x = pad + (i * (w - pad * 2)) / Math.max(1, points.length - 1);
    const y = h - pad - (p.v / maxV) * (h - pad * 2);
    return `${x},${y}`;
  }).join(' ');
  return `<div class="score-trend" role="img" aria-label="Readiness score trend">
    <svg viewBox="0 0 ${w} ${h}" width="100%" height="auto" preserveAspectRatio="none">
      <polyline points="${coords}" fill="none" stroke="${VIZ_STROKE.accent}" stroke-width="2" vector-effect="non-scaling-stroke"/>
      ${points.map((p, i) => {
        const x = pad + (i * (w - pad * 2)) / Math.max(1, points.length - 1);
        const y = h - pad - (p.v / maxV) * (h - pad * 2);
        return `<circle cx="${x}" cy="${y}" r="2.5" fill="${VIZ_STROKE.accent}"/>`;
      }).join('')}
    </svg>
    <span class="muted score-trend-caption">${points.length} run${points.length === 1 ? '' : 's'} · current ${end}</span>
  </div>`;
}

function trafficHopState(hop, verdict) {
  if (!verdict) return hop === 'probe' ? 'ok' : 'muted';
  if (verdict === 'protected') {
    if (hop === 'probe' || hop === 'edge') return 'ok';
    return 'muted';
  }
  if (verdict === 'bypassable' || verdict === 'penetrated') {
    if (hop === 'probe') return 'ok';
    if (hop === 'origin') return 'danger';
    return 'warn';
  }
  return 'warn';
}

function renderTrafficPath(detail) {
  const verdict = detail?.verdict?.verdict;
  const hops = [
    { key: 'probe', label: 'External probe', sub: 'sent' },
    { key: 'edge', label: 'CDN / WAF', sub: 'blocked?' },
    { key: 'lb', label: 'Load balancer', sub: 'forwarded?' },
    { key: 'origin', label: 'Origin / agent', sub: 'observed?' },
  ];
  const nodes = hops.map((h) => {
    const st = trafficHopState(h.key, verdict);
    return `<div class="traffic-path-node traffic-path-node--${st}">
      <span class="traffic-path-label">${vizEsc(h.label)}</span>
      <span class="traffic-path-sub muted">${vizEsc(h.sub)}</span>
    </div>`;
  }).join('<span class="traffic-path-arrow" aria-hidden="true">→</span>');
  const statusLine = verdict
    ? `Verdict evidence: ${vizEsc(verdict)} (${vizEsc(detail.verdict.confidence || '')})`
    : 'Awaiting correlated probe and agent evidence.';
  return `<div class="traffic-path" role="img" aria-label="Traffic path diagram">
    <div class="traffic-path-track">${nodes}</div>
    <p class="muted traffic-path-caption">${statusLine}</p>
  </div>`;
}

function renderTruthTable(verdict) {
  const current = normalizeVerdictKey(verdict?.verdict || '');
  const rows = [
    ['protected', 'Blocked before origin; observation absent or consistent with policy.'],
    ['bypassable', 'Edge did not stop traffic; origin/agent observed the marker.'],
    ['penetrated', 'Protection failed; unwanted reach confirmed by evidence.'],
    ['misplaced', 'Agent or canary placement does not match the declared protected path.'],
  ];
  const body = rows.map(([key, desc]) => {
    const active = current === key ? ' truth-row--active' : '';
    return `<tr class="truth-row${active}"><td><span class="truth-outcome truth-outcome--${key}">${key}</span></td><td>${vizEsc(desc)}</td></tr>`;
  }).join('');
  return `<div class="truth-table-viz">
    <table class="truth-table"><thead><tr><th>Outcome</th><th>Meaning (evidence-oriented)</th></tr></thead><tbody>${body}</tbody></table>
  </div>`;
}

function renderRunTimeline(eventsPayload) {
  const items = eventsPayload?.items || eventsPayload || [];
  if (!items.length) {
    return '<div class="run-timeline-viz empty">No timeline events yet.</div>';
  }
  const max = items.length - 1;
  const bars = items.map((e, i) => {
    const pct = max ? (i / max) * 100 : 50;
    const label = `${e.signal_type || 'event'} · ${(e.timestamp || '').slice(11, 19) || '—'}`;
    return `<div class="run-timeline-marker" style="left:${pct}%"><span class="run-timeline-dot"></span><span class="run-timeline-tip">${vizEsc(label)}</span></div>`;
  }).join('');
  return `<div class="run-timeline-viz" role="img" aria-label="Run event timeline">
    <div class="run-timeline-rail">${bars}</div>
    <ol class="run-timeline-list">${items.map((e) => `<li>${vizEsc(e.timestamp)} · ${vizEsc(e.signal_type)} · ${vizEsc(e.source || '')}</li>`).join('')}</ol>
  </div>`;
}

const SOC_SWIMLANE_STAGES = ['submitted', 'approved', 'scheduled', 'running', 'stopped', 'closed'];

function renderSocSwimlane(requestsPayload) {
  const items = requestsPayload?.items || requestsPayload || [];
  const lanes = SOC_SWIMLANE_STAGES.map((stage) => {
    const chips = items
      .filter((r) => r.state === stage)
      .map((r) => `<span class="soc-swimlane-chip" title="${vizEsc(r.reason || '')}">${vizEsc(r.id)}</span>`)
      .join('') || '<span class="muted soc-swimlane-empty">—</span>';
    return `<div class="soc-swimlane-lane"><span class="soc-swimlane-label">${stage}</span><div class="soc-swimlane-body">${chips}</div></div>`;
  }).join('');
  return `<div class="soc-swimlane" aria-label="High-scale request lifecycle swimlane">${lanes}</div>`;
}

function isDiscoveryFeatureDisabledError(err) {
  const msg = String(err?.message ?? '');
  return msg === 'discovery_feature_disabled' || msg.includes('discovery_feature_disabled');
}

async function refreshFeatureFlags() {
  try {
    await api('/v1/waf/coverage');
    wafFeatureEnabled = true;
  } catch (err) {
    wafFeatureEnabled = !isWafFeatureDisabledError(err);
  }
  try {
    await api('/v1/discovery/inbox');
    discoveryFeatureEnabled = true;
  } catch (err) {
    discoveryFeatureEnabled = !isDiscoveryFeatureDisabledError(err);
  }
}

function navEntries() {
  return NAV.filter(([id]) => (id === 'discovery' ? discoveryFeatureEnabled : true));
}

function renderNav() {
  el('nav').innerHTML = navEntries().map(([id, label]) =>
    `<a href="#${id}" class="${route === id ? 'active' : ''}" data-route="${id}">${label}</a>`,
  ).join('');
  el('nav').querySelectorAll('a').forEach((a) => {
    a.onclick = (e) => {
      e.preventDefault();
      route = a.dataset.route;
      location.hash = route;
      render();
    };
  });
}

async function render() {
  await refreshFeatureFlags();
  renderNav();
  const title = navEntries().find(([id]) => id === route)?.[1]
    ?? NAV.find(([id]) => id === route)?.[1]
    ?? 'AstraNull';
  el('pageTitle').textContent = title;
  const view = el('view');
  try {
    if (route === 'dashboard') view.innerHTML = await viewDashboard();
    else if (route === 'onboarding') view.innerHTML = await viewOnboarding();
    else if (route === 'environments') view.innerHTML = await viewEnvironments();
    else if (route === 'target-groups') view.innerHTML = await viewTargetGroups();
    else if (route === 'agents') view.innerHTML = await viewAgents();
    else if (route === 'checks') view.innerHTML = await viewChecks();
    else if (route === 'runs') view.innerHTML = await viewRuns();
    else if (route === 'findings') view.innerHTML = await viewFindings();
    else if (route === 'evidence') view.innerHTML = await viewEvidence();
    else if (route === 'waf-posture') view.innerHTML = await viewWafPosture();
    else if (route === 'cve-pipeline') view.innerHTML = await viewCvePipeline();
    else if (route === 'discovery') view.innerHTML = await viewDiscovery();
    else if (route === 'supply-chain') view.innerHTML = await viewSupplyChain();
    else if (route === 'remediation') view.innerHTML = await viewRemediation();
    else if (route === 'high-scale') view.innerHTML = await viewHighScale();
    else if (route === 'soc') view.innerHTML = await viewSoc();
    else if (route === 'reports') view.innerHTML = await viewReports();
    else if (route === 'notifications') view.innerHTML = await viewNotifications();
    else if (route === 'audit') view.innerHTML = await viewAudit();
    else if (route === 'release-evidence') view.innerHTML = await viewReleaseEvidence();
    else if (route === 'settings') view.innerHTML = await viewSettings();
    bindHandlers();
    if (route === 'soc') applySocOut();
    if (route === 'high-scale') applyHighScaleOut();
    if (route === 'waf-posture') applyWafOut();
  } catch (err) {
    view.innerHTML = `<div class="card">Error: ${err.message}</div>`;
  }
}

async function loadEnvBadge() {
  try {
    const envs = await api('/v1/environments');
    const names = envs.items.map((e) => e.name).join(', ') || 'No environments';
    el('envBadge').textContent = names.slice(0, 48);
  } catch {
    el('envBadge').textContent = 'Developer validation · Safe checks only';
  }
}

async function viewEnvironments() {
  const data = await api('/v1/environments');
  if (!data.items.length) {
    return '<div class="empty">No environments. <button class="btn" data-action="create-env">Create environment</button></div>';
  }
  return `<div class="card"><button class="btn" data-action="create-env">Add environment</button></div>
    <div class="card"><table><thead><tr><th>Name</th><th>Status</th><th>ID</th></tr></thead><tbody>
    ${data.items.map((e) => `<tr><td>${e.name}</td><td>${e.status || 'active'}</td><td>${e.id}</td></tr>`).join('')}
    </tbody></table></div>`;
}

async function viewEvidence() {
  const [data, runs, findings] = await Promise.all([
    api('/v1/evidence'),
    api('/v1/test-runs'),
    api('/v1/findings'),
  ]);
  const verdicts = [];
  for (const r of runs.items.slice(-20)) {
    try {
      const detail = await api(`/v1/test-runs/${r.id}`);
      if (detail.verdict) verdicts.push({ ...detail.verdict, test_run_id: r.id });
    } catch {
      /* partial chain */
    }
  }
  const exportData = buildEvidenceChainExport({
    evidence: data.items,
    runs: runs.items,
    verdicts,
    findings: findings.items,
  });
  lastEvidenceExport = exportData;
  return `${renderEvidenceChainPanel(data.items, exportData)}
    ${renderExportInspectionPanel({
    panelId: 'evidenceCustodyPreview',
    heading: 'Evidence export inspection',
    emptyMessage: 'Export the evidence-chain JSON to inspect digest metadata for this bundle.',
    summaryRows: summarizeEvidenceExport(exportData),
    preview: lastEvidenceCustodyPreview,
  })}`;
}

async function viewNotifications() {
  const data = await api('/v1/notifications');
  return `<div class="card"><button class="btn" data-action="create-notify-rule">Add rule (metadata only)</button>
    <p class="muted">Developer validation records intended deliveries only — no Slack/email/Teams send.</p>
    <h4>Rules</h4>${data.rules.length ? data.rules.map((r) => `<div>${r.channel} → ${r.destination}</div>`).join('') : '<div class="empty">No rules yet.</div>'}
    <h4>Recent events</h4>${data.events.length ? `<ul>${data.events.slice().reverse().map((e) => `<li>${e.created_at} · ${e.trigger} · ${e.subject}</li>`).join('')}</ul>` : '<div class="empty">No notification events yet.</div>'}
  </div>`;
}

async function viewDashboard() {
  const [s, tgs, checks, runs, hs] = await Promise.all([
    api('/v1/state'),
    api('/v1/target-groups'),
    api('/v1/checks'),
    api('/v1/test-runs'),
    api('/v1/high-scale-requests'),
  ]);
  await loadEnvBadge();
  const verdictByRunId = {};
  for (const r of runs.items.slice(-8)) {
    try {
      const d = await api(`/v1/test-runs/${r.id}`);
      if (d.verdict?.verdict) verdictByRunId[r.id] = d.verdict.verdict;
    } catch {
      /* keep heatmap partial */
    }
  }
  const factorList = s.readiness.factors?.length
    ? s.readiness.factors
    : [{ label: 'Posture', score: s.readiness.score, detail: 'Awaiting factor breakdown.' }];
  return `
    <div class="card platform-promise">
      <p class="muted"><strong>No-access-first:</strong> ${PLATFORM_PROMISE}</p>
      <p class="muted">Declare target groups manually or via import — no cloud credentials and no automatic IP inventory discovery in core scope.</p>
    </div>
    <div class="grid">
      <div class="card"><div class="muted">Open findings</div><div class="metric">${s.open_findings}</div></div>
      <div class="card"><div class="muted">Agents online</div><div class="metric">${s.agents_online}</div></div>
      <div class="card"><div class="muted">Target groups</div><div class="metric">${s.target_groups}</div></div>
    </div>
    <div class="card viz-grid">
      <h3>Readiness snapshot</h3>
      <div class="viz-grid-row">
        <div class="viz-grid-cell">${renderReadinessGauge(s.readiness.score)}</div>
        <div class="viz-grid-cell">${renderReadinessRadar(factorList)}</div>
        <div class="viz-grid-cell viz-grid-cell--wide">${renderScoreTrend(runs, s.readiness.score)}</div>
      </div>
    </div>
    <div class="card">
      <h3>Vector / target heatmap</h3>
      ${renderVectorHeatmap(tgs, checks, runs, hs, verdictByRunId)}
    </div>
    <div class="card">
      <h3>Readiness factors</h3>
      <ul>${factorList.map((f) => `<li><strong>${f.label}</strong> (${f.score}) — ${f.detail}</li>`).join('')}</ul>
    </div>`;
}

function apiBaseUrl() {
  return `${location.protocol}//${location.host}`;
}

async function viewOnboarding() {
  const [envs, tgs, agents, runs, tokens] = await Promise.all([
    api('/v1/environments'),
    api('/v1/target-groups'),
    api('/v1/agents'),
    api('/v1/test-runs'),
    api('/v1/bootstrap-tokens'),
  ]);
  const targets = [];
  for (const g of tgs.items) {
    try {
      const detail = await api(`/v1/target-groups/${g.id}`);
      targets.push(...(detail.targets || []));
    } catch {
      /* partial onboarding state */
    }
  }
  const progress = computeOnboardingProgress({
    environments: envs.items,
    targetGroups: tgs.items,
    targets,
    agents: agents.items,
    runs: runs.items,
    hasToken: tokens.items.length > 0 || Boolean(lastTokenSecret),
  });
  const tgName = tgs.items[0]?.name;
  const installCommands = buildInstallCommands({
    apiBase: apiBaseUrl(),
    token: lastTokenSecret || '<BOOTSTRAP_TOKEN>',
    targetGroupName: tgName,
  });
  return renderOnboardingWizard(progress, installCommands, {
    tokenSecret: lastTokenSecret,
    targetValue: targets[0]?.value,
  });
}

async function viewTargetGroups() {
  const data = await api('/v1/target-groups');
  if (!data.items.length) {
    return `<div class="empty">No target groups. <button class="btn" data-action="create-tg">Create target group</button></div>`;
  }
  const rows = data.items.map((g) => `<tr><td>${g.name}</td><td>${g.id}</td><td><button class="btn secondary" data-action="tg-detail" data-id="${g.id}">Open</button></td></tr>`).join('');
  return `<div class="card"><button class="btn" data-action="create-tg">Create target group</button></div>
    <div class="card"><table><thead><tr><th>Name</th><th>ID</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>
    <div id="tgDetail"></div>`;
}

async function viewAgents() {
  const [agents, tgs, tokens] = await Promise.all([
    api('/v1/agents'),
    api('/v1/target-groups'),
    api('/v1/bootstrap-tokens'),
  ]);
  const installCommands = buildInstallCommands({
    apiBase: apiBaseUrl(),
    token: lastTokenSecret || '<BOOTSTRAP_TOKEN>',
    targetGroupName: tgs.items[0]?.name,
  });
  return `
    <div class="card">
      <h3>Install commands</h3>
      <p class="muted">Copy the command for your deployment method. Bootstrap tokens are shown once in Settings or Onboarding.</p>
      ${renderInstallCommandsPanel(installCommands, activeInstallTab)}
      <p class="muted">Outbound-only polling — no inbound management port. Canary observation is customer-approved metadata only.</p>
      ${tokens.items.length ? '' : '<p class="muted">No bootstrap tokens yet — <button type="button" class="btn secondary" data-action="goto-settings">create token</button>.</p>'}
    </div>
    <div class="card">${agents.items.length ? `<table><thead><tr><th>Name</th><th>Status</th><th>Last heartbeat</th></tr></thead><tbody>
      ${agents.items.map((a) => `<tr><td>${a.name}</td><td>${a.status}</td><td>${a.last_heartbeat_at || '-'}</td></tr>`).join('')}
    </tbody></table>` : '<div class="empty">No agents registered. Generate a token in Settings and run the install command.</div>'}
    </div>`;
}

async function viewChecks() {
  const data = await api('/v1/checks');
  const families = [...new Set(data.items.map((c) => c.vector_family))];
  const matrix = families.map((f) => {
    const items = data.items.filter((c) => c.vector_family === f);
    return `<tr><td>${f}</td><td>${items.length}</td><td>${items.map((c) => c.safety_class || c.risk_class).join(', ')}</td></tr>`;
  }).join('');
  return `<div class="card"><h3>Vector coverage matrix</h3><table><thead><tr><th>Family</th><th>Checks</th><th>Safety</th></tr></thead><tbody>${matrix}</tbody></table></div>
    <div class="card"><table><thead><tr><th>Check</th><th>Family</th><th>Safety</th><th>Description</th></tr></thead><tbody>
    ${data.items.map((c) => `<tr><td>${c.name}</td><td>${c.vector_family}</td><td><span class="pill ${c.risk_class === 'safe' ? 'safe' : ''}">${c.safety_class || c.risk_class}</span></td><td>${c.description}</td></tr>`).join('')}
  </tbody></table></div>`;
}

async function viewRuns() {
  const runs = await api('/v1/test-runs');
  if (!runs.items.length) {
    return `<div class="empty">No runs yet. <button class="btn" data-action="start-run">Start safe validation</button></div>`;
  }
  const latest = runs.items[runs.items.length - 1];
  const detail = await api(`/v1/test-runs/${latest.id}`);
  const events = await api(`/v1/test-runs/${latest.id}/events`);
  return `
    <div class="card"><button class="btn" data-action="start-run">Start safe validation</button></div>
    <div class="card"><h3>Latest run ${latest.id}</h3>
      <p>Status: ${detail.status} · Check: ${detail.check_id}</p>
      <p class="muted">Vector: ${detail.vector_family || '-'} · Safety: ${detail.safety_class || '-'}</p>
      <h4>Traffic path</h4>
      ${renderTrafficPath(detail)}
      ${renderVerdictExplanation(detail, events)}
      <h4>Verdict truth table</h4>
      ${renderTruthTable(detail.verdict)}
      <h4>Timeline</h4>
      ${renderRunTimeline(events)}
      <ul class="timeline">${events.items.map((e) => `<li>${e.timestamp} · ${e.signal_type} · ${e.source || ''}</li>`).join('')}</ul>
      <p class="muted">Probe results use metadata-only safe probe simulation (no live customer traffic).</p>
    </div>`;
}

async function viewFindings() {
  const data = await api('/v1/findings');
  if (!data.items.length) return '<div class="empty">No findings yet. Run a safe validation that correlates to bypassable or penetrated.</div>';
  const focusId = selectedFindingId && data.items.some((f) => f.id === selectedFindingId)
    ? selectedFindingId
    : data.items[0].id;
  const finding = await api(`/v1/findings/${focusId}`);
  let runMeta = '';
  let explanationHtml = renderFindingVerdictExplanation(finding, null, null);
  if (finding.test_run_id) {
    const [runDetail, events] = await Promise.all([
      api(`/v1/test-runs/${finding.test_run_id}`),
      api(`/v1/test-runs/${finding.test_run_id}/events`),
    ]);
    runMeta = `<p class="muted">Run <code>${vizEsc(finding.test_run_id)}</code> · Check ${vizEsc(runDetail.check_id || '—')}</p>`;
    explanationHtml = renderFindingVerdictExplanation(finding, runDetail, events);
  }
  const rowClass = (id) => (id === focusId ? ' finding-row--active' : '');
  return `<div class="card"><table><thead><tr><th>Title</th><th>Severity</th><th>Status</th><th></th></tr></thead><tbody>
    ${data.items.map((f) => `<tr class="finding-row${rowClass(f.id)}">
      <td>${vizEsc(f.title)}</td>
      <td><span class="pill high">${vizEsc(f.severity)}</span></td>
      <td>${vizEsc(f.status)}</td>
      <td class="finding-actions">
        <button type="button" class="btn secondary" data-action="view-finding" data-id="${vizEsc(f.id)}">View</button>
        <button type="button" class="btn secondary" data-action="export-finding" data-id="${vizEsc(f.id)}">Export</button>
      </td>
    </tr>`).join('')}
  </tbody></table></div>
  <div class="card finding-detail">
    <h3>${vizEsc(finding.title)}</h3>
    <p>Severity: <span class="pill high">${vizEsc(finding.severity)}</span> · Status: ${vizEsc(finding.status)}</p>
    ${runMeta}
    ${explanationHtml}
  </div>
  ${renderExportInspectionPanel({
    panelId: 'findingCustodyPreview',
    heading: 'Finding export inspection',
    emptyMessage: 'Export a finding to inspect custody metadata without rendering the full export body.',
    preview: lastFindingCustodyPreview,
  })}`;
}

function hsDefaultWindowLocal() {
  const pad = (n) => String(n).padStart(2, '0');
  const toLocal = (d) =>
    `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
  const start = new Date(Date.now() + 86400000);
  const end = new Date(Date.now() + 172800000);
  return { start: toLocal(start), end: toLocal(end) };
}

/** SOC-009 metadata-only authorization proof artifact types (no traffic execution). */
const HS_AUTH_ARTIFACT_TYPES = [
  ['customer_authorization_letter', 'Customer authorization letter'],
  ['target_ownership_confirmation', 'Target ownership confirmation'],
  ['business_approval', 'Business approval'],
  ['legal_approval', 'Legal approval'],
  ['emergency_contacts', 'Emergency contacts'],
  ['stop_criteria', 'Stop criteria'],
  ['test_plan', 'Test plan'],
  ['scope_rate_plan', 'Scope / rate plan'],
  ['abort_criteria', 'Abort criteria'],
  ['provider_approval', 'Provider approval'],
];

function renderAuthorizationPackStatus(pack) {
  if (!pack || typeof pack !== 'object') return '';
  const status = pack.status ?? pack.overall_status ?? pack.authorization_pack_status;
  if (!status) return '';
  const missing = pack.missing ?? pack.missing_requirements ?? pack.missing_fields ?? [];
  const missingList = Array.isArray(missing) && missing.length
    ? `<ul class="muted hs-pack-missing">${missing.map((m) => `<li>${vizEsc(typeof m === 'string' ? m : m.name ?? m.field ?? JSON.stringify(m))}</li>`).join('')}</ul>`
    : '';
  return `<div class="hs-pack-status" role="status">
    <span class="pill">${vizEsc(String(status))}</span>
    ${missingList}
  </div>`;
}

function buildHsArtifactUploadBody(type, requestId, providerName) {
  const win = hsDefaultWindowLocal();
  const body = {
    type,
    reference_uri: `metadata://ui/${type}/${requestId}`,
    approval_reference: 'ui-metadata-reference',
    approver: 'customer-declared',
    valid_window: {
      start: new Date(win.start).toISOString(),
      end: new Date(win.end).toISOString(),
    },
    approved_targets: ['declared-target-group-scope'],
    approved_scenario_families: ['metadata-declared-families'],
    max_rate: 'metadata-only-cap',
    max_duration_minutes: 60,
    abort_criteria: 'SOC kill switch and customer on-call escalation',
    emergency_contacts: 'declared-on-request',
  };
  if (providerName && type === 'provider_approval') body.provider_name = providerName;
  return body;
}

function isWafFeatureDisabledError(err) {
  const msg = String(err?.message ?? '');
  return msg === 'waf_feature_disabled' || msg.includes('waf_feature_disabled');
}

function wafPostureStatusPill(status) {
  const key = (status || 'unknown').toLowerCase();
  return `<span class="waf-status-pill waf-status-pill--${vizEsc(key)}">${vizEsc(key)}</span>`;
}

function applyWafOut() {
  const out = document.getElementById('wafOut');
  if (!out) return;
  out.textContent = typeof lastWafOut.payload === 'string'
    ? lastWafOut.payload
    : JSON.stringify(lastWafOut.payload, null, 2);
  out.classList.toggle('waf-out-error', lastWafOut.isError);
}

function setWafOut(payload, isError = false) {
  lastWafOut = { payload, isError };
  applyWafOut();
}

async function runWafAction(fn) {
  try {
    const result = await fn();
    setWafOut(result ?? { ok: true });
    await render();
    return result;
  } catch (err) {
    setWafOut(err.message || 'WAF action failed.', true);
    await render();
    return null;
  }
}

async function fetchWafAssetRows(assets) {
  const details = await Promise.all(
    assets.map(async (asset) => {
      try {
        const payload = await api(`/v1/waf/assets/${asset.id}`);
        return {
          ...asset,
          posture_status: payload.current_posture?.status ?? asset.status ?? 'unknown',
          reason_codes: payload.current_posture?.reason_codes ?? [],
        };
      } catch {
        return {
          ...asset,
          posture_status: asset.status ?? 'unknown',
          reason_codes: [],
        };
      }
    }),
  );
  return details;
}

function renderWafDisabledConsole() {
  return `
    <div id="waf-posture" class="card waf-disabled">
      <h3>WAF Posture</h3>
      <p class="muted">This optional add-on is disabled in the current environment (<code>waf_feature_disabled</code>).</p>
      <p class="muted">No-access mode does not require cloud or WAF vendor credentials — declare assets and run bounded marker validations when the feature is enabled.</p>
    </div>`;
}

async function viewWafPosture() {
  let coverage;
  let assetsPayload;
  let validationsPayload;
  let targetGroupsPayload;
  try {
    [coverage, assetsPayload, validationsPayload, targetGroupsPayload] = await Promise.all([
      api('/v1/waf/coverage'),
      api('/v1/waf/assets'),
      api('/v1/waf/validations'),
      api('/v1/target-groups'),
    ]);
  } catch (err) {
    if (isWafFeatureDisabledError(err)) return renderWafDisabledConsole();
    throw err;
  }

  const tgNameById = Object.fromEntries(
    (targetGroupsPayload.items || []).map((g) => [g.id, g.name]),
  );
  const assets = await fetchWafAssetRows(assetsPayload.items || []);
  const validations = validationsPayload.items || [];

  const coverageCards = [
    ['Protected', coverage.protected],
    ['Underprotected', coverage.underprotected],
    ['Unprotected', coverage.unprotected],
    ['Unknown', coverage.unknown],
    ['Excluded', coverage.excluded],
    ['Total assets', coverage.total_assets],
  ].map(([label, value]) => `<div class="card waf-coverage-card"><div class="muted">${vizEsc(label)}</div><div class="metric">${value ?? 0}</div></div>`).join('');

  const assetRows = assets.length
    ? assets.map((a) => {
      const reasons = (a.reason_codes || []).length
        ? a.reason_codes.map((c) => `<code>${vizEsc(c)}</code>`).join(', ')
        : '—';
      const tgLabel = tgNameById[a.target_group_id] || a.target_group_id || '—';
      return `<tr>
        <td><code>${vizEsc(a.canonical_url || a.hostname || '—')}</code></td>
        <td>${wafPostureStatusPill(a.posture_status)}</td>
        <td>${vizEsc(a.owner_hint || '—')}</td>
        <td>${vizEsc(tgLabel)}</td>
        <td>${reasons}</td>
        <td>
          <button type="button" class="btn secondary" data-action="waf-run-validation" data-id="${vizEsc(a.id)}">Run marker validation</button>
          <button type="button" class="btn secondary" data-action="waf-finalize-pass" data-id="${vizEsc(a.id)}">Finalize pass</button>
        </td>
      </tr>`;
    }).join('')
    : '';

  const validationRows = validations.length
    ? validations.map((r) => `<tr>
        <td><code>${vizEsc(r.id)}</code></td>
        <td>${vizEsc(r.mode || '—')}</td>
        <td>${vizEsc(r.status || '—')}</td>
        <td>${vizEsc(formatUtc(r.created_at))}</td>
        <td>${vizEsc(formatUtc(r.finalized_at))}</td>
      </tr>`).join('')
    : '<tr><td colspan="5"><div class="empty">No validation runs yet. Create an asset and start a safe marker validation.</div></td></tr>';

  const emptyAssets = assets.length
    ? ''
    : `<div class="empty">No WAF assets declared yet.
        <button type="button" class="btn" data-action="waf-create-demo-asset">Create declared demo WAF asset</button>
      </div>`;

  return `
    <div id="waf-posture" class="card">
      <h3>WAF Posture console</h3>
      <p class="muted">Customer-declared assets only — bounded marker and canary validations with metadata-only evidence. No cloud connector credentials required for core no-access mode.</p>
      <button type="button" class="btn secondary" data-action="waf-create-demo-asset">Add demo asset (tg_1)</button>
      <pre id="wafOut" class="waf-out muted"></pre>
    </div>
    <div class="grid waf-coverage-grid">${coverageCards}</div>
    <div class="card">
      <h4>Declared assets</h4>
      ${emptyAssets}
      ${assets.length ? `<table><thead><tr>
        <th>Asset URL</th><th>Status</th><th>Owner</th><th>Target group</th><th>Posture reasons</th><th>Actions</th>
      </tr></thead><tbody>${assetRows}</tbody></table>` : ''}
    </div>
    <div class="card">
      <h4>Validation runs</h4>
      <table><thead><tr>
        <th>Run</th><th>Mode</th><th>Status</th><th>Created</th><th>Finalized</th>
      </tr></thead><tbody>${validationRows}</tbody></table>
    </div>
    <div class="card waf-evidence-safety">
      <h4>Evidence safety</h4>
      <p class="muted">Metadata-only summaries are shown here and in exports. Raw request/response payloads, secrets, and full policy bodies are never rendered in the UI.</p>
    </div>`;
}

function renderWafAddonDisabled(title) {
  return `
    <div class="card waf-disabled">
      <h3>${vizEsc(title)}</h3>
      <p class="muted">This optional add-on is disabled in the current environment (<code>waf_feature_disabled</code>).</p>
    </div>`;
}

function renderDiscoveryDisabled() {
  return `
    <div class="card waf-disabled">
      <h3>Discovery</h3>
      <p class="muted">External discovery is disabled in the current environment (<code>discovery_feature_disabled</code>).</p>
    </div>`;
}

function normalizeListPayload(data) {
  if (Array.isArray(data)) return data;
  return data.items ?? [];
}

async function viewCvePipeline() {
  if (!wafFeatureEnabled) return renderWafAddonDisabled('CVE Pipeline');
  const listPayload = await api('/v1/waf/cve-pipeline');
  const items = listPayload.items ?? [];
  const detail = selectedCveId && lastCveDetail?.item?.id === selectedCveId
    ? lastCveDetail
    : (selectedCveId ? { item: items.find((i) => i.id === selectedCveId) ?? null, matches: [], recommendations: [] } : null);
  return renderCvePipelinePage({
    items,
    selectedId: selectedCveId,
    detail: detail?.item ? detail : null,
    showIngestForm: showCveIngestForm,
  });
}

async function viewDiscovery() {
  if (!discoveryFeatureEnabled) return renderDiscoveryDisabled();
  const [inboxPayload, candidatesPayload, entitiesPayload] = await Promise.all([
    api('/v1/discovery/inbox'),
    api('/v1/discovery/candidates'),
    api('/v1/discovery/entities'),
  ]);
  return renderDiscoveryPage({
    inbox: inboxPayload.items ?? [],
    candidates: normalizeListPayload(candidatesPayload),
    entities: normalizeListPayload(entitiesPayload),
    activeTab: activeDiscoveryTab,
    discoveryMode,
  });
}

async function viewSupplyChain() {
  if (!wafFeatureEnabled) return renderWafAddonDisabled('Supply Chain');
  const payload = await api('/v1/waf/supply-chain/risks');
  const items = payload.items ?? [];
  const detail = selectedSupplyChainRiskId
    ? items.find((r) => r.id === selectedSupplyChainRiskId) ?? null
    : null;
  return renderSupplyChainPage({
    items,
    selectedId: selectedSupplyChainRiskId,
    detail,
    showCnameForm: showSupplyCnameForm,
    showDependencyForm: showSupplyDependencyForm,
  });
}

async function viewRemediation() {
  if (!wafFeatureEnabled) return renderWafAddonDisabled('Remediation');
  const payload = await api('/v1/waf/action-items');
  return renderRemediationPage({
    items: payload.items ?? [],
    selectedId: selectedActionItemId,
    grouped: remediationGroupedView,
  });
}

async function viewHighScale() {
  const [data, tgs] = await Promise.all([
    api('/v1/high-scale-requests'),
    api('/v1/target-groups'),
  ]);
  const rows = await Promise.all(
    data.items.map(async (r) => {
      try {
        const arts = await api(`/v1/high-scale-requests/${r.id}/artifacts`);
        return { ...r, artifactCount: arts.items.length };
      } catch {
        return { ...r, artifactCount: 0 };
      }
    }),
  );
  const win = hsDefaultWindowLocal();
  const tgOptions = tgs.items.length
    ? tgs.items.map((g) => `<option value="${g.id}">${g.name}</option>`).join('')
    : '<option value="">No target groups</option>';
  return `
    <div id="high-scale" class="card">
      <h3>High-scale requests</h3>
      <p class="muted">Customers submit scope and authorization metadata only. Execution requires SOC approval, schedule window, and governed dry-run adapter — no customer-triggered traffic.</p>
      <form class="hs-form" id="hsRequestForm">
        <label>Target group <select id="hsTargetGroup" required>${tgOptions}</select></label>
        <label>Objective / reason <textarea id="hsObjective" rows="2" required placeholder="What readiness question are you validating?"></textarea></label>
        <div class="hs-form-row">
          <label>Window start <input type="datetime-local" id="hsWindowStart" value="${win.start}" required></label>
          <label>Window end <input type="datetime-local" id="hsWindowEnd" value="${win.end}" required></label>
        </div>
        <label>Timezone <input type="text" id="hsTimezone" value="UTC" placeholder="e.g. UTC or America/New_York"></label>
        <div class="hs-form-row">
          <label>Emergency contact name <input type="text" id="hsContactName" required placeholder="On-call lead"></label>
          <label>Emergency contact <input type="text" id="hsContact" required placeholder="email or phone"></label>
        </div>
        <label>Provider name <input type="text" id="hsProviderName" placeholder="CDN/DDoS provider"></label>
        <label class="hs-inline"><input type="checkbox" id="hsProviderApproval"> Provider approval required</label>
        <div class="hs-form-row">
          <label>Environment
            <select id="hsEnvironment" required>
              <option value="">Select environment</option>
              <option value="production">Production</option>
              <option value="staging">Staging</option>
              <option value="lab">Lab</option>
            </select>
          </label>
          <label>Business criticality
            <select id="hsCriticality" required>
              <option value="">Select criticality</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </label>
        </div>
        <label>Requested scenario / vector families
          <input type="text" id="hsScenarioFamilies" required placeholder="e.g. l7, dns, origin (comma-separated metadata)">
        </label>
        <div class="hs-form-row">
          <label>Safe requested max rate (metadata)
            <input type="text" id="hsMaxRate" required placeholder="e.g. 500 rps cap — declaration only">
          </label>
          <label>Safe max duration (minutes, metadata)
            <input type="number" id="hsMaxDuration" min="1" max="240" value="30" required>
          </label>
        </div>
        <label>Stop criteria <textarea id="hsStopCriteria" rows="2" required placeholder="Written thresholds and conditions to pause or stop (metadata)"></textarea></label>
        <label>Abort criteria <textarea id="hsAbortCriteria" rows="2" required placeholder="Conditions that require immediate abort (metadata)"></textarea></label>
        <label class="hs-inline"><input type="checkbox" id="hsScopeConfirmation" required> I confirm the declared target group scope is accurate</label>
        <button type="button" class="btn" data-action="hs-submit-request">Submit request</button>
      </form>
      <pre id="hsRequestOut" class="hs-out muted"></pre>
    </div>
    <div class="card"><h3>SOC authorization pack</h3>
      <p class="muted">Attach metadata-only proof references for SOC-009 (customer, business, legal, scope/rate, stop/abort, provider when applicable). SOC reviews artifacts; <code>authorization_pack_status</code> gates approve.</p>
      ${rows.length ? rows.map((r) => {
        const providerName = r.provider_context?.provider_name ?? r.provider_context?.provider ?? r.provider_context?.name ?? '';
        const packStatus = renderAuthorizationPackStatus(r.authorization_pack_status);
        const artifactButtons = HS_AUTH_ARTIFACT_TYPES.map(([type, label]) => {
          const hideProvider = type === 'provider_approval' && !providerName && !r.provider_context?.requires_provider_approval;
          if (hideProvider) return '';
          return `<button type="button" class="btn secondary hs-artifact-btn" data-action="hs-artifact-type" data-id="${r.id}" data-type="${type}" data-provider="${vizEsc(providerName)}">${vizEsc(label)}</button>`;
        }).join('');
        return `<div class="hs-pack-row" style="margin:0.6rem 0">
          <div><code>${vizEsc(r.id)}</code> · ${vizEsc(r.state)} · artifacts: ${r.artifactCount}</div>
          ${packStatus}
          <div class="soc-action-grid hs-artifact-grid">${artifactButtons}</div>
        </div>`;
      }).join('') : '<div class="empty">No high-scale requests yet. Submit a request, then attach authorization pack metadata for SOC review.</div>'}
    </div>`;
}

function socDevScheduleWindow() {
  return {
    window_start: new Date(Date.now() - 60000).toISOString(),
    window_end: new Date(Date.now() + 3600000).toISOString(),
  };
}

function socStateChip(state) {
  const s = (state || 'unknown').replace(/_/g, ' ');
  return `<span class="soc-chip soc-chip--${state || 'unknown'}">${s}</span>`;
}

function applySocOut() {
  const out = document.getElementById('socOut');
  if (!out) return;
  out.textContent = typeof lastSocOut.payload === 'string'
    ? lastSocOut.payload
    : JSON.stringify(lastSocOut.payload, null, 2);
  out.classList.toggle('soc-out-error', lastSocOut.isError);
}

function setSocOut(payload, isError = false) {
  lastSocOut = { payload, isError };
  applySocOut();
}

function applyHighScaleOut() {
  const out = document.getElementById('hsRequestOut');
  if (!out) return;
  out.textContent = typeof lastHighScaleOut.payload === 'string'
    ? lastHighScaleOut.payload
    : JSON.stringify(lastHighScaleOut.payload, null, 2);
  out.classList.toggle('hs-out-error', lastHighScaleOut.isError);
}

function setHighScaleOut(payload, isError = false) {
  lastHighScaleOut = { payload, isError };
  applyHighScaleOut();
}

async function runSocAction(fn, refresh = true) {
  try {
    const result = await fn();
    setSocOut(result ?? { ok: true });
    if (refresh) await render();
    return result;
  } catch (err) {
    setSocOut(err.message, true);
    if (refresh) await render();
    return null;
  }
}

async function viewSoc() {
  if (!['soc', 'owner'].includes(el('role').value)) {
    return '<div class="empty">Switch role to SOC or Owner to use the SOC console.</div>';
  }
  const data = await api('/v1/high-scale-requests');
  const rows = await Promise.all(
    data.items.map(async (r) => {
      try {
        const arts = await api(`/v1/high-scale-requests/${r.id}/artifacts`);
        const pending = arts.items.filter((a) => a.status === 'pending_review').length;
        return { ...r, artifactCount: arts.items.length, pendingArtifacts: pending };
      } catch {
        return { ...r, artifactCount: 0, pendingArtifacts: 0 };
      }
    }),
  );
  const queueRows = rows.length
    ? rows.map((r) => `<tr>
        <td><code>${r.id}</code></td>
        <td>${socStateChip(r.state)}</td>
        <td>${r.target_group_id || '—'}</td>
        <td>${r.reason || '—'}</td>
        <td>${r.artifactCount}${r.pendingArtifacts ? ` <span class="muted">(${r.pendingArtifacts} pending)</span>` : ''}</td>
      </tr>
      <tr class="soc-actions-row"><td colspan="5">
        <div class="soc-action-grid">
          <button class="btn secondary" data-action="soc-review-pack" data-id="${r.id}">Review pack</button>
          <button class="btn secondary" data-action="soc-approve" data-id="${r.id}">Approve</button>
          <button class="btn secondary" data-action="soc-schedule" data-id="${r.id}">Schedule</button>
          <button class="btn secondary" data-action="soc-start" data-id="${r.id}">Start (dry-run)</button>
          <button class="btn secondary" data-action="soc-stop" data-id="${r.id}">Stop</button>
          <button class="btn secondary" data-action="soc-adapter" data-id="${r.id}">Adapter</button>
          <button class="btn secondary" data-action="soc-note" data-id="${r.id}">SOC note</button>
          <button class="btn secondary" data-action="soc-post-report" data-id="${r.id}">Post-test report</button>
          <button class="btn secondary" data-action="soc-close" data-id="${r.id}">Close</button>
        </div>
      </td></tr>`).join('')
    : '<tr><td colspan="5"><div class="empty">No requests in queue.</div></td></tr>';
  return `
    <div class="card">
      <h3>SOC Console</h3>
      <p class="muted">Developer validation workflow. Actions call SOC-only <code>/internal/soc/*</code> routes; backend RBAC and gates remain authoritative. Start invokes the governed dry-run adapter only — not customer traffic or production fleet execution.</p>
    </div>
    <div class="card soc-band">
      <h4>Execution · kill switch</h4>
      <p class="muted">Tenant-scoped emergency stop. Auto-stops running high-scale requests when activated.</p>
      <div class="soc-action-grid">
        <button class="btn secondary" data-action="soc-kill-on">Activate kill switch</button>
        <button class="btn secondary" data-action="soc-kill-off">Clear kill switch</button>
      </div>
    </div>
    <div class="card soc-band">
      <h4>Lifecycle swimlane</h4>
      <p class="muted">High-scale requests move through SOC-gated states only; customer UI cannot start governed execution.</p>
      ${renderSocSwimlane({ items: rows })}
    </div>
    <div class="card soc-band">
      <h4>Queue · authorization · schedule · closure</h4>
      <table class="soc-queue-table"><thead><tr>
        <th>Request</th><th>State</th><th>Target group</th><th>Reason</th><th>Artifacts</th>
      </tr></thead><tbody>${queueRows}</tbody></table>
      <p class="muted">Close requires request <code>stopped</code> and a stored post-test report (<code>post_test_report_required</code> if missing).</p>
    </div>
    <div class="card soc-band">
      <h4>Action output</h4>
      <pre id="socOut" class="soc-out muted"></pre>
    </div>`;
}

async function viewReports() {
  const hasReport = Boolean(lastReportId);
  return `<div class="card">
    ${renderReportBuilder(lastReportKind, lastReportFormat, hasReport)}
    <div id="reportOut">${hasReport ? '' : '<div class="empty">No report generated yet. Select a report type and generate to enable export.</div>'}
    </div></div>
    ${renderExportInspectionPanel({
    panelId: 'reportCustodyPreview',
    heading: 'Report export inspection',
    emptyMessage: 'Export a report to inspect manifest metadata without rendering the raw JSON payload.',
    preview: lastReportCustodyPreview,
  })}`;
}

async function viewAudit() {
  const data = await api('/v1/audit-log');
  return `<div class="card"><table><thead><tr><th>Time</th><th>Action</th><th>Resource</th></tr></thead><tbody>
    ${data.items.slice().reverse().map((a) => `<tr><td>${a.timestamp}</td><td>${a.action}</td><td>${a.resource_type || ''} ${a.resource_id || ''}</td></tr>`).join('')}
  </tbody></table></div>`;
}

async function fetchReleaseEvidencePanelData() {
  const res = await fetch('/v1/production-release-evidence', { headers: headers() });
  const data = await res.json().catch(() => ({}));
  if (res.status === 403) {
    return { items: [], permissionDenied: true, loadError: null };
  }
  if (!res.ok) {
    return {
      items: [],
      permissionDenied: false,
      loadError: data.error || data.message || res.statusText,
    };
  }
  return { items: data.items || [], permissionDenied: false, loadError: null };
}

async function fetchReleaseEvidenceAttestationData() {
  const res = await fetch('/v1/production-release-evidence/attestation', { headers: headers() });
  const data = await res.json().catch(() => ({}));
  if (res.status === 403) {
    return { attestation: null, permissionDenied: true, loadError: null };
  }
  if (!res.ok) {
    return {
      attestation: null,
      permissionDenied: false,
      loadError: data.error || data.message || res.statusText,
    };
  }
  const attestation = data.attestation && typeof data.attestation === 'object'
    ? data.attestation
    : data;
  return { attestation, permissionDenied: false, loadError: null };
}

async function viewReleaseEvidence() {
  const [evidence, attestation] = await Promise.all([
    fetchReleaseEvidencePanelData(),
    fetchReleaseEvidenceAttestationData(),
  ]);
  return `<div class="card">
    ${renderStagingReadinessAttestationPanel(attestation.attestation, {
    permissionDenied: attestation.permissionDenied,
    loadError: attestation.loadError,
  })}
    ${renderReleaseEvidencePanel({
    items: evidence.items,
    permissionDenied: evidence.permissionDenied,
    loadError: evidence.loadError,
  })}
  </div>`;
}

async function viewSettings() {
  const [tokens, tenant, stateSnapshot, releaseEvidence] = await Promise.all([
    api('/v1/bootstrap-tokens'),
    api('/v1/tenants/current'),
    api('/v1/state'),
    fetchReleaseEvidencePanelData(),
  ]);
  const supportPreview = buildSupportReadinessPreview({
    kill_switch: stateSnapshot.kill_switch,
    release_evidence_items: releaseEvidence.items,
  });
  return `
    <div class="card"><h3>Tenant</h3><p>${tenant.name} · ${tenant.id}</p>
      <p class="muted">Privacy: metadata-only by default · retention ${tenant.privacy_settings?.metadata_retention_days ?? 90}d</p></div>
    ${renderSupportReadinessPanel(supportPreview)}
    ${renderReleaseEvidencePanel({
    items: releaseEvidence.items,
    permissionDenied: releaseEvidence.permissionDenied,
    loadError: releaseEvidence.loadError,
    compact: true,
  })}
    <p class="muted"><button type="button" class="btn secondary" data-action="goto-release-evidence">Open full release evidence view</button></p>
    <div class="card">
      <h3>API keys (bootstrap tokens)</h3>
      <button class="btn" data-action="create-token">Create bootstrap token</button>
      ${lastTokenSecret ? `<div class="secret-box">Shown once: ${lastTokenSecret}</div>` : '<p class="muted">Token secret is shown once at creation only.</p>'}
      <table><thead><tr><th>Name</th><th>Uses</th><th>Expires</th></tr></thead><tbody>
        ${tokens.items.map((t) => `<tr><td>${t.name}</td><td>${t.registrations_used}/${t.max_registrations}</td><td>${t.expires_at}</td></tr>`).join('')}
      </tbody></table>
    </div>`;
}

async function copyTextToClipboard(text, statusElId, successMsg = 'Copied') {
  try {
    await navigator.clipboard.writeText(text);
    const status = document.getElementById(statusElId);
    if (status) {
      status.textContent = successMsg;
      setTimeout(() => { status.textContent = ''; }, 2500);
    }
    return true;
  } catch {
    return false;
  }
}

function bindHandlers() {
  document.querySelectorAll('[data-install-tab]').forEach((tab) => {
    tab.onclick = () => {
      activeInstallTab = tab.dataset.installTab;
      render();
    };
  });
  document.querySelectorAll('[data-action="copy-install"]').forEach((b) => {
    b.onclick = async () => {
      const pre = document.getElementById(b.dataset.copyTarget || 'installCommandPre');
      if (!pre) return;
      await copyTextToClipboard(pre.textContent, 'installCopyStatus', 'Command copied');
    };
  });
  document.querySelectorAll('#reportKindSelect').forEach((sel) => {
    sel.onchange = () => { lastReportKind = sel.value; };
  });
  document.querySelectorAll('input[name="reportFormat"]').forEach((input) => {
    input.onchange = () => { if (input.checked) lastReportFormat = input.value; };
  });
  document.querySelectorAll('[data-action="copy-evidence-ids"]').forEach((b) => {
    b.onclick = async () => {
      const src = document.getElementById('evidenceIdList');
      if (!src?.value) return;
      await copyTextToClipboard(src.value, 'evidenceCopyStatus', 'Evidence IDs copied');
    };
  });
  document.querySelectorAll('[data-action="export-evidence-chain"]').forEach((b) => {
    b.onclick = async () => {
      const src = document.getElementById('evidenceChainExport');
      if (!src?.value) return;
      try {
        lastEvidenceCustodyPreview = await buildEvidenceCustodyPreview(lastEvidenceExport);
        replacePanel('evidenceCustodyPreview', renderExportInspectionPanel({
          panelId: 'evidenceCustodyPreview',
          heading: 'Evidence export inspection',
          emptyMessage: 'Export the evidence-chain JSON to inspect digest metadata for this bundle.',
          summaryRows: summarizeEvidenceExport(lastEvidenceExport),
          preview: lastEvidenceCustodyPreview,
        }));
      } catch {
        replacePanel('evidenceCustodyPreview', renderExportInspectionPanel({
          panelId: 'evidenceCustodyPreview',
          heading: 'Evidence export inspection',
          emptyMessage: 'Export the evidence-chain JSON to inspect digest metadata for this bundle.',
          summaryRows: summarizeEvidenceExport(lastEvidenceExport),
          errorMessage: 'Unable to compute a browser-side digest preview for this export.',
        }));
      }
      const copied = await copyTextToClipboard(src.value, 'evidenceCopyStatus', 'Evidence chain JSON copied');
      if (!copied) {
        const status = document.getElementById('evidenceCopyStatus');
        if (status) status.textContent = 'Copy blocked — use browser permissions or select from preview.';
      }
    };
  });
  document.querySelectorAll('[data-action="copy-evidence-id"]').forEach((b) => {
    b.onclick = async () => {
      await copyTextToClipboard(b.dataset.id, 'evidenceCopyStatus', `Copied ${b.dataset.id}`);
    };
  });
  document.querySelectorAll('[data-action="onboard-create-env"]').forEach((b) => {
    b.onclick = async () => {
      await api('/v1/environments', { method: 'POST', body: JSON.stringify({ name: `Validation ${Date.now()}` }) });
      render();
    };
  });
  document.querySelectorAll('[data-action="onboard-create-tg"]').forEach((b) => {
    b.onclick = async () => {
      await api('/v1/target-groups', { method: 'POST', body: JSON.stringify({ name: `Service ${Date.now()}` }) });
      render();
    };
  });
  document.querySelectorAll('[data-action="onboard-add-target"]').forEach((b) => {
    b.onclick = async () => {
      const value = document.getElementById('onboardTargetValue')?.value?.trim();
      if (!value) return;
      const tgs = await api('/v1/target-groups');
      const tg = tgs.items[0];
      if (!tg) return;
      await api(`/v1/target-groups/${tg.id}/targets`, {
        method: 'POST',
        body: JSON.stringify({ kind: 'fqdn', value }),
      });
      render();
    };
  });
  document.querySelectorAll('[data-action="onboard-create-token"]').forEach((b) => {
    b.onclick = async () => {
      const tgs = await api('/v1/target-groups');
      const tg = tgs.items[0];
      if (!tg) return;
      const tok = await api('/v1/bootstrap-tokens', {
        method: 'POST',
        body: JSON.stringify({ name: 'Onboarding token', target_group_id: tg.id, max_registrations: 1 }),
      });
      lastTokenSecret = tok.secret;
      render();
    };
  });
  document.querySelectorAll('[data-action="onboard-start-run"]').forEach((b) => {
    b.onclick = async () => {
      const tgs = await api('/v1/target-groups');
      const tg = tgs.items[0];
      if (!tg) return;
      const detail = await api(`/v1/target-groups/${tg.id}`);
      const target = detail.targets[0];
      if (!target) return;
      await api('/v1/test-runs', {
        method: 'POST',
        body: JSON.stringify({
          check_id: 'origin.direct_bypass.safe',
          target_group_id: tg.id,
          target_id: target.id,
        }),
      });
      route = 'runs';
      render();
    };
  });
  document.querySelectorAll('[data-action="goto-runs"]').forEach((b) => {
    b.onclick = () => { route = 'runs'; render(); };
  });
  document.querySelectorAll('[data-action="goto-evidence"]').forEach((b) => {
    b.onclick = () => { route = 'evidence'; render(); };
  });
  document.querySelectorAll('[data-action="goto-findings"]').forEach((b) => {
    b.onclick = () => { route = 'findings'; render(); };
  });
  document.querySelectorAll('[data-action="create-env"]').forEach((b) => {
    b.onclick = async () => {
      await api('/v1/environments', { method: 'POST', body: JSON.stringify({ name: `Env ${Date.now()}` }) });
      render();
    };
  });
  document.querySelectorAll('[data-action="create-notify-rule"]').forEach((b) => {
    b.onclick = async () => {
      await api('/v1/notifications', {
        method: 'POST',
        body: JSON.stringify({ channel: 'webhook', destination: 'metadata-only' }),
      });
      render();
    };
  });
  document.querySelectorAll('[data-action="hs-artifact-type"]').forEach((b) => {
    b.onclick = async () => {
      const type = b.dataset.type;
      const requestId = b.dataset.id;
      const body = buildHsArtifactUploadBody(type, requestId, b.dataset.provider || '');
      await api(`/v1/high-scale-requests/${requestId}/artifacts`, {
        method: 'POST',
        body: JSON.stringify(body),
      });
      render();
    };
  });
  document.querySelectorAll('[data-action="soc-adapter"]').forEach((b) => {
    b.onclick = () => runSocAction(
      () => api(`/internal/soc/high-scale/${b.dataset.id}/adapter-status`),
      false,
    );
  });
  document.querySelectorAll('[data-action="soc-review-pack"]').forEach((b) => {
    b.onclick = () => runSocAction(async () => {
      const id = b.dataset.id;
      const arts = await api(`/v1/high-scale-requests/${id}/artifacts`);
      const pending = arts.items.filter((a) => a.status === 'pending_review');
      const reviewed = [];
      for (const art of pending) {
        const res = await api(`/internal/soc/high-scale/${id}/artifacts/${art.id}/review`, {
          method: 'POST',
          body: JSON.stringify({ status: 'accepted' }),
        });
        reviewed.push(res);
      }
      return { action: 'soc-review-pack', accepted: reviewed.length, pending_before: pending.length, artifacts: arts.items };
    });
  });
  document.querySelectorAll('[data-action="soc-approve"]').forEach((b) => {
    b.onclick = () => runSocAction(
      () => api(`/internal/soc/high-scale/${b.dataset.id}/approve`, { method: 'POST', body: '{}' }),
    );
  });
  document.querySelectorAll('[data-action="soc-schedule"]').forEach((b) => {
    b.onclick = () => runSocAction(
      () => api(`/internal/soc/high-scale/${b.dataset.id}/schedule`, {
        method: 'POST',
        body: JSON.stringify(socDevScheduleWindow()),
      }),
    );
  });
  document.querySelectorAll('[data-action="soc-start"]').forEach((b) => {
    b.onclick = () => runSocAction(
      () => api(`/internal/soc/high-scale/${b.dataset.id}/start`, { method: 'POST', body: '{}' }),
    );
  });
  document.querySelectorAll('[data-action="soc-stop"]').forEach((b) => {
    b.onclick = () => runSocAction(
      () => api(`/internal/soc/high-scale/${b.dataset.id}/stop`, { method: 'POST', body: '{}' }),
    );
  });
  document.querySelectorAll('[data-action="soc-post-report"]').forEach((b) => {
    b.onclick = () => runSocAction(
      () => api(`/internal/soc/high-scale/${b.dataset.id}/post-test-report`, {
        method: 'POST',
        body: JSON.stringify({
          impact_summary: 'Developer validation dry-run; adapter reports no traffic generated.',
          recommendations: 'Complete authorization pack and dual SOC approve before production adapter.',
          customer_summary: 'SOC-gated validation exercise; not a production load test.',
          residual_risk: 'low',
          next_steps: 'Stop run if still active, finalize post-test report, then close.',
        }),
      }),
      false,
    );
  });
  document.querySelectorAll('[data-action="soc-close"]').forEach((b) => {
    b.onclick = () => runSocAction(
      () => api(`/internal/soc/high-scale/${b.dataset.id}/close`, { method: 'POST', body: '{}' }),
    );
  });
  document.querySelectorAll('[data-action="soc-note"]').forEach((b) => {
    b.onclick = () => runSocAction(
      () => api(`/internal/soc/high-scale/${b.dataset.id}/notes`, {
        method: 'POST',
        body: JSON.stringify({ body: 'SOC console note (developer validation transcript).' }),
      }),
      false,
    );
  });
  document.querySelectorAll('[data-action="soc-kill-on"]').forEach((b) => {
    b.onclick = () => runSocAction(
      () => api('/internal/soc/kill-switch', {
        method: 'POST',
        body: JSON.stringify({ active: true, reason: 'SOC console kill switch (developer validation)' }),
      }),
    );
  });
  document.querySelectorAll('[data-action="soc-kill-off"]').forEach((b) => {
    b.onclick = () => runSocAction(
      () => api('/internal/soc/kill-switch', {
        method: 'POST',
        body: JSON.stringify({ active: false }),
      }),
    );
  });
  document.querySelectorAll('[data-action="create-tg"]').forEach((b) => {
    b.onclick = async () => {
      await api('/v1/target-groups', { method: 'POST', body: JSON.stringify({ name: `Group ${Date.now()}` }) });
      render();
    };
  });
  document.querySelectorAll('[data-action="create-token"]').forEach((b) => {
    b.onclick = async () => {
      const tgs = await api('/v1/target-groups');
      const tg = tgs.items[0];
      const tok = await api('/v1/bootstrap-tokens', {
        method: 'POST',
        body: JSON.stringify({ name: 'UI token', target_group_id: tg?.id, max_registrations: 1 }),
      });
      lastTokenSecret = tok.secret;
      render();
    };
  });
  document.querySelectorAll('[data-action="view-finding"]').forEach((b) => {
    b.onclick = () => {
      selectedFindingId = b.dataset.id;
      render();
    };
  });
  document.querySelectorAll('[data-action="export-finding"]').forEach((b) => {
    b.onclick = async () => {
      replacePanel('findingCustodyPreview', renderExportInspectionPanel({
        panelId: 'findingCustodyPreview',
        heading: 'Finding export inspection',
        emptyMessage: 'Export a finding to inspect custody metadata without rendering the full export body.',
        errorMessage: 'Exporting finding metadata…',
      }));
      try {
        const exported = await api(`/v1/findings/${b.dataset.id}/export`, { method: 'POST' });
        const { custody, ...payload } = exported;
        lastFindingCustodyPreview = await buildCustodyPreviewFromExport({
          payload,
          custody,
          fallbackType: 'finding_export',
          fallbackFormat: 'json',
          note: 'Finding exports are redacted and metadata-only. This UI preview omits the raw export body by design.',
        });
        replacePanel('findingCustodyPreview', renderExportInspectionPanel({
          panelId: 'findingCustodyPreview',
          heading: 'Finding export inspection',
          emptyMessage: 'Export a finding to inspect custody metadata without rendering the full export body.',
          summaryRows: summarizeFindingExport(exported),
          preview: lastFindingCustodyPreview,
        }));
      } catch (err) {
        replacePanel('findingCustodyPreview', renderExportInspectionPanel({
          panelId: 'findingCustodyPreview',
          heading: 'Finding export inspection',
          emptyMessage: 'Export a finding to inspect custody metadata without rendering the full export body.',
          errorMessage: err.message,
        }));
      }
    };
  });
  document.querySelectorAll('[data-action="start-run"]').forEach((b) => {
    b.onclick = async () => {
      const tgs = await api('/v1/target-groups');
      const tg = tgs.items[0];
      if (!tg) return alert('Create a target group first');
      const detail = await api(`/v1/target-groups/${tg.id}`);
      const target = detail.targets[0];
      await api('/v1/test-runs', {
        method: 'POST',
        body: JSON.stringify({
          check_id: 'origin.direct_bypass.safe',
          target_group_id: tg.id,
          target_id: target?.id,
        }),
      });
      route = 'runs';
      render();
    };
  });
  document.querySelectorAll('[data-action="waf-create-demo-asset"]').forEach((b) => {
    b.onclick = () => runWafAction(() => api('/v1/waf/assets', {
      method: 'POST',
      body: JSON.stringify({
        target_group_id: 'tg_1',
        canonical_url: 'https://waf-app.example.com',
        owner_hint: 'edge-team',
      }),
    }));
  });
  document.querySelectorAll('[data-action="waf-run-validation"]').forEach((b) => {
    b.onclick = () => runWafAction(() => api('/v1/waf/validations', {
      method: 'POST',
      body: JSON.stringify({
        waf_asset_id: b.dataset.id,
        modes: ['marker'],
        probe_profile: { max_requests: 1, timeout_ms: 3000 },
        marker_profile: { marker_type: 'header', expected_action: 'block' },
      }),
    }));
  });
  document.querySelectorAll('[data-action="waf-finalize-pass"]').forEach((b) => {
    b.onclick = () => runWafAction(async () => {
      const assetId = b.dataset.id;
      const vals = await api('/v1/waf/validations');
      const openRun = (vals.items || [])
        .filter((r) => r.waf_asset_id === assetId && r.status !== 'finalized')
        .sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)))[0];
      if (!openRun) throw new Error('No open validation run for this asset.');
      const requestId = `ui_${Date.now().toString(36)}`;
      return api(`/v1/waf/validations/${openRun.id}/finalize`, {
        method: 'POST',
        body: JSON.stringify({
          waf_detected: true,
          validation_passed: true,
          scenario_results: [{
            scenario_family: 'marker',
            passed: true,
            observed_action: 'block',
            evidence_summary: { request_id: requestId, blocked: true },
          }],
        }),
      });
    });
  });
  document.querySelectorAll('[data-action="hs-submit-request"]').forEach((b) => {
    b.onclick = async () => {
      const targetGroupId = el('hsTargetGroup')?.value;
      const objective = el('hsObjective')?.value?.trim();
      const windowStart = el('hsWindowStart')?.value;
      const windowEnd = el('hsWindowEnd')?.value;
      const timezone = el('hsTimezone')?.value?.trim();
      const contactName = el('hsContactName')?.value?.trim();
      const contact = el('hsContact')?.value?.trim();
      const providerName = el('hsProviderName')?.value?.trim();
      const requiresProvider = el('hsProviderApproval')?.checked === true;
      const environment = el('hsEnvironment')?.value;
      const criticality = el('hsCriticality')?.value;
      const scenarioRaw = el('hsScenarioFamilies')?.value?.trim();
      const maxRate = el('hsMaxRate')?.value?.trim();
      const maxDuration = el('hsMaxDuration')?.value;
      const stopCriteriaText = el('hsStopCriteria')?.value?.trim();
      const abortCriteriaText = el('hsAbortCriteria')?.value?.trim();
      const scopeOk = el('hsScopeConfirmation')?.checked === true;
      if (
        !targetGroupId || !objective || !windowStart || !windowEnd || !contactName || !contact
        || !environment || !criticality || !scenarioRaw || !maxRate || !maxDuration
        || !stopCriteriaText || !abortCriteriaText || !scopeOk
      ) {
        setHighScaleOut('Complete required intake fields (environment, criticality, scenarios, safe limits, stop/abort criteria) and confirm scope.', true);
        return;
      }
      if (!providerName && !requiresProvider) {
        setHighScaleOut('Provide a provider name or mark provider approval required.', true);
        return;
      }
      const requested_scenario_families = scenarioRaw.split(',').map((s) => s.trim()).filter(Boolean);
      if (!requested_scenario_families.length) {
        setHighScaleOut('Provide at least one requested scenario family (metadata).', true);
        return;
      }
      const provider_context = { requires_provider_approval: requiresProvider };
      if (providerName) provider_context.provider_name = providerName;
      const payload = {
        target_group_id: targetGroupId,
        objective,
        environment,
        business_criticality: criticality,
        requested_scenario_families,
        requested_limits: {
          max_rate: maxRate,
          max_duration_minutes: Number(maxDuration),
        },
        stop_criteria: { description: stopCriteriaText },
        abort_criteria: { description: abortCriteriaText },
        requested_window: {
          start: new Date(windowStart).toISOString(),
          end: new Date(windowEnd).toISOString(),
          timezone: timezone || undefined,
        },
        emergency_contacts: [{ name: contactName, contact }],
        provider_context,
        scope_confirmation: true,
      };
      try {
        const created = await api('/v1/high-scale-requests', {
          method: 'POST',
          body: JSON.stringify(payload),
        });
        setHighScaleOut(
          `Submitted ${created.id} (${created.state}). Attach authorization pack metadata for SOC review.`,
          false,
        );
        render();
      } catch (err) {
        setHighScaleOut(err.message, true);
      }
    };
  });
  document.querySelectorAll('[data-action="gen-report"]').forEach((b) => {
    b.onclick = async () => {
      const kind = document.getElementById('reportKindSelect')?.value || lastReportKind;
      lastReportKind = kind;
      const r = await api('/v1/reports', { method: 'POST', body: JSON.stringify({ kind }) });
      lastReportId = r.id;
      lastReportSummary = r.summary;
      lastReportCustodyPreview = null;
      ['exportSelectedBtn', 'copyReportBtn'].forEach((id) => {
        const btn = document.getElementById(id);
        if (btn) btn.disabled = false;
      });
      document.getElementById('reportOut').innerHTML = `<pre>${JSON.stringify(r.summary, null, 2)}</pre>`;
      replacePanel('reportCustodyPreview', renderExportInspectionPanel({
        panelId: 'reportCustodyPreview',
        heading: 'Report export inspection',
        emptyMessage: 'Export a report to inspect manifest metadata without rendering the raw JSON payload.',
        summaryRows: [
          ['Report ID', `<code>${vizEsc(r.id)}</code>`],
          ['Kind', vizEsc(kind)],
        ],
      }));
    };
  });
  document.querySelectorAll('[data-action="export-report-selected"]').forEach((b) => {
    b.onclick = async () => {
      if (!lastReportId) return;
      const format = document.querySelector('input[name="reportFormat"]:checked')?.value || lastReportFormat;
      lastReportFormat = format;
      replacePanel('reportCustodyPreview', renderExportInspectionPanel({
        panelId: 'reportCustodyPreview',
        heading: 'Report export inspection',
        emptyMessage: 'Export a report to inspect manifest metadata without rendering the raw JSON payload.',
        errorMessage: 'Exporting report metadata…',
      }));
      try {
        let content = '';
        if (format === 'json') {
          const exported = await api(`/v1/reports/${lastReportId}/export?format=json`);
          lastReportCustodyPreview = await buildCustodyPreviewFromExport({
            payload: exported.payload,
            custody: exported.custody,
            fallbackType: 'report_export',
            fallbackFormat: 'json',
            note: 'Report JSON exports are redacted and metadata-only. The preview intentionally shows manifest fields instead of the raw payload.',
          });
          document.getElementById('reportOut').innerHTML = renderReportContentPreview('json', '');
          replacePanel('reportCustodyPreview', renderExportInspectionPanel({
            panelId: 'reportCustodyPreview',
            heading: 'Report export inspection',
            emptyMessage: 'Export a report to inspect manifest metadata without rendering the raw JSON payload.',
            summaryRows: summarizeReportExport(exported.payload, format),
            preview: lastReportCustodyPreview,
          }));
          return;
        }

        const res = await fetch(`/v1/reports/${lastReportId}/export?format=${format}`, { headers: headers() });
        if (!res.ok) {
          const failure = await res.json().catch(() => ({}));
          throw new Error(failure.error || failure.message || res.statusText);
        }
        content = await res.text();
        const exported = await api(`/v1/reports/${lastReportId}/export?format=json`);
        lastReportCustodyPreview = await buildCustodyPreviewFromExport({
          payload: exported.payload,
          custody: exported.custody,
          fallbackType: 'report_export',
          fallbackFormat: format,
          note: 'Custody metadata is derived from the canonical JSON export while the selected rendered format remains redacted and self-contained.',
        });
        document.getElementById('reportOut').innerHTML = renderReportContentPreview(format, content);
        replacePanel('reportCustodyPreview', renderExportInspectionPanel({
          panelId: 'reportCustodyPreview',
          heading: 'Report export inspection',
          emptyMessage: 'Export a report to inspect manifest metadata without rendering the raw JSON payload.',
          summaryRows: summarizeReportExport(exported.payload, format),
          preview: lastReportCustodyPreview,
        }));
      } catch (err) {
        replacePanel('reportCustodyPreview', renderExportInspectionPanel({
          panelId: 'reportCustodyPreview',
          heading: 'Report export inspection',
          emptyMessage: 'Export a report to inspect manifest metadata without rendering the raw JSON payload.',
          errorMessage: err.message,
        }));
        document.getElementById('reportOut').innerHTML = `<div class="empty">${vizEsc(err.message)}</div>`;
      }
    };
  });
  document.querySelectorAll('[data-action="copy-report-summary"]').forEach((b) => {
    b.onclick = async () => {
      if (!lastReportSummary) return;
      const text = JSON.stringify(lastReportSummary, null, 2);
      const out = document.getElementById('reportOut');
      if (out) {
        const note = document.createElement('p');
        note.className = 'muted';
        note.textContent = 'Summary JSON copied to clipboard.';
        out.prepend(note);
        setTimeout(() => note.remove(), 2500);
      }
      await navigator.clipboard.writeText(text);
    };
  });

  document.querySelectorAll('[data-action="goto-settings"]').forEach((b) => {
    b.onclick = () => { route = 'settings'; render(); };
  });
  document.querySelectorAll('[data-action="goto-release-evidence"]').forEach((b) => {
    b.onclick = () => {
      route = 'release-evidence';
      location.hash = route;
      render();
    };
  });

  document.querySelectorAll('[data-action="cve-ingest-toggle"]').forEach((b) => {
    b.onclick = () => {
      showCveIngestForm = !showCveIngestForm;
      render();
    };
  });
  document.querySelectorAll('[data-action="cve-ingest-cancel"]').forEach((b) => {
    b.onclick = () => {
      showCveIngestForm = false;
      render();
    };
  });
  document.querySelectorAll('[data-action="cve-ingest-submit"]').forEach((b) => {
    b.onclick = async () => {
      const cveId = el('cveIngestId')?.value?.trim();
      const severity = el('cveIngestSeverity')?.value?.trim();
      const productsRaw = el('cveIngestProducts')?.value?.trim();
      const affected_products = productsRaw
        ? productsRaw.split(',').map((s) => s.trim()).filter(Boolean)
        : [];
      if (!cveId || !severity || !affected_products.length) return;
      await api('/v1/waf/cve-pipeline', {
        method: 'POST',
        body: JSON.stringify({ cve_id: cveId, severity, affected_products }),
      });
      showCveIngestForm = false;
      render();
    };
  });
  document.querySelectorAll('[data-action="cve-view"]').forEach((b) => {
    b.onclick = async () => {
      selectedCveId = b.dataset.id;
      lastCveDetail = null;
      try {
        const listPayload = await api('/v1/waf/cve-pipeline');
        const item = (listPayload.items ?? []).find((i) => i.id === selectedCveId);
        if (item) {
          if (!item.triage_result) {
            const triaged = await api(`/v1/waf/cve-pipeline/${selectedCveId}/triage`, {
              method: 'POST',
              body: '{}',
            });
            Object.assign(item, triaged.item ?? item);
          }
          const matched = await api(`/v1/waf/cve-pipeline/${selectedCveId}/match`, {
            method: 'POST',
            body: '{}',
          });
          lastCveDetail = {
            item,
            matches: matched.matches ?? [],
            recommendations: [],
          };
        }
      } catch {
        lastCveDetail = null;
      }
      render();
    };
  });

  document.querySelectorAll('[data-discovery-tab]').forEach((tab) => {
    tab.onclick = () => {
      activeDiscoveryTab = tab.dataset.discoveryTab;
      render();
    };
  });
  document.querySelectorAll('#discoveryModeSelect').forEach((sel) => {
    sel.onchange = () => {
      discoveryMode = sel.value;
      const mode = DISCOVERY_MODES.find((m) => m.id === discoveryMode);
      const hint = document.getElementById('discoveryModeHint');
      if (hint && mode) hint.textContent = mode.description;
      sel.title = mode?.description ?? '';
    };
  });
  document.querySelectorAll('[data-action="discovery-approve"]').forEach((b) => {
    b.onclick = async () => {
      await api(`/v1/discovery/candidates/${b.dataset.id}/approve`, {
        method: 'POST',
        body: JSON.stringify({}),
      });
      render();
    };
  });
  document.querySelectorAll('[data-action="discovery-reject"]').forEach((b) => {
    b.onclick = async () => {
      await api(`/v1/discovery/candidates/${b.dataset.id}/reject`, {
        method: 'POST',
        body: JSON.stringify({ reason: 'out_of_scope' }),
      });
      render();
    };
  });

  document.querySelectorAll('[data-action="supply-view"]').forEach((b) => {
    b.onclick = () => {
      selectedSupplyChainRiskId = b.dataset.id;
      render();
    };
  });
  document.querySelectorAll('[data-action="supply-assess-cname-toggle"]').forEach((b) => {
    b.onclick = () => {
      showSupplyCnameForm = !showSupplyCnameForm;
      render();
    };
  });
  document.querySelectorAll('[data-action="supply-assess-dep-toggle"]').forEach((b) => {
    b.onclick = () => {
      showSupplyDependencyForm = !showSupplyDependencyForm;
      render();
    };
  });
  document.querySelectorAll('[data-action="supply-assess-cname-cancel"]').forEach((b) => {
    b.onclick = () => {
      showSupplyCnameForm = false;
      render();
    };
  });
  document.querySelectorAll('[data-action="supply-assess-dep-cancel"]').forEach((b) => {
    b.onclick = () => {
      showSupplyDependencyForm = false;
      render();
    };
  });
  document.querySelectorAll('[data-action="supply-assess-cname-submit"]').forEach((b) => {
    b.onclick = async () => {
      const hostname = el('supplyCnameHost')?.value?.trim();
      if (!hostname) return;
      const body = { hostname };
      const hash = el('supplyCnameHash')?.value?.trim();
      const sig = el('supplyCnameSig')?.value?.trim();
      if (hash) body.cname_chain_hash = hash;
      if (sig) body.provider_error_signature_id = sig;
      if (el('supplyCnameConnector')?.checked) body.connector_confirmation = true;
      await api('/v1/waf/supply-chain/assess/dangling-cname', {
        method: 'POST',
        body: JSON.stringify(body),
      });
      showSupplyCnameForm = false;
      render();
    };
  });
  document.querySelectorAll('[data-action="supply-assess-dep-submit"]').forEach((b) => {
    b.onclick = async () => {
      const hostname = el('supplyDepHost')?.value?.trim();
      if (!hostname) return;
      const body = { hostname };
      const scriptHost = el('supplyDepScript')?.value?.trim();
      const depHash = el('supplyDepHash')?.value?.trim();
      const status = el('supplyDepStatus')?.value;
      if (scriptHost) body.script_host = scriptHost;
      if (depHash) body.dependency_url_hash = depHash;
      if (status) body.status_code = Number(status);
      await api('/v1/waf/supply-chain/assess/dangling-dependency', {
        method: 'POST',
        body: JSON.stringify(body),
      });
      showSupplyDependencyForm = false;
      render();
    };
  });

  document.querySelectorAll('[data-action="remediation-view"]').forEach((b) => {
    b.onclick = () => {
      selectedActionItemId = b.dataset.id;
      render();
    };
  });
  document.querySelectorAll('[data-action="remediation-group-toggle"]').forEach((input) => {
    input.onchange = () => {
      remediationGroupedView = input.checked === true;
      render();
    };
  });
  document.querySelectorAll('[data-action="remediation-status"]').forEach((sel) => {
    sel.onchange = async () => {
      const id = sel.dataset.id;
      const status = sel.value;
      if (!id || !status) return;
      await api(`/v1/waf/action-items/${id}`, {
        method: 'PATCH',
        body: JSON.stringify({ status }),
      });
      render();
    };
  });
}

window.addEventListener('hashchange', () => {
  route = location.hash.replace('#', '') || 'dashboard';
  render();
});

el('tenantId').onchange = () => render();
el('role').onchange = () => render();
route = location.hash.replace('#', '') || 'dashboard';
loadEnvBadge().catch(() => {});
render();
