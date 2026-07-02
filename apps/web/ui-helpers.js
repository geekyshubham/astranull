/** Pure UI helpers — importable from app.js and unit tests. */

export const INSTALL_TABS = Object.freeze([
  { id: 'linux', label: 'Linux' },
  { id: 'docker', label: 'Docker' },
  { id: 'helm', label: 'Kubernetes / Helm' },
]);

export const UI_REPORT_KINDS = Object.freeze([
  { id: 'executive', label: 'Executive Readiness Report', audience: 'CISO / leadership' },
  { id: 'technical', label: 'Technical Evidence Report', audience: 'Engineers / security' },
  { id: 'audit', label: 'Audit Evidence Pack', audience: 'Auditors / compliance' },
  { id: 'soc', label: 'SOC High-Scale Report', audience: 'SOC operators' },
]);

export const REPORT_EXPORT_FORMATS = Object.freeze([
  { id: 'json', label: 'JSON' },
  { id: 'markdown', label: 'Markdown' },
  { id: 'html', label: 'HTML' },
]);

export const ONBOARDING_STEPS = Object.freeze([
  { id: 'environment', label: 'Environment', hint: 'Create a validation environment (prod, staging, or lab).' },
  { id: 'target_group', label: 'Target group', hint: 'Declare customer-owned business service scope.' },
  { id: 'target', label: 'Declared target', hint: 'Add at least one FQDN, URL, or IP — no automatic discovery.' },
  { id: 'token', label: 'Bootstrap token', hint: 'One-time token for outbound agent registration.' },
  { id: 'install', label: 'Install agent', hint: 'Optional but recommended for inside-path observation evidence.' },
  { id: 'safe_run', label: 'First safe run', hint: 'Start a bounded metadata-only validation against declared targets.' },
  { id: 'review', label: 'Review result', hint: 'Inspect verdict, evidence chain, and findings.' },
]);

function esc(text) {
  return String(text ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;');
}

/**
 * @param {{ apiBase?: string, token?: string, targetGroupName?: string }} opts
 */
export function buildInstallCommands(opts = {}) {
  const token = opts.token || '<BOOTSTRAP_TOKEN>';
  const apiBase = opts.apiBase || 'http://localhost:3000';
  const tg = opts.targetGroupName || 'Your Target Group';
  return {
    linux: [
      'sudo bash agents/linux/install.sh \\',
      `  --token ${token} \\`,
      `  --api ${apiBase} \\`,
      '  --sha256 <ARTIFACT_SHA256>',
    ].join('\n'),
    docker: [
      'docker run -d --name astranull-agent \\',
      '  --restart unless-stopped \\',
      `  -e ASTRANULL_API_BASE=${apiBase} \\`,
      `  -e ASTRANULL_BOOTSTRAP_TOKEN=${token} \\`,
      '  astranull/agent:dev',
    ].join('\n'),
    helm: [
      'helm upgrade --install astranull-agent agents/linux/helm \\',
      '  --namespace astranull --create-namespace \\',
      `  --set bootstrapToken=${token} \\`,
      `  --set apiBase=${apiBase} \\`,
      `  --set targetGroup="${tg}"`,
    ].join('\n'),
  };
}

/**
 * @param {Record<string, string>} commands
 * @param {string} activeTab
 */
export function renderInstallCommandsPanel(commands, activeTab = 'linux') {
  const tabs = INSTALL_TABS.map((t) => {
    const active = t.id === activeTab ? ' active' : '';
    return `<button type="button" class="tab install-tab${active}" data-install-tab="${t.id}">${esc(t.label)}</button>`;
  }).join('');
  const cmd = commands[activeTab] || commands.linux || '';
  return `<div class="install-panel" data-active-install-tab="${esc(activeTab)}">
    <div class="tabs install-tabs" role="tablist">${tabs}</div>
    <div class="install-command-row">
      <pre class="secret-box install-command" id="installCommandPre">${esc(cmd)}</pre>
      <button type="button" class="btn secondary copy-btn" data-action="copy-install" data-copy-target="installCommandPre">Copy command</button>
    </div>
    <p class="muted install-copy-status" id="installCopyStatus" aria-live="polite"></p>
  </div>`;
}

/**
 * @param {{ evidence?: object[], runs?: object[], verdicts?: object[], findings?: object[] }} input
 */
export function buildEvidenceChainExport(input = {}) {
  const evidence = input.evidence || [];
  const runs = input.runs || [];
  const verdicts = input.verdicts || [];
  const findings = input.findings || [];
  const runById = Object.fromEntries(runs.map((r) => [r.id, r]));
  const chain = evidence.map((e) => {
    const run = e.test_run_id ? runById[e.test_run_id] : null;
    const verdict = verdicts.find((v) => v.test_run_id === e.test_run_id)
      || verdicts.find((v) => (v.evidence_ids || []).includes(e.id));
    const linkedFindings = findings.filter((f) => (f.evidence_ids || []).includes(e.id));
    return {
      evidence_id: e.id,
      label: e.label,
      test_run_id: e.test_run_id ?? null,
      run_status: run?.status ?? null,
      verdict: verdict?.verdict ?? null,
      verdict_confidence: verdict?.confidence ?? null,
      finding_ids: linkedFindings.map((f) => f.id),
      created_at: e.created_at ?? null,
    };
  });
  const orphanVerdictLinks = [];
  for (const v of verdicts) {
    for (const eid of v.evidence_ids || []) {
      if (!evidence.some((e) => e.id === eid)) {
        orphanVerdictLinks.push({
          evidence_id: eid,
          test_run_id: v.test_run_id,
          verdict: v.verdict,
          source: 'verdict_reference',
        });
      }
    }
  }
  const payload = {
    exported_at: new Date().toISOString(),
    evidence_ids: evidence.map((e) => e.id),
    chain,
    orphan_references: orphanVerdictLinks,
  };
  return {
    payload,
    json: JSON.stringify(payload, null, 2),
    idList: payload.evidence_ids.join('\n'),
  };
}

/**
 * @param {object[]} items
 * @param {{ json: string, idList: string, payload: object }} exportData
 */
export function renderEvidenceChainPanel(items, exportData) {
  const hasItems = items.length > 0;
  const rows = hasItems
    ? items.map((e) => `<tr>
        <td><code>${esc(e.id)}</code></td>
        <td>${esc(e.label)}</td>
        <td>${esc(e.test_run_id || '—')}</td>
        <td><button type="button" class="btn secondary" data-action="copy-evidence-id" data-id="${esc(e.id)}">Copy ID</button></td>
      </tr>`).join('')
    : '<tr><td colspan="4"><div class="empty">No evidence yet. Complete a safe validation to populate the vault.</div></td></tr>';
  const chainPreview = hasItems
    ? `<ol class="evidence-chain-list">${exportData.payload.chain.map((c) =>
      `<li><code>${esc(c.evidence_id)}</code> → run ${esc(c.test_run_id || '—')} · verdict ${esc(c.verdict || 'pending')}</li>`,
    ).join('')}</ol>`
    : '';
  return `<div class="card evidence-chain-panel">
    <div class="evidence-chain-actions">
      <button type="button" class="btn secondary" data-action="copy-evidence-ids" ${hasItems ? '' : 'disabled'}>Copy all IDs</button>
      <button type="button" class="btn secondary" data-action="export-evidence-chain" ${hasItems ? '' : 'disabled'}>Export chain JSON</button>
      <span class="muted evidence-copy-status" id="evidenceCopyStatus" aria-live="polite"></span>
    </div>
    <textarea id="evidenceChainExport" class="evidence-export-src" hidden readonly>${esc(exportData.json)}</textarea>
    <textarea id="evidenceIdList" class="evidence-export-src" hidden readonly>${esc(exportData.idList)}</textarea>
    <h4>Evidence chain</h4>
    ${chainPreview}
    <table><thead><tr><th>ID</th><th>Label</th><th>Run</th><th></th></tr></thead><tbody>${rows}</tbody></table>
  </div>`;
}

/**
 * @param {{ environments: object[], targetGroups: object[], targets: object[], agents: object[], runs: object[], hasToken: boolean }} ctx
 */
export function computeOnboardingProgress(ctx) {
  const checks = {
    environment: (ctx.environments || []).length > 0,
    target_group: (ctx.targetGroups || []).length > 0,
    target: (ctx.targets || []).length > 0,
    token: Boolean(ctx.hasToken),
    install: (ctx.agents || []).some((a) => a.status === 'online'),
    safe_run: (ctx.runs || []).some((r) => ['completed', 'verdicted', 'running'].includes(r.status)),
    review: (ctx.runs || []).some((r) => r.status === 'verdicted'),
  };
  const steps = ONBOARDING_STEPS.map((step) => ({
    ...step,
    done: checks[step.id] === true,
    optional: step.id === 'install',
  }));
  const firstOpen = steps.findIndex((s) => !s.done && !s.optional);
  const firstIncomplete = firstOpen === -1
    ? steps.findIndex((s) => !s.done)
    : firstOpen;
  const currentStep = firstIncomplete === -1 ? steps.length - 1 : firstIncomplete;
  const complete = steps.filter((s) => !s.optional).every((s) => s.done);
  return { steps, currentStep, complete, checks };
}

/**
 * @param {ReturnType<typeof computeOnboardingProgress>} progress
 * @param {Record<string, string>} installCommands
 * @param {{ tokenSecret?: string | null, targetValue?: string }} opts
 */
export function renderOnboardingWizard(progress, installCommands, opts = {}) {
  const { steps, currentStep, complete } = progress;
  const pct = Math.round(((currentStep + (complete ? 1 : 0)) / steps.length) * 100);
  const rail = steps.map((s, i) => {
    const cls = s.done ? 'onboarding-step--done' : (i === currentStep ? 'onboarding-step--active' : '');
    const opt = s.optional ? ' <span class="muted">(optional)</span>' : '';
    return `<li class="onboarding-step ${cls}" data-step="${s.id}">
      <span class="onboarding-step-num">${i + 1}</span>
      <span class="onboarding-step-label">${esc(s.label)}${opt}</span>
    </li>`;
  }).join('');
  const active = steps[currentStep] || steps[steps.length - 1];
  const tokenBlock = opts.tokenSecret
    ? `<div class="secret-box">Shown once: ${esc(opts.tokenSecret)}</div>`
    : '<p class="muted">Token secret is shown once at creation.</p>';
  const panels = {
    environment: `<p class="muted">${esc(active.hint)}</p>
      <button type="button" class="btn" data-action="onboard-create-env">Create environment</button>`,
    target_group: `<p class="muted">${esc(active.hint)}</p>
      <button type="button" class="btn" data-action="onboard-create-tg">Create target group</button>`,
    target: `<p class="muted">${esc(active.hint)}</p>
      <label class="onboard-field">FQDN or host <input type="text" id="onboardTargetValue" value="${esc(opts.targetValue || 'origin.example.com')}" placeholder="origin.example.com"></label>
      <button type="button" class="btn" data-action="onboard-add-target">Add declared target</button>`,
    token: `<p class="muted">${esc(active.hint)}</p>
      <button type="button" class="btn" data-action="onboard-create-token">Generate bootstrap token</button>
      ${tokenBlock}`,
    install: `<p class="muted">${esc(active.hint)}</p>
      ${renderInstallCommandsPanel(installCommands, 'linux')}
      <p class="muted">Agent not required for the first safe run in developer validation, but improves placement evidence.</p>`,
    safe_run: `<p class="muted">${esc(active.hint)}</p>
      <button type="button" class="btn" data-action="onboard-start-run">Start first safe validation</button>`,
    review: `<p class="muted">${esc(active.hint)}</p>
      <div class="onboard-review-actions">
        <button type="button" class="btn secondary" data-action="goto-runs">Open test runs</button>
        <button type="button" class="btn secondary" data-action="goto-evidence">Open evidence vault</button>
        <button type="button" class="btn secondary" data-action="goto-findings">Open findings</button>
      </div>`,
  };
  const panelHtml = panels[active.id] || '';
  return `<div class="card onboarding-wizard" id="onboardingWizard">
    <div class="onboarding-progress" role="progressbar" aria-valuenow="${pct}" aria-valuemin="0" aria-valuemax="100">
      <div class="onboarding-progress-bar" style="width:${pct}%"></div>
      <span class="onboarding-progress-label">${complete ? 'Onboarding complete' : `Step ${currentStep + 1} of ${steps.length}`}</span>
    </div>
    <ol class="onboarding-rail">${rail}</ol>
    <div class="onboarding-panel">
      <h4>${esc(active.label)}</h4>
      ${panelHtml}
    </div>
  </div>`;
}

/**
 * @param {string} selectedKind
 * @param {string} selectedFormat
 * @param {boolean} hasReport
 */
export function renderReportBuilder(selectedKind = 'executive', selectedFormat = 'json', hasReport = false) {
  const kindOptions = UI_REPORT_KINDS.map((k) => {
    const sel = k.id === selectedKind ? ' selected' : '';
    return `<option value="${k.id}"${sel}>${esc(k.label)} — ${esc(k.audience)}</option>`;
  }).join('');
  const formatRadios = REPORT_EXPORT_FORMATS.map((f) => {
    const checked = f.id === selectedFormat ? ' checked' : '';
    return `<label class="report-format-option"><input type="radio" name="reportFormat" value="${f.id}"${checked}> ${esc(f.label)}</label>`;
  }).join('');
  return `<div class="report-builder" id="reportBuilder">
    <div class="report-builder-row">
      <label>Report type
        <select id="reportKindSelect">${kindOptions}</select>
      </label>
      <fieldset class="report-format-fieldset">
        <legend class="muted">Export format</legend>
        ${formatRadios}
      </fieldset>
    </div>
    <div class="report-builder-actions">
      <button type="button" class="btn" data-action="gen-report">Generate report</button>
      <button type="button" class="btn secondary" data-action="export-report-selected" ${hasReport ? '' : 'disabled'} id="exportSelectedBtn">Export selected format</button>
      <button type="button" class="btn secondary" data-action="copy-report-summary" ${hasReport ? '' : 'disabled'} id="copyReportBtn">Copy summary JSON</button>
    </div>
    <p class="muted report-builder-note">Exports are redacted metadata — no secrets or raw packet payloads.</p>
  </div>`;
}

/** Safe defaults for developer validation — references only, not staffed production support. */
export const SUPPORT_READINESS_DEFAULT_PREVIEW = Object.freeze({
  staffing_mode: 'developer_validation',
  headline: 'Support readiness references (not staffed production on-call)',
  disclaimer:
    'This panel shows policy and escalation references for planning and release review. It does not mean 24/7 production support is staffed until support signoff and named rotation evidence are recorded.',
  playbook_reference: 'docs/support-playbook.md',
  validator_cli: 'npm run support:readiness:evidence',
  sla_policy_reference: 'policy://support/customer-sla/pending-ga',
  escalation_path_reference: 'runbook://support/escalation/preview',
  soc_escalation_path_reference: 'runbook://support/soc-escalation/preview',
  on_call_rotation: {
    rotation_name: 'not-configured',
    owner: null,
    schedule_reference: 'schedule://on-call/pending-named-rotation',
  },
  severity_tiers: Object.freeze([
    { severity: 'S1', response_minutes: 15 },
    { severity: 'S2', response_minutes: 60 },
    { severity: 'S3', response_minutes: 240 },
    { severity: 'S4', response_minutes: null },
  ]),
  escalation_contacts: Object.freeze([
    { role: 'support', contact_reference: 'escalation://support/primary-queue' },
    { role: 'engineering', contact_reference: 'escalation://eng/platform-oncall' },
    { role: 'soc', contact_reference: 'escalation://soc/high-scale' },
  ]),
  evidence_recorded: false,
  evidence_validation_ok: null,
  readiness_id: null,
  environment: null,
  support_signoff_owner: null,
  incident_tabletop_id: null,
  customer_comms_template_count: null,
  soc_escalation_state: Object.freeze({
    kill_switch_active: false,
    reason: null,
    updated_at: null,
  }),
});

/**
 * @param {{ kill_switch?: { active?: boolean, reason?: string | null, updated_at?: string | null }, release_evidence_items?: object[] }} input
 */
export function buildSupportReadinessPreview(input = {}) {
  const base = {
    ...SUPPORT_READINESS_DEFAULT_PREVIEW,
    severity_tiers: [...SUPPORT_READINESS_DEFAULT_PREVIEW.severity_tiers],
    escalation_contacts: [...SUPPORT_READINESS_DEFAULT_PREVIEW.escalation_contacts],
    on_call_rotation: { ...SUPPORT_READINESS_DEFAULT_PREVIEW.on_call_rotation },
    soc_escalation_state: { ...SUPPORT_READINESS_DEFAULT_PREVIEW.soc_escalation_state },
  };

  const kill = input.kill_switch || {};
  base.soc_escalation_state = {
    kill_switch_active: Boolean(kill.active),
    reason: kill.reason ?? null,
    updated_at: kill.updated_at ?? null,
  };

  const items = input.release_evidence_items || [];
  const supportItem = items.find((item) => item.kind === 'support_readiness');
  const manifest = supportItem?.evidence;
  const summary = manifest?.readiness_summary;

  if (summary && typeof summary === 'object') {
    base.evidence_recorded = true;
    const validationOk = supportItem?.validation?.ok ?? manifest?.validation?.ok;
    base.evidence_validation_ok = validationOk ?? null;
    base.readiness_id = summary.readiness_id ?? null;
    base.environment = summary.environment ?? null;
    base.support_signoff_owner = summary.support_signoff_owner ?? null;
    base.incident_tabletop_id = summary.incident_tabletop_id ?? null;
    base.customer_comms_template_count = summary.customer_comms_template_count ?? null;
    if (summary.sla_policy_reference) base.sla_policy_reference = summary.sla_policy_reference;
    if (summary.soc_escalation_path_reference) {
      base.soc_escalation_path_reference = summary.soc_escalation_path_reference;
    }
    if (summary.on_call_rotation && typeof summary.on_call_rotation === 'object') {
      base.on_call_rotation = {
        rotation_name: summary.on_call_rotation.rotation_name ?? base.on_call_rotation.rotation_name,
        owner: summary.on_call_rotation.owner ?? null,
        schedule_reference:
          summary.on_call_rotation.schedule_reference ?? base.on_call_rotation.schedule_reference,
      };
    }
    if (base.evidence_validation_ok === true) {
      base.staffing_mode = 'evidence_indexed';
      base.headline = 'Support readiness evidence indexed (production staffing still a release gate)';
    }
  }

  return base;
}

/**
 * @param {ReturnType<typeof buildSupportReadinessPreview>} preview
 */
export function renderSupportReadinessPanel(preview) {
  const modeClass = preview.staffing_mode === 'evidence_indexed'
    ? 'support-readiness-badge--indexed'
    : 'support-readiness-badge--preview';
  const socState = preview.soc_escalation_state || {};
  const killLabel = socState.kill_switch_active
    ? `Active — ${esc(socState.reason || 'no reason recorded')}`
    : 'Inactive (developer validation default)';

  const tierRows = (preview.severity_tiers || []).map((t) => {
    const mins = t.response_minutes == null ? 'best effort' : `${t.response_minutes} min target`;
    return `<tr><td><code>${esc(t.severity)}</code></td><td>${esc(mins)}</td></tr>`;
  }).join('');

  const contactRows = (preview.escalation_contacts || []).map((c) =>
    `<tr><td>${esc(c.role)}</td><td><code>${esc(c.contact_reference)}</code></td></tr>`,
  ).join('');

  const socRoutes = [
    { severity: 'S1', escalation_reference: 'escalation://soc/kill-switch-page' },
    { severity: 'S2', escalation_reference: 'escalation://soc/review-queue' },
  ];
  const socRouteRows = socRoutes.map((r) =>
    `<tr><td><code>${esc(r.severity)}</code></td><td><code>${esc(r.escalation_reference)}</code></td></tr>`,
  ).join('');

  const evidenceLine = preview.evidence_recorded
    ? `Recorded evidence manifest${preview.readiness_id ? ` · <code>${esc(preview.readiness_id)}</code>` : ''}`
      + `${preview.evidence_validation_ok === true ? ' · validator ok' : preview.evidence_validation_ok === false ? ' · validator incomplete' : ''}`
    : 'No accepted support readiness release evidence attached for this tenant.';

  const rotation = preview.on_call_rotation || {};
  return `<section class="card support-readiness-panel" id="supportReadinessPanel" aria-labelledby="supportReadinessHeading">
    <div class="support-readiness-header">
      <h3 id="supportReadinessHeading">Support &amp; on-call readiness</h3>
      <span class="support-readiness-badge ${modeClass}">${esc(preview.headline)}</span>
    </div>
    <p class="muted support-readiness-disclaimer">${esc(preview.disclaimer)}</p>
    <div class="support-readiness-grid">
      <div>
        <h4>SLA policy reference</h4>
        <p><code>${esc(preview.sla_policy_reference)}</code></p>
        <table class="support-readiness-table"><thead><tr><th>Severity</th><th>Response target</th></tr></thead><tbody>${tierRows}</tbody></table>
      </div>
      <div>
        <h4>Escalation path reference</h4>
        <p><code>${esc(preview.escalation_path_reference)}</code></p>
        <table class="support-readiness-table"><thead><tr><th>Role</th><th>Contact reference</th></tr></thead><tbody>${contactRows}</tbody></table>
      </div>
      <div>
        <h4>SOC escalation</h4>
        <p>Path: <code>${esc(preview.soc_escalation_path_reference)}</code></p>
        <p class="support-readiness-soc-state">Kill switch: <strong>${killLabel}</strong>${socState.updated_at ? ` · updated ${esc(socState.updated_at)}` : ''}</p>
        <table class="support-readiness-table"><thead><tr><th>Severity</th><th>Route reference</th></tr></thead><tbody>${socRouteRows}</tbody></table>
      </div>
      <div>
        <h4>On-call rotation (reference)</h4>
        <ul class="support-readiness-meta">
          <li>Rotation: <code>${esc(rotation.rotation_name)}</code></li>
          <li>Owner role: ${rotation.owner ? `<code>${esc(rotation.owner)}</code>` : '<span class="muted">pending named owner</span>'}</li>
          <li>Schedule: <code>${esc(rotation.schedule_reference)}</code></li>
        </ul>
        <h4>Readiness status</h4>
        <p class="muted">${evidenceLine}</p>
        <ul class="support-readiness-meta">
          <li>Playbook: <code>${esc(preview.playbook_reference)}</code></li>
          <li>Validator: <code>${esc(preview.validator_cli)}</code></li>
          ${preview.support_signoff_owner ? `<li>Signoff owner (evidence): <code>${esc(preview.support_signoff_owner)}</code></li>` : ''}
          ${preview.incident_tabletop_id ? `<li>Tabletop id: <code>${esc(preview.incident_tabletop_id)}</code></li>` : ''}
          ${preview.customer_comms_template_count != null ? `<li>Comms templates (count): ${esc(String(preview.customer_comms_template_count))}</li>` : ''}
        </ul>
      </div>
    </div>
  </section>`;
}

/** Mirrors `PRODUCTION_RELEASE_EVIDENCE_KINDS` in `src/contracts/productionReleaseEvidence.mjs`. */
export const PRODUCTION_RELEASE_EVIDENCE_KINDS = Object.freeze([
  'third_party_security_review',
  'migration_apply',
  'operator_runbook_exercise',
  'oidc_prod_auth_preflight',
  'edge_protection',
  'agent_sbom_provenance',
  'agent_install_matrix',
  'agent_mtls_gateway',
  'agent_trust_key_ceremony',
  'governed_adapter',
  'provider_approval',
  'kill_switch_drill',
  'postgres_concurrency',
  'dr_restore',
  'ui_accessibility_matrix',
  'notification_provider_config',
  'probe_fleet_matrix',
  'vector_safety_policy',
  'secret_rotation_drill',
  'observability_slo',
  'support_readiness',
  'evidence_snapshot_manifest',
  'postgres_tenant_query_audit',
  'rollback_fixforward',
  'kms_vault_posture',
  'control_plane_container_release',
  'staging_e2e_matrix',
  'compliance_legal_signoff',
  'authorization_custody',
  'placement_confidence_staging',
  'gateway_load_abuse',
]);

const CUSTODY_URI_FIELD_PRIORITY = Object.freeze([
  'evidence_uri',
  'review_report_uri',
  'remediation_tracker_uri',
  'runner_evidence_uri',
  'post_apply_check_uri',
  'signoff_reference',
]);

/**
 * @param {Record<string, unknown>|null|undefined} evidence
 */
export function pickReleaseEvidenceCustodyUri(evidence) {
  if (!evidence || typeof evidence !== 'object') return null;
  for (const field of CUSTODY_URI_FIELD_PRIORITY) {
    const value = evidence[field];
    if (typeof value === 'string' && value.trim()) return value.trim();
  }
  for (const [key, value] of Object.entries(evidence)) {
    if (typeof value !== 'string' || !value.trim()) continue;
    const normalized = key.replace(/([a-z])([A-Z])/g, '$1_$2').toLowerCase();
    if (normalized.endsWith('_uri') || normalized.endsWith('_reference')) {
      return value.trim();
    }
  }
  return null;
}

/**
 * @param {{ ok?: boolean, missing_fields?: string[], forbidden_fields?: string[] }|null|undefined} validation
 */
export function summarizeReleaseEvidenceValidation(validation) {
  if (!validation) return 'No validation summary';
  if (validation.ok) return 'Contract valid (metadata-only)';
  const parts = [];
  if (validation.missing_fields?.length) {
    parts.push(`missing ${validation.missing_fields.length} field(s)`);
  }
  if (validation.forbidden_fields?.length) {
    parts.push(`forbidden ${validation.forbidden_fields.length} field(s)`);
  }
  return parts.length ? `Invalid — ${parts.join('; ')}` : 'Invalid';
}

/**
 * @param {Array<{ kind?: string }>} items
 */
export function computeReleaseEvidenceCoverage(items = []) {
  const recorded = new Set(
    items.map((item) => item?.kind).filter((kind) => typeof kind === 'string' && kind),
  );
  const missing = PRODUCTION_RELEASE_EVIDENCE_KINDS.filter((kind) => !recorded.has(kind));
  return {
    expected: PRODUCTION_RELEASE_EVIDENCE_KINDS.length,
    recorded: recorded.size,
    missing,
    kindsComplete: missing.length === 0 && recorded.size > 0,
  };
}

function truncateUri(uri, max = 72) {
  const text = String(uri);
  if (text.length <= max) return text;
  return `${text.slice(0, max - 1)}…`;
}

const STAGING_ATTESTATION_GATE_BANNER = `<p class="release-evidence-gate muted">
  Staging readiness attestation summarizes metadata-only evidence inventory. It does <strong>not</strong> clear production promotion —
  operator, security, legal, and SOC gates in <code>docs/release-checklist.md</code> remain authoritative.
</p>`;

/**
 * @param {{
 *   required?: string[],
 *   present?: string[],
 *   missing?: string[],
 *   invalid?: Array<{ kind?: string }>,
 *   rejected?: Array<{ kind?: string, status?: string }>,
 * }|null|undefined} kinds
 */
export function summarizeStagingAttestationEvidenceCounts(kinds = {}) {
  const required = Array.isArray(kinds.required) ? kinds.required.length : 0;
  const present = Array.isArray(kinds.present) ? kinds.present.length : 0;
  const missing = Array.isArray(kinds.missing) ? kinds.missing.length : 0;
  const invalid = Array.isArray(kinds.invalid) ? kinds.invalid.length : 0;
  const rejected = Array.isArray(kinds.rejected) ? kinds.rejected.length : 0;
  return { required, present, missing, invalid, rejected };
}

/**
 * @param {Record<string, unknown>|null|undefined} attestation
 * @param {{
 *   loadError?: string|null,
 *   permissionDenied?: boolean,
 *   compact?: boolean,
 * }} [opts]
 */
export function renderStagingReadinessAttestationPanel(attestation, opts = {}) {
  if (opts.permissionDenied) {
    return `<section class="staging-readiness-attestation-panel staging-readiness-attestation-panel--denied" id="staging-readiness-attestation">
      <h3>Staging readiness attestation</h3>
      ${STAGING_ATTESTATION_GATE_BANNER}
      <p class="muted">Your role cannot read release evidence attestation (<code>release_evidence:read</code>). Switch to owner, admin, SOC, or auditor.</p>
    </section>`;
  }

  if (opts.loadError) {
    return `<section class="staging-readiness-attestation-panel staging-readiness-attestation-panel--error" id="staging-readiness-attestation">
      <h3>Staging readiness attestation</h3>
      ${STAGING_ATTESTATION_GATE_BANNER}
      <p class="muted">Unable to load staging readiness attestation: ${esc(opts.loadError)}</p>
    </section>`;
  }

  if (!attestation || typeof attestation !== 'object') {
    return `<section class="staging-readiness-attestation-panel staging-readiness-attestation-panel--empty" id="staging-readiness-attestation">
      <h3>Staging readiness attestation</h3>
      ${STAGING_ATTESTATION_GATE_BANNER}
      <p class="muted">No attestation summary returned. Re-run <code>npm run release:staging-attestation</code> or refresh after evidence is recorded.</p>
    </section>`;
  }

  const counts = summarizeStagingAttestationEvidenceCounts(attestation.required_evidence_kinds);
  const productionReady = attestation.production_ready === true;
  const signoffStatus = typeof attestation.signoff_status === 'string'
    ? attestation.signoff_status
    : 'unknown';
  const releaseId = attestation.release_id ?? '—';
  const profile = typeof attestation.profile === 'string' && attestation.profile.trim()
    ? attestation.profile.trim()
    : null;
  const blockers = Array.isArray(attestation.blocker_summary) ? attestation.blocker_summary : [];
  const statusBadge = productionReady
    ? '<span class="badge badge--warn">Evidence inventory complete — promotion gates still open</span>'
    : '<span class="badge badge--warn">Attestation blocked</span>';

  const countsLine = `<p class="staging-attestation-counts">
    ${statusBadge}
    Required kinds present: <strong>${counts.present}</strong> / ${counts.required}
    · missing <strong>${counts.missing}</strong>
    · invalid <strong>${counts.invalid}</strong>
    · rejected <strong>${counts.rejected}</strong>
  </p>`;

  const metaGrid = `<dl class="staging-attestation-meta">
    <div><dt>production_ready</dt><dd><code>${productionReady ? 'true' : 'false'}</code></dd></div>
    <div><dt>signoff_status</dt><dd><code>${esc(signoffStatus)}</code></dd></div>
    <div><dt>release_id</dt><dd><code>${esc(String(releaseId))}</code></dd></div>
    ${profile ? `<div><dt>profile</dt><dd><code>${esc(profile)}</code></dd></div>` : ''}
    ${
  attestation.record_counts?.total != null
    ? `<div><dt>evidence records</dt><dd>${esc(String(attestation.record_counts.total))}</dd></div>`
    : ''
}
  </dl>`;

  const combinedGates = attestation.release_checklist_gates?.combined;
  const checklistGatesLine = combinedGates && typeof combinedGates === 'object'
    ? `<p class="staging-attestation-checklist-gates">
    Checklist gates:
    unchecked <strong>${Number(combinedGates.unchecked) || 0}</strong>
    · in progress <strong>${Number(combinedGates.in_progress) || 0}</strong>
    · complete <strong>${Number(combinedGates.complete) || 0}</strong>
  </p>`
    : '';

  const externalGateWarn = attestation.external_gates?.local_developer_validation_cannot_satisfy === true
    ? '<p class="staging-attestation-external-gate-warn">Local validation cannot satisfy external staging, security, SOC, or legal gates.</p>'
    : '';

  const blockerList = blockers.length
    ? `<details class="staging-attestation-blockers" open>
      <summary class="muted">Blockers (${blockers.length})</summary>
      <ul class="staging-attestation-blocker-list">${blockers.map((line) => `<li>${esc(line)}</li>`).join('')}</ul>
    </details>`
    : '<p class="muted staging-attestation-clear">No attestation blockers reported for required evidence kinds.</p>';

  const missingKinds = attestation.required_evidence_kinds?.missing;
  const missingDetails = Array.isArray(missingKinds) && missingKinds.length && !opts.compact
    ? `<details class="staging-attestation-missing"><summary class="muted">Missing required kinds (${missingKinds.length})</summary>
      <p class="muted"><code>${missingKinds.map((k) => esc(k)).join('</code>, <code>')}</code></p></details>`
    : '';

  const invalidKinds = attestation.required_evidence_kinds?.invalid;
  const invalidLines = Array.isArray(invalidKinds) && invalidKinds.length && !opts.compact
    ? invalidKinds.map((entry) => {
      const parts = [];
      if (entry.missing_fields?.length) parts.push(`${entry.missing_fields.length} missing field(s)`);
      if (entry.forbidden_fields?.length) parts.push(`${entry.forbidden_fields.length} forbidden field(s)`);
      const detail = parts.length ? ` (${parts.join('; ')})` : '';
      return `<li><code>${esc(entry.kind || '—')}</code>${esc(detail)}</li>`;
    }).join('')
    : '';
  const invalidDetails = invalidLines
    ? `<details class="staging-attestation-invalid"><summary class="muted">Invalid required kinds (${invalidKinds.length})</summary><ul>${invalidLines}</ul></details>`
    : '';

  const rejectedKinds = attestation.required_evidence_kinds?.rejected;
  const rejectedDetails = Array.isArray(rejectedKinds) && rejectedKinds.length && !opts.compact
    ? `<details class="staging-attestation-rejected"><summary class="muted">Rejected kinds (${rejectedKinds.length})</summary>
      <ul>${rejectedKinds.map((entry) => `<li><code>${esc(entry.kind || '—')}</code> · status <code>${esc(entry.status || '—')}</code></li>`).join('')}</ul></details>`
    : '';

  return `<section class="staging-readiness-attestation-panel${opts.compact ? ' staging-readiness-attestation-panel--compact' : ''}" id="staging-readiness-attestation">
    <h3>Staging readiness attestation</h3>
    ${STAGING_ATTESTATION_GATE_BANNER}
    ${countsLine}
    ${metaGrid}
    ${checklistGatesLine}
    ${externalGateWarn}
    <p class="muted">Summary only — evidence bodies, secrets, and raw payloads are never rendered in this panel.</p>
    ${blockerList}
    ${missingDetails}
    ${invalidDetails}
    ${rejectedDetails}
  </section>`;
}

/**
 * @param {{
 *   items?: Array<Record<string, unknown>>,
 *   loadError?: string|null,
 *   permissionDenied?: boolean,
 *   compact?: boolean,
 * }} opts
 */
export function renderReleaseEvidencePanel(opts = {}) {
  const items = Array.isArray(opts.items) ? opts.items : [];
  const coverage = computeReleaseEvidenceCoverage(items);
  const sorted = items.slice().sort((a, b) => String(b.created_at || '').localeCompare(String(a.created_at || '')));
  const gateBanner = `<p class="release-evidence-gate muted">
    Metadata-only release evidence supports review. It does <strong>not</strong> mean production readiness is complete —
    staging, legal, SOC, and security signoffs in <code>docs/release-checklist.md</code> remain governing gates.
  </p>`;

  if (opts.permissionDenied) {
    return `<section class="release-evidence-panel release-evidence-panel--denied" id="release-evidence">
      <h3>Production release evidence</h3>
      ${gateBanner}
      <p class="muted">Your role cannot read release evidence (<code>release_evidence:read</code>). Switch to owner, admin, SOC, or auditor.</p>
    </section>`;
  }

  if (opts.loadError) {
    return `<section class="release-evidence-panel release-evidence-panel--error" id="release-evidence">
      <h3>Production release evidence</h3>
      ${gateBanner}
      <p class="muted">Unable to load release evidence: ${esc(opts.loadError)}</p>
    </section>`;
  }

  const coverageLine = `<p class="release-evidence-coverage">
    <span class="badge badge--warn">Release gates open</span>
    Accepted kinds recorded: <strong>${coverage.recorded}</strong> / ${coverage.expected}
    ${coverage.kindsComplete ? '' : ` · ${coverage.missing.length} kind(s) still unattached`}
  </p>`;

  const empty = sorted.length
    ? ''
    : `<div class="empty release-evidence-empty">
      No release evidence attached for this tenant yet. Validate bundles with
      <code>npm run release:evidence:bundle</code> and submit via <code>POST /v1/production-release-evidence</code>.
    </div>`;

  const rows = sorted.map((item) => {
    const custodyUri = pickReleaseEvidenceCustodyUri(item.evidence);
    const custodyCell = custodyUri
      ? `<code class="release-evidence-uri" title="${esc(custodyUri)}">${esc(truncateUri(custodyUri))}</code>`
      : '<span class="muted">—</span>';
    const validation = summarizeReleaseEvidenceValidation(item.validation);
    return `<tr>
      <td><code>${esc(item.kind || '—')}</code></td>
      <td>${esc(item.status || '—')}</td>
      <td class="release-evidence-validation">${esc(validation)}</td>
      <td>${esc(item.release_id || '—')}</td>
      <td>${esc(item.created_at || '—')}</td>
      <td>${custodyCell}</td>
    </tr>`;
  }).join('');

  const table = sorted.length
    ? `<div class="release-evidence-table-wrap"><table class="release-evidence-table">
      <thead><tr>
        <th>Kind</th><th>Status</th><th>Validation</th><th>Release ID</th><th>Created</th><th>Custody URI preview</th>
      </tr></thead><tbody>${rows}</tbody></table></div>`
    : '';

  const missingKinds = coverage.missing.length && !opts.compact
    ? `<details class="release-evidence-missing"><summary class="muted">Kinds not yet recorded (${coverage.missing.length})</summary>
      <p class="muted"><code>${coverage.missing.map((k) => esc(k)).join('</code>, <code>')}</code></p></details>`
    : '';

  return `<section class="release-evidence-panel${opts.compact ? ' release-evidence-panel--compact' : ''}" id="release-evidence">
    <h3>Production release evidence</h3>
    ${gateBanner}
    ${coverageLine}
    <p class="muted">Lists accepted metadata-only evidence. Raw bodies, secrets, logs, packet captures, SQL dumps, and IP inventories are never rendered here.</p>
    ${empty}
    ${table}
    ${missingKinds}
  </section>`;
}

export const CVE_PIPELINE_STAGES = Object.freeze([
  'ingest', 'triage', 'match', 'validate', 'recommend', 'ticket', 'retest', 'resolved',
]);

export const DISCOVERY_MODES = Object.freeze([
  { id: 'D0_declared_only', label: 'D0 Declared-only', description: 'Only customer-declared targets are tested. No passive discovery.' },
  { id: 'D1_import_assisted', label: 'D1 Import-assisted', description: 'Customer uploads CSV/CMDB lists; AstraNull normalizes and suggests target groups.' },
  { id: 'D2_connector_assisted', label: 'D2 Connector-assisted', description: 'Read-only connectors list known assets; user approves imports.' },
  { id: 'D3_entity_discovery', label: 'D3 Entity discovery', description: 'Org/entity research with passive discovery; candidates require review.' },
  { id: 'D4_continuous_discovery', label: 'D4 Continuous discovery', description: 'Scheduled discovery with approval workflow for new candidates.' },
]);

export const EXPOSURE_TYPE_META = Object.freeze({
  dangling_cname: { label: 'Dangling CNAME', icon: '⛓' },
  deleted_cloud_app: { label: 'Deleted cloud app', icon: '☁' },
  dangling_script_inclusion: { label: 'Dangling script', icon: '⌁' },
  orphaned_redirect: { label: 'Orphaned redirect', icon: '↪' },
  vendor_dependency_risk: { label: 'Vendor dependency', icon: '⚙' },
  subdomain_takeover_risk: { label: 'Subdomain takeover', icon: '⚠' },
});

export const ACTION_ITEM_STATUSES = Object.freeze([
  'open',
  'ticketed',
  'remediation_started',
  'retest_pending',
  'resolved',
  'accepted_risk',
]);

function formatUtcShort(value) {
  if (!value) return '—';
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? String(value) : parsed.toISOString().slice(0, 19).replace('T', ' ');
}

export function renderConfidenceBar(confidence, opts = {}) {
  const n = Math.max(0, Math.min(1, Number(confidence) || 0));
  const pct = Math.round(n * 100);
  const label = opts.label ?? `${pct}%`;
  return `<div class="confidence-bar" role="meter" aria-valuenow="${pct}" aria-valuemin="0" aria-valuemax="100" aria-label="${esc(label)}">
    <div class="confidence-bar-fill" style="width:${pct}%"></div>
    <span class="confidence-bar-label">${esc(label)}</span>
  </div>`;
}

export function renderStageBadge(stage) {
  const key = String(stage ?? 'unknown').toLowerCase();
  return `<span class="stage-badge stage-badge--${esc(key)}">${esc(key)}</span>`;
}

export function renderSeverityBadge(severity) {
  const key = String(severity ?? 'unknown').toLowerCase();
  const cls = ['critical', 'high'].includes(key) ? ' high' : key === 'low' ? ' safe' : '';
  return `<span class="severity-badge severity-badge--${esc(key)} pill${cls}">${esc(key)}</span>`;
}

export function renderRiskStateBadge(state) {
  const key = String(state ?? 'unknown').toLowerCase();
  return `<span class="state-badge state-badge--${esc(key)}">${esc(key.replace(/_/g, ' '))}</span>`;
}

export function renderExposureTypeBadge(exposureType) {
  const meta = EXPOSURE_TYPE_META[exposureType] ?? { label: exposureType, icon: '•' };
  return `<span class="exposure-badge exposure-badge--${esc(exposureType)}"><span class="exposure-badge-icon" aria-hidden="true">${esc(meta.icon)}</span> ${esc(meta.label)}</span>`;
}

export function renderEntityTypeBadge(entityType) {
  const key = String(entityType ?? 'unknown').toLowerCase();
  return `<span class="entity-type-badge entity-type-badge--${esc(key)}">${esc(key.replace(/_/g, ' '))}</span>`;
}

export function renderDiscoveryModeSelector(activeMode = 'D0_declared_only') {
  const options = DISCOVERY_MODES.map((m) => {
    const selected = m.id === activeMode ? ' selected' : '';
    return `<option value="${esc(m.id)}" title="${esc(m.description)}"${selected}>${esc(m.label)}</option>`;
  }).join('');
  const active = DISCOVERY_MODES.find((m) => m.id === activeMode) ?? DISCOVERY_MODES[0];
  return `<div class="discovery-mode-selector">
    <label class="discovery-mode-label">Discovery mode
      <select id="discoveryModeSelect" class="discovery-mode-select" title="${esc(active.description)}">${options}</select>
    </label>
    <p class="muted discovery-mode-hint" id="discoveryModeHint">${esc(active.description)}</p>
  </div>`;
}

export function groupActionItems(items = []) {
  const groups = new Map();
  for (const item of items) {
    const assetKey = item.asset?.display ?? item.asset?.id ?? 'unknown';
    const key = `${item.category}::${assetKey}`;
    if (!groups.has(key)) {
      groups.set(key, {
        merge_key: key,
        category: item.category,
        asset: item.asset,
        items: [],
      });
    }
    groups.get(key).items.push(item);
  }
  return [...groups.values()].sort((a, b) => b.items.length - a.items.length);
}

export function buildSiemEventPreview(actionItem) {
  if (!actionItem) return null;
  const findingId = actionItem.finding_ids?.[0] ?? actionItem.action_item_id;
  return {
    event_type: 'waf.drift.detected',
    event_id: actionItem.action_item_id,
    occurred_at: actionItem.updated_at ?? actionItem.created_at ?? new Date().toISOString(),
    severity: actionItem.severity ?? 'medium',
    asset: {
      display: actionItem.asset?.display ?? 'declared asset',
      ...(actionItem.asset?.owner_hint ? { owner_hint: actionItem.asset.owner_hint } : {}),
    },
    finding: {
      id: findingId,
      summary: actionItem.evidence?.summary ?? actionItem.title,
      reason_codes: [],
      evidence_url: actionItem.evidence?.links?.[0]?.url ?? null,
      retest_url: actionItem.retest_url ?? null,
    },
    recommendation: {
      vendor: 'generic',
      type: actionItem.category,
      summary: actionItem.recommended_solution ?? 'Review remediation guidance.',
    },
  };
}

/**
 * @param {{ items?: object[], selectedId?: string|null, detail?: object|null, showIngestForm?: boolean }} data
 */
export function renderCvePipelinePage(data = {}) {
  const items = data.items ?? [];
  const selectedId = data.selectedId ?? null;
  const detail = data.detail ?? null;
  const showIngest = Boolean(data.showIngestForm);

  const rows = items.length
    ? items.map((item) => {
      const products = (item.affected_products || []).map((p) => `<code>${esc(p)}</code>`).join(', ') || '—';
      const exploited = item.known_exploited ? 'yes' : 'no';
      const active = item.id === selectedId ? ' cve-row--active' : '';
      return `<tr class="cve-row${active}" data-cve-row="${esc(item.id)}">
        <td><code>${esc(item.cve_id)}</code></td>
        <td>${renderSeverityBadge(item.severity)}</td>
        <td>${renderStageBadge(item.stage)}</td>
        <td>${products}</td>
        <td>${exploited}</td>
        <td>${esc(formatUtcShort(item.created_at))}</td>
        <td><button type="button" class="btn secondary" data-action="cve-view" data-id="${esc(item.id)}">View</button></td>
      </tr>`;
    }).join('')
    : '';

  const empty = items.length
    ? ''
    : '<div class="empty">No CVE items tracked. Use the API or add a CVE to start the pipeline.</div>';

  const ingestForm = showIngest
    ? `<div class="card cve-ingest-form" id="cveIngestForm">
      <h4>Ingest CVE</h4>
      <form class="hs-form" id="cveIngestFields">
        <label>CVE ID <input type="text" id="cveIngestId" placeholder="CVE-2026-12345" required></label>
        <label>Severity
          <select id="cveIngestSeverity" required>
            <option value="critical">critical</option>
            <option value="high">high</option>
            <option value="medium" selected>medium</option>
            <option value="low">low</option>
            <option value="unknown">unknown</option>
          </select>
        </label>
        <label>Affected products <input type="text" id="cveIngestProducts" placeholder="Apache Tomcat 10.1, nginx" required></label>
        <div class="form-actions">
          <button type="button" class="btn" data-action="cve-ingest-submit">Create pipeline item</button>
          <button type="button" class="btn secondary" data-action="cve-ingest-cancel">Cancel</button>
        </div>
      </form>
    </div>`
    : '';

  let detailHtml = '';
  if (detail?.item) {
    const triage = detail.item.triage_result;
    const factors = triage?.factors
      ? Object.entries(triage.factors).map(([k, v]) => `<li><code>${esc(k)}</code>: ${v ? 'yes' : 'no'}</li>`).join('')
      : '<li class="muted">No triage factors yet. Run triage from the API or workflow.</li>';
    const matches = (detail.matches || []).map((m) => `<tr>
      <td><code>${esc(m.asset_display)}</code></td>
      <td>${esc(m.match_source)}</td>
      <td>${renderConfidenceBar(m.match_confidence, { label: m.confidence_level })}</td>
      <td>${m.requires_review ? '<span class="pill">review</span>' : '—'}</td>
    </tr>`).join('') || '<tr><td colspan="4"><span class="muted">No asset matches yet.</span></td></tr>';
    const recs = (detail.recommendations || []).map((r) => {
      const rec = r.recommendation ?? r.recommendation_json ?? {};
      return `<li><strong>${esc(r.vendor ?? rec.vendor ?? 'generic')}</strong> · ${esc(rec.recommendation_type ?? r.recommendation_type ?? 'guidance')} — ${esc(rec.action_summary ?? rec.why ?? '')}</li>`;
    }).join('') || '<li class="muted">No vendor recommendations generated yet.</li>';

    detailHtml = `<div class="card cve-detail-panel" id="cveDetailPanel">
      <h4>${esc(detail.item.cve_id)}</h4>
      <p>${renderSeverityBadge(detail.item.severity)} ${renderStageBadge(detail.item.stage)}
        ${detail.item.known_exploited ? '<span class="pill high">known exploited</span>' : ''}</p>
      <h5>Triage factors</h5>
      <ul class="cve-triage-factors">${factors}</ul>
      ${triage?.summary ? `<p class="muted">${esc(triage.summary)}</p>` : ''}
      <h5>Asset matches</h5>
      <table><thead><tr><th>Asset</th><th>Source</th><th>Confidence</th><th>Review</th></tr></thead><tbody>${matches}</tbody></table>
      <h5>Recommendations by vendor</h5>
      <ul>${recs}</ul>
    </div>`;
  }

  return `<div id="cve-pipeline" class="card">
    <h3>CVE Pipeline</h3>
    <p class="muted">Metadata-only CVE ingestion, triage, asset matching, and WAF mitigation recommendations. No exploit payloads or automatic WAF deployment.</p>
    <div class="page-actions">
      <button type="button" class="btn" data-action="cve-ingest-toggle">${showIngest ? 'Hide ingest form' : 'Ingest CVE'}</button>
    </div>
    ${ingestForm}
    ${empty}
    ${items.length ? `<table class="cve-pipeline-table"><thead><tr>
      <th>CVE ID</th><th>Severity</th><th>Stage</th><th>Affected products</th><th>Known exploited</th><th>Created</th><th></th>
    </tr></thead><tbody>${rows}</tbody></table>` : ''}
    ${detailHtml}
  </div>`;
}

/**
 * @param {{ inbox?: object[], candidates?: object[], entities?: object[], activeTab?: string, discoveryMode?: string, selectedId?: string|null }} data
 */
export function renderDiscoveryPage(data = {}) {
  const activeTab = data.activeTab === 'all' ? 'all' : 'inbox';
  const inbox = data.inbox ?? [];
  const candidates = data.candidates ?? [];
  const entities = data.entities ?? [];
  const rowsSource = activeTab === 'inbox' ? inbox : candidates;

  const tabInboxCls = activeTab === 'inbox' ? ' active' : '';
  const tabAllCls = activeTab === 'all' ? ' active' : '';

  const rows = rowsSource.length
    ? rowsSource.map((c) => {
      const id = c.id ?? c.candidate_id;
      return `<tr>
        <td><code>${esc(c.hostname)}</code></td>
        <td>${esc(c.source_type)}</td>
        <td>${renderConfidenceBar(c.confidence)}</td>
        <td>${esc(c.ownership_status)}</td>
        <td>${esc(formatUtcShort(c.first_seen_at))}</td>
        <td>${esc(formatUtcShort(c.last_seen_at))}</td>
        <td class="discovery-actions">
          <button type="button" class="btn secondary" data-action="discovery-approve" data-id="${esc(id)}">Approve</button>
          <button type="button" class="btn secondary" data-action="discovery-reject" data-id="${esc(id)}">Reject</button>
        </td>
      </tr>`;
    }).join('')
    : '';

  const empty = rowsSource.length
    ? ''
    : '<div class="empty">No discovery candidates. Your organization is in declared-only mode.</div>';

  const entityRows = entities.length
    ? entities.map((e) => `<tr>
        <td>${renderEntityTypeBadge(e.entity_type)}</td>
        <td>${esc(e.display_name ?? e.name)}</td>
        <td>${(e.root_domains || []).map((d) => `<code>${esc(d)}</code>`).join(', ') || '—'}</td>
        <td>${renderConfidenceBar(e.confidence)}</td>
      </tr>`).join('')
    : '<tr><td colspan="4"><span class="muted">No entities declared yet.</span></td></tr>';

  return `<div id="discovery" class="card">
    <h3>External discovery inbox</h3>
    <p class="muted">Passive, approval-gated candidate discovery. Candidates are not tested until approved into declared scope.</p>
    ${renderDiscoveryModeSelector(data.discoveryMode)}
    <div class="tabs discovery-tabs" role="tablist">
      <button type="button" class="tab discovery-tab${tabInboxCls}" data-discovery-tab="inbox">Inbox</button>
      <button type="button" class="tab discovery-tab${tabAllCls}" data-discovery-tab="all">All Candidates</button>
    </div>
    ${empty}
    ${rowsSource.length ? `<table class="discovery-table"><thead><tr>
      <th>Hostname</th><th>Source</th><th>Confidence</th><th>Ownership</th><th>First seen</th><th>Last seen</th><th>Actions</th>
    </tr></thead><tbody>${rows}</tbody></table>` : ''}
    <div class="card discovery-entities">
      <h4>Entity management</h4>
      <table><thead><tr><th>Type</th><th>Name</th><th>Root domains</th><th>Confidence</th></tr></thead><tbody>${entityRows}</tbody></table>
    </div>
  </div>`;
}

/**
 * @param {{ items?: object[], selectedId?: string|null, detail?: object|null, showCnameForm?: boolean, showDependencyForm?: boolean }} data
 */
export function renderSupplyChainPage(data = {}) {
  const items = data.items ?? [];
  const selectedId = data.selectedId ?? null;
  const detail = data.detail ?? null;

  const rows = items.length
    ? items.map((r) => {
      const active = r.id === selectedId ? ' supply-row--active' : '';
      return `<tr class="supply-row${active}">
        <td><code>${esc(r.hostname)}</code></td>
        <td>${renderExposureTypeBadge(r.exposure_type)}</td>
        <td>${renderSeverityBadge(r.severity)}</td>
        <td>${renderRiskStateBadge(r.state)}</td>
        <td>${renderConfidenceBar(r.confidence)}</td>
        <td>${esc(r.owner_hint || '—')}</td>
        <td><button type="button" class="btn secondary" data-action="supply-view" data-id="${esc(r.id)}">View</button></td>
      </tr>`;
    }).join('')
    : '';

  const empty = items.length
    ? ''
    : '<div class="empty">No supply chain risks detected.</div>';

  const cnameForm = data.showCnameForm
    ? `<div class="card supply-assess-form" id="supplyCnameForm">
      <h4>Assess dangling CNAME</h4>
      <form class="hs-form">
        <label>Hostname <input type="text" id="supplyCnameHost" placeholder="stale.app.example.com" required></label>
        <label>CNAME chain hash <input type="text" id="supplyCnameHash" placeholder="metadata hash (optional)"></label>
        <label>Provider error signature <input type="text" id="supplyCnameSig" placeholder="azure_app_deleted_v1 (optional)"></label>
        <label class="hs-inline"><input type="checkbox" id="supplyCnameConnector"> Connector confirms missing</label>
        <div class="form-actions">
          <button type="button" class="btn" data-action="supply-assess-cname-submit">Run assessment</button>
          <button type="button" class="btn secondary" data-action="supply-assess-cname-cancel">Cancel</button>
        </div>
      </form>
    </div>`
    : '';

  const depForm = data.showDependencyForm
    ? `<div class="card supply-assess-form" id="supplyDependencyForm">
      <h4>Assess dangling dependency</h4>
      <form class="hs-form">
        <label>Hostname <input type="text" id="supplyDepHost" placeholder="www.example.com" required></label>
        <label>Script host <input type="text" id="supplyDepScript" placeholder="cdn.thirdparty.example"></label>
        <label>Dependency URL hash <input type="text" id="supplyDepHash" placeholder="sha256 metadata (optional)"></label>
        <label>HTTP status <input type="number" id="supplyDepStatus" placeholder="404" min="100" max="599"></label>
        <div class="form-actions">
          <button type="button" class="btn" data-action="supply-assess-dep-submit">Run assessment</button>
          <button type="button" class="btn secondary" data-action="supply-assess-dep-cancel">Cancel</button>
        </div>
      </form>
    </div>`
    : '';

  let detailHtml = '';
  if (detail) {
    const evidence = detail.evidence_summary ?? {};
    const evidenceRows = Object.entries(evidence).map(([k, v]) =>
      `<tr><th scope="row">${esc(k)}</th><td>${esc(String(v))}</td></tr>`,
    ).join('') || '<tr><td colspan="2"><span class="muted">No evidence summary fields.</span></td></tr>';
    const steps = (detail.remediation_steps || []).map((s) => `<li>${esc(s)}</li>`).join('')
      || '<li class="muted">No remediation steps recorded.</li>';
    detailHtml = `<div class="card supply-detail-panel" id="supplyDetailPanel">
      <h4>${esc(detail.hostname)}</h4>
      <p>${renderExposureTypeBadge(detail.exposure_type)} ${renderSeverityBadge(detail.severity)} ${renderRiskStateBadge(detail.state)}</p>
      <h5>Evidence summary</h5>
      <table><tbody>${evidenceRows}</tbody></table>
      <h5>Remediation steps</h5>
      <ol>${steps}</ol>
      <h5>Assessment metadata</h5>
      <p class="muted">Phase: <code>${esc(detail.phase ?? 'AP0_detect_only')}</code> · Confidence: ${renderConfidenceBar(detail.confidence)} · Owner hint: ${esc(detail.owner_hint || '—')}</p>
    </div>`;
  }

  return `<div id="supply-chain" class="card">
    <h3>Supply chain risks</h3>
    <p class="muted">Detect-only dangling asset and dependency risks using metadata-only DNS and page dependency signals. No automated acquisition.</p>
    <div class="page-actions">
      <button type="button" class="btn secondary" data-action="supply-assess-cname-toggle">${data.showCnameForm ? 'Hide CNAME form' : 'Assess Dangling CNAME'}</button>
      <button type="button" class="btn secondary" data-action="supply-assess-dep-toggle">${data.showDependencyForm ? 'Hide dependency form' : 'Assess Dangling Dependency'}</button>
    </div>
    ${cnameForm}
    ${depForm}
    ${empty}
    ${items.length ? `<table class="supply-chain-table"><thead><tr>
      <th>Hostname</th><th>Exposure</th><th>Severity</th><th>State</th><th>Confidence</th><th>Owner</th><th></th>
    </tr></thead><tbody>${rows}</tbody></table>` : ''}
    ${detailHtml}
  </div>`;
}

/**
 * @param {{ items?: object[], selectedId?: string|null, grouped?: boolean }} data
 */
export function renderRemediationPage(data = {}) {
  const items = data.items ?? [];
  const selectedId = data.selectedId ?? null;
  const grouped = Boolean(data.grouped);
  const selected = items.find((i) => i.action_item_id === selectedId) ?? null;

  const statusOptions = ACTION_ITEM_STATUSES.map((s) => {
    const sel = selected?.status === s ? ' selected' : '';
    return `<option value="${esc(s)}"${sel}>${esc(s.replace(/_/g, ' '))}</option>`;
  }).join('');

  function renderItemRow(item) {
    const active = item.action_item_id === selectedId ? ' remediation-row--active' : '';
    return `<tr class="remediation-row${active}">
      <td>${esc(item.title)}</td>
      <td><code>${esc(item.category)}</code></td>
      <td>${esc(item.asset?.display ?? '—')}</td>
      <td>${renderSeverityBadge(item.severity)}</td>
      <td>
        <select class="remediation-status-select" data-action="remediation-status" data-id="${esc(item.action_item_id)}">
          ${ACTION_ITEM_STATUSES.map((s) => {
            const sel = item.status === s ? ' selected' : '';
            return `<option value="${esc(s)}"${sel}>${esc(s.replace(/_/g, ' '))}</option>`;
          }).join('')}
        </select>
      </td>
      <td>${esc(item.owner ?? '—')}</td>
      <td>${esc(formatUtcShort(item.created_at))}</td>
      <td><button type="button" class="btn secondary" data-action="remediation-view" data-id="${esc(item.action_item_id)}">View</button></td>
    </tr>`;
  }

  let tableBody = '';
  if (grouped) {
    const groups = groupActionItems(items);
    tableBody = groups.length
      ? groups.map((g) => {
        const header = `<tr class="remediation-group-header"><td colspan="8"><strong>${esc(g.category)}</strong> · ${esc(g.asset?.display ?? '—')} <span class="muted">(${g.items.length} item${g.items.length === 1 ? '' : 's'})</span></td></tr>`;
        return header + g.items.map((item) => renderItemRow(item)).join('');
      }).join('')
      : '';
  } else {
    tableBody = items.map((item) => renderItemRow(item)).join('');
  }

  const empty = items.length
    ? ''
    : '<div class="empty">No remediation action items. WAF posture findings will create action items automatically.</div>';

  let detailHtml = '';
  if (selected) {
    const siem = buildSiemEventPreview(selected);
    detailHtml = `<div class="card remediation-detail-panel" id="remediationDetailPanel">
      <h4>${esc(selected.title)}</h4>
      <p>${renderSeverityBadge(selected.severity)} · Status:
        <select id="remediationDetailStatus" data-action="remediation-status" data-id="${esc(selected.action_item_id)}">${statusOptions}</select>
      </p>
      <h5>Evidence summary</h5>
      <p>${esc(selected.evidence?.summary ?? '—')}</p>
      <h5>Recommended solution</h5>
      <p>${esc(selected.recommended_solution ?? '—')}</p>
      <h5>Retest URL</h5>
      <p><code>${esc(selected.retest_url ?? '—')}</code></p>
      <h5>SIEM event preview</h5>
      <pre class="siem-preview">${esc(JSON.stringify(siem, null, 2))}</pre>
    </div>`;
  }

  return `<div id="remediation" class="card">
    <h3>Remediation action items</h3>
    <p class="muted">Workflow action items from WAF posture findings. Metadata-only evidence and ticket/SIEM connector previews.</p>
    <div class="page-actions">
      <label class="grouping-toggle hs-inline">
        <input type="checkbox" id="remediationGroupedToggle" data-action="remediation-group-toggle"${grouped ? ' checked' : ''}>
        Group by category and asset
      </label>
    </div>
    ${empty}
    ${items.length ? `<table class="remediation-table"><thead><tr>
      <th>Title</th><th>Category</th><th>Asset</th><th>Severity</th><th>Status</th><th>Owner</th><th>Created</th><th></th>
    </tr></thead><tbody>${tableBody}</tbody></table>` : ''}
    ${detailHtml}
  </div>`;
}