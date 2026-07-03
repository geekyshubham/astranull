/** Pure UI helpers — importable from app.js and unit tests. */

export const UI_ROLE_PERMISSIONS = Object.freeze({
  'finding:write': ['owner', 'admin', 'engineer'],
  'bootstrap_token:create': ['owner', 'admin', 'engineer'],
  'environment:write': ['owner', 'admin', 'engineer'],
  'target_group:write': ['owner', 'admin', 'engineer'],
  'test_run:start': ['owner', 'admin', 'engineer'],
  'audit:read': ['owner', 'admin', 'soc'],
  'release_evidence:read': ['owner', 'admin'],
  'waf:run': ['owner', 'admin', 'engineer'],
  'waf:write': ['owner', 'admin', 'engineer'],
  'waf:connector_read': ['owner', 'admin', 'engineer', 'auditor'],
  'waf:connector_write': ['owner', 'admin'],
  'cve_pipeline:write': ['owner', 'admin', 'engineer'],
  'discovery:write': ['owner', 'admin', 'engineer'],
  'discovery:approve': ['owner', 'admin'],
  'high_scale:request': ['owner', 'admin', 'engineer'],
  'high_scale:write': ['owner', 'admin', 'engineer'],
  'soc:high_scale': ['soc'],
  'soc:kill_switch': ['soc'],
});

/** @param {string} role @param {string} permission */
export function roleHasUiPermission(role, permission) {
  const allowed = UI_ROLE_PERMISSIONS[permission];
  if (!allowed) return false;
  return allowed.includes(String(role ?? '').toLowerCase());
}

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

export const ONBOARDING_HEARTBEAT_POLL_MS = 3000;
export const ONBOARDING_HEARTBEAT_TIMEOUT_MS = 120000;
export const ONBOARDING_PLACEMENT_TEST_CHECK_ID = 'path.protected_canary.safe';

export const ONBOARDING_STEPS = Object.freeze([
  { id: 'environment', label: 'Environment', hint: 'Create a validation environment (prod, staging, or lab).' },
  { id: 'target_group', label: 'Target group', hint: 'Declare customer-owned business service scope.' },
  { id: 'target', label: 'Declared target', hint: 'Add at least one FQDN, URL, or IP — no automatic discovery.' },
  { id: 'token', label: 'Bootstrap token', hint: 'One-time token for outbound agent registration.' },
  { id: 'install', label: 'Install agent', hint: 'Optional but recommended for inside-path observation evidence.' },
  {
    id: 'verify_heartbeat',
    label: 'Verify heartbeat',
    hint: 'Wait for the agent to register and send its first heartbeat — proves outbound connectivity.',
  },
  {
    id: 'placement_test',
    label: 'Placement test',
    hint: 'Optional safe canary run to prove the agent can observe traffic on the declared path.',
  },
  { id: 'safe_run', label: 'First safe run', hint: 'Start a bounded metadata-only validation against declared targets.' },
  { id: 'review', label: 'Review result', hint: 'Inspect verdict, evidence chain, and findings.' },
]);

/** Friendly empty-state copy aligned with docs/ux/00-ux-principles.md and page wireframes. */
export const PAGE_EMPTY_STATES = Object.freeze({
  dashboard: {
    id: 'dashboard',
    message: 'Start by creating a target group for one internet-facing service. AstraNull will help you install an agent and run the first safe validation.',
    hint: 'No cloud credentials or automatic IP inventory discovery — declare scope manually.',
    primary: { action: 'create-tg', label: 'Create target group' },
    secondary: { action: 'goto-onboarding', label: 'Open setup guide' },
  },
  environments: {
    id: 'environments',
    message: 'Create an environment to separate prod, staging, or lab validation scope.',
    primary: { action: 'create-env', label: 'Create environment' },
    secondary: { action: 'goto-onboarding', label: 'Onboarding wizard' },
  },
  target_groups: {
    id: 'target_groups',
    message: 'Add the first target you want AstraNull to validate.',
    hint: 'Declare customer-owned FQDNs, URLs, or IPs — format validation only, no discovery.',
    primary: { action: 'create-tg', label: 'Create target group' },
    secondary: { action: 'goto-onboarding', label: 'Onboarding wizard' },
  },
  agents: {
    id: 'agents',
    message: 'Install an agent where it can observe this target\'s traffic.',
    hint: 'Outbound-only registration — no inbound management port required.',
    primary: { action: 'goto-onboarding', label: 'Install agent' },
    secondary: { action: 'goto-settings', label: 'Create bootstrap token' },
  },
  checks: {
    id: 'checks',
    message: 'Enable safe checks after you declare a target group and install an agent for placement evidence.',
    primary: { action: 'goto-target-groups', label: 'Declare targets' },
    secondary: { action: 'goto-onboarding', label: 'Onboarding wizard' },
  },
  runs: {
    id: 'runs',
    message: 'Run your first safe validation to prove outside probe and inside agent evidence.',
    primary: { action: 'start-run', label: 'Start safe validation' },
    secondary: { action: 'goto-onboarding', label: 'Complete setup first' },
  },
  findings: {
    id: 'findings',
    message: 'No findings yet. Findings appear when a safe validation correlates to bypassable or penetrated traffic.',
    primary: { action: 'start-run', label: 'Start safe validation' },
    secondary: { action: 'goto-runs', label: 'View test runs' },
  },
  evidence: {
    id: 'evidence',
    message: 'No evidence yet. Complete a safe validation to populate the evidence vault.',
    primary: { action: 'start-run', label: 'Start safe validation' },
    secondary: { action: 'goto-runs', label: 'View test runs' },
  },
  high_scale: {
    id: 'high_scale',
    message: 'No high-scale requests yet. Submit a request with scope confirmation — AstraNull SOC reviews before anything executes.',
    hint: 'Customers cannot self-launch governed high-scale tests.',
    primary: { action: 'goto-high-scale-form', label: 'Submit request' },
    secondary: { action: 'goto-target-groups', label: 'Declare target group first' },
  },
  reports: {
    id: 'reports',
    message: 'No report generated yet. Select a report type and generate to enable export.',
    primary: { action: 'gen-report', label: 'Generate report' },
    secondary: null,
  },
  audit: {
    id: 'audit',
    message: 'No audit events recorded yet. Admin, agent, test, and approval actions appear here.',
    primary: { action: 'goto-onboarding', label: 'Run first setup action' },
    secondary: null,
  },
  notifications: {
    id: 'notifications',
    message: 'No notification rules yet. Add a metadata-only rule to record intended delivery in developer validation.',
    primary: { action: 'create-notify-rule', label: 'Add rule' },
    secondary: null,
  },
  settings_tokens: {
    id: 'settings_tokens',
    message: 'No bootstrap tokens yet. Create a one-time token for outbound agent registration.',
    primary: { action: 'create-token', label: 'Create bootstrap token' },
    secondary: { action: 'goto-onboarding', label: 'Onboarding wizard' },
  },
  soc_queue: {
    id: 'soc_queue',
    message: 'No requests in queue. Customer high-scale requests appear here for SOC review.',
    primary: { action: 'goto-high-scale', label: 'View customer requests' },
    secondary: null,
  },
  onboarding_heartbeat: {
    id: 'onboarding_heartbeat',
    message: 'No agent heartbeat yet. Run the install command on a host that can reach your API outbound and observe declared targets.',
    hint: 'Common fixes: expired bootstrap token, firewall blocking HTTPS, wrong target group binding, NTP clock skew, or the agent service not started.',
    primary: { action: 'onboard-retry-heartbeat', label: 'Retry heartbeat check' },
    secondary: { action: 'goto-agents', label: 'Open Agents page' },
  },
});

/**
 * @param {{
 *   id?: string,
 *   message: string,
 *   hint?: string | null,
 *   primary?: { action: string, label: string } | null,
 *   secondary?: { action: string, label: string } | null,
 * }} config
 */
export function renderFriendlyEmptyState(config) {
  const primary = config.primary
    ? `<button type="button" class="btn" data-action="${esc(config.primary.action)}">${esc(config.primary.label)}</button>`
    : '';
  const secondary = config.secondary
    ? `<button type="button" class="btn secondary" data-action="${esc(config.secondary.action)}">${esc(config.secondary.label)}</button>`
    : '';
  const hint = config.hint
    ? `<p class="muted friendly-empty-hint">${esc(config.hint)}</p>`
    : '';
  const pageAttr = config.id ? ` data-empty-page="${esc(config.id)}"` : '';
  return `<div class="empty friendly-empty"${pageAttr}>
    <p class="friendly-empty-message">${esc(config.message)}</p>
    ${hint}
    <div class="friendly-empty-actions">${primary}${secondary}</div>
  </div>`;
}

function esc(text) {
  return String(text ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;');
}

function notificationAttempts(events = []) {
  return events.flatMap((event) => {
    const attempts = Array.isArray(event?.delivery_attempts) ? event.delivery_attempts : [];
    return attempts.map((attempt) => ({
      event_id: event.id,
      trigger: event.trigger,
      created_at: event.created_at,
      ...attempt,
    }));
  });
}

/**
 * @param {{ rules?: object[], events?: object[] }} data
 * @param {{ lastRetryResult?: object|null }} [options]
 */
export function renderNotificationOpsPanel(data = {}, options = {}) {
  const canWrite = options.canWrite === true;
  const attempts = notificationAttempts(data.events ?? []);
  const retryItems = attempts.filter((a) => a.status === 'provider_retry_scheduled');
  const dlqItems = attempts.filter((a) => a.status === 'provider_failed_dlq');
  const statusCounts = attempts.reduce((acc, attempt) => {
    const status = String(attempt.status ?? 'unknown');
    acc[status] = (acc[status] ?? 0) + 1;
    return acc;
  }, {});
  const countRows = Object.entries(statusCounts)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([status, count]) => `<tr><td><code>${esc(status)}</code></td><td>${count}</td></tr>`)
    .join('');

  const safeAttemptRows = dlqItems.slice(-8).reverse().map((attempt) => {
    const reason = String(attempt.reason ?? attempt.provider_error ?? '—').slice(0, 80);
    const attemptId = String(attempt.id ?? '');
    const redriveBtn = canWrite && attemptId
      ? `<button type="button" class="btn secondary btn-sm" data-action="redrive-notification-dlq" data-attempt-id="${esc(attemptId)}" data-dry-run="false">Redrive</button>`
      : '—';
    return `<tr>
      <td><code>${esc(attempt.event_id ?? '—')}</code></td>
      <td><code>${esc(attempt.rule_id ?? '—')}</code></td>
      <td>${esc(attempt.channel ?? '—')}</td>
      <td>${esc(attempt.destination_preview ?? 'metadata-only')}</td>
      <td>${esc(reason)}</td>
      <td>${esc(attempt.attempt_number ?? '—')} / ${esc(attempt.max_attempts ?? '—')}</td>
      <td>${redriveBtn}</td>
    </tr>`;
  }).join('');

  const result = options.lastRetryResult;
  const resultHtml = result
    ? `<p class="muted notification-retry-result">Last metadata-only retry run: due ${esc(result.due_count ?? 0)}, processed ${esc((result.processed ?? []).length ?? 0)}, dry-run ${esc(Boolean(result.dry_run))}.</p>`
    : '<p class="muted notification-retry-result">No retry processing run in this UI session.</p>';

  const redriveResult = options.lastRedriveResult;
  const redriveResultHtml = redriveResult
    ? `<p class="muted notification-redrive-result">Last DLQ redrive: requeued ${esc(redriveResult.requeued_count ?? 0)}, skipped ${esc(redriveResult.skipped_count ?? 0)}, still DLQ ${esc(redriveResult.still_dlq_count ?? 0)}, dry-run ${esc(Boolean(redriveResult.dry_run))}.</p>`
    : '<p class="muted notification-redrive-result">No DLQ redrive run in this UI session.</p>';

  const dlqTable = dlqItems.length
    ? `<table class="notification-dlq-table"><thead><tr><th>Event</th><th>Rule</th><th>Channel</th><th>Destination preview</th><th>Reason</th><th>Attempt</th><th>Action</th></tr></thead><tbody>${safeAttemptRows}</tbody></table>`
    : '<p class="muted notification-dlq-empty">No DLQ attempts in the recent notification ledger.</p>';

  return `<section class="notification-ops-panel">
    <h4>Delivery operations</h4>
    <p class="muted">Developer-validation visibility only. Retry and DLQ redrive from this page are metadata-only through HTTP/UI. Production provider redrive requires governed operator execution, staging delivery evidence, an externally scheduled runner, and explicit <code>ASTRANULL_NOTIFICATION_DELIVERY_MODE</code> configuration outside this UI path.</p>
    <div class="notification-ops-summary">
      <span>Rules: <strong>${esc((data.rules ?? []).length)}</strong></span>
      <span>Events: <strong>${esc((data.events ?? []).length)}</strong></span>
      <span>Retry scheduled: <strong>${retryItems.length}</strong></span>
      <span>DLQ: <strong>${dlqItems.length}</strong></span>
    </div>
    ${countRows ? `<table class="notification-status-table"><thead><tr><th>Status</th><th>Attempts</th></tr></thead><tbody>${countRows}</tbody></table>` : '<p class="muted">No delivery attempts recorded yet.</p>'}
    ${canWrite ? `<div class="notification-retry-actions">
      <button type="button" class="btn secondary" data-action="process-notification-retries" data-dry-run="true">Preview due retries</button>
      <button type="button" class="btn" data-action="process-notification-retries" data-dry-run="false">Process due retries (metadata-only)</button>
    </div>` : '<p class="muted notification-retry-actions">Notification write access is required to process retries or redrive DLQ attempts.</p>'}
    ${resultHtml}
    ${redriveResultHtml}
    <h5>DLQ attempts</h5>
    ${dlqTable}
  </section>`;
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

export const PLACEMENT_STATUS_LABELS = Object.freeze({
  proven: 'Proven',
  needs_baseline: 'Needs baseline',
  missing_agent: 'Missing agent',
  misplaced_risk: 'Misplaced risk',
});

/**
 * @param {object} readiness
 * @returns {object|null}
 */
export function extractPlacementDiagnosticsFromReadiness(readiness) {
  const factor = readiness?.factors?.find((f) => f.key === 'agent_placement');
  return factor?.placement_diagnostics ?? null;
}

/**
 * @param {object|null} diagnostics
 * @param {{ compact?: boolean, heading?: string }} [opts]
 */
export function renderPlacementDiagnosticsPanel(diagnostics, opts = {}) {
  const heading = opts.heading ?? 'Placement diagnostics';
  const compact = Boolean(opts.compact);
  if (!diagnostics) {
    return `<section class="card placement-diagnostics-panel placement-diagnostics-panel--empty" aria-labelledby="placementDiagnosticsHeading">
      <h3 id="placementDiagnosticsHeading">${esc(heading)}</h3>
      <p class="muted">Placement diagnostics are not available yet. Declare target groups and register bound agents to establish baseline evidence.</p>
    </section>`;
  }

  const groups = diagnostics.groups ?? [];
  const summary = diagnostics.summary ?? '';
  const unboundCount = diagnostics.unbound_online_agent_count ?? 0;
  const counts = [
    ['proven', diagnostics.proven ?? 0],
    ['needs_baseline', diagnostics.needs_baseline ?? 0],
    ['missing_agent', diagnostics.missing_agent ?? 0],
    ['misplaced_risk', diagnostics.misplaced_risk ?? 0],
  ];
  const countBadges = counts
    .map(([status, count]) => {
      const label = PLACEMENT_STATUS_LABELS[status] ?? status;
      return `<span class="placement-status-pill placement-status-pill--${esc(status)}">${esc(label)}: ${esc(count)}</span>`;
    })
    .join('');

  if (groups.length === 0) {
    return `<section class="card placement-diagnostics-panel${compact ? ' placement-diagnostics-panel--compact' : ''}" aria-labelledby="placementDiagnosticsHeading">
      <h3 id="placementDiagnosticsHeading">${esc(heading)}</h3>
      <p class="muted">${esc(summary)}</p>
      <div class="placement-status-row">${countBadges}</div>
      ${unboundCount > 0 ? `<p class="muted placement-unbound-note">${esc(unboundCount)} online agent(s) are not bound to a declared target group.</p>` : ''}
    </section>`;
  }

  const rows = groups
    .map((g) => {
      const statusLabel = PLACEMENT_STATUS_LABELS[g.status] ?? g.status;
      const warnings = (g.warnings ?? []).join(', ');
      const bound = (g.bound_agent_ids ?? []).length;
      const online = (g.online_bound_agent_ids ?? []).length;
      const obs = g.recent_observation_count ?? 0;
      return `<tr>
        <td>${esc(g.target_group_name ?? g.target_group_id)}</td>
        <td><span class="placement-status-pill placement-status-pill--${esc(g.status)}">${esc(statusLabel)}</span></td>
        <td>${esc(bound)} bound · ${esc(online)} online</td>
        <td>${esc(obs)}</td>
        <td class="muted">${esc(warnings || '—')}</td>
      </tr>`;
    })
    .join('');

  return `<section class="card placement-diagnostics-panel${compact ? ' placement-diagnostics-panel--compact' : ''}" aria-labelledby="placementDiagnosticsHeading">
    <h3 id="placementDiagnosticsHeading">${esc(heading)}</h3>
    <p class="muted">${esc(summary)}</p>
    <div class="placement-status-row">${countBadges}</div>
    ${unboundCount > 0 ? `<p class="muted placement-unbound-note">${esc(unboundCount)} online agent(s) are not bound to a declared target group — they do not prove placement for declared groups.</p>` : ''}
    <table class="placement-diagnostics-table">
      <thead><tr><th>Target group</th><th>Status</th><th>Agents</th><th>Recent obs.</th><th>Warnings</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
    <p class="muted placement-diagnostics-note">Developer-validation diagnostics only — staging/live baseline evidence is required for production placement signoff.</p>
  </section>`;
}

/**
 * @param {object|null} diagnostics
 */
export function renderPlacementGuideLink(diagnostics) {
  const needsAction = (diagnostics?.needs_baseline ?? 0) > 0
    || (diagnostics?.missing_agent ?? 0) > 0
    || (diagnostics?.misplaced_risk ?? 0) > 0;
  if (!needsAction) return '';
  return `<p class="muted placement-guide-link">See <a href="https://docs.astranull.example/agent/placement-guide" rel="noopener noreferrer">Agent placement guide</a> for host, canary, mirror, and log-tail modes.</p>`;
}

/**
 * @param {object[]} agents
 * @param {object[]} [targetGroups]
 */
export const TARGET_GROUP_DETAIL_TABS = Object.freeze([
  { id: 'targets', label: 'Targets' },
  { id: 'runs', label: 'Recent runs' },
  { id: 'settings', label: 'Settings' },
]);

export const TARGET_KIND_OPTIONS = Object.freeze([
  'fqdn',
  'url',
  'ip',
  'dns',
  'canary',
]);

export const EXPECTED_BEHAVIOR_OPTIONS = Object.freeze([
  { id: 'must_block_before_origin', label: 'Must block before origin' },
  { id: 'must_allow', label: 'Must allow' },
  { id: 'must_challenge', label: 'Must challenge' },
  { id: 'must_rate_limit', label: 'Must rate limit' },
  { id: 'no_observe', label: 'No observe' },
]);

/**
 * @param {object} detail
 * @param {object[]} [runs]
 * @param {object[]} [agents]
 * @param {string} [activeTab]
 * @param {{ canWrite?: boolean, canRun?: boolean }} [options]
 */
export function renderTargetGroupDetailPanel(detail, runs = [], agents = [], activeTab = 'targets', options = {}) {
  const canWrite = options.canWrite === true;
  const canRun = options.canRun === true;
  const tab = TARGET_GROUP_DETAIL_TABS.some((t) => t.id === activeTab) ? activeTab : 'targets';
  const safety = detail.safety_policy ?? {};
  const maxRuns = safety.max_runs_per_hour ?? 60;
  const minSeconds = safety.min_seconds_between_runs ?? 0;
  const linkedAgents = (agents || []).filter((a) => a.target_group_id === detail.id);
  const agentSummary = linkedAgents.length
    ? linkedAgents.map((a) => `${esc(a.name ?? a.id)} · ${esc(a.status)}`).join(', ')
    : '<span class="muted">No agents bound — install one for placement evidence.</span>';

  const tabs = TARGET_GROUP_DETAIL_TABS.map((t) => {
    const active = t.id === tab ? ' active' : '';
    return `<button type="button" class="tab tg-tab${active}" data-tg-tab="${esc(t.id)}">${esc(t.label)}</button>`;
  }).join('');

  const kindOptions = (selected) => TARGET_KIND_OPTIONS.map((k) => {
    const selectedAttr = k === selected ? ' selected' : '';
    return `<option value="${esc(k)}"${selectedAttr}>${esc(k)}</option>`;
  }).join('');

  const behaviorOptions = (selected) => EXPECTED_BEHAVIOR_OPTIONS.map((b) => {
    const selectedAttr = b.id === selected ? ' selected' : '';
    return `<option value="${esc(b.id)}"${selectedAttr}>${esc(b.label)}</option>`;
  }).join('');

  const targetFieldAttrs = canWrite ? '' : ' disabled';
  const targetActionsCell = canWrite
    ? (t) => `<td class="tg-target-actions">
          <button type="button" class="btn secondary" data-action="tg-target-save" data-id="${esc(t.id)}" data-group-id="${esc(detail.id)}">Save</button>
          <button type="button" class="btn secondary" data-action="tg-target-delete" data-id="${esc(t.id)}" data-group-id="${esc(detail.id)}">Delete</button>
        </td>`
    : () => '<td class="muted">Read-only</td>';
  const targetsTab = (detail.targets || []).length
    ? `<table class="tg-targets-table"><thead><tr>
        <th>Type</th><th>Value</th><th>Expected behavior</th>${canWrite ? '<th>Actions</th>' : ''}
      </tr></thead><tbody>${(detail.targets || []).map((t) => `<tr>
        <td><select id="tgTargetKind_${esc(t.id)}" class="tg-target-field"${targetFieldAttrs}>${kindOptions(t.kind || 'fqdn')}</select></td>
        <td><input type="text" id="tgTargetValue_${esc(t.id)}" class="tg-target-field" value="${esc(t.value)}"${targetFieldAttrs} /></td>
        <td><select id="tgTargetBehavior_${esc(t.id)}" class="tg-target-field"${targetFieldAttrs}>${behaviorOptions(t.expected_behavior || detail.expected_behavior_default || 'must_block_before_origin')}</select></td>
        ${targetActionsCell(t)}
      </tr>`).join('')}</tbody></table>`
    : '<p class="muted">No declared targets yet — add one in Onboarding.</p>';

  const runsTab = runs.length
    ? `<table class="tg-runs-table"><thead><tr>
        <th>Run</th><th>Status</th><th>Check</th><th>Created</th>
      </tr></thead><tbody>${runs.slice(-10).reverse().map((r) => `<tr>
        <td><code>${esc(r.id)}</code></td>
        <td>${esc(r.status)}</td>
        <td><code>${esc(r.check_id || '—')}</code></td>
        <td>${esc(formatUtcShort(r.created_at))}</td>
      </tr>`).join('')}</tbody></table>`
    : '<p class="muted">No runs for this group yet.</p>';

  const settingsFieldAttrs = canWrite ? '' : ' disabled';
  const settingsActions = canWrite
    ? `<div class="form-actions">
      <button type="button" class="btn" data-action="tg-save-settings" data-id="${esc(detail.id)}">Save settings</button>
      <button type="button" class="btn secondary" data-action="tg-archive" data-id="${esc(detail.id)}">Archive group</button>
    </div>
    <p class="muted tg-archive-hint">Archiving removes the group from active validation. Active runs block archive.</p>`
    : '<p class="muted">Settings are read-only for your role.</p>';
  const settingsTab = `<form class="tg-settings-form" id="tgSettingsForm" onsubmit="return false">
    <label>Name <input type="text" id="tgSettingsName" value="${esc(detail.name)}"${settingsFieldAttrs} /></label>
    <label>Description <textarea id="tgSettingsDescription" rows="3"${settingsFieldAttrs}>${esc(detail.description || '')}</textarea></label>
    <fieldset class="tg-safety-policy">
      <legend>Safety policy</legend>
      <label>Max runs per hour <input type="number" id="tgSettingsMaxRuns" min="1" max="240" value="${esc(maxRuns)}"${settingsFieldAttrs} /></label>
      <label>Min seconds between runs <input type="number" id="tgSettingsMinSeconds" min="0" max="3600" value="${esc(minSeconds)}"${settingsFieldAttrs} /></label>
    </fieldset>
    ${settingsActions}
  </form>`;

  const tabPanels = {
    targets: targetsTab,
    runs: runsTab,
    settings: settingsTab,
  };

  return `<div class="card tg-detail-panel" id="tgDetail" data-active-tg-tab="${esc(tab)}">
    <h3>${esc(detail.name)}</h3>
    <p class="muted">Owner: ${esc(detail.owner || '—')} · Criticality: ${esc(detail.criticality || '—')} · Linked agents: ${agentSummary}</p>
    <div class="tabs tg-detail-tabs" role="tablist">${tabs}</div>
    <div class="tg-detail-tab-panel" data-tg-tab-panel="${esc(tab)}">${tabPanels[tab]}</div>
    <div class="friendly-empty-actions">
      ${canRun ? `<button type="button" class="btn" data-action="start-run" data-group-id="${esc(detail.id)}">Run safe validation</button>` : ''}
      <button type="button" class="btn secondary" data-action="goto-agents">Install agent</button>
    </div>
  </div>`;
}

export function renderAgentFleetTable(agents, targetGroups = []) {
  const tgById = Object.fromEntries((targetGroups || []).map((g) => [g.id, g.name ?? g.id]));
  if (!agents?.length) {
    return renderFriendlyEmptyState(PAGE_EMPTY_STATES.agents);
  }
  const rows = agents
    .map((a) => {
      const tgLabel = a.target_group_id ? (tgById[a.target_group_id] ?? a.target_group_id) : '—';
      const placement = a.placement_type ?? ((a.capabilities || []).join(', ') || '—');
      return `<tr>
        <td>${esc(a.name ?? a.id)}</td>
        <td>${esc(a.status)}</td>
        <td>${esc(placement)}</td>
        <td>${esc(tgLabel)}</td>
        <td>${esc(a.version ?? '—')}</td>
        <td>${esc(a.last_heartbeat_at ?? '—')}</td>
      </tr>`;
    })
    .join('');
  return `<table class="agent-fleet-table"><thead><tr><th>Name</th><th>Status</th><th>Placement</th><th>Target group</th><th>Version</th><th>Last heartbeat</th></tr></thead><tbody>${rows}</tbody></table>`;
}

/**
 * @param {object} check
 */
export function renderProbeProfileKind(check) {
  const profile = check?.probe_profile;
  if (!profile) {
    return check?.risk_class === 'soc_gated' ? 'SOC-gated' : '—';
  }
  const kind = profile.kind ?? 'unknown';
  const maxReq = profile.max_requests != null ? ` · max ${profile.max_requests}` : '';
  return `${kind}${maxReq}`;
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
 * @param {object | null | undefined} agent
 * @param {number} [nowMs]
 */
export function agentHasRecentHeartbeat(agent, nowMs = Date.now()) {
  if (!agent || agent.status !== 'online') return false;
  const hb = agent.last_heartbeat_at;
  if (!hb) return false;
  const age = nowMs - Date.parse(hb);
  return Number.isFinite(age) && age >= 0 && age < ONBOARDING_HEARTBEAT_TIMEOUT_MS;
}

/**
 * @param {object[]} agents
 * @param {{ nowMs?: number, pollStartedAt?: number }} [opts]
 */
export function resolveOnboardingHeartbeatState(agents, opts = {}) {
  const nowMs = opts.nowMs ?? Date.now();
  const startedAt = opts.pollStartedAt ?? nowMs;
  const list = agents || [];
  const online = list.filter((a) => agentHasRecentHeartbeat(a, nowMs));
  const elapsedMs = Math.max(0, nowMs - startedAt);
  if (online.length) {
    return { status: 'online', agents: online, elapsedMs };
  }
  if (elapsedMs >= ONBOARDING_HEARTBEAT_TIMEOUT_MS) {
    return { status: 'timeout', agents: list, elapsedMs };
  }
  const stale = list.some((a) => a.last_heartbeat_at && !agentHasRecentHeartbeat(a, nowMs));
  return { status: stale ? 'stale' : 'waiting', agents: list, elapsedMs };
}

/**
 * @param {object | null | undefined} agent
 * @param {object | null | undefined} readinessDiagnostics
 */
export function summarizeOnboardingPlacementConfidenceHint(agent, readinessDiagnostics) {
  if (readinessDiagnostics?.groups?.some((g) => g.status === 'proven')) {
    return 'Placement confidence is supported: baseline traffic was observed for a declared target group.';
  }
  if (agent?.capabilities?.includes?.('canary')) {
    return 'Canary-capable agent detected — placement confidence improves when protected-path canary traffic is observed.';
  }
  if (readinessDiagnostics?.groups?.some((g) => g.status === 'needs_baseline')) {
    return 'Placement confidence is limited until baseline or canary traffic is seen — run the optional placement test.';
  }
  if (agent) {
    return 'Heartbeat received. Run the optional placement test to strengthen placement confidence before the first validation.';
  }
  return 'Placement confidence cannot be proven yet — verify agent bind, observation mode, and protected-path visibility.';
}

/**
 * @param {ReturnType<typeof resolveOnboardingHeartbeatState>} state
 * @param {{ placementHint?: string, allowSkip?: boolean }} [opts]
 */
export function renderOnboardingHeartbeatPanel(state, opts = {}) {
  const placementHint = opts.placementHint
    ? `<p class="muted onboarding-placement-hint"><strong>Placement confidence:</strong> ${esc(opts.placementHint)}</p>`
    : '';
  if (state.status === 'online') {
    const agent = state.agents[0];
    return `<div class="onboarding-heartbeat-panel onboarding-heartbeat-panel--online" id="onboardingHeartbeatPanel">
      <p class="onboarding-heartbeat-status onboarding-heartbeat-status--online">
        Agent online — last heartbeat ${esc(agent?.last_heartbeat_at ?? 'received')}.
      </p>
      ${placementHint}
      <p class="muted">Proceed to the optional placement test or start the first safe validation.</p>
    </div>`;
  }
  if (state.status === 'timeout') {
    const skip = opts.allowSkip
      ? `<button type="button" class="btn secondary" data-action="onboard-skip-heartbeat">Continue without agent</button>`
      : '';
    return `<div class="onboarding-heartbeat-panel onboarding-heartbeat-panel--timeout" id="onboardingHeartbeatPanel">
      ${renderFriendlyEmptyState(PAGE_EMPTY_STATES.onboarding_heartbeat)}
      ${skip}
    </div>`;
  }
  const statusLabel = state.status === 'stale'
    ? 'Agent registered but heartbeat is stale — waiting for a fresh heartbeat…'
    : 'Waiting for agent heartbeat…';
  const seconds = Math.floor((state.elapsedMs ?? 0) / 1000);
  return `<div class="onboarding-heartbeat-panel onboarding-heartbeat-panel--waiting" id="onboardingHeartbeatPanel">
    <p class="onboarding-heartbeat-status onboarding-heartbeat-status--waiting" aria-live="polite">
      <span class="onboarding-heartbeat-spinner" aria-hidden="true"></span>
      ${esc(statusLabel)}
    </p>
    <p class="muted">Polling <code>GET /v1/agents</code> every ${ONBOARDING_HEARTBEAT_POLL_MS / 1000}s (elapsed ${seconds}s).</p>
    ${placementHint}
    <p class="muted onboarding-troubleshoot">Agent not connecting?
      <button type="button" class="btn secondary" data-action="goto-agents">Open Agents page</button>
      <button type="button" class="btn secondary" data-action="goto-settings">Regenerate token</button>
    </p>
  </div>`;
}

/**
 * @param {{ placementTestDone?: boolean }} [opts]
 */
export function renderOnboardingPlacementTestPanel(opts = {}) {
  if (opts.placementTestDone) {
    return `<p class="muted onboarding-placement-done">Placement test run started — inspect observations on Test Runs when complete.</p>`;
  }
  return `<p class="muted">Runs a bounded protected-path canary check (<code>${esc(ONBOARDING_PLACEMENT_TEST_CHECK_ID)}</code>) — metadata only, no exploit payloads.</p>
    <button type="button" class="btn" data-action="onboard-start-placement-test">Start placement test</button>
    <p class="muted">Optional — skip if you will run the first safe validation immediately after heartbeat verification.</p>`;
}

/**
 * @param {{ environments: object[], targetGroups: object[], targets: object[], agents: object[], runs: object[], hasToken: boolean, heartbeatSkipped?: boolean }} ctx
 */
export function computeOnboardingProgress(ctx) {
  const nowMs = ctx.nowMs ?? Date.now();
  const checks = {
    environment: (ctx.environments || []).length > 0,
    target_group: (ctx.targetGroups || []).length > 0,
    target: (ctx.targets || []).length > 0,
    token: Boolean(ctx.hasToken),
    install: (ctx.agents || []).length > 0,
    verify_heartbeat: Boolean(ctx.heartbeatSkipped)
      || (ctx.agents || []).some((a) => agentHasRecentHeartbeat(a, nowMs)),
    placement_test: (ctx.runs || []).some((r) =>
      r.check_id === ONBOARDING_PLACEMENT_TEST_CHECK_ID
      && ['completed', 'verdicted', 'running'].includes(r.status)),
    safe_run: (ctx.runs || []).some((r) =>
      r.check_id !== ONBOARDING_PLACEMENT_TEST_CHECK_ID
      && ['completed', 'verdicted', 'running'].includes(r.status)),
    review: (ctx.runs || []).some((r) => r.status === 'verdicted'),
  };
  const steps = ONBOARDING_STEPS.map((step) => ({
    ...step,
    done: checks[step.id] === true,
    optional: step.id === 'install' || step.id === 'placement_test',
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
 * @param {{
 *   tokenSecret?: string | null,
 *   targetValue?: string,
 *   heartbeatState?: ReturnType<typeof resolveOnboardingHeartbeatState>,
 *   placementHint?: string,
 *   heartbeatAllowSkip?: boolean,
 *   placementTestDone?: boolean,
 * }} opts
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
      <p class="muted">Agent not required for the first safe run in developer validation, but improves placement evidence.</p>
      <p class="muted onboarding-troubleshoot">Agent not connecting? Verify outbound HTTPS to the API, NTP clock sync, and that the bootstrap token has not expired.
        <button type="button" class="btn secondary" data-action="goto-agents">Open Agents page</button>
        <button type="button" class="btn secondary" data-action="goto-settings">Regenerate token</button>
      </p>`,
    verify_heartbeat: `<p class="muted">${esc(active.hint)}</p>
      ${renderOnboardingHeartbeatPanel(
        opts.heartbeatState ?? { status: 'waiting', agents: [], elapsedMs: 0 },
        { placementHint: opts.placementHint, allowSkip: opts.heartbeatAllowSkip },
      )}`,
    placement_test: `<p class="muted">${esc(active.hint)}</p>
      ${opts.placementHint ? `<p class="muted onboarding-placement-hint"><strong>Placement confidence:</strong> ${esc(opts.placementHint)}</p>` : ''}
      ${renderOnboardingPlacementTestPanel({ placementTestDone: opts.placementTestDone })}`,
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

/** Allowed WAF drift workflow states (matches PATCH /v1/waf/drift-events/:id). */
export const WAF_DRIFT_WORKFLOW_STATUSES = Object.freeze([
  'open',
  'acknowledged',
  'remediation_started',
  'retest_pending',
  'resolved',
  'accepted_risk',
  'false_positive',
]);

const WAF_DRIFT_SUMMARY_FIELD_MAX = 48;
const WAF_DRIFT_REASON_CODE_MAX = 6;
const WAF_DRIFT_REASON_CODE_LEN_MAX = 40;

function boundWafDriftSummaryField(value, maxLen = WAF_DRIFT_SUMMARY_FIELD_MAX) {
  if (typeof value !== 'string') return '';
  const trimmed = value.trim();
  if (!trimmed) return '';
  return trimmed.length > maxLen ? `${trimmed.slice(0, maxLen)}…` : trimmed;
}

/**
 * Coarse safe summary for drift before/after snapshots (no raw evidence).
 * @param {Record<string, unknown>|null|undefined} summary
 */
export function summarizeWafDriftPostureSummary(summary) {
  if (!summary || typeof summary !== 'object' || Array.isArray(summary)) return '—';
  const parts = [];
  const status = boundWafDriftSummaryField(summary.status);
  if (status) parts.push(`status: ${status}`);
  if (Array.isArray(summary.reason_codes) && summary.reason_codes.length) {
    const codes = summary.reason_codes
      .filter((c) => typeof c === 'string')
      .map((c) => boundWafDriftSummaryField(c, WAF_DRIFT_REASON_CODE_LEN_MAX))
      .filter(Boolean)
      .slice(0, WAF_DRIFT_REASON_CODE_MAX);
    if (codes.length) parts.push(`reasons: ${codes.join(', ')}`);
  }
  const product = boundWafDriftSummaryField(
    (typeof summary.detected_product === 'string' && summary.detected_product)
    || (typeof summary.product === 'string' && summary.product)
    || '',
  );
  if (product) parts.push(`product: ${product}`);
  const vendor = boundWafDriftSummaryField(
    typeof summary.detected_vendor === 'string' ? summary.detected_vendor : '',
  );
  if (vendor) parts.push(`vendor: ${vendor}`);
  const confidenceStr = boundWafDriftSummaryField(
    typeof summary.confidence === 'string' ? summary.confidence : '',
  );
  if (confidenceStr) {
    parts.push(`confidence: ${confidenceStr}`);
  } else if (typeof summary.confidence === 'number' && Number.isFinite(summary.confidence)) {
    parts.push(`confidence: ${Math.round(summary.confidence * 100)}%`);
  }
  if (summary.waf_detected === true) parts.push('waf_detected: yes');
  if (summary.waf_detected === false) parts.push('waf_detected: no');
  const joined = parts.join(' · ');
  return joined.length > 220 ? `${joined.slice(0, 217)}…` : joined || '—';
}

/** Allowlisted connector config keys (metadata-only; matches backend CONNECTOR_CONFIG_SAFE_KEYS). */
const WAF_CONNECTOR_CONFIG_SAFE_KEYS = new Set([
  'account_ref_hash',
  'zone_ref_hash',
  'resource_ref_hash',
  'default_snapshot_kind',
  'read_only',
  'owner_hint',
  'tag_summary',
  'polling_interval_minutes',
  'region_summary',
  'notes_hash',
]);

const WAF_CONNECTOR_META_FIELD_MAX = 64;
const WAF_CONNECTOR_HEALTH_SUMMARY_MAX = 220;

function boundConnectorMetaField(value, maxLen = WAF_CONNECTOR_META_FIELD_MAX) {
  if (value == null) return '';
  const trimmed = String(value).trim();
  if (!trimmed) return '';
  return trimmed.length > maxLen ? `${trimmed.slice(0, maxLen)}…` : trimmed;
}

/**
 * Resolve last successful poll timestamp from connector API metadata.
 * @param {Record<string, unknown>|null|undefined} connector
 */
export function resolveWafConnectorLastPollAt(connector) {
  if (!connector || typeof connector !== 'object' || Array.isArray(connector)) return null;
  if (connector.last_poll_at) return connector.last_poll_at;
  return connector.last_success_at ?? null;
}

/**
 * Metadata-only connector health summary (no secrets, raw config bodies, or snapshot payloads).
 * @param {Record<string, unknown>|null|undefined} connector
 */
export function summarizeWafConnectorHealthSummary(connector) {
  if (!connector || typeof connector !== 'object' || Array.isArray(connector)) return '—';
  const parts = [];
  const status = boundConnectorMetaField(connector.status, 32);
  if (status) parts.push(`status: ${status}`);

  const config = connector.config;
  if (config && typeof config === 'object' && !Array.isArray(config)) {
    if (config.read_only === true) parts.push('read_only: yes');
    else if (config.read_only === false) parts.push('read_only: no');
    if (Number.isFinite(config.polling_interval_minutes) && config.polling_interval_minutes > 0) {
      parts.push(`poll_interval_min: ${Math.floor(config.polling_interval_minutes)}`);
    }
    const ownerHint = boundConnectorMetaField(config.owner_hint, 48);
    if (ownerHint) parts.push(`owner: ${ownerHint}`);
    for (const key of WAF_CONNECTOR_CONFIG_SAFE_KEYS) {
      if (key === 'read_only' || key === 'owner_hint' || key === 'polling_interval_minutes') continue;
      const value = config[key];
      if (value == null || value === '') continue;
      parts.push(`${key}: configured`);
    }
  }

  const hasCredential = Boolean(
    typeof connector.secret_id === 'string' && connector.secret_id.trim(),
  );
  parts.push(`outbound_credential: ${hasCredential ? 'configured' : 'none'}`);

  const lastErrorAt = connector.last_error_at;
  if (
    lastErrorAt
    && ['error', 'degraded', 'rate_limited', 'permission_insufficient', 'revoked'].includes(status)
  ) {
    parts.push(`last_error_at: ${boundConnectorMetaField(formatUtcShort(lastErrorAt), 32)}`);
  }

  const joined = parts.join(' · ');
  return joined.length > WAF_CONNECTOR_HEALTH_SUMMARY_MAX
    ? `${joined.slice(0, WAF_CONNECTOR_HEALTH_SUMMARY_MAX - 1)}…`
    : joined || '—';
}

export const WAF_CONNECTOR_POLL_ERROR_GUIDANCE = Object.freeze({
  connector_poll_failed:
    'Outbound connector poll failed. Manual metadata snapshot ingest may still work when snapshots are supplied.',
  connector_not_found: 'Connector was not found in this tenant scope.',
  waf_feature_disabled: 'WAF connectors are disabled in this environment.',
});

/**
 * @param {Record<string, unknown>|null|undefined} result
 */
export function summarizeWafConnectorPollResult(result) {
  const payload = result && typeof result === 'object' && !Array.isArray(result) ? result : {};
  const summary = { ok: true };
  const pollJob = payload.poll_job;
  if (pollJob && typeof pollJob === 'object' && !Array.isArray(pollJob)) {
    const job = {};
    const id = boundConnectorMetaField(pollJob.id, 64);
    const status = boundConnectorMetaField(pollJob.status, 32);
    if (id) job.id = id;
    if (status) job.status = status;
    if (Number.isFinite(pollJob.snapshot_count)) job.snapshot_count = pollJob.snapshot_count;
    const health = pollJob.health;
    if (health && typeof health === 'object' && !Array.isArray(health)) {
      const safeHealth = {};
      const healthStatus = boundConnectorMetaField(health.status, 32);
      const healthCode = boundConnectorMetaField(health.health_code, 64);
      if (healthStatus) safeHealth.status = healthStatus;
      if (healthCode) safeHealth.health_code = healthCode;
      if (Number.isFinite(health.attempts)) safeHealth.attempts = health.attempts;
      if (Object.keys(safeHealth).length) job.health = safeHealth;
    } else if (Number.isFinite(pollJob.attempts)) {
      job.attempts = pollJob.attempts;
    }
    if (Object.keys(job).length) summary.poll_job = job;
  }
  if (Array.isArray(payload.snapshots)) {
    summary.snapshots_count = payload.snapshots.length;
  }
  return summary;
}

/**
 * @param {{ message?: string, pollMessage?: string, pollHealth?: Record<string, unknown> }|null|undefined} err
 */
export function summarizeWafConnectorPollError(err) {
  const codeOrMessage = boundConnectorMetaField(err?.message, 120) || 'Connector poll failed.';
  const guidance = WAF_CONNECTOR_POLL_ERROR_GUIDANCE[codeOrMessage];
  const summary = { ok: false, error: codeOrMessage };
  if (guidance) summary.guidance = guidance;
  const pollMessage = boundConnectorMetaField(err?.pollMessage, 160);
  if (pollMessage && pollMessage !== codeOrMessage) summary.message = pollMessage;
  const health = err?.pollHealth;
  if (health && typeof health === 'object' && !Array.isArray(health)) {
    const safeHealth = {};
    const healthStatus = boundConnectorMetaField(health.status, 32);
    const healthCode = boundConnectorMetaField(health.health_code, 64);
    if (healthStatus) safeHealth.status = healthStatus;
    if (healthCode) safeHealth.health_code = healthCode;
    if (Number.isFinite(health.attempts)) safeHealth.attempts = health.attempts;
    if (Object.keys(safeHealth).length) summary.health = safeHealth;
  }
  return summary;
}

export const WAF_REPORT_EXPORT_KINDS = Object.freeze([
  { id: 'executive_coverage', label: 'Executive coverage' },
  { id: 'technical_evidence', label: 'Technical evidence' },
  { id: 'drift_audit', label: 'Drift audit' },
  { id: 'connector_health', label: 'Connector health' },
]);

/**
 * @param {object[]} items
 * @returns {Record<string, { id: string, status?: string }>}
 */
export function buildRetestMapByDriftEventId(items = []) {
  const map = {};
  for (const item of items) {
    if (!item?.drift_event_id || map[item.drift_event_id]) continue;
    map[item.drift_event_id] = { id: item.id, status: item.status };
  }
  return map;
}

function formatWafCoverageRatio(ratio) {
  const value = Number(ratio ?? 0);
  if (!Number.isFinite(value)) return '—';
  return `${Math.round(value * 10000) / 100}%`;
}

/**
 * @param {{ items?: object[] }} data
 */
export function renderWafCriticalityCard(data = {}) {
  const items = data.items ?? [];
  if (!items.length) {
    return `<div class="card waf-criticality-card">
      <h4>Criticality coverage</h4>
      <p class="muted">Rollup by declared <code>business_criticality</code> from posture snapshots.</p>
      <div class="empty">No WAF assets with declared criticality yet.</div>
    </div>`;
  }

  const rows = items.map((item) => `<tr>
    <td><code>${esc(item.business_criticality || 'unknown')}</code></td>
    <td>${item.asset_count ?? 0}</td>
    <td>${formatWafCoverageRatio(item.coverage_ratio)}</td>
    <td>${item.protected ?? 0}</td>
    <td>${item.underprotected ?? 0}</td>
    <td>${item.unprotected ?? 0}</td>
    <td>${item.critical_gap_count ?? 0}</td>
  </tr>`).join('');

  return `<div class="card waf-criticality-card">
    <h4>Criticality coverage</h4>
    <p class="muted">Coverage rollup by <code>business_criticality</code> (<code>GET /v1/waf/coverage/criticality</code>).</p>
    <table class="waf-criticality-table">
      <thead><tr>
        <th>Criticality</th><th>Assets</th><th>Coverage</th><th>Protected</th><th>Underprotected</th><th>Unprotected</th><th>Critical gaps</th>
      </tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>`;
}

export const WAF_POSTURE_TABS = Object.freeze([
  { id: 'overview', label: 'Overview' },
  { id: 'roadmap', label: 'Roadmap' },
  { id: 'assets', label: 'Assets' },
]);

const WAF_ROADMAP_TIER_META = Object.freeze({
  tier_1: { label: 'Tier 1', window: '0–14 days' },
  tier_2: { label: 'Tier 2', window: '15–60 days' },
  tier_3: { label: 'Tier 3', window: '61–180 days' },
  tier_4: { label: 'Tier 4', window: 'Quarterly review' },
});

const WAF_CONTROL_BYPASS_REASONS = new Set([
  'origin_bypass_confirmed',
  'marker_rule_not_blocking',
  'monitor_only_behavior',
  'validation_failed',
]);

/**
 * @param {string} assetId
 * @param {object[]} validations
 * @param {number} [lookbackDays]
 * @returns {number|null}
 */
export function computeWafAssetPassRate(assetId, validations = [], lookbackDays = 30) {
  if (!assetId || !validations.length) return null;
  const cutoff = new Date();
  cutoff.setUTCDate(cutoff.getUTCDate() - Math.max(1, lookbackDays));
  const cutoffIso = cutoff.toISOString();
  const relevant = validations.filter(
    (run) =>
      run.waf_asset_id === assetId
      && run.status === 'finalized'
      && String(run.finalized_at ?? run.created_at ?? '') >= cutoffIso,
  );
  if (!relevant.length) return null;
  const passed = relevant.filter((run) => run.summary_json?.validation_passed === true).length;
  return Math.round((passed / relevant.length) * 10000) / 100;
}

/**
 * @param {number|null|undefined} rate
 * @param {number} [lookbackDays]
 */
export function formatWafPassRateDisplay(rate, lookbackDays = 30) {
  if (rate == null || !Number.isFinite(Number(rate))) return '—';
  return `${Math.round(Number(rate) * 100) / 100}% (${lookbackDays}d)`;
}

/**
 * @param {object|null|undefined} effectiveness
 */
export function formatWafRuleHealthDisplay(effectiveness) {
  if (!effectiveness || typeof effectiveness !== 'object') return '—';
  const ruleCount = effectiveness.rule_count;
  if (!Number.isFinite(Number(ruleCount))) return '—';
  const count = Math.floor(Number(ruleCount));
  const updated = effectiveness.last_rule_update_at
    ? formatUtcShort(effectiveness.last_rule_update_at)
    : null;
  return updated ? `${count} rules · updated ${updated}` : `${count} rules`;
}

/**
 * @param {object|null|undefined} effectiveness
 * @param {string[]} [reasonCodes]
 */
export function resolveWafControlBypassStatus(effectiveness, reasonCodes = []) {
  const fromApi = typeof effectiveness?.control_bypass_status === 'string'
    ? effectiveness.control_bypass_status.trim().toLowerCase()
    : '';
  if (['none', 'suspected', 'confirmed'].includes(fromApi)) return fromApi;
  const codes = new Set((reasonCodes ?? []).map((code) => String(code).trim().toLowerCase()));
  if (codes.has('origin_bypass_confirmed')) return 'confirmed';
  if ([...codes].some((code) => WAF_CONTROL_BYPASS_REASONS.has(code))) return 'suspected';
  return 'none';
}

/**
 * @param {{ items?: object[], vendor_mix?: object[] }} data
 */
export function renderWafVendorMixCard(data = {}) {
  const mix = data.vendor_mix ?? data.items ?? [];
  if (!mix.length) {
    return `<div class="card waf-vendor-mix-card">
      <h4>Vendor mix</h4>
      <p class="muted">Protected asset share by detected WAF/CDN vendor (<code>GET /v1/waf/coverage/vendors</code>).</p>
      <div class="empty">No vendor detections yet. Finalize a validation with vendor metadata or connect a read-only WAF connector.</div>
    </div>`;
  }

  const rows = mix.map((item) => `<tr>
    <td><code>${esc(item.vendor ?? 'unknown')}</code></td>
    <td>${esc(item.product ?? '—')}</td>
    <td>${item.asset_count ?? 0}</td>
    <td>${item.protected_count ?? 0}</td>
    <td>${Number.isFinite(Number(item.protected_share_pct)) ? `${item.protected_share_pct}%` : '—'}</td>
  </tr>`).join('');

  return `<div class="card waf-vendor-mix-card">
    <h4>Vendor mix</h4>
    <p class="muted">Protected asset share by detected WAF/CDN vendor (<code>GET /v1/waf/coverage/vendors</code>).</p>
    <table class="waf-vendor-mix-table">
      <thead><tr>
        <th>Vendor</th><th>Product</th><th>Assets</th><th>Protected</th><th>Protected share</th>
      </tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>`;
}

/**
 * @param {{ items?: object[] }} data
 */
export function renderWafGeographyCard(data = {}) {
  const items = data.items ?? [];
  if (!items.length) {
    return `<div class="card waf-geography-card">
      <h4>Geography coverage</h4>
      <p class="muted">Rollup by declared region/country (<code>GET /v1/waf/coverage/geography</code>).</p>
      <div class="empty">No geography metadata yet. Declare <code>region_code</code> on target groups or asset owner hints.</div>
    </div>`;
  }

  const rows = items.map((item) => `<tr>
    <td><code>${esc(item.region_code ?? '—')}</code></td>
    <td>${esc(item.region_label ?? item.region_code ?? '—')}</td>
    <td>${item.asset_count ?? 0}</td>
    <td>${formatWafCoverageRatio(item.coverage_ratio)}</td>
    <td>${item.unprotected_critical_count ?? 0}</td>
  </tr>`).join('');

  return `<div class="card waf-geography-card">
    <h4>Geography coverage</h4>
    <p class="muted">Declared region/country rollups only — no geo-IP discovery (<code>GET /v1/waf/coverage/geography</code>).</p>
    <table class="waf-geography-table">
      <thead><tr>
        <th>Region</th><th>Label</th><th>Assets</th><th>Coverage</th><th>Unprotected critical</th>
      </tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>`;
}

function renderWafRoadmapTierSection(tierId, items = []) {
  const meta = WAF_ROADMAP_TIER_META[tierId] ?? { label: tierId, window: '' };
  if (!items.length) {
    return `<section class="waf-roadmap-tier waf-roadmap-tier--empty">
      <h5>${esc(meta.label)} <span class="muted">(${esc(meta.window)})</span></h5>
      <p class="muted">No assets in this tier.</p>
    </section>`;
  }

  const rows = items.map((item) => {
    const reasons = (item.primary_reason_codes ?? []).length
      ? item.primary_reason_codes.map((code) => `<code>${esc(code)}</code>`).join(', ')
      : '—';
    const factorDetails = `<details class="waf-roadmap-factors">
      <summary>Risk ${item.risk_score ?? '—'} · factors</summary>
      <p class="muted">Primary gaps: ${reasons}</p>
      <p class="muted">Recommended: ${esc(item.recommended_action ?? 'Review WAF posture gap.')}</p>
    </details>`;
    return `<tr>
      <td><code>${esc(item.hostname ?? item.waf_asset_id ?? '—')}</code></td>
      <td>${esc(item.owner_hint ?? '—')}</td>
      <td>${item.risk_score ?? '—'}</td>
      <td><span class="waf-status-pill waf-status-pill--${esc(String(item.posture_status ?? 'unknown').toLowerCase())}">${esc(item.posture_status ?? 'unknown')}</span></td>
      <td>${reasons}</td>
      <td>${esc(item.recommended_action ?? '—')}</td>
      <td><code>${esc(item.detected_vendor ?? 'none')}</code></td>
      <td>${factorDetails}</td>
    </tr>`;
  }).join('');

  return `<section class="waf-roadmap-tier">
    <h5>${esc(meta.label)} <span class="muted">(${esc(meta.window)})</span></h5>
    <table class="waf-roadmap-table">
      <thead><tr>
        <th>Asset</th><th>Owner</th><th>Risk</th><th>Status</th><th>Primary gap</th><th>Recommended action</th><th>Vendor</th><th>Breakdown</th>
      </tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </section>`;
}

/**
 * @param {{ tiers?: Record<string, object[]>, generated_at?: string, method?: string, emptyReason?: string }} data
 */
export function renderWafRoadmapPanel(data = {}) {
  const tiers = data.tiers ?? {};
  const tierIds = ['tier_1', 'tier_2', 'tier_3', 'tier_4'];
  const totalItems = tierIds.reduce((sum, tierId) => sum + (tiers[tierId]?.length ?? 0), 0);
  const generatedAt = data.generated_at ? formatUtcShort(data.generated_at) : '—';
  const method = data.method ? `<code>${esc(data.method)}</code>` : '—';

  if (!totalItems) {
    const emptyCopy = data.emptyReason === 'risk_not_run'
      ? 'Risk scoring has not produced roadmap tiers yet. Finalize validations on declared assets to seed risk scores.'
      : 'No roadmap items yet. Declare assets and finalize safe validations so risk scoring can rank deployment priorities.';
    return `<div class="card waf-roadmap-panel">
      <h4>Deployment roadmap</h4>
      <p class="muted">Tiered WAF deployment priorities from <code>GET /v1/waf/coverage/risk-roadmap</code>.</p>
      <div class="empty waf-roadmap-empty">${emptyCopy}</div>
    </div>`;
  }

  const tierSections = tierIds.map((tierId) => renderWafRoadmapTierSection(tierId, tiers[tierId] ?? [])).join('');
  return `<div class="card waf-roadmap-panel">
    <h4>Deployment roadmap</h4>
    <p class="muted">Tiered priorities from <code>GET /v1/waf/coverage/risk-roadmap</code> · generated ${esc(generatedAt)} · method ${method}</p>
    ${tierSections}
  </div>`;
}

/**
 * @param {string} activeTab
 */
/**
 * @param {{
 *   catalogSummary?: object|null,
 *   intakes?: object[],
 *   showIntakeForm?: boolean,
 *   canWrite?: boolean,
 * }} data
 */
export function renderWafScenarioCadencePanel(data = {}) {
  const summary = data.catalogSummary ?? {};
  const intakes = data.intakes ?? [];
  const canWrite = data.canWrite === true;
  const showIntake = canWrite && Boolean(data.showIntakeForm);
  const totalProducts = summary.total_products ?? 0;
  const breadthMet = summary.breadth_target_met === true;
  const catalogVersion = summary.catalog_version ?? '—';
  const byDeployment = summary.by_deployment_type ?? {};

  const deploymentRows = Object.entries(byDeployment).map(([type, count]) =>
    `<tr><td><code>${esc(type)}</code></td><td>${count}</td></tr>`,
  ).join('') || '<tr><td colspan="2"><span class="muted">Catalog not loaded.</span></td></tr>';

  const bypassRows = [
    ['Direct origin reachability', 'origin_bypass_confirmed'],
    ['Unproxied DNS / grey-cloud', 'waf_fingerprint_lost'],
    ['CDN present, WAF not validated', 'marker_rule_not_blocking'],
    ['Allowlisted probe path', 'monitor_only_behavior'],
    ['Host/SNI mismatch', 'origin_bypass_confirmed'],
    ['Policy detached from hostname', 'policy_detached'],
  ].map(([label, code]) => `<tr><td>${esc(label)}</td><td><code>${esc(code)}</code></td></tr>`).join('');

  const intakeRows = intakes.length
    ? intakes.map((item) => `<tr>
        <td>${esc(item.pattern_title)}</td>
        <td>${(item.advisory_refs || []).map((ref) => `<code>${esc(ref)}</code>`).join(', ') || '—'}</td>
        <td><code>${esc(item.proposed_scenario_family || '—')}</code></td>
        <td><code>${esc(item.risk_class || '—')}</code></td>
        <td><code>${esc(item.intake_stage || 'intake')}</code></td>
        <td>${esc(formatUtcShort(item.created_at))}</td>
      </tr>`).join('')
    : '<tr><td colspan="6"><span class="muted">No emerging scenario intakes yet. Submit metadata-only threat pattern references below.</span></td></tr>';

  const intakeForm = showIntake
    ? `<div class="card waf-scenario-intake-form" id="wafScenarioIntakeForm">
      <h5>Submit emerging scenario intake</h5>
      <form class="hs-form" id="wafScenarioIntakeFields">
        <label>Pattern title <input type="text" id="wafScenarioIntakeTitle" placeholder="HTTP/2 normalization edge class" required></label>
        <label>Advisory references <input type="text" id="wafScenarioIntakeAdvisories" placeholder="CVE-2026-12345, advisory:vendor-bulletin-2026-01" required></label>
        <label>Proposed scenario family
          <select id="wafScenarioIntakeFamily">
            <option value="">— optional —</option>
            <option value="protocol_evasion_marker">protocol_evasion_marker</option>
            <option value="content_type_confusion_marker">content_type_confusion_marker</option>
            <option value="http2_parser_marker">http2_parser_marker</option>
            <option value="bot_challenge_marker">bot_challenge_marker</option>
            <option value="sqli_marker">sqli_marker</option>
            <option value="xss_marker">xss_marker</option>
          </select>
        </label>
        <label>Risk class
          <select id="wafScenarioIntakeRisk" required>
            <option value="metadata_only" selected>metadata_only</option>
            <option value="safe">safe</option>
            <option value="manual_review_required">manual_review_required</option>
            <option value="soc_gated">soc_gated</option>
          </select>
        </label>
        <label>Threat summary <textarea id="wafScenarioIntakeSummary" rows="2" placeholder="Metadata-only description of the pattern class (no payloads)."></textarea></label>
        <div class="form-actions">
          <button type="button" class="btn" data-action="waf-scenario-intake-submit">Submit intake</button>
          <button type="button" class="btn secondary" data-action="waf-scenario-intake-cancel">Cancel</button>
        </div>
      </form>
    </div>`
    : '';

  return `<div class="card waf-scenario-cadence-panel">
    <h4>Scenario cadence &amp; vendor catalog</h4>
    <p class="muted">Governed intake for emerging threat patterns and versioned WAF/CDN fingerprint catalog. No live exploit payloads — metadata references only.</p>
    <div class="waf-cadence-summary-grid">
      <div class="waf-cadence-metric">
        <div class="muted">Catalog version</div>
        <div class="metric"><code>${esc(catalogVersion)}</code></div>
      </div>
      <div class="waf-cadence-metric">
        <div class="muted">Product entries</div>
        <div class="metric">${totalProducts} ${breadthMet ? '<span class="pill low">50+ target met</span>' : ''}</div>
      </div>
      <div class="waf-cadence-metric">
        <div class="muted">Unique vendors</div>
        <div class="metric">${summary.unique_vendors ?? '—'}</div>
      </div>
    </div>
    <h5>Catalog breadth by deployment type</h5>
    <table class="waf-catalog-deployment-table"><thead><tr><th>Deployment</th><th>Products</th></tr></thead><tbody>${deploymentRows}</tbody></table>
    <h5>Control-bypass taxonomy</h5>
    <p class="muted">Use <strong>control bypass</strong> as the umbrella term for paths where declared WAF/CDN protection does not block or challenge traffic before origin.</p>
    <table class="waf-control-bypass-table"><thead><tr><th>Bypass class</th><th>Reason code</th></tr></thead><tbody>${bypassRows}</tbody></table>
    ${canWrite
    ? `<div class="page-actions">
      <button type="button" class="btn" data-action="waf-scenario-intake-toggle">${showIntake ? 'Hide intake form' : 'Submit scenario intake'}</button>
    </div>
    ${intakeForm}`
    : '<p class="muted">Scenario intake submission requires WAF write permission.</p>'}
    <h5>Emerging scenario intakes</h5>
    <table class="waf-scenario-intake-table"><thead><tr>
      <th>Pattern</th><th>Advisories</th><th>Family</th><th>Risk</th><th>Stage</th><th>Created</th>
    </tr></thead><tbody>${intakeRows}</tbody></table>
  </div>`;
}

export function renderWafPostureTabs(activeTab = 'overview') {
  const tab = WAF_POSTURE_TABS.some((entry) => entry.id === activeTab) ? activeTab : 'overview';
  const buttons = WAF_POSTURE_TABS.map((entry) => {
    const active = entry.id === tab ? ' active' : '';
    return `<button type="button" class="tab waf-posture-tab${active}" data-waf-posture-tab="${esc(entry.id)}">${esc(entry.label)}</button>`;
  }).join('');
  return `<div class="tabs waf-posture-tabs" role="tablist" data-active-waf-tab="${esc(tab)}">${buttons}</div>`;
}

/**
 * @param {{
 *   assets?: object[],
 *   validations?: object[],
 *   tgNameById?: Record<string, string>,
 *   selectedAssetId?: string|null,
 * }} data
 */
export function renderWafAssetsTable(data = {}) {
  const assets = data.assets ?? [];
  const validations = data.validations ?? [];
  const tgNameById = data.tgNameById ?? {};
  const selectedAssetId = data.selectedAssetId ?? null;
  const canRun = data.canRun !== false;
  const canWrite = data.canWrite === true;
  const lookbackDays = 30;

  if (!assets.length) {
    return `<div class="card waf-assets-panel">
      <h4>Declared assets</h4>
      <div class="empty">No WAF assets declared yet.
        ${canWrite
    ? '<button type="button" class="btn" data-action="waf-create-demo-asset">Create declared demo WAF asset</button>'
    : '<span class="muted">Ask an engineer or admin to declare assets.</span>'}
      </div>
    </div>`;
  }

  const rows = assets.map((asset) => {
    const passRate = asset.effectiveness?.scenario_pass_rate ?? computeWafAssetPassRate(asset.id, validations, lookbackDays);
    const tgLabel = tgNameById[asset.target_group_id] || asset.target_group_id || '—';
    const vendor = asset.detected_vendor ?? asset.expected_vendor_hint ?? '—';
    const selectedCls = asset.id === selectedAssetId ? ' waf-asset-row--selected' : '';
    return `<tr class="waf-asset-row${selectedCls}" data-waf-asset-id="${esc(asset.id)}">
      <td><code>${esc(asset.canonical_url || asset.hostname || '—')}</code></td>
      <td><span class="waf-status-pill waf-status-pill--${esc(String(asset.posture_status ?? 'unknown').toLowerCase())}">${esc(asset.posture_status ?? 'unknown')}</span></td>
      <td><code>${esc(vendor)}</code></td>
      <td>${formatWafPassRateDisplay(passRate, lookbackDays)}</td>
      <td>${formatWafRuleHealthDisplay(asset.effectiveness)}</td>
      <td>${esc(tgLabel)}</td>
      <td>${esc(asset.owner_hint || '—')}</td>
      <td class="waf-asset-actions">
        <button type="button" class="btn secondary" data-action="waf-view-asset" data-id="${esc(asset.id)}">View detail</button>
        ${canRun ? `<button type="button" class="btn secondary" data-action="waf-run-validation" data-id="${esc(asset.id)}">Run marker validation</button>` : ''}
      </td>
    </tr>`;
  }).join('');

  return `<div class="card waf-assets-panel">
    <h4>Declared assets</h4>
    <p class="muted">Per-asset pass rate uses finalized validations in the last ${lookbackDays} days. Rule health appears when connector snapshots are available.</p>
    <table class="waf-assets-table">
      <thead><tr>
        <th>Asset</th><th>Status</th><th>Vendor</th><th>Pass rate</th><th>Rule health</th><th>Target group</th><th>Owner</th><th>Actions</th>
      </tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>`;
}

/**
 * @param {object|null|undefined} detail
 */
export function renderWafAssetEffectivenessSection(detail) {
  if (!detail?.asset) {
    return `<div class="card waf-asset-effectiveness">
      <h4>Asset effectiveness</h4>
      <p class="muted">Select an asset to review scenario pass rate, rule health, and control-bypass status.</p>
    </div>`;
  }

  const asset = detail.asset;
  const posture = detail.current_posture ?? {};
  const effectiveness = detail.effectiveness ?? {};
  const reasonCodes = posture.reason_codes ?? [];
  const passRate = effectiveness.scenario_pass_rate ?? null;
  const lookbackDays = effectiveness.lookback_days ?? 30;
  const bypassStatus = resolveWafControlBypassStatus(effectiveness, reasonCodes);
  const riskFactors = Array.isArray(posture.risk_factors) ? posture.risk_factors : [];
  const factorRows = riskFactors.length
    ? riskFactors.map((factor) => `<tr>
        <td><code>${esc(factor.factor ?? '—')}</code></td>
        <td>${esc(factor.value ?? '—')}</td>
        <td>${factor.contribution ?? '—'}</td>
      </tr>`).join('')
    : '<tr><td colspan="3"><span class="muted">No persisted risk factors for this asset yet.</span></td></tr>';

  return `<div class="card waf-asset-effectiveness" id="wafAssetDetail">
    <h4>Asset effectiveness · <code>${esc(asset.canonical_url || asset.hostname || asset.id)}</code></h4>
    <p class="muted">Metadata-only effectiveness metrics. Outside-in inference limits exact rule/config visibility without a connected WAF API.</p>
    <div class="waf-effectiveness-grid">
      <div class="waf-effectiveness-metric">
        <div class="muted">Scenario pass rate</div>
        <div class="metric">${formatWafPassRateDisplay(passRate, lookbackDays)}</div>
      </div>
      <div class="waf-effectiveness-metric">
        <div class="muted">Rule health</div>
        <div class="metric waf-effectiveness-metric--compact">${formatWafRuleHealthDisplay(effectiveness)}</div>
      </div>
      <div class="waf-effectiveness-metric">
        <div class="muted">Control bypass</div>
        <div class="metric"><span class="waf-status-pill waf-status-pill--${esc(bypassStatus)}">${esc(bypassStatus)}</span></div>
      </div>
      <div class="waf-effectiveness-metric">
        <div class="muted">Risk score / tier</div>
        <div class="metric">${posture.risk_score ?? '—'} · <code>${esc(posture.priority_band ?? '—')}</code></div>
      </div>
    </div>
    <table class="waf-effectiveness-factors-table">
      <thead><tr><th>Factor</th><th>Value</th><th>Contribution</th></tr></thead>
      <tbody>${factorRows}</tbody>
    </table>
    <p class="muted waf-effectiveness-hint">WAF detected but not validated: <em>WAF detected, but AstraNull has not proven it blocks before origin yet.</em></p>
  </div>`;
}

/**
 * @param {{ selectedKind?: string, selectedFormat?: string }} data
 */
export function renderWafReportsPanel(data = {}) {
  const selectedKind = data.selectedKind ?? 'executive_coverage';
  const selectedFormat = data.selectedFormat ?? 'json';
  const kindOptions = WAF_REPORT_EXPORT_KINDS.map((kind) => {
    const selected = kind.id === selectedKind ? ' selected' : '';
    return `<option value="${esc(kind.id)}"${selected}>${esc(kind.label)}</option>`;
  }).join('');
  const formatOptions = ['json', 'markdown'].map((format) => {
    const selected = format === selectedFormat ? ' selected' : '';
    return `<option value="${esc(format)}"${selected}>${esc(format)}</option>`;
  }).join('');

  return `<div class="card waf-reports-panel">
    <h4>WAF reports (developer export)</h4>
    <p class="muted">Metadata-only exports with custody manifests. Immutable storage, staging evidence, and production signoff remain open.</p>
    <div class="waf-reports-controls">
      <label class="muted">Report kind
        <select id="wafReportKind" class="waf-report-select" aria-label="WAF report kind">${kindOptions}</select>
      </label>
      <label class="muted">Format
        <select id="wafReportFormat" class="waf-report-select" aria-label="WAF report export format">${formatOptions}</select>
      </label>
      <button type="button" class="btn secondary" data-action="waf-report-export">Export report</button>
      <button type="button" class="btn secondary" data-action="waf-report-custody-preview">Preview custody</button>
    </div>
    <div id="wafReportCustodyPreview" class="waf-report-custody-preview muted">Select a report kind and preview custody metadata (summary only — no full payload dump).</div>
  </div>`;
}

/**
 * @param {{ items?: object[], assetLabelById?: Record<string, string>, retestByDriftId?: Record<string, { id: string, status?: string }> }} data
 */
export function renderWafDriftQueue(data = {}) {
  const items = data.items ?? [];
  const assetLabelById = data.assetLabelById ?? {};
  const retestByDriftId = data.retestByDriftId ?? {};
  const canWrite = data.canWrite === true;

  const driftDisclaimer = '<p class="muted waf-drift-disclaimer">Developer-validation workflow visibility only — not production signoff or customer-facing assurance.</p>';

  if (!items.length) {
    return `<div class="card waf-drift-queue">
      <h4>Posture drift queue</h4>
      ${driftDisclaimer}
      <div class="empty waf-drift-empty">No drift events yet. Drift appears only after evidence-backed posture weakening (for example, a protected asset fails a safe marker validation).</div>
    </div>`;
  }

  const rows = items.map((item) => {
    const assetLabel = assetLabelById[item.waf_asset_id]
      || item.waf_asset_id
      || '—';
    const before = summarizeWafDriftPostureSummary(item.before_summary);
    const after = summarizeWafDriftPostureSummary(item.after_summary);
    const findingCell = item.finding_id
      ? `<code>${esc(item.finding_id)}</code>`
      : '—';
    const retest = retestByDriftId[item.id];
    const retestStatus = String(retest?.status ?? '').toLowerCase();
    let retestFollowUp = '';
    if (retest?.id) {
      if (retestStatus === 'completed') {
        retestFollowUp = `<span class="muted waf-retest-terminal">Retest <code>${esc(retest.id)}</code>: completed</span>`;
      } else {
        const statusLine = retestStatus
          ? `<span class="muted waf-retest-status">Retest <code>${esc(retest.id)}</code>: ${esc(retestStatus)}</span>`
          : '';
        const executeBtn = (retestStatus === 'requested' || retestStatus === 'running')
          ? `<button type="button" class="btn secondary" data-action="waf-retest-execute" data-retest-id="${esc(retest.id)}">Execute retest</button>`
          : '';
        const completeBtn = (retestStatus === 'delegated' || retestStatus === 'running')
          ? `<button type="button" class="btn secondary" data-action="waf-retest-complete" data-retest-id="${esc(retest.id)}">Complete retest</button>`
          : '';
        retestFollowUp = [statusLine, executeBtn, completeBtn].filter(Boolean).join(' ');
      }
    }
    const currentStatus = String(item.status ?? 'open').toLowerCase();
    const statusSelect = WAF_DRIFT_WORKFLOW_STATUSES.map((s) => {
      const selected = s === currentStatus ? ' selected' : '';
      return `<option value="${esc(s)}"${selected}>${esc(s.replace(/_/g, ' '))}</option>`;
    }).join('');

    return `<tr class="waf-drift-row" data-drift-id="${esc(item.id)}">
      <td><code>${esc(item.drift_type ?? '—')}</code></td>
      <td><code>${esc(assetLabel)}</code></td>
      <td>${renderSeverityBadge(item.severity)}</td>
      <td>${renderRiskStateBadge(item.status)}</td>
      <td>${esc(formatUtcShort(item.created_at))}</td>
      <td class="waf-drift-summary-cell"><span class="waf-drift-summary">${esc(before)}</span> → <span class="waf-drift-summary">${esc(after)}</span></td>
      <td>${findingCell}</td>
      <td class="waf-drift-actions">
        ${canWrite
    ? `<label class="waf-drift-status-label muted">Status
          <select class="waf-drift-status-select" data-waf-drift-status-select aria-label="Drift status">${statusSelect}</select>
        </label>
        <button type="button" class="btn secondary" data-action="waf-drift-status" data-id="${esc(item.id)}">Update status</button>
        <button type="button" class="btn secondary" data-action="waf-drift-retest" data-id="${esc(item.id)}">Request retest</button>
        ${retestFollowUp}`
    : '<span class="muted">Read-only</span>'}
      </td>
    </tr>`;
  }).join('');

  return `<div class="card waf-drift-queue">
    <h4>Posture drift queue</h4>
    ${driftDisclaimer}
    <p class="muted">Evidence-backed behavior drift only — safe posture summaries, no raw request/response or policy bodies.</p>
    <table class="waf-drift-table"><thead><tr>
      <th>Drift type</th><th>Asset</th><th>Severity</th><th>Status</th><th>First seen</th><th>Before → after</th><th>Finding</th><th>Actions</th>
    </tr></thead><tbody>${rows}</tbody></table>
  </div>`;
}

export const WAF_VALIDATION_PLAN_SCENARIOS = Object.freeze([
  { id: 'marker', label: 'Marker (safe)' },
  { id: 'fingerprint', label: 'Fingerprint (safe)' },
  { id: 'origin_bypass', label: 'Origin bypass (safe)' },
  { id: 'rate_limit_marker', label: 'Rate limit marker (safe)' },
]);

export const WAF_VALIDATION_PLAN_SCHEDULE_INTERVALS = Object.freeze([
  { id: 'daily', label: 'Daily' },
  { id: 'weekly', label: 'Weekly' },
  { id: 'monthly', label: 'Monthly' },
]);

function wafPlanDelegatedJobCount(plan) {
  if (!plan || typeof plan !== 'object') return 0;
  if (Array.isArray(plan.delegated_jobs)) return plan.delegated_jobs.length;
  if (Number.isFinite(plan.delegated_jobs_count)) return plan.delegated_jobs_count;
  return 0;
}

function wafPlanContinuationLabel(plan) {
  if (typeof plan?.continuation_required === 'boolean') {
    return plan.continuation_required ? 'required' : 'not required';
  }
  const state = String(plan?.state ?? '').toLowerCase();
  if (state === 'running') return 'may be required (running)';
  return '—';
}

function renderWafValidationPlanScenarioCell(scenarios) {
  if (!Array.isArray(scenarios) || !scenarios.length) return '—';
  const labels = scenarios
    .filter((s) => typeof s === 'string' && s.length > 0)
    .map((s) => s.slice(0, 40))
    .slice(0, 6)
    .map((s) => `<code>${esc(s)}</code>`);
  return labels.length ? labels.join(', ') : '—';
}

function mergeWafValidationPlanRows(plans = [], scheduledPlans = []) {
  const byId = new Map();
  for (const plan of [...scheduledPlans, ...plans]) {
    if (plan && typeof plan === 'object' && plan.id) byId.set(plan.id, plan);
  }
  return [...byId.values()].sort((a, b) => String(b.created_at ?? '').localeCompare(String(a.created_at ?? '')));
}

/**
 * @param {{
 *   plans?: object[],
 *   scheduledPlans?: object[],
 *   targetGroups?: { id: string, name?: string }[],
 *   tgNameById?: Record<string, string>,
 *   unavailable?: { code?: string, message?: string },
 *   canRun?: boolean,
 * }} data
 */
export function renderWafValidationPlansPanel(data = {}) {
  const canRun = data.canRun !== false;
  const targetGroups = data.targetGroups ?? [];
  const tgNameById = data.tgNameById
    ?? Object.fromEntries(targetGroups.map((g) => [g.id, g.name ?? g.id]));
  const plans = mergeWafValidationPlanRows(data.plans ?? [], data.scheduledPlans ?? []);
  const unavailable = data.unavailable;
  const hasTargetGroups = targetGroups.length > 0;

  const disclaimer = '<p class="muted waf-plan-disclaimer">Developer-validation orchestration only. Plan <code>completed</code> means safe jobs were delegated — not final WAF posture closure or production signoff.</p>';

  let warningHtml = '';
  if (unavailable) {
    const code = esc(String(unavailable.code ?? unavailable.message ?? 'plan_panel_unavailable').slice(0, 120));
    const msg = esc(String(unavailable.message ?? '').slice(0, 200));
    const detail = msg && msg !== code ? ` — ${msg}` : '';
    warningHtml = `<div class="waf-plan-warning" role="alert"><strong>Validation plans unavailable.</strong> <code>${code}</code>${detail}</div>`;
  }

  const tgOptions = hasTargetGroups
    ? targetGroups.map((g) => `<option value="${esc(g.id)}">${esc(g.name || g.id)}</option>`).join('')
    : '<option value="">No declared target groups</option>';

  const scenarioChecks = WAF_VALIDATION_PLAN_SCENARIOS.map((s) => {
    const checked = s.id === 'marker' ? ' checked' : '';
    return `<label class="waf-plan-scenario"><input type="checkbox" name="waf-plan-scenario" value="${esc(s.id)}"${checked} /> ${esc(s.label)}</label>`;
  }).join('');

  const scheduleOptions = WAF_VALIDATION_PLAN_SCHEDULE_INTERVALS.map((s, idx) => {
    const selected = idx === 0 ? ' selected' : '';
    return `<option value="${esc(s.id)}"${selected}>${esc(s.label)}</option>`;
  }).join('');

  const panelFrozen = Boolean(unavailable) || !canRun;
  const formDisabledAttr = hasTargetGroups && !panelFrozen ? '' : ' disabled';
  const formNote = hasTargetGroups
    ? ''
    : '<p class="muted waf-plan-form-empty">Declare at least one target group before creating a validation plan.</p>';

  const formHtml = `<form class="waf-plan-form"${formDisabledAttr} aria-label="Create WAF validation plan">
    ${formNote}
    <div class="waf-plan-form-grid">
      <label>Target group
        <select id="wafPlanTargetGroup" class="waf-plan-input"${formDisabledAttr}>${tgOptions}</select>
      </label>
      <label>Mode
        <select id="wafPlanMode" class="waf-plan-input" data-waf-plan-mode${formDisabledAttr}>
          <option value="manual">Manual</option>
          <option value="scheduled">Scheduled</option>
        </select>
      </label>
      <label id="wafPlanScheduleRow" class="waf-plan-schedule-row" hidden>Schedule interval
        <select id="wafPlanScheduleInterval" class="waf-plan-input"${formDisabledAttr}>${scheduleOptions}</select>
      </label>
      <label>Max concurrent
        <input id="wafPlanMaxConcurrent" class="waf-plan-input" type="number" min="1" max="8" value="2"${formDisabledAttr} />
      </label>
      <label>Timeout (ms)
        <input id="wafPlanTimeoutMs" class="waf-plan-input" type="number" min="1000" max="300000" step="1000" value="60000"${formDisabledAttr} />
      </label>
    </div>
    <fieldset class="waf-plan-scenarios-fieldset"${formDisabledAttr}>
      <legend class="muted">Safe scenarios</legend>
      <div class="waf-plan-scenarios">${scenarioChecks}</div>
    </fieldset>
    <button type="button" class="btn" data-action="waf-plan-create"${formDisabledAttr}>Create validation plan</button>
  </form>`;

  const terminalStates = new Set(['completed', 'cancelled', 'failed']);
  const planRows = unavailable
    ? `<tr><td colspan="11"><div class="empty waf-plan-empty">Validation plans are temporarily unavailable. Retry after the service is restored.</div></td></tr>`
    : plans.length
    ? plans.map((plan) => {
      const state = String(plan.state ?? '—').toLowerCase();
      const tgLabel = tgNameById[plan.target_group_id] || plan.target_group_id || '—';
      const schedule = plan.schedule_interval
        ? esc(String(plan.schedule_interval))
        : (plan.mode === 'scheduled' ? '—' : 'n/a');
      const delegatedCount = wafPlanDelegatedJobCount(plan);
      const continuation = esc(wafPlanContinuationLabel(plan));
      const canMutate = !panelFrozen && !terminalStates.has(state);
      const executeBtn = canMutate
        ? `<button type="button" class="btn secondary" data-action="waf-plan-execute" data-plan-id="${esc(plan.id)}">Execute</button>`
        : '';
      const cancelBtn = canMutate
        ? `<button type="button" class="btn secondary" data-action="waf-plan-cancel" data-plan-id="${esc(plan.id)}">Cancel</button>`
        : '';
      return `<tr class="waf-plan-row" data-plan-id="${esc(plan.id)}">
        <td><code>${esc(plan.id)}</code></td>
        <td>${esc(tgLabel)}</td>
        <td>${esc(plan.mode ?? '—')}</td>
        <td>${schedule}</td>
        <td class="waf-plan-scenarios-cell">${renderWafValidationPlanScenarioCell(plan.scenarios)}</td>
        <td>${esc(plan.state ?? '—')}</td>
        <td>${esc(formatUtcShort(plan.created_at))}</td>
        <td>${esc(formatUtcShort(plan.executed_at))}</td>
        <td>${delegatedCount}</td>
        <td>${continuation}</td>
        <td class="waf-plan-actions">${executeBtn} ${cancelBtn}</td>
      </tr>`;
    }).join('')
    : '<tr><td colspan="11"><div class="empty waf-plan-empty">No validation plans yet. Create a bounded safe plan for a declared target group.</div></td></tr>';

  const tableHtml = `<table class="waf-plan-table"><thead><tr>
    <th>Plan</th><th>Target group</th><th>Mode</th><th>Schedule</th><th>Scenarios</th><th>State</th>
    <th>Created</th><th>Executed</th><th>Delegated jobs</th><th>Continuation</th><th>Actions</th>
  </tr></thead><tbody>${planRows}</tbody></table>`;

  return `<div class="card waf-plan-panel">
    <h4>Validation plan orchestration</h4>
    ${disclaimer}
    ${warningHtml}
    <p class="muted">Safe bounded scenarios only — governed delegation via signed-worker paths, not unmanaged traffic generation.</p>
    ${formHtml}
    ${tableHtml}
  </div>`;
}

/**
 * @param {{
 *   connectors?: object[],
 *   unavailable?: { code?: string, message?: string },
 *   permissionDenied?: { code?: string, message?: string },
 * }} data
 */
export function renderWafConnectorsPanel(data = {}) {
  const connectors = data.connectors ?? [];
  const unavailable = data.unavailable;
  const permissionDenied = data.permissionDenied;
  const canPoll = data.canPoll !== false;
  const disclaimer = '<p class="muted waf-connectors-disclaimer">Developer-validation connector health only — metadata summaries, no credentials, policy bodies, or raw provider payloads.</p>';

  let warningHtml = '';
  if (permissionDenied) {
    const code = esc(String(permissionDenied.code ?? permissionDenied.message ?? 'forbidden').slice(0, 120));
    warningHtml = `<div class="waf-connectors-warning" role="alert"><strong>Connector access denied.</strong> <code>${code}</code></div>`;
  } else if (unavailable) {
    const code = esc(String(unavailable.code ?? unavailable.message ?? 'connectors_unavailable').slice(0, 120));
    const msg = esc(String(unavailable.message ?? '').slice(0, 200));
    const detail = msg && msg !== code ? ` — ${msg}` : '';
    warningHtml = `<div class="waf-connectors-warning" role="alert"><strong>Connectors unavailable.</strong> <code>${code}</code>${detail}</div>`;
  }

  if (permissionDenied && !connectors.length) {
    return `<div class="card waf-connectors-panel">
      <h4>WAF connectors (health)</h4>
      ${disclaimer}
      ${warningHtml}
      <div class="empty waf-connectors-empty">Your role cannot read connector health. Core WAF posture remains available without connector access.</div>
    </div>`;
  }

  if (unavailable && !connectors.length) {
    return `<div class="card waf-connectors-panel">
      <h4>WAF connectors (health)</h4>
      ${disclaimer}
      ${warningHtml}
      <div class="empty waf-connectors-empty">Connector health is temporarily unavailable. Retry after the service is restored.</div>
    </div>`;
  }

  if (!connectors.length) {
    return `<div class="card waf-connectors-panel">
      <h4>WAF connectors (health)</h4>
      ${disclaimer}
      ${warningHtml}
      <div class="empty waf-connectors-empty">No WAF connectors configured yet. Optional read-only connectors ingest metadata snapshots; core no-access mode does not require them.</div>
    </div>`;
  }

  const rows = connectors.map((connector) => {
    const lastPoll = resolveWafConnectorLastPollAt(connector);
    const healthSummary = summarizeWafConnectorHealthSummary(connector);
    const status = String(connector.status ?? 'unknown').toLowerCase();
    const pollDisabled = status === 'disabled' || Boolean(unavailable) || Boolean(permissionDenied) || !canPoll;
    const pollDisabledAttr = pollDisabled ? ' disabled' : '';
    const name = boundConnectorMetaField(connector.name, 80) || '—';
    return `<tr class="waf-connector-row" data-connector-id="${esc(connector.id)}">
      <td><code>${esc(connector.provider ?? '—')}</code></td>
      <td>${esc(name)}</td>
      <td>${renderRiskStateBadge(connector.status)}</td>
      <td>${esc(formatUtcShort(lastPoll))}</td>
      <td class="waf-connector-health-cell"><span class="waf-connector-health-summary">${esc(healthSummary)}</span></td>
      <td class="waf-connector-actions">
        ${canPoll ? `<button type="button" class="btn secondary" data-action="waf-connector-poll" data-id="${esc(connector.id)}"${pollDisabledAttr}>Poll now</button>` : '<span class="muted">—</span>'}
      </td>
    </tr>`;
  }).join('');

  return `<div class="card waf-connectors-panel">
    <h4>WAF connectors (health)</h4>
    ${disclaimer}
    ${warningHtml}
    <p class="muted">Poll triggers outbound provider pull when configured (<code>secret_id</code> + supported provider) or accepts manual metadata snapshots via API. Results appear in WAF output below — summary only.</p>
    <table class="waf-connectors-table"><thead><tr>
      <th>Provider</th><th>Name</th><th>Status</th><th>Last poll</th><th>Health summary</th><th>Actions</th>
    </tr></thead><tbody>${rows}</tbody></table>
  </div>`;
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
  const canWrite = data.canWrite === true;
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
    ${canWrite
    ? `<div class="page-actions">
      <button type="button" class="btn" data-action="cve-ingest-toggle">${showIngest ? 'Hide ingest form' : 'Ingest CVE'}</button>
    </div>`
    : ''}
    ${ingestForm}
    ${empty}
    ${items.length ? `<table class="cve-pipeline-table"><thead><tr>
      <th>CVE ID</th><th>Severity</th><th>Stage</th><th>Affected products</th><th>Known exploited</th><th>Created</th><th></th>
    </tr></thead><tbody>${rows}</tbody></table>` : ''}
    ${detailHtml}
  </div>`;
}

/**
 * @param {{ inbox?: object[], candidates?: object[], entities?: object[], targetGroups?: object[], activeTab?: string, discoveryMode?: string, selectedId?: string|null, canApprove?: boolean, canWrite?: boolean }} data
 */
export function renderDiscoveryPage(data = {}) {
  const canApprove = data.canApprove !== false;
  const canWrite = data.canWrite === true;
  const activeTab = data.activeTab === 'all' ? 'all' : 'inbox';
  const inbox = data.inbox ?? [];
  const candidates = data.candidates ?? [];
  const entities = data.entities ?? [];
  const targetGroups = data.targetGroups ?? [];
  const rowsSource = activeTab === 'inbox' ? inbox : candidates;
  const hasApprovedImportCandidates = rowsSource.some(
    (c) => c.state === 'approved_target' && !c.approved_target_id,
  );

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
          ${canApprove
    ? `<button type="button" class="btn secondary" data-action="discovery-approve" data-id="${esc(id)}">Approve</button>
          <button type="button" class="btn secondary" data-action="discovery-reject" data-id="${esc(id)}">Reject</button>`
    : ''}
          ${canApprove && c.state === 'approved_target' && !c.approved_target_id
    ? `${targetGroups.length
      ? `<select id="discoveryImportTargetGroup_${esc(id)}" class="discovery-import-target-select" aria-label="Import ${esc(c.hostname)} into target group">
          ${targetGroups.map((g) => `<option value="${esc(g.id)}">${esc(g.name ?? g.id)}</option>`).join('')}
        </select>`
      : '<span class="muted">Declare a target group first</span>'}
        <button type="button" class="btn secondary" data-action="discovery-import" data-id="${esc(id)}"${targetGroups.length ? '' : ' disabled'}>Import</button>`
    : ''}
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
    ${canApprove && targetGroups.length && hasApprovedImportCandidates
    ? '<p class="muted discovery-import-target-label">Approved candidates must be imported into an existing declared target group.</p>'
    : ''}
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
  const canWrite = data.canWrite === true;
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
    ${canWrite
    ? `<div class="page-actions">
      <button type="button" class="btn secondary" data-action="supply-assess-cname-toggle">${data.showCnameForm ? 'Hide CNAME form' : 'Assess Dangling CNAME'}</button>
      <button type="button" class="btn secondary" data-action="supply-assess-dep-toggle">${data.showDependencyForm ? 'Hide dependency form' : 'Assess Dangling Dependency'}</button>
    </div>`
    : ''}
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
  const canWrite = data.canWrite === true;
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
        ${canWrite
    ? `<select class="remediation-status-select" data-action="remediation-status" data-id="${esc(item.action_item_id)}">
          ${ACTION_ITEM_STATUSES.map((s) => {
            const sel = item.status === s ? ' selected' : '';
            return `<option value="${esc(s)}"${sel}>${esc(s.replace(/_/g, ' '))}</option>`;
          }).join('')}
        </select>`
    : esc(item.status?.replace(/_/g, ' ') ?? '—')}
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
        ${canWrite
    ? `<select id="remediationDetailStatus" data-action="remediation-status" data-id="${esc(selected.action_item_id)}">${statusOptions}</select>`
    : esc(selected.status?.replace(/_/g, ' ') ?? '—')}
      </p>
      <h5>Evidence summary</h5>
      <p>${esc(selected.evidence?.summary ?? '—')}</p>
      <h5>Recommended solution</h5>
      <p>${esc(selected.recommended_solution ?? '—')}</p>
      <h5>Retest URL</h5>
      <p><code>${esc(selected.retest_url ?? '—')}</code></p>
      <h5>SIEM event preview</h5>
      <pre class="siem-preview">${esc(JSON.stringify(siem, null, 2))}</pre>
      ${canWrite
    ? `<div class="form-actions">
        <button type="button" class="btn secondary" data-action="remediation-deliver" data-id="${esc(selected.action_item_id)}" data-channel="webhook">Dry-run deliver</button>
      </div>`
    : ''}
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
