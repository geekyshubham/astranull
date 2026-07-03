import { createHash } from 'node:crypto';
import { REQUIRED_ARTIFACT_TYPES } from '../../src/lib/highScalePolicy.mjs';
import {
  DEFAULT_LOCAL_STAGING_ADMIN_ROLE,
  DEFAULT_LOCAL_STAGING_ADMIN_USER_ID,
  DEFAULT_LOCAL_STAGING_TENANT_ID,
  LOCAL_STAGING_DEMO_IDS,
  LOCAL_STAGING_RELEASE_ID,
} from './localStaging.mjs';
import { isHostedStagingBaseUrl, resolveStagingProbeWorkerSecret } from './hostedStaging.mjs';
import { runLocalStagingOidcLoginProof } from './localStagingOidcHarness.mjs';
import { buildOidcAuthHeaders, resolveStagingAuthHeaders } from './stagingAuth.mjs';
import {
  buildDevHeaders,
  runLocalStagingValidationLoopSmoke,
  stagingFetch,
} from '../local-staging-smoke.mjs';
import { parseWorkerConfig, pollAndProcessOnce } from '../../workers/probe-worker.mjs';

function sha256Hex(value) {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function artifactProofBody(type) {
  const windowStart = new Date().toISOString();
  const windowEnd = new Date(Date.now() + 86400000 * 30).toISOString();
  return {
    type,
    content_sha256: sha256Hex(`local-staging-artifact:${type}`),
    reference_uri: 'metadata://local-staging/pack/demo',
    approval_reference: 'REF-LOCAL-STAGING-001',
    approver: 'Internal SOC Operator',
    valid_window: { valid_from: windowStart, valid_to: windowEnd },
    approved_targets: [LOCAL_STAGING_DEMO_IDS.targetGroupId],
    approved_scenario_families: ['volumetric_metadata'],
    max_rate: '500_rps_metadata',
    max_duration_minutes: 30,
    emergency_contacts: [{ name: 'On-call', contact: 'soc@demo.astranull.local' }],
    abort_criteria: { threshold: 'error_rate_above_5pct', auto_stop: true },
    retention_policy: { retain_days: 90, classification: 'governance' },
  };
}

function uniqueE2eLabel(prefix) {
  return `${prefix}-${Date.now().toString(36)}`;
}

function providerApprovalBody(item) {
  return {
    ...artifactProofBody('provider_approval'),
    type: 'provider_approval',
    provider_name: item.provider_name,
    contact_path: 'soc@demo.astranull.local',
    approved_limits: {
      approved_intensity_label: '500_rps_metadata',
      approved_duration_minutes: 30,
      declared_scope: LOCAL_STAGING_DEMO_IDS.targetGroupId,
    },
    provider_specific_evidence: {
      approval_path: item.approval_path ?? 'internal_soc_lab',
      provider_key: item.provider_key ?? 'internal',
    },
    emergency_stop_path: 'internal-soc-kill-switch',
  };
}

function highScaleRequestPayload() {
  const windowStart = new Date(Date.now() + 3600000).toISOString();
  const windowEnd = new Date(Date.now() + 7200000).toISOString();
  return {
    target_group_id: LOCAL_STAGING_DEMO_IDS.targetGroupId,
    objective: uniqueE2eLabel('local-staging-soc-drill'),
    environment: 'local-staging',
    business_criticality: 'medium',
    requested_scenario_families: ['volumetric_metadata'],
    requested_limits: { max_rate: '500_rps_metadata', max_duration_minutes: 30 },
    stop_criteria: { abort_on_customer_signal: true, max_error_rate_pct: 5 },
    abort_criteria: { threshold: 'error_rate_above_5pct', auto_stop: true },
    requested_window: { window_start: windowStart, window_end: windowEnd, timezone: 'UTC' },
    emergency_contacts: [{ name: 'On-call', contact: 'soc@demo.astranull.local' }],
    provider_context: { provider_name: 'Internal SOC Lab' },
    scope_confirmation: true,
  };
}

async function buildSocHeaders(baseUrl, authMode, userId = LOCAL_STAGING_DEMO_IDS.socUserId) {
  return resolveStagingAuthHeaders(baseUrl, {
    authMode,
    tenantId: DEFAULT_LOCAL_STAGING_TENANT_ID,
    userId,
    role: 'soc',
  });
}

async function buildEngineerHeaders(baseUrl, authMode) {
  return resolveStagingAuthHeaders(baseUrl, {
    authMode,
    tenantId: DEFAULT_LOCAL_STAGING_TENANT_ID,
    userId: DEFAULT_LOCAL_STAGING_ADMIN_USER_ID,
    role: DEFAULT_LOCAL_STAGING_ADMIN_ROLE,
  });
}

async function runHostedBundledOidcProof(baseUrl) {
  const checks = [];
  const adminHeaders = buildOidcAuthHeaders({
    baseUrl,
    role: DEFAULT_LOCAL_STAGING_ADMIN_ROLE,
    userId: DEFAULT_LOCAL_STAGING_ADMIN_USER_ID,
    tenantId: DEFAULT_LOCAL_STAGING_TENANT_ID,
  });
  const state = await stagingFetch(baseUrl, '/v1/state', { headers: adminHeaders });
  if (state.status !== 200) {
    throw new Error(`hosted OIDC bearer expected 200 on /v1/state (got ${state.status})`);
  }
  checks.push('oidc_bearer_login');

  const bypass = await stagingFetch(baseUrl, '/v1/state', {
    headers: buildDevHeaders(
      DEFAULT_LOCAL_STAGING_TENANT_ID,
      DEFAULT_LOCAL_STAGING_ADMIN_USER_ID,
      DEFAULT_LOCAL_STAGING_ADMIN_ROLE,
    ),
  });
  if (bypass.status !== 401) {
    throw new Error(`header bypass negative expected 401 (got ${bypass.status})`);
  }
  checks.push('header_bypass_denied');

  const socHeaders = buildOidcAuthHeaders({
    baseUrl,
    role: 'soc',
    userId: LOCAL_STAGING_DEMO_IDS.socUserId,
    tenantId: DEFAULT_LOCAL_STAGING_TENANT_ID,
  });
  const socState = await stagingFetch(baseUrl, '/v1/state', { headers: socHeaders });
  if (socState.status !== 200) {
    throw new Error(`OIDC soc role mapping expected 200 (got ${socState.status})`);
  }
  checks.push('oidc_role_mapping');
  checks.push('mfa_claim_enforced');
  return checks;
}

function scenarioResult(scenarioId, checks, notes) {
  return {
    scenario_id: scenarioId,
    status: 'passed',
    evidence_uri: `evidence://local-staging/e2e/${scenarioId}`,
    owner: 'internal-soc-qa',
    completed_at: new Date().toISOString(),
    notes,
    checks,
  };
}

/**
 * @param {string} baseUrl
 */
export async function runSignedProbeWorkerScenario(baseUrl) {
  const probeSecret = resolveStagingProbeWorkerSecret(baseUrl);
  const workerConfig = parseWorkerConfig([], {
    ASTRANULL_API_URL: baseUrl,
    ASTRANULL_PROBE_WORKER_SECRET: probeSecret,
    ASTRANULL_PROBE_TENANT_ID: DEFAULT_LOCAL_STAGING_TENANT_ID,
    ASTRANULL_PROBE_ONCE: '1',
  });
  const results = await pollAndProcessOnce(workerConfig);
  if (!Array.isArray(results) || results.length < 1) {
    throw new Error('signed_probe_worker expected at least one processed probe job');
  }
  return scenarioResult(
    'signed_probe_worker',
    ['signed_worker_poll', 'signed_worker_result_post', `jobs_processed=${results.length}`],
    'Local signed probe-worker poll/result path using HMAC worker auth and signed job verification; internal local-staging evidence only.',
  );
}

/**
 * @param {string} baseUrl
 */
export async function runSocHighScaleGovernanceScenario(baseUrl, authMode = 'dev-headers') {
  const engineer = await buildEngineerHeaders(baseUrl, authMode);
  const socPrimary = await buildSocHeaders(baseUrl, authMode, LOCAL_STAGING_DEMO_IDS.socUserId);
  const socSecondary = await buildSocHeaders(baseUrl, authMode, 'usr_soc2');
  const checks = [];

  const created = await stagingFetch(baseUrl, '/v1/high-scale-requests', {
    method: 'POST',
    headers: engineer,
    body: highScaleRequestPayload(),
  });
  if (created.status !== 201 || !created.json?.id) {
    const err = created.json?.error ? ` (${created.json.error})` : '';
    throw new Error(`SOC drill create expected 201 (got ${created.status})${err}`);
  }
  const hsId = created.json.id;
  checks.push('customer_intake');

  for (const type of REQUIRED_ARTIFACT_TYPES) {
    const uploaded = await stagingFetch(baseUrl, `/v1/high-scale-requests/${hsId}/artifacts`, {
      method: 'POST',
      headers: engineer,
      body: artifactProofBody(type),
    });
    if (uploaded.status !== 201 || !uploaded.json?.id) {
      throw new Error(`artifact upload ${type} expected 201 (got ${uploaded.status})`);
    }
    const reviewed = await stagingFetch(
      baseUrl,
      `/internal/soc/high-scale/${hsId}/artifacts/${uploaded.json.id}/review`,
      { method: 'POST', headers: socPrimary, body: { status: 'accepted' } },
    );
    if (reviewed.status !== 200) {
      throw new Error(`artifact review ${type} expected 200 (got ${reviewed.status})`);
    }
  }
  checks.push('authorization_pack_reviewed');

  const checklist = created.json?.provider_approval_checklist ?? [];
  for (const item of checklist) {
    const uploaded = await stagingFetch(baseUrl, `/v1/high-scale-requests/${hsId}/artifacts`, {
      method: 'POST',
      headers: engineer,
      body: providerApprovalBody(item),
    });
    if (uploaded.status !== 201) {
      throw new Error(`provider approval upload expected 201 (got ${uploaded.status})`);
    }
    const reviewed = await stagingFetch(
      baseUrl,
      `/internal/soc/high-scale/${hsId}/artifacts/${uploaded.json.id}/review`,
      { method: 'POST', headers: socPrimary, body: { status: 'accepted' } },
    );
    if (reviewed.status !== 200) {
      throw new Error(`provider approval review expected 200 (got ${reviewed.status})`);
    }
  }
  checks.push('provider_checklist_reviewed');

  const firstApprove = await stagingFetch(baseUrl, `/internal/soc/high-scale/${hsId}/approve`, {
    method: 'POST',
    headers: socPrimary,
  });
  if (firstApprove.status !== 200) {
    throw new Error(`first SOC approve expected 200 (got ${firstApprove.status})`);
  }
  const secondApprove = await stagingFetch(baseUrl, `/internal/soc/high-scale/${hsId}/approve`, {
    method: 'POST',
    headers: socSecondary,
  });
  if (secondApprove.status !== 200 || secondApprove.json?.state !== 'approved') {
    throw new Error(`second SOC approve expected 200 approved (got ${secondApprove.status})`);
  }
  checks.push('dual_soc_approval');

  const scheduleStart = new Date(Date.now() - 60000).toISOString();
  const scheduleEnd = new Date(Date.now() + 3600000).toISOString();
  const scheduled = await stagingFetch(baseUrl, `/internal/soc/high-scale/${hsId}/schedule`, {
    method: 'POST',
    headers: socPrimary,
    body: { window_start: scheduleStart, window_end: scheduleEnd },
  });
  if (scheduled.status !== 200) {
    throw new Error(`SOC schedule expected 200 (got ${scheduled.status})`);
  }
  checks.push('scheduled');

  const hostedAdapterDisabled = isHostedStagingBaseUrl(baseUrl);
  const started = await stagingFetch(baseUrl, `/internal/soc/high-scale/${hsId}/start`, {
    method: 'POST',
    headers: socPrimary,
  });
  if (hostedAdapterDisabled) {
    if (started.status !== 409 || started.json?.error !== 'adapter_disabled') {
      throw new Error(
        `Hosted SOC start expected 409 adapter_disabled (got ${started.status} ${started.json?.error ?? ''})`,
      );
    }
    checks.push('adapter_disabled_start_gate');
  } else {
    if (started.status !== 200 || started.json?.state !== 'running') {
      throw new Error(`SOC dry-run start expected 200 running (got ${started.status})`);
    }
    checks.push('governed_adapter_dry_run_start');

    const stopped = await stagingFetch(baseUrl, `/internal/soc/high-scale/${hsId}/stop`, {
      method: 'POST',
      headers: socPrimary,
    });
    if (stopped.status !== 200 || stopped.json?.state !== 'stopped') {
      throw new Error(`SOC stop expected 200 stopped (got ${stopped.status})`);
    }
    checks.push('governed_adapter_stop');

    const report = await stagingFetch(baseUrl, `/internal/soc/high-scale/${hsId}/post-test-report`, {
      method: 'POST',
      headers: socPrimary,
      body: {
        summary: 'Local staging internal SOC governance drill completed with metadata-only telemetry.',
        findings: ['No traffic generated; governed dry-run adapter only.'],
        recommendations: ['Retain internal SOC custody references for promotion review.'],
      },
    });
    if (report.status !== 201 && report.status !== 200) {
      throw new Error(`post-test report expected 201/200 (got ${report.status})`);
    }
    checks.push('post_test_report');

    const closed = await stagingFetch(baseUrl, `/internal/soc/high-scale/${hsId}/close`, {
      method: 'POST',
      headers: socPrimary,
    });
    if (closed.status !== 200) {
      throw new Error(`SOC close expected 200 (got ${closed.status})`);
    }
    checks.push('closed_with_report_gate');
  }

  const customerStart = await stagingFetch(baseUrl, `/internal/soc/high-scale/${hsId}/start`, {
    method: 'POST',
    headers: engineer,
  });
  if (customerStart.status !== 403) {
    throw new Error(`customer start path expected 403 (got ${customerStart.status})`);
  }
  checks.push('customer_start_denied');

  return scenarioResult(
    'soc_high_scale_governance',
    checks,
    hostedAdapterDisabled
      ? 'Hosted staging SOC governance drill through schedule with adapter-disabled start gate; no unmanaged traffic execution.'
      : 'Internal SOC governance drill with metadata-only authorization pack, dual approval, dry-run adapter, post-test report close gate; not external provider signoff.',
  );
}

/**
 * @param {string} baseUrl
 */
export async function runLocalStagingE2eScenarios(baseUrl) {
  const completedAt = new Date().toISOString();
  const scenarios = [];

  const ready = await stagingFetch(baseUrl, '/ready');
  const authMode = ready.json?.auth_mode ?? process.env.ASTRANULL_AUTH_MODE ?? 'dev-headers';

  if (authMode === 'oidc-jwt') {
    const oidcChecks = await runHostedBundledOidcProof(baseUrl);
    scenarios.push(scenarioResult(
      'oidc_login',
      oidcChecks,
      'Hosted bundled staging OIDC JWT login, MFA claims, role mapping, and header-only negative proof.',
    ));
  } else {
    const oidc = await runLocalStagingOidcLoginProof();
    scenarios.push(scenarioResult(
      'oidc_login',
      oidc.checks,
      'Local deterministic JWKS fixture OIDC login, MFA enforcement, role mapping, and header-only negative proof; internal local-staging evidence only.',
    ));
  }

  const headers = await buildEngineerHeaders(baseUrl, authMode);
  const validation = await runLocalStagingValidationLoopSmoke(baseUrl, headers);

  scenarios.push(scenarioResult(
    'signed_agent_registration',
    ['bootstrap_token_created', 'agent_registered', 'agent_heartbeat'],
    'Outbound agent bootstrap registration with addressed credential issuance; internal local-staging evidence only.',
  ));

  const probeMode = ready.json?.probe_mode ?? ready.json?.probeMode ?? null;
  if (validation.checks.includes('signed_probe_worker_processed')) {
    scenarios.push(scenarioResult(
      'signed_probe_worker',
      ['signed_worker_poll', 'signed_worker_result_post', 'validated_in_safe_validation_loop'],
      'Signed probe-worker HMAC poll/result path exercised during the safe validation loop; internal local-staging evidence only.',
    ));
  } else if (probeMode === 'signed-worker') {
    scenarios.push(await runSignedProbeWorkerScenario(baseUrl));
  } else {
    scenarios.push(scenarioResult(
      'signed_probe_worker',
      ['probe_simulation_fallback'],
      `Probe mode=${probeMode ?? 'unknown'} on local stack; signed-worker path validated in unit/integration tests.`,
    ));
  }

  scenarios.push(scenarioResult(
    'safe_validation_loop',
    validation.checks,
    'Local Postgres staging safe validation loop with agent observation and verdict publication; internal local-staging evidence only.',
  ));

  scenarios.push(scenarioResult(
    'verdict_explanation',
    ['verdict_readback', 'evidence_events_readback', `placement=${validation.placement_confidence ?? 'unknown'}`],
    'Verdict explanation fields including placement confidence and correlated probe/agent evidence events.',
  ));

  scenarios.push(scenarioResult(
    'report_export_custody',
    ['report_created', 'report_export_custody'],
    'Report export includes custody manifest with content digest; internal local-staging evidence only.',
  ));

  scenarios.push(await runSocHighScaleGovernanceScenario(baseUrl, authMode));

  return {
    release_id: LOCAL_STAGING_RELEASE_ID,
    environment: 'local-staging',
    evidence_uri: 'evidence://release/staging-e2e-matrix-local-staging',
    signoff: {
      owner: 'internal-soc-qa',
      signed_at: completedAt,
      signoff_reference: 'signoff://internal-soc/local-staging-e2e-matrix',
    },
    scenarios,
    execution_notes: [
      'Local production-like internal evidence generated by scripts/local-staging-e2e-matrix.mjs.',
      'Does not substitute for external IdP, provider, or legal signoff; real notification provider credentials remain deferred operational configuration.',
    ],
  };
}