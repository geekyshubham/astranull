/**
 * Complete metadata-only production release evidence samples for every contract kind.
 * Used by bundle and contract unit tests; not for API submission without operator signoff.
 */
const AGENT_INSTALL_MATRIX_FORMATS = Object.freeze([
  'generic',
  'deb',
  'rpm',
  'container',
  'kubernetes',
]);

const AGENT_INSTALL_MATRIX_CHECKS = Object.freeze([
  'install',
  'heartbeat',
  'job_poll',
  'upgrade_rollback',
  'revoke',
  'uninstall',
  'no_inbound_port',
  'signature_verify',
]);

function agentInstallCheckDetail(format, checkName) {
  const detail = {
    status: 'passed',
    observed_at: '2026-07-02T00:00:00.000Z',
  };
  if (checkName === 'heartbeat') detail.heartbeat_count = 3;
  if (checkName === 'job_poll') detail.job_poll_count = 2;
  if (checkName === 'no_inbound_port') detail.inbound_listener_count = 0;
  if (checkName === 'signature_verify') {
    detail.signing_format = format === 'generic' ? 'tarball' : format;
    detail.trust_anchor_reference = `trust://agent-signing/${format}`;
  }
  return detail;
}

function agentInstallMatrixRow(format) {
  const runtimeFields = {};
  if (format === 'container') {
    runtimeFields.runtime = 'docker';
    runtimeFields.image_reference_redacted = 'registry.example/astranull-agent:rel-2026-07-02';
  }
  if (format === 'kubernetes') {
    runtimeFields.runtime = 'kubernetes';
    runtimeFields.deployment_mode = 'daemonset';
    runtimeFields.namespace_redacted = 'astranull-agents';
    runtimeFields.helm_release_redacted = 'astranull-agent';
  }
  return {
    format,
    environment: 'staging',
    distro: ['deb', 'rpm', 'generic'].includes(format) ? 'linux' : null,
    ...runtimeFields,
    status: 'passed',
    checks: Object.fromEntries(AGENT_INSTALL_MATRIX_CHECKS.map((check) => [check, 'passed'])),
    failed_checks: [],
    check_details: Object.fromEntries(
      AGENT_INSTALL_MATRIX_CHECKS.map((check) => [check, agentInstallCheckDetail(format, check)]),
    ),
  };
}

export const PRODUCTION_RELEASE_EVIDENCE_COMPLETE = {
  third_party_security_review: {
    reviewer_org: 'Independent Security Review Co',
    scope_summary: 'Production API, UI, SOC workflow, agent control, and release process.',
    review_report_uri: 'evidence://security-review/report',
    findings_status: 'all-critical-high-remediated',
    remediation_tracker_uri: 'evidence://security-review/remediation-tracker',
    risk_acceptance_reference: 'risk://accepted-medium-items',
    reviewed_at: '2026-07-02T00:00:00.000Z',
    security_owner: 'security-lead',
  },
  migration_apply: {
    environment: 'staging',
    database_cluster_reference: 'db-cluster/staging/astranull',
    migration_version: '0006_notification_rule_triggers',
    runner_evidence_uri: 'evidence://db/migration-run',
    started_at: '2026-07-02T00:00:00.000Z',
    completed_at: '2026-07-02T00:05:00.000Z',
    operator: 'database-operator',
    post_apply_check_uri: 'evidence://db/post-apply-check',
  },
  operator_runbook_exercise: {
    environment: 'staging',
    runbook_version: '2026-07-02',
    exercise_window: '2026-07-02T00:00:00.000Z/2026-07-02T02:00:00.000Z',
    operator: 'release-manager',
    evidence_uri: 'evidence://runbook/staging-exercise',
    exceptions: [],
    signoff_reference: 'signoff://ops-security',
  },
  oidc_prod_auth_preflight: {
    created_at: '2026-07-02T00:00:00.000Z',
    node_env: 'production',
    ok: true,
    checks: [{ id: 'auth_mode_oidc_jwt', ok: true, required: true, detail: 'ok' }],
    auth_posture: { auth_mode: 'oidc-jwt', jwks_redirect_policy: 'manual' },
    evidence_uri: 'evidence://auth/oidc-prod-preflight',
  },
  edge_protection: {
    release_id: 'rel-2026-07-02',
    edge_stack_summary: 'CDN + WAF + API gateway metadata summary',
    rate_limiting_summary: 'Per-tenant and global rate limits configured',
    logging_redaction_summary: 'Edge logs route to SIEM with redaction policy v2',
    signoff_owner: 'security-lead',
    signoff_at: '2026-07-02T00:00:00.000Z',
    controls: [{ control_id: 'tls_termination', evidence_uri: 'evidence://edge/tls' }],
    evidence_uri: 'evidence://edge/protection-matrix',
  },
  agent_sbom_provenance: {
    created_at: '2026-07-02T00:00:00.000Z',
    package_format: 'container',
    package: { name: 'astranull-agent', sha256: 'a'.repeat(64), size: 1024 },
    sbom: {
      sha256: 'b'.repeat(64),
      size: 2048,
      summary: { sbom_format: 'cyclonedx', component_count: 12 },
    },
    provenance: {
      sha256: 'c'.repeat(64),
      size: 1024,
      summary: { subject_count: 1, materials_count: 3 },
    },
    evidence_uri: 'evidence://agent/sbom-provenance',
  },
  agent_install_matrix: {
    schema_version: 1,
    artifact_type: 'agent_install_matrix_evidence',
    created_at: '2026-07-02T00:00:00.000Z',
    matrix_id: 'agent-install-2026-07-02',
    overall_status: 'passed',
    required_formats: [...AGENT_INSTALL_MATRIX_FORMATS],
    required_checks: [...AGENT_INSTALL_MATRIX_CHECKS],
    coverage_gaps: {
      missing_formats: [],
      failed_checks: [],
      formats_covered: [...AGENT_INSTALL_MATRIX_FORMATS],
    },
    rows: AGENT_INSTALL_MATRIX_FORMATS.map((format) => agentInstallMatrixRow(format)),
    evidence_uri: 'evidence://agent/install-matrix',
  },
  agent_mtls_gateway: {
    schema_version: 1,
    artifact_type: 'agent_mtls_gateway_evidence',
    created_at: '2026-07-02T00:00:00.000Z',
    validation: { ok: true, missing_fields: [], forbidden_fields: [], invalid_fingerprint_headers: [] },
    release_id: 'rel-agent-mtls-2026-07-02',
    environment: 'staging',
    gateway_summary: {
      gateway_reference: 'gateway://staging/agent-control',
      proxy_type: 'nginx-ingress',
      tls_termination_point: 'edge_gateway',
    },
    staging_proof_summary: {
      staging_agent_reference: 'agent://staging/prod-origin-01',
      registration_evidence_uri: 'evidence://agent/staging-registration-2026-07-02',
      heartbeat_evidence_uri: 'evidence://agent/staging-heartbeat-2026-07-02',
      fingerprint_match_confirmed: true,
    },
    rotation_revocation_summary: {
      drill_reference: 'drill://agent/client-cert-rotation-revocation-2026-07-02',
      rotation_tested: true,
      revocation_tested: true,
    },
    security_signoff: {
      owner: 'security-lead',
      role: 'security-owner',
      signed_at: '2026-07-02T11:30:00.000Z',
      signoff_reference: 'signoff://security/agent-mtls-gateway',
    },
    evidence_uri: 'evidence://agent/mtls-gateway',
  },
  agent_trust_key_ceremony: {
    schema_version: 1,
    artifact_type: 'agent_trust_key_ceremony_evidence',
    created_at: '2026-07-02T00:00:00.000Z',
    validation: { ok: true, missing_fields: [], forbidden_fields: [], missing_signoff: false },
    ceremony_summary: {
      drill_id: 'agent-trust-key-2026-07-02',
      environment: 'staging',
      tenant_id: 'ten_demo',
      signing_key_method: 'generate',
      active_fingerprint_sha256: 'a'.repeat(64),
      custody_uri_count: 2,
    },
    custody_uris: [
      'custody://security/agent-trust-key-ceremony/2026-07-02',
      'custody://security/agent-trust-key-rotation/2026-07-02',
    ],
    evidence_uri: 'evidence://agent/trust-key-ceremony',
  },
  governed_adapter: {
    adapter_id: 'adapter-partner-01',
    adapter_type: 'partner_adapter',
    authorization_pack_id: 'authz-pack-2026-07-02',
    scheduled_window: { start_at: '2026-07-02T10:00:00.000Z', end_at: '2026-07-02T11:00:00.000Z' },
    soc_approvers: ['soc-lead'],
    provider_approval_reference: 'approval://provider/case-001',
    kill_switch_hook: 'kill-switch://tenant/stop-path',
    telemetry_metadata: { channel: 'metadata-only' },
    dry_run_status: { mode: 'dry_run', traffic_generated: false, validated_at: '2026-07-02T00:00:00.000Z' },
    stop_close_evidence: { stop_reference: 'stop://001', close_reference: 'close://001' },
    evidence_uri: 'evidence://soc/governed-adapter',
  },
  provider_approval: {
    authorized_scope_hash: 'sha256:scope-metadata-digest',
    soc_reviewer: 'soc-lead',
    legal_signoff: { reference: 'legal://signoff/001', signed_at: '2026-07-02T00:00:00.000Z' },
    custody_ids: ['custody://approval/001'],
    provider_key: 'cloudflare',
    approval_reference: 'ticket://provider/CF-100',
    evidence_uri: 'evidence://soc/provider-approval',
  },
  kill_switch_drill: {
    created_at: '2026-07-02T00:00:00.000Z',
    drill_id: 'ks-drill-2026-07-02',
    tenant_id: 'ten_demo',
    response_latency_ms: 45000,
    latency_ok: true,
    transcript: {
      activation_at: '2026-07-02T00:00:00.000Z',
      stop_signal_at: '2026-07-02T00:00:45.000Z',
      affected_request_ids: ['req-ks-1'],
      cancelled_safe_run_ids: ['run-safe-1'],
      soc_actors: [{ actor_id: 'soc-lead-1', role: 'soc_operator' }],
      audit_event_ids: ['audit://ks/1'],
      closeout: {
        signoff_by: 'soc-lead-1',
        signoff_role: 'soc_operator',
        signed_at: '2026-07-02T00:01:00.000Z',
        signoff_reference: 'signoff://ks/drill-closeout',
      },
    },
    evidence_uri: 'evidence://soc/kill-switch-drill',
  },
  postgres_concurrency: {
    environment: 'staging',
    tenant_count: 2,
    concurrent_actors: 4,
    duration_seconds: 120,
    route_families_exercised: ['catalog', 'auth', 'agents'],
    isolation: { cross_tenant_read_rejections: 1, cross_tenant_write_rejections: 0, cross_tenant_leaks: 0 },
    rls_evidence: { error_ids: ['err-1'], audit_evidence_ids: ['audit-1'] },
    operator_signoff: { operator: 'db-operator', signed_at: '2026-07-02T00:00:00.000Z', reference: 'signoff://db' },
    evidence_uri: 'evidence://db/postgres-concurrency',
  },
  dr_restore: {
    drill_id: 'dr-drill-2026-07-02',
    environment: 'staging',
    drill_type: 'restore',
    started_at: '2026-07-02T00:00:00.000Z',
    completed_at: '2026-07-02T01:00:00.000Z',
    backup_manifest: {
      manifest_uri: 'evidence://dr/backup-manifest',
      sha256: 'd'.repeat(64),
      backup_reference: 'backup://2026-07-01',
    },
    restore_target: {
      cluster_reference: 'db-cluster/staging',
      database_reference: 'astranull',
      restore_mode: 'point_in_time',
    },
    rpo_rto: {
      rpo_target_minutes: 60,
      rto_target_minutes: 120,
      measured_rpo_minutes: 30,
      measured_rto_minutes: 90,
    },
    operator_approvals: [
      {
        role: 'dba',
        operator: 'db-operator',
        approved_at: '2026-07-02T00:00:00.000Z',
        signoff_reference: 'signoff://dr/001',
      },
    ],
    evidence_custody_ids: ['custody://dr/001'],
    recovery_decision: {
      decision: 'forward_fix',
      decision_reference: 'decision://dr/001',
      operator: 'db-operator',
      decided_at: '2026-07-02T01:00:00.000Z',
    },
    post_restore_verification: {
      signoff_reference: 'signoff://dr/post-restore',
      checks: [{ check_id: 'schema_ok', status: 'passed', evidence_uri: 'evidence://dr/check-1' }],
    },
    evidence_uri: 'evidence://ops/dr-restore',
  },
  ui_accessibility_matrix: {
    created_at: '2026-07-02T00:00:00.000Z',
    runs: [
      {
        page: 'dashboard',
        viewport: 'desktop',
        browser: 'chromium',
        axe_status: 'pass',
        keyboard_status: 'pass',
        screen_reader_status: 'pass',
        issues: { critical: 0, serious: 0, moderate: 0, minor: 0 },
      },
    ],
    evidence_uri: 'evidence://ux/accessibility-matrix',
  },
  notification_provider_config: {
    schema_version: 1,
    artifact_type: 'notification_provider_config_evidence',
    created_at: '2026-07-02T00:00:00.000Z',
    release_id: 'rel-2026-07-02',
    validation: { ok: true, missing_fields: [], invalid_fields: [], forbidden_fields: [], coverage_gaps: [] },
    providers: [{ provider_id: 'email-primary', channel: 'email', delivery_mode: 'metadata-only' }],
    signoff: { soc: { reference: 'signoff://soc/notifications' }, security: { reference: 'signoff://sec/notifications' } },
    evidence_uri: 'evidence://notifications/provider-config',
  },
  probe_fleet_matrix: {
    schema_version: 1,
    artifact_type: 'probe_fleet_matrix_evidence',
    created_at: '2026-07-02T00:00:00.000Z',
    fleet_id: 'probe-fleet-staging-001',
    overall_status: 'passed',
    coverage_gaps: { missing_regions: [], missing_probe_profiles: [], failed_controls: [] },
    rows: [{ region: 'us-east-1', status: 'passed', controls: { signed_jobs_only: 'passed' } }],
    evidence_uri: 'evidence://probe/fleet-matrix',
  },
  vector_safety_policy: {
    schema_version: 1,
    artifact_type: 'vector_safety_policy_catalog',
    created_at: '2026-07-02T00:00:00.000Z',
    validation: { ok: true, total_checks: 45, customer_runnable_count: 36, soc_request_only_count: 9, gaps: [] },
    customer_runnable_policies: [{ check_id: 'direct_origin_bypass', probe_profile: 'http_head_only' }],
    soc_request_only_markers: [{ check_id: 'high_scale_provider_exercise', customer_runnable: false }],
    evidence_uri: 'evidence://detection/vector-safety-policy',
  },
  secret_rotation_drill: {
    schema_version: 1,
    artifact_type: 'secret_rotation_drill_evidence',
    created_at: '2026-07-02T00:00:00.000Z',
    validation: { ok: true, missing_fields: [], forbidden_fields: [], missing_signoff: false },
    drill_summary: {
      drill_id: 'sec-rotation-2026-07-02',
      environment: 'staging',
      tenant_count: 3,
      zero_plaintext_attested: true,
    },
    evidence_uri: 'evidence://security/secret-rotation-drill',
  },
  observability_slo: {
    schema_version: 1,
    artifact_type: 'observability_slo_release_evidence',
    created_at: '2026-07-02T00:00:00.000Z',
    validation: { ok: true, missing_controls: [], missing_critical_controls: [], invalid_fields: [], forbidden_fields: [] },
    environment: 'staging',
    incident_drill_id: 'incident-drill-2026-07-02',
    metric_scrape_auth: {
      auth_mechanism: 'gateway-oidc',
      gateway_reference: 'gateway://metrics/staging',
      evidence_uri: 'evidence://observability/scrape-auth',
      validated_at: '2026-07-02T00:00:00.000Z',
    },
    dashboard_ids: ['dash-readiness', 'dash-soc'],
    alert_routes: [{ route_id: 'pager-primary', alert_name: 'slo_burn_rate', destination_reference: 'pager://primary' }],
    slo_targets: [{ slo_id: 'api-availability', target: '99.9', measurement_window: '30d' }],
    on_call: { owner: 'ops-lead', rotation_reference: 'rotation://primary', evidence_uri: 'evidence://ops/rotation' },
    redaction_policy: { policy_reference: 'policy://redaction/v1', summary: 'metadata-only logs and traces' },
    evidence_uri: 'evidence://observability/slo',
  },
  support_readiness: {
    schema_version: 1,
    artifact_type: 'support_on_call_readiness_evidence',
    created_at: '2026-07-02T00:00:00.000Z',
    validation: { ok: true, missing_fields: [], forbidden_fields: [], missing_owner: false },
    readiness_summary: {
      readiness_id: 'support-readiness-2026-07-02',
      environment: 'staging',
      support_signoff_owner: 'support-lead',
    },
    evidence_uri: 'evidence://support/readiness',
  },
  evidence_snapshot_manifest: {
    schema_version: 1,
    artifact_type: 'immutable_evidence_snapshot_manifest',
    created_at: '2026-07-02T00:00:00.000Z',
    validation: { ok: true, gaps: [], forbidden_fields: [], snapshot_count: 2 },
    summary: {
      tenant_id: 'ten_demo',
      batch_id: 'snapshot-batch-2026-07-02',
      snapshots: [{ snapshot_id: 'snap-001', snapshot_hash: 'sha256:snapshot-digest' }],
    },
    evidence_uri: 'evidence://custody/snapshot-manifest',
  },
  postgres_tenant_query_audit: {
    schema_version: 1,
    artifact_type: 'postgres_tenant_query_audit',
    scanned_files: ['src/persistence/postgres/testRunRepository.mjs'],
    finding_count: 0,
    findings: [],
    evidence_uri: 'evidence://db/tenant-query-audit',
  },
  rollback_fixforward: {
    schema_version: 1,
    artifact_type: 'rollback_fixforward_release_evidence',
    created_at: '2026-07-02T00:00:00.000Z',
    validation: { ok: true, missing_fields: [], forbidden_fields: [], missing_signoff: false },
    plan_summary: {
      release_id: 'rel-2026-07-02',
      environment: 'staging',
      owner: 'release-manager',
      migration_strategy: 'forward_fix',
      migration_version: '0007_production_release_evidence',
      tested_command_count: 2,
      signoff_count: 2,
    },
    evidence_uri: 'evidence://release/rollback-fixforward-plan',
  },
  kms_vault_posture: {
    schema_version: 1,
    artifact_type: 'kms_vault_posture_evidence',
    created_at: '2026-07-02T00:00:00.000Z',
    validation: { ok: true, missing_fields: [], forbidden_fields: [] },
    environment: 'staging',
    vault_summary: {
      vault_reference: 'vault://staging/secrets',
      kms_provider: 'cloud-kms-metadata',
      encryption_at_rest: 'enabled',
    },
    key_rotation_policy: {
      policy_reference: 'policy://kms/rotation/v1',
      rotation_interval_days: 90,
      last_rotation_drill_reference: 'drill://kms/rotation-2026-07-02',
    },
    access_control_summary: {
      break_glass_procedure_reference: 'runbook://security/break-glass',
      least_privilege_attested: true,
    },
    drill_reference: 'drill://kms/vault-access-2026-07-02',
    security_signoff: {
      owner: 'security-lead',
      signed_at: '2026-07-02T00:00:00.000Z',
      signoff_reference: 'signoff://security/kms-vault',
    },
    evidence_uri: 'evidence://security/kms-vault-posture',
  },
  control_plane_container_release: {
    schema_version: 1,
    artifact_type: 'control_plane_container_release_evidence',
    created_at: '2026-07-02T00:00:00.000Z',
    release_id: 'rel-control-plane-2026-07-02',
    image: {
      repository: 'registry.example/astranull-control-plane',
      digest_sha256: 'e'.repeat(64),
      tag: '2026-07-02-staging',
    },
    scan_summary: {
      scanner: 'container-scan-metadata',
      critical_count: 0,
      high_count: 0,
      report_uri: 'evidence://release/container-scan',
    },
    signing_summary: {
      signer_reference: 'cosign://release-signer',
      signature_verified: true,
      provenance_uri: 'evidence://release/slsa-provenance',
    },
    promotion_summary: {
      source_environment: 'staging',
      promotion_approved_by: 'release-manager',
      promoted_at: '2026-07-02T00:00:00.000Z',
    },
    rollback_reference: 'rollback://control-plane/rel-2026-07-01',
    evidence_uri: 'evidence://release/control-plane-container',
  },
  staging_e2e_matrix: {
    schema_version: 1,
    artifact_type: 'staging_e2e_matrix_evidence',
    created_at: '2026-07-02T00:00:00.000Z',
    release_id: 'rel-2026-07-02',
    environment: 'staging',
    scenarios: [
      {
        scenario_id: 'catalog-target-group-flow',
        status: 'passed',
        evidence_uri: 'evidence://e2e/catalog-target-group',
      },
      {
        scenario_id: 'soc_high_scale_governance',
        status: 'passed',
        evidence_uri: 'evidence://e2e/soc_high_scale_governance',
      },
    ],
    overall_status: 'passed',
    signoff: {
      owner: 'qa-lead',
      signed_at: '2026-07-02T00:00:00.000Z',
      signoff_reference: 'signoff://qa/staging-e2e',
    },
    evidence_uri: 'evidence://release/staging-e2e-matrix',
  },
  compliance_legal_signoff: {
    schema_version: 1,
    artifact_type: 'compliance_legal_signoff_evidence',
    created_at: '2026-07-02T00:00:00.000Z',
    release_id: 'rel-2026-07-02',
    legal_owner: 'legal-counsel',
    auditor_owner: 'compliance-auditor',
    signoffs: [
      {
        role: 'legal',
        reference: 'signoff://legal/release-2026-07-02',
        signed_at: '2026-07-02T00:00:00.000Z',
      },
      {
        role: 'compliance',
        reference: 'signoff://compliance/release-2026-07-02',
        signed_at: '2026-07-02T00:00:00.000Z',
      },
    ],
    reviewed_templates: [
      { template_id: 'customer-dpa', review_status: 'approved', evidence_uri: 'evidence://legal/dpa-review' },
      { template_id: 'authorization-pack', review_status: 'approved', evidence_uri: 'evidence://legal/authz-pack-review' },
    ],
    evidence_uri: 'evidence://compliance/legal-signoff',
  },
  authorization_custody: {
    schema_version: 1,
    artifact_type: 'authorization_custody_evidence',
    created_at: '2026-07-02T00:00:00.000Z',
    release_id: 'rel-2026-07-02',
    custody_summary: {
      custody_system_reference: 'custody://soc/authorization-vault',
      artifact_count: 3,
      chain_of_custody_verified: true,
    },
    required_artifacts: [
      { artifact_id: 'authz-pack-001', custody_id: 'custody://authz/001', status: 'sealed' },
      { artifact_id: 'provider-approval-001', custody_id: 'custody://approval/001', status: 'sealed' },
    ],
    retention_policy: {
      policy_reference: 'policy://custody/retention/v1',
      retention_years: 7,
    },
    legal_signoff: {
      reference: 'signoff://legal/custody-2026-07-02',
      signed_at: '2026-07-02T00:00:00.000Z',
    },
    evidence_uri: 'evidence://soc/authorization-custody',
  },
  placement_confidence_staging: {
    schema_version: 1,
    artifact_type: 'placement_confidence_staging_evidence',
    created_at: '2026-07-02T00:00:00.000Z',
    release_id: 'rel-2026-07-02',
    environment: 'staging',
    scenarios: [
      {
        scenario_id: 'probe-agent-correlation',
        status: 'passed',
        correlation_score: 'high',
        evidence_uri: 'evidence://placement/probe-agent-correlation',
      },
    ],
    evidence_correlation_summary: {
      probe_evidence_count: 12,
      agent_evidence_count: 8,
      correlated_pairs: 8,
      gaps: [],
    },
    signoff: {
      owner: 'detection-lead',
      signed_at: '2026-07-02T00:00:00.000Z',
      signoff_reference: 'signoff://detection/placement-confidence',
    },
    evidence_uri: 'evidence://detection/placement-confidence-staging',
  },
  gateway_load_abuse: {
    schema_version: 1,
    artifact_type: 'gateway_load_abuse_evidence',
    created_at: '2026-07-02T00:00:00.000Z',
    release_id: 'rel-2026-07-02',
    environment: 'staging',
    rate_limit_results: [
      {
        control_id: 'api-global-rate-limit',
        status: 'passed',
        threshold_metadata: 'metadata-only-bounded-test',
        evidence_uri: 'evidence://edge/rate-limit-api',
      },
    ],
    abuse_detection_results: [
      {
        control_id: 'anomaly-detection',
        status: 'passed',
        alert_fired: true,
        evidence_uri: 'evidence://edge/abuse-detection',
      },
    ],
    edge_alerting_summary: {
      siem_route_reference: 'siem://edge-alerts/staging',
      alert_count: 2,
      false_positive_rate_metadata: 'within-threshold',
    },
    signoff: {
      owner: 'security-lead',
      signed_at: '2026-07-02T00:00:00.000Z',
      signoff_reference: 'signoff://security/gateway-load-abuse',
    },
    evidence_uri: 'evidence://edge/gateway-load-abuse',
  },
};

/** Kinds added after the initial bundle scaffold; each has a standalone JSON sample under tests/fixtures/release-evidence-samples/. */
export const NEW_PRODUCTION_RELEASE_EVIDENCE_KINDS = Object.freeze([
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

export function completeEvidenceRecords(kinds) {
  return kinds.map((kind) => ({
    kind,
    evidence: PRODUCTION_RELEASE_EVIDENCE_COMPLETE[kind],
  }));
}

export function stampAcceptedReleaseRecords(records, releaseId, status = 'accepted') {
  const normalizedReleaseId = releaseId === null || releaseId === undefined
    ? null
    : String(releaseId).trim();
  return records.map((record) => ({
    ...record,
    status: record.status ?? status,
    ...(normalizedReleaseId ? { release_id: normalizedReleaseId } : {}),
  }));
}
