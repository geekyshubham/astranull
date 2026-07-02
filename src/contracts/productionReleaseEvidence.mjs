import { GOVERNED_ADAPTER_TYPES } from './governedExecutionAdapter.mjs';
import { validateKillSwitchExerciseEvidence } from './killSwitchValidation.mjs';

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

export const PRODUCTION_RELEASE_EVIDENCE_REQUIREMENTS = Object.freeze({
  third_party_security_review: Object.freeze([
    'reviewer_org',
    'scope_summary',
    'review_report_uri',
    'findings_status',
    'remediation_tracker_uri',
    'risk_acceptance_reference',
    'reviewed_at',
    'security_owner',
  ]),
  migration_apply: Object.freeze([
    'environment',
    'database_cluster_reference',
    'migration_version',
    'runner_evidence_uri',
    'started_at',
    'completed_at',
    'operator',
    'post_apply_check_uri',
  ]),
  operator_runbook_exercise: Object.freeze([
    'environment',
    'runbook_version',
    'exercise_window',
    'operator',
    'evidence_uri',
    'exceptions',
    'signoff_reference',
  ]),
  oidc_prod_auth_preflight: Object.freeze([
    'created_at',
    'node_env',
    'ok',
    'checks',
    'auth_posture',
    'evidence_uri',
  ]),
  edge_protection: Object.freeze([
    'release_id',
    'edge_stack_summary',
    'rate_limiting_summary',
    'logging_redaction_summary',
    'signoff_owner',
    'signoff_at',
    'controls',
    'evidence_uri',
  ]),
  agent_sbom_provenance: Object.freeze([
    'created_at',
    'package_format',
    'package',
    'sbom',
    'provenance',
    'evidence_uri',
  ]),
  agent_install_matrix: Object.freeze([
    'created_at',
    'matrix_id',
    'overall_status',
    'rows',
    'evidence_uri',
  ]),
  agent_mtls_gateway: Object.freeze([
    'schema_version',
    'artifact_type',
    'created_at',
    'validation',
    'release_id',
    'environment',
    'gateway_summary',
    'staging_proof_summary',
    'rotation_revocation_summary',
    'security_signoff',
    'evidence_uri',
  ]),
  agent_trust_key_ceremony: Object.freeze([
    'schema_version',
    'artifact_type',
    'created_at',
    'validation',
    'ceremony_summary',
    'custody_uris',
    'evidence_uri',
  ]),
  governed_adapter: Object.freeze([
    'adapter_id',
    'adapter_type',
    'authorization_pack_id',
    'scheduled_window',
    'soc_approvers',
    'provider_approval_reference',
    'kill_switch_hook',
    'telemetry_metadata',
    'dry_run_status',
    'stop_close_evidence',
    'evidence_uri',
  ]),
  provider_approval: Object.freeze([
    'authorized_scope_hash',
    'soc_reviewer',
    'legal_signoff',
    'custody_ids',
    'provider_key',
    'approval_reference',
    'evidence_uri',
  ]),
  kill_switch_drill: Object.freeze([
    'created_at',
    'drill_id',
    'tenant_id',
    'response_latency_ms',
    'latency_ok',
    'transcript',
    'evidence_uri',
  ]),
  postgres_concurrency: Object.freeze([
    'environment',
    'tenant_count',
    'concurrent_actors',
    'duration_seconds',
    'route_families_exercised',
    'isolation',
    'rls_evidence',
    'operator_signoff',
    'evidence_uri',
  ]),
  dr_restore: Object.freeze([
    'drill_id',
    'environment',
    'drill_type',
    'started_at',
    'completed_at',
    'backup_manifest',
    'restore_target',
    'rpo_rto',
    'operator_approvals',
    'evidence_custody_ids',
    'recovery_decision',
    'post_restore_verification',
    'evidence_uri',
  ]),
  ui_accessibility_matrix: Object.freeze([
    'created_at',
    'runs',
    'evidence_uri',
  ]),
  notification_provider_config: Object.freeze([
    'schema_version',
    'artifact_type',
    'created_at',
    'release_id',
    'validation',
    'providers',
    'signoff',
    'evidence_uri',
  ]),
  probe_fleet_matrix: Object.freeze([
    'schema_version',
    'artifact_type',
    'created_at',
    'fleet_id',
    'overall_status',
    'coverage_gaps',
    'rows',
    'evidence_uri',
  ]),
  vector_safety_policy: Object.freeze([
    'schema_version',
    'artifact_type',
    'created_at',
    'validation',
    'customer_runnable_policies',
    'soc_request_only_markers',
    'evidence_uri',
  ]),
  secret_rotation_drill: Object.freeze([
    'schema_version',
    'artifact_type',
    'created_at',
    'validation',
    'drill_summary',
    'evidence_uri',
  ]),
  observability_slo: Object.freeze([
    'schema_version',
    'artifact_type',
    'created_at',
    'validation',
    'environment',
    'incident_drill_id',
    'metric_scrape_auth',
    'dashboard_ids',
    'alert_routes',
    'slo_targets',
    'on_call',
    'redaction_policy',
    'evidence_uri',
  ]),
  support_readiness: Object.freeze([
    'schema_version',
    'artifact_type',
    'created_at',
    'validation',
    'readiness_summary',
    'evidence_uri',
  ]),
  evidence_snapshot_manifest: Object.freeze([
    'schema_version',
    'artifact_type',
    'created_at',
    'validation',
    'summary',
    'evidence_uri',
  ]),
  postgres_tenant_query_audit: Object.freeze([
    'schema_version',
    'artifact_type',
    'scanned_files',
    'finding_count',
    'findings',
    'evidence_uri',
  ]),
  rollback_fixforward: Object.freeze([
    'schema_version',
    'artifact_type',
    'created_at',
    'validation',
    'plan_summary',
    'evidence_uri',
  ]),
  kms_vault_posture: Object.freeze([
    'schema_version',
    'artifact_type',
    'created_at',
    'validation',
    'environment',
    'vault_summary',
    'key_rotation_policy',
    'access_control_summary',
    'drill_reference',
    'security_signoff',
    'evidence_uri',
  ]),
  control_plane_container_release: Object.freeze([
    'schema_version',
    'artifact_type',
    'created_at',
    'release_id',
    'image',
    'scan_summary',
    'signing_summary',
    'promotion_summary',
    'rollback_reference',
    'evidence_uri',
  ]),
  staging_e2e_matrix: Object.freeze([
    'schema_version',
    'artifact_type',
    'created_at',
    'release_id',
    'environment',
    'scenarios',
    'overall_status',
    'signoff',
    'evidence_uri',
  ]),
  compliance_legal_signoff: Object.freeze([
    'schema_version',
    'artifact_type',
    'created_at',
    'release_id',
    'legal_owner',
    'auditor_owner',
    'signoffs',
    'reviewed_templates',
    'evidence_uri',
  ]),
  authorization_custody: Object.freeze([
    'schema_version',
    'artifact_type',
    'created_at',
    'release_id',
    'custody_summary',
    'required_artifacts',
    'retention_policy',
    'legal_signoff',
    'evidence_uri',
  ]),
  placement_confidence_staging: Object.freeze([
    'schema_version',
    'artifact_type',
    'created_at',
    'release_id',
    'environment',
    'scenarios',
    'evidence_correlation_summary',
    'signoff',
    'evidence_uri',
  ]),
  gateway_load_abuse: Object.freeze([
    'schema_version',
    'artifact_type',
    'created_at',
    'release_id',
    'environment',
    'rate_limit_results',
    'abuse_detection_results',
    'edge_alerting_summary',
    'signoff',
    'evidence_uri',
  ]),
});

const FORBIDDEN_KEYS = new Set([
  'api_key',
  'apikey',
  'attachment',
  'attachments',
  'auth_tag',
  'authorization',
  'body',
  'ciphertext',
  'connection_string',
  'credential',
  'credentials',
  'database_url',
  'headers',
  'ip_inventory',
  'ip_list',
  'log',
  'logs',
  'packet',
  'packet_capture',
  'packet_payload',
  'password',
  'payload',
  'pcap',
  'private_key',
  'public_key_der_base64',
  'key_material',
  'raw_body',
  'raw_dump',
  'raw_headers',
  'raw_logs',
  'raw_log',
  'raw_packet',
  'raw_sql',
  'secret',
  'sql_dump',
  'target_ip_inventory',
  'target_ips',
  'token',
]);

function normalizeKey(key) {
  return key
    .replace(/([a-z])([A-Z])/g, '$1_$2')
    .replace(/[^A-Za-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toLowerCase();
}

function hasValue(value) {
  if (value === null || value === undefined) return false;
  if (typeof value === 'string' && value.trim() === '') return false;
  return true;
}

function collectForbiddenFields(value, path = '') {
  if (value === null || value === undefined || typeof value !== 'object') return [];
  const findings = [];
  if (Array.isArray(value)) {
    value.forEach((entry, index) => {
      findings.push(...collectForbiddenFields(entry, `${path}[${index}]`));
    });
    return findings;
  }
  for (const [key, nested] of Object.entries(value)) {
    const keyPath = path ? `${path}.${key}` : key;
    const normalized = normalizeKey(key);
    if (FORBIDDEN_KEYS.has(normalized) || normalized.startsWith('raw_')) {
      findings.push(keyPath);
    }
    findings.push(...collectForbiddenFields(nested, keyPath));
  }
  return findings;
}

const UNAPPROVED_EXECUTION_STATES = new Set([
  'live_traffic',
  'traffic_active',
  'production_execution',
  'attack_running',
  'traffic_generation_enabled',
]);

const SCHEDULED_WINDOW_REQUIRED_FIELDS = Object.freeze(['start_at', 'end_at']);

const DRY_RUN_STATUS_REQUIRED_FIELDS = Object.freeze(['mode', 'traffic_generated', 'validated_at']);

const KILL_SWITCH_TRANSCRIPT_REQUIRED_FIELDS = Object.freeze([
  'activation_at',
  'stop_signal_at',
  'affected_request_ids',
  'cancelled_safe_run_ids',
  'soc_actors',
  'audit_event_ids',
  'closeout',
]);

const KILL_SWITCH_CLOSEOUT_REQUIRED_FIELDS = Object.freeze([
  'signoff_by',
  'signoff_role',
  'signed_at',
  'signoff_reference',
]);

const KILL_SWITCH_SOC_ACTOR_REQUIRED_FIELDS = Object.freeze(['actor_id', 'role']);

function parseIsoMs(value) {
  if (!hasValue(value)) return null;
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? ms : null;
}

function missingNestedFieldPaths(object, requiredFields, prefix) {
  if (!hasValue(object) || typeof object !== 'object' || Array.isArray(object)) {
    return requiredFields.map((field) => `${prefix}.${field}`);
  }
  return requiredFields
    .filter((field) => !hasValue(object[field]))
    .map((field) => `${prefix}.${field}`);
}

function pushInvalidField(invalid_fields, field, reason, extra = {}) {
  invalid_fields.push({ field, reason, ...extra });
}

function appendExerciseValidationFailures(invalid_fields, exerciseValidation, prefix) {
  if (!exerciseValidation || exerciseValidation.ok) return;
  for (const stepId of exerciseValidation.missing_steps ?? []) {
    pushInvalidField(invalid_fields, prefix, 'missing_exercise_step', { step_id: stepId });
  }
  for (const entry of exerciseValidation.invalid_steps ?? []) {
    pushInvalidField(invalid_fields, prefix, 'invalid_exercise_step', {
      step_id: entry?.step_id ?? null,
      detail: entry?.reason ?? 'invalid_step',
    });
  }
  for (const entry of exerciseValidation.missing_fields ?? []) {
    pushInvalidField(invalid_fields, `${prefix}.steps`, 'missing_exercise_step_fields', {
      step_id: entry?.step_id ?? null,
      fields: entry?.fields ?? [],
    });
  }
  for (const fieldPath of exerciseValidation.forbidden_fields ?? []) {
    pushInvalidField(invalid_fields, `${prefix}.${fieldPath}`, 'forbidden_exercise_field');
  }
}

function validateGovernedAdapterInvalidFields(evidence) {
  const invalid_fields = [];

  if (
    hasValue(evidence?.adapter_type)
    && !GOVERNED_ADAPTER_TYPES.includes(evidence.adapter_type)
  ) {
    pushInvalidField(invalid_fields, 'adapter_type', 'unsupported_adapter_type', {
      allowed: GOVERNED_ADAPTER_TYPES,
    });
  }

  const scheduledWindow = evidence?.scheduled_window;
  if (hasValue(scheduledWindow)) {
    for (const fieldPath of missingNestedFieldPaths(
      scheduledWindow,
      SCHEDULED_WINDOW_REQUIRED_FIELDS,
      'scheduled_window',
    )) {
      pushInvalidField(invalid_fields, fieldPath, 'missing_scheduled_window_field');
    }
  }

  const dryRun = evidence?.dry_run_status;
  if (hasValue(dryRun) && typeof dryRun === 'object' && !Array.isArray(dryRun)) {
    for (const fieldPath of missingNestedFieldPaths(
      dryRun,
      DRY_RUN_STATUS_REQUIRED_FIELDS,
      'dry_run_status',
    )) {
      pushInvalidField(invalid_fields, fieldPath, 'missing_dry_run_status_field');
    }
    if (hasValue(dryRun.mode) && dryRun.mode !== 'dry_run') {
      pushInvalidField(invalid_fields, 'dry_run_status.mode', 'must_be_dry_run', {
        allowed: ['dry_run'],
      });
    }
    if (dryRun.traffic_generated === true) {
      pushInvalidField(invalid_fields, 'dry_run_status.traffic_generated', 'traffic_must_not_be_generated');
    }
  }

  const executionState = evidence?.high_scale_execution_state;
  if (hasValue(executionState) && UNAPPROVED_EXECUTION_STATES.has(String(executionState))) {
    pushInvalidField(invalid_fields, 'high_scale_execution_state', 'unapproved_execution_state', {
      value: executionState,
    });
  }

  if (evidence?.traffic_generation_enabled === true) {
    pushInvalidField(invalid_fields, 'traffic_generation_enabled', 'unapproved_high_scale_execution');
  }
  if (evidence?.live_traffic_started === true) {
    pushInvalidField(invalid_fields, 'live_traffic_started', 'unapproved_high_scale_execution');
  }

  return invalid_fields;
}

function validateKillSwitchDrillInvalidFields(evidence) {
  const invalid_fields = [];

  if (evidence?.latency_ok !== true) {
    pushInvalidField(invalid_fields, 'latency_ok', 'latency_not_ok');
  }

  const responseLatencyMs = evidence?.response_latency_ms;
  if (
    typeof responseLatencyMs !== 'number'
    || !Number.isFinite(responseLatencyMs)
    || responseLatencyMs < 0
  ) {
    pushInvalidField(invalid_fields, 'response_latency_ms', 'invalid_response_latency_ms');
  }

  const transcript = evidence?.transcript;
  if (!hasValue(transcript) || typeof transcript !== 'object' || Array.isArray(transcript)) {
    return invalid_fields;
  }

  for (const field of KILL_SWITCH_TRANSCRIPT_REQUIRED_FIELDS) {
    if (!hasValue(transcript[field])) {
      pushInvalidField(invalid_fields, `transcript.${field}`, 'missing_transcript_field');
    }
  }

  const closeout = transcript.closeout;
  if (hasValue(closeout) && typeof closeout === 'object' && !Array.isArray(closeout)) {
    for (const field of KILL_SWITCH_CLOSEOUT_REQUIRED_FIELDS) {
      if (!hasValue(closeout[field])) {
        pushInvalidField(invalid_fields, `transcript.closeout.${field}`, 'missing_closeout_field');
      }
    }
  }

  const socActors = Array.isArray(transcript.soc_actors) ? transcript.soc_actors : [];
  socActors.forEach((actor, index) => {
    for (const field of KILL_SWITCH_SOC_ACTOR_REQUIRED_FIELDS) {
      if (!hasValue(actor?.[field])) {
        pushInvalidField(invalid_fields, `transcript.soc_actors[${index}].${field}`, 'missing_soc_actor_field');
      }
    }
  });

  if (transcript.exercise != null) {
    appendExerciseValidationFailures(
      invalid_fields,
      validateKillSwitchExerciseEvidence(transcript.exercise),
      'transcript.exercise',
    );
  }

  const activationMs = parseIsoMs(transcript.activation_at);
  const stopMs = parseIsoMs(transcript.stop_signal_at);
  if (hasValue(transcript.activation_at) && activationMs === null) {
    pushInvalidField(invalid_fields, 'transcript.activation_at', 'invalid_iso_timestamp');
  }
  if (hasValue(transcript.stop_signal_at) && stopMs === null) {
    pushInvalidField(invalid_fields, 'transcript.stop_signal_at', 'invalid_iso_timestamp');
  }

  if (
    activationMs !== null
    && stopMs !== null
    && typeof responseLatencyMs === 'number'
    && Number.isFinite(responseLatencyMs)
  ) {
    const computedLatency = stopMs - activationMs;
    if (computedLatency < 0) {
      pushInvalidField(invalid_fields, 'transcript.stop_signal_at', 'stop_before_activation');
    } else if (computedLatency !== responseLatencyMs) {
      pushInvalidField(invalid_fields, 'response_latency_ms', 'latency_mismatch', {
        expected_ms: computedLatency,
        provided_ms: responseLatencyMs,
      });
    }
  }

  return invalid_fields;
}

function validateKindSpecificInvalidFields(kind, evidence) {
  if (kind === 'governed_adapter') {
    return validateGovernedAdapterInvalidFields(evidence);
  }
  if (kind === 'kill_switch_drill') {
    return validateKillSwitchDrillInvalidFields(evidence);
  }
  return [];
}

export function validateProductionReleaseEvidence(kind, evidence) {
  if (!PRODUCTION_RELEASE_EVIDENCE_KINDS.includes(kind)) {
    return {
      ok: false,
      invalid_kind: kind,
      missing_fields: [],
      forbidden_fields: collectForbiddenFields(evidence),
      invalid_fields: [],
    };
  }

  const required = PRODUCTION_RELEASE_EVIDENCE_REQUIREMENTS[kind];
  const missing_fields = required.filter((field) => !hasValue(evidence?.[field]));
  const forbidden_fields = collectForbiddenFields(evidence);
  const invalid_fields = validateKindSpecificInvalidFields(kind, evidence);

  return {
    ok:
      missing_fields.length === 0
      && forbidden_fields.length === 0
      && invalid_fields.length === 0,
    invalid_kind: null,
    missing_fields,
    forbidden_fields,
    invalid_fields,
  };
}
